from __future__ import annotations

import hashlib
import json
import os
import tempfile
import time
from pathlib import Path

import pytest

from hermes_installer.authority.build_execution import (
    BuildOutputSpec, ContentAddressedBuildStore, ManagedBuildResult,
    RootBuildExecutionService,
)
from hermes_installer.authority.types import AuthorityDenied


def completed(**changes):
    now = time.monotonic()
    values = {
        "process_id": "managed-job-1", "generation": "generation-1",
        "uid": os.getuid(), "pid": 12345, "start_ticks": 55, "exit_code": 0,
        "timed_out": False, "cancelled": False, "cleanup_verified": True,
        "started_monotonic": now - .25, "finished_monotonic": now - .05,
        "kernel_limits": {"PrivateNetwork": "yes", "IPAddressDeny": "0.0.0.0/0 ::/0",
                          "NoNewPrivileges": "yes", "ProtectSystem": "strict"},
    }
    values.update(changes)
    return ManagedBuildResult(**values)


class Profile:
    target_id = "coral-cpython-build:start"
    generation = "generation-1"
    source_artifact_id = "coral-python39-source"
    source_sha256 = "1" * 64
    toolchain_artifact_id = "aarch64-toolchain"
    toolchain_sha256 = "2" * 64
    builder_artifact_id = "fixed-builder"
    builder_sha256 = "3" * 64
    argv_recipe = ("/catalog/builder", "build", "--fixed")
    environment = {"LANG": "C"}
    max_lifetime_seconds = 600
    output_root_id = "coral-build-output"
    output_owner_uid = os.getuid()

    def __init__(self, output_root: Path, outputs: dict[str, tuple[bytes, bool]]):
        self.output_root = output_root
        self.output_specs = {
            name: BuildOutputSpec(name, hashlib.sha256(data).hexdigest(), len(data), len(data), executable)
            for name, (data, executable) in outputs.items()
        }
        self.required_outputs = {name: spec.sha256 for name, spec in self.output_specs.items()}

    def attest_outputs(self):
        observed = {}
        for name, spec in self.output_specs.items():
            data = (self.output_root / name).read_bytes()
            observed[name] = hashlib.sha256(data).hexdigest()
        if observed != self.required_outputs:
            raise ValueError("enrolled output digest mismatch")
        return observed


def write_output(root: Path, name: str, data: bytes, *, executable=False):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    path.chmod(0o700 if executable else 0o600)
    return path


def make_store(root: Path) -> ContentAddressedBuildStore:
    return ContentAddressedBuildStore(root, signing_key=b"k" * 32, owner_uid=os.getuid())


def test_complete_output_manifest_is_cas_published_and_signature_resolves():
    with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
        base = Path(temporary)
        output_root = base / "build-output"
        output_root.mkdir(mode=0o700)
        output_root.chmod(0o700)
        runtime = write_output(output_root, "bin/python3.9", b"ELF fixture runtime", executable=True)
        module = write_output(output_root, "lib/tflite.so", b"native module bytes")
        profile = Profile(output_root, {
            "bin/python3.9": (runtime.read_bytes(), True),
            "lib/tflite.so": (module.read_bytes(), False),
        })
        store = make_store(base / "private-cas")

        record = store.publish(profile, enrollment_id="enroll-1",
                               operation_id="coral-cpython39-source-build-v1", process=completed())

        assert record.exit_code == 0
        assert record.generation == profile.generation
        assert record.source_sha256 == profile.source_sha256
        assert len(record.outputs) == 2
        assert {item.name for item in record.outputs} == set(profile.required_outputs)
        assert {item.name: item.executable for item in record.outputs} == {
            "bin/python3.9": True, "lib/tflite.so": False,
        }
        assert all(item.artifact_id == f"build-output:{item.sha256}:{'x' if item.executable else 'd'}"
                   for item in record.outputs)
        unsigned = dict(record.to_wire())
        signature = unsigned.pop("signature")
        digest = unsigned.pop("attestation_sha256")
        assert digest == hashlib.sha256(json.dumps(
            unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("ascii")).hexdigest()
        assert signature
        assert store.resolve(profile) == record
        for item in record.outputs:
            resolved = store.resolve_output(profile, item.artifact_id)
            assert resolved.read_bytes() == (output_root / item.name).read_bytes()
            assert resolved.stat().st_mode & 0o777 == (0o555 if item.executable else 0o444)


@pytest.mark.parametrize("changes", [
    {"exit_code": 1}, {"exit_code": None}, {"timed_out": True},
    {"cancelled": True}, {"cleanup_verified": False},
    {"generation": "stale-generation"},
    {"kernel_limits": {"PrivateNetwork": "no"}},
    {"uid": 0} if os.getuid() != 0 else {"uid": 1234},
])
def test_failed_or_unisolated_build_never_publishes_attestation(changes):
    with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
        base = Path(temporary)
        output_root = base / "build-output"
        output_root.mkdir(mode=0o700)
        write_output(output_root, "bin/python3.9", b"output", executable=True)
        profile = Profile(output_root, {"bin/python3.9": (b"output", True)})
        store = make_store(base / "private-cas")
        with pytest.raises(AuthorityDenied):
            store.publish(profile, enrollment_id="enroll-1",
                          operation_id="coral-cpython39-source-build-v1",
                          process=completed(**changes))
        assert not (store.root / "attestations").exists()


def test_output_manifest_rejects_missing_extra_symlink_mutation_and_wrong_mode():
    with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
        base = Path(temporary)
        output_root = base / "build-output"
        output_root.mkdir(mode=0o700)
        output = write_output(output_root, "bin/runtime", b"pinned", executable=True)
        profile = Profile(output_root, {"bin/runtime": (b"pinned", True)})
        store = make_store(base / "private-cas")

        output.write_bytes(b"mutated")
        with pytest.raises(AuthorityDenied):
            store.publish(profile, enrollment_id="e", operation_id="coral-cpython39-source-build-v1",
                          process=completed())
        output.write_bytes(b"pinned")
        write_output(output_root, "unreviewed", b"extra")
        with pytest.raises(AuthorityDenied):
            store.publish(profile, enrollment_id="e", operation_id="coral-cpython39-source-build-v1",
                          process=completed())
        (output_root / "unreviewed").unlink()
        output.chmod(0o600)
        with pytest.raises(AuthorityDenied):
            store.publish(profile, enrollment_id="e", operation_id="coral-cpython39-source-build-v1",
                          process=completed())
        output.chmod(0o700)
        (output_root / "link").symlink_to(output)
        with pytest.raises(AuthorityDenied):
            store.publish(profile, enrollment_id="e", operation_id="coral-cpython39-source-build-v1",
                          process=completed())
        (output_root / "link").unlink()
        output.unlink()
        with pytest.raises(AuthorityDenied):
            store.publish(profile, enrollment_id="e", operation_id="coral-cpython39-source-build-v1",
                          process=completed())
        assert not (store.root / "attestations").exists()


def test_cancelled_publication_does_not_activate_the_new_generation_receipt():
    with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
        base = Path(temporary)
        output_root = base / "build-output"
        output_root.mkdir(mode=0o700)
        write_output(output_root, "bin/runtime", b"pinned", executable=True)
        profile = Profile(output_root, {"bin/runtime": (b"pinned", True)})
        store = make_store(base / "private-cas")
        with pytest.raises(AuthorityDenied):
            store.publish(profile, enrollment_id="e", operation_id="coral-cpython39-source-build-v1",
                          process=completed(), cancelled=lambda: True)
        assert not store.root.exists()


def test_tampered_root_receipt_or_published_object_is_rejected():
    with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
        base = Path(temporary)
        output_root = base / "build-output"
        output_root.mkdir(mode=0o700)
        write_output(output_root, "bin/runtime", b"pinned", executable=True)
        profile = Profile(output_root, {"bin/runtime": (b"pinned", True)})
        store = make_store(base / "private-cas")
        record = store.publish(profile, enrollment_id="e", operation_id="coral-cpython39-source-build-v1",
                               process=completed())

        path = store.resolve_output(profile, record.outputs[0].artifact_id)
        path.chmod(0o755)
        with pytest.raises(AuthorityDenied):
            store.resolve(profile)
        path.chmod(0o555)
        manifest = store.root / "attestations" / f"{record.attestation_id}.json"
        manifest.chmod(0o600)
        contents = json.loads(manifest.read_text())
        contents["builder_sha256"] = "4" * 64
        manifest.write_text(json.dumps(contents, sort_keys=True, separators=(",", ":")))
        manifest.chmod(0o600)
        with pytest.raises(AuthorityDenied):
            store.resolve(profile)


@pytest.mark.parametrize("payload", [
    b"{}", b'{"schema":1}',
    b'{"schema":1,"enrollment_id":"e","generation":"g","operation_id":"colibri-source-build-v1","parameters":{"path":"/tmp"}}',
])
def test_selection_parser_rejects_missing_fields_or_caller_parameters(payload):
    with pytest.raises(AuthorityDenied):
        RootBuildExecutionService._request(payload)


def test_fixed_selection_parser_accepts_only_sol_operation_ids():
    for operation_id in ("coral-cpython39-source-build-v1", "colibri-source-build-v1"):
        payload = ("{\"schema\":1,\"enrollment_id\":\"e\",\"generation\":\"g\","
                   f"\"operation_id\":\"{operation_id}\",\"parameters\":{{}}}}").encode()
        assert RootBuildExecutionService._request(payload)["operation_id"] == operation_id
    with pytest.raises(AuthorityDenied):
        RootBuildExecutionService._request(
            b'{"schema":1,"enrollment_id":"e","generation":"g",'
            b'"operation_id":"coral-cpython-build:start","parameters":{}}')



def test_root_handler_resolves_fixed_inputs_runs_managed_job_and_publishes_receipt(monkeypatch):
    import json
    from types import SimpleNamespace

    from hermes_installer.authority.types import (
        EffectAuthorization, HostContext, Sensitivity, canonical_digest,
    )

    uid = os.getuid()
    monkeypatch.setattr(os, "geteuid", lambda: uid)
    with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
        base = Path(temporary)
        staging = base / "artifact-store"
        staging.mkdir(mode=0o700)
        source_root = staging / "source-tree"
        source_root.mkdir(mode=0o700)
        toolchain_root = staging / "toolchain-tree"
        toolchain_root.mkdir(mode=0o700)
        builder = staging / "builder"
        builder.write_bytes(b"fixed builder bytes")
        builder.chmod(0o700)
        output_root = base / "build-output"
        output_root.mkdir(mode=0o700)
        profile = Profile(output_root, {"bin/python3.9": (b"fixture-built-runtime", True)})

        class Catalog:
            def resolve(self, target_id, generation):
                assert target_id == profile.target_id
                assert generation == profile.generation
                return profile

        source_digest, toolchain_digest, builder_digest = (
            profile.source_sha256, profile.toolchain_sha256,
            hashlib.sha256(builder.read_bytes()).hexdigest(),
        )
        profile.builder_sha256 = builder_digest
        profile.source_sha256 = source_digest
        profile.toolchain_sha256 = toolchain_digest
        rows = {
            "coral-python39-source": SimpleNamespace(sha256=source_digest, tree_files=(object(),)),
            "aarch64-toolchain": SimpleNamespace(sha256=toolchain_digest, tree_files=(object(),)),
            "fixed-builder": SimpleNamespace(sha256=builder_digest, tree_files=()),
        }

        class Artifacts:
            artifacts = rows

            def materialize_tree(self, artifact_id, digest, _root, *, expected_uid):
                path = source_root if artifact_id == "coral-python39-source" else toolchain_root
                return SimpleNamespace(artifact_id=artifact_id, sha256=digest, path=path)

            def resolve(self, artifact_id, digest, _root, *, expected_uid):
                return SimpleNamespace(artifact_id=artifact_id, sha256=digest, path=builder)

        class Launcher:
            def run(self, inputs, *, timeout, cancelled):
                assert inputs.target_id == profile.target_id
                assert inputs.source_root == source_root
                assert inputs.toolchain_root == toolchain_root
                assert inputs.builder_executable == builder
                assert timeout > 0 and not cancelled()
                write_output(output_root, "bin/python3.9", b"fixture-built-runtime", executable=True)
                return completed()

        store = make_store(base / "cas")
        service = RootBuildExecutionService(
            build_catalog=Catalog(), artifact_catalog=Artifacts(), artifact_staging_root=staging,
            launcher=Launcher(), authority_key=b"k" * 32, store=store, expected_uid=uid,
        )
        payload = json.dumps({"schema": 1, "enrollment_id": "enrollment:coral",
                              "generation": profile.generation,
                              "operation_id": "coral-cpython39-source-build-v1",
                              "parameters": {}}, sort_keys=True, separators=(",", ":")).encode("ascii")
        digest = canonical_digest(payload)
        context = HostContext(
            principal_id="principal:coral", profile_id="profile:coral", namespace_id="namespace:coral",
            uid=uid, purpose="build", intent_id="intent:build", trace_id="trace:build",
            sensitivity=Sensitivity.PRIVATE, lineage_hash="a" * 64, policy_revision="policy:1",
            capabilities=frozenset({"hermes-profile-invoke"}), issued_at_monotonic=time.monotonic(),
            monotonic_expires_at=time.monotonic() + 60, nonce="nonce:context", grant_id="grant:context",
            signature="context-signature", final_payload_digest=digest,
            enrollment_id="enrollment:coral", generation=profile.generation, operation="process.start",
        )
        authorization = EffectAuthorization(
            principal_id=context.principal_id, profile_id=context.profile_id,
            namespace_id=context.namespace_id, uid=uid, purpose="build", sensitivity=Sensitivity.PRIVATE,
            trace_id="trace:build", policy_revision="policy:1", lineage_hash="a" * 64,
            capability="hermes-profile-invoke", intent_id="intent:build",
            target=profile.target_id, recipient=None, request_digest=digest, retry_index=0,
            issued_at_monotonic=time.monotonic(), monotonic_expires_at=time.monotonic() + 60,
            grant_id="grant:effect", nonce="nonce:effect", context_digest="b" * 64,
            signature="effect-signature", final_payload_digest=digest,
            enrollment_id="enrollment:coral", generation=profile.generation, operation="process.start",
        )

        response = service(context=context, authorization=authorization, payload=payload,
                           timeout=20, peer_pid=uid + 100, peer_pidfd=1, cancelled=lambda: False)

        receipt = json.loads(response["body"])
        assert response["status"] == 200
        assert response["receipt_id"] == receipt["attestation_id"]
        assert receipt["target_id"] == profile.target_id
        assert receipt["outputs"][0]["sha256"] == hashlib.sha256(b"fixture-built-runtime").hexdigest()
        assert store.resolve(profile).attestation_id == receipt["attestation_id"]
