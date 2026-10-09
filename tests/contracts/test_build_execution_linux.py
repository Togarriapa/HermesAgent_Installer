"""Root build receipt integration over the real Linux systemd build runner.

The output here is a synthetic custody fixture. It proves that the selected
build effect, terminal cleanup proof, output hashing, private CAS and signed
receipt join end-to-end; it does not prove ARM64 output or runtime ABI.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import time
import unittest
import uuid
from pathlib import Path
from types import SimpleNamespace

from hermes_installer.authority.build_execution import (
    BuildOutputSpec,
    ContentAddressedBuildStore,
    RootBuildExecutionService,
)
from hermes_installer.authority.types import (
    AuthorityDenied,
    EffectAuthorization,
    HostContext,
    Sensitivity,
    canonical_digest,
)
from tests.contracts import test_managed_build_custody_linux


class FixtureFactInspector:
    def inspect(self, _profile, _spec, path: Path):
        try:
            result = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            raise AuthorityDenied("build.fixture", "managed output is not the expected fixture record") from None
        if (not isinstance(result, dict) or result.get("source_write_denied") is not True
                or result.get("toolchain_write_denied") is not True
                or result.get("loopback_reached") is not False
                or result.get("external_reached") is not False
                or result.get("uid") <= 0):
            raise AuthorityDenied("build.fixture", "isolated build fixture effects were not verified")
        return {"fixture": "linux-root-managed-build-v1"}


class RootBuildExecutionLinuxTests(unittest.TestCase):
    def test_root_build_handler_publishes_only_real_terminal_fixture_output(self):
        fixture_type = test_managed_build_custody_linux.BuildCustodyLinuxTests
        try:
            fixture_type.setUpClass()
        except unittest.SkipTest as exc:
            self.skipTest(str(exc))
        fixture = fixture_type("test_build_runs_under_real_isolation_and_emits_terminal_cleanup_proof")
        fixture.setUp()
        peer_pidfd = None
        try:
            fixture.target = "colibri-source-build:start"
            fixture.profile = fixture.profile.__class__(
                **{
                    field: getattr(fixture.profile, field)
                    for field in fixture.profile.__dataclass_fields__
                    if field != "operation_targets"
                },
                operation_targets={"process.start": fixture.target},
            )
            fixture.manager.profiles = {fixture.profile.profile_id: fixture.profile}
            fixture.inputs.target_id = fixture.target

            now = time.monotonic()
            payload = json.dumps({
                "schema": 1,
                "enrollment_id": "build-enrollment-" + fixture.token,
                "generation": fixture.inputs.generation,
                "operation_id": "colibri-source-build-v1",
                "parameters": {},
            }, sort_keys=True, separators=(",", ":")).encode("ascii")
            digest = canonical_digest(payload)
            context = HostContext(
                principal_id="ci-controller-" + fixture.token,
                profile_id="ci-controller-" + fixture.token,
                namespace_id="ci-namespace-" + fixture.token,
                uid=65534,
                purpose="selected-process-operation",
                intent_id="ci-build-intent-" + fixture.token,
                trace_id="ci-build-trace-" + fixture.token,
                sensitivity=Sensitivity.UNKNOWN,
                lineage_hash="e" * 64,
                policy_revision="ci-build-v1",
                capabilities=frozenset({"hermes-profile-invoke"}),
                issued_at_monotonic=now,
                monotonic_expires_at=now + 30,
                nonce="ci-context-nonce-" + fixture.token,
                grant_id="ci-context-grant-" + fixture.token,
                signature="ci-context-signature",
                final_payload_digest=digest,
                enrollment_id="build-enrollment-" + fixture.token,
                generation=fixture.inputs.generation,
                operation="process.start",
            )
            authorization = EffectAuthorization(
                principal_id=context.principal_id, profile_id=context.profile_id,
                namespace_id=context.namespace_id, uid=context.uid, purpose=context.purpose,
                sensitivity=context.sensitivity, trace_id=context.trace_id,
                policy_revision=context.policy_revision, lineage_hash=context.lineage_hash,
                capability="hermes-profile-invoke", intent_id=context.intent_id,
                target=fixture.target, recipient=None, request_digest=digest, retry_index=0,
                issued_at_monotonic=now, monotonic_expires_at=now + 30,
                grant_id="ci-effect-grant-" + fixture.token, nonce="ci-effect-nonce-" + fixture.token,
                context_digest=canonical_digest(context.claims()), signature="ci-effect-signature",
                final_payload_digest=digest, enrollment_id=context.enrollment_id,
                generation=fixture.inputs.generation, operation="process.start",
            )

            facts = {"fixture": "linux-root-managed-build-v1"}
            output_spec = BuildOutputSpec("effects.json", "file", 65536, "data", facts)
            build_profile = SimpleNamespace(
                target_id=fixture.target,
                generation=fixture.inputs.generation,
                service_generation_digest=fixture.inputs.service_generation_digest,
                build_service_enrollment_id=fixture.profile.enrollment_id,
                build_service_generation=fixture.profile.generation,
                source_artifact_id=fixture.inputs.source_artifact_id,
                source_sha256=fixture.inputs.source_sha256,
                toolchain_artifact_id=fixture.inputs.toolchain_artifact_id,
                toolchain_sha256=fixture.inputs.toolchain_sha256,
                builder_artifact_id=fixture.inputs.builder_artifact_id,
                builder_sha256=fixture.inputs.builder_sha256,
                argv_recipe=fixture.inputs.argv_recipe,
                environment=fixture.inputs.environment,
                max_lifetime_seconds=fixture.inputs.max_lifetime_seconds,
                output_root_id="ci-build-output-" + fixture.token,
                output_root=fixture.output,
                output_owner_uid=fixture.uid,
                output_specs={"effects.json": output_spec},
            )

            class BuildCatalog:
                def resolve_service(self, target_id, generation, service_catalog):
                    assert target_id == fixture.target and generation == fixture.inputs.generation
                    assert service_catalog is services
                    return build_profile, SimpleNamespace(
                        enrollment_id=build_profile.build_service_enrollment_id,
                        generation=build_profile.build_service_generation,
                        service_uid=fixture.uid,
                        service_gid=fixture.gid,
                    )

            class ArtifactCatalog:
                artifacts = {
                    fixture.inputs.source_artifact_id: SimpleNamespace(
                        sha256=fixture.inputs.source_sha256, tree_files=fixture.inputs.source_tree_files),
                    fixture.inputs.toolchain_artifact_id: SimpleNamespace(
                        sha256=fixture.inputs.toolchain_sha256, tree_files=fixture.inputs.toolchain_tree_files),
                    fixture.inputs.builder_artifact_id: SimpleNamespace(
                        sha256=fixture.inputs.builder_sha256, tree_files=()),
                }

                @staticmethod
                def _row(artifact_id, path, digest, files=(), manifest=None):
                    return SimpleNamespace(artifact_id=artifact_id, sha256=digest, path=path,
                                           tree_files=files, tree_manifest_sha256=(
                                               manifest if manifest is not None else hashlib.sha256(b"[]").hexdigest()))

                def materialize_tree(self, artifact_id, digest, _staging, *, expected_uid):
                    assert expected_uid == 0
                    if artifact_id == fixture.inputs.source_artifact_id:
                        return self._row(artifact_id, fixture.source, digest, fixture.inputs.source_tree_files,
                                         fixture.inputs.source_tree_manifest_sha256)
                    return self._row(artifact_id, fixture.toolchain, digest, fixture.inputs.toolchain_tree_files,
                                     fixture.inputs.toolchain_tree_manifest_sha256)

                def resolve(self, artifact_id, digest, _staging, *, expected_uid):
                    assert expected_uid == 0 and artifact_id == fixture.inputs.builder_artifact_id
                    return self._row(artifact_id, fixture.builder, digest)

            services = object()
            store = ContentAddressedBuildStore(fixture.stage / "build-cas", signing_key=b"b" * 32, owner_uid=0)
            service = RootBuildExecutionService(
                build_catalog=BuildCatalog(), service_catalog=services,
                artifact_catalog=ArtifactCatalog(), artifact_staging_root=fixture.stage,
                launcher=fixture.runner, fact_inspector=FixtureFactInspector(),
                store=store, expected_uid=0,
            )
            self.assertEqual(set(service.handlers()), {("process.start", fixture.target)})
            peer_pidfd = os.pidfd_open(os.getpid(), 0)
            response = service(
                context=context, authorization=authorization, payload=payload,
                timeout=30, peer_pid=os.getpid(), peer_pidfd=peer_pidfd,
                cancelled=lambda: False,
            )
            receipt = json.loads(base64.b64decode(response["body"], validate=True))
            self.assertEqual(response["status"], 200)
            self.assertEqual(receipt["build_target_id"], fixture.target)
            self.assertEqual(receipt["build_generation"], fixture.inputs.generation)
            self.assertTrue(receipt["terminal_success_record_id"])
            self.assertEqual(receipt["execution"]["exit_code"], 0)
            self.assertIs(receipt["execution"]["cleanup_verified"], True)
            self.assertEqual(receipt["output_records"][0]["relative_path"], "effects.json")
            self.assertEqual(receipt["output_records"][0]["observed_target_facts"], facts)
            self.assertTrue(store.resolve_output(build_profile, "effects.json").is_file())
            self.assertEqual(list(fixture.output.iterdir()), [])
        finally:
            if peer_pidfd is not None:
                os.close(peer_pidfd)
            fixture.tearDown()
