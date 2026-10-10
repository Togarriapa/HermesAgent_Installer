from __future__ import annotations

import os
import hashlib
import stat
from types import SimpleNamespace
from pathlib import Path

import pytest

from hermes_installer.managed_process_custodian import RemoteOriginKernelProof
from hermes_installer.models.private_deployment import (
    _inspect_existing_model_tree_fd,
    _revalidate_existing_model_tree_metadata,
    PrivateEndpointObservation,
    PrivateDeploymentDenied,
    PrivateModelDeploymentObservation,
    RootExistingModelSelectionRegistry,
    _validate_model_subpath,
    _tcp4_listener_inodes,
    _supporting_source_receipt_digest,
    inspect_loopback_listener,
    RootExistingModelArtifactObserver,
)
from hermes_installer.models.artifacts import ArtifactFile, ArtifactManifest


def _proof(*, netns: int, pid: int = 4242) -> RemoteOriginKernelProof:
    return RemoteOriginKernelProof(
        process_id="process-1", enrollment_id="svc-1", profile_id="colibri-main",
        profile_generation="generation-1", uid=1001, gid=1001, pid=pid,
        pid_starttime_ticks=9876, executable_device=1, executable_inode=2,
        executable_sha256="a" * 64, cgroup_id="0::/system.slice/colibri.service",
        mount_namespace_inode=42, network_namespace_inode=netns,
        pidfd_registry_handle="held-pidfd-1", expires_monotonic=999999.0,
    )


def _proc_fixture(root: Path, proof: RemoteOriginKernelProof, *, table: str,
                  cgroup: str | None = None, uid: int | None = None) -> None:
    process = root / str(proof.pid)
    (process / "net").mkdir(parents=True, exist_ok=True)
    (process / "fd").mkdir(exist_ok=True)
    # stat fields after comm begin at field 3; starttime is field 22/index 19.
    tail = ["S"] + ["0"] * 18 + [str(proof.pid_starttime_ticks)]
    (process / "stat").write_text(f"{proof.pid} (selected (service)) " + " ".join(tail))
    (process / "status").write_text(f"Name:\ttest\nUid:\t{uid or proof.uid}\t{uid or proof.uid}\t{uid or proof.uid}\t{uid or proof.uid}\n")
    (process / "cgroup").write_text(cgroup or proof.cgroup_id)
    (process / "net/tcp").write_text(table)
    ns_source = root / "netns"
    ns_source.write_text("namespace")
    (process / "ns").mkdir(exist_ok=True)
    try:
        (process / "ns/net").unlink()
    except FileNotFoundError:
        pass
    (process / "ns/net").symlink_to(ns_source)
    try:
        (process / "fd/9").unlink()
    except FileNotFoundError:
        pass
    (process / "fd/9").symlink_to("socket:[4567]")


def _table(*rows: str) -> str:
    return "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n" + "\n".join(rows)


def test_tcp_parser_accepts_only_exact_loopback_listener() -> None:
    table = _table(
        "0: 0100007F:1F40 00000000:0000 0A 0:0 00:00000000 0 0 0 4567",
        "1: 00000000:1F40 00000000:0000 0A 0:0 00:00000000 0 0 0 1111",
        "2: 0100007F:1F40 00000000:0000 01 0:0 00:00000000 0 0 0 2222",
        "3: 0100007F:1F41 00000000:0000 0A 0:0 00:00000000 0 0 0 3333",
    )
    assert _tcp4_listener_inodes(table, 8000) == {4567}


def test_listener_observation_requires_exact_process_fd_cgroup_uid_and_netns(tmp_path: Path,
                                                                             monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    proof = _proof(netns=(tmp_path / "netns").stat().st_ino if (tmp_path / "netns").exists() else 0)
    table = _table("0: 0100007F:1F40 00000000:0000 0A 0:0 00:00000000 0 0 0 4567")
    _proc_fixture(tmp_path, proof, table=table)
    proof = _proof(netns=(tmp_path / "netns").stat().st_ino)
    observed = inspect_loopback_listener(proof, port=8000, proc_root=tmp_path, monotonic=lambda: 12.0)
    assert (observed.address, observed.port, observed.socket_inode, observed.owner_fd) == (
        "127.0.0.1", 8000, 4567, 9,
    )
    assert len(observed.observation_sha256) == 64

    for mutation in (
        {"table": _table("0: 00000000:1F40 00000000:0000 0A 0:0 00:00000000 0 0 0 4567")},
        {"cgroup": "0::/system.slice/other.service"},
        {"uid": 2020},
        {"table": _table("0: 0100007F:1F41 00000000:0000 0A 0:0 00:00000000 0 0 0 4567")},
    ):
        _proc_fixture(tmp_path, proof, table=mutation.pop("table", table), **mutation)
        with pytest.raises(PrivateDeploymentDenied):
            inspect_loopback_listener(proof, port=8000, proc_root=tmp_path)


def test_listener_observation_rejects_other_ports_and_nonroot(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    with pytest.raises(PrivateDeploymentDenied):
        inspect_loopback_listener(_proof(netns=1), port=8000)


def test_signed_receipt_claims_are_domain_payload_and_signature_excluded() -> None:
    common = dict(
        schema=1, receipt_handle="opaque-receipt", receipt_sha256="a" * 64,
        boot_id="boot-1", model_binding_id="model-binding",
        model_selection_sha256="b" * 64, endpoint_receipt_handle="endpoint-receipt",
        profile_id="hermes-memory", namespace_id="ns-1", service_enrollment_id="svc-1",
        service_generation="gen-1", source_model_id="model/source", source_revision="c" * 40,
        license_artifact_id="license", license_sha256="d" * 64,
        model_artifact_id="existing-model:" + "e" * 64, model_artifact_sha256="e" * 64,
        model_tree_manifest_sha256="f" * 64, model_member_observation_sha256="1" * 64,
        runtime_artifact_id="runtime", runtime_artifact_sha256="2" * 64,
        load_config_artifact_id="load-config", load_config_sha256="3" * 64,
        served_model_id="model-alias", capability="extraction-text", dimensions=None,
        process_identity_digest="4" * 64, kernel_process_receipt_handle="kernel-receipt",
        load_observation_handle="load-observation", capability_probe_receipt_handle="probe",
        issued_monotonic=10.0, expires_monotonic=20.0, signature=b"sig",
    )
    receipt = PrivateModelDeploymentObservation(**common)
    claims = receipt.claims()
    assert "signature" not in claims and "receipt_sha256" not in claims
    assert claims["served_model_id"] == "model-alias"
    assert receipt.signature == b"sig"

    endpoint = PrivateEndpointObservation(
        schema=1, receipt_handle="endpoint", receipt_sha256="5" * 64, boot_id="boot-1",
        endpoint_binding_id="endpoint-binding", endpoint_selection_sha256="6" * 64,
        profile_id="colibri-main", namespace_id="ns-1", principal_id="root-principal",
        service_enrollment_id="svc-1", service_generation="gen-1",
        process_profile_id="colibri-main", process_profile_generation="gen-1",
        endpoint_target_id="colibri-main", connector_route_ids=("colibri-openai-v1",),
        recipient_id="memory-engine", credential_reference_id=None,
        server_config_artifact_id="config", server_config_sha256="7" * 64,
        runtime_artifact_records=({"artifact_id": "runtime", "sha256": "8" * 64},),
        process_identity_digest="9" * 64, kernel_process_receipt_handle="kernel",
        private_network_receipt_handle="network", listening_endpoint_observation_handle="listener",
        ownership_observation_sha256="a" * 64, issued_monotonic=10.0,
        expires_monotonic=20.0, signature=b"sig",
    )
    assert endpoint.claims()["connector_route_ids"] == ["colibri-openai-v1"]


def test_v136_source_receipt_digest_binds_exact_observed_catalog_receipts() -> None:
    rows = [
        {"artifact_id": "glm52-artifact-metadata-v1", "sha256": "a" * 64,
         "size_bytes": 56232, "receipt_handle": "model-source-observation:manifest-123456789012"},
        {"artifact_id": "glm52-upstream-mit-license-cf457fa", "sha256": "b" * 64,
         "size_bytes": 1065, "receipt_handle": "model-source-observation:license-1234567890123456"},
        {"artifact_id": "glm52-quantized-readme-6bbb01e", "sha256": "c" * 64,
         "size_bytes": 17468, "receipt_handle": "model-source-observation:readme-1234567890123456"},
    ]
    digest = _supporting_source_receipt_digest(rows)
    assert len(digest) == 64
    assert _supporting_source_receipt_digest(list(reversed(rows))) == digest
    altered = [dict(row) for row in rows]
    altered[0]["receipt_handle"] = "model-source-observation:other-1234567890123456"
    assert _supporting_source_receipt_digest(altered) != digest
    with pytest.raises(PrivateDeploymentDenied):
        _supporting_source_receipt_digest(rows[:2])


def test_fixture_owned_existing_tree_verifies_pinned_members_by_fd(tmp_path: Path) -> None:
    """Fixture-only helper tests bytes/identity; this is not root deployment proof."""
    model_root = tmp_path / "chosen-existing-model"
    model_root.mkdir(mode=0o700)
    (model_root / "weights").mkdir(mode=0o700)
    first = b"pinned tensor bytes"
    second = b"pinned config bytes"
    (model_root / "weights/shard.bin").write_bytes(first)
    (model_root / "config.json").write_bytes(second)
    os.chmod(model_root / "weights/shard.bin", 0o400)
    os.chmod(model_root / "config.json", 0o400)
    git_sha = hashlib.sha1(f"blob {len(second)}\0".encode() + second).hexdigest()
    manifest = ArtifactManifest(
        "fixture-model", "a" * 40, "fixture", "none",
        (
            ArtifactFile("weights/shard.bin", len(first), hashlib.sha256(first).hexdigest(), "sha256", "fixture://weights"),
            ArtifactFile("config.json", len(second), git_sha, "git-sha1", "fixture://config"),
        ),
        len(first) + len(second),
    )
    fd = os.open(model_root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        facts = _inspect_existing_model_tree_fd(fd, manifest, expected_uid=os.getuid())
        assert facts.member_count == 2
        assert facts.total_size_bytes == len(first) + len(second)
        assert [row["path"] for row in facts.members] == ["config.json", "weights/shard.bin"]
        assert len(facts.tree_manifest_sha256) == len(facts.member_observation_sha256) == 64
        _revalidate_existing_model_tree_metadata(fd, facts, expected_uid=os.getuid())
    finally:
        os.close(fd)


    (model_root / "unexpected.txt").write_text("extra")
    fd = os.open(model_root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        with pytest.raises(PrivateDeploymentDenied):
            _inspect_existing_model_tree_fd(fd, manifest, expected_uid=os.getuid())
    finally:
        os.close(fd)
    (model_root / "unexpected.txt").unlink()

    os.chmod(model_root / "weights/shard.bin", 0o600)
    (model_root / "weights/shard.bin").write_bytes(b"changed tensor bytes")
    os.chmod(model_root / "weights/shard.bin", 0o400)
    fd = os.open(model_root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        with pytest.raises(PrivateDeploymentDenied):
            _inspect_existing_model_tree_fd(fd, manifest, expected_uid=os.getuid())
        with pytest.raises(PrivateDeploymentDenied):
            _revalidate_existing_model_tree_metadata(fd, facts, expected_uid=os.getuid())
    finally:
        os.close(fd)

    os.chmod(model_root / "weights/shard.bin", 0o600)
    (model_root / "weights/shard.bin").write_bytes(first)
    os.chmod(model_root / "weights/shard.bin", 0o400)
    (model_root / "unlisted-link").symlink_to("config.json")
    fd = os.open(model_root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        with pytest.raises(PrivateDeploymentDenied):
            _inspect_existing_model_tree_fd(fd, manifest, expected_uid=os.getuid())
    finally:
        os.close(fd)

def test_pinned_glm_manifest_parses_from_already_observed_bytes() -> None:
    from hermes_installer.models.artifacts import MODEL_BYTES, MODEL_SIZE_CLAIM

    metadata = Path("planning/glm52-artifact-metadata.json").read_bytes()
    manifest = ArtifactManifest.from_metadata_bytes(metadata)
    assert manifest.model_id == "mastouri/GLM-5.2-colibri-int4-g64-with-int8-mtp"
    assert manifest.revision == "6bbb01ed3e515a8730b694dfae73aadfd6774581"
    assert manifest.total_bytes == MODEL_BYTES == 429_276_220_139
    assert manifest.declared_storage_bytes == MODEL_SIZE_CLAIM == 429_276_080_522


def test_existing_model_observer_rejects_unissued_selection_object(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A caller-created lookalike selection cannot select a root model directory."""
    monkeypatch.setattr(os, "geteuid", lambda: 0)

    class FakeSelectionRegistry:
        def resolve_selection(self, _handle: str) -> object:
            return SimpleNamespace(selection_handle="selection-from-caller")

        def verify_current(self, _selection: object) -> object:
            return _selection

        def open_selected_directory(self, _handle: str) -> object:
            raise AssertionError("unissued selections must be rejected before opening a directory")

    class FakeArtifactObserver:
        def observe(self, *_args: object, **_kwargs: object) -> object:
            raise AssertionError("source artifact resolution must not precede selection validation")

        def verify_current(self, _observation: object) -> bool:
            return False

    observer = RootExistingModelArtifactObserver(
        object(), object(), object(), FakeSelectionRegistry(), FakeArtifactObserver(),
    )
    with pytest.raises(PrivateDeploymentDenied, match="not issued by the protected root selection registry"):
        observer.observe_selected_tree("selection-from-caller")


def test_existing_model_choice_path_is_relative_and_cannot_escape() -> None:
    assert _validate_model_subpath("models/glm52") == "models/glm52"
    for candidate in ("", ".", "../model", "models/../other", "/root/model", "models\\glm52"):
        with pytest.raises(PrivateDeploymentDenied):
            _validate_model_subpath(candidate)


def test_existing_model_selection_fails_before_tty_without_source_catalog_pins(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No source/license catalog pins means no path prompt or selection receipt."""
    monkeypatch.setattr(os, "geteuid", lambda: 0)

    class ArtifactCatalog:
        artifacts = {}

    class ArtifactObserver:
        runtime_bindings = SimpleNamespace(artifact_catalog=ArtifactCatalog())

        def observe(self, *_args: object, **_kwargs: object) -> object:
            raise AssertionError("catalog rows are absent")

        def verify_current(self, _observation: object) -> bool:
            return False

    class NeverRootFilesystem:
        def resolve_selection(self, _handle: str) -> object:
            raise AssertionError("catalog pins must be checked before filesystem selection")

        def verify_current(self, _selection: object) -> object:
            raise AssertionError("catalog pins must be checked before filesystem selection")

        def open_selected_subdirectory(self, *_args: object, **_kwargs: object) -> object:
            raise AssertionError("catalog pins must be checked before filesystem selection")

    registry = RootExistingModelSelectionRegistry(
        object(), NeverRootFilesystem(), object(), ArtifactObserver(),
        input_reader=lambda _prompt: (_ for _ in ()).throw(AssertionError("no TTY prompt expected")),
    )
    with pytest.raises(PrivateDeploymentDenied, match="absent from the protected artifact catalog"):
        registry.observe_existing_model_directory("root-store-receipt")
