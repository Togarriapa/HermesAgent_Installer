from __future__ import annotations

import hashlib
import json
import os
import subprocess
import time
from pathlib import Path

import pytest

from hermes_installer.authority import installer_release_build as release_build


def _sealed_distribution(tmp_path):
    root = tmp_path / "source"
    root.mkdir(mode=0o700)
    body = b"selected source bytes\n"
    (root / "module.py").write_bytes(body)
    os.chmod(root / "module.py", 0o600)
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    file_fd = os.open(root / "module.py", os.O_RDONLY)
    try:
        info = os.fstat(file_fd)
    finally:
        os.close(file_fd)
    receipt = release_build.VerifiedInstallerDistributionReceipt(
        release_build._SEAL,
        candidate_git_sha="a" * 40,
        git_tree_sha1="b" * 40,
        source_tree_sha256="c" * 64,
        baseline_tree_sha256="d" * 64,
        amendment_manifest_sha256="e" * 64,
        source_catalog_sha256="f" * 64,
        files=(release_build.DistributionFile(
            "module.py", hashlib.sha256(body).hexdigest(), len(body), 0o600,
            info.st_dev, info.st_ino, info.st_ctime_ns),),
        root_fd=fd,
        expected_uid=os.geteuid(),
        handle="h" * 43,
    )
    return receipt, root


def test_distribution_receipt_rechecks_nofollow_bytes_and_inode(tmp_path):
    receipt, root = _sealed_distribution(tmp_path)
    try:
        receipt.verify_current()
        path = root / "module.py"
        path.unlink()
        path.write_bytes(b"selected source bytes\n")
        os.chmod(path, 0o600)
        with pytest.raises(release_build.InstallerReleaseBuildError):
            receipt.verify_current()
    finally:
        receipt.close()


@pytest.mark.skipif(not Path("/usr/bin/git").exists(), reason="root source exporter requires system Git")
def test_git_batch_streams_large_request_and_response_pipes(tmp_path):
    repository = tmp_path / "repository"
    repository.mkdir()
    subprocess.run(["/usr/bin/git", "init", "-q", str(repository)], check=True)
    body = b"candidate source blob\n" * 32
    blob = subprocess.run(["/usr/bin/git", "-C", str(repository), "hash-object", "-w", "--stdin"],
                          input=body, stdout=subprocess.PIPE, check=True).stdout.decode("ascii").strip()
    # Repeated IDs are valid cat-file requests and drive both pipes beyond
    # their usual capacity while keeping the test's Git object store tiny.
    result = release_build.RootInstallerDistributionRegistry._git_batch(repository, [blob] * 2048)
    assert len(result) == 2048
    assert all(item == body for item in result)


def test_build_receipt_is_single_use_and_detects_output_mutation(tmp_path):
    output = tmp_path / "output"
    output.mkdir(mode=0o700)
    body = b"release module\n"
    (output / "module.py").write_bytes(body)
    os.chmod(output / "module.py", 0o444)
    info = os.stat(output / "module.py", follow_symlinks=False)
    row = release_build.BuildOutputFile("module.py", hashlib.sha256(body).hexdigest(), len(body), 0o444,
                                        ("module",), info.st_dev, info.st_ino)
    manifest = release_build._canonical_json({
        "schema": 1, "candidate_git_sha": "a" * 40,
        "files": [{"relative_path": row.relative_path, "sha256": row.sha256,
                   "size_bytes": row.size_bytes, "mode": row.mode, "roles": list(row.roles)}],
    })
    (output / release_build.RELEASE_MANIFEST_PATH).write_bytes(manifest)
    os.chmod(output / release_build.RELEASE_MANIFEST_PATH, 0o444)
    root_fd = os.open(output, os.O_RDONLY | os.O_DIRECTORY)
    receipt = release_build.VerifiedInstallerReleaseBuildReceipt(
        release_build._SEAL, handle="r" * 43, candidate_git_sha="a" * 40,
        distribution_receipt_handle="d" * 43, interpreter_receipt_handle="i" * 43,
        source_tree_sha256="c" * 64, baseline_tree_sha256="b" * 64,
        amendment_manifest_sha256="e" * 64, source_catalog_sha256="f" * 64,
        role_closure_manifest_sha256=hashlib.sha256(manifest).hexdigest(),
        root_setup_plan_sha256="0" * 64, builder_artifact_sha256="1" * 64,
        issued_monotonic=time.monotonic(),
        deployment_predecessor=release_build.DeploymentPredecessor("absent", info.st_dev, info.st_ino),
        files=(row,), manifest_sha256=hashlib.sha256(manifest).hexdigest(), root_fd=root_fd,
        expected_uid=os.geteuid())
    try:
        receipt.verify_current()
        opened = receipt.open_file("module.py")
        try:
            assert os.read(opened, len(body)) == body
        finally:
            os.close(opened)
        receipt.consume()
        with pytest.raises(release_build.BootstrapEnrollmentPending):
            receipt.verify_current()
    finally:
        receipt.close()


def test_enumeration_rejects_unsealed_symlink(tmp_path):
    root = tmp_path / "tree"
    root.mkdir()
    (root / "actual").write_bytes(b"ok")
    (root / "link").symlink_to(root / "actual")
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with pytest.raises(release_build.InstallerReleaseBuildError):
            release_build._enumerate_regular_files(fd)
    finally:
        os.close(fd)


def test_source_paths_reject_parent_and_platform_aliases():
    for value in ("../escape", "/absolute", "a//b", "a\\b", "a/./b"):
        with pytest.raises(release_build.InstallerReleaseBuildError):
            release_build._validate_relative_path(value)


def test_runtime_dependency_receipt_requires_exact_locked_version():
    registry = release_build.RootInstallerRuntimeArtifactRegistry()
    handle = registry._mint_observed("PyYAML", "6.0.3", {"site-packages/yaml/__init__.py": "a" * 64},
                                     frozenset({"6.0.3"}))
    receipt = registry.resolve(handle)
    assert (receipt.package_name, receipt.version, receipt.closure_sha256) == (
        "pyyaml", "6.0.3", release_build._manifest_digest({"site-packages/yaml/__init__.py": "a" * 64}))
    with pytest.raises(release_build.InstallerReleaseBuildError):
        registry._mint_observed("PyYAML", "6.0.4", {"site-packages/yaml/__init__.py": "a" * 64},
                                frozenset({"6.0.3"}))


def test_runtime_lock_requires_version_and_hash_pins():
    lock = Path(__file__).parents[2] / release_build.RUNTIME_REQUIREMENTS_PATH
    parsed = release_build._locked_package_versions(lock.read_bytes())
    assert parsed["pyyaml"] == frozenset({"6.0.3"})
    with pytest.raises(release_build.InstallerReleaseBuildError):
        release_build._locked_package_versions(b"PyYAML==6.0.3\n")


def test_wheel_record_rejects_digest_and_unlisted_member_changes():
    import base64

    body = b"package bytes"
    record = "yaml/__init__.py,sha256={},{}\n".format(
        base64.urlsafe_b64encode(hashlib.sha256(body).digest()).decode().rstrip("="), len(body))
    record += "PyYAML-6.0.3.dist-info/RECORD,,\n"
    rows = {"yaml/__init__.py": body, "PyYAML-6.0.3.dist-info/RECORD": record.encode()}
    release_build._verify_wheel_record(rows, "PyYAML-6.0.3.dist-info/RECORD")

    rows["yaml/__init__.py"] = b"changed"
    with pytest.raises(release_build.InstallerReleaseBuildError):
        release_build._verify_wheel_record(rows, "PyYAML-6.0.3.dist-info/RECORD")

    rows["yaml/__init__.py"] = body
    rows["yaml/unlisted.py"] = b"extra"
    with pytest.raises(release_build.InstallerReleaseBuildError):
        release_build._verify_wheel_record(rows, "PyYAML-6.0.3.dist-info/RECORD")


def test_pinned_download_rejects_unreviewed_digest_without_network(monkeypatch):
    monkeypatch.setattr(release_build, "BOOTSTRAP_PYYAML_URL", "https://files.pythonhosted.org/test.whl")
    payload = b"fixture payload"

    class Response:
        status = 200
        headers = type("Headers", (), {"get_content_length": lambda self: len(payload)})()

        def __enter__(self):
            return self

        def __exit__(self, *_):
            return None

        def geturl(self):
            return release_build.BOOTSTRAP_PYYAML_URL

        def read(self, maximum=-1):
            return payload if maximum < 0 or maximum >= len(payload) else payload[:maximum]

    monkeypatch.setattr(release_build.urllib.request, "build_opener",
                        lambda *handlers: type("Opener", (), {"open": lambda self, request, timeout: Response()})())
    with pytest.raises(release_build.InstallerReleaseBuildError):
        release_build._download_pinned(release_build.BOOTSTRAP_PYYAML_URL, "0" * 64,
                                       len(payload), 1024)


def test_bootstrap_transition_descriptor_requires_exact_sealed_shape():
    if not hasattr(os, "memfd_create"):
        pytest.skip("sealed memfd is a Linux kernel facility")
    descriptor = os.memfd_create("handoff-test", os.MFD_ALLOW_SEALING)
    try:
        body = release_build._canonical_json({
            "schema": 1, "handoff_handle": "h" * 43, "nonce": "n" * 43,
        })
        os.write(descriptor, body)
        with pytest.raises(release_build.InstallerReleaseBuildError):
            release_build._decode_sealed_handoff_descriptor(descriptor)
        seals = (release_build.fcntl.F_SEAL_WRITE | release_build.fcntl.F_SEAL_GROW
                 | release_build.fcntl.F_SEAL_SHRINK | release_build.fcntl.F_SEAL_SEAL)
        release_build.fcntl.fcntl(descriptor, release_build.fcntl.F_ADD_SEALS, seals)
        parsed, info, observed = release_build._decode_sealed_handoff_descriptor(descriptor)
        assert observed == body and info.st_size == len(body)
        assert parsed == {"schema": 1, "handoff_handle": "h" * 43, "nonce": "n" * 43}
    finally:
        os.close(descriptor)


def test_bootstrap_transition_descriptor_rejects_duplicate_and_extra_identity_fields():
    if not hasattr(os, "memfd_create"):
        pytest.skip("sealed memfd is a Linux kernel facility")

    def sealed(body: bytes) -> int:
        descriptor = os.memfd_create("handoff-negative-test", os.MFD_ALLOW_SEALING)
        os.write(descriptor, body)
        seals = (release_build.fcntl.F_SEAL_WRITE | release_build.fcntl.F_SEAL_GROW
                 | release_build.fcntl.F_SEAL_SHRINK | release_build.fcntl.F_SEAL_SEAL)
        release_build.fcntl.fcntl(descriptor, release_build.fcntl.F_ADD_SEALS, seals)
        return descriptor

    duplicate = sealed(b'{"schema":1,"schema":1,"handoff_handle":"' + b"h" * 43
                       + b'","nonce":"' + b"n" * 43 + b'"}')
    try:
        with pytest.raises(ValueError, match="duplicate key"):
            release_build._decode_sealed_handoff_descriptor(duplicate)
    finally:
        os.close(duplicate)

    extra = sealed(release_build._canonical_json({
        "schema": 1, "handoff_handle": "h" * 43, "nonce": "n" * 43,
        "candidate_git_sha": "a" * 40,
    }))
    try:
        with pytest.raises(release_build.InstallerReleaseBuildError):
            release_build._decode_sealed_handoff_descriptor(extra)
    finally:
        os.close(extra)


def test_fixed_reexec_driver_is_static_and_has_no_caller_identity_channel():
    source = release_build._fixed_reexec_entry_code()
    compile(source, "<fixed-reexec-entry>", "exec")
    assert "os.read(3, 4097)" in source
    assert "F_GET_SEALS" in source and "O_NOFOLLOW" in source
    assert "sys.argv" not in source and "os.environ" not in source
    assert "candidate_git_sha" not in source.split("transport =", 1)[0]


def test_runtime_handoff_cannot_be_constructed_without_registry_seal():
    with pytest.raises(TypeError, match="only be issued"):
        release_build.RootBootstrapRuntimeHandoff(object(), schema=1)


def test_deployment_predecessor_absence_is_a_sealed_typed_observation(monkeypatch):
    monkeypatch.setattr(release_build, "_require_linux_root", lambda: None)
    monkeypatch.setattr(release_build, "_read_deployment_predecessor", lambda: release_build.DeploymentPredecessor(
        "absent", 17, 23))
    proof = release_build.observe_deployment_predecessor()
    assert (proof.schema, proof.state, proof.parent_device, proof.parent_inode) == (1, "absent", 17, 23)
    assert proof.candidate_git_sha is None
    assert proof.deployment_receipt_sha256 is None
    assert proof.deployment_receipt_device is None and proof.deployment_receipt_inode is None
    assert proof.verified_release_receipt_handle is None
    with pytest.raises(TypeError, match="root-minted"):
        release_build.VerifiedDeploymentPredecessor(
            object(), state="absent", parent_device=17, parent_inode=23,
            candidate_git_sha=None, deployment_receipt_sha256=None,
            deployment_receipt_device=None, deployment_receipt_inode=None,
            verified_release_receipt_handle=None, issued_monotonic=time.monotonic())


def test_deployment_predecessor_present_invalid_release_fails_closed(monkeypatch):
    import sys
    import types

    class InvalidVerifier:
        @staticmethod
        def verify_installed_release():
            raise ValueError("corrupt receipt")

    monkeypatch.setattr(release_build, "_require_linux_root", lambda: None)
    monkeypatch.setattr(release_build, "_read_deployment_predecessor", lambda: release_build.DeploymentPredecessor(
        "present", 17, 23, "a" * 64, 29, 31, "b" * 40))
    module = types.ModuleType("hermes_installer.authority.installer_release")
    module.InstalledRootReleaseVerifier = InvalidVerifier
    monkeypatch.setitem(sys.modules, module.__name__, module)
    with pytest.raises(release_build.InstallerReleaseBuildError, match="not a verified"):
        release_build.observe_deployment_predecessor()
