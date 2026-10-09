from __future__ import annotations

import hashlib
import os
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
            info.st_dev, info.st_ino),),
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
