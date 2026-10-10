from __future__ import annotations

import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from hermes_installer.authority import installer_release_build as release_build
from hermes_installer.authority.application_effect_source_catalog import APPLICATION_EFFECT_SOURCE_MEMBERS


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


def test_distribution_receipt_materializes_and_verifies_many_files_under_low_nofile(tmp_path):
    script = r'''
import hashlib
import os
import resource
import sys
from pathlib import Path

resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
from hermes_installer.authority import installer_release_build as rb

root = Path(sys.argv[1]) / "source"
root.mkdir(mode=0o700)
exported = []
for index in range(140):
    name = f"modules/member-{index:03d}.py"
    path = root / name
    path.parent.mkdir(exist_ok=True)
    body = (f"member {index}" + chr(10)).encode()
    path.write_bytes(body)
    os.chmod(path, 0o444)
    exported.append((name, hashlib.sha256(body).hexdigest(), len(body)))
os.chmod(root / "modules", 0o555)
os.chmod(root, 0o555)
root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
rows = rb._inspect_source_tree(root_fd, tuple(exported))
receipt = rb.VerifiedInstallerDistributionReceipt(
    rb._SEAL, candidate_git_sha="a" * 40, git_tree_sha1="b" * 40,
    source_tree_sha256="c" * 64, baseline_tree_sha256="d" * 64,
    amendment_manifest_sha256="e" * 64, source_catalog_sha256="f" * 64,
    files=tuple(rows), root_fd=root_fd, expected_uid=os.geteuid(), handle="h" * 43)
try:
    receipt.verify_current()
    for row in rows:
        fd = receipt.open_file(row.relative_path)
        try:
            member_index = int(row.relative_path.split("-")[-1].split(".")[0])
            assert os.read(fd, row.size_bytes) == (f"member {member_index}" + chr(10)).encode()
        finally:
            os.close(fd)
    replaced = root / rows[0].relative_path
    os.chmod(replaced.parent, 0o755)
    backup = replaced.parent / "replacement.tmp"
    backup.write_bytes(replaced.read_bytes())
    os.chmod(backup, 0o444)
    os.replace(backup, replaced)
    os.chmod(replaced.parent, 0o555)
    try:
        receipt.verify_current()
    except rb.InstallerReleaseBuildError:
        print("LOW_NOFILE_OK_TRUST_REJECTION_PRESERVED")
    else:
        raise AssertionError("identical-byte replacement was accepted")
finally:
    receipt.close()
'''
    env = dict(os.environ)
    env["PYTHONPATH"] = str(Path(__file__).parents[2] / "src")
    result = subprocess.run(
        [sys.executable, "-c", script, str(tmp_path)],
        check=False, capture_output=True, text=True, timeout=30, env=env,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "LOW_NOFILE_OK_TRUST_REJECTION_PRESERVED"


def test_initial_setup_prefixes_create_only_fixed_owned_directories_and_fsync(tmp_path, monkeypatch):
    parent = tmp_path / "etc"
    parent.mkdir(mode=0o755)
    parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
    real_fsync = os.fsync
    synced = []
    monkeypatch.setattr(release_build.os, "fsync", lambda fd: (synced.append(fd), real_fsync(fd))[1])
    try:
        release_build._ensure_owned_child_directory(
            parent_fd, "hermes-installer", 0o755,
            expected_uid=os.geteuid(), expected_gid=os.getegid())
        setup_fd = os.open("hermes-installer", os.O_RDONLY | os.O_DIRECTORY, dir_fd=parent_fd)
        try:
            release_build._ensure_owned_child_directory(
                setup_fd, "credentials", 0o700,
                expected_uid=os.geteuid(), expected_gid=os.getegid())
            before = len(synced)
            # Idempotent verification must not normalize or rewrite existing directories.
            release_build._ensure_owned_child_directory(
                setup_fd, "credentials", 0o700,
                expected_uid=os.geteuid(), expected_gid=os.getegid())
            assert len(synced) == before
            assert (parent / "hermes-installer" / "credentials").stat().st_mode & 0o777 == 0o700
        finally:
            os.close(setup_fd)
        assert len(synced) >= 4  # each newly created directory and its parent
    finally:
        os.close(parent_fd)


def test_initial_setup_prefixes_reject_symlink_and_unsafe_existing_mode(tmp_path):
    parent = tmp_path / "etc"
    parent.mkdir()
    target = tmp_path / "target"
    target.mkdir()
    (parent / "hermes-installer").symlink_to(target, target_is_directory=True)
    parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with pytest.raises(release_build.InstallerReleaseBuildError):
            release_build._ensure_owned_child_directory(
                parent_fd, "hermes-installer", 0o755,
                expected_uid=os.geteuid(), expected_gid=os.getegid())
        (parent / "hermes-installer").unlink()
        (parent / "hermes-installer").mkdir(mode=0o777)
        os.chmod(parent / "hermes-installer", 0o777)
        with pytest.raises(release_build.InstallerReleaseBuildError):
            release_build._ensure_owned_child_directory(
                parent_fd, "hermes-installer", 0o755,
                expected_uid=os.geteuid(), expected_gid=os.getegid())
        assert (parent / "hermes-installer").stat().st_mode & 0o777 == 0o777
    finally:
        os.close(parent_fd)


def test_builder_stages_all_ten_application_effect_members_from_exact_source_rows(tmp_path):
    repo = Path(__file__).parents[2]

    class Source:
        def __init__(self, tamper_digest: bool = False):
            rows = []
            for index, (_artifact_id, path, _role, digest, _size) in enumerate(
                    APPLICATION_EFFECT_SOURCE_MEMBERS):
                info = (repo / path).stat()
                rows.append(release_build.DistributionFile(
                    path, ("0" * 64 if tamper_digest and index == 0 else digest),
                    info.st_size, 0o600, info.st_dev, info.st_ino, info.st_ctime_ns))
            self.files = tuple(rows)

        def open_file(self, path):
            return os.open(repo / path, os.O_RDONLY)

    output = tmp_path / "builder-output"
    output.mkdir()
    output_fd = os.open(output, os.O_RDONLY | os.O_DIRECTORY)
    try:
        builder = object.__new__(release_build.RootInstalledReleaseBuilder)
        staged = []
        builder._stage_application_effect_sources(Source(), output_fd, staged, set())
        expected = set(APPLICATION_EFFECT_SOURCE_MEMBERS)
        actual = {(path, role[0], digest, size)
                  for path, digest, size, _mode, role in staged}
        self_expected = {(path, role, digest, size)
                         for _artifact_id, path, role, digest, size in expected}
        assert actual == self_expected
        assert all((output / path).read_bytes() == (repo / path).read_bytes()
                   and (output / path).stat().st_mode & 0o777 == 0o444
                   for _artifact_id, path, _role, _digest, _size in APPLICATION_EFFECT_SOURCE_MEMBERS)

        with pytest.raises(release_build.InstallerReleaseBuildError):
            builder._stage_application_effect_sources(Source(tamper_digest=True), output_fd, [], set())
    finally:
        os.close(output_fd)


@pytest.mark.skipif(os.geteuid() != 0, reason="foreign-owner custody requires root")
def test_initial_setup_prefixes_reject_foreign_owned_existing_directory(tmp_path):
    parent = tmp_path / "etc"
    parent.mkdir()
    child = parent / "hermes-installer"
    child.mkdir(mode=0o755)
    os.chown(child, 1, 1)
    parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with pytest.raises(release_build.InstallerReleaseBuildError):
            release_build._ensure_owned_child_directory(parent_fd, "hermes-installer", 0o755)
        assert child.stat().st_uid == 1
    finally:
        os.close(parent_fd)


def test_release_builder_pins_literal_model_store_template_and_native_source_modules():
    assert release_build.EXISTING_MODEL_STORE_TEMPLATE_ID == "installer-existing-model-store-root-template-v1"
    assert release_build.EXISTING_MODEL_STORE_TEMPLATE_PATH.endswith(
        "2026-10-10-existing-model-store-selection-source-v139/existing-model-store-root-template-v1.json")
    assert release_build.EXISTING_MODEL_STORE_TEMPLATE_SHA256 == (
        "3a145ddd21cf8ba524307844a1ab7fb78a4a066afad59bfbbb9164327c2f570f")
    assert release_build.EXISTING_MODEL_STORE_TEMPLATE_BYTES == 712
    targets = {name: target for name, _source, target, _digest, _size, _role
               in release_build.REVIEWED_SOURCE_MODULES}
    assert targets["hermes_installer.native_invocations"] == (
        "src/hermes_installer/native_invocations.py")
    assert targets["hermes_installer.native_boundary"] == (
        "src/hermes_installer/native_boundary.py")
    assert targets["hermes_installer.authority.native_source_definitions"] == (
        "lib/python/hermes_installer/authority/native_source_definitions.py")
    for _name, source_path, target_path, digest, size, _role in release_build.REVIEWED_SOURCE_MODULES:
        source = Path(__file__).parents[2] / source_path
        body = source.read_bytes()
        assert target_path.startswith(("src/hermes_installer/", "lib/python/hermes_installer/"))
        assert (hashlib.sha256(body).hexdigest(), len(body)) == (digest, size)


def test_private_loopback_policy_is_an_exact_installed_template_member():
    source_path = Path(__file__).parents[2] / release_build.PRIVATE_LOOPBACK_POLICY_TEMPLATE_PATH
    body = source_path.read_bytes()
    assert release_build.PRIVATE_LOOPBACK_POLICY_TEMPLATE_ID == "installer-private-loopback-nft-v1"
    assert release_build.STAGED_PRIVATE_LOOPBACK_POLICY_TEMPLATE_PATH == (
        "templates/private-loopback-policy-v1.json")
    assert (hashlib.sha256(body).hexdigest(), len(body)) == (
        release_build.PRIVATE_LOOPBACK_POLICY_TEMPLATE_SHA256,
        release_build.PRIVATE_LOOPBACK_POLICY_TEMPLATE_BYTES,
    )
    assert release_build.PRIVATE_LOOPBACK_POLICY_TEMPLATE_ID in release_build.ROOT_PLAN_TEMPLATE_ARTIFACT_IDS


def test_first_source_actor_preloads_exact_installed_launcher_module_closure():
    release_build._load_installed_setup_module_closure()
    for name in (
        "hermes_installer.root_setup",
        "hermes_installer.authority.installer_release",
        "hermes_installer.authority.bootstrap_runtime_factory",
        "hermes_installer.registry.resources_runtime",
    ):
        module = sys.modules[name]
        origin = Path(module.__spec__.origin)
        assert origin.is_file()
        assert origin == origin.resolve(strict=True)


def test_transitive_setup_module_actor_row_is_staged_as_installed_support(tmp_path):
    release_build._load_installed_setup_module_closure()
    module = sys.modules["hermes_installer.registry.resources_runtime"]
    origin = Path(module.__spec__.origin).resolve(strict=True)
    body = origin.read_bytes()
    digest = hashlib.sha256(body).hexdigest()
    source_root = tmp_path / "source"
    source_path = source_root / "src/hermes_installer/registry/resources_runtime.py"
    source_path.parent.mkdir(parents=True, mode=0o700)
    source_path.write_bytes(body)
    source_path.chmod(0o600)
    source_fd = os.open(source_root, os.O_RDONLY | os.O_DIRECTORY)
    file_fd = os.open(source_path, os.O_RDONLY)
    try:
        info = os.fstat(file_fd)
    finally:
        os.close(file_fd)
    source = release_build.VerifiedInstallerDistributionReceipt(
        release_build._SEAL,
        candidate_git_sha="a" * 40,
        git_tree_sha1="b" * 40,
        source_tree_sha256="c" * 64,
        baseline_tree_sha256="d" * 64,
        amendment_manifest_sha256="e" * 64,
        source_catalog_sha256="f" * 64,
        files=(release_build.DistributionFile(
            "src/hermes_installer/registry/resources_runtime.py", digest, len(body),
            0o600, info.st_dev, info.st_ino, info.st_ctime_ns),),
        root_fd=source_fd,
        expected_uid=os.geteuid(),
        handle="h" * 43,
    )
    output = tmp_path / "published"
    output.mkdir(mode=0o700)
    output_fd = os.open(output, os.O_RDONLY | os.O_DIRECTORY)
    builder = object.__new__(release_build.RootInstalledReleaseBuilder)
    try:
        staged = builder._stage_actor_module_rows(
            source, output_fd,
            (("hermes_installer.registry.resources_runtime", str(origin), digest,
              info.st_dev, info.st_ino),),
        )
        installed = output / "lib/python/hermes_installer/registry/resources_runtime.py"
        assert len(staged) == 1
        assert staged[0] == (
            "lib/python/hermes_installer/registry/resources_runtime.py", digest,
            len(body), 0o444, ("module",),
        )
        assert installed.read_bytes() == body
        from hermes_installer.authority.installer_release import _artifact_id_for
        assert _artifact_id_for(staged[0][0], ["module"]) == (
            "installer-module:hermes_installer.registry.resources_runtime")
    finally:
        os.close(output_fd)
        source.close()


def test_published_setup_support_closure_imports_without_checkout_fallback(tmp_path):
    repo = Path(__file__).parents[2]
    source_root = repo / "src"
    installed_python = tmp_path / "release/lib/python"
    installed_python.mkdir(parents=True)
    preload_and_stage = r"""
import importlib, pathlib, shutil, sys
source_root = pathlib.Path(sys.argv[1]).resolve(strict=True)
installed_root = pathlib.Path(sys.argv[2])
sys.path.insert(0, str(source_root))
from hermes_installer.authority.installer_release_build import _load_installed_setup_module_closure
_load_installed_setup_module_closure()
captured = set()
for name, module in tuple(sys.modules.items()):
    if name != 'hermes_installer' and not name.startswith('hermes_installer.'):
        continue
    origin = getattr(getattr(module, '__spec__', None), 'origin', None)
    if not isinstance(origin, str):
        continue
    path = pathlib.Path(origin).resolve(strict=True)
    try:
        relative = path.relative_to(source_root)
    except ValueError:
        continue
    target = installed_root / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(path, target)
    captured.add(name)
assert 'hermes_installer.registry.resources_runtime' in captured
"""
    subprocess.run(
        [sys.executable, "-I", "-c", preload_and_stage, str(source_root), str(installed_python)],
        cwd=tmp_path, check=True, capture_output=True, text=True,
    )
    verify_installed = r"""
import pathlib, sys
installed_root = pathlib.Path(sys.argv[1]).resolve(strict=True)
sys.path.insert(0, str(installed_root))
from hermes_installer.root_setup import (
    _import_v180_native_support_closure, _import_v187_listener_activation_closure,
)
_import_v180_native_support_closure()
_import_v187_listener_activation_closure()
from hermes_installer.registry import resources_runtime
origin = pathlib.Path(resources_runtime.__spec__.origin).resolve(strict=True)
assert origin.is_relative_to(installed_root)
for name, module in tuple(sys.modules.items()):
    if name != 'hermes_installer' and not name.startswith('hermes_installer.'):
        continue
    module_origin = getattr(getattr(module, '__spec__', None), 'origin', None)
    if isinstance(module_origin, str):
        assert pathlib.Path(module_origin).resolve(strict=True).is_relative_to(installed_root), name
"""
    subprocess.run(
        [sys.executable, "-I", "-c", verify_installed, str(installed_python)],
        cwd=tmp_path, check=True, capture_output=True, text=True,
    )


def test_release_builder_stages_only_the_exact_native_health_fixture_members():
    expected = {
        "src/hermes_installer/native_health_fixture/request.txt": (
            "fixtures/native-health/request.txt", "a8ff376fd03484db8c7dc0af141e8e894671467cdc5833ee50a08571d0ee3e7c", 182),
        "src/hermes_installer/native_health_fixture/seed-value.txt": (
            "fixtures/native-health/seed-value.txt", "b7cf82519f80550d09ae0ef0f183ad6be9543cc4c15873982cea91819e9a962a", 67),
        "src/hermes_installer/native_health_fixture/expected-tool-result.json": (
            "fixtures/native-health/expected-tool-result.json", "23a5b879d3b43b985c468917f34bdd7b592ab35cfd72e767287f16764436523a", 240),
        "src/hermes_installer/native_health_fixture/tool-result.schema.json": (
            "fixtures/native-health/tool-result.schema.json", "6b89864f728e6e3e65b34d935c486bad0bc3c0a57bcee92dde5eec33fb1286f5", 526),
        "src/hermes_installer/native_health_fixture/recipe.json": (
            "fixtures/native-health/recipe.json", "ba7486d3070f725d125ed0e8c42aa986969bc8a597c2473024705d6fd8ac05a7", 845),
    }
    assert {source: (target, digest, size)
            for source, target, digest, size in release_build.REVIEWED_HEALTH_FIXTURES} == expected
    for source, (_target, digest, size) in expected.items():
        body = (Path(__file__).parents[2] / source).read_bytes()
        assert (hashlib.sha256(body).hexdigest(), len(body)) == (digest, size)


def test_network_startup_helper_stager_is_exact_and_read_only(tmp_path, monkeypatch):
    repo = Path(__file__).parents[2]
    source_path = "helpers/private-loopback-worker-gate.py"
    body = (repo / source_path).read_bytes()
    source_root = tmp_path / "source"
    target = source_root / source_path
    target.parent.mkdir(parents=True)
    os.chmod(source_root, 0o700)
    target.write_bytes(body)
    os.chmod(target, 0o755)
    digest = hashlib.sha256(body).hexdigest()
    size = len(body)
    info = target.stat()
    source_fd = os.open(source_root, os.O_RDONLY | os.O_DIRECTORY)
    source = release_build.VerifiedInstallerDistributionReceipt(
        release_build._SEAL,
        candidate_git_sha="a" * 40,
        git_tree_sha1="b" * 40,
        source_tree_sha256="c" * 64,
        baseline_tree_sha256="d" * 64,
        amendment_manifest_sha256="e" * 64,
        source_catalog_sha256="f" * 64,
        files=(release_build.DistributionFile(
            source_path, digest, size, 0o755,
            info.st_dev, info.st_ino, info.st_ctime_ns),),
        root_fd=source_fd,
        expected_uid=os.geteuid(),
        handle="h" * 43,
    )

    output = tmp_path / "worker-helper-output"
    output.mkdir()
    output_fd = os.open(output, os.O_RDONLY | os.O_DIRECTORY)
    builder = object.__new__(release_build.RootInstalledReleaseBuilder)
    try:
        # Without the finalized source pin, the builder omits the helper; once
        # reviewed, the exact source row is staged under that approved tuple.
        production_pin = release_build.NETWORK_STARTUP_HELPER
        if production_pin[3] is None:
            assert production_pin[4] is None
            assert builder._stage_network_startup_helper(source, output_fd) is None
            assert not (output / source_path).exists()
        else:
            assert production_pin[3:5] == (digest, size)
            assert builder._stage_network_startup_helper(source, output_fd) == (
                source_path, digest, size, 0o444, ("network-startup-helper",))
            assert (output / source_path).read_bytes() == body
            (output / source_path).unlink()
        monkeypatch.setattr(release_build, "NETWORK_STARTUP_HELPER", (
            "installer-private-loopback-worker-gate-v180", source_path, source_path,
            digest, None, "network-startup-helper"))
        with pytest.raises(release_build.InstallerReleaseBuildError,
                           match="source policy is malformed"):
            builder._stage_network_startup_helper(source, output_fd)

        # A test-only fixed descriptor exercises the actual held-byte copy and
        # mode policy without changing or approving the production source pin.
        monkeypatch.setattr(release_build, "NETWORK_STARTUP_HELPER", (
            "installer-private-loopback-worker-gate-v180", source_path, source_path,
            digest, size, "network-startup-helper"))
        row = builder._stage_network_startup_helper(source, output_fd)
        assert row == (source_path, digest, size, 0o444, ("network-startup-helper",))
        assert (output / source_path).read_bytes() == body
        assert (output / source_path).stat().st_mode & 0o777 == 0o444

        monkeypatch.setattr(release_build, "NETWORK_STARTUP_HELPER", (
            "installer-private-loopback-worker-gate-v180", source_path, source_path,
            "0" * 64, size, "network-startup-helper"))
        with pytest.raises(release_build.InstallerReleaseBuildError,
                           match="source differs from its reviewed pin"):
            builder._stage_network_startup_helper(source, output_fd)

        monkeypatch.setattr(release_build, "NETWORK_STARTUP_HELPER", (
            "installer-private-loopback-worker-gate-v180", "helpers/unreviewed.py",
            "helpers/unreviewed.py", digest, size, "network-startup-helper"))
        with pytest.raises(release_build.InstallerReleaseBuildError, match="policy is malformed"):
            builder._stage_network_startup_helper(source, output_fd)
    finally:
        source.close()
        os.close(output_fd)


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
    result = tuple(release_build.RootInstallerDistributionRegistry._git_batch(repository, [blob] * 2048))
    assert len(result) == 2048
    assert all(item == body for item in result)


@pytest.mark.skipif(not Path("/usr/bin/git").exists(), reason="root source exporter requires system Git")
def test_source_export_replaces_git_checkout_with_exact_blob_tree(tmp_path):
    repository = tmp_path / "checkout"
    repository.mkdir()
    subprocess.run(["/usr/bin/git", "init", "-q", str(repository)], check=True)
    (repository / "module.py").write_bytes(b"candidate module\n")
    (repository / "nested").mkdir()
    (repository / "nested" / "data.json").write_bytes(b'{"schema":1}\n')
    subprocess.run(["/usr/bin/git", "-C", str(repository), "add", "."], check=True)
    subprocess.run(["/usr/bin/git", "-C", str(repository), "-c", "user.name=Fixture", "-c",
                    "user.email=fixture@example.invalid", "commit", "-qm", "fixture"], check=True)

    rows = release_build.RootInstallerDistributionRegistry._export_commit(repository, "HEAD")

    assert {path for path, _, _ in rows} == {"module.py", "nested/data.json"}
    assert not (repository / ".git").exists()
    assert (repository / "module.py").read_bytes() == b"candidate module\n"
    assert (repository / "nested" / "data.json").read_bytes() == b'{"schema":1}\n'
    assert not list(repository.parent.glob(".stage-source-*"))


@pytest.mark.skipif(os.name != "posix" or os.geteuid() != 0,
                    reason="fixed deployment-parent custody requires Linux root")
def test_owned_deployment_parent_children_are_created_or_conflicts_preserved(tmp_path):
    parent = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        app = release_build._ensure_owned_directory_child(parent, "hermes-installer")
        try:
            deployments = release_build._ensure_owned_directory_child(app, "deployments")
            try:
                assert os.stat("hermes-installer", dir_fd=parent, follow_symlinks=False).st_mode & 0o777 == 0o700
                assert os.stat("deployments", dir_fd=app, follow_symlinks=False).st_mode & 0o777 == 0o700
            finally:
                os.close(deployments)
        finally:
            os.close(app)
    finally:
        os.close(parent)

    conflict_parent = tmp_path / "conflict"
    conflict_parent.mkdir(mode=0o700)
    conflict = conflict_parent / "deployments"
    conflict.mkdir(mode=0o755)
    conflict_fd = os.open(conflict_parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        with pytest.raises(release_build.InstallerReleaseBuildError):
            release_build._ensure_owned_directory_child(conflict_fd, "deployments")
        assert os.stat(conflict, follow_symlinks=False).st_mode & 0o777 == 0o755
    finally:
        os.close(conflict_fd)


def test_build_receipt_is_single_use_and_detects_output_mutation(tmp_path, monkeypatch):
    output = tmp_path / "output"
    output.mkdir(mode=0o700)
    body = b"release module\n"
    (output / "module.py").write_bytes(body)
    os.chmod(output / "module.py", 0o444)
    info = os.stat(output / "module.py", follow_symlinks=False)
    row = release_build.BuildOutputFile("module.py", hashlib.sha256(body).hexdigest(), len(body), 0o444,
                                        ("module",), info.st_dev, info.st_ino)
    sibling_body = b"sealed sibling\n"
    (output / "sibling.py").write_bytes(sibling_body)
    os.chmod(output / "sibling.py", 0o444)
    sibling_info = os.stat(output / "sibling.py", follow_symlinks=False)
    sibling = release_build.BuildOutputFile(
        "sibling.py", hashlib.sha256(sibling_body).hexdigest(), len(sibling_body), 0o444,
        ("module",), sibling_info.st_dev, sibling_info.st_ino)
    rows = (row, sibling)
    manifest = release_build._canonical_json({
        "schema": 1, "candidate_git_sha": "a" * 40,
        "files": [{"relative_path": item.relative_path, "sha256": item.sha256,
                   "size_bytes": item.size_bytes, "mode": item.mode, "roles": list(item.roles)}
                  for item in rows],
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
        files=rows, manifest_sha256=hashlib.sha256(manifest).hexdigest(), root_fd=root_fd,
        expected_uid=os.geteuid())
    try:
        receipt.verify_current()
        hashed_bytes = 0
        original_hash_fd = release_build._hash_fd

        def count_hash_bytes(fd, maximum):
            nonlocal hashed_bytes
            digest, size = original_hash_fd(fd, maximum)
            hashed_bytes += size
            return digest, size

        monkeypatch.setattr(release_build, "_hash_fd", count_hash_bytes)
        opened = receipt.open_file("module.py")
        try:
            assert os.read(opened, len(body)) == body
        finally:
            os.close(opened)
        # Copy-time validation hashes only the requested member. A whole closure
        # hash here would reread every sibling for each of the 938 publication
        # opens and make the bounded transaction quadratic.
        assert hashed_bytes == len(body)
        receipt.consume()
        with pytest.raises(release_build.BootstrapEnrollmentPending):
            receipt.verify_current()
    finally:
        receipt.close()


def test_build_receipt_rejects_expiry_during_copy_and_unsealed_extra_file(tmp_path, monkeypatch):
    output = tmp_path / "output"
    output.mkdir(mode=0o700)
    body = b"sealed bytes\n"
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
    issued = time.monotonic()
    receipt = release_build.VerifiedInstallerReleaseBuildReceipt(
        release_build._SEAL, handle="r" * 43, candidate_git_sha="a" * 40,
        distribution_receipt_handle="d" * 43, interpreter_receipt_handle="i" * 43,
        source_tree_sha256="c" * 64, baseline_tree_sha256="b" * 64,
        amendment_manifest_sha256="e" * 64, source_catalog_sha256="f" * 64,
        role_closure_manifest_sha256=hashlib.sha256(manifest).hexdigest(),
        root_setup_plan_sha256="0" * 64, builder_artifact_sha256="1" * 64,
        issued_monotonic=issued,
        deployment_predecessor=release_build.DeploymentPredecessor("absent", info.st_dev, info.st_ino),
        files=(row,), manifest_sha256=hashlib.sha256(manifest).hexdigest(), root_fd=root_fd,
        expected_uid=os.geteuid())
    try:
        monkeypatch.setattr(release_build.time, "monotonic", lambda: receipt.expires_monotonic)
        with pytest.raises(release_build.BootstrapEnrollmentPending):
            receipt.open_file("module.py")
        monkeypatch.undo()
        (output / "extra.py").write_bytes(b"unsealed")
        with pytest.raises(release_build.InstallerReleaseBuildError):
            receipt.verify_current()
    finally:
        receipt.close()


def test_builder_assigns_one_interpreter_and_finite_runtime_member_roles():
    assert release_build._runtime_output_roles("runtime/bin/python") == ("interpreter",)
    assert release_build._runtime_output_roles("runtime/bin/python3") == ("runtime-member",)
    assert release_build._runtime_output_roles("runtime/lib/python3.14/os.py") == ("runtime-member",)
    with pytest.raises(release_build.InstallerReleaseBuildError):
        release_build._runtime_output_roles("source/runtime/bin/python")


def test_build_receipt_checks_copied_member_and_final_closure(tmp_path):
    output = tmp_path / "output"
    output.mkdir(mode=0o700)
    body = b"sealed bytes\n"
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
        (output / "extra.py").write_bytes(b"unsealed")
        with pytest.raises(release_build.InstallerReleaseBuildError):
            receipt.verify_current()
        (output / "extra.py").unlink()
        os.chmod(output / "module.py", 0o644)
        (output / "module.py").write_bytes(b"tampered bytes\n")
        with pytest.raises(release_build.InstallerReleaseBuildError):
            receipt.open_file("module.py")
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


def test_hash_then_read_rewinds_a_consumed_descriptor(tmp_path):
    body = b"sealed interpreter bytes" * 37
    path = tmp_path / "interpreter"
    path.write_bytes(body)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        digest, size, copied = release_build._hash_and_read_fd(fd, len(body))
        assert copied == body
        assert size == len(body)
        assert digest == hashlib.sha256(body).hexdigest()
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
    lock_bytes = lock.read_bytes()
    parsed = release_build._locked_package_versions(lock_bytes)
    assert parsed["pyyaml"] == frozenset({"6.0.3"})
    # Hash-locked requirements intentionally do not name a platform wheel;
    # the provisioner selects the reviewed wheel by its exact digest.
    assert release_build._lock_contains_exact_pyyaml(lock_bytes)
    without_reviewed_wheel = lock_bytes.replace(
        f"    --hash=sha256:{release_build.BOOTSTRAP_PYYAML_SHA256} \\\n".encode(), b"")
    assert not release_build._lock_contains_exact_pyyaml(without_reviewed_wheel)
    with pytest.raises(release_build.InstallerReleaseBuildError):
        release_build._locked_package_versions(b"PyYAML==6.0.3\n")


def test_runtime_site_search_paths_deduplicate_purelib_and_platlib(monkeypatch, tmp_path):
    monkeypatch.setattr(release_build.sysconfig, "get_path", lambda _key: str(tmp_path))
    assert release_build._runtime_site_search_paths() == [str(tmp_path.resolve())]


def test_only_absent_fixed_optional_stdlib_zip_is_ignored(tmp_path):
    runtime = tmp_path / "runtime"
    library = runtime / "lib"
    library.mkdir(parents=True)
    optional_zip = library / f"python{sys.version_info.major}{sys.version_info.minor}.zip"

    assert release_build._is_absent_optional_stdlib_zip(optional_zip, runtime, set())
    assert not release_build._is_absent_optional_stdlib_zip(optional_zip, runtime, {
        optional_zip.relative_to(runtime).as_posix(),
    })
    assert not release_build._is_absent_optional_stdlib_zip(library / "python999.zip", runtime, set())
    assert not release_build._is_absent_optional_stdlib_zip(runtime / "missing.zip", runtime, set())

    optional_zip.symlink_to(library / "missing-target.zip")
    assert not release_build._is_absent_optional_stdlib_zip(optional_zip, runtime, set())
    optional_zip.unlink()
    optional_zip.write_bytes(b"unrecorded archive")
    assert not release_build._is_absent_optional_stdlib_zip(optional_zip, runtime, set())


def test_bundled_pip_is_bound_to_fixed_cpython_site_directory(tmp_path):
    relative_files = (
        Path("pip/__init__.py"),
        Path("pip-26.2.1.dist-info/METADATA"),
        Path("../../../bin/pip"),
        Path("../../../bin/pip3"),
        Path("../../../bin/pip3.14"),
    )
    for relative in relative_files:
        target = tmp_path / "lib/python3.14/site-packages" / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("pinned runtime archive member", encoding="utf-8")

    class Distribution:
        files = relative_files
        version = "26.2.1"

        def locate_file(self, item):
            return tmp_path / "lib/python3.14/site-packages" / item

    release_build._verify_bundled_pip_distribution(Distribution(), tmp_path)

    class EscapingDistribution:
        files = (Path("../../../bin/pipx"),)
        version = "26.2.1"

        def locate_file(self, item):
            target = tmp_path / "lib/python3.14/site-packages" / item
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("unexpected package", encoding="utf-8")
            return target

    with pytest.raises(release_build.InstallerReleaseBuildError, match="escaped its fixed CPython site directory"):
        release_build._verify_bundled_pip_distribution(EscapingDistribution(), tmp_path)


def test_selected_installer_python_requirement_is_parsed_from_toml():
    release_build._require_python_requirement(b'[project]\nrequires-python = ">=3.11"\n')
    with pytest.raises(release_build.InstallerReleaseBuildError, match="valid installer Python requirement"):
        release_build._require_python_requirement(b'[project\nrequires-python = ">=3.11"\n')


def _runtime_archive(entries):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        for name, kind, value in entries:
            member = tarfile.TarInfo(name)
            if kind == "file":
                body = value
                member.type = tarfile.REGTYPE
                member.mode = 0o755
                member.size = len(body)
                archive.addfile(member, io.BytesIO(body))
            else:
                member.type = tarfile.SYMTYPE
                member.mode = 0o777
                member.linkname = value
                archive.addfile(member)
    return output.getvalue()


def _extract_fixture_runtime(monkeypatch, archive_bytes, destination):
    monkeypatch.setattr(release_build, "BOOTSTRAP_RUNTIME_ARCHIVE_BYTES", len(archive_bytes))
    monkeypatch.setattr(release_build, "BOOTSTRAP_RUNTIME_ARCHIVE_SHA256",
                        hashlib.sha256(archive_bytes).hexdigest())
    monkeypatch.setattr(release_build, "BOOTSTRAP_RUNTIME_MAX_EXPANDED", 1024 * 1024)
    release_build._extract_verified_runtime_archive(archive_bytes, destination)


def test_runtime_archive_accepts_normalized_internal_parent_symlink(monkeypatch, tmp_path):
    archive = _runtime_archive([
        ("python/lib/target", "file", b"runtime member"),
        ("python/lib/alias", "symlink", "../lib/target"),
    ])
    destination = tmp_path / "python"
    destination.mkdir()
    _extract_fixture_runtime(monkeypatch, archive, destination)
    assert (destination / "lib/target").read_bytes() == b"runtime member"
    assert (destination / "lib/alias").is_symlink()
    assert (destination / "lib/alias").resolve() == (destination / "lib/target")


@pytest.mark.parametrize("target", [
    "../../outside", "/usr/bin/python", ".././target", "../target//file", "..\\outside",
])
def test_runtime_archive_rejects_escaping_or_nonportable_symlink_targets(monkeypatch, tmp_path, target):
    archive = _runtime_archive([("python/lib/escape", "symlink", target)])
    destination = tmp_path / "python"
    destination.mkdir()
    with pytest.raises(release_build.InstallerReleaseBuildError):
        _extract_fixture_runtime(monkeypatch, archive, destination)


def test_runtime_archive_rejects_cyclic_symlink(monkeypatch, tmp_path):
    archive = _runtime_archive([("python/lib/cycle", "symlink", "cycle")])
    destination = tmp_path / "python"
    destination.mkdir()
    with pytest.raises(release_build.InstallerReleaseBuildError, match="broken or cyclic"):
        _extract_fixture_runtime(monkeypatch, archive, destination)


@pytest.mark.skipif(os.name != "posix" or os.geteuid() != 0,
                    reason="runtime closure requires root-owned sealed directories")
def test_runtime_closure_rows_allow_only_contained_parent_relative_symlinks(tmp_path):
    root = tmp_path / "python"
    (root / "bin").mkdir(parents=True)
    root.chmod(0o555)
    (root / "bin").chmod(0o555)
    os.symlink("../lib/target", root / "bin/alias")
    rows = release_build._runtime_archive_rows(root)
    assert rows == [("bin/alias", hashlib.sha256(b"../lib/target").hexdigest(),
                     len(b"../lib/target"), 0o777, "../lib/target")]

    (root / "bin/alias").unlink()
    os.symlink("../../outside", root / "bin/alias")
    with pytest.raises(release_build.InstallerReleaseBuildError, match="escapes its fixed prefix"):
        release_build._runtime_archive_rows(root)


def test_runtime_closure_modes_match_the_sealed_tree_modes():
    assert release_build._sealed_runtime_mode(0o755) == 0o555
    assert release_build._sealed_runtime_mode(0o644) == 0o444
    assert release_build._sealed_runtime_mode(0o700) == 0o555
    assert release_build._sealed_runtime_mode(0o600) == 0o444


@pytest.mark.skipif(os.name != "posix" or os.geteuid() != 0,
                    reason="runtime mode currentness requires a root-owned Linux tree")
def test_root_runtime_tree_seals_before_closure_and_rejects_writable_mode(tmp_path):
    root = tmp_path / "runtime"
    root.mkdir(mode=0o700)
    executable = root / "bin/python3.14"
    data = root / "lib/config.dat"
    executable.parent.mkdir()
    data.parent.mkdir()
    executable.write_bytes(b"interpreter")
    data.write_bytes(b"runtime data")
    executable.chmod(0o755)
    data.chmod(0o644)

    release_build._seal_runtime_tree(root)
    assert executable.stat().st_mode & 0o777 == 0o555
    assert data.stat().st_mode & 0o777 == 0o444
    closure = release_build._runtime_closure_digest(root)
    release_build._verify_runtime_materialization(root, closure)

    data.parent.chmod(0o777)
    with pytest.raises(release_build.InstallerReleaseBuildError, match="directory mode is not read-only sealed"):
        release_build._verify_runtime_materialization(root, closure)
    data.parent.chmod(0o555)

    executable.chmod(0o666)
    with pytest.raises(release_build.InstallerReleaseBuildError, match="not read-only sealed"):
        release_build._verify_runtime_materialization(root, closure)
    executable.chmod(0o555)

    root.chmod(0o777)
    with pytest.raises(release_build.InstallerReleaseBuildError, match="directory mode is not read-only sealed"):
        release_build._verify_runtime_materialization(root, closure)


def test_wheel_record_rejects_digest_and_unlisted_member_changes():
    import base64

    body = b"package bytes"
    record = "yaml/__init__.py,sha256={},{}\n".format(
        base64.urlsafe_b64encode(hashlib.sha256(body).digest()).decode().rstrip("="), len(body))
    record += "pyyaml-6.0.3.dist-info/RECORD,,\n"
    rows = {"yaml/__init__.py": body, "pyyaml-6.0.3.dist-info/RECORD": record.encode()}
    release_build._verify_wheel_record(rows, "pyyaml-6.0.3.dist-info/RECORD")

    rows["yaml/__init__.py"] = b"changed"
    with pytest.raises(release_build.InstallerReleaseBuildError):
        release_build._verify_wheel_record(rows, "pyyaml-6.0.3.dist-info/RECORD")
    rows["yaml/__init__.py"] = body
    rows["yaml/unlisted.py"] = b"extra"
    with pytest.raises(release_build.InstallerReleaseBuildError):
        release_build._verify_wheel_record(rows, "pyyaml-6.0.3.dist-info/RECORD")


def _fixture_pyyaml_wheel(files, *, symlink_member=None):
    import base64
    import csv
    import io
    import stat
    import zipfile

    members = dict(files)
    record_name = "pyyaml-6.0.3.dist-info/RECORD"
    output = io.BytesIO()
    rows = []
    for name, body in members.items():
        rows.append((name, "sha256=" + base64.urlsafe_b64encode(
            hashlib.sha256(body).digest()).decode().rstrip("="), str(len(body))))
    rows.append((record_name, "", ""))
    record = io.StringIO(newline="")
    csv.writer(record, lineterminator="\n").writerows(rows)
    members[record_name] = record.getvalue().encode()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, body in members.items():
            info = zipfile.ZipInfo(name)
            info.external_attr = ((stat.S_IFLNK | 0o777) if name == symlink_member
                                  else (stat.S_IFREG | 0o644)) << 16
            archive.writestr(info, body)
    return output.getvalue()


def test_materialize_pinned_wheel_accepts_only_the_closed_pyyaml_package_set(monkeypatch, tmp_path):
    import zipfile

    files = {
        "_yaml/__init__.py": b"# native extension package\n",
        "yaml/__init__.py": b"__version__ = '6.0.3'\n",
        "yaml/_yaml.cpython-314-aarch64-linux-gnu.so": b"fixture extension bytes",
        "pyyaml-6.0.3.dist-info/WHEEL": (
            b"Wheel-Version: 1.0\nTag: cp314-cp314-manylinux_2_28_aarch64\n"),
        "pyyaml-6.0.3.dist-info/METADATA": b"Name: PyYAML\nVersion: 6.0.3\n",
    }
    wheel = _fixture_pyyaml_wheel(files)
    monkeypatch.setattr(release_build, "BOOTSTRAP_PYYAML_SHA256", hashlib.sha256(wheel).hexdigest())
    monkeypatch.setattr(release_build, "BOOTSTRAP_PYYAML_BYTES", len(wheel))
    target = tmp_path / "site-packages"
    target.mkdir()
    release_build._materialize_pyyaml_wheel(wheel, target)
    assert (target / "_yaml/__init__.py").read_bytes() == files["_yaml/__init__.py"]
    assert (target / "yaml/_yaml.cpython-314-aarch64-linux-gnu.so").read_bytes() == files[
        "yaml/_yaml.cpython-314-aarch64-linux-gnu.so"]

    malicious = _fixture_pyyaml_wheel({**files, "unreviewed/__init__.py": b"no"})
    monkeypatch.setattr(release_build, "BOOTSTRAP_PYYAML_SHA256", hashlib.sha256(malicious).hexdigest())
    monkeypatch.setattr(release_build, "BOOTSTRAP_PYYAML_BYTES", len(malicious))
    with pytest.raises(release_build.InstallerReleaseBuildError, match="unreviewed package path"):
        release_build._materialize_pyyaml_wheel(malicious, tmp_path / "other")

    linked = _fixture_pyyaml_wheel(files, symlink_member="_yaml/__init__.py")
    monkeypatch.setattr(release_build, "BOOTSTRAP_PYYAML_SHA256", hashlib.sha256(linked).hexdigest())
    monkeypatch.setattr(release_build, "BOOTSTRAP_PYYAML_BYTES", len(linked))
    with pytest.raises(release_build.InstallerReleaseBuildError, match="link or special"):
        release_build._materialize_pyyaml_wheel(linked, tmp_path / "linked")

    for escaped_name in ("_yaml/../evil.py", "../evil.py", "/yaml/evil.py", "yaml\\evil.py"):
        escaped = _fixture_pyyaml_wheel({**files, escaped_name: b"escape"})
        monkeypatch.setattr(release_build, "BOOTSTRAP_PYYAML_SHA256", hashlib.sha256(escaped).hexdigest())
        monkeypatch.setattr(release_build, "BOOTSTRAP_PYYAML_BYTES", len(escaped))
        with pytest.raises(release_build.InstallerReleaseBuildError):
            release_build._materialize_pyyaml_wheel(escaped, tmp_path / ("escape-" + str(len(escaped_name))))

    malformed = b"not a zip archive"
    monkeypatch.setattr(release_build, "BOOTSTRAP_PYYAML_SHA256", hashlib.sha256(malformed).hexdigest())
    monkeypatch.setattr(release_build, "BOOTSTRAP_PYYAML_BYTES", len(malformed))
    with pytest.raises(zipfile.BadZipFile):
        release_build._materialize_pyyaml_wheel(malformed, tmp_path / "malformed")


def test_pinned_download_rejects_unreviewed_digest_without_network(monkeypatch):
    monkeypatch.setattr(release_build, "BOOTSTRAP_PYYAML_URL", "https://files.pythonhosted.org/test.whl")
    payload = b"fixture payload"

    class Response:
        status = 200
        headers = type("Headers", (), {"get_all": lambda self, name, default=None: [str(len(payload))]})()

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


def test_runtime_download_follows_only_one_exact_public_asset_redirect(monkeypatch):
    payload = b"pinned runtime bytes"
    digest = hashlib.sha256(payload).hexdigest()
    url = release_build.BOOTSTRAP_RUNTIME_ARCHIVE_URL
    location = "https://release-assets.githubusercontent.com/release/asset?sig=fixture-secret"
    monkeypatch.setattr(release_build, "BOOTSTRAP_RUNTIME_ARCHIVE_SHA256", digest)
    monkeypatch.setattr(release_build, "BOOTSTRAP_RUNTIME_ARCHIVE_BYTES", len(payload))
    monkeypatch.setattr(release_build, "BOOTSTRAP_RUNTIME_MAX_DOWNLOAD", len(payload))
    requests = []

    class Response:
        status = 200
        headers = type("Headers", (), {"get_all": lambda self, name, default=None: [str(len(payload))]})()

        def __init__(self):
            self.offset = 0
            self.closed = False

        def geturl(self):
            return location

        def read(self, count=-1):
            if count < 0:
                count = len(payload)
            result = payload[self.offset:self.offset + count]
            self.offset += len(result)
            return result

        def close(self):
            self.closed = True

    response = Response()

    class Opener:
        def open(self, request, timeout):
            requests.append(request)
            assert timeout == 30
            if len(requests) == 1:
                from email.message import Message
                headers = Message()
                headers["Location"] = location
                raise release_build.urllib.error.HTTPError(
                    url, 302, "Found", headers, io.BytesIO())
            return response

    monkeypatch.setattr(release_build.urllib.request, "build_opener",
                        lambda *handlers: Opener())
    assert release_build._download_pinned(
        url, digest, len(payload), len(payload)) == payload
    assert len(requests) == 2
    assert requests[0].full_url == url
    assert requests[1].full_url == location
    for request in requests:
        assert request.get_header("Authorization") is None
        assert request.get_header("Cookie") is None
        assert request.get_header("Proxy-authorization") is None
        assert request.get_header("Referer") is None
    assert response.closed


@pytest.mark.parametrize("location", [
    None,
    "https://release-assets.githubusercontent.com.evil.invalid/file?sig=x",
    "https://release-assets.githubusercontent.com./file?sig=x",
    "https://user@release-assets.githubusercontent.com/file?sig=x",
    "http://release-assets.githubusercontent.com/file?sig=x",
    "https://release-assets.githubusercontent.com:444/file?sig=x",
    "https://release-assets.githubusercontent.com/file#fragment",
    "https://reléase-assets.githubusercontent.com/file?sig=x",
    "//release-assets.githubusercontent.com/file?sig=x",
    "https://release-assets.githubusercontent.com/" + "x" * 8200,
])
def test_runtime_redirect_rejects_unreviewed_locations(location):
    with pytest.raises(release_build.InstallerReleaseBuildError):
        release_build._validate_runtime_asset_redirect(location)


def test_runtime_download_rejects_a_second_redirect_and_hash_mismatch(monkeypatch):
    payload = b"wrong bytes"
    digest = hashlib.sha256(b"expected bytes").hexdigest()
    url = release_build.BOOTSTRAP_RUNTIME_ARCHIVE_URL
    location = "https://release-assets.githubusercontent.com/release/asset?sig=fixture-secret"
    monkeypatch.setattr(release_build, "BOOTSTRAP_RUNTIME_ARCHIVE_SHA256", digest)
    monkeypatch.setattr(release_build, "BOOTSTRAP_RUNTIME_ARCHIVE_BYTES", len(payload))
    monkeypatch.setattr(release_build, "BOOTSTRAP_RUNTIME_MAX_DOWNLOAD", len(payload))

    class Opener:
        def open(self, request, timeout):
            from email.message import Message
            headers = Message()
            headers["Location"] = location
            raise release_build.urllib.error.HTTPError(
                request.full_url, 302, "Found", headers, io.BytesIO())

    monkeypatch.setattr(release_build.urllib.request, "build_opener",
                        lambda *handlers: Opener())
    with pytest.raises(release_build.InstallerReleaseBuildError):
        release_build._download_pinned(url, digest, len(payload), len(payload))

    class OneRedirectThenWrongBody:
        calls = 0

        def open(self, request, timeout):
            from email.message import Message
            self.calls += 1
            if self.calls == 1:
                headers = Message()
                headers["Location"] = location
                raise release_build.urllib.error.HTTPError(
                    request.full_url, 302, "Found", headers, io.BytesIO())

            class Response:
                status = 200
                headers = type("Headers", (), {"get_all": lambda self, name, default=None: [str(len(payload))]})()

                def __init__(self):
                    self.offset = 0

                def geturl(self):
                    return location

                def read(self, count=-1):
                    if count < 0:
                        count = len(payload)
                    result = payload[self.offset:self.offset + count]
                    self.offset += len(result)
                    return result

                def close(self):
                    return None

            return Response()

    monkeypatch.setattr(release_build.urllib.request, "build_opener",
                        lambda *handlers: OneRedirectThenWrongBody())
    with pytest.raises(release_build.InstallerReleaseBuildError, match="bytes do not match"):
        release_build._download_pinned(url, digest, len(payload), len(payload))


def test_pyyaml_download_keeps_no_redirect_policy(monkeypatch):
    calls = []

    class Opener:
        def open(self, request, timeout):
            calls.append(request.full_url)
            from email.message import Message
            headers = Message()
            headers["Location"] = "https://release-assets.githubusercontent.com/unreviewed"
            raise release_build.urllib.error.HTTPError(
                request.full_url, 302, "Found", headers, io.BytesIO())

    monkeypatch.setattr(release_build.urllib.request, "build_opener",
                        lambda *handlers: Opener())
    with pytest.raises(release_build.InstallerReleaseBuildError):
        release_build._download_pinned(
            release_build.BOOTSTRAP_PYYAML_URL,
            release_build.BOOTSTRAP_PYYAML_SHA256,
            release_build.BOOTSTRAP_PYYAML_BYTES,
            1_048_576,
        )
    assert calls == [release_build.BOOTSTRAP_PYYAML_URL]


def test_declared_content_length_is_optional_but_must_be_unambiguous_and_exact():
    from email.message import Message

    headers = Message()
    assert release_build._declared_content_length(headers, 12) is None
    headers["Content-Length"] = "12"
    assert release_build._declared_content_length(headers, 12) is True
    headers["Content-Length"] = "13"
    assert release_build._declared_content_length(headers, 12) is False
    headers = Message()
    headers["Content-Length"] = "12"
    headers["Content-Length"] = "12"
    assert release_build._declared_content_length(headers, 12) is False
    headers = Message()
    headers["Content-Length"] = "12, 12"
    assert release_build._declared_content_length(headers, 12) is False


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


def test_bootstrap_handoff_uses_linux_uapi_when_python_omits_seal_names(monkeypatch):
    if not hasattr(os, "memfd_create") or not sys.platform.startswith("linux"):
        pytest.skip("Linux sealed memfd is required")
    for name in ("F_ADD_SEALS", "F_GET_SEALS", "F_SEAL_SEAL", "F_SEAL_SHRINK",
                 "F_SEAL_GROW", "F_SEAL_WRITE"):
        monkeypatch.delattr(release_build.fcntl, name, raising=False)
    descriptor = os.memfd_create("handoff-uapi-test", os.MFD_ALLOW_SEALING)
    try:
        body = release_build._canonical_json({
            "schema": 1, "handoff_handle": "h" * 43, "nonce": "n" * 43,
        })
        os.write(descriptor, body)
        constants = release_build._memfd_seal_constants()
        required = (constants["F_SEAL_WRITE"] | constants["F_SEAL_GROW"]
                    | constants["F_SEAL_SHRINK"] | constants["F_SEAL_SEAL"])
        release_build.fcntl.fcntl(descriptor, constants["F_ADD_SEALS"], required)
        parsed, info, observed = release_build._decode_sealed_handoff_descriptor(descriptor)
        assert observed == body and info.st_size == len(body)
        assert parsed["handoff_handle"] == "h" * 43
        assert release_build.fcntl.fcntl(descriptor, constants["F_GET_SEALS"]) & required == required
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
    argv = release_build._fixed_reexec_argv(Path("/fixed/runtime/python"))
    compile(source, "<fixed-reexec-entry>", "exec")
    assert argv[:5] == ["/fixed/runtime/python", "-B", "-I", "-S", "-c"]
    assert argv[5] == source
    assert "os.read(3, 4097)" in source
    assert "F_GET_SEALS" in source and "O_NOFOLLOW" in source
    assert "sys.argv" not in source and "os.environ" not in source
    assert "candidate_git_sha" not in source.split("transport =", 1)[0]


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="FD_CLOEXEC exec semantics require Linux")
def test_bootstrap_fd3_survives_exec_and_same_fd_cloexec_is_repaired():
    if not hasattr(os, "memfd_create"):
        pytest.skip("sealed memfd is a Linux kernel facility")
    def exercise(source_is_fd3: bool) -> None:
        # Run each descriptor layout in an isolated fork so pytest capture and
        # the parent process never lose or replace their own descriptor 3.
        child = os.fork()
        if child == 0:
            saved_fd3 = None
            original_fd3_inheritable = False
            memfd = -1
            try:
                try:
                    original_fd3_inheritable = os.get_inheritable(3)
                    saved_fd3 = os.dup(3)
                except OSError:
                    saved_fd3 = None
                if source_is_fd3:
                    try:
                        os.close(3)
                    except OSError:
                        pass
                elif saved_fd3 is None:
                    assert os.open(os.devnull, os.O_RDONLY) == 3

                memfd = os.memfd_create("handoff-exec-test", os.MFD_ALLOW_SEALING | os.MFD_CLOEXEC)
                assert (memfd == 3) is source_is_fd3
                body = release_build._canonical_json({
                    "schema": 1, "handoff_handle": "h" * 43, "nonce": "n" * 43,
                })
                os.write(memfd, body)
                seals = (release_build.fcntl.F_SEAL_WRITE | release_build.fcntl.F_SEAL_GROW
                         | release_build.fcntl.F_SEAL_SHRINK | release_build.fcntl.F_SEAL_SEAL)
                release_build.fcntl.fcntl(memfd, release_build.fcntl.F_ADD_SEALS, seals)

                if source_is_fd3:
                    # Demonstrate the kernel identity-dup case leaves CLOEXEC set.
                    os.dup2(memfd, 3, inheritable=True)
                    assert release_build.fcntl.fcntl(3, release_build.fcntl.F_GETFD) & release_build.fcntl.FD_CLOEXEC
                release_build._install_bootstrap_transition_fd3(memfd)
                assert not release_build.fcntl.fcntl(3, release_build.fcntl.F_GETFD) & release_build.fcntl.FD_CLOEXEC

                code = ("import fcntl,os,sys; "
                        "assert fcntl.fcntl(3,fcntl.F_GET_SEALS) & 15 == 15; "
                        "assert os.read(3,4097) == " + repr(body) + "; sys.exit(0)")
                pid = os.fork()
                if pid == 0:
                    try:
                        os.execve(sys.executable, [sys.executable, "-I", "-S", "-c", code],
                                  {"PATH": "/usr/bin:/bin"})
                    except BaseException:
                        os._exit(120)
                _, status = os.waitpid(pid, 0)
                assert os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0

                # The negative exec control must fail specifically because FD 3
                # was closed at exec, rather than because the child failed to start.
                os.set_inheritable(3, False)
                missing_fd_code = (
                    "import errno,os,sys; "
                    "exec(\"try: os.fstat(3)\\nexcept OSError as e: "
                    "sys.exit(5 if e.errno == errno.EBADF else 6)\\nsys.exit(0)\")")
                pid = os.fork()
                if pid == 0:
                    try:
                        os.execve(sys.executable, [sys.executable, "-I", "-S", "-c", missing_fd_code],
                                  {"PATH": "/usr/bin:/bin"})
                    except BaseException:
                        os._exit(120)
                _, status = os.waitpid(pid, 0)
                assert os.WIFEXITED(status) and os.WEXITSTATUS(status) == 5
            except BaseException:
                os._exit(1)
            finally:
                if memfd > 3:
                    try:
                        os.close(memfd)
                    except OSError:
                        pass
                try:
                    os.close(3)
                except OSError:
                    pass
                if saved_fd3 is not None:
                    os.dup2(saved_fd3, 3, inheritable=original_fd3_inheritable)
                    os.close(saved_fd3)
                os._exit(0)

        _, status = os.waitpid(child, 0)
        assert os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0

    exercise(source_is_fd3=True)
    exercise(source_is_fd3=False)


def test_release_build_cas_reservation_uses_selected_input_bounds_and_retains_headroom(tmp_path):
    executable = tmp_path / "python"
    executable.write_bytes(b"python-runtime-executable")
    source = SimpleNamespace(files=(SimpleNamespace(size_bytes=101), SimpleNamespace(size_bytes=203)))
    interpreter = SimpleNamespace(
        files=(SimpleNamespace(size_bytes=307), SimpleNamespace(size_bytes=409)),
        open_executable=lambda: os.open(executable, os.O_RDONLY),
    )
    plan_bytes = b"rendered plan"
    reservation = release_build._release_build_output_reservation(source, interpreter, plan_bytes)
    expected = (2 * (101 + 203) + 307 + 409 + len(b"python-runtime-executable") + len(plan_bytes)
                + release_build.MAX_RELEASE_BUILD_MANIFEST_BYTES)
    assert reservation == expected

    retained_pi_output_bytes = 606_706_296
    release_build._require_release_build_cas_capacity(retained_pi_output_bytes, reservation)
    release_build._require_release_build_cas_capacity(
        release_build.MAX_RELEASE_BUILD_CAS_BYTES - reservation, reservation)
    with pytest.raises(release_build.BootstrapEnrollmentPending, match="bounded capacity"):
        release_build._require_release_build_cas_capacity(
            release_build.MAX_RELEASE_BUILD_CAS_BYTES - reservation + 1, reservation)
    with pytest.raises(release_build.BootstrapEnrollmentPending, match="bounded capacity"):
        release_build._require_release_build_cas_capacity(0, release_build.MAX_RELEASE_BUILD_CAS_BYTES + 1)


@pytest.fixture
def _root_owned_tmp_path():
    root = Path(tempfile.mkdtemp(prefix="hermes-release-builder-receipt-", dir="/root"))
    try:
        yield root
    finally:
        shutil.rmtree(root)


@pytest.mark.skipif(not sys.platform.startswith("linux") or os.geteuid() != 0,
                    reason="release builder output custody requires root-owned Linux fixtures")
def test_build_selected_mints_receipt_bound_to_resolved_source_and_interpreter(_root_owned_tmp_path, monkeypatch):
    cas = _root_owned_tmp_path / "release-build-cas"
    cas.mkdir(mode=0o700)
    os.chmod(cas, 0o700)
    runtime = _root_owned_tmp_path / "python"
    runtime.write_bytes(b"selected isolated interpreter")
    runtime.chmod(0o555)
    distribution_handle = "d" * 43
    interpreter_handle = "i" * 43
    candidate_sha = "a" * 40

    class SelectedSource:
        files = (SimpleNamespace(size_bytes=19),)
        receipt_handle = distribution_handle
        candidate_git_sha = candidate_sha
        source_tree_sha256 = "c" * 64
        baseline_tree_sha256 = "b" * 64
        amendment_manifest_sha256 = "e" * 64
        source_catalog_sha256 = "f" * 64

        def verify_current(self):
            return None

    source = SelectedSource()

    class SelectedInterpreter:
        files = ()
        receipt_handle = interpreter_handle
        candidate_git_sha = candidate_sha

        def verify_current(self):
            return None

        def open_executable(self):
            return os.open(runtime, os.O_RDONLY)

    interpreter = SelectedInterpreter()

    class SelectedActor:
        def verify_current(self, actual_source, actual_interpreter):
            assert actual_source is source
            assert actual_interpreter is interpreter

    actor = SelectedActor()

    class SourceRegistry:
        def resolve(self, handle):
            assert handle == distribution_handle
            return source

    class InterpreterRegistry:
        def resolve(self, handle, source_handle):
            assert (handle, source_handle) == (interpreter_handle, distribution_handle)
            return interpreter

    class ActorVerifier:
        def resolve_current(self, source_handle, runtime_handle):
            assert (source_handle, runtime_handle) == (distribution_handle, interpreter_handle)
            return actor

    builder = object.__new__(release_build.RootInstalledReleaseBuilder)
    builder.distribution_registry = SourceRegistry()
    builder.interpreter_registry = InterpreterRegistry()
    builder.actor_verifier = ActorVerifier()
    builder._receipts = {}
    builder._used = set()
    monkeypatch.setattr(release_build, "BUILD_CAS_ROOT", cas)
    monkeypatch.setattr(release_build, "_require_linux_root", lambda: None)
    monkeypatch.setattr(release_build, "_ensure_root_directory", lambda *_args: None)
    monkeypatch.setattr(builder, "_verify_builder_is_loaded_from_source", lambda _source: None)
    monkeypatch.setattr(builder, "_render_plan", lambda _source: b'{"selected":"plan"}\n')
    monkeypatch.setattr(builder, "_builder_digest", lambda _source: "1" * 64)
    monkeypatch.setattr(
        release_build, "_read_deployment_predecessor",
        lambda: release_build.DeploymentPredecessor("absent", 1, 2))

    def stage_one_member(root_fd, _source, _interpreter, _actor):
        body = b"selected source member\n"
        release_build._write_relative(root_fd, "lib/python/selected.py", body, mode=0o444)
        return [("lib/python/selected.py", hashlib.sha256(body).hexdigest(), len(body),
                 0o444, ("module",))]

    monkeypatch.setattr(builder, "_stage_fixed_layout", stage_one_member)
    handle = builder.build_selected(distribution_handle, interpreter_handle)
    receipt = builder.resolve_build_receipt(handle)
    try:
        assert receipt.distribution_receipt_handle == distribution_handle
        assert receipt.interpreter_receipt_handle == interpreter_handle
        assert receipt.candidate_git_sha == candidate_sha
        assert receipt.root_setup_plan_sha256 == hashlib.sha256(b'{"selected":"plan"}\n').hexdigest()
        manifest_fd = receipt.open_manifest()
        try:
            manifest_bytes = os.read(manifest_fd, release_build.MAX_RELEASE_BUILD_MANIFEST_BYTES)
        finally:
            os.close(manifest_fd)
        manifest = json.loads(manifest_bytes)
        assert manifest["candidate_git_sha"] == candidate_sha
        assert {row["relative_path"] for row in manifest["files"]} == {
            "lib/python/selected.py", release_build.STAGED_PLAN_PATH}
        member_fd = receipt.open_file("lib/python/selected.py")
        try:
            assert os.read(member_fd, 128) == b"selected source member\n"
        finally:
            os.close(member_fd)
    finally:
        receipt.close()


@pytest.mark.skipif(not sys.platform.startswith("linux") or os.geteuid() != 0,
                    reason="capacity lock requires a root-owned protected Linux fixture")
def test_release_build_cas_capacity_lock_serializes_usage_reservations():
    root = Path(tempfile.mkdtemp(prefix="hermes-release-build-cas-lock-", dir="/root"))
    os.chmod(root, 0o700)
    lock_fd = -1
    try:
        with release_build._locked_release_build_cas(root):
            lock_path = root / ".capacity.lock"
            info = lock_path.stat(follow_symlinks=False)
            assert info.st_uid == 0 and info.st_gid == 0 and info.st_nlink == 1
            assert release_build.stat.S_IMODE(info.st_mode) == 0o600
            lock_fd = os.open(lock_path, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
            with pytest.raises(BlockingIOError):
                release_build.fcntl.flock(lock_fd, release_build.fcntl.LOCK_EX | release_build.fcntl.LOCK_NB)
        release_build.fcntl.flock(lock_fd, release_build.fcntl.LOCK_EX | release_build.fcntl.LOCK_NB)
    finally:
        if lock_fd >= 0:
            os.close(lock_fd)
        (root / ".capacity.lock").unlink(missing_ok=True)
        os.rmdir(root)


def test_runtime_handoff_cannot_be_constructed_without_registry_seal():
    with pytest.raises(TypeError, match="only be issued"):
        release_build.RootBootstrapRuntimeHandoff(object(), schema=1)


def test_deployment_predecessor_absence_is_a_sealed_typed_observation(monkeypatch):
    monkeypatch.setattr(release_build, "_require_linux_root", lambda: None)
    monkeypatch.setattr(release_build, "_ensure_fixed_deployment_parent", lambda: None)
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
    monkeypatch.setattr(release_build, "_ensure_fixed_deployment_parent", lambda: None)
    monkeypatch.setattr(release_build, "_read_deployment_predecessor", lambda: release_build.DeploymentPredecessor(
        "present", 17, 23, "a" * 64, 29, 31, "b" * 40))
    module = types.ModuleType("hermes_installer.authority.installer_release")
    module.InstalledRootReleaseVerifier = InvalidVerifier
    monkeypatch.setitem(sys.modules, module.__name__, module)
    with pytest.raises(release_build.InstallerReleaseBuildError, match="not a verified"):
        release_build.observe_deployment_predecessor()
