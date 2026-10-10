from __future__ import annotations

import hashlib
import io
import json
import os
import subprocess
import sys
import tarfile
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


def test_release_builder_pins_literal_model_store_template_and_native_source_modules():
    assert release_build.EXISTING_MODEL_STORE_TEMPLATE_ID == "installer-existing-model-store-root-template-v1"
    assert release_build.EXISTING_MODEL_STORE_TEMPLATE_PATH.endswith(
        "2026-10-10-existing-model-store-selection-source-v139/existing-model-store-root-template-v1.json")
    assert release_build.EXISTING_MODEL_STORE_TEMPLATE_SHA256 == (
        "3a145ddd21cf8ba524307844a1ab7fb78a4a066afad59bfbbb9164327c2f570f")
    assert release_build.EXISTING_MODEL_STORE_TEMPLATE_BYTES == 712
    for _name, source_path, target_path, digest, size in release_build.REVIEWED_SOURCE_MODULES:
        source = Path(__file__).parents[2] / source_path
        body = source.read_bytes()
        assert target_path.startswith(("src/hermes_installer/", "lib/python/hermes_installer/"))
        assert (hashlib.sha256(body).hexdigest(), len(body)) == (digest, size)


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
