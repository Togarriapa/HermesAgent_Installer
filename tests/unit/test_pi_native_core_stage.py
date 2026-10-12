"""Bounded failure and filesystem-custody fixtures for Pi source staging."""
import importlib.util
import io
import json
import os
import stat
import tarfile
from pathlib import Path

import pytest


HELPER_PATH = Path(__file__).resolve().parents[2] / "tools" / "pi_native_core_stage.py"
_SPEC = importlib.util.spec_from_file_location("pi_native_core_stage", HELPER_PATH)
stage = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(stage)


def _archive(members):
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w:gz") as archive:
        for name, kind, body in members:
            info = tarfile.TarInfo(name)
            if kind == "file":
                info.size = len(body)
                archive.addfile(info, io.BytesIO(body))
            else:
                info.type = tarfile.SYMTYPE
                info.linkname = body.decode("ascii")
                archive.addfile(info)
    return raw.getvalue()


def test_download_hash_mismatch_removes_bytes_before_any_extraction(monkeypatch, tmp_path):
    payload = b"unqualified source bytes"
    path = tmp_path / "candidate.tar.gz"
    monkeypatch.setattr(stage.urllib.request, "urlopen",
                        lambda *_args, **_kwargs: io.BytesIO(payload))

    with pytest.raises(RuntimeError, match="SHA-256 differs"):
        stage._download_archive(str(path), "0" * 64, "https://github.com/fixed/release/archive")

    assert not path.exists()


def test_root_interpreter_requires_supported_version_and_platform_modules(monkeypatch):
    monkeypatch.setattr(stage.os, "geteuid", lambda: 0)
    monkeypatch.setattr(stage.sys, "executable", "/usr/bin/python3")
    monkeypatch.setattr(stage.sys, "flags", type("Flags", (), {"isolated": 1})())
    monkeypatch.setattr(stage.sys, "version_info", (3, 9, 18))
    with pytest.raises(RuntimeError, match="3.10 or newer"):
        stage._require_root_python()

    monkeypatch.setattr(stage.sys, "version_info", (3, 11, 0))
    monkeypatch.setattr(stage.importlib.util, "find_spec", lambda _name: None)
    with pytest.raises(RuntimeError, match="sqlite3"):
        stage._require_root_python()


def test_existing_candidate_generation_refuses_before_network_or_write(monkeypatch, tmp_path):
    commit = "a" * 40
    target = tmp_path / f"hermes-installer-core-{commit[:9]}"
    target.mkdir()
    parent_fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    downloaded = []
    monkeypatch.setattr(stage, "_open_root_opt", lambda: os.dup(parent_fd))
    monkeypatch.setattr(stage, "_require_root_python", lambda: None)
    monkeypatch.setattr(stage, "OPT", str(tmp_path))
    monkeypatch.setattr(stage, "_download_archive", lambda *_args: downloaded.append(True))
    monkeypatch.setattr(stage.sys, "argv", ["pi_native_core_stage.py", "--source-commit", commit,
                                               "--archive-sha256", "b" * 64])
    try:
        assert stage.main() == 4
    finally:
        os.close(parent_fd)

    assert downloaded == []
    assert list(target.iterdir()) == []


@pytest.mark.parametrize("name,kind,body", [
    ("../escape", "file", b"outside"),
    ("/absolute", "file", b"outside"),
    ("src/link", "symlink", b"/etc/passwd"),
])
def test_archive_rejects_unsafe_members_before_tree_creation(tmp_path, name, kind, body):
    archive_path = tmp_path / "bad.tar.gz"
    archive_path.write_bytes(_archive([(name, kind, body)]))
    destination = tmp_path / "target"

    with pytest.raises(RuntimeError):
        stage._validated_members(str(archive_path))

    assert not destination.exists()
    assert not (tmp_path / "escape").exists()


@pytest.mark.skipif(os.geteuid() != 0, reason="root-owned Pi extraction contract")
def test_regular_member_and_provenance_receive_root_custody(tmp_path):
    content = b"reviewed adapter source\n"
    raw_archive = _archive([("src/hermes_installer/core_runtime.py", "file", content)])
    archive_path = tmp_path / "one.tar.gz"
    archive_path.write_bytes(raw_archive)
    destination = tmp_path / "generation"
    destination.mkdir(mode=0o755)
    root_fd = os.open(destination, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        with tarfile.open(archive_path, "r:gz") as archive:
            member = archive.getmembers()[0]
            stage._write_member(root_fd, archive, member, ("src", "hermes_installer",
                                                             "core_runtime.py"))
        stage._write_receipt(root_fd, "a" * 40, "b" * 64)
    finally:
        os.close(root_fd)

    source = destination / "src" / "hermes_installer" / "core_runtime.py"
    receipt = destination / ".source-provenance.json"
    source_info, receipt_info = source.stat(), receipt.stat()
    assert source.read_bytes() == content
    assert (source_info.st_uid, source_info.st_gid, stat.S_IMODE(source_info.st_mode)) == (0, 0, 0o644)
    assert (receipt_info.st_uid, receipt_info.st_gid, stat.S_IMODE(receipt_info.st_mode)) == (0, 0, 0o444)
    assert json.loads(receipt.read_bytes()) == {
        "schema": 1, "source_commit": "a" * 40, "archive_sha256": "b" * 64,
    }


@pytest.mark.skipif(os.geteuid() != 0, reason="root-owned Pi extraction contract")
def test_cleanup_refuses_replaced_staging_directory(tmp_path):
    original = tmp_path / ".stage"
    original.mkdir(mode=0o755)
    original_identity = (original.stat().st_dev, original.stat().st_ino)
    original.rename(tmp_path / ".stage-original")
    original.mkdir(mode=0o755)
    parent_fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        with pytest.raises(RuntimeError, match="changed before cleanup"):
            stage._remove_tree_at(parent_fd, original.name, original_identity)
    finally:
        os.close(parent_fd)
    assert original.is_dir()
