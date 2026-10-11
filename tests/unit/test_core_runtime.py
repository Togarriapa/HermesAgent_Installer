"""Effects and fail-closed checks for the finite core-service adapter.

These tests use temporary files and mocked systemd calls; target acceptance is
performed separately on the enrolled Pi.
"""
import hashlib
import json
import os
import stat

import pytest

from hermes_installer import core_runtime as core


def test_launcher_uses_isolated_pinned_loopback_without_secret_arguments():
    launcher = core._launcher().decode()
    assert "HERMES_DASHBOARD_SESSION_TOKEN" in launcher
    assert "--isolated --host 127.0.0.1 --port 8766" in launcher
    assert "auth.json" not in launcher


def test_owned_journal_detects_mutated_service_file(tmp_path, monkeypatch):
    unit, launcher, token, journal = (tmp_path / name for name in
                                      ("unit", "launcher", "token", "ownership.json"))
    contents = {unit: b"unit", launcher: b"launch", token: b"credential"}
    for path, body in contents.items():
        path.write_bytes(body)
    record = {"schema": 1, "service": core.SERVICE,
              "unit_sha256": hashlib.sha256(contents[unit]).hexdigest(),
              "launcher_sha256": hashlib.sha256(contents[launcher]).hexdigest(),
              "token_sha256": hashlib.sha256(contents[token]).hexdigest()}
    journal.write_text(json.dumps(record))
    journal.chmod(0o600)
    monkeypatch.setattr(core, "UNIT", unit)
    monkeypatch.setattr(core, "LAUNCHER", launcher)
    monkeypatch.setattr(core, "TOKEN", token)
    monkeypatch.setattr(core, "JOURNAL", journal)
    assert core._journal()["service"] == core.SERVICE
    launcher.write_bytes(b"changed")
    with pytest.raises(core.CoreRuntimeError, match="changed"):
        core._journal()


def test_atomic_refuses_to_replace_existing_path(tmp_path):
    target = tmp_path / "owned"
    target.write_bytes(b"user data")
    with pytest.raises(core.CoreRuntimeError, match="occupied"):
        core._atomic(target, b"replacement", 0o600)
    assert target.read_bytes() == b"user data"


def test_unit_binds_service_identity_and_protected_credential(monkeypatch):
    class Account:
        pw_uid = 1000
        pw_dir = "/home/admin"
        pw_gid = os.getgid()

    monkeypatch.setattr(core.pwd, "getpwnam", lambda _: Account())
    unit = core._unit().decode()
    assert "User=admin" in unit
    assert "ExecStart=" + str(core.LAUNCHER) in unit
    assert "LoadCredential=hermes-session-token:" + str(core.TOKEN) in unit
    assert "127.0.0.1" not in unit  # listener is fixed in the verified launcher argv
