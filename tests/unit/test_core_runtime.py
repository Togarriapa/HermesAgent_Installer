"""Effects and fail-closed checks for the finite core-service adapter.

These tests use temporary files and mocked systemd calls; target acceptance is
performed separately on the enrolled Pi.
"""
import hashlib
import json
import os
from types import SimpleNamespace

import pytest

from hermes_installer import core_runtime as core


def _resource_receipt(*, prompt_matches=False):
    return {
        "state": "discovered", "materialized": True, "discovered": True,
        "selectable_profile_mutations": [], "functional": False,
        "enabled": False, "target_verified": False,
        "resource_counts": {"native_skills": 396, "source_profiles_preserved": 208},
        "native_receipt": {
            "hermes_revision": core.COMMIT, "python_version": "3.14.7",
            "profile_identity_loaded": True, "loaded_skill_count": 396,
            "active_prompt_matches_bundled_primary": prompt_matches,
        },
    }


def _fake_runtime(tmp_path, monkeypatch, *, fail_enable_once=False):
    etc = tmp_path / "etc" / "hermes-installer"
    var = tmp_path / "var" / "lib" / "hermes-installer"
    unit_dir = tmp_path / "etc" / "systemd" / "system"
    libexec = tmp_path / "usr" / "local" / "libexec"
    home = tmp_path / "home" / "admin" / ".hermes"
    for path in (etc, var.parent, unit_dir, libexec, home):
        path.mkdir(parents=True, exist_ok=True)
    for path in (etc, unit_dir, libexec):
        path.chmod(0o755)
    monkeypatch.setattr(core, "ETC_INSTALLER", etc)
    monkeypatch.setattr(core, "VAR_LIB_INSTALLER", var)
    monkeypatch.setattr(core, "SYSTEMD_UNIT_DIR", unit_dir)
    monkeypatch.setattr(core, "LIBEXEC_DIR", libexec)
    monkeypatch.setattr(core, "TOKEN", etc / "jarvis-core" / "session-token")
    monkeypatch.setattr(core, "JOURNAL", var / "core-runtime" / "ownership.json")
    monkeypatch.setattr(core, "UNIT", unit_dir / core.SERVICE)
    monkeypatch.setattr(core, "LAUNCHER", libexec / "hermes-jarvis-core-launcher")
    monkeypatch.setattr(core, "HOME", home.parent)
    monkeypatch.setattr(core, "HERMES_HOME", home)
    monkeypatch.setattr(core, "WORKSPACE", home / "workspaces" / "jarvis-core")
    monkeypatch.setattr(core, "ROOT_UID", os.getuid())
    monkeypatch.setattr(core, "GATEWAY_GID", os.getgid())
    monkeypatch.setattr(core, "FILE_CONTRACT", (
        (core.UNIT, "unit_sha256", os.getuid(), os.getuid(), 0o644),
        (core.LAUNCHER, "launcher_sha256", os.getuid(), os.getuid(), 0o755),
        (core.TOKEN, "token_sha256", os.getuid(), os.getgid(), 0o640)))
    monkeypatch.setattr(core.os, "geteuid", lambda: 0)

    class Account:
        pw_uid = 1000
        pw_gid = 1000
        pw_dir = "/home/admin"

    monkeypatch.setattr(core.pwd, "getpwnam", lambda _: Account())
    monkeypatch.setattr(core.grp, "getgrgid", lambda _: SimpleNamespace(gr_gid=os.getgid()))
    identity = {"commit": core.COMMIT, "lock_sha256": core.LOCK_SHA256,
                "python_sha256": "a" * 64, "python_link": "pinned-link",
                "python_uid": 1000, "python_gid": 1000, "python_mode": 0o755}
    monkeypatch.setattr(core, "_identity", lambda: identity)
    monkeypatch.setattr(core, "_owned_listener", lambda: True)
    monkeypatch.setattr(core, "_launcher", lambda: b"test fixed core launcher")
    monkeypatch.setattr(core, "_install_bundled_resources", lambda _account: _resource_receipt())

    calls = []
    enabled = {"value": False}
    failure = {"pending": fail_enable_once}

    def fake_run(argv, check=True):
        calls.append((tuple(argv), core.UNIT.exists()))
        out = ""
        if argv[:2] == ["systemctl", "is-active"]:
            out = "active" if enabled["value"] else "inactive"
        elif argv[:2] == ["systemctl", "show"] and "FragmentPath" in argv[2]:
            out = str(core.UNIT) if core.UNIT.exists() else ""
        elif argv[:2] == ["systemctl", "show"] and "MainPID" in argv[2]:
            out = "0"
        elif argv[:2] == ["systemctl", "enable"]:
            if failure["pending"]:
                failure["pending"] = False
                if check:
                    raise core.CoreRuntimeError("injected service start failure")
            enabled["value"] = True
        elif argv[:2] == ["systemctl", "disable"]:
            enabled["value"] = False
        return SimpleNamespace(stdout=out, returncode=0)

    monkeypatch.setattr(core, "_run", fake_run)
    monkeypatch.setattr(core, "_wait_for_listener", lambda: None)
    return calls, enabled


def test_install_resume_and_rollback_use_only_fixed_owned_paths(tmp_path, monkeypatch):
    calls, enabled = _fake_runtime(tmp_path, monkeypatch)
    preserve = core.HERMES_HOME / "auth.json"
    preserve.write_text("user credential")
    first = core.install_or_resume()
    token = core.TOKEN.read_bytes()
    second = core.install_or_resume()
    assert token == core.TOKEN.read_bytes()
    assert enabled["value"]
    assert "listener verified" in first and "listener verified" in second
    assert preserve.read_text() == "user credential"
    monkeypatch.setattr(core, "_owned_listener", lambda: False)
    assert core.rollback().startswith("journal-owned core service files removed")
    assert not core.UNIT.exists() and not core.LAUNCHER.exists()
    assert preserve.read_text() == "user credential"
    assert any(argv == ("systemctl", "daemon-reload") and not unit_exists
               for argv, unit_exists in calls)


def test_failed_start_is_resumable_without_rotating_session_credential(tmp_path, monkeypatch):
    _fake_runtime(tmp_path, monkeypatch, fail_enable_once=True)
    with pytest.raises(core.CoreRuntimeError, match="injected"):
        core.install_or_resume()
    token = core.TOKEN.read_bytes()
    assert json.loads(core.JOURNAL.read_text())["state"] == "installed"
    message = core.install_or_resume()
    assert "listener verified" in message
    assert core.TOKEN.read_bytes() == token


def test_rollback_cleans_journaled_preparing_partial_stage(tmp_path, monkeypatch):
    _fake_runtime(tmp_path, monkeypatch)
    original = core._owned_file
    interrupted = {"done": False}

    def fail_during_launcher(path, body, mode, uid, gid, expected, repair):
        if path == core.LAUNCHER and not interrupted["done"]:
            path.write_bytes(b"partial launcher")
            os.chown(path, uid, gid)
            path.chmod(mode)
            interrupted["done"] = True
            raise core.CoreRuntimeError("injected interruption")
        return original(path, body, mode, uid, gid, expected, repair)

    monkeypatch.setattr(core, "_owned_file", fail_during_launcher)
    with pytest.raises(core.CoreRuntimeError, match="injected"):
        core.install_or_resume()
    monkeypatch.setattr(core, "_owned_file", original)
    assert json.loads(core.JOURNAL.read_text())["state"] == "preparing"
    monkeypatch.setattr(core, "_owned_listener", lambda: False)
    assert core.rollback().startswith("journal-owned core service files removed")
    assert not core.TOKEN.exists() and not core.LAUNCHER.exists()


def test_launcher_uses_isolated_pinned_loopback_without_secret_arguments():
    launcher = core._launcher().decode()
    assert "HERMES_DASHBOARD_SESSION_TOKEN" in launcher
    assert "--isolated --host 127.0.0.1 --port 8766" in launcher
    assert "HERMES_DISABLE_LAZY_INSTALLS=1" in launcher
    assert "PYTHONNOUSERSITE=1 PYTHONDONTWRITEBYTECODE=1" in launcher
    assert "unset PYTHONHOME PYTHONUSERBASE PYTHONSTARTUP VIRTUAL_ENV" in launcher
    assert "auth.json" not in launcher


def test_bundled_resource_import_uses_exact_admin_home_source_and_pm_python(tmp_path, monkeypatch):
    installer_python = tmp_path / "installer-python"
    runuser = tmp_path / "runuser"
    for executable in (installer_python, runuser):
        executable.write_text("fixed fixture executable")
        executable.chmod(0o755)
    monkeypatch.setattr(core.sys, "executable", str(installer_python))
    monkeypatch.setattr(core, "RUNUSER", runuser)
    monkeypatch.setattr(core, "ROOT_UID", os.getuid())
    calls = []

    def fake_run(argv, **kwargs):
        calls.append((argv, kwargs))
        return SimpleNamespace(returncode=0, stdout=json.dumps(_resource_receipt()), stderr="")

    monkeypatch.setattr(core.subprocess, "run", fake_run)
    account = SimpleNamespace(pw_uid=os.getuid(), pw_gid=os.getgid())
    receipt = core._install_bundled_resources(account)
    argv, kwargs = calls[0]
    assert argv == [str(runuser), "-u", "admin", "--", str(installer_python.resolve()), "-m",
                    "hermes_installer.registry.manual_jarvis_skills", "import-bundled",
                    "--home", str(core.HERMES_HOME), "--hermes-source", str(core.SOURCE),
                    "--python", str(core.PYTHON)]
    assert kwargs["timeout"] == 600
    assert kwargs["env"]["HOME"] == str(core.HOME)
    assert receipt["state"] == "discovered"
    assert receipt["functional"] is False and receipt["target_verified"] is False


def test_resource_import_does_not_overwrite_or_gate_on_existing_primary_prompt(tmp_path, monkeypatch):
    installer_python = tmp_path / "installer-python"
    runuser = tmp_path / "runuser"
    for executable in (installer_python, runuser):
        executable.write_text("fixed fixture executable")
        executable.chmod(0o755)
    monkeypatch.setattr(core.sys, "executable", str(installer_python))
    monkeypatch.setattr(core, "RUNUSER", runuser)
    monkeypatch.setattr(core, "ROOT_UID", os.getuid())
    monkeypatch.setattr(core.subprocess, "run", lambda *args, **kwargs:
                        SimpleNamespace(returncode=0, stdout=json.dumps(_resource_receipt()), stderr=""))

    receipt = core._install_bundled_resources(SimpleNamespace(pw_uid=os.getuid()))

    assert receipt["native_receipt"]["active_prompt_matches_bundled_primary"] is False


def test_resource_import_rejects_a_receipt_that_claims_functional_use(tmp_path, monkeypatch):
    installer_python = tmp_path / "installer-python"
    runuser = tmp_path / "runuser"
    for executable in (installer_python, runuser):
        executable.write_text("fixed fixture executable")
        executable.chmod(0o755)
    monkeypatch.setattr(core.sys, "executable", str(installer_python))
    monkeypatch.setattr(core, "RUNUSER", runuser)
    monkeypatch.setattr(core, "ROOT_UID", os.getuid())
    receipt = _resource_receipt()
    receipt["functional"] = True
    monkeypatch.setattr(core.subprocess, "run", lambda *args, **kwargs:
                        SimpleNamespace(returncode=0, stdout=json.dumps(receipt), stderr=""))

    with pytest.raises(core.CoreRuntimeError, match="receipt is invalid"):
        core._install_bundled_resources(SimpleNamespace(pw_uid=os.getuid()))


def test_owned_journal_detects_mutated_service_file(tmp_path, monkeypatch):
    unit, launcher, token, journal = (tmp_path / name for name in
                                      ("unit", "launcher", "token", "ownership.json"))
    contents = {unit: b"unit", launcher: b"launch", token: b"credential"}
    for path, body in contents.items():
        path.write_bytes(body)
    unit.chmod(0o644)
    launcher.chmod(0o755)
    token.chmod(0o640)
    record = {"schema": 1, "state": "installed", "service": core.SERVICE,
              "unit_sha256": hashlib.sha256(contents[unit]).hexdigest(),
              "launcher_sha256": hashlib.sha256(contents[launcher]).hexdigest(),
              "token_sha256": hashlib.sha256(contents[token]).hexdigest()}
    journal.write_text(json.dumps(record))
    journal.chmod(0o600)
    monkeypatch.setattr(core, "UNIT", unit)
    monkeypatch.setattr(core, "LAUNCHER", launcher)
    monkeypatch.setattr(core, "TOKEN", token)
    monkeypatch.setattr(core, "JOURNAL", journal)
    monkeypatch.setattr(core, "ROOT_UID", os.getuid())
    monkeypatch.setattr(core, "GATEWAY_GID", os.getgid())
    monkeypatch.setattr(core, "FILE_CONTRACT", (
        (unit, "unit_sha256", os.getuid(), os.getgid(), 0o644),
        (launcher, "launcher_sha256", os.getuid(), os.getgid(), 0o755),
        (token, "token_sha256", os.getuid(), os.getgid(), 0o640)))
    class Account:
        pw_uid = 1000
        pw_dir = "/home/admin"
        pw_gid = 1000
    monkeypatch.setattr(core.pwd, "getpwnam", lambda _: Account())
    monkeypatch.setattr(core, "_unit", lambda: contents[unit])
    monkeypatch.setattr(core, "_launcher", lambda: contents[launcher])
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


def test_preparing_transaction_repairs_only_partial_owned_file(tmp_path):
    target = tmp_path / "launcher"
    target.write_bytes(b"partial")
    target.chmod(0o700)
    expected = b"fixed root-owned launcher"
    core._owned_file(target, expected, 0o700, os.getuid(), os.getgid(),
                     hashlib.sha256(expected).hexdigest(), repair=True)
    assert target.read_bytes() == expected


def test_unit_binds_service_identity_and_protected_credential(monkeypatch):
    class Account:
        pw_uid = 1000
        pw_dir = "/home/admin"
        pw_gid = 1000

    monkeypatch.setattr(core.pwd, "getpwnam", lambda _: Account())
    unit = core._unit().decode()
    assert "User=admin" in unit
    assert "Group=1000" in unit
    assert "ExecStart=" + str(core.LAUNCHER) in unit
    assert "LoadCredential=hermes-session-token:" + str(core.TOKEN) in unit
    assert "127.0.0.1" not in unit  # listener is fixed in the verified launcher argv
