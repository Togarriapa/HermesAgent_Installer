"""Effects and fail-closed checks for the finite core-service adapter.

These tests use temporary files and mocked systemd calls; target acceptance is
performed separately on the enrolled Pi.
"""
import hashlib
import json
import os
import pwd
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest

from hermes_installer import core_runtime as core


def _exec_start_pre(unit_bytes):
    """Run the generated ExecStartPre with systemd-like credential files."""
    if os.geteuid() != 0:
        raise AssertionError("the Pi startup-guard fixture requires root to model admin")
    line = next((row for row in unit_bytes.decode().splitlines()
                 if row.startswith("ExecStartPre=")), None)
    if line is None:
        return None
    cred_dir = Path(tempfile.mkdtemp(prefix="core-start-guard-", dir="/tmp"))
    cred_dir.chmod(0o700)
    admin = pwd.getpwnam("admin")
    try:
        loads = [row.partition("=")[2] for row in unit_bytes.decode().splitlines()
                 if row.startswith("LoadCredential=")]
        credentials = []
        for item in loads:
            name, separator, source = item.partition(":")
            if not separator:
                raise AssertionError("generated service credential declaration is malformed")
            credentials.append((name, Path(source)))
        for name, source in credentials:
            target = cred_dir / name
            target.write_bytes(source.read_bytes())
            target.chmod(0o400)
            os.chown(target, admin.pw_uid, admin.pw_gid)
        argv = shlex.split(line.partition("=")[2])
        env = {"CREDENTIALS_DIRECTORY": str(cred_dir), "PATH": "/usr/bin:/bin"}
        result = subprocess.run(
            argv, cwd="/", env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            check=False,
        )
        return result.returncode
    finally:
        for child in cred_dir.iterdir():
            child.unlink()
        cred_dir.rmdir()


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


def _isolate_resource_import_paths(tmp_path, monkeypatch):
    """Keep import-eligibility checks away from a host's real Hermes tree."""
    home = tmp_path / "isolated-home" / "admin"
    hermes_home = home / ".hermes"
    cas = tmp_path / "isolated-resource-cas"
    home.mkdir(parents=True)
    hermes_home.mkdir()
    cas.mkdir()
    monkeypatch.setattr(core, "HOME", home)
    monkeypatch.setattr(core, "HERMES_HOME", hermes_home)
    monkeypatch.setattr(core, "RESOURCES_CAS", cas)


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
    monkeypatch.setattr(core, "_owned_listener", lambda **_kwargs: True)
    monkeypatch.setattr(core, "_launcher", lambda: b"test fixed core launcher")
    monkeypatch.setattr(core, "_install_bundled_resources", lambda _account: _resource_receipt())
    monkeypatch.setattr(core, "_write_resources_discovery", lambda: {
        "resource_counts": {"native_skills": 396, "source_profiles_preserved": 208},
        "active_prompt_matches_bundled_primary": False,
    })

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
        elif argv[:2] == ["systemctl", "stop"]:
            enabled["value"] = False
        elif argv[:2] in (["systemctl", "start"], ["systemctl", "restart"]):
            enabled["value"] = True
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


def test_launcher_uses_only_pinned_hermes_and_installer_adapter_paths():
    import shlex

    launcher = core._launcher().decode("ascii")
    expected = shlex.quote(f"{core.SOURCE}:{core.ADAPTER_SOURCE}")
    assert f"export PYTHONPATH={expected}" in launcher
    assert "python -P -m hermes_cli.main" in launcher


def test_generated_core_launcher_has_valid_shell_syntax():
    result = subprocess.run(
        ["sh", "-n"], input=core._launcher(), stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, check=False, timeout=5,
    )
    assert result.returncode == 0, result.stderr.decode("utf-8", "replace")


def test_native_plugin_bootstrap_embedded_scripts_parse_on_target_runtime():
    from hermes_installer.remote import native_plugin_bootstrap as bootstrap

    scripts = (
        bootstrap._OFFICIAL_ENABLE_SCRIPT,
        bootstrap._OFFICIAL_SELECTION_READ_SCRIPT,
        bootstrap._OFFICIAL_SELECTION_BACKUP_SCRIPT,
        bootstrap._OFFICIAL_SELECTION_RESTORE_SCRIPT,
    )
    for index, source in enumerate(scripts):
        compile(source, f"native-plugin-bootstrap-script-{index}", "exec")


def _install_legacy_service_fixture(tmp_path, monkeypatch):
    calls, enabled = _fake_runtime(tmp_path, monkeypatch)
    # Establish a complete temporary owned install using the same fixture actor
    # and fixed temp paths; do not manufacture a journal fragment by hand.
    core.install_or_resume()
    launcher_bytes = core._legacy_launcher()
    core.LAUNCHER.write_bytes(launcher_bytes)
    core.LAUNCHER.chmod(0o755)
    record = json.loads(core.JOURNAL.read_text())
    record.update({"state": "active",
                   "launcher_sha256": hashlib.sha256(launcher_bytes).hexdigest(),
                   "unit_sha256": hashlib.sha256(core._unit()).hexdigest()})
    core.JOURNAL.write_text(json.dumps(record, sort_keys=True) + "\n")
    core.JOURNAL.chmod(0o600)
    # The production recipe is the post-migration comparator. The on-disk
    # legacy launcher and journal hashes above remain the migration input.
    monkeypatch.setattr(core, "_launcher", _REAL_CORE_LAUNCHER)
    monkeypatch.setattr(core, "ADAPTER_MIGRATION_BACKUP",
                        core.JOURNAL.parent / "adapter-migration-backup")
    monkeypatch.setattr(core, "_validate_adapter_source_path", lambda: None)
    monkeypatch.setattr(core, "_core_source_generation", lambda: "c" * 64)
    monkeypatch.setattr(core, "_identity", lambda: {
        "commit": core.COMMIT, "lock_sha256": core.LOCK_SHA256,
        "python_sha256": "a" * 64, "python_link": "pinned-link",
        "python_uid": 1000, "python_gid": 1000, "python_mode": 0o755,
    })
    bootstrap = ModuleType("hermes_installer.remote.native_plugin_bootstrap")
    def enable_plugin():
        calls.append((("bridge", "enable"), core.UNIT.exists()))
        return SimpleNamespace(plugin_key="hermes-installer-resources-delegation")
    bootstrap.enable_native_resources_plugin = enable_plugin
    selection = {"value": "d" * 64}
    bootstrap.verify_native_resources_plugin_selection = lambda: SimpleNamespace(
        plugin_key="hermes-installer-resources-delegation", selection_sha256=selection["value"])
    bootstrap.capture_native_resources_plugin_selection = lambda: SimpleNamespace(
        plugin_key="hermes-installer-resources-delegation", snapshot_json=b'{"schema":1}',
        prior_selection_sha256="e" * 64, migrated_selection_sha256="d" * 64)
    def restore_selection(_snapshot, *, expected_current_sha256):
        assert expected_current_sha256 == "d" * 64
        selection["value"] = "e" * 64
        return "e" * 64
    bootstrap.restore_native_resources_plugin_selection = restore_selection
    inspector = ModuleType("hermes_installer.remote.core_gateway_inspector")
    inspector._current_native_adapter_generation = lambda *, deadline: "a" * 64
    inspector.verify_staged_native_resources_plugin = lambda *, deadline: "b" * 64
    monkeypatch.setitem(sys.modules,
                        "hermes_installer.remote.native_plugin_bootstrap", bootstrap)
    monkeypatch.setitem(sys.modules,
                        "hermes_installer.remote.core_gateway_inspector", inspector)
    return calls, enabled, launcher_bytes, selection


_REAL_CORE_LAUNCHER = core._launcher


@pytest.mark.skipif(os.geteuid() != 0, reason="legacy core migration requires the real root actor")
def test_adapter_migration_activates_bridge_before_owned_core_restart(tmp_path, monkeypatch):
    calls, _enabled, old_launcher, _selection = _install_legacy_service_fixture(tmp_path, monkeypatch)
    token = core.TOKEN.read_bytes()
    old_unit = core.UNIT.read_bytes()

    result = core.install_or_resume()

    assert "migrated to the immutable installer adapter generation" in result
    record = json.loads(core.JOURNAL.read_text())
    assert record["adapter_migration_state"] == "active"
    assert record["launcher_sha256"] == hashlib.sha256(core.LAUNCHER.read_bytes()).hexdigest()
    assert core.LAUNCHER.read_bytes() != old_launcher
    assert core.UNIT.read_bytes() == old_unit
    assert core.TOKEN.read_bytes() == token
    assert (core.ADAPTER_MIGRATION_BACKUP / "launcher").read_bytes() == old_launcher
    ordered = [call[0] for call in calls]
    assert ordered.index(("bridge", "enable")) < ordered.index(("systemctl", "restart", core.SERVICE))


@pytest.mark.skipif(os.geteuid() != 0, reason="legacy core migration requires the real root actor")
def test_adapter_migration_restores_exact_owned_files_after_restart_failure(tmp_path, monkeypatch):
    calls, _enabled, old_launcher, _selection = _install_legacy_service_fixture(tmp_path, monkeypatch)
    token = core.TOKEN.read_bytes()
    old_unit = core.UNIT.read_bytes()
    old_journal = core.JOURNAL.read_bytes()
    monkeypatch.setattr(core, "_wait_for_listener",
                        lambda: (_ for _ in ()).throw(core.CoreRuntimeError("injected post-restart failure")))

    with pytest.raises(core.CoreRuntimeError, match="injected post-restart failure"):
        core.migrate_owned_core_to_adapter_path()

    assert core.LAUNCHER.read_bytes() == old_launcher
    assert core.UNIT.read_bytes() == old_unit
    assert core.JOURNAL.read_bytes() == old_journal
    assert core.TOKEN.read_bytes() == token
    assert [call[0] for call in calls].count(("systemctl", "restart", core.SERVICE)) == 2


@pytest.mark.skipif(os.geteuid() != 0, reason="legacy core migration requires the real root actor")
def test_post_migration_recovery_restores_exact_legacy_files_and_selection(tmp_path, monkeypatch):
    calls, enabled, old_launcher, selection = _install_legacy_service_fixture(tmp_path, monkeypatch)
    old_unit = core.UNIT.read_bytes()
    core.migrate_owned_core_to_adapter_path()
    assert core.LAUNCHER.read_bytes() != old_launcher
    assert selection["value"] == "d" * 64

    def current_listener(*, legacy_launcher=False):
        return enabled["value"] and (
            legacy_launcher == (core.LAUNCHER.read_bytes() == old_launcher))
    monkeypatch.setattr(core, "_owned_listener", current_listener)
    result = core.recover_owned_core_from_adapter_migration()

    assert "exact prior Hermes core and plugin selection restored" in result
    assert core.LAUNCHER.read_bytes() == old_launcher
    assert core.UNIT.read_bytes() == old_unit
    assert json.loads(core.JOURNAL.read_text())["state"] == "active"
    assert selection["value"] == "e" * 64
    ordered = [call[0] for call in calls]
    assert ordered.index(("systemctl", "stop", core.SERVICE)) < ordered.index(
        ("systemctl", "start", core.SERVICE))


@pytest.mark.skipif(os.geteuid() != 0, reason="legacy core migration requires the real root actor")
def test_post_migration_recovery_refuses_changed_current_launcher_before_touching_state(tmp_path, monkeypatch):
    calls, _enabled, _old_launcher, _selection = _install_legacy_service_fixture(tmp_path, monkeypatch)
    core.migrate_owned_core_to_adapter_path()
    before_journal = core.JOURNAL.read_bytes()
    before_unit = core.UNIT.read_bytes()
    core.LAUNCHER.write_bytes(b"unrecognized changed launcher")
    with pytest.raises(core.CoreRuntimeError, match="owned service file changed|recipe"):
        core.recover_owned_core_from_adapter_migration()
    assert core.JOURNAL.read_bytes() == before_journal
    assert core.UNIT.read_bytes() == before_unit
    assert not any(call[0] == ("systemctl", "stop", core.SERVICE) for call in calls)


@pytest.mark.skipif(os.geteuid() != 0, reason="adapter update needs the real root actor")
def test_native_adapter_update_stops_before_restart_on_failure_can_launch_new_launcher(tmp_path, monkeypatch):
    calls, enabled, _old_launcher, selection = _install_legacy_service_fixture(
        tmp_path, monkeypatch, journal_state="installed")
    memory = core.HERMES_HOME / "memories" / "owner.md"
    memory.parent.mkdir(parents=True)
    memory.write_text("existing owner memory")
    core.migrate_owned_core_to_adapter_path()
    prior = json.loads(core.JOURNAL.read_text())
    assert prior["state"] == "installed"
    prior_launcher = core.LAUNCHER.read_bytes()
    prior_unit = core.UNIT.read_bytes()
    token = core.TOKEN.read_bytes()
    old_source = core.ADAPTER_SOURCE
    monkeypatch.setattr(core, "ADAPTER_SOURCE", old_source.parent.parent / "hermes-installer-core-bbbbbbbbb" / "src")
    monkeypatch.setattr(core, "ADAPTER_UPDATE_BACKUPS", core.JOURNAL.parent / "adapter-update-backups")
    monkeypatch.setattr(core, "_validate_adapter_source_path", lambda: None)
    monkeypatch.setattr(core, "_validate_adapter_generation_path", lambda _path: None)
    monkeypatch.setattr(core, "_owned_listener", lambda **_kwargs: enabled["value"])
    monkeypatch.setattr(core, "_owned_listener_pidfd", lambda **_kwargs: enabled["value"])
    _fake_update_pidfd(monkeypatch, enabled)
    real_run = core._run
    reload_service_states = []
    automatic_restarts = []
    guard_denials = []
    def model_restart_on_failure(argv, check=True):
        result = real_run(argv, check)
        if argv == ["systemctl", "daemon-reload"]:
            reload_service_states.append(enabled["value"])
            # Model an old process failing in the ExecStart replacement window.
            # Restart=on-failure tries the just-read launcher, subject to the
            # actual generated root-side guard and still-prior preparing journal.
            if (enabled["value"] and "Restart=on-failure" in core.UNIT.read_text()
                    and core.LAUNCHER.read_bytes() == core._launcher()):
                enabled["value"] = False
                try:
                    status = _exec_start_pre(core.UNIT.read_bytes())
                    if status:
                        guard_denials.append(status)
                    else:
                        enabled["value"] = True
                        journal = json.loads(core.JOURNAL.read_text())
                        automatic_restarts.append({
                            "state": journal["state"],
                            "adapter_source": journal["adapter_source"],
                            "update_state": journal["adapter_update_state"],
                            "launcher_sha256": hashlib.sha256(core.LAUNCHER.read_bytes()).hexdigest(),
                        })
        return result
    monkeypatch.setattr(core, "_run", model_restart_on_failure)

    result = core.install_or_resume()

    updated = json.loads(core.JOURNAL.read_text())
    assert "updated to the verified immutable installer adapter generation" in result
    assert updated["adapter_source"] == str(core.ADAPTER_SOURCE)
    assert updated["state"] == "installed"
    assert updated["adapter_generation"] == "a" * 64
    assert updated["plugin_selection_sha256"] == prior["plugin_selection_sha256"]
    assert core.LAUNCHER.read_bytes() != prior_launcher
    assert core.UNIT.read_bytes() == prior_unit
    assert core.TOKEN.read_bytes() == token
    assert memory.read_text() == "existing owner memory"
    backup = core.ADAPTER_UPDATE_BACKUPS / prior["adapter_generation"]
    assert (backup / "launcher").read_bytes() == prior_launcher
    assert json.loads((backup / "journal.json").read_bytes()) == prior
    assert selection["value"] == prior["plugin_selection_sha256"]
    assert reload_service_states == [False]
    assert automatic_restarts == []
    assert guard_denials == []
    ordered = [call[0] for call in calls]
    assert ordered.index(("systemctl", "stop", core.SERVICE)) < ordered.index(
        ("systemctl", "start", core.SERVICE))


@pytest.mark.skipif(os.geteuid() != 0, reason="adapter update needs the real root actor")
def test_native_adapter_update_restart_failure_restores_exact_prior_generation(tmp_path, monkeypatch):
    _calls, enabled, _old_launcher, _selection = _install_legacy_service_fixture(
        tmp_path, monkeypatch, journal_state="installed")
    core.migrate_owned_core_to_adapter_path()
    migrated_raw = core.JOURNAL.read_bytes()
    migrated_record = json.loads(migrated_raw)
    prior_unguarded_unit = core._unit(startup_guard=False)
    core._atomic_replace(core.UNIT, prior_unguarded_unit, 0o644, core.ROOT_UID, core.ROOT_UID)
    migrated_record["unit_sha256"] = hashlib.sha256(prior_unguarded_unit).hexdigest()
    core._replace_journal(migrated_record, expected_raw=migrated_raw)
    prior = core.JOURNAL.read_bytes()
    launcher = core.LAUNCHER.read_bytes()
    unit = core.UNIT.read_bytes()
    token = core.TOKEN.read_bytes()
    old_source = core.ADAPTER_SOURCE
    monkeypatch.setattr(core, "ADAPTER_SOURCE", old_source.parent.parent / "hermes-installer-core-ccccccccc" / "src")
    monkeypatch.setattr(core, "ADAPTER_UPDATE_BACKUPS", core.JOURNAL.parent / "adapter-update-backups")
    monkeypatch.setattr(core, "_validate_adapter_source_path", lambda: None)
    monkeypatch.setattr(core, "_validate_adapter_generation_path", lambda _path: None)
    monkeypatch.setattr(core, "_owned_listener", lambda **_kwargs: enabled["value"])
    monkeypatch.setattr(core, "_owned_listener_pidfd", lambda **_kwargs: enabled["value"])
    _fake_update_pidfd(monkeypatch, enabled)
    attempts = {"wait": 0}
    def fail_first_restart():
        attempts["wait"] += 1
        if attempts["wait"] == 1:
            raise core.CoreRuntimeError("injected adapter update restart failure")
    monkeypatch.setattr(core, "_wait_for_listener", fail_first_restart)

    with pytest.raises(core.CoreRuntimeError, match="injected adapter update restart failure"):
        core.update_owned_core_adapter()

    assert core.JOURNAL.read_bytes() == prior
    assert core.LAUNCHER.read_bytes() == launcher
    assert core.UNIT.read_bytes() == unit
    assert core.TOKEN.read_bytes() == token
    assert enabled["value"]
    assert attempts["wait"] == 2


@pytest.mark.skipif(os.geteuid() != 0, reason="adapter update needs the real root actor")
def test_interrupted_adapter_update_recovers_from_journaled_generation_backup(tmp_path, monkeypatch):
    _calls, enabled, _old_launcher, _selection = _install_legacy_service_fixture(
        tmp_path, monkeypatch, journal_state="installed")
    core.migrate_owned_core_to_adapter_path()
    migrated_raw = core.JOURNAL.read_bytes()
    migrated_record = json.loads(migrated_raw)
    prior_unguarded_unit = core._unit(startup_guard=False)
    core._atomic_replace(core.UNIT, prior_unguarded_unit, 0o644, core.ROOT_UID, core.ROOT_UID)
    migrated_record["unit_sha256"] = hashlib.sha256(prior_unguarded_unit).hexdigest()
    core._replace_journal(migrated_record, expected_raw=migrated_raw)
    prior = core.JOURNAL.read_bytes()
    launcher = core.LAUNCHER.read_bytes()
    unit = core.UNIT.read_bytes()
    old_source = core.ADAPTER_SOURCE
    monkeypatch.setattr(core, "ADAPTER_SOURCE", old_source.parent.parent / "hermes-installer-core-ddddddddd" / "src")
    monkeypatch.setattr(core, "ADAPTER_UPDATE_BACKUPS", core.JOURNAL.parent / "adapter-update-backups")
    monkeypatch.setattr(core, "_validate_adapter_source_path", lambda: None)
    monkeypatch.setattr(core, "_validate_adapter_generation_path", lambda _path: None)
    monkeypatch.setattr(core, "_owned_listener", lambda **_kwargs: enabled["value"])
    monkeypatch.setattr(core, "_owned_listener_pidfd", lambda **_kwargs: enabled["value"])
    _fake_update_pidfd(monkeypatch, enabled)
    replace_journal = core._replace_journal
    interrupted = {"done": False}
    def interrupt_before_new_journal(record, *, expected_raw=None):
        if (record.get("adapter_source")==str(core.ADAPTER_SOURCE)
                and record.get("adapter_update_state")=="preparing"
                and not interrupted["done"]):
            interrupted["done"] = True
            raise KeyboardInterrupt()
        return replace_journal(record, expected_raw=expected_raw)
    monkeypatch.setattr(core, "_replace_journal", interrupt_before_new_journal)

    with pytest.raises(KeyboardInterrupt):
        core.update_owned_core_adapter()
    interrupted_record = json.loads(core.JOURNAL.read_text())
    assert interrupted_record["adapter_update_state"] == "preparing"
    assert interrupted_record["adapter_source"] == str(old_source)
    assert core.LAUNCHER.read_bytes() != launcher
    assert core.UNIT.read_bytes() != unit
    assert _exec_start_pre(core.UNIT.read_bytes()) != 0

    monkeypatch.setattr(core, "_replace_journal", replace_journal)
    core._recover_interrupted_adapter_update()

    assert core.JOURNAL.read_bytes() == prior
    assert core.LAUNCHER.read_bytes() == launcher
    assert core.UNIT.read_bytes() == unit
    assert enabled["value"]
    assert _exec_start_pre(core.UNIT.read_bytes()) is None  # exact prior unit is guardless


@pytest.mark.skipif(os.geteuid() != 0, reason="adapter update recovery needs the real root actor")
def test_starting_and_partial_rollback_interruption_fail_closed_in_exec_start_pre(tmp_path, monkeypatch):
    _calls, enabled, _old_launcher, _selection = _install_legacy_service_fixture(
        tmp_path, monkeypatch, journal_state="installed")
    core.migrate_owned_core_to_adapter_path()
    migrated_raw = core.JOURNAL.read_bytes()
    migrated = json.loads(migrated_raw)
    prior_unit = core._unit(startup_guard=False)
    core._atomic_replace(core.UNIT, prior_unit, 0o644, core.ROOT_UID, core.ROOT_UID)
    migrated["unit_sha256"] = hashlib.sha256(prior_unit).hexdigest()
    core._replace_journal(migrated, expected_raw=migrated_raw)
    prior = core.JOURNAL.read_bytes()
    prior_launcher = core.LAUNCHER.read_bytes()
    old_source = core.ADAPTER_SOURCE
    monkeypatch.setattr(core, "ADAPTER_SOURCE", old_source.parent.parent / "hermes-installer-core-eeeeeeeee" / "src")
    monkeypatch.setattr(core, "ADAPTER_UPDATE_BACKUPS", core.JOURNAL.parent / "adapter-update-backups")
    monkeypatch.setattr(core, "_validate_adapter_source_path", lambda: None)
    monkeypatch.setattr(core, "_validate_adapter_generation_path", lambda _path: None)
    monkeypatch.setattr(core, "_owned_listener", lambda **_kwargs: enabled["value"])
    monkeypatch.setattr(core, "_owned_listener_pidfd", lambda **_kwargs: enabled["value"])
    _fake_update_pidfd(monkeypatch, enabled)

    real_run = core._run
    def interrupt_after_starting_recipe(argv, check=True):
        if argv == ["systemctl", "start", core.SERVICE]:
            assert _exec_start_pre(core.UNIT.read_bytes()) == 0
            raise KeyboardInterrupt()
        return real_run(argv, check)
    monkeypatch.setattr(core, "_run", interrupt_after_starting_recipe)
    with pytest.raises(KeyboardInterrupt):
        core.update_owned_core_adapter()
    starting = json.loads(core.JOURNAL.read_bytes())
    assert starting["adapter_update_state"] == "starting"
    assert starting["adapter_source"] == str(core.ADAPTER_SOURCE)

    atomic_replace = core._atomic_replace
    def interrupt_after_prior_launcher(path, *args, **kwargs):
        if Path(path) == core.JOURNAL:
            raise KeyboardInterrupt()
        return atomic_replace(path, *args, **kwargs)
    monkeypatch.setattr(core, "_atomic_replace", interrupt_after_prior_launcher)
    with pytest.raises(KeyboardInterrupt):
        core._recover_interrupted_adapter_update()
    assert core.LAUNCHER.read_bytes() == prior_launcher
    assert _exec_start_pre(core.UNIT.read_bytes()) != 0

    monkeypatch.setattr(core, "_atomic_replace", atomic_replace)
    monkeypatch.setattr(core, "_run", real_run)
    core._recover_interrupted_adapter_update()
    assert core.JOURNAL.read_bytes() == prior
    assert core.LAUNCHER.read_bytes() == prior_launcher
    assert core.UNIT.read_bytes() == prior_unit
    assert enabled["value"]


def _adapter_cohort_starting_fixture(tmp_path, monkeypatch):
    """Build the exact on-disk systemd inputs used by the M1 source-start gate."""
    from hermes_installer.remote import obsidian_owner_lifecycle as obsidian

    runtime = tmp_path / "runtime"
    home = tmp_path / "home" / "admin" / ".hermes"
    unit_dir = tmp_path / "etc" / "systemd" / "system"
    libexec = tmp_path / "usr" / "local" / "libexec"
    token_path = tmp_path / "etc" / "hermes-installer" / "session-token"
    for directory in (runtime, home, unit_dir, libexec, token_path.parent,
                      tmp_path / "backups", tmp_path / "overlays"):
        directory.mkdir(parents=True, exist_ok=True)
        directory.chmod(0o700 if directory not in {unit_dir, libexec} else 0o755)
    monkeypatch.setattr(core, "PYTHON", Path(sys.executable))
    monkeypatch.setattr(core, "JOURNAL", runtime / "ownership.json")
    monkeypatch.setattr(core, "RESOURCES_RECORD", runtime / "resources.json")
    monkeypatch.setattr(core, "ADAPTER_UPDATE_COHORT", runtime / "cohort.json")
    monkeypatch.setattr(core, "ADAPTER_UPDATE_BACKUPS", tmp_path / "backups")
    monkeypatch.setattr(core, "RESOURCES_SKILL_OVERLAYS", tmp_path / "overlays")
    monkeypatch.setattr(core, "UNIT", unit_dir / core.SERVICE)
    monkeypatch.setattr(core, "LAUNCHER", libexec / "launcher")
    monkeypatch.setattr(core, "TOKEN", token_path)
    monkeypatch.setattr(obsidian, "OWNER_REGISTRATION", runtime / "obsidian-registration.json")
    token = b"test-session-token\n"
    token_path.write_bytes(token)

    old_source = tmp_path / "adapter-old" / "src"
    new_source = tmp_path / "adapter-new" / "src"
    old_adapter, new_adapter = "a" * 64, "b" * 64
    core_generation = "c" * 64
    artifact_old, artifact_new = "d" * 64, "e" * 64
    old_launcher = core._launcher(adapter_source=old_source)
    new_launcher = core._launcher(adapter_source=new_source)
    old_unit = core._unit(adapter_source=old_source, cohort_gate=True)
    new_unit = core._unit(adapter_source=new_source, cohort_gate=True)
    core.LAUNCHER.write_bytes(new_launcher)
    core.LAUNCHER.chmod(0o755)
    core.UNIT.write_bytes(new_unit)
    core.UNIT.chmod(0o644)
    new_recipe = core._adapter_recipe_sha256(
        str(new_source), new_adapter, hashlib.sha256(new_unit).hexdigest(),
        hashlib.sha256(new_launcher).hexdigest())
    old_recipe = core._adapter_recipe_sha256(
        str(old_source), old_adapter, hashlib.sha256(old_unit).hexdigest(),
        hashlib.sha256(old_launcher).hexdigest())
    token_sha = hashlib.sha256(token).hexdigest()
    backup = {"path": str(core.ADAPTER_UPDATE_BACKUPS / old_adapter),
              "source_generation": old_adapter, "files": {}}
    journal = {
        "schema": 1, "state": "installed", "service": core.SERVICE,
        "adapter_migration_state": "active", "adapter_source": str(new_source),
        "adapter_generation": new_adapter, "core_source_generation": core_generation,
        "plugin_selection_sha256": "f" * 64, "token_sha256": token_sha,
        "unit_sha256": hashlib.sha256(new_unit).hexdigest(),
        "launcher_sha256": hashlib.sha256(new_launcher).hexdigest(),
        "adapter_update_state": "starting", "adapter_update_backup": backup,
        "adapter_update_previous_source": str(old_source),
        "adapter_update_target_source": str(new_source),
        "adapter_update_target_generation": new_adapter,
        "adapter_update_staged_plugin_sha256": "1" * 64,
        "adapter_update_cohort_transaction_id": "2" * 32,
    }
    journal_raw = core._canonical_json(journal)
    core.JOURNAL.write_bytes(journal_raw)
    core.JOURNAL.chmod(0o600)
    resources = {"core_source_generation": core_generation,
                 "core_ownership_sha256": hashlib.sha256(journal_raw).hexdigest(),
                 "artifact_sha256": artifact_new}
    resources_raw = core._canonical_json(resources)
    core.RESOURCES_RECORD.write_bytes(resources_raw)
    core.RESOURCES_RECORD.chmod(0o600)
    old_journal_sha = hashlib.sha256(b"prior-journal\n").hexdigest()
    old_resources_sha = hashlib.sha256(b"prior-resources\n").hexdigest()
    recon = {
        "schema": 1, "purpose": "helper-only-base-reconstruction",
        "cohort_transaction_id": "2" * 32, "owner_uid": 1000,
        "home_role": "jarvis-primary-home", "phase": "source-starting",
        "old_base_artifact_sha256": artifact_old,
        "new_base_artifact_sha256": artifact_new,
        "old_composed_artifact_sha256": artifact_old,
        "new_composed_artifact_sha256": artifact_new,
        "overlay_journal_sha256": core._ABSENT_DIGEST, "overlay_contents": [],
        "base_non_installer_manifest_sha256": "3" * 64,
        "composed_non_installer_manifest_sha256": "3" * 64,
        "materialized_tree_sha256": "4" * 64,
        "old_installed_journal_sha256": "5" * 64,
        "new_installed_journal_sha256": "6" * 64,
        "old_discovery_sha256": old_resources_sha,
        "new_discovery_sha256": hashlib.sha256(resources_raw).hexdigest(),
        "old_core_source_generation": core_generation,
        "new_core_source_generation": core_generation,
        "old_source_recipe_sha256": old_recipe,
        "new_source_recipe_sha256": new_recipe,
    }
    cohort = {
        "schema": 1, "purpose": core._ADAPTER_COHORT_PURPOSE,
        "cohort_transaction_id": "2" * 32, "owner_uid": 1000,
        "home_role": "jarvis-primary-home", "phase": "source-starting",
        "old_source": str(old_source), "new_source": str(new_source),
        "old_adapter_generation": old_adapter, "new_adapter_generation": new_adapter,
        "old_core_source_generation": core_generation,
        "new_core_source_generation": core_generation,
        "old_source_recipe_sha256": old_recipe, "new_source_recipe_sha256": new_recipe,
        "old_unit_sha256": hashlib.sha256(old_unit).hexdigest(),
        "old_launcher_sha256": hashlib.sha256(old_launcher).hexdigest(),
        "new_unit_sha256": hashlib.sha256(new_unit).hexdigest(),
        "new_launcher_sha256": hashlib.sha256(new_launcher).hexdigest(),
        "guarded_old_unit_sha256": hashlib.sha256(old_unit).hexdigest(),
        "guarded_old_recipe_sha256": old_recipe,
        "old_process_identity_sha256": "7" * 64,
        "old_journal_sha256": old_journal_sha,
        "new_journal_sha256": None,
        "old_resources_record_sha256": old_resources_sha,
        "pre_switch_resources_record_sha256": old_resources_sha,
        "starting_journal_sha256": hashlib.sha256(journal_raw).hexdigest(),
        "starting_resources_record_sha256": hashlib.sha256(resources_raw).hexdigest(),
        "new_resources_record_sha256": None,
        "old_artifact_sha256": artifact_old, "new_artifact_sha256": artifact_new,
        "owner_generation_backup_name": ".jarvis-resources-skills-helper-transition-" + "2" * 32,
        "primary_record_sha256": core._ABSENT_DIGEST,
        "obsidian_registration_state": "absent",
        "obsidian_registration_sha256": core._ABSENT_DIGEST,
        "obsidian_vault_tree_sha256": core._ABSENT_DIGEST,
        "reconstruction": recon,
        "reconstruction_sha256": hashlib.sha256(core._canonical_json(recon)).hexdigest(),
    }
    core._write_adapter_update_cohort(cohort, expected_raw=None)
    assert core._read_adapter_update_cohort()[0] == cohort
    return new_unit, cohort, journal_raw, resources_raw


@pytest.mark.skipif(os.geteuid() != 0, reason="ExecStartPre cohort gate requires the enrolled Pi root actor")
def test_m1_boot_gate_admits_only_the_exact_source_starting_journal_and_resources(tmp_path, monkeypatch):
    unit, cohort, journal_raw, resources_raw = _adapter_cohort_starting_fixture(tmp_path, monkeypatch)
    assert _exec_start_pre(unit) == 0

    # A reboot during any incomplete phase must fail closed even when the
    # systemd unit and launcher already contain the new source recipe.
    for phase in ("prepared", "resources-rebound", "rolling-back"):
        changed = dict(cohort)
        changed["phase"] = phase
        changed_reconstruction = dict(changed["reconstruction"])
        changed_reconstruction["phase"] = phase
        changed["reconstruction"] = changed_reconstruction
        changed["reconstruction_sha256"] = hashlib.sha256(
            core._canonical_json(changed_reconstruction)).hexdigest()
        core._atomic_replace(core.ADAPTER_UPDATE_COHORT,
            core._canonical_json(changed), 0o400, core.ROOT_UID, core.ROOT_UID)
        assert _exec_start_pre(unit) != 0
    core._atomic_replace(core.ADAPTER_UPDATE_COHORT,
        core._canonical_json(cohort), 0o400, core.ROOT_UID, core.ROOT_UID)

    core.JOURNAL.write_bytes(b'{"partial":"journal"}\n')
    assert _exec_start_pre(unit) != 0
    core.JOURNAL.write_bytes(journal_raw)
    core.RESOURCES_RECORD.write_bytes(b'{"partial":"resources"}\n')
    assert _exec_start_pre(unit) != 0
    core.RESOURCES_RECORD.write_bytes(resources_raw)
    assert _exec_start_pre(unit) == 0


@pytest.mark.skipif(os.geteuid() != 0, reason="cohort rollback custody requires the enrolled Pi root actor")
def test_m1_rollback_refuses_owner_resources_edit_before_any_restore_effect(tmp_path, monkeypatch):
    _unit, cohort, journal_raw, resources_raw = _adapter_cohort_starting_fixture(tmp_path, monkeypatch)
    prior = {"adapter_source": cohort["old_source"]}
    contents = {
        "journal.json": b"prior-journal\n",
        "resources-record.json": b"prior-resources\n",
        "overlay-record.json": b"",
        "obsidian-registration.json": b"",
        "unit": core._unit(adapter_source=Path(cohort["old_source"]), cohort_gate=True),
        "launcher": core._launcher(adapter_source=Path(cohort["old_source"])),
        "primary-record.json": b"",
    }
    core._check_adapter_cohort_rollback_currentness(cohort, prior, contents)
    original_journal = core.JOURNAL.read_bytes()
    original_unit = core.UNIT.read_bytes()
    original_launcher = core.LAUNCHER.read_bytes()
    core.RESOURCES_RECORD.write_bytes(b"owner edit after source switch\n")
    with pytest.raises(core.CoreRuntimeError, match="outside the exact source cohort"):
        core._check_adapter_cohort_rollback_currentness(cohort, prior, contents)
    assert core.JOURNAL.read_bytes() == original_journal
    assert core.UNIT.read_bytes() == original_unit
    assert core.LAUNCHER.read_bytes() == original_launcher
    assert journal_raw == original_journal
    assert resources_raw != core.RESOURCES_RECORD.read_bytes()


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
    _isolate_resource_import_paths(tmp_path, monkeypatch)
    installer_python = tmp_path / "installer-python"
    interpreter_target = tmp_path / "pm-python-target"
    runuser = tmp_path / "runuser"
    for executable in (interpreter_target, runuser):
        executable.write_text("fixed fixture executable")
        executable.chmod(0o755)
    installer_python.symlink_to(interpreter_target)
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
    assert argv == [str(runuser), "-u", "admin", "--", str(installer_python), "-m",
                    "hermes_installer.registry.manual_jarvis_skills", "import-bundled",
                    "--home", str(core.HERMES_HOME), "--hermes-source", str(core.SOURCE),
                    "--python", str(core.PYTHON)]
    assert kwargs["timeout"] == 600
    assert kwargs["env"]["HOME"] == str(core.HOME)
    assert kwargs["env"]["PYTHONNOUSERSITE"] == "1"
    # Importer output is only an attempt signal; root discovery comes from a
    # fresh independently pinned native-loader readback after import.
    assert receipt == {}


def test_admin_import_prompt_claim_is_discarded_for_independent_root_readback(tmp_path, monkeypatch):
    _isolate_resource_import_paths(tmp_path, monkeypatch)
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

    assert receipt == {}


def test_root_discards_admin_discovery_booleans_and_uses_separate_readback(tmp_path, monkeypatch):
    _isolate_resource_import_paths(tmp_path, monkeypatch)
    runuser = tmp_path / "runuser"
    runuser.write_text("fixed fixture executable")
    runuser.chmod(0o755)
    monkeypatch.setattr(core, "RUNUSER", runuser)
    monkeypatch.setattr(core, "ROOT_UID", os.getuid())
    monkeypatch.setattr(core, "_validated_executable", lambda path, _owners: path)
    receipt = _resource_receipt()
    receipt["functional"] = True
    monkeypatch.setattr(core.subprocess, "run", lambda *args, **kwargs:
                        SimpleNamespace(returncode=0, stdout=json.dumps(receipt), stderr=""))

    assert core._install_bundled_resources(SimpleNamespace(pw_uid=os.getuid())) == {}


def test_discovery_refresh_requires_current_owned_listener_and_never_changes_service(monkeypatch):
    monkeypatch.setattr(core, "ROOT_UID", os.getuid())
    monkeypatch.setattr(core.os, "geteuid", lambda: os.getuid())
    monkeypatch.setattr(core, "_identity", lambda **_kwargs: {"commit": core.COMMIT})
    monkeypatch.setattr(core, "_journal", lambda: {"state": "installed", "source_commit": core.COMMIT})
    repairs=[]
    monkeypatch.setattr(core, "_repair_pinned_pm_directory_modes",
                        lambda identity, record: repairs.append((identity,record)))
    writes = []
    monkeypatch.setattr(core, "_write_resources_discovery", lambda **kwargs: writes.append(kwargs) or {
        "resource_counts": {"native_skills": 396}})
    monkeypatch.setattr(core, "_run", lambda *_args, **_kwargs:
                        (_ for _ in ()).throw(AssertionError("service action is forbidden")))
    verified = "owned isolated service and process-bound loopback listener verified at 127.0.0.1:8766;"
    monkeypatch.setattr(core, "status", lambda: verified)

    result = core.refresh_resources_discovery()

    assert writes == [{"repair_umask_dirs": True}]
    assert repairs == [({"commit": core.COMMIT}, {"state": "installed", "source_commit": core.COMMIT})]
    assert "service lifecycle unchanged" in result


def test_pm_directory_repair_changes_only_exact_0775_held_directory(tmp_path, monkeypatch):
    monkeypatch.setattr(core, "ROOT_UID", os.getuid())
    monkeypatch.setattr(core.os, "geteuid", lambda: os.getuid())
    target = tmp_path / "pm-bin"
    target.mkdir(mode=0o775)
    target.chmod(0o775)
    parent_fd = os.open(tmp_path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    target_fd = os.open(target, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        core._repair_verified_pm_directory_fds(
            {target: target_fd}, {target: parent_fd}, {target: (os.getuid(), os.getgid(), 0o775)})
        assert target.stat().st_mode & 0o777 == 0o755
    finally:
        os.close(target_fd)
        os.close(parent_fd)

    unsafe = tmp_path / "unknown-mode"
    unsafe.mkdir(mode=0o777)
    unsafe.chmod(0o777)
    parent_fd = os.open(tmp_path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    target_fd = os.open(unsafe, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        with pytest.raises(core.CoreRuntimeError, match="changed during metadata repair"):
            core._repair_verified_pm_directory_fds(
                {unsafe: target_fd}, {unsafe: parent_fd}, {unsafe: (os.getuid(), os.getgid(), 0o775)})
        assert unsafe.stat().st_mode & 0o777 == 0o777
    finally:
        os.close(target_fd)
        os.close(parent_fd)


def test_legacy_resources_refresh_requires_pinned_archive_and_identical_materialized_members(
        tmp_path, monkeypatch):
    from hermes_installer.registry import manual_jarvis_skills as native

    archive = b"exact retained legacy artifact fixture"
    digest = hashlib.sha256(archive).hexdigest()
    cas = tmp_path / "cas"
    cas.mkdir(mode=0o700)
    retained = cas / (digest + ".zip")
    retained.write_bytes(archive)
    retained.chmod(0o600)
    old_manifest = {"schema": 1, "source": {"revision": "pinned"},
                    "installer": {"sha256": "old helper"}}
    current_manifest = {**old_manifest, "installer": {"sha256": "new helper"}}
    members = {"skills/example/SKILL.md": b"verified member"}
    monkeypatch.setattr(core, "RESOURCES_CAS", cas)
    monkeypatch.setattr(core, "LEGACY_MATERIALIZED_RESOURCES_ARTIFACT_SHA256", digest)
    monkeypatch.setattr(core, "ROOT_UID", os.getuid())
    monkeypatch.setattr(core, "HERMES_HOME", tmp_path / "home")
    monkeypatch.setattr(core.os, "geteuid", lambda: core.ROOT_UID)
    monkeypatch.setattr(native, "_read_artifact", lambda _archive, _digest:
                        (old_manifest, dict(members)))
    monkeypatch.setattr(native, "_canonical_json", lambda value:
                        json.dumps(value, sort_keys=True, separators=(",", ":")).encode())
    calls = []
    monkeypatch.setattr(core, "_hash_generation_tree", lambda *args, **kwargs:
                        calls.append((args[2], args[3], kwargs)) or "a" * 64)

    result = core._verified_legacy_materialization(native, current_manifest, members,
                                                    repair_umask_dirs=True)

    assert result[0] == archive
    assert result[1] == old_manifest and result[2] == members and result[3] == digest
    assert calls == [(members, digest, {"repair_umask_dirs": True})]
    with pytest.raises(core.CoreRuntimeError, match="byte-compatible"):
        core._verified_legacy_materialization(native, current_manifest,
            {**members, "skills/example/SKILL.md": b"changed"}, repair_umask_dirs=True)
    with pytest.raises(core.CoreRuntimeError, match="not authorized"):
        core._verified_legacy_materialization(native, current_manifest, members,
                                               repair_umask_dirs=False)


def test_root_native_readback_checks_current_loader_results_against_owned_bytes(monkeypatch, tmp_path):
    skills = [f"skill-{index:03d}" for index in range(396)]
    rows = [{"skill_id": name, "archive_path": f"skills/{name}/SKILL.md"} for name in skills]
    files = {row["archive_path"]: f"body-{row['skill_id']}".encode() for row in rows}
    files["registry/profiles/hermes/SOUL.md"] = b"bundled prompt"
    manifest = {"skill_members": rows}
    active_prompt = b"existing active prompt"
    expected_digests = {"profile:default": hashlib.sha256(active_prompt).hexdigest()}
    expected_digests.update({"skill:" + row["skill_id"]: hashlib.sha256(files[row["archive_path"]]).hexdigest()
                             for row in rows})
    payload = {"python_version": "3.14.7", "profile": "default", "skills": skills,
        "loaded": skills, "visible_profiles": ["default"], "profile_display_name": "Default",
        "profile_file_sha256": expected_digests["profile:default"],
        "managed_prompt_block_sha256": None,
        "effective_prompt_contains_managed_block": False,
        "effective_prompt_truncated": False,
        "native_effective_prompt_sha256": expected_digests["profile:default"],
        "native_effective_prompt_chars": len("existing active prompt"),
        "expected_managed_block_sha256": None, "digests": expected_digests}
    monkeypatch.setattr(core.pwd, "getpwnam", lambda _name: SimpleNamespace(
        pw_uid=1000, pw_gid=1000, pw_dir="/home/admin"))
    monkeypatch.setattr(core, "_validated_executable", lambda path, _owners: path)
    monkeypatch.setattr(core, "SOURCE", tmp_path)
    monkeypatch.setattr(core.subprocess, "run", lambda *_args, **_kwargs:
        SimpleNamespace(returncode=0, stdout=json.dumps(payload).encode()))

    receipt = core._root_native_readback(manifest, files, active_prompt)
    assert receipt["loaded_skill_count"] == 396
    assert receipt["active_prompt_matches_bundled_primary"] is False

    # Hermes strips/filters/truncates SOUL text before returning it. The native
    # digest may differ from raw file bytes; the separate raw-file digest binds
    # the loaded profile to the root-verified file without duplicating loader logic.
    payload["digests"]["profile:default"] = "b" * 64
    payload["native_effective_prompt_sha256"] = "b" * 64
    receipt = core._root_native_readback(manifest, files, active_prompt)
    assert receipt["loaded_skill_count"] == 396
    assert receipt["active_primary_prompt_sha256"] == hashlib.sha256(active_prompt).hexdigest()
    assert receipt["native_loaded_primary_prompt_sha256"] == "b" * 64

    payload["loaded"] = skills[:-1]
    with pytest.raises(core.CoreRuntimeError, match="did not match") as error:
        core._root_native_readback(manifest, files, active_prompt)
    assert '"loaded_mismatch"' in str(error.value)
    assert '"loaded_expected_mismatch_count":1' in str(error.value)
    assert "skill-000" not in str(error.value)
    assert active_prompt.decode() not in str(error.value)


def test_missing_resources_projection_is_explicitly_pending(monkeypatch, tmp_path):
    monkeypatch.setattr(core, "RESOURCES_RECORD", tmp_path / "missing.json")
    result = core.read_current_resources_discovery(core_source_generation="d" * 64)

    assert result == {
        "core_version": None, "provider": None, "model": None, "account_state": "unknown",
        "resources_state": "pending", "resource_counts": None, "resources_revision": None,
        "artifact_sha256": None, "discovery_observed_at_utc": None,
        "active_prompt_matches_bundled_primary": None,
    }


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
    assert f"ExecStartPre={core.PYTHON} -I -S -c" in unit
    assert "ExecStartPre=+" not in unit
    assert "LoadCredential=core-ownership-journal:" + str(core.JOURNAL) in unit
    assert "127.0.0.1" not in unit  # listener is fixed in the verified launcher argv
