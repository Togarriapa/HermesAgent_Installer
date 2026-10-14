"""Effect and fail-closed tests for the root-only Pi ingress migration helper.

These tests use in-memory fixed-file/systemd fixtures. They must be run on the
Pi with the candidate test environment; they are not target acceptance.
"""
import base64
import hashlib
import importlib.util
import io
import json
import os
import stat
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest


HELPER_PATH = Path(__file__).resolve().parents[2] / "tools" / "pi_native_core_adopt.py"
_SPEC = importlib.util.spec_from_file_location("pi_native_core_adopt", HELPER_PATH)
adopt = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(adopt)


OLD_SOURCE = b"/opt/hermes-installer-core-aaaaaaaaa/src"
NEW_SOURCE = b"/opt/hermes-installer-core-bbbbbbbbb/src"


def _adapter_refresh_row(*, committed=False):
    names = {"journal.json", "unit", "launcher", "plugin-selection.json",
             "resources-record.json", "overlay-record.json", "primary-record.json",
             "obsidian-registration.json", "cohort.json"}
    reference = None
    transaction = cohort_sha = None
    if committed:
        reference = {
            "path": "/var/lib/hermes-installer/core-runtime/adapter-update-backups/" + "f" * 64,
            "source_generation": "f" * 64,
            "files": {name: "b" * 64 for name in names},
        }
        transaction, cohort_sha = "c" * 32, "d" * 64
    return {
        "schema": 1, "purpose": "adapter-refresh",
        "old_core_journal_sha256": "e" * 64,
        "old_core_adapter_source": OLD_SOURCE.decode(),
        "old_core_adapter_generation": "f" * 64,
        "old_core_source_generation": "1" * 64,
        "old_inspector_process_identity_sha256": "2" * 64,
        "old_observer_state": "verified-owned", "old_observer_device": 10,
        "old_observer_inode": 11,
        "core_update_backup_reference": reference,
        "core_update_cohort_transaction_id": transaction,
        "core_update_cohort_sha256": cohort_sha,
    }


def _unit(module, source=OLD_SOURCE):
    return (b"[Service]\nEnvironment=PYTHONPATH=" + source + b"\n"
            b"ExecStart=/opt/hermes-jarvis-mvp-gateway-venv/bin/python -m hermes_installer.remote."
            + module.encode("ascii") + b"\nUser=root\nGroup=981\n"
            b"RuntimeDirectory=hermes-jarvis-mvp-core\nRuntimeDirectoryMode=0750\n"
            b"ProtectSystem=strict\n")


def test_recovery_resolves_preparing_journal_before_accepting_legacy_listener():
    events = []

    def forbidden_native_journal_read():
        raise AssertionError("legacy path must not read native journal")

    core = SimpleNamespace(
        _journal=forbidden_native_journal_read,
        _recover_interrupted_adapter_migration=lambda: events.append("recover-if-needed"),
        _owned_listener=lambda **kwargs: (events.append("legacy-listener-check")
                                          or kwargs.get("legacy_launcher", False)),
    )

    assert adopt._restore_legacy_core(core)
    assert events == ["recover-if-needed", "legacy-listener-check"]


def test_installed_adapter_rollback_uses_exact_compatibility_recovery(monkeypatch, tmp_path):
    source = tmp_path / "src"
    source.mkdir()
    events = []
    legacy = {"running": False}
    core = SimpleNamespace(
        ADAPTER_SOURCE=source,
        _recover_interrupted_adapter_migration=lambda: events.append("recover-if-needed"),
        _owned_listener=lambda **kwargs: (events.append(
            "legacy-listener" if kwargs.get("legacy_launcher") else "adapter-listener")
            or (legacy["running"] if kwargs.get("legacy_launcher") else not legacy["running"])),
        _journal=lambda: {"state": "installed", "adapter_migration_state": "active"},
        recover_owned_core_from_adapter_migration=lambda: pytest.fail(
            "normal recovery rejects the installed lifecycle state"),
    )
    def recover(_core, expected):
        events.append(("compat-recovery", expected))
        legacy["running"] = True

    monkeypatch.setattr(adopt, "_recover_installed_adapter_to_legacy", recover)

    assert adopt._restore_legacy_core(core, source)
    assert events == ["recover-if-needed", "legacy-listener", "adapter-listener",
                      ("compat-recovery", source), "legacy-listener"]


def test_installed_adapter_rollback_refuses_different_candidate_before_recovery(monkeypatch, tmp_path):
    source = tmp_path / "src"
    source.mkdir()
    other = tmp_path / "other"
    other.mkdir()
    core = SimpleNamespace(ADAPTER_SOURCE=source)
    with pytest.raises(RuntimeError, match="differ"):
        adopt._recover_installed_adapter_to_legacy(core, other)


def _installed_recovery_fixture(monkeypatch, tmp_path, *, foreign_backup=False,
                                selection_already_prior=False, core_running=True,
                                restore_reports_failure=False):
    source = tmp_path / "src"
    source.mkdir()
    backup = tmp_path / "adapter-migration-backup"
    backup.mkdir(mode=0o700)
    for name in ("journal.json", "unit", "launcher", "plugin-selection.json", "manifest.json"):
        (backup / name).write_bytes(b"fixture")

    previous = {"schema": 1, "service": "hermes-jarvis-core.service", "state": "active"}
    unit, launcher = b"legacy unit bytes\n", b"legacy launcher bytes\n"
    token = b"a" * 64 + b"\n"
    previous.update({
        "unit_sha256": hashlib.sha256(unit).hexdigest(),
        "launcher_sha256": hashlib.sha256(launcher).hexdigest(),
        "token_sha256": hashlib.sha256(token).hexdigest(),
    })
    backup_journal = json.dumps(previous, sort_keys=True).encode()
    snapshot = b'{"selected":"legacy"}\n'
    manifest = {"journal.json": hashlib.sha256(backup_journal).hexdigest(),
                "unit": hashlib.sha256(unit).hexdigest(),
                "launcher": hashlib.sha256(launcher).hexdigest(),
                "plugin-selection.json": hashlib.sha256(snapshot).hexdigest()}
    if foreign_backup:
        manifest["unit"] = "0" * 64
    manifest_raw = json.dumps(manifest, sort_keys=True).encode()
    current = {"state": "installed", "adapter_migration_state": "active",
               "adapter_source": str(source), "adapter_generation": "a" * 64,
               "core_source_generation": "b" * 64, "plugin_selection_sha256": "c" * 64,
               "adapter_migration_backup": manifest}
    protected = {backup / "manifest.json": manifest_raw,
                 backup / "journal.json": backup_journal,
                 backup / "unit": unit, backup / "launcher": launcher,
                 backup / "plugin-selection.json": snapshot,
                 tmp_path / "token": token}
    events = []
    old_files = {"unit": unit, "launcher": launcher}
    adapter_files = {"unit": b"adapter unit", "launcher": b"adapter launcher"}
    state = {"adapter_running": core_running,
             "selection": "d" * 64 if selection_already_prior else "c" * 64,
             "selection_prior": selection_already_prior,
             "files": adapter_files.copy(), "loaded_files": adapter_files.copy()}
    monkeypatch.setattr(adopt.Path, "resolve", lambda path, strict=False: path)
    real_listdir = adopt.os.listdir
    monkeypatch.setattr(adopt.os, "listdir", lambda path: [
        "journal.json", "unit", "launcher", "plugin-selection.json", "manifest.json"]
        if path == backup else real_listdir(path))
    real_lstat = adopt.Path.lstat
    monkeypatch.setattr(adopt.Path, "lstat", lambda path: SimpleNamespace(
        st_mode=stat.S_IFDIR | 0o700, st_uid=0, st_gid=0) if path == backup else real_lstat(path))

    def projection(path, **kwargs):
        assert kwargs["owner"] == 0
        assert kwargs["group"] == (981 if path == tmp_path / "token" else 0)
        assert kwargs["mode"] == (0o640 if path == tmp_path / "token" else 0o600)
        return protected[path]

    class Selection:
        @property
        def selection_sha256(self):
            return state["selection"]

    def run(args, check=True):
        events.append(tuple(args))
        if args[1:] == ["stop", "hermes-jarvis-core.service"]:
            state["adapter_running"] = False
        elif args[1:] == ["daemon-reload"]:
            state["loaded_files"] = state["files"].copy()
        elif args[1:] == ["start", "hermes-jarvis-core.service"]:
            state["adapter_running"] = True
        if args[1:3] == ["is-active", "hermes-jarvis-core.service"]:
            return SimpleNamespace(stdout="active\n" if state["adapter_running"] else "inactive\n")
        if args[1:3] == ["show", "--property=MainPID"]:
            return SimpleNamespace(stdout="123\n" if state["adapter_running"] else "0\n")
        return SimpleNamespace(stdout="")

    def read_legacy():
        events.append("readback-legacy")
        assert state["adapter_running"]
        assert state["files"] == state["loaded_files"] == old_files
        return previous, backup_journal, state["files"].copy()

    def owned_listener(*, legacy_launcher=False):
        kind = "legacy" if legacy_launcher else "adapter"
        events.append(("listener", kind))
        expected_files = old_files if legacy_launcher else adapter_files
        return (state["adapter_running"]
                and state["loaded_files"] == expected_files)

    def restore_backup():
        events.append("restore-backup")
        state["files"].update(old_files)
        state["adapter_running"] = False

    core = SimpleNamespace(
        ADAPTER_SOURCE=source, ADAPTER_MIGRATION_BACKUP=backup, TOKEN=tmp_path / "token",
        GATEWAY_GID=981, SERVICE="hermes-jarvis-core.service", UNIT="unit", LAUNCHER="launcher",
        _journal=lambda: current,
        _owned_unit_loaded=lambda: (events.append(("unit-loaded", state["loaded_files"].copy()))
                                    or state["loaded_files"] == state["files"]),
        _owned_listener=owned_listener,
        _core_source_generation=lambda: "b" * 64,
        _projection_file=projection, _unit=lambda: unit, _legacy_launcher=lambda: launcher,
        _run=run,
        _restore_adapter_migration_backup=restore_backup,
        _read_legacy_owned_runtime=read_legacy,
    )
    inspector = ModuleType("hermes_installer.remote.core_gateway_inspector")
    inspector._current_native_adapter_generation = lambda **_kwargs: "a" * 64
    inspector.verify_staged_native_resources_plugin = lambda **_kwargs: True
    bootstrap = ModuleType("hermes_installer.remote.native_plugin_bootstrap")
    def restore_selection(snapshot_bytes, *, expected_current_sha256):
        events.append("restore-plugin-selection")
        assert snapshot_bytes == snapshot and expected_current_sha256 == "c" * 64
        state["selection"] = "d" * 64
        state["selection_prior"] = True
        if restore_reports_failure:
            raise RuntimeError("fixed Hermes command printed status before success marker")
        return "d" * 64

    def capture_selection():
        events.append("capture-selection")
        return SimpleNamespace(
            snapshot_json=snapshot if state["selection_prior"] else b'{"selected":"migrated"}\n',
            prior_selection_sha256=state["selection"],
            migrated_selection_sha256="c" * 64,
        )

    bootstrap.capture_native_resources_plugin_selection = capture_selection
    bootstrap.restore_native_resources_plugin_selection = restore_selection
    package = ModuleType("hermes_installer")
    package.__path__ = []
    remote = ModuleType("hermes_installer.remote")
    remote.__path__ = []
    remote.core_gateway_inspector = inspector
    remote.native_plugin_bootstrap = bootstrap
    monkeypatch.setitem(sys.modules, package.__name__, package)
    monkeypatch.setitem(sys.modules, remote.__name__, remote)
    monkeypatch.setitem(sys.modules, inspector.__name__, inspector)
    monkeypatch.setitem(sys.modules, bootstrap.__name__, bootstrap)
    return core, source, events, state


def test_installed_adapter_recovery_restores_verified_legacy_backup_in_order(monkeypatch, tmp_path):
    core, source, events, state = _installed_recovery_fixture(monkeypatch, tmp_path)

    adopt._recover_installed_adapter_to_legacy(core, source)

    stop = events.index(("systemctl", "stop", core.SERVICE))
    plugin_restore = events.index("restore-plugin-selection")
    restore = events.index("restore-backup")
    start = events.index(("systemctl", "start", core.SERVICE))
    readback = events.index("readback-legacy")
    assert stop < plugin_restore < restore < start < readback
    assert state["adapter_running"]
    assert state["selection"] == "d" * 64
    assert state["files"] == {"unit": b"legacy unit bytes\n",
                               "launcher": b"legacy launcher bytes\n"}


def test_interrupted_stopped_recovery_accepts_exact_prior_selection_without_reenabling(
        monkeypatch, tmp_path):
    core, source, events, state = _installed_recovery_fixture(
        monkeypatch, tmp_path, selection_already_prior=True, core_running=False)

    adopt._recover_installed_adapter_to_legacy(core, source)

    assert "restore-plugin-selection" not in events
    assert events.index("capture-selection") < events.index("restore-backup")
    assert events.index("restore-backup") < events.index(("systemctl", "start", core.SERVICE))
    assert state["adapter_running"]
    assert state["selection"] == "d" * 64


def test_recovery_accepts_restore_cli_noise_only_after_exact_snapshot_readback(
        monkeypatch, tmp_path):
    core, source, events, state = _installed_recovery_fixture(
        monkeypatch, tmp_path, restore_reports_failure=True)

    adopt._recover_installed_adapter_to_legacy(core, source)

    assert "restore-plugin-selection" in events
    assert events.count("capture-selection") == 3
    assert state["adapter_running"]


def test_installed_adapter_recovery_rejects_foreign_backup_before_stopping_core(
        monkeypatch, tmp_path):
    core, source, events, _state = _installed_recovery_fixture(
        monkeypatch, tmp_path, foreign_backup=True)

    with pytest.raises(RuntimeError, match="backup bytes differ"):
        adopt._recover_installed_adapter_to_legacy(core, source)

    assert not any(event == ("systemctl", "stop", core.SERVICE) for event in events)


def _switch_fixture(monkeypatch, *, gateway=None, inspector=None, config=None,
                    installed=True):
    gateway = gateway if gateway is not None else _unit("core_gateway")
    inspector = inspector if inspector is not None else _unit("core_gateway_inspector")
    config = config if config is not None else json.dumps({
        "gateway_unit_sha256": hashlib.sha256(gateway).hexdigest(),
        "provider": "codex", "credential_ref": "keyring:codex-primary",
        "selected_data_root": "/home/admin/.hermes", "port": 8766,
    }, sort_keys=True).encode() + b"\n"
    monkeypatch.setattr(adopt, "_unit_is_exact_and_active", lambda _name: True)
    monkeypatch.setattr(adopt, "_verify_inspector_process", lambda *_args: None)
    monkeypatch.setattr(adopt, "_verify_installed_source",
                        lambda _source: None if installed else
                        (_ for _ in ()).throw(RuntimeError("unowned source")))
    monkeypatch.setattr(adopt, "_unit_state", lambda _name: "active")
    def file_info(raw, *, gid, mode, inode):
        return SimpleNamespace(st_mode=stat.S_IFREG | mode, st_uid=0, st_gid=gid,
                               st_dev=1, st_ino=inode, st_size=len(raw), st_mtime_ns=1)

    fixed = {
        adopt.FIXED_UNITS[adopt.GATEWAY]: (gateway, file_info(gateway, gid=0, mode=0o644, inode=1)),
        adopt.FIXED_UNITS[adopt.INSPECTOR]: (inspector, file_info(inspector, gid=0, mode=0o644, inode=2)),
        adopt.GATEWAY_CONFIG: (config, file_info(config, gid=981, mode=0o440, inode=3)),
    }
    monkeypatch.setattr(adopt, "_read_fixed", lambda path, **_kwargs: fixed[path])
    effects = []
    monkeypatch.setattr(adopt, "_run", lambda *args, **_kwargs: effects.append(args) or "")
    return fixed, effects, gateway, inspector, config


@pytest.mark.parametrize("drift", ["gateway-bytes", "config-inode"])
def test_ingress_drift_after_intake_refuses_before_any_stop_or_write(monkeypatch, drift):
    fixed, effects, gateway, inspector, old_config = _switch_fixture(monkeypatch)
    saved, config_raw, config_info, new_units, new_config = adopt._source_switch(
        Path(NEW_SOURCE.decode()))
    writes = []
    monkeypatch.setattr(adopt, "_atomic_fixed", lambda *args, **kwargs: writes.append(args))
    monkeypatch.setattr(adopt, "_unit_is_fixed", lambda _name: True)

    if drift == "gateway-bytes":
        path = adopt.FIXED_UNITS[adopt.GATEWAY]
        raw, info = fixed[path]
        changed = raw + b"# external replacement\n"
        fixed[path] = (changed, SimpleNamespace(**{
            **vars(info), "st_size": len(changed), "st_ino": info.st_ino + 10}))
    else:
        path = adopt.GATEWAY_CONFIG
        raw, info = fixed[path]
        fixed[path] = (raw, SimpleNamespace(**{**vars(info), "st_ino": info.st_ino + 10}))

    with pytest.raises(RuntimeError, match="changed after the adoption snapshot"):
        adopt._replace_ingress_units(new_units, new_config, config_info, saved, config_raw)

    assert effects == []
    assert writes == []
    assert fixed[adopt.FIXED_UNITS[adopt.INSPECTOR]][0] == inspector


def test_ingress_drift_after_union_intake_refuses_before_backup_effect(monkeypatch):
    gateway = _unit("core_gateway")
    old_config = json.dumps({
        "gateway_unit_sha256": hashlib.sha256(gateway).hexdigest(),
        "provider": "codex", "credential_ref": "keyring:codex-primary",
        "selected_data_root": "/home/admin/.hermes", "port": 8766,
        "allowed_emails": ["old@example.com"],
    }, sort_keys=True).encode() + b"\n"
    fixed, effects, _gateway, inspector, _old_config = _switch_fixture(
        monkeypatch, gateway=gateway, config=old_config)
    monkeypatch.setattr(adopt.os, "geteuid", lambda: 0)
    monkeypatch.setattr(adopt, "_read_approved_email_union",
                        lambda: ("old@example.com", "new@example.com"))
    saved, config_raw, config_info, _new_units, _new_config = adopt._source_switch(
        Path(NEW_SOURCE.decode()), read_approved_email_union=True)
    writes = []
    path = adopt.FIXED_UNITS[adopt.INSPECTOR]
    raw, info = fixed[path]
    fixed[path] = (raw + b"# changed after intake\n", SimpleNamespace(
        **{**vars(info), "st_size": len(raw) + len(b"# changed after intake\n"),
           "st_ino": info.st_ino + 1}))
    monkeypatch.setattr(adopt, "_save_ingress_backup", lambda *_args: writes.append("backup"))

    with pytest.raises(RuntimeError, match="changed after the adoption snapshot"):
        adopt._recheck_ingress_snapshot(saved, config_raw, config_info)

    assert writes == []
    assert effects == []
    assert fixed[adopt.FIXED_UNITS[adopt.INSPECTOR]][0] != inspector


def test_switch_changes_only_two_import_roots_and_gateway_digest(monkeypatch):
    _fixed, _effects, gateway, inspector, old_config = _switch_fixture(monkeypatch)

    saved, config_raw, _info, new_units, new_config = adopt._source_switch(
        Path(NEW_SOURCE.decode()))

    expected_gateway = gateway.replace(OLD_SOURCE, NEW_SOURCE, 1)
    expected_inspector = inspector.replace(OLD_SOURCE, NEW_SOURCE, 1)
    assert new_units[adopt.FIXED_UNITS[adopt.GATEWAY]] == expected_gateway
    assert new_units[adopt.FIXED_UNITS[adopt.INSPECTOR]] == expected_inspector
    assert saved[adopt.FIXED_UNITS[adopt.GATEWAY]][0] == gateway
    assert saved[adopt.FIXED_UNITS[adopt.INSPECTOR]][0] == inspector
    assert config_raw == old_config

    before = json.loads(old_config)
    after = json.loads(new_config)
    assert after == {
        **before,
        "gateway_unit_sha256": hashlib.sha256(expected_gateway).hexdigest(),
    }
    assert after["credential_ref"] == "keyring:codex-primary"
    assert after["selected_data_root"] == "/home/admin/.hermes"


def test_approved_email_union_is_bounded_normalized_and_only_changes_new_config(monkeypatch):
    old_gateway = _unit("core_gateway")
    prior_config = json.dumps({
        "gateway_unit_sha256": hashlib.sha256(old_gateway).hexdigest(),
        "allowed_emails": ["Owner@example.test"],
        "credential_ref": "keyring:codex-primary",
        "selected_data_root": "/home/admin/.hermes",
    }, sort_keys=True).encode() + b"\n"
    fixed, effects, gateway, inspector, _ = _switch_fixture(monkeypatch, config=prior_config)
    payload = b'[" Owner@example.test ","Second@example.test","third@example.test"]'
    monkeypatch.setattr(adopt.sys, "stdin", SimpleNamespace(buffer=io.BytesIO(payload)))

    saved, old_bytes, _info, new_units, new_bytes = adopt._source_switch(
        Path(NEW_SOURCE.decode()), read_approved_email_union=True)

    expected_gateway = gateway.replace(OLD_SOURCE, NEW_SOURCE, 1)
    expected_inspector = inspector.replace(OLD_SOURCE, NEW_SOURCE, 1)
    assert old_bytes == prior_config
    assert saved[adopt.FIXED_UNITS[adopt.GATEWAY]][0] == gateway
    assert new_units[adopt.FIXED_UNITS[adopt.GATEWAY]] == expected_gateway
    assert new_units[adopt.FIXED_UNITS[adopt.INSPECTOR]] == expected_inspector
    assert json.loads(new_bytes)["allowed_emails"] == [
        "owner@example.test", "second@example.test", "third@example.test"]
    assert fixed[adopt.GATEWAY_CONFIG][0] == prior_config
    assert effects == []


@pytest.mark.parametrize("payload", [
    b'{"allowed_emails":["owner@example.test"]}',
    b'["other@example.test"]',
    b'["owner@example.test"," OWNER@example.test "]',
    b'["not-an-email"]',
    b'["owner@example.test"] trailing',
    b'["owner@example.test"]' + b" " * adopt._APPROVED_EMAIL_UNION_MAX_BYTES,
])
def test_invalid_approved_email_union_refuses_before_any_system_effect(monkeypatch, payload):
    old_gateway = _unit("core_gateway")
    prior_config = json.dumps({
        "gateway_unit_sha256": hashlib.sha256(old_gateway).hexdigest(),
        "allowed_emails": ["owner@example.test"],
        "credential_ref": "keyring:codex-primary",
    }).encode() + b"\n"
    fixed, effects, gateway, inspector, _ = _switch_fixture(monkeypatch, config=prior_config)
    monkeypatch.setattr(adopt.sys, "stdin", SimpleNamespace(buffer=io.BytesIO(payload)))

    with pytest.raises(RuntimeError, match="approved email union") as error:
        adopt._source_switch(Path(NEW_SOURCE.decode()), read_approved_email_union=True)

    assert "owner@example.test" not in str(error.value)
    assert effects == []
    assert fixed[adopt.FIXED_UNITS[adopt.GATEWAY]][0] == gateway
    assert fixed[adopt.FIXED_UNITS[adopt.INSPECTOR]][0] == inspector
    assert fixed[adopt.GATEWAY_CONFIG][0] == prior_config


def test_source_switch_without_union_keeps_existing_email_bytes_and_does_not_read_stdin(monkeypatch):
    old_gateway = _unit("core_gateway")
    prior_config = json.dumps({
        "gateway_unit_sha256": hashlib.sha256(old_gateway).hexdigest(),
        "allowed_emails": ["Owner@example.test"],
        "credential_ref": "keyring:codex-primary",
    }).encode() + b"\n"
    _fixed, _effects, _gateway, _inspector, _ = _switch_fixture(monkeypatch, config=prior_config)

    class NoRead:
        def read(self, _limit):
            pytest.fail("the no-union lane must not consume stdin")

    monkeypatch.setattr(adopt.sys, "stdin", SimpleNamespace(buffer=NoRead()))
    _saved, old_bytes, _info, _new_units, new_bytes = adopt._source_switch(
        Path(NEW_SOURCE.decode()))

    assert old_bytes == prior_config
    assert json.loads(new_bytes)["allowed_emails"] == ["Owner@example.test"]


def test_backup_persists_exact_prospective_config_and_original_config(tmp_path, monkeypatch):
    parent = tmp_path / "protected"
    parent.mkdir(mode=0o700)
    parent.chmod(0o700)
    monkeypatch.setattr(adopt, "INGRESS_BACKUP", parent / "backup.json")
    gateway, inspector = _unit("core_gateway"), _unit("core_gateway_inspector")
    config = b'{"allowed_emails":["owner@example.test"]}\n'
    new_config = b'{"allowed_emails":["owner@example.test","second@example.test"],"gateway_unit_sha256":"' + b"a" * 64 + b'"}\n'
    saved = {adopt.FIXED_UNITS[adopt.GATEWAY]: (gateway, None),
             adopt.FIXED_UNITS[adopt.INSPECTOR]: (inspector, None)}
    units = {adopt.FIXED_UNITS[adopt.GATEWAY]: gateway + b"candidate\n",
             adopt.FIXED_UNITS[adopt.INSPECTOR]: inspector + b"candidate\n"}
    info = SimpleNamespace(st_mode=stat.S_IFREG | 0o440, st_gid=981)

    row = _adapter_refresh_row()
    adopt._save_ingress_backup("a" * 40, saved, config, info, units, new_config,
                               adapter_refresh=row)
    value = json.loads((parent / "backup.json").read_bytes())

    assert base64.b64decode(value["gateway_config"]) == config
    assert base64.b64decode(value["new_gateway_config"]) == new_config
    assert value["new_config_sha256"] == hashlib.sha256(new_config).hexdigest()
    assert value["adapter_refresh"] == row


def test_adapter_refresh_row_is_closed_and_core_join_is_all_or_none():
    row = _adapter_refresh_row()
    assert adopt._valid_adapter_refresh_row(row)
    row["core_update_cohort_sha256"] = "d" * 64
    assert not adopt._valid_adapter_refresh_row(row)
    row = _adapter_refresh_row(committed=True)
    assert adopt._valid_adapter_refresh_row(row)
    row["old_observer_inode"] = True
    assert not adopt._valid_adapter_refresh_row(row)


def test_adapter_refresh_join_accepts_eleven_members_only_for_actual_core_transition(
        monkeypatch):
    old_plugin = {"plugin.yaml": b"fixed manifest", "__init__.py": b"old module"}
    new_plugin = {"plugin.yaml": b"fixed manifest", "__init__.py": b"new module"}
    old_hashes = {name: hashlib.sha256(data).hexdigest()
                  for name, data in old_plugin.items()}
    new_hashes = {name: hashlib.sha256(data).hexdigest()
                  for name, data in new_plugin.items()}
    transition = {
        "schema": 1, "purpose": "fixed-native-resources-plugin",
        "old_adapter_generation": "f" * 64, "new_adapter_generation": "9" * 64,
        "plugin_selection_sha256": "c" * 64,
        "old_members": old_hashes, "new_members": new_hashes,
    }
    previous = {
        "adapter_generation": "f" * 64, "adapter_source": OLD_SOURCE.decode(),
        "core_source_generation": "1" * 64, "plugin_selection_sha256": "c" * 64,
    }
    previous_raw = (json.dumps(previous, sort_keys=True, separators=(",", ":")) + "\n").encode()
    row = _adapter_refresh_row()
    row["old_core_journal_sha256"] = hashlib.sha256(previous_raw).hexdigest()
    current = {
        "adapter_generation": "9" * 64, "adapter_source": NEW_SOURCE.decode(),
        "core_source_generation": "1" * 64, "plugin_selection_sha256": "c" * 64,
        "adapter_migration_state": "active", "adapter_update_state": "active",
        "adapter_update_previous_source": OLD_SOURCE.decode(),
        "adapter_update_cohort_transaction_id": "a" * 32,
    }
    cohort = {
        "cohort_transaction_id": "a" * 32, "phase": "committed",
        "old_source": OLD_SOURCE.decode(), "new_source": NEW_SOURCE.decode(),
        "old_adapter_generation": "f" * 64, "new_adapter_generation": "9" * 64,
        "old_core_source_generation": "1" * 64, "new_core_source_generation": "1" * 64,
        "native_plugin_transition": transition,
    }
    contents = {name: name.encode() for name in adopt._ADAPTER_BACKUP_BASE_MEMBERS}
    contents["journal.json"] = previous_raw
    contents["plugin-selection.json"] = (
        b'{"schema":1,"selection_sha256":"' + b"c" * 64 + b'"}\n')
    for name, backup_name in adopt._NATIVE_PLUGIN_BACKUP_NAMES.items():
        contents[backup_name] = old_plugin[name]
    reference = {
        "path": "/var/lib/hermes-installer/core-runtime/adapter-update-backups/" + "f" * 64,
        "source_generation": "f" * 64,
        "files": {name: hashlib.sha256(data).hexdigest()
                  for name, data in contents.items()},
    }
    cohort_raw = (json.dumps(cohort, sort_keys=True, separators=(",", ":")) + "\n").encode()

    class Core:
        @staticmethod
        def _read_active_adapter_runtime():
            return current, b"current journal", {}

        @staticmethod
        def _read_adapter_update_cohort():
            return cohort, cohort_raw

        @staticmethod
        def _adapter_update_backup_reference(_cohort):
            return reference

        @staticmethod
        def _read_adapter_update_backup(_reference):
            return previous, contents

        @staticmethod
        def _read_installed_native_resources_plugin_members():
            return SimpleNamespace(members=new_plugin)

    ingress = {
        "candidate_sha": "b" * 40, "state": "units-switched",
        "adapter_refresh": row,
    }
    ingress_raw = (json.dumps(ingress, sort_keys=True, separators=(",", ":")) + "\n").encode()
    writes = []
    monkeypatch.setattr(adopt, "_read_fixed", lambda *_args, **_kwargs: (
        ingress_raw, SimpleNamespace(st_mode=stat.S_IFREG | 0o600)))
    monkeypatch.setattr(adopt, "_atomic_fixed", lambda _path, raw, **_kwargs: writes.append(raw))

    result = adopt._set_adapter_refresh_core_join(
        Core(), "b" * 40, reference, cohort["cohort_transaction_id"],
        hashlib.sha256(cohort_raw).hexdigest())
    assert adopt._valid_adapter_refresh_row(result)
    assert result["core_update_backup_reference"] == reference
    assert json.loads(writes[0])["adapter_refresh"]["core_update_cohort_sha256"] == (
        hashlib.sha256(cohort_raw).hexdigest())
    joined = adopt._verify_current_adapter_refresh_join(Core(), result)
    assert joined[2] == reference

    writes.clear()
    bad_transition = {**transition, "old_members": {
        **old_hashes, "__init__.py": "e" * 64}}
    cohort["native_plugin_transition"] = bad_transition
    cohort_raw = (json.dumps(cohort, sort_keys=True, separators=(",", ":")) + "\n").encode()
    with pytest.raises(RuntimeError, match="join is not current"):
        adopt._set_adapter_refresh_core_join(
            Core(), "b" * 40, reference, cohort["cohort_transaction_id"],
            hashlib.sha256(cohort_raw).hexdigest())
    assert writes == []

    malformed = _adapter_refresh_row(committed=True)
    malformed["core_update_backup_reference"]["files"]["arbitrary.py"] = "a" * 64
    assert not adopt._valid_adapter_refresh_row(malformed)


def test_adapter_refresh_switch_stops_exact_old_peer_before_fixed_file_writes(
        monkeypatch, tmp_path):
    old_gateway = _unit("core_gateway")
    old_inspector = _unit("core_gateway_inspector")
    new_gateway = old_gateway.replace(OLD_SOURCE, NEW_SOURCE)
    new_inspector = old_inspector.replace(OLD_SOURCE, NEW_SOURCE)
    config = b'{"allowed_emails":["owner@example.test"]}\n'
    new_config = b'{"allowed_emails":["owner@example.test"],"new":true}\n'
    gateway_path = tmp_path / "gateway.service"
    inspector_path = tmp_path / "inspector.service"
    tunnel_path = tmp_path / "tunnel.service"
    config_path = tmp_path / "config.json"
    for path, raw, mode in (
            (gateway_path, old_gateway, 0o644), (inspector_path, old_inspector, 0o644),
            (tunnel_path, b"tunnel\n", 0o644), (config_path, config, 0o440)):
        path.write_bytes(raw)
        path.chmod(mode)
    paths = {adopt.GATEWAY: gateway_path, adopt.INSPECTOR: inspector_path,
             adopt.TUNNEL: tunnel_path}
    monkeypatch.setattr(adopt, "FIXED_UNITS", paths)
    monkeypatch.setattr(adopt, "GATEWAY_CONFIG", config_path)
    monkeypatch.setattr(adopt, "_unit_is_fixed", lambda _name: True)
    events = []
    monkeypatch.setattr(adopt, "_recheck_ingress_snapshot",
                        lambda *_args: events.append("last-old-tuple-cas"))

    def run(*args, **_kwargs):
        # `_run` receives the executable name as argv[0] already.
        events.append(tuple(args))
        return ""

    monkeypatch.setattr(adopt, "_run", run)
    monkeypatch.setattr(adopt, "_stop_captured_inspector",
                        lambda _custody: events.append("stop-held-inspector-and-retire-socket"))
    saved = {gateway_path: (old_gateway, None), inspector_path: (old_inspector, None)}
    custody = {"pidfd": -1}
    new_units = {gateway_path: new_gateway, inspector_path: new_inspector}
    adopt._replace_ingress_units_for_adapter_refresh(
        new_units, new_config, config_path.stat(), saved, config, custody)

    assert gateway_path.read_bytes() == new_gateway
    assert inspector_path.read_bytes() == new_inspector
    assert config_path.read_bytes() == new_config
    cas_index = events.index("last-old-tuple-cas")
    stop_tunnel_index = events.index(("systemctl", "stop", adopt.TUNNEL))
    stop_gateway_index = events.index(("systemctl", "stop", adopt.GATEWAY))
    stop_inspector_index = events.index("stop-held-inspector-and-retire-socket")
    reload_index = events.index(("systemctl", "daemon-reload"))
    assert cas_index < stop_tunnel_index < stop_gateway_index < stop_inspector_index < reload_index
    assert not any(event[1] == "start" for event in events if isinstance(event, tuple))


def test_adapter_refresh_accepts_old_observer_clean_unlink_after_held_process_exit(
        monkeypatch, tmp_path):
    pid = adopt.os.getpid()
    invocation = "a" * 32
    source = OLD_SOURCE
    unit = _unit("core_gateway_inspector")
    boot_id = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    cgroup = (Path("/proc") / str(pid) / "cgroup").read_text().splitlines()
    identity = {
        "pid": pid, "start_ticks": 123, "boot_id": boot_id,
        "invocation_id": invocation, "source": source.decode(),
        "unit_sha256": hashlib.sha256(unit).hexdigest(),
        "executable": adopt.os.readlink(Path("/proc") / str(pid) / "exe"),
        "cgroup": cgroup,
    }
    observer = tmp_path / "native-observer.sock"
    parent_identity = (101, 202)
    real_lstat = Path.lstat

    def lstat(path):
        if path == observer.parent:
            return SimpleNamespace(st_mode=stat.S_IFDIR | 0o750, st_uid=0, st_gid=1000,
                                   st_dev=parent_identity[0], st_ino=parent_identity[1])
        return real_lstat(path)

    monkeypatch.setattr(Path, "lstat", lstat)
    monkeypatch.setattr(adopt, "_verify_inspector_process", lambda *_args: None)
    monkeypatch.setattr(adopt, "_proc_start_ticks", lambda _pid: 123)
    monkeypatch.setattr(adopt, "_unit_state", lambda _name: "inactive")
    stopped = {"value": False}

    def run(*args, **kwargs):
        if args[1:3] == ("show", "--property=MainPID"):
            return "0" if stopped["value"] else str(pid)
        if args[1:3] == ("show", "--property=InvocationID"):
            return invocation
        if args[1:] == ("stop", adopt.INSPECTOR):
            stopped["value"] = True
        return ""

    class Poller:
        def __init__(self):
            self.stopped = False

        def register(self, *_args):
            return None

        def poll(self, timeout=0):
            if timeout == 30_000:
                self.stopped = True
            return [(1, 1)] if self.stopped else []

    monkeypatch.setattr(adopt, "_run", run)
    monkeypatch.setattr(adopt.select, "poll", Poller)
    custody = {
        "pidfd": 7, "pid": pid, "start_ticks": 123, "boot_id": boot_id,
        "invocation_id": invocation, "identity": identity,
        "observer_socket": observer, "observer_state": "verified-owned",
        "observer_device": 303, "observer_inode": 404,
        "observer_parent_identity": parent_identity, "unit_raw": unit,
        "source": source,
    }

    adopt._stop_captured_inspector(custody)

    assert stopped["value"] is True
    assert not observer.exists()
    observer.write_bytes(b"replacement path")
    stopped["value"] = False
    with pytest.raises(RuntimeError, match="socket changed"):
        adopt._stop_captured_inspector(custody)
    assert observer.read_bytes() == b"replacement path"


def test_adapter_refresh_pre_effect_failure_preserves_live_ingress(monkeypatch, tmp_path):
    paths = {
        adopt.GATEWAY: tmp_path / "gateway.service",
        adopt.INSPECTOR: tmp_path / "inspector.service",
        adopt.TUNNEL: tmp_path / "tunnel.service",
    }
    config_path = tmp_path / "gateway.json"
    monkeypatch.setattr(adopt, "FIXED_UNITS", paths)
    monkeypatch.setattr(adopt, "GATEWAY_CONFIG", config_path)
    old_gateway = _unit("core_gateway")
    old_inspector = _unit("core_gateway_inspector")
    new_gateway = old_gateway.replace(OLD_SOURCE, NEW_SOURCE)
    new_inspector = old_inspector.replace(OLD_SOURCE, NEW_SOURCE)
    old_config = b'{"allowed_emails":["owner@example.test"]}\n'
    new_config = b'{"allowed_emails":["owner@example.test","next@example.test"]}\n'
    saved = {paths[adopt.GATEWAY]: (old_gateway, None),
             paths[adopt.INSPECTOR]: (old_inspector, None)}
    new_units = {paths[adopt.GATEWAY]: new_gateway,
                 paths[adopt.INSPECTOR]: new_inspector}
    config_info = SimpleNamespace(st_mode=stat.S_IFREG | 0o440, st_gid=981)
    custody = {"pidfd": adopt.os.open("/dev/null", adopt.os.O_RDONLY),
               "row": _adapter_refresh_row(),
               "identity": {"unit_sha256": hashlib.sha256(old_inspector).hexdigest()}}
    events = []

    class GatewayConfig:
        @staticmethod
        def load(**_kwargs):
            return object()

    gateway_module = ModuleType("hermes_installer.remote.core_gateway")
    gateway_module.CoreGatewayConfig = GatewayConfig
    monkeypatch.setitem(sys.modules, "hermes_installer.remote.core_gateway", gateway_module)
    monkeypatch.setattr(adopt, "_adapter_refresh_snapshot", lambda *_args: (
        {"adapter_source": OLD_SOURCE.decode()}, b"old core journal", {}, {}, custody))
    monkeypatch.setattr(adopt, "_verify_gateway_tunnel", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(adopt, "_source_switch", lambda *_args, **_kwargs:
                        (saved, old_config, config_info, new_units, new_config))
    monkeypatch.setattr(adopt, "_save_ingress_backup", lambda *_args, **_kwargs:
                        events.append("backup"))
    monkeypatch.setattr(adopt, "_set_backup_state", lambda *_args, **_kwargs:
                        events.append("journal-state"))
    monkeypatch.setattr(adopt, "_set_runtime_inspector_digest", lambda *_args, **_kwargs:
                        events.append("runtime-journal"))
    monkeypatch.setattr(adopt, "_runtime_repaired_inspector", lambda *_args:
                        (_ for _ in ()).throw(RuntimeError("pre-effect fixture failure")))
    monkeypatch.setattr(adopt, "_run", lambda *args, **_kwargs:
                        events.append(tuple(args)) or "")
    monkeypatch.setattr(adopt, "_restore_adapter_refresh_core", lambda *_args:
                        events.append("Core rollback"))
    monkeypatch.setattr(adopt, "_restore_old_ingress", lambda *_args:
                        events.append("ingress restore"))

    result = adopt._apply_adapter_refresh(
        "a" * 40, Path("/opt/hermes-installer-core-bbbbbbbbb/src"), "b" * 64,
        Path("/candidate/tools/pi_core_lifecycle_qualification.py"), (),
        object(), Path("/run/hermes-jarvis-native-observer/native-observer.sock"),
        approved_union=False)

    assert result == 4
    # The runtime-repaired unit digest is written only after the exact
    # replacement Inspector recipe has been constructed successfully.
    assert events == ["backup", "journal-state"]
    assert not any(isinstance(event, tuple) and event[0] in {"systemctl", "write"}
                   for event in events)


def test_adapter_refresh_resume_recovers_partial_core_before_qualification(monkeypatch):
    row = _adapter_refresh_row()
    prior_raw = b"exact retained old Core journal\n"
    row["old_core_journal_sha256"] = hashlib.sha256(prior_raw).hexdigest()
    old_record = {
        "adapter_source": row["old_core_adapter_source"],
        "adapter_generation": row["old_core_adapter_generation"],
        "core_source_generation": row["old_core_source_generation"],
    }
    state = {"phase": "partial"}
    events = []

    def current_is_old(_core, _row):
        return state["phase"] == "old"

    monkeypatch.setattr(adopt, "_backup_value", lambda _sha: (
        {"adapter_refresh": row}, b"old gateway", b"old inspector", b"old config"))
    monkeypatch.setattr(adopt, "_adapter_refresh_current_is_old", current_is_old)
    monkeypatch.setattr(adopt, "_set_backup_state", lambda phase: events.append(("journal", phase)))

    def restore_owned_core_adapter_update():
        assert state["phase"] == "partial"
        assert events[-1] == ("journal", "recovery-required")
        events.append("fixed-root-locked-Core-recovery")
        state["phase"] = "old"

    def read_active():
        events.append(("read-Core", state["phase"]))
        if state["phase"] != "old":
            raise RuntimeError("partial Core cannot satisfy ordinary active reader")
        return old_record, prior_raw, {"unit": b"old unit", "launcher": b"old launcher"}

    def snapshot(*, core_source_generation):
        assert state["phase"] == "old"
        assert core_source_generation == row["old_core_source_generation"]
        events.append("snapshot-old-bindings")
        return {"resources_record": b"old Resources"}

    core = SimpleNamespace(restore_owned_core_adapter_update=restore_owned_core_adapter_update,
                           _read_active_adapter_runtime=read_active,
                           _snapshot_adapter_update_bindings=snapshot)

    record, raw, files, snapshots = adopt._recover_adapter_refresh_core_for_resume(
        core, "a" * 40, row)

    assert record == old_record
    assert raw == prior_raw
    assert files["unit"] == b"old unit"
    assert snapshots["resources_record"] == b"old Resources"
    assert events == [("journal", "recovery-required"),
                      "fixed-root-locked-Core-recovery", ("read-Core", "old"),
                      ("read-Core", "old"), "snapshot-old-bindings"]


@pytest.mark.parametrize("prior_cohort", [
    b"",
    b'{"obsidian_vault_tree_sha256":"' + b"f" * 64 + b'","schema":1}\n',
])
def test_resume_all_joined_rolling_back_core_uses_latest_vault_snapshot(
        monkeypatch, tmp_path, capsys, prior_cohort):
    row = _adapter_refresh_row(committed=True)
    original_join = (row["core_update_backup_reference"],
                     row["core_update_cohort_transaction_id"],
                     row["core_update_cohort_sha256"])
    old_gateway = _unit("core_gateway", OLD_SOURCE)
    old_inspector = _unit("core_gateway_inspector", OLD_SOURCE)
    new_gateway = _unit("core_gateway", NEW_SOURCE)
    new_inspector = _unit("core_gateway_inspector", NEW_SOURCE)
    old_config = b'{"allowed_emails":["owner@example.test"]}\n'
    new_config = b'{"allowed_emails":["owner@example.test","next@example.test"]}\n'
    prior_raw = b"exact old Core journal\n"
    row["old_core_journal_sha256"] = hashlib.sha256(prior_raw).hexdigest()
    prior_record = {
        "adapter_source": row["old_core_adapter_source"],
        "adapter_generation": row["old_core_adapter_generation"],
        "core_source_generation": row["old_core_source_generation"],
    }
    contents = {
        "journal.json": prior_raw, "unit": b"old Core unit", "launcher": b"old launcher",
        "resources-record.json": b"old Resources", "overlay-record.json": b"old overlay",
        "primary-record.json": b"old primary",
        "cohort.json": prior_cohort,
        "obsidian-registration.json": b"exact current owner registration",
    }
    rolling_cohort = {"phase": "rolling-back",
                      "cohort_transaction_id": row["core_update_cohort_transaction_id"],
                      "old_source": row["old_core_adapter_source"],
                      "old_adapter_generation": row["old_core_adapter_generation"],
                      "old_core_source_generation": row["old_core_source_generation"],
                      "old_journal_sha256": row["old_core_journal_sha256"],
                      "new_source": "/opt/hermes-installer-core-bbbbbbbbb/src",
                      "obsidian_vault_tree_sha256": "a" * 64}
    value = {
        "state": "recovery-required",
        "old_gateway_sha256": hashlib.sha256(old_gateway).hexdigest(),
        "old_inspector_sha256": hashlib.sha256(old_inspector).hexdigest(),
        "old_config_sha256": hashlib.sha256(old_config).hexdigest(),
        "new_gateway_sha256": hashlib.sha256(new_gateway).hexdigest(),
        "new_inspector_sha256": hashlib.sha256(new_inspector).hexdigest(),
        "runtime_inspector_sha256": None,
        "new_config_sha256": hashlib.sha256(new_config).hexdigest(),
        "post_core_config_sha256": None,
        "gateway_gid": 981, "gateway_mode": 0o440,
        "adapter_refresh": row,
    }
    paths = {adopt.GATEWAY: tmp_path / "gateway.service",
             adopt.INSPECTOR: tmp_path / "inspector.service",
             adopt.TUNNEL: tmp_path / "tunnel.service"}
    config_path = tmp_path / "gateway.json"
    backup_path = tmp_path / "ingress-backup.json"
    backup_path.write_bytes(b"retained transaction")
    monkeypatch.setattr(adopt, "FIXED_UNITS", paths)
    monkeypatch.setattr(adopt, "GATEWAY_CONFIG", config_path)
    monkeypatch.setattr(adopt, "INGRESS_BACKUP", backup_path)
    monkeypatch.setattr(adopt, "_backup_value", lambda _sha: (
        value, old_gateway, old_inspector, old_config))
    monkeypatch.setattr(adopt, "_unit_is_fixed", lambda _name: True)
    monkeypatch.setattr(adopt, "_unit_source", lambda _raw, _module: OLD_SOURCE)
    monkeypatch.setattr(adopt, "_set_adapter_refresh_core_join", lambda *_args:
                        pytest.fail("resume must preserve the already recorded join"))
    monkeypatch.setattr(adopt, "_run_core_refresh_qualification", lambda *_args:
                        pytest.fail("rolling-back recovery must not replay qualification"))
    monkeypatch.setattr(adopt, "_read_candidate_qualification_inputs", lambda *_args:
                        pytest.fail("rollback recovery must not depend on the candidate runner"))
    monkeypatch.setattr(adopt, "_remove_ingress_backup", lambda:
                        events.append("remove-retained-ingress-transaction"))
    events = []
    states = {adopt.GATEWAY: "active", adopt.TUNNEL: "active", adopt.INSPECTOR: "inactive"}

    def unit_state(name):
        return states[name]

    def run(*args, **_kwargs):
        events.append(tuple(args))
        if args[1:3] == ("stop", adopt.TUNNEL):
            states[adopt.TUNNEL] = "inactive"
        if args[1:3] == ("stop", adopt.GATEWAY):
            states[adopt.GATEWAY] = "inactive"
        return ""

    monkeypatch.setattr(adopt, "_unit_state", unit_state)
    monkeypatch.setattr(adopt, "_run", run)
    monkeypatch.setattr(adopt, "_set_backup_state", lambda phase:
                        events.append(("ingress-state", phase)))
    monkeypatch.setattr(adopt, "_read_fixed", lambda path, **_kwargs: (
        old_gateway if path == paths[adopt.GATEWAY] else
        old_inspector if path == paths[adopt.INSPECTOR] else old_config,
        SimpleNamespace(st_mode=stat.S_IFREG | 0o440, st_gid=981)))

    class Core:
        UNIT = "unit"
        LAUNCHER = "launcher"

        def __init__(self):
            self.old = False

        def _read_adapter_update_cohort(self):
            return rolling_cohort, b"rolling-back cohort"

        def _adapter_update_backup_reference(self, cohort):
            assert cohort is rolling_cohort
            return row["core_update_backup_reference"]

        def _read_adapter_update_backup(self, reference):
            assert reference == row["core_update_backup_reference"]
            return prior_record, contents

        def _read_active_adapter_runtime(self):
            events.append(("Core-read", self.old))
            if not self.old:
                raise RuntimeError("Core is still in retained rolling-back phase")
            return prior_record, prior_raw, {"unit": contents["unit"],
                                             "launcher": contents["launcher"]}

        def _snapshot_adapter_update_bindings(self, *, core_source_generation):
            assert self.old
            assert core_source_generation == row["old_core_source_generation"]
            return {
                "resources_record": contents["resources-record.json"],
                "overlay_record": contents["overlay-record.json"],
                "primary_record": contents["primary-record.json"],
                "prior_cohort": contents["cohort.json"],
                "obsidian_registration": contents["obsidian-registration.json"],
                "obsidian_registration_state": "registered",
                # Notes may have changed since the prior cohort, but this
                # digest is the update-start snapshot retained by rolling-back.
                "obsidian_vault_tree_sha256": rolling_cohort["obsidian_vault_tree_sha256"],
            }

        def restore_owned_core_adapter_update(self):
            events.append("fixed-Core-rollback"); self.old = True

    core = Core()

    def restore_ingress(_value, gateway, inspector, config, **kwargs):
        assert gateway == old_gateway and inspector == old_inspector and config == old_config
        assert kwargs["observer_socket"] == observer_socket
        assert kwargs["expected_observer_source"] == Path(row["old_core_adapter_source"])
        events.append("restore-exact-old-ingress-and-peer")
        states.update({adopt.INSPECTOR: "active", adopt.GATEWAY: "active",
                       adopt.TUNNEL: "active"})
        return True

    observer_socket = tmp_path / "old-observer.sock"
    monkeypatch.setattr(adopt, "_restore_old_ingress", restore_ingress)

    source = Path("/opt/hermes-installer-core-bbbbbbbbb/src")
    core.__file__ = str(source / "hermes_installer" / "core_runtime.py")
    core._validate_adapter_source_path = lambda: None
    package = ModuleType("hermes_installer")
    package.__path__ = []
    package.core_runtime = core
    remote = ModuleType("hermes_installer.remote")
    remote.__path__ = []
    gateway_module = ModuleType("hermes_installer.remote.core_gateway")
    gateway_module.CoreGatewayConfig = SimpleNamespace(load=lambda **_kwargs: object())
    observer_module = ModuleType("hermes_installer.remote.core_native_observer")
    observer_module.CORE_NATIVE_OBSERVER_SOCKET = observer_socket
    remote.core_gateway = gateway_module
    remote.core_native_observer = observer_module
    monkeypatch.setitem(sys.modules, "hermes_installer", package)
    monkeypatch.setitem(sys.modules, "hermes_installer.remote", remote)
    monkeypatch.setitem(sys.modules, "hermes_installer.remote.core_gateway", gateway_module)
    monkeypatch.setitem(sys.modules, "hermes_installer.remote.core_native_observer", observer_module)
    monkeypatch.setattr(adopt.os, "geteuid", lambda: 0)
    monkeypatch.setattr(sys, "argv", [str(HELPER_PATH), "--candidate-sha", "b" * 40,
                                      "--resume"])
    monkeypatch.setattr(sys, "path", [])
    monkeypatch.setattr(adopt.Path, "resolve", lambda path, strict=False: path)
    monkeypatch.setattr(adopt, "_verify_source_provenance",
                        lambda _sha, _path: "c" * 64)

    result = adopt.main()

    assert result == 0
    assert core.old is True
    assert states == {adopt.GATEWAY: "active", adopt.TUNNEL: "active",
                      adopt.INSPECTOR: "active"}
    assert "fixed-Core-rollback" in events
    assert "restore-exact-old-ingress-and-peer" in events
    assert "remove-retained-ingress-transaction" in events
    assert not any(event == "remove-retained-ingress-transaction" for event in events[:-1])
    assert "Interrupted adapter rollback completed" in capsys.readouterr().out
    assert (row["core_update_backup_reference"],
            row["core_update_cohort_transaction_id"],
            row["core_update_cohort_sha256"]) == original_join


def test_legacy_backup_resume_derives_only_the_original_email_recipe():
    candidate = "a" * 40
    source = Path(f"/opt/hermes-installer-core-{candidate[:9]}/src")
    old_gateway, old_inspector = _unit("core_gateway"), _unit("core_gateway_inspector")
    old_config = json.dumps({
        "gateway_unit_sha256": hashlib.sha256(old_gateway).hexdigest(),
        "allowed_emails": ["owner@example.test"],
        "credential_ref": "keyring:codex-primary",
    }, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    new_gateway = old_gateway.replace(OLD_SOURCE, str(source).encode("ascii"), 1)
    new_inspector = old_inspector.replace(OLD_SOURCE, str(source).encode("ascii"), 1)
    expected_value = json.loads(old_config)
    expected_value["gateway_unit_sha256"] = hashlib.sha256(new_gateway).hexdigest()
    expected = (json.dumps(expected_value, sort_keys=True, separators=(",", ":")) + "\n").encode()
    record = {"new_gateway_sha256": hashlib.sha256(new_gateway).hexdigest(),
              "new_inspector_sha256": hashlib.sha256(new_inspector).hexdigest(),
              "new_config_sha256": hashlib.sha256(expected).hexdigest()}

    resumed = adopt._journaled_new_gateway_config(
        record, old_gateway, old_inspector, old_config, source)

    assert resumed == expected
    assert json.loads(resumed)["allowed_emails"] == ["owner@example.test"]


def test_recorded_new_config_cannot_add_unapproved_members_or_change_other_fields():
    candidate = "b" * 40
    source = Path(f"/opt/hermes-installer-core-{candidate[:9]}/src")
    old_gateway, old_inspector = _unit("core_gateway"), _unit("core_gateway_inspector")
    old_config = json.dumps({
        "gateway_unit_sha256": hashlib.sha256(old_gateway).hexdigest(),
        "allowed_emails": ["owner@example.test"],
        "credential_ref": "keyring:codex-primary",
    }, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    new_gateway = old_gateway.replace(OLD_SOURCE, str(source).encode("ascii"), 1)
    new_inspector = old_inspector.replace(OLD_SOURCE, str(source).encode("ascii"), 1)
    prior = json.loads(old_config)
    prior["gateway_unit_sha256"] = hashlib.sha256(new_gateway).hexdigest()
    prior["allowed_emails"] = ["other@example.test"]
    prospective = (json.dumps(prior, sort_keys=True, separators=(",", ":")) + "\n").encode()
    record = {"new_gateway_sha256": hashlib.sha256(new_gateway).hexdigest(),
              "new_inspector_sha256": hashlib.sha256(new_inspector).hexdigest(),
              "new_config_sha256": hashlib.sha256(prospective).hexdigest(),
              "new_gateway_config": base64.b64encode(prospective).decode("ascii")}

    with pytest.raises(RuntimeError, match="approved email union"):
        adopt._journaled_new_gateway_config(
            record, old_gateway, old_inspector, old_config, source)


def test_backup_reader_binds_exact_prospective_config_digest(monkeypatch):
    old_gateway, old_inspector = _unit("core_gateway"), _unit("core_gateway_inspector")
    old_config = b'{"gateway_unit_sha256":"old"}\n'
    next_config = b'{"allowed_emails":["owner@example.test","member@example.test"]}\n'
    candidate = "c" * 40
    value = {
        "schema": 1, "state": "prepared", "candidate_sha": candidate,
        "gateway_unit": base64.b64encode(old_gateway).decode(),
        "inspector_unit": base64.b64encode(old_inspector).decode(),
        "gateway_config": base64.b64encode(old_config).decode(),
        "gateway_mode": 0o440, "gateway_gid": 981,
        "old_gateway_sha256": hashlib.sha256(old_gateway).hexdigest(),
        "old_inspector_sha256": hashlib.sha256(old_inspector).hexdigest(),
        "old_config_sha256": hashlib.sha256(old_config).hexdigest(),
        "new_gateway_sha256": "1" * 64, "new_inspector_sha256": "2" * 64,
        "new_config_sha256": hashlib.sha256(next_config).hexdigest(),
        "new_gateway_config": base64.b64encode(next_config).decode(),
        "post_core_config_sha256": None, "runtime_inspector_sha256": None,
    }
    info = SimpleNamespace(st_mode=stat.S_IFREG | 0o600)
    monkeypatch.setattr(adopt, "_read_fixed", lambda *_args, **_kwargs:
                        ((json.dumps(value, sort_keys=True) + "\n").encode(), info))

    loaded, _old_gateway, _old_inspector, _old_config = adopt._backup_value(candidate)
    assert base64.b64decode(loaded["new_gateway_config"]) == next_config

    value["new_gateway_config"] = None
    with pytest.raises(RuntimeError, match="rollback record is malformed"):
        adopt._backup_value(candidate)
    value["new_gateway_config"] = base64.b64encode(next_config + b"\n").decode()
    with pytest.raises(RuntimeError, match="rollback record is malformed"):
        adopt._backup_value(candidate)
    value.pop("new_gateway_config")
    legacy_loaded, *_ = adopt._backup_value(candidate)
    assert legacy_loaded["new_gateway_config"] is None
    assert legacy_loaded["prior_completed_ingress_sha256"] is None


@pytest.mark.parametrize("action", ["--rollback", "--resume"])
def test_union_input_flag_is_denied_for_resume_or_rollback_before_source_effects(monkeypatch, action):
    monkeypatch.setattr(adopt.os, "geteuid", lambda: 0)
    monkeypatch.setattr(adopt.sys, "argv", [
        str(HELPER_PATH), "--candidate-sha", "d" * 40,
        action, "--approved-email-union-stdin"])
    with pytest.raises(SystemExit):
        adopt.main()


@pytest.mark.parametrize("union_requested,registration_exists,expected", [
    (True, True, False), (True, False, False), (False, True, True)])
def test_multi_email_adoption_preserves_owner_registration_and_keeps_gate_pending(
        monkeypatch, capsys, union_requested, registration_exists, expected):
    calls = []
    state = {"registration": b"exact prior registration" if registration_exists else None,
             "vault": b"exact existing vault bytes"}
    owner_module = ModuleType("hermes_installer.remote.obsidian_owner_lifecycle")
    def prepare_owner():
        calls.append("sole-owner-preparation")
        state["registration"] = b"rewritten registration"
        state["vault"] = b"rewritten vault"
    owner_module.prepare_sole_existing_chat_owner_for_legacy_migration = prepare_owner
    monkeypatch.setitem(__import__("sys").modules,
                        owner_module.__name__, owner_module)
    emails = (["owner@example.test", "member@example.test", "third@example.test"]
              if union_requested else ["owner@example.test"])
    prospective = json.dumps({"allowed_emails": emails}, sort_keys=True,
                              separators=(",", ":")).encode() + b"\n"

    prepared = adopt._prepare_existing_owner_before_migration(prospective, union_requested)

    assert prepared is expected
    assert calls == ([] if union_requested else ["sole-owner-preparation"])
    if union_requested:
        assert state == {"registration": b"exact prior registration" if registration_exists else None,
                         "vault": b"exact existing vault bytes"}
        output = capsys.readouterr().out
        assert "preserved" in output and "pending" in output
        assert "owner@example.test" not in output


def test_runtime_inspector_recipe_preserves_primary_group_and_adds_only_fixed_paths():
    raw = _unit("core_gateway_inspector")
    repaired = adopt._runtime_repaired_inspector(raw)
    text = repaired.decode("ascii")
    assert "Group=981\n" in text
    assert adopt.NATIVE_OBSERVER_PRESTART in text
    assert adopt.NATIVE_OBSERVER_READ_WRITE in text
    assert adopt.NATIVE_OBSERVER_SUPPLEMENTARY_GROUPS in text
    assert text.count(adopt.NATIVE_OBSERVER_PRESTART) == 1
    assert adopt._runtime_repaired_inspector(repaired) == repaired
    bad_template = raw.replace(
        b"RuntimeDirectory=hermes-jarvis-mvp-core\n",
        b"RuntimeDirectory=hermes-jarvis-mvp-core hermes-jarvis-native-observer:root:admin\n")
    assert b"RuntimeDirectory=hermes-jarvis-mvp-core\n" in adopt._runtime_repaired_inspector(bad_template)

    with pytest.raises(RuntimeError, match="unexpected runtime-access directive"):
        adopt._runtime_repaired_inspector(raw + b"SupplementaryGroups=audio\n")


def test_runtime_inspector_digest_journal_is_candidate_cas_bound(monkeypatch):
    candidate, base, repaired = "a" * 40, "b" * 64, "c" * 64
    record = {"schema": 1, "candidate_sha": candidate,
              "new_inspector_sha256": base, "state": "recovery-required"}
    writes = []
    info = SimpleNamespace(st_mode=stat.S_IFREG | 0o600)
    monkeypatch.setattr(adopt, "_read_fixed", lambda *_args, **_kwargs:
                        (json.dumps(record).encode(), info))
    monkeypatch.setattr(adopt, "_atomic_fixed", lambda _path, raw, **_kwargs:
                        writes.append(json.loads(raw)))

    adopt._set_runtime_inspector_digest(candidate, base, repaired)
    assert writes == [{**record, "runtime_inspector_sha256": repaired}]
    with pytest.raises(RuntimeError, match="protected Inspector repair journal changed"):
        adopt._set_runtime_inspector_digest("d" * 40, base, repaired)
    assert len(writes) == 1


def test_core_config_resume_refresh_is_journal_bound_and_commit_before_write(monkeypatch):
    candidate = "d" * 40
    source = Path(f"/opt/hermes-installer-core-{candidate[:9]}/src")
    old_gateway = _unit("core_gateway")
    old_inspector = _unit("core_gateway_inspector")
    switched_gateway = old_gateway.replace(OLD_SOURCE, str(source).encode("ascii"), 1)
    switched_inspector = old_inspector.replace(OLD_SOURCE, str(source).encode("ascii"), 1)
    old_config = json.dumps({"gateway_unit_sha256": hashlib.sha256(old_gateway).hexdigest(),
                             "core_unit_sha256": "2" * 64,
                             "core_launcher_sha256": "3" * 64,
                             "credential_ref": "keyring:codex-primary",
                             "allowed_emails": ["owner@example.test"],
                             "selected_data_root": "/home/admin/.hermes"},
                            sort_keys=True, separators=(",", ":")).encode() + b"\n"
    switched_value = json.loads(old_config)
    switched_value["gateway_unit_sha256"] = hashlib.sha256(switched_gateway).hexdigest()
    switched_value["allowed_emails"] = ["owner@example.test", "member@example.test",
                                         "third@example.test"]
    switched = (json.dumps(switched_value, sort_keys=True, separators=(",", ":")) + "\n").encode()
    assert old_config != switched
    core_unit, launcher = b"current owned unit", b"current owned launcher"
    unit_sha, launcher_sha = hashlib.sha256(core_unit).hexdigest(), hashlib.sha256(launcher).hexdigest()
    backup = {"state": "recovery-required", "candidate_sha": candidate,
              "new_gateway_sha256": hashlib.sha256(switched_gateway).hexdigest(),
              "new_inspector_sha256": hashlib.sha256(switched_inspector).hexdigest(),
              "new_config_sha256": hashlib.sha256(switched).hexdigest(),
              "new_gateway_config": base64.b64encode(switched).decode("ascii"),
              "post_core_config_sha256": None}
    files = {adopt.GATEWAY_CONFIG: switched}
    info = SimpleNamespace(st_mode=stat.S_IFREG | 0o440, st_gid=981)
    root_info = SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_gid=0)
    writes = []

    class Core:
        UNIT = Path("/fixture/core.service")
        LAUNCHER = Path("/fixture/core-launcher")

        @staticmethod
        def _journal():
            return {"state": "installed", "adapter_migration_state": "active",
                    "adapter_source": str(source), "adapter_generation": "a" * 64,
                    "unit_sha256": unit_sha, "launcher_sha256": launcher_sha}

        @staticmethod
        def _owned_listener():
            return True

    monkeypatch.setattr(adopt, "INGRESS_BACKUP", Path("/fixture/backup.json"))
    monkeypatch.setattr(adopt, "_backup_value",
                        lambda sha: (backup, old_gateway, old_inspector, old_config)
                        if sha == candidate else pytest.fail("candidate mismatch"))

    def read_fixed(path, **_kwargs):
        if path == adopt.GATEWAY_CONFIG:
            return files[path], info
        if path == Core.UNIT:
            return core_unit, SimpleNamespace(st_mode=stat.S_IFREG | 0o644, st_gid=0)
        if path == Core.LAUNCHER:
            return launcher, SimpleNamespace(st_mode=stat.S_IFREG | 0o755, st_gid=0)
        if path == adopt.INGRESS_BACKUP:
            return b"protected backup", root_info
        raise AssertionError("unexpected fixed file")

    monkeypatch.setattr(adopt, "_read_fixed", read_fixed)

    def atomic_fixed(path, raw, **_kwargs):
        writes.append(path)
        if path == adopt.GATEWAY_CONFIG:
            files[path] = raw

    monkeypatch.setattr(adopt, "_atomic_fixed", atomic_fixed)
    class NoUnionInput:
        def read(self, _limit):
            pytest.fail("resume must use the exact journaled config without new input")

    monkeypatch.setattr(adopt.sys, "stdin", SimpleNamespace(buffer=NoUnionInput()))
    first = adopt._refresh_migrated_core_config(candidate, source, Core)
    assert json.loads(first) == {**json.loads(switched), "core_unit_sha256": unit_sha,
                                 "core_launcher_sha256": launcher_sha}
    assert json.loads(first)["allowed_emails"] == [
        "owner@example.test", "member@example.test", "third@example.test"]
    assert writes == [adopt.INGRESS_BACKUP, adopt.GATEWAY_CONFIG]
    assert backup["post_core_config_sha256"] == hashlib.sha256(first).hexdigest()
    assert adopt._refresh_migrated_core_config(candidate, source, Core) == first
    assert writes == [adopt.INGRESS_BACKUP, adopt.GATEWAY_CONFIG]


def test_core_config_resume_cas_rejects_unrecorded_bytes_before_effects(monkeypatch):
    candidate = "e" * 40
    source = Path(f"/opt/hermes-installer-core-{candidate[:9]}/src")
    switched = b'{"gateway_unit_sha256":"1"}\n'
    backup = {"state": "recovery-required", "new_config_sha256": hashlib.sha256(switched).hexdigest(),
              "post_core_config_sha256": None}
    writes = []
    monkeypatch.setattr(adopt, "_backup_value",
                        lambda _sha: (backup, b"gateway", b"inspector", switched))
    monkeypatch.setattr(adopt, "_read_fixed", lambda *_args, **_kwargs:
                        (b"unrecorded config bytes", SimpleNamespace(st_mode=stat.S_IFREG | 0o440,
                                                                       st_gid=981)))
    monkeypatch.setattr(adopt, "_atomic_fixed", lambda *args, **kwargs: writes.append(args))

    with pytest.raises(RuntimeError, match="outside the saved adoption transaction"):
        adopt._refresh_migrated_core_config(candidate, source, SimpleNamespace())
    assert writes == []


def _completed_ingress_handoff_fixture(tmp_path, monkeypatch):
    runtime = tmp_path / "core-runtime"
    runtime.mkdir(mode=0o700)
    runtime.chmod(0o700)
    active = runtime / "native-adoption-ingress-backup.json"
    old_gateway = _unit("core_gateway")
    old_inspector = _unit("core_gateway_inspector")
    gateway_path, inspector_path = runtime / "gateway.service", runtime / "inspector.service"
    gateway_path.write_bytes(old_gateway)
    inspector_path.write_bytes(old_inspector)
    gateway_path.chmod(0o644)
    inspector_path.chmod(0o644)
    monkeypatch.setattr(adopt, "FIXED_UNITS", {
        adopt.GATEWAY: gateway_path, adopt.INSPECTOR: inspector_path,
        adopt.TUNNEL: runtime / "tunnel.service"})
    config_path = runtime / "gateway.json"
    config_path.write_bytes(b'{"allowed_emails":["owner@example.test"]}\n')
    config_path.chmod(0o440)
    adopt.os.chown(config_path, 0, 981)
    old_config = config_path.read_bytes()
    prospective_config = (json.dumps({
        "allowed_emails": ["owner@example.test"],
        "gateway_unit_sha256": hashlib.sha256(old_gateway).hexdigest(),
    }, sort_keys=True, separators=(",", ":")) + "\n").encode()
    old_values = {
        "schema": 1, "state": "migrated", "candidate_sha": "a" * 40,
        "gateway_unit": base64.b64encode(old_gateway).decode("ascii"),
        "inspector_unit": base64.b64encode(old_inspector).decode("ascii"),
        "gateway_config": base64.b64encode(old_config).decode("ascii"),
        "gateway_mode": 0o440, "gateway_gid": 981,
        "new_gateway_sha256": hashlib.sha256(old_gateway).hexdigest(),
        "new_inspector_sha256": hashlib.sha256(old_inspector).hexdigest(),
        "new_config_sha256": hashlib.sha256(prospective_config).hexdigest(),
        "post_core_config_sha256": "b" * 64,
        "old_gateway_sha256": hashlib.sha256(old_gateway).hexdigest(),
        "old_inspector_sha256": hashlib.sha256(old_inspector).hexdigest(),
        "old_config_sha256": hashlib.sha256(old_config).hexdigest(),
        "runtime_inspector_sha256": None,
        "new_gateway_config": base64.b64encode(prospective_config).decode("ascii"),
        "adapter_refresh": None,
    }
    old_raw = (json.dumps(old_values, sort_keys=True, separators=(",", ":"))
               + "\n").encode("ascii")
    active.write_bytes(old_raw)
    active.chmod(0o600)
    info = active.stat()
    monkeypatch.setattr(adopt, "INGRESS_BACKUP", active)
    monkeypatch.setattr(adopt, "INGRESS_HISTORY", runtime / "native-adoption-ingress-history")
    predecessor_sha, _identity = adopt._archive_completed_ingress_bytes(old_raw)
    predecessor = {"raw": old_raw, "identity": adopt._ingress_backup_identity(info),
                   "sha256": predecessor_sha}
    monkeypatch.setattr(adopt, "GATEWAY_CONFIG", config_path)
    saved = {gateway_path: (old_gateway, gateway_path.stat()),
             inspector_path: (old_inspector, inspector_path.stat())}
    return runtime, active, predecessor, saved, config_path


def _qualification_report_fixture(candidate="b" * 40, archive="c" * 64):
    transition = {
        "schema": 1, "purpose": "fixed-native-resources-plugin",
        "old_adapter_generation": "d" * 64, "new_adapter_generation": "e" * 64,
        "plugin_selection_sha256": "6" * 64,
        "old_members": {"plugin.yaml": "8" * 64, "__init__.py": "1" * 64},
        "new_members": {"plugin.yaml": "8" * 64, "__init__.py": "2" * 64},
    }
    def snapshot(source, generation, members, plugin_transition=None):
        result = {
            "journal_sha256": "1" * 64, "unit_sha256": "2" * 64,
            "launcher_sha256": "3" * 64, "token_custody_verified": True,
            "token_sha256": "4" * 64, "adapter_source": source,
            "adapter_generation": generation, "core_source_generation": "5" * 64,
            "plugin_selection_sha256": "6" * 64, "resources_record_sha256": "7" * 64,
            "overlay_record_sha256": "absent", "overlay_content_count": 0,
            "overlay_contents_sha256": "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945",
            "primary_record_sha256": "absent",
            "obsidian_registration_state": "absent", "obsidian_registration_sha256": "absent",
            "obsidian_vault_tree_sha256": "absent", "adapter_update_state": "active",
            "adapter_update_previous_source": None,
            "adapter_update_backup_source_generation": generation,
            "primary_prompt_soul_sha256": "a" * 64, "primary_prompt_state": "unmanaged",
            "primary_owner_prefix_sha256": "b" * 64, "primary_owner_prefix_length": 12,
            "primary_immutable_backup_sha256": None,
            "native_plugin_members_sha256": dict(members),
            "native_plugin_transition": (
                None if plugin_transition is None else {
                    **plugin_transition,
                    "old_members": dict(plugin_transition["old_members"]),
                    "new_members": dict(plugin_transition["new_members"]),
                }),
        }
        return result
    return {
        "schema": 1, "action": "core-service adapter-update",
        "candidate_commit": candidate, "candidate_archive_sha256": archive,
        "source_receipt_is_operator_paired_not_signature": True,
        "ancestor_and_verifier_custody_checked_before_execution": True,
        "cli_exit_code": 4,
        "cli_failure_origin": {"exception_type": "RuntimeError", "frames": [
            {"source_relative_path": "hermes_installer/core_runtime.py",
             "function": "_replace_launcher", "line": 1234}]},
        "cli_output": {"stdout_bytes": 0, "stdout_sha256": "0" * 64,
                       "stderr_bytes": 0, "stderr_sha256": "0" * 64},
        "before": snapshot("/opt/hermes-installer-core-aaaaaaaaa/src", "d" * 64,
                           transition["old_members"]),
        "after": snapshot("/opt/hermes-installer-core-bbbbbbbbb/src", "e" * 64,
                          transition["new_members"], transition),
        "after_readback_error_type": None, "cohort_phase": "source-starting",
        "checks": {name: False for name in adopt._QUALIFICATION_CHECKS},
        "outcome": "pending_or_failed", "rollback_qualification": "not_run",
        "interruption_recovery_qualification": "not_run", "acceptance": "not_claimed",
    }


def _qualification_diagnostic_line(captured):
    assert captured.out == ""
    lines = [line for line in captured.err.splitlines()
             if line.startswith(adopt._QUALIFICATION_DIAGNOSTIC_PREFIX)]
    assert len(lines) == 1
    encoded = lines[0][len(adopt._QUALIFICATION_DIAGNOSTIC_PREFIX):]
    record = json.loads(encoded)
    assert encoded == json.dumps(record, sort_keys=True, separators=(",", ":"))
    assert set(record) == {
        "schema", "candidate_commit", "candidate_archive_sha256", "reason",
        "returncode", "stdout_bytes", "stderr_bytes", "elapsed_ms",
    }
    assert record["schema"] == 1
    assert record["candidate_commit"] == "b" * 40
    assert record["candidate_archive_sha256"] == "c" * 64
    assert len(lines[0].encode("ascii") + b"\n") <= 4096
    assert "PRIVATE" not in lines[0]
    for key, maximum in (("stdout_bytes", 64 * 1024 + 1),
                         ("stderr_bytes", 16 * 1024 + 1),
                         ("elapsed_ms", 300_000)):
        value = record[key]
        assert value is None or type(value) is int and 0 <= value <= maximum
    value = record["returncode"]
    assert value is None or type(value) is int and -255 <= value <= 255
    summary = _qualification_last_phase_record(captured)
    assert adopt._valid_qualification_last_phase_summary(summary)
    stack = _qualification_stack_observation_record(captured)
    assert adopt._valid_qualification_stack_observation_summary(stack)
    return record


def _qualification_last_phase_record(captured):
    summaries = [line for line in captured.err.splitlines()
                 if line.startswith(adopt._QUALIFICATION_LAST_PHASE_PREFIX)]
    assert len(summaries) == 1
    summary_encoded = summaries[0][len(adopt._QUALIFICATION_LAST_PHASE_PREFIX):]
    summary = json.loads(summary_encoded)
    assert summary_encoded == json.dumps(summary, sort_keys=True, separators=(",", ":"))
    assert set(summary) == {
        "schema", "candidate_commit", "candidate_archive_sha256", "last_phase",
        "last_sequence", "last_elapsed_ms", "record_count", "rejected_record_count",
    }
    assert summary["schema"] == 1
    assert summary["candidate_commit"] == "b" * 40
    assert summary["candidate_archive_sha256"] == "c" * 64
    assert 0 <= summary["record_count"] <= 16
    assert 0 <= summary["rejected_record_count"] <= 16
    assert len(summaries[0].encode("ascii") + b"\n") <= 4096
    return summary


def _qualification_stack_observation_record(captured):
    summaries = [line for line in captured.err.splitlines()
                 if line.startswith(adopt._QUALIFICATION_STACK_OBSERVATION_PREFIX)]
    assert len(summaries) == 1
    encoded = summaries[0][len(adopt._QUALIFICATION_STACK_OBSERVATION_PREFIX):]
    summary = json.loads(encoded)
    assert encoded == json.dumps(summary, sort_keys=True, separators=(",", ":"))
    assert adopt._valid_qualification_stack_observation_summary(summary)
    assert len((summaries[0] + "\n").encode("ascii")) <= 4096
    return summary


@pytest.mark.skipif(os.geteuid() != 0, reason="protected failure report fixture requires root")
def test_nonzero_qualification_persists_only_validated_sanitized_report(
        tmp_path, monkeypatch, capsys):
    parent = tmp_path / "core-runtime"
    parent.mkdir(mode=0o700)
    parent.chmod(0o700)
    adopt.os.chown(parent, 0, 0)
    report = _qualification_report_fixture()
    raw = (json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n").encode()
    monkeypatch.setattr(adopt, "CORE_QUALIFICATION_FAILURE",
                        parent / "core-adapter-qualification-last-failure.json")
    tool = Path(adopt.__file__)
    tool_info = tool.lstat()
    identity = (tool_info.st_dev, tool_info.st_ino, tool_info.st_size,
                tool_info.st_mtime_ns, tool_info.st_ctime_ns)
    monkeypatch.setattr(adopt.subprocess, "run", lambda *_args, **_kwargs:
                        SimpleNamespace(returncode=4, stdout=raw, stderr=b""))

    with pytest.raises(adopt._QualificationDiagnosticError) as caught:
        adopt._run_core_refresh_qualification("b" * 40, "c" * 64, tool, identity)
    diagnostic = _qualification_diagnostic_line(capsys.readouterr())
    assert diagnostic["reason"] == "validated_failure"
    assert diagnostic["returncode"] == 4
    assert diagnostic["stdout_bytes"] == len(raw)
    assert diagnostic["stderr_bytes"] == 0
    assert caught.value.record == diagnostic

    failure = adopt.CORE_QUALIFICATION_FAILURE
    saved = failure.read_bytes()
    info = failure.stat()
    assert stat.S_IMODE(info.st_mode) == 0o600
    assert (info.st_uid, info.st_gid) == (0, 0)
    assert b"_replace_launcher" in saved
    assert b"PRIVATE" not in saved
    persisted = json.loads(saved)
    assert persisted["cli_failure_origin"] == report["cli_failure_origin"]
    for snapshot in (persisted["before"], persisted["after"]):
        assert snapshot["overlay_record_sha256"] == "absent"
        assert snapshot["overlay_content_count"] == 0
        assert snapshot["primary_prompt_state"] == "unmanaged"
        assert snapshot["primary_record_sha256"] == "absent"
        assert snapshot["obsidian_registration_state"] == "absent"
        assert snapshot["obsidian_registration_sha256"] == "absent"
        assert snapshot["obsidian_vault_tree_sha256"] == "absent"
    assert persisted["before"]["native_plugin_members_sha256"] == (
        persisted["after"]["native_plugin_transition"]["old_members"])
    assert persisted["after"]["native_plugin_members_sha256"] == (
        persisted["after"]["native_plugin_transition"]["new_members"])


def test_verified_qualification_remains_silent(tmp_path, monkeypatch, capsys):
    report = _qualification_report_fixture()
    report["cli_exit_code"] = 0
    report["cli_failure_origin"] = None
    report["cohort_phase"] = "committed"
    report["checks"] = {name: True for name in adopt._QUALIFICATION_CHECKS}
    report["outcome"] = "verified_adapter_update"
    raw = (json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n").encode()
    tool = Path(adopt.__file__)
    info = tool.lstat()
    identity = (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
    invocation = {}

    def run(*args, **kwargs):
        invocation["args"] = args
        invocation["kwargs"] = kwargs
        return SimpleNamespace(returncode=0, stdout=raw, stderr=b"")

    monkeypatch.setattr(adopt.subprocess, "run", run)

    result = adopt._run_core_refresh_qualification("b" * 40, "c" * 64, tool, identity)

    assert result == report
    captured = capsys.readouterr()
    assert captured.out == captured.err == ""
    assert invocation["args"] == (("/usr/bin/python3", "-I", str(tool),
                                   "--candidate-sha", "b" * 40,
                                   "--archive-sha256", "c" * 64),)
    assert invocation["kwargs"] == {
        "stdin": adopt.subprocess.DEVNULL, "stdout": adopt.subprocess.PIPE,
        "stderr": adopt.subprocess.PIPE, "timeout": 300,
        "env": {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "HOME": "/root"},
        "check": False,
    }


def test_eligible_failure_report_persistence_refusal_is_distinct_and_sanitized(
        monkeypatch, capsys):
    report = _qualification_report_fixture()
    raw = (json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n").encode()
    tool = Path(adopt.__file__)
    info = tool.lstat()
    identity = (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
    monkeypatch.setattr(adopt.subprocess, "run", lambda *_args, **_kwargs:
                        SimpleNamespace(returncode=4, stdout=raw, stderr=b""))
    attempted = []
    sentinel = "PRIVATE persistence location"

    def persistence_attempt(value):
        attempted.append(value)
        raise OSError(sentinel)

    monkeypatch.setattr(adopt, "_persist_qualification_failure", persistence_attempt)
    with pytest.raises(adopt._QualificationDiagnosticError) as caught:
        adopt._run_core_refresh_qualification("b" * 40, "c" * 64, tool, identity)

    diagnostic = _qualification_diagnostic_line(capsys.readouterr())
    assert len(attempted) == 1 and attempted[0] == report
    assert diagnostic["reason"] == "failure_report_persistence"
    assert diagnostic["returncode"] == 4
    assert sentinel not in json.dumps(diagnostic)
    assert caught.value.record == diagnostic


@pytest.mark.parametrize("report_kind", [
    "malformed", "foreign-candidate", "unsafe-origin", "forged-absent-digest",
    "inconsistent-registration-sentinel", "plugin-map-extra-member",
    "plugin-transition-member-tamper", "plugin-transition-extra-member",
    "plugin-transition-manifest-tamper",
])
@pytest.mark.skipif(os.geteuid() != 0, reason="protected failure report fixture requires root")
def test_untrusted_qualification_failure_report_cannot_replace_last_failure(
        tmp_path, monkeypatch, report_kind, capsys):
    parent = tmp_path / "core-runtime"
    parent.mkdir(mode=0o700)
    parent.chmod(0o700)
    adopt.os.chown(parent, 0, 0)
    failure = parent / "core-adapter-qualification-last-failure.json"
    failure.write_bytes(b"prior protected report")
    failure.chmod(0o600)
    adopt.os.chown(failure, 0, 0)
    monkeypatch.setattr(adopt, "CORE_QUALIFICATION_FAILURE", failure)
    report = _qualification_report_fixture()
    if report_kind == "malformed":
        raw = b"not a JSON report"
    else:
        if report_kind == "foreign-candidate":
            report["candidate_commit"] = "f" * 40
        elif report_kind == "unsafe-origin":
            report["cli_failure_origin"]["frames"][0]["source_relative_path"] = "/etc/shadow"
        elif report_kind == "forged-absent-digest":
            report["before"]["resources_record_sha256"] = "absent"
        elif report_kind == "inconsistent-registration-sentinel":
            report["before"]["obsidian_registration_state"] = "registered"
        elif report_kind == "plugin-map-extra-member":
            report["before"]["native_plugin_members_sha256"]["other.py"] = "a" * 64
        elif report_kind == "plugin-transition-member-tamper":
            assert report["after"]["native_plugin_transition"]["new_members"] is not (
                report["after"]["native_plugin_members_sha256"])
            report["after"]["native_plugin_transition"]["new_members"]["__init__.py"] = "f" * 64
        elif report_kind == "plugin-transition-extra-member":
            report["after"]["native_plugin_transition"]["new_members"]["other.py"] = "f" * 64
        else:
            report["after"]["native_plugin_transition"]["new_members"]["plugin.yaml"] = "f" * 64
        raw = (json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n").encode()
    tool = Path(adopt.__file__)
    tool_info = tool.lstat()
    identity = (tool_info.st_dev, tool_info.st_ino, tool_info.st_size,
                tool_info.st_mtime_ns, tool_info.st_ctime_ns)
    monkeypatch.setattr(adopt.subprocess, "run", lambda *_args, **_kwargs:
                        SimpleNamespace(returncode=4, stdout=raw, stderr=b""))
    monkeypatch.setattr(adopt, "_persist_qualification_failure",
                        lambda *_args: pytest.fail("rejected report reached persistence"))

    with pytest.raises(adopt._QualificationDiagnosticError) as caught:
        adopt._run_core_refresh_qualification("b" * 40, "c" * 64, tool, identity)
    diagnostic = _qualification_diagnostic_line(capsys.readouterr())
    assert diagnostic["reason"] == "report_rejected"
    assert diagnostic["returncode"] == 4
    assert caught.value.record == diagnostic
    assert failure.read_bytes() == b"prior protected report"


@pytest.mark.parametrize("case,reason", [
    ("execution", "execution_os_error"),
    ("timeout", "timeout"),
    ("identity-read", "tool_identity_read_failure"),
    ("identity-change", "tool_identity_change"),
    ("malformed", "malformed_result_types"),
    ("output-bound", "output_bound"),
    ("stderr-bound", "output_bound"),
    ("exit-mismatch", "exit_report_verification_mismatch"),
])
def test_qualification_refusal_emits_closed_reason_without_private_values(
        monkeypatch, capsys, case, reason):
    tool = Path(adopt.__file__)
    tool_info = tool.lstat()
    identity = (tool_info.st_dev, tool_info.st_ino, tool_info.st_size,
                tool_info.st_mtime_ns, tool_info.st_ctime_ns)
    sentinel = b"PRIVATE qualification sentinel"
    if case == "execution":
        def run(*_args, **_kwargs):
            raise OSError(sentinel.decode())
        monkeypatch.setattr(adopt.subprocess, "run", run)
    elif case == "timeout":
        checkpoint = {
            "schema": 1, "candidate_commit": "b" * 40,
            "candidate_archive_sha256": "c" * 64, "sequence": 1,
            "phase": "stage_verifier", "elapsed_ms": 10,
        }
        partial_stderr = (adopt._QUALIFICATION_CHECKPOINT_PREFIX
                          + json.dumps(checkpoint, sort_keys=True,
                                       separators=(",", ":")) + "\npartial").encode()
        def run(*_args, **_kwargs):
            raise adopt.subprocess.TimeoutExpired("private command", 300,
                                                  output=sentinel, stderr=partial_stderr)
        monkeypatch.setattr(adopt.subprocess, "run", run)
    else:
        report = _qualification_report_fixture()
        raw = (json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n").encode()
        rc = 4
        out = raw
        err = b""
        if case == "malformed":
            rc = "4"
        elif case == "output-bound":
            out = b"x" * (64 * 1024 + 1)
        elif case == "stderr-bound":
            err = b"x" * (16 * 1024 + 1)
        elif case == "exit-mismatch":
            rc = 0
        monkeypatch.setattr(adopt.subprocess, "run", lambda *_args, **_kwargs:
                            SimpleNamespace(returncode=rc, stdout=out, stderr=err))
        monkeypatch.setattr(adopt, "_persist_qualification_failure",
                            lambda *_args: pytest.fail("refusal reached failure persistence"))
        if case == "identity-read":
            original_lstat = Path.lstat

            def lstat(path):
                if path == tool:
                    raise OSError(sentinel.decode())
                return original_lstat(path)
            monkeypatch.setattr(Path, "lstat", lstat)
        elif case == "identity-change":
            identity = (*identity[:-1], identity[-1] + 1)

    with pytest.raises(adopt._QualificationDiagnosticError) as caught:
        adopt._run_core_refresh_qualification("b" * 40, "c" * 64, tool, identity)
    captured = capsys.readouterr()
    diagnostic = _qualification_diagnostic_line(captured)
    assert diagnostic["reason"] == reason
    assert sentinel.decode() not in json.dumps(diagnostic)
    assert caught.value.record == diagnostic
    if case == "timeout":
        assert diagnostic["stdout_bytes"] == len(sentinel)
        assert diagnostic["stderr_bytes"] is not None
        summary = _qualification_last_phase_record(captured)
        assert summary["last_phase"] == "stage_verifier"
        assert summary["last_sequence"] == 1
        assert summary["record_count"] == 1 and summary["rejected_record_count"] == 1
        assert sentinel.decode() not in captured.err
    if case == "execution":
        assert diagnostic["returncode"] is None
        assert diagnostic["stdout_bytes"] is None
        assert diagnostic["stderr_bytes"] is None
    if case == "output-bound":
        assert diagnostic["stdout_bytes"] == 64 * 1024 + 1
    if case == "stderr-bound":
        assert diagnostic["stderr_bytes"] == 16 * 1024 + 1


def test_qualification_diagnostic_rejects_unclosed_records_before_serialization(capsys):
    base = adopt._qualification_diagnostic("b" * 40, "c" * 64, "timeout",
                                           None, 2**40, None, 2**40)
    assert base["stdout_bytes"] == 64 * 1024 + 1
    assert base["elapsed_ms"] == 300_000
    for invalid in (
        {**base, "private": "PRIVATE sentinel"},
        {**base, "schema": True},
        {**base, "reason": "PRIVATE sentinel"},
        {**base, "stderr_bytes": True},
    ):
        adopt._emit_qualification_diagnostic(invalid)
    assert capsys.readouterr().err == ""


def test_qualification_checkpoint_summary_retains_only_validated_prefix_records():
    def line(sequence, phase, elapsed, *, candidate="b" * 40):
        record = {
            "schema": 1, "candidate_commit": candidate,
            "candidate_archive_sha256": "c" * 64, "sequence": sequence,
            "phase": phase, "elapsed_ms": elapsed,
        }
        return (adopt._QUALIFICATION_CHECKPOINT_PREFIX
                + json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode()

    prefix = line(1, "stage_verifier", 1) + line(2, "runtime_load", 2)
    valid = adopt._qualification_last_phase_summary(prefix, "b" * 40, "c" * 64)
    assert valid["last_phase"] == "runtime_load"
    assert valid["last_sequence"] == 2 and valid["last_elapsed_ms"] == 2
    assert valid["record_count"] == 2 and valid["rejected_record_count"] == 0

    rounded_equal = adopt._qualification_last_phase_summary(
        prefix + line(3, "before_snapshot", 2), "b" * 40, "c" * 64)
    assert rounded_equal["last_phase"] == "before_snapshot"
    assert rounded_equal["last_sequence"] == 3 and rounded_equal["last_elapsed_ms"] == 2
    assert rounded_equal["record_count"] == 3
    saturated_equal = adopt._qualification_last_phase_summary(
        line(1, "stage_verifier", 300_000)
        + line(2, "runtime_load", 300_000), "b" * 40, "c" * 64)
    assert saturated_equal["last_phase"] == "runtime_load"
    assert saturated_equal["last_elapsed_ms"] == 300_000

    truncated = adopt._qualification_last_phase_summary(
        prefix + b"HERMES_CORE_QUALIFICATION_CHECKPOINT_V1={truncated",
        "b" * 40, "c" * 64)
    assert truncated["last_phase"] == "runtime_load"
    assert truncated["record_count"] == 2 and truncated["rejected_record_count"] == 1

    wrong_request = adopt._qualification_last_phase_summary(
        line(1, "stage_verifier", 1, candidate="d" * 40), "b" * 40, "c" * 64)
    assert wrong_request["last_phase"] is None
    assert wrong_request["record_count"] == 0 and wrong_request["rejected_record_count"] == 1

    wrong_order = adopt._qualification_last_phase_summary(
        prefix + line(4, "after_snapshot", 3), "b" * 40, "c" * 64)
    assert wrong_order["last_phase"] is None
    assert wrong_order["record_count"] == 2 and wrong_order["rejected_record_count"] == 1

    backwards_phase = adopt._qualification_last_phase_summary(
        line(1, "runtime_load", 1) + line(2, "stage_verifier", 2),
        "b" * 40, "c" * 64)
    assert backwards_phase["last_phase"] is None
    assert backwards_phase["record_count"] == 1
    assert backwards_phase["rejected_record_count"] == 1

    decreasing_elapsed = adopt._qualification_last_phase_summary(
        line(1, "stage_verifier", 2) + line(2, "runtime_load", 1),
        "b" * 40, "c" * 64)
    assert decreasing_elapsed["last_phase"] is None
    assert decreasing_elapsed["record_count"] == 1
    assert decreasing_elapsed["rejected_record_count"] == 1

    oversized = adopt._qualification_last_phase_summary(
        b"x" * (16 * 1024 + 1), "b" * 40, "c" * 64)
    assert oversized["last_phase"] is None
    assert oversized["record_count"] == 0 and oversized["rejected_record_count"] == 1

    base_record = {
        "schema": 1, "candidate_commit": "b" * 40,
        "candidate_archive_sha256": "c" * 64, "sequence": 1,
        "phase": "stage_verifier", "elapsed_ms": 1,
    }
    invalid_lines = [
        (adopt._QUALIFICATION_CHECKPOINT_PREFIX
         + json.dumps({**base_record, "extra": "x"}, sort_keys=True,
                      separators=(",", ":")) + "\n").encode(),
        (adopt._QUALIFICATION_CHECKPOINT_PREFIX
         + json.dumps({**base_record, "phase": "private_phase"}, sort_keys=True,
                      separators=(",", ":")) + "\n").encode(),
        (adopt._QUALIFICATION_CHECKPOINT_PREFIX
         + '{"schema":1,"schema":1,"candidate_commit":"' + "b" * 40
         + '","candidate_archive_sha256":"' + "c" * 64
         + '","sequence":1,"phase":"stage_verifier","elapsed_ms":1}\n').encode(),
        (adopt._QUALIFICATION_CHECKPOINT_PREFIX
         + json.dumps(base_record, sort_keys=True) + "\n").encode(),
    ]
    for invalid_line in invalid_lines:
        invalid_summary = adopt._qualification_last_phase_summary(
            invalid_line, "b" * 40, "c" * 64)
        assert invalid_summary["last_phase"] is None
        assert invalid_summary["record_count"] == 0
        assert invalid_summary["rejected_record_count"] == 1

    too_many = b"".join(line(index, "stage_verifier", index)
                        for index in range(1, 18))
    too_many_summary = adopt._qualification_last_phase_summary(
        too_many, "b" * 40, "c" * 64)
    assert too_many_summary["last_phase"] is None
    assert too_many_summary["record_count"] == 1
    assert too_many_summary["rejected_record_count"] == 1

    skipped_optional_phases = adopt._qualification_last_phase_summary(
        line(1, "stage_verifier", 1) + line(2, "runtime_load", 2)
        + line(3, "before_snapshot", 3) + line(4, "adapter_update", 4)
        + line(5, "after_snapshot", 5) + line(6, "success_checks", 6)
        + line(7, "report_emission", 7), "b" * 40, "c" * 64)
    assert skipped_optional_phases["last_phase"] == "report_emission"
    assert skipped_optional_phases["record_count"] == 7
    assert skipped_optional_phases["rejected_record_count"] == 0

    overlong_line = line(1, "x" * 5000, 1)
    overlong_summary = adopt._qualification_last_phase_summary(
        overlong_line, "b" * 40, "c" * 64)
    assert overlong_summary["last_phase"] is None
    assert overlong_summary["record_count"] == 0
    assert overlong_summary["rejected_record_count"] == 1


def test_stack_observation_accepts_one_canonical_candidate_bound_sample():
    sample = {
        "schema": 2, "candidate_commit": "b" * 40,
        "candidate_archive_sha256": "c" * 64, "elapsed_ms": 250_000,
        "labels": ["listener", "updater"],
        "frames": [
            {"source_relative_path": "hermes_installer/core_runtime.py",
             "function": "_wait_for_listener", "line": 6995},
            {"source_relative_path": "hermes_installer/core_runtime.py",
             "function": "_update_owned_core_adapter_locked", "line": 6260},
        ],
        "examined_frames": 8,
        "unmatched_frames": 6, "truncated": False, "unknown": False,
    }
    line = (adopt._QUALIFICATION_STACK_SAMPLE_PREFIX
            + json.dumps(sample, sort_keys=True, separators=(",", ":")) + "\n").encode()
    checkpoint = (adopt._QUALIFICATION_CHECKPOINT_PREFIX + json.dumps({
        "schema": 1, "candidate_commit": "b" * 40,
        "candidate_archive_sha256": "c" * 64, "sequence": 1,
        "phase": "adapter_update", "elapsed_ms": 250_000,
    }, sort_keys=True, separators=(",", ":")) + "\n").encode()
    summary = adopt._qualification_stack_observation_summary(
        checkpoint + line, "b" * 40, "c" * 64)
    assert summary == sample
    assert adopt._valid_qualification_stack_observation_summary(summary)
    phase = adopt._qualification_last_phase_summary(
        checkpoint + line, "b" * 40, "c" * 64)
    assert phase["last_phase"] == "adapter_update"
    assert phase["record_count"] == 1 and phase["rejected_record_count"] == 0


def test_stack_observation_missing_or_invalid_records_are_unknown():
    candidate, archive = "b" * 40, "c" * 64
    expected = {
        "schema": 2, "candidate_commit": candidate,
        "candidate_archive_sha256": archive, "elapsed_ms": None,
        "labels": [], "frames": [], "examined_frames": 0, "unmatched_frames": 0,
        "truncated": False, "unknown": True,
    }
    valid = {
        "schema": 2, "candidate_commit": candidate,
        "candidate_archive_sha256": archive, "elapsed_ms": 250_000,
        "labels": ["importer"],
        "frames": [{"source_relative_path": "hermes_installer/core_runtime.py",
                    "function": "_run_same_materialization_import", "line": 4971}],
        "examined_frames": 3,
        "unmatched_frames": 2, "truncated": False, "unknown": False,
    }

    def encoded(record):
        return (adopt._QUALIFICATION_STACK_SAMPLE_PREFIX
                + json.dumps(record, sort_keys=True, separators=(",", ":"))
                + "\n").encode()

    assert adopt._qualification_stack_observation_summary(b"", candidate, archive) == expected
    invalid_records = (
        {**valid, "candidate_commit": "d" * 40},
        {**valid, "schema": True},
        {**valid, "elapsed_ms": None},
        {**valid, "labels": ["private_function"]},
        {**valid, "examined_frames": True},
        {**valid, "unmatched_frames": 3},
        {**valid, "labels": [], "unknown": False},
        {**valid, "truncated": True, "unknown": False},
        {**valid, "private": "PRIVATE sentinel"},
        {**valid, "labels": ["importer"] * 13},
        {**valid, "examined_frames": 33},
        {**valid, "frames": [{"source_relative_path": "outside.py",
                               "function": "_run_same_materialization_import", "line": 2}]},
        {**valid, "frames": [{"source_relative_path": "hermes_installer/core_runtime.py",
                               "function": "_update_owned_core_adapter_locked", "line": 2}]},
        {**valid, "frames": [{"source_relative_path": "hermes_installer/core_runtime.py",
                               "function": "_run_same_materialization_import", "line": True}]},
        {**valid, "frames": [{"source_relative_path": "hermes_installer/core_runtime.py",
                               "function": "_run_same_materialization_import",
                               "line": 2 * 1024 * 1024 + 1}]},
        {**valid, "frames": []},
    )
    for record in invalid_records:
        summary = adopt._qualification_stack_observation_summary(
            encoded(record), candidate, archive)
        assert summary == expected
    assert adopt._qualification_stack_observation_summary(
        encoded(valid) + encoded(valid), candidate, archive) == expected

    capped = {
        **valid, "labels": ["importer"] * 12,
        "frames": [valid["frames"][0]] * 12,
        "examined_frames": 32, "unmatched_frames": 0,
        "truncated": True, "unknown": True,
    }
    capped_summary = adopt._qualification_stack_observation_summary(
        encoded(capped), candidate, archive)
    assert capped_summary == capped
    assert capped_summary["elapsed_ms"] == 250_000
    assert capped_summary["labels"] == ["importer"] * 12

    noncanonical = (
        adopt._QUALIFICATION_STACK_SAMPLE_PREFIX
        + json.dumps(valid, separators=(",", ":")) + "\n").encode()
    assert adopt._qualification_stack_observation_summary(
        noncanonical, candidate, archive) == expected

    duplicate_key = (
        adopt._QUALIFICATION_STACK_SAMPLE_PREFIX
        + '{"schema":1,"schema":1}\n').encode()
    assert adopt._qualification_stack_observation_summary(
        duplicate_key, candidate, archive) == expected
    assert adopt._qualification_stack_observation_summary(
        encoded(valid)[:-1], candidate, archive) == expected
    historical_v1 = (adopt._QUALIFICATION_STACK_SAMPLE_V1_PREFIX
                     + json.dumps({"schema": 1}) + "\n").encode()
    assert adopt._qualification_stack_observation_summary(
        historical_v1, candidate, archive) == expected
    assert adopt._valid_qualification_stack_observation_summary(expected)


def test_stack_observation_emits_only_the_closed_unknown_summary(capsys):
    adopt._emit_qualification_stack_observation({
        "schema": 2, "candidate_commit": "b" * 40,
        "candidate_archive_sha256": "c" * 64, "elapsed_ms": None,
        "labels": [], "frames": [], "examined_frames": 0, "unmatched_frames": 0,
        "truncated": False, "unknown": True,
    })
    captured = capsys.readouterr()
    assert captured.out == ""
    lines = [line for line in captured.err.splitlines()
             if line.startswith(adopt._QUALIFICATION_STACK_OBSERVATION_PREFIX)]
    assert len(lines) == 1
    encoded = lines[0][len(adopt._QUALIFICATION_STACK_OBSERVATION_PREFIX):]
    record = json.loads(encoded)
    assert encoded == json.dumps(record, sort_keys=True, separators=(",", ":"))
    assert adopt._valid_qualification_stack_observation_summary(record)
    assert "PRIVATE" not in lines[0]
    assert len((lines[0] + "\n").encode("ascii")) <= 4096


def test_qualification_last_phase_emitter_rejects_unclosed_summary(capsys):
    summary = {
        "schema": 1, "candidate_commit": "b" * 40,
        "candidate_archive_sha256": "c" * 64, "last_phase": None,
        "last_sequence": None, "last_elapsed_ms": None,
        "record_count": 0, "rejected_record_count": 0,
        "private": "PRIVATE_SUMMARY_SENTINEL",
    }
    adopt._emit_qualification_last_phase_summary(summary)
    assert capsys.readouterr().err == ""


def test_completed_ingress_handoff_archives_raw_predecessor_then_replaces_atomically(
        tmp_path, monkeypatch):
    runtime, active, predecessor, saved, config_path = _completed_ingress_handoff_fixture(
        tmp_path, monkeypatch)
    new_gateway = _unit("core_gateway", NEW_SOURCE)
    new_inspector = _unit("core_gateway_inspector", NEW_SOURCE)
    new_config = b'{"allowed_emails":["owner@example.test"],"new":true}\n'
    config_info = config_path.stat()
    old_inode = active.stat().st_ino

    adopt._save_ingress_backup(
        "b" * 40, saved, config_path.read_bytes(), config_info,
        {adopt.FIXED_UNITS[adopt.GATEWAY]: new_gateway,
         adopt.FIXED_UNITS[adopt.INSPECTOR]: new_inspector},
        new_config, adapter_refresh=_adapter_refresh_row(),
        completed_predecessor=predecessor)

    replacement = json.loads(active.read_bytes())
    parsed, *_ = adopt._backup_value("b" * 40)
    adopt._verify_archived_completed_ingress(parsed)
    archived = adopt.INGRESS_HISTORY / (predecessor["sha256"] + ".json")
    assert archived.read_bytes() == predecessor["raw"]
    assert stat.S_IMODE(archived.stat().st_mode) == 0o600
    assert replacement["prior_completed_ingress_sha256"] == predecessor["sha256"]
    assert parsed["prior_completed_ingress_sha256"] == predecessor["sha256"]
    assert replacement["state"] == "prepared"
    assert replacement["runtime_inspector_sha256"] is None
    assert active.stat().st_ino != old_inode
    assert predecessor["raw"] != active.read_bytes()


def test_completed_ingress_handoff_refuses_changed_active_bytes_without_replacing(
        tmp_path, monkeypatch):
    _runtime, active, predecessor, saved, config_path = _completed_ingress_handoff_fixture(
        tmp_path, monkeypatch)
    active.write_bytes(b'{"state":"foreign-drift"}\n')
    drifted = active.read_bytes()
    new_gateway = _unit("core_gateway", NEW_SOURCE)
    new_inspector = _unit("core_gateway_inspector", NEW_SOURCE)
    with pytest.raises(adopt._IngressSnapshotConflict):
        adopt._save_ingress_backup(
            "b" * 40, saved, config_path.read_bytes(), config_path.stat(),
            {adopt.FIXED_UNITS[adopt.GATEWAY]: new_gateway,
             adopt.FIXED_UNITS[adopt.INSPECTOR]: new_inspector},
            b'{"new":true}\n', adapter_refresh=_adapter_refresh_row(),
            completed_predecessor=predecessor)
    assert active.read_bytes() == drifted


def test_completed_ingress_history_is_immutable_and_digest_addressed(tmp_path, monkeypatch):
    runtime = tmp_path / "core-runtime"
    runtime.mkdir(mode=0o700)
    runtime.chmod(0o700)
    monkeypatch.setattr(adopt, "INGRESS_HISTORY", runtime / "native-adoption-ingress-history")
    raw = b'{"schema":1,"state":"migrated","embedded":"retained exact bytes"}\n'
    digest, first_identity = adopt._archive_completed_ingress_bytes(raw)
    path = adopt.INGRESS_HISTORY / (digest + ".json")
    inode = path.stat().st_ino
    assert path.read_bytes() == raw
    assert adopt._archive_completed_ingress_bytes(raw)[0] == digest
    assert path.stat().st_ino == inode
    path.write_bytes(b"changed archive bytes")
    with pytest.raises(RuntimeError, match="history entry"):
        adopt._archive_completed_ingress_bytes(raw)
    assert path.read_bytes() == b"changed archive bytes"
    assert first_identity[1] == inode


@pytest.mark.parametrize("replaced", ["parent", "history"])
def test_completed_ingress_history_reader_rejects_replaced_directory_before_archive_read(
        tmp_path, monkeypatch, replaced):
    real_parent = tmp_path / "core-runtime"
    real_parent.mkdir(mode=0o700)
    real_parent.chmod(0o700)
    adopt.os.chown(real_parent, 0, 0)
    real_history = real_parent / "native-adoption-ingress-history"
    real_history.mkdir(mode=0o700)
    real_history.chmod(0o700)
    adopt.os.chown(real_history, 0, 0)
    if replaced == "parent":
        alias_parent = tmp_path / "replaced-parent"
        alias_parent.symlink_to(real_parent, target_is_directory=True)
        history = alias_parent / real_history.name
    else:
        history = real_parent / "replaced-history"
        history.symlink_to(real_history, target_is_directory=True)
    monkeypatch.setattr(adopt, "INGRESS_HISTORY", history)
    monkeypatch.setattr(adopt, "_read_fixed", lambda *_args, **_kwargs:
                        pytest.fail("archive bytes must not be read from replaced history custody"))

    with pytest.raises(RuntimeError, match="fixed ingress history"):
        adopt._verify_archived_completed_ingress({"prior_completed_ingress_sha256": "a" * 64})


def test_nonterminal_predecessor_is_refused_before_history_or_core_reads(tmp_path, monkeypatch):
    runtime = tmp_path / "core-runtime"
    runtime.mkdir(mode=0o700)
    runtime.chmod(0o700)
    active = runtime / "native-adoption-ingress-backup.json"
    raw = b'{"candidate_sha":"' + b"a" * 40 + b'"}\n'
    active.write_bytes(raw)
    active.chmod(0o600)
    monkeypatch.setattr(adopt, "INGRESS_BACKUP", active)
    history = runtime / "native-adoption-ingress-history"
    monkeypatch.setattr(adopt, "INGRESS_HISTORY", history)
    monkeypatch.setattr(adopt, "_backup_value", lambda _candidate: (
        {"state": "recovery-required", "candidate_sha": "a" * 40,
         "post_core_config_sha256": "b" * 64}, b"", b"", b""))

    class NoCoreRead:
        def _read_active_adapter_runtime(self):
            pytest.fail("nonterminal predecessor must deny before Core/service reads")

    with pytest.raises(RuntimeError, match="not complete"):
        adopt._retain_completed_ingress_for_refresh(NoCoreRead(), runtime / "observer.sock",
                                                     "c" * 40)
    assert active.read_bytes() == raw
    assert not history.exists()


@pytest.mark.parametrize("case", ["duplicate-root", "unowned-root", "unit-root-mismatch",
                                    "config-digest-mismatch"])
def test_qualification_refusals_happen_before_systemd_effects(monkeypatch, case):
    gateway, inspector, config = _unit("core_gateway"), _unit("core_gateway_inspector"), None
    if case == "duplicate-root":
        gateway += b"Environment=PYTHONPATH=" + OLD_SOURCE + b"\n"
    elif case == "unit-root-mismatch":
        inspector = _unit("core_gateway_inspector", b"/opt/hermes-installer-core-ccccccccc/src")
    elif case == "config-digest-mismatch":
        config = json.dumps({"gateway_unit_sha256": "0" * 64,
                             "credential_ref": "keyring:codex-primary"}).encode()
    fixed, effects, *_ = _switch_fixture(monkeypatch, gateway=gateway,
                                         inspector=inspector, config=config,
                                         installed=case != "unowned-root")

    with pytest.raises(RuntimeError):
        adopt._source_switch(Path(NEW_SOURCE.decode()))

    assert effects == []
    assert fixed[adopt.FIXED_UNITS[adopt.GATEWAY]][0] == gateway
    assert fixed[adopt.FIXED_UNITS[adopt.INSPECTOR]][0] == inspector


@pytest.mark.parametrize("failed_write", [1, 2, 3])
def test_failed_old_file_restore_keeps_all_ingress_stopped(monkeypatch, failed_write):
    old_gateway, old_inspector = _unit("core_gateway"), _unit("core_gateway_inspector")
    new_gateway = old_gateway.replace(OLD_SOURCE, NEW_SOURCE, 1)
    new_inspector = old_inspector.replace(OLD_SOURCE, NEW_SOURCE, 1)
    old_config = json.dumps({"gateway_unit_sha256": hashlib.sha256(old_gateway).hexdigest(),
                             "credential_ref": "keyring:codex-primary"}).encode() + b"\n"
    new_config = json.dumps({"gateway_unit_sha256": hashlib.sha256(new_gateway).hexdigest(),
                             "credential_ref": "keyring:codex-primary"}).encode() + b"\n"
    files = {adopt.FIXED_UNITS[adopt.GATEWAY]: new_gateway,
             adopt.FIXED_UNITS[adopt.INSPECTOR]: new_inspector,
             adopt.GATEWAY_CONFIG: new_config}
    value = {"new_gateway_sha256": hashlib.sha256(new_gateway).hexdigest(),
             "new_inspector_sha256": hashlib.sha256(new_inspector).hexdigest(),
             "new_config_sha256": hashlib.sha256(new_config).hexdigest(),
             "gateway_gid": 981, "gateway_mode": 0o440}
    monkeypatch.setattr(adopt, "_unit_is_fixed", lambda _name: True)
    monkeypatch.setattr(adopt, "_read_fixed", lambda path, **_kwargs:
                        (files[path], SimpleNamespace(st_mode=stat.S_IFREG | 0o440, st_gid=981)))
    writes = []

    def write(path, raw, **_kwargs):
        writes.append(path)
        if len(writes) == failed_write:
            raise OSError("injected atomic replacement failure")
        files[path] = raw

    actions = []
    def run(*args, **_kwargs):
        actions.append(args)
        return ""

    monkeypatch.setattr(adopt, "_atomic_fixed", write)
    monkeypatch.setattr(adopt, "_run", run)

    assert not adopt._restore_old_ingress(value, old_gateway, old_inspector, old_config)
    assert [call[2] for call in actions if len(call) > 2 and call[1] == "stop"] == [
        adopt.TUNNEL, adopt.GATEWAY, adopt.INSPECTOR,
        adopt.TUNNEL, adopt.GATEWAY, adopt.INSPECTOR,
    ]
    assert not any(call[1] == "start" for call in actions)
    # Atomic replacement failure can leave old/new files mixed, never a partial
    # file. Public ingress is stopped while recovery is incomplete.
    assert files[adopt.FIXED_UNITS[adopt.GATEWAY]] in {old_gateway, new_gateway}
    assert files[adopt.FIXED_UNITS[adopt.INSPECTOR]] in {old_inspector, new_inspector}
    assert files[adopt.GATEWAY_CONFIG] in {old_config, new_config}


def test_union_rollback_restores_exact_original_one_email_config(monkeypatch):
    old_gateway, old_inspector = _unit("core_gateway"), _unit("core_gateway_inspector")
    new_gateway = old_gateway.replace(OLD_SOURCE, NEW_SOURCE, 1)
    new_inspector = old_inspector.replace(OLD_SOURCE, NEW_SOURCE, 1)
    old_config = json.dumps({
        "gateway_unit_sha256": hashlib.sha256(old_gateway).hexdigest(),
        "allowed_emails": ["Owner@example.test"],
        "credential_ref": "keyring:codex-primary",
    }, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    new_config = json.dumps({
        "gateway_unit_sha256": hashlib.sha256(new_gateway).hexdigest(),
        "allowed_emails": ["owner@example.test", "member@example.test",
                            "third@example.test"],
        "credential_ref": "keyring:codex-primary",
    }, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    files = {adopt.FIXED_UNITS[adopt.GATEWAY]: new_gateway,
             adopt.FIXED_UNITS[adopt.INSPECTOR]: new_inspector,
             adopt.GATEWAY_CONFIG: new_config}
    states = {name: "active" for name in (adopt.INSPECTOR, adopt.GATEWAY, adopt.TUNNEL)}
    info = SimpleNamespace(st_mode=stat.S_IFREG | 0o440, st_gid=981)
    monkeypatch.setattr(adopt, "_unit_is_fixed", lambda _name: True)
    monkeypatch.setattr(adopt, "_read_fixed", lambda path, **_kwargs: (files[path], info))
    monkeypatch.setattr(adopt, "_atomic_fixed", lambda path, raw, **_kwargs:
                        files.__setitem__(path, raw))
    monkeypatch.setattr(adopt, "_unit_state", lambda name: states[name])
    monkeypatch.setattr(adopt, "_unit_is_exact_and_active", lambda name: states[name] == "active")
    monkeypatch.setattr(adopt, "_verify_inspector_process", lambda *_args: None)
    monkeypatch.setattr(adopt, "_verify_gateway_tunnel", lambda *_args, **_kwargs: {
        adopt.GATEWAY: True, adopt.TUNNEL: True})
    monkeypatch.setattr(adopt, "_run", lambda *args, **_kwargs:
                        states.__setitem__(args[2], "inactive") if args[1] == "stop" else
                        states.__setitem__(args[2], "active") if args[1] == "start" else "")
    gateway_module = ModuleType("hermes_installer.remote.core_gateway")
    gateway_module.CoreGatewayConfig = SimpleNamespace(load=lambda **_kwargs: object())
    monkeypatch.setitem(__import__("sys").modules, gateway_module.__name__, gateway_module)
    journal = {
        "new_gateway_sha256": hashlib.sha256(new_gateway).hexdigest(),
        "new_inspector_sha256": hashlib.sha256(new_inspector).hexdigest(),
        "new_config_sha256": hashlib.sha256(new_config).hexdigest(),
        "post_core_config_sha256": None,
        "gateway_gid": 981, "gateway_mode": 0o440,
    }

    assert adopt._restore_old_ingress(journal, old_gateway, old_inspector, old_config)
    assert files[adopt.FIXED_UNITS[adopt.GATEWAY]] == old_gateway
    assert files[adopt.FIXED_UNITS[adopt.INSPECTOR]] == old_inspector
    assert files[adopt.GATEWAY_CONFIG] == old_config


@pytest.mark.parametrize("failed_start", [adopt.INSPECTOR, adopt.GATEWAY, adopt.TUNNEL])
def test_failed_restore_start_closes_partial_ingress(monkeypatch, failed_start):
    old_gateway, old_inspector = _unit("core_gateway"), _unit("core_gateway_inspector")
    new_gateway = old_gateway.replace(OLD_SOURCE, NEW_SOURCE, 1)
    new_inspector = old_inspector.replace(OLD_SOURCE, NEW_SOURCE, 1)
    old_config = json.dumps({"gateway_unit_sha256": hashlib.sha256(old_gateway).hexdigest()}).encode()
    new_config = json.dumps({"gateway_unit_sha256": hashlib.sha256(new_gateway).hexdigest()}).encode()
    files = {adopt.FIXED_UNITS[adopt.GATEWAY]: new_gateway,
             adopt.FIXED_UNITS[adopt.INSPECTOR]: new_inspector,
             adopt.GATEWAY_CONFIG: new_config}
    value = {"new_gateway_sha256": hashlib.sha256(new_gateway).hexdigest(),
             "new_inspector_sha256": hashlib.sha256(new_inspector).hexdigest(),
             "new_config_sha256": hashlib.sha256(new_config).hexdigest(),
             "gateway_gid": 981, "gateway_mode": 0o440}
    states = {name: "inactive" for name in (adopt.INSPECTOR, adopt.GATEWAY, adopt.TUNNEL)}
    actions = []

    def run(*args, **_kwargs):
        actions.append(args)
        if args[1] == "start":
            if args[2] == failed_start:
                raise RuntimeError("injected start failure")
            states[args[2]] = "active"
        elif args[1] == "stop":
            states[args[2]] = "inactive"
        return ""

    monkeypatch.setattr(adopt, "_unit_is_fixed", lambda _name: True)
    monkeypatch.setattr(adopt, "_read_fixed", lambda path, **_kwargs:
                        (files[path], SimpleNamespace(st_mode=stat.S_IFREG | 0o440, st_gid=981)))
    monkeypatch.setattr(adopt, "_atomic_fixed", lambda path, raw, **_kwargs: files.__setitem__(path, raw))
    monkeypatch.setattr(adopt, "_run", run)
    monkeypatch.setattr(adopt, "_unit_state", lambda name: states.get(name, "inactive"))
    monkeypatch.setattr(adopt, "_unit_is_exact_and_active", lambda name: states[name] == "active")
    monkeypatch.setattr(adopt, "_verify_inspector_process", lambda *_args: None)
    monkeypatch.setattr(adopt, "_verify_gateway_tunnel", lambda *_args, **_kwargs: {
        adopt.GATEWAY: True, adopt.TUNNEL: True})
    monkeypatch.setattr(adopt, "_unit_source", lambda *_args: OLD_SOURCE)
    monkeypatch.setitem(__import__("sys").modules,
                        "hermes_installer.remote.core_gateway",
                        SimpleNamespace(CoreGatewayConfig=SimpleNamespace(
                            load=lambda **_kwargs: object())))

    assert not adopt._restore_old_ingress(value, old_gateway, old_inspector, old_config)
    assert files[adopt.FIXED_UNITS[adopt.GATEWAY]] == old_gateway
    assert files[adopt.FIXED_UNITS[adopt.INSPECTOR]] == old_inspector
    assert files[adopt.GATEWAY_CONFIG] == old_config
    assert all(states[name] == "inactive" for name in states)
    assert [call[2] for call in actions if call[1] == "start"] == [
        adopt.INSPECTOR, adopt.GATEWAY, adopt.TUNNEL,
    ][:([adopt.INSPECTOR, adopt.GATEWAY, adopt.TUNNEL].index(failed_start) + 1)]


def test_cli_rollback_recovers_core_before_restoring_old_ingress(monkeypatch, tmp_path):
    candidate = "b" * 40
    source = Path(f"/opt/hermes-installer-core-{candidate[:9]}/src")
    old_gateway, old_inspector = _unit("core_gateway"), _unit("core_gateway_inspector")
    old_config = json.dumps({"gateway_unit_sha256": hashlib.sha256(old_gateway).hexdigest()}).encode()
    value = {
        "old_gateway_sha256": hashlib.sha256(old_gateway).hexdigest(),
        "old_inspector_sha256": hashlib.sha256(old_inspector).hexdigest(),
        "old_config_sha256": hashlib.sha256(old_config).hexdigest(),
        "new_gateway_sha256": "1" * 64, "new_inspector_sha256": "2" * 64,
        "new_config_sha256": "3" * 64,
    }
    events = []
    legacy = {"value": False}
    core = SimpleNamespace(
        SERVICE="hermes-jarvis-core.service",
        _validate_adapter_source_path=lambda: events.append("validate-source"),
        _owned_listener=lambda **kwargs: legacy["value"] if kwargs.get("legacy_launcher") else False,
        _journal=lambda: {"adapter_migration_state": "preparing"},
        _recover_interrupted_adapter_migration=lambda: (events.append("recover-core"),
                                                           legacy.__setitem__("value", True)),
        _owned_unit_loaded=lambda: True,
    )
    core.__file__ = str(source / "hermes_installer" / "core_runtime.py")
    package = ModuleType("hermes_installer")
    package.__path__ = []
    package.core_runtime = core
    remote = ModuleType("hermes_installer.remote")
    remote.__path__ = []
    gateway_module = ModuleType("hermes_installer.remote.core_gateway")
    gateway_module.CoreGatewayConfig = SimpleNamespace(load=lambda **_kwargs: object())
    observer_module = ModuleType("hermes_installer.remote.core_native_observer")
    observer_module.CORE_NATIVE_OBSERVER_SOCKET = tmp_path / "unused.sock"
    remote.core_gateway = gateway_module
    remote.core_native_observer = observer_module
    monkeypatch.setitem(sys.modules, "hermes_installer", package)
    monkeypatch.setitem(sys.modules, "hermes_installer.remote", remote)
    monkeypatch.setitem(sys.modules, "hermes_installer.remote.core_gateway", gateway_module)
    monkeypatch.setitem(sys.modules, "hermes_installer.remote.core_native_observer", observer_module)
    monkeypatch.setattr(adopt.os, "geteuid", lambda: 0)
    monkeypatch.setattr(sys, "argv", [str(HELPER_PATH), "--candidate-sha", candidate, "--rollback"])
    monkeypatch.setattr(adopt.Path, "resolve", lambda path, strict=False: path)
    monkeypatch.setattr(adopt, "_verify_source_provenance",
                        lambda sha, path: events.append(("source", sha, path)))
    monkeypatch.setattr(adopt, "_backup_value", lambda _sha: (value, old_gateway,
                                                                 old_inspector, old_config))
    fixed_bytes = {adopt.FIXED_UNITS[adopt.GATEWAY]: old_gateway,
                   adopt.FIXED_UNITS[adopt.INSPECTOR]: old_inspector,
                   adopt.GATEWAY_CONFIG: old_config}
    monkeypatch.setattr(adopt, "_read_fixed", lambda path, **_kwargs:
                        (fixed_bytes[path], SimpleNamespace(st_mode=stat.S_IFREG | 0o440, st_gid=981)))
    monkeypatch.setattr(adopt, "_unit_is_fixed", lambda _name: True)
    monkeypatch.setattr(adopt, "_run", lambda *args, **_kwargs: events.append(args) or "")
    monkeypatch.setattr(adopt, "_restore_old_ingress",
                        lambda *_args: events.append("restore-old-ingress") or True)

    class Backup:
        def unlink(self):
            events.append("remove-backup")

    monkeypatch.setattr(adopt, "INGRESS_BACKUP", Backup())

    assert adopt.main() == 0
    assert events.index("recover-core") < events.index("restore-old-ingress")
    assert events.index("restore-old-ingress") < events.index("remove-backup")
    assert events[0] == ("source", candidate, source)


@pytest.mark.parametrize("failure", [None, "ingress-drift", "late-ingress-drift",
                                     "late-ingress-read-failure", "late-unit-ownership",
                                     "owner", "migration", "migration-unclassified",
                                     "inspector-restart", "fresh-observer"])
def test_apply_keeps_gateway_and_tunnel_stopped_until_core_and_observer_are_fresh(
        monkeypatch, tmp_path, failure, capsys):
    candidate = "c" * 40
    source = Path(f"/opt/hermes-installer-core-{candidate[:9]}/src")
    old_gateway, old_inspector = _unit("core_gateway"), _unit("core_gateway_inspector")
    new_gateway = old_gateway.replace(OLD_SOURCE, NEW_SOURCE, 1)
    new_inspector = old_inspector.replace(OLD_SOURCE, NEW_SOURCE, 1)
    old_config = json.dumps({"gateway_unit_sha256": hashlib.sha256(old_gateway).hexdigest(),
                             "credential_ref": "keyring:codex-primary"}).encode() + b"\n"
    new_config = json.dumps({"gateway_unit_sha256": hashlib.sha256(new_gateway).hexdigest(),
                             "credential_ref": "keyring:codex-primary"}).encode() + b"\n"

    def fake_info(raw, *, gid, mode, inode):
        return SimpleNamespace(st_mode=stat.S_IFREG | mode, st_uid=0, st_gid=gid,
                               st_dev=1, st_ino=inode, st_size=len(raw), st_mtime_ns=1)

    config_info = fake_info(old_config, gid=981, mode=0o440, inode=3)
    saved = {
        adopt.FIXED_UNITS[adopt.GATEWAY]:
            (old_gateway, fake_info(old_gateway, gid=0, mode=0o644, inode=1)),
        adopt.FIXED_UNITS[adopt.INSPECTOR]:
            (old_inspector, fake_info(old_inspector, gid=0, mode=0o644, inode=2)),
    }
    ingress_files = {
        adopt.FIXED_UNITS[adopt.GATEWAY]: saved[adopt.FIXED_UNITS[adopt.GATEWAY]],
        adopt.FIXED_UNITS[adopt.INSPECTOR]: saved[adopt.FIXED_UNITS[adopt.INSPECTOR]],
        adopt.GATEWAY_CONFIG: (old_config, config_info),
    }
    events = []
    legacy = {"value": True}
    states = {adopt.GATEWAY: "active", adopt.TUNNEL: "active", adopt.INSPECTOR: "active"}
    backup_state = {"present": False}

    def migrate():
        assert states[adopt.GATEWAY] == states[adopt.TUNNEL] == "inactive"
        events.append("migrate-core")
        if failure == "migration":
            raise CoreRuntimeError("native bridge activation is unavailable; existing core remains active")
        if failure == "migration-unclassified":
            raise RuntimeError("native bridge activation is unavailable; existing core remains active")
        legacy["value"] = False
        return "migration verified"

    def owned_listener(**kwargs):
        if kwargs.get("legacy_launcher"):
            events.append("verify-legacy-core")
            return legacy["value"]
        events.append("verify-migrated-core")
        return not legacy["value"]

    class CoreRuntimeError(RuntimeError):
        pass

    def read_active_adapter():
        events.append("read-active-adapter-runtime")
        raise CoreRuntimeError(
            "no complete journaled native adapter runtime is eligible for update")

    def read_legacy_runtime():
        # Exercise the current selector contract: native-adapter denial is
        # followed by the full legacy-owned reader, whose process and fixed
        # ingress evidence are still current in this fixture.
        events.append("read-legacy-owned-runtime")
        if (not all(adopt._unit_is_fixed(name)
                    for name in (adopt.INSPECTOR, adopt.GATEWAY, adopt.TUNNEL))
                or any(states[name] != "active"
                       for name in (adopt.INSPECTOR, adopt.GATEWAY, adopt.TUNNEL))
                or not owned_listener(legacy_launcher=True)):
            raise CoreRuntimeError("legacy owned runtime fixture is not current")
        return ({"state": "active", "source": OLD_SOURCE.decode()},
                b"legacy journal snapshot", {"source": OLD_SOURCE})

    core = SimpleNamespace(
        SERVICE="hermes-jarvis-core.service",
        CoreRuntimeError=CoreRuntimeError,
        _validate_adapter_source_path=lambda: events.append("validate-source"),
        _owned_listener=owned_listener,
        _read_active_adapter_runtime=read_active_adapter,
        _read_legacy_owned_runtime=read_legacy_runtime,
        migrate_owned_core_to_adapter_path=migrate,
    )
    core.__file__ = str(source / "hermes_installer" / "core_runtime.py")
    package = ModuleType("hermes_installer")
    package.__path__ = []
    package.core_runtime = core
    remote = ModuleType("hermes_installer.remote")
    remote.__path__ = []
    gateway_module = ModuleType("hermes_installer.remote.core_gateway")
    gateway_module.CoreGatewayConfig = SimpleNamespace(
        load=lambda **_kwargs: (events.append("load-gateway-config") or object()))
    observer_module = ModuleType("hermes_installer.remote.core_native_observer")
    observer_module.CORE_NATIVE_OBSERVER_SOCKET = tmp_path / "unused.sock"
    lifecycle_module = ModuleType("hermes_installer.remote.obsidian_owner_lifecycle")

    def prepare_owner():
        assert states[adopt.GATEWAY] == states[adopt.TUNNEL] == "inactive"
        events.append("prepare-owner")
        if failure == "owner":
            raise RuntimeError("injected owner preparation failure")

    lifecycle_module.prepare_sole_existing_chat_owner_for_legacy_migration = prepare_owner
    remote.core_gateway = gateway_module
    remote.core_native_observer = observer_module
    remote.obsidian_owner_lifecycle = lifecycle_module
    for name, module in (
            ("hermes_installer", package), ("hermes_installer.remote", remote),
            ("hermes_installer.remote.core_gateway", gateway_module),
            ("hermes_installer.remote.core_native_observer", observer_module),
            ("hermes_installer.remote.obsidian_owner_lifecycle", lifecycle_module)):
        monkeypatch.setitem(sys.modules, name, module)

    class Backup:
        def exists(self):
            return backup_state["present"]

        def is_symlink(self):
            return False

        def unlink(self, **_kwargs):
            events.append("remove-backup")
            backup_state["present"] = False

    monkeypatch.setattr(adopt, "INGRESS_BACKUP", Backup())
    monkeypatch.setattr(adopt.os, "geteuid", lambda: 0)
    monkeypatch.setattr(adopt.Path, "resolve", lambda path, strict=False: path)
    monkeypatch.setattr(sys, "argv", [str(HELPER_PATH), "--candidate-sha", candidate, "--apply"])
    monkeypatch.setattr(adopt, "_verify_source_provenance",
                        lambda sha, path: events.append(("source", sha, path)))
    def unit_is_fixed(name):
        return not (failure == "late-unit-ownership" and "save-backup" in events
                    and name == adopt.GATEWAY)

    monkeypatch.setattr(adopt, "_unit_is_fixed", unit_is_fixed)
    monkeypatch.setattr(adopt, "_unit_is_exact_and_active", lambda _name: True)
    monkeypatch.setattr(adopt, "_verify_inspector_process", lambda *_args: None)
    def read_fixed(path, **_kwargs):
        if (failure == "late-ingress-read-failure" and "save-backup" in events
                and path == adopt.GATEWAY_CONFIG):
            raise RuntimeError("fixed input permissions changed")
        return ingress_files[path]

    monkeypatch.setattr(adopt, "_read_fixed", read_fixed)
    monkeypatch.setattr(adopt, "_verify_gateway_tunnel",
                        lambda *_args, **_kwargs: events.append("verify-ingress") or {
                            adopt.GATEWAY: True, adopt.TUNNEL: True})

    def wait_socket(**_kwargs):
        assert states[adopt.GATEWAY] == states[adopt.TUNNEL] == "inactive"
        assert "prepare-owner" in events and "migrate-core" in events
        events.append("fresh-observer")
        if failure == "fresh-observer":
            raise RuntimeError("injected observer failure")
        return (1, 3)

    monkeypatch.setattr(adopt, "_wait_observer_socket", wait_socket)
    def source_switch(_source, **_kwargs):
        if failure == "ingress-drift":
            raw, info = ingress_files[adopt.FIXED_UNITS[adopt.INSPECTOR]]
            changed = raw + b"# drift before backup\n"
            ingress_files[adopt.FIXED_UNITS[adopt.INSPECTOR]] = (
                changed, SimpleNamespace(**{**vars(info), "st_size": len(changed),
                                             "st_ino": info.st_ino + 1}))
        return (saved, old_config, config_info,
                {adopt.FIXED_UNITS[adopt.GATEWAY]: new_gateway,
                 adopt.FIXED_UNITS[adopt.INSPECTOR]: new_inspector}, new_config)

    monkeypatch.setattr(adopt, "_source_switch", source_switch)

    actual_recheck_snapshot = adopt._recheck_ingress_snapshot

    def recheck_snapshot(*args):
        events.append("recheck-ingress-snapshot")
        actual_recheck_snapshot(*args)

    monkeypatch.setattr(adopt, "_recheck_ingress_snapshot", recheck_snapshot)
    def save_backup(*_args):
        events.append("save-backup")
        backup_state["present"] = True
        if failure == "late-ingress-drift":
            raw, info = ingress_files[adopt.GATEWAY_CONFIG]
            changed = raw + b" "
            ingress_files[adopt.GATEWAY_CONFIG] = (
                changed, SimpleNamespace(**{**vars(info), "st_size": len(changed),
                                             "st_ino": info.st_ino + 1}))

    monkeypatch.setattr(adopt, "_save_ingress_backup", save_backup)
    monkeypatch.setattr(adopt, "_set_runtime_inspector_digest",
                        lambda *_args: events.append("journal-runtime-inspector"))
    monkeypatch.setattr(adopt, "_set_backup_state", lambda state: events.append(("backup-state", state)))

    def run(*args, **_kwargs):
        if args[1] in {"stop", "start", "restart"}:
            action, name = args[1], args[2]
            events.append((action, name))
            if action == "stop":
                states[name] = "inactive"
            elif action == "start":
                states[name] = "active"
            else:
                if failure == "inspector-restart" and name == adopt.INSPECTOR:
                    raise RuntimeError("injected Inspector restart failure")
                states[name] = "active"
        return ""

    original_replace_units = adopt._replace_ingress_units

    def replace_units(*args):
        events.append("switch-fixed-units")
        return original_replace_units(*args)

    monkeypatch.setattr(adopt, "_run", run)
    monkeypatch.setattr(adopt, "_atomic_fixed",
                        lambda path, *_args, **_kwargs: events.append(("write", path)))
    monkeypatch.setattr(adopt, "_replace_ingress_units", replace_units)
    monkeypatch.setattr(adopt, "_restore_legacy_core",
                        lambda _core, _source: events.append("recover-core") or True)
    monkeypatch.setattr(adopt, "_restore_old_ingress",
                        lambda *_args: events.append("restore-old-ingress") or True)
    monkeypatch.setattr(adopt, "_backup_value", lambda _sha: ({}, old_gateway,
                                                                 old_inspector, old_config))
    # The dedicated _refresh_migrated_core_config tests exercise the journal,
    # protected backup and CAS checks. Keep this effect-order fixture focused on
    # the main transaction sequencing while modeling its successful config bind.
    def bind_migrated_core(*_args):
        events.append("bind-migrated-core-config")
        bound = json.loads(new_config)
        bound["core_unit_sha256"] = "3" * 64
        bound["core_launcher_sha256"] = "4" * 64
        return json.dumps(bound, sort_keys=True).encode() + b"\n"

    monkeypatch.setattr(adopt, "_refresh_migrated_core_config", bind_migrated_core)

    result = adopt.main()
    assert events.index("read-active-adapter-runtime") < events.index("read-legacy-owned-runtime")
    assert events.index("read-legacy-owned-runtime") < events.index("load-gateway-config")
    gateway_tunnel_starts = [index for index, event in enumerate(events)
                             if isinstance(event, tuple) and event[0] == "start"
                             and event[1] in {adopt.GATEWAY, adopt.TUNNEL}]
    migrate_at = events.index("migrate-core") if "migrate-core" in events else None
    fresh_checks = [index for index, event in enumerate(events) if event == "fresh-observer"]
    fresh_at = fresh_checks[0] if fresh_checks else None
    if failure is None:
        assert result == 0
        assert migrate_at is not None and fresh_at is not None
        assert gateway_tunnel_starts
        assert len(fresh_checks) == 1
        assert all(index > migrate_at and index > fresh_checks[-1]
                   for index in gateway_tunnel_starts)
        assert events.index("prepare-owner") < migrate_at < fresh_at
        assert migrate_at < events.index("verify-migrated-core")
        assert events.index("save-backup") < events.index("journal-runtime-inspector")
        assert events.index("journal-runtime-inspector") < events.index("switch-fixed-units")
        assert events.index("verify-migrated-core") < events.index(("restart", adopt.INSPECTOR))
        assert events.index(("restart", adopt.INSPECTOR)) < fresh_at
        assert backup_state["present"]
        assert "save-backup" in events and "remove-backup" not in events
        assert events.index("recheck-ingress-snapshot") < events.index("save-backup")
    elif failure == "ingress-drift":
        assert result == 4
        assert "recheck-ingress-snapshot" in events
        assert "save-backup" not in events
        assert not any(isinstance(event, tuple) and event[0] in {"stop", "start", "restart"}
                       for event in events)
        assert not backup_state["present"]
    elif failure in {"late-ingress-drift", "late-ingress-read-failure",
                     "late-unit-ownership"}:
        assert result == 4
        assert "save-backup" in events
        assert "restore-old-ingress" not in events
        assert not any(isinstance(event, tuple) and event[0] in {"stop", "start", "restart"}
                       for event in events)
        assert backup_state["present"]
    else:
        assert result == 4
        assert not gateway_tunnel_starts
        assert "restore-old-ingress" in events
        expected_phase = {
            "owner": "prepare existing Chat owner and vault",
            "migration": "migrate owned Core and verify listener",
            "migration-unclassified": "migrate owned Core and verify listener",
            "inspector-restart": "restart Inspector for migrated Core PID",
            "fresh-observer": "bind fresh Inspector observer to migrated Core",
        }[failure]
        output = capsys.readouterr().out
        assert "Failed phase: " + expected_phase in output
        if failure in {"migration", "migration-unclassified"}:
            expected_reason = "native_bridge_unavailable" if failure == "migration" else "unclassified"
            assert "Core migration reason code: " + expected_reason in output


@pytest.mark.parametrize("fail_observer", [False, True])
def test_resume_requires_exact_saved_candidate_and_keeps_ingress_closed_until_observer(
        monkeypatch, tmp_path, fail_observer):
    candidate = "f" * 40
    source = Path(f"/opt/hermes-installer-core-{candidate[:9]}/src")
    old_gateway, old_inspector = _unit("core_gateway"), _unit("core_gateway_inspector")
    new_gateway = old_gateway.replace(OLD_SOURCE, str(source).encode("ascii"), 1)
    new_inspector = old_inspector.replace(OLD_SOURCE, str(source).encode("ascii"), 1)
    old_config = b"old config bytes\n"
    current_config = b"post-core config bytes\n"
    value = {"state": "recovery-required", "candidate_sha": candidate,
             "new_gateway_sha256": hashlib.sha256(new_gateway).hexdigest(),
             "new_inspector_sha256": hashlib.sha256(new_inspector).hexdigest(),
             "new_config_sha256": hashlib.sha256(b"pre-core config bytes\n").hexdigest(),
             "post_core_config_sha256": hashlib.sha256(current_config).hexdigest()}
    files = {adopt.FIXED_UNITS[adopt.GATEWAY]: new_gateway,
             adopt.FIXED_UNITS[adopt.INSPECTOR]: new_inspector,
             adopt.GATEWAY_CONFIG: current_config}
    states = {adopt.INSPECTOR: "active", adopt.GATEWAY: "inactive", adopt.TUNNEL: "inactive"}
    events = []
    info = SimpleNamespace(st_mode=stat.S_IFREG | 0o440, st_gid=981)
    monkeypatch.setattr(adopt, "_backup_value",
                        lambda sha: (value, old_gateway, old_inspector, b"pre-core config bytes\n")
                        if sha == candidate else pytest.fail("wrong candidate"))
    monkeypatch.setattr(adopt, "_unit_is_fixed", lambda _name: True)
    monkeypatch.setattr(adopt, "_unit_state", lambda name: states[name])
    monkeypatch.setattr(adopt, "_unit_is_exact_and_active", lambda name: states[name] == "active")
    monkeypatch.setattr(adopt, "_verify_inspector_process", lambda *_args: events.append("verify-inspector"))
    monkeypatch.setattr(adopt, "_read_fixed", lambda path, **_kwargs: (files[path], info))
    monkeypatch.setattr(adopt, "_set_runtime_inspector_digest",
                        lambda *_args: events.append("journal-runtime-inspector"))
    monkeypatch.setattr(adopt, "_atomic_fixed",
                        lambda path, raw, **_kwargs: files.__setitem__(path, raw))
    monkeypatch.setattr(adopt, "_refresh_migrated_core_config",
                        lambda *_args: events.append("refresh-config") or current_config)
    monkeypatch.setattr(adopt, "_verify_gateway_tunnel",
                        lambda _config, *, require_active: (events.append(
                            "verify-active" if require_active else "verify-stopped"), True)[1])
    def wait_observer(**_kwargs):
        events.append("wait-observer")
        if fail_observer:
            raise RuntimeError("socket unavailable")
        return (1, 2)

    monkeypatch.setattr(adopt, "_wait_observer_socket", wait_observer)
    monkeypatch.setattr(adopt, "_set_backup_state", lambda state: events.append(("backup-state", state)))

    def run(*args, **_kwargs):
        if args[1] in {"start", "restart", "stop"}:
            events.append((args[1], args[2]))
            states[args[2]] = "inactive" if args[1] == "stop" else "active"
        return ""

    monkeypatch.setattr(adopt, "_run", run)
    config_type = SimpleNamespace(load=lambda **_kwargs: object())
    core = SimpleNamespace()
    if fail_observer:
        with pytest.raises(RuntimeError, match="socket unavailable"):
            adopt._resume_adoption(candidate, source, core, config_type, tmp_path / "observer.sock")
        assert states[adopt.GATEWAY] == states[adopt.TUNNEL] == "inactive"
        assert ("backup-state", "recovery-required") in events
        assert not any(event in {("start", adopt.GATEWAY), ("start", adopt.TUNNEL)}
                       for event in events)
    else:
        adopt._resume_adoption(candidate, source, core, config_type, tmp_path / "observer.sock")
        assert events.index("refresh-config") < events.index(("restart", adopt.INSPECTOR))
        assert events.index(("restart", adopt.INSPECTOR)) < events.index("wait-observer")
        observer_checks = [index for index, event in enumerate(events) if event == "wait-observer"]
        assert len(observer_checks) == 2
        assert events.index("journal-runtime-inspector") < max(
            index for index, event in enumerate(events)
            if event == ("restart", adopt.INSPECTOR))
        assert observer_checks[-1] < events.index(("start", adopt.GATEWAY))
        assert events.index(("start", adopt.GATEWAY)) < events.index(("start", adopt.TUNNEL))
        assert ("backup-state", "migrated") in events
