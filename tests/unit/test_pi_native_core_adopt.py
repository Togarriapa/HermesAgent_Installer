"""Effect and fail-closed tests for the root-only Pi ingress migration helper.

These tests use in-memory fixed-file/systemd fixtures. They must be run on the
Pi with the candidate test environment; they are not target acceptance.
"""
import base64
import hashlib
import importlib.util
import io
import json
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

    adopt._save_ingress_backup("a" * 40, saved, config, info, units, new_config)
    value = json.loads((parent / "backup.json").read_bytes())

    assert base64.b64decode(value["gateway_config"]) == config
    assert base64.b64decode(value["new_gateway_config"]) == new_config
    assert value["new_config_sha256"] == hashlib.sha256(new_config).hexdigest()


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

    core = SimpleNamespace(
        SERVICE="hermes-jarvis-core.service",
        CoreRuntimeError=CoreRuntimeError,
        _validate_adapter_source_path=lambda: events.append("validate-source"),
        _owned_listener=owned_listener,
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
