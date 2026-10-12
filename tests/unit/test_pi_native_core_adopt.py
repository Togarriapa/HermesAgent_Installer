"""Effect and fail-closed tests for the root-only Pi ingress migration helper.

These tests use in-memory fixed-file/systemd fixtures. They must be run on the
Pi with the candidate test environment; they are not target acceptance.
"""
import hashlib
import importlib.util
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
            + module.encode("ascii") + b"\n")


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
    fixed = {
        adopt.FIXED_UNITS[adopt.GATEWAY]: (gateway, SimpleNamespace(st_mode=stat.S_IFREG | 0o644, st_gid=0)),
        adopt.FIXED_UNITS[adopt.INSPECTOR]: (inspector, SimpleNamespace(st_mode=stat.S_IFREG | 0o644, st_gid=0)),
        adopt.GATEWAY_CONFIG: (config, SimpleNamespace(st_mode=stat.S_IFREG | 0o440, st_gid=981)),
    }
    monkeypatch.setattr(adopt, "_read_fixed", lambda path, **_kwargs: fixed[path])
    effects = []
    monkeypatch.setattr(adopt, "_run", lambda *args, **_kwargs: effects.append(args) or "")
    return fixed, effects, gateway, inspector, config


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


@pytest.mark.parametrize("failure", [None, "owner", "migration", "migration-unclassified",
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
    config_info = SimpleNamespace(st_mode=stat.S_IFREG | 0o440, st_gid=981)
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
    monkeypatch.setattr(adopt, "_unit_is_fixed", lambda _name: True)
    monkeypatch.setattr(adopt, "_unit_is_exact_and_active", lambda _name: True)
    monkeypatch.setattr(adopt, "_verify_inspector_process", lambda *_args: None)
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
    monkeypatch.setattr(adopt, "_source_switch", lambda _source: (
        {adopt.FIXED_UNITS[adopt.GATEWAY]: (old_gateway, None),
         adopt.FIXED_UNITS[adopt.INSPECTOR]: (old_inspector, None)},
        old_config, config_info,
        {adopt.FIXED_UNITS[adopt.GATEWAY]: new_gateway,
         adopt.FIXED_UNITS[adopt.INSPECTOR]: new_inspector}, new_config))
    def save_backup(*_args):
        events.append("save-backup")
        backup_state["present"] = True

    monkeypatch.setattr(adopt, "_save_ingress_backup", save_backup)
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

    def replace_units(*_args):
        events.append("switch-fixed-units")
        for name in (adopt.TUNNEL, adopt.GATEWAY, adopt.INSPECTOR):
            run("systemctl", "stop", name)
        return None

    monkeypatch.setattr(adopt, "_run", run)
    monkeypatch.setattr(adopt, "_replace_ingress_units", replace_units)
    monkeypatch.setattr(adopt, "_restore_legacy_core", lambda _core: events.append("recover-core") or True)
    monkeypatch.setattr(adopt, "_restore_old_ingress",
                        lambda *_args: events.append("restore-old-ingress") or True)
    monkeypatch.setattr(adopt, "_backup_value", lambda _sha: ({}, old_gateway,
                                                                 old_inspector, old_config))

    result = adopt.main()
    gateway_tunnel_starts = [index for index, event in enumerate(events)
                             if isinstance(event, tuple) and event[0] == "start"
                             and event[1] in {adopt.GATEWAY, adopt.TUNNEL}]
    migrate_at = events.index("migrate-core") if "migrate-core" in events else None
    fresh_at = events.index("fresh-observer") if "fresh-observer" in events else None
    if failure is None:
        assert result == 0
        assert migrate_at is not None and fresh_at is not None
        assert gateway_tunnel_starts
        assert all(index > migrate_at and index > fresh_at for index in gateway_tunnel_starts)
        assert events.index("prepare-owner") < migrate_at < fresh_at
        assert migrate_at < events.index("verify-migrated-core")
        assert events.index("verify-migrated-core") < events.index(("restart", adopt.INSPECTOR))
        assert events.index(("restart", adopt.INSPECTOR)) < fresh_at
        assert backup_state["present"]
        assert "save-backup" in events and "remove-backup" not in events
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
