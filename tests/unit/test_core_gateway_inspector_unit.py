"""Static and isolated-effect checks for the fixed root Inspector service."""
import os
import shlex
import stat
import subprocess
import threading
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from hermes_installer.remote import core_gateway, core_gateway_inspector

import pytest


UNIT = (Path(__file__).resolve().parents[2] / "templates" / "core-gateway"
        / "hermes-jarvis-core-inspector.service")


def test_inspector_unit_keeps_primary_group_and_limits_native_write_access():
    lines = UNIT.read_text(encoding="ascii").splitlines()
    service = lines[lines.index("[Service]") + 1:]

    assert service.count("Group=981") == 1
    assert service.count("RuntimeDirectory=hermes-jarvis-mvp-core") == 1
    assert not any(line.startswith("RuntimeDirectory=")
                   and ":root:admin" in line for line in service)
    assert service.count(
        "ExecStartPre=/usr/bin/install -d -o root -g 1000 -m 0750 "
        "/run/hermes-jarvis-native-observer") == 1
    assert service.count("SupplementaryGroups=1000") == 1
    assert service.count("ReadWritePaths=/var/lib/hermes-installer/core-runtime") == 1
    assert "ProtectSystem=strict" in service


@pytest.mark.skipif(os.geteuid() != 0, reason="root ownership effect requires the Pi root test role")
def test_inspector_prestart_recipe_creates_exact_private_runtime_directory(tmp_path):
    lines = UNIT.read_text(encoding="ascii").splitlines()
    recipe = next(line.split("=", 1)[1] for line in lines
                  if line.startswith("ExecStartPre="))
    arguments = shlex.split(recipe)
    target = tmp_path / "native-observer"
    arguments[-1] = str(target)
    subprocess.run(arguments, check=True, stdin=subprocess.DEVNULL,
                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)

    info = target.stat()
    assert stat.S_ISDIR(info.st_mode)
    assert (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) == (0, 1000, 0o750)


def _optional_observer_start_fixture(monkeypatch, *, failure=None, error=None,
                                     source_failure=False, stop_initial=False,
                                     stop_after_registry=False, dead_worker=False,
                                     unavailable_socket=False, source_result=None):
    from hermes_installer.components.resources_active_profile_source import RootVerifiedJarvisMasterSource
    from hermes_installer.remote import core_native_observer

    events = []
    stop = threading.Event()
    if stop_initial:
        stop.set()
    custody = SimpleNamespace(_core_pidfd=778899)
    registry_type = core_native_observer.RootCoreNativeObservationRegistry
    registry = object.__new__(registry_type)
    clock = {"value": 0.0, "reads": []}
    monkeypatch.setattr(core_gateway_inspector, "_CORE_NATIVE_CUSTODY", None)
    monkeypatch.setattr(core_gateway_inspector, "_CORE_NATIVE_REGISTRY", None)
    monkeypatch.setattr(core_gateway_inspector, "_CORE_NATIVE_REGISTRY_TYPE", None)
    monkeypatch.setattr(core_gateway_inspector, "_CORE_NATIVE_STOP", None)
    monkeypatch.setattr(core_gateway_inspector, "_CORE_NATIVE_THREAD", None)
    monkeypatch.setattr(core_gateway_inspector, "capture_current_core_native_custody",
        lambda _config: events.append("custody") or (_raise_if(failure, "custody", error)
            if failure == "custody" else custody))

    def master_source(cls, _custody, *, config):
        events.append("master_source")
        if source_failure:
            raise RuntimeError("PRIVATE source text")
        return source_result

    monkeypatch.setattr(RootVerifiedJarvisMasterSource, "current_master_source",
                        classmethod(master_source))
    monkeypatch.setattr(registry_type, "close", lambda _self: events.append("registry_close"))

    def make_registry(cls, _custody, *, selected_profile_source, config):
        events.append("registry")
        if failure == "registry":
            raise error
        if stop_after_registry:
            stop.set()
        return registry

    monkeypatch.setattr(registry_type, "from_current_core_custody", classmethod(make_registry))
    monkeypatch.setattr(core_native_observer, "serve_core_native_observer",
                        lambda **_kwargs: events.append("serve"))

    class Worker:
        def __init__(self, *, target, kwargs, daemon, name):
            events.append("worker_construct")
            self.alive = not dead_worker

        def start(self):
            events.append("worker_start")
            if failure == "worker_start":
                raise error

        def is_alive(self):
            return self.alive

        def join(self, *, timeout):
            events.append(("worker_join", timeout))

    real_threading = threading
    monkeypatch.setattr(core_gateway_inspector, "threading", SimpleNamespace(
        Thread=Worker, Event=real_threading.Event,
        current_thread=real_threading.current_thread))

    def lstat(path):
        events.append("lstat")
        if unavailable_socket:
            raise FileNotFoundError("PRIVATE socket path")
        if Path(path) == core_gateway_inspector.CORE_NATIVE_OBSERVER_DIRECTORY:
            return SimpleNamespace(st_mode=stat.S_IFDIR | 0o750, st_uid=0, st_gid=1000)
        return SimpleNamespace(st_mode=stat.S_IFSOCK | 0o660, st_uid=0, st_gid=1000)

    closed = []
    monkeypatch.setattr(core_gateway_inspector, "os", SimpleNamespace(
        lstat=lstat, close=lambda fd: closed.append(fd)))

    def monotonic():
        clock["reads"].append(clock["value"])
        return clock["value"]

    monkeypatch.setattr(core_gateway_inspector, "time", SimpleNamespace(
        monotonic=monotonic, sleep=lambda _seconds: events.append("sleep")))
    return SimpleNamespace(events=events, stop=stop, custody=custody, registry=registry,
        worker_type=Worker, closed=closed, clock=clock, failure=failure, error=error)


def _raise_if(failure, stage, error):
    if failure == stage:
        raise error


_OPTIONAL_OBSERVER_STAGES = (
    "imports", "custody", "master_source", "registry", "worker_start",
    "listener_wait", "publish")


def test_optional_observer_start_emits_once_only_stages_in_order_and_keeps_source_none_fallback(
        monkeypatch, capsys):
    fixture = _optional_observer_start_fixture(monkeypatch, source_failure=True)
    assert core_gateway_inspector._start_optional_core_native_observer(object(), fixture.stop) is True
    captured = capsys.readouterr().err.splitlines()
    assert captured == ["HERMES_OPTIONAL_OBSERVER_STAGE_V1=" + stage
                        for stage in _OPTIONAL_OBSERVER_STAGES]
    assert fixture.events.count("lstat") == 2
    assert fixture.events.count("sleep") == 0
    assert core_gateway_inspector._CORE_NATIVE_CUSTODY is fixture.custody
    assert core_gateway_inspector._CORE_NATIVE_REGISTRY is fixture.registry


@pytest.mark.parametrize(("error_type", "label"), [
    (core_gateway_inspector.CoreInspectionDenied, "CoreInspectionDenied"),
    (FileNotFoundError, "FileNotFoundError"), (FileExistsError, "FileExistsError"),
    (PermissionError, "PermissionError"), (ModuleNotFoundError, "ModuleNotFoundError"),
    (ImportError, "ImportError"), (NameError, "NameError"),
    (AttributeError, "AttributeError"), (TypeError, "TypeError"),
    (ValueError, "ValueError"), (OSError, "OSError"),
    (TimeoutError, "TimeoutError"), (RuntimeError, "RuntimeError"),
])
def test_optional_observer_refusal_uses_only_exact_allowlisted_type_identity(
        monkeypatch, capsys, error_type, label):
    fixture = _optional_observer_start_fixture(
        monkeypatch, failure="custody", error=error_type("PRIVATE exception message"))
    assert core_gateway_inspector._start_optional_core_native_observer(object(), fixture.stop) is False
    output = capsys.readouterr().err
    assert output.splitlines() == [
        "HERMES_OPTIONAL_OBSERVER_STAGE_V1=imports",
        "HERMES_OPTIONAL_OBSERVER_STAGE_V1=custody",
        "HERMES_OPTIONAL_OBSERVER_REFUSAL_V1=custody/" + label,
    ]
    assert "PRIVATE" not in output
    assert len(output.encode("ascii")) <= 7 * 128 + 256


def test_optional_observer_registry_refusal_closes_custody_without_publication(
        monkeypatch, capsys):
    fixture = _optional_observer_start_fixture(
        monkeypatch, failure="registry", error=RuntimeError("PRIVATE registry detail"))
    assert core_gateway_inspector._start_optional_core_native_observer(object(), fixture.stop) is False
    output = capsys.readouterr().err
    assert output.splitlines() == [
        "HERMES_OPTIONAL_OBSERVER_STAGE_V1=" + stage
        for stage in _OPTIONAL_OBSERVER_STAGES[:4]
    ] + ["HERMES_OPTIONAL_OBSERVER_REFUSAL_V1=registry/RuntimeError"]
    assert "PRIVATE" not in output
    assert fixture.stop.is_set() and fixture.closed == [fixture.custody._core_pidfd]
    assert "worker_construct" not in fixture.events and "registry_close" not in fixture.events
    assert core_gateway_inspector._CORE_NATIVE_CUSTODY is None
    assert core_gateway_inspector._CORE_NATIVE_REGISTRY is None
    assert core_gateway_inspector._CORE_NATIVE_REGISTRY_TYPE is None
    assert core_gateway_inspector._CORE_NATIVE_THREAD is None


def test_optional_observer_refusal_rejects_exception_name_spoof_and_cleans_owned_state(
        monkeypatch, capsys):
    class SpoofedRuntimeError(RuntimeError):
        def __str__(self):
            raise AssertionError("refusal diagnostics must not stringify the exception")

    SpoofedRuntimeError.__name__ = "RuntimeError"
    error = SpoofedRuntimeError("PRIVATE exception content")
    fixture = _optional_observer_start_fixture(
        monkeypatch, failure="worker_start", error=error)
    assert core_gateway_inspector._start_optional_core_native_observer(object(), fixture.stop) is False
    output = capsys.readouterr().err
    assert output.splitlines()[-1] == "HERMES_OPTIONAL_OBSERVER_REFUSAL_V1=worker_start/OtherError"
    assert "PRIVATE" not in output and "RuntimeError" not in output
    assert fixture.stop.is_set()
    assert ("worker_join", 1.0) in fixture.events
    assert "registry_close" in fixture.events and fixture.closed == [fixture.custody._core_pidfd]
    assert core_gateway_inspector._CORE_NATIVE_CUSTODY is None
    assert core_gateway_inspector._CORE_NATIVE_REGISTRY is None


def test_optional_observer_refusal_at_import_boundary_is_closed_and_private(
        monkeypatch, capsys):
    import builtins

    fixture = _optional_observer_start_fixture(monkeypatch)
    missing = ModuleNotFoundError("PRIVATE import details")
    original_import = builtins.__import__

    def import_with_fixed_failure(name, globals=None, locals=None, fromlist=(), level=0):
        if level == 2 and "RootVerifiedJarvisMasterSource" in fromlist:
            raise missing
        return original_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", import_with_fixed_failure)
    assert core_gateway_inspector._start_optional_core_native_observer(object(), fixture.stop) is False
    output = capsys.readouterr().err
    assert output.splitlines() == [
        "HERMES_OPTIONAL_OBSERVER_STAGE_V1=imports",
        "HERMES_OPTIONAL_OBSERVER_REFUSAL_V1=imports/ModuleNotFoundError",
    ]
    assert "PRIVATE" not in output and fixture.events == []


def test_optional_observer_currentness_exception_remains_failure_at_master_source(
        monkeypatch, capsys):
    from hermes_installer.components.resources_active_profile_source import RootVerifiedJarvisMasterSource

    source = object.__new__(RootVerifiedJarvisMasterSource)
    object.__setattr__(source, "profile_id", "hermes")
    object.__setattr__(source, "native_profile_key", "default")
    object.__setattr__(source, "display_name", "Jarvis")
    fixture = _optional_observer_start_fixture(monkeypatch, source_result=source)

    def currentness_raises(self, *, custody, now):
        raise ValueError("PRIVATE currentness details")

    monkeypatch.setattr(RootVerifiedJarvisMasterSource, "is_current_sealed", currentness_raises)
    assert core_gateway_inspector._start_optional_core_native_observer(object(), fixture.stop) is False
    output = capsys.readouterr().err
    assert output.splitlines()[-1] == "HERMES_OPTIONAL_OBSERVER_REFUSAL_V1=master_source/ValueError"
    assert "PRIVATE" not in output and "registry" not in fixture.events


def test_optional_observer_thread_death_is_one_listener_refusal_with_cleanup(
        monkeypatch, capsys):
    fixture = _optional_observer_start_fixture(monkeypatch, dead_worker=True)
    assert core_gateway_inspector._start_optional_core_native_observer(object(), fixture.stop) is False
    lines = capsys.readouterr().err.splitlines()
    assert lines[-2:] == [
        "HERMES_OPTIONAL_OBSERVER_STAGE_V1=listener_wait",
        "HERMES_OPTIONAL_OBSERVER_REFUSAL_V1=listener_wait/CoreInspectionDenied",
    ]
    assert fixture.events.count("lstat") == 0
    assert ("worker_join", 1.0) in fixture.events
    assert "registry_close" in fixture.events and fixture.closed == [fixture.custody._core_pidfd]


def test_optional_observer_initial_cancel_is_silent_and_cancel_after_registry_cleans_up(
        monkeypatch, capsys):
    initial = _optional_observer_start_fixture(monkeypatch, stop_initial=True)
    assert core_gateway_inspector._start_optional_core_native_observer(object(), initial.stop) is False
    assert capsys.readouterr().err == ""
    assert initial.events == [] and initial.closed == []

    cancelled = _optional_observer_start_fixture(monkeypatch, stop_after_registry=True)
    assert core_gateway_inspector._start_optional_core_native_observer(object(), cancelled.stop) is False
    lines = capsys.readouterr().err.splitlines()
    assert lines == ["HERMES_OPTIONAL_OBSERVER_STAGE_V1=" + stage
                     for stage in _OPTIONAL_OBSERVER_STAGES[:4]] + [
        "HERMES_OPTIONAL_OBSERVER_REFUSAL_V1=registry/CoreInspectionDenied"]
    assert "worker_construct" not in cancelled.events
    assert "registry_close" in cancelled.events
    assert cancelled.closed == [cancelled.custody._core_pidfd]
    assert core_gateway_inspector._CORE_NATIVE_CUSTODY is None


def test_optional_observer_listener_diagnostic_does_not_restate_deadline_or_break_on_sink_error(
        monkeypatch):
    fixture = _optional_observer_start_fixture(monkeypatch, unavailable_socket=True)

    class SlowBrokenSink:
        def write(self, line):
            if line == "HERMES_OPTIONAL_OBSERVER_STAGE_V1=listener_wait\n":
                fixture.clock["value"] = 3.0
            raise OSError("PRIVATE sink")

        def flush(self):
            raise OSError("PRIVATE sink")

    monkeypatch.setattr(core_gateway_inspector.sys, "stderr", SlowBrokenSink())
    assert core_gateway_inspector._start_optional_core_native_observer(object(), fixture.stop) is False
    assert fixture.clock["reads"] == [0.0, 3.0]
    assert "sleep" not in fixture.events
    assert fixture.stop.is_set()
    assert fixture.closed == [fixture.custody._core_pidfd]
    assert "registry_close" in fixture.events


def test_optional_observer_success_survives_broken_diagnostic_sink(monkeypatch):
    fixture = _optional_observer_start_fixture(monkeypatch)

    class BrokenSink:
        def write(self, _line):
            raise OSError("PRIVATE sink")

        def flush(self):
            raise OSError("PRIVATE sink")

    monkeypatch.setattr(core_gateway_inspector.sys, "stderr", BrokenSink())
    assert core_gateway_inspector._start_optional_core_native_observer(object(), fixture.stop) is True
    assert not fixture.stop.is_set()
    assert fixture.closed == []
    assert fixture.events.count("lstat") == 2
    assert core_gateway_inspector._CORE_NATIVE_CUSTODY is fixture.custody
    assert core_gateway_inspector._CORE_NATIVE_REGISTRY is fixture.registry
    assert core_gateway_inspector._CORE_NATIVE_REGISTRY_TYPE is type(fixture.registry)
    assert core_gateway_inspector._CORE_NATIVE_THREAD is not None


@pytest.mark.parametrize("allowed_emails", [frozenset(), frozenset({
    "owner@example.test", "member@example.test", "guest@example.test",
})])
@pytest.mark.parametrize("action_fields", [
    ("list", {}), ("read", {"profile_id": "hermes", "file_kind": "soul"}),
    ("write", {"profile_id": "hermes", "file_kind": "soul", "expected_sha256": "a" * 64,
               "content": "proposed", "idempotency_key": "safe_key_123456789012345678"}),
    ("skills-list", {}), ("skills-archives-list", {}),
    ("skill-read", {"skill_id": "helper"}),
    ("skill-write", {"skill_id": "helper", "expected_sha256": "a" * 64,
                     "content": "proposed", "idempotency_key": "safe_key_123456789012345678"}),
    ("skill-archive", {"skill_id": "helper", "expected_sha256": "a" * 64,
                       "idempotency_key": "safe_key_123456789012345678"}),
    ("skill-restore", {"skill_id": "helper", "expected_sha256": "a" * 64,
                       "idempotency_key": "safe_key_123456789012345678", "restore_id": "b" * 64}),
    ("skill-restore-list", {"skill_id": "helper"}),
])
def test_profile_admin_inspector_denies_non_singleton_allowlist_before_ingress_or_native_effects(
        allowed_emails, action_fields):
    digest = "a" * 64
    config = core_gateway.CoreGatewayConfig(
        hostname="jarvis.example.test", issuer="https://team.cloudflareaccess.com",
        audience="core-test-audience", allowed_emails=allowed_emails,
        gateway_uid=996, gateway_gid=981, core_uid=1000, core_gid=1000,
        boot_id="12345678-1234-1234-1234-123456789012",
        gateway_unit_sha256=digest, gateway_python_sha256=digest,
        tunnel_unit_sha256=digest, cloudflared_binary_sha256=digest,
        core_unit_sha256=digest, core_launcher_sha256=digest,
        core_python=core_gateway_inspector.CORE_PYTHON_LINK,
        core_python_sha256=core_gateway_inspector.CORE_PYTHON_SHA256,
        ingress_socket=core_gateway.CORE_INGRESS_SOCKET,
        config_path=core_gateway.CORE_CONFIG, config_sha256=digest)
    action, fields = action_fields
    request = {
        "schema": 1, "op": "owner-profile-admin", "action": action,
        "nonce": "b" * 64, "peer_pid": 551, "peer_uid": 996, "peer_gid": 981,
        "access_jwt": "signed-access-token", "core_generation": "c" * 64,
        "ingress_nonce": "d" * 64, "ingress_proof_sha256": "e" * 64,
        **fields,
    }
    with patch.object(core_gateway_inspector, "_consume_ingress_issue",
                      side_effect=AssertionError("non-singleton admin must stop before ingress consumption")) as consume:
        with pytest.raises(core_gateway_inspector.CoreInspectionDenied,
                           match="Administrator access setup is pending"):
            core_gateway_inspector.observe_profile_admin(
                config, request=request, caller_pid=440, caller_uid=996, caller_gid=981,
                peer_pid=551, peer_uid=996, peer_gid=981)
    consume.assert_not_called()
