from __future__ import annotations

import ast
import hashlib
import importlib.util
import shlex
import types
from enum import IntEnum
from pathlib import Path
from types import MethodType

ROOT = Path(__file__).resolve().parents[2]
PATCH_MODULE = ROOT / "scripts" / "xpra_control_guard_patch.py"
ORIGINAL_COMMAND = ROOT / "tests" / "fixtures" / "vendor" / "xpra-server-6.5.4-command.py"
spec = importlib.util.spec_from_file_location("xpra_control_guard_patch_v262", PATCH_MODULE)
assert spec and spec.loader
patcher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(patcher)


class ExitCode(IntEnum):
    UNSUPPORTED = 12


class Packet:
    def __init__(self, *args):
        self.args = args


class _Log:
    def __init__(self):
        self.warnings = []

    def warn(self, *args):
        self.warnings.append(args)

    def error(self, *args):
        self.warnings.append(args)

    def info(self, *args):
        self.warnings.append(args)

    def estr(self, *args):
        self.warnings.append(args)

    def __call__(self, *args, **kwargs):
        self.warnings.append((args, kwargs))


def _method(source: bytes, name: str, globals_: dict | None = None):
    tree = ast.parse(source)
    owner = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "ChildCommandServer")
    node = next(node for node in owner.body if isinstance(node, ast.FunctionDef) and node.name == name)
    namespace = {"typedict": object, "Packet": Packet, "ExitCode": ExitCode, "log": _Log(),
                 "shlex": shlex, "source_env": lambda value: {"source": value},
                 "parse_env": lambda value: {"start": value}, "COMMAND_SIGNALS": ("SIGTERM",)}
    if globals_:
        namespace.update(globals_)
    exec(compile(ast.Module(body=[node], type_ignores=[]), f"pinned-command-{name}.py", "exec"), namespace)
    return namespace[name], namespace


def _options(start_new_commands: bool):
    return types.SimpleNamespace(
        exit_with_children=True, terminate_children=True, start_new_commands=start_new_commands,
        start=["trusted-start"], start_late=[], start_child=["/opt/hermes/AppDir/AppRun"],
        start_child_late=[], start_after_connect=[], start_child_after_connect=[],
        start_on_connect=[], start_child_on_connect=[], start_on_disconnect=[],
        start_child_on_disconnect=[], start_on_last_client_exit=[],
        start_child_on_last_client_exit=[], exec_wrapper="", source_start=[], start_env=[],
    )


def test_fixed_patch_is_bound_to_exact_original_command_bytes():
    original = ORIGINAL_COMMAND.read_bytes()
    patched = patcher.patch_command_bytes(original)
    assert len(original) == 23_581
    assert hashlib.sha256(original).hexdigest() == "804eca53b88e23996fb41c394318531548193a750f07e6846dbdaffe8db7126e"
    assert len(patched) == 24_117
    assert hashlib.sha256(patched).hexdigest() == "09e90f7dcb8a76687c59ee8c538faef21ce2881bdaed4cafb760eb8fe141f2d3"
    try:
        patcher.patch_command_bytes(original + b"# altered\n")
    except ValueError as exc:
        assert "pinned official" in str(exc)
    else:
        raise AssertionError("changed upstream command.py was accepted")


def test_disabled_client_run_denies_before_reading_caps_or_starting_process():
    method, namespace = _method(patcher.patch_command_bytes(ORIGINAL_COMMAND.read_bytes()), "_handle_hello_request_run")
    sent = []

    class BombCaps:
        def __getattribute__(self, _name):
            raise AssertionError("disabled run request parsed client data")

    target = types.SimpleNamespace(start_new_commands=False, start_command=lambda *a, **k: (_ for _ in ()).throw(
        AssertionError("disabled run request launched a process")))
    proto = types.SimpleNamespace(send_now=sent.append)
    assert method(target, proto, BombCaps()) is True
    assert len(sent) == 1
    assert sent[0].args[1]["run_response"] == {
        "code": ExitCode.UNSUPPORTED, "message": "command execution is disabled"
    }


def test_enabled_client_run_keeps_the_existing_start_command_behavior():
    method, _namespace = _method(patcher.patch_command_bytes(ORIGINAL_COMMAND.read_bytes()), "_handle_hello_request_run")
    calls = []
    proc = types.SimpleNamespace(pid=491)
    target = types.SimpleNamespace(
        start_new_commands=True,
        get_server_source=lambda proto: "source",
        start_command=lambda *args, **kwargs: calls.append((args, kwargs)) or proc,
    )
    sent = []
    proto = types.SimpleNamespace(send_now=sent.append)
    caps = types.SimpleNamespace(strtupleget=lambda key: ("untrusted-client-program", "--arg"))
    assert method(target, proto, caps) is True
    assert calls == [(('untrusted-client-program', ('untrusted-client-program', '--arg')),
                      {"ignore": True, "source": "source"})]
    assert sent[0].args[1]["run_response"] == {"pid": 491}


def test_signal_packet_is_unregistered_and_direct_handler_denies_when_disabled():
    source = patcher.patch_command_bytes(ORIGINAL_COMMAND.read_bytes())
    init_packets, _ = _method(source, "init_packet_handlers", {
        "ChildCommandServer": types.SimpleNamespace(PREFIX="command")
    })
    disabled_calls = []
    disabled = types.SimpleNamespace(start_new_commands=False, add_packets=lambda *a: disabled_calls.append(a),
                                     add_legacy_alias=lambda *a: disabled_calls.append(a))
    init_packets(disabled)
    assert disabled_calls == []

    signal_method, _ = _method(source, "_process_command_signal")

    class BombPacket:
        def __getattribute__(self, _name):
            raise AssertionError("disabled signal request parsed packet fields")

    signal_method(types.SimpleNamespace(start_new_commands=False), None, BombPacket())


def test_enabled_signal_packet_remains_registered_and_calls_existing_signal_path():
    source = patcher.patch_command_bytes(ORIGINAL_COMMAND.read_bytes())
    init_packets, _ = _method(source, "init_packet_handlers", {
        "ChildCommandServer": types.SimpleNamespace(PREFIX="command")
    })
    calls = []
    enabled = types.SimpleNamespace(start_new_commands=True, add_packets=lambda *a: calls.append(("packets", a)),
                                    add_legacy_alias=lambda *a: calls.append(("alias", a)))
    init_packets(enabled)
    assert calls == [("packets", ("command-signal",)), ("packets", ("command-start",)),
                     ("alias", ("start-command", "command-start"))]

    signal_method, namespace = _method(source, "_process_command_signal", {
        "get_child_reaper": lambda: types.SimpleNamespace(get_proc_info=lambda pid: types.SimpleNamespace(returncode=None)),
        "send_signame": lambda pid, sig: calls.append(("signal", pid, sig)),
    })
    packet = types.SimpleNamespace(get_u32=lambda index: 492, get_str=lambda index: "SIGTERM")
    signal_method(types.SimpleNamespace(start_new_commands=True), None, packet)
    assert ("signal", 492, "SIGTERM") in calls


def test_initialization_keeps_fixed_start_child_and_only_registers_run_when_enabled():
    source = patcher.patch_command_bytes(ORIGINAL_COMMAND.read_bytes())
    init, _ = _method(source, "init")
    for enabled in (False, True):
        handlers = {"run": "stale"}
        target = types.SimpleNamespace(
            hello_request_handlers=handlers,
            _handle_hello_request_run=lambda *_args: True,
        )
        init(target, _options(enabled))
        assert target.start_child_commands == ["/opt/hermes/AppDir/AppRun"]
        assert (handlers.get("run") is target._handle_hello_request_run) == enabled


def test_fixed_server_command_startup_methods_are_byte_semantically_unchanged():
    original = ast.parse(ORIGINAL_COMMAND.read_text(encoding="utf-8"))
    patched = ast.parse(patcher.patch_command_bytes(ORIGINAL_COMMAND.read_bytes()).decode("utf-8"))

    def methods(tree):
        owner = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "ChildCommandServer")
        names = {"threaded_command_setup", "exec_start_commands", "_exec_commands", "start_command"}
        return {node.name: ast.dump(node, include_attributes=False) for node in owner.body
                if isinstance(node, ast.FunctionDef) and node.name in names}

    assert methods(original) == methods(patched)


def test_fixed_configured_child_still_reaches_server_owned_start_command():
    source = patcher.patch_command_bytes(ORIGINAL_COMMAND.read_bytes())
    exec_commands, _ = _method(source, "_exec_commands")
    exec_start_commands, _ = _method(source, "exec_start_commands")
    calls = []
    target = types.SimpleNamespace(
        start_commands=[], start_child_commands=["/opt/hermes-jarvis-mvp-20261011/Hermes-Desktop.AppDir/Hermes"],
        session_name="fixed-test-session", start_command=lambda *a, **kw: calls.append((a, kw)) or "started",
    )
    target._exec_commands = MethodType(exec_commands, target)
    exec_start_commands(target)
    assert calls == [((target.start_child_commands[0], target.start_child_commands[0]),
                      {"ignore": False, "source": None})]
