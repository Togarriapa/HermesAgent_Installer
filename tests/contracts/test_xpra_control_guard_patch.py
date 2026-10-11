from __future__ import annotations

import ast
import importlib.util
import sys
import textwrap
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PATCH_MODULE = ROOT / "scripts" / "xpra_control_guard_patch.py"
ORIGINAL_STUB = ROOT / "tests" / "fixtures" / "vendor" / "xpra-server-6.5.4-stub.py"

spec = importlib.util.spec_from_file_location("xpra_control_guard_patch", PATCH_MODULE)
assert spec and spec.loader
patcher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(patcher)


def _args_control(data: bytes):
    tree = ast.parse(data)
    cls = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "StubServerMixin")
    method = next(node for node in cls.body if isinstance(node, ast.FunctionDef) and node.name == "args_control")
    module = ast.Module(body=[method], type_ignores=[])
    namespace = {"noop": object()}
    exec(compile(module, "pinned-xpra-stub.py", "exec"), namespace)
    return namespace["args_control"]


def test_control_disabled_returns_before_importing_deliberately_blocked_package(monkeypatch):
    patched = patcher.patch_bytes(ORIGINAL_STUB.read_bytes())
    method = _args_control(patched)
    features = types.SimpleNamespace(control=False)
    xpra = types.ModuleType("xpra")
    xpra.__path__ = []
    server = types.ModuleType("xpra.server")
    server.features = features
    net = types.ModuleType("xpra.net")
    net.__path__ = []
    xpra.server = server
    xpra.net = net
    monkeypatch.setitem(sys.modules, "xpra", xpra)
    monkeypatch.setitem(sys.modules, "xpra.server", server)
    monkeypatch.setitem(sys.modules, "xpra.net", net)
    monkeypatch.setitem(sys.modules, "xpra.net.control", None)
    assert method(object(), "start", "run a command") is None
    assert sys.modules["xpra.net.control"] is None


def test_control_enabled_still_registers_the_existing_command(monkeypatch):
    patched = patcher.patch_bytes(ORIGINAL_STUB.read_bytes())
    method = _args_control(patched)
    features = types.SimpleNamespace(control=True)
    server = types.ModuleType("xpra.server")
    server.features = features
    control = types.ModuleType("xpra.net.control")
    control.__path__ = []
    common = types.ModuleType("xpra.net.control.common")
    calls = []
    common.add_args_control_command = lambda *args, **kwargs: calls.append((args, kwargs))
    xpra = types.ModuleType("xpra")
    xpra.__path__ = []
    net = types.ModuleType("xpra.net")
    net.__path__ = []
    xpra.server = server
    xpra.net = net
    net.control = control
    control.common = common
    for name, module in {
        "xpra": xpra,
        "xpra.server": server,
        "xpra.net": net,
        "xpra.net.control": control,
        "xpra.net.control.common": common,
    }.items():
        monkeypatch.setitem(sys.modules, name, module)
    target = types.SimpleNamespace(control_command_start=lambda: None)
    method(target, "start", "run command", min_args=1)
    assert calls == [((target, "start", "run command"), {"min_args": 1, "run": target.control_command_start})]


def test_changed_vendor_source_is_rejected():
    original = ORIGINAL_STUB.read_bytes()
    try:
        patcher.patch_bytes(original + b"# unexpected change\n")
    except ValueError as exc:
        assert "does not match" in str(exc)
    else:
        raise AssertionError("changed Xpra source was accepted")


def test_core_and_window_patches_reject_unrecognized_source_bytes():
    for transform in (patcher.patch_core_bytes, patcher.patch_window_bytes):
        try:
            transform(b"changed or unpinned source")
        except ValueError as exc:
            assert "pinned official Xpra 6.5.4 source" in str(exc)
        else:
            raise AssertionError("changed core/window source was accepted")


def test_repacked_payload_and_control_graph_allow_only_the_reviewed_delta(tmp_path, monkeypatch):
    monkeypatch.setattr(patcher, "PATCHED_MEMBER_FACTS", {
        patcher.STUB_RELATIVE.as_posix(): (patcher.PATCHED_SIZE, patcher.PATCHED_SHA256),
    })
    monkeypatch.setattr(patcher, "PATCHED_CONTROL_MD5S", (
        (patcher.STUB_RELATIVE.as_posix(), patcher.SOURCE_MD5, patcher.PATCHED_MD5),
    ))
    original = tmp_path / "original"
    rebuilt = tmp_path / "rebuilt"
    for root in (original, rebuilt):
        (root / patcher.STUB_RELATIVE.parent).mkdir(parents=True)
        (root / "usr/share/xpra").mkdir(parents=True)
        (root / "DEBIAN").mkdir()
        (root / patcher.STUB_RELATIVE).write_bytes(ORIGINAL_STUB.read_bytes())
        (root / "usr/share/xpra/unchanged.txt").write_text("kept", encoding="utf-8")
        (root / "DEBIAN/control").write_text(
            "Package: xpra-server\nVersion: 6.5.4-r0-1\nArchitecture: arm64\n",
            encoding="utf-8",
        )
        (root / "DEBIAN/md5sums").write_text(
            f"{patcher.SOURCE_MD5}  {patcher.STUB_RELATIVE.as_posix()}\n",
            encoding="ascii",
        )
    stub = rebuilt / patcher.STUB_RELATIVE
    stub.write_bytes(patcher.patch_bytes(stub.read_bytes()))
    patcher.update_control_directory(rebuilt / "DEBIAN")
    patcher.verify_repacked_package(original, rebuilt)

    (rebuilt / "usr/share/xpra/unchanged.txt").write_text("changed", encoding="utf-8")
    try:
        patcher.verify_repacked_package(original, rebuilt)
    except ValueError as exc:
        assert "unrelated payload member" in str(exc)
    else:
        raise AssertionError("an unrelated changed package member was accepted")


def test_core_and_window_control_registration_guards_skip_imports_only_when_disabled(monkeypatch):
    def compile_method(signature: bytes, body: bytes, name: str):
        source = signature + body
        tree = ast.parse(textwrap.dedent(source.decode("utf-8")))
        method = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == name)
        namespace = {"noop": object()}
        exec(compile(ast.Module(body=[method], type_ignores=[]), "pinned-xpra-method.py", "exec"), namespace)
        return namespace[name]

    core = compile_method(
        patcher.CORE_NEW,
        b'        self.args_control("readonly", "set readonly", validation=[parse_boolean_value])\n',
        "add_core_control_commands",
    )
    window = compile_method(
        patcher.WINDOW_NEW,
        b'        ac = self.args_control\n        ac("focus", "give focus", validation=[int])\n',
        "add_window_control_commands",
    )
    xpra = types.ModuleType("xpra")
    xpra.__path__ = []
    server = types.ModuleType("xpra.server")
    features = types.SimpleNamespace(control=False)
    server.features = features
    xpra.server = server
    monkeypatch.setitem(sys.modules, "xpra", xpra)
    monkeypatch.setitem(sys.modules, "xpra.server", server)
    monkeypatch.setitem(sys.modules, "xpra.net.control", None)
    monkeypatch.setitem(sys.modules, "xpra.util", None)
    target = types.SimpleNamespace(calls=[], args_control=lambda *args, **kwargs: target.calls.append((args, kwargs)))
    assert core(target) is None
    assert window(target) is None
    assert target.calls == []

    features.control = True
    net = types.ModuleType("xpra.net")
    net.__path__ = []
    control = types.ModuleType("xpra.net.control")
    control.__path__ = []
    common = types.ModuleType("xpra.net.control.common")
    common.parse_boolean_value = lambda value: value
    common.parse_4intlist = lambda value: value
    util = types.ModuleType("xpra.util")
    util.__path__ = []
    parsing = types.ModuleType("xpra.util.parsing")
    parsing.parse_scaling_value = lambda value: value
    parsing.from0to100 = lambda value: value
    for name, module in {
        "xpra.net": net,
        "xpra.net.control": control,
        "xpra.net.control.common": common,
        "xpra.util": util,
        "xpra.util.parsing": parsing,
    }.items():
        monkeypatch.setitem(sys.modules, name, module)
    core(target)
    window(target)
    assert [call[0][0] for call in target.calls] == ["readonly", "focus"]
