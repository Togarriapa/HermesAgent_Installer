from __future__ import annotations

import ast
import importlib.util
import sys
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


def test_repacked_payload_and_control_graph_allow_only_the_reviewed_delta(tmp_path):
    original = tmp_path / "original"
    rebuilt = tmp_path / "rebuilt"
    for root in (original, rebuilt):
        (root / "data" / patcher.STUB_RELATIVE.parent).mkdir(parents=True)
        (root / "data/usr/share/xpra").mkdir(parents=True)
        (root / "DEBIAN").mkdir()
        (root / "data" / patcher.STUB_RELATIVE).write_bytes(ORIGINAL_STUB.read_bytes())
        (root / "data" / "usr/share/xpra/unchanged.txt").write_text("kept", encoding="utf-8")
        (root / "DEBIAN/control").write_text(
            "Package: xpra-server\nVersion: 6.5.4-r0-1\nArchitecture: arm64\n",
            encoding="utf-8",
        )
        (root / "DEBIAN/md5sums").write_text(
            f"{patcher.SOURCE_MD5}  {patcher.STUB_RELATIVE.as_posix()}\n",
            encoding="ascii",
        )
    patcher.patch_tree(rebuilt / "data")
    patcher.update_control_directory(rebuilt / "DEBIAN")
    patcher.verify_repacked_package(original, rebuilt)

    (rebuilt / "data/usr/share/xpra/unchanged.txt").write_text("changed", encoding="utf-8")
    try:
        patcher.verify_repacked_package(original, rebuilt)
    except ValueError as exc:
        assert "unrelated payload member" in str(exc)
    else:
        raise AssertionError("an unrelated changed package member was accepted")
