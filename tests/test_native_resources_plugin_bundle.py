"""Contract tests for the opt-in official Hermes Resources plugin bootstrap."""
from __future__ import annotations

import importlib
import sys
import types


def test_official_register_entrypoint_installs_hooks_before_observer_startup(monkeypatch):
    plugin = importlib.import_module(
        "hermes_installer.components.resources_native_plugin_bundle")
    calls = []
    class Client:
        pass

    bridge = types.ModuleType("hermes_installer.remote.core_native_observer")
    bridge.CoreNativeObservationClient = Client
    bridge.register_native_resources_observer = lambda ctx, runtime: calls.append(
        ("observer", ctx, runtime)) or ("observer-hook",)
    monkeypatch.setitem(sys.modules, bridge.__name__, bridge)
    lifecycle = types.ModuleType("hermes_installer.remote.core_lifecycle_startup")
    lifecycle.register_lifecycle_startup_probe = lambda server, *, client: calls.append(
        ("lifecycle", server, client))
    monkeypatch.setitem(sys.modules, lifecycle.__name__, lifecycle)
    gateway = types.ModuleType("tui_gateway.server")
    tui_gateway = types.ModuleType("tui_gateway")
    tui_gateway.server = gateway
    monkeypatch.setitem(sys.modules, "tui_gateway", tui_gateway)
    monkeypatch.setitem(sys.modules, "tui_gateway.server", gateway)
    effects = importlib.import_module("hermes_installer.remote.jarvis_final_effects")
    projects = importlib.import_module("hermes_installer.remote.jarvis_project_context_engine")
    invocations = importlib.import_module("hermes_installer.native_invocations")

    def install_gate(ctx, client, **kwargs):
        calls.append(("gate", ctx, client, kwargs))
        return ("effect-gate",)

    monkeypatch.setattr(effects, "install_jarvis_final_effect_middleware", install_gate)
    monkeypatch.setattr(projects, "install_current_project_context_middleware",
                        lambda ctx: calls.append(("projects", ctx)) or "projects-hook")
    monkeypatch.setattr(invocations, "install_pinned_tool_executor_dispatch_bridge",
                        lambda: calls.append(("pin",)) or "installed")
    class Context:
        plugin_id = plugin.PLUGIN_ID

    ctx = Context()
    registrations = plugin.register(ctx)
    assert [call[0] for call in calls] == ["lifecycle", "gate", "projects", "pin", "observer"]
    assert calls[0][1] is gateway and type(calls[0][2]) is Client
    assert calls[1][1] is ctx
    assert type(calls[1][2]) is Client
    assert calls[1][3] == {"obsidian_binding": None}
    assert calls[-1] == ("observer", ctx, None)
    assert registrations == ("observer-hook", "effect-gate", "projects-hook")


def test_executor_pin_failure_keeps_effect_gate_and_observer_registered(monkeypatch):
    plugin = importlib.import_module(
        "hermes_installer.components.resources_native_plugin_bundle")
    calls = []
    class Client:
        pass

    bridge = types.ModuleType("hermes_installer.remote.core_native_observer")
    bridge.CoreNativeObservationClient = Client
    bridge.register_native_resources_observer = lambda ctx, runtime: calls.append(
        ("observer", ctx, runtime)) or ("observer-hook",)
    monkeypatch.setitem(sys.modules, bridge.__name__, bridge)
    lifecycle = types.ModuleType("hermes_installer.remote.core_lifecycle_startup")
    lifecycle.register_lifecycle_startup_probe = lambda server, *, client: calls.append(
        ("lifecycle", server, client))
    monkeypatch.setitem(sys.modules, lifecycle.__name__, lifecycle)
    gateway = types.ModuleType("tui_gateway.server")
    tui_gateway = types.ModuleType("tui_gateway")
    tui_gateway.server = gateway
    monkeypatch.setitem(sys.modules, "tui_gateway", tui_gateway)
    monkeypatch.setitem(sys.modules, "tui_gateway.server", gateway)
    effects = importlib.import_module("hermes_installer.remote.jarvis_final_effects")
    projects = importlib.import_module("hermes_installer.remote.jarvis_project_context_engine")
    invocations = importlib.import_module("hermes_installer.native_invocations")

    def install_gate(ctx, client, **kwargs):
        calls.append(("gate", ctx, client, kwargs))
        return ("effect-gate",)

    monkeypatch.setattr(effects, "install_jarvis_final_effect_middleware", install_gate)
    monkeypatch.setattr(projects, "install_current_project_context_middleware",
                        lambda ctx: calls.append(("projects", ctx)) or "projects-hook")

    def stale_pin():
        calls.append(("pin-failed",))
        raise RuntimeError("pinned source changed")

    monkeypatch.setattr(invocations, "install_pinned_tool_executor_dispatch_bridge", stale_pin)

    class Context:
        plugin_id = plugin.PLUGIN_ID

    ctx = Context()
    registrations = plugin.register(ctx)
    assert [call[0] for call in calls] == ["lifecycle", "gate", "projects", "pin-failed", "observer"]
    assert calls[1][1] is ctx
    assert type(calls[1][2]) is Client
    assert calls[1][3] == {"obsidian_binding": None}
    assert registrations == ("observer-hook", "effect-gate", "projects-hook")


def test_official_register_entrypoint_ignores_another_plugin_scope(monkeypatch):
    plugin = importlib.import_module(
        "hermes_installer.components.resources_native_plugin_bundle")
    calls = []
    bridge = types.ModuleType("hermes_installer.remote.core_native_observer")
    bridge.register_native_resources_observer = lambda *args: calls.append(args)
    monkeypatch.setitem(sys.modules, bridge.__name__, bridge)
    class Context:
        plugin_id = "unrelated-plugin"

    plugin.register(Context())
    assert calls == []
