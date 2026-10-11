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
    effects = importlib.import_module("hermes_installer.remote.jarvis_final_effects")
    invocations = importlib.import_module("hermes_installer.native_invocations")
    monkeypatch.setattr(effects, "install_jarvis_final_effect_middleware",
                        lambda ctx, client: calls.append(("gate", ctx, client)) or ("effect-gate",))
    monkeypatch.setattr(invocations, "install_pinned_tool_executor_dispatch_bridge",
                        lambda: calls.append(("pin",)) or "installed")
    class Context:
        plugin_id = plugin.PLUGIN_ID

    ctx = Context()
    registrations = plugin.register(ctx)
    assert [call[0] for call in calls] == ["gate", "pin", "observer"]
    assert calls[0][1] is ctx
    assert type(calls[0][2]) is Client
    assert calls[-1] == ("observer", ctx, None)
    assert registrations == ("observer-hook", "effect-gate")


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
    effects = importlib.import_module("hermes_installer.remote.jarvis_final_effects")
    invocations = importlib.import_module("hermes_installer.native_invocations")
    monkeypatch.setattr(effects, "install_jarvis_final_effect_middleware",
                        lambda ctx, client: calls.append(("gate", ctx, client)) or ("effect-gate",))

    def stale_pin():
        calls.append(("pin-failed",))
        raise RuntimeError("pinned source changed")

    monkeypatch.setattr(invocations, "install_pinned_tool_executor_dispatch_bridge", stale_pin)

    class Context:
        plugin_id = plugin.PLUGIN_ID

    ctx = Context()
    registrations = plugin.register(ctx)
    assert [call[0] for call in calls] == ["gate", "pin-failed", "observer"]
    assert calls[0][1] is ctx
    assert type(calls[0][2]) is Client
    assert registrations == ("observer-hook", "effect-gate")


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
