"""Contract tests for the opt-in official Hermes Resources plugin bootstrap."""
from __future__ import annotations

import importlib
import sys
import types


def test_official_register_entrypoint_installs_hooks_before_observer_startup(monkeypatch):
    plugin = importlib.import_module(
        "hermes_installer.components.resources_native_plugin_bundle")
    calls = []
    bridge = types.ModuleType("hermes_installer.remote.core_native_observer")
    bridge.register_native_resources_observer = lambda ctx, runtime: calls.append((ctx, runtime))
    monkeypatch.setitem(sys.modules, bridge.__name__, bridge)
    class Context:
        plugin_id = plugin.PLUGIN_ID

    ctx = Context()
    plugin.register(ctx)
    assert calls == [(ctx, None)]


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
