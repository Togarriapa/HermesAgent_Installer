"""Contract tests for the embedded official-Hermes plugin scripts.

These tests must run with the Pi's reviewed interpreter/toolchain; they execute
only stubbed config APIs and never touch the installed Hermes home.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import io
import json
import sys
from types import ModuleType

import pytest

from hermes_installer.remote.native_plugin_bootstrap import (
    _OFFICIAL_ENABLE_SCRIPT,
    _OFFICIAL_SELECTION_READ_SCRIPT,
    _OFFICIAL_SELECTION_RESTORE_SCRIPT,
)


def _install_hermes_config_stubs(monkeypatch, state):
    hermes_cli = ModuleType("hermes_cli")
    config_module = ModuleType("hermes_cli.config")
    plugins_module = ModuleType("hermes_cli.plugins_cmd")
    toolset_module = ModuleType("hermes_cli.toolset_validation")

    def load_config():
        return copy.deepcopy(state)

    def save_config(config, **_kwargs):
        state.clear()
        state.update(copy.deepcopy(config))

    def parse_platform_toolsets_value(value):
        if isinstance(value, list) and all(isinstance(item, str) for item in value):
            return list(value)
        return None

    def cmd_enable(key, *, allow_tool_override):
        assert allow_tool_override is None
        plugins = state.setdefault("plugins", {})
        plugins["enabled"] = [*plugins.get("enabled", []), key]
        plugins["disabled"] = [item for item in plugins.get("disabled", []) if item != key]
        for platform, values in state.get("platform_toolsets", {}).items():
            parsed = parse_platform_toolsets_value(values)
            if parsed is not None and "resources_internal" not in parsed:
                state["platform_toolsets"][platform] = [*parsed, "resources_internal"]

    def cmd_disable(key):
        plugins = state.setdefault("plugins", {})
        plugins["enabled"] = [item for item in plugins.get("enabled", []) if item != key]
        plugins["disabled"] = [*plugins.get("disabled", []), key]
        for platform, values in state.get("platform_toolsets", {}).items():
            parsed = parse_platform_toolsets_value(values)
            if parsed is not None:
                state["platform_toolsets"][platform] = [
                    item for item in parsed if item != "resources_internal"]

    config_module.load_config = load_config
    config_module.save_config = save_config
    plugins_module.cmd_enable = cmd_enable
    plugins_module.cmd_disable = cmd_disable
    plugins_module._toggle_plugin_toolset = lambda *_args, **_kwargs: None
    toolset_module.parse_platform_toolsets_value = parse_platform_toolsets_value
    monkeypatch.setitem(sys.modules, "hermes_cli", hermes_cli)
    monkeypatch.setitem(sys.modules, "hermes_cli.config", config_module)
    monkeypatch.setitem(sys.modules, "hermes_cli.plugins_cmd", plugins_module)
    monkeypatch.setitem(sys.modules, "hermes_cli.toolset_validation", toolset_module)


def test_embedded_official_scripts_are_valid_python():
    compile(_OFFICIAL_ENABLE_SCRIPT, "<official-enable-script>", "exec")
    compile(_OFFICIAL_SELECTION_READ_SCRIPT, "<official-selection-read-script>", "exec")
    compile(_OFFICIAL_SELECTION_RESTORE_SCRIPT,
            "<official-selection-restore-script>", "exec")


def test_official_enable_script_effect_and_selection_readback(monkeypatch, capsys):
    state = {"plugins": {"enabled": [], "disabled": []},
             "platform_toolsets": {"tui": ["core"]}, "unrelated": {"keep": True}}
    _install_hermes_config_stubs(monkeypatch, state)

    exec(compile(_OFFICIAL_ENABLE_SCRIPT, "<official-enable-script>", "exec"), {})
    assert state["plugins"] == {
        "enabled": ["hermes-installer-resources-delegation"], "disabled": []}
    assert state["platform_toolsets"] == {"tui": ["core", "resources_internal"]}
    assert state["unrelated"] == {"keep": True}
    assert capsys.readouterr().out.strip() == "native-plugin-selection-verified"

    exec(compile(_OFFICIAL_SELECTION_READ_SCRIPT,
                 "<official-selection-read-script>", "exec"), {})
    expected = {"enabled": ["hermes-installer-resources-delegation"],
                "disabled": [], "platform_toolsets": {"tui": ["core", "resources_internal"]}}
    digest = hashlib.sha256(json.dumps(
        expected, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")).hexdigest()
    assert capsys.readouterr().out.strip() == "native-plugin-selection:" + digest


def test_selection_script_denies_plugin_absent_from_saved_config(monkeypatch):
    state = {"plugins": {"enabled": [], "disabled": []}, "platform_toolsets": {}}
    _install_hermes_config_stubs(monkeypatch, state)
    with pytest.raises(RuntimeError, match="fixed Resources plugin is not selected"):
        exec(compile(_OFFICIAL_SELECTION_READ_SCRIPT,
                     "<official-selection-read-script>", "exec"), {})


def test_restore_repairs_only_exact_official_failed_enable_rollback(monkeypatch, capsys):
    key = "hermes-installer-resources-delegation"
    state = {"plugins": {"enabled": [], "disabled": [key]},
             "unrelated": {"keep": True}}
    _install_hermes_config_stubs(monkeypatch, state)
    prior = {"schema": 1, "plugins_present": True, "enabled_present": False,
             "disabled_present": False, "enabled": [], "disabled": [],
             "platform_present": False, "platform_toolsets": {}}
    snapshot = json.dumps(prior, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True).encode("ascii")
    migrated = {"enabled": [key], "disabled": [], "platform_toolsets": {}}
    expected_current = hashlib.sha256(json.dumps(
        migrated, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")).hexdigest()
    request = {"snapshot_b64": base64.b64encode(snapshot).decode("ascii"),
               "expected_current_sha256": expected_current}
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(request)))

    with pytest.raises(SystemExit) as result:
        exec(compile(_OFFICIAL_SELECTION_RESTORE_SCRIPT,
                     "<official-selection-restore-script>", "exec"), {})
    assert result.value.code == 0

    assert state == {"plugins": {}, "unrelated": {"keep": True}}
    assert capsys.readouterr().out.startswith("native-plugin-selection-restored:")


@pytest.mark.parametrize("selection", [
    {"plugins": {"enabled": [], "disabled": ["hermes-installer-resources-delegation",
                                                "another-plugin"]}},
    {"plugins": {"enabled": [], "disabled": ["hermes-installer-resources-delegation"]},
     "platform_toolsets": {"tui": ["core", "unrelated"]}},
])
def test_restore_refuses_other_selection_changes_after_failed_enable(monkeypatch, selection):
    key = "hermes-installer-resources-delegation"
    state = {**copy.deepcopy(selection), "unrelated": {"keep": True}}
    _install_hermes_config_stubs(monkeypatch, state)
    import hermes_cli.config as config_module
    saves = []
    monkeypatch.setattr(config_module, "save_config",
                        lambda config, **_kwargs: saves.append(copy.deepcopy(config)))
    prior = {"schema": 1, "plugins_present": True, "enabled_present": False,
             "disabled_present": False, "enabled": [], "disabled": [],
             "platform_present": False, "platform_toolsets": {}}
    snapshot = json.dumps(prior, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True).encode("ascii")
    migrated = {"enabled": [key], "disabled": [], "platform_toolsets": {}}
    expected_current = hashlib.sha256(json.dumps(
        migrated, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")).hexdigest()
    request = {"snapshot_b64": base64.b64encode(snapshot).decode("ascii"),
               "expected_current_sha256": expected_current}
    from unittest.mock import patch
    with patch("sys.stdin", io.StringIO(json.dumps(request))):
        with pytest.raises(RuntimeError, match="current plugin selection changed"):
            exec(compile(_OFFICIAL_SELECTION_RESTORE_SCRIPT,
                         "<official-selection-restore-script>", "exec"), {})
    assert state == {**copy.deepcopy(selection), "unrelated": {"keep": True}}
    assert saves == []
