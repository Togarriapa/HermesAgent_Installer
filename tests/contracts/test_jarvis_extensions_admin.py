from __future__ import annotations

import asyncio

import pytest

from hermes_installer.remote.core_client import CoreRpcClient
from hermes_installer.remote.jarvis_chat import JarvisChatDenied
from hermes_installer.remote.jarvis_extensions_admin import (
    _valid_plugin_setting,
    _source_label,
    build_extension_snapshot,
)
from hermes_installer.remote.jarvis_extensions_assets import FEATURE_ASSETS
from hermes_installer.remote.jarvis_feature_contract import validate_feature_assets


class _FixedClient(CoreRpcClient):
    def __init__(self, result):
        self.result = result
        self.calls = []

    async def _rpc(self, method, params):
        self.calls.append((method, params))
        return self.result


def test_extension_writes_use_only_fixed_native_management_actions():
    client = _FixedClient({"installed": True, "name": "research-helper"})
    assert asyncio.run(client.install_skill("research-helper")) == {
        "installed": True, "name": "research-helper",
    }
    assert client.calls[-1] == ("skills.manage", {"action": "install", "query": "research-helper"})

    client.result = {"ok": True, "plugin_name": "owner-helper"}
    assert asyncio.run(client.install_plugin("owner-helper"))["ok"] is True
    assert client.calls[-1] == ("plugins.manage", {
        "action": "install", "catalog_name": "owner-helper", "enable": False, "force": False,
    })

    client.result = {"ok": True, "name": "owner-helper"}
    assert asyncio.run(client.remove_plugin("owner-helper")) == {
        "ok": True, "name": "owner-helper", "reversible": False,
    }
    assert client.calls[-1] == ("plugins.manage", {"action": "remove", "name": "owner-helper"})

    client.result = {"servers": [{"name": "github", "source": "config"}]}
    client.result = {"removed": True, "name": "github"}
    assert asyncio.run(client.remove_mcp("github"))["removed"] is True
    assert client.calls[-1] == ("mcp.servers.remove", {"name": "github"})


def test_extension_native_write_postconditions_fail_closed():
    client = _FixedClient({"ok": True, "name": "different"})
    with pytest.raises(JarvisChatDenied):
        asyncio.run(client.remove_plugin("owner-helper"))
    client.result = {"installed": False, "name": "owner-helper"}
    with pytest.raises(JarvisChatDenied):
        asyncio.run(client.install_skill("owner-helper"))
    client.result = {"output": "1 skill(s) available", "result": {
        "added": [], "removed": [], "unchanged": [], "total": 1, "commands": 1,
    }}
    assert asyncio.run(client.reload_skills()) == {"total": 1, "commands": 1}
    assert client.calls[-1] == ("skills.reload", {})


def test_extension_snapshot_keeps_provenance_and_prefixes_builtins():
    result = build_extension_snapshot(
        skills=[{"category": "general", "names": ["web-facts", "local-procedure"]}],
        plugins=[
            {"name": "web", "key": "web", "version": "1.2.0", "source": "bundled",
             "status": "enabled", "settings_schema": []},
            {"name": "owner-tool-package", "key": "owner-tool", "version": "1.0", "source": "user",
             "status": "disabled", "settings_schema": [{"key": "mode", "type": "string"}]},
        ],
        mcps=[
            {"name": "github", "transport": "http", "enabled": True, "source": "config"},
            {"name": "plugin-server", "transport": "stdio", "enabled": True, "source": "plugin"},
        ],
        skill_catalog={"web-facts"},
    )

    by_identity = {(item["kind"], item["name"]): item for item in result["items"]}
    assert by_identity[("plugins", "web")]["label"] == "Hermes web"
    assert by_identity[("plugins", "web")]["source"] == "builtin"
    assert by_identity[("plugins", "owner-tool-package")]["source"] == "useradded"
    assert by_identity[("plugins", "owner-tool-package")]["editable"] is True
    assert by_identity[("plugins", "owner-tool-package")]["removable"] is True
    assert by_identity[("plugins", "owner-tool-package")]["key"] == "owner-tool"
    assert by_identity[("skills", "web-facts")]["source"] == "bundledResources"
    assert by_identity[("skills", "local-procedure")]["source"] == "unknown"
    assert by_identity[("mcps", "github")]["source"] == "useradded"
    assert by_identity[("mcps", "plugin-server")]["source"] == "bundledResources"
    assert result["availableActions"]["skills"]["edit"] is False
    assert result["availableActions"]["plugins"]["remove"] is True
    assert result["availableActions"]["mcps"]["edit"] is False


def test_extension_snapshot_rejects_unbounded_native_inventory():
    with pytest.raises(ValueError, match="exceeded its bound"):
        build_extension_snapshot(skills=[], plugins=[{}] * 513, mcps=[])


@pytest.mark.parametrize(("source", "provenance", "label"), [
    ("bundled", "builtin", "Hermes files"),
    ("user", "useradded", "files"),
    ("config", "useradded", "files"),
    ("plugin", "bundledResources", "files"),
    ("unrecognized", "unknown", "files"),
])
def test_provenance_labels_are_truthful(source, provenance, label):
    assert _source_label(source, "files") == (provenance, label)


def test_plugin_setting_edits_match_the_native_nonsecret_schema():
    assert _valid_plugin_setting({"type": "enum", "choices": ["safe", "strict"]}, "strict")
    assert not _valid_plugin_setting({"type": "enum", "choices": ["safe", "strict"]}, "unsafe")
    assert not _valid_plugin_setting({"type": "secret"}, "secret-value")
    assert not _valid_plugin_setting({"type": "number"}, True)


def test_extensions_feature_asset_uses_only_fixed_routes():
    validate_feature_assets((FEATURE_ASSETS,))
    assert ("GET", "/chat/api/extensions") in FEATURE_ASSETS.api_routes
    assert ("POST", "/chat/api/extensions/plugins/remove") in FEATURE_ASSETS.api_routes
