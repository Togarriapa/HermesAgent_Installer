from __future__ import annotations

import asyncio
from types import SimpleNamespace

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
        self.responses = []

    async def _rpc(self, method, params):
        self.calls.append((method, params))
        return self.responses.pop(0) if self.responses else self.result


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

    client.responses = [{"ok": True, "removed": True}, {"servers": []}]
    assert asyncio.run(client.remove_mcp("github")) == {
        "ok": True, "name": "github", "removed": True,
    }
    assert client.calls[-2:] == [
        ("mcp.servers.remove", {"name": "github"}),
        ("mcp.servers.list", {}),
    ]


def test_mcp_removal_requires_native_absence_readback():
    client = _FixedClient({})
    client.responses = [
        {"ok": True, "removed": True},
        {"servers": [{"name": "github", "transport": "http", "enabled": True,
                      "source": "config"}]},
    ]
    with pytest.raises(JarvisChatDenied, match="not reflected"):
        asyncio.run(client.remove_mcp("github"))


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
            {"name": "github", "transport": "http", "enabled": True, "source": "config",
             "config_revision": "not-a-jarvis-owner-proof"},
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
    assert by_identity[("mcps", "github")]["source"] == "unknown"
    assert by_identity[("mcps", "github")]["removable"] is False
    assert by_identity[("mcps", "plugin-server")]["source"] == "bundledResources"
    # Resource overlays and owner-added Hermes-home entrypoints use the
    # source-bound root adapter. Unrecognized native rows remain read-only.
    assert result["availableActions"]["skills"]["edit"] is True
    assert result["availableActions"]["skills"]["remove"] is True
    assert "Hermes stock skills remain read-only" in result["availableActions"]["skills"]["reason"]
    assert result["availableActions"]["plugins"]["remove"] is True
    assert result["availableActions"]["mcps"]["edit"] is False


def test_mcp_removal_ownership_requires_exact_jarvis_add_readback_fingerprint():
    from hermes_installer.remote.jarvis_extensions_admin import _mcp_config_revision

    row = {"name": "github", "transport": "http", "enabled": True,
           "source": "config"}
    revision = _mcp_config_revision(row)
    assert revision is not None
    unknown = build_extension_snapshot(skills=[], plugins=[], mcps=[row])
    owned = build_extension_snapshot(skills=[], plugins=[], mcps=[row],
        owner_added_mcp_revisions={"github": revision})
    changed = build_extension_snapshot(skills=[], plugins=[], mcps=[
        {**row, "enabled": False}], owner_added_mcp_revisions={"github": revision})

    assert unknown["items"][0]["source"] == "unknown"
    assert unknown["items"][0]["removable"] is False
    assert owned["items"][0]["source"] == "useradded"
    assert owned["items"][0]["removable"] is True
    assert changed["items"][0]["source"] == "unknown"
    assert changed["items"][0]["removable"] is False


def test_skill_snapshot_joins_root_manifest_to_native_skills_and_preserves_source():
    result = build_extension_snapshot(
        skills=[{"category": "general", "names": ["owner-helper"]}],
        plugins=[], mcps=[], skill_catalog={"resource-helper"},
        native_skill_files=[
            SimpleNamespace(skill_id="owner-helper", display_name="owner-helper",
                sha256="a" * 64, source="owner-added", editable=True, overlay_active=False),
            SimpleNamespace(skill_id="resource-helper", display_name="resource-helper",
                sha256="b" * 64, source="resources", editable=True, overlay_active=False),
            SimpleNamespace(skill_id="resource-edit", display_name="resource-edit",
                sha256="c" * 64, source="resources", editable=True, overlay_active=True),
        ], archived_skill_files=[
            {"skill_id": "resource-helper", "source": "resources", "versions": [
                {"restore_id": "d" * 64, "sha256": "e" * 64}]},
            {"skill_id": "archived-owner-helper", "source": "owner-added", "versions": [
                {"restore_id": "restore-token_0123456789", "sha256": "f" * 64}]},
        ])
    by_name = {row["name"]: row for row in result["items"] if row["kind"] == "skills"}
    assert by_name["owner-helper"]["source"] == "useradded"
    assert by_name["owner-helper"]["editable"] is True
    assert by_name["owner-helper"]["loaded"] is True
    assert by_name["resource-helper"]["source"] == "bundledResources"
    assert by_name["resource-helper"]["originLabel"] == "Resources (owner overlay)"
    assert by_name["resource-helper"]["overlayActive"] is False
    assert by_name["resource-helper"]["removable"] is False
    assert by_name["resource-edit"]["overlayActive"] is True
    assert by_name["resource-edit"]["removable"] is True
    assert by_name["resource-helper"]["archivedVersions"][0]["restoreId"] == "d" * 64
    assert by_name["archived-owner-helper"]["archivedVersions"][0]["restoreId"] == "restore-token_0123456789"
    assert result["availableActions"]["skills"]["edit"] is True
    assert result["availableActions"]["skills"]["remove"] is True


def test_extension_snapshot_rejects_unbounded_native_inventory():
    with pytest.raises(ValueError, match="exceeded its bound"):
        build_extension_snapshot(skills=[], plugins=[{}] * 513, mcps=[])


@pytest.mark.parametrize(("source", "provenance", "label"), [
    ("bundled", "builtin", "Hermes files"),
    ("user", "useradded", "files"),
    ("catalog", "useradded", "files"),
    ("config", "unknown", "files"),
    ("plugin", "bundledResources", "files"),
    ("entrypoint", "unknown", "files"),
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
    assert ("POST", "/chat/api/extensions/skills/edit") in FEATURE_ASSETS.api_routes
    assert ("POST", "/chat/api/extensions/skills/remove") in FEATURE_ASSETS.api_routes
    assert ("POST", "/chat/api/extensions/skills/restore-list") in FEATURE_ASSETS.api_routes
    assert ("POST", "/chat/api/extensions/skills/restore") in FEATURE_ASSETS.api_routes
