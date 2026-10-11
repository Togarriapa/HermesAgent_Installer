"""Contract tests for the closed Settings projection and its static feature assets."""
from __future__ import annotations

import re

from hermes_installer.remote.jarvis_feature_contract import validate_feature_assets
from hermes_installer.remote.jarvis_native_controls_assets import FEATURE_ASSETS
from hermes_installer.remote.jarvis_native_controls import (
    build_native_controls_snapshot,
    decode_native_controls,
)


def _opaque(kind: str, name: str) -> str:
    return ("a" if kind == "plugin" else "b") * 32


def _base(*, plugins=None, mcp=None):
    return build_native_controls_snapshot(
        provider={"value": "OpenRouter", "status": "configured-unverified"},
        model={"value": "zai/glm-5.2", "status": "configured-unverified"},
        core_version={"value": "012345abcdef", "status": "verified"},
        plugins=plugins,
        mcp=mcp,
        opaque_id=_opaque,
    )


def test_native_controls_projects_fixed_observations_and_keeps_auth_unknown():
    snapshot = _base(
        plugins={"plugins": [{"name": "example-plugin", "version": "1.2.3", "enabled": True}]},
        mcp={"servers": [{"name": "docs", "transport": "http", "tools": 2,
                           "connected": True, "disabled": False, "status": "connected"}],
             "checked_at": 1_797_000_000_000},
    )
    public = snapshot.to_public_dict()

    assert public["readiness"] == "pending"
    assert public["accountState"] == {"value": "unknown", "status": "pending"}
    assert public["provider"] == {"value": "OpenRouter", "status": "configured-unverified"}
    assert public["plugins"] == {
        "state": "observed",
        "items": [{"id": "a" * 32, "label": "example-plugin", "version": "1.2.3",
                   "enabled": True, "loaded": True}],
    }
    assert public["mcp"]["state"] == "observed"
    assert public["mcp"]["servers"][0] == {
        "id": "b" * 32, "label": "docs", "transport": "http", "toolCount": 2,
        "connected": True, "disabled": False, "status": "connected",
    }
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", public["mcp"]["checkedAt"])
    assert decode_native_controls(public) == snapshot


def test_empty_plugin_manager_is_unknown_but_empty_timestamped_mcp_is_observed():
    public = _base(plugins={"plugins": []}, mcp={"servers": [], "checked_at": 1_797_000_000_000}).to_public_dict()

    assert public["plugins"] == {"state": "unknown", "items": []}
    assert public["mcp"]["state"] == "observed"
    assert public["mcp"]["servers"] == []


def test_malformed_or_expansive_native_rows_fail_closed_per_section():
    public = _base(
        plugins={"plugins": [{"name": "https://secret.invalid", "version": "1", "enabled": True}]},
        mcp={"servers": [{"name": "bad/name", "transport": "stdio", "tools": 1,
                           "connected": True, "disabled": False, "status": "connected"}],
             "checked_at": 1_797_000_000_000},
    ).to_public_dict()

    assert public["provider"]["value"] == "OpenRouter"
    assert public["plugins"] == {"state": "unknown", "items": []}
    assert public["mcp"] == {"state": "unknown", "checkedAt": None, "servers": []}


def test_wire_decoder_rejects_extra_keys_and_never_accepts_auth_claims():
    public = _base(plugins={"plugins": []}, mcp=None).to_public_dict()
    public["mcp"]["raw_config"] = {"token": "must-not-pass"}
    decoded = decode_native_controls(public).to_public_dict()

    assert decoded["provider"] == {"value": None, "status": "pending"}
    assert decoded["accountState"] == {"value": "unknown", "status": "pending"}


def test_native_controls_feature_uses_the_shared_frozen_shell_contract():
    validate_feature_assets((FEATURE_ASSETS,))

    assert FEATURE_ASSETS.feature_id == "native-controls"
    assert FEATURE_ASSETS.api_routes == (("GET", "/chat/api/settings"),)
    assert "<script" not in FEATURE_ASSETS.view_html.lower()
    assert "textContent" in FEATURE_ASSETS.mount_js
    assert FEATURE_ASSETS.mount_js.startswith("function mount(")
    assert FEATURE_ASSETS.unmount_js.startswith("function unmount(")
