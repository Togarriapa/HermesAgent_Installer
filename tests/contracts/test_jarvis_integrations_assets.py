"""Contract checks for the independently composed read-only integrations view."""
from __future__ import annotations

from hermes_installer.remote.jarvis_feature_contract import validate_feature_assets
from hermes_installer.remote.jarvis_integrations_assets import FEATURE_ASSETS


def test_integration_menu_uses_only_existing_fixed_read_routes():
    feature = FEATURE_ASSETS
    validate_feature_assets((feature,))

    assert feature.feature_id == "integrations"
    assert feature.api_routes == (
        ("GET", "/chat/api/capabilities"),
        ("GET", "/chat/api/channels"),
    )
    assert "api.get('/chat/api/capabilities')" in feature.mount_js
    assert "api.get('/chat/api/channels')" in feature.mount_js
    assert "api.post(" not in feature.mount_js
    assert "fetch(" not in feature.mount_js


def test_menu_keeps_unknown_account_state_and_uses_fixed_installer_resume():
    feature = FEATURE_ASSETS

    # Fixture contract from current owner APIs: the channel adapter deliberately
    # returns no invented rows and explains why native account state is unknown.
    channel_status_fixture = {
        "schema": 1,
        "observed_at": "2026-10-11T12:00:00Z",
        "channels": [],
        "pending_reasons": [
            "No reviewed native messaging status reader is available; channel configuration and connection state are unknown."
        ],
    }
    assert channel_status_fixture["channels"] == []
    assert "unknown" in channel_status_fixture["pending_reasons"][0]
    assert "Configured" in feature.mount_js
    assert "Unknown" in feature.mount_js
    assert "No reviewed native messaging status reader is available" in feature.mount_js
    assert "hermes-installer setup" in feature.view_html
    assert "Credentials are not collected here" in feature.view_html
    assert "input" not in feature.view_html.lower()
    assert "secret" not in feature.mount_js.lower()


def test_catalog_declarations_are_labeled_pending_and_never_as_activation():
    feature = FEATURE_ASSETS

    catalog_fixture = {
        "readiness": "pending",
        "source": {
            "kind": "offline-bundle",
            "catalogVersion": "2.3.1",
            "revision": "113f42d33be9e0c8f0f47f5ca998e687323dec83",
        },
        "items": [{"id": "discord", "kind": "channels", "name": "Discord",
                   "state": "bundled", "readiness": "pending"}],
    }
    assert catalog_fixture["items"][0]["readiness"] == "pending"
    assert "Bundled definition · readiness pending" in feature.mount_js
    assert "Configured" in feature.mount_js
    assert "connected" in feature.mount_js
    assert "Pairing" in feature.view_html or "pairing" in feature.view_html.lower()
