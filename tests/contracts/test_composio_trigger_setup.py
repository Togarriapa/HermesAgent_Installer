from __future__ import annotations

from copy import deepcopy

import pytest

from hermes_installer.components.composio_trigger_setup import (
    ComposioTriggerSetupUnavailable,
    ComposioWhatsAppTriggerDiscovery,
)


PIN = "20260721_00"
ROW = {
    "slug": "WHATSAPP_FIXTURE_ONLY_DO_NOT_ENROLL",
    "name": "Synthetic fixture trigger",
    "description": "Synthetic schema fixture; not a Composio trigger",
    "type": "webhook",
    "toolkit": {"slug": "whatsapp", "name": "WhatsApp", "logo": "fixture"},
    "config": {"fixture_setting": {"type": "string", "required": True}},
    "payload": {"fixture_value": {"type": "string"}},
    "version": PIN,
    "requires_webhook_endpoint_setup": True,
}


class RecordingRootGet:
    def __init__(self, pages=None, selected=None, error=None):
        self.pages = pages or [{"items": [deepcopy(ROW)], "next_cursor": None}]
        self.selected = deepcopy(selected or ROW)
        self.error = error
        self.calls = []

    def get_json(self, **kwargs):
        self.calls.append(kwargs)
        if self.error:
            raise self.error
        if kwargs["path"].endswith("/" + ROW["slug"]):
            return deepcopy(self.selected)
        return deepcopy(self.pages.pop(0))


def discovery(broker):
    return ComposioWhatsAppTriggerDiscovery(
        broker, credential_reference_id="vault://profile/composio/project-key",
        toolkit_version=PIN)


def test_discovery_is_authenticated_root_broker_only_and_exactly_versioned():
    broker = RecordingRootGet()
    rows = discovery(broker).discover()
    assert [row.slug for row in rows] == [ROW["slug"]]
    call = broker.calls[0]
    assert call["path"] == "/api/v3.1/triggers_types"
    assert call["query"] == {
        "toolkit_slugs": ["whatsapp"],
        "toolkit_versions": {"whatsapp": PIN},
        "limit": 50,
    }
    assert call["credential_reference_id"] == "vault://profile/composio/project-key"
    assert call["usage"] == "composio-trigger-discovery"
    assert call["max_response_bytes"] == 2 * 1024 * 1024
    assert call["timeout_seconds"] == 10.0
    assert "secret" not in repr(call).casefold()


def test_selected_trigger_is_re_fetched_and_receipt_is_only_discovery_not_readiness():
    broker = RecordingRootGet()
    row, receipt = discovery(broker).select(ROW["slug"])
    assert len(broker.calls) == 2
    assert broker.calls[1]["path"] == f"/api/v3.1/triggers_types/{ROW['slug']}"
    assert broker.calls[1]["query"] == {"toolkit_versions": {"whatsapp": PIN}}
    assert row.schema_sha256 == receipt.schema_sha256
    assert receipt.status == "discovered-not-configured"
    assert receipt.selected_slug == ROW["slug"]


@pytest.mark.parametrize("mutation", [
    {"toolkit": {"slug": "slack"}},
    {"version": "20260915_00"},
])
def test_selected_schema_must_match_source_and_webhook_pin(mutation):
    selected = deepcopy(ROW)
    selected.update(mutation)
    broker = RecordingRootGet(selected=selected)
    with pytest.raises(ComposioTriggerSetupUnavailable):
        discovery(broker).select(ROW["slug"])


def test_schema_drift_between_catalog_and_selected_get_type_fails_closed():
    changed = deepcopy(ROW)
    changed["payload"]["fixture_value"]["maxLength"] = 10
    broker = RecordingRootGet(selected=changed)
    with pytest.raises(ComposioTriggerSetupUnavailable, match="schema changed"):
        discovery(broker).select(ROW["slug"])


def test_polling_trigger_type_can_still_use_authenticated_webhook_delivery():
    selected = deepcopy(ROW)
    selected["type"] = "poll"
    broker = RecordingRootGet(pages=[{"items": [selected], "next_cursor": None}], selected=selected)
    # Composio's trigger type can poll the provider, while delivery to our
    # receiver still uses the separately signed Composio webhook channel.
    row, receipt = discovery(broker).select(ROW["slug"])
    assert row.trigger_type == "poll"
    assert receipt.status == "discovered-not-configured"


def test_unlisted_slug_never_becomes_an_arbitrary_path():
    broker = RecordingRootGet()
    with pytest.raises(ComposioTriggerSetupUnavailable):
        discovery(broker).select("UNKNOWN_TRIGGER")
    assert len(broker.calls) == 1
    assert broker.calls[0]["path"] == "/api/v3.1/triggers_types"


def test_authenticated_transport_failure_fails_closed_without_detail_leak():
    broker = RecordingRootGet(error=RuntimeError("secret token leaked"))
    with pytest.raises(ComposioTriggerSetupUnavailable, match="account remains unconfigured") as error:
        discovery(broker).discover()
    assert "secret token" not in str(error.value)


def test_catalog_bounds_pages_and_rejects_cursor_loops():
    broker = RecordingRootGet(pages=[
        {"items": [], "next_cursor": "same"},
        {"items": [], "next_cursor": "same"},
    ])
    with pytest.raises(ComposioTriggerSetupUnavailable, match="cursor"):
        discovery(broker).discover()


def test_bad_credential_reference_and_non_pinned_version_rejected():
    broker = RecordingRootGet()
    with pytest.raises(ValueError):
        ComposioWhatsAppTriggerDiscovery(broker, credential_reference_id="secret-key", toolkit_version=PIN)
    with pytest.raises(ValueError):
        ComposioWhatsAppTriggerDiscovery(broker,
            credential_reference_id="vault://profile/composio/project-key", toolkit_version="latest")
