from __future__ import annotations

from copy import deepcopy
import hashlib
import json

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
        broker, credential_reference_id="composio_project_key",
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
    assert call["credential_reference_id"] == "composio_project_key"
    assert call["usage"] == "composio-trigger-discovery"
    assert call["max_response_bytes"] == 2 * 1024 * 1024
    assert 0 < call["timeout_seconds"] <= 30.0
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
    assert receipt.request_policy_artifact_id == "installer-composio-whatsapp-catalog-read-policy-v1"
    assert receipt.request_policy_sha256 == "319076116a060e371c10886e5c2cfea274ed4d985aa03f5e66a4f611f949cfc5"


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


def test_schema_digest_matches_root_canonical_optional_field_projection():
    row = deepcopy(ROW)
    row["name"] = "WhatsApp Nachricht"
    broker = RecordingRootGet(pages=[{"items": [row], "next_cursor": None}], selected=row)
    parsed, _ = discovery(broker).select(ROW["slug"])
    projection = {
        "slug": row["slug"], "name": row["name"], "description": row["description"],
        "type": row["type"], "toolkit": {"slug": "whatsapp", "version": PIN},
        "config": row["config"], "payload": row["payload"],
        "requires_webhook_endpoint_setup": True,
    }
    expected = hashlib.sha256(json.dumps(
        projection, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False).encode("ascii")).hexdigest()
    assert parsed.schema_sha256 == expected


def test_polling_trigger_type_can_still_use_authenticated_webhook_delivery():
    selected = deepcopy(ROW)
    selected["type"] = "poll"
    broker = RecordingRootGet(pages=[{"items": [selected], "next_cursor": None}], selected=selected)
    # Composio's trigger type can poll the provider, while delivery to our
    # receiver still uses the separately signed Composio webhook channel.
    row, receipt = discovery(broker).select(ROW["slug"])
    assert row.trigger_type == "poll"
    assert receipt.status == "discovered-not-configured"


def test_actual_root_source_receipt_handles_are_bound_into_selected_catalog_receipt():
    class RootResponse(dict):
        exchange_receipt_handle: str

        def __init__(self, doc, n):
            super().__init__(doc)
            self.exchange_receipt_handle = f"root-exchange-{n}"

    class ReceiptedRootGet(RecordingRootGet):
        def get_json(self, **kwargs):
            doc = super().get_json(**kwargs)
            return RootResponse(doc, len(self.calls))

    broker = ReceiptedRootGet()
    _, receipt = discovery(broker).select(ROW["slug"])
    assert receipt.source_exchange_receipt_handles == ("root-exchange-1", "root-exchange-2")


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
        ComposioWhatsAppTriggerDiscovery(broker, credential_reference_id="space key", toolkit_version=PIN)
    with pytest.raises(ValueError):
        ComposioWhatsAppTriggerDiscovery(broker, credential_reference_id="vault://project/key", toolkit_version=PIN)
    with pytest.raises(ValueError):
        ComposioWhatsAppTriggerDiscovery(broker,
            credential_reference_id="composio_project_key", toolkit_version="latest")
