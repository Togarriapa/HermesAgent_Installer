from __future__ import annotations

import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest

from hermes_installer.components.plugin_effects import (
    PluginActionSchema, PluginEffectDispatcher, PluginEffectUnavailable, StaticPluginActionSchemas,
)
from hermes_installer.components.plugin_homelab_schemas import (
    PLUGIN_ACTION_SCHEMAS, PLUGIN_HOMELAB_ADAPTER_SHA256,
    PLUGIN_HOMELAB_MANIFEST_SHA256,
)


AUTH = {
    "resolve-session-principal-to-user", "read-active-user-identity",
    "read-user-effective-groups", "verify-effective-System-membership",
    "list-current-effective-System-members-for-alarm-delivery",
}
CF_READ = {
    "read-approved-dns-records", "read-approved-tunnel-state",
    "read-approved-tunnel-connectors", "read-approved-tunnel-configuration",
}
CF_WRITE = {"update-approved-dns-record", "update-approved-tunnel-configuration"}
OPS_READ = {
    "host-health", "cpu-memory-temperature-and-disk", "approved-service-status",
    "approved-container-status", "bounded-service-logs", "installed-runtime-and-container-versions",
    "backup-status-and-integrity-metadata", "nextcloud-status",
    "nextcloud-background-job-status", "nextcloud-maintenance-state",
}
OPS_WRITE = {
    "restart-approved-service", "restart-approved-container", "update-approved-service-or-container",
    "rollback-approved-service-or-container", "run-approved-backup", "run-approved-restore",
    "enter-or-exit-nextcloud-maintenance-mode", "run-approved-nextcloud-repair",
    "run-approved-nextcloud-background-job-operation", "bounded-approved-cleanup",
}
DESTRUCTIVE = {
    "update-approved-service-or-container", "rollback-approved-service-or-container",
    "run-approved-restore", "run-approved-nextcloud-repair", "bounded-approved-cleanup",
}


def test_catalog_covers_exact_source_actions_and_binds_hashes_operations_and_stable_ids():
    assert len(PLUGIN_ACTION_SCHEMAS) == 31
    assert {a for (adapter, a) in PLUGIN_ACTION_SCHEMAS if adapter == "authentik-authorization"} == AUTH
    assert {a for (adapter, a) in PLUGIN_ACTION_SCHEMAS if adapter == "cloudflare-homelab"} == CF_READ | CF_WRITE
    assert {a for (adapter, a) in PLUGIN_ACTION_SCHEMAS if adapter == "homelab-ops-broker"} == OPS_READ | OPS_WRITE

    for (adapter, action), row in PLUGIN_ACTION_SCHEMAS.items():
        assert isinstance(row, PluginActionSchema)
        assert (row.adapter_id, row.action_id) == (adapter, action)
        assert row.adapter_sha256 == PLUGIN_HOMELAB_ADAPTER_SHA256
        assert row.argument_schema_id == f"{adapter}.{action}.arguments.v1"
        assert row.result_schema_id == f"{adapter}.{action}.result.v1"
        assert row.operation == f"plugin.{adapter}.{'write' if action in CF_WRITE | OPS_WRITE else 'read'}"
        assert row.request_bytes_limit == 262_144
        assert row.response_bytes_limit <= 2_097_152
        assert row.deadline_seconds <= 30
        assert row.argument_schema["type"] == "object"
        assert row.result_schema["type"] == "object"
        if action in CF_WRITE | OPS_WRITE:
            assert row.requires_idempotency is True
            assert row.expected_state == "committed"
        else:
            assert row.expected_state == "read-complete"
        if action in CF_WRITE or action in DESTRUCTIVE:
            assert row.requires_confirmation is True
        assert len(PLUGIN_HOMELAB_MANIFEST_SHA256[adapter]) == 64

    repo = Path(__file__).resolve().parents[2]
    for adapter, expected in PLUGIN_HOMELAB_MANIFEST_SHA256.items():
        manifest = repo / "resources/vendor/hermes-agent-resources-2.3.1/plugins" / f"{adapter}.yaml"
        assert hashlib.sha256(manifest.read_bytes()).hexdigest() == expected
    adapter_source = repo / "src/hermes_installer/components/plugin_homelab.py"
    assert hashlib.sha256(adapter_source.read_bytes()).hexdigest() == PLUGIN_HOMELAB_ADAPTER_SHA256


def test_catalog_is_immutable_and_rejects_selected_action_schema_drift_before_authority():
    row = PLUGIN_ACTION_SCHEMAS[("cloudflare-homelab", "read-approved-dns-records")]
    with pytest.raises(TypeError):
        PLUGIN_ACTION_SCHEMAS[("cloudflare-homelab", "new-action")] = row

    selected = SimpleNamespace(
        adapter_id=row.adapter_id, manifest_sha256=PLUGIN_HOMELAB_MANIFEST_SHA256[row.adapter_id],
        adapter_sha256=row.adapter_sha256, action_id=row.action_id,
        argument_schema_id=row.argument_schema_id, result_schema_id="wrong.result.schema",
        effect_enrollment_id="enrollment-1", operation=row.operation,
        capability=f"plugin:{row.adapter_id}", target_id="zone-1", generation="g1", recipient=None,
    )

    class Resolver:
        def resolve(self, adapter_id, action_id):
            return selected

    class Authority:
        calls = []

        def context(self, **kwargs):
            self.calls.append("context")

        def authorize_effect(self, *args, **kwargs):
            self.calls.append("authorize")

        def perform_effect(self, *args, **kwargs):
            self.calls.append("perform")

    authority = Authority()
    identity = SimpleNamespace(kind="plugins", resource_id=row.adapter_id,
                                content_digest=PLUGIN_HOMELAB_MANIFEST_SHA256[row.adapter_id])
    dispatcher = PluginEffectDispatcher(
        authority=authority, invocation_contexts=lambda **_: (object(),),
        selected_effects=Resolver(), action_schemas=StaticPluginActionSchemas(PLUGIN_ACTION_SCHEMAS),
        identity=identity,
    )
    with pytest.raises(PluginEffectUnavailable, match="does not match its source"):
        dispatcher.invoke(row.adapter_id, row.action_id,
                          {"hostname": "ha.togarriapahome.uk"})
    assert authority.calls == []


@pytest.mark.parametrize("action", sorted(CF_WRITE | OPS_WRITE))
def test_mutating_rows_require_idempotency_and_never_claim_verified_commit(action):
    adapter = "cloudflare-homelab" if action in CF_WRITE else "homelab-ops-broker"
    row = PLUGIN_ACTION_SCHEMAS[(adapter, action)]
    assert row.requires_idempotency
    assert row.expected_state == "committed"
    if adapter == "cloudflare-homelab" or action in DESTRUCTIVE:
        assert row.requires_confirmation
