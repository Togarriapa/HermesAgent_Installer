"""Effect-time tests for the protected homelab plugin broker."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from hermes_installer.authority.types import canonical_digest
from hermes_installer.network import HTTPResult
from hermes_installer.plugin_homelab_broker import (
    FixedHomelabHTTPSBackend, HomelabActionEnrollment, HomelabEffectDenied,
    HomelabTargetEnrollment, build_plugin_homelab_effect_handlers,
    parse_homelab_action_record,
)


CF_HASH = "5623e42ba85a5056c7cae8e3e1ae5b0d48613071220772e82027864f6cfdd7c5"


class _Network:
    def __init__(self, rows):
        self.rows = list(rows)
        self.calls = []

    def request(self, url, *, method, headers, body, cancelled=None):
        self.calls.append((url, method, headers, body))
        if cancelled and cancelled():
            raise RuntimeError("cancelled")
        value = self.rows.pop(0)
        return HTTPResult(200, {"content-type": "application/json"}, json.dumps(value).encode())


class _Vault:
    def __init__(self, credential="fixture-token"):
        self.credential = credential
        self.calls = []

    def resolve_reference(self, reference, **kwargs):
        self.calls.append((reference, kwargs))
        return self.credential


class _Ledger:
    def __init__(self): self.rows = {}
    def claim(self, key, digest, op):
        if key in self.rows: return self.rows[key]
        self.rows[key] = {"digest": digest, "operation_id": op, "state": "new", "receipt": {}}
        return self.rows[key]
    def finish(self, key, state, receipt):
        self.rows[key] = {**self.rows[key], "state": state, "receipt": receipt}


class _System:
    def __init__(self, allowed=True): self.allowed = allowed; self.calls = 0
    def require_fresh_system_member(self, **kwargs):
        self.calls += 1
        if not self.allowed: raise HomelabEffectDenied("system.denied", "not a current System member")


class _Confirmation:
    def __init__(self, allowed=True): self.allowed = allowed; self.calls = 0
    def consume_plugin_confirmation(self, **kwargs):
        self.calls += 1
        return object() if self.allowed else None


def _pair(action_id="read-approved-dns-records", *, write=False, schema=None):
    operation = "plugin.cloudflare-homelab.write" if write else "plugin.cloudflare-homelab.read"
    action = HomelabActionEnrollment(
        adapter_id="cloudflare-homelab", manifest_sha256=CF_HASH,
        handler_artifact_id="homelab-broker-v1", handler_sha256="a" * 64,
        action_id=action_id, argument_schema_id=f"schema-{action_id}",
        operation=operation, capability="plugin:cloudflare-homelab", target_id="zone-ha",
        generation="gen-4", principal_id="alice", profile_id="hermes", recipient="alice",
        enrollment_id="enroll-cloudflare", argument_schema=schema or {
            "type": "object", "properties": {"hostname": {"type": "string", "enum": ["ha.togarriapahome.uk"]}},
            "required": ["hostname"], "additionalProperties": False},
        mutating=write, confirmation_policy_id="confirm-dns" if write else None,
        idempotency_policy_id="idem-dns" if write else None)
    target = HomelabTargetEnrollment(
        adapter_id="cloudflare-homelab", enrollment_id="enroll-cloudflare", principal_id="alice",
        profile_id="hermes", recipient="alice", account_id="acct_1", zone_id="zone_1",
        dns_record_ids={"ha.togarriapahome.uk": "record_1"}, tunnel_ids={"ha": "tunnel_1"},
        credential_reference_id="cloudflare_token", credential_scope="cloudflare-zone-write",
        action_ids=frozenset({action_id}))
    return action, target


def _request(action, arguments, *, write=False, confirmation=True):
    value = {"schema": 1, "adapter_id": action.adapter_id, "action_id": action.action_id,
             "enrollment_id": action.enrollment_id, "generation": action.generation,
             "arguments": arguments}
    if write:
        value["idempotency_key"] = "idem-1"
        if confirmation: value["opaque_confirmation_attestation_id"] = "confirm-1"
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _grants(action, payload):
    digest = canonical_digest(payload)
    ctx = SimpleNamespace(final_payload_digest=digest, operation=action.operation,
        principal_id="alice", profile_id="hermes", capabilities=frozenset({action.capability}))
    grant = SimpleNamespace(request_digest=digest, final_payload_digest=digest,
        capability=action.capability, target=action.target, operation=action.operation,
        enrollment_id=action.enrollment_id, generation=action.generation, principal_id="alice",
        profile_id="hermes", recipient="alice", monotonic_expires_at=10**10)
    return ctx, grant


class PluginHomelabBrokerTests(unittest.TestCase):
    def test_selected_effect_record_has_exact_schema_and_root_scope_join(self):
        _, target = _pair()
        schema = {"type": "object", "properties": {"hostname": {"type": "string",
            "enum": ["ha.togarriapahome.uk"]}}, "required": ["hostname"], "additionalProperties": False}
        record = {"adapter_id": "cloudflare-homelab", "manifest_sha256": CF_HASH,
            "handler_artifact_id": "homelab-broker-v1", "handler_sha256": "a" * 64,
            "action_id": "read-approved-dns-records", "argument_schema_id": "dns-read-v1",
            "operation": "plugin.cloudflare-homelab.read", "capability": "plugin:cloudflare-homelab",
            "target_id": "zone-ha", "generation": "gen-4", "principal_id": "alice",
            "profile_id": "hermes", "recipient": "alice", "credential_reference_id": "cloudflare_token",
            "scope_reference_id": "cloudflare-zone-write", "confirmation_policy_id": None,
            "idempotency_policy_id": None, "request_bytes_limit": 262144,
            "response_bytes_limit": 2097152, "deadline_seconds": 30.0}
        action = parse_homelab_action_record(record, argument_schemas={"dns-read-v1": schema}, target=target)
        self.assertEqual((action.operation, action.target), (record["operation"], "plugin:cloudflare-homelab:zone-ha:gen-4"))
        with self.assertRaisesRegex(ValueError, "unknown or missing"):
            parse_homelab_action_record({**record, "url": "https://evil.test"},
                argument_schemas={"dns-read-v1": schema}, target=target)

    def test_cloudflare_dns_read_is_concretely_bound_to_enrolled_record(self):
        action, target = _pair()
        network = _Network([{"success": True, "result": {"id": "record_1", "name": "ha.togarriapahome.uk", "content": "192.0.2.4"}}])
        ledger, vault = _Ledger(), _Vault()
        handlers = build_plugin_homelab_effect_handlers(actions={(action.operation, action.target): (action, target)},
            vault=vault, backend=FixedHomelabHTTPSBackend(network), ledger=ledger)
        payload = _request(action, {"hostname": "ha.togarriapahome.uk"})
        context, grant = _grants(action, payload)
        response = handlers[(action.operation, action.target)](context=context, authorization=grant,
            payload=payload, timeout=5, peer_pid=123, cancelled=lambda: False)
        body = json.loads(response["body"])
        self.assertEqual(body["state"], "read-complete")
        self.assertEqual(body["result"]["content"], "192.0.2.4")
        self.assertEqual(network.calls[0][0], "https://api.cloudflare.com/client/v4/zones/zone_1/dns_records/record_1")
        self.assertEqual(vault.calls[0][0], "cloudflare_token")

    def test_dns_write_fresh_membership_and_confirmation_precede_effect(self):
        schema = {"type": "object", "properties": {"hostname": {"type": "string"},
            "content": {"type": "string"}, "ttl": {"type": "integer"}, "proxied": {"type": "boolean"}},
            "required": ["hostname", "content", "ttl", "proxied"], "additionalProperties": False}
        action, target = _pair("update-approved-dns-record", write=True, schema=schema)
        network = _Network([]); system = _System(False); confirmation = _Confirmation()
        handlers = build_plugin_homelab_effect_handlers(actions={(action.operation, action.target): (action, target)},
            vault=_Vault(), backend=FixedHomelabHTTPSBackend(network), ledger=_Ledger(),
            confirmation=confirmation, system_membership=system)
        payload = _request(action, {"hostname": "ha.togarriapahome.uk", "content": "192.0.2.8", "ttl": 300, "proxied": False}, write=True)
        context, grant = _grants(action, payload)
        with self.assertRaisesRegex(HomelabEffectDenied, "current System"):
            handlers[(action.operation, action.target)](context=context, authorization=grant,
                payload=payload, timeout=5, peer_pid=123, cancelled=lambda: False)
        self.assertEqual(system.calls, 1)
        self.assertEqual(network.calls, [])
        self.assertEqual(confirmation.calls, 0)

    def test_cloudflare_update_performs_only_the_enrolled_record_and_reports_ambiguous_until_readback(self):
        schema = {"type": "object", "properties": {"hostname": {"type": "string"},
            "content": {"type": "string"}, "ttl": {"type": "integer"}, "proxied": {"type": "boolean"}},
            "required": ["hostname", "content", "ttl", "proxied"], "additionalProperties": False}
        action, target = _pair("update-approved-dns-record", write=True, schema=schema)
        network = _Network([
            {"success": True, "result": {"id": "record_1", "name": "ha.togarriapahome.uk", "type": "A", "content": "192.0.2.4"}},
            {"success": True, "result": {"id": "record_1", "name": "ha.togarriapahome.uk", "type": "A", "content": "192.0.2.8"}},
        ])
        ledger, system, confirmation = _Ledger(), _System(True), _Confirmation(True)
        handlers = build_plugin_homelab_effect_handlers(actions={(action.operation, action.target): (action, target)},
            vault=_Vault(), backend=FixedHomelabHTTPSBackend(network), ledger=ledger,
            confirmation=confirmation, system_membership=system)
        payload = _request(action, {"hostname": "ha.togarriapahome.uk", "content": "192.0.2.8", "ttl": 300, "proxied": False}, write=True)
        context, grant = _grants(action, payload)
        response = handlers[(action.operation, action.target)](context=context, authorization=grant,
            payload=payload, timeout=5, peer_pid=123, cancelled=lambda: False)
        result = json.loads(response["body"])
        self.assertEqual(result["state"], "ambiguous")
        self.assertEqual(result["verification_status"], "verification-required")
        self.assertEqual([call[1] for call in network.calls], ["GET", "PUT"])
        self.assertEqual(network.calls[1][0], network.calls[0][0])
        self.assertEqual(system.calls, 1)
        self.assertEqual(confirmation.calls, 1)
        self.assertEqual(list(ledger.rows.values())[0]["state"], "ambiguous")

    def test_unowned_record_conflict_is_preserved_without_put(self):
        schema = {"type": "object", "properties": {"hostname": {"type": "string"},
            "content": {"type": "string"}, "ttl": {"type": "integer"}, "proxied": {"type": "boolean"}},
            "required": ["hostname", "content", "ttl", "proxied"], "additionalProperties": False}
        action, target = _pair("update-approved-dns-record", write=True, schema=schema)
        current = {"success": True, "result": {"id": "record_1", "name": "other.togarriapahome.uk", "type": "A"}}
        network = _Network([current]); system = _System(True); confirm = _Confirmation(True)
        handlers = build_plugin_homelab_effect_handlers(actions={(action.operation, action.target): (action, target)},
            vault=_Vault(), backend=FixedHomelabHTTPSBackend(network), ledger=_Ledger(),
            confirmation=confirm, system_membership=system)
        payload = _request(action, {"hostname": "ha.togarriapahome.uk", "content": "192.0.2.8", "ttl": 300, "proxied": False}, write=True)
        context, grant = _grants(action, payload)
        with self.assertRaisesRegex(HomelabEffectDenied, "no longer matches"):
            handlers[(action.operation, action.target)](context=context, authorization=grant,
                payload=payload, timeout=5, peer_pid=123, cancelled=lambda: False)
        self.assertEqual(len(network.calls), 1)
        self.assertEqual(network.calls[0][1], "GET")

    def test_payload_scope_and_peer_mismatch_do_not_dispatch(self):
        action, target = _pair()
        network = _Network([])
        handlers = build_plugin_homelab_effect_handlers(actions={(action.operation, action.target): (action, target)},
            vault=_Vault(), backend=FixedHomelabHTTPSBackend(network), ledger=_Ledger())
        payload = _request(action, {"hostname": "ha.togarriapahome.uk", "url": "https://evil.test"})
        context, grant = _grants(action, payload)
        with self.assertRaises(HomelabEffectDenied):
            handlers[(action.operation, action.target)](context=context, authorization=grant,
                payload=payload, timeout=5, peer_pid=123, cancelled=lambda: False)
        self.assertEqual(network.calls, [])

    def test_authentik_snapshot_uses_fresh_root_reader_without_system_read_gate(self):
        class Policy:
            def __init__(self): self.calls = []
            def principal_snapshot(self, context, *, require_system_membership=False):
                self.calls.append(require_system_membership)
                if require_system_membership: raise HomelabEffectDenied("system.denied", "not System")
                return SimpleNamespace(principal_id="alice", subject_id="user-1", username="alice",
                    email="alice@example.test", direct_group_ids={"g1"}, effective_group_ids={"g1", "g2"},
                    system_member=False, policy_revision="rev-1", checked_at_monotonic=5.0)
            def authorize_delivery_recipient(self, recipient_id): return "recipient@example.test"

        action = HomelabActionEnrollment(adapter_id="authentik-authorization",
            manifest_sha256="88075741bee9d27e1b7c8536cda4e641c335c952cde7e1083c8d3131be25ce2e",
            handler_artifact_id="authentik-reader", handler_sha256="b" * 64,
            action_id="read-user-effective-groups", argument_schema_id="schema-groups",
            operation="plugin.authentik-authorization.read", capability="plugin:authentik-authorization",
            target_id="authz", generation="gen-1", principal_id="alice", profile_id="hermes",
            recipient="alice", enrollment_id="auth-enroll",
            argument_schema={"type": "object", "properties": {}, "additionalProperties": False}, mutating=False)
        target = HomelabTargetEnrollment(adapter_id="authentik-authorization", enrollment_id="auth-enroll",
            principal_id="alice", profile_id="hermes", recipient="alice", action_ids=frozenset({action.action_id}))
        policy = Policy()
        handlers = build_plugin_homelab_effect_handlers(actions={(action.operation, action.target): (action, target)},
            vault=_Vault(), backend=FixedHomelabHTTPSBackend(_Network([])), ledger=_Ledger(), authentik_policy=policy)
        payload = _request(action, {})
        context, grant = _grants(action, payload)
        response = handlers[(action.operation, action.target)](context=context, authorization=grant,
            payload=payload, timeout=5, peer_pid=123, cancelled=lambda: False)
        result = json.loads(response["body"])
        self.assertEqual(result["result"]["effective_group_ids"], ["g1", "g2"])
        self.assertEqual(policy.calls, [False])

    def test_operations_broker_uses_only_root_host_id_and_manifest_operation(self):
        manifest = "bb4de61e7136f57e6fed77b3d907f2f669b2c7f070eb124ed9b0a783109d35d2"
        action = HomelabActionEnrollment(
            adapter_id="homelab-ops-broker", manifest_sha256=manifest,
            handler_artifact_id="homelab-broker-v1", handler_sha256="c" * 64,
            action_id="restart-approved-service", argument_schema_id="schema-host-op",
            operation="plugin.homelab-ops-broker.write", capability="plugin:homelab-ops-broker",
            target_id="physical-hosts", generation="gen-7", principal_id="alice", profile_id="hermes",
            recipient="alice", enrollment_id="enroll-ops", mutating=True,
            idempotency_policy_id="idem-ops", argument_schema={"type": "object", "properties": {
                "host": {"type": "string", "enum": ["hermes", "nextcloud"]},
                "action": {"type": "string", "enum": ["restart-approved-service"]}},
                "required": ["host", "action"], "additionalProperties": False})
        target = HomelabTargetEnrollment(
            adapter_id="homelab-ops-broker", enrollment_id="enroll-ops", principal_id="alice",
            profile_id="hermes", recipient="alice", broker_origin="https://ops.internal:9443",
            host_target_ids={"hermes": "host-17", "nextcloud": "host-22"},
            credential_reference_id="ops_token", credential_scope="homelab-ops-restart",
            action_ids=frozenset({"restart-approved-service"}))
        network = _Network([{"success": True, "result": {"operation": "restart-approved-service", "accepted": True}}])
        system = _System(True); ledger = _Ledger()
        handlers = build_plugin_homelab_effect_handlers(actions={(action.operation, action.target): (action, target)},
            vault=_Vault(), backend=FixedHomelabHTTPSBackend(network), ledger=ledger,
            system_membership=system)
        payload = _request(action, {"host": "hermes", "action": "restart-approved-service"}, write=True, confirmation=False)
        context, grant = _grants(action, payload)
        response = handlers[(action.operation, action.target)](context=context, authorization=grant,
            payload=payload, timeout=5, peer_pid=123, cancelled=lambda: False)
        self.assertEqual(json.loads(response["body"])["state"], "ambiguous")
        self.assertEqual(network.calls[0][0], "https://ops.internal:9443/v1/targets/host-17/operations/restart-approved-service")
        self.assertEqual(network.calls[0][1], "POST")
        self.assertNotIn(b"ssh", network.calls[0][3])
        self.assertEqual(system.calls, 1)

    def test_ops_backend_rejects_unlisted_shell_action_without_effect(self):
        manifest = "bb4de61e7136f57e6fed77b3d907f2f669b2c7f070eb124ed9b0a783109d35d2"
        action = HomelabActionEnrollment(
            adapter_id="homelab-ops-broker", manifest_sha256=manifest,
            handler_artifact_id="homelab-broker-v1", handler_sha256="d" * 64,
            action_id="restart-approved-service", argument_schema_id="schema-host-op",
            operation="plugin.homelab-ops-broker.write", capability="plugin:homelab-ops-broker",
            target_id="physical-hosts", generation="gen-7", principal_id="alice", profile_id="hermes",
            recipient="alice", enrollment_id="enroll-ops", mutating=True,
            idempotency_policy_id="idem-ops", argument_schema={"type": "object", "properties": {
                "host": {"type": "string", "enum": ["hermes"]}, "action": {"type": "string"}},
                "required": ["host", "action"], "additionalProperties": False})
        target = HomelabTargetEnrollment(adapter_id="homelab-ops-broker", enrollment_id="enroll-ops",
            principal_id="alice", profile_id="hermes", recipient="alice", broker_origin="https://ops.internal",
            host_target_ids={"hermes": "host-17", "nextcloud": "host-22"},
            credential_reference_id="ops_token", credential_scope="homelab-ops-restart",
            action_ids=frozenset({"restart-approved-service"}))
        network = _Network([])
        handlers = build_plugin_homelab_effect_handlers(actions={(action.operation, action.target): (action, target)},
            vault=_Vault(), backend=FixedHomelabHTTPSBackend(network), ledger=_Ledger(),
            system_membership=_System(True))
        payload = _request(action, {"host": "hermes", "action": "arbitrary-shell"}, write=True, confirmation=False)
        context, grant = _grants(action, payload)
        with self.assertRaisesRegex(HomelabEffectDenied, "allowlist"):
            handlers[(action.operation, action.target)](context=context, authorization=grant,
                payload=payload, timeout=5, peer_pid=123, cancelled=lambda: False)
        self.assertEqual(network.calls, [])


if __name__ == "__main__":
    unittest.main()
