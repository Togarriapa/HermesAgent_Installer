from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from types import SimpleNamespace

import pytest

from hermes_installer.components.plugin_effects import (
    build_plugin_effects_facade,
    PluginEffectDispatcher,
    PluginActionSchema,
    PluginEffectUnavailable,
    StaticPluginActionSchemas,
)


@dataclass(frozen=True)
class Selected:
    adapter_id: str = "web"
    manifest_sha256: str = "a" * 64
    adapter_sha256: str = "b" * 64
    action_id: str = "retrieve-public-web-content"
    argument_schema_id: str = "web-retrieve-v1"
    result_schema_id: str = "web-result-v1"
    effect_enrollment_id: str = "enrollment1"
    operation: str = "plugin.web.read"
    capability: str = "plugin:web"
    target_id: str = "web-target"
    generation: str = "g1"
    recipient: str = "public-web"


class Resolver:
    def __init__(self, selected=None):
        self.selected = selected or Selected()
        self.calls = []

    def resolve(self, adapter_id, action_id):
        self.calls.append((adapter_id, action_id))
        if self.selected is None:
            return None
        if (adapter_id, action_id) != (self.selected.adapter_id, self.selected.action_id):
            return None
        return self.selected


class Authority:
    def __init__(self):
        self.calls = []

    def context(self, **kwargs):
        self.calls.append(("context", kwargs))
        return SimpleNamespace(principal_id="principal1", profile_id="profile1",
                               operation=kwargs["operation"],
                               final_payload_digest=kwargs["final_payload_digest"])

    def authorize_effect(self, context, **kwargs):
        self.calls.append(("authorize", kwargs))
        return SimpleNamespace(**kwargs)

    def verify_effect(self, authorization, context, **kwargs):
        self.calls.append(("verify", kwargs))
        return object()

    def perform_effect(self, authorization, *, operation, payload, timeout):
        self.calls.append(("perform", operation, payload, timeout))
        body = {"schema": 1, "operation_id": "op-1", "state": "read-complete",
                "result": {"authority": "none"}, "verification_status": "verified",
                "resume_action_id": None}
        return SimpleNamespace(status=200, body=json.dumps(body).encode())


def dispatcher(*, selected=None, authority=None, invocation_contexts=None, identity=None):
    resolver = Resolver(selected)
    authority = authority or Authority()
    invocation_contexts = invocation_contexts or (lambda **_: (object(),))
    identity = identity or SimpleNamespace(kind="plugins", resource_id="web",
                                           content_digest="a" * 64)
    schema = PluginActionSchema(
        adapter_id="web", action_id="retrieve-public-web-content",
        argument_schema_id="web-retrieve-v1", result_schema_id="web-result-v1",
        operation="plugin.web.read", adapter_sha256="b" * 64,
        argument_schema={"type": "object", "properties": {
            "url": {"type": "string", "minLength": 1, "maxLength": 1024,
                    "pattern": "^https://"},
        }, "required": ["url"], "additionalProperties": False},
        result_schema={"type": "object", "properties": {
            "authority": {"type": "string", "enum": ["none"]},
        }, "required": ["authority"], "additionalProperties": False},
        request_bytes_limit=8192, response_bytes_limit=4096, deadline_seconds=8.0,
    )
    return PluginEffectDispatcher(authority=authority, invocation_contexts=invocation_contexts,
                                  selected_effects=resolver,
                                  action_schemas=StaticPluginActionSchemas({("web", schema.action_id): schema}),
                                  identity=identity), resolver, authority


def test_dispatch_binds_canonical_envelope_to_one_use_authority_grant():
    client, resolver, authority = dispatcher()

    result = client.invoke("web", "retrieve-public-web-content", {"url": "https://example.com/docs"})

    assert result["state"] == "read-complete"
    assert result["result"] == {"authority": "none"}
    assert [call[0] for call in authority.calls] == ["context", "authorize", "verify", "perform"]
    context_args = authority.calls[0][1]
    payload = authority.calls[3][2]
    envelope = json.loads(payload)
    assert envelope == {
        "schema": 1, "adapter_id": "web", "action_id": "retrieve-public-web-content",
        "enrollment_id": "enrollment1", "generation": "g1",
        "arguments": {"url": "https://example.com/docs"},
    }
    digest = hashlib.sha256(payload).hexdigest()
    assert context_args["operation"] == "plugin.web.read"
    assert context_args["final_payload_digest"] == digest
    assert authority.calls[1][1] == {
        "capability": "plugin:web", "target": "plugin:web:web-target:g1",
        "recipient": "public-web", "request_digest": digest, "retry_index": 0,
    }
    assert resolver.calls == [("web", "retrieve-public-web-content")]


def test_missing_selected_enrollment_fails_before_authority_or_network_effect():
    missing = Resolver(None)
    missing.selected = None
    authority = Authority()
    client = PluginEffectDispatcher(
        authority=authority, invocation_contexts=lambda **_: (object(),),
        selected_effects=missing,
        action_schemas=StaticPluginActionSchemas({}),
        identity=SimpleNamespace(kind="plugins", resource_id="web", content_digest="a" * 64),
    )

    with pytest.raises(PluginEffectUnavailable, match="no selected root enrollment"):
        client.invoke("web", "retrieve-public-web-content", {"url": "https://example.com"})

    assert authority.calls == []


@pytest.mark.parametrize("arguments", [
    {"url": "https://example.com", "method": "DELETE"},
    {"url": "http://example.com"},
    {"url": 1},
])
def test_unreviewed_or_malformed_arguments_are_rejected_before_authority(arguments):
    client, _, authority = dispatcher()

    with pytest.raises(PluginEffectUnavailable):
        client.invoke("web", "retrieve-public-web-content", arguments)

    assert authority.calls == []


def test_identity_manifest_operation_or_target_tampering_fails_closed():
    wrong_identity = SimpleNamespace(kind="plugins", resource_id="web", content_digest="c" * 64)
    client, _, authority = dispatcher(identity=wrong_identity)
    with pytest.raises(PluginEffectUnavailable, match="selected Plugin action"):
        client.invoke("web", "retrieve-public-web-content", {"url": "https://example.com"})
    assert authority.calls == []

    bad = Selected(operation="host.write")
    client, _, authority = dispatcher(selected=bad)
    with pytest.raises(PluginEffectUnavailable, match="selected Plugin action"):
        client.invoke("web", "retrieve-public-web-content", {"url": "https://example.com"})
    assert authority.calls == []


def test_empty_provenance_and_authority_context_mismatch_never_perform():
    authority = Authority()
    client, _, _ = dispatcher(authority=authority, invocation_contexts=lambda **_: ())
    with pytest.raises(PluginEffectUnavailable, match="lineage"):
        client.invoke("web", "retrieve-public-web-content", {"url": "https://example.com"})
    assert authority.calls == []

    class MismatchAuthority(Authority):
        def context(self, **kwargs):
            self.calls.append(("context", kwargs))
            return SimpleNamespace(principal_id="other", profile_id="profile1",
                                   operation="plugin.other.read",
                                   final_payload_digest=kwargs["final_payload_digest"])

    mismatch = MismatchAuthority()
    client, _, _ = dispatcher(authority=mismatch)
    with pytest.raises(PluginEffectUnavailable, match="does not match"):
        client.invoke("web", "retrieve-public-web-content", {"url": "https://example.com"})
    assert [call[0] for call in mismatch.calls] == ["context"]


@pytest.mark.parametrize("envelope", [
    {"schema": 1, "operation_id": "op-1", "state": "committed",
     "result": {"authority": "none"}, "verification_status": "not-verified", "resume_action_id": None},
    {"schema": 1, "operation_id": "op-1", "state": "read-complete",
     "result": {"authority": "granted"}, "verification_status": "not-applicable", "resume_action_id": None},
    {"schema": 1, "operation_id": "op-1", "state": "read-complete",
     "result": {"authority": "none"}, "verification_status": "not-applicable",
     "resume_action_id": "bad id"},
])
def test_invalid_envelope_state_receipt_or_nested_result_fails_closed(envelope):
    class MaliciousAuthority(Authority):
        def perform_effect(self, authorization, *, operation, payload, timeout):
            self.calls.append(("perform", operation, payload, timeout))
            return SimpleNamespace(status=200, body=json.dumps(envelope).encode())

    authority = MaliciousAuthority()
    client, _, _ = dispatcher(authority=authority)
    with pytest.raises(PluginEffectUnavailable):
        client.invoke("web", "retrieve-public-web-content", {"url": "https://example.com"})


def test_confirmation_and_idempotency_are_policy_bound_and_not_optional():
    selected = Selected(operation="plugin.web.read")
    client, _, authority = dispatcher(selected=selected)
    client.action_schemas = StaticPluginActionSchemas({("web", selected.action_id): PluginActionSchema(
        adapter_id="web", action_id=selected.action_id,
        argument_schema_id=selected.argument_schema_id, result_schema_id=selected.result_schema_id,
        operation=selected.operation, adapter_sha256=selected.adapter_sha256,
        argument_schema={"type": "object", "properties": {"url": {"type": "string"}},
                        "required": ["url"], "additionalProperties": False},
        result_schema={"type": "object"}, requires_idempotency=True, requires_confirmation=True,
    )})
    with pytest.raises(PluginEffectUnavailable, match="idempotency key"):
        client.invoke("web", "retrieve-public-web-content", {"url": "https://example.com"})
    assert authority.calls == []

    result = client.invoke("web", "retrieve-public-web-content", {"url": "https://example.com"},
                           idempotency_key="task-1", opaque_confirmation_attestation_id="attest-1")
    assert result["state"] == "read-complete"
    envelope = json.loads(authority.calls[-1][2])
    assert envelope["idempotency_key"] == "task-1"
    assert envelope["opaque_confirmation_attestation_id"] == "attest-1"


def test_trusted_factory_fails_closed_when_root_selected_package_binding_is_absent():
    authority = Authority()
    with pytest.raises(PluginEffectUnavailable, match="native-package binding"):
        build_plugin_effects_facade(
            authority=authority, invocation_contexts=lambda **_: (),
            identity=SimpleNamespace(kind="plugins", resource_id="web"),
            action_schemas=StaticPluginActionSchemas({}),
        )
    assert authority.calls == []


def test_component_catalog_is_complete_pinned_and_keeps_actions_finite():
    from hermes_installer.components.plugin_effects import (
        _EXPECTED_ACTION_KEYS,
        component_plugin_action_schema_registry,
    )

    catalog = component_plugin_action_schema_registry()
    assert len(_EXPECTED_ACTION_KEYS) == 61
    assert set(catalog._schemas) == _EXPECTED_ACTION_KEYS
    for adapter_id, action_id in _EXPECTED_ACTION_KEYS:
        row = catalog.resolve(adapter_id, action_id)
        assert row.adapter_id == adapter_id
        assert row.action_id == action_id
        assert row.argument_schema_id == f"{adapter_id}.{action_id}.arguments.v1"
        assert row.result_schema_id == f"{adapter_id}.{action_id}.result.v1"
    assert catalog.resolve("github", "arbitrary-http") is None
