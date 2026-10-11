from __future__ import annotations

import hashlib
import json
import sys
import time
import types
from types import SimpleNamespace

import pytest

from hermes_installer.components.resources_internal_dispatch import (
    PROFILE_ID,
    ResourcesDispatchDenied,
    RootSelectedInternalProfileDispatchClaim,
    register_resources_delegate,
)


class Parent:
    session_id = "owner-turn-17"
    valid_tool_names = frozenset({"resources_delegate", "delegate_task", "read_file"})


def digest(value: bytes | str) -> str:
    if isinstance(value, str):
        value = value.encode()
    return hashlib.sha256(value).hexdigest()


def current_claim(parent, **overrides):
    prompt = b"You are the source-selected internal orchestration profile."
    values = dict(
        claim_id="claim_0123456789abcdef",
        profile_id=PROFILE_ID,
        source_revision="resources-source-rev-17",
        generation_sha256=digest("generation"),
        profile_manifest_sha256=digest("profile-manifest"),
        effective_prompt=prompt,
        effective_prompt_sha256=digest(prompt),
        parent_agent=parent,
        parent_session_id=parent.session_id,
        owner_subject_sha256=digest("owner-subject"),
        parent_tool_names=parent.valid_tool_names,
        configured_parent_tool_names=parent.valid_tool_names,
        profile_tool_names=frozenset(),
        inherited_child_tool_names=parent.valid_tool_names,
        delegation_policy_handle="policy_0123456789abcdef",
        delegation_policy_sha256=digest("policy"),
        parent_tool_configuration_sha256=digest("tool-config"),
        allow_inherited_mcp=False,
        allow_native_orchestrator_delegation=True,
        parent_privacy_grants=frozenset({"owner-private"}),
        profile_privacy_requirements=frozenset({"owner-private"}),
        route_class="existing-owner-codex-zero-additional-metered",
        route_receipt_sha256=digest("bound-route-receipt"),
        max_additional_metered_microusd=0,
        expires_monotonic=time.monotonic() + 10,
    )
    values.update(overrides)
    return RootSelectedInternalProfileDispatchClaim(**values)


class OneShotIssuer:
    def __init__(self, claim):
        self.claim = claim
        self.calls = []

    def consume_current_claim(self, profile_id, parent_agent, **bound_call):
        self.calls.append((profile_id, parent_agent, bound_call))
        return self.claim


class FakeRegistry:
    def __init__(self):
        self.entries = {}

    def snapshot_registration(self, name, *, scope=None):
        return self.entries.get((scope, name))


@pytest.fixture
def native_registry(monkeypatch):
    registry = FakeRegistry()
    tools_package = types.ModuleType("tools")
    tools_package.__path__ = []
    registry_module = types.ModuleType("tools.registry")
    registry_module.registry = registry
    monkeypatch.setitem(sys.modules, "tools", tools_package)
    monkeypatch.setitem(sys.modules, "tools.registry", registry_module)
    return registry


class NativeContext:
    def __init__(self, registry, native_result='{"accepted":true,"task_id":"native-1"}'):
        self.registry = registry
        self._manager = SimpleNamespace(scope_key="owner-profile")
        self.native_result = native_result
        self.registration = None
        self.dispatches = []

    def register_tool(self, *, name, toolset, schema, handler, **kwargs):
        self.registration = (name, toolset, schema, handler, kwargs)
        self.registry.entries[(self._manager.scope_key, name)] = SimpleNamespace(
            name=name, toolset=toolset, schema=schema, handler=handler)
        return object()

    def dispatch_tool(self, tool_name, args, **kwargs):
        self.dispatches.append((tool_name, args, kwargs))
        return self.native_result


def test_registered_tool_dispatches_through_native_delegate_with_exact_parent(native_registry):
    parent = Parent()
    issuer = OneShotIssuer(current_claim(parent))
    context = NativeContext(native_registry)
    receipt = register_resources_delegate(context, issuer)

    name, toolset, schema, handler, options = context.registration
    assert (name, toolset, options["override"]) == ("resources_delegate", "resources_internal", False)
    assert schema["parameters"]["additionalProperties"] is False
    assert set(schema["parameters"]["properties"]) == {"goal"}
    approved_goal = "  Use the selected profile.  "
    result = json.loads(handler({"goal": approved_goal}, parent_agent=parent, tool_call_id="call-17", turn_id="turn-17"))

    assert result["state"] == "native-dispatch-accepted"
    assert result["profile_id"] == PROFILE_ID
    assert result["isolation_claim"] is False
    # The effect preserves the exact trusted parent object; there is no
    # caller-controlled profile, provider, toolset, route, or prompt field.
    assert [call[0] for call in issuer.calls] == [PROFILE_ID]
    assert issuer.calls[0][1] is parent
    assert issuer.calls[0][2] == {
        "tool_call_id": "call-17", "tool_name": "resources_delegate",
        "arguments": {"goal": approved_goal}, "turn_id": "turn-17",
    }
    assert receipt.verify_current(context)
    tool_name, args, kwargs = context.dispatches[0]
    assert tool_name == "delegate_task"
    assert set(args) == {"tasks"}
    assert len(args["tasks"]) == 1
    assert args["tasks"][0]["goal"] == approved_goal
    assert "  Use the selected profile.  " in args["tasks"][0]["context"]
    assert "provider" not in args and "toolsets" not in args
    assert kwargs == {"parent_agent": parent}
    assert "source-selected internal profile identity" in args["tasks"][0]["context"]


@pytest.mark.parametrize("claim_change", [
    {"expires_monotonic": 1.0},
    {"profile_id": "general"},
    {"max_additional_metered_microusd": 1},
    {"route_class": "new-metered-route"},
    {"profile_tool_names": frozenset({"delegate_task", "read_file", "shell"})},
    {"profile_privacy_requirements": frozenset({"owner-private", "other-private"})},
    {"effective_prompt_sha256": "0" * 64},
])
def test_claim_mismatch_denies_before_native_delegation(claim_change, native_registry):
    parent = Parent()
    context = NativeContext(native_registry)
    register_resources_delegate(context, OneShotIssuer(current_claim(parent, **claim_change)))
    response = json.loads(context.registration[3]({"goal": "bounded task"}, parent_agent=parent, tool_call_id="call-19", turn_id="turn-19"))

    assert response["success"] is False
    assert response["state"] == "pending"
    assert context.dispatches == []


def test_missing_parent_and_caller_authority_fields_are_denied_without_dispatch(native_registry):
    parent = Parent()
    context = NativeContext(native_registry)
    register_resources_delegate(context, OneShotIssuer(current_claim(parent)))
    handler = context.registration[3]

    no_parent = json.loads(handler({"goal": "bounded task"}))
    caller_selector = json.loads(handler({"goal": "bounded task", "profile_id": "orchestrator"},
                                         parent_agent=parent, tool_call_id="call-18", turn_id="turn-18"))
    assert no_parent["success"] is False
    assert caller_selector["success"] is False
    assert context.dispatches == []


def test_native_delegate_failure_stays_pending_and_is_not_reported_as_completion(native_registry):
    parent = Parent()
    context = NativeContext(native_registry, '{"error":"native pause gate"}')
    register_resources_delegate(context, OneShotIssuer(current_claim(parent)))

    response = json.loads(context.registration[3]({"goal": "bounded task"}, parent_agent=parent, tool_call_id="call-19", turn_id="turn-19"))

    assert response["success"] is False
    assert response["state"] == "native-delegation-denied"
    assert len(context.dispatches) == 1


def test_registration_denies_absent_root_claim_issuer(native_registry):
    context = NativeContext(native_registry)
    with pytest.raises(ResourcesDispatchDenied, match="claim source is unavailable"):
        register_resources_delegate(context, None)
    assert context.registration is None


def test_missing_provider_call_or_turn_identity_denies_without_claim_consumption(native_registry):
    parent = Parent()
    issuer = OneShotIssuer(current_claim(parent))
    context = NativeContext(native_registry)
    register_resources_delegate(context, issuer)
    handler = context.registration[3]

    response = json.loads(handler({"goal": "bounded task"}, parent_agent=parent))

    assert response["success"] is False
    assert response["state"] == "pending"
    assert issuer.calls == []
    assert context.dispatches == []


def test_replaced_live_registration_denies_before_claim_or_native_effect(native_registry):
    parent = Parent()
    issuer = OneShotIssuer(current_claim(parent))
    context = NativeContext(native_registry)
    register_resources_delegate(context, issuer)
    native_registry.entries[(context._manager.scope_key, "resources_delegate")] = SimpleNamespace(
        name="resources_delegate", toolset="unrelated", schema={}, handler=lambda *_: "")

    response = json.loads(context.registration[3]({"goal": "bounded task"}, parent_agent=parent,
                                                  tool_call_id="call-1", turn_id="turn-1"))

    assert response["success"] is False
    assert issuer.calls == []
    assert context.dispatches == []
