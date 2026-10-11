from __future__ import annotations

import hashlib
import json
import time

import pytest

from hermes_installer.components.resources_internal_dispatch import (
    PROFILE_ID,
    ResourcesDispatchDenied,
    RootSelectedInternalProfileDispatchClaim,
    register_resources_delegate,
)


class Parent:
    session_id = "owner-turn-17"
    valid_tool_names = frozenset({"delegate_task", "read_file"})


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
        profile_tool_names=parent.valid_tool_names,
        inherited_child_tool_names=parent.valid_tool_names,
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


class NativeContext:
    def __init__(self, native_result='{"accepted":true,"task_id":"native-1"}'):
        self.native_result = native_result
        self.registration = None
        self.dispatches = []

    def register_tool(self, *, name, toolset, schema, handler, **kwargs):
        self.registration = (name, toolset, schema, handler, kwargs)
        return object()

    def dispatch_tool(self, tool_name, args, **kwargs):
        self.dispatches.append((tool_name, args, kwargs))
        return self.native_result


def test_registered_tool_dispatches_through_native_delegate_with_exact_parent():
    parent = Parent()
    issuer = OneShotIssuer(current_claim(parent))
    context = NativeContext()
    register_resources_delegate(context, issuer)

    name, toolset, schema, handler, options = context.registration
    assert (name, toolset, options["override"]) == ("resources_delegate", "resources_internal", False)
    assert schema["parameters"]["additionalProperties"] is False
    assert set(schema["parameters"]["properties"]) == {"goal"}
    result = json.loads(handler({"goal": "Use the selected profile."}, parent_agent=parent, tool_call_id="call-17", turn_id="turn-17"))

    assert result["state"] == "native-dispatch-accepted"
    assert result["profile_id"] == PROFILE_ID
    assert result["isolation_claim"] is False
    # The effect preserves the exact trusted parent object; there is no
    # caller-controlled profile, provider, toolset, route, or prompt field.
    assert [call[0] for call in issuer.calls] == [PROFILE_ID]
    assert issuer.calls[0][1] is parent
    assert issuer.calls[0][2] == {
        "tool_call_id": "call-17", "tool_name": "resources_delegate",
        "arguments": {"goal": "Use the selected profile."}, "turn_id": "turn-17",
    }
    tool_name, args, kwargs = context.dispatches[0]
    assert tool_name == "delegate_task"
    assert set(args) == {"goal", "context"}
    assert "provider" not in args and "toolsets" not in args
    assert kwargs == {"parent_agent": parent}
    assert "source-selected internal profile identity" in args["context"]
    assert "Use the selected profile." in args["context"]


@pytest.mark.parametrize("claim_change", [
    {"expires_monotonic": 1.0},
    {"profile_id": "general"},
    {"max_additional_metered_microusd": 1},
    {"route_class": "new-metered-route"},
    {"profile_tool_names": frozenset({"delegate_task", "read_file", "shell"})},
    {"profile_privacy_requirements": frozenset({"owner-private", "other-private"})},
    {"effective_prompt_sha256": "0" * 64},
])
def test_claim_mismatch_denies_before_native_delegation(claim_change):
    parent = Parent()
    context = NativeContext()
    register_resources_delegate(context, OneShotIssuer(current_claim(parent, **claim_change)))
    response = json.loads(context.registration[3]({"goal": "bounded task"}, parent_agent=parent, tool_call_id="call-19", turn_id="turn-19"))

    assert response["success"] is False
    assert response["state"] == "pending"
    assert context.dispatches == []


def test_missing_parent_and_caller_authority_fields_are_denied_without_dispatch():
    parent = Parent()
    context = NativeContext()
    register_resources_delegate(context, OneShotIssuer(current_claim(parent)))
    handler = context.registration[3]

    no_parent = json.loads(handler({"goal": "bounded task"}))
    caller_selector = json.loads(handler({"goal": "bounded task", "profile_id": "orchestrator"},
                                         parent_agent=parent, tool_call_id="call-18", turn_id="turn-18"))
    assert no_parent["success"] is False
    assert caller_selector["success"] is False
    assert context.dispatches == []


def test_native_delegate_failure_stays_pending_and_is_not_reported_as_completion():
    parent = Parent()
    context = NativeContext('{"error":"native pause gate"}')
    register_resources_delegate(context, OneShotIssuer(current_claim(parent)))

    response = json.loads(context.registration[3]({"goal": "bounded task"}, parent_agent=parent, tool_call_id="call-19", turn_id="turn-19"))

    assert response["success"] is False
    assert response["state"] == "native-delegation-denied"
    assert len(context.dispatches) == 1


def test_registration_denies_absent_root_claim_issuer():
    context = NativeContext()
    with pytest.raises(ResourcesDispatchDenied, match="claim source is unavailable"):
        register_resources_delegate(context, None)
    assert context.registration is None


def test_missing_provider_call_or_turn_identity_denies_without_claim_consumption():
    parent = Parent()
    issuer = OneShotIssuer(current_claim(parent))
    context = NativeContext()
    register_resources_delegate(context, issuer)
    handler = context.registration[3]

    response = json.loads(handler({"goal": "bounded task"}, parent_agent=parent))

    assert response["success"] is False
    assert response["state"] == "pending"
    assert issuer.calls == []
    assert context.dispatches == []
