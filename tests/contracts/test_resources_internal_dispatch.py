from __future__ import annotations

import hashlib
import json
import sys
import time
import types
from dataclasses import replace
from types import SimpleNamespace
from enum import Enum

import pytest

from hermes_installer.components.resources_internal_dispatch import (
    PROFILE_ID,
    ResourcesDispatchDenied,
    RootSelectedInternalProfileDispatchClaim,
    register_resources_delegate,
)
from hermes_installer.remote.jarvis_mission_executor import MissionBinding


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
        gateway_turn_id="gateway-turn-00000000000000000001",
        core_generation=digest("core-generation"),
        core_source_generation=digest("core-source-generation"),
        mission_binding=MissionBinding(
            schema=2, mission_id="mission_0123456789abcdef01234567", revision=2,
            plan_sha256=digest("plan"), task_sha256=digest('{"goal":"bounded task"}'),
            source_profile_id="orchestrator", execution_mode="oneshot",
            autonomy_mode="approval_required", selected_source_ids=("researcher",),
            scope_sha256=digest("scope"), authorization_sha256=None,
        ),
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

    def authorize_mission_claim(self, claim, *, task_sha256):
        self.authorization_calls = getattr(self, "authorization_calls", []) + [(claim, task_sha256)]
        raise AssertionError("untrusted test issuer must not authorize a mission")


class FakeDelivery:
    def __init__(self, source_id):
        self.profile_id = source_id
        self.source_revision = "catalog-rev-7"
        self.generation_sha256 = digest("generation-" + source_id)
        self.effective_prompt = ("Verified prompt for " + source_id).encode()
        self.effective_prompt_sha256 = digest(self.effective_prompt)


class FakeAuthorization:
    pass


class FakeRootClaimSource(OneShotIssuer):
    def __init__(self, claim):
        super().__init__(claim)
        self.source_reads = []
        self.admissions = []

    def read_selected_expert_source(self, *, resources_claim, source_id):
        assert resources_claim is self.claim
        if source_id.startswith("team-"):
            raise PermissionError("team expansion is not part of the retained profile catalog")
        self.source_reads.append(source_id)
        return FakeDelivery(source_id)

    def admit_selected_expert_child(self, *, resources_claim, child, source, goal):
        assert resources_claim is self.claim
        assert child.valid_tool_names <= {"web_search", "web_extract", "todo_list", "skills_list", "skill_view"}
        assert "delegate_task" not in child.valid_tool_names
        self.admissions.append((source.profile_id, goal, child))
        return FakeAuthorization()


def install_native_child_fakes(monkeypatch):
    observer = types.ModuleType("hermes_installer.remote.core_native_observer")
    observer.RootInternalProfileClaimSource = FakeRootClaimSource
    observer.RootNativeSelectedSourceDelivery = FakeDelivery
    observer.RootVerifiedNativeChildAuthorization = FakeAuthorization
    adapter = types.ModuleType("hermes_installer.remote.native_child_adapter")

    class Mode(Enum):
        EXPERT_READ_RESEARCH = "expert-read-research"

    adapter.NativeChildMode = Mode
    children = []
    calls = []

    def build_native_child(**kwargs):
        child = SimpleNamespace(
            valid_tool_names={"web_search", "web_extract", "todo_list", "skills_list", "skill_view"},
            source=kwargs["source"], parent=kwargs["parent_agent"], mode=kwargs["mode"],
        )
        children.append((kwargs, child))
        return child

    def run_native_child(**kwargs):
        calls.append(kwargs)
        if kwargs["source"].profile_id == "failed-expert":
            raise RuntimeError("native child failed")
        return {"draft": "review this", "source_id": kwargs["source"].profile_id}

    adapter.build_native_child = build_native_child
    adapter.run_native_child = run_native_child
    monkeypatch.setitem(sys.modules, "hermes_installer.remote.core_native_observer", observer)
    monkeypatch.setitem(sys.modules, "hermes_installer.remote.native_child_adapter", adapter)
    return children, calls, Mode


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


def test_registered_tool_runs_only_root_selected_expert_through_native_child_lifecycle(native_registry, monkeypatch):
    parent = Parent()
    claim = current_claim(parent)
    issuer = FakeRootClaimSource(claim)
    children, calls, Mode = install_native_child_fakes(monkeypatch)
    context = NativeContext(native_registry)
    receipt = register_resources_delegate(context, issuer)

    name, toolset, schema, handler, options = context.registration
    assert (name, toolset, options["override"]) == ("resources_delegate", "resources_internal", False)
    assert schema["parameters"]["additionalProperties"] is False
    assert set(schema["parameters"]["properties"]) == {"goal"}
    approved_goal = "bounded task"
    result = json.loads(handler({"goal": approved_goal}, parent_agent=parent, tool_call_id="call-17", turn_id="turn-17"))

    assert result["state"] == "expert-drafts-ready"
    assert result["execution_mode"] == "oneshot"
    assert result["jarvis_review_required"] is True
    assert result["final_effect_authority"] is False
    assert [call[0] for call in issuer.calls] == [PROFILE_ID]
    assert issuer.calls[0][1] is parent
    assert issuer.calls[0][2] == {
        "tool_call_id": "call-17", "tool_name": "resources_delegate",
        "arguments": {"goal": approved_goal}, "turn_id": "turn-17",
    }
    assert issuer.source_reads == ["researcher"]
    assert [row[0] for row in issuer.admissions] == ["researcher"]
    assert len(children) == len(calls) == 1
    assert children[0][0]["mode"] is Mode.EXPERT_READ_RESEARCH
    assert children[0][0]["source"].effective_prompt == b"Verified prompt for researcher"
    assert calls[0]["parent_agent"] is parent
    assert calls[0]["authorization"] is not None
    assert receipt.verify_current(context)
    assert context.dispatches == []


def test_exact_plan_selection_fans_out_in_order_with_separate_reviewable_drafts(native_registry, monkeypatch):
    parent = Parent()
    binding = MissionBinding(
        schema=2, mission_id="mission_0123456789abcdef01234567", revision=3,
        plan_sha256=digest("plan-3"), task_sha256=digest('{"goal":"bounded task"}'),
        source_profile_id="orchestrator", execution_mode="kanban",
        autonomy_mode="approval_required", selected_source_ids=("researcher", "writer"),
        scope_sha256=digest("scope-3"), authorization_sha256=None,
    )
    claim = current_claim(parent, mission_binding=binding)
    issuer = FakeRootClaimSource(claim)
    children, calls, _ = install_native_child_fakes(monkeypatch)
    context = NativeContext(native_registry)
    register_resources_delegate(context, issuer)

    response = json.loads(context.registration[3]({"goal": "bounded task"}, parent_agent=parent,
                                                  tool_call_id="call-team", turn_id="turn-team"))

    assert response["state"] == "expert-drafts-ready"
    assert response["execution_mode"] == "kanban"
    assert [item["source_id"] for item in response["drafts"]] == ["researcher", "writer"]
    assert issuer.source_reads == ["researcher", "writer"]
    assert [item[0] for item in issuer.admissions] == ["researcher", "writer"]
    assert len(children) == len(calls) == 2
    assert context.dispatches == []


def test_team_bundle_stays_pending_without_verified_expansion(native_registry, monkeypatch):
    parent = Parent()
    binding = MissionBinding(
        schema=2, mission_id="mission_0123456789abcdef01234567", revision=4,
        plan_sha256=digest("plan-4"), task_sha256=digest('{"goal":"bounded task"}'),
        source_profile_id="orchestrator", execution_mode="oneshot",
        autonomy_mode="approval_required", selected_source_ids=("team-research",),
        scope_sha256=digest("scope-4"), authorization_sha256=None,
    )
    claim = current_claim(parent, mission_binding=binding)
    issuer = FakeRootClaimSource(claim)
    children, calls, _ = install_native_child_fakes(monkeypatch)
    context = NativeContext(native_registry)
    register_resources_delegate(context, issuer)

    response = json.loads(context.registration[3]({"goal": "bounded task"}, parent_agent=parent,
                                                  tool_call_id="call-team-bundle", turn_id="turn-team-bundle"))

    assert response["success"] is False
    assert response["state"] == "pending"
    assert issuer.source_reads == []
    assert children == []
    assert calls == []
    assert context.dispatches == []


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


def test_legacy_mission_binding_cannot_start_expert_children(native_registry, monkeypatch):
    parent = Parent()
    binding = MissionBinding(
        schema=1, mission_id="mission_0123456789abcdef01234567", revision=2,
        plan_sha256=digest("plan"), task_sha256=digest("approved task"),
        source_profile_id="orchestrator",
    )
    issuer = OneShotIssuer(current_claim(parent, mission_binding=binding))
    context = NativeContext(native_registry)
    register_resources_delegate(context, issuer)

    install_native_child_fakes(monkeypatch)
    response = json.loads(context.registration[3]({"goal": "bounded task"}, parent_agent=parent,
                                                   tool_call_id="call-mission", turn_id="turn-20"))

    assert response["success"] is False
    assert response["state"] == "pending"
    assert getattr(issuer, "source_reads", []) == []
    assert context.dispatches == []


def test_selected_plan_cannot_be_replayed_with_a_different_goal(native_registry, monkeypatch):
    parent = Parent()
    claim = current_claim(parent)
    issuer = FakeRootClaimSource(claim)
    children, calls, _ = install_native_child_fakes(monkeypatch)
    context = NativeContext(native_registry)
    register_resources_delegate(context, issuer)

    response = json.loads(context.registration[3]({"goal": "different task"}, parent_agent=parent,
                                                  tool_call_id="call-goal-mismatch", turn_id="turn-goal-mismatch"))

    assert response["success"] is False
    assert response["state"] == "pending"
    assert issuer.source_reads == []
    assert children == []
    assert calls == []
    assert context.dispatches == []


def test_missing_parent_and_caller_authority_fields_are_denied_without_dispatch(native_registry):
    parent = Parent()
    context = NativeContext(native_registry)
    register_resources_delegate(context, OneShotIssuer(current_claim(parent)))
    handler = context.registration[3]

    no_parent = json.loads(handler({"goal": "bounded task"}))
    caller_selector = json.loads(handler({"goal": "bounded task", "profile_id": "orchestrator"},
                                         parent_agent=parent, tool_call_id="call-18", turn_id="turn-18"))
    caller_source = json.loads(handler({"goal": "bounded task", "source_id": "researcher"},
                                        parent_agent=parent, tool_call_id="call-19", turn_id="turn-19"))
    assert no_parent["success"] is False
    assert caller_selector["success"] is False
    assert caller_source["success"] is False
    assert issuer.calls == []
    assert context.dispatches == []


def test_child_lifecycle_failure_stays_pending_and_is_not_reported_as_completion(native_registry, monkeypatch):
    parent = Parent()
    claim = current_claim(parent)
    claim = replace(
        claim,
        mission_binding=MissionBinding(
            schema=2, mission_id="mission_0123456789abcdef01234567", revision=2,
            plan_sha256=digest("plan"), task_sha256=digest('{"goal":"bounded task"}'),
            source_profile_id="orchestrator", execution_mode="kanban",
            autonomy_mode="approval_required", selected_source_ids=("failed-expert",),
            scope_sha256=digest("scope"), authorization_sha256=None,
        ),
    )
    issuer = FakeRootClaimSource(claim)
    install_native_child_fakes(monkeypatch)
    context = NativeContext(native_registry)
    register_resources_delegate(context, issuer)

    response = json.loads(context.registration[3]({"goal": "bounded task"}, parent_agent=parent, tool_call_id="call-19", turn_id="turn-19"))

    assert response["success"] is False
    assert response["state"] == "pending"
    assert len(issuer.admissions) == 1
    assert context.dispatches == []


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
