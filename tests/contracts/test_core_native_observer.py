"""Fail-closed contracts for the additive pinned-Hermes observation adapter.

Run these through the identified Pi validation path; local execution is not
authoritative for this hardware-bound integration.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from hermes_installer.remote.core_native_observer import (
    CoreNativeObservationClient,
    CoreNativeObservationUnavailable,
    ObservedProviderAttempt,
    ObservedNativeToolCall,
    RootVerifiedNativeChildAuthorization,
    RootVerifiedMasterReadCall,
    _NATIVE_CHILD_AUTHORIZATION_SEAL,
    _MASTER_READ_CALL_SEAL,
    _codex_account_fingerprint,
    _mission_binding_from_wire,
    install_native_codex_process_observer,
)
from hermes_installer.remote.jarvis_mission_executor import MissionBinding


class _PluginContext:
    def __init__(self):
        self.middleware = {}

    def register_middleware(self, name, callback):
        self.middleware.setdefault(name, []).append(callback)
        return callback


def test_non_codex_routes_pass_through_without_observation(tmp_path: Path):
    ctx = _PluginContext()
    client = CoreNativeObservationClient(socket_path=tmp_path / "unused.sock")
    install_native_codex_process_observer(ctx, client=client)
    callback = ctx.middleware["llm_execution"][0]
    seen = []

    result = callback(
        provider="openai", api_mode="chat_completions",
        base_url="https://api.openai.com/v1", request={"model": "gpt-test"},
        next_call=lambda request: seen.append(request) or {"status": "complete"},
    )

    assert result == {"status": "complete"}
    assert seen == [{"model": "gpt-test"}]


def test_selected_codex_route_disables_tools_when_root_mode_is_uncertain(
        tmp_path: Path, monkeypatch):
    import hermes_installer.remote.core_native_observer as observer

    ctx = _PluginContext()
    client = CoreNativeObservationClient(socket_path=tmp_path / "not-started.sock")
    install_native_codex_process_observer(ctx, client=client)
    monkeypatch.setattr(observer, "_codex_account_fingerprint", lambda _resolver: "a" * 64)
    request = {
        "model": "gpt-6-luna",
        "tools": [{"name": "resources_delegate"}],
        "input": [{"type": "message", "role": "user",
                   "content": [{"type": "input_text", "text": "ordinary chat"}]}],
    }
    seen = []

    result = ctx.middleware["llm_execution"][0](
        provider="openai-codex", api_mode="codex_responses",
        base_url="https://chatgpt.com/backend-api/codex", model="gpt-6-luna",
        request=request, session_id="session-1", turn_id="turn-1",
        api_request_id="request-1", next_call=lambda value: seen.append(value) or "completed",
    )

    assert result.status == "completed"
    assert "authority could not be verified" in result.output_text
    assert seen == []
    assert request["tools"] == [{"name": "resources_delegate"}]


def test_non_codex_fallback_is_not_called_for_root_planned_turn(tmp_path: Path, monkeypatch):
    import hashlib
    from hermes_installer.remote.core_gateway_inspector import PlanningContext

    ctx = _PluginContext()
    client = CoreNativeObservationClient(socket_path=tmp_path / "observer.sock")
    prompt = "root planner request"
    context = PlanningContext(1, "m" * 24, 1, "a" * 64, "b" * 64,
        hashlib.sha256(prompt.encode()).hexdigest(), "c" * 64, "d" * 64, "e" * 64, "hermes")
    monkeypatch.setattr(client, "planning_context_for_attempt", lambda **_kwargs: context)
    install_native_codex_process_observer(ctx, client=client)
    request = {"model": "gpt-test", "tools": [{"name": "resources_delegate"}],
        "input": [{"type": "message", "role": "user",
                   "content": [{"type": "input_text", "text": prompt}]}]}
    dispatched = []

    result = ctx.middleware["llm_execution"][0](
        provider="openai", api_mode="chat_completions", base_url="https://api.openai.com/v1",
        request=request, session_id="session-plan", turn_id="turn-plan",
        next_call=lambda value: dispatched.append(value) or {"status": "complete"},
    )

    assert result.status == "completed"
    assert result.output[0].type == "message"
    assert not any(item.type == "function_call" for item in result.output)
    assert dispatched == []
    assert request["tools"] == [{"name": "resources_delegate"}]


def test_planned_codex_does_not_dispatch_when_root_cannot_register_attempt(
        tmp_path: Path, monkeypatch):
    import hashlib
    import hermes_installer.remote.core_native_observer as observer
    from hermes_installer.remote.core_gateway_inspector import PlanningContext

    ctx = _PluginContext()
    client = CoreNativeObservationClient(socket_path=tmp_path / "observer.sock")
    prompt = "root planner request"
    context = PlanningContext(1, "m" * 24, 1, "a" * 64, "b" * 64,
        hashlib.sha256(prompt.encode()).hexdigest(), "c" * 64, "d" * 64, "e" * 64, "hermes")
    monkeypatch.setattr(client, "planning_context_for_attempt", lambda **_kwargs: context)
    monkeypatch.setattr(client, "register_attempt", lambda **_kwargs:
                        (_ for _ in ()).throw(CoreNativeObservationUnavailable("test denial")))
    monkeypatch.setattr(observer, "_codex_account_fingerprint", lambda _resolver: "f" * 64)
    install_native_codex_process_observer(ctx, client=client)
    request = {"model": "gpt-6-luna", "tools": [{"name": "resources_delegate"}],
        "input": [{"type": "message", "role": "user",
                   "content": [{"type": "input_text", "text": prompt}]}]}
    dispatched = []

    result = ctx.middleware["llm_execution"][0](
        provider="openai-codex", api_mode="codex_responses",
        base_url="https://chatgpt.com/backend-api/codex", model="gpt-6-luna",
        request=request, session_id="session-plan", turn_id="turn-plan",
        api_request_id="request-plan", next_call=lambda value: dispatched.append(value),
    )

    assert result.status == "completed"
    assert result.output[0].type == "message"
    assert not any(item.type == "function_call" for item in result.output)
    assert dispatched == []
    assert request["tools"] == [{"name": "resources_delegate"}]


def test_root_enrolled_planning_turn_reaches_provider_with_zero_tools(tmp_path: Path, monkeypatch):
    import hashlib
    from types import SimpleNamespace

    import hermes_installer.remote.core_native_observer as observer
    from hermes_installer.remote.core_gateway_inspector import PlanningContext

    ctx = _PluginContext()
    client = CoreNativeObservationClient(socket_path=tmp_path / "observer.sock")
    prompt = "Root-owned planning prompt"
    prompt_digest = hashlib.sha256(prompt.encode()).hexdigest()
    context = PlanningContext(1, "m" * 24, 1, "a" * 64, "b" * 64,
        prompt_digest, "c" * 64, "d" * 64, "e" * 64, "hermes")
    monkeypatch.setattr(client, "planning_context_for_attempt", lambda **_kwargs: context)
    attempt = ObservedProviderAttempt("x" * 32, "o" * 32, __import__("time").monotonic() + 20)
    monkeypatch.setattr(client, "register_attempt", lambda **_kwargs: attempt)
    receipts = []
    monkeypatch.setattr(client, "register_response", lambda **kwargs: receipts.append(kwargs))
    monkeypatch.setattr(observer, "_codex_account_fingerprint", lambda _resolver: "f" * 64)
    install_native_codex_process_observer(ctx, client=client)
    request = {
        "model": "gpt-6-luna",
        "tools": [{"name": "resources_delegate"}, {"name": "terminal"}],
        "input": [{"type": "message", "role": "user",
                   "content": [{"type": "input_text", "text": prompt}]}],
    }
    seen = []
    response = SimpleNamespace(output=[], output_text='{"execution_mode":"oneshot",'
        '"selected_source_ids":[],"plan":{}}',
        model_dump=lambda **_kwargs: {"output": [], "output_text": "bounded"})
    result = ctx.middleware["llm_execution"][0](
        provider="openai-codex", api_mode="codex_responses",
        base_url="https://chatgpt.com/backend-api/codex", model="gpt-6-luna",
        request=request, session_id="session-plan", turn_id="turn-plan",
        api_request_id="request-plan",
        next_call=lambda value: seen.append(value) or response,
    )

    assert result is response
    assert request["tools"] == [{"name": "resources_delegate"}, {"name": "terminal"}]
    assert seen[0]["tools"] == []
    assert seen[0]["tool_choice"] == "none"
    assert receipts[0]["response_text"] == response.output_text


def test_master_plan_readback_requires_root_retained_completion_record():
    """Gateway mission rows alone cannot create root-verified plan data."""
    import threading

    import hermes_installer.remote.core_native_observer as observer

    registry = object.__new__(observer.RootCoreNativeObservationRegistry)
    registry._lock = threading.RLock()
    registry._master_plan_records = {}
    key = ("a" * 64, "mission_12345678901234567890", 1)
    assert registry.read_master_plan_record(
        owner_subject_sha256=key[0], mission_id=key[1], revision=key[2]) is None

    record = observer.RootObservedMasterPlanRecord(
        owner_subject_sha256=key[0], mission_id=key[1], revision=key[2],
        gateway_turn_id="turn_12345678901234567890", conversation_id="conversation_1234567890",
        session_id="session_12345678901234567890", owner_turn_handle="o" * 32,
        core_generation="b" * 64, core_source_generation="c" * 64,
        goal_sha256="d" * 64, catalog_sha256="e" * 64, planner_prompt_sha256="f" * 64,
        master_source_generation_sha256="1" * 64, master_source_manifest_sha256="2" * 64,
        master_prompt_sha256="3" * 64, plan_json="{}", plan_sha256="4" * 64,
        response_sha256="5" * 64, selected_source_ids=(), execution_mode="oneshot",
        _seal=observer._MASTER_PLAN_RECORD_SEAL,
    )
    registry._master_plan_records[key] = record
    assert record.is_root_observed() is True
    assert registry.read_master_plan_record(
        owner_subject_sha256=key[0], mission_id=key[1], revision=key[2]) is record
    assert registry.read_master_plan_record(
        owner_subject_sha256="6" * 64, mission_id=key[1], revision=key[2]) is None


@pytest.mark.parametrize("retry_count", [None, -1, 1, True])
def test_codex_attempt_rejects_unknown_or_retry_count_before_ipc(tmp_path: Path, retry_count):
    client = CoreNativeObservationClient(socket_path=tmp_path / "unused.sock")
    with pytest.raises(CoreNativeObservationUnavailable):
        client.register_attempt(
            session_id="session-1", turn_id="turn-1", api_request_id="request-1",
            provider="openai-codex", model="gpt-6-luna",
            base_url="https://chatgpt.com/backend-api/codex",
            api_mode="codex_responses", account_fingerprint="a" * 64,
            request_sha256="b" * 64, parent_tool_names=("delegate_task",),
            prompt_sha256="c" * 64, retry_count=retry_count,
        )


def test_credential_pool_or_api_bearer_never_counts_as_selected_subscription():
    with pytest.raises(CoreNativeObservationUnavailable):
        _codex_account_fingerprint(lambda: {
            "provider": "openai-codex", "base_url": "https://chatgpt.com/backend-api/codex",
            "api_key": "not-a-real-token", "source": "credential_pool",
            "auth_mode": "api_key",
        })


def test_provider_attempt_receipt_can_cover_original_owner_turn_deadline():
    import time

    now = time.monotonic()
    attempt = ObservedProviderAttempt(
        handle="a" * 32, owner_turn_handle="o" * 32, expires_monotonic=now + 300,
    )
    assert attempt.expires_monotonic > now + 30
    with pytest.raises(CoreNativeObservationUnavailable):
        ObservedProviderAttempt(
            handle="b" * 32, owner_turn_handle="o" * 32, expires_monotonic=now + 601,
        )


def test_initial_planner_admission_accepts_no_parent_turn_but_rejects_tool_drift():
    from types import SimpleNamespace
    from hermes_installer.remote.native_child_adapter import NativeChildMode

    parent = SimpleNamespace(
        session_id="owner-session", _current_turn_id=None,
        provider="openai-codex", api_mode="codex_responses",
        base_url="https://chatgpt.com/backend-api/codex", model="gpt-6-luna",
    )
    child = SimpleNamespace(
        session_id="planner-session", _current_turn_id=None, valid_tool_names=set(),
        provider="openai-codex", api_mode="codex_responses",
        base_url="https://chatgpt.com/backend-api/codex", model="gpt-6-luna",
    )
    source = SimpleNamespace(
        profile_id="hermes", generation_sha256="a" * 64,
        source_member_manifest_sha256="b" * 64, effective_prompt_sha256="c" * 64,
    )
    now = __import__("time").monotonic()
    authorization = RootVerifiedNativeChildAuthorization(
        owner_turn_handle="o" * 32, gateway_turn_id="gateway-turn",
        owner_subject_sha256="d" * 64, core_generation="e" * 64,
        core_source_generation="f" * 64, parent_session_id=parent.session_id,
        parent_turn_id="", child_session_id=child.session_id, profile_id="hermes",
        source_generation_sha256=source.generation_sha256,
        source_manifest_sha256=source.source_member_manifest_sha256,
        prompt_sha256=source.effective_prompt_sha256,
        goal_sha256=__import__("hashlib").sha256(b"bounded plan").hexdigest(),
        account_fingerprint="1" * 64, mode=NativeChildMode.PLANNER.value,
        allowed_tool_names=(), tool_closure_sha256=__import__("hashlib").sha256(b"[]").hexdigest(),
        additional_metered_budget=0, admission_handle="h" * 32,
        expires_monotonic=now + 20, initial_owner_turn=True,
        _parent_agent=parent, _child_agent=child, _source=source,
        _seal=_NATIVE_CHILD_AUTHORIZATION_SEAL,
    )

    assert authorization.matches_child(
        parent_agent=parent, child=child, source=source,
        mode=NativeChildMode.PLANNER, goal="bounded plan", now=now,
    )
    child.valid_tool_names.add("delegate_task")
    assert not authorization.matches_child(
        parent_agent=parent, child=child, source=source,
        mode=NativeChildMode.PLANNER, goal="bounded plan", now=now,
    )


def test_owner_turn_registration_is_not_available_from_core_worker_socket(tmp_path: Path):
    client = CoreNativeObservationClient(socket_path=tmp_path / "unused.sock")
    # Owner turns are accepted only by the inspector's authenticated gateway op,
    # which independently validates Access and consumes the one-use ingress proof.
    # The native worker socket cannot mint owner authority from caller metadata.
    with pytest.raises(CoreNativeObservationUnavailable):
        client._rpc("register-owner-turn", {"gateway_turn_id": "caller-selected"})


def test_mission_binding_roundtrips_only_the_root_sealed_typed_wire_shape():
    binding = MissionBinding(
        schema=2, mission_id="m" * 24, revision=3,
        plan_sha256="a" * 64, task_sha256="b" * 64,
        source_profile_id="hermes", execution_mode="oneshot",
        autonomy_mode="approval_required", selected_source_ids=("orchestrator",),
        scope_sha256="c" * 64, authorization_sha256=None,
    )
    assert _mission_binding_from_wire(None) is None
    assert _mission_binding_from_wire(binding.to_wire()) == binding
    with pytest.raises(CoreNativeObservationUnavailable):
        _mission_binding_from_wire({**binding.to_wire(), "owner_subject_sha256": "c" * 64})
    with pytest.raises(CoreNativeObservationUnavailable):
        _mission_binding_from_wire({**binding.to_wire(), "mission_id": "mission-17"})


def test_root_caller_receipt_binds_exact_observed_tool_effect_and_expiry():
    now = __import__("time").monotonic()
    call = ObservedNativeToolCall(
        handle="h" * 32, attempt_handle="a" * 32, owner_turn_handle="o" * 32,
        tool_call_id="call-1", tool_name="web_search", arguments_sha256="b" * 64,
        expires_monotonic=now + 10,
    )
    receipt = RootVerifiedMasterReadCall(
        observed_call_handle=call.handle, owner_turn_handle=call.owner_turn_handle,
        tool_call_id=call.tool_call_id, tool_name=call.tool_name,
        arguments_sha256=call.arguments_sha256, source_generation_sha256="c" * 64,
        mode="expert_read", expires_monotonic=now + 5, _seal=_MASTER_READ_CALL_SEAL,
    )

    assert receipt.matches_call(call, tool_name="web_search", arguments_sha256="b" * 64, now=now)
    assert not receipt.matches_call(call, tool_name="terminal", arguments_sha256="b" * 64, now=now)
    assert not receipt.matches_call(call, tool_name="web_search", arguments_sha256="d" * 64, now=now)
    assert not receipt.matches_call(call, tool_name="web_search", arguments_sha256="b" * 64,
                                    now=receipt.expires_monotonic)
