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
    ObservedNativeToolCall,
    RootVerifiedMasterReadCall,
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


def test_selected_codex_route_passes_through_when_root_observer_is_not_started(
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

    assert result == "completed"
    assert seen == [request]


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
