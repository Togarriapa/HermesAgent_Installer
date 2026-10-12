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
    RootCoreNativeObservationRegistry,
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


@pytest.mark.parametrize("capture,expected_text", [(True, "exact provider answer"), (False, None)])
def test_observer_forwards_exact_child_output_only_for_root_admitted_capture(
        tmp_path: Path, monkeypatch, capture: bool, expected_text: str | None):
    """Root can retain exact Expert output for a sealed child, never ordinary chat text."""
    from types import SimpleNamespace
    import time
    import hermes_installer.remote.core_native_observer as observer

    client = CoreNativeObservationClient(socket_path=tmp_path / "unused.sock")
    attempt = ObservedProviderAttempt("x" * 32, "o" * 32, time.monotonic() + 20,
                                     capture_child_output=capture)
    receipts = []
    monkeypatch.setattr(client, "planning_context_for_attempt", lambda **_kwargs: None)
    monkeypatch.setattr(client, "register_attempt", lambda **_kwargs: attempt)
    monkeypatch.setattr(client, "register_response", lambda **kwargs: receipts.append(kwargs))
    monkeypatch.setattr(observer, "_codex_account_fingerprint", lambda _resolver: "f" * 64)
    ctx = _PluginContext()
    install_native_codex_process_observer(ctx, client=client)
    prompt = "child task"
    request = {"model": "gpt-6-luna", "tools": [],
        "input": [{"type": "message", "role": "user",
                   "content": [{"type": "input_text", "text": prompt}]}]}
    output = "exact provider answer"
    response = SimpleNamespace(output_text=output, model_dump=lambda **_kwargs: {
        "output_text": output, "output": []})

    result = ctx.middleware["llm_execution"][0](
        provider="openai-codex", api_mode="codex_responses",
        base_url="https://chatgpt.com/backend-api/codex", model="gpt-6-luna",
        request=request, session_id="child-session", turn_id="child-turn",
        api_request_id="child-request", next_call=lambda _value: response,
    )

    assert result is response
    assert len(receipts) == 1
    assert receipts[0]["response_text"] == expected_text
    if expected_text is not None:
        assert receipts[0]["response_text_sha256"] == __import__("hashlib").sha256(
            output.encode()).hexdigest()


def test_team_completion_excerpt_survives_child_lease_expiry_only_until_owner_bound():
    """Sequential Team work keeps observed output DATA, never a completed child lease."""
    import hermes_installer.remote.core_native_observer as observer

    registry = object.__new__(observer.RootCoreNativeObservationRegistry)
    for name in (
        "_obsidian_bindings", "_policies", "_owner_policy_handles", "_attempts",
        "_calls", "_claims", "_mission_pending", "_consumed_dispatches",
        "_child_sessions", "_planning_completions", "_expert_completions",
        "_team_completion_evidence",
        "_team_messages", "_team_bindings", "_team_completion_counts",
        "_master_selections", "_selected_source_deliveries", "_master_source_deliveries",
        "_obsidian_draft_read_deliveries", "_obsidian_draft_review_proposals",
    ):
        setattr(registry, name, {})
    registry._obsidian_scoped_calls = set()
    registry._team_edge_issued = set()
    registry._child_sessions["completed-child"] = {
        "expiry": 130.0, "mode": "expert-read-research", "complete": True,
    }
    registry._expert_completions["root-completion"] = {
        "expiry": 130.0, "team_binding_id": "team-binding",
    }
    registry._team_completion_evidence["root-completion"] = {
        "completion_handle": "root-completion", "owner": object(),
        "team_binding_id": "team-binding", "profile_id": "researcher",
        "team_message_handle": None, "response_text": "exact root-observed excerpt",
        "response_text_sha256": "a" * 64, "peer": (1, 1, 1),
        "data_expires_monotonic": 600.0,
    }

    registry._prune(140.0)
    assert "completed-child" not in registry._child_sessions
    assert "root-completion" not in registry._expert_completions
    evidence = registry._team_completion_evidence["root-completion"]
    assert evidence["response_text"] == (
        "exact root-observed excerpt")
    assert not {"child", "admission_handle", "source", "final_attempt"}.intersection(evidence)

    registry._prune(600.0)
    assert "root-completion" not in registry._team_completion_evidence


def test_master_plan_readback_uses_canonical_root_durable_completion_record(monkeypatch):
    """Only canonical root-published zero-tool records survive a registry restart."""
    import threading
    import hashlib
    import json

    import hermes_installer.remote.core_native_observer as observer

    registry = object.__new__(observer.RootCoreNativeObservationRegistry)
    registry._lock = threading.RLock()
    registry._master_plan_records = {}
    key = ("a" * 64, "mission_12345678901234567890", 1)
    monkeypatch.setattr(observer, "_read_root_master_plan_bytes", lambda *_args: None)
    assert registry.read_master_plan_record(
        owner_subject_sha256=key[0], mission_id=key[1], revision=key[2]) is None

    plan = {"execution_mode": "oneshot", "selected_source_ids": [], "plan": {}}
    plan_sha256 = hashlib.sha256(json.dumps(plan, ensure_ascii=False, sort_keys=True,
        separators=(",", ":"), allow_nan=False).encode("utf-8")).hexdigest()

    record = observer.RootObservedMasterPlanRecord(
        owner_subject_sha256=key[0], mission_id=key[1], revision=key[2],
        gateway_turn_id="turn_12345678901234567890", conversation_id="conversation_1234567890",
        session_id="session_12345678901234567890", native_turn_id="native_turn_1234567890",
        owner_turn_handle="o" * 32,
        core_generation="b" * 64, core_source_generation="c" * 64,
        goal_sha256="d" * 64, catalog_sha256="e" * 64, planner_prompt_sha256="f" * 64,
        master_source_generation_sha256="1" * 64, master_source_manifest_sha256="2" * 64,
        master_prompt_sha256="3" * 64, attempt_handle="h" * 32,
        api_request_id="request_1234567890123456", provider="openai-codex",
        api_mode="codex_responses", base_url="https://chatgpt.com/backend-api/codex",
        model="gpt-6-luna", account_fingerprint="6" * 64, request_sha256="7" * 64,
        retry_count=0, completed=True, request_tool_count=0, tool_call_count=0,
        plan_json="{}", plan_sha256=plan_sha256,
        response_sha256="5" * 64, selected_source_ids=(), execution_mode="oneshot",
        _seal=observer._MASTER_PLAN_RECORD_SEAL,
    )
    assert record.is_root_observed() is True
    durable = observer._master_plan_record_bytes(record)
    # A fresh registry with no in-memory completion cache recovers only the exact
    # canonical root record. The BFF row is not consulted by this method.
    monkeypatch.setattr(observer, "_read_root_master_plan_bytes", lambda *_args: durable)
    assert registry.read_master_plan_record(
        owner_subject_sha256=key[0], mission_id=key[1], revision=key[2]) == record
    changed = json.loads(durable)
    changed["tool_call_count"] = 1
    changed_bytes = json.dumps(changed, ensure_ascii=False, sort_keys=True,
        separators=(",", ":"), allow_nan=False).encode("utf-8")
    assert observer._root_master_plan_record_from_bytes(changed_bytes,
        owner_subject_sha256=key[0], mission_id=key[1], revision=key[2]) is None
    monkeypatch.setattr(observer, "_read_root_master_plan_bytes", lambda *_args: durable + b" ")
    assert registry.read_master_plan_record(
        owner_subject_sha256=key[0], mission_id=key[1], revision=key[2]) is None


def test_obsidian_origin_journal_binds_owner_draft_bytes_and_rejects_replay_or_tamper():
    import hermes_installer.remote.core_native_observer as observer

    record = {
        "draft_id": "D" * 43, "owner_subject_sha256": "a" * 64,
        "registration_sha256": "b" * 64, "origin_execution_id": "child_session_123456",
        "origin_source_id": "expert_alpha", "origin_source_revision": "source-r17",
        "source_generation_sha256": "c" * 64, "mission_sha256": "d" * 64,
        "content_sha256": "e" * 64, "base_sha256": None, "state": "private-draft",
    }
    record["origin_record_sha256"] = observer._obsidian_origin_record_digest(record)
    raw = observer._canonical({"schema": 1, "records": [record]})

    recovered = observer._obsidian_origin_snapshot_from_bytes(raw)

    assert recovered[("a" * 64, "D" * 43)] == record
    changed = dict(record, content_sha256="f" * 64)
    assert observer._obsidian_origin_snapshot_from_bytes(
        observer._canonical({"schema": 1, "records": [changed]})) is None
    assert observer._obsidian_origin_snapshot_from_bytes(
        observer._canonical({"schema": 1, "records": [record, record]})) is None


def test_exact_private_draft_markdown_reader_is_master_only_not_in_expert_child_closure():
    import hermes_installer.remote.core_native_observer as observer
    from hermes_installer.remote.obsidian_native_tools import _EXPERT_TOOLS, _TOOL_NAMES

    assert observer._OBSIDIAN_READ_TOOL_NAMES == _EXPERT_TOOLS
    assert "obsidian_read_private_draft" not in observer._OBSIDIAN_READ_TOOL_NAMES
    assert "obsidian_read_private_draft" in observer._OBSIDIAN_MASTER_READ_TOOL_NAMES
    assert set(_TOOL_NAMES) == set(observer._OBSIDIAN_TOOL_NAMES)
    assert "obsidian_promote_reviewed_draft" not in observer._OBSIDIAN_READ_TOOL_NAMES


def test_obsidian_origin_sidecar_atomic_readback_and_restart_load(tmp_path, monkeypatch):
    import os
    import hermes_installer.remote.core_native_observer as observer

    if os.geteuid() != 0:
        pytest.skip("root-owned Obsidian journal custody is qualified on the Pi")
    directory = tmp_path / "core-runtime"
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    monkeypatch.setattr(observer, "_open_root_master_plan_store",
                        lambda: os.open(directory, flags))
    record = {
        "draft_id": "R" * 43, "owner_subject_sha256": "a" * 64,
        "registration_sha256": "b" * 64, "origin_execution_id": "JarvisTurn_123456",
        "origin_source_id": "hermes", "origin_source_revision": "master-r8",
        "source_generation_sha256": "c" * 64, "mission_sha256": None,
        "content_sha256": "d" * 64, "base_sha256": None, "state": "private-draft",
    }
    record["origin_record_sha256"] = observer._obsidian_origin_record_digest(record)
    raw = observer._canonical({"schema": 1, "records": [record]})

    observer._publish_root_obsidian_origin_bytes(raw)

    assert observer._read_root_obsidian_origin_bytes() == raw
    assert observer._load_root_obsidian_origin_snapshot()[("a" * 64, "R" * 43)] == record
    assert set(path.name for path in directory.iterdir()) == {observer._OBSIDIAN_ORIGIN_STORE_NAME}
    assert b"private markdown" not in raw


def test_obsidian_completion_history_and_tombstone_join_without_retaining_markdown():
    import hermes_installer.remote.core_native_observer as observer

    origin = {
        "draft_id": "D" * 43, "owner_subject_sha256": "a" * 64,
        "registration_sha256": "b" * 64, "origin_execution_id": "child_session_123456",
        "origin_source_id": "expert_alpha", "origin_source_revision": "source-r17",
        "source_generation_sha256": "c" * 64, "mission_sha256": "d" * 64,
        "content_sha256": "e" * 64, "base_sha256": None, "state": "private-draft",
    }
    origin["origin_record_sha256"] = observer._obsidian_origin_record_digest(origin)
    history_body = {
        "record_id": "H" * 43, "origin": origin,
        "proposal": {"proposal_sha256": "f" * 64},
        "approval": {"pending_id": "P" * 43, "review_sha256": "1" * 64},
        "result": {"destination": "Notes/Expert.md", "note_id": "N" * 43,
                   "title": "Expert", "content_sha256": "e" * 64, "state": "promoted"},
        "completed_at": 12.5,
    }
    history_record = {**history_body,
        "record_sha256": hashlib.sha256(observer._canonical(history_body)).hexdigest()}
    history = observer._canonical({"schema": 1, "records": [history_record]})

    assert observer._obsidian_history_from_bytes(history) == [history_record]
    tampered = dict(history_record, result={**history_record["result"], "markdown": "private"})
    tampered_body = {key: value for key, value in tampered.items() if key != "record_sha256"}
    tampered["record_sha256"] = hashlib.sha256(observer._canonical(tampered_body)).hexdigest()
    assert observer._obsidian_history_from_bytes(
        observer._canonical({"schema": 1, "records": [tampered]})) is None

    tombstone = {
        "owner_subject_sha256": "a" * 64, "draft_id": "D" * 43,
        "origin_record_sha256": origin["origin_record_sha256"],
        "history_record_id": history_record["record_id"],
        "history_record_sha256": history_record["record_sha256"],
        "destination": "Notes/Expert.md", "note_id": "N" * 43,
        "content_sha256": "e" * 64, "completed_at": 12.5,
    }
    tombstone["completed_record_sha256"] = hashlib.sha256(
        observer._canonical(tombstone)).hexdigest()
    assert observer._reserved_origin_tombstone(history_record) == tombstone
    state = observer._canonical({"schema": 2, "records": [], "completed": [tombstone]})
    assert observer._obsidian_origin_state_from_bytes(state) == (
        {}, {("a" * 64, "D" * 43): tombstone})
    assert observer._obsidian_origin_state_from_bytes(observer._canonical({
        "schema": 2, "records": [origin], "completed": [tombstone]})) is None


def test_typed_obsidian_origin_is_short_lived_and_exact_owner_registration_digest():
    import time

    from hermes_installer.remote.obsidian_native_scope import (
        _decode_draft_origin, ObsidianRootScopeUnavailable,
    )

    issued = time.monotonic()
    row = {"schema": 1, "nonce": "fresh", "ok": True,
        "draft_id": "D" * 43, "owner_subject_sha256": "a" * 64,
        "registration_sha256": "b" * 64, "origin_execution_id": "expert_session_123",
        "origin_source_id": "expert_alpha", "origin_source_revision": "source-r17",
        "source_generation_sha256": "c" * 64, "mission_sha256": "d" * 64,
        "content_sha256": "e" * 64, "base_sha256": None,
        "origin_record_sha256": "f" * 64, "state": "private-draft",
        "issued_monotonic": issued, "expires_monotonic": issued + 4,
    }
    origin = _decode_draft_origin(row)
    assert origin.matches(draft_id="D" * 43, owner_subject_sha256="a" * 64,
                          registration_sha256="b" * 64, content_sha256="e" * 64,
                          base_sha256=None)
    assert not origin.matches(draft_id="D" * 43, owner_subject_sha256="9" * 64,
                              registration_sha256="b" * 64, content_sha256="e" * 64,
                              base_sha256=None)
    with pytest.raises(ObsidianRootScopeUnavailable, match="stale"):
        _decode_draft_origin({**row, "expires_monotonic": issued})


def test_root_observed_expert_draft_origin_resolves_only_for_current_master_promotion():
    import hashlib
    import os
    import threading
    import time
    from types import SimpleNamespace

    import hermes_installer.remote.core_native_observer as observer

    owner_sha, registration_sha = "a" * 64, "b" * 64
    draft_id = "D" * 43
    markdown = "# Expert draft\nObserved private bytes.\n"
    content_sha = hashlib.sha256(markdown.encode()).hexdigest()
    generation = "c" * 64
    source = SimpleNamespace(source_revision="r17", generation_sha256=generation)
    source.is_current_sealed = lambda *_args, **_kwargs: True
    mission = MissionBinding(
        schema=2, mission_id="mission_" + "1" * 24, revision=1,
        plan_sha256="d" * 64, task_sha256="e" * 64,
        source_profile_id="hermes", execution_mode="oneshot",
        autonomy_mode="approval_required", selected_source_ids=("expert_alpha",),
        scope_sha256="2" * 64,
    )
    owner = SimpleNamespace(
        owner_subject_sha256=owner_sha, owner_turn_handle="T" * 43,
        gateway_turn_id="gateway-turn",
        core_generation="f" * 64, core_source_generation="1" * 64,
        expires_monotonic=time.monotonic() + 30, mission_binding=mission,
    )
    child = {"session_id": "expert_session_123", "profile_id": "expert_alpha",
             "source_generation_sha256": generation, "source": source}
    current_master_source = SimpleNamespace(
        profile_id="hermes", source_revision="master-current-r18", generation_sha256="9" * 64,
    )
    current_master_source.is_current_sealed = lambda *_args, **_kwargs: True
    draft = SimpleNamespace(
        execution_id=child["session_id"], source_instance_id=child["profile_id"],
        title="Expert draft", base_note_id=None, base_sha256=None, citations=(),
        content_sha256=content_sha,
    )
    review = SimpleNamespace(draft=draft, markdown=markdown)
    active = {}

    registry = object.__new__(RootCoreNativeObservationRegistry)
    registry._lock = threading.RLock()
    registry._closed = False
    registry._custody = SimpleNamespace(
        core_pid=os.getpid(), core_start_ticks="5678", core_generation=owner.core_generation,
        core_source_generation=owner.core_source_generation,
    )
    registry._config = SimpleNamespace(core_uid=1000, core_gid=1000)
    registry._obsidian_origin_store_ok = True
    registry._obsidian_draft_origins = {}
    registry._obsidian_completed_drafts = {}
    registry._obsidian_resolved_origin_calls = set()
    registry._obsidian_scoped_calls = set()
    registry._obsidian_draft_read_deliveries = {}
    registry._obsidian_draft_review_proposals = {}
    registry._ensure_open = lambda: None
    registry._prune = lambda _now: None
    registry._classify_current_call = lambda _handle, _peer, **_kwargs: active["classification"]
    peer = (os.getpid(), os.geteuid(), os.getegid())
    startup_binding = {"binding_id": "B" * 43, "expiry": time.monotonic() + 20,
        "peer": peer, "owner_subject_sha256": owner_sha,
        "registration_sha256": registration_sha, "core_generation": owner.core_generation,
        "core_source_generation": owner.core_source_generation,
        "core_pid": os.getpid(), "core_start_ticks": "5678"}
    startup_bindings = {startup_binding["binding_id"]: startup_binding}

    def validate_binding(*, binding_id, **_kwargs):
        row = startup_bindings[binding_id]
        if row["expiry"] <= time.monotonic():
            raise ValueError("startup binding expired")
        return (Path("/home/admin/.hermes/jarvis-second-brain"), owner_sha,
                registration_sha, row)

    registry._validate_obsidian_origin_binding = validate_binding
    registry._read_obsidian_owner_draft = lambda *_args, **_kwargs: review
    registry._persist_obsidian_origin = lambda records: active.update(persisted=records)
    create_arguments = observer._canonical({"title": draft.title, "markdown": markdown})
    create_call = {"handle": "C" * 43, "tool_name": "obsidian_create_private_draft",
                   "arguments": create_arguments, "expiry": time.monotonic() + 20}
    active["classification"] = (create_call, owner, child, "expert_read")

    created = registry._handle(peer, {
        "schema": 1, "op": "record-obsidian-draft-origin", "nonce": "record",
        "observed_call_handle": create_call["handle"],
        "startup_binding_id": "B" * 43, "draft_id": draft_id,
    })

    assert created["ok"] is True
    assert active["persisted"][(owner_sha, draft_id)]["origin_execution_id"] == child["session_id"]

    read_args = {"draft_id": draft_id, "expected_draft_sha256": content_sha}
    read_call = {"handle": "R" * 43, "tool_name": "obsidian_read_private_draft",
                 "tool_call_id": "read-draft-call",
                 "arguments": observer._canonical(read_args),
                 "expiry": time.monotonic() + 20}
    registry._obsidian_scoped_calls.add(read_call["handle"])
    active["classification"] = (read_call, owner, current_master_source, "master_read")
    read_result = registry._handle(peer, {
        "schema": 1, "op": "read-obsidian-private-draft", "nonce": "read",
        "observed_call_handle": read_call["handle"],
        "startup_binding_id": "B" * 43, "draft_id": draft_id,
        "expected_content_sha256": content_sha,
    })
    assert read_result["review_complete"] is True
    assert read_result["markdown"] == markdown
    assert read_result["content_sha256"] == content_sha
    assert read_result["origin_execution_id"] == child["session_id"]
    assert read_result["origin_source_id"] == child["profile_id"]
    assert read_result["delivery"]["complete"] is True
    assert read_result["delivery"]["returned_content_sha256"] == content_sha

    promote_arguments = {"draft_id": draft_id, "expected_draft_sha256": content_sha,
        "destination": "Notes/Expert.md", "expected_base_sha256": None,
        "review_disposition": "approve"}
    promote_call = {"handle": "P" * 43, "tool_call_id": "promote-draft-call",
        "tool_name": "obsidian_promote_reviewed_draft",
        "arguments": observer._canonical(promote_arguments),
        "arguments_sha256": hashlib.sha256(observer._canonical(promote_arguments)).hexdigest(),
        "expiry": time.monotonic() + 20}
    active["classification"] = (promote_call, owner, current_master_source, "master_effect")
    with pytest.raises(ValueError, match="complete draft bytes were not delivered"):
        registry._propose_obsidian_draft_review(
            call=promote_call, owner=owner, source=current_master_source, peer=peer,
            startup_binding_id="B" * 43)

    from unittest.mock import patch
    from hermes_installer.native_invocations import NativeToolDispatch, canonical_tool_arguments
    from hermes_installer.remote.obsidian_native_scope import (
        RootObsidianCallScope, RootSelectedObsidianVaultBinding,
        _BINDING_SEAL, _SCOPE_SEAL, _decode_draft_review,
    )
    from hermes_installer.remote.obsidian_native_tools import (
        ObsidianNativeTools, _admit_current_obsidian_call,
    )
    from hermes_installer.remote.obsidian_second_brain import ObsidianVaultStore

    issued = time.monotonic()
    binding = RootSelectedObsidianVaultBinding(
        binding_id="B" * 43, registration_sha256=registration_sha,
        owner_subject_sha256=owner_sha, core_generation=owner.core_generation,
        core_source_generation=owner.core_source_generation, core_pid=os.getpid(),
        core_start_ticks="5678", selected_owner_uid=os.geteuid(),
        vault_root="/home/admin/.hermes/jarvis-second-brain",
        issued_monotonic=issued, expires_monotonic=issued + 20,
        _seal=_BINDING_SEAL)
    observed_read = ObservedNativeToolCall(
        handle=read_call["handle"], attempt_handle="A" * 43,
        owner_turn_handle=owner.owner_turn_handle, tool_call_id=read_call["tool_call_id"],
        tool_name=read_call["tool_name"],
        arguments_sha256=hashlib.sha256(read_call["arguments"]).hexdigest(),
        expires_monotonic=read_call["expiry"])
    scope = RootObsidianCallScope(
        observed_call_handle=observed_read.handle, owner_turn_handle=owner.owner_turn_handle,
        tool_call_id=observed_read.tool_call_id, tool_name=observed_read.tool_name,
        arguments_sha256=observed_read.arguments_sha256, owner_subject_sha256=owner_sha,
        registration_sha256=registration_sha, startup_binding_id=binding.binding_id,
        core_generation=owner.core_generation, core_source_generation=owner.core_source_generation,
        source_generation_sha256=current_master_source.generation_sha256,
        mode="master_read", execution_id=owner.owner_turn_handle,
        source_instance_id="hermes", mission_binding=None, selected_note_ids=None,
        issued_monotonic=issued, expires_monotonic=issued + 4, _seal=_SCOPE_SEAL)

    native_client = CoreNativeObservationClient()
    native_client._rpc = lambda operation, payload: registry._handle(peer, {
        "schema": 1, "op": operation, "nonce": "native-client",
        **dict(payload),
    })

    native_dispatch = NativeToolDispatch(
        object(), observed_read.tool_call_id, observed_read.tool_name,
        canonical_tool_arguments(read_args))
    native_handler = ObsidianNativeTools(object.__new__(ObsidianVaultStore)).handler(
        "obsidian_read_private_draft")
    with patch("hermes_installer.native_invocations.current_native_tool_dispatch",
               return_value=native_dispatch):
        with _admit_current_obsidian_call(
                observed_call=observed_read, scope=scope, binding=binding,
                observer_client=native_client):
            native_result = native_handler(read_args)

    active["classification"] = (read_call, owner, current_master_source, "master_read")
    altered_result = {**native_result, "markdown": "altered"}
    with pytest.raises(ValueError, match="native result differs"):
        native_client.confirm_obsidian_draft_read_delivery(
            observed_call=observed_read, binding=binding, tool_result=altered_result)
    native_client.confirm_obsidian_draft_read_delivery(
        observed_call=observed_read, binding=binding, tool_result=native_result)

    # The old startup binding has expired, while its receipt remains eligible
    # as provenance data under a new binding with the same process/custody facts.
    startup_binding["expiry"] = time.monotonic() - 1
    fresh_startup = {**startup_binding, "binding_id": "N" * 43,
                     "expiry": time.monotonic() + 20}
    startup_bindings[fresh_startup["binding_id"]] = fresh_startup
    active["classification"] = (promote_call, owner, current_master_source, "master_effect")
    from hermes_installer.remote.jarvis_final_effects import review_digest
    registry._final_effect_ledger = lambda: SimpleNamespace(issue_pending=lambda **values:
        SimpleNamespace(pending_id="P" * 43,
            review_sha256=values["review_sha256"], expires_monotonic=time.monotonic() + 15))
    promotion_review_sha = review_digest(
        promote_call["tool_name"], hashlib.sha256(promote_call["arguments"]).hexdigest())
    request_result = registry._handle(peer, {
        "schema": 1, "op": "request-final-effect", "nonce": "proposal-request",
        "observed_call_handle": promote_call["handle"],
        "review_sha256": promotion_review_sha, "startup_binding_id": "N" * 43,
    })
    assert request_result["ok"] is True
    proposal = registry._obsidian_draft_review_proposals[promote_call["handle"]]
    assert proposal["read_delivery_receipt_id"] == native_result["read_delivery"]["receipt_id"]
    assert proposal["read_delivery_output_sha256"] == hashlib.sha256(
        observer._canonical(native_result)).hexdigest()
    assert proposal["origin_record_sha256"] == active["persisted"][(owner_sha, draft_id)]["origin_record_sha256"]
    assert proposal["disposition"] == "approve"

    changed_facts = {**fresh_startup, "core_start_ticks": "changed-start"}
    startup_bindings[changed_facts["binding_id"]] = changed_facts
    changed_fact_call = dict(promote_call, handle="W" * 43)
    active["classification"] = (
        changed_fact_call, owner, current_master_source, "master_effect")
    with pytest.raises(ValueError, match="complete draft bytes were not delivered"):
        registry._propose_obsidian_draft_review(
            call=changed_fact_call, owner=owner, source=current_master_source, peer=peer,
            startup_binding_id="N" * 43)
    startup_bindings["N" * 43] = fresh_startup

    confirmed_receipt_id = native_result["read_delivery"]["receipt_id"]
    registry._obsidian_draft_read_deliveries[confirmed_receipt_id]["complete"] = False
    registry._obsidian_draft_read_deliveries[confirmed_receipt_id]["covered_byte_length"] = 0
    changed_promote = dict(promote_call, handle="Q" * 43)
    active["classification"] = (changed_promote, owner, current_master_source, "master_effect")
    with pytest.raises(ValueError, match="complete draft bytes were not delivered"):
        registry._propose_obsidian_draft_review(
            call=changed_promote, owner=owner, source=current_master_source, peer=peer,
            startup_binding_id="N" * 43)

    changed_args = {**read_args, "expected_draft_sha256": "9" * 64}
    changed_call = {**read_call, "handle": "Z" * 43,
                    "arguments": observer._canonical(changed_args)}
    active["classification"] = (changed_call, owner, current_master_source, "master_read")
    with pytest.raises(ValueError, match="retained pending private origin"):
        registry._handle(peer, {
            "schema": 1, "op": "read-obsidian-private-draft", "nonce": "digest-denied",
            "observed_call_handle": changed_call["handle"],
            "startup_binding_id": "N" * 43, "draft_id": draft_id,
            "expected_content_sha256": "9" * 64,
        })

    expert_read = dict(read_call, handle="X" * 43)
    active["classification"] = (expert_read, owner, child, "expert_read")
    with pytest.raises(ValueError, match="only the current Jarvis master read"):
        registry._handle(peer, {
            "schema": 1, "op": "read-obsidian-private-draft", "nonce": "expert-read-denied",
            "observed_call_handle": expert_read["handle"],
            "startup_binding_id": "N" * 43, "draft_id": draft_id,
            "expected_content_sha256": content_sha,
        })


    promote_args = {"draft_id": draft_id, "expected_draft_sha256": content_sha,
                    "destination": "Notes/Expert.md", "expected_base_sha256": None,
                    "review_disposition": "approve"}
    promote_call = {"handle": "P" * 43, "tool_name": "obsidian_promote_reviewed_draft",
                    "arguments": observer._canonical(promote_args),
                    "expiry": time.monotonic() + 20}
    active["classification"] = (promote_call, owner, current_master_source, "master_effect")
    resolved = registry._handle(peer, {
        "schema": 1, "op": "resolve-obsidian-draft-origin", "nonce": "resolve",
        "observed_call_handle": promote_call["handle"],
        "startup_binding_id": "N" * 43, "draft_id": draft_id,
        "expected_content_sha256": content_sha,
    })
    assert resolved["ok"] is True
    assert resolved["origin_execution_id"] == child["session_id"]
    assert resolved["origin_source_id"] == child["profile_id"]
    assert resolved["source_generation_sha256"] == generation
    assert resolved["source_generation_sha256"] != current_master_source.generation_sha256

    with pytest.raises(ValueError, match="replayed"):
        registry._handle(peer, {
            "schema": 1, "op": "resolve-obsidian-draft-origin", "nonce": "replay",
            "observed_call_handle": promote_call["handle"],
            "startup_binding_id": "N" * 43, "draft_id": draft_id,
            "expected_content_sha256": content_sha,
        })

    expert_promote = dict(promote_call, handle="X" * 43)
    active["classification"] = (expert_promote, owner, child, "expert_read")
    with pytest.raises(ValueError, match="only the current Jarvis owner promotion"):
        registry._handle(peer, {
            "schema": 1, "op": "resolve-obsidian-draft-origin", "nonce": "expert-denied",
            "observed_call_handle": expert_promote["handle"],
            "startup_binding_id": "N" * 43, "draft_id": draft_id,
            "expected_content_sha256": content_sha,
        })


def test_obsidian_read_delivery_client_uses_allowlisted_protocol_transport(monkeypatch):
    """Exercise the real public client method, framing, allowlist, and response decoder."""
    import json
    import os
    import stat
    import struct
    import time
    from types import SimpleNamespace

    import hermes_installer.remote.core_native_observer as observer
    from hermes_installer.remote.obsidian_native_scope import (
        RootSelectedObsidianVaultBinding, _BINDING_SEAL,
    )

    observed = ObservedNativeToolCall(
        handle="H" * 43, attempt_handle="A" * 43, owner_turn_handle="T" * 43,
        tool_call_id="draft-read", tool_name="obsidian_read_private_draft",
        arguments_sha256="a" * 64, expires_monotonic=time.monotonic() + 20)
    now = time.monotonic()
    binding = RootSelectedObsidianVaultBinding(
        binding_id="B" * 43, registration_sha256="b" * 64,
        owner_subject_sha256="c" * 64, core_generation="d" * 64,
        core_source_generation="e" * 64, core_pid=os.getpid(),
        core_start_ticks="987", selected_owner_uid=os.geteuid(),
        vault_root="/home/admin/.hermes/jarvis-second-brain",
        issued_monotonic=now, expires_monotonic=now + 20, _seal=_BINDING_SEAL)
    returned = {"receipt_id": "R" * 43, "receipt_sha256": "f" * 64,
                "complete": True, "covered_byte_length": 3}
    exchange = {}

    class Transport:
        def __init__(self, *_args):
            self.incoming = bytearray()

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def settimeout(self, _timeout):
            pass

        def connect(self, _path):
            pass

        def getsockopt(self, *_args):
            return struct.pack("3i", 999, 0, 1000)

        def sendall(self, payload):
            size = struct.unpack("!I", payload[:4])[0]
            request = json.loads(payload[4:4 + size])
            exchange.setdefault("requests", []).append(request)
            if request["op"] == "confirm-obsidian-draft-read-delivery":
                response = {"schema": 1, "nonce": request["nonce"], "ok": True,
                            "confirmed": True, "receipt_sha256": returned["receipt_sha256"]}
            else:
                response = {"schema": 1, "nonce": request["nonce"], "ok": True,
                    "pending_id": "P" * 43, "review_sha256": request["review_sha256"],
                    "expires_monotonic": time.monotonic() + 20}
            raw = json.dumps(response, separators=(",", ":")).encode()
            self.incoming.extend(struct.pack("!I", len(raw)) + raw)

        def recv(self, size):
            result = bytes(self.incoming[:size])
            del self.incoming[:size]
            return result

    socket_path = Path("/run/hermes-jarvis-native-observer/native-observer.sock")
    real_lstat = Path.lstat

    def lstat(path):
        if path == socket_path.parent:
            return SimpleNamespace(st_mode=stat.S_IFDIR | 0o750, st_uid=0, st_gid=1000)
        if path == socket_path:
            return SimpleNamespace(st_mode=stat.S_IFSOCK | 0o660, st_uid=0, st_gid=1000)
        return real_lstat(path)

    monkeypatch.setattr(Path, "lstat", lstat)
    monkeypatch.setattr(observer.socket, "socket", Transport)
    monkeypatch.setattr(observer.os, "getgroups", lambda: [1000])
    client = CoreNativeObservationClient(socket_path=socket_path)
    result = {"draft_id": "D" * 43, "byte_length": 3, "review_complete": True,
              "read_delivery": returned}
    client.confirm_obsidian_draft_read_delivery(
        observed_call=observed, binding=binding, tool_result=result)
    confirmation = exchange["requests"][0]
    assert confirmation["op"] == "confirm-obsidian-draft-read-delivery"
    assert confirmation["receipt_id"] == returned["receipt_id"]
    import hashlib
    assert confirmation["tool_result_sha256"] == hashlib.sha256(
        json.dumps(result, ensure_ascii=False, sort_keys=True,
                   separators=(",", ":"), allow_nan=False).encode()).hexdigest()
    client.request_final_effect(
        observed_call_handle=observed.handle, review_sha256="9" * 64,
        startup_binding_id=binding.binding_id)
    approval_request = exchange["requests"][1]
    assert approval_request["op"] == "request-final-effect"
    assert approval_request["startup_binding_id"] == binding.binding_id

    incomplete = {**result, "title": "Large draft", "markdown": None,
        "content_sha256": "a" * 64, "byte_length": 32_769,
        "review_complete": False,
        "next_step": "Use the owner draft review flow to reduce the draft before Jarvis reviews it.",
        "read_delivery": {"receipt_id": returned["receipt_id"],
            "receipt_sha256": returned["receipt_sha256"], "complete": False,
            "covered_byte_length": 0}}
    client.confirm_obsidian_draft_read_delivery(
        observed_call=observed, binding=binding, tool_result=incomplete)
    assert exchange["requests"][2]["op"] == "confirm-obsidian-draft-read-delivery"
    assert exchange["requests"][2]["tool_result_sha256"] == hashlib.sha256(
        json.dumps(incomplete, ensure_ascii=False, sort_keys=True,
                   separators=(",", ":"), allow_nan=False).encode()).hexdigest()


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
