"""Closed-cohort startup-chat seam contracts; this is not Pi acceptance evidence."""
from __future__ import annotations

import hashlib
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

import hermes_installer.remote.core_native_observer as observer
from hermes_installer.remote.core_lifecycle_startup import register_lifecycle_startup_probe


def _cohort(**overrides):
    now = time.monotonic()
    values = {
        "transaction_id": "transaction-1",
        "starting_journal_sha256": "1" * 64,
        "cohort_sha256": "2" * 64,
        "core_generation": "3" * 64,
        "old_adapter_generation": "4" * 64,
        "new_adapter_generation": "5" * 64,
        "core_source_generation": "6" * 64,
        "generation_a1_sha256": "7" * 64,
        "js_sha256": "8" * 64,
        "rs_sha256": "9" * 64,
        "u1_sha256": "a" * 64,
        "l1_sha256": "b" * 64,
        "primary_source_sha256": "c" * 64,
        "active_soul_sha256": "d" * 64,
        "native_inventory_sha256": "e" * 64,
        "peer_pid": 411,
        "peer_uid": 1000,
        "peer_gid": 1000,
        "peer_start_ticks": "12345",
        "boot_id": "11111111-2222-3333-4444-555555555555",
        "invocation_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        "provider": observer._CODEX_PROVIDER,
        "api_mode": observer._CODEX_MODE,
        "base_url": observer._CODEX_ENDPOINT,
        "model": "gpt-6-luna",
        "account_fingerprint": "f" * 64,
        "issued_monotonic": now,
        "deadline_monotonic": now + 60,
    }
    values.update(overrides)
    return observer.make_root_lifecycle_startup_cohort(**values)


def _registry_for_probe(cohort, monkeypatch):
    registry = object.__new__(observer.RootCoreNativeObservationRegistry)
    registry._closed = False
    registry._config = object()
    registry._lock = threading.RLock()
    registry._lifecycle_startup_probes = {}
    registry._lifecycle_startup_attempts = {}
    monkeypatch.setattr(registry, "_prune", lambda _now: None)
    monkeypatch.setattr(registry, "_ensure_open", lambda: None)
    monkeypatch.setattr(registry, "_lifecycle_startup_peer_current",
                        lambda row, _cohort: row.get("current") is True)
    return registry


def _enrolled_row(cohort, *, handle="P" * 43, peer=(411, 1000, 1000)):
    nonce = "0123456789abcdef0123456789abcdef"
    return {
        "cohort": cohort, "pidfd": -1, "probe_id": "probe-1", "session_id": "session-1",
        "nonce": nonce,
        "expected_text_sha256": hashlib.sha256(
            (observer._LIFECYCLE_STARTUP_PROMPT_PREFIX + nonce).encode("ascii")).hexdigest(),
        "expiry": cohort.deadline_monotonic, "claimed_peer": None,
        "attempt_handle": None, "completion_handle": None, "consumed": False,
        "current": True, "test_handle": handle, "test_peer": peer,
    }


def test_lifecycle_handler_registers_only_the_fixed_method_and_rejects_extra_params():
    class Server:
        def __init__(self):
            self.rows = []

        def register_method(self, name, handler):
            self.rows.append((name, handler))

        @staticmethod
        def _ok(rid, result):
            return {"jsonrpc": "2.0", "id": rid, "result": result}

    server = Server()
    client = observer.CoreNativeObservationClient(socket_path=Path("/unused"))
    client.claim_lifecycle_startup_probe = lambda _handle: pytest.fail(
        "malformed RPC must be rejected before claim")
    register_lifecycle_startup_probe(server, client=client)
    assert [name for name, _handler in server.rows] == ["jarvis.lifecycle_startup_probe"]
    with pytest.raises(observer.CoreNativeObservationUnavailable):
        server.rows[0][1]("request-1", {"probe_handle": "P" * 43, "prompt": "caller controlled"})


def test_root_probe_claim_is_current_peer_only_and_single_use(monkeypatch):
    cohort = _cohort()
    registry = _registry_for_probe(cohort, monkeypatch)
    handle = "P" * 43
    row = _enrolled_row(cohort, handle=handle)
    registry._lifecycle_startup_probes[handle] = row

    with pytest.raises(ValueError, match="unavailable to this native peer"):
        registry._handle((412, 1000, 1000), {
            "schema": 1, "op": "claim-lifecycle-startup-probe", "nonce": "n",
            "probe_handle": handle,
        })
    assert row["claimed_peer"] is None

    claimed = registry._handle((411, 1000, 1000), {
        "schema": 1, "op": "claim-lifecycle-startup-probe", "nonce": "n",
        "probe_handle": handle,
    })
    assert claimed["ok"] is True and claimed["active_soul_sha256"] == cohort.active_soul_sha256
    assert claimed["native_inventory_sha256"] == cohort.native_inventory_sha256
    with pytest.raises(ValueError, match="unavailable to this native peer"):
        registry._handle((411, 1000, 1000), {
            "schema": 1, "op": "claim-lifecycle-startup-probe", "nonce": "n2",
            "probe_handle": handle,
        })


def test_root_completion_seals_actual_codex_terminal_and_rejects_tool_use_replay(monkeypatch):
    cohort = _cohort()
    registry = _registry_for_probe(cohort, monkeypatch)
    handle = "P" * 43
    peer = (cohort.peer_pid, cohort.peer_uid, cohort.peer_gid)
    row = _enrolled_row(cohort, handle=handle, peer=peer)
    row["claimed_peer"] = peer
    registry._lifecycle_startup_probes[handle] = row
    prompt_sha = hashlib.sha256((observer._LIFECYCLE_STARTUP_PROMPT_PREFIX + row["nonce"]
                                 + observer._LIFECYCLE_STARTUP_PROMPT_SUFFIX).encode("ascii")).hexdigest()
    attempt_request = {
        "schema": 1, "op": "register-lifecycle-startup-attempt", "nonce": "attempt",
        "probe_handle": handle, "probe_id": row["probe_id"], "session_id": row["session_id"],
        "turn_id": "turn-1", "api_request_id": "api-1", "provider": cohort.provider,
        "api_mode": cohort.api_mode, "base_url": cohort.base_url, "model": cohort.model,
        "account_fingerprint": cohort.account_fingerprint, "request_sha256": "a" * 64,
        "prompt_sha256": prompt_sha, "tool_names": [], "retry_count": 0,
    }
    forged = dict(attempt_request, tool_names=["terminal"])
    with pytest.raises(ValueError, match="provider attempt differs"):
        registry._handle(peer, forged)
    assert row["attempt_handle"] is None

    attempt = registry._handle(peer, attempt_request)
    attempt_handle = attempt["attempt_handle"]
    text = observer._LIFECYCLE_STARTUP_PROMPT_PREFIX + row["nonce"]
    text_sha = hashlib.sha256(text.encode()).hexdigest()
    completion = registry._handle(peer, {
        "schema": 1, "op": "register-lifecycle-startup-response", "nonce": "response",
        "probe_handle": handle, "attempt_handle": attempt_handle,
        "turn_id": "turn-1", "api_request_id": "api-1", "request_sha256": "a" * 64,
        "response_sha256": "b" * 64, "response_text": text,
        "response_text_sha256": text_sha, "completed": True, "tool_call_count": 0,
    })
    proof = registry.consume_lifecycle_startup_completion(
        probe_handle=handle, completion_handle=completion["completion_handle"],
        native_response_sha256=text_sha)
    assert type(proof) is observer.CoreVerifiedLifecycleStartupCompletion
    assert proof.is_root_verified()
    assert (proof.core_generation, proof.old_adapter_generation, proof.new_adapter_generation,
            proof.js_sha256, proof.rs_sha256, proof.u1_sha256, proof.l1_sha256,
            proof.generation_a1_sha256) == (
                cohort.core_generation, cohort.old_adapter_generation, cohort.new_adapter_generation,
                cohort.js_sha256, cohort.rs_sha256, cohort.u1_sha256, cohort.l1_sha256,
                cohort.generation_a1_sha256)
    assert (proof.schema, proof.purpose, proof.provider, proof.api_mode, proof.base_url,
            proof.boot_id, proof.peer_uid, proof.peer_gid, proof.prompt_sha256) == (
                1, "lifecycle-startup", cohort.provider, cohort.api_mode, cohort.base_url,
                cohort.boot_id, cohort.peer_uid, cohort.peer_gid, prompt_sha)
    with pytest.raises(observer.CoreNativeObservationUnavailable, match="replayed"):
        registry.consume_lifecycle_startup_completion(
            probe_handle=handle, completion_handle=completion["completion_handle"],
            native_response_sha256=text_sha)


def test_root_completion_rejects_native_response_mismatch_and_expired_cohort(monkeypatch):
    cohort = _cohort()
    registry = _registry_for_probe(cohort, monkeypatch)
    handle = "P" * 43
    peer = (cohort.peer_pid, cohort.peer_uid, cohort.peer_gid)
    row = _enrolled_row(cohort, handle=handle, peer=peer)
    row.update({"claimed_peer": peer, "completion_handle": "C" * 43,
        "provider_terminal": {"turn_id": "turn-1", "api_request_id": "api-1",
            "request_sha256": "a" * 64, "response_sha256": "b" * 64,
            "prompt_sha256": "d" * 64, "response_text_sha256": "c" * 64}})
    registry._lifecycle_startup_probes[handle] = row
    with pytest.raises(observer.CoreNativeObservationUnavailable, match="mismatched"):
        registry.consume_lifecycle_startup_completion(
            probe_handle=handle, completion_handle="C" * 43,
            native_response_sha256="d" * 64)
    row["expiry"] = time.monotonic() - 1
    with pytest.raises(observer.CoreNativeObservationUnavailable, match="stale"):
        registry.consume_lifecycle_startup_completion(
            probe_handle=handle, completion_handle="C" * 43,
            native_response_sha256="c" * 64)


def test_lifecycle_llm_observer_consumes_exact_no_tool_terminal_once(monkeypatch, tmp_path):
    cohort = _cohort()
    context = observer.LifecycleStartupProbeContext(
        probe_handle="P" * 43, probe_id="probe-1", session_id="session-1",
        nonce="0123456789abcdef0123456789abcdef",
        deadline_monotonic=cohort.deadline_monotonic,
        cohort_sha256=cohort.cohort_sha256, core_generation=cohort.core_generation,
        core_source_generation=cohort.core_source_generation,
        generation_a1_sha256=cohort.generation_a1_sha256, js_sha256=cohort.js_sha256,
        rs_sha256=cohort.rs_sha256, u1_sha256=cohort.u1_sha256,
        l1_sha256=cohort.l1_sha256, primary_source_sha256=cohort.primary_source_sha256,
        active_soul_sha256=cohort.active_soul_sha256,
        native_inventory_sha256=cohort.native_inventory_sha256,
        provider=cohort.provider, api_mode=cohort.api_mode, base_url=cohort.base_url,
        model=cohort.model, account_fingerprint=cohort.account_fingerprint,
        _seal=observer._LIFECYCLE_STARTUP_CONTEXT_SEAL,
    )
    client = observer.CoreNativeObservationClient(socket_path=tmp_path / "unused.sock")
    monkeypatch.setattr(observer, "_codex_account_fingerprint",
                        lambda _resolver: cohort.account_fingerprint)
    attempt_calls = []
    terminal_calls = []

    def register_attempt(_context, **kwargs):
        attempt_calls.append(kwargs)
        return "A" * 43

    def register_terminal(_context, **kwargs):
        terminal_calls.append(kwargs)
        return "C" * 43

    client.register_lifecycle_startup_attempt = register_attempt
    client.register_lifecycle_startup_response = register_terminal
    context_manager = observer.lifecycle_startup_probe_scope(
        context, identity="Selected Jarvis identity", expected_instructions=
        "Fixed native Hermes system prompt\nSelected Jarvis identity")
    class PluginContext:
        def __init__(self):
            self.middleware = {}

        def register_middleware(self, name, callback):
            self.middleware.setdefault(name, []).append(callback)
            return callback

    ctx = PluginContext()
    observer.install_native_codex_process_observer(ctx, client=client)
    callback = ctx.middleware["llm_execution"][0]
    prompt = (observer._LIFECYCLE_STARTUP_PROMPT_PREFIX + context.nonce
              + observer._LIFECYCLE_STARTUP_PROMPT_SUFFIX)
    request = {
        "instructions": "Fixed native Hermes system prompt\nSelected Jarvis identity",
        "input": [{"type": "message", "role": "user", "content": [
            {"type": "input_text", "text": prompt}]}],
        "tools": [], "tool_choice": "none",
    }
    provider_text = observer._LIFECYCLE_STARTUP_PROMPT_PREFIX + context.nonce
    response = SimpleNamespace(
        status="completed", error=None, incomplete_details=None, output_text=provider_text,
        output=[], model_dump=lambda **_kwargs: {"status": "completed", "output_text": provider_text},
    )
    seen = []
    with context_manager:
        observed = callback(
            provider=cohort.provider, api_mode=cohort.api_mode, base_url=cohort.base_url,
            model=cohort.model, request=request, session_id=context.session_id,
            turn_id="turn-1", api_request_id="api-1",
            next_call=lambda value: seen.append(value) or response,
        )
        assert observed is response
        assert len(seen) == 1 and seen[0]["tool_choice"] == "none" and seen[0]["tools"] == []
        assert len(attempt_calls) == len(terminal_calls) == 1
        terminal = observer.take_lifecycle_startup_terminal(context)
        assert terminal["completion_handle"] == "C" * 43

        altered = dict(request, tools=[{"name": "terminal"}])
        denied_seen = []
        denied = callback(
            provider=cohort.provider, api_mode=cohort.api_mode, base_url=cohort.base_url,
            model=cohort.model, request=altered, session_id=context.session_id,
            turn_id="turn-2", api_request_id="api-2",
            next_call=lambda value: denied_seen.append(value) or response,
        )
        assert denied.status == "completed" and denied_seen == []
        assert len(attempt_calls) == len(terminal_calls) == 1
