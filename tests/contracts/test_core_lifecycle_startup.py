"""Closed-cohort startup-chat seam contracts; this is not Pi acceptance evidence."""
from __future__ import annotations

import hashlib
import os
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

import hermes_installer.core_runtime as core_runtime
import hermes_installer.remote.core_native_observer as observer
import hermes_installer.remote.core_lifecycle_startup as lifecycle_startup
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


def _root_cli_registry_for_probe(cohort, monkeypatch):
    from types import SimpleNamespace

    registry = object.__new__(observer.RootLifecycleNativeObservationRegistry)
    registry._custody = SimpleNamespace(cohort=cohort,
                                        expires_monotonic=cohort.deadline_monotonic)
    registry._cohort = cohort
    registry._pidfd = -1
    registry._lock = threading.RLock()
    registry._closed = False
    registry._lifecycle_startup_probes = {}
    registry._lifecycle_startup_attempts = {}
    monkeypatch.setattr(registry, "_custody_current", lambda: True)
    return registry


@pytest.mark.skipif(os.geteuid() != 0 or not hasattr(os, "pidfd_open"),
                    reason="Root lifecycle registry requires the Root actor and Linux pidfds")
def test_root_lifecycle_registry_uses_live_pidfd_and_refuses_exited_peer(monkeypatch):
    monkeypatch.setattr(core_runtime, "verify_starting_lifecycle_observer_custody",
                        lambda _custody: True)
    cohort = _cohort(peer_pid=os.getpid())
    live_fd = os.pidfd_open(os.getpid(), 0)
    live_custody = core_runtime.StartingLifecycleObserverCustody(
        cohort=cohort, peer_pid=cohort.peer_pid, peer_uid=cohort.peer_uid,
        peer_gid=cohort.peer_gid, peer_start_ticks=cohort.peer_start_ticks,
        boot_id=cohort.boot_id, invocation_id=cohort.invocation_id,
        pidfd=live_fd, expires_monotonic=cohort.deadline_monotonic,
        new_read=None, _seal=core_runtime._STARTING_LIFECYCLE_OBSERVER_SEAL)
    registry = None
    try:
        registry = observer.RootLifecycleNativeObservationRegistry.from_starting_custody(
            live_custody)
        assert registry._custody_current()
        assert os.fstat(live_fd).st_ino > 0  # the registry owns only its duplicate
    finally:
        if registry is not None:
            registry.close()
        os.close(live_fd)

    read_fd, write_fd = os.pipe()
    child = os.fork()
    if child == 0:
        os.close(write_fd)
        try:
            os.read(read_fd, 1)
        finally:
            os._exit(0)
    os.close(read_fd)
    exited_fd = None
    try:
        try:
            exited_fd = os.pidfd_open(child, 0)
        finally:
            os.write(write_fd, b"x")
    finally:
        os.close(write_fd)
        os.waitpid(child, 0)
    exited_cohort = _cohort(peer_pid=child)
    exited_custody = core_runtime.StartingLifecycleObserverCustody(
        cohort=exited_cohort, peer_pid=exited_cohort.peer_pid,
        peer_uid=exited_cohort.peer_uid, peer_gid=exited_cohort.peer_gid,
        peer_start_ticks=exited_cohort.peer_start_ticks, boot_id=exited_cohort.boot_id,
        invocation_id=exited_cohort.invocation_id, pidfd=exited_fd,
        expires_monotonic=exited_cohort.deadline_monotonic, new_read=None,
        _seal=core_runtime._STARTING_LIFECYCLE_OBSERVER_SEAL)
    try:
        with pytest.raises(observer.CoreNativeObservationUnavailable,
                           match="Root starting lifecycle custody is unavailable"):
            observer.RootLifecycleNativeObservationRegistry.from_starting_custody(
                exited_custody)
        assert os.fstat(exited_fd).st_ino > 0
    finally:
        os.close(exited_fd)


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

        @staticmethod
        def _err(rid, code, message, data=None):
            error = {"code": code, "message": message}
            if data is not None:
                error["data"] = data
            return {"jsonrpc": "2.0", "id": rid, "error": error}

    server = Server()
    client = observer.CoreNativeObservationClient(socket_path=Path("/unused"))
    client.claim_lifecycle_startup_probe = lambda _handle: pytest.fail(
        "malformed RPC must be rejected before claim")
    register_lifecycle_startup_probe(server, client=client)
    assert [name for name, _handler in server.rows] == ["jarvis.lifecycle_startup_probe"]
    refusal = server.rows[0][1]("request-1", {
        "probe_handle": "P" * 43, "prompt": "caller controlled"})
    assert refusal == {
        "jsonrpc": "2.0", "id": "request-1", "error": {
            "code": -32000, "message": "lifecycle startup probe refused",
            "data": '{"exception_type":"CoreNativeObservationUnavailable","schema":1,"stage":"parameters"}',
        },
    }


@pytest.mark.parametrize("stage", sorted(lifecycle_startup._RPC_DIAGNOSTIC_STAGES))
def test_startup_refusal_emits_only_canonical_bounded_stage_and_type(monkeypatch, stage):
    class Server:
        def register_method(self, name, handler):
            self.handler = handler

        @staticmethod
        def _ok(rid, result):
            return {"jsonrpc": "2.0", "id": rid, "result": result}

        @staticmethod
        def _err(rid, code, message, data=None):
            return {"jsonrpc": "2.0", "id": rid, "error": {
                "code": code, "message": message, "data": data}}

    server = Server()
    client = observer.CoreNativeObservationClient(socket_path=Path("/unused"))

    def refuse(_params, *, client):
        raise lifecycle_startup._StartupProbeRefusal(stage, "RuntimeError")

    monkeypatch.setattr(lifecycle_startup, "_run_probe", refuse)
    register_lifecycle_startup_probe(server, client=client)
    result = server.handler("request-2", {"probe_handle": "P" * 43})
    error = result["error"]
    assert set(result) == {"jsonrpc", "id", "error"}
    assert set(error) == {"code", "message", "data"}
    assert error["code"] == -32000
    assert error["message"] == "lifecycle startup probe refused"
    assert error["data"] == lifecycle_startup._startup_refusal_data(stage, "RuntimeError")
    assert len(error["data"].encode("ascii")) <= 512


def test_lifecycle_handler_refuses_registration_without_pinned_error_seam():
    class Server:
        registered = False

        def register_method(self, _name, _handler):
            self.registered = True

        @staticmethod
        def _ok(rid, result):
            return {"jsonrpc": "2.0", "id": rid, "result": result}

    server = Server()
    client = observer.CoreNativeObservationClient(socket_path=Path("/unused"))
    with pytest.raises(observer.CoreNativeObservationUnavailable):
        register_lifecycle_startup_probe(server, client=client)
    assert server.registered is False


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


def test_root_cli_lifecycle_registry_is_separate_fixed_three_op_surface(monkeypatch):
    cohort = _cohort()
    registry = _root_cli_registry_for_probe(cohort, monkeypatch)
    handle = registry.enroll_lifecycle_startup_probe(cohort=cohort)
    peer = (cohort.peer_pid, cohort.peer_uid, cohort.peer_gid)

    with pytest.raises(ValueError, match="unsupported lifecycle observer operation"):
        registry._handle_lifecycle(peer, {
            "schema": 1, "op": "register-tool-call", "nonce": "n",
        })
    with pytest.raises(ValueError, match="unavailable to this native peer"):
        registry._handle_lifecycle((cohort.peer_pid + 1, cohort.peer_uid, cohort.peer_gid), {
            "schema": 1, "op": "claim-lifecycle-startup-probe", "nonce": "n",
            "probe_handle": handle,
        })
    assert registry._lifecycle_startup_probes[handle]["claimed_peer"] is None

    claimed = registry._handle_lifecycle(peer, {
        "schema": 1, "op": "claim-lifecycle-startup-probe", "nonce": "n",
        "probe_handle": handle,
    })
    assert claimed["ok"] is True
    with pytest.raises(ValueError, match="unavailable to this native peer"):
        registry._handle_lifecycle(peer, {
            "schema": 1, "op": "claim-lifecycle-startup-probe", "nonce": "replay",
            "probe_handle": handle,
        })

    row = registry._lifecycle_startup_probes[handle]
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
    with pytest.raises(ValueError, match="provider attempt differs"):
        registry._handle_lifecycle(peer, dict(attempt_request, tool_names=["terminal"]))
    attempt = registry._handle_lifecycle(peer, attempt_request)
    text = observer._LIFECYCLE_STARTUP_PROMPT_PREFIX + row["nonce"]
    text_sha = hashlib.sha256(text.encode("utf-8")).hexdigest()
    completed = registry._handle_lifecycle(peer, {
        "schema": 1, "op": "register-lifecycle-startup-response", "nonce": "response",
        "probe_handle": handle, "attempt_handle": attempt["attempt_handle"],
        "turn_id": "turn-1", "api_request_id": "api-1", "request_sha256": "a" * 64,
        "response_sha256": "b" * 64, "response_text": text,
        "response_text_sha256": text_sha, "completed": True, "tool_call_count": 0,
    })
    proof = registry.consume_lifecycle_startup_completion(
        probe_handle=handle, completion_handle=completed["completion_handle"],
        native_response_sha256=text_sha)
    assert type(proof) is observer.CoreVerifiedLifecycleStartupCompletion
    assert proof.is_root_verified()
    assert (proof.new_adapter_generation, proof.core_source_generation, proof.generation_a1_sha256,
            proof.js_sha256, proof.rs_sha256, proof.u1_sha256, proof.l1_sha256) == (
                cohort.new_adapter_generation, cohort.core_source_generation,
                cohort.generation_a1_sha256, cohort.js_sha256, cohort.rs_sha256,
                cohort.u1_sha256, cohort.l1_sha256)
    with pytest.raises(observer.CoreNativeObservationUnavailable, match="replayed"):
        registry.consume_lifecycle_startup_completion(
            probe_handle=handle, completion_handle=completed["completion_handle"],
            native_response_sha256=text_sha)
    monkeypatch.setattr(registry, "_custody_current", lambda: False)
    with pytest.raises(PermissionError, match="no longer current"):
        registry._handle_lifecycle(peer, {
            "schema": 1, "op": "claim-lifecycle-startup-probe", "nonce": "stale",
            "probe_handle": handle,
        })


def test_native_client_selects_lifecycle_socket_only_for_three_fixed_ops(tmp_path):
    client = observer.CoreNativeObservationClient(socket_path=tmp_path / "ordinary.sock")
    lifecycle = observer.LIFECYCLE_NATIVE_OBSERVER_SOCKET
    assert client._socket_for_operation("claim-lifecycle-startup-probe") == lifecycle
    assert client._socket_for_operation("register-lifecycle-startup-attempt") == lifecycle
    assert client._socket_for_operation("register-lifecycle-startup-response") == lifecycle
    assert client._socket_for_operation("register-attempt") == tmp_path / "ordinary.sock"
    assert client._socket_for_operation("register-tool-call") == tmp_path / "ordinary.sock"


def test_root_cli_lifecycle_server_preserves_foreign_socket_and_cleans_its_inode(
        tmp_path, monkeypatch):
    if os.geteuid() != 0:
        pytest.skip("Root-owned lifecycle socket fixture requires the Pi root test runner")
    runtime = tmp_path / "lifecycle-runtime"
    runtime.mkdir()
    os.chown(runtime, 0, 1000)
    os.chmod(runtime, 0o750)
    lifecycle_socket = runtime / "lifecycle-observer.sock"
    owner_record = runtime / "lifecycle-observer.owner.json"
    lock_file = runtime / "lifecycle-observer.lock"
    ordinary_socket = tmp_path / "ordinary-observer.sock"
    ordinary_socket.write_bytes(b"preserve")
    monkeypatch.setattr(observer, "LIFECYCLE_NATIVE_OBSERVER_SOCKET", lifecycle_socket)
    monkeypatch.setattr(observer, "_LIFECYCLE_NATIVE_OBSERVER_OWNER", owner_record)
    monkeypatch.setattr(observer, "_LIFECYCLE_NATIVE_OBSERVER_LOCK", lock_file)
    monkeypatch.setattr(observer, "_CORE_NATIVE_OBSERVER_GROUP", 1000)

    registry = object.__new__(observer.RootLifecycleNativeObservationRegistry)
    registry.close = lambda: None
    foreign = lifecycle_socket
    foreign.write_bytes(b"foreign path")
    denied = observer.RootLifecycleNativeObservationServer(registry)
    denied.start()
    assert denied.wait_ready(timeout=3.0) is False
    denied.close()
    assert foreign.read_bytes() == b"foreign path"
    assert ordinary_socket.read_bytes() == b"preserve"

    foreign.unlink()
    server = observer.RootLifecycleNativeObservationServer(registry)
    server.start()
    assert server.wait_ready(timeout=3.0) is True
    owned = lifecycle_socket.lstat()
    assert owned.st_uid == 0 and owned.st_gid == 1000
    assert (owned.st_mode & 0o777) == 0o660
    record, identity = observer.RootLifecycleNativeObservationServer._read_owner_record()
    assert record["socket_dev"] == owned.st_dev and record["socket_ino"] == owned.st_ino
    owner_before_close = owner_record.lstat()
    server.close()
    assert not lifecycle_socket.exists()
    assert not owner_record.exists()
    assert (owner_before_close.st_dev, owner_before_close.st_ino) == identity
    assert ordinary_socket.read_bytes() == b"preserve"


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
