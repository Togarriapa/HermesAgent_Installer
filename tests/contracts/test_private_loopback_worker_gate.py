"""Controlled contracts and genuine local socket effects for the fixed gate."""
from __future__ import annotations

import importlib.util
import multiprocessing
import os
import select
import signal
import socket
import struct
import json
import secrets
from unittest import mock
from pathlib import Path


_HELPER_PATH = Path(__file__).resolve().parents[2] / "helpers" / "private-loopback-worker-gate.py"
_SPEC = importlib.util.spec_from_file_location("private_loopback_worker_gate_helper", _HELPER_PATH)
assert _SPEC is not None and _SPEC.loader is not None
_HELPER = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_HELPER)


def _free_port() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]
    finally:
        sock.close()


def _contract(allowed: int, denied: int) -> dict[str, object]:
    return {
        "schema": 1,
        "purpose": "private-loopback-worker-start",
        "nonce": "a" * 32,
        "network_id": "network-fixture",
        "service_generation_digest": "b" * 64,
        "enrollment_id": "worker-fixture",
        "profile_id": "profile-fixture",
        "generation": "generation-fixture",
        "uid": 1000,
        "gid": 1000,
        "namespace_inode": 1,
        "role": "listener",
        "allowed_bind_port": allowed,
        "allowed_connect_port": None,
        "denied_port": denied,
        "application_executable": "/usr/bin/example",
        "application_argv": ["/usr/bin/example"],
        "application_environment": {"PATH": "/usr/bin:/bin"},
    }


def _test_authority_endpoint(tmp_path: Path, monkeypatch):
    path = Path("/tmp") / f"hpg-{os.getpid()}-{secrets.token_hex(4)}.sock"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(path))
    listener.listen(4)
    monkeypatch.setattr(_HELPER, "_selected_authority_socket", lambda _uid: str(path))
    return listener


def _probe_child(allowed: int, denied: int, result_queue) -> None:
    checks, state = _HELPER._probe(_contract(allowed, denied))
    result_queue.put((os.getpid(), checks, state))


def test_live_worker_probe_reports_unsupported_effects_instead_of_authorizing_start(tmp_path, monkeypatch):
    """Run real local bind attempts; a successful forbidden bind is not a pass."""
    endpoint = _test_authority_endpoint(tmp_path, monkeypatch)
    allowed, denied = _free_port(), _free_port()
    while denied == allowed:
        denied = _free_port()
    context = multiprocessing.get_context("fork")
    result_queue = context.Queue(maxsize=1)
    child = context.Process(target=_probe_child, args=(allowed, denied, result_queue))
    child.start()
    child_pid, checks, state = result_queue.get(timeout=3)
    child.join(timeout=3)
    assert child.exitcode == 0
    assert child_pid == child.pid and child_pid != os.getpid()

    # The allowed control must be a real successful bind, and the wrong-port
    # result must be the actual kernel errno/outcome. The helper's readiness
    # classification is recomputed from those observations, never from fixture
    # properties or caller-supplied status text.
    assert checks["allowed_bind"] == {"outcome": "bound", "errno": None}
    assert checks["af_unix_control"] == {"outcome": "connected", "errno": None}
    denied_probe = checks["wrong_port_bind"]
    assert denied_probe["outcome"] in {"bound", "error"}
    if denied_probe["outcome"] == "error":
        assert type(denied_probe["errno"]) is int
    expected_denials = {1, 13}  # EPERM/EACCES on Linux.
    actual_denials = all(
        checks[name]["outcome"] == "error" and checks[name]["errno"] in expected_denials
        for name in ("wrong_port_bind", "ipv6_bind", "wildcard_bind")
    )
    assert (state == "ready") is actual_denials
    if denied_probe["outcome"] == "bound":
        assert state == "unsupported"
    endpoint.close()


def test_actual_gate_runner_never_executes_after_observed_unsupported_bind_policy(tmp_path, monkeypatch):
    """Drive main() with real socket probes and assert its unsupported branch."""
    endpoint = _test_authority_endpoint(tmp_path, monkeypatch)
    allowed, denied = _free_port(), _free_port()
    while denied == allowed:
        denied = _free_port()
    contract = _contract(allowed, denied)
    raw = json.dumps(contract, sort_keys=True, separators=(",", ":"),
                     ensure_ascii=True).encode("ascii")
    digest = __import__("hashlib").sha256(raw).hexdigest()
    real_checks, real_state = _HELPER._probe(contract)
    assert all(name in real_checks for name in (
        "wrong_port_bind", "ipv6_bind", "wildcard_bind", "af_unix_control"))
    assert real_checks["allowed_bind"] == {"outcome": "bound", "errno": None}

    manager, worker = __import__("socket").socketpair(__import__("socket").AF_UNIX,
                                                       __import__("socket").SOCK_STREAM)
    await_root_release = _HELPER._await_root_release
    emitted = []
    exec_calls = []

    def issue_real_one_use_grant(channel, *, nonce, contract_sha256):
        grant = {
            "schema": 1, "purpose": "private-loopback-worker-release",
            "nonce": nonce, "contract_sha256": contract_sha256, "decision": "release",
        }
        encoded = json.dumps(grant, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=True).encode("ascii")
        manager.sendall(struct.pack("!I", len(encoded)) + encoded)
        return await_root_release(channel, nonce=nonce,
                                  contract_sha256=contract_sha256)

    try:
        with mock.patch.object(_HELPER.sys, "argv", ["private-loopback-worker-gate"]), \
             mock.patch.object(_HELPER, "_read_contract", return_value=(contract, digest)), \
             mock.patch.object(_HELPER, "_self_identity", return_value={"pid": os.getpid()}), \
             mock.patch.object(_HELPER, "_gate_channel_from_activation", return_value=worker), \
             mock.patch.object(_HELPER, "_send_frame", side_effect=lambda _fd, value, _bound: emitted.append(value)), \
             mock.patch.object(_HELPER, "_await_root_release", side_effect=issue_real_one_use_grant), \
             mock.patch.object(_HELPER.os, "kill") as kill, \
             mock.patch.object(_HELPER.os, "execve", side_effect=lambda *args: exec_calls.append(args)
                               or (_ for _ in ()).throw(OSError("controlled exec return"))), \
             mock.patch.object(_HELPER, "_emit", side_effect=lambda value: emitted.append(value)):
            result = _HELPER.main()
        assert emitted[0]["checks"] == real_checks
        assert emitted[0]["state"] == real_state
        if real_state == "unsupported":
            assert result == 77
            assert not exec_calls
            kill.assert_not_called()
        else:
            assert result == 75  # controlled execve return is unavailable, never success
            assert len(exec_calls) == 1
            kill.assert_called_once_with(os.getpid(), signal.SIGSTOP)
    finally:
        manager.close()
        worker.close()
        endpoint.close()


def test_contract_validation_rejects_role_port_mismatch_before_probe():
    row = _contract(14500, 14501)
    row["allowed_bind_port"] = None
    try:
        _HELPER._validate_contract(row)
    except _HELPER.GateError as exc:
        assert "role" in str(exc)
    else:
        raise AssertionError("invalid network role/port contract was accepted")


def test_non_enforcement_errno_does_not_count_as_denial():
    """Controlled result check keeps conflict/unavailable distinct from EPERM."""
    row = _contract(14500, 14501)
    original = _HELPER._bind_probe
    original_unix = _HELPER._unix_control_probe
    try:
        def controlled(family, address, port):
            if port == 14500 and address == "127.0.0.1":
                return {"outcome": "bound", "errno": None}
            if family == socket.AF_INET6:
                return {"outcome": "error", "errno": 98}  # EADDRINUSE, not policy denial.
            if address == "0.0.0.0":
                return {"outcome": "error", "errno": 13}
            return {"outcome": "error", "errno": 1}

        _HELPER._bind_probe = controlled
        _HELPER._unix_control_probe = lambda _contract: {"outcome": "connected", "errno": None}
        _checks, state = _HELPER._probe(row)
        assert state == "unsupported"
    finally:
        _HELPER._bind_probe = original
        _HELPER._unix_control_probe = original_unix


def test_sigcont_alone_cannot_release_the_before_app_gate():
    """A same-UID signal can resume scheduling, never satisfy the manager grant."""
    parent_channel, child_channel = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    read_fd, write_fd = os.pipe()
    pid = os.fork()
    if pid == 0:
        parent_channel.close()
        os.close(read_fd)
        try:
            os.kill(os.getpid(), signal.SIGSTOP)
            _HELPER._await_root_release(
                child_channel, nonce="a" * 32, contract_sha256="b" * 64)
            os.write(write_fd, b"released")
            os._exit(0)
        except BaseException:
            os._exit(2)
    child_channel.close()
    os.close(write_fd)
    waited, status = os.waitpid(pid, os.WUNTRACED)
    assert waited == pid and os.WIFSTOPPED(status)
    os.kill(pid, signal.SIGCONT)
    ready, _, _ = select.select([read_fd], [], [], 0.1)
    assert not ready
    assert os.waitpid(pid, os.WNOHANG) == (0, 0)

    grant = {
        "schema": 1, "purpose": "private-loopback-worker-release",
        "nonce": "a" * 32, "contract_sha256": "b" * 64, "decision": "release",
    }
    raw = json.dumps(grant, sort_keys=True, separators=(",", ":"),
                     ensure_ascii=True).encode("ascii")
    parent_channel.sendall(struct.pack("!I", len(raw)) + raw)
    ready, _, _ = select.select([read_fd], [], [], 1)
    assert ready and os.read(read_fd, 16) == b"released"
    _, status = os.waitpid(pid, 0)
    assert os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0
    parent_channel.close()
    os.close(read_fd)


def test_manager_release_frame_is_bound_to_exact_contract_and_one_use_schema():
    left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    wrong = {
        "schema": 1, "purpose": "private-loopback-worker-release",
        "nonce": "c" * 32, "contract_sha256": "b" * 64, "decision": "release",
    }
    raw = json.dumps(wrong, sort_keys=True, separators=(",", ":"),
                     ensure_ascii=True).encode("ascii")
    left.sendall(struct.pack("!I", len(raw)) + raw)
    try:
        _HELPER._await_root_release(right, nonce="a" * 32, contract_sha256="b" * 64)
    except _HELPER.GateError as exc:
        assert "does not match" in str(exc)
    else:
        raise AssertionError("a grant for another nonce released the application gate")
    left.close()
    right.close()
