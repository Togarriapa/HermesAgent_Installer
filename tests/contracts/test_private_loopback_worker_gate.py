"""Controlled contracts and genuine local socket effects for the fixed gate."""
from __future__ import annotations

import importlib.util
import multiprocessing
import os
import socket
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


def _probe_child(allowed: int, denied: int, result_queue) -> None:
    checks, state = _HELPER._probe(_contract(allowed, denied))
    result_queue.put((os.getpid(), checks, state))


def test_live_worker_probe_reports_unsupported_effects_instead_of_authorizing_start():
    """Run real local bind attempts; a successful forbidden bind is not a pass."""
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
        _checks, state = _HELPER._probe(row)
        assert state == "unsupported"
    finally:
        _HELPER._bind_probe = original
