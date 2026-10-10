from __future__ import annotations

import json
import os
import socket
import threading

import pytest

from hermes_installer.authority.private_loopback_worker_gate import (
    application_release_frame,
    create_root_private_loopback_gate_channel,
    namespace_observation_frame,
    receive_frame,
    send_frame,
    validate_awaiting_namespace,
    validate_gate_result,
)
from hermes_installer.authority.types import AuthorityDenied


def _awaiting(channel, nonce, contract):
    return {"schema": 2, "state": "awaiting-namespace", "nonce": nonce,
            "launch_contract_sha256": contract, "pid": 21, "start_ticks": 901,
            "uid": os.getuid(), "gid": os.getgid()}


def test_named_systemd_gate_channel_authenticates_exact_helper_and_frame_credentials(tmp_path):
    if os.geteuid() != 0 or not hasattr(socket, "SO_PEERCRED") or not hasattr(socket, "SO_PASSCRED"):
        pytest.skip("named gate channel requires Linux root and kernel peer credentials")
    parent = tmp_path / "gate"
    parent.mkdir(mode=0o700)
    os.chmod(parent, 0o700)
    channel = create_root_private_loopback_gate_channel(parent)
    assert channel.socket_path.name == "control.sock"
    assert channel.systemd_open_file_property.endswith(":hermes-private-loopback-gate")
    nonce, contract = channel.nonce, "a" * 64
    outcome = []

    def accept():
        outcome.append(channel.accept_helper(expected_uid=os.getuid(),
                                             deadline=__import__("time").monotonic() + 2,
                                             cancelled=lambda: False))

    thread = threading.Thread(target=accept)
    thread.start()
    peer = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    peer.connect(str(channel.socket_path))
    send_frame(peer, _awaiting(channel, nonce, contract))
    thread.join(timeout=2)
    assert not thread.is_alive()
    connected, frame, frame_digest = outcome[0]
    assert frame == _awaiting(channel, nonce, contract)
    assert len(frame_digest) == 64
    validated = validate_awaiting_namespace(frame, nonce=nonce, contract_sha256=contract,
                                            expected_uid=os.getuid(), expected_gid=os.getgid())
    assert validated["pid"] > 1
    connected.close()
    peer.close()
    channel.close()
    assert not channel.socket_path.exists()


def test_v190_namespace_observation_result_and_release_are_distinct_frames():
    namespace = namespace_observation_frame(
        nonce="n" * 32, contract_sha256="a" * 64,
        service_generation_digest="b" * 64, projection_handle="projection1",
        unit_invocation_id="invoke1", pid=7, start_ticks=88,
        cgroup="/system.slice/hermes-installer-test.service",
        namespace_device=4, namespace_inode=99)
    left, right = socket.socketpair()
    send_frame(left, namespace)
    assert receive_frame(right) == namespace
    result = {"schema": 2, "state": "ready", "nonce": "n" * 32,
              "launch_contract_sha256": "a" * 64,
              "namespace_gate_sha256": __import__("hashlib").sha256(
                  json.dumps(namespace, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=True).encode("ascii")).hexdigest(),
              "identity": {"pid": 7, "start_ticks": 88, "uid": 1000, "gid": 1000,
                           "cgroup": "/system.slice/hermes-installer-test.service",
                           "namespace_device": 4, "namespace_inode": 99,
                           "capabilities": {"CapEff": 0, "CapPrm": 0, "CapBnd": 0,
                                             "CapAmb": 0, "CapInh": 0}},
              "checks": {"wrong_port_bind": {"outcome": "error", "errno": 13},
                         "ipv6_bind": {"outcome": "error", "errno": 13},
                         "wildcard_bind": {"outcome": "error", "errno": 13},
                         "allowed_bind": {"outcome": "bound", "errno": None},
                         "af_unix_control": {"outcome": "connected", "errno": None}}}
    gate_digest = validate_gate_result(
        result, nonce="n" * 32, contract_sha256="a" * 64,
        expected_identity=result["identity"], gate_frame=namespace,
        allowed_bind=True, allowed_connect=False)
    release = application_release_frame(
        nonce="n" * 32, contract_sha256="a" * 64,
        namespace_gate_sha256=gate_digest, service_generation_digest="b" * 64,
        projection_handle="projection1", pid=7, start_ticks=88,
        unit_invocation_id="invoke1")
    send_frame(left, release)
    assert receive_frame(right) == release
    left.close()
    right.close()


def test_gate_denies_nonready_or_wrong_nonce_before_release():
    namespace = namespace_observation_frame(
        nonce="n" * 32, contract_sha256="a" * 64,
        service_generation_digest="b" * 64, projection_handle="projection1",
        unit_invocation_id="invoke1", pid=7, start_ticks=88,
        cgroup="/system.slice/hermes-installer-test.service",
        namespace_device=4, namespace_inode=99)
    result = {"schema": 2, "state": "unsupported", "nonce": "n" * 32,
              "launch_contract_sha256": "a" * 64, "namespace_gate_sha256": "0" * 64,
              "identity": {}, "checks": {}}
    with pytest.raises(AuthorityDenied):
        validate_gate_result(result, nonce="n" * 32, contract_sha256="a" * 64,
                             expected_identity={}, gate_frame=namespace,
                             allowed_bind=True, allowed_connect=False)
    with pytest.raises(AuthorityDenied):
        validate_awaiting_namespace(_awaiting(None, "x" * 32, "a" * 64), nonce="n" * 32,
                                    contract_sha256="a" * 64, expected_uid=1000,
                                    expected_gid=1000)


def test_successful_forbidden_bind_probe_never_produces_application_release():
    namespace = namespace_observation_frame(
        nonce="n" * 32, contract_sha256="a" * 64,
        service_generation_digest="b" * 64, projection_handle="projection1",
        unit_invocation_id="invoke1", pid=7, start_ticks=88,
        cgroup="/system.slice/hermes-installer-test.service",
        namespace_device=4, namespace_inode=99)
    identity = {"pid": 7, "start_ticks": 88, "uid": 1000, "gid": 1000,
                "cgroup": "/system.slice/hermes-installer-test.service",
                "namespace_device": 4, "namespace_inode": 99,
                "capabilities": {"CapEff": 0, "CapPrm": 0, "CapBnd": 0,
                                  "CapAmb": 0, "CapInh": 0}}
    result = {"schema": 2, "state": "ready", "nonce": "n" * 32,
              "launch_contract_sha256": "a" * 64,
              "namespace_gate_sha256": __import__("hashlib").sha256(
                  json.dumps(namespace, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=True).encode("ascii")).hexdigest(),
              "identity": identity,
              "checks": {"wrong_port_bind": {"outcome": "bound", "errno": None},
                         "ipv6_bind": {"outcome": "error", "errno": 13},
                         "wildcard_bind": {"outcome": "error", "errno": 13},
                         "af_unix_control": {"outcome": "connected", "errno": None}}}
    with pytest.raises(AuthorityDenied, match="forbidden bind"):
        validate_gate_result(result, nonce="n" * 32, contract_sha256="a" * 64,
                             expected_identity=identity, gate_frame=namespace,
                             allowed_bind=False, allowed_connect=False)
