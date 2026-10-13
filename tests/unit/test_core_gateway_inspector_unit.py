"""Static and isolated-effect checks for the fixed root Inspector service."""
import hashlib
import dataclasses
import os
import shlex
import stat
import subprocess
from pathlib import Path
import time
from types import SimpleNamespace
from unittest.mock import patch
from hermes_installer.remote import core_gateway, core_gateway_inspector, global_admin

import pytest


UNIT = (Path(__file__).resolve().parents[2] / "templates" / "core-gateway"
        / "hermes-jarvis-core-inspector.service")


def test_inspector_unit_keeps_primary_group_and_limits_native_write_access():
    lines = UNIT.read_text(encoding="ascii").splitlines()
    service = lines[lines.index("[Service]") + 1:]

    assert service.count("Group=981") == 1
    assert service.count("RuntimeDirectory=hermes-jarvis-mvp-core") == 1
    assert not any(line.startswith("RuntimeDirectory=")
                   and ":root:admin" in line for line in service)
    assert service.count(
        "ExecStartPre=/usr/bin/install -d -o root -g 1000 -m 0750 "
        "/run/hermes-jarvis-native-observer") == 1
    assert service.count("SupplementaryGroups=1000") == 1
    assert service.count("ReadWritePaths=/var/lib/hermes-installer/core-runtime") == 1
    assert "ProtectSystem=strict" in service


def test_profile_admin_child_is_action_parent_peer_and_identity_bound_and_one_use():
    now = time.monotonic()
    parent = SimpleNamespace(caller_pid=44, caller_start_ticks="start-44",
        nonce="a" * 64, proof_sha256="b" * 64, expires_monotonic=now + 4)
    parent_key = (44, "start-44", parent.nonce, parent.proof_sha256)
    child_key = (44, "start-44", "c" * 64, "d" * 64)
    principal = SimpleNamespace(subject="original-subject", token_fingerprint="e" * 64)
    config = SimpleNamespace(config_sha256="f" * 64, boot_id="boot")
    child = core_gateway_inspector._RetainedProfileAdminChild(
        parent_key, "read", now - 0.1, now + 3,
        (551, 996, 981), "9" * 64, config.config_sha256, config.boot_id,
        hashlib.sha256(b"original-subject").hexdigest(), principal.token_fingerprint,
        4, "8" * 64, "profile-admin-child")
    with patch.dict(core_gateway_inspector._PROFILE_ADMIN_CHILDREN, {child_key: child}, clear=True):
        consumed = core_gateway_inspector._consume_profile_admin_child(
            caller_pid=44, caller_start_ticks="start-44", nonce=child_key[2],
            proof_sha256=child_key[3], action="read", parent=parent,
            peer=(551, 996, 981), core_generation="9" * 64, config=config,
            principal=principal, expected_revision=4, expected_record_sha256="8" * 64)
        assert consumed is child
        with pytest.raises(core_gateway_inspector.CoreInspectionDenied,
                           match="one-use profile administrator child"):
            core_gateway_inspector._consume_profile_admin_child(
                caller_pid=44, caller_start_ticks="start-44", nonce=child_key[2],
                proof_sha256=child_key[3], action="read", parent=parent,
                peer=(551, 996, 981), core_generation="9" * 64, config=config,
                principal=principal, expected_revision=4, expected_record_sha256="8" * 64)


@pytest.mark.parametrize("wrong", [
    {"action": "write"}, {"peer": (552, 996, 981)},
    {"expected_revision": 5}, {"purpose": "ordinary-ingress"},
])
def test_profile_admin_child_denies_foreign_action_peer_or_registration(wrong):
    now = time.monotonic()
    parent = SimpleNamespace(caller_pid=44, caller_start_ticks="start-44",
        nonce="a" * 64, proof_sha256="b" * 64, expires_monotonic=now + 4)
    child_key = (44, "start-44", "c" * 64, "d" * 64)
    principal = SimpleNamespace(subject="original-subject", token_fingerprint="e" * 64)
    config = SimpleNamespace(config_sha256="f" * 64, boot_id="boot")
    child = core_gateway_inspector._RetainedProfileAdminChild(
        (44, "start-44", parent.nonce, parent.proof_sha256), "read", now - 0.1, now + 3,
        (551, 996, 981), "9" * 64, config.config_sha256, config.boot_id,
        hashlib.sha256(b"original-subject").hexdigest(), principal.token_fingerprint,
        4, "8" * 64, "profile-admin-child")
    kwargs = {"caller_pid": 44, "caller_start_ticks": "start-44",
        "nonce": child_key[2], "proof_sha256": child_key[3], "action": "read",
        "parent": parent, "peer": (551, 996, 981), "core_generation": "9" * 64,
        "config": config, "principal": principal, "expected_revision": 4,
        "expected_record_sha256": "8" * 64}
    kwargs.update({key: value for key, value in wrong.items() if key != "purpose"})
    if "purpose" in wrong:
        child = dataclasses.replace(child, purpose=wrong["purpose"])
    with patch.dict(core_gateway_inspector._PROFILE_ADMIN_CHILDREN, {child_key: child}, clear=True):
        with pytest.raises(core_gateway_inspector.CoreInspectionDenied,
                           match="one-use profile administrator child"):
            core_gateway_inspector._consume_profile_admin_child(**kwargs)


def _derive_profile_admin_fixture(*, parent_expiry=None):
    now = time.monotonic()
    expiry = parent_expiry if parent_expiry is not None else now + 4.0
    principal = SimpleNamespace(subject="original-subject", email="owner@example.test",
        token_fingerprint="e" * 64, expires_at=time.time() + max(0, expiry - now))
    config = SimpleNamespace(config_sha256="f" * 64, boot_id="boot",
        policy=lambda _jwks: object(), allowed_emails=frozenset({"owner@example.test"}))
    proof = {"nonce": "a" * 64, "proof_sha256": "b" * 64,
        "issued_monotonic": now - 0.1, "expires_monotonic": expiry,
        "peer_pid": 551, "peer_uid": 996, "peer_gid": 981,
        "origin_socket_device": 11, "origin_socket_inode": 22,
        "core_generation": "9" * 64, "config_sha256": config.config_sha256,
        "boot_id": config.boot_id}
    core_gateway_inspector._retain_ingress_issue(
        caller_pid=44, caller_start_ticks="start-44", proof=proof)
    request = {"op": "derive-profile-admin-ingress", "nonce": os.urandom(32).hex(),
        "peer_pid": 551, "peer_uid": 996, "peer_gid": 981,
        "access_jwt": "signed-current-token", "core_generation": proof["core_generation"],
        "ingress_nonce": proof["nonce"], "ingress_proof_sha256": proof["proof_sha256"],
        "action": "read"}
    return config, principal, proof, request


def test_real_profile_admin_derivation_uses_absolute_parent_deadline_and_actual_child_ledger():
    """Exercise retained-parent lookup, real derivation, cap accounting and child consumption."""
    with (patch.dict(core_gateway_inspector._RETAINED_INGRESS_ISSUES, {}, clear=True),
          patch.dict(core_gateway_inspector._PROFILE_ADMIN_CHILDREN, {}, clear=True),
          patch.dict(core_gateway_inspector._PROFILE_ADMIN_CHILD_COUNTS, {}, clear=True)):
        config, principal, proof, request = _derive_profile_admin_fixture()
        with (patch.object(core_gateway_inspector, "_proc_start_ticks", return_value="start-44"),
              patch.object(core_gateway_inspector, "_learning_jwks", return_value={}),
              patch("hermes_installer.remote.gateway.validate_access_jwt", return_value=principal),
              patch.object(core_gateway_inspector, "_current_profile_admin_status",
                  return_value={"authorized": True, "revision": 7,
                                "record_sha256": "8" * 64})):
            children = []
            for _ in range(16):
                request["nonce"] = os.urandom(32).hex()
                child = core_gateway_inspector.derive_profile_admin_ingress(config,
                    request=request, caller_pid=44, caller_uid=0, caller_gid=0,
                    peer_pid=551, peer_uid=996, peer_gid=981)
                assert child["expires_monotonic"] == proof["expires_monotonic"]
                assert child["expires_monotonic"] > time.monotonic()
                children.append(child)
            request["nonce"] = os.urandom(32).hex()
            with pytest.raises(core_gateway_inspector.CoreInspectionDenied,
                               match="capacity is exhausted"):
                core_gateway_inspector.derive_profile_admin_ingress(config,
                    request=request, caller_pid=44, caller_uid=0, caller_gid=0,
                    peer_pid=551, peer_uid=996, peer_gid=981)
        parent = core_gateway_inspector._peek_ingress_issue(caller_pid=44,
            caller_start_ticks="start-44", nonce=proof["nonce"],
            proof_sha256=proof["proof_sha256"], peer=(551, 996, 981),
            core_generation=proof["core_generation"], config=config)
        child = children[0]
        retained_child = next(value for value in core_gateway_inspector._PROFILE_ADMIN_CHILDREN.values()
                              if value.action == "read")
        child_key = next(key for key, value in core_gateway_inspector._PROFILE_ADMIN_CHILDREN.items()
                         if value is retained_child)
        with pytest.raises(core_gateway_inspector.CoreInspectionDenied,
                           match="original ingress proof"):
            core_gateway_inspector._consume_ingress_issue(caller_pid=child_key[0],
                caller_start_ticks=child_key[1], nonce=child_key[2], proof_sha256=child_key[3],
                peer=(551, 996, 981), core_generation=proof["core_generation"], config=config)
        consumed = core_gateway_inspector._consume_profile_admin_child(
            caller_pid=child_key[0], caller_start_ticks=child_key[1],
            nonce=child_key[2], proof_sha256=child_key[3], action="read", parent=parent,
            peer=(551, 996, 981), core_generation=proof["core_generation"], config=config,
            principal=principal, expected_revision=7, expected_record_sha256="8" * 64)
        assert consumed.expires_monotonic == child["expires_monotonic"]
        with pytest.raises(core_gateway_inspector.CoreInspectionDenied,
                           match="one-use profile administrator child"):
            core_gateway_inspector._consume_profile_admin_child(
                caller_pid=child_key[0], caller_start_ticks=child_key[1],
                nonce=child_key[2], proof_sha256=child_key[3], action="read", parent=parent,
                peer=(551, 996, 981), core_generation=proof["core_generation"], config=config,
                principal=principal, expected_revision=7, expected_record_sha256="8" * 64)


def test_real_profile_admin_derivation_rejects_expired_or_consumed_parent_and_short_jwt_bound():
    with (patch.dict(core_gateway_inspector._RETAINED_INGRESS_ISSUES, {}, clear=True),
          patch.dict(core_gateway_inspector._PROFILE_ADMIN_CHILDREN, {}, clear=True),
          patch.dict(core_gateway_inspector._PROFILE_ADMIN_CHILD_COUNTS, {}, clear=True)):
        # Root carries an independently verified shorter JWT deadline over same-host IPC.
        config, principal, proof, request = _derive_profile_admin_fixture()
        principal = SimpleNamespace(subject=principal.subject, email=principal.email,
            token_fingerprint=principal.token_fingerprint, expires_at=time.time() + 0.25)
        with (patch.object(core_gateway_inspector, "_proc_start_ticks", return_value="start-44"),
              patch.object(core_gateway_inspector, "_learning_jwks", return_value={}),
              patch("hermes_installer.remote.gateway.validate_access_jwt", return_value=principal),
              patch.object(core_gateway_inspector, "_current_profile_admin_status",
                  return_value={"authorized": True, "revision": 7,
                                "record_sha256": "8" * 64})):
            child = core_gateway_inspector.derive_profile_admin_ingress(config,
                request=request, caller_pid=44, caller_uid=0, caller_gid=0,
                peer_pid=551, peer_uid=996, peer_gid=981)
            assert child["expires_monotonic"] < proof["expires_monotonic"]
            core_gateway_inspector._consume_ingress_issue(caller_pid=44,
                caller_start_ticks="start-44", nonce=proof["nonce"],
                proof_sha256=proof["proof_sha256"], peer=(551, 996, 981),
                core_generation=proof["core_generation"], config=config)
            request["nonce"] = os.urandom(32).hex()
            with pytest.raises(core_gateway_inspector.CoreInspectionDenied,
                               match="original ingress proof"):
                core_gateway_inspector.derive_profile_admin_ingress(config,
                    request=request, caller_pid=44, caller_uid=0, caller_gid=0,
                    peer_pid=551, peer_uid=996, peer_gid=981)
        with patch.dict(core_gateway_inspector._RETAINED_INGRESS_ISSUES, {}, clear=True):
            expired_config, _principal, _proof, expired_request = _derive_profile_admin_fixture(
                parent_expiry=time.monotonic() - 0.1)
            with pytest.raises(core_gateway_inspector.CoreInspectionDenied,
                               match="original ingress proof"):
                core_gateway_inspector.derive_profile_admin_ingress(expired_config,
                    request=expired_request, caller_pid=44, caller_uid=0, caller_gid=0,
                    peer_pid=551, peer_uid=996, peer_gid=981)


def test_expired_profile_admin_child_has_zero_native_effects():
    now = time.monotonic()
    config = SimpleNamespace()
    request = {"schema": 1, "op": "owner-profile-admin", "action": "list",
        "nonce": "a" * 64, "peer_pid": 551, "peer_uid": 996, "peer_gid": 981,
        "access_jwt": "signed-current-token", "core_generation": "9" * 64,
        "ingress_nonce": "b" * 64, "ingress_proof_sha256": "c" * 64,
        "child_nonce": "d" * 64, "child_proof_sha256": "e" * 64,
        "expected_admin_revision": 3, "expected_admin_sha256": "f" * 64}
    retained = SimpleNamespace(expires_monotonic=now + 4, issued_monotonic=now - 0.1,
        nonce="b" * 64, proof_sha256="c" * 64)
    with patch.object(core_gateway_inspector, "_proc_start_ticks", return_value="start"), \
         patch.object(core_gateway_inspector, "_peek_ingress_issue", return_value=retained), \
         patch.object(core_gateway_inspector, "observe_current_ingress",
                      side_effect=AssertionError("expired child must stop before native ingress or files")):
        with pytest.raises(core_gateway_inspector.CoreInspectionDenied,
                           match="one-use profile administrator child expired"):
            core_gateway_inspector._observe_profile_admin_transaction(config,
                request=request, caller_pid=44, caller_uid=0, caller_gid=0,
                peer_pid=551, peer_uid=996, peer_gid=981,
                child_expires_monotonic=now - 0.1)


@pytest.mark.skipif(os.geteuid() != 0, reason="root ownership effect requires the Pi root test role")
def test_inspector_prestart_recipe_creates_exact_private_runtime_directory(tmp_path):
    lines = UNIT.read_text(encoding="ascii").splitlines()
    recipe = next(line.split("=", 1)[1] for line in lines
                  if line.startswith("ExecStartPre="))
    arguments = shlex.split(recipe)
    target = tmp_path / "native-observer"
    arguments[-1] = str(target)
    subprocess.run(arguments, check=True, stdin=subprocess.DEVNULL,
                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)

    info = target.stat()
    assert stat.S_ISDIR(info.st_mode)
    assert (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) == (0, 1000, 0o750)


@pytest.mark.parametrize("allowed_emails", [frozenset(), frozenset({
    "owner@example.test", "member@example.test", "guest@example.test",
})])
@pytest.mark.parametrize("action_fields", [
    ("list", {}), ("read", {"profile_id": "hermes", "file_kind": "soul"}),
    ("write", {"profile_id": "hermes", "file_kind": "soul", "expected_sha256": "a" * 64,
               "content": "proposed", "idempotency_key": "safe_key_123456789012345678"}),
    ("skills-list", {}), ("skills-archives-list", {}),
    ("skill-read", {"skill_id": "helper"}),
    ("skill-write", {"skill_id": "helper", "expected_sha256": "a" * 64,
                     "content": "proposed", "idempotency_key": "safe_key_123456789012345678"}),
    ("skill-archive", {"skill_id": "helper", "expected_sha256": "a" * 64,
                       "idempotency_key": "safe_key_123456789012345678"}),
    ("skill-restore", {"skill_id": "helper", "expected_sha256": "a" * 64,
                       "idempotency_key": "safe_key_123456789012345678", "restore_id": "b" * 64}),
    ("skill-restore-list", {"skill_id": "helper"}),
])
def test_profile_admin_inspector_denies_non_singleton_allowlist_before_ingress_or_native_effects(
        allowed_emails, action_fields):
    digest = "a" * 64
    config = core_gateway.CoreGatewayConfig(
        hostname="jarvis.example.test", issuer="https://team.cloudflareaccess.com",
        audience="core-test-audience", allowed_emails=allowed_emails,
        gateway_uid=996, gateway_gid=981, core_uid=1000, core_gid=1000,
        boot_id="12345678-1234-1234-1234-123456789012",
        gateway_unit_sha256=digest, gateway_python_sha256=digest,
        tunnel_unit_sha256=digest, cloudflared_binary_sha256=digest,
        core_unit_sha256=digest, core_launcher_sha256=digest,
        core_python=core_gateway_inspector.CORE_PYTHON_LINK,
        core_python_sha256=core_gateway_inspector.CORE_PYTHON_SHA256,
        ingress_socket=core_gateway.CORE_INGRESS_SOCKET,
        config_path=core_gateway.CORE_CONFIG, config_sha256=digest)
    action, fields = action_fields
    request = {
        "schema": 1, "op": "owner-profile-admin", "action": action,
        "nonce": "b" * 64, "peer_pid": 551, "peer_uid": 996, "peer_gid": 981,
        "access_jwt": "signed-access-token", "core_generation": "c" * 64,
        "ingress_nonce": "d" * 64, "ingress_proof_sha256": "e" * 64,
        "child_nonce": "f" * 64, "child_proof_sha256": "7" * 64,
        "expected_admin_revision": 0, "expected_admin_sha256": "0" * 64,
        **fields,
    }
    principal = SimpleNamespace(email=(next(iter(allowed_emails)) if allowed_emails else "owner@example.test"),
        subject="immutable-subject", token_fingerprint=hashlib.sha256(
            b"signed-access-token").hexdigest())
    with patch.object(core_gateway_inspector, "_learning_jwks", return_value={}), \
            patch("hermes_installer.remote.gateway.validate_access_jwt", return_value=principal), \
            patch.object(global_admin, "locked"), \
            patch.object(global_admin, "read_locked", return_value=(None, None)), \
            patch.object(core_gateway_inspector, "_peek_ingress_issue",
                return_value=SimpleNamespace(expires_monotonic=time.monotonic() + 5)), \
            patch.object(core_gateway_inspector, "_consume_ingress_issue",
                      side_effect=AssertionError("non-singleton admin must stop before ingress consumption")) as consume:
        with pytest.raises(core_gateway_inspector.CoreInspectionDenied,
                           match="original administrator setup"):
            core_gateway_inspector.observe_profile_admin(
                config, request=request, caller_pid=440, caller_uid=996, caller_gid=981,
                peer_pid=551, peer_uid=996, peer_gid=981)
    consume.assert_not_called()
