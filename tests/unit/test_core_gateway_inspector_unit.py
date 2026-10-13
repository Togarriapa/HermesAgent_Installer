"""Static and isolated-effect checks for the fixed root Inspector service."""
import os
import shlex
import stat
import subprocess
from pathlib import Path
from unittest.mock import patch
from hermes_installer.remote import core_gateway, core_gateway_inspector

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
        **fields,
    }
    with patch.object(core_gateway_inspector, "_consume_ingress_issue",
                      side_effect=AssertionError("non-singleton admin must stop before ingress consumption")) as consume:
        with pytest.raises(core_gateway_inspector.CoreInspectionDenied,
                           match="pending original global-admin registration"):
            core_gateway_inspector.observe_profile_admin(
                config, request=request, caller_pid=440, caller_uid=996, caller_gid=981,
                peer_pid=551, peer_uid=996, peer_gid=981)
    consume.assert_not_called()
