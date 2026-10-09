"""Actual Linux AF_UNIX verifier exchange between distinct service UIDs.

The test uses only generated JWT/account fixtures, never Cloudflare or user credentials.
CI runs this module as root solely so it can drop three short-lived subprocesses to
unique unprivileged UIDs and inspect socket ownership/peer credentials.
"""
from __future__ import annotations

import base64
import importlib.util
import json
import os
import platform
import secrets
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from hermes_installer.remote.gateway import RemotePolicy
from hermes_installer.remote.policy import AccessPolicyIdentity
from hermes_installer.remote.verifier_ipc import verifier_config_digest


HAS_CRYPTO = importlib.util.find_spec("jwt") is not None and importlib.util.find_spec("cryptography") is not None
LINUX_PEERCRED = platform.system() == "Linux" and hasattr(socket, "SO_PEERCRED")
HELPER = Path(__file__).resolve().parents[1] / "fixtures" / "remote_verifier_uid_harness.py"


def _free_ids():
    used_uids = {entry.st_uid for entry in Path("/proc").iterdir() if entry.name.isdigit()}
    used_gids = set()
    try:
        for line in Path("/etc/group").read_text(encoding="utf-8").splitlines():
            fields = line.split(":")
            if len(fields) > 2 and fields[2].isdigit():
                used_gids.add(int(fields[2]))
    except OSError:
        pass
    candidates = range(62000, 62500)
    gid = next((item for item in candidates if item not in used_gids), None)
    uids = []
    for item in candidates:
        if item not in used_uids and item not in uids:
            uids.append(item)
        if len(uids) == 3:
            break
    if gid is None or len(uids) != 3:
        raise unittest.SkipTest("no three free fixture-only Linux UIDs/GID")
    return gid, uids


def _drop(uid, gid, supplementary=()):
    def apply():
        os.setgroups(list(supplementary))
        os.setgid(gid)
        os.setuid(uid)
    return apply


@unittest.skipUnless(LINUX_PEERCRED and HAS_CRYPTO, "Linux SO_PEERCRED and isolated crypto lock required")
class TwoUidVerifierSubprocessTests(unittest.TestCase):
    def test_allow_and_foreign_peer_denial_use_real_uid_credentials(self):
        if os.geteuid() != 0:
            self.skipTest("dedicated UID subprocess setup requires the isolated CI job's root wrapper")

        import jwt
        from cryptography.hazmat.primitives.asymmetric import rsa

        gateway_gid, (gateway_uid, verifier_uid, foreign_uid) = _free_ids()
        identity = AccessPolicyIdentity(
            account_id="acct-ci", application_id="app-1", policy_id="policy-1",
            identity_provider_id="idp-1", hostname="desktop.ci.example",
            application_name="HermesInstaller:ci:desktop",
            policy_name="HermesInstaller:ci:allowed-emails",
            identity_provider_name="HermesInstaller:ci:otp",
            allowed_emails=frozenset({"ci-owner@example.net"}), audience="ci-app-audience",
        )
        public_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        numbers = public_key.public_key().public_numbers()

        def b64(value):
            return base64.urlsafe_b64encode(value.to_bytes((value.bit_length() + 7) // 8, "big")).rstrip(b"=").decode()

        jwk = {
            "kty": "RSA", "kid": "ci-test", "alg": "RS256", "use": "sig",
            "n": b64(numbers.n), "e": b64(numbers.e),
        }
        issuer = "https://team.cloudflareaccess.com"
        wall = int(time.time())
        token = jwt.encode(
            {"iss": issuer, "aud": [identity.audience], "iat": wall, "nbf": wall,
             "exp": wall + 180, "sub": "ci-subject", "email": "ci-owner@example.net"},
            public_key, algorithm="RS256", headers={"kid": "ci-test"},
        )
        policy = RemotePolicy(
            identity.hostname, issuer, identity.audience, identity.allowed_emails,
            {"ci-test": jwk},
        )
        digest = verifier_config_digest(identity, issuer=issuer, audience=identity.audience)

        with tempfile.TemporaryDirectory(prefix="hermes-remote-uid-", dir="/run") as raw:
            root = Path(raw)
            os.chown(root, verifier_uid, gateway_gid)
            os.chmod(root, 0o750)
            socket_path = root / "policy.sock"
            config_path = root / "fixture.json"
            payload = {
                "gateway_uid": gateway_uid, "gateway_gid": gateway_gid,
                "socket_path": str(socket_path), "account_id": identity.account_id,
                "hostname": identity.hostname, "application_name": identity.application_name,
                "policy_name": identity.policy_name, "idp_name": identity.identity_provider_name,
                "email": "ci-owner@example.net", "audience": identity.audience, "issuer": issuer,
                "jwk": jwk, "jwt": token, "config_digest": digest,
                "session_id": secrets.token_urlsafe(24), "verifier_uid": verifier_uid,
                "app": {
                    "id": "app-1", "aud": identity.audience, "name": identity.application_name,
                    "type": "self_hosted", "domain": identity.hostname, "allowed_idps": ["idp-1"],
                    "self_hosted_domains": [],
                },
                "idp": {"id": "idp-1", "name": identity.identity_provider_name, "type": "onetimepin"},
                "policy": {
                    "id": "policy-1", "name": identity.policy_name, "decision": "allow",
                    "include": [{"email": {"email": "ci-owner@example.net"}}],
                    "exclude": [], "require": [], "precedence": 1,
                },
            }
            config_path.write_text(json.dumps(payload, separators=(",", ":")), encoding="utf-8")
            os.chown(config_path, verifier_uid, gateway_gid)
            os.chmod(config_path, 0o440)

            service_env = {
                "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                "HOME": str(root), "PYTHONPATH": str(HELPER.parents[2] / "src"),
                "PYTHONDONTWRITEBYTECODE": "1",
            }
            service = subprocess.Popen(
                [sys.executable, str(HELPER), "service", str(config_path)],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                env=service_env, preexec_fn=_drop(verifier_uid, verifier_uid, (gateway_gid,)),
                text=True,
            )
            try:
                deadline = time.monotonic() + 8
                while time.monotonic() < deadline and not socket_path.exists() and service.poll() is None:
                    time.sleep(0.025)
                self.assertIsNone(service.poll(), "fixture custodian exited before binding")
                socket_info = os.stat(socket_path, follow_symlinks=False)
                self.assertTrue(stat.S_ISSOCK(socket_info.st_mode))
                self.assertEqual(socket_info.st_uid, verifier_uid)
                self.assertEqual(socket_info.st_gid, gateway_gid)
                self.assertEqual(stat.S_IMODE(socket_info.st_mode), 0o660)

                request = {
                    "jwt": token, "hostname": identity.hostname, "issuer": issuer,
                    "audience": identity.audience, "email": "ci-owner@example.net",
                    "jwk": jwk, "config_digest": digest, "session_id": payload["session_id"],
                    "socket_path": str(socket_path), "verifier_uid": verifier_uid,
                }
                gateway_env = dict(service_env)
                gateway = subprocess.run(
                    [sys.executable, str(HELPER), "gateway"], input=json.dumps(request),
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=gateway_env,
                    preexec_fn=_drop(gateway_uid, gateway_gid), text=True, timeout=8,
                )
                self.assertEqual(gateway.returncode, 0, gateway.stderr[-1000:])
                grant = json.loads(gateway.stdout)
                self.assertEqual(grant, {
                    "decision": "allow", "action": "issue", "subject": "ci-subject",
                    "profile_id": "hermes-desktop",
                })

                foreign = subprocess.run(
                    [sys.executable, str(HELPER), "foreign"], input=json.dumps(request),
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=gateway_env,
                    preexec_fn=_drop(foreign_uid, foreign_uid), text=True, timeout=4,
                )
                self.assertEqual(foreign.returncode, 0, foreign.stderr[-1000:])
                self.assertEqual(json.loads(foreign.stdout)["response_bytes"], 0,
                                 "foreign UID must be rejected before the verifier reads policy")

                service.send_signal(signal.SIGTERM)
                stdout, stderr = service.communicate(timeout=8)
                self.assertEqual(service.returncode, 0, stderr[-1000:])
                evidence = json.loads(stdout.strip().splitlines()[-1])
                self.assertEqual(evidence["fixture_get_count"], 12,
                                 "the foreign UID probe must produce zero Cloudflare fixture reads")
            finally:
                if service.poll() is None:
                    service.kill()
                    service.communicate(timeout=2)
