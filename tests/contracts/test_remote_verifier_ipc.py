import asyncio
import base64
import contextlib
import importlib.util
import json
import os
import secrets
import tempfile
import threading
import time
import unittest
from pathlib import Path

from hermes_installer.remote.gateway import GatewayDenied, Principal, RemotePolicy, validate_access_jwt
from hermes_installer.remote.policy import AccessPolicyIdentity, FreshAccessPolicyAuthority
from hermes_installer.remote.verifier_ipc import (
    PolicyVerifierClient,
    PolicyVerifierService,
    VerifierRuntime,
    verifier_config_digest,
)


CRYPTO_AVAILABLE = importlib.util.find_spec("jwt") is not None and importlib.util.find_spec("cryptography") is not None
PEER_CREDENTIALS = hasattr(__import__("socket"), "SO_PEERCRED")


class FixtureAccount:
    def __init__(self, app, idp, policies):
        self.app, self.idp, self.policies = app, idp, policies
        self.reads = []
        self.block = False
        self._network = None

    def request(self, method, path, payload=None):
        self.reads.append((method, path))
        if method != "GET":
            raise AssertionError("verifier attempted a non-GET request")
        if self.block:
            self._network = self.network
            until = time.monotonic() + 10
            while time.monotonic() < until and not self.network.cancelled.is_set():
                time.sleep(0.01)
            if self.network.cancelled.is_set():
                raise RuntimeError("fixture read was cancelled")
        if path.endswith("/access/apps/app-1"):
            return self.app
        if path.endswith("/access/identity_providers/idp-1"):
            return self.idp
        if "/policies?" in path:
            page = int(path.rsplit("page=", 1)[1])
            return self.policies[(page - 1) * 100:page * 100]
        raise AssertionError("verifier attempted an unreviewed URL")

    @property
    def network(self):
        return self._network_proxy

    @network.setter
    def network(self, value):
        self._network_proxy = value


@unittest.skipUnless(CRYPTO_AVAILABLE and PEER_CREDENTIALS, "requires pinned crypto and Linux SO_PEERCRED")
class PolicyVerifierUnixIPCTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        import jwt
        from cryptography.hazmat.primitives.asymmetric import rsa

        self.jwt = jwt
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public = self.key.public_key().public_numbers()

        def b64(value):
            return base64.urlsafe_b64encode(value.to_bytes((value.bit_length() + 7) // 8, "big")).rstrip(b"=").decode()

        jwk = {"kty": "RSA", "kid": "ipc-fixture", "alg": "RS256", "use": "sig", "n": b64(public.n), "e": b64(public.e)}
        self.identity = AccessPolicyIdentity(
            "acct-1", "app-1", "policy-1", "idp-1", "desk.example.net",
            "HermesInstaller:op:desktop", "HermesInstaller:op:allowed-emails",
            "HermesInstaller:op:email-code", frozenset({"owner@example.net"}), "app-aud",
        )
        self.app = {
            "id": "app-1", "aud": self.identity.audience, "name": self.identity.application_name, "type": "self_hosted",
            "domain": "desk.example.net", "allowed_idps": ["idp-1"], "self_hosted_domains": [],
        }
        self.idp = {"id": "idp-1", "name": self.identity.identity_provider_name, "type": "onetimepin"}
        self.policy_row = {
            "id": "policy-1", "name": self.identity.policy_name, "decision": "allow",
            "include": [{"email": {"email": "owner@example.net"}}], "exclude": [], "require": [], "precedence": 1,
        }
        self.account = FixtureAccount(self.app, self.idp, [self.policy_row])
        self.resolve_calls = []
        authority = FreshAccessPolicyAuthority(
            self.identity, "vault://fixture/access-read",
            lambda ref: self.resolve_calls.append(ref) or "separate-read-token-canary",
            lambda _token: self.account,
        )
        self.wall = int(time.time())
        self.remote_policy = RemotePolicy(
            "desk.example.net", "https://team.cloudflareaccess.com", self.identity.audience,
            frozenset({"owner@example.net"}), {"ipc-fixture": jwk},
        )
        self.digest = verifier_config_digest(self.identity, issuer=self.remote_policy.issuer, audience=self.identity.audience)
        runtime = VerifierRuntime(self.remote_policy, authority, "hermes-desktop", self.digest)
        self.temp = tempfile.TemporaryDirectory()
        self.socket_path = Path(self.temp.name) / "policy.sock"
        self.uid = os.geteuid()
        self.service = PolicyVerifierService(runtime, gateway_uid=self.uid)
        await self.service.start(self.socket_path)
        self.client = PolicyVerifierClient(self.socket_path, verifier_uid=self.uid, config_digest=self.digest)
        self.token = self._token()
        self.expected = validate_access_jwt(self.token, policy=self.remote_policy, now=lambda: self.wall)

    async def asyncTearDown(self):
        await self.service.close()
        self.temp.cleanup()

    def _token(self):
        return self.jwt.encode({
            "iss": self.remote_policy.issuer, "aud": [self.remote_policy.audience],
            "iat": self.wall, "nbf": self.wall, "exp": self.wall + 300,
            "sub": "subject-1", "email": "owner@example.net",
        }, self.key, algorithm="RS256", headers={"kid": "ipc-fixture"})

    async def test_grant_is_fresh_bound_and_anchored_to_read_start(self):
        grant = await self.client.authorize(action="issue", session_id=secrets.token_urlsafe(24),
                                            access_jwt=self.token, expected=self.expected)
        self.assertEqual(grant.principal.subject, "subject-1")
        self.assertLessEqual(grant.valid_until_monotonic, grant.observed_start_monotonic + 60)
        self.assertLessEqual(grant.valid_until_monotonic, grant.jwt_deadline_monotonic)
        self.assertIn(("/accounts/acct-1/access/identity_providers/idp-1",
                       "GET"), [(path, method) for method, path in self.account.reads])
        self.assertEqual(set(method for method, _ in self.account.reads), {"GET"})
        self.assertNotIn("separate-read-token-canary", repr(self.service.runtime.authority))

    async def test_policy_removal_and_idp_replacement_deny_same_signed_jwt(self):
        session = secrets.token_urlsafe(24)
        await self.client.authorize(action="issue", session_id=session, access_jwt=self.token, expected=self.expected)
        self.account.policies = []
        with self.assertRaises(GatewayDenied):
            await self.client.authorize(action="renew", session_id=session, access_jwt=self.token, expected=self.expected)
        self.account.policies = [self.policy_row]
        self.account.idp = dict(self.idp, type="github")
        with self.assertRaises(GatewayDenied):
            await self.client.authorize(action="socket", session_id=session, access_jwt=self.token, expected=self.expected)

    async def test_wrong_config_and_generic_url_write_fields_have_no_api_effect(self):
        before = len(self.account.reads)
        wrong = PolicyVerifierClient(self.socket_path, verifier_uid=self.uid, config_digest="f" * 64)
        with self.assertRaises(GatewayDenied):
            await wrong.authorize(action="issue", session_id=secrets.token_urlsafe(24),
                                  access_jwt=self.token, expected=self.expected)
        request = {
            "version": 1, "action": "issue", "nonce": secrets.token_urlsafe(32),
            "profile_id": "hermes-desktop", "session_id": secrets.token_urlsafe(24),
            "config_digest": self.digest, "access_jwt": self.token,
            "url": "https://api.cloudflare.com/client/v4/accounts/foreign/access/apps",
            "method": "DELETE", "account_id": "foreign",
        }
        reader, writer = await asyncio.open_unix_connection(str(self.socket_path))
        writer.write(json.dumps(request, separators=(",", ":")).encode() + b"\n")
        await writer.drain()
        response = json.loads(await asyncio.wait_for(reader.readline(), 2))
        writer.close()
        await writer.wait_closed()
        self.assertIs(response["decision"], False)
        self.assertEqual(len(self.account.reads), before)

    async def test_request_nonce_replay_does_not_repeat_policy_reads(self):
        request = {
            "version": 1, "action": "issue", "nonce": secrets.token_urlsafe(32),
            "profile_id": "hermes-desktop", "session_id": secrets.token_urlsafe(24),
            "config_digest": self.digest, "access_jwt": self.token,
        }

        async def send():
            reader, writer = await asyncio.open_unix_connection(str(self.socket_path))
            writer.write(json.dumps(request, separators=(",", ":")).encode() + b"\n")
            await writer.drain()
            result = json.loads(await asyncio.wait_for(reader.readline(), 3))
            writer.close()
            await writer.wait_closed()
            return result

        first = await send()
        reads = len(self.account.reads)
        replay = await send()
        self.assertIs(first["decision"], True)
        self.assertIs(replay["decision"], False)
        self.assertEqual(len(self.account.reads), reads)

    async def test_client_cancellation_signals_bounded_read_worker(self):
        self.account.block = True
        task = asyncio.create_task(self.client.authorize(
            action="renew", session_id=secrets.token_urlsafe(24),
            access_jwt=self.token, expected=self.expected,
        ))
        await asyncio.sleep(0.1)
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task
        self.account.block = False
        # A new decision proves the cancelled read released its bounded worker slot.
        grant = await asyncio.wait_for(self.client.authorize(
            action="issue", session_id=secrets.token_urlsafe(24),
            access_jwt=self.token, expected=self.expected,
        ), 3)
        self.assertTrue(grant.valid_until_monotonic > time.monotonic())
