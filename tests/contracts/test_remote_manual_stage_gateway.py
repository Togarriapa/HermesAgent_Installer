"""Effects and fail-closed tests for the separately owned Jarvis stage."""
import base64
import hashlib
import json
import time
import unittest
from unittest import mock
from urllib.parse import urlsplit, parse_qs

from hermes_installer.network import HTTPResult
from hermes_installer.remote.gateway import RemotePolicy
from hermes_installer.remote.manual_stage import (
    ManualGatewayStageConfig, ManualStageDenied, StageEdgeAccessVerifier,
    StageGatewayPolicySessionAdapter,
    _PendingProbe, _cookie_value, _stage_edge_https_request,
)
from hermes_installer.remote.gateway import Principal
from hermes_installer.remote.manual_stage_inspector import StageInspectionDenied, _validate_nft

try:
    import jwt
    from cryptography.hazmat.primitives.asymmetric import rsa
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False


@unittest.skipUnless(HAS_CRYPTO, "install the pinned remote component dependencies")
class ManualStageGatewayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public = cls.key.public_key().public_numbers()
        def b64(number):
            return base64.urlsafe_b64encode(number.to_bytes((number.bit_length() + 7) // 8, "big")).rstrip(b"=").decode()
        cls.jwks = {"stage-kid": {"kty": "RSA", "kid": "stage-kid", "alg": "RS256", "use": "sig",
                                   "n": b64(public.n), "e": b64(public.e)}}

    def setUp(self):
        from pathlib import Path
        self.config = ManualGatewayStageConfig(
            hostname="jarvis.togarriapahome.uk", issuer="https://team.cloudflareaccess.com",
            audience="stage-app-aud", allowed_emails=frozenset({"owner@example.net"}),
            gateway_uid=18000, gateway_gid=1800, xpra_uid=18001, display_number=118,
            xpra_binary=Path("/usr/bin/python3.13"), xpra_binary_sha256="a" * 64,
            xpra_program=Path("/usr/bin/xpra"), xpra_program_sha256="b" * 64,
            xpra_argv_sha256="e" * 64,
            unit_fragment=Path("/etc/systemd/system/hermes-xpra-stage.service"), unit_sha256="f" * 64,
            appdir=Path("/usr/share/xpra/www"), appdir_manifest_sha256="d" * 64,
            boot_id="00000000-0000-0000-0000-000000000001",
            config_path=Path("/etc/hermes-installer/gateway-stage.json"), config_sha256="c" * 64)
        self.verifier = StageEdgeAccessVerifier(self.config)
        self.verifier.policy = RemotePolicy(self.config.hostname, self.config.issuer, self.config.audience,
                                            self.config.allowed_emails, self.jwks)

    def token(self, **changes):
        now = int(time.time())
        claims = {"iss": self.config.issuer, "aud": [self.config.audience], "iat": now - 1,
                  "nbf": now - 1, "exp": now + 120, "sub": "jarvis-stage-owner",
                  "email": "owner@example.net"}
        claims.update(changes)
        return jwt.encode(claims, self.key, algorithm="RS256", headers={"kid": "stage-kid"})

    def test_one_use_probe_binds_forwarded_assertion_and_consumes_before_denial(self):
        token = self.token()
        principal = __import__("hermes_installer.remote.gateway", fromlist=["validate_access_jwt"]).validate_access_jwt(
            token, policy=self.verifier.policy)
        nonce = "one-use-stage-nonce"
        self.verifier._pending[nonce] = _PendingProbe(
            "websocket-attach", "session-bound-id-123456", hashlib.sha256(token.encode()).hexdigest(),
            principal.email, principal.subject, self.config.config_sha256, time.monotonic() + 5)
        with self.assertRaises(ManualStageDenied):
            self.verifier.consume_probe(nonce=nonce, cookie_jwt=token, forwarded_jwt="different")
        self.assertNotIn(nonce, self.verifier._pending)
        with self.assertRaises(ManualStageDenied):
            self.verifier.consume_probe(nonce=nonce, cookie_jwt=token, forwarded_jwt=token)

    def test_expired_and_wrong_config_probe_are_denied(self):
        token = self.token()
        principal = __import__("hermes_installer.remote.gateway", fromlist=["validate_access_jwt"]).validate_access_jwt(
            token, policy=self.verifier.policy)
        digest = hashlib.sha256(token.encode()).hexdigest()
        for nonce, expiry, config_digest in (("expired-stage-nonce", time.monotonic() - 1, self.config.config_sha256),
                                             ("changed-stage-nonce", time.monotonic() + 5, "d" * 64)):
            self.verifier._pending[nonce] = _PendingProbe("renew", "session-bound-id-123456", digest,
                principal.email, principal.subject, config_digest, expiry)
            with self.subTest(nonce=nonce), self.assertRaises(ManualStageDenied):
                self.verifier.consume_probe(nonce=nonce, cookie_jwt=token, forwarded_jwt=token)
            self.assertNotIn(nonce, self.verifier._pending)

    def test_verify_requires_fresh_exact_same_edge_witness_and_caps_lease(self):
        token = self.token()
        verifier = self.verifier
        class FakeBoundedNetwork:
            def __init__(self, **kwargs):
                self.requester = kwargs["requester"]
            def request(self, url, *, method, headers):
                nonce = parse_qs(urlsplit(url).query, strict_parsing=True)["nonce"][0]
                body = verifier.consume_probe(nonce=nonce,
                    cookie_jwt=headers["Cookie"].split("=", 1)[1],
                    forwarded_jwt=headers["Cookie"].split("=", 1)[1])
                return HTTPResult(200, {"cache-control": "no-store, no-cache", "content-type": "application/json", "content-length": str(len(body))}, body)
        with mock.patch("hermes_installer.remote.manual_stage.BoundedNetwork", FakeBoundedNetwork):
            principal, lease, jwt_deadline = verifier.verify(
                token, action="websocket-attach", session_id="session-bound-id-123456")
        self.assertEqual(principal.email, "owner@example.net")
        self.assertLessEqual(lease - time.monotonic(), 30.05)
        self.assertGreater(jwt_deadline, lease)
        self.assertFalse(verifier._pending)

    def test_edge_requester_rejects_alias_hosts_routes_and_query_forms(self):
        for url in (
            "https://example.net/__stage_access_probe?nonce=a",
            "https://jarvis.togarriapahome.uk/other?nonce=a",
            "https://jarvis.togarriapahome.uk/__stage_access_probe?nonce=a&nonce=b",
            "https://jarvis.togarriapahome.uk/__stage_access_probe?nonce=",
        ):
            with self.subTest(url=url), self.assertRaises(Exception):
                _stage_edge_https_request(url, "GET", {}, None, 1.0, 4096)

    def test_probe_cookie_parser_rejects_duplicate_and_noncanonical_access_token(self):
        self.assertEqual(_cookie_value("other=x; CF_Authorization=eyJabc.def.ghi", "CF_Authorization"),
                         "eyJabc.def.ghi")
        for header in ("CF_Authorization=one; CF_Authorization=two", "CF_Authorization=bad=padding",
                       "CF_Authorization", ""):
            with self.subTest(header=header), self.assertRaises(ManualStageDenied):
                _cookie_value(header, "CF_Authorization")

    def test_root_inspector_accepts_only_exact_gateway_uid_output_rule(self):
        rows = {"nftables": [
            {"metainfo": {"version": "1.0"}},
            {"table": {"family": "inet", "name": "hermes_jarvis_mvp", "handle": 1}},
            {"chain": {"family": "inet", "table": "hermes_jarvis_mvp", "name": "output",
                       "type": "filter", "hook": "output", "prio": -10, "policy": "accept"}},
            {"rule": {"family": "inet", "table": "hermes_jarvis_mvp", "chain": "output", "handle": 2,
                "comment": "Jarvis MVP display gateway only", "expr": [
                    {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "daddr"}}, "right": "127.0.0.1"}},
                    {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 14500}},
                    {"match": {"op": "!=", "left": {"meta": {"key": "skuid"}}, "right": 18000}},
                    {"reject": {"type": "tcp reset"}},
                ]}},
        ]}
        _validate_nft(json.dumps(rows).encode(), 18000)
        rows["nftables"][3]["rule"]["expr"][2]["match"]["right"] = 18001
        with self.assertRaises(StageInspectionDenied):
            _validate_nft(json.dumps(rows).encode(), 18000)

    def test_xpra_argv_requires_root_configured_hash_and_fixed_app_only_surface(self):
        from hermes_installer.remote.manual_stage_inspector import _validate_xpra_argv
        argv = ("/usr/bin/python3.13", "/usr/bin/xpra", "start", ":118",
                "--bind-tcp=127.0.0.1:14500,auth=http-header:property=X-Forwarded-Proto,value=https",
                "--start-new-commands=no", "--clipboard=no", "--speaker=off",
                "--microphone=off", "--webcam=no", "--file-transfer=no",
                "--printing=no", "--open-files=no", "--open-url=no")
        from dataclasses import replace
        config = replace(self.config, xpra_argv_sha256=hashlib.sha256(b"\0".join(x.encode() for x in argv)).hexdigest())
        with mock.patch("hermes_installer.remote.manual_stage_inspector._process_argv", return_value=argv):
            self.assertEqual(_validate_xpra_argv(config, 123), config.xpra_argv_sha256)
        bad = argv + ("--start-child=/bin/sh",)
        config = replace(config, xpra_argv_sha256=hashlib.sha256(b"\0".join(x.encode() for x in bad)).hexdigest())
        with mock.patch("hermes_installer.remote.manual_stage_inspector._process_argv", return_value=bad):
            with self.assertRaises(StageInspectionDenied):
                _validate_xpra_argv(config, 123)

    def test_manual_stage_composes_existing_server_without_managed_authority(self):
        from hermes_installer.remote.manual_stage import (
            StageFixedXpraConnector, StageGatewayLaunch, create_stage_gateway_app,
        )
        from hermes_installer.remote.server import GatewayRuntime
        sessions = StageGatewayPolicySessionAdapter(self.config, self.verifier)
        connector = StageFixedXpraConnector(self.config, sessions)
        launch = StageGatewayLaunch(self.verifier.policy, sessions, connector)
        runtime = GatewayRuntime(policy=launch.policy, root_sessions=sessions,
                                 connector_factory=connector.open, max_lease_seconds=30,
                                 max_active_sockets=1, watchdog_seconds=5)
        app = create_stage_gateway_app(launch)
        paths = {route.resource.canonical for route in app.router.routes()}
        self.assertIn("/__stage_access_probe", paths)
        self.assertIn("/client/{tail}", paths)
        self.assertIsNone(runtime.private_origin_probe)
        self.assertEqual(runtime.max_lease_seconds, 30)

    def test_active_edge_watchdog_rechecks_and_closes_revoked_session(self):
        from hermes_installer.remote.gateway import validate_access_jwt
        sessions = StageGatewayPolicySessionAdapter(self.config, self.verifier)
        principal = validate_access_jwt(self.token(), policy=self.verifier.policy)
        clock = [100.0]
        sessions.monotonic = lambda: clock[0]
        sessions._verify_xpra_current = lambda: None
        with mock.patch("hermes_installer.remote.manual_stage._read_config_current"), \
                mock.patch.object(self.verifier, "verify", return_value=(principal, 130.0, 140.0)) as verify:
            admission = sessions.admit(access_jwt=self.token(), action="websocket-attach",
                                       route_id="xpra-websocket")
            clock[0] = 103.9
            sessions.verify_fresh_access_edge(admission.handle)
            verify.assert_called_once()
            verify.reset_mock()
            clock[0] = 104.0
            sessions.verify_fresh_access_edge(admission.handle)
            verify.assert_called_once()
            verify.side_effect = ManualStageDenied("edge now denies token")
            clock[0] = 108.0
            with self.assertRaises(ManualStageDenied):
                sessions.verify_fresh_access_edge(admission.handle)
            with self.assertRaises(ManualStageDenied):
                sessions.current(admission.handle)

    def test_manual_websocket_lease_is_bounded_and_failed_renewal_revokes_handle(self):
        class FixtureEdge:
            def __init__(self, config):
                self.config = config
            def verify(self, _token, *, action, session_id):
                self.assertions = (action, session_id)
                now = time.monotonic()
                return Principal("owner@example.net", "subject", time.time() + 120, "f" * 64), now + 30, now + 120
        edge = FixtureEdge(self.config)
        sessions = StageGatewayPolicySessionAdapter(self.config, edge)
        with mock.patch.object(sessions, "_verify_xpra_current"), \
             mock.patch("hermes_installer.remote.manual_stage._read_config_current"):
            admission = sessions.admit(access_jwt="fixture-token", action="websocket-attach",
                                       route_id="xpra-websocket")
            self.assertLessEqual(admission.lease_expires_monotonic - admission.issued_monotonic, 30.01)
            challenge = sessions.challenge(admission.handle)
            self.assertGreater(challenge.expires_monotonic - admission.issued_monotonic, 25)
            with self.assertRaises(ManualStageDenied):
                sessions.renew(handle=admission.handle, session_id=admission.session_id,
                               access_jwt="fixture-token", renewal_nonce="replayed")
            with self.assertRaises(ManualStageDenied):
                sessions.current(admission.handle)
