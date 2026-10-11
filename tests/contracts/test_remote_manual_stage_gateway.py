"""Effects and fail-closed tests for the separately owned Jarvis stage."""
import base64
import hashlib
import json
import os
import secrets
import socket
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
import unittest
from unittest import mock
from hermes_installer.remote.gateway import RemotePolicy
from hermes_installer.remote.manual_stage import (
    ManualGatewayStageConfig, ManualStageDenied, StageAcceptedIngressObservation,
    StageEdgeAccessVerifier, StageGatewayPolicySessionAdapter, _CURRENT_INGRESS,
    _mint_accepted_ingress,
)
from hermes_installer.remote.gateway import Principal
from hermes_installer.remote.manual_stage_inspector import (
    MAX_APP_FILE_BYTES, MAX_APP_TREE_BYTES, XPRA_CONTROL_STUB_PATH,
    XPRA_CONTROL_STUB_SHA256, XPRA_CONTROL_STUB_SIZE, XPRA_CORE_PATH,
    XPRA_CORE_SHA256, XPRA_CORE_SIZE, XPRA_PINNED_MODULES, XPRA_WINDOW_PATH,
    XPRA_WINDOW_SHA256, XPRA_WINDOW_SIZE, XPRA_COMMAND_PATH, XPRA_COMMAND_SIZE,
    XPRA_COMMAND_SHA256, StageInspectionDenied,
    _check_app_file_size, _validate_nft, _verify_pinned_xpra_modules,
    verify_current_inspection,
)

try:
    import jwt
    from cryptography.hazmat.primitives.asymmetric import rsa
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

try:
    import aiohttp  # noqa: F401
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False


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
        self.ingress_tmp = tempfile.TemporaryDirectory(prefix="hermes-stage-ingress-")
        self.addCleanup(self.ingress_tmp.cleanup)
        self.ingress_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(self.ingress_socket.close)
        ingress_path = Path(self.ingress_tmp.name) / "origin.sock"
        self.ingress_socket.bind(str(ingress_path))
        os.chmod(ingress_path, 0o660)
        ingress_stat = os.lstat(ingress_path)
        self.config = ManualGatewayStageConfig(
            hostname="jarvis.togarriapahome.uk", issuer="https://team.cloudflareaccess.com",
            audience="stage-app-aud", allowed_emails=frozenset({"owner@example.net"}),
            gateway_uid=os.getuid(), gateway_gid=os.getgid(), xpra_uid=18001, display_number=118,
            xpra_binary=Path("/usr/bin/python3.13"), xpra_binary_sha256="a" * 64,
            xpra_program=Path("/usr/bin/xpra"), xpra_program_sha256="b" * 64,
            xpra_argv_sha256="e" * 64,
            unit_fragment=Path("/etc/systemd/system/hermes-xpra-stage.service"), unit_sha256="f" * 64,
            appdir=Path("/opt/hermes-jarvis-mvp-20261011/Hermes-Desktop.AppDir"),
            appdir_manifest_sha256="d" * 64,
            boot_id="00000000-0000-0000-0000-000000000000",
            gateway_unit_sha256="1" * 64, tunnel_unit_sha256="2" * 64,
            cloudflared_binary_sha256="3" * 64,
            ingress_socket=ingress_path,
            config_path=Path("/etc/hermes-installer/gateway-stage.json"), config_sha256="c" * 64)
        self.listener_identity = (ingress_stat.st_dev, ingress_stat.st_ino)
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

    def root_ingress_observation(self, *, issued=None, expires=None, peer=(77, 981, 981),
                                 config_digest=None):
        from hermes_installer.remote import manual_stage_inspector as inspector
        from hermes_installer.remote.manual_stage_inspector import StageVerifiedIngressObservation
        issued = time.monotonic() if issued is None else issued
        expires = issued + 4.8 if expires is None else expires
        return StageVerifiedIngressObservation(
            schema=1, nonce=secrets.token_hex(32), boot_id=self.config.boot_id,
            issued_monotonic=issued, expires_monotonic=expires,
            peer_pid=peer[0], peer_uid=peer[1], peer_gid=peer[2], peer_start_ticks="123",
            tunnel_unit_sha256=self.config.tunnel_unit_sha256,
            tunnel_config_sha256=inspector._tunnel_config_digest(self.config),
            tunnel_executable_sha256=self.config.cloudflared_binary_sha256,
            origin_socket_device=self.listener_identity[0], origin_socket_inode=self.listener_identity[1],
            config_sha256=config_digest or self.config.config_sha256,
            proof_sha256="a" * 64, _seal=inspector._OBSERVATION_SEAL)

    def make_ingress(self, token):
        from types import SimpleNamespace
        from hermes_installer.remote.gateway import validate_access_jwt
        start = time.monotonic()
        principal = validate_access_jwt(token, policy=self.verifier.policy)
        root = self.root_ingress_observation(issued=start, expires=start + 4.9)
        return _mint_accepted_ingress(self.config, request_started=start, token=token,
            principal=principal, peer_pid=77, peer_uid=981, peer_gid=981, root_observation=root,
            listener_identity=self.listener_identity)

    def fixture_ingress(self, token, principal=None, *, started=None, expires=None):
        from types import SimpleNamespace
        principal = principal or Principal("owner@example.net", "subject", time.time() + 120, "f" * 64)
        started = time.monotonic() if started is None else started
        root = self.root_ingress_observation(issued=started, expires=expires or started + 4.9)
        return StageAcceptedIngressObservation(started, expires or started + 4.9,
            hashlib.sha256(token.encode("ascii")).hexdigest(), principal, started + 120,
            77, 981, 981, self.config.config_sha256, root, self.listener_identity[0], self.listener_identity[1], __import__(
                "hermes_installer.remote.manual_stage", fromlist=["_INGRESS_SEAL"])._INGRESS_SEAL)

    def test_authorization_requires_exact_fresh_protected_ingress(self):
        token = self.token()
        with self.assertRaises(ManualStageDenied):
            self.verifier.verify(token, action="websocket-attach", session_id="session-bound-id-123456")
        ingress = self.make_ingress(token)
        principal, lease, jwt_deadline = self.verifier.verify(token, action="websocket-attach",
            session_id="session-bound-id-123456", accepted_ingress=ingress)
        self.assertEqual(principal.email, "owner@example.net")
        self.assertLessEqual(lease - ingress.request_started_monotonic, 30.01)
        self.assertGreater(jwt_deadline, lease)
        with self.assertRaises(ManualStageDenied):
            self.verifier.verify(self.token(sub="other"), action="renew",
                session_id="session-bound-id-123456", accepted_ingress=ingress)
        with self.assertRaises(ManualStageDenied):
            ingress.verify_current(self.config, now=ingress.witness_expires_monotonic)

    def test_heartbeat_is_one_use_and_bound_to_original_token_and_principal(self):
        token = self.token()
        ingress = self.make_ingress(token)
        sessions = StageGatewayPolicySessionAdapter(self.config, self.verifier)
        ctx = _CURRENT_INGRESS.set(ingress)
        try:
            with mock.patch("hermes_installer.remote.manual_stage._read_config_current"), \
                    mock.patch.object(sessions, "_verify_xpra_current"):
                admission = sessions.admit(access_jwt=token, action="websocket-attach", route_id="xpra-websocket")
        finally:
            _CURRENT_INGRESS.reset(ctx)
        session_id, nonce = sessions.heartbeat_material(admission.handle)
        next_nonce, deadline = sessions.heartbeat(session_id=session_id, nonce=nonce, accepted_ingress=ingress)
        self.assertRegex(next_nonce, r"^[0-9a-f]{64}$")
        self.assertLessEqual(deadline - time.monotonic(), 5.01)
        with self.assertRaises(ManualStageDenied):
            sessions.heartbeat(session_id=session_id, nonce=nonce, accepted_ingress=ingress)

    def test_config_changed_or_expired_heartbeat_closes_session(self):
        token = self.token()
        ingress = self.make_ingress(token)
        sessions = StageGatewayPolicySessionAdapter(self.config, self.verifier)
        context = _CURRENT_INGRESS.set(ingress)
        try:
            with mock.patch("hermes_installer.remote.manual_stage._read_config_current"), \
                    mock.patch.object(sessions, "_verify_xpra_current"):
                admission = sessions.admit(access_jwt=token, action="websocket-attach", route_id="xpra-websocket")
        finally:
            _CURRENT_INGRESS.reset(context)
        sid, nonce = sessions.heartbeat_material(admission.handle)
        bad = __import__("dataclasses").replace(ingress, config_sha256="e" * 64)
        with self.assertRaises(ManualStageDenied):
            sessions.heartbeat(session_id=sid, nonce=nonce, accepted_ingress=bad)
        with self.assertRaises(ManualStageDenied):
            sessions.current(admission.handle)

    def test_request_ingress_joins_unix_peer_jwt_and_fresh_root_proof(self):
        import asyncio
        from types import SimpleNamespace
        from hermes_installer.remote import manual_stage

        token = self.token()
        class PeerSocket:
            family = __import__("socket").AF_UNIX
            def getsockname(self):
                return str(self.config.ingress_socket)
            def getsockopt(self, _level, _option, _size):
                return __import__("struct").pack("3i", 77, 981, 981)
        peer = PeerSocket()
        peer.config = self.config
        root = self.root_ingress_observation(peer=(77, 981, 981))
        listener = SimpleNamespace(st_mode=__import__("stat").S_IFSOCK | 0o660,
            st_uid=self.config.gateway_uid, st_gid=self.config.gateway_gid,
            st_dev=self.listener_identity[0], st_ino=self.listener_identity[1])
        class Headers(dict):
            def getall(self, key, default=()):
                value = self.get(key, default)
                return value if isinstance(value, list) else [value] if value != default else []
        request = SimpleNamespace(
            headers=Headers({"Host": self.config.hostname, "Cf-Access-Jwt-Assertion": token,
                             "X-Forwarded-For": "203.0.113.77", "Forwarded": "for=attacker.invalid"}),
            path="/client/bootstrap.html", method="GET",
            transport=SimpleNamespace(get_extra_info=lambda name: peer if name == "socket" else None))
        with mock.patch("hermes_installer.remote.manual_stage.os.lstat", return_value=listener), \
                mock.patch.object(manual_stage.socket, "SO_PEERCRED", 17, create=True), \
                mock.patch("hermes_installer.remote.manual_stage_inspector.verify_current_ingress",
                           return_value=root, create=True) as inspect:
            accepted = asyncio.run(manual_stage._accept_stage_ingress(request, self.config, self.verifier.policy))
        self.assertEqual(accepted.peer_pid, 77)
        self.assertEqual(accepted.peer_uid, 981)
        self.assertEqual(accepted.principal.email, "owner@example.net")
        inspect.assert_called_once_with(self.config, peer_pid=77, peer_uid=981, peer_gid=981)

    def test_accepted_ingress_rejects_replaced_socket_path(self):
        ingress = self.make_ingress(self.token())
        from types import SimpleNamespace
        replacement = SimpleNamespace(st_mode=__import__("stat").S_IFSOCK | 0o660,
            st_uid=self.config.gateway_uid, st_gid=self.config.gateway_gid,
            st_dev=self.listener_identity[0], st_ino=self.listener_identity[1] + 1)
        with mock.patch("hermes_installer.remote.manual_stage.os.lstat", return_value=replacement):
            with self.assertRaises(ManualStageDenied):
                ingress.verify_current(self.config)

    def test_accepted_ingress_rejects_sealed_root_proof_that_returns_false(self):
        from dataclasses import replace
        ingress = self.make_ingress(self.token())
        stale = self.root_ingress_observation(config_digest="e" * 64)
        self.assertIsNotNone(stale._seal)
        self.assertIs(stale.verify_current(self.config, ingress.peer_pid, ingress.peer_uid,
                                           ingress.peer_gid), False)
        with self.assertRaises(ManualStageDenied):
            replace(ingress, _root_observation=stale).verify_current(self.config)

    def test_request_ingress_rejects_tcp_duplicate_assertion_and_origin_spoof(self):
        import asyncio
        from types import SimpleNamespace
        from hermes_installer.remote import manual_stage
        token = self.token()
        class Headers(dict):
            def getall(self, key, default=()):
                value = self.get(key, default)
                return value if isinstance(value, list) else [value] if value != default else []
        class Peer:
            family = __import__("socket").AF_INET
        request = SimpleNamespace(headers=Headers({
            "Host": self.config.hostname, "Cf-Access-Jwt-Assertion": token}),
            path="/", method="GET",
            transport=SimpleNamespace(get_extra_info=lambda name: Peer() if name == "socket" else None))
        from hermes_installer.remote import manual_stage_inspector
        with mock.patch.object(manual_stage_inspector, "verify_current_ingress", create=True) as inspect:
            with self.assertRaises(ManualStageDenied):
                asyncio.run(manual_stage._accept_stage_ingress(request, self.config, self.verifier.policy))
            inspect.assert_not_called()
        request.transport = SimpleNamespace(get_extra_info=lambda name: None)
        request.headers["Cf-Access-Jwt-Assertion"] = [token, token]
        with self.assertRaises(ManualStageDenied):
            asyncio.run(manual_stage._accept_stage_ingress(request, self.config, self.verifier.policy))
        request.headers["Cf-Access-Jwt-Assertion"] = token
        request.headers["Origin"] = "https://evil.invalid"
        with self.assertRaises(ManualStageDenied):
            asyncio.run(manual_stage._accept_stage_ingress(request, self.config, self.verifier.policy))

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

    def test_boot_refresh_changes_only_the_boot_id_field(self):
        from hermes_installer.remote.manual_stage_bootstrap import _replace_boot_id
        original = {"schema": 2, "hostname": self.config.hostname, "gateway_uid": 996,
                    "gateway_gid": 981, "xpra_uid": 1000, "boot_id": "0" * 36,
                    "allowed_emails": ["owner@example.net"], "audience": "aud",
                    "gateway_unit_sha256": "1" * 64, "tunnel_unit_sha256": "2" * 64,
                    "cloudflared_binary_sha256": "3" * 64,
                    "ingress_socket": "/run/hermes-jarvis-mvp-gateway/origin.sock"}
        updated = json.loads(_replace_boot_id(json.dumps(original).encode(), "1" * 36))
        self.assertEqual(updated["boot_id"], "1" * 36)
        original.pop("boot_id")
        updated.pop("boot_id")
        self.assertEqual(updated, original)
        with self.assertRaises(StageInspectionDenied):
            _replace_boot_id(json.dumps({**original, "schema": 1}).encode(), "1" * 36)

    def test_boot_refresh_nft_effect_is_additive_and_rejects_foreign_owned_table(self):
        from hermes_installer.remote.manual_stage_bootstrap import ensure_owned_nft_rule
        inventory = json.dumps({"nftables": [
            {"metainfo": {"version": "1.0"}},
            {"table": {"family": "ip", "name": "unrelated", "handle": 7}},
        ]}).encode()
        exact_table = json.dumps({"nftables": [
            {"metainfo": {"version": "1.0"}},
            {"table": {"family": "inet", "name": "hermes_jarvis_mvp", "handle": 1}},
            {"chain": {"family": "inet", "table": "hermes_jarvis_mvp", "name": "output",
                       "type": "filter", "hook": "output", "prio": -10, "policy": "accept"}},
            {"rule": {"family": "inet", "table": "hermes_jarvis_mvp", "chain": "output", "handle": 2,
                "comment": "Jarvis MVP display gateway only", "expr": [
                    {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "daddr"}}, "right": "127.0.0.1"}},
                    {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 14500}},
                    {"match": {"op": "!=", "left": {"meta": {"key": "skuid"}}, "right": 996}},
                    {"reject": {"type": "tcp reset"}},
                ]}},
        ]}).encode()
        with mock.patch("hermes_installer.remote.manual_stage_bootstrap._run_fixed",
                        side_effect=[inventory, exact_table]) as run_fixed, \
             mock.patch("hermes_installer.remote.manual_stage_bootstrap._apply_nft_creation_batch") as apply:
            self.assertEqual(ensure_owned_nft_rule(), exact_table)
        apply.assert_called_once_with()
        self.assertIn(("ip", "unrelated"), __import__(
            "hermes_installer.remote.manual_stage_bootstrap", fromlist=["_parse_tables"])._parse_tables(inventory))
        self.assertNotIn(b"flush", __import__(
            "hermes_installer.remote.manual_stage_bootstrap", fromlist=["NFT_CREATE_BATCH"]).NFT_CREATE_BATCH)
        self.assertEqual(run_fixed.call_count, 2)

        wrong_table = exact_table.replace(b"Jarvis MVP display gateway only", b"foreign rule")
        occupied_inventory = json.dumps({"nftables": [
            {"metainfo": {"version": "1.0"}},
            {"table": {"family": "ip", "name": "unrelated", "handle": 7}},
            {"table": {"family": "inet", "name": "hermes_jarvis_mvp", "handle": 1}},
        ]}).encode()
        with mock.patch("hermes_installer.remote.manual_stage_bootstrap._run_fixed",
                        side_effect=[occupied_inventory, wrong_table]), \
             mock.patch("hermes_installer.remote.manual_stage_bootstrap._apply_nft_creation_batch") as apply:
            with self.assertRaises(StageInspectionDenied):
                ensure_owned_nft_rule()
        apply.assert_not_called()

        with mock.patch("hermes_installer.remote.manual_stage_bootstrap._run_fixed",
                        side_effect=[occupied_inventory, exact_table]), \
             mock.patch("hermes_installer.remote.manual_stage_bootstrap._apply_nft_creation_batch") as apply:
            self.assertEqual(ensure_owned_nft_rule(), exact_table)
        apply.assert_not_called()

    def test_stale_boot_config_override_is_root_only(self):
        with mock.patch("hermes_installer.remote.manual_stage.os.geteuid", return_value=1000):
            with self.assertRaises(ManualStageDenied):
                ManualGatewayStageConfig.load(allow_stale_boot_id=True)

    def test_xpra_argv_requires_root_configured_hash_and_fixed_app_only_surface(self):
        from hermes_installer.remote.manual_stage_inspector import _validate_xpra_argv
        argv = ("/usr/bin/python3.13", "/usr/bin/xpra", "start", ":118",
                "--bind-tcp=127.0.0.1:14500,auth=http-header:property=X-Forwarded-Proto,value=https",
                "--daemon=no", "--systemd-run=no", "--bind=none", "--html=on", "--remote-logging=no",
                "--start-child=/opt/hermes-jarvis-mvp-20261011/Hermes-Desktop.AppDir/Hermes",
                "--exit-with-children=yes", "--terminate-children=yes", "--start-new-commands=no",
                "--commands=yes", "--shell=no", "--control=no", "--audio=no", "--tray=no",
                "--file-transfer=no", "--open-files=no", "--open-url=no", "--forward-xdg-open=no",
                "--clipboard=no", "--webcam=no", "--speaker=off", "--microphone=off",
                "--notifications=no", "--system-tray=no", "--sharing=no", "--mdns=no",
                "--dbus=no", "--dbus-control=no", "--dbus-launch=", "--http-scripts=off",
                "--printing=no", "--xvfb=/usr/bin/Xvfb -screen 0 1920x1080x24 +extension GLX +extension RANDR +extension RENDER +extension Composite -extension DOUBLE-BUFFER -nolisten tcp -noreset -auth $XAUTHORITY")
        from dataclasses import replace
        config = replace(self.config, xpra_argv_sha256=hashlib.sha256(b"\0".join(x.encode() for x in argv)).hexdigest())
        with mock.patch("hermes_installer.remote.manual_stage_inspector._process_argv", return_value=argv):
            self.assertEqual(_validate_xpra_argv(config, 123), config.xpra_argv_sha256)
        bad = tuple("--start-child=/bin/sh" if x.startswith("--start-child=") else x for x in argv)
        config = replace(config, xpra_argv_sha256=hashlib.sha256(b"\0".join(x.encode() for x in bad)).hexdigest())
        with mock.patch("hermes_installer.remote.manual_stage_inspector._process_argv", return_value=bad):
            with self.assertRaises(StageInspectionDenied):
                _validate_xpra_argv(config, 123)
        bad = tuple("--commands=no" if x == "--commands=yes" else x for x in argv)
        config = replace(self.config, xpra_argv_sha256=hashlib.sha256(b"\0".join(x.encode() for x in bad)).hexdigest())
        with mock.patch("hermes_installer.remote.manual_stage_inspector._process_argv", return_value=bad):
            with self.assertRaises(StageInspectionDenied):
                _validate_xpra_argv(config, 123)
        bad = (*argv, "--start=/tmp/unreviewed-command")
        config = replace(self.config, xpra_argv_sha256=hashlib.sha256(b"\0".join(x.encode() for x in bad)).hexdigest())
        with mock.patch("hermes_installer.remote.manual_stage_inspector._process_argv", return_value=bad):
            with self.assertRaises(StageInspectionDenied):
                _validate_xpra_argv(config, 123)
        bad = (*argv, "--start-new-commands=no")
        config = replace(self.config, xpra_argv_sha256=hashlib.sha256(b"\0".join(x.encode() for x in bad)).hexdigest())
        with mock.patch("hermes_installer.remote.manual_stage_inspector._process_argv", return_value=bad):
            with self.assertRaises(StageInspectionDenied):
                _validate_xpra_argv(config, 123)
        bad = (*argv, "--start-after-connect=/tmp/unreviewed-command")
        config = replace(self.config, xpra_argv_sha256=hashlib.sha256(b"\0".join(x.encode() for x in bad)).hexdigest())
        with mock.patch("hermes_installer.remote.manual_stage_inspector._process_argv", return_value=bad):
            with self.assertRaises(StageInspectionDenied):
                _validate_xpra_argv(config, 123)
        for extra in ("--source-start=/tmp/unreviewed-source", "--exec-wrapper=/bin/sh"):
            bad = (*argv, extra)
            config = replace(self.config, xpra_argv_sha256=hashlib.sha256(
                b"\0".join(x.encode() for x in bad)).hexdigest())
            with self.subTest(extra=extra), mock.patch(
                    "hermes_installer.remote.manual_stage_inspector._process_argv", return_value=bad):
                with self.assertRaises(StageInspectionDenied):
                    _validate_xpra_argv(config, 123)
        bad = tuple(arg for arg in argv if arg != "--remote-logging=no")
        config = replace(self.config, xpra_argv_sha256=hashlib.sha256(b"\0".join(x.encode() for x in bad)).hexdigest())
        with mock.patch("hermes_installer.remote.manual_stage_inspector._process_argv", return_value=bad):
            with self.assertRaises(StageInspectionDenied):
                _validate_xpra_argv(config, 123)

    def test_xpra_config_search_roots_must_be_explicitly_empty_and_unique(self):
        import os
        import tempfile
        import hermes_installer.remote.manual_stage_inspector as inspector
        from hermes_installer.remote.manual_stage_inspector import _require_xpra_config_isolated_environment

        good = (b"PATH=/usr/bin\0XPRA_DEFAULT_CONF_DIRS=\0XPRA_SYSTEM_CONF_DIRS=\0"
                b"XPRA_USER_CONF_DIRS=\0")
        real_open = os.open
        with tempfile.NamedTemporaryFile() as env_fixture:
            env_fixture.write(good)
            env_fixture.flush()
            def fixture_open(path, flags, *args, **kwargs):
                if path == "/proc/123/environ":
                    self.assertTrue(flags & getattr(os, "O_NOFOLLOW", 0))
                    return real_open(env_fixture.name, flags, *args, **kwargs)
                return real_open(path, flags, *args, **kwargs)
            with mock.patch.object(inspector.os, "open", side_effect=fixture_open):
                _require_xpra_config_isolated_environment(123)
        cases = {
            "unset": b"PATH=/usr/bin\0XPRA_DEFAULT_CONF_DIRS=\0XPRA_SYSTEM_CONF_DIRS=\0",
            "nonempty": good.replace(b"XPRA_USER_CONF_DIRS=\0", b"XPRA_USER_CONF_DIRS=/tmp\0"),
            "duplicate": good + b"XPRA_USER_CONF_DIRS=\0",
            "malformed": good.rstrip(b"\0"),
        }
        for label, raw in cases.items():
            with self.subTest(case=label), tempfile.NamedTemporaryFile() as env_fixture:
                env_fixture.write(raw)
                env_fixture.flush()
                def fixture_open(path, flags, *args, **kwargs):
                    if path == "/proc/123/environ":
                        return real_open(env_fixture.name, flags, *args, **kwargs)
                    return real_open(path, flags, *args, **kwargs)
                with mock.patch.object(inspector.os, "open", side_effect=fixture_open), \
                        self.assertRaises(StageInspectionDenied):
                    _require_xpra_config_isolated_environment(123)

    def test_inspector_accepts_observed_hermes_file_sizes_with_bounded_totals(self):
        _check_app_file_size(195_497_248)
        _check_app_file_size(MAX_APP_FILE_BYTES)
        self.assertGreaterEqual(MAX_APP_TREE_BYTES, 363_556_225)
        with self.assertRaises(StageInspectionDenied):
            _check_app_file_size(MAX_APP_FILE_BYTES + 1)

    def test_listener_readback_matches_ipv4_loopback_port_and_selected_pid_inode(self):
        from pathlib import Path
        import os
        import hermes_installer.remote.manual_stage_inspector as inspector

        real_read_text = Path.read_text
        real_iterdir = Path.iterdir
        real_readlink = os.readlink
        pid = 4242
        fd_path = Path(f"/proc/{pid}/fd")
        fd_entry = fd_path / "7"
        proc_rows = {"text": ""}

        def proc_read_text(path, *args, **kwargs):
            if path == Path("/proc/net/tcp"):
                return ("sl local_address rem_address st tx_queue tr tm->when retrnsmt uid timeout inode\n"
                        + proc_rows["text"])
            return real_read_text(path, *args, **kwargs)

        def proc_iterdir(path):
            if path == fd_path:
                return iter((fd_entry,))
            return real_iterdir(path)

        def listener_result(local_address, inode="424242", process_inode="424242"):
            row = f"0: {local_address} 00000000:0000 0A 00000000:00000000 00:00000000 00000000 1000 0 {inode} 1\n"
            proc_rows["text"] = row
            def readlink(path, *args, **kwargs):
                if path == fd_entry:
                    return f"socket:[{process_inode}]"
                return real_readlink(path, *args, **kwargs)
            with mock.patch.object(Path, "read_text", proc_read_text), \
                    mock.patch.object(Path, "iterdir", proc_iterdir), \
                    mock.patch.object(inspector.os, "readlink", readlink):
                return inspector._listener_owned_by(pid)

        self.assertTrue(listener_result("0100007F:38A4"))  # 127.0.0.1:14500
        self.assertFalse(listener_result("0100007F:38B4"))  # 14516
        self.assertFalse(listener_result("00000000:38A4"))  # public IPv4 bind
        self.assertFalse(listener_result("0100007F:38A4", process_inode="999999"))

    def test_xpra_control_modules_pin_independent_paths_sizes_hashes_and_rejects_changes(self):
        from pathlib import Path
        import os
        import stat
        import tempfile
        import hermes_installer.remote.manual_stage_inspector as inspector

        self.assertEqual(str(XPRA_CONTROL_STUB_PATH),
                         "/usr/lib/python3/dist-packages/xpra/server/subsystem/stub.py")
        self.assertEqual(XPRA_CONTROL_STUB_SIZE, 5071)
        self.assertEqual(XPRA_CONTROL_STUB_SHA256,
                         "da12f27c1421dc71248b568791f186ee3d470d0969c4020da0d9d6d7a1a02279")
        self.assertEqual((XPRA_CORE_PATH, XPRA_CORE_SIZE, XPRA_CORE_SHA256),
                         (Path("/usr/lib/python3/dist-packages/xpra/server/core.py"), 75743,
                          "95a8bb41304181555ac33482931ba1c2460b4a1b03e458c3c5e8825adcf34e77"))
        self.assertEqual((XPRA_WINDOW_PATH, XPRA_WINDOW_SIZE, XPRA_WINDOW_SHA256),
                         (Path("/usr/lib/python3/dist-packages/xpra/server/subsystem/window.py"), 42476,
                          "7fd74d70e6a50e2f02727e263bdbec34826d23871abf4feedb230741ef09264f"))
        self.assertEqual((XPRA_COMMAND_PATH, XPRA_COMMAND_SIZE, XPRA_COMMAND_SHA256),
                         (Path("/usr/lib/python3/dist-packages/xpra/server/subsystem/command.py"),
                          24117,
                          "09e90f7dcb8a76687c59ee8c538faef21ce2881bdaed4cafb760eb8fe141f2d3"))
        self.assertEqual(XPRA_PINNED_MODULES, (
            (Path("/usr/lib/python3/dist-packages/xpra/server/subsystem/stub.py"), 5071,
             "da12f27c1421dc71248b568791f186ee3d470d0969c4020da0d9d6d7a1a02279"),
            (Path("/usr/lib/python3/dist-packages/xpra/server/core.py"), 75743,
             "95a8bb41304181555ac33482931ba1c2460b4a1b03e458c3c5e8825adcf34e77"),
            (Path("/usr/lib/python3/dist-packages/xpra/server/subsystem/window.py"), 42476,
             "7fd74d70e6a50e2f02727e263bdbec34826d23871abf4feedb230741ef09264f"),
            (Path("/usr/lib/python3/dist-packages/xpra/server/subsystem/command.py"), 24117,
             "09e90f7dcb8a76687c59ee8c538faef21ce2881bdaed4cafb760eb8fe141f2d3"),
        ))

        payloads = {
            "stub.py": b"positive patched stub module fixture\n",
            "core.py": b"positive patched core module fixture\n",
            "window.py": b"positive patched window module fixture\n",
            "command.py": b"positive patched command module fixture\n",
        }
        fixture_modules = []
        with tempfile.TemporaryDirectory(dir="/private/tmp") as tmp:
            for name, payload in payloads.items():
                fixture = Path(tmp) / name
                fixture.write_bytes(payload)
                fixture.chmod(0o644)
                fixture_modules.append((fixture, len(payload), hashlib.sha256(payload).hexdigest()))
            real_fstat = os.fstat

            def root_owned_fstat(fd):
                info = real_fstat(fd)
                values = list(info)
                if stat.S_ISDIR(info.st_mode):
                    values[0] = stat.S_IFDIR | 0o755
                values[4] = 0
                return os.stat_result(values)

            with mock.patch.object(inspector, "XPRA_PINNED_MODULES", tuple(fixture_modules)), \
                    mock.patch.object(inspector.os, "fstat", side_effect=root_owned_fstat):
                expected_binding = []
                for path, size, digest in fixture_modules:
                    expected_binding.extend((str(path).encode("ascii"), str(size).encode("ascii"),
                                             digest.encode("ascii")))
                expected_pin_digest = hashlib.sha256(
                    b"hermes-xpra-pinned-modules-v262\0" + b"\0".join(expected_binding)).hexdigest()
                self.assertEqual(_verify_pinned_xpra_modules(), expected_pin_digest)

                original_sizes = (4978, 75_650, 42_383, 23_581)
                for (path, _size, _digest), original_size in zip(fixture_modules, original_sizes):
                    path.chmod(0o600)
                    path.write_bytes(b"U" * original_size)
                    path.chmod(0o644)
                    with self.subTest(unpatched=path.name), self.assertRaises(StageInspectionDenied):
                        _verify_pinned_xpra_modules()
                    path.chmod(0o600)
                    path.write_bytes(payloads[path.name])
                    path.chmod(0o644)

                for path, size, _digest in fixture_modules:
                    path.chmod(0o600)
                    path.write_bytes(b"T" * size)
                    path.chmod(0o644)
                    with self.subTest(tampered=path.name), self.assertRaises(StageInspectionDenied):
                        _verify_pinned_xpra_modules()
                    path.chmod(0o600)
                    path.write_bytes(payloads[path.name])
                    path.chmod(0o644)

                for path, _size, _digest in fixture_modules:
                    path.unlink()
                    target = Path(tmp) / f"{path.stem}-target.py"
                    target.write_bytes(payloads[path.name])
                    target.chmod(0o644)
                    path.symlink_to(target)
                    with self.subTest(symlink=path.name), self.assertRaises(StageInspectionDenied):
                        _verify_pinned_xpra_modules()
                    path.unlink()
                    path.write_bytes(payloads[path.name])
                    path.chmod(0o644)

    def test_stage_http_adapter_maps_only_canonical_client_assets_to_xpra_root(self):
        from types import SimpleNamespace
        from hermes_installer.remote.http_framing import build_asset_request
        from hermes_installer.remote.manual_stage import _StageHTTPConnector
        connector = object.__new__(_StageHTTPConnector)
        connector.owner = SimpleNamespace(verify_current=lambda _admission: None)
        connector.admission = object()
        connector.sock = mock.Mock()
        frame = build_asset_request("GET", "/client/js/Client.js", canonicalize=lambda x: x)
        connector.write(frame)
        emitted = connector.sock.sendall.call_args.args[0]
        self.assertTrue(emitted.startswith(b"GET /js/Client.js HTTP/1.1\r\n"))
        self.assertIn(b"X-Forwarded-Proto: https\r\n", emitted)
        self.assertNotIn(b"/client/", emitted)
        connector.sock.reset_mock()
        for path in ("/client/../../etc/passwd", "/client/not-in-manifest"):
            with self.subTest(path=path), self.assertRaises(ManualStageDenied):
                connector.write(build_asset_request("GET", path, canonicalize=lambda x: x))
        connector.sock.sendall.assert_not_called()

    @unittest.skipUnless(HAS_AIOHTTP, "install the isolated gateway runtime dependencies")
    def test_upstream_websocket_large_frame_splits_and_idle_is_not_eof(self):
        from types import SimpleNamespace
        from hermes_installer.remote.manual_stage import _StageWebSocketConnector
        connector = object.__new__(_StageWebSocketConnector)
        connector.owner = SimpleNamespace(verify_current=lambda _admission: None)
        connector.admission = object()
        connector._rx_lock = __import__("threading").Lock()
        connector._rx_buffer = bytearray()
        payload = bytes((index % 251 for index in range(150_000)))
        results = iter([payload, None])
        def fake_run(coro, timeout=5):
            coro.close()
            return next(results)
        connector._run = fake_run
        chunks = [connector.read(), connector.read(), connector.read()]
        self.assertEqual([len(chunk) for chunk in chunks], [65_536, 65_536, 18_928])
        self.assertEqual(b"".join(chunks), payload)
        self.assertIsNone(connector.read())

    @unittest.skipUnless(HAS_AIOHTTP, "install the isolated gateway runtime dependencies")
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
        self.assertIn("/__stage_access_heartbeat", paths)
        self.assertIn("/client/{tail}", paths)
        self.assertIsNone(runtime.private_origin_probe)
        self.assertEqual(runtime.max_lease_seconds, 30)

    @unittest.skipUnless(HAS_AIOHTTP, "install the isolated gateway runtime dependencies")
    def test_stage_middleware_denies_before_redirect_and_injects_heartbeat_before_assets(self):
        import asyncio
        from types import SimpleNamespace
        from aiohttp import web
        from aiohttp.test_utils import TestClient, TestServer
        from hermes_installer.remote.manual_stage import (
            StageFixedXpraConnector, StageGatewayLaunch, _STAGE_HEARTBEAT_SCRIPT,
            _stage_ingress_middleware,
        )
        sessions = StageGatewayPolicySessionAdapter(self.config, self.verifier)
        connector = StageFixedXpraConnector(self.config, sessions)
        launch = StageGatewayLaunch(self.verifier.policy, sessions, connector)
        ingress = self.make_ingress(self.token())
        app = web.Application(middlewares=[web.middleware(_stage_ingress_middleware)])
        app["manual_stage_launch"] = launch
        app["gateway_runtime"] = SimpleNamespace(sessions={})
        app["stage_listener_identity"] = self.listener_identity
        async def redirect(_request):
            raise web.HTTPFound("/client/bootstrap.html")
        async def index(_request):
            return web.Response(text="<html><head><script src='/client/js/Client.js'></script></head><body></body></html>",
                                content_type="text/html")
        app.router.add_get("/", redirect)
        app.router.add_get("/client/index.html", index)

        async def exercise():
            client = TestClient(TestServer(app))
            await client.start_server()
            try:
                with mock.patch("hermes_installer.remote.manual_stage._accept_stage_ingress",
                                new=mock.AsyncMock(side_effect=ManualStageDenied("no proof"))):
                    denied = await client.get("/", allow_redirects=False)
                self.assertEqual(denied.status, 403)
                with mock.patch("hermes_installer.remote.manual_stage._read_config_current"), \
                        mock.patch("hermes_installer.remote.manual_stage._accept_stage_ingress",
                                   new=mock.AsyncMock(return_value=ingress)):
                    delivered = await client.get("/client/index.html")
                body = await delivered.text()
                self.assertEqual(delivered.status, 200)
                self.assertIn(_STAGE_HEARTBEAT_SCRIPT, body)
                self.assertLess(body.index(_STAGE_HEARTBEAT_SCRIPT), body.index("/client/js/Client.js"))
            finally:
                await client.close()
        asyncio.run(exercise())

    def test_inspector_serializes_fresh_proofs_without_caching_and_bounds_queue(self):
        from hermes_installer.remote import manual_stage_inspector as inspector
        active = 0
        maximum = 0
        calls = 0
        guard = threading.Lock()

        def observed(_config):
            nonlocal active, maximum, calls
            with guard:
                calls += 1
                serial = calls
                active += 1
                maximum = max(maximum, active)
            try:
                time.sleep(0.025)
                return f"{serial:064x}"
            finally:
                with guard:
                    active -= 1

        with mock.patch.object(inspector, "_request_current_inspection", side_effect=observed):
            with ThreadPoolExecutor(max_workers=6) as pool:
                proofs = list(pool.map(
                    lambda _n: verify_current_inspection(self.config, queue_timeout_seconds=1.0), range(6)))
            self.assertEqual(len(set(proofs)), 6)
            self.assertEqual(calls, 6)
            self.assertEqual(maximum, 1)

            inspector._INSPECTION_IPC_LOCK.acquire()
            try:
                with self.assertRaises(StageInspectionDenied):
                    verify_current_inspection(self.config, queue_timeout_seconds=0.05)
                self.assertEqual(calls, 6)
            finally:
                inspector._INSPECTION_IPC_LOCK.release()

    def test_connector_uses_only_fresh_admission_inspection_and_denies_stale_or_changed(self):
        from hermes_installer.remote.manual_stage import StageFixedXpraConnector
        principal = Principal("owner@example.net", "subject", time.time() + 120, "f" * 64)
        clock = [100.0]
        sessions = StageGatewayPolicySessionAdapter(self.config, self.verifier)
        sessions.monotonic = lambda: clock[0]
        connector = StageFixedXpraConnector(self.config, sessions)
        fake_connector = object()
        with mock.patch("hermes_installer.remote.manual_stage._read_config_current"), \
                mock.patch.object(self.verifier, "verify", return_value=(principal, 130.0, 140.0)), \
                mock.patch.object(sessions, "_verify_xpra_current") as inspect, \
                mock.patch("hermes_installer.remote.manual_stage._StageHTTPConnector", return_value=fake_connector) as create:
            token = _CURRENT_INGRESS.set(self.fixture_ingress("fixture-token", principal, started=100.0))
            try:
                admission = sessions.admit(access_jwt="fixture-token", action="asset-read", route_id="xpra-http")
            finally:
                _CURRENT_INGRESS.reset(token)
            record = sessions._records[admission.handle]
            self.assertEqual(record.last_edge_check, 100.0)
            self.assertEqual(record.last_inspection_check, 100.0)
            inspect.assert_called_once()
            self.assertIs(connector.open(admission.handle), fake_connector)
            # Opening the connector relies on the exact admission witness; it
            # does not launch another full app-tree walk.
            inspect.assert_called_once()
            create.assert_called_once()

            clock[0] = 105.01
            with self.assertRaises(ManualStageDenied):
                connector.open(admission.handle)
            create.assert_called_once()

        # A changed root-owned config fails before connector construction even
        # when the admission's proof itself is still fresh.
        clock[0] = 200.0
        sessions = StageGatewayPolicySessionAdapter(self.config, self.verifier)
        sessions.monotonic = lambda: clock[0]
        connector = StageFixedXpraConnector(self.config, sessions)
        with mock.patch("hermes_installer.remote.manual_stage._read_config_current"), \
                mock.patch.object(self.verifier, "verify", return_value=(principal, 230.0, 240.0)), \
                mock.patch.object(sessions, "_verify_xpra_current"), \
                mock.patch("hermes_installer.remote.manual_stage._StageHTTPConnector") as create:
            token = _CURRENT_INGRESS.set(self.fixture_ingress("fixture-token", principal, started=200.0))
            try:
                admission = sessions.admit(access_jwt="fixture-token", action="asset-read", route_id="xpra-http")
            finally:
                _CURRENT_INGRESS.reset(token)
            with mock.patch("hermes_installer.remote.manual_stage._read_config_current",
                            side_effect=ManualStageDenied("config changed")):
                with self.assertRaises(ManualStageDenied):
                    connector.open(admission.handle)
            create.assert_not_called()

    def test_admission_denies_if_queued_inspection_outlives_edge_or_root_witness(self):
        principal = Principal("owner@example.net", "subject", time.time() + 120, "f" * 64)
        clock = [100.0]
        sessions = StageGatewayPolicySessionAdapter(self.config, self.verifier)
        sessions.monotonic = lambda: clock[0]

        def slow_inspection(**_kwargs):
            # Simulate time spent waiting for the global inspector queue. The
            # edge witness was completed before this wait and must not be
            # restamped when the queued inspection returns.
            clock[0] = 105.01

        with mock.patch("hermes_installer.remote.manual_stage._read_config_current"), \
                mock.patch.object(self.verifier, "verify", return_value=(principal, 130.0, 140.0)), \
                mock.patch.object(sessions, "_verify_xpra_current", side_effect=slow_inspection):
            token = _CURRENT_INGRESS.set(self.fixture_ingress("fixture-token", principal, started=100.0))
            with self.assertRaises(ManualStageDenied):
                try:
                    sessions.admit(access_jwt="fixture-token", action="asset-read", route_id="xpra-http")
                finally:
                    _CURRENT_INGRESS.reset(token)
        self.assertEqual(sessions._records, {})

    def test_watchdog_inspection_timestamp_is_conservative_and_slow_check_closes(self):
        principal = Principal("owner@example.net", "subject", time.time() + 120, "f" * 64)
        clock = [100.0]
        sessions = StageGatewayPolicySessionAdapter(self.config, self.verifier)
        sessions.monotonic = lambda: clock[0]
        with mock.patch("hermes_installer.remote.manual_stage._read_config_current"), \
                mock.patch.object(self.verifier, "verify", return_value=(principal, 130.0, 140.0)), \
                mock.patch.object(sessions, "_verify_xpra_current"):
            token = _CURRENT_INGRESS.set(self.fixture_ingress("fixture-token", principal, started=100.0))
            try:
                admission = sessions.admit(access_jwt="fixture-token", action="websocket-attach",
                                           route_id="xpra-websocket")
            finally:
                _CURRENT_INGRESS.reset(token)
        clock[0] = 102.0
        with mock.patch.object(sessions, "_verify_xpra_current", side_effect=lambda **_kw: clock.__setitem__(0, 102.25)):
            sessions.refresh_active_inspection(admission.handle)
        self.assertEqual(sessions._records[admission.handle].last_inspection_check, 102.0)

        clock[0] = 103.0
        with mock.patch.object(sessions, "_verify_xpra_current", side_effect=lambda **_kw: clock.__setitem__(0, 108.01)):
            with self.assertRaises(ManualStageDenied):
                sessions.refresh_active_inspection(admission.handle)
        with self.assertRaises(ManualStageDenied):
            sessions.current(admission.handle)

    def test_renewal_binds_edge_and_inspection_times_before_inspector_queue(self):
        principal = Principal("owner@example.net", "subject", time.time() + 120, "f" * 64)
        clock = [200.0]
        sessions = StageGatewayPolicySessionAdapter(self.config, self.verifier)
        sessions.monotonic = lambda: clock[0]
        with mock.patch("hermes_installer.remote.manual_stage._read_config_current"), \
                mock.patch.object(self.verifier, "verify", return_value=(principal, 230.0, 240.0)), \
                mock.patch.object(sessions, "_verify_xpra_current"):
            token = _CURRENT_INGRESS.set(self.fixture_ingress("fixture-token", principal, started=200.0))
            try:
                admission = sessions.admit(access_jwt="fixture-token", action="websocket-attach",
                                           route_id="xpra-websocket")
            finally:
                _CURRENT_INGRESS.reset(token)
        clock[0] = 201.0
        challenge = sessions.challenge(admission.handle)
        token = _CURRENT_INGRESS.set(self.fixture_ingress("fixture-token", principal, started=201.0))
        with mock.patch.object(self.verifier, "verify", return_value=(principal, 230.0, 240.0)), \
                mock.patch.object(sessions, "_verify_xpra_current", side_effect=lambda **_kw: clock.__setitem__(0, 201.25)):
            try:
                sessions.renew(handle=admission.handle, session_id=admission.session_id,
                               access_jwt="fixture-token", renewal_nonce=challenge.renewal_nonce)
            finally:
                _CURRENT_INGRESS.reset(token)
        record = sessions._records[admission.handle]
        self.assertEqual(record.last_edge_check, 201.0)
        self.assertEqual(record.last_inspection_check, 201.0)
        self.assertEqual(record.admission.policy_verified_monotonic, 201.0)

        clock[0] = 202.0
        challenge = sessions.challenge(admission.handle)
        token = _CURRENT_INGRESS.set(self.fixture_ingress("fixture-token", principal, started=202.0))
        with mock.patch.object(self.verifier, "verify", return_value=(principal, 230.0, 240.0)), \
                mock.patch.object(sessions, "_verify_xpra_current", side_effect=lambda **_kw: clock.__setitem__(0, 207.01)):
            with self.assertRaises(ManualStageDenied):
                try:
                    sessions.renew(handle=admission.handle, session_id=admission.session_id,
                                   access_jwt="fixture-token", renewal_nonce=challenge.renewal_nonce)
                finally:
                    _CURRENT_INGRESS.reset(token)
        with self.assertRaises(ManualStageDenied):
            sessions.current(admission.handle)

    def test_active_edge_watchdog_rechecks_and_closes_revoked_session(self):
        from hermes_installer.remote.gateway import validate_access_jwt
        sessions = StageGatewayPolicySessionAdapter(self.config, self.verifier)
        principal = validate_access_jwt(self.token(), policy=self.verifier.policy)
        clock = [100.0]
        sessions.monotonic = lambda: clock[0]
        sessions._verify_xpra_current = lambda: None
        with mock.patch("hermes_installer.remote.manual_stage._read_config_current"), \
                mock.patch.object(self.verifier, "verify", return_value=(principal, 130.0, 140.0)) as verify:
            token = self.token()
            context = _CURRENT_INGRESS.set(self.fixture_ingress(token, principal, started=100.0))
            try:
                admission = sessions.admit(access_jwt=token, action="websocket-attach",
                                           route_id="xpra-websocket")
            finally:
                _CURRENT_INGRESS.reset(context)
            clock[0] = 103.9
            sessions.assert_current_proofs(admission.handle)
            verify.assert_called_once()
            clock[0] = 104.0
            sessions.refresh_active_edge(admission.handle)
            clock[0] = 108.0
            with self.assertRaises(ManualStageDenied):
                sessions.refresh_active_edge(admission.handle)
            with self.assertRaises(ManualStageDenied):
                sessions.current(admission.handle)

    def test_manual_websocket_lease_is_bounded_and_failed_renewal_revokes_handle(self):
        class FixtureEdge:
            def __init__(self, config):
                self.config = config
            def verify(self, _token, *, action, session_id, accepted_ingress=None):
                self.assertions = (action, session_id)
                now = time.monotonic()
                return Principal("owner@example.net", "subject", time.time() + 120, "f" * 64), now + 30, now + 120
        edge = FixtureEdge(self.config)
        sessions = StageGatewayPolicySessionAdapter(self.config, edge)
        with mock.patch.object(sessions, "_verify_xpra_current"), \
             mock.patch("hermes_installer.remote.manual_stage._read_config_current"):
            context = _CURRENT_INGRESS.set(self.fixture_ingress("fixture-token"))
            try:
                admission = sessions.admit(access_jwt="fixture-token", action="websocket-attach",
                                           route_id="xpra-websocket")
            finally:
                _CURRENT_INGRESS.reset(context)
            self.assertLessEqual(admission.lease_expires_monotonic - admission.issued_monotonic, 30.01)
            challenge = sessions.challenge(admission.handle)
            self.assertGreater(challenge.expires_monotonic - admission.issued_monotonic, 25)
            with self.assertRaises(ManualStageDenied):
                sessions.renew(handle=admission.handle, session_id=admission.session_id,
                               access_jwt="fixture-token", renewal_nonce="replayed")
            with self.assertRaises(ManualStageDenied):
                sessions.current(admission.handle)
