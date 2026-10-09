import dataclasses
import importlib.util
import sys
import time
import types
import unittest
import unittest.mock
import queue

from hermes_installer.remote.gateway import GatewayDenied, RemotePolicy
from hermes_installer.remote.jwks import JWKSCache
from hermes_installer.remote.http_framing import HTTPFrameError
from hermes_installer.network import HTTPResult


class FakeNetwork:
    def __init__(self, **kwargs):
        self.options = kwargs
        self.requested = None
        self.result = None

    def request(self, url, *, method, headers, cancelled=None):
        self.requested = (url, method, headers)
        if cancelled is not None and cancelled():
            raise GatewayDenied("cancelled")
        return self.result


class RemoteJWKSUnitTests(unittest.TestCase):
    def test_issuer_and_key_set_are_fixed_bounded_and_cached(self):
        with self.assertRaises(ValueError):
            JWKSCache("https://evil.example")
        body = b'{"keys":[{"kty":"RSA","kid":"kid1","use":"sig","alg":"RS256","n":"a","e":"AQAB"},{"kty":"oct","kid":"bad"}]}'
        seen = []

        def factory(**kw):
            network = FakeNetwork(**kw)
            network.result = HTTPResult(200, {"Content-Length": str(len(body))}, body)
            seen.append(network)
            return network

        now = [0.0]
        cache = JWKSCache("https://team.cloudflareaccess.com", clock=lambda: now[0])
        with unittest.mock.patch("hermes_installer.remote.jwks.BoundedNetwork", factory):
            first = cache.load()
            self.assertEqual(set(first), {"kid1"})
            self.assertEqual(cache.key("kid1")["kty"], "RSA")
            self.assertEqual(len(seen), 1)
            self.assertEqual(seen[0].requested[0], "https://team.cloudflareaccess.com/cdn-cgi/access/certs")
            with self.assertRaises(GatewayDenied):
                cache.key("missing")
            self.assertEqual(len(seen), 2)
            with self.assertRaises(GatewayDenied):
                cache.key("still-missing")
            self.assertEqual(len(seen), 2)

    def test_jwks_redirect_compression_and_oversize_are_rejected(self):
        cases = (
            HTTPResult(302, {"Location": "https://evil.example"}, b"{}"),
            HTTPResult(200, {"Content-Encoding": "gzip"}, b"{}"),
            HTTPResult(200, {"Content-Length": "999999"}, b"{}"),
            HTTPResult(200, {}, b"x" * (262144 + 1)),
        )
        for result in cases:
            def factory(**kw):
                network = FakeNetwork(**kw)
                network.result = result
                return network
            cache = JWKSCache("https://team.cloudflareaccess.com")
            with unittest.mock.patch("hermes_installer.remote.jwks.BoundedNetwork", factory):
                with self.assertRaises(GatewayDenied):
                    cache.load()


@dataclasses.dataclass(frozen=True)
class AdmissionRequest:
    schema: int
    request_id: str
    hostname: str
    origin: str
    route_id: str
    action: str
    client_nonce: str


class OpaqueHandle(str):
    @property
    def value(self):
        return str(self)


class FixtureRootAuthority:
    """Synthetic root IPC fixture; it is not Access or native target evidence."""
    def __init__(self):
        self.allowed = True
        self.calls = []
        self.records = {}
        self.n = 0

    def admit_remote_session(self, access_jwt, request):
        self.calls.append(("admit", access_jwt, request))
        if not self.allowed or access_jwt != b"fixture-access-token":
            raise GatewayDenied("root Access/current policy denied")
        self.n += 1
        handle = OpaqueHandle(f"{self.n:043d}")
        session_id = f"root-session-{self.n}"
        self.records[handle] = (session_id, request.route_id, request.action)
        now = time.monotonic()
        return types.SimpleNamespace(
            schema=1, remote_session_handle=handle, session_id=session_id,
            admission_kind="one-shot-asset" if request.action == "asset-read" else "leased-websocket",
            principal_binding_id="opaque-binding", profile_id="hermes-desktop",
            gateway_generation="gateway-generation", desktop_generation="desktop-generation",
            route_id=request.route_id, issued_monotonic=now,
            lease_expires_monotonic=now + 30, jwt_expires_monotonic=now + 60,
            policy_verified_monotonic=now, policy_revision="fixture-policy-revision",
            policy_config_digest="a" * 64,
        )

    def challenge_remote_session(self, handle):
        session_id, _route, _action = self.records[handle]
        return types.SimpleNamespace(schema=1, session_id=session_id,
                                     renewal_nonce="R" * 43, expires_monotonic=time.monotonic() + 20)

    def renew_remote_session(self, handle, token, nonce):
        self.calls.append(("renew", token, nonce))
        if not self.allowed or token != b"fixture-access-token" or nonce != "R" * 43:
            raise GatewayDenied("root fresh Access/policy denied")
        session_id, _route, _action = self.records[handle]
        now = time.monotonic()
        return types.SimpleNamespace(schema=1, remote_session_handle=handle, session_id=session_id,
                                     lease_expires_monotonic=now + 30,
                                     jwt_expires_monotonic=now + 60,
                                     policy_verified_monotonic=now)

    def close_remote_session(self, handle):
        record = self.records.pop(handle, None)
        if record is None:
            raise GatewayDenied("unknown root session")
        return types.SimpleNamespace(schema=1, session_id=record[0], state="closed")


class FakeRootConnector:
    def __init__(self, authority, handle):
        record = authority.records[handle]
        self.session_id, self.route_id, action = record
        self.expires_monotonic = time.monotonic() + 25
        self.authority = authority
        self.handle = handle
        self.incoming = bytearray()
        self.outgoing = queue.Queue()
        self.closed = False
        self.writes = []
        if action == "asset-read":
            self.route_id = "xpra-http"
        else:
            self.route_id = "xpra-websocket"

    def write(self, data):
        if self.closed:
            raise GatewayDenied("connector closed")
        self.writes.append(data)
        if self.route_id == "xpra-http":
            line = data.split(b"\r\n", 1)[0]
            if line == b"GET /client/index.html HTTP/1.1":
                body = b"<!doctype html><body>fixture native app client</body>"
                ctype = b"text/html"
            else:
                body = b"body{margin:0}"
                ctype = b"text/css"
            self.incoming.extend(b"HTTP/1.1 200 OK\r\nContent-Type: " + ctype + b"\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)
        else:
            self.outgoing.put(data)
        return len(data)

    def read(self, maximum_bytes):
        if self.closed:
            return b""
        if self.route_id == "xpra-websocket":
            try:
                data = self.outgoing.get(timeout=2)
            except queue.Empty:
                return b""
            return data[:maximum_bytes]
        if not self.incoming:
            return b""
        result = bytes(self.incoming[:maximum_bytes])
        del self.incoming[:maximum_bytes]
        return result

    def close(self):
        self.closed = True
        self.outgoing.put(b"")


AIOHTTP_AVAILABLE = importlib.util.find_spec("aiohttp") is not None
@unittest.skipUnless(AIOHTTP_AVAILABLE, "install the isolated remote runtime lock before HTTP/WebSocket cohort")
class RemoteGatewayRootBridgeTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        from aiohttp.test_utils import TestClient, TestServer
        from hermes_installer.remote.root_sessions import RootRemoteSessionClient
        from hermes_installer.remote.server import GatewayRuntime, create_app
        authority_module = types.ModuleType("hermes_installer.authority.remote_sessions")
        authority_module.RemoteAdmissionRequest = AdmissionRequest
        sys.modules[authority_module.__name__] = authority_module
        self.addCleanup(sys.modules.pop, authority_module.__name__, None)
        self.authority = FixtureRootAuthority()
        self.root = RootRemoteSessionClient(self.authority, "desk.example.net", "https://desk.example.net",
                                            frozenset({"xpra-http"}), "xpra-websocket")
        self.opened = []
        runtime = GatewayRuntime(RemotePolicy("desk.example.net", "https://team.cloudflareaccess.com", "aud",
                                               frozenset({"owner@example.net"}), {}), root_sessions=self.root,
                                 connector_factory=lambda handle: self._open(handle))
        self.client = TestClient(TestServer(create_app(runtime)))
        await self.client.start_server()
        self.headers = {"Host": "desk.example.net", "Origin": "https://desk.example.net",
                        "Cf-Access-Jwt-Assertion": "fixture-access-token"}

    def _open(self, handle):
        connector = FakeRootConnector(self.authority, handle)
        self.opened.append(connector)
        return connector

    async def asyncTearDown(self):
        await self.client.close()

    async def test_asset_uses_root_admission_and_fixed_connector_frame(self):
        response = await self.client.get("/client/css/client.css", headers=self.headers)
        self.assertEqual(response.status, 200)
        self.assertIn("#float_menu{display:none!important}", await response.text())
        self.assertEqual(len(self.opened), 1)
        frame = self.opened[0].writes[0]
        self.assertTrue(frame.startswith(b"GET /client/css/client.css HTTP/1.1\r\n"))
        self.assertNotIn(b"fixture-access-token", frame)
        self.assertTrue(self.opened[0].closed)
        call = self.authority.calls[0]
        self.assertEqual(call[0:2], ("admit", b"fixture-access-token"))
        self.assertEqual((call[2].action, call[2].route_id), ("asset-read", "xpra-http"))

    async def test_root_denial_precedes_connector_and_any_xpra_response(self):
        self.authority.allowed = False
        response = await self.client.get("/client/css/client.css", headers=self.headers)
        self.assertEqual(response.status, 403)
        self.assertEqual(self.opened, [])

    async def test_unpinned_asset_and_arbitrary_index_query_are_rejected(self):
        response = await self.client.get("/client/server-info", headers=self.headers)
        self.assertEqual(response.status, 403)
        response = await self.client.get("/client/index.html?server=evil", headers=self.headers)
        self.assertEqual(response.status, 403)
        self.assertEqual(self.authority.calls, [])

    async def test_session_renewal_uses_fresh_raw_access_token_and_local_one_use_challenge(self):
        created = await self.client.post("/session", headers=self.headers)
        self.assertEqual(created.status, 200)
        session = await created.json()
        self.assertNotIn("remote_session_handle", session)
        renew = await self.client.post("/renew", headers=self.headers,
                                      json={"lease_id": session["lease_id"],
                                            "challenge": session["renewal_challenge"]})
        self.assertEqual(renew.status, 200)
        self.assertEqual(self.authority.calls[-1][0], "renew")
        self.assertEqual(self.authority.calls[-1][1], b"fixture-access-token")
        replay = await self.client.post("/renew", headers=self.headers,
                                        json={"lease_id": session["lease_id"],
                                              "challenge": session["renewal_challenge"]})
        self.assertEqual(replay.status, 403)

    async def test_binary_websocket_uses_opaque_root_connector_and_closes_on_logout(self):
        created = await self.client.post("/session", headers=self.headers)
        self.assertEqual(created.status, 200)
        session = await created.json()
        path = ("/client/?lease=" + session["lease_id"] + "&profile=hermes-desktop&nonce=" + session["socket_nonce"])
        socket = await self.client.ws_connect(path, headers=self.headers, protocols=("binary",))
        await socket.send_bytes(b"allowed-screen-input")
        response = await socket.receive(timeout=2)
        self.assertEqual(response.data, b"allowed-screen-input")
        self.assertTrue(self.opened[-1].writes[0] == b"allowed-screen-input")
        await socket.close()
        self.assertTrue(self.opened[-1].closed)

    async def test_access_denial_on_fresh_renewal_removes_session(self):
        created = await self.client.post("/session", headers=self.headers)
        session = await created.json()
        self.authority.allowed = False
        response = await self.client.post("/renew", headers=self.headers,
                                          json={"lease_id": session["lease_id"],
                                                "challenge": session["renewal_challenge"]})
        self.assertEqual(response.status, 403)


if __name__ == "__main__":
    unittest.main()
