"""Synthetic-only transport integration fixtures; they do not establish host acceptance."""
from __future__ import annotations

import asyncio
import json
import time
import unittest

from hermes_installer.authority.types import (
    BrokeredEffectResponse, EffectAuthorization, HostContext,
    Sensitivity as AuthoritySensitivity, canonical_bytes, canonical_digest,
)
from hermes_installer.mcp.broker import mcp_intent
from hermes_installer.mcp.client import MCPClient
from hermes_installer.mcp.transports import StdioTransport, StreamableHTTPTransport, TransportError
from hermes_installer.policy import DispatchAuthorization, DispatchContext, Sensitivity as PolicySensitivity


class FixtureAuthority:
    def __call__(self, context, capability, intent_id, now, remaining, cancelled):
        if cancelled() or capability not in context.capabilities:
            return None
        return DispatchAuthorization(
            principal_id=context.principal_id, profile_id=context.profile_id,
            namespace=context.namespace, trace_id=context.trace_id,
            capabilities=context.capabilities, effective_sensitivity=context.effective_sensitivity,
            policy_revision=context.policy_revision, purpose=context.purpose, capability=capability,
            intent_id=intent_id, lineage_sha256=context.provenance[7:], grant_id=context.grant_id,
            expires_at_monotonic=min(context.lease_expires_at, now + remaining + 1),
        )


def fixture_context(*, loopback=False, stdio=False):
    caps = {"mcp:fixture:connect", "mcp:fixture:read"}
    if loopback:
        caps.add("mcp:test:loopback")
    if stdio:
        caps.add("mcp:test:stdio")
    return DispatchContext(
        profile_id="fixture-profile", purpose="mcp-transport-fixture",
        sensitivity=PolicySensitivity.PUBLIC, principal_id="fixture-principal",
        namespace="fixture-namespace", provenance="sha256:" + "b" * 64,
        capabilities=frozenset(caps), policy_revision="fixture-policy-v1",
        grant_id="fixture-grant", lease_expires_at=time.monotonic() + 30,
    )


class FakeManagedHandle:
    def __init__(self):
        self.writes = []
        self.responses = asyncio.Queue()
        self.stopped = False

    async def write(self, data, *, timeout):
        self.writes.append(data)
        message = json.loads(data)
        if "id" in message:
            method = message["method"]
            if method == "initialize":
                result = {"protocolVersion": "2025-03-26", "capabilities": {},
                          "serverInfo": {"name": "stdio fixture", "version": "1"}}
            else:
                result = {}
            await self.responses.put(json.dumps({"jsonrpc": "2.0", "id": message["id"],
                                                 "result": result}).encode() + b"\n")

    async def read(self, *, maximum_bytes, timeout):
        return await asyncio.wait_for(self.responses.get(), timeout)

    async def wait(self, *, timeout):
        return 0

    async def stop(self, reason, *, timeout):
        self.stopped = True


class MCPTransportTests(unittest.IsolatedAsyncioTestCase):
    async def test_stdio_uses_only_supervised_handle_and_requires_host_grant(self):
        context, handle = fixture_context(stdio=True), FakeManagedHandle()
        transport = StdioTransport(handle, service_id="fixture")
        with self.assertRaises(TransportError):
            await transport.request({"jsonrpc": "2.0", "id": 1, "method": "initialize"})
        self.assertEqual(handle.writes, [])
        grant = FixtureAuthority()(context, "mcp:fixture:connect", "fixture-connect",
                                  time.monotonic(), 3, lambda: False)
        response = await transport.request(
            {"jsonrpc": "2.0", "id": 1, "method": "initialize"},
            dispatch_context=context, dispatch_authorization=grant,
        )
        self.assertEqual(response["result"]["serverInfo"]["name"], "stdio fixture")
        await transport.close()
        self.assertTrue(handle.stopped)

    async def test_forged_stdio_handle_is_denied_before_any_child_io(self):
        context, handle = fixture_context(), FakeManagedHandle()
        transport = StdioTransport(handle, service_id="fixture")
        grant = FixtureAuthority()(context, "mcp:fixture:connect", "fixture-connect",
                                  time.monotonic(), 3, lambda: False)
        with self.assertRaises(TransportError):
            await transport.request({"jsonrpc": "2.0", "id": 1, "method": "initialize"},
                                    dispatch_context=context, dispatch_authorization=grant)
        self.assertEqual(handle.writes, [])

    async def test_http_streamable_transport_pins_loopback_fixture_and_negotiates(self):
        requests = []
        credential_checks = []
        credential_scopes = []

        async def serve(reader, writer):
            try:
                first = await reader.readline()
                headers = {}
                while True:
                    line = await reader.readline()
                    if line == b"\r\n":
                        break
                    key, value = line.decode().split(":", 1)
                    headers[key.lower()] = value.strip()
                length = int(headers["content-length"])
                payload = json.loads(await reader.readexactly(length))
                requests.append(payload)
                credential_checks.append(
                    headers.get("authorization") == "Bearer fixture-secret-canary"
                )
                method = payload["method"]
                if "id" not in payload:
                    status, body = 202, b""
                    content_type = "application/json"
                elif method == "initialize":
                    status, body = 200, json.dumps({
                        "jsonrpc": "2.0", "id": payload["id"],
                        "result": {"protocolVersion": "2025-03-26", "capabilities": {},
                                   "serverInfo": {"name": "HTTP fixture", "version": "1"}},
                    }).encode()
                    content_type = "application/json"
                elif method == "tools/list":
                    status, body = 200, json.dumps({
                        "jsonrpc": "2.0", "id": payload["id"],
                        "result": {"tools": [{
                            "name": "get_state",
                            "description": "Read one selected entity",
                            "inputSchema": {
                                "type": "object",
                                "properties": {"entity_id": {"type": "string"}},
                                "required": ["entity_id"],
                                "additionalProperties": False,
                            },
                            "annotations": {"readOnlyHint": True, "destructiveHint": False},
                        }]},
                    }).encode()
                    content_type = "application/json"
                elif method == "tools/call":
                    status, body = 200, json.dumps({
                        "jsonrpc": "2.0", "id": payload["id"],
                        "result": {"content": [{
                            "type": "text", "text": "sensor.office is 21 C",
                        }], "isError": False},
                    }).encode()
                    content_type = "application/json"
                else:
                    status, body = 200, json.dumps({
                        "jsonrpc": "2.0", "id": payload["id"], "result": {},
                    }).encode()
                    content_type = "application/json"
                writer.write(
                    f"HTTP/1.1 {status} fixture\r\n"
                    f"Content-Type: {content_type}\r\n"
                    f"Content-Length: {len(body)}\r\n"
                    "Mcp-Session-Id: fixture-session\r\n"
                    "Connection: close\r\n\r\n".encode() + body
                )
                await writer.drain()
            finally:
                writer.close()
                await writer.wait_closed()

        server = await asyncio.start_server(serve, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        from pathlib import Path
        import os
        import tempfile
        import threading

        from hermes_installer.authority.client import AuthorityClient
        from hermes_installer.authority.service import (
            AuthorityService, EffectRule, PrincipalBinding,
        )
        from hermes_installer.authority.types import Sensitivity
        from hermes_installer.mcp.broker import (
            ProtectedMCPService, build_mcp_handlers,
        )

        class FixturePolicy:
            revision = "mcp-http-fixture-v1"

            def classify(self, *, purpose, intent, source_contexts, binding):
                return Sensitivity.UNKNOWN, canonical_digest({
                    "purpose": purpose, "intent": intent, "sources": [],
                })

            def allow_effect(self, *, context, rule, request_digest, retry_index):
                return True

        class FixtureNetwork:
            def __init__(self, bound_transport):
                self.transport = bound_transport

            def exchange(self, request, *, context, authorization, timeout, cancelled):
                return asyncio.run(self.transport.request(
                    request, dispatch_context=context,
                    dispatch_authorization=authorization,
                ))

        uid, gid = os.getuid(), os.getgid()
        capability_set = frozenset({
            "mcp:fixture:connect", "mcp:fixture:read", "mcp:test:loopback",
        })
        binding = PrincipalBinding(
            uid=uid, principal_id="fixture-principal", profile_id="fixture-profile",
            namespace_id="fixture-namespace", capabilities=capability_set,
        )
        service_record = ProtectedMCPService(
            service_id="fixture", channel="http", allowed_tools=frozenset({"get_state"}),
            transport_binding_id="fixture-binding", reviewed_revision="a" * 64,
            selection_arguments={"get_state": ("entity_id",)},
        )
        from hermes_installer.authority.enrollment import RootMCPCredentialHandle

        class FixtureVault:
            def resolve_reference(self, reference, *, peer_uid, required_scope, principal_id):
                if (reference != "fixture-token" or peer_uid != uid
                        or principal_id != binding.principal_id):
                    raise PermissionError("fixture credential binding mismatch")
                credential_scopes.append(required_scope)
                return "fixture-secret-canary"

        credential_handle = RootMCPCredentialHandle(
            "fixture", "fixture-token", FixtureVault(),
        )
        transport = StreamableHTTPTransport(
            f"http://127.0.0.1:{port}/mcp", service_id="fixture",
            credential_handle=credential_handle, timeout=2,
        )
        transport_factory = lambda _service, _context: FixtureNetwork(transport)
        handlers = build_mcp_handlers({"fixture": service_record},
                                      transport_factory=transport_factory)
        rules = {}
        for capability in ("mcp:fixture:connect", "mcp:fixture:read"):
            rule = EffectRule(
                capability=capability, operation="mcp.request", target="mcp:fixture:http",
            )
            rules[(rule.capability, rule.operation, rule.target)] = rule
        authority_service = AuthorityService(
            signing_key=b"fixture-authority-key-32-bytes-long!!",
            key_id="mcp-http-fixture", bindings_by_uid={uid: binding},
            rules=rules, handlers=handlers, policy=FixturePolicy(),
        )
        stop_event = threading.Event()
        with tempfile.TemporaryDirectory(prefix="hermes-mcp-authority-") as temp:
            socket_path = Path(temp) / "authority.sock"
            listener = threading.Thread(
                target=authority_service.serve_unix,
                kwargs={
                    "socket_path": socket_path, "socket_gid": gid,
                    "stop_event": stop_event, "expected_uid": uid,
                },
                daemon=True,
            )
            listener.start()
            deadline = time.monotonic() + 2
            while not socket_path.exists() and time.monotonic() < deadline:
                await asyncio.sleep(0.01)
            authority = AuthorityClient(
                socket_path, server_uid=uid, server_gid=gid, timeout=2,
            )
            client = MCPClient(
                transport, {"get_state"}, service_id="fixture",
                selection="sensor.office", authority_client=authority, timeout=2,
                result_scrubber=lambda _value: {
                    "content": [{"type": "text", "text": "Selected entity state read"}],
                },
            )
            try:
                async with server:
                    await client.initialize()
                    await client.discover()
                    self.assertEqual([item["method"] for item in requests],
                                     ["initialize", "notifications/initialized", "tools/list"])
                    self.assertEqual(await client.call_read(
                        "get_state", {"entity_id": "sensor.office"},
                    ), {"content": [{"type": "text", "text": "Selected entity state read"}]})
                    self.assertEqual(requests[-1]["params"]["arguments"]["entity_id"],
                                     "sensor.office")
                    self.assertTrue(all(credential_checks))
                    self.assertEqual(set(credential_scopes), {
                        "mcp:fixture:connect", "mcp:fixture:read",
                    })
                    await client.close()
            finally:
                stop_event.set()
                listener.join(timeout=2)
                server.close()
                await server.wait_closed()

    async def test_http_transport_rejects_private_network_without_host_capability(self):
        context, handle = fixture_context(loopback=False), FakeManagedHandle()
        grant = FixtureAuthority()(context, "mcp:fixture:connect", "fixture-connect",
                                  time.monotonic(), 3, lambda: False)
        server = await asyncio.start_server(lambda r, w: None, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        transport = StreamableHTTPTransport(f"http://127.0.0.1:{port}/mcp", service_id="fixture")
        try:
            with self.assertRaises(TransportError):
                await transport.request({"jsonrpc": "2.0", "id": 1, "method": "initialize"},
                                        dispatch_context=context, dispatch_authorization=grant)
        finally:
            server.close()
            await server.wait_closed()


if __name__ == "__main__":
    unittest.main()
