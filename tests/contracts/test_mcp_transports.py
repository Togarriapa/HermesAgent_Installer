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
                        "result": {"tools": []},
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
        context = fixture_context(loopback=True)
        transport = StreamableHTTPTransport(
            f"http://127.0.0.1:{port}/mcp", service_id="fixture", timeout=2,
        )
        class InProcessAuthority:
            """Synthetic signed-authority boundary; the HTTP request stays loopback-only."""
            def __init__(self, bound_transport):
                self.transport = bound_transport
                self.context_value = None

            def context(self, *, purpose, intent, lease_seconds, cancelled=None, **_kwargs):
                now = time.monotonic()
                ctx = HostContext(
                    principal_id="fixture-principal", profile_id="fixture-profile",
                    namespace_id="fixture-namespace", uid=1000, purpose=purpose,
                    intent_id=canonical_digest({"purpose": purpose, "intent": intent}),
                    trace_id="fixture-trace", sensitivity=AuthoritySensitivity.UNKNOWN,
                    lineage_hash="a" * 64, policy_revision="fixture-policy",
                    capabilities=frozenset({"mcp:fixture:connect", "mcp:fixture:read",
                                             "mcp:test:loopback"}),
                    issued_at_monotonic=now, monotonic_expires_at=now + min(lease_seconds, 20),
                    nonce="fixture-context-nonce", grant_id="fixture-context-grant",
                    signature="fixture-context-signature",
                    final_payload_digest=_kwargs.get("final_payload_digest"),
                    operation=_kwargs.get("operation"),
                )
                self.context_value = ctx
                return ctx

            def authorize_effect(self, context, *, capability, target, recipient,
                                 request_digest, retry_index, cancelled=None):
                now = time.monotonic()
                return EffectAuthorization(
                    principal_id=context.principal_id, profile_id=context.profile_id,
                    namespace_id=context.namespace_id, uid=context.uid,
                    purpose=context.purpose, sensitivity=context.sensitivity,
                    trace_id=context.trace_id, policy_revision=context.policy_revision,
                    lineage_hash=context.lineage_hash, capability=capability,
                    intent_id=context.intent_id, target=target, recipient=recipient,
                    request_digest=request_digest, retry_index=retry_index,
                    issued_at_monotonic=now, monotonic_expires_at=min(
                        context.monotonic_expires_at, now + 5),
                    grant_id="fixture-effect-grant", nonce="fixture-effect-nonce",
                    context_digest=canonical_digest(context.claims()),
                    signature="fixture-effect-signature",
                    final_payload_digest=context.final_payload_digest,
                    operation=context.operation,
                )

            def mcp_request(self, authorization, *, target, payload, timeout, cancelled=None):
                if (authorization.target != target or target != "mcp:fixture:http"
                        or canonical_digest(payload) != authorization.request_digest
                        or self.context_value is None
                        or canonical_digest(payload) != self.context_value.final_payload_digest
                        or authorization.final_payload_digest != self.context_value.final_payload_digest
                        or authorization.operation != self.context_value.operation
                        or cancelled and cancelled()):
                    raise PermissionError("fixture authority binding mismatch")
                envelope = json.loads(payload.decode("utf-8"))
                request = {"jsonrpc": "2.0", "id": envelope["request_id"],
                           "method": envelope["method"], "params": envelope["params"]}
                response = asyncio.run(self.transport.request(
                    request, dispatch_context=self.context_value,
                    dispatch_authorization=authorization,
                ))
                body = canonical_bytes(response) if envelope["request_id"] is not None else b""
                return BrokeredEffectResponse(
                    status=200, body=body, headers={"content-type": "application/json"},
                    receipt_id="fixture-effect-receipt",
                )

        authority = InProcessAuthority(transport)
        client = MCPClient(transport, {"get_state"}, service_id="fixture",
                           selection="sensor.office", authority_client=authority, timeout=2)
        async with server:
            await client.initialize()
            await client.discover()
            self.assertEqual([item["method"] for item in requests],
                             ["initialize", "notifications/initialized", "tools/list"])
            await client.close()

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
