"""Executable MCP protocol fixtures; these identities and grants are synthetic only."""
from __future__ import annotations

import asyncio
import time
import unittest
from types import SimpleNamespace

from hermes_installer.mcp.client import MCPClient, MCPError
from hermes_installer.mcp.privacy import MCPPrivacyError, scrub_mcp_result
from hermes_installer.mcp.transports import StreamableHTTPTransport
from hermes_installer.authority import BrokeredEffectResponse, canonical_bytes, canonical_digest
from hermes_installer.policy import DispatchAuthorization, DispatchContext, Sensitivity


class FixtureAuthority:
    def __init__(self):
        self.calls = 0
        self.denied = False

    def __call__(self, context, capability, intent_id, now, remaining, cancelled):
        self.calls += 1
        if self.denied or cancelled() or capability not in context.capabilities:
            return None
        return DispatchAuthorization(
            principal_id=context.principal_id,
            profile_id=context.profile_id,
            namespace=context.namespace,
            trace_id=context.trace_id,
            capabilities=context.capabilities,
            effective_sensitivity=context.effective_sensitivity,
            policy_revision=context.policy_revision,
            purpose=context.purpose,
            capability=capability,
            intent_id=intent_id,
            lineage_sha256=context.provenance[7:],
            grant_id=context.grant_id,
            expires_at_monotonic=min(context.lease_expires_at, now + remaining),
        )


def fixture_context():
    return DispatchContext(
        profile_id="fixture-profile", purpose="mcp-fixture-read",
        sensitivity=Sensitivity.PUBLIC, principal_id="fixture-principal",
        namespace="fixture-namespace", provenance="sha256:" + "a" * 64,
        capabilities=frozenset({"mcp:fixture:connect", "mcp:fixture:read"}),
        policy_revision="fixture-policy-v1", grant_id="fixture-grant",
        lease_expires_at=time.monotonic() + 30,
    )


class BrokerAuthorityFixture:
    def __init__(self):
        self.contexts = []
        self.grants = []
        self.effects = []
        self.block_method = None
        self.cancel_observed = False

    def context(self, *, purpose, intent, source_contexts=(), trace_id=None, lease_seconds=30, cancelled=None):
        context = SimpleNamespace(purpose=purpose, intent_id=canonical_digest({"purpose": purpose, "intent": intent}),
                                  uid=1000, profile_id="fixture-profile",
                                  monotonic_expires_at=time.monotonic() + lease_seconds)
        self.contexts.append((purpose, intent, context))
        return context

    def authorize_effect(self, context, *, capability, target, recipient, request_digest,
                         retry_index=0, cancelled=None):
        grant = SimpleNamespace(
            target=target, capability=capability, request_digest=request_digest,
            intent_id=context.intent_id, context_digest="fixture-context-digest",
            monotonic_expires_at=min(context.monotonic_expires_at, time.monotonic() + 5),
        )
        self.grants.append(grant)
        return grant

    def mcp_request(self, grant, *, target, payload, timeout, cancelled=None):
        self.effects.append((grant, target, payload, timeout, cancelled))
        if target != grant.target or canonical_digest(payload) != grant.request_digest:
            raise AssertionError("broker binding mismatch")
        request = __import__("json").loads(payload)
        method, rid = request["method"], request["request_id"]
        if method == self.block_method:
            import time as time_module
            while cancelled is not None and not cancelled():
                time_module.sleep(0.002)
            self.cancel_observed = cancelled is not None and cancelled()
            raise RuntimeError("cancelled by host caller")
        if method == "notifications/initialized":
            return BrokeredEffectResponse(202, b"", {}, "fixture-receipt")
        if method == "initialize":
            result = {"protocolVersion": "2025-03-26", "capabilities": {"tools": {}},
                      "serverInfo": {"name": "fixture", "version": "1"}}
        elif method == "tools/list":
            result = {"tools": [{"name": "get_state", "inputSchema": {
                "type": "object", "properties": {"entity_id": {"type": "string"}},
                "required": ["entity_id"], "additionalProperties": False,
            }, "annotations": {"readOnlyHint": True, "destructiveHint": False}}]}
        elif method == "tools/call":
            result = {"content": [{"type": "text", "text": "brokered fixture state"}], "isError": False}
        elif method == "ping":
            result = {}
        else:
            raise AssertionError(f"unexpected MCP method {method}")
        body = canonical_bytes({"jsonrpc": "2.0", "id": rid, "result": result})
        return BrokeredEffectResponse(200, body, {"content-type": "application/json"}, "fixture-receipt")


class FixtureTransport:
    def __init__(self, *, slow_call=False, bad_version=False):
        self.calls = []
        self.closed = False
        self.slow_call = slow_call
        self.bad_version = bad_version
        self.cancelled = []

    async def request(self, payload):
        self.calls.append(payload)
        method = payload["method"]
        rid = payload.get("id")
        if method == "initialize":
            return {"jsonrpc": "2.0", "id": rid, "result": {
                "protocolVersion": "2099-01-01" if self.bad_version else "2025-03-26",
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "fixture", "version": "1"},
            }}
        if method == "notifications/initialized":
            return {}
        if method == "tools/list":
            cursor = payload["params"].get("cursor")
            if cursor:
                return {"jsonrpc": "2.0", "id": rid, "result": {
                    "tools": [],
                }}
            return {"jsonrpc": "2.0", "id": rid, "result": {
                "tools": [{"name": "get_state", "inputSchema": {
                    "type": "object", "properties": {"entity_id": {"type": "string"}},
                    "required": ["entity_id"], "additionalProperties": False},
                    "annotations": {"readOnlyHint": True}}],
                "nextCursor": "page-2",
            }}
        if method == "tools/call":
            if self.slow_call:
                await asyncio.Event().wait()
            return {"jsonrpc": "2.0", "id": rid, "result": {
                "content": [{"type": "text", "text": "synthetic state"}],
                "isError": False,
            }}
        if method == "ping":
            return {"jsonrpc": "2.0", "id": rid, "result": {}}
        return {"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": "method not found"}}

    async def cancel_request(self, request_id):
        self.cancelled.append(request_id)

    async def close(self):
        self.closed = True


class MCPProtocolTests(unittest.IsolatedAsyncioTestCase):
    def make_client(self, transport, authority=None, *, timeout=1.0, scrubber=None):
        return MCPClient(
            transport, {"get_state"}, service_id="fixture",
            selection="sensor.office", dispatch_context=fixture_context(),
            context_authorizer=authority or FixtureAuthority(),
            timeout=timeout, result_scrubber=scrubber,
        )

    async def test_host_authority_brokers_each_rpc_with_fresh_exact_grant(self):
        authority = BrokerAuthorityFixture()
        transport = StreamableHTTPTransport("https://example.invalid/mcp", service_id="fixture")
        client = MCPClient(
            transport, {"get_state"}, service_id="fixture", selection="sensor.office",
            timeout=1.0, authority_client=authority,
            result_scrubber=lambda result: result,
        )
        await client.initialize()
        await client.discover()
        value = await client.call_read("get_state", {"entity_id": "sensor.office"})
        self.assertEqual(value["content"][0]["text"], "brokered fixture state")
        self.assertEqual(len(authority.contexts), 4)  # initialize, initialized, list, selected read
        self.assertEqual(len(authority.grants), 4)
        self.assertEqual(len(authority.effects), 4)
        self.assertTrue(all(target == "mcp:fixture:http" for _, target, *_ in authority.effects))
        self.assertTrue(all(grant.request_digest == canonical_digest(payload)
                            for grant, _, payload, *_ in authority.effects))
        self.assertNotIn(b"example.invalid", b"".join(payload for _, _, payload, *_ in authority.effects))
        self.assertIsNone(transport._session_id)  # no direct HTTP exchange occurred
        await client.close()

    async def test_host_broker_cancel_callback_is_signalled_at_aggregate_deadline(self):
        authority = BrokerAuthorityFixture()
        authority.block_method = "tools/call"
        client = MCPClient(
            StreamableHTTPTransport("https://example.invalid/mcp", service_id="fixture"),
            {"get_state"}, service_id="fixture", selection="sensor.office",
            timeout=0.05, authority_client=authority,
            result_scrubber=lambda result: result,
        )
        await client.initialize()
        await client.discover()
        started = time.monotonic()
        with self.assertRaises(MCPError):
            await client.call_read("get_state", {"entity_id": "sensor.office"})
        self.assertLessEqual(time.monotonic() - started, 0.07)
        await asyncio.sleep(0.01)
        self.assertTrue(authority.cancel_observed)
        await client.close()

    async def test_handshake_pagination_schema_scoped_read_and_health(self):
        seen = []
        transport = FixtureTransport()
        client = self.make_client(transport, scrubber=lambda result: seen.append(result) or {"filtered": True})
        result = await client.initialize()
        self.assertEqual(result["protocolVersion"], "2025-03-26")
        tools = await client.discover()
        self.assertEqual(set(tools), {"get_state"})
        read = await client.call_read("get_state", {"entity_id": "sensor.office"})
        self.assertEqual(read, {"filtered": True})
        self.assertEqual(seen[0]["content"][0]["text"], "synthetic state")
        self.assertTrue(await client.health())
        self.assertEqual([call["method"] for call in transport.calls].count("tools/list"), 2)
        await client.close()

    async def test_no_authority_fails_before_network(self):
        transport = FixtureTransport()
        client = MCPClient(transport, {"get_state"}, service_id="fixture", selection="sensor.office")
        with self.assertRaises(MCPError):
            await client.initialize()
        self.assertEqual(transport.calls, [])

    async def test_unsupported_version_and_mutating_tool_hint_fail_closed(self):
        bad_version = self.make_client(FixtureTransport(bad_version=True))
        with self.assertRaises(MCPError):
            await bad_version.initialize()
        self.assertFalse(bad_version.ready)

        transport = FixtureTransport()
        client = self.make_client(transport, scrubber=lambda result: result)
        await client.initialize()
        await client.discover()
        client._tools["get_state"]["annotations"]["readOnlyHint"] = False
        with self.assertRaises(PermissionError):
            await client.call_read("get_state", {"entity_id": "sensor.office"})
        with self.assertRaises(PermissionError):
            await client.call_read("get_state", {"entity_id": "sensor.kitchen"})
        await client.close()

    async def test_timeout_cancels_remote_request_and_revoked_authority_denies(self):
        transport = FixtureTransport(slow_call=True)
        authority = FixtureAuthority()
        client = self.make_client(transport, authority, timeout=0.05, scrubber=lambda result: result)
        await client.initialize()
        await client.discover()
        started = time.monotonic()
        with self.assertRaises(MCPError):
            await client.call_read("get_state", {"entity_id": "sensor.office"})
        elapsed = time.monotonic() - started
        self.assertLessEqual(elapsed, 0.07)
        self.assertEqual(len(transport.cancelled), 1)
        authority.denied = True
        with self.assertRaises(MCPError):
            await client.call_read("get_state", {"entity_id": "sensor.office"})
        await client.close()

    async def test_service_scrubber_removes_private_canaries_recursively(self):
        scrub = scrub_mcp_result("google-gmail")
        result = scrub({"content": [{"type": "text", "text": "Bearer canary-token"},
                                   {"type": "resource", "access_token": "canary-secret",
                                    "body": "api_key=canary-key"}],
                        "authorization": "canary-header", "safe": True})
        self.assertEqual(result["content"][0]["text"], "Bearer [REDACTED]")
        self.assertNotIn("access_token", result["content"][1])
        self.assertEqual(result["content"][1]["body"], "api_key=[REDACTED]")
        self.assertNotIn("authorization", result)
        with self.assertRaises(MCPPrivacyError):
            scrub_mcp_result("unreviewed-server")

    async def test_missing_scrubber_fails_before_selected_resource_effect(self):
        transport = FixtureTransport()
        client = self.make_client(transport)
        await client.initialize()
        await client.discover()
        before = len(transport.calls)
        with self.assertRaises(MCPError):
            await client.call_read("get_state", {"entity_id": "sensor.office"})
        self.assertEqual(len(transport.calls), before)
        await client.close()

    async def test_incidental_nested_selection_and_broad_list_do_not_authorize(self):
        transport = FixtureTransport()
        client = self.make_client(transport, scrubber=lambda result: result)
        await client.initialize()
        await client.discover()
        with self.assertRaises(PermissionError):
            await client.call_read("get_state", {"entity_id": "sensor.kitchen",
                                                 "note": {"text": "sensor.office"}})
        with self.assertRaises(PermissionError):
            await client.call_read("get_state", {"filter": ["sensor.office"]})
        self.assertFalse(any(item["method"] == "tools/call" for item in transport.calls))
        await client.close()


if __name__ == "__main__":
    unittest.main()
