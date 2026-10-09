"""Protected MCP broker contract tests; all identities and transport effects are synthetic."""
from __future__ import annotations

import time
import unittest
from types import SimpleNamespace

from hermes_installer.authority import canonical_bytes, canonical_digest
from hermes_installer.mcp.broker import (
    MCPBrokerError, ProtectedMCPService, build_mcp_handlers, mcp_intent,
)


class FakeBrokerTransport:
    def __init__(self):
        self.calls = []

    def exchange(self, request, *, context, authorization, timeout, cancelled):
        self.calls.append(request)
        method, request_id = request["method"], request["id"]
        if cancelled():
            raise RuntimeError("cancelled")
        if method == "initialize":
            result = {"protocolVersion": "2025-03-26", "capabilities": {"tools": {}},
                      "serverInfo": {"name": "fixture", "version": "1"}}
        elif method == "tools/list":
            result = {"tools": [{
                "name": "get_state",
                "inputSchema": {
                    "type": "object", "properties": {"entity_id": {"type": "string"}},
                    "required": ["entity_id"], "additionalProperties": False,
                },
                "annotations": {"readOnlyHint": True, "destructiveHint": False},
            }]}
        elif method == "tools/call":
            result = {"content": [{"type": "text", "text": "synthetic state"}], "isError": False}
        else:
            result = {}
        return {"jsonrpc": "2.0", "id": request_id, "result": result}


class MCPBrokerTests(unittest.TestCase):
    def setUp(self):
        self.service = ProtectedMCPService(
            "fixture", "http", frozenset({"get_state"}), "root-binding-fixture", "a" * 64,
            selection_arguments={"get_state": ("entity_id",)},
        )
        self.transport = FakeBrokerTransport()
        self.handler = build_mcp_handlers(
            {"fixture": self.service},
            transport_factory=lambda service, context: self.transport,
        )[("mcp.request", "mcp:fixture:http")]
        self.purpose = "mcp-selected-resource-read"

    def invoke(self, method, params, selection="sensor.office", request_id=1, *,
               intent_selection=None, intent_params=None):
        binding_selection = selection if intent_selection is None else intent_selection
        bound_params = params if intent_params is None else intent_params
        intent = mcp_intent("fixture", "http", request_id, method, binding_selection, bound_params)
        intent_id = canonical_digest({"purpose": self.purpose, "intent": intent})
        context = SimpleNamespace(
            purpose=self.purpose, intent_id=intent_id, uid=1000, profile_id="fixture-profile",
        )
        envelope = {
            "schema": 1, "service_id": "fixture", "request_id": request_id,
            "method": method, "selection": selection, "params": params,
        }
        payload = canonical_bytes(envelope)
        capability = "mcp:fixture:read" if method == "tools/call" else "mcp:fixture:connect"
        authorization = SimpleNamespace(
            target="mcp:fixture:http", recipient=None, request_digest=canonical_digest(payload),
            capability=capability, intent_id=intent_id,
        )
        return self.handler(
            context=context, authorization=authorization, payload=payload, timeout=1.0,
            peer_pid=1234, cancelled=lambda: False,
        )

    def test_protected_service_selection_policy_is_immutable_and_pinned(self):
        record = self.service
        with self.assertRaises(TypeError):
            record.selection_arguments["get_state"] = ("other",)
        with self.assertRaises(ValueError):
            ProtectedMCPService(
                "unreviewed", "http", frozenset({"read"}), "root-binding",
                "0" * 64,
            )

    def test_protected_schema_and_effect_gate_selected_read(self):
        initialize = self.invoke("initialize", {
            "protocolVersion": "2025-03-26", "capabilities": {},
            "clientInfo": {"name": "hermes-installer", "version": "0.1.0"},
        })
        self.assertEqual(initialize["status"], 200)
        listing = self.invoke("tools/list", {})
        self.assertEqual(listing["status"], 200)
        result = self.invoke("tools/call", {
            "name": "get_state", "arguments": {"entity_id": "sensor.office"},
        })
        self.assertEqual(result["status"], 200)
        self.assertIn(b"synthetic state", result["body"])
        self.assertEqual([call["method"] for call in self.transport.calls],
                         ["initialize", "tools/list", "tools/call"])

    def test_incidental_selection_or_intent_mismatch_has_no_transport_effect(self):
        self.invoke("initialize", {
            "protocolVersion": "2025-03-26", "capabilities": {},
            "clientInfo": {"name": "hermes-installer", "version": "0.1.0"},
        })
        self.invoke("tools/list", {})
        before = len(self.transport.calls)
        with self.assertRaises(MCPBrokerError):
            self.invoke("tools/call", {
                "name": "get_state",
                "arguments": {"entity_id": "sensor.kitchen", "metadata": {"selected": "sensor.office"}},
            })
        self.assertEqual(len(self.transport.calls), before)
        with self.assertRaises(MCPBrokerError):
            self.invoke("tools/call", {
                "name": "get_state", "arguments": {"entity_id": "sensor.office"},
            }, intent_selection="sensor.kitchen")
        self.assertEqual(len(self.transport.calls), before)


if __name__ == "__main__":
    unittest.main()
