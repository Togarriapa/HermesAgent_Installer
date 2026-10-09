"""Native dispatcher contract fixtures exercise the real authority MCP broker."""
from __future__ import annotations

import asyncio
import hashlib
import json
import threading
import time
import unittest
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace
from urllib.parse import urlsplit

from hermes_installer.authority.service import AuthorityService, EffectRule, PrincipalBinding
from hermes_installer.authority.native_runtime_observer import NativeRuntimeObserver
from hermes_installer.authority.types import Sensitivity, canonical_digest
from hermes_installer.mcp.broker import ProtectedMCPService, build_mcp_handlers
from hermes_installer.mcp.native_execution import (
    NativeMCPDispatcher, NativeMCPExecutionDenied, RootNativeMCPInvocation,
)
from hermes_installer.mcp.transports import StreamableHTTPTransport


ARGUMENT_SCHEMA = {
    "type": "object", "properties": {"fileKey": {"type": "string"}},
    "required": ["fileKey"], "additionalProperties": False,
}
RESULT_SCHEMA = {
    "type": "object", "properties": {
        "content": {"type": "array", "items": {"type": "object", "properties": {
            "type": {"type": "string"}, "text": {"type": "string"},
        }, "required": ["type", "text"], "additionalProperties": False}},
        "isError": {"type": "boolean"},
    }, "required": ["content", "isError"], "additionalProperties": False,
}


class _Policy:
    revision = "native-mcp-fixture-policy"

    def classify(self, *, purpose, intent, source_contexts, binding):
        return Sensitivity.PRIVATE, canonical_digest({"intent": intent, "profile": binding.profile_id})

    def allow_effect(self, *, context, rule, request_digest, retry_index):
        return context.sensitivity is Sensitivity.PRIVATE and retry_index == 0


class _FixtureServer:
    def __init__(self):
        self.requests = []
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                request = json.loads(self.rfile.read(int(self.headers["content-length"])))
                owner.requests.append((request, self.headers.get("authorization")))
                method = request["method"]
                if method == "initialize":
                    result = {"protocolVersion": "2025-03-26", "capabilities": {},
                              "serverInfo": {"name": "fixture", "version": "1"}}
                elif method == "tools/list":
                    result = {"tools": [{
                        "name": "get_metadata", "description": "Read selected Figma file",
                        "inputSchema": ARGUMENT_SCHEMA,
                        "annotations": {"readOnlyHint": True, "destructiveHint": False},
                    }]}
                elif method == "tools/call":
                    result = {"content": [{"type": "text", "text": "Bearer fixture-secret-canary"}],
                              "isError": False}
                else:
                    result = {}
                if "id" not in request:
                    body, status = b"", 202
                else:
                    body, status = json.dumps({"jsonrpc": "2.0", "id": request["id"],
                                               "result": result}).encode(), 200
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, _format, *_args):
                return

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.endpoint = f"http://127.0.0.1:{self.server.server_port}/mcp"

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)


class NativeMCPExecutionTests(unittest.TestCase):
    def setUp(self):
        self.http = _FixtureServer()
        self.binding = SimpleNamespace(
            id="action-mcp-read", adapter_id="hermes-installer.native-mcp-dispatch.v1",
            handler_artifact_id="hermes-installer.native-mcp-dispatch.v1",
            native_package_id="package-a", native_package_generation="package-gen-a",
            profile_id="profile-a", process_generation="process-gen-a",
            native_server_name="figma", native_tool_name="mcp__figma__read_metadata",
            native_schema_sha256=hashlib.sha256(json.dumps(
                ARGUMENT_SCHEMA, ensure_ascii=False, sort_keys=True,
                separators=(",", ":"), allow_nan=False,
            ).encode()).hexdigest(),
            mcp_enrollment_id="figma", mcp_generation="service-gen-a",
            mcp_tool_name="get_metadata", request_schema_id="schema-args",
            result_schema_id="schema-result", effect_operation="mcp.request",
            effect_target="mcp:figma:http", capability="mcp:figma:read",
            recipient=None, scope_bindings=(("fileKey", "selected-file"),),
        )
        service_record = ProtectedMCPService(
            service_id="figma", channel="http", allowed_tools=frozenset({"get_metadata"}),
            transport_binding_id="root-http-binding", reviewed_revision="a" * 64,
            selection_arguments={"get_metadata": ("fileKey",)},
        )

        class Credential:
            def headers_for(self, service_id, context, grant):
                if (service_id != "figma" or context.uid != grant.uid
                        or grant.capability not in {"mcp:figma:connect", "mcp:figma:read"}):
                    raise PermissionError("fixture credential scope mismatch")
                return {"Authorization": "Bearer fixture-secret-canary"}

        credential = Credential()

        class FixtureTransport:
            def exchange(self, request, *, context, authorization, timeout, cancelled):
                if cancelled() or timeout <= 0:
                    raise TimeoutError
                transport = StreamableHTTPTransport(
                    self_endpoint, service_id="figma", credential_handle=credential,
                    timeout=min(timeout, 2.0),
                )
                return asyncio.run(transport.request(
                    request, dispatch_context=context, dispatch_authorization=authorization,
                ))

        self_endpoint = self.http.endpoint
        handlers = build_mcp_handlers(
            {"figma": service_record}, transport_factory=lambda _service, _context: FixtureTransport(),
        )
        caps = frozenset({"mcp:figma:connect", "mcp:figma:read", "mcp:test:loopback"})
        rules = {
            ("mcp:figma:connect", "mcp.request", "mcp:figma:http"):
                EffectRule("mcp:figma:connect", "mcp.request", "mcp:figma:http"),
            ("mcp:figma:read", "mcp.request", "mcp:figma:http"):
                EffectRule("mcp:figma:read", "mcp.request", "mcp:figma:http"),
        }

        class SourceObservers:
            observers = {"mcp-result-observer": SimpleNamespace(
                source_kind="tool-result", profile_id="profile-a",
                generation="process-gen-a", producer_uid=1234,
            )}

            def __init__(self):
                self.captured = []

            def record_observed_event(self, observer_id, **kwargs):
                if observer_id != "mcp-result-observer":
                    raise PermissionError("unknown fixture observer")
                return "e" * 40

            def capture_observed_source(self, observer_id, event_id, payload, **kwargs):
                if observer_id != "mcp-result-observer" or event_id != "e" * 40:
                    raise PermissionError("unknown fixture event")
                self.captured.append(payload)
                return "r" * 40

        class ReceiptDelivery:
            def take_source_receipt(self, handle, *, peer_uid, peer_pid, peer_pidfd):
                if (handle != "r" * 40 or peer_uid != 1234 or peer_pid != 3456
                        or peer_pidfd != 77):
                    raise PermissionError("receipt peer mismatch")
                return handle

        self.source_observers = SourceObservers()
        observer = NativeRuntimeObserver(
            source_observers=self.source_observers,
            effect_observer_ids={
                ("mcp:figma:read", "mcp.request", "mcp:figma:http"):
                    "mcp-result-observer",
            },
        )
        self.authority = AuthorityService(
            signing_key=b"n" * 32, key_id="native-mcp-test",
            bindings_by_uid={1234: PrincipalBinding(
                1234, "principal:a", "profile-a", "namespace-a", caps,
            )}, rules=rules, handlers=handlers, policy=_Policy(),
            profile_generations={"profile-a": "process-gen-a"},
            native_runtime_observer=observer,
            source_receipt_delivery=ReceiptDelivery(),
        )
        self.invocation = RootNativeMCPInvocation(
            invocation_handle="i" * 40, package_id="package-a", profile_id="profile-a",
            package_generation="package-gen-a", process_generation="process-gen-a",
            adapter_id="hermes-installer.native-mcp-dispatch.v1", action_id="action-mcp-read",
            arguments_sha256=hashlib.sha256(b'{"fileKey":"selected-file"}').hexdigest(),
            parent_closure_digest="b" * 64, expires_monotonic=time.monotonic() + 30,
            source_receipt_handles=(), native_process_identity="native-process-fixture",
        )

        class Resolver:
            def __init__(self, owner):
                self.owner, self.consumed = owner, False

            def consume(self, handle, *, peer_uid, peer_pid, peer_pidfd):
                if (self.consumed or handle != self.owner.invocation_handle or peer_uid != 1234
                        or peer_pid != 3456 or peer_pidfd != 77):
                    raise PermissionError("fixture invocation binding denied")
                self.consumed = True
                return self.owner

            def is_current(self, invocation):
                return invocation is self.owner and self.consumed

        class Registrations:
            def resolve_action(self, action_id):
                if action_id != self_action:
                    raise KeyError(action_id)
                return self_binding

        class Schemas:
            def resolve(self, schema_id, **identity):
                if identity != {
                    "native_package_id": "package-a",
                    "native_package_generation": "package-gen-a",
                    "adapter_id": "hermes-installer.native-mcp-dispatch.v1",
                    "action_id": "action-mcp-read",
                    "schema_kind": "arguments" if schema_id == "schema-args" else "result",
                }:
                    raise KeyError("schema join mismatch")
                return ARGUMENT_SCHEMA if schema_id == "schema-args" else RESULT_SCHEMA

        self_action, self_binding = self.binding.id, self.binding
        # NativeMCPDispatcher uses /proc identity checks at the actual effect
        # boundary. The contract fixture pins a deterministic fake live peer;
        # Linux custody proves kernel PIDFD identity in its separate workflow.
        from unittest.mock import patch
        self.identity_patch = patch.object(AuthorityService, "_native_process_identity",
                                           staticmethod(lambda _pid, _uid: "native-process-fixture"))
        self.identity_patch.start()
        self.dispatcher = NativeMCPDispatcher(
            self.authority, registration_index=Registrations(), schema_catalog=Schemas(),
            protected_services={"figma": service_record},
            current_mcp_generations={"figma": "service-gen-a"},
            invocation_resolver=Resolver(self.invocation), timeout=5.0,
        )

    def tearDown(self):
        self.identity_patch.stop()
        self.http.close()

    def test_root_dispatch_initializes_discovers_calls_and_scrubs_selected_read(self):
        response = self.dispatcher.dispatch_native_mcp(
            peer_uid=1234, peer_pid=3456, peer_pidfd=77,
            invocation_handle=self.invocation.invocation_handle,
            canonical_arguments=b'{"fileKey":"selected-file"}', cancelled=lambda: False,
        )
        self.assertEqual(response.status, 200)
        self.assertNotIn(b"fixture-secret-canary", response.body)
        self.assertIn(b"Bearer [REDACTED]", response.body)
        self.assertEqual(response.source_receipt_handle, "r" * 40)
        self.assertEqual(self.source_observers.captured, [response.body])
        methods = [row[0]["method"] for row in self.http.requests]
        self.assertEqual(methods, ["initialize", "notifications/initialized", "tools/list", "tools/call"])
        call = self.http.requests[-1][0]
        self.assertEqual(call["params"], {
            "name": "get_metadata", "arguments": {"fileKey": "selected-file"},
        })

    def test_selected_resource_mismatch_is_denied_before_any_network_request(self):
        with self.assertRaises(NativeMCPExecutionDenied):
            self.dispatcher.dispatch_native_mcp(
                peer_uid=1234, peer_pid=3456, peer_pidfd=77,
                invocation_handle=self.invocation.invocation_handle,
                canonical_arguments=b'{"fileKey":"other-file"}', cancelled=lambda: False,
            )
        self.assertEqual(self.http.requests, [])

    def test_missing_root_result_observer_denies_before_network_request(self):
        observer = self.authority.native_runtime_observer
        self.authority.native_runtime_observer = None
        try:
            with self.assertRaises(NativeMCPExecutionDenied):
                self.dispatcher.dispatch_native_mcp(
                    peer_uid=1234, peer_pid=3456, peer_pidfd=77,
                    invocation_handle=self.invocation.invocation_handle,
                    canonical_arguments=b'{"fileKey":"selected-file"}',
                    cancelled=lambda: False,
                )
        finally:
            self.authority.native_runtime_observer = observer
        self.assertEqual(self.http.requests, [])

    def test_revoked_invocation_is_rechecked_before_each_effect(self):
        self.dispatcher._invocations.is_current = lambda _invocation: False
        with self.assertRaises(NativeMCPExecutionDenied):
            self.dispatcher.dispatch_native_mcp(
                peer_uid=1234, peer_pid=3456, peer_pidfd=77,
                invocation_handle=self.invocation.invocation_handle,
                canonical_arguments=b'{"fileKey":"selected-file"}',
                cancelled=lambda: False,
            )
        self.assertEqual(self.http.requests, [])


if __name__ == "__main__":
    unittest.main()
