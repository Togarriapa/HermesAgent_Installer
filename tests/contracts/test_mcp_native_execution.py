"""Native dispatcher contract fixtures exercise the real authority MCP broker."""
from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import sys
import tempfile
import threading
import time
import unittest
from dataclasses import dataclass, replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlsplit
from unittest.mock import patch

from hermes_installer.authority.service import AuthorityService, EffectRule, PrincipalBinding
from hermes_installer.authority.native_runtime_observer import (
    NativeActionSelection, NativeInvocationRegistry, NativeRuntimeObserver,
)
from hermes_installer.authority.types import HostContext, Sensitivity, SourceReceipt, canonical_digest
from hermes_installer.authority.runtime_bindings import RootRuntimeBindings
from hermes_installer.authority.mcp_discovery_registry import MCPDiscoveryObservationRegistry
from hermes_installer.artifacts import ArtifactCatalog, ArtifactSpec
from hermes_installer.mcp.broker import ProtectedMCPService, build_mcp_handlers
from hermes_installer.mcp.native_execution import (
    NativeMCPDispatcher, NativeMCPExecutionDenied, build_native_mcp_schema_catalog,
)
from hermes_installer.mcp.native_dispatch import (
    HANDLER_ARTIFACT_ID, NativeMCPRegistrationIndex, schema_sha256,
)
from hermes_installer.authority.native_runtime_observer import _NativeInvocation
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
                        "outputSchema": RESULT_SCHEMA,
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
        self.handler_digest = "d" * 64
        self.binding_record = {
            "id": "action-mcp-read", "handler_artifact_id": HANDLER_ARTIFACT_ID,
            "native_package_id": "package-a", "native_package_generation": "package-gen-a",
            "profile_id": "profile-a", "process_generation": "process-gen-a",
            "native_server_name": "figma", "native_tool_name": "mcp__figma__read_metadata",
            "native_schema_sha256": schema_sha256(ARGUMENT_SCHEMA),
            "mcp_enrollment_id": "figma", "mcp_generation": "service-gen-a",
            "mcp_tool_name": "get_metadata", "request_schema_id": "schema-args",
            "result_schema_id": "schema-result", "effect_operation": "mcp.request",
            "effect_target": "mcp:figma:http", "capability": "mcp:figma:read",
            "recipient": None, "scope_bindings": [{
                "argument_field": "fileKey", "selected_resource_id": "selected-file",
            }],
            "handler_artifact_sha256": self.handler_digest,
        }
        protected_service = ProtectedMCPService(
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
            {"figma": protected_service}, transport_factory=lambda _service, _context: FixtureTransport(),
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
                self.events = {}
                self.current = True
                self.revoke_after_capture = False
                self.provider_observer = SimpleNamespace(
                    source_kind="provider-result", observer_enrollment_id="provider-result-observer",
                    role_id="role.native", package_id="package-a",
                    native_package_generation="package-gen-a", profile_id="profile-a",
                    generation="process-gen-a",
                    source_registration_ids=("registration.provider",),
                )
                self.observers["provider-result-observer"] = self.provider_observer
                binding_id = "binding.native.mcp"
                self.package = SimpleNamespace(
                    package_id="package-a", generation="package-gen-a",
                    profile_id="profile-a", profile_generation="process-gen-a",
                    action_records={"action-mcp-read": SimpleNamespace(
                        adapter_id=HANDLER_ARTIFACT_ID, action_id="action-mcp-read",
                        operation="mcp.request", generation="package-gen-a",
                        action_binding_id=binding_id,
                    )},
                    process_role_records={"role.native": SimpleNamespace(
                        package_id="package-a", native_package_generation="package-gen-a",
                        profile_id="profile-a", profile_generation="process-gen-a",
                        observer_enrollment_ids=("provider-result-observer",),
                        action_binding_ids=(binding_id,),
                        registration_ids=("registration.native.mcp", "registration.provider"),
                        workflow_ids=(),
                    )},
                    registration_records={
                        "registration.native.mcp": SimpleNamespace(
                            registration_id="registration.native.mcp", generation="package-gen-a",
                            adapter_id=HANDLER_ARTIFACT_ID,
                            action_bindings=(SimpleNamespace(action_binding_id=binding_id),),
                        ),
                        "registration.provider": SimpleNamespace(
                            registration_id="registration.provider", generation="package-gen-a",
                            adapter_id=HANDLER_ARTIFACT_ID, action_bindings=(),
                        ),
                    },
                    workflow_records={},
                )
                self.loaded_proof = SimpleNamespace(observed_registration_ids=(
                    "registration.provider", "registration.native.mcp",
                ))

            def record_observed_event(self, observer_id, **kwargs):
                if observer_id != "mcp-result-observer":
                    raise PermissionError("unknown fixture observer")
                self.events["e" * 40] = kwargs
                return "e" * 40

            def capture_observed_source(self, observer_id, event_id, payload, **kwargs):
                if observer_id != "mcp-result-observer" or event_id != "e" * 40:
                    raise PermissionError("unknown fixture event")
                self.captured.append(payload)
                if self.revoke_after_capture:
                    self.current = False
                handle = "l" * 40 if b'"tools"' in payload else "r" * 40
                event = self.events[event_id]
                parent = event["parent_context"]
                now = time.monotonic()
                binding = self_authority._binding(parent.uid)
                receipt = SourceReceipt(
                    receipt_id="receipt-" + handle, issuer_id="host-authority",
                    source_kind="tool-result", principal_id=binding.principal_id,
                    profile_id=binding.profile_id, namespace_id=binding.namespace_id,
                    uid=binding.uid, origin_id="fixture-mcp-response",
                    process_generation=parent.generation, payload_digest=canonical_digest(payload),
                    sensitivity=Sensitivity.PRIVATE, parent_lineage_hash=parent.lineage_hash,
                    policy_revision=self_authority._policy_revision(),
                    recipient_ceiling=frozenset(), issued_at_monotonic=now,
                    monotonic_expires_at=min(parent.monotonic_expires_at, now + 30),
                    signature="pending", enrollment_id=parent.enrollment_id,
                    native_process_identity=parent.native_process_identity,
                    parent_receipt_ids=tuple(sorted(item.receipt_id for item in parent.source_receipts)),
                    nonce="fixture-response-nonce",
                )
                receipt = replace(receipt, signature=self_authority._sign(receipt.claims()))
                self_authority._source_receipt_handles[handle] = receipt
                return handle

            def take_source_receipt(self, *_args, **_kwargs):
                return "r" * 40

            def _resolve(self, *_args, **_kwargs):
                return self.provider_observer

            def _resolve_package_role(self, _observer):
                return self.package, None

            def _resolve_loaded_package_proof(self, *_args, **_kwargs):
                if not self.current:
                    return None
                return self.loaded_proof

        class ReceiptDelivery:
            def take_source_receipt(self, handle, *, peer_uid, peer_pid, peer_pidfd):
                if (handle not in {"r" * 40, "l" * 40} or peer_uid != 1234 or peer_pid != 3456
                        or peer_pidfd != self_peer_pidfd):
                    raise PermissionError("receipt peer mismatch")
                return handle

        self.source_observers = SourceObservers()
        self_authority = self.authority = None
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
            service_generation_digest="c" * 64,
        )
        self_authority = self.authority
        self.identity_patch = patch.object(
            AuthorityService, "_native_process_identity",
            staticmethod(lambda _pid, _uid: "native-process-fixture"),
        )
        self.identity_patch.start()
        self.producer_fd = os.open(os.devnull, os.O_RDONLY)
        self.gateway_fd = os.open(os.devnull, os.O_RDONLY)
        self_peer_pidfd = self.producer_fd
        producer_identity = SimpleNamespace(
            profile_id="profile-a", generation="process-gen-a", kernel_uid=1234,
            executable_sha256="e" * 64,
        )
        gateway_identity = SimpleNamespace(
            profile_id="gateway-profile", generation="gateway-gen", kernel_uid=4321,
            executable_sha256="f" * 64,
        )

        def process_resolver(pid, pidfd, *, profile_id, generation):
            if not self.source_observers.current:
                return None
            if ((pid, profile_id, generation) == (3456, "profile-a", "process-gen-a")
                    and os.fstat(pidfd)[:2] == os.fstat(self.producer_fd)[:2]):
                return producer_identity
            if (pid, pidfd, profile_id, generation) == (
                    4567, self.gateway_fd, "gateway-profile", "gateway-gen"):
                return gateway_identity
            return None

        bridge = SimpleNamespace(
            bridge_id="native-mcp-fixture-bridge", producer_uid=1234,
            producer_profile_id="profile-a", producer_generation="process-gen-a",
            gateway_profile_id="gateway-profile", gateway_generation="gateway-gen",
        )
        selected_action = NativeActionSelection(
            package_id="package-a", profile_id="profile-a", generation="process-gen-a",
            package_generation="package-gen-a",
            adapter_id=HANDLER_ARTIFACT_ID, action_id="action-mcp-read",
            registration_id="registration.native.mcp", operation="mcp.request",
            validate_arguments=lambda body: body == b'{"fileKey":"selected-file"}',
        )

        def action_resolver(_bridge, identity, tool_name):
            if identity is not producer_identity or tool_name != "mcp__figma__read_metadata":
                raise PermissionError("unselected native action")
            return selected_action

        self.invocation_registry = NativeInvocationRegistry(
            service=self.authority, source_observers=self.source_observers,
            bridges={bridge.bridge_id: bridge},
            provider_result_observer_ids={
                ("fixture-provider", "provider.fixed", "fixture-recipient"):
                    "provider-result-observer",
            },
            provider_tool_call_parser=lambda *_args: (),
            process_resolver=process_resolver, action_resolver=action_resolver,
        )
        self.authority.attach_native_invocation_registry(self.invocation_registry)
        context = self.authority._issue_context(1234, {
            "purpose": "native-mcp-fixture", "intent": "selected-plugin-read",
            "trace_id": "native-mcp-fixture-trace", "lease_seconds": 30,
            "source_contexts": [],
            "final_payload_digest": hashlib.sha256(
                b'{"fileKey":"selected-file"}',
            ).hexdigest(),
            "operation": "provider.dispatch",
        }, peer_pid=3456)
        source_receipt = self.authority.issue_source_receipt(
            HostContext.from_wire(context),
            source_kind="tool-result", origin_id="fixture-provider-result",
            payload=b"root-captured provider result", ttl_seconds=30,
        )
        self.source_handle = "s" * 40
        self.authority._source_receipt_handles[self.source_handle] = source_receipt
        self.invocation_handle = "i" * 40
        self.invocation = _NativeInvocation(
            invocation_handle=self.invocation_handle,
            response_handle="d" * 43, observed_call_handle="o" * 40,
            bridge=bridge, producer_identity=producer_identity, producer_pid=3456,
            producer_pidfd=self.producer_fd, gateway_identity=gateway_identity,
            gateway_pid=4567, gateway_pidfd=self.gateway_fd, package_id="package-a",
            profile_id="profile-a", generation="process-gen-a",
            package_generation="package-gen-a",
            adapter_id=HANDLER_ARTIFACT_ID, action_id="action-mcp-read",
            registration_id="registration.native.mcp",
            tool_name="mcp__figma__read_metadata",
            arguments_sha256=hashlib.sha256(b'{"fileKey":"selected-file"}').hexdigest(),
            canonical_arguments=b'{"fileKey":"selected-file"}',
            operation="mcp.request",
            parent_closure_digest="b" * 64, receipt_handles=(self.source_handle,),
            observer_id="provider-result-observer", loaded_package_proof=self.source_observers.loaded_proof,
            expires_monotonic=time.monotonic() + 30,
            service_generation_digest=self.authority.service_generation_digest,
        )
        self.invocation_registry._invocations[self.invocation_handle] = self.invocation
        def artifact_bytes(schema):
            return json.dumps(schema, sort_keys=True, separators=(",", ":"),
                              ensure_ascii=False, allow_nan=False).encode("utf-8")

        schema_records = []
        schema_bytes = {"schema-args": artifact_bytes(ARGUMENT_SCHEMA),
                        "schema-result": artifact_bytes(RESULT_SCHEMA)}
        for schema_id, schema_kind in (("schema-args", "arguments"),
                                       ("schema-result", "result")):
            schema_records.append({
                "id": schema_id, "artifact_id": "artifact-" + schema_id,
                "sha256": hashlib.sha256(schema_bytes[schema_id]).hexdigest(),
                "schema_kind": schema_kind, "native_package_id": "package-a",
                "native_package_generation": "package-gen-a", "adapter_id": HANDLER_ARTIFACT_ID,
                "action_id": "action-mcp-read", "source_receipt_handle": "pending",
                "size_bytes": len(schema_bytes[schema_id]), "derivation_receipt_handle": None,
            })
        stage = Path(tempfile.mkdtemp(prefix="mcp-schema-fixture-"))
        os.chmod(stage, 0o700)
        self.schema_stage = stage
        artifact_specs = []
        for index, record in enumerate(schema_records):
            body = schema_bytes[record["id"]]
            receipt = self.authority.issue_source_receipt(
                HostContext.from_wire(context), source_kind="static-context",
                origin_id=record["id"], payload=body, ttl_seconds=30,
            )
            handle = ("q" if index == 0 else "w") * 40
            self.authority._source_receipt_handles[handle] = receipt
            record["source_receipt_handle"] = handle
            spec = ArtifactSpec(
                artifact_id=record["artifact_id"], version="1", sha256=record["sha256"],
                source_url=f"https://schemas.hermes.invalid/{record['id']}.json",
                max_bytes=256 * 1024, size_bytes=len(body), filename="schema.json",
            )
            artifact_specs.append(spec)
            object_dir = stage / "objects" / record["artifact_id"] / record["sha256"]
            object_dir.mkdir(parents=True, mode=0o700)
            (object_dir / "schema.json").write_bytes(body)
            os.chmod(object_dir / "schema.json", 0o400)
        self.schema_artifact_catalog = ArtifactCatalog.from_records(tuple(artifact_specs))
        self.schema_catalog = build_native_mcp_schema_catalog(
            schema_records, authority_service=self.authority,
            artifact_catalog=self.schema_artifact_catalog,
            staging_root=stage, expected_uid=os.getuid(),
        )
        service_record = {
            "id": "figma", "channel": "http", "allowed_tools": ["get_metadata"],
            "selection_arguments": {"get_metadata": ["fileKey"]},
        }
        self.registration_index = NativeMCPRegistrationIndex.from_protected_records(
            [self.binding_record], services={"figma": service_record},
            mcp_generation_by_enrollment={"figma": "service-gen-a"},
            profile_id="profile-a", process_generation="process-gen-a",
            native_package_id="package-a", native_package_generation="package-gen-a",
            handler_artifact_sha256=self.handler_digest,
        )
        adapter_record = SimpleNamespace(
            action_id="action-mcp-read", argument_schema_id="schema-args",
            result_schema_id="schema-result", adapter_artifact_id=HANDLER_ARTIFACT_ID,
            adapter_sha256=self.handler_digest,
        )
        package_record = SimpleNamespace(adapter_records={HANDLER_ARTIFACT_ID: adapter_record})
        enrollment = SimpleNamespace(
            digest=self.authority.service_generation_digest,
            resolve_native_package=lambda package_id, package_generation: package_record,
        )
        runtime_bindings = RootRuntimeBindings(
            enrollment_catalog=enrollment, build_catalog=None, device_catalog=None,
            process_manager=None, effect_handlers={}, native_bridges={}, artifact_catalog=None,
            build_store=None, service_connector=None,
            # Dynamic discovery is rooted in the actual selected tools/list
            # response and must not depend on a catalog child row existing.
            native_schema_artifact_records=(),
        )
        self.discovery_registry = MCPDiscoveryObservationRegistry(
            service=self.authority, invocation_registry=None,
            runtime_bindings=runtime_bindings, registration_index=self.registration_index,
            protected_services={"figma": protected_service},
            current_mcp_generations={"figma": "service-gen-a"},
        )
        self.issuer_patches = []
        self.publication_patch = None
        self.real_schema_issuer = sys.platform.startswith("linux") and os.geteuid() == 0
        if self.real_schema_issuer:
            from hermes_installer.authority.artifacts import RootSchemaDerivationReceiptRegistry
            from hermes_installer.authority.bootstrap_enrollment import RootArtifactReceiptRegistry
            from hermes_installer.authority.setup_policy_publication import PolicyPublicationReceiptResolver
            from hermes_installer.protected_enrollment import RootJournalSelection
            protected_parent = Path("/var/lib/hermes-installer")
            protected_parent.mkdir(mode=0o755, parents=True, exist_ok=True)
            parent_info = protected_parent.lstat()
            if parent_info.st_uid != 0 or parent_info.st_mode & 0o022:
                raise RuntimeError("Linux test root-journal parent is not safely root-owned")
            self.schema_journal = Path(tempfile.mkdtemp(prefix="mcp-schema-journal-", dir=protected_parent))
            os.chmod(self.schema_journal, 0o700)
            import shutil
            self.addCleanup(shutil.rmtree, self.schema_journal, ignore_errors=True)
            (self.schema_journal / "bootstrap-receipts").mkdir(mode=0o700)
            journal_info = self.schema_journal.stat()
            journal = RootJournalSelection(
                "installer-authority-journal-v1", self.schema_journal,
                journal_info.st_dev, journal_info.st_ino, "generation-1",
                self.authority.service_generation_digest,
            )
            package_registry = SimpleNamespace(
                native_schema_artifact_records=[],
                resolve_native_package=lambda _package, _generation: SimpleNamespace(),
            )
            self.root_schema_rows = package_registry.native_schema_artifact_records
            self.issuer = RootSchemaDerivationReceiptRegistry.from_root_runtime(
                self.schema_artifact_catalog,
                RootArtifactReceiptRegistry(
                    self.schema_journal / "bootstrap-receipts",
                    catalog=self.schema_artifact_catalog, artifact_root=self.schema_stage,
                ),
                package_registry, self.discovery_registry, journal, expected_uid=0,
            )
            self.publication_state = "prepared"
            self.publication_handles = (self.source_handle,)
            self.publication_patch = patch.object(
                PolicyPublicationReceiptResolver, "resolve_current",
                side_effect=self._fixture_publication,
            )
            self.publication_patch.start()
        else:
            from hermes_installer.authority.artifacts import RootSchemaDerivationReceiptRegistry
            self.issuer = object.__new__(RootSchemaDerivationReceiptRegistry)
            self.issuer.mcp_discovery_registry = self.discovery_registry

            def observe_fixture(registry, observation):
                retained = registry.mcp_discovery_registry.resolve_schema_observation({
                    "schema": 1, "artifact_id": observation.artifact_id,
                    "artifact_sha256": observation.artifact_sha256,
                    "size_bytes": observation.size_bytes, "schema_kind": observation.schema_kind,
                    "package_id": observation.package_id,
                    "package_generation": observation.package_generation,
                    "adapter_id": observation.adapter_id, "action_id": observation.action_id,
                    "source_kind": "mcp-tools-list",
                    "parent_receipt_handles": list(observation.parent_receipt_handles),
                    "source_observation_handle": observation.source_observation_handle,
                    "source_member_path": None,
                    "service_generation_digest": observation.service_generation_digest,
                })
                if retained != observation:
                    raise AssertionError("fixture issuer did not re-resolve the root witness")
                return retained

            def mint_fixture(_registry, observation):
                return hashlib.sha256((observation.source_observation_handle + ":receipt").encode()).hexdigest()

            self.issuer_patches = [
                patch.object(RootSchemaDerivationReceiptRegistry, "observe_mcp_tools_list", observe_fixture,
                             create=True),
                patch.object(RootSchemaDerivationReceiptRegistry, "mint_schema_artifact", mint_fixture,
                             create=True),
            ]
            for issuer_patch in self.issuer_patches:
                issuer_patch.start()
        self.discovery_registry.attach_schema_derivation_registry(self.issuer)
        with self.assertRaises(TypeError):
            NativeMCPDispatcher(
                self.authority, registration_index=self.registration_index,
                schema_catalog=self.schema_catalog,
                protected_services={"figma": protected_service},
                current_mcp_generations={"figma": "service-gen-a"},
                invocation_resolver=self.invocation_registry,
                mcp_discovery_registry=self.discovery_registry,
            )
        self.discovery_registry.attach_invocation_registry(self.invocation_registry)
        self.assertTrue(self.discovery_registry.ready)
        from hermes_installer.authority.mcp_discovery_registry import MCPDiscoveryUnavailable
        with self.assertRaises(MCPDiscoveryUnavailable):
            self.discovery_registry.attach_invocation_registry(self.invocation_registry)
        self.protected_service = protected_service
        # NativeMCPDispatcher uses /proc identity checks at the actual effect
        # boundary. The contract fixture pins a deterministic fake live peer;
        # Linux custody proves kernel PIDFD identity in its separate workflow.
        self.dispatcher = NativeMCPDispatcher(
            self.authority, registration_index=self.registration_index,
            schema_catalog=self.schema_catalog,
            protected_services={"figma": protected_service},
            current_mcp_generations={"figma": "service-gen-a"},
            invocation_resolver=self.invocation_registry,
            mcp_discovery_registry=self.discovery_registry, timeout=5.0,
        )
        self.authority.attach_native_mcp_dispatcher(self.dispatcher)

    def tearDown(self):
        for issuer_patch in self.issuer_patches:
            issuer_patch.stop()
        if self.publication_patch is not None:
            self.publication_patch.stop()
        self.identity_patch.stop()
        self.discovery_registry.close()
        self.invocation_registry.close()
        try:
            os.close(self.producer_fd)
            os.close(self.gateway_fd)
        except OSError:
            pass
        self.http.close()
        import shutil
        shutil.rmtree(self.schema_stage, ignore_errors=True)

    def test_root_dispatch_initializes_discovers_calls_and_scrubs_selected_read(self):
        response = self._service_dispatch(b'{"fileKey":"selected-file"}')
        self.assertEqual(response["status"], 200)
        body = base64.b64decode(response["body"], validate=True)
        self.assertNotIn(b"fixture-secret-canary", body)
        self.assertIn(b"Bearer [REDACTED]", body)
        self.assertEqual(response["source_receipt_handle"], "r" * 40)
        self.assertEqual(len(self.source_observers.captured), 2)
        self.assertEqual(self.source_observers.captured[-1], body)
        self.assertIn(b'"tools"', self.source_observers.captured[0])
        self.assertEqual(len(self.discovery_registry._records), 2)
        retained_record = next(record for record in self.discovery_registry._records.values()
                               if record.observation.schema_kind == "arguments")
        retained = retained_record.observation
        result_record = next(record for record in self.discovery_registry._records.values()
                             if record.observation.schema_kind == "result")
        self.assertEqual(result_record.observation.schema_bytes, json.dumps(
            RESULT_SCHEMA, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        ).encode())
        for proof in (retained, result_record.observation):
            digest = hashlib.sha256(proof.schema_bytes).hexdigest()
            self.assertEqual(proof.artifact_id, f"native-mcp-schema:{digest}")
            self.assertEqual(proof.artifact_sha256, digest)
        self.assertTrue(retained_record.derivation_receipt_handle)
        self.assertTrue(result_record.derivation_receipt_handle)
        self.assertNotEqual(retained_record.derivation_receipt_handle,
                            result_record.derivation_receipt_handle)
        from hermes_installer.authority.mcp_discovery_registry import MCPDiscoveryUnavailable
        observed = self.discovery_registry.resolve_schema_observation({
            "schema": 1,
            "artifact_id": retained.artifact_id,
            "artifact_sha256": retained.artifact_sha256,
            "size_bytes": retained.size_bytes,
            "schema_kind": retained.schema_kind,
            "package_id": retained.package_id,
            "package_generation": retained.package_generation,
            "adapter_id": retained.adapter_id,
            "action_id": retained.action_id,
            "source_kind": "mcp-tools-list",
            "parent_receipt_handles": list(retained.parent_receipt_handles),
            "source_observation_handle": retained.source_observation_handle,
            "source_member_path": None,
            "service_generation_digest": retained.service_generation_digest,
        })
        self.assertEqual(observed.schema_bytes, json.dumps(
            ARGUMENT_SCHEMA, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        ).encode())
        if sys.platform.startswith("linux") and os.geteuid() == 0:
            self._verify_real_schema_derivation(retained)
        capture_args = {
            "invocation": retained_record.invocation,
            "peer_uid": retained_record.peer_uid, "peer_pid": retained_record.peer_pid,
            "peer_pidfd": retained_record.peer_pidfd, "service": self.protected_service,
            "binding": self.registration_index.resolve_action(retained.action_id),
            "mcp_generation": retained.mcp_generation,
            "selection": dict(retained_record.selection),
            "request_payload": retained_record.request_payload,
            "response_payload": retained_record.response_payload,
            "response_receipt_handle": retained.response_receipt_handle,
            "context": retained_record.context,
            "authorization": retained_record.authorization,
            "parent_receipt_handles": retained.parent_receipt_handles,
            "schema_kind": "arguments",
        }
        with self.assertRaises(MCPDiscoveryUnavailable):
            self.discovery_registry.capture_tools_list(**capture_args)
        tampered_response = json.loads(retained_record.response_payload)
        tampered_response["result"]["tools"][0]["inputSchema"]["type"] = "array"
        capture_args["response_payload"] = json.dumps(
            tampered_response, sort_keys=True, separators=(",", ":"),
        ).encode()
        with self.assertRaises(MCPDiscoveryUnavailable):
            self.discovery_registry.capture_tools_list(**capture_args)
        forged = {"source_observation_handle": retained.source_observation_handle,
                  "artifact_id": "different-artifact"}
        with self.assertRaises(MCPDiscoveryUnavailable):
            self.discovery_registry.resolve_schema_observation(forged)
        self.source_observers.current = False
        with self.assertRaises(MCPDiscoveryUnavailable):
            self.discovery_registry.resolve_schema_observation({
                "schema": 1,
                "artifact_id": retained.artifact_id,
                "artifact_sha256": retained.artifact_sha256,
                "size_bytes": retained.size_bytes,
                "schema_kind": retained.schema_kind,
                "package_id": retained.package_id,
                "package_generation": retained.package_generation,
                "adapter_id": retained.adapter_id,
                "action_id": retained.action_id,
                "source_kind": "mcp-tools-list",
                "parent_receipt_handles": list(retained.parent_receipt_handles),
                "source_observation_handle": retained.source_observation_handle,
                "source_member_path": None,
                "service_generation_digest": retained.service_generation_digest,
            })
        methods = [row[0]["method"] for row in self.http.requests]
        self.assertEqual(methods, ["initialize", "notifications/initialized", "tools/list", "tools/call"])
        call = self.http.requests[-1][0]
        self.assertEqual(call["params"], {
            "name": "get_metadata", "arguments": {"fileKey": "selected-file"},
        })

    def _verify_real_schema_derivation(self, observation):
        """Use the retained real tools/list proof to issue and resolve root CAS bytes."""
        if not self.real_schema_issuer:
            return
        retained_record = next(
            record for record in self.discovery_registry._records.values()
            if record.observation.source_observation_handle == observation.source_observation_handle
        )
        handle = retained_record.derivation_receipt_handle
        self.assertTrue(handle)
        row = {
            "id": "schema-args", "artifact_id": observation.artifact_id,
            "sha256": observation.artifact_sha256, "schema_kind": "arguments",
            "native_package_id": observation.package_id,
            "native_package_generation": observation.package_generation,
            "adapter_id": observation.adapter_id, "action_id": observation.action_id,
            "source_receipt_handle": observation.response_receipt_handle,
            "size_bytes": observation.size_bytes, "derivation_receipt_handle": handle,
        }
        self.root_schema_rows.append(row)

        def resolve_schema(*selector):
            for candidate in self.root_schema_rows:
                if (candidate["id"], candidate["native_package_id"],
                        candidate["native_package_generation"], candidate["adapter_id"],
                        candidate["action_id"], candidate["schema_kind"]) == selector:
                    return candidate
            raise LookupError

        self.issuer.native_package_registry.resolve_native_schema_record = resolve_schema
        self.publication_state = "active"
        self.publication_handles = (*observation.parent_receipt_handles, handle)
        binding = self.registration_index.resolve_action(observation.action_id)
        resolved = self.issuer.resolve_schema_artifact(
            handle, selected_binding=binding, schema_role="arguments",
        )
        self.assertEqual(resolved.canonical_schema_bytes, observation.schema_bytes)
        self.assertEqual(resolved.source_receipt_handle, observation.response_receipt_handle)
        self.assertEqual(resolved.derivation_receipt_handle, handle)

    def _fixture_publication(self):
        from hermes_installer.authority.setup_policy_publication import (
            RootSetupPublicationReceipt, _SEAL as PUB_SEAL,
        )
        info = self.schema_journal.stat()
        return RootSetupPublicationReceipt(
            1, "receipt-" + "a" * 32, "transaction-" + "b" * 32,
            "installer-bootstrap-policy-generation-v1", "c" * 64,
            self.schema_journal, info.st_dev, info.st_ino, "d" * 64, "e" * 64,
            "f" * 64, "g" * 64, None, "h" * 64,
            tuple(self.publication_handles), self.publication_state, PUB_SEAL,
        )

    def test_selected_resource_mismatch_is_denied_before_any_network_request(self):
        with self.assertRaises(NativeMCPExecutionDenied):
            self._service_dispatch(b'{"fileKey":"other-file"}')
        self.assertEqual(self.http.requests, [])

    def test_missing_root_result_observer_denies_before_network_request(self):
        observer = self.authority.native_runtime_observer
        self.authority.native_runtime_observer = None
        try:
            with self.assertRaises(NativeMCPExecutionDenied):
                self._service_dispatch(b'{"fileKey":"selected-file"}')
        finally:
            self.authority.native_runtime_observer = observer
        self.assertEqual(self.http.requests, [])

    def test_revoked_invocation_is_rechecked_before_each_effect(self):
        self.source_observers.current = False
        with self.assertRaises(NativeMCPExecutionDenied):
            self._service_dispatch(b'{"fileKey":"selected-file"}')
        self.assertEqual(self.http.requests, [])

    def test_revocation_after_result_capture_blocks_release(self):
        self.source_observers.revoke_after_capture = True
        with self.assertRaises(NativeMCPExecutionDenied):
            self._service_dispatch(b'{"fileKey":"selected-file"}')
        self.assertEqual([row[0]["method"] for row in self.http.requests], [
            "initialize", "notifications/initialized", "tools/list",
        ])
        self.assertEqual(len(self.source_observers.captured), 1)

    def _service_dispatch(self, arguments):
        return self.authority._dispatch_native_mcp(
            1234, 3456, self.producer_fd,
            {"schema": 1, "invocation_handle": self.invocation_handle,
             "canonical_arguments_b64": base64.b64encode(arguments).decode("ascii")},
            cancelled=lambda: False,
        )


if __name__ == "__main__":
    unittest.main()
