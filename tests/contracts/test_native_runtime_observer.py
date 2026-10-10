from __future__ import annotations

import unittest
import hashlib
import json
import time
from dataclasses import dataclass
from types import MappingProxyType, ModuleType
from types import SimpleNamespace

from hermes_installer.authority.native_runtime_observer import (
    NativeActionSelection,
    NativeInvocationContextProvider,
    NativeInvocationRegistry,
    NativeRuntimeObserver,
    NativeRuntimeObserverUnavailable,
    _NativeInvocation,
    _ObservedProviderResponse,
)
from hermes_installer.authority.types import AuthorityDenied, HostContext, Sensitivity, canonical_digest


class _SourceObservers:
    def __init__(self):
        self.observers = {"observer.tool": SimpleNamespace(
            source_kind="tool-result", profile_id="profile-a", generation="generation-a",
            producer_uid=2001,
        )}
        self.calls = []

    def record_observed_event(self, observer_id, **kwargs):
        self.calls.append(("record", observer_id, kwargs))
        return "e" * 40

    def capture_observed_source(self, observer_id, event_id, payload, **kwargs):
        self.calls.append(("capture", observer_id, event_id, payload, kwargs))
        return "r" * 40


class _RegistrationContext:
    def __init__(self):
        self.tools = {}

    def register_tool(self, name, toolset, schema, handler, **_kwargs):
        self.tools[name] = (toolset, schema, handler)
        return True


class _SelectedAdapter:
    def register(self, context, runtime_context):
        context.register_tool(
            "selected_tool", "hermes-installer",
            {"name": "selected_tool", "description": "Selected tool",
             "parameters": {"type": "object", "properties": {}, "additionalProperties": False}},
            lambda: runtime_context.plugin_effects.invoke(),
            description="Selected tool",
        )


class _PluginManagerFixture:
    """The pinned Hermes seam: manager discovery consumes this module map."""
    def __init__(self):
        self._predeclared_modules = {}

    def load_predeclared(self, context):
        for module in self._predeclared_modules.values():
            module.register(context)


def _context():
    return HostContext(
        principal_id="principal-a", profile_id="profile-a", namespace_id="namespace-a",
        uid=2001, purpose="tool.invoke", intent_id="intent-a", trace_id="trace-a",
        sensitivity=Sensitivity.PRIVATE, lineage_hash=canonical_digest({"empty": True}),
        policy_revision="policy-a", capabilities=frozenset({"plugin"}),
        issued_at_monotonic=1.0, monotonic_expires_at=20.0, nonce="nonce-a",
        grant_id="grant-a", signature="root-signature", enrollment_id="enrollment-a",
        generation="generation-a", native_process_identity="123:2001",
    )


def _authorization(context):
    return SimpleNamespace(
        capability="plugin.resource-overlay-store.write",
        operation="plugin.resource-overlay-store.write", target="overlay.target",
        profile_id=context.profile_id, principal_id=context.principal_id,
        uid=context.uid, generation=context.generation,
        native_process_identity=context.native_process_identity,
        source_receipts=context.source_receipts,
        request_digest=None,
    )


class NativeRuntimeObserverContracts(unittest.TestCase):
    def _observer(self, source_observers=None):
        source_observers = source_observers or _SourceObservers()
        observer = NativeRuntimeObserver(
            source_observers=source_observers,
            effect_observer_ids={
                ("plugin.resource-overlay-store.write", "plugin.resource-overlay-store.write",
                 "overlay.target"): "observer.tool",
            },
        )
        return observer, source_observers

    def test_unenrolled_or_untyped_effect_observer_fails_closed(self):
        with self.assertRaises(NativeRuntimeObserverUnavailable):
            NativeRuntimeObserver(
                source_observers=_SourceObservers(),
                effect_observer_ids={
                    ("plugin.resource-overlay-store.write", "plugin.resource-overlay-store.write",
                     "overlay.target"): "observer.missing",
                },
            )

    def test_pinned_manager_registers_only_selected_adapter_and_trusted_context(self):
        from hermes_installer.native_plugin_loader import (
            SelectedNativeAdapter, SelectedNativePackage, _canonical,
            _parse_native_candidate_index, predeclare_selected_native_package,
        )
        from hermes_installer.registry.resources_runtime import (
            NativePluginRuntimeContext, ResourceIdentity,
        )

        digest = "a" * 64
        argument_schema = {"type": "object", "properties": {}, "additionalProperties": False}
        result_schema = {"type": "object", "additionalProperties": True}
        canonical_schema = json.dumps(
            argument_schema, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
        ).encode("utf-8")
        effect = SimpleNamespace(adapter_id="adapter-a", action_id="action-a")
        selection = SimpleNamespace(
            package_id="package-a", profile_id="profile-a", generation="generation-a",
            compiled_closure_sha256=digest, resolver_digest="b" * 64,
            adapter_rows=(effect,), _require_live=lambda: None,
            manifest_digest_for_adapter=lambda _adapter_id: digest,
            resolve=lambda adapter_id, action_id: effect
            if (adapter_id, action_id) == ("adapter-a", "action-a") else None,
        )
        index = {
            "schema": 1, "package_id": "package-a", "profile_id": "profile-a",
            "generation": "generation-a", "resolver_sha256": "b" * 64,
            "candidates": [{
                "native_tool_name": "selected_tool", "adapter_id": "adapter-a",
                "action_id": "action-a", "argument_schema": argument_schema,
                "result_schema": result_schema,
                "native_schema_sha256": hashlib.sha256(canonical_schema).hexdigest(),
                "observer_enrollment_ids": ["observer-a"],
                "native_server_name": "hermes-installer", "description": "Selected tool",
            }],
        }
        candidate_rows = _parse_native_candidate_index(
            _canonical(index), selected=selection,
            manifest=MappingProxyType({"adapters": [{"adapter_id": "adapter-a",
                                                       "action_ids": ["action-a"]}]}),
        )
        module = ModuleType("fixture_selected_adapter")
        adapter = _SelectedAdapter()
        selected = SelectedNativeAdapter("adapter-a", module, "register", ("selected_tool",),
                                         digest, adapter.register)
        package = SelectedNativePackage(selection, __import__("pathlib").Path("/fixture"),
                                        digest, {"adapter-a": selected}, candidate_rows=candidate_rows)
        effects = SimpleNamespace(invoke=lambda: "root-brokered")
        base_context = NativePluginRuntimeContext(
            identity=ResourceIdentity("adapter-a", "plugins", "1", "selected", "rev", digest),
            declared_capabilities=("display-only",), authority=object(),
            invocation_contexts=lambda **_kwargs: (), selected_adapters=object(),
        )
        class RuntimeContextWithEffects(NativePluginRuntimeContext):
            __slots__ = ("plugin_effects",)

        runtime_context = object.__new__(RuntimeContextWithEffects)
        for name in NativePluginRuntimeContext.__slots__:
            object.__setattr__(runtime_context, name, getattr(base_context, name))
        object.__setattr__(runtime_context, "plugin_effects", effects)
        manager = _PluginManagerFixture()
        installed = predeclare_selected_native_package(
            manager, package, lambda adapter_id: runtime_context if adapter_id == "adapter-a" else None)
        self.assertEqual(installed, ("adapter-a",))
        registration = _RegistrationContext()
        manager.load_predeclared(registration)
        self.assertEqual(tuple(registration.tools), ("selected_tool",))
        self.assertEqual(registration.tools["selected_tool"][2](), "root-brokered")
        self.assertEqual(runtime_context.plugin_effects, effects)

    def test_completed_result_is_root_observed_and_receipt_is_one_use_handle(self):
        observer, source_observers = self._observer()
        service = SimpleNamespace(_source_receipt_handles={})
        context = _context()
        result = observer.observe_effect_result(
            service=service, context=context, authorization=_authorization(context),
            operation="plugin.resource-overlay-store.write", target="overlay.target",
            response_status=200, result_payload=b"exact root-validated response",
            peer_pid=123, peer_pidfd=456,
        )
        self.assertEqual(result, "r" * 40)
        self.assertEqual([call[0] for call in source_observers.calls], ["record", "capture"])
        self.assertEqual(source_observers.calls[0][1], "observer.tool")
        self.assertEqual(source_observers.calls[0][2]["payload_bytes"], b"exact root-validated response")
        self.assertEqual(source_observers.calls[1][2], "e" * 40)

    def test_native_tool_result_clears_only_root_resolved_pending_call(self):
        from hermes_installer.authority.native_runtime_observer import RootNativeToolEffectInvocation
        from hermes_installer.authority.native_turn_observation import RootNativeTurnObservationRegistry

        observer, source_observers = self._observer()
        context = _context()
        payload = b'{"operation":"selected"}'
        digest = canonical_digest(payload)
        authorization = _authorization(context)
        authorization.request_digest = digest
        identity = SimpleNamespace(
            kernel_uid=2001, profile_id="profile-a", generation="generation-a",
        )
        invocation = RootNativeToolEffectInvocation(
            invocation_handle="i" * 40, observed_call_handle="c" * 40,
            response_observation_handle="o" * 40, response_receipt_handle="r" * 40,
            native_request_handle="n" * 40, turn_handle="t" * 40,
            producer_identity=identity, producer_pid=123, profile_id="profile-a",
            generation="generation-a", package_id="package-a",
            native_package_generation="package-generation-a",
            service_generation_digest="a" * 64, adapter_id="adapter-a",
            action_id="action-a", tool_name="selected_tool",
            arguments_sha256="b" * 64, source_receipt_handles=("r" * 40,),
            operation="plugin.resource-overlay-store.write", request_digest=digest,
            expires_monotonic=time.monotonic() + 30.0,
        )
        service = SimpleNamespace(
            _source_receipt_handles={}, service_generation_digest="a" * 64,
        )
        invocation_registry = object.__new__(NativeInvocationRegistry)
        invocation_registry.service = service
        invocation_registry.source_observers = source_observers
        invocation_registry.resolve_invocation_for_effect = lambda *args: invocation
        turn_registry = object.__new__(RootNativeTurnObservationRegistry)
        turn_registry.service = service
        recorded = []
        turn_registry.record_tool_result = lambda *args, **kwargs: recorded.append((args, kwargs))
        observer.attach_turn_observation(
            invocation_registry=invocation_registry,
            native_turn_observation_registry=turn_registry,
        )
        receipt = observer.observe_effect_result(
            service=service, context=context, authorization=authorization,
            operation="plugin.resource-overlay-store.write", target="overlay.target",
            response_status=200, result_payload=b"exact result", peer_pid=123,
            peer_pidfd=456, request_payload=payload, request_sha256=digest,
        )
        self.assertEqual(receipt, "r" * 40)
        self.assertEqual(len(recorded), 1)
        self.assertEqual(recorded[0][0][0], "t" * 40)
        self.assertEqual(recorded[0][0][1], receipt)
        self.assertEqual(recorded[0][1]["observed_call_handle"], "c" * 40)

    def test_wrong_operation_cancelled_or_closed_generation_produces_no_event(self):
        observer, source_observers = self._observer()
        context = _context()
        args = dict(
            service=SimpleNamespace(_source_receipt_handles={}), context=context,
            authorization=_authorization(context),
            operation="plugin.resource-overlay-store.write", target="overlay.target",
            response_status=200, result_payload=b"response", peer_pid=123, peer_pidfd=456,
        )
        with self.assertRaises(AuthorityDenied):
            observer.observe_effect_result(**{**args, "operation": "plugin.resource-overlay-store.read"})
        with self.assertRaises(AuthorityDenied):
            observer.observe_effect_result(**{**args, "response_status": 500})
        with self.assertRaises(AuthorityDenied):
            observer.observe_effect_result(**args, cancelled=lambda: True)
        observer.close()
        with self.assertRaises(AuthorityDenied):
            observer.observe_effect_result(**args)
        self.assertEqual(source_observers.calls, [])

    def test_invocation_provider_uses_lexical_binding_and_checks_exact_action(self):
        @dataclass(frozen=True)
        class Binding:
            invocation_handle: str = "i" * 40
            package_id: str = "package-a"
            profile_id: str = "profile-a"
            generation: str = "generation-a"
            adapter_id: str = "adapter-a"
            action_id: str = "action-a"
            arguments_sha256: str = "a" * 64
            parent_closure_digest: str = "b" * 64
            expires_monotonic: float = 20.0

        @dataclass(frozen=True)
        class Contexts:
            invocation_handle: str = "i" * 40
            source_receipt_handles: tuple[str, ...] = ("r" * 40,)
            parent_closure_digest: str = "b" * 64
            arguments_sha256: str = "a" * 64
            expires_monotonic: float = 19.0

        class Authority:
            def __init__(self):
                self.lookups = []

            def get_invocation_contexts(self, invocation_handle):
                self.lookups.append(invocation_handle)
                return Contexts()

        authority = Authority()
        binding = Binding()
        provider = NativeInvocationContextProvider(
            authority=authority,
            selected_package=SimpleNamespace(
                package_id="package-a", profile_id="profile-a", generation="generation-a"),
            current_binding=lambda: binding,
            monotonic=lambda: 10.0,
        )
        contexts = provider(
            adapter_id="adapter-a", action_id="action-a", arguments_sha256="a" * 64,
            purpose="native-hermes-chat", intent="untrusted labels do not select lineage",
        )
        self.assertEqual(contexts.source_receipt_handles, ("r" * 40,))
        self.assertEqual(authority.lookups, ["i" * 40])
        with self.assertRaises(AuthorityDenied):
            provider(adapter_id="adapter-b", action_id="action-a", arguments_sha256="a" * 64,
                     purpose="native-hermes-chat", intent="x")
        with self.assertRaises(AuthorityDenied):
            provider(adapter_id="adapter-a", action_id="action-a", arguments_sha256="c" * 64,
                     purpose="native-hermes-chat", intent="x")

    def test_response_delivery_is_exact_peer_request_digest_and_one_use(self):
        registry = object.__new__(NativeInvocationRegistry)
        registry._lock = __import__("threading").RLock()
        registry._closed = False
        registry.monotonic = lambda: 10.0
        producer = SimpleNamespace(profile_id="profile-a", generation="generation-a")
        gateway = SimpleNamespace(profile_id="gateway-profile", generation="gateway-generation")
        bridge = SimpleNamespace(
            producer_uid=2001, gateway_profile_id="gateway-profile",
            gateway_generation="gateway-generation",
        )
        body = b"dechunked provider entity"
        digest = __import__("hashlib").sha256(body).hexdigest()
        response = _ObservedProviderResponse(
            handle="p" * 43, delivery_handle="d" * 43,
            native_request_handle="n" * 43, response_digest=digest,
            receipt_handles=(), bridge=bridge, producer_identity=producer,
            producer_pid=123, producer_pidfd=456, gateway_identity=gateway,
            gateway_pid=124, gateway_pidfd=457, observer_id="observer",
            package_id="package", profile_id="profile-a", generation="generation-a",
            native_package_generation="package-generation-a",
            loaded_package_proof="proof", expires_monotonic=20.0, calls={},
            request_context=SimpleNamespace(), authorization=SimpleNamespace(retry_index=0),
            target="provider://fixed", recipient="provider:fixed", request_digest="a" * 64,
            retry_index=0, response_status=200, response_headers={}, response_bytes=body,
            response_receipt_handle="s" * 43,
        )
        registry._responses = {response.handle: response}
        registry._deliveries = {response.delivery_handle: response}
        registry._calls = {}
        registry._invocations = {}
        registry._issued_handles = {response.handle, response.delivery_handle}
        registry._retained_response_bytes = len(body)
        registry.process_resolver = lambda pid, _fd, **_kwargs: producer if pid == 123 else gateway
        registry._loaded_proof = lambda *_args: "proof"

        for kwargs in (
            {"peer_uid": 2002, "peer_pid": 123, "peer_pidfd": 456,
             "response_body_sha256": digest, "native_request_handle": "n" * 43},
            {"peer_uid": 2001, "peer_pid": 123, "peer_pidfd": 456,
             "response_body_sha256": "0" * 64, "native_request_handle": "n" * 43},
            {"peer_uid": 2001, "peer_pid": 123, "peer_pidfd": 456,
             "response_body_sha256": digest, "native_request_handle": "x" * 43},
        ):
            with self.assertRaises(AuthorityDenied):
                registry.take_native_response_metadata(
                    response_delivery_handle="d" * 43, **kwargs)

        metadata = registry.take_native_response_metadata(
            peer_uid=2001, peer_pid=123, peer_pidfd=456,
            response_delivery_handle="d" * 43, response_body_sha256=digest,
            native_request_handle="n" * 43,
        )
        self.assertEqual(metadata.producer_context_handle, "p" * 43)
        self.assertEqual(metadata.tool_call_bindings, ())
        with self.assertRaises(AuthorityDenied):
            registry.take_native_response_metadata(
                peer_uid=2001, peer_pid=123, peer_pidfd=456,
                response_delivery_handle="d" * 43, response_body_sha256=digest,
                native_request_handle="n" * 43,
            )
    def test_invocation_provider_rejects_expired_or_mismatched_root_ancestry(self):
        binding = SimpleNamespace(
            invocation_handle="i" * 40, package_id="package-a", profile_id="profile-a",
            generation="generation-a", adapter_id="adapter-a", action_id="action-a",
            arguments_sha256="a" * 64, parent_closure_digest="b" * 64,
            expires_monotonic=9.0,
        )
        provider = NativeInvocationContextProvider(
            authority=SimpleNamespace(get_invocation_contexts=lambda _handle: None),
            selected_package=SimpleNamespace(
                package_id="package-a", profile_id="profile-a", generation="generation-a"),
            current_binding=lambda: binding,
            monotonic=lambda: 10.0,
        )
        with self.assertRaises(AuthorityDenied):
            provider(adapter_id="adapter-a", action_id="action-a", arguments_sha256="a" * 64,
                     purpose="native-hermes-chat", intent="x")

        binding.expires_monotonic = 20.0
        with self.assertRaises(AuthorityDenied):
            provider(adapter_id="adapter-a", action_id="action-a", arguments_sha256="a" * 64,
                     purpose="native-hermes-chat", intent="x")

    def test_invocation_provider_rejects_empty_lineage(self):
        binding = SimpleNamespace(
            invocation_handle="i" * 40, package_id="package-a", profile_id="profile-a",
            generation="generation-a", adapter_id="adapter-a", action_id="action-a",
            arguments_sha256="a" * 64, parent_closure_digest="b" * 64,
            expires_monotonic=20.0,
        )
        contexts = SimpleNamespace(
            invocation_handle="i" * 40, source_receipt_handles=(),
            parent_closure_digest="b" * 64, arguments_sha256="a" * 64,
            expires_monotonic=19.0,
        )
        provider = NativeInvocationContextProvider(
            authority=SimpleNamespace(get_invocation_contexts=lambda _handle: contexts),
            selected_package=SimpleNamespace(
                package_id="package-a", profile_id="profile-a", generation="generation-a"),
            current_binding=lambda: binding,
            monotonic=lambda: 10.0,
        )
        with self.assertRaises(AuthorityDenied):
            provider(adapter_id="adapter-a", action_id="action-a", arguments_sha256="a" * 64,
                     purpose="native-hermes-chat", intent="x")

    def test_native_mcp_invocation_is_root_consumed_once_and_revalidated(self):
        import hashlib
        import threading
        from types import SimpleNamespace

        identity = SimpleNamespace(kernel_uid=2001, profile_id="profile-a", generation="generation-a")
        gateway_identity = SimpleNamespace(kernel_uid=0, profile_id="gateway", generation="gateway-gen")
        bridge = SimpleNamespace(gateway_profile_id="gateway", gateway_generation="gateway-gen")
        proof = object()
        observer = SimpleNamespace(observer_enrollment_id="observer-id")
        receipt = SimpleNamespace(profile_id="profile-a", process_generation="generation-a",
                                  uid=2001, monotonic_expires_at=30.0)
        service = SimpleNamespace(service_generation_digest="c" * 64,
                                  _source_receipt_handles={"receipt-handle": receipt},
                                  _lock=threading.RLock())
        source_observers = SimpleNamespace(
            observers={"observer-id": observer},
            _resolve_package_role=lambda _observer: (object(), object()),
            _resolve_loaded_package_proof=lambda *args, **kwargs: proof,
        )
        args = b'{"city":"Lisbon"}'
        digest = hashlib.sha256(args).hexdigest()
        action = NativeActionSelection("package-a", "profile-a", "generation-a",
                                       "hermes-installer.native-mcp-dispatch.v1",
                                       "mcp-row-a", lambda value: value == args)
        registry = object.__new__(NativeInvocationRegistry)
        registry.service = service
        registry.source_observers = source_observers
        registry.monotonic = lambda: 10.0
        registry.process_resolver = lambda pid, _fd, *, profile_id, generation: (
            identity if pid == 41 and profile_id == "profile-a" and generation == "generation-a"
            else gateway_identity if pid == 51 and profile_id == "gateway" and generation == "gateway-gen"
            else None
        )
        registry.action_resolver = lambda _bridge, _identity, _name: action
        registry._lock = threading.RLock()
        registry._closed = False
        registry._responses = {}
        registry._deliveries = {}
        registry._calls = {}
        registry._issued_handles = {"i" * 40}
        invocation = _NativeInvocation(
            invocation_handle="i" * 40, response_handle="r" * 40,
            observed_call_handle="o" * 40, bridge=bridge,
            producer_identity=identity, producer_pid=41, producer_pidfd=141,
            gateway_identity=gateway_identity, gateway_pid=51, gateway_pidfd=151,
            package_id="package-a", profile_id="profile-a", generation="generation-a",
            adapter_id="hermes-installer.native-mcp-dispatch.v1", action_id="mcp-row-a",
            tool_name="weather.lookup", arguments_sha256=digest,
            parent_closure_digest="d" * 64, receipt_handles=("receipt-handle",),
            observer_id="observer-id", loaded_package_proof=proof,
            expires_monotonic=25.0, service_generation_digest="c" * 64,
        )
        registry._invocations = {invocation.invocation_handle: invocation}
        registry._mcp_dispatches = {}

        result = registry.consume_native_mcp_invocation(2001, 41, 141,
                                                        invocation.invocation_handle, args)
        self.assertEqual(result.tool_name, "weather.lookup")
        self.assertEqual(result.action_id, "mcp-row-a")
        self.assertEqual(result.source_receipt_handles, ("receipt-handle",))
        self.assertTrue(registry.is_current_native_mcp_invocation(result, 2001, 41, 141))
        with self.assertRaises(AuthorityDenied):
            registry.consume_native_mcp_invocation(2001, 41, 141,
                                                   invocation.invocation_handle, args)
        service.service_generation_digest = "e" * 64
        self.assertFalse(registry.is_current_native_mcp_invocation(result, 2001, 41, 141))

if __name__ == "__main__":
    unittest.main()
