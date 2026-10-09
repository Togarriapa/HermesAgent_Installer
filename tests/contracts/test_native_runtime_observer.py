from __future__ import annotations

import unittest
from dataclasses import dataclass
from types import ModuleType
from types import SimpleNamespace

from hermes_installer.authority.native_runtime_observer import (
    NativeInvocationContextProvider,
    NativeRuntimeObserver,
    NativeRuntimeObserverUnavailable,
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


class _SelectedAdapter:
    def register(self, context, runtime_context):
        context.register_tool("selected_tool", "selected", {"type": "object"},
                              lambda: runtime_context.plugin_effects.invoke())


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
            SelectedNativeAdapter, SelectedNativePackage, predeclare_selected_native_package,
        )
        from hermes_installer.registry.resources_runtime import (
            NativePluginRuntimeContext, ResourceIdentity,
        )

        digest = "a" * 64
        module = ModuleType("fixture_selected_adapter")
        adapter = _SelectedAdapter()
        selected = SelectedNativeAdapter("adapter-a", module, "register", ("selected_tool",),
                                         digest, adapter.register)
        selection = SimpleNamespace(
            package_id="package-a", profile_id="profile-a", generation="generation-a",
            compiled_closure_sha256=digest, _require_live=lambda: None,
            manifest_digest_for_adapter=lambda _adapter_id: digest,
        )
        package = SelectedNativePackage(selection, __import__("pathlib").Path("/fixture"),
                                        digest, {"adapter-a": selected})
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
        self.assertEqual(authority.lookups, ["i" * 40])

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


if __name__ == "__main__":
    unittest.main()
