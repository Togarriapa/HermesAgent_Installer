"""Protected provider account/bridge/observer joins (PR-F02/PR-F03/HI-T11)."""
from __future__ import annotations

import hashlib
import inspect
import json
import unittest
from dataclasses import MISSING, fields
from pathlib import Path
from types import SimpleNamespace

from hermes_installer.authority.enrollment import NativeBridgeEnrollment, ProtectedEnrollment
from hermes_installer.authority.provider_runtime_composition import (
    ProviderRuntimeUnavailable,
    attach_provider_response_registry,
    build_provider_runtime_selection,
)
from hermes_installer.authority.service import AuthorityService, EffectRule, PrincipalBinding
from hermes_installer.authority.native_bridge import NativeBridgeBroker
from hermes_installer.authority.runtime_bindings import RootRuntimeBindings
from hermes_installer.authority.source_observers import SourceObserverEnrollment
from hermes_installer.policy import PROVIDER_RECIPIENT, canonical_provider_target
from hermes_installer.provider_effect_handlers import (
    OPENROUTER_MODEL,
    OpenRouterLiveAdmission,
    ProviderEnrollment,
    build_provider_handlers,
    canonical_provider_request,
)


class _Policy:
    revision = "provider-composition-fixture"

    def classify(self, **_kwargs):
        raise AssertionError("provider response composition must not classify request content")

    def allow_effect(self, **_kwargs):
        return True


class _Admission:
    def check_attempt(self, **_kwargs):
        return None


class _Vault:
    def resolve_reference(self, *_args, **_kwargs):
        return "fixture-secret-from-root-vault"


def _policy_record() -> dict[str, object]:
    module = Path(inspect.getsourcefile(canonical_provider_request))
    record: dict[str, object] = {
        "id": "provider-output-reject-4096-v1",
        "revision": 1,
        "route_schema_id": "provider-chat-compatible-v1",
        "output_limit_mode": "reject-over-ceiling",
        "output_limit_ceiling": 4096,
        "canonicalizer_artifact_id": "provider-canonicalizer-v1",
        "canonicalizer_sha256": hashlib.sha256(module.read_bytes()).hexdigest(),
    }
    record["normalization_policy_sha256"] = hashlib.sha256(
        json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    ).hexdigest()
    return record


def _protected_enrollment(provider_record, bridge, service):
    values = {}
    for item in fields(ProtectedEnrollment):
        if item.default is not MISSING:
            values[item.name] = item.default
        elif item.default_factory is not MISSING:
            values[item.name] = item.default_factory()
        else:
            values[item.name] = {}
    values.update(
        key_id="fixture-key",
        bindings_by_uid=service.bindings_by_uid, rules=service.rules,
        policy=_Policy(), process_profiles={},
        provider_enrollments={"provider-account-1": provider_record},
        mcp_services={}, mcp_http_bindings={}, delegations={}, memory_providers={},
        native_bridges={bridge.bridge_id: bridge}, artifact_catalog={}, package_catalog={},
        artifact_catalog_path=Path("/root/fixture-catalog.json"),
        artifact_staging_directory=Path("/root/fixture-artifacts"),
        protected_enrollment_digest="e" * 64,
    )
    return ProtectedEnrollment(**values)


def _runtime_bindings(bridges, observers):
    return RootRuntimeBindings(
        enrollment_catalog=SimpleNamespace(digest="e" * 64), build_catalog=None,
        device_catalog=None, process_manager=None, effect_handlers={},
        native_bridges=bridges, artifact_catalog=None, build_store=None,
        service_connector=None, source_observer_enrollments=observers,
    )


def _fixture(*, observer=True, handler=True, inference_rule=True, admission=None):
    target = canonical_provider_target(OPENROUTER_MODEL)
    recipient = PROVIDER_RECIPIENT
    policy = _policy_record()
    canonicalizer_hash = str(policy["canonicalizer_sha256"])
    route = {
        "id": "provider-account-1", "provider": "openrouter",
        "account_id": "account-ref-fingerprint", "principal_id": "producer-principal",
        "target": target, "recipient": recipient,
        "credential_ref": "keyring://fixture/openrouter",
        "credential_scope": "provider:openrouter:account:fixture",
        "models": [OPENROUTER_MODEL], "allowed_sensitivities": ["public"],
        "additional_metered_fee_usd": 0.0,
    }
    bridge = NativeBridgeEnrollment(
        bridge_id="bridge-1", producer_profile_id="producer", producer_uid=2101,
        producer_generation="gen-1", producer_executable=Path("/root/hermes"),
        producer_executable_sha256="a" * 64, producer_principal_id="producer-principal",
        gateway_profile_id="gateway", gateway_uid=2102, gateway_generation="gen-2",
        gateway_executable=Path("/root/gateway"), gateway_executable_sha256="b" * 64,
        gateway_principal_id="gateway-principal", canonicalizer_artifact_id="provider-canonicalizer-v1",
        canonicalizer_sha256=canonicalizer_hash,
        normalization_policy_id=str(policy["id"]),
        normalization_policy_sha256=str(policy["normalization_policy_sha256"]),
        normalization_policy_revision=1, route_schema_id=str(policy["route_schema_id"]),
        output_limit_mode=str(policy["output_limit_mode"]), output_limit_ceiling=4096,
        approved_operation="provider.dispatch", provider_enrollment_id="provider-account-1",
        target=target, recipient=recipient,
    )
    producer = PrincipalBinding(
        2101, "producer-principal", "producer", "producer-ns",
        frozenset({"provider-dispatch", "provider-inference", "provider-tool-call"}),
    )
    gateway = PrincipalBinding(
        2102, "gateway-principal", "gateway", "gateway-ns", frozenset({"provider-dispatch"}),
    )
    rules = {}
    for capability in ("provider-inference", "provider-tool-call"):
        if capability == "provider-inference" and not inference_rule:
            continue
        rule = EffectRule(capability, "provider.dispatch", target, recipient)
        rules[(capability, rule.operation, rule.target)] = rule
    vault = _Vault()
    service = AuthorityService(
        signing_key=b"P" * 32, key_id="provider-runtime-fixture",
        bindings_by_uid={2101: producer, 2102: gateway}, rules=rules,
        handlers={}, policy=_Policy(),
        profile_generations={"producer": "gen-1", "gateway": "gen-2"},
        service_generation_digest="e" * 64,
    )
    bridge_map = {bridge.bridge_id: bridge}
    observer_map = {}
    if observer:
        observer_map["provider-result-1"] = SourceObserverEnrollment(
            observer_enrollment_id="provider-result-1", source_kind="provider-result",
            origin_id="provider.result", profile_id="producer", principal_id="producer-principal",
            namespace_id="producer-ns", enrollment_id="provider-account-1", generation="gen-1",
            producer_uid=2101, producer_executable_sha256="a" * 64,
            package_id="hermes-package", package_sha256="c" * 64, role_id="hermes-main",
            role_artifact_id="hermes-main", role_sha256="d" * 64, channel_id="provider.result",
            capture_schema_id="provider-result-schema", source_action_id="provider-result",
            target_id=target, recipient=recipient, allowed_parent_source_kinds=frozenset(),
        )
    admission = admission if admission is not None else OpenRouterLiveAdmission()
    provider_handlers = build_provider_handlers(
        enrollments={(target, recipient): ProviderEnrollment(
            provider="openrouter", account_id="account-ref-fingerprint",
            principal_id="producer-principal", target=target, recipient=recipient,
            credential_ref="keyring://fixture/openrouter",
            credential_scope="provider:openrouter:account:fixture",
            models=frozenset({OPENROUTER_MODEL}), allowed_sensitivities=frozenset({"public"}),
            additional_metered_fee_usd=0.0,
        )},
        normalization_policies={(target, recipient): policy}, admission=admission, vault=vault,
    ) if handler else {}
    service.handlers.update(provider_handlers)
    enrollment = _protected_enrollment(route, bridge, service)
    bindings = _runtime_bindings(bridge_map, observer_map)
    return service, enrollment, bindings, bridge_map, observer_map, provider_handlers, vault


class ProviderRuntimeCompositionTests(unittest.TestCase):
    def test_exact_selected_account_get_admission_and_result_observer_join(self):
        service, enrollment, bindings, bridges, observers, handlers, vault = _fixture()
        selected = build_provider_runtime_selection(
            service=service, enrollment=enrollment, bindings=bindings,
            bridges=bridges, provider_handlers=service.handlers, vault=vault,
            source_observer_enrollments=observers,
        )
        bridge = next(iter(bridges.values()))
        self.assertEqual(selected.provider_enrollments_by_id[bridge.provider_enrollment_id].account_id,
                         "account-ref-fingerprint")
        self.assertEqual(selected.provider_result_observer_ids[
            (bridge.provider_enrollment_id, bridge.target, bridge.recipient)
        ], "provider-result-1")
        self.assertEqual(selected.root_selected_enrollments_by_bridge[bridge.bridge_id][
            (bridge.target, bridge.recipient)
        ].credential_ref, "keyring://fixture/openrouter")
        self.assertEqual(selected.normalization_policies_by_route[(bridge.target, bridge.recipient)]["output_limit_ceiling"], 4096)
        self.assertEqual(selected.provider_tool_call_parser(
            "provider-account-1", 200, {"Content-Type": "application/json"},
            b'{"choices":[{"finish_reason":"stop","message":{"tool_calls":[]}}]}',
        ), ())

    def test_constructs_and_attaches_native_response_registry_to_selected_broker(self):
        service, enrollment, bindings, bridges, observers, handlers, vault = _fixture()
        bridge = next(iter(bridges.values()))
        from hermes_installer.authority.provider_runtime_composition import build_provider_runtime_selection
        selected = build_provider_runtime_selection(
            service=service, enrollment=enrollment,
            bindings=bindings, bridges=bridges,
            provider_handlers=service.handlers, vault=vault, source_observer_enrollments=observers,
        )

        class _ProcessManager:
            def resolve_live_peer(self, *_args, **_kwargs):
                return None

        class _SourceRegistry:
            def __init__(self):
                self.service = service
                self.observers = observers

            def record_observed_event(self, *_args, **_kwargs): pass
            def capture_observed_source(self, *_args, **_kwargs): pass
            def take_source_receipt(self, *_args, **_kwargs): pass
            def _resolve(self, *_args, **_kwargs): pass
            def _resolve_package_role(self, *_args, **_kwargs): pass
            def _resolve_loaded_package_proof(self, *_args, **_kwargs): pass

        manager = _ProcessManager()
        service.process_effect_handler = manager
        source_registry = _SourceRegistry()
        service.source_observer_registry = source_registry
        catalog = SimpleNamespace(digest="e" * 64)
        root_bindings = RootRuntimeBindings(
            enrollment_catalog=catalog, build_catalog=None, device_catalog=None,
            process_manager=manager, effect_handlers={}, native_bridges=bridges,
            artifact_catalog=None, build_store=None, service_connector=None,
            source_observer_enrollments=observers,
        )
        from hermes_installer.authority.runtime_composition import _ProtectedNativeActionResolver
        from hermes_installer.mcp.native_schema_catalog import (
            NativeMCPProtectedSchemaCatalog, NativeSchemaArtifact,
        )
        schema_catalog = NativeMCPProtectedSchemaCatalog((NativeSchemaArtifact(
            id="schema-fixture", artifact_id="artifact-fixture", sha256="f" * 64,
            size_bytes=16, derivation_receipt_handle=None,
            schema_kind="arguments", native_package_id="package-fixture",
            native_package_generation="package-gen", adapter_id="adapter-fixture",
            action_id="action-fixture", source_receipt_handle="source-receipt-fixture",
            schema={"type": "object"},
        ),))
        action_resolver = _ProtectedNativeActionResolver(
            root_bindings, schema_catalog, service_generation_digest="e" * 64,
        )
        canonicalizer_hash = str(next(iter(selected.normalization_policies_by_route.values()))[
            "canonicalizer_sha256"])
        broker = NativeBridgeBroker(
            service=service, bridges=bridges, process_resolver=manager.resolve_live_peer,
            canonicalizer=canonical_provider_request,
            root_selected_enrollments=selected.root_selected_enrollments_by_bridge,
            canonicalizer_sha256=canonicalizer_hash,
        )
        service.native_bridge_broker = None
        registry = attach_provider_response_registry(
            service=service, broker=broker, selection=selected,
            source_observers=source_registry,
            process_resolver=manager.resolve_live_peer, action_resolver=action_resolver,
        )
        self.assertIs(service.native_invocation_registry, registry)
        self.assertIs(service.native_bridge_broker, broker)
        self.assertIs(broker.provider_response_registry, registry)
        self.assertEqual(registry.provider_result_observer_ids[
            (bridge.provider_enrollment_id, bridge.target, bridge.recipient)
        ], "provider-result-1")

    def test_unselected_or_unadmitted_account_never_gets_a_runtime_join(self):
        for options in ({"handler": False}, {"observer": False}):
            with self.subTest(options=options):
                service, enrollment, bindings, bridges, observers, handlers, vault = _fixture(**options)
                with self.assertRaises(ProviderRuntimeUnavailable):
                    build_provider_runtime_selection(
                        service=service, enrollment=enrollment, bindings=bindings,
                        bridges=bridges, provider_handlers=service.handlers, vault=vault,
                        source_observer_enrollments=observers,
                    )

    def test_required_request_derived_capability_rules_are_independent(self):
        service, enrollment, bindings, bridges, observers, handlers, vault = _fixture(inference_rule=False)
        with self.assertRaises(ProviderRuntimeUnavailable):
            build_provider_runtime_selection(
                service=service, enrollment=enrollment, bindings=bindings,
                bridges=bridges, provider_handlers=service.handlers, vault=vault,
                source_observer_enrollments=observers,
            )

    def test_callable_but_unreviewed_admission_is_not_account_eligibility(self):
        service, enrollment, bindings, bridges, observers, handlers, vault = _fixture(
            admission=_Admission(),
        )
        with self.assertRaises(ProviderRuntimeUnavailable):
            build_provider_runtime_selection(
                service=service, enrollment=enrollment, bindings=bindings,
                bridges=bridges, provider_handlers=service.handlers, vault=vault,
                source_observer_enrollments=observers,
            )


if __name__ == "__main__":
    unittest.main()
