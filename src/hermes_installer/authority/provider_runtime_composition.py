"""Root-only provider enrollment joins for HI11 response observation.

This module converts only the already validated ProtectedEnrollment and live
AuthorityService handler rows into the small immutable maps consumed by the
native bridge/response registry. It does not enable an unselected account,
resolve credentials, or claim that catalog/key checks are account admission.
"""
from __future__ import annotations

import hashlib
import inspect
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Mapping

from .service import AuthorityService


class ProviderRuntimeUnavailable(PermissionError):
    """A protected provider/observer join is absent, stale, or ambiguous."""


@dataclass(frozen=True, slots=True)
class ProviderRuntimeSelection:
    """Validated root-selected routes and observer indexes for one service epoch."""

    provider_enrollments_by_id: Mapping[str, Any]
    bridges_by_id: Mapping[str, Any]
    root_selected_enrollments_by_bridge: Mapping[str, Mapping[tuple[str, str], Any]]
    normalization_policies_by_route: Mapping[tuple[str, str], Mapping[str, object]]
    provider_result_observer_ids: Mapping[tuple[str, str, str], str]
    provider_tool_call_parser: Any


def build_provider_runtime_selection(*, service: AuthorityService,
                                     enrollment: Any,
                                     bindings: Any,
                                     bridges: Mapping[str, Any],
                                     provider_handlers: Mapping[tuple[str, str], Any] | None = None,
                                     vault: Any | None = None,
                                     source_observer_enrollments: Mapping[str, Any] | None = None) -> ProviderRuntimeSelection:
    """Join bridge, provider, GET admission, effect rule, and result observer.

    Inputs must be root-loaded typed enrollment objects. A bridge selects one
    provider enrollment by its protected ID; a provider catalog entry without
    that bridge join is never included. The active fixed handler must carry the
    exact route, protected vault, zero-cost normalization policy and live
    admission callback. Rules must cover both request-derived capabilities.
    """
    from hermes_installer.authority.enrollment import NativeBridgeEnrollment, ProtectedEnrollment
    from hermes_installer.authority.source_observers import SourceObserverEnrollment
    from hermes_installer.provider_effect_handlers import (
        NormalizationPolicy, ProviderEnrollment, _FixedProviderHandler,
        canonical_provider_request,
    )
    from hermes_installer.provider_response_observer import parse_successful_provider_tool_calls

    if (not isinstance(service, AuthorityService) or not isinstance(enrollment, ProtectedEnrollment)
            or not isinstance(bridges, Mapping) or not bridges
            or not isinstance(provider_handlers, Mapping)
            or vault is None or not isinstance(source_observer_enrollments, Mapping)):
        raise ProviderRuntimeUnavailable("protected provider runtime dependencies are unavailable")
    if (service.service_generation_digest != enrollment.protected_enrollment_digest
            or not isinstance(bindings.native_bridges, Mapping)
            or dict(bridges) != dict(bindings.native_bridges)):
        raise ProviderRuntimeUnavailable("provider bridge snapshot differs from active protected generation")
    module_path = inspect.getsourcefile(canonical_provider_request)
    if not module_path:
        raise ProviderRuntimeUnavailable("provider canonicalizer source identity is unavailable")
    canonicalizer_sha = hashlib.sha256(__import__("pathlib").Path(module_path).read_bytes()).hexdigest()

    typed_by_id: dict[str, Any] = {}
    for provider_id, raw in enrollment.provider_enrollments.items():
        if (not isinstance(provider_id, str) or not isinstance(raw, Mapping)
                or raw.get("id") != provider_id):
            raise ProviderRuntimeUnavailable("protected provider enrollment identity is malformed")
        fields = dict(raw)
        fields.pop("id", None)
        try:
            fields["models"] = frozenset(fields["models"])
            fields["allowed_sensitivities"] = frozenset(fields["allowed_sensitivities"])
            route = ProviderEnrollment(**fields)
        except (KeyError, TypeError, ValueError):
            raise ProviderRuntimeUnavailable("protected provider route is invalid") from None
        typed_by_id[provider_id] = route

    handler_map = dict(provider_handlers)
    bridge_routes: dict[str, Mapping[tuple[str, str], Any]] = {}
    normalization_by_route: dict[tuple[str, str], Mapping[str, object]] = {}
    result_observers: dict[tuple[str, str, str], str] = {}
    route_by_id: dict[str, Any] = {}
    for bridge_id, bridge in bridges.items():
        if (not isinstance(bridge, NativeBridgeEnrollment) or bridge_id != bridge.bridge_id
                or bridge.approved_operation != "provider.dispatch"
                or bridge.canonicalizer_artifact_id != "provider-canonicalizer-v1"
                or bridge.canonicalizer_sha256 != canonicalizer_sha
                or service.profile_generations.get(bridge.producer_profile_id) != bridge.producer_generation
                or service.profile_generations.get(bridge.gateway_profile_id) != bridge.gateway_generation):
            raise ProviderRuntimeUnavailable("provider bridge generation or canonicalizer is stale")
        route_id = bridge.provider_enrollment_id
        route = typed_by_id.get(route_id)
        if (route is None or route.target != bridge.target or route.recipient != bridge.recipient
                or route.principal_id != bridge.producer_principal_id):
            raise ProviderRuntimeUnavailable("provider bridge does not select its exact account enrollment")
        producer_binding = service.bindings_by_uid.get(bridge.producer_uid)
        gateway_binding = service.bindings_by_uid.get(bridge.gateway_uid)
        if (producer_binding is None or gateway_binding is None
                or producer_binding.principal_id != bridge.producer_principal_id
                or producer_binding.profile_id != bridge.producer_profile_id
                or gateway_binding.principal_id != bridge.gateway_principal_id
                or gateway_binding.profile_id != bridge.gateway_profile_id
                or "provider-dispatch" not in producer_binding.capabilities):
            raise ProviderRuntimeUnavailable("provider bridge peer principal or dispatch capability changed")

        handler = handler_map.get(("provider.dispatch", bridge.target))
        if (type(handler) is not _FixedProviderHandler
                or handler._enrollment != route or handler._vault is not vault
                or not callable(getattr(handler._admission, "check_attempt", None))):
            raise ProviderRuntimeUnavailable("provider is not currently selected with a root vault and live admission")
        policy = {
            "id": bridge.normalization_policy_id,
            "revision": bridge.normalization_policy_revision,
            "route_schema_id": bridge.route_schema_id,
            "output_limit_mode": bridge.output_limit_mode,
            "output_limit_ceiling": bridge.output_limit_ceiling,
            "canonicalizer_artifact_id": bridge.canonicalizer_artifact_id,
            "canonicalizer_sha256": bridge.canonicalizer_sha256,
            "normalization_policy_sha256": bridge.normalization_policy_sha256,
        }
        try:
            parsed_policy = NormalizationPolicy.from_record(policy, provider=route.provider)
        except Exception:
            raise ProviderRuntimeUnavailable("provider normalization policy is not currently valid") from None
        if handler._normalization_policy.as_record() != parsed_policy.as_record():
            raise ProviderRuntimeUnavailable("provider handler uses a different normalization policy")
        key = (route.target, route.recipient)
        old = normalization_by_route.setdefault(key, MappingProxyType(policy))
        if dict(old) != policy:
            raise ProviderRuntimeUnavailable("one provider route has conflicting normalization policies")

        for capability in ("provider-inference", "provider-tool-call"):
            rule = service.rules.get((capability, "provider.dispatch", route.target))
            if (rule is None or rule.capability != capability or rule.operation != "provider.dispatch"
                    or rule.target != route.target or rule.recipient != route.recipient
                    or capability not in producer_binding.capabilities):
                raise ProviderRuntimeUnavailable("provider route lacks an active request-derived capability rule")

        matches = [observer for observer_id, observer in source_observer_enrollments.items()
                   if isinstance(observer, SourceObserverEnrollment)
                   and observer_id == observer.observer_enrollment_id
                   and observer.source_kind == "provider-result"
                   and observer.profile_id == bridge.producer_profile_id
                   and observer.generation == bridge.producer_generation
                   and observer.principal_id == bridge.producer_principal_id
                   and observer.producer_uid == bridge.producer_uid
                   and observer.target_id == bridge.target
                   and observer.recipient == bridge.recipient]
        if len(matches) != 1:
            raise ProviderRuntimeUnavailable("provider response lacks one exact selected result observer")
        observer = matches[0]
        result_observers[(route_id, route.target, route.recipient)] = observer.observer_enrollment_id
        bridge_routes[bridge_id] = MappingProxyType({key: route})
        route_by_id[route_id] = route

    if set(route_by_id) != {bridge.provider_enrollment_id for bridge in bridges.values()}:
        raise ProviderRuntimeUnavailable("provider runtime route selection is incomplete")

    def parse_tool_calls(provider_enrollment_id: str, status: int,
                         headers: Mapping[str, str], response_bytes: bytes) -> tuple[Any, ...]:
        selected = route_by_id.get(provider_enrollment_id)
        if selected is None:
            raise ProviderRuntimeUnavailable("provider result parser received an unselected enrollment")
        return parse_successful_provider_tool_calls(selected.provider, status, headers, response_bytes)

    return ProviderRuntimeSelection(
        provider_enrollments_by_id=MappingProxyType(typed_by_id),
        bridges_by_id=MappingProxyType(dict(bridges)),
        root_selected_enrollments_by_bridge=MappingProxyType(bridge_routes),
        normalization_policies_by_route=MappingProxyType(normalization_by_route),
        provider_result_observer_ids=MappingProxyType(result_observers),
        provider_tool_call_parser=parse_tool_calls,
    )


def attach_provider_response_registry(*, service: AuthorityService, broker: Any,
                                      selection: ProviderRuntimeSelection,
                                      source_observers: Any, process_resolver: Any,
                                      action_resolver: Any) -> Any:
    """Construct and attach the selected response registry to its HI11 broker.

    The schema/action resolver must already be built from source-verified
    protected schema records by root composition. This function accepts no
    caller-supplied provider, observer, parser, or schema names: all route and
    result-observer selections come from ``selection``.
    """
    from .native_bridge import NativeBridgeBroker
    from .native_runtime_observer import NativeInvocationRegistry
    from .runtime_composition import _ProtectedNativeActionResolver

    if (not isinstance(service, AuthorityService)
            or not isinstance(broker, NativeBridgeBroker)
            or broker.service is not service
            or broker.provider_response_registry is not None
            or service.native_invocation_registry is not None
            or service.native_bridge_broker is not None
            or not isinstance(selection, ProviderRuntimeSelection)
            or not isinstance(getattr(source_observers, "observers", None), Mapping)
            or not callable(process_resolver)
            or not isinstance(action_resolver, _ProtectedNativeActionResolver)):
        raise ProviderRuntimeUnavailable("native provider response registry prerequisites are unavailable")
    if (broker.bridges != dict(selection.bridges_by_id)
            or set(selection.root_selected_enrollments_by_bridge) != set(broker.bridges)
            or getattr(source_observers, "service", None) is not service
            or getattr(service, "source_observer_registry", None) is not source_observers
            or set(selection.provider_result_observer_ids)
                != {(bridge.provider_enrollment_id, bridge.target, bridge.recipient)
                    for bridge in broker.bridges.values()}
            or process_resolver != getattr(service.process_effect_handler, "resolve_live_peer", None)
            or process_resolver != broker.process_resolver):
        raise ProviderRuntimeUnavailable("provider bridge, source observer, and response selection do not join")
    try:
        registry = NativeInvocationRegistry(
            service=service,
            source_observers=source_observers,
            bridges=broker.bridges,
            provider_result_observer_ids=selection.provider_result_observer_ids,
            provider_tool_call_parser=selection.provider_tool_call_parser,
            process_resolver=process_resolver,
            action_resolver=action_resolver,
            monotonic=service.monotonic,
        )
        broker.attach_provider_response_registry(registry)
        service.attach_native_invocation_registry(registry)
        service.attach_native_bridge_broker(broker)
    except Exception:
        raise ProviderRuntimeUnavailable("root provider response registry rejected the protected join") from None
    return registry
