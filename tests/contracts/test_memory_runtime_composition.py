from types import SimpleNamespace

import pytest

from hermes_installer.authority.memory_runtime_composition import (
    RootMemoryNetworkLeaseResolver,
    RootMemoryNetworkUnavailable,
    compose_root_memory_runtime,
)
from hermes_installer.authority.runtime_bindings import RootRuntimeBindings
from hermes_installer.memory.namespace_connector import (
    MemoryNamespaceConnector, MemoryNamespaceUnavailable,
)


def _bindings(catalog, process_manager):
    return RootRuntimeBindings(
        enrollment_catalog=catalog, build_catalog=None, device_catalog=None,
        process_manager=process_manager, effect_handlers={}, native_bridges={},
        artifact_catalog=None, build_store=None, service_connector=None,
    )


def test_network_resolver_rejects_a_handle_without_a_protected_endpoint_join():
    catalog = SimpleNamespace(digest="a" * 64)
    custody = SimpleNamespace(
        resolve_private_loopback_network_lease=lambda _endpoint: object(),
    )
    resolver = RootMemoryNetworkLeaseResolver(_bindings(catalog, custody))

    with pytest.raises(RootMemoryNetworkUnavailable,
                       match="selected endpoint has no current custody-owned"):
        resolver.resolve("network-binding-a")


def test_network_resolver_rejects_malformed_selector_before_catalog_access():
    def unexpected(*_args, **_kwargs):
        raise AssertionError("malformed selector reached protected catalog")

    catalog = SimpleNamespace(digest="a" * 64,
                              resolve_private_loopback_binding_handle=unexpected)
    resolver = RootMemoryNetworkLeaseResolver(_bindings(catalog, object()))

    with pytest.raises(RootMemoryNetworkUnavailable, match="selector is malformed"):
        resolver.resolve("")


def test_memory_connector_uses_protected_resolver_without_generic_lease_fallback():
    catalog = SimpleNamespace(digest="a" * 64)
    generic_custody = SimpleNamespace(
        resolve_namespace_lease=lambda _binding: (_ for _ in ()).throw(
            AssertionError("generic namespace lease must not be used")),
    )
    bindings = _bindings(catalog, generic_custody)
    resolver = RootMemoryNetworkLeaseResolver(bindings)
    enrollment = SimpleNamespace(
        service_enrollment_id="service-a", service_generation="generation-a",
        profile_id="profile-a", principal_id="principal-a", namespace_identity="ns-a",
        target_id="memory-agentmemory:profile-a", literal_loopback_port=8000,
        fixed_route_map={"agentmemory-search": object()}, limits={"request_bytes": 2048},
    )
    route_binding = SimpleNamespace(
        target_id=enrollment.target_id, route_id="agentmemory-search",
        profile_id=enrollment.profile_id, generation=enrollment.service_generation,
        namespace_identity=enrollment.namespace_identity,
        literal_loopback_port=enrollment.literal_loopback_port,
        memory_enrollment=enrollment,
    )
    connector = MemoryNamespaceConnector(
        catalog=catalog, process_manager=generic_custody,
        vault=SimpleNamespace(resolve_reference=lambda *_args, **_kwargs: "secret"),
        route_resolver=lambda *_args: route_binding,
        private_network_lease_resolver=resolver,
    )

    with pytest.raises(MemoryNamespaceUnavailable, match="private memory network lease"):
        connector.request(
            enrollment=enrollment, route_id="agentmemory-search", request=object(),
            before_connect=lambda _digest: None, timeout=1.0,
            deadline=__import__("time").monotonic() + 1.0,
            cancelled=lambda: False,
        )


def test_runtime_composition_keeps_lifecycle_unavailable_without_active_proofs():
    bindings = _bindings(SimpleNamespace(digest="a" * 64), object())
    enrollment = SimpleNamespace(memory_enrollments={"memory-a": object()})

    result = compose_root_memory_runtime(
        bindings=bindings, enrollment=enrollment, memory_runtime={},
        service=SimpleNamespace(monotonic=__import__("time").monotonic),
    )

    assert result.network_lease_resolver is not None
    assert result.prestart_receipt_registry is None
    assert result.semantic_readiness_registry is None
    assert result.enablement_registry is None
    assert result.lifecycle_registry is None
    assert "durable root service-enable choice registry is unavailable" in result.unavailable_reason
