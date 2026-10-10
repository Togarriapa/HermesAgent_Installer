from types import SimpleNamespace

import pytest

from hermes_installer.authority.memory_runtime_composition import (
    RootMemoryNetworkLeaseResolver,
    RootMemoryNetworkUnavailable,
    compose_root_memory_runtime,
)
from hermes_installer.authority.runtime_bindings import RootRuntimeBindings


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
