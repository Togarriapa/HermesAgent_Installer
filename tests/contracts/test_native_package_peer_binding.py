from __future__ import annotations

import os
from types import SimpleNamespace

import pytest

from hermes_installer.authority.service import AuthorityDenied, AuthorityService, PrincipalBinding


def _service(manager=None, catalog=None):
    uid = os.getuid()
    binding = PrincipalBinding(uid, "native-principal", "native-profile", "native-namespace", frozenset({"native.metadata"}))
    service = AuthorityService(
        signing_key=b"n" * 32, key_id="native-package-binding-test",
        bindings_by_uid={uid: binding}, rules={}, handlers={},
    )
    service.root_runtime_bindings = SimpleNamespace(
        process_manager=manager,
        enrollment_catalog=catalog,
    )
    return service


def test_bind_uses_only_current_peer_loaded_package_and_read_is_peer_bound(monkeypatch):
    proof = SimpleNamespace(
        process_id="a" * 32, profile_id="profile-a", generation="generation-a",
        kernel_uid=os.getuid(),
        mount=SimpleNamespace(package_id="package-a", resolver_sha256="b" * 64),
    )
    package = SimpleNamespace(
        package_id="package-a", profile_id="profile-a", generation="generation-a",
        compiled_closure_sha256="c" * 64, entrypoint_sha256="d" * 64,
        resolver_sha256="b" * 64,
    )
    manager = SimpleNamespace(resolve_native_package_for_peer=lambda pid, fd: proof)
    catalog = SimpleNamespace(
        resolve_profile_native_package=lambda profile, generation: package,
        resolve_native_package=lambda package_id, generation: package,
    )
    service = _service(manager, catalog)
    resolver = {
        "schema": 1, "package_id": "package-a", "profile_id": "profile-a",
        "generation": "generation-a", "process_role_records_sha256": "e" * 64,
        "adapters": [], "owner_overlay_operation_records": [],
        "resolver_sha256": "f" * 64,
    }
    monkeypatch.setattr(service, "_current_native_package_resolver", lambda _proof, _package: resolver)

    binding = service._dispatch(os.getuid(), 123, 8, "native.package.bind", {"schema": 1},
                                cancelled=lambda: False)
    assert binding["package_id"] == "package-a"
    assert binding["resolver_digest"] == "f" * 64
    assert service._dispatch(os.getuid(), 123, 8, "native.package.resolver.read",
                             {"schema": 1, "binding_handle": binding["opaque_binding_handle"]},
                             cancelled=lambda: False) == resolver
    with pytest.raises(AuthorityDenied, match="absent or stale"):
        service._dispatch(os.getuid(), 124, 8, "native.package.resolver.read",
                          {"schema": 1, "binding_handle": binding["opaque_binding_handle"]},
                          cancelled=lambda: False)


def test_binding_denies_missing_loaded_process_and_caller_selectors():
    manager = SimpleNamespace(resolve_native_package_for_peer=lambda _pid, _fd: None)
    service = _service(manager, SimpleNamespace())
    with pytest.raises(AuthorityDenied, match="no current loaded native package"):
        service._dispatch(os.getuid(), 123, 8, "native.package.bind", {"schema": 1},
                          cancelled=lambda: False)
    with pytest.raises(AuthorityDenied, match="malformed"):
        service._dispatch(os.getuid(), 123, 8, "native.package.bind",
                          {"schema": 1, "profile_id": "caller-selected"},
                          cancelled=lambda: False)


def test_binding_read_revokes_lease_when_loaded_package_currentness_changes(monkeypatch):
    proof = SimpleNamespace(
        process_id="a" * 32, profile_id="profile-a", generation="generation-a",
        kernel_uid=os.getuid(),
        mount=SimpleNamespace(package_id="package-a", resolver_sha256="b" * 64),
    )
    package = SimpleNamespace(
        package_id="package-a", profile_id="profile-a", generation="generation-a",
        compiled_closure_sha256="c" * 64, entrypoint_sha256="d" * 64,
        resolver_sha256="b" * 64,
    )
    current = {"proof": proof}
    manager = SimpleNamespace(resolve_native_package_for_peer=lambda _pid, _fd: current["proof"])
    catalog = SimpleNamespace(
        resolve_profile_native_package=lambda _profile, _generation: package,
        resolve_native_package=lambda _package_id, _generation: package,
    )
    service = _service(manager, catalog)
    resolver = {"schema": 1, "resolver_sha256": "f" * 64}
    monkeypatch.setattr(service, "_current_native_package_resolver", lambda _proof, _package: resolver)
    binding = service._bind_selected_native_package(os.getuid(), 123, 8)
    current["proof"] = None
    with pytest.raises(AuthorityDenied, match="loaded package or resolver changed"):
        service._read_selected_native_resolver(os.getuid(), 123, 8,
                                               binding["opaque_binding_handle"])
    assert binding["opaque_binding_handle"] not in service._native_package_binding_leases
