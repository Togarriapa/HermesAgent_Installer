from __future__ import annotations

import hashlib
import json
from types import SimpleNamespace

import pytest
import urllib.request

from hermes_installer.authority.application_workload_execution import (
    RootOwnedApplicationFixtureServer,
    RootApplicationWorkloadAuthority,
)
from hermes_installer.authority.types import AuthorityDenied


class _Invocations:
    def is_selected_application_invocation_current(self, invocation):
        return True


class _Service:
    service_generation_digest = "a" * 64

    @staticmethod
    def monotonic():
        return 1.0


class _CatalogWithoutWorkloadJoin:
    """An active app row alone cannot authorize a caller-selected workload."""


def test_admission_denies_without_protected_action_to_workload_mapping():
    arguments = json.dumps({}, sort_keys=True, separators=(",", ":")).encode()
    invocation = SimpleNamespace(
        request_sha256=hashlib.sha256(arguments).hexdigest(),
        service_generation_digest="a" * 64,
        expires_monotonic=20.0,
        profile_id="profile-1",
        profile_generation="generation-1",
    )
    authority = RootApplicationWorkloadAuthority.__new__(RootApplicationWorkloadAuthority)
    authority.catalog = _CatalogWithoutWorkloadJoin()
    authority.invocations = _Invocations()
    authority.service = _Service()

    with pytest.raises(AuthorityDenied, match="action-to-workload"):
        authority.admit_selected_workload(invocation, arguments)


def test_owned_fixture_receipt_requires_live_loopback_listener():
    binding = SimpleNamespace(expires_monotonic=30.0)

    class Controllers:
        def resolve_binding(self, handle):
            return binding if handle == "c" * 32 else None

        @staticmethod
        def verify_binding(value):
            return value is binding

    server = RootOwnedApplicationFixtureServer(controllers=Controllers(), monotonic=lambda: 1.0,
        service_generation_digest="a" * 64)
    receipt = server.start(setup_session_id="setup-session", controller_binding_handle="c" * 32)
    try:
        assert receipt.url.startswith("http://127.0.0.1:")
        assert server.resolve(receipt.handle, setup_session_id="setup-session",
            service_generation_digest="a" * 64) is receipt
        with urllib.request.urlopen(receipt.url, timeout=2) as response:
            assert response.status == 200
            assert response.read(256) == RootOwnedApplicationFixtureServer._BODY
        with pytest.raises(AuthorityDenied, match="stale"):
            server.resolve(receipt.handle, setup_session_id="other",
                service_generation_digest="a" * 64)
    finally:
        server.close()
