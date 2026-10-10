from __future__ import annotations

import hashlib
import json
from types import SimpleNamespace

import pytest

from hermes_installer.authority.application_workload_execution import (
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
