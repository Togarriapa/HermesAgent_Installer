from __future__ import annotations

import base64

import pytest

from hermes_installer.authority.service import AuthorityService
from hermes_installer.authority.types import AuthorityDenied


class _Registry:
    def __init__(self):
        self.call = None

    def execute_rpc(self, **kwargs):
        self.call = kwargs
        return {
            "schema": 1,
            "invocation_handle": kwargs["invocation_handle"],
            "registration_id": "resource-overlay-store:tool:resource_overlay_read",
            "result_schema_id": "native-owner-overlay-read-result-v1",
            "result_sha256": "a" * 64,
            "canonical_result_b64": base64.b64encode(b"{}").decode("ascii"),
        }


def _service(registry):
    service = AuthorityService.__new__(AuthorityService)
    service.active_owner_overlay_registry = registry
    return service


def test_owner_overlay_service_dispatch_uses_kernel_peer_and_exact_wire():
    registry = _Registry()
    service = _service(registry)
    raw = b'{"record_id":"entry"}'
    result = service._dispatch_native_owner_overlay(
        501, 72, 18,
        {"schema": 1, "invocation_handle": "b" * 43,
         "canonical_arguments_b64": base64.b64encode(raw).decode("ascii")},
        cancelled=lambda: False,
    )
    assert registry.call == {
        "invocation_handle": "b" * 43, "canonical_argument_bytes": raw,
        "peer_uid": 501, "peer_pid": 72, "peer_pidfd": 18,
    }
    assert result["invocation_handle"] == "b" * 43


@pytest.mark.parametrize("payload", [
    {"schema": 1, "invocation_handle": "b" * 43,
     "canonical_arguments_b64": base64.b64encode(b"{}").decode(), "registration_id": "caller"},
    {"schema": 1, "invocation_handle": "b" * 43,
     "canonical_arguments_b64": "e30"},
])
def test_owner_overlay_service_dispatch_rejects_selectors_and_noncanonical_base64(payload):
    registry = _Registry()
    service = _service(registry)
    with pytest.raises(AuthorityDenied):
        service._dispatch_native_owner_overlay(
            501, 72, 18, payload, cancelled=lambda: False,
        )
    assert registry.call is None


def test_owner_overlay_service_dispatch_denies_cancellation_before_registry():
    registry = _Registry()
    service = _service(registry)
    payload = {"schema": 1, "invocation_handle": "b" * 43,
               "canonical_arguments_b64": base64.b64encode(b"{}").decode()}
    with pytest.raises(AuthorityDenied):
        service._dispatch_native_owner_overlay(
            501, 72, 18, payload, cancelled=lambda: True,
        )
    assert registry.call is None
