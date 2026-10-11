from __future__ import annotations

import base64
import hashlib
import json
from types import SimpleNamespace

import pytest

from hermes_installer.native_plugin_loader import (
    NativePluginLoadUnavailable, RootSelectedOwnerOverlayRPCProxy,
)


_REGISTRATIONS = {
    "read": "resource-overlay-store:tool:resource_overlay_read",
    "history": "resource-overlay-store:tool:resource_overlay_history",
    "write": "resource-overlay-store:tool:resource_overlay_write",
    "delete": "resource-overlay-store:tool:resource_overlay_delete",
}


class _Authority:
    def __init__(self):
        self.calls = []
        self.result = {}

    def execute_owner_overlay(self, invocation_handle, canonical_arguments):
        self.calls.append((invocation_handle, canonical_arguments))
        body = json.dumps(self.result, sort_keys=True, separators=(",", ":")).encode()
        return {
            "schema": 1, "invocation_handle": invocation_handle,
            "registration_id": _REGISTRATIONS[self.method],
            "result_schema_id": "result-schema-v1",
            "result_sha256": hashlib.sha256(body).hexdigest(),
            "canonical_result_b64": base64.b64encode(body).decode(),
        }


def _proxy(method: str, *, binding=None, authority=None):
    authority = authority or _Authority()
    authority.method = method
    rows = tuple(SimpleNamespace(
        method=name, registration_id=registration, result_schema_id="result-schema-v1",
    ) for name, registration in _REGISTRATIONS.items())
    package = SimpleNamespace(
        _selection=SimpleNamespace(owner_overlay_operations=rows),
        package_id="package-v1", profile_id="profile-v1", generation="generation-v1",
    )
    return RootSelectedOwnerOverlayRPCProxy(
        authority=authority, package=package,
        current_binding=lambda: binding,
    ), authority


def _binding(method: str, *, adapter="resource-overlay-store", action=None):
    return SimpleNamespace(
        invocation_handle="a" * 43, package_id="package-v1", profile_id="profile-v1",
        generation="generation-v1", adapter_id=adapter,
        action_id=action or _REGISTRATIONS[method],
    )


@pytest.mark.parametrize("method,args,result", [
    ("read", {"record_id": "one"}, {"found": False, "record_id": "one"}),
    ("history", {"record_id": "one"}, {"record_id": "one", "revisions": []}),
    ("write", {"record_id": "one", "value": b"payload", "expected_revision": None},
     {"record_id": "one", "revision": "b" * 64}),
    ("delete", {"record_id": "one", "expected_revision": "c" * 64},
     {"record_id": "one", "deleted_revision": "d" * 64}),
])
def test_proxy_uses_only_current_registration_and_fixed_rpc(method, args, result):
    proxy, authority = _proxy(method, binding=_binding(method))
    authority.result = result
    assert proxy._call(method, args) == result
    assert len(authority.calls) == 1
    invocation, raw = authority.calls[0]
    assert invocation == "a" * 43
    parsed = json.loads(raw)
    assert json.dumps(parsed, sort_keys=True, separators=(",", ":")).encode() == raw
    assert parsed["record_id"] == "one"


def test_proxy_denies_calls_without_exact_live_local_invocation():
    proxy, authority = _proxy("read", binding=None)
    with pytest.raises(NativePluginLoadUnavailable):
        proxy.read("one")
    assert authority.calls == []

    proxy, authority = _proxy("read", binding=_binding("read", adapter="other"))
    with pytest.raises(NativePluginLoadUnavailable):
        proxy.read("one")
    assert authority.calls == []


def test_proxy_validates_root_result_schema_id_and_bytes():
    authority = _Authority()
    authority.method = "read"
    authority.result = {"found": False, "record_id": "one"}
    proxy, _ = _proxy("read", binding=_binding("read"), authority=authority)
    original = authority.execute_owner_overlay

    def wrong_schema(invocation_handle, canonical_arguments):
        response = original(invocation_handle, canonical_arguments)
        return {**response, "result_schema_id": "caller-schema"}

    authority.execute_owner_overlay = wrong_schema
    with pytest.raises(NativePluginLoadUnavailable):
        proxy.read("one")
