from __future__ import annotations

from types import SimpleNamespace

import pytest

from hermes_installer.authority.native_runtime_observer import RootNativeToolEffectInvocation
from hermes_installer.authority.web_content_artifacts import (
    RootWebContentArtifactRegistry,
    WebContentArtifactDenied,
)


def _invocation(*, expiry: float = 100.0, parents: tuple[str, ...] = ("p" * 32,)):
    return RootNativeToolEffectInvocation(
        invocation_handle="i" * 32,
        observed_call_handle="c" * 32,
        response_observation_handle="o" * 32,
        response_receipt_handle="r" * 32,
        native_request_handle="n" * 32,
        turn_handle="t" * 32,
        producer_identity={"pid": 42},
        producer_pid=42,
        profile_id="profile-a",
        generation="generation-a",
        package_id="package-a",
        native_package_generation="package-generation-a",
        service_generation_digest="d" * 64,
        adapter_id="adapter-a",
        action_id="action-a",
        tool_name="tool-a",
        arguments_sha256="a" * 64,
        source_receipt_handles=parents,
        operation="plugin.web.read",
        request_digest="b" * 64,
        expires_monotonic=expiry,
    )


def _registry(returned):
    auth = SimpleNamespace(operation="plugin.web.read", target="target-a")
    context = object()

    class Resolver:
        def resolve_current_invocation_for_effect(self, *args):
            assert args == (context, auth, "plugin.web.read", "target-a", "b" * 64, "i" * 32)
            if isinstance(returned, Exception):
                raise returned
            return returned

    registry = object.__new__(RootWebContentArtifactRegistry)
    registry.service = SimpleNamespace(
        native_invocation_registry=Resolver(),
        service_generation_digest="d" * 64,
    )
    registry.monotonic = lambda: 50.0
    observation = SimpleNamespace(
        _authorization=auth,
        _context=context,
        _invocation=_invocation(),
        canonical_request_sha256="b" * 64,
        native_invocation_handle="i" * 32,
        profile_id="profile-a",
        owner_generation="generation-a",
        parent_source_receipt_handles=("p" * 32,),
    )
    return registry, observation


def test_current_invocation_is_revalidated_without_consuming_it():
    invocation = _invocation()
    registry, observation = _registry(invocation)
    registry._verify_current_invocation(observation)


@pytest.mark.parametrize("replacement", [
    _invocation(expiry=49.0),
    _invocation(parents=("x" * 32,)),
    PermissionError("revoked"),
])
def test_stale_or_changed_invocation_is_denied(replacement):
    registry, observation = _registry(replacement)
    with pytest.raises(WebContentArtifactDenied):
        registry._verify_current_invocation(observation)
