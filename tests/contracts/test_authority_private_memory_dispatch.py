from __future__ import annotations

import os
import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from hermes_installer.authority.runtime_bindings import RootRuntimeBindings
from hermes_installer.authority.service import AuthorityService, EffectRule, PrincipalBinding
from hermes_installer.authority.types import AuthorityDenied, canonical_bytes
from hermes_installer.memory.broker import DurableMemoryQueue
from hermes_installer.providers.private_memory import RootPrivateMemoryRouteResolver


class _Routes:
    def resolve_selected_private_route(self, **_kwargs):
        raise AssertionError("a missing durable job must be rejected before route resolution")

    def revalidate_private_route(self, *_args, **_kwargs):
        raise AssertionError("a missing durable job must be rejected before route revalidation")


class _Consent:
    def resolve_private_engine_selection(self, *_args, **_kwargs):
        raise AssertionError("a missing durable job must be rejected before consent resolution")

    def revalidate_private_engine_selection(self, *_args, **_kwargs):
        raise AssertionError("a missing durable job must be rejected before consent revalidation")


class _Models:
    def resolve_deployment(self, *_args, **_kwargs):
        raise AssertionError("a missing durable job must be rejected before model resolution")

    def revalidate_deployment(self, *_args, **_kwargs):
        raise AssertionError("a missing durable job must be rejected before model revalidation")


class _Policy:
    revision = "private-memory-fixture"

    def classify(self, *, purpose, intent, source_contexts, binding):
        from hermes_installer.authority.types import Sensitivity

        return Sensitivity.PRIVATE, "a" * 64

    def allow_effect(self, **_kwargs):
        return True


def _service_and_runtime(root: Path):
    binding = PrincipalBinding(
        os.getuid(), "principal:memory", "profile:memory", "namespace:memory",
        frozenset({"provider-inference", "memory-capture", "memory-extraction", "memory-embedding"}),
    )
    rule = EffectRule("provider-inference", "provider.dispatch", "private-route:fixed", "memory:private")
    service = AuthorityService(
        signing_key=b"p" * 32, key_id="private-memory-fixture",
        bindings_by_uid={binding.uid: binding},
        rules={(rule.capability, rule.operation, rule.target): rule}, handlers={},
        policy=_Policy(), service_generation_digest="a" * 64,
        profile_generations={binding.profile_id: "generation:memory"},
    )
    catalog = SimpleNamespace(digest="a" * 64)
    runtime = RootRuntimeBindings(
        enrollment_catalog=catalog, build_catalog=None, device_catalog=None,
        process_manager=None, effect_handlers={}, native_bridges={}, artifact_catalog=None,
        build_store=None, service_connector=None, protected_principal_bindings=(binding,),
    )
    service.attach_root_runtime_bindings(runtime)
    resolver = RootPrivateMemoryRouteResolver.from_root_runtime(
        runtime, _Routes(), _Consent(), _Models(), service,
    )
    queue = DurableMemoryQueue(
        root / "queue", owner_state=lambda _profile: ("openviking", 1),
        consent_issuer=lambda **_kwargs: None,
    )
    service.memory_owner_state = lambda _profile: ("openviking", 1)
    service.attach_private_memory_effect_runtime(queue, resolver)
    return service, queue


def test_root_service_rejects_unknown_job_before_route_or_effect_lookup():
    with tempfile.TemporaryDirectory() as tmp:
        service, _queue = _service_and_runtime(Path(tmp))
        payload = canonical_bytes({"model": "selected-model", "messages": []})
        with pytest.raises(AuthorityDenied, match="active durable job or signed source closure"):
            service.dispatch_private_memory_model(
                "J" * 43, payload, 5.0, cancelled=lambda: False,
            )


def test_root_service_rejects_unattached_or_duplicate_effect_runtime():
    binding = PrincipalBinding(
        os.getuid(), "principal:memory", "profile:memory", "namespace:memory",
        frozenset({"provider-inference"}),
    )
    service = AuthorityService(
        signing_key=b"q" * 32, key_id="private-memory-attach-fixture",
        bindings_by_uid={binding.uid: binding}, rules={}, handlers={}, policy=_Policy(),
    )
    with pytest.raises(AuthorityDenied, match="effect runtime"):
        service.attach_private_memory_effect_runtime(object(), object())
    with pytest.raises(AuthorityDenied, match="unavailable"):
        service.dispatch_private_memory_model(
            "J" * 43, canonical_bytes({"model": "selected-model"}), 5.0,
            cancelled=lambda: False,
        )
