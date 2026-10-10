"""Synthetic protocol tests; no endpoint, model, or private inference is qualified."""
from __future__ import annotations

import json
import math
import sys
import types
import unittest
from dataclasses import dataclass, replace
from unittest.mock import patch

from hermes_installer.authority.types import AuthorityDenied, HostContext, Sensitivity
from hermes_installer.memory.private_engine import (
    PrivateMemoryEngineUnavailable, RootPrivateMemoryEngine,
)
from hermes_installer.memory.broker import MemoryTarget, _build_private_engine_registry
from hermes_installer.memory.enrollment import MemoryServiceEnrollment
from test_memory_enrollment import record as enrollment_record


@dataclass(frozen=True)
class _SelectedRoutes:
    selection_id: str = "selection:fixture"
    profile_id: str = "profile:one"
    namespace_id: str = "namespace:one"
    memory_provider: str = "agentmemory"
    memory_owner_generation: int = 3
    service_generation_digest: str = "a" * 64
    extract_route_id: str = "private:extract:fixture"
    embed_route_id: str = "private:embed:fixture"
    extraction_served_model_id: str = "glm-5.2-fixture"
    embedding_served_model_id: str = "embed-fixture-v1"
    embedding_dimensions: int = 2
    protocol_sha256: str = "0158fa3c3b8dcc6befb008f3b617ca084f0470b05eb9b99f2f12b27735eca2d4"
    endpoint_selection_receipt_handle: str = "endpoint-receipt-fixture"
    extraction_model_deployment_receipt_handle: str = "extract-deployment-fixture"
    embedding_model_deployment_receipt_handle: str = "embed-deployment-fixture"
    expires_monotonic: float = 100.0


def _context(action="extract") -> HostContext:
    stage = "extraction" if action == "extract" else "embedding"
    return HostContext(
        principal_id="principal:one", profile_id="profile:one", namespace_id="namespace:one",
        uid=1001, purpose="memory-" + stage, intent_id="memory:" + action,
        trace_id="trace:fixture", sensitivity=Sensitivity.PRIVATE,
        lineage_hash="b" * 64, policy_revision="policy:fixture",
        capabilities=frozenset(), issued_at_monotonic=1, monotonic_expires_at=30,
        nonce="nonce:fixture", grant_id="grant:fixture", signature="signature:fixture",
        operation="memory." + action,
    )


class _Dispatcher:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def dispatch_memory_request(self, context, **kwargs):
        self.calls.append((context, kwargs))
        return self.responses.pop(0)


class RootPrivateMemoryEngineCodecTests(unittest.TestCase):
    def _engine(self, dispatcher, *, selected=None, now=10.0):
        provider_pkg = types.ModuleType("hermes_installer.providers")
        provider_pkg.__path__ = []
        provider_mod = types.ModuleType("hermes_installer.providers.private_memory")
        provider_mod.RootSelectedPrivateMemoryEngineRoutes = _SelectedRoutes
        with patch.dict(sys.modules, {
            "hermes_installer.providers": provider_pkg,
            "hermes_installer.providers.private_memory": provider_mod,
        }):
            engine = RootPrivateMemoryEngine.from_selected_routes(
                selected or _SelectedRoutes(), dispatcher, monotonic=lambda: now,
            )
        return engine

    def test_fixed_extraction_request_and_strict_bounded_result(self):
        dispatcher = _Dispatcher([json.dumps({
            "object": "chat.completion", "model": "glm-5.2-fixture",
            "choices": [{"index": 0, "finish_reason": "stop", "message": {
                "role": "assistant", "content": '{"facts":["synthetic fact"]}',
            }}],
        }).encode()])
        engine = self._engine(dispatcher)
        context = _context()
        self.assertEqual(engine.extract(
            text="captured synthetic transcript", context=context,
            timeout=20, cancelled=lambda: False,
        ), ["synthetic fact"])
        sent_context, call = dispatcher.calls[0]
        self.assertIs(sent_context, context)
        self.assertEqual(call["route_id"], "private:extract:fixture")
        self.assertEqual(call["model_id"], "glm-5.2-fixture")
        request = json.loads(call["payload"])
        self.assertEqual(set(request), {"model", "messages", "stream", "temperature", "max_tokens"})
        self.assertEqual(request["messages"][1], {"role": "user", "content": "captured synthetic transcript"})
        self.assertFalse(request["stream"])
        self.assertEqual(request["temperature"], 0)

    def test_embedding_orders_indices_and_empty_input_has_no_effect(self):
        dispatcher = _Dispatcher([json.dumps({
            "object": "list", "model": "embed-fixture-v1", "data": [
                {"object": "embedding", "index": 1, "embedding": [0.25, 0.75]},
                {"object": "embedding", "index": 0, "embedding": [1, 0]},
            ],
        }).encode()])
        engine = self._engine(dispatcher)
        self.assertEqual(engine.embed(
            facts=["first", "second"], context=_context("embed"),
            timeout=20, cancelled=lambda: False,
        ), [[1.0, 0.0], [0.25, 0.75]])
        call = dispatcher.calls[0][1]
        self.assertEqual(call["route_id"], "private:embed:fixture")
        self.assertEqual(call["model_id"], "embed-fixture-v1")
        self.assertEqual(json.loads(call["payload"])["encoding_format"], "float")
        self.assertEqual(engine.embed(
            facts=[], context=_context("embed"), timeout=20, cancelled=lambda: False,
        ), [])
        self.assertEqual(len(dispatcher.calls), 1)

    def test_rejects_model_mismatch_bad_dimension_nonfinite_and_stale_selection(self):
        mismatched = _Dispatcher([json.dumps({
            "object": "chat.completion", "model": "other-model", "choices": [],
        }).encode()])
        engine = self._engine(mismatched)
        with self.assertRaises(PrivateMemoryEngineUnavailable):
            engine.extract(text="private text", context=_context(), timeout=5, cancelled=lambda: False)

        bad_vector = _Dispatcher([json.dumps({
            "object": "list", "model": "embed-fixture-v1", "data": [
                {"object": "embedding", "index": 0, "embedding": [math.inf, 1]},
            ],
        }, allow_nan=True).encode()])
        engine = self._engine(bad_vector)
        with self.assertRaises(PrivateMemoryEngineUnavailable):
            engine.embed(facts=["fact"], context=_context("embed"), timeout=5, cancelled=lambda: False)

        expired = _SelectedRoutes(expires_monotonic=9.0)
        with self.assertRaises(PrivateMemoryEngineUnavailable):
            self._engine(_Dispatcher([]), selected=expired)

        malformed = _Dispatcher([b'{"model":"glm-5.2-fixture","model":"attacker"}'])
        with self.assertRaises(PrivateMemoryEngineUnavailable):
            self._engine(malformed).extract(
                text="private text", context=_context(), timeout=5, cancelled=lambda: False,
            )

    def test_runtime_registry_joins_engine_selection_to_exact_enrollment_or_stays_off(self):
        enrollment = MemoryServiceEnrollment.from_protected_record(enrollment_record())
        target = MemoryTarget.from_enrollment(enrollment)
        target_key = (target.profile_id, target.namespace_id, target.provider)
        routes = replace(
            _SelectedRoutes(), profile_id=target.profile_id, namespace_id=target.namespace_id,
            memory_owner_generation=enrollment.memory_owner_generation,
            service_generation_digest="c" * 64,
            extract_route_id=enrollment.private_extraction_embedding_routes["extract"],
            embed_route_id=enrollment.private_extraction_embedding_routes["embed"],
            expires_monotonic=1e12,
        )
        provider_pkg = types.ModuleType("hermes_installer.providers")
        provider_pkg.__path__ = []
        provider_mod = types.ModuleType("hermes_installer.providers.private_memory")
        provider_mod.RootSelectedPrivateMemoryEngineRoutes = _SelectedRoutes
        with patch.dict(sys.modules, {
            "hermes_installer.providers": provider_pkg,
            "hermes_installer.providers.private_memory": provider_mod,
        }):
            engines, unavailable = _build_private_engine_registry(
                {target_key: target},
                lambda enrollment_id, owner_epoch: (
                    routes, _Dispatcher([])
                ) if (enrollment_id, owner_epoch) == (
                    enrollment.service_enrollment_id, enrollment.memory_owner_generation
                ) else None,
                "c" * 64,
            )
            self.assertEqual(set(engines), {target_key})
            self.assertEqual(unavailable, {})
            denied, reasons = _build_private_engine_registry(
                {target_key: target}, lambda *_: (_ for _ in ()).throw(
                    AuthorityDenied("memory.selection", "no eligible selected route")
                ), "c" * 64,
            )
        self.assertEqual(denied, {})
        self.assertIn("no eligible selected route", reasons[target_key])


if __name__ == "__main__":
    unittest.main()
