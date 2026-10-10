from __future__ import annotations

import hashlib
import threading
import unittest
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import patch

from hermes_installer.authority.native_turn_observation import (
    RootNativeTurnObservationRegistry,
    RootProviderResponseObservation,
    RootTurnTranscriptEvent,
    _Turn,
    build_root_turn_transcript,
)
from hermes_installer.authority.types import AuthorityDenied
from hermes_installer.authority.types import canonical_digest
from hermes_installer.authority.types import RootCompletedNativeTurnPresentation


def _handle(char: str) -> str:
    return char * 43


def _response(*, source_handles: tuple[str, ...], pending=()) -> RootProviderResponseObservation:
    body = b'{"choices":[{"message":{"content":"answer"}}]}'
    return RootProviderResponseObservation(
        response_observation_handle=_handle("o"),
        final_response_delivery_handle=None,
        native_request_handle=_handle("q"),
        source_receipt_handles=(*source_handles, _handle("r")),
        response_receipt_handle=_handle("r"),
        response_bytes=body,
        response_sha256=hashlib.sha256(body).hexdigest(),
        producer_identity="selected-process-identity",
        producer_pid=733,
        producer_pidfd=9,
        profile_id="profile:one",
        process_generation="generation:one",
        native_package_generation="package-generation:one",
        observer_enrollment_id="observer:provider-result",
        service_generation_digest="a" * 64,
        expires_monotonic=70.0,
        complete=True,
        pending_tool_call_handles=tuple(pending),
        response_status=200,
        response_headers={"content-type": "application/json"},
        request_context=object(),
        authorization=object(),
        target="private-provider",
        recipient="selected-model",
            request_sha256="b" * 64,
        retry_index=0,
        gateway_identity="selected-gateway-identity",
        gateway_pid=734,
        gateway_pidfd=10,
        loaded_package_proof=object(),
    )


class NativeTurnObservationContracts(unittest.TestCase):
    def test_root_transcript_is_canonical_ordered_event_serialization(self):
        events = (
            RootTurnTranscriptEvent("input", _handle("i"), "task-input", b"user bytes"),
            RootTurnTranscriptEvent("request", _handle("q"), "native-request", b'{"model":"x"}'),
        )
        payload = build_root_turn_transcript(events)
        decoded = __import__("json").loads(payload)
        self.assertEqual(decoded["schema"], 1)
        self.assertEqual(decoded["format"], "root-observed-turn-events-v1")
        self.assertEqual([row["sequence"] for row in decoded["events"]], [0, 1])
        self.assertEqual(decoded["events"][0]["payload_b64"], "dXNlciBieXRlcw==")
        self.assertEqual(decoded["events"][1]["payload_sha256"], hashlib.sha256(b'{"model":"x"}').hexdigest())
        with self.assertRaises(AuthorityDenied):
            build_root_turn_transcript((RootTurnTranscriptEvent(
                "worker-claim", _handle("w"), "task-input", b"user bytes"),))

    def test_registry_defaults_to_fixed_root_transcript_builder(self):
        source = SimpleNamespace(resolve_delivered_source_receipt=lambda *_a, **_k: None)
        input_observer = SimpleNamespace(resolve_event_for_source_handle=lambda *_a, **_k: None)
        custody = SimpleNamespace(resolve_managed_task_process_handle=lambda *_a: None)
        selected = SimpleNamespace(
            resolve_current_execution=lambda *_a: None,
            resolve_selection_handle=lambda *_a: None,
        )
        registry = RootNativeTurnObservationRegistry(
            service=object(), selected_execution_registry=selected,
            input_observer=input_observer, source_observers=source,
            process_custody=custody, response_resolver=lambda _handle: None,
        )
        self.assertIs(registry.transcript_builder, build_root_turn_transcript)

    def _registry(self, response, *, pending=()):
        registry = object.__new__(RootNativeTurnObservationRegistry)
        registry.monotonic = lambda: 10.0
        registry._turns = {}
        registry._by_source = {
            _handle("i"): {_handle("t")}, _handle("s"): {_handle("t")},
        }
        registry._begun_inputs = {_handle("i"): 80.0}
        registry._completed = {}
        registry._used_final_responses = {}
        registry._lock = threading.RLock()
        registry._closed = False
        registry.response_resolver = lambda handle: response
        registry.source_observers = SimpleNamespace(
            _lock=threading.RLock(), _payload_capsules={},
        )
        parent_receipts = []
        for char, receipt_id in (("i", "receipt:input"), ("s", "receipt:request")):
            receipt = SimpleNamespace(
                receipt_id=receipt_id, source_kind="task-input" if char == "i" else "provider-request",
                profile_id="profile:one", process_generation="generation:one",
                monotonic_expires_at=70.0, parent_receipt_ids=(),
                payload_digest="c" * 64,
            )
            parent_receipts.append(receipt)
            registry.source_observers._payload_capsules[_handle(char)] = (
                receipt, None, bytearray(b"parent"), "epoch")
        response_receipt = SimpleNamespace(
            receipt_id="receipt:response", source_kind="provider-result",
            profile_id="profile:one", process_generation="generation:one",
            monotonic_expires_at=70.0,
            parent_receipt_ids=tuple(item.receipt_id for item in parent_receipts),
            payload_digest=response.response_sha256,
        )
        registry.source_observers._payload_capsules[_handle("r")] = (
            response_receipt, None, bytearray(response.response_bytes), "epoch")
        registry._turns[_handle("t")] = _Turn(
            handle=_handle("t"), selected=object(), input_receipt_handle=_handle("i"),
            input_event=object(), peer_identity="selected-process-identity",
            peer_pid=733, peer_uid=2001, profile_id="profile:one",
            generation="generation:one", package_generation="package-generation:one",
            service_generation_digest="a" * 64, parent_closure_digest="c" * 64,
            expires_monotonic=80.0, request_handles=[_handle("q")],
            request_sha256_by_handle={_handle("q"): "b" * 64},
            request_retry_index_by_handle={_handle("q"): 0},
            pending_tool_handles=set(pending),
        )
        return registry

    def test_only_root_minted_final_handle_for_terminal_complete_response(self):
        response = _response(source_handles=(_handle("i"), _handle("s")))
        registry = self._registry(response)
        final_handle = registry.register_brokered_response(_handle("t"), _handle("o"))
        self.assertIsInstance(final_handle, str)
        self.assertGreaterEqual(len(final_handle), 32)
        self.assertNotEqual(final_handle, response.response_observation_handle)
        self.assertEqual(registry._turns[_handle("t")].final_response_observation_handle, _handle("o"))

    def test_pending_tool_result_never_gets_final_delivery_handle(self):
        call = _handle("c")
        response = _response(source_handles=(_handle("i"), _handle("s")), pending=(call,))
        registry = self._registry(response, pending=(call,))
        self.assertIsNone(registry.register_brokered_response(_handle("t"), _handle("o")))
        self.assertIsNone(registry._turns[_handle("t")].final_response_handle)

    def test_provider_cannot_supply_its_own_final_delivery_handle(self):
        response = _response(source_handles=(_handle("i"), _handle("s")))
        with self.assertRaises(ValueError):
            replace(response, final_response_delivery_handle=_handle("f"))

    def test_authority_service_dispatches_only_the_typed_root_finish_presentation(self):
        from hermes_installer.authority.service import AuthorityService

        service = object.__new__(AuthorityService)
        service.monotonic = lambda: 10.0
        service.native_turn_observation_registry = None
        registry = object.__new__(RootNativeTurnObservationRegistry)
        registry.service = service
        presentation = RootCompletedNativeTurnPresentation(
            schema=1, receipt_handle=_handle("p"), turn_handle=_handle("t"),
            state="completed", expires_monotonic=70.0,
        )
        calls = []
        registry.finish_selected_native_turn = lambda *args: (calls.append(args) or presentation)
        service.attach_native_turn_observation_registry(registry)
        payload = {
            "schema": 1, "turn_handle": _handle("t"),
            "final_response_delivery_handle": _handle("f"),
        }
        result = service._dispatch_native_turn_finish(
            2001, 733, 901, payload, cancelled=lambda: False,
        )
        self.assertEqual(result["receipt_handle"], _handle("p"))
        self.assertEqual(calls, [(2001, 733, 901, _handle("t"), _handle("f"))])
        with self.assertRaises(AuthorityDenied):
            service._dispatch_native_turn_finish(
                2001, 733, 901, {**payload, "worker_claim": "completed"},
                cancelled=lambda: False,
            )

    def test_foreign_response_cannot_attach_to_turn(self):
        response = replace(_response(source_handles=(_handle("i"), _handle("s"))),
                           profile_id="profile:other")
        registry = self._registry(response)
        with self.assertRaises(AuthorityDenied):
            registry.register_brokered_response(_handle("t"), _handle("o"))

    def test_tool_result_must_be_directly_root_parented_to_observed_response(self):
        response_receipt = SimpleNamespace(
            profile_id="profile:one", process_generation="generation:one",
            monotonic_expires_at=70.0, receipt_id="receipt:response",
        )
        registry = self._registry(_response(source_handles=(_handle("i"), _handle("s"))),
                                  pending=(_handle("c"),))
        registry._turns[_handle("t")].pending_tool_parent_receipt_ids[_handle("c")] = response_receipt.receipt_id
        tool_receipt = SimpleNamespace(
            profile_id="profile:one", process_generation="generation:one",
            monotonic_expires_at=70.0, parent_receipt_ids=("receipt:unrelated",),
        )
        registry.source_observers._payload_capsules[_handle("x")] = (tool_receipt, None, bytearray(b"x"), "epoch")
        with self.assertRaises(AuthorityDenied):
            registry.record_tool_result(
                _handle("t"), _handle("x"), live_producer_identity="selected-process-identity",
                observed_call_handle=_handle("c"),
            )
        tool_receipt.parent_receipt_ids = (response_receipt.receipt_id,)
        registry.source_observers._payload_capsules[_handle("x")] = (tool_receipt, None, bytearray(b"x"), "epoch")
        registry.record_tool_result(
            _handle("t"), _handle("x"), live_producer_identity="selected-process-identity",
            observed_call_handle=_handle("c"),
        )
        self.assertEqual(registry._turns[_handle("t")].tool_result_receipts, [_handle("x")])
        self.assertNotIn(_handle("c"), registry._turns[_handle("t")].pending_tool_handles)

    def test_native_request_requires_exact_root_retained_parent_digest_and_retry(self):
        response = _response(source_handles=(_handle("i"), _handle("s")))
        registry = self._registry(response)
        identity = SimpleNamespace(
            profile_id="profile:one", generation="generation:one", kernel_uid=2001,
            start_ticks=77, executable_sha256="d" * 64,
            cgroup_identity="cg:selected", namespace_identity="ns:selected",
        )
        registry._turns[_handle("t")].peer_identity = identity
        source_receipt = SimpleNamespace(
            receipt_id="receipt:input", profile_id="profile:one",
            process_generation="generation:one", monotonic_expires_at=70.0,
            parent_receipt_ids=(),
        )
        request_body = b'{"model":"selected","messages":[]}'
        request_observation = SimpleNamespace(
            schema=1, receipt_handle=_handle("n"), native_request_handle=_handle("z"),
            bridge_id="bridge:selected", producer_profile_id="profile:one",
            producer_process_generation="generation:one",
            native_package_generation="package-generation:one",
            producer_process_identity=canonical_digest({
                "profile_id": identity.profile_id, "generation": identity.generation,
                "kernel_uid": identity.kernel_uid, "start_ticks": identity.start_ticks,
                "executable_sha256": identity.executable_sha256,
                "cgroup_identity": identity.cgroup_identity,
                "namespace_identity": identity.namespace_identity,
            }),
            request_sha256=hashlib.sha256(request_body).hexdigest(),
            request_size_bytes=len(request_body), retry_index=2,
            parent_source_receipt_handles=(_handle("i"),),
            parent_closure_digest=canonical_digest([source_receipt.receipt_id]),
            context_digest="e" * 64, issued_monotonic=1.0, expires_monotonic=70.0,
        )
        registry.source_observers._payload_capsules[_handle("i")] = (
            source_receipt, None, bytearray(b"input"), "epoch")
        registry.service = SimpleNamespace(_source_receipt_handles={_handle("i"): source_receipt})
        registry.native_bridge_broker = SimpleNamespace(
            resolve_native_request_observation=lambda handle, *, turn_handle: request_observation,
            request_bytes=lambda handle, producer_identity: request_body,
        )
        registry._turns[_handle("t")].expires_monotonic = 80.0
        registry._turns[_handle("t")].service_generation_digest = "a" * 64
        from hermes_installer.authority import native_bridge
        with patch.object(native_bridge, "RootNativeRequestObservation", type(request_observation), create=True):
            with self.assertRaises(AuthorityDenied):
                registry.register_native_request(
                    _handle("t"), _handle("z"), _handle("n"), (_handle("i"),),
                    identity, "f" * 64, 0,
                )
            self.assertNotIn(_handle("z"), registry._turns[_handle("t")].request_handles)
            registry.register_native_request(
                _handle("t"), _handle("z"), _handle("n"), (_handle("i"),),
                identity, hashlib.sha256(request_body).hexdigest(), 2,
            )
        self.assertEqual(registry._turns[_handle("t")].request_retry_index_by_handle[_handle("z")], 2)
        self.assertEqual(registry._turns[_handle("t")].request_observations[_handle("z")][1], request_body)

    def test_request_broker_attachment_is_typed_same_service_and_one_time(self):
        from hermes_installer.authority.native_bridge import NativeBridgeBroker

        service = object()
        registry = object.__new__(RootNativeTurnObservationRegistry)
        registry.service = service
        registry.native_bridge_broker = None
        registry._lock = threading.RLock()
        broker = object.__new__(NativeBridgeBroker)
        broker.service = service
        broker.resolve_native_request_observation = lambda *_args, **_kwargs: None
        broker.request_bytes = lambda *_args: b""
        registry.attach_native_request_broker(broker)
        self.assertIs(registry.native_bridge_broker, broker)
        with self.assertRaises(AuthorityDenied):
            registry.attach_native_request_broker(broker)

        wrong_service = object.__new__(NativeBridgeBroker)
        wrong_service.service = object()
        wrong_service.resolve_native_request_observation = broker.resolve_native_request_observation
        wrong_service.request_bytes = broker.request_bytes
        other = object.__new__(RootNativeTurnObservationRegistry)
        other.service = service
        other.native_bridge_broker = None
        other._lock = threading.RLock()
        with self.assertRaises(AuthorityDenied):
            other.attach_native_request_broker(wrong_service)

    def test_close_zeroizes_completed_transcript_and_denies_new_turns(self):
        registry = object.__new__(RootNativeTurnObservationRegistry)
        registry._lock = threading.RLock()
        registry._closed = False
        registry._turns = {_handle("t"): object()}
        registry._by_source = {_handle("i"): {_handle("t")}}
        registry._begun_inputs = {_handle("i"): 50.0}
        registry._used_final_responses = {_handle("f"): 50.0}
        registry._persisting_completed = set()
        payload = bytearray(b"private captured transcript")
        registry._completed = {_handle("p"): (object(), payload)}
        registry.close()
        self.assertTrue(registry._closed)
        self.assertEqual(bytes(payload), b"\0" * len(payload))
        self.assertFalse(registry._completed)
        self.assertFalse(registry._turns)
        self.assertFalse(registry._by_source)
        with self.assertRaises(AuthorityDenied):
            registry.begin_selected_turn(_handle("s"), _handle("i"))

    def test_close_refuses_while_durable_capture_is_in_progress(self):
        registry = object.__new__(RootNativeTurnObservationRegistry)
        registry._lock = threading.RLock()
        registry._closed = False
        registry._persisting_completed = {_handle("p")}
        with self.assertRaises(AuthorityDenied):
            registry.close()
        self.assertFalse(registry._closed)


if __name__ == "__main__":
    unittest.main()
