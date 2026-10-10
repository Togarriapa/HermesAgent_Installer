from __future__ import annotations

import hashlib
import os
import threading
import types
import unittest
from unittest.mock import patch

from hermes_installer.authority.channel_peer_delivery import (
    ChannelEventDelivery, ChannelRuntimeBinding, RootChannelPeerDeliveryRegistry,
)
from hermes_installer.authority.native_custody_proof import LoadedPackageClosureProof
from hermes_installer.authority.resource_source_controllers import (
    RootResourceControllerRegistry, RootResourceEventHandle,
)
from hermes_installer.authority.runtime_bindings import RootRuntimeBindings
from hermes_installer.authority.service import AuthorityService
from hermes_installer.authority.source_observers import SourceObserverEnrollment
from hermes_installer.managed_process_custodian import LoadedNativePackageProof


class ChannelPeerDeliveryTests(unittest.TestCase):
    def test_wire_types_reject_unknown_fields_and_payload_digest_changes(self):
        binding = ChannelRuntimeBinding(
            1, "A" * 43, "delivery-1", "profile-1", "profile-gen-1",
            "package-1", "profile-gen-1", "a" * 64, 40.0,
        )
        self.assertEqual(ChannelRuntimeBinding.from_wire(binding.to_wire()), binding)
        with self.assertRaises(Exception):
            ChannelRuntimeBinding.from_wire({**binding.to_wire(), "caller_pid": 44})

        payload = b'{"message":"hello"}'
        wire = {
            "schema": 1, "delivery_handle": "B" * 43,
            "binding_handle": "A" * 43, "channel_ingress_id": "ingress-1",
            "event_handle": "C" * 43,
            "normalized_payload_b64": __import__("base64").b64encode(payload).decode("ascii"),
            "payload_sha256": hashlib.sha256(payload).hexdigest(),
            "source_receipt_handle": "D" * 43,
            "producer_context_delivery_handle": "E" * 43,
            "sequence": 1, "expires_monotonic": 35.0,
        }
        self.assertEqual(ChannelEventDelivery.from_wire(wire).normalized_payload, payload)
        with self.assertRaises(Exception):
            ChannelEventDelivery.from_wire({**wire, "payload_sha256": "0" * 64})

    def test_bind_and_take_derive_current_peer_and_deliver_once(self):
        uid, pid = 501, 4242
        pidfd, writer = os.pipe()
        os.close(writer)
        now = [10.0]
        service = types.SimpleNamespace(
            authority_epoch="epoch-1", service_generation_digest="f" * 64,
            monotonic=lambda: now[0],
        )
        identity = types.SimpleNamespace(
            kernel_uid=uid, profile_id="profile-1", generation="profile-gen-1",
            namespace_identity="mnt:21;net:22", start_ticks=100,
            cgroup_identity="/profile/one", executable_sha256="e" * 64,
        )
        mount = types.SimpleNamespace(package_id="package-1")
        mounted = LoadedNativePackageProof(
            "process-1", "profile-1", "profile-gen-1", uid, 100,
            "/profile/one", "mnt:21;net:22", "e" * 64, mount, 9.0,
        )
        manager = types.SimpleNamespace(
            resolve_native_package_for_peer=lambda _pid, _fd: mounted,
            resolve_live_peer=lambda _pid, _fd, **_kwargs: identity,
        )
        observer = SourceObserverEnrollment(
            observer_enrollment_id="observer-1", source_kind="native-input",
            origin_id="telegram-message", profile_id="profile-1", principal_id="principal-1",
            namespace_id="namespace-1", enrollment_id="enrollment-1",
            generation="profile-gen-1", producer_uid=uid,
            producer_executable_sha256="e" * 64, package_id="package-1",
            package_sha256="f" * 64, role_id="role-1", role_artifact_id="role-artifact-1",
            role_sha256="a" * 64, source_action_id="receive-message",
            target_id="selected-channel", recipient="selected-user",
            allowed_parent_source_kinds=frozenset({"native-input"}),
            channel_id="ingress-1", capture_schema_id="channel-message-v1",
        )
        delivery_row = {
            "id": "delivery-1", "profile_id": "profile-1",
            "process_generation": "profile-gen-1", "native_package_id": "package-1",
            "native_package_generation": "profile-gen-1", "authority_endpoint_id": "authority-1",
            "allowed_channel_ingress_ids": ("ingress-1",),
            "source_observer_enrollment_ids": ("observer-1",), "generation": "binding-gen-1",
        }
        # These exact resolver methods are replaced with protected-fixture readers;
        # the registry still exercises real DTO validation, proof joins and queue state.
        bindings = RootRuntimeBindings(
            enrollment_catalog=object(), build_catalog=object(), device_catalog=object(),
            process_manager=manager, effect_handlers={}, native_bridges={},
            artifact_catalog=object(), build_store=object(), service_connector=object(),
            source_observer_enrollments={"observer-1": observer},
            channel_delivery_binding_records=(delivery_row,),
        )
        registry = object.__new__(RootResourceControllerRegistry)
        registry.service = service
        registry._lock = threading.RLock()
        registry._events = {}
        event_payload = b'{"message":"fixture inbound"}'
        event = RootResourceEventHandle(
            "E" * 43, "F" * 43, "resource-1", "resource-gen-1", "native-input",
            "observer-1", ("receipt-1",), "b" * 64,
            hashlib.sha256(event_payload).hexdigest(), 9.0, 50.0, "epoch-1",
        )
        record = types.SimpleNamespace(
            handle=event, payload=event_payload,
            parent_context=types.SimpleNamespace(profile_id="profile-1"),
        )
        registry._events[event.handle] = record
        source_observers = types.SimpleNamespace(observers={"observer-1": observer})
        loader = object.__new__(__import__(
            "hermes_installer.authority.native_custody_proof",
            fromlist=["RootNativeLoaderObservationStore"],
        ).RootNativeLoaderObservationStore)
        loaded = LoadedPackageClosureProof(
            1, "proof-1", "package-1", "profile-1", "profile-gen-1", "c" * 64,
            "d" * 64, "e" * 64, 21, "mount-1", "f" * 64, ("ro",), 1, 2,
            identity, "loader-role", "a" * 64, "ready-event", ("receive-message",),
            8.0, 45.0, "f" * 64,
        )
        loader.resolve_loaded_package_closure = lambda *_args: loaded
        with patch("hermes_installer.authority.channel_peer_delivery._pidfd_matches",
                   return_value=True), \
             patch.object(RootRuntimeBindings, "resolve_channel_delivery_binding",
                          lambda self, *_args: delivery_row), \
             patch.object(RootRuntimeBindings, "resolve_native_package",
                          lambda self, *_args: types.SimpleNamespace()):
            peer_registry = RootChannelPeerDeliveryRegistry(
                service=service, runtime_bindings=bindings,
                resource_controller_registry=registry, source_observers=source_observers,
                loader_observations=loader, monotonic=lambda: now[0],
            )
            try:
                channel_binding = peer_registry.bind(peer_uid=uid, peer_pid=pid, peer_pidfd=pidfd)
                self.assertEqual(channel_binding.profile_id, "profile-1")
                self.assertEqual(peer_registry.publish_captured_event(
                    channel_ingress_id="ingress-1", event_handle=event), 1)
                delivery = peer_registry.take(
                    peer_uid=uid, peer_pid=pid, peer_pidfd=pidfd,
                    binding_handle=channel_binding.binding_handle,
                )
                self.assertEqual(delivery.normalized_payload, event_payload)
                self.assertIsNone(peer_registry.take(
                    peer_uid=uid, peer_pid=pid, peer_pidfd=pidfd,
                    binding_handle=channel_binding.binding_handle,
                ))
            finally:
                peer_registry.close()
                os.close(pidfd)

    def test_take_rejects_wrong_peer_or_unselected_channel(self):
        registry = object.__new__(RootChannelPeerDeliveryRegistry)
        registry._lock = threading.RLock()
        registry._peers = {}
        registry._event_bytes = 0
        registry._closed = False
        with self.assertRaises(Exception):
            registry.take(peer_uid=1, peer_pid=2, peer_pidfd=3, binding_handle="G" * 43)

    def test_authority_dispatch_accepts_only_fixed_bind_and_single_take_shapes(self):
        binding = ChannelRuntimeBinding(
            1, "A" * 43, "delivery-1", "profile-1", "profile-gen-1",
            "package-1", "profile-gen-1", "f" * 64, 40.0,
        )
        class Registry:
            def bind(self, **kwargs):
                assert kwargs == {"peer_uid": 501, "peer_pid": 42, "peer_pidfd": 9}
                return binding
            def take(self, **kwargs):
                assert kwargs == {"peer_uid": 501, "peer_pid": 42, "peer_pidfd": 9,
                                  "binding_handle": "A" * 43}
                return None

        service = object.__new__(AuthorityService)
        service.channel_peer_delivery_registry = Registry()
        self.assertEqual(service._dispatch(
            501, 42, 9, "channel.runtime.bind", {"schema": 1}, cancelled=lambda: False,
        ), binding.to_wire())
        self.assertIsNone(service._dispatch(
            501, 42, 9, "channel.event.take",
            {"schema": 1, "binding_handle": "A" * 43, "max_events": 1},
            cancelled=lambda: False,
        ))
        for operation, payload in (
            ("channel.runtime.bind", {"schema": 1, "profile_id": "caller-choice"}),
            ("channel.event.take", {"schema": 1, "binding_handle": "A" * 43,
                                     "max_events": 64}),
        ):
            with self.assertRaises(Exception):
                service._dispatch(501, 42, 9, operation, payload, cancelled=lambda: False)


if __name__ == "__main__":
    unittest.main()
