from __future__ import annotations

import os
import unittest
from types import SimpleNamespace

from hermes_installer.authority.native_input_observer import (
    RootNativeInputObserver,
    RootNativeInputSelection,
)
from hermes_installer.authority.types import AuthorityDenied


class NativeInputObserverContracts(unittest.TestCase):
    def test_selected_resource_factory_has_no_legacy_worker_selected_resolvers(self):
        registry = SimpleNamespace(capture_observed_ingress=lambda *_a, **_k: None)
        selected = SimpleNamespace(
            select_resource_task=lambda *_a: None,
            resolve_selected_native_input_target=lambda *_a: None,
        )
        observer = RootNativeInputObserver.for_selected_resource_tasks(
            service=SimpleNamespace(), source_observers=registry,
            selected_execution_registry=selected,
            process_resolver=lambda *_a, **_k: None,
            loaded_package_proof_resolver=lambda *_a, **_k: None,
            monotonic=lambda: 10.0,
        )
        self.assertIs(observer.selected_execution_registry, selected)
        self.assertIsNone(observer.task_input_resolver)
        self.assertIsNone(observer.health_input_resolver)
        self.assertIsNone(observer.desktop_input_resolver)
        with self.assertRaises(AuthorityDenied):
            observer.record_admitted_task_input("a" * 32, "node:one", object(), b"input")
        with self.assertRaises(AuthorityDenied):
            observer.record_selected_health_input("h" * 32, object(), "fixture:one")

    def test_private_consent_selection_handle_is_retained_as_opaque_root_selection(self):
        handle = "c" * 43
        selection = RootNativeInputSelection(
            source_path="root-admitted-task", observer_enrollment_id="observer:root",
            payload_bytes=b"private input", parent_context=None, parent_receipt_handles=(),
            peer_pid=700, peer_pidfd=9, peer_uid=2001, peer_identity=object(),
            profile_id="profile:one", generation="generation:one", package_id="package:one",
            compiled_closure_sha256="a" * 64, expires_monotonic=100.0,
            invocation_id="invocation:root-owned", private_consent_selection_handle=handle,
        )
        self.assertEqual(selection.private_consent_selection_handle, handle)
        with self.assertRaises(ValueError):
            RootNativeInputSelection(
                source_path="root-admitted-task", observer_enrollment_id="observer:root",
                payload_bytes=b"private input", parent_context=None, parent_receipt_handles=(),
                peer_pid=700, peer_pidfd=9, peer_uid=2001, peer_identity=object(),
                profile_id="profile:one", generation="generation:one", package_id="package:one",
                 compiled_closure_sha256="a" * 64, expires_monotonic=100.0,
                 invocation_id="invocation:root-owned", private_consent_selection_handle="worker-claim",
             )

    def test_unregistered_native_input_fails_closed_and_closes_transferred_pidfd(self):
        read_fd, write_fd = os.pipe()
        os.close(write_fd)
        selection = RootNativeInputSelection(
            source_path="root-admitted-task", observer_enrollment_id="observer:missing",
            payload_bytes=b"exact admitted bytes", parent_context=None,
            parent_receipt_handles=(), peer_pid=700, peer_pidfd=read_fd,
            peer_uid=2001, peer_identity=object(), profile_id="profile:one",
            generation="generation:one", package_id="package:one",
            compiled_closure_sha256="a" * 64, expires_monotonic=100.0,
            invocation_id="invocation:root-owned",
        )
        registry = SimpleNamespace(observers={}, capture_observed_ingress=lambda *_a, **_k: None)
        observer = RootNativeInputObserver(
            service=SimpleNamespace(), source_observers=registry,
            task_input_resolver=lambda *_args: selection,
            health_input_resolver=lambda *_args: selection,
            desktop_input_resolver=lambda *_args: selection,
            process_resolver=lambda *_a, **_k: None,
            loaded_package_proof_resolver=lambda *_a, **_k: None,
            monotonic=lambda: 10.0,
        )
        try:
            with self.assertRaises(AuthorityDenied):
                observer.record_admitted_task_input(
                    "a" * 32, "node:one", object(), b"exact admitted bytes")
            with self.assertRaises(OSError):
                os.fstat(read_fd)
        finally:
            try:
                os.close(read_fd)
            except OSError:
                pass
