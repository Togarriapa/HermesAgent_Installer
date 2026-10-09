from __future__ import annotations

import os
import unittest
from types import SimpleNamespace

from hermes_installer.authority.native_observer_wiring import (
    RootTaskInputCoordinator, _InitialInputRecord,
)
from hermes_installer.authority.types import AuthorityDenied
from hermes_installer.managed_process_custodian import ManagedTaskHandle
from hermes_installer.registry.resource_jobs import RootTaskInitialInputReceipt


class NativeTaskInputCoordinatorContracts(unittest.TestCase):
    def _coordinator(self):
        identity = object()
        task = ManagedTaskHandle("t" * 43, "process-generation", "process:task")
        read_fd, write_fd = os.pipe()
        os.close(write_fd)
        def resolve_lease(value):
            if value is not task:
                return None
            owned_fd = os.dup(read_fd)
            return SimpleNamespace(
                process_id=task.process_id, profile_id="profile:native",
                generation=task.generation, uid=2001, pid=733,
                expires_monotonic=100.0, pidfd=owned_fd,
                close=lambda: os.close(owned_fd),
            )
        selected = SimpleNamespace(selection_handle="s" * 43)
        receipt = RootTaskInitialInputReceipt(
            schema=1, receipt_handle="r" * 43, task_handle=task.handle_id,
            admission_id="admission:one", node_id="node:one", process_id=task.process_id,
            process_generation=task.generation, selected_execution_handle=selected.selection_handle,
            source_receipt_handle="h" * 43, producer_context_delivery_handle="h" * 43,
            native_loader_ready_event_id="l" * 43, stdin_sha256="a" * 64,
            stdin_size_bytes=5, parent_closure_digest="b" * 64,
            service_generation_digest="c" * 64, resource_generation="resource:one",
            issued_monotonic=1.0, expires_monotonic=90.0,
        )
        input_observer = SimpleNamespace(
            resolve_task_input_receipt=lambda handle: receipt,
            retain_task_input_receipt=lambda value: None,
            record_selected_task_input=lambda **_kw: None,
            discard_task_input_observation=lambda **_kw: None,
        )
        selection_registry = SimpleNamespace(
            resolve_current_execution=lambda value: value,
            select_resource_task=lambda *_a: None,
            resolve_selected_native_input_target=lambda *_a: None,
        )
        custody = SimpleNamespace(
            resolve_managed_task_process_handle=resolve_lease,
            resolve_live_peer=lambda pid, _fd, **_kw: identity if pid == 733 else None,
        )
        delivery = SimpleNamespace(resolve_delivered_source_receipt=lambda handle, **_kw: handle)
        task_native = SimpleNamespace(
            bind_running_task=lambda *_a: None, bind_task_input=lambda **_k: None,
            cancel_running_task=lambda *_a: None, cancel_task_input=lambda **_k: None,
        )
        coordinator = RootTaskInputCoordinator(
            task_native_observation_registry=task_native,
            selected_native_execution_registry=selection_registry,
            initial_native_input_observer=input_observer,
            source_delivery_registry=delivery,
            process_custody_registry=custody,
            monotonic=lambda: 10.0,
        )
        source = SimpleNamespace()
        coordinator._records[receipt.receipt_handle] = _InitialInputRecord(
            receipt=receipt, admission_handle=object(), source=source,
            selected_execution=selected, managed_task_handle=task,
            cancelled=lambda: False, peer_pid=733, peer_uid=2001,
            peer_identity=identity, profile_id="profile:native",
            generation=task.generation,
        )
        return coordinator, receipt, task, read_fd

    def test_custody_consumes_current_peer_bound_receipt_once(self):
        coordinator, receipt, task, read_fd = self._coordinator()
        try:
            current = coordinator.resolve_initial_input_receipt(
                receipt.receipt_handle, task_handle=task,
                stdin_sha256=receipt.stdin_sha256, stdin_size_bytes=receipt.stdin_size_bytes,
            )
            self.assertIs(current, receipt)
            consumed = coordinator.consume_initial_input_receipt(
                receipt.receipt_handle, task_handle=task,
                stdin_sha256=receipt.stdin_sha256, stdin_size_bytes=receipt.stdin_size_bytes,
            )
            self.assertIs(consumed, receipt)
            with self.assertRaises(AuthorityDenied):
                coordinator.consume_initial_input_receipt(
                    receipt.receipt_handle, task_handle=task,
                    stdin_sha256=receipt.stdin_sha256, stdin_size_bytes=receipt.stdin_size_bytes,
                )
        finally:
            try:
                os.close(read_fd)
            except OSError:
                pass

    def test_receipt_rejects_changed_prompt_digest_before_consumption(self):
        coordinator, receipt, task, read_fd = self._coordinator()
        try:
            with self.assertRaises(AuthorityDenied):
                coordinator.consume_initial_input_receipt(
                    receipt.receipt_handle, task_handle=task,
                    stdin_sha256="d" * 64, stdin_size_bytes=receipt.stdin_size_bytes,
                )
        finally:
            try:
                os.close(read_fd)
            except OSError:
                pass

    def test_custody_revoke_invalidates_exact_prepared_receipt(self):
        coordinator, receipt, task, read_fd = self._coordinator()
        try:
            self.assertTrue(coordinator.revoke_initial_input_receipt(
                receipt.receipt_handle, task_handle=task))
            with self.assertRaises(AuthorityDenied):
                coordinator.resolve_initial_input_receipt(
                    receipt.receipt_handle, task_handle=task,
                    stdin_sha256=receipt.stdin_sha256,
                    stdin_size_bytes=receipt.stdin_size_bytes,
                )
            self.assertFalse(coordinator.revoke_initial_input_receipt(
                receipt.receipt_handle, task_handle=task))
        finally:
            try:
                os.close(read_fd)
            except OSError:
                pass
