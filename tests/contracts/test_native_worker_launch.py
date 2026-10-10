"""Finite admission checks for the active native Hermes launch path."""
from __future__ import annotations

import unittest
import threading
import time
from pathlib import Path
from types import SimpleNamespace

from hermes_installer.authority.native_worker_launch import (
    NativeHermesWorkerLaunchUnavailable,
    RootActiveNativeHermesWorkerLaunchOwner,
    RootNativeHermesWorkerSelection,
)
from hermes_installer.authority.native_worker_start_recipe import ARGV_SUFFIX
from hermes_installer.managed_process_custodian import (
    AuthorityDenied,
    ManagedProcessEffectHandler,
    RootSelectedHealthControl,
    _argv_matches_recipe,
)


class NativeWorkerLaunchAdmissionTests(unittest.TestCase):
    @staticmethod
    def _selection_owner():
        runtime = SimpleNamespace()
        runtime.service = SimpleNamespace(root_authority_runtime=runtime)
        runtime.bindings = object()
        runtime.service.root_runtime_bindings = runtime.bindings
        owner = object.__new__(RootActiveNativeHermesWorkerLaunchOwner)
        owner.runtime = runtime
        owner._issuer = object()
        owner._closed = False
        owner._selections = {}
        owner._proofs = {}
        owner._lock = threading.RLock()
        owner._gate_member_fds = None
        projections = []

        def resolve(network_id, profile_id):
            projection = SimpleNamespace(
                network_id=network_id, process_profile_id=profile_id,
                runtime_record={"execution_mode": "native-hermes-cli-module-v1"},
                expires_monotonic=time.monotonic() + 30.0)
            projections.append(projection)
            return projection

        owner.network_owner = SimpleNamespace(
            resolve_selected_worker=resolve,
            verify_current=lambda projection: projection,
            retire_selected_worker_projection=lambda projection: projections.remove(projection)
            if projection in projections else None)
        return owner, projections

    def test_generic_python_child_rule_still_rejects_finite_module_recipe(self) -> None:
        profile = SimpleNamespace(
            argv_recipe=("/opt/hermes/python", "{child_artifact}"),
            executable=Path("/opt/hermes/python"),
        )
        argv = [str(profile.executable), *ARGV_SUFFIX]
        self.assertFalse(_argv_matches_recipe(profile, argv, {}))

    def test_legacy_process_start_cannot_bypass_selected_native_gate(self) -> None:
        manager = object.__new__(ManagedProcessEffectHandler)
        manager._native_worker_profile_id = "native-profile"
        with self.assertRaises(AuthorityDenied) as caught:
            manager._start_reserved(
                SimpleNamespace(profile_id="native-profile"), None, None, b"", 1.0,
                None, None, lambda: False,
            )
        self.assertEqual(caught.exception.code, "native_worker.gate")

    def test_public_owner_constructor_rejects_unjoined_runtime_inputs(self) -> None:
        with self.assertRaises(NativeHermesWorkerLaunchUnavailable):
            RootActiveNativeHermesWorkerLaunchOwner.from_root_runtime(
                object(), object(), object(), object())

    def test_unissued_selection_cannot_be_resolved(self) -> None:
        runtime = SimpleNamespace()
        runtime.service = SimpleNamespace(root_authority_runtime=runtime,
                                          root_runtime_bindings=object())
        runtime.bindings = runtime.service.root_runtime_bindings
        owner = object.__new__(RootActiveNativeHermesWorkerLaunchOwner)
        owner._closed = False
        owner.runtime = runtime
        owner._issuer = object()
        owner._selections = {}
        forged = RootNativeHermesWorkerSelection(
            "network", "profile", "handle", 9999999999.0, None, object())
        with self.assertRaises(NativeHermesWorkerLaunchUnavailable):
            # Exercise issuer validation without constructing any runtime or
            # consulting caller-provided selection fields.
            owner._require_selection(forged)

    def test_manager_retires_native_worker_before_closing_source_custody(self) -> None:
        events = []
        manager = object.__new__(ManagedProcessEffectHandler)
        manager._native_worker_profile_id = "native-profile"
        manager._lock = threading.RLock()
        handle = SimpleNamespace(profile=SimpleNamespace(profile_id="native-profile"), stopped=False)
        manager._handles = {"worker": handle}
        manager._native_worker_launch_owner = SimpleNamespace(close=lambda: events.append("owner"))
        manager._committed_pm_executable_resolver = SimpleNamespace(close=lambda: events.append("resolver"))
        manager._committed_pm_executable_identity = object()
        manager._stop = lambda _handle, timeout: (events.append("stop") or
                                                   SimpleNamespace(cleanup_verified=True))
        manager.close()
        self.assertEqual(events, ["stop", "owner", "resolver"])

    def test_manager_preserves_source_custody_when_worker_stop_is_ambiguous(self) -> None:
        manager = object.__new__(ManagedProcessEffectHandler)
        manager._native_worker_profile_id = "native-profile"
        manager._lock = threading.RLock()
        handle = SimpleNamespace(profile=SimpleNamespace(profile_id="native-profile"), stopped=False)
        manager._handles = {"worker": handle}
        owner = SimpleNamespace(closed=False)
        owner.close = lambda: setattr(owner, "closed", True)
        manager._native_worker_launch_owner = owner
        manager._committed_pm_executable_resolver = None
        manager._committed_pm_executable_identity = None
        manager._stop = lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("ambiguous"))
        with self.assertRaises(AuthorityDenied) as caught:
            manager.close()
        self.assertEqual(caught.exception.code, "native_worker.cleanup")
        self.assertFalse(owner.closed)

    def test_completed_selections_retire_network_entries_for_unbounded_sequential_starts(self) -> None:
        owner, projections = self._selection_owner()
        for _ in range(9):
            selection = owner.select_worker("network", "profile")
            owner.release_selection(selection)
        self.assertEqual(owner._selections, {})
        self.assertEqual(projections, [])

    def test_live_selection_capacity_remains_bounded_until_lifecycle_release(self) -> None:
        owner, projections = self._selection_owner()
        selections = [owner.select_worker("network", "profile") for _ in range(4)]
        with self.assertRaises(NativeHermesWorkerLaunchUnavailable):
            owner.select_worker("network", "profile")
        for selection in selections:
            owner.release_selection(selection)
        self.assertEqual(projections, [])

    def test_health_loader_event_requires_current_retained_control(self) -> None:
        manager = object.__new__(ManagedProcessEffectHandler)
        manager._lock = threading.RLock()
        manager._health_controls = {}
        manager._health_control_current = lambda _control, _seal: True
        seal = object()
        control = RootSelectedHealthControl(
            1, "health-control-1234567890123456", "process-handle-1234567890123456",
            "process-id", "hermes-agent-health-v1", "enrollment", "profile", "generation",
            "a" * 64, "transaction", "committed-receipt", "health-fixture", "b" * 64,
            1.0, 30.0, manager, seal,
        )
        manager._health_controls[control.control_handle] = (
            control, SimpleNamespace(stopped=False, native_loader_ready_event_id="ready-event-1234567890"),
            object(), seal)
        self.assertEqual(
            manager.resolve_selected_health_loader_ready_event(control.control_handle),
            "ready-event-1234567890")

    def test_health_loader_event_denies_missing_or_foreign_control(self) -> None:
        manager = object.__new__(ManagedProcessEffectHandler)
        manager._lock = threading.RLock()
        manager._health_controls = {}
        manager._health_control_current = lambda _control, _seal: True
        with self.assertRaises(AuthorityDenied):
            manager.resolve_selected_health_loader_ready_event("missing-control-123456")

    def test_fixed_health_start_rejects_unbound_or_caller_supplied_authority(self) -> None:
        manager = object.__new__(ManagedProcessEffectHandler)
        manager.native_health_start_authority = object()
        with self.assertRaises(AuthorityDenied):
            manager.start_selected_native_health("admission-handle-1234567890123456")


if __name__ == "__main__":
    unittest.main()
