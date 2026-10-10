"""Finite admission checks for the active native Hermes launch path."""
from __future__ import annotations

import unittest
import threading
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
    _argv_matches_recipe,
)


class NativeWorkerLaunchAdmissionTests(unittest.TestCase):
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
        forged = RootNativeHermesWorkerSelection("network", "profile", "handle", None, object())
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


if __name__ == "__main__":
    unittest.main()
