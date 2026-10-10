"""Production capture-composition seam tests; no worker transcript surface."""
from types import SimpleNamespace
import unittest

from hermes_installer.authority.native_turn_observation import RootNativeTurnObservationRegistry
from hermes_installer.authority.types import AuthorityDenied
from hermes_installer.memory.broker import MemoryTarget
from hermes_installer.memory.capture import (
    MemoryCaptureUnavailable, attach_root_memory_capture_coordinator,
)
from hermes_installer.memory.enrollment import MemoryServiceEnrollment
from test_memory_enrollment import record


class MemoryCaptureCompositionTests(unittest.TestCase):
    def _runtime(self, *, authorized=True):
        service = SimpleNamespace(native_turn_observation_registry=None)
        if authorized:
            service.authorize_completed_memory_turn = lambda *_args, **_kwargs: None
        selected = SimpleNamespace(
            resolve_current_execution=lambda *_args: None,
            resolve_selection_handle=lambda *_args: None,
        )
        input_observer = SimpleNamespace(resolve_event_for_source_handle=lambda *_args: None)
        sources = SimpleNamespace(
            resolve_delivered_source_receipt=lambda *_args: None,
        )
        custody = SimpleNamespace(resolve_managed_task_process_handle=lambda *_args: None)
        registry = RootNativeTurnObservationRegistry(
            service=service, selected_execution_registry=selected,
            input_observer=input_observer, source_observers=sources,
            process_custody=custody, response_resolver=lambda _handle: None,
        )
        service.native_turn_observation_registry = registry
        enrollment = MemoryServiceEnrollment.from_protected_record(record())
        target = MemoryTarget.from_enrollment(enrollment)
        queue = SimpleNamespace(enqueue_completed_turn=lambda **_kwargs: "a" * 43)
        return service, registry, {("profile-one", "namespace-one", "agentmemory"): target}, queue

    def test_root_builder_attaches_one_exact_coordinator_to_native_turn_registry(self):
        service, registry, targets, queue = self._runtime()
        coordinator = attach_root_memory_capture_coordinator(
            service=service, targets=targets, queue=queue,
            owner_state=lambda _profile: ("agentmemory", 4),
            expected_active_generation_digest="a" * 64,
        )
        self.assertIs(registry._memory_capture_coordinator, coordinator)
        self.assertIs(coordinator.service, service)
        self.assertEqual(coordinator.targets["service-agentmemory-one"], next(iter(targets.values())))
        with self.assertRaises(AuthorityDenied):
            registry.attach_memory_capture_coordinator(coordinator)

    def test_missing_root_consent_and_source_authority_fails_before_attachment(self):
        service, registry, targets, queue = self._runtime(authorized=False)
        with self.assertRaises(MemoryCaptureUnavailable):
            attach_root_memory_capture_coordinator(
                service=service, targets=targets, queue=queue,
                owner_state=lambda _profile: ("agentmemory", 4),
                expected_active_generation_digest="a" * 64,
            )
        self.assertIsNone(registry._memory_capture_coordinator)


if __name__ == "__main__":
    unittest.main()
