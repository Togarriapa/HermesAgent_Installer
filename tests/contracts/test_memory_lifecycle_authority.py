"""Selected memory lifecycle bindings remain finite and profile joined (SK-T01)."""
from types import SimpleNamespace
import unittest

from hermes_installer.memory.enrollment import MemoryServiceEnrollment
from hermes_installer.memory.lifecycle_authority import (
    MemoryLifecycleDenied, MemorySelectedLifecycleActionBinding,
)
from test_memory_enrollment import record


def enrolled_agentmemory():
    value = record()
    value["lifecycle_binding"] = {
        "service_enrollment_id": value["service_enrollment_id"],
        "service_generation": value["service_generation"],
        "enablement_selection_handle": "memory-choice-one",
        "start_operation_id": "memory-agentmemory-serve-v1",
        "start_parameter_schema_id": "no-caller-parameters-v1",
        "prestart_receipt_handles": ["package-receipt", "engine-receipt"],
        "readiness_route_id": "agentmemory-ready",
        "readiness_schema_id": "agentmemory-livez-result-v1",
        "restart_policy": "bounded-owned-restart",
        "maximum_restart_attempts": 1,
        "original_deadline_seconds": 60,
    }
    return MemoryServiceEnrollment.from_protected_record(value)


class FakeCatalog:
    def resolve(self, enrollment_id, generation):
        return SimpleNamespace(profile_id="profile-one", principal_id="principal-one",
                               generation="service-gen-7", namespace_identity="namespace-one",
                               service_uid=12001, service_gid=12001)

    def resolve_operation(self, enrollment_id, generation, operation):
        return SimpleNamespace(enrollment_id="service-agentmemory-one",
                               profile_id="profile-one", principal_id="principal-one",
                               generation="service-gen-7", service_uid=12001, service_gid=12001,
                               namespace_identity="namespace-one", target_id=f"target:{operation}")

    def resolve_launch_recipe(self, enrollment_id, generation, operation_id):
        return SimpleNamespace(operation_id=operation_id,
                               process_start_target="target:process.start",
                               executable_sha256="a" * 64,
                               recipe=SimpleNamespace(argv_recipe=(), cwd_root_id="home", cwd_subpath=""))


class MemoryLifecycleBindingTests(unittest.TestCase):
    def test_start_payload_and_source_binding_are_exact_and_canonical(self):
        enrollment = enrolled_agentmemory()
        binding = MemorySelectedLifecycleActionBinding.resolve(
            enrollment, FakeCatalog(), action="start", source_closure_sha256="b" * 64,
            source_receipt_handles=("receipt-one", "receipt-two"),
        )
        self.assertEqual(binding.role, "memory-agentmemory")
        self.assertEqual(binding.operation, "process.start")
        self.assertEqual(binding.capability, "hermes-profile-invoke")
        self.assertEqual(binding.payload(), (
            b'{"enrollment_id":"service-agentmemory-one","generation":"service-gen-7",'
            b'"operation_id":"memory-agentmemory-serve-v1","parameters":{},"schema":1}'
        ))
        self.assertEqual(binding.source_closure_sha256, "b" * 64)
        self.assertEqual(binding.source_receipt_handles, ("receipt-one", "receipt-two"))

    def test_controls_require_root_retained_process_handle_and_use_fixed_operations(self):
        enrollment = enrolled_agentmemory()
        status = MemorySelectedLifecycleActionBinding.resolve(
            enrollment, FakeCatalog(), action="status", source_closure_sha256="c" * 64,
            source_receipt_handles=("receipt-one",),
        )
        self.assertEqual(status.operation, "process.status")
        self.assertEqual(status.capability, "hermes-process-control")
        with self.assertRaises(MemoryLifecycleDenied):
            status.payload()
        bound = status.with_retained_process("root-process-handle")
        self.assertEqual(bound.payload(), b'{"generation":"service-gen-7","process_id":"root-process-handle","schema":1}')
        stop = MemorySelectedLifecycleActionBinding.resolve(
            enrollment, FakeCatalog(), action="stop", source_closure_sha256="c" * 64,
            source_receipt_handles=("receipt-one",),
        ).with_retained_process("root-process-handle")
        with self.assertRaises(MemoryLifecycleDenied):
            stop.payload()
        self.assertEqual(stop.with_stop_reason("shutdown").payload(),
            b'{"generation":"service-gen-7","grace_seconds":5,"process_id":"root-process-handle","reason":"shutdown","schema":1}')
        with self.assertRaises(MemoryLifecycleDenied):
            stop.with_stop_reason("worker-selected")

    def test_catalog_mismatch_and_missing_lifecycle_fail_before_process_resolution(self):
        enrollment = enrolled_agentmemory()

        class Mismatched(FakeCatalog):
            def resolve(self, enrollment_id, generation):
                return SimpleNamespace(profile_id="other", principal_id="principal-one",
                                       generation=generation, namespace_identity="namespace-one",
                                       service_uid=12001, service_gid=12001)

        with self.assertRaises(MemoryLifecycleDenied):
            MemorySelectedLifecycleActionBinding.resolve(
                enrollment, Mismatched(), action="start", source_closure_sha256="d" * 64,
                source_receipt_handles=("receipt-one",),
            )

        unavailable = MemoryServiceEnrollment.from_protected_record(record())
        with self.assertRaises(MemoryLifecycleDenied):
            MemorySelectedLifecycleActionBinding.resolve(
                unavailable, FakeCatalog(), action="start", source_closure_sha256="d" * 64,
                source_receipt_handles=("receipt-one",),
            )


if __name__ == "__main__":
    unittest.main()
