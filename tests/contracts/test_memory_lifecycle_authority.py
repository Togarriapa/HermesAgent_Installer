"""Selected memory lifecycle bindings remain finite and profile joined (SK-T01)."""
from types import SimpleNamespace
import os
import sys
import time
import unittest

from hermes_installer.memory.enrollment import MemoryServiceEnrollment
from hermes_installer.memory.lifecycle_authority import (
    MemoryLifecycleDenied, MemorySelectedLifecycleActionBinding,
    RootMemoryServiceLifecycle, RootVerifiedMemoryLifecycleAdmission,
)
from test_memory_enrollment import record


def enrolled_agentmemory():
    value = record()
    value["lifecycle_binding"] = {
        "service_enrollment_id": value["service_enrollment_id"],
        "service_generation": value["service_generation"],
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
        return SimpleNamespace(operation=operation, enrollment_id="service-agentmemory-one",
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

    @unittest.skipUnless(sys.platform.startswith("linux") and os.geteuid() == 0,
                         "requires controlled Linux root PIDFD fixture")
    def test_effect_passes_sealed_lifecycle_and_controller_separately_from_short_grant(self):
        from hermes_installer.authority.selected_startup_authority import (
            RootControllerProcessIdentityLease,
        )
        from test_selected_startup_authority import _current_identity

        enrollment = enrolled_agentmemory()
        bindings = {
            action: MemorySelectedLifecycleActionBinding.resolve(
                enrollment, FakeCatalog(), action=action,
                source_closure_sha256="e" * 64,
                source_receipt_handles=("receipt-one", "receipt-two"),
            ) for action in ("start", "status", "stop")
        }
        controller_identity = _current_identity(os.getpid())
        controller = RootControllerProcessIdentityLease(
            proof_handle="a" * 43, startup_authorization_handle="b" * 43,
            pid=os.getpid(), uid=0, start_ticks=controller_identity["start_ticks"],
            pidfd=os.pidfd_open(os.getpid(), 0),
            cgroup_identity=controller_identity["cgroup_identity"],
            mount_namespace_inode=controller_identity["mount_namespace_inode"],
            network_namespace_inode=controller_identity["network_namespace_inode"],
            proof_sha256="f" * 64, expires_monotonic=time.monotonic() + 30,
            _current_check=lambda: True,
        )
        now = time.monotonic()
        admission = RootVerifiedMemoryLifecycleAdmission._from_root_registry(
            service_generation_digest="a" * 64, enrollment=enrollment,
            consent_id="lifecycle-consent", consent_revision=enrollment.background_consent_revision,
            source_closure_sha256="e" * 64,
            source_receipt_handles=("receipt-one", "receipt-two"),
            sensitivity="PRIVATE", issued_monotonic=now,
            expires_monotonic=now + 20, original_deadline=now + 90,
            action_bindings=bindings, controller_lease=controller,
            consent_record=object(), source_closure=object(), current_check=lambda _admission: True,
        )
        captured = {}

        class Authority:
            def issue_root_selected_service_effect(self, *_args):
                return object()

            def consume_root_selected_service_effect(self, *_args):
                return object()

        class Custody:
            def perform_root_selected_service_effect(self, profile, effect, payload, **kwargs):
                captured.update(kwargs)
                return "managed-result"

        lifecycle = RootMemoryServiceLifecycle(
            authority_service=Authority(), custody=Custody(), monotonic=time.monotonic)
        try:
            result = lifecycle._effect(admission, admission.action("start"),
                                       timeout=10, cancelled=None)
            self.assertEqual(result, "managed-result")
            self.assertIs(captured["memory_admission"], admission)
            self.assertIs(captured["controller_proof"], controller)
            self.assertGreater(captured["timeout"], 0)
            self.assertFalse(captured["cancelled"]())
        finally:
            controller.close()


if __name__ == "__main__":
    unittest.main()
