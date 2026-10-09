from __future__ import annotations

import hashlib
import os
import platform
import time
import unittest
import uuid
from pathlib import Path
from types import SimpleNamespace

from hermes_installer.authority.root_controller_custody import (
    ControllerExecutablePin,
    RootControllerEventBinding,
    RootControllerRoleCatalog,
    RootControllerRoleModuleRegistry,
    RootControllerRoleResolver,
    RootSelectedIngressBinding,
    SystemdMainPidInspector,
)


@unittest.skipUnless(platform.system() == "Linux" and os.geteuid() == 0,
                     "requires the dedicated Linux root systemd fixture")
class RootControllerSystemdCustodyTests(unittest.TestCase):
    def test_actual_systemd_mainpid_procfs_identity_loaded_role_and_pidfd(self):
        unit = os.environ.get("HERMES_ROOT_CONTROLLER_TEST_UNIT")
        self.assertTrue(unit, "run this test as the MainPID of its dedicated systemd unit")
        generation = hashlib.sha256(b"active-root-controller-fixture-generation").hexdigest()
        controller_generation = "linux-fixture-" + uuid.uuid4().hex
        role_source = b"def dispatch(event, node):\n    return (event, node)\n"
        role_sha = hashlib.sha256(role_source).hexdigest()
        executable_path = Path(os.path.realpath("/proc/self/exe"))
        executable_sha = hashlib.sha256(Path("/proc/self/exe").read_bytes()).hexdigest()
        role = {
            "id": "linux-fixture-role", "controller_kind": "root-scheduler",
            "daemon_unit_id": unit,
            "daemon_executable_artifact_id": "linux-fixture-python",
            "daemon_executable_sha256": executable_sha,
            "role_module_artifact_id": "linux-fixture-resource-role",
            "role_module_sha256": role_sha,
            "controller_generation": controller_generation,
            "source_observer_enrollment_ids": ["linux-fixture-observer"],
            "allowed_backend_enrollment_ids": ["linux-fixture-backend"],
            "allowed_operations": ["resource.cron.run"], "max_lease_seconds": 20,
        }
        catalog = RootControllerRoleCatalog([role], generation_digest=generation)
        module_registry = RootControllerRoleModuleRegistry()
        module_registry.load_verified(
            module_name="hermes_root_resource_fixture_" + uuid.uuid4().hex,
            artifact_id="linux-fixture-resource-role", expected_sha256=role_sha,
            source_bytes=role_source, service_generation_digest=generation,
            controller_generation=controller_generation,
        )
        observer = SimpleNamespace(
            observer_enrollment_id="linux-fixture-observer", source_kind="schedule-event")
        backend = SimpleNamespace(
            backend_id="linux-fixture-backend", observer_enrollment_id="linux-fixture-observer",
            operation="resource.cron.run")
        node = SimpleNamespace(
            node_id="linux-fixture-node", backend_enrollment_id="linux-fixture-backend",
            effect="resource.cron.run")
        resource = SimpleNamespace(
            observer_enrollment_id="linux-fixture-observer", kind="crons", selected_enabled=True)
        event = SimpleNamespace(observer_enrollment_id="linux-fixture-observer")
        binding = RootControllerEventBinding(
            role=catalog.get("linux-fixture-role"), event=event,
            resource_enrollment=resource, node=node, backend=backend,
            source_observer=observer, service_generation_digest=generation,
            authority_epoch="linux-fixture-epoch", expires_monotonic=time.monotonic() + 15,
        )
        selected_observer = SimpleNamespace(
            observer_enrollment_id="linux-fixture-observer", source_kind="schedule-event",
            channel_id="linux-fixture-issuer", profile_id="linux-fixture-profile",
            principal_id="linux-fixture-principal", capture_schema_id="timer-input-v1")
        selected_issuer = SimpleNamespace(
            issuer_channel_id="linux-fixture-issuer",
            observer_enrollment_id="linux-fixture-observer",
            producer_profile_id="linux-fixture-profile", capture_schema_id="timer-input-v1")
        selected_backend = SimpleNamespace(
            backend_id="linux-fixture-backend", source_issuer_channel_id="linux-fixture-issuer",
            observer_enrollment_id="linux-fixture-observer", operation="resource.cron.run",
            profile_id="linux-fixture-profile", principal_id="linux-fixture-principal",
            generation="d" * 64)
        ingress_binding = RootSelectedIngressBinding(
            role=catalog.get("linux-fixture-role"), source_issuer=selected_issuer,
            source_observer=selected_observer, backend=selected_backend,
            resource_generation="d" * 64, service_generation_digest=generation,
            authority_epoch="linux-fixture-epoch",
            selected_ingress_binding_id="linux-fixture-timer-binding",
            expires_monotonic=time.monotonic() + 15)
        inspector = SystemdMainPidInspector()
        resolver = RootControllerRoleResolver(
            catalog=catalog,
            event_binding_resolver=lambda _handle, _node: binding,
            inspector=inspector,
            executable_resolver=lambda artifact_id: ControllerExecutablePin(
                artifact_id, executable_path, executable_sha),
            loaded_role_registry=module_registry,
            current_generation_digest=lambda: generation,
            selected_ingress_binding_resolver=lambda _role, _issuer, _backend: ingress_binding,
        )
        ingress_proof = resolver.resolve_selected_ingress_controller(
            "linux-fixture-role", "linux-fixture-issuer", "linux-fixture-backend")
        try:
            self.assertEqual(ingress_proof.pid, os.getpid())
            self.assertEqual(ingress_proof.uid, 0)
            self.assertEqual(ingress_proof.live_peer_identity.cgroup, f"/system.slice/{unit}")
            self.assertEqual(ingress_proof.role_artifact_sha256, role_sha)
            self.assertTrue(inspector.is_pidfd_live(ingress_proof.pidfd, os.getpid()))
            self.assertTrue(ingress_proof.revalidate())
        finally:
            resolver.release_ingress_proof(ingress_proof.proof_handle)
            ingress_proof.close()
        custody = resolver.resolve_for_event("linux-fixture-event", "linux-fixture-node")
        try:
            self.assertEqual(custody.pid, os.getpid())
            self.assertEqual(custody.uid, 0)
            self.assertEqual(custody.identity.daemon_unit_id, unit)
            self.assertEqual(custody.identity.cgroup, f"/system.slice/{unit}")
            self.assertEqual(custody.identity.executable_sha256, executable_sha)
            self.assertTrue(custody.revalidate())
            duplicate = custody.duplicate_pidfd()
            try:
                self.assertTrue(inspector.is_pidfd_live(duplicate, os.getpid()))
            finally:
                inspector.close_pidfd(duplicate)
        finally:
            custody.close()
            module_registry.revoke_generation(generation)


if __name__ == "__main__":
    unittest.main()
