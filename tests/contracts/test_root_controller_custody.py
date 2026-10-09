from __future__ import annotations

import hashlib
import os
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

from hermes_installer.authority.root_controller_custody import (
    ControllerExecutablePin,
    RootControllerEventBinding,
    RootControllerProcessIdentity,
    RootControllerRoleCatalog,
    RootControllerRoleEnrollment,
    RootControllerRoleModuleRegistry,
    RootControllerRoleResolver,
)
from hermes_installer.authority.types import AuthorityDenied


GENERATION = "a" * 64
ROLE_SOURCE = b"def dispatch(event, node):\n    return (event, node)\n"
ROLE_SHA = hashlib.sha256(ROLE_SOURCE).hexdigest()


def role_record(**updates):
    record = {
        "id": "timer-role",
        "controller_kind": "root-scheduler",
        "daemon_unit_id": "hermes-authority.service",
        "daemon_executable_artifact_id": "authority-daemon",
        "daemon_executable_sha256": "b" * 64,
        "role_module_artifact_id": "resource-controller-role",
        "role_module_sha256": ROLE_SHA,
        "controller_generation": "release-42",
        "source_observer_enrollment_ids": ["timer-observer"],
        "allowed_backend_enrollment_ids": ["selected-backend"],
        "allowed_operations": ["resource.cron.run"],
        "max_lease_seconds": 30,
    }
    record.update(updates)
    return record


class FakeInspector:
    def __init__(self):
        self.live: set[int] = set()
        self.next_fd = os.open(os.devnull, os.O_RDONLY)
        self.pid = os.getpid()
        self.start = 77123
        self.identity = self._new_identity()

    def _new_identity(self):
        fd = os.dup(self.next_fd)
        self.live.add(fd)
        return RootControllerProcessIdentity(
            daemon_unit_id="hermes-authority.service", pid=self.pid, pidfd=fd,
            uid=0, start_time_ticks=self.start, cgroup="/system.slice/hermes-authority.service",
            executable_artifact_id="authority-daemon", executable_sha256="b" * 64,
            pid_namespace=(1, 2), mount_namespace=(1, 3), user_namespace=(1, 4),
            observed_monotonic=10.0,
        )

    def inspect(self, unit_id, executable_pin):
        if unit_id != self.identity.daemon_unit_id or executable_pin.artifact_id != "authority-daemon":
            raise AuthorityDenied("controller.systemd", "wrong unit")
        return self._new_identity()

    def duplicate_pidfd(self, pidfd, pid):
        if not self.is_pidfd_live(pidfd, pid):
            raise AuthorityDenied("controller.pidfd", "dead fd")
        duplicate = os.dup(pidfd)
        self.live.add(duplicate)
        return duplicate

    def close_pidfd(self, pidfd):
        self.live.discard(pidfd)
        try:
            os.close(pidfd)
        except OSError:
            pass

    def is_pidfd_live(self, pidfd, pid):
        return pid == self.pid and pidfd in self.live

    def close(self):
        for fd in tuple(self.live):
            self.close_pidfd(fd)
        os.close(self.next_fd)


class RootControllerCustodyTests(unittest.TestCase):
    def setUp(self):
        self.now = 100.0
        self.current_generation = GENERATION
        self.inspector = FakeInspector()
        self.role = RootControllerRoleEnrollment(
            id="timer-role", controller_kind="root-scheduler",
            daemon_unit_id="hermes-authority.service",
            daemon_executable_artifact_id="authority-daemon",
            daemon_executable_sha256="b" * 64,
            role_module_artifact_id="resource-controller-role",
            role_module_sha256=ROLE_SHA, controller_generation="release-42",
            source_observer_enrollment_ids=("timer-observer",),
            allowed_backend_enrollment_ids=("selected-backend",),
            allowed_operations=("resource.cron.run",), max_lease_seconds=30,
        )
        self.catalog = RootControllerRoleCatalog([role_record()], generation_digest=GENERATION)
        self.registry = RootControllerRoleModuleRegistry(
            monotonic=lambda: self.now, pid=lambda: os.getpid(),
            start_time_resolver=lambda _pid: self.inspector.start,
        )
        self.registry.load_verified(
            module_name="test_root_resource_role_" + str(id(self)),
            artifact_id=self.role.role_module_artifact_id,
            expected_sha256=self.role.role_module_sha256, source_bytes=ROLE_SOURCE,
            service_generation_digest=GENERATION,
            controller_generation=self.role.controller_generation,
        )
        self.binding = self._binding()
        self.resolver = RootControllerRoleResolver(
            catalog=self.catalog,
            event_binding_resolver=lambda handle, node: self.binding,
            inspector=self.inspector,
            executable_resolver=lambda artifact_id: ControllerExecutablePin(
                artifact_id, Path("/usr/bin/python3"), "b" * 64),
            loaded_role_registry=self.registry,
            current_generation_digest=lambda: self.current_generation,
            monotonic=lambda: self.now,
        )

    def tearDown(self):
        self.registry.revoke_generation(GENERATION)
        self.inspector.close()

    def _binding(self):
        observer = SimpleNamespace(
            observer_enrollment_id="timer-observer", source_kind="schedule-event")
        backend = SimpleNamespace(
            backend_id="selected-backend", observer_enrollment_id="timer-observer",
            operation="resource.cron.run")
        node = SimpleNamespace(
            node_id="daily-report", backend_enrollment_id="selected-backend",
            effect="resource.cron.run")
        resource = SimpleNamespace(
            observer_enrollment_id="timer-observer", kind="crons", selected_enabled=True)
        event = SimpleNamespace(observer_enrollment_id="timer-observer")
        return RootControllerEventBinding(
            role=self.role, event=event, resource_enrollment=resource,
            node=node, backend=backend, source_observer=observer,
            service_generation_digest=GENERATION, authority_epoch="epoch-3",
            expires_monotonic=self.now + 20,
        )

    def test_event_resolves_actual_role_and_owned_duplicate_pidfd(self):
        custody = self.resolver.resolve_for_event("root-event-opaque-handle", "daily-report")
        self.assertEqual(custody.pid, os.getpid())
        self.assertEqual(custody.uid, 0)
        self.assertEqual(custody.row.role_module_sha256, ROLE_SHA)
        self.assertEqual(custody.identity.pid_namespace, (1, 2))
        self.assertTrue(custody.revalidate())
        caller_fd = custody.duplicate_pidfd()
        custody.close()
        self.assertIn(caller_fd, self.inspector.live)
        self.inspector.close_pidfd(caller_fd)

    def test_forged_observer_or_backend_join_is_denied_before_pidfd_open(self):
        self.binding = self._binding()
        self.binding = replace(
            self.binding, source_observer=SimpleNamespace(
                observer_enrollment_id="unlisted-observer", source_kind="schedule-event"))
        before = set(self.inspector.live)
        with self.assertRaises(AuthorityDenied):
            self.resolver.resolve_for_event("event", "daily-report")
        self.assertEqual(self.inspector.live, before)

    def test_generation_revocation_and_deadline_invalidate_held_pidfd(self):
        custody = self.resolver.resolve_for_event("event", "daily-report")
        self.current_generation = "c" * 64
        self.assertFalse(custody.revalidate())
        custody.close()
        self.current_generation = GENERATION
        self.now = 131
        with self.assertRaises(AuthorityDenied):
            self.resolver.resolve_for_event("event", "daily-report")

    def test_missing_or_changed_loaded_module_proof_is_denied(self):
        self.registry.revoke_generation(GENERATION)
        before = set(self.inspector.live)
        with self.assertRaises(AuthorityDenied):
            self.resolver.resolve_for_event("event", "daily-report")
        self.assertEqual(self.inspector.live, before)

    def test_mutating_a_loaded_role_handler_invalidates_the_module_proof(self):
        proof = self.registry.require_loaded(
            self.role.role_module_artifact_id, self.role.role_module_sha256,
            pid=os.getpid(), start_time_ticks=self.inspector.start,
            service_generation_digest=GENERATION,
            controller_generation=self.role.controller_generation,
        )
        proof.module.dispatch = lambda event, node: None
        before = set(self.inspector.live)
        with self.assertRaises(AuthorityDenied):
            self.resolver.resolve_for_event("event", "daily-report")
        self.assertEqual(self.inspector.live, before)

    def test_duplicate_or_unknown_role_fields_cannot_enter_catalog(self):
        with self.assertRaises(AuthorityDenied):
            RootControllerRoleCatalog([role_record(), role_record()], generation_digest=GENERATION)
        with self.assertRaises(AuthorityDenied):
            RootControllerRoleCatalog([role_record(worker_claim=True)], generation_digest=GENERATION)


if __name__ == "__main__":
    unittest.main()
