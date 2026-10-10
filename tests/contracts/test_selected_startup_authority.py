"""HI-T13/RT-F03: root setup controller identity stays PIDFD-bound."""
from __future__ import annotations

import os
import sys
import time
import unittest

from hermes_installer.authority.selected_startup_authority import (
    RootControllerProcessIdentityLease,
    RootSelectedStartupRoleBinding,
    SelectedStartupDenied,
    startup_selection_payload,
)


def _current_identity(pid: int) -> dict[str, object]:
    proc = f"/proc/{pid}"
    stat_text = open(f"{proc}/stat", encoding="ascii").read()
    start_ticks = int(stat_text[stat_text.rfind(")") + 2:].split()[19])
    status = open(f"{proc}/status", encoding="ascii").read().splitlines()
    uid = int(next(line for line in status if line.startswith("Uid:")).split()[1])
    cgroup = open(f"{proc}/cgroup", encoding="ascii").read().strip().split(":", 2)[-1]
    return {
        "pid": pid, "uid": uid, "start_ticks": start_ticks,
        "cgroup_identity": cgroup if cgroup.startswith("/") else "/" + cgroup,
        "mount_namespace_inode": os.stat(f"{proc}/ns/mnt").st_ino,
        "network_namespace_inode": os.stat(f"{proc}/ns/net").st_ino,
    }


@unittest.skipUnless(
    sys.platform.startswith("linux") and hasattr(os, "pidfd_open") and os.geteuid() == 0,
    "requires Linux root PIDFD/procfs fixture",
)
class RootControllerLeaseTests(unittest.TestCase):
    def make_lease(self, *, current=lambda: True, expiry=None):
        pid = os.getpid()
        identity = _current_identity(pid)
        pidfd = os.pidfd_open(pid, 0)
        return RootControllerProcessIdentityLease(
            proof_handle="a" * 43,
            startup_authorization_handle="b" * 43,
            pid=pid,
            uid=identity["uid"],
            start_ticks=identity["start_ticks"],
            pidfd=pidfd,
            cgroup_identity=identity["cgroup_identity"],
            mount_namespace_inode=identity["mount_namespace_inode"],
            network_namespace_inode=identity["network_namespace_inode"],
            proof_sha256="d" * 64,
            expires_monotonic=expiry if expiry is not None else time.monotonic() + 5,
            _current_check=current,
        )

    def test_live_root_pidfd_lease_is_current_and_closes(self):
        lease = self.make_lease()
        try:
            self.assertTrue(lease.is_current())
        finally:
            lease.close()
        self.assertFalse(lease.is_current())

    def test_expired_or_revoked_controller_lease_is_not_current(self):
        expired = self.make_lease(expiry=time.monotonic() - 1)
        try:
            self.assertFalse(expired.is_current())
        finally:
            expired.close()

        revoked = self.make_lease(current=lambda: False)
        try:
            self.assertFalse(revoked.is_current())
        finally:
            revoked.close()

    def test_malformed_controller_proof_is_rejected_and_fd_remains_caller_owned(self):
        pidfd = os.pidfd_open(os.getpid(), 0)
        identity = _current_identity(os.getpid())
        try:
            with self.assertRaises(SelectedStartupDenied):
                RootControllerProcessIdentityLease(
                    proof_handle="caller-selected",
                    startup_authorization_handle="b" * 43,
                    pid=os.getpid(), uid=0,
                    start_ticks=identity["start_ticks"], pidfd=pidfd,
                    cgroup_identity=identity["cgroup_identity"],
                    mount_namespace_inode=identity["mount_namespace_inode"],
                    network_namespace_inode=identity["network_namespace_inode"],
                    proof_sha256="d" * 64,
                    expires_monotonic=time.monotonic() + 5,
                    _current_check=lambda: True,
                )
            os.fstat(pidfd)
        finally:
            os.close(pidfd)


class SelectedStartupPayloadTests(unittest.TestCase):
    def binding(self, action: str, operation: str, capability: str,
                operation_id: str, *, process_id: str | None = None,
                stop_reason: str | None = None):
        return RootSelectedStartupRoleBinding(
            role="display", action=action,
            service_enrollment_id="display-enrollment", profile_id="display-profile",
            generation="generation-1", principal_id="display-principal",
            namespace_identity="display-namespace", subject_uid=1001, subject_gid=1001,
            operation_id=operation_id, operation=operation, capability=capability,
            target=f"target:{operation}", recipe_sha256="a" * 64,
            source_closure_sha256="b" * 64, source_receipt_handles=(),
            service_profile=object(), process_operation=object(), source_closure=object(),
            process_id=process_id, stop_reason=stop_reason,
        )

    def test_start_status_and_stop_have_only_fixed_root_derived_payloads(self):
        start = self.binding(
            "start", "process.start", "hermes-profile-invoke",
            "native-display-start-v1",
        )
        self.assertEqual(
            startup_selection_payload(start),
            b'{"enrollment_id":"display-enrollment","generation":"generation-1",'
            b'"operation_id":"native-display-start-v1","parameters":{},"schema":1}',
        )
        status = self.binding(
            "status", "process.status", "hermes-process-control",
            "process.status", process_id="root-owned-handle",
        )
        self.assertEqual(
            startup_selection_payload(status),
            b'{"generation":"generation-1","process_id":"root-owned-handle","schema":1}',
        )
        stop = self.binding(
            "stop", "process.stop", "hermes-process-control", "process.stop",
            process_id="root-owned-handle", stop_reason="shutdown",
        )
        self.assertEqual(
            startup_selection_payload(stop),
            b'{"generation":"generation-1","grace_seconds":5,'
            b'"process_id":"root-owned-handle","reason":"shutdown","schema":1}',
        )

    def test_control_binding_cannot_invent_process_id_or_stop_reason(self):
        with self.assertRaises(SelectedStartupDenied):
            self.binding("status", "process.status", "hermes-process-control", "process.status")
        with self.assertRaises(SelectedStartupDenied):
            self.binding(
                "stop", "process.stop", "hermes-process-control", "process.stop",
                process_id="root-owned-handle", stop_reason="caller-choice",
            )


if __name__ == "__main__":
    unittest.main()
