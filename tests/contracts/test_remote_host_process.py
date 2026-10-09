"""HI10 root receipt parsing contracts; fixtures are not target acceptance."""
from __future__ import annotations

import unittest

from hermes_installer.authority.types import AuthorityDenied
from hermes_installer.remote.host_process import parse_process_inspection


class RootProcessInspectionReceiptTests(unittest.TestCase):
    @staticmethod
    def attestation(role):
        return {
            "schema": 1, "verified": True, "role": role,
            "artifact_verified": True, "parent_chain_verified": True,
            "kernel_uid": 1001, "cgroup_identity": "unit.slice/process.scope",
            "namespace_identity": "ns-1", "seccomp_mode": 2, "no_new_privs": True,
            "forbidden_flags_present": False, "relaunch_monitor_verified": True,
            "window_denial_verified": True, "policy_manifest_sha256": "c" * 64,
            "native_generation": "generation-1", "observation_monotonic": 20.0,
            "expires_monotonic": 25.0, "evidence_refs": ["evidence-opaque-1"],
        }
    def setUp(self):
        self.value = {
            "schema": 1, "process_id": "process-1", "generation": "generation-1",
            "profile_id": "hermes-desktop", "cgroup_identity": "unit.slice/process.scope",
            "observation_monotonic": 20.0, "expires_monotonic": 25.0,
            "complete": True,
            "processes": [
                {"opaque_member_id": "member-xpra", "parent_member_id": None,
                 "kernel_uid": 1001, "pidfd_identity": "pidfd-a", "starttime": 11,
                 "exe_device": 4, "exe_inode": 55, "exe_sha256": "a" * 64,
                 "cgroup_identity": "unit.slice/process.scope", "role": "xpra-server",
                 "sandbox_attestation": self.attestation("xpra-server")},
                {"opaque_member_id": "member-renderer", "parent_member_id": "member-xpra",
                 "kernel_uid": 1001, "pidfd_identity": "pidfd-b", "starttime": 12,
                 "exe_device": 4, "exe_inode": 56, "exe_sha256": "b" * 64,
                 "cgroup_identity": "unit.slice/process.scope", "role": "electron-renderer",
                 "sandbox_attestation": self.attestation("electron-renderer")},
            ],
        }

    def parse(self, value=None):
        return parse_process_inspection(
            self.value if value is None else value, receipt_id="root-receipt",
            process_id="process-1", generation="generation-1",
            profile_id="hermes-desktop", now_monotonic=21.0,
        )

    def test_accepts_complete_root_receipt_and_keeps_process_ids_opaque(self):
        receipt = self.parse()
        self.assertEqual(receipt.processes[1].parent_member_id, "member-xpra")
        self.assertEqual(receipt.processes[1].member_id, "member-renderer")
        self.assertFalse(hasattr(receipt.processes[1], "pid"))
        self.assertEqual(receipt.receipt_id, "root-receipt")

    def test_rejects_incomplete_expired_or_substituted_generation(self):
        for update in (
            {"complete": False}, {"expires_monotonic": 21.0},
            {"generation": "stale"}, {"profile_id": "other-profile"},
        ):
            value = {**self.value, **update}
            with self.subTest(update=update), self.assertRaises(AuthorityDenied):
                self.parse(value)

    def test_rejects_missing_member_and_cyclic_parent_evidence(self):
        value = {**self.value, "processes": self.value["processes"][:1]}
        value["processes"][0] = {**value["processes"][0], "parent_member_id": "missing"}
        with self.assertRaises(AuthorityDenied):
            self.parse(value)
        cyclic = [dict(item) for item in self.value["processes"]]
        cyclic[0] = {**cyclic[0], "parent_member_id": "member-renderer"}
        with self.assertRaises(AuthorityDenied):
            self.parse({**self.value, "processes": cyclic})

    def test_rejects_caller_supplied_pid_or_path_claims(self):
        value = {**self.value, "pid": 1234}
        with self.assertRaises(AuthorityDenied):
            self.parse(value)
        row = {**self.value["processes"][0], "pid": 9999}
        with self.assertRaises(AuthorityDenied):
            self.parse({**self.value, "processes": [row]})

    def test_rejects_incomplete_root_sandbox_enrollment_evidence(self):
        row = dict(self.value["processes"][1])
        row["sandbox_attestation"] = {**row["sandbox_attestation"], "verified": False}
        with self.assertRaises(AuthorityDenied):
            self.parse({**self.value, "processes": [self.value["processes"][0], row]})
        row["sandbox_attestation"] = {**row["sandbox_attestation"], "forbidden_flags_present": True}
        with self.assertRaises(AuthorityDenied):
            self.parse({**self.value, "processes": [self.value["processes"][0], row]})


if __name__ == "__main__":
    unittest.main()
