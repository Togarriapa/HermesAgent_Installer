"""Safety boundary for the human-authorized, read-only Pi probe scope."""

from datetime import datetime, timedelta, timezone
from dataclasses import replace
import hashlib
import json
import unittest

from hermes_installer.verification.pi_lease import (
    AUTHORIZATION_REFERENCE,
    RETAINED_HUMAN_INSTRUCTION,
    PiObservation,
    build_pi_contract_test_request,
    build_pi_read_only_lease,
)


class PiLeaseTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 10, 9, 19, 0, tzinfo=timezone.utc)
        self.observation = PiObservation(
            device_id="48dfbc75-8877-40bb-b391-9b08301911ad",
            observed_at=(self.now - timedelta(seconds=15)).isoformat(),
            uid=1000, gid=1000, owner="admin", architecture="aarch64",
            model="Raspberry Pi 5 Model B Rev 1.1",
            staging_root="/home/admin/HermesInstaller/data/devtest-luna-resource-wire-51d3883/native-resources-8b806b49/acceptance/ev-rb02-7b895616",
            staging_uid=1000, staging_gid=1000, staging_mode=0o700,
            staging_is_symlink=False, checkout_sha="f" * 40,
        )

    def test_manifest_binds_candidate_separately_and_limits_scope(self):
        lease = build_pi_read_only_lease(self.observation, candidate_sha="a" * 40, now=self.now)
        document = lease.to_dict()
        manifest = lease.to_manifest()
        self.assertEqual("a" * 40, document["candidate_sha"])
        self.assertEqual("f" * 40, document["observed_checkout_sha"])
        self.assertNotEqual(document["candidate_sha"], document["observed_checkout_sha"])
        self.assertEqual(AUTHORIZATION_REFERENCE, document["authorization_reference"])
        self.assertEqual(RETAINED_HUMAN_INSTRUCTION, document["retained_human_instruction"])
        self.assertFalse(document["cryptographic_grant"])
        self.assertFalse(document["authorization_signature_verified"])
        self.assertEqual(("AC16",), document["allowed_acceptance"])
        self.assertEqual({"bounded_read_only_discovery", "isolated_contract_tests"}, set(document["allowed_actions"]))
        self.assertIn("profile_invocation", document["denied_actions"])
        self.assertIn("account_or_cloud_mutation", document["denied_actions"])
        self.assertLessEqual(datetime.fromisoformat(document["expires_at"].replace("Z", "+00:00")) - self.now, timedelta(minutes=10))
        self.assertEqual(lease.manifest_sha256, manifest["manifest_sha256"])
        self.assertEqual(lease.manifest_sha256, hashlib.sha256(
            json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
        ).hexdigest())

    def test_stale_or_wrong_identity_observation_cannot_mint_scope(self):
        stale = replace(self.observation, observed_at=(self.now - timedelta(minutes=6)).isoformat())
        with self.assertRaisesRegex(PermissionError, "stale"):
            build_pi_read_only_lease(stale, candidate_sha="a" * 40, now=self.now)
        wrong = PiObservation(
            device_id="another-device", observed_at=self.observation.observed_at,
            uid=1000, gid=1000, owner="admin", architecture="aarch64",
            model=self.observation.model, staging_root=self.observation.staging_root,
            staging_uid=1000, staging_gid=1000, staging_mode=0o700,
            staging_is_symlink=False, checkout_sha="f" * 40,
        )
        with self.assertRaisesRegex(PermissionError, "device"):
            build_pi_read_only_lease(wrong, candidate_sha="a" * 40, now=self.now)

    def test_unowned_or_untrusted_staging_facts_cannot_mint_scope(self):
        for changes in (
            {"uid": 0}, {"owner": "other"}, {"architecture": "x86_64"},
            {"staging_uid": 0}, {"staging_mode": 0o755}, {"staging_is_symlink": True},
            {"staging_root": "/tmp/acceptance"},
        ):
            with self.subTest(changes=changes), self.assertRaises(PermissionError):
                build_pi_read_only_lease(replace(self.observation, **changes), candidate_sha="a" * 40, now=self.now)

    def test_candidate_timestamp_and_lease_bounds_are_validated(self):
        with self.assertRaisesRegex(ValueError, "full lowercase"):
            build_pi_read_only_lease(self.observation, candidate_sha="A" * 40, now=self.now)
        with self.assertRaisesRegex(ValueError, "timezone"):
            build_pi_read_only_lease(self.observation, candidate_sha="a" * 40, now=datetime(2026, 10, 9, 19, 0))
        with self.assertRaisesRegex(ValueError, "capped"):
            build_pi_read_only_lease(
                self.observation, candidate_sha="a" * 40, now=self.now,
                lease_duration=timedelta(minutes=11),
            )

    def test_managed_install_and_profile_execution_remain_out_of_scope(self):
        lease = build_pi_read_only_lease(self.observation, candidate_sha="a" * 40, now=self.now)
        self.assertIn("managed_install", lease.denied_actions)
        self.assertIn("profile_invocation", lease.denied_actions)
        self.assertIn("model_inference", lease.denied_actions)
        self.assertIn("arbitrary_shell", lease.denied_actions)

    def test_contract_request_is_fixed_to_exact_candidate_and_non_shell_suite(self):
        lease = build_pi_read_only_lease(self.observation, candidate_sha="f" * 40, now=self.now)
        request = build_pi_contract_test_request(lease, python_executable="/usr/bin/python3", now=self.now)
        value = request.to_dict()
        self.assertEqual("f" * 40, value["candidate_sha"])
        self.assertEqual(lease.manifest_sha256, value["target_manifest_sha256"])
        self.assertEqual(("PATH", "PYTHONPATH", "PYTHONDONTWRITEBYTECODE"), request.environment_allowlist)
        self.assertEqual(120, request.timeout_seconds)
        self.assertEqual("/home/admin/HermesInstaller/data/devtest-luna-resource-wire-51d3883/native-resources-8b806b49/repo", request.cwd)
        self.assertEqual("-m", request.argv[1])
        self.assertEqual("unittest", request.argv[2])
        self.assertNotIn(request.argv[0].rsplit("/", 1)[-1], {"sh", "bash", "dash", "zsh"})
        self.assertEqual(8, len(request.expected_assertions))

    def test_contract_request_rejects_candidate_mismatch_interpreter_and_expired_lease(self):
        other_checkout = build_pi_read_only_lease(self.observation, candidate_sha="a" * 40, now=self.now)
        with self.assertRaisesRegex(PermissionError, "does not match"):
            build_pi_contract_test_request(other_checkout, python_executable="/usr/bin/python3", now=self.now)
        matching = build_pi_read_only_lease(self.observation, candidate_sha="f" * 40, now=self.now)
        with self.assertRaisesRegex(PermissionError, "interpreter"):
            build_pi_contract_test_request(matching, python_executable="/tmp/python3", now=self.now)
        with self.assertRaisesRegex(PermissionError, "expired"):
            build_pi_contract_test_request(matching, python_executable="/usr/bin/python3", now=self.now + timedelta(minutes=11))


if __name__ == "__main__":
    unittest.main()
