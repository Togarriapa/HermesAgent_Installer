"""Target workflows require explicit, current owner authorization and scope."""

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import unittest
from unittest.mock import patch
from hermes_installer.verification.acceptance import AuthorizedTarget, TargetWorkflowRunner
from hermes_installer.evidence import EvidenceClass, EvidenceRecord, EvidenceState
from hermes_installer.verification.profiles import profile_for


def target(**changes):
    value = {
        "target_id": "pi5-test-01",
        "platform": "raspberry-pi-5-arm64",
        "owner": "owner-123",
        "authorization_reference": "enrollment-42",
        "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
        "allowed_acceptance": ["AC01"],
    }
    value.update(changes)
    return AuthorizedTarget.parse(value, manifest_sha256=hashlib.sha256(b"manifest").hexdigest())


class TargetWorkflowTests(unittest.TestCase):
    def test_unenrolled_target_is_rejected_before_probe(self):
        runner = TargetWorkflowRunner(workflows={}, authorize=lambda _: False)
        with self.assertRaisesRegex(PermissionError, "could not be verified"):
            runner.run("AC01", target(), "a" * 40, "/tmp/evidence")

    def test_workflow_is_scoped_to_authorized_acceptance_id(self):
        called = []
        runner = TargetWorkflowRunner(workflows={}, authorize=lambda _: called.append("authorize") or True)
        with self.assertRaisesRegex(PermissionError, "does not include"):
            runner.run("AC02", target(), "a" * 40, "/tmp/evidence")
        self.assertEqual(["authorize"], called)

    def test_directly_constructed_target_is_validated_before_authorizer_or_probe(self):
        called = []
        forged = AuthorizedTarget(
            target_id="..",
            platform="unsupported",
            owner="",
            authorization_reference="",
            expires_at=(datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
            allowed_acceptance=("AC01",),
            manifest_sha256="invalid",
        )
        runner = TargetWorkflowRunner(workflows={}, authorize=lambda _: called.append("authorize") or True)
        with self.assertRaisesRegex(ValueError, "target_id"):
            runner.run("AC01", forged, "a" * 40, "/tmp/evidence")
        self.assertEqual(called, [])

    def test_target_expiring_after_parse_is_rejected_before_authorizer_or_probe(self):
        called = []
        runner = TargetWorkflowRunner(workflows={}, authorize=lambda _: called.append("authorize") or True)
        stale = replace(target(), expires_at=(datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat())
        with self.assertRaisesRegex(PermissionError, "expired"):
            runner.run("AC01", stale, "a" * 40, "/tmp/evidence")
        self.assertEqual(called, [])

    def test_authorization_that_expires_during_owner_check_is_rejected(self):
        called = []
        current = target(expires_at=(datetime.now(timezone.utc) + timedelta(seconds=30)).isoformat())
        base = datetime.now(timezone.utc)

        class AdvancingDateTime(datetime):
            calls = 0

            @classmethod
            def now(cls, tz=None):
                cls.calls += 1
                return base + timedelta(seconds=0 if cls.calls == 1 else 60)

        runner = TargetWorkflowRunner(workflows={}, authorize=lambda _: called.append("authorize") or True)
        with patch("hermes_installer.verification.acceptance.datetime", AdvancingDateTime):
            with self.assertRaisesRegex(PermissionError, "expired"):
                runner.run("AC01", current, "a" * 40, "/tmp/evidence")
        self.assertEqual(["authorize"], called)

    def test_missing_operator_result_is_explicitly_pending(self):
        result = TargetWorkflowRunner(workflows={}, authorize=lambda _: True).run("AC01", target(), "a" * 40, "/tmp/evidence")
        self.assertEqual(result.state.value, "pending")
        self.assertIn("no target effects occurred", result.message)
        self.assertIsNone(result.record)

    def test_registered_workflow_is_invoked_and_candidate_target_binding_is_enforced(self):
        enrolled = target(platform="fixture-x86_64")
        calls = []

        def pending_probe(observed_target, output_dir):
            calls.append((observed_target.target_id, output_dir))
            return EvidenceRecord(
                evidence_id="EV-R0169", candidate_sha="a" * 40,
                evidence_class=EvidenceClass.FIXTURE, state=EvidenceState.PENDING,
                platform="fixture-x86_64", target_id=observed_target.target_id,
                started_at=datetime.now(timezone.utc).isoformat(),
                finished_at=datetime.now(timezone.utc).isoformat(), command="fixture probe",
                exit_code=None,
                assertions={name: None for name in profile_for("EV-R0169", "AC01").assertions},
                blocker="fixture only; target acceptance remains pending",
            )

        runner = TargetWorkflowRunner(workflows={"AC01": pending_probe}, authorize=lambda _: True)
        result = runner.run("AC01", enrolled, "a" * 40, "/tmp/evidence")
        self.assertEqual([(enrolled.target_id, "/tmp/evidence")], calls)
        self.assertEqual(EvidenceState.PENDING, result.state)
        self.assertEqual("a" * 40, result.record.candidate_sha)
        self.assertEqual(enrolled.target_id, result.record.target_id)

        def wrong_candidate(observed_target, output_dir):
            record = pending_probe(observed_target, output_dir)
            from dataclasses import replace
            return replace(record, candidate_sha="b" * 40)

        wrong_runner = TargetWorkflowRunner(workflows={"AC01": wrong_candidate}, authorize=lambda _: True)
        with self.assertRaisesRegex(ValueError, "not bound"):
            wrong_runner.run("AC01", enrolled, "a" * 40, "/tmp/evidence")

    def test_structural_pass_observation_remains_pending_without_verifier_authentication(self):
        enrolled = target(platform="fixture-x86_64")
        profile = profile_for("EV-R0169", "AC01")

        def observed_pass(observed_target, _output_dir):
            return EvidenceRecord(
                evidence_id="EV-R0169", candidate_sha="a" * 40,
                evidence_class=EvidenceClass.FIXTURE, state=EvidenceState.PASS,
                platform="fixture-x86_64", target_id=observed_target.target_id,
                started_at=datetime.now(timezone.utc).isoformat(),
                finished_at=datetime.now(timezone.utc).isoformat(), command="fixture probe",
                exit_code=0, assertions={name: True for name in profile.assertions},
                artifact_sha256="a" * 64,
            )

        result = TargetWorkflowRunner(workflows={"AC01": observed_pass}, authorize=lambda _: True).run(
            "AC01", enrolled, "a" * 40, "/tmp/evidence"
        )
        self.assertEqual(EvidenceState.PENDING, result.state)
        self.assertEqual(EvidenceState.PASS, result.record.state)
        self.assertIn("verifier authentication", result.message)

    def test_workflow_cannot_change_evidence_profile_or_target_lane(self):
        enrolled = target(platform="fixture-x86_64")

        def wrong_profile(observed_target, _output_dir):
            return EvidenceRecord(
                evidence_id="EV-R0170", candidate_sha="a" * 40,
                evidence_class=EvidenceClass.FIXTURE, state=EvidenceState.PENDING,
                platform="fixture-x86_64", target_id=observed_target.target_id,
                started_at=datetime.now(timezone.utc).isoformat(),
                finished_at=datetime.now(timezone.utc).isoformat(), command="fixture probe",
                exit_code=None,
                assertions={name: None for name in profile_for("EV-R0170", "AC02").assertions},
                blocker="not observed",
            )

        runner = TargetWorkflowRunner(workflows={"AC01": wrong_profile}, authorize=lambda _: True)
        with self.assertRaisesRegex(ValueError, "no installer-owned"):
            runner.run("AC01", enrolled, "a" * 40, "/tmp/evidence")


if __name__ == "__main__":
    unittest.main()
