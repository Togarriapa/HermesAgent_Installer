"""Exact request/result binding for target-owner acceptance transcripts."""

from datetime import datetime, timedelta, timezone
import hashlib
import json
import tempfile
import unittest
from uuid import uuid4
from pathlib import Path

from hermes_installer.evidence import EvidenceClass, EvidenceState, load_acceptance_catalog
from hermes_installer.state import OwnedRoot
from hermes_installer.verification.acceptance import AuthorizedTarget
from hermes_installer.verification.operator_evidence import ProbeRequest, build_probe_request, verify_operator_result
from hermes_installer.verification.profiles import PROBE_PROFILES, profile_for


SHA = "a" * 40


def target():
    manifest_sha = hashlib.sha256(b"authorized target manifest").hexdigest()
    return AuthorizedTarget.parse({
        "target_id": "fixture-pi-01", "platform": "fixture-x86_64", "owner": "owner-42",
        "authorization_reference": "operator-enrollment-01",
        "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
        "allowed_acceptance": ["AC01"],
    }, manifest_sha256=manifest_sha)


def request_value(enrolled):
    request = build_probe_request(
        request_id=str(uuid4()), acceptance_id="AC01", evidence_id="EV-R0169",
        candidate_sha=SHA, target_id=enrolled.target_id, platform=enrolled.platform,
        authorization_reference=enrolled.authorization_reference,
        target_manifest_sha256=enrolled.manifest_sha256,
        argv=("/usr/bin/hermes-installer", "verify", "--json"), cwd="/home/pi/HermesInstaller",
        environment_allowlist=("HOME", "PATH"), timeout_seconds=120,
        stdout_limit_bytes=65536, stderr_limit_bytes=32768,
    )
    return request.to_dict()


def result_value(request, enrolled, **changes):
    start = datetime.now(timezone.utc) - timedelta(seconds=10)
    value = {
        "schema_version": 1, "request_id": request["request_id"],
        "request_sha256": hashlib.sha256(json.dumps(request, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest(),
        "acceptance_id": request["acceptance_id"], "evidence_id": request["evidence_id"],
        "candidate_sha": request["candidate_sha"], "target_id": enrolled.target_id,
        "platform": enrolled.platform, "owner": enrolled.owner,
        "authorization_reference": enrolled.authorization_reference,
        "started_at": start.isoformat(), "finished_at": datetime.now(timezone.utc).isoformat(),
        "exit_code": 0,
        "argv_sha256": hashlib.sha256(json.dumps({"argv": request["argv"]}, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest(),
        "cwd_sha256": hashlib.sha256(request["cwd"].encode()).hexdigest(),
        "environment_names": ["HOME", "PATH"],
        "stdout_sha256": hashlib.sha256(b"bounded stdout").hexdigest(), "stdout_bytes": 14,
        "stderr_sha256": hashlib.sha256(b"").hexdigest(), "stderr_bytes": 0,
        "output_truncated": False,
        "assertions": {name: True for name in request["expected_assertions"]},
        "effects": ["installer.status_candidate_bound"],
    }
    value.update(changes)
    return value


class OperatorEvidenceTests(unittest.TestCase):
    def test_every_acceptance_evidence_id_has_an_installer_owned_profile(self):
        catalog = load_acceptance_catalog(Path(__file__).parents[2] / "planning")
        criteria = catalog["acceptance"] + catalog["additional_acceptance"]
        expected_pairs = {
            (str(criterion["id"]), str(evidence_id))
            for criterion in criteria
            for evidence_id in criterion["evidence_ids"]
        }
        actual_pairs = {
            (acceptance_id, evidence_id)
            for evidence_id, profile in PROBE_PROFILES.items()
            for acceptance_id in profile.acceptance_ids
        }
        self.assertTrue(expected_pairs.issubset(actual_pairs))
        self.assertTrue({("AC18", f"EV-HI{number:02d}") for number in range(1, 10)}.issubset(actual_pairs))
        for acceptance_id, evidence_id in expected_pairs:
            self.assertTrue(profile_for(evidence_id, acceptance_id).assertions)

    def test_exact_candidate_target_command_and_assertions_are_retained_before_record_is_emitted(self):
        enrolled = target()
        request = request_value(enrolled)
        result = result_value(request, enrolled)
        verified = verify_operator_result(request, result, enrolled)
        self.assertEqual("pass", verified.state.value)
        result["assertions"][request["expected_assertions"][0]] = False
        with tempfile.TemporaryDirectory() as temp:
            record = verified.retain(OwnedRoot(Path(temp)))
            self.assertEqual(EvidenceState.PASS, record.state)
            self.assertEqual(EvidenceClass.FIXTURE, record.evidence_class)
            artifact = next(Path(temp).rglob("*.json"))
            self.assertEqual(hashlib.sha256(artifact.read_bytes()).hexdigest(), record.artifact_sha256)
            self.assertEqual(0o600, artifact.stat().st_mode & 0o777)
            persisted = json.loads(artifact.read_text())
            self.assertNotIn("stdout", persisted["result"])
            self.assertNotIn("environment", persisted["result"])
            self.assertTrue(persisted["result"]["assertions"][request["expected_assertions"][0]])

    def test_unretained_result_does_not_create_an_evidence_record(self):
        enrolled = target()
        request = request_value(enrolled)
        verified = verify_operator_result(request, result_value(request, enrolled), enrolled)
        self.assertFalse(hasattr(verified, "record"))

    def test_candidate_command_target_and_manifest_mismatches_are_rejected(self):
        enrolled = target()
        request = request_value(enrolled)
        for mutation in (
            {"candidate_sha": "b" * 40},
            {"target_id": "another-pi"},
            {"request_sha256": "0" * 64},
            {"argv_sha256": "0" * 64},
            {"cwd_sha256": "0" * 64},
        ):
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                verify_operator_result(request, result_value(request, enrolled, **mutation), enrolled)

    def test_secret_values_shells_raw_output_and_environment_escape_are_rejected(self):
        enrolled = target()
        base = request_value(enrolled)
        for mutation in (
            {"argv": ["/bin/sh", "-c", "whoami"]},
            {"argv": ["/usr/bin/client", "--api-key", "plain-text"]},
            {"environment_allowlist": ["HERMES_API_TOKEN"]},
        ):
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                ProbeRequest.from_dict({**base, **mutation})
        request = base
        with self.assertRaises(ValueError):
            verify_operator_result(request, result_value(request, enrolled, environment_names=["HOME", "SECRET_TOKEN"]), enrolled)
        with self.assertRaises(ValueError):
            verify_operator_result(request, {**result_value(request, enrolled), "stdout": "raw log"}, enrolled)

    def test_assertion_profile_and_evidence_class_are_installer_owned(self):
        enrolled = target()
        base = request_value(enrolled)
        with self.assertRaisesRegex(ValueError, "installer-owned evidence profile"):
            ProbeRequest.from_dict({**base, "expected_assertions": ["anything_passed"]})
        with self.assertRaisesRegex(ValueError, "determined by the enrolled target"):
            ProbeRequest.from_dict({**base, "evidence_class": EvidenceClass.PHYSICAL_PI.value})

    def test_output_limits_and_truncation_are_enforced(self):
        enrolled = target()
        request = request_value(enrolled)
        for mutation in (
            {"stdout_bytes": request["stdout_limit_bytes"] + 1},
            {"output_truncated": True},
        ):
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                verify_operator_result(request, result_value(request, enrolled, **mutation), enrolled)

    def test_unattempted_assertion_is_retained_as_pending_not_failure_or_pass(self):
        enrolled = AuthorizedTarget.parse({
            "target_id": "pi5-test-01", "platform": "raspberry-pi-5-arm64", "owner": "owner-123",
            "authorization_reference": "enrollment-42",
            "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
            "allowed_acceptance": ["AC16"],
        }, manifest_sha256=hashlib.sha256(b"manifest").hexdigest())
        request = build_probe_request(
            request_id=str(uuid4()), acceptance_id="AC16", evidence_id="EV-RB02",
            candidate_sha=SHA, target_id=enrolled.target_id, platform=enrolled.platform,
            authorization_reference=enrolled.authorization_reference,
            target_manifest_sha256=enrolled.manifest_sha256,
            argv=("/usr/bin/hermes-installer", "resources", "status", "--json"),
            cwd="/home/pi/HermesInstaller", environment_allowlist=("HOME", "PATH"),
            timeout_seconds=30, stdout_limit_bytes=65536, stderr_limit_bytes=32768,
        ).to_dict()
        assertions = {name: True for name in request["expected_assertions"]}
        assertions["selected_native_workflow_invoked"] = None
        verified = verify_operator_result(request, result_value(request, enrolled, assertions=assertions), enrolled)
        self.assertEqual(EvidenceState.PENDING, verified.state)
        self.assertIn("not observed", verified.blocker)
        false_assertions = dict(assertions)
        false_assertions["selected_native_workflow_invoked"] = False
        failed = verify_operator_result(request, result_value(request, enrolled, assertions=false_assertions), enrolled)
        self.assertEqual(EvidenceState.FAIL, failed.state)
        with tempfile.TemporaryDirectory() as temp:
            record = verified.retain(OwnedRoot(Path(temp)))
            self.assertEqual(EvidenceState.PENDING, record.state)
            self.assertIsNone(record.assertions["selected_native_workflow_invoked"])
            report = acceptance_report(
                candidate_sha=SHA, traceability=load_acceptance_catalog(Path(__file__).parents[2] / "planning"),
                records=[record], verify_record=lambda _record: True,
            )
            ac16 = next(row for row in report["acceptance"] if row["acceptance_id"] == "AC16")
            self.assertEqual("pending", ac16["state"])

    def test_failed_effect_or_exceeded_deadline_stays_a_failure(self):
        enrolled = target()
        request = request_value(enrolled)
        failed = verify_operator_result(request, result_value(request, enrolled, exit_code=7), enrolled)
        self.assertEqual(EvidenceState.FAIL, failed.state)
        self.assertIn("status 7", failed.blocker)
        bad_result = result_value(request, enrolled,
            started_at=(datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat(),
            finished_at=datetime.now(timezone.utc).isoformat())
        with self.assertRaisesRegex(ValueError, "timeout"):
            verify_operator_result(request, bad_result, enrolled)


if __name__ == "__main__":
    unittest.main()
