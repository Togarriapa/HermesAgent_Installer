"""Target workflows require explicit, current owner authorization and scope."""

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import unittest
from unittest.mock import patch
import json
import tempfile
from pathlib import Path

from hermes_installer.verification.acceptance import AuthorizedTarget, TargetWorkflowRunner
from hermes_installer.state import OwnedRoot
from hermes_installer.verification.operator_evidence import ProbeRequest, build_probe_request
from hermes_installer.evidence import EvidenceClass, acceptance_report, load_acceptance_catalog


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
        runner = TargetWorkflowRunner(authorize=lambda _: False)
        with self.assertRaisesRegex(PermissionError, "could not be verified"):
            runner.run("AC01", target(), "a" * 40, "/tmp/evidence")

    def test_workflow_is_scoped_to_authorized_acceptance_id(self):
        called = []
        runner = TargetWorkflowRunner(authorize=lambda _: called.append("authorize") or True)
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
        runner = TargetWorkflowRunner(authorize=lambda _: called.append("authorize") or True)
        with self.assertRaisesRegex(ValueError, "target_id"):
            runner.run("AC01", forged, "a" * 40, "/tmp/evidence")
        self.assertEqual(called, [])

    def test_target_expiring_after_parse_is_rejected_before_authorizer_or_probe(self):
        called = []
        runner = TargetWorkflowRunner(authorize=lambda _: called.append("authorize") or True)
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

        runner = TargetWorkflowRunner(authorize=lambda _: called.append("authorize") or True)
        with patch("hermes_installer.verification.acceptance.datetime", AdvancingDateTime):
            with self.assertRaisesRegex(PermissionError, "expired"):
                runner.run("AC01", current, "a" * 40, "/tmp/evidence")
        self.assertEqual(["authorize"], called)

    def test_missing_operator_result_is_explicitly_pending(self):
        result = TargetWorkflowRunner(authorize=lambda _: True).run("AC01", target(), "a" * 40, "/tmp/evidence")
        self.assertEqual(result.state.value, "pending")
        self.assertIn("target effects were not started", result.message)
        self.assertEqual("operator_result_missing", result.blocker_code)
        self.assertTrue(result.next_step)

    def test_collector_requires_enrollment_and_binds_candidate_before_retaining(self):
        enrolled = target(platform="fixture-x86_64")
        request = build_probe_request(
            request_id="c5b49d58-828f-4dc7-b3b4-539ff51ac3f9", acceptance_id="AC01", evidence_id="EV-R0169",
            candidate_sha="a" * 40, target_id=enrolled.target_id, platform=enrolled.platform,
            authorization_reference=enrolled.authorization_reference,
            target_manifest_sha256=enrolled.manifest_sha256, argv=("/usr/bin/status", "--json"),
            cwd="/tmp/target", environment_allowlist=("HOME",), timeout_seconds=30,
            stdout_limit_bytes=4096, stderr_limit_bytes=4096,
        ).to_dict()
        def result_json():
            finished = datetime.now(timezone.utc)
            started = finished - timedelta(seconds=1)
            return {
                "schema_version": 1, "request_id": request["request_id"],
                "request_sha256": hashlib.sha256(json.dumps(request, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest(),
                "acceptance_id": "AC01", "evidence_id": "EV-R0169", "candidate_sha": "a" * 40,
                "target_id": enrolled.target_id, "platform": enrolled.platform, "owner": enrolled.owner,
                "authorization_reference": enrolled.authorization_reference,
                "started_at": started.isoformat(), "finished_at": finished.isoformat(),
                "exit_code": 0,
                "argv_sha256": hashlib.sha256(json.dumps({"argv": request["argv"]}, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest(),
                "cwd_sha256": hashlib.sha256(request["cwd"].encode()).hexdigest(),
                "environment_names": ["HOME"], "stdout_sha256": hashlib.sha256(b"ok").hexdigest(),
                "stderr_sha256": hashlib.sha256(b"").hexdigest(), "stdout_bytes": 2, "stderr_bytes": 0,
                "output_truncated": False,
                "assertions": {name: True for name in request["expected_assertions"]},
                "effects": ["installer.status_read"],
            }
        with tempfile.TemporaryDirectory() as temp:
            denied = TargetWorkflowRunner(authorize=lambda _: False)
            with self.assertRaises(PermissionError):
                denied.collect_result(request, result_json(), enrolled, "a" * 40, OwnedRoot(Path(temp) / "denied"))
            self.assertFalse((Path(temp) / "denied").exists())

            collector = TargetWorkflowRunner(authorize=lambda _: True)
            with self.assertRaisesRegex(ValueError, "candidate SHA"):
                collector.collect_result(request, result_json(), enrolled, "b" * 40, OwnedRoot(Path(temp) / "wrong-candidate"))
            self.assertFalse((Path(temp) / "wrong-candidate").exists())
            collected = collector.collect_result(request, result_json(), enrolled, "a" * 40, OwnedRoot(Path(temp) / "accepted"))
            self.assertEqual("pending", collected.state.value)
            self.assertEqual("pass", collected.observed_state.value)
            self.assertEqual("pass", collected.record.state.value)
            self.assertIn("must authenticate", collected.message)
            self.assertEqual("artifact_authentication_required", collected.blocker_code)
            self.assertIn("pending until it verifies", collected.next_step)
            self.assertEqual(1, len(list((Path(temp) / "accepted").rglob("*.json"))))
            catalog = load_acceptance_catalog(Path(__file__).parents[2] / "planning")
            report = acceptance_report(candidate_sha="a" * 40, traceability=catalog, records=[collected.record])
            ac01 = next(row for row in report["acceptance"] if row["acceptance_id"] == "AC01")
            self.assertEqual("pending", ac01["state"])
            self.assertFalse(report["evidence"][0]["trusted"])


if __name__ == "__main__":
    unittest.main()
