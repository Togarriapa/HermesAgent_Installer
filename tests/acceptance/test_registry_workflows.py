"""The fixed AC16 registry workflow exercises the shipped bundle, not a stub."""

from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from hermes_installer.evidence import EvidenceState
from hermes_installer.verification.acceptance import AuthorizedTarget, TargetWorkflowRunner
from hermes_installer.verification.profiles import profile_for
from hermes_installer.verification.registry_workflows import build_fixed_workflows


CHECKOUT = Path(__file__).resolve().parents[2]
GIT = "/usr/bin/git" if Path("/usr/bin/git").exists() else "/usr/local/bin/git"
SHA = subprocess.run(
    [GIT, "-C", str(CHECKOUT), "rev-parse", "--verify", "HEAD^{commit}"],
    check=True, capture_output=True, text=True,
).stdout.strip()


def fixture_target() -> AuthorizedTarget:
    return AuthorizedTarget.parse({
        "target_id": "fixture-native-registry-01",
        "platform": "fixture-x86_64",
        "owner": "fixture-owner",
        "authorization_reference": "fixture-enrollment-01",
        "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
        "allowed_acceptance": ["AC16"],
    }, manifest_sha256=hashlib.sha256(b"native workflow fixture enrollment").hexdigest())


class RegistryWorkflowTests(unittest.TestCase):
    def test_ac16_adapter_verifies_and_materializes_the_actual_packaged_registry(self):
        target = fixture_target()
        workflows = build_fixed_workflows(checkout=CHECKOUT, candidate_sha=SHA)
        self.assertEqual({"AC16"}, set(workflows))
        with tempfile.TemporaryDirectory() as directory:
            result = TargetWorkflowRunner(workflows, authorize=lambda _target: True).run(
                "AC16", target, SHA, str(Path(directory) / "evidence"),
            )
            self.assertEqual(EvidenceState.PENDING, result.state)
            self.assertEqual(EvidenceState.PASS, result.record.state)
            expected = set(profile_for("EV-RB01", "AC16").assertions)
            self.assertEqual(expected, set(result.record.assertions))
            self.assertTrue(all(result.record.assertions.values()))
            self.assertEqual(hashlib.sha256(
                (Path(directory) / "evidence" / "evidence" / "native-bundle" /
                 target.target_id / f"{SHA}.json").read_bytes()
            ).hexdigest(), result.record.artifact_sha256)
            summary = json.loads((Path(directory) / "evidence" / "evidence" / "native-bundle" /
                                  target.target_id / f"{SHA}.json").read_text(encoding="utf-8"))
            self.assertEqual("EV-RB01", summary["evidence_id"])
            self.assertEqual(SHA, summary["candidate_sha"])
            self.assertGreater(summary["resource_count"], 0)
            self.assertGreater(summary["materialized_file_count"], summary["resource_count"])
            self.assertTrue(summary["crosswalk_complete"])
            self.assertFalse(summary["network_access_performed"])
            self.assertIn("verifier authentication", result.message)

    def test_packaged_bundle_workflow_does_not_use_network_and_candidate_is_exact(self):
        workflow = build_fixed_workflows(checkout=CHECKOUT, candidate_sha=SHA)["AC16"]
        target = fixture_target()
        with tempfile.TemporaryDirectory() as directory, patch.object(
            socket, "create_connection", side_effect=AssertionError("network attempted")
        ), patch.object(
            socket, "socket", side_effect=AssertionError("network attempted")
        ):
            record = workflow(target, str(Path(directory) / "evidence"))
            self.assertEqual(EvidenceState.PASS, record.state)

        wrong_sha = "0" * 40 if SHA != "0" * 40 else "1" * 40
        wrong_candidate_workflow = build_fixed_workflows(
            checkout=CHECKOUT, candidate_sha=wrong_sha,
        )["AC16"]
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "does not match"):
                wrong_candidate_workflow(target, str(Path(directory) / "evidence"))
            self.assertFalse((Path(directory) / "evidence").exists())

    def test_existing_evidence_artifact_cannot_be_overwritten_after_tampering(self):
        target = fixture_target()
        workflow = build_fixed_workflows(checkout=CHECKOUT, candidate_sha=SHA)["AC16"]
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "evidence"
            workflow(target, str(output))
            artifact = output / "evidence" / "native-bundle" / target.target_id / f"{SHA}.json"
            artifact.write_text("tampered\n", encoding="utf-8")
            with self.assertRaisesRegex(PermissionError, "differs"):
                workflow(target, str(output))


if __name__ == "__main__":
    unittest.main()
