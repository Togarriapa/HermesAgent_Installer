"""Production verify composition stays fixed, scoped, and unauthenticated by default."""

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from uuid import uuid4

from hermes_installer.evidence import EvidenceState
from hermes_installer.cli import build_parser, run
from hermes_installer.results import CommandResult, OutcomeState
from hermes_installer.verification.pi_lease import PiObservation, build_pi_read_only_lease, build_pi_contract_test_request
from hermes_installer.verification.runtime_workflows import load_target_scope, run_verify_cli


CHECKOUT = Path(__file__).resolve().parents[2]
GIT = "/usr/bin/git" if Path("/usr/bin/git").exists() else "/usr/local/bin/git"
SHA = subprocess.run(
    [GIT, "-C", str(CHECKOUT), "rev-parse", "--verify", "HEAD^{commit}"],
    check=True, capture_output=True, text=True,
).stdout.strip()


def lease_value():
    observed = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    from hermes_installer.verification.pi_lease import STAGING_PARENT, DEVICE_ID
    lease = build_pi_read_only_lease(PiObservation(
        device_id=DEVICE_ID, observed_at=observed, uid=1000, gid=1000, owner="admin",
        architecture="aarch64", model="Raspberry Pi 5 Model B Rev 1.1",
        staging_root=f"{STAGING_PARENT}/ev-rb08-{SHA[:12]}",
        staging_uid=1000, staging_gid=1000, staging_mode=0o700, staging_is_symlink=False,
        temporary_source_link_absent=True, checkout_sha=SHA,
    ), candidate_sha=SHA)
    return lease


def write_lease(path: Path):
    path.write_text(json.dumps(lease_value().to_manifest(), sort_keys=True), encoding="utf-8")
    path.chmod(0o600)
    return load_target_scope(path)


def result_for(request):
    canonical = lambda value: json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    sha = lambda value: hashlib.sha256(value).hexdigest()
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    return {
        "schema_version": 1,
        "request_id": request.request_id,
        "request_sha256": request.request_sha256,
        "acceptance_id": request.acceptance_id,
        "evidence_id": request.evidence_id,
        "candidate_sha": request.candidate_sha,
        "target_id": request.target_id,
        "platform": request.platform,
        "owner": "admin",
        "authorization_reference": request.authorization_reference,
        "started_at": now,
        "finished_at": now,
        "exit_code": 0,
        "timed_out": False,
        "argv_sha256": sha(canonical({"argv": list(request.argv)})),
        "cwd_sha256": sha(request.cwd.encode()),
        "environment_names": ["PATH", "PYTHONPATH", "PYTHONDONTWRITEBYTECODE"],
        "stdout_sha256": sha(b""),
        "stderr_sha256": sha(b""),
        "stdout_bytes": 0,
        "stderr_bytes": 0,
        "output_truncated": False,
        "assertions": {name: None for name in request.expected_assertions},
        "effects": [],
    }


class RuntimeWorkflowTests(unittest.TestCase):
    def test_verify_cli_exposes_only_fixed_workflow_and_result_inputs(self):
        args = build_parser().parse_args([
            "verify", "--target", "scope.json", "--output", "evidence",
            "--acceptance", "AC16", "--request", "request.json", "--result", "result.json",
        ])
        self.assertEqual("verify", args.command)
        self.assertEqual(["AC16"], args.acceptance)
        self.assertEqual(Path("request.json"), args.request)
        with self.assertRaises(SystemExit):
            build_parser().parse_args(["verify", "--target", "scope.json", "--output", "evidence", "--acceptance", "AC00"])

    def test_cli_run_dispatches_to_fixed_verifier_with_only_parsed_paths_and_ids(self):
        args = build_parser().parse_args([
            "verify", "--target", "scope.json", "--output", "evidence", "--acceptance", "AC16",
        ])
        expected = CommandResult("verify", OutcomeState.PENDING, "test pending")
        with patch("hermes_installer.cli._configuration", return_value=object()), \
                patch("hermes_installer.verification.runtime_workflows.run_verify_cli", return_value=expected) as dispatch:
            result = run(args)
        self.assertIs(result, expected)
        kwargs = dispatch.call_args.kwargs
        self.assertEqual(Path("scope.json"), kwargs["target_path"])
        self.assertEqual(Path("evidence"), kwargs["output_path"])
        self.assertEqual(("AC16",), kwargs["requested_acceptance"])
        self.assertIsNone(kwargs["request_path"])
        self.assertIsNone(kwargs["result_path"])

    def test_private_pi_lease_is_exact_scope_not_a_cryptographic_grant(self):
        with tempfile.TemporaryDirectory() as directory:
            manifest = Path(directory) / "pi-lease.json"
            scope = write_lease(manifest)
            self.assertEqual("PI-HERMES", scope.target.target_id)
            self.assertFalse(scope.lease.cryptographic_grant)
            self.assertFalse(scope.lease.authorization_signature_verified)
            self.assertEqual(SHA, scope.lease.candidate_sha)

    def test_local_ac16_workflow_runs_only_after_exact_candidate_and_scope_checks(self):
        with tempfile.TemporaryDirectory() as directory:
            manifest = Path(directory) / "pi-lease.json"
            write_lease(manifest)
            output = Path(directory) / "output"
            with patch("hermes_installer.verification.runtime_workflows._local_owner_scope_matches", return_value=True):
                result = run_verify_cli(target_path=manifest, output_path=output, checkout=CHECKOUT)
            self.assertEqual(EvidenceState.PENDING.value, result.state.value)
            self.assertTrue(any(item.code == "verify.ac16" for item in result.findings))
            report_finding = next(item for item in result.findings if item.code == "verify.report")
            report = json.loads(Path(report_finding.details["path"]).read_text(encoding="utf-8"))
            self.assertFalse(report["full_acceptance"])
            self.assertEqual("pending", report["state"])
            rb01 = next(item for item in report["evidence"] if item["evidence_id"] == "EV-RB01")
            self.assertFalse(rb01["trusted"])
            self.assertEqual("pass", rb01["state"])

    def test_cli_structurally_verifies_and_retains_operator_result_without_promoting_auth(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            scope = write_lease(root / "pi-lease.json")
            request = build_pi_contract_test_request(scope.lease, python_executable="/usr/bin/python3.14")
            request_path = root / "request.json"
            request_path.write_text(json.dumps(request.to_dict()), encoding="utf-8")
            result_path = root / "result.json"
            result_path.write_text(json.dumps(result_for(request)), encoding="utf-8")
            output = root / "output"
            result = run_verify_cli(
                target_path=root / "pi-lease.json", output_path=output, checkout=CHECKOUT,
                request_path=request_path, result_path=result_path,
            )
            self.assertEqual(EvidenceState.PENDING.value, result.state.value)
            finding = next(item for item in result.findings if item.code == "verify.operator-result")
            self.assertEqual(request.request_sha256, finding.details["request_sha256"])
            self.assertFalse(finding.details["operator_authenticated"])
            report_finding = next(item for item in result.findings if item.code == "verify.report")
            report = json.loads(Path(report_finding.details["path"]).read_text(encoding="utf-8"))
            rb08 = next(item for item in report["evidence"] if item["evidence_id"] == "EV-RB08")
            self.assertFalse(rb08["trusted"])
            self.assertEqual("pending", rb08["state"])
            self.assertTrue(all(value is None for value in rb08["assertions"].values()))
            self.assertEqual(12, len(rb08["assertions"]))
            self.assertFalse(rb08["trusted"])

    def test_operator_request_scope_mismatch_is_rejected_without_retention(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            scope = write_lease(root / "pi-lease.json")
            request = build_pi_contract_test_request(scope.lease, python_executable="/usr/bin/python3.14")
            request_value = request.to_dict()
            request_value["cwd"] = "/tmp/unrelated"
            request_path = root / "request.json"
            request_path.write_text(json.dumps(request_value), encoding="utf-8")
            result_path = root / "result.json"
            result_path.write_text(json.dumps(result_for(request)), encoding="utf-8")
            output = root / "output"
            result = run_verify_cli(target_path=root / "pi-lease.json", output_path=output,
                                    checkout=CHECKOUT, request_path=request_path, result_path=result_path)
            self.assertEqual("failed", result.state.value)
            self.assertIn("rejected", result.message)
            self.assertFalse(output.exists())

    def test_tampered_or_nonprivate_scope_manifest_is_rejected_before_output(self):
        with tempfile.TemporaryDirectory() as directory:
            manifest = Path(directory) / "pi-lease.json"
            scope = write_lease(manifest)
            value = json.loads(manifest.read_text(encoding="utf-8"))
            value["candidate_sha"] = "0" * 40
            manifest.write_text(json.dumps(value), encoding="utf-8")
            manifest.chmod(0o600)
            with self.assertRaisesRegex(ValueError, "digest"):
                load_target_scope(manifest)

            write_lease(manifest)
            manifest.chmod(0o644)
            with self.assertRaisesRegex(PermissionError, "mode 0600"):
                load_target_scope(manifest)

    def test_digest_valid_but_wrong_typed_or_expired_lease_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            manifest = Path(directory) / "pi-lease.json"
            write_lease(manifest)
            for mutation, message in (
                (lambda value: value.__setitem__("cryptographic_grant", 0), "invalid types"),
                (lambda value: value.__setitem__("expires_at", "2000-01-01T00:00:00Z"), "action bounds"),
            ):
                write_lease(manifest)
                value = json.loads(manifest.read_text(encoding="utf-8"))
                value.pop("manifest_sha256")
                mutation(value)
                canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
                value["manifest_sha256"] = hashlib.sha256(canonical).hexdigest()
                manifest.write_text(json.dumps(value), encoding="utf-8")
                manifest.chmod(0o600)
                with self.assertRaisesRegex(ValueError, message):
                    load_target_scope(manifest)


if __name__ == "__main__":
    unittest.main()
