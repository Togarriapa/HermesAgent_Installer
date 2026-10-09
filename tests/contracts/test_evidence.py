"""Evidence aggregation must never convert a fixture or skipped run to acceptance."""

import unittest

from hermes_installer.evidence import EvidenceRecord, acceptance_report, load_acceptance_catalog, write_report


SHA = "a" * 40
NOW = "2026-10-09T17:00:00+00:00"


def record(evidence_id="EV-R0169", evidence_class="fixture", state="pass", **overrides):
    value = {
        "evidence_id": evidence_id,
        "candidate_sha": SHA,
        "evidence_class": evidence_class,
        "state": state,
        "platform": "linux-x86_64-fixture",
        "target_id": None,
        "started_at": NOW,
        "finished_at": NOW,
        "command": "python -m unittest tests.contracts.test_evidence",
        "exit_code": 0,
        "assertions": {"unrelated_bytes_preserved": True, "owned_generation_activated": True},
        "artifact_sha256": "b" * 64,
        "blocker": None,
        "resume_command": None,
    }
    value.update(overrides)
    return EvidenceRecord.from_dict(value)


def criterion_catalog():
    return {
        "requirements": [{"id": "R0169", "change": "verification-documentation", "task_id": "VD-R0169", "state": "specified; implementation-pending"}],
        "evidence": [{"id": "EV-R0169", "requirement_ids": ["R0169"], "task_ids": ["VD-R0169"]}],
        "acceptance": [
            {"id": f"AC{i:02d}", "text": f"criterion {i}", "evidence_ids": [f"EV-R{168+i:04d}"]}
            for i in range(1, 13)
        ],
        "additional_acceptance": [
            {"id": f"AC{i:02d}", "text": f"criterion {i}", "evidence_ids": [f"EV-R{195+i:04d}"]}
            for i in range(13, 16)
        ] + [
            {"id": f"AC{i:02d}", "text": f"criterion {i}", "evidence_ids": [f"EV-AMENDMENT-{i:02d}"]}
            for i in range(16, 19)
        ],
    }


class EvidenceContractTests(unittest.TestCase):
    def test_fixture_pass_is_reported_but_never_full_target_acceptance(self):
        report = acceptance_report(candidate_sha=SHA, traceability=criterion_catalog(), records=[record()], verify_record=lambda _: True)
        self.assertEqual(report["state"], "pending")
        self.assertEqual(report["acceptance"][0]["fixture_state"], "pass")
        self.assertEqual(report["acceptance"][0]["target_state"], "pending")
        self.assertEqual(report["acceptance"][0]["physical_pi_state"], "pending")
        self.assertEqual(report["acceptance"][0]["account_state"], "pending")
        requirement = next(row for row in report["requirements"] if row["requirement_id"] == "R0169")
        self.assertEqual(requirement["evidence_state"], "pass")
        self.assertEqual(requirement["state"], "pending")

    def test_skip_and_config_only_cannot_be_pass_evidence(self):
        configured = record(evidence_class="configuration")
        skipped = record(evidence_id="EV-R0170", state="skipped", exit_code=None, assertions={}, artifact_sha256=None, blocker="hardware lane not enrolled")
        report = acceptance_report(candidate_sha=SHA, traceability=criterion_catalog(), records=[configured, skipped], verify_record=lambda _: True)
        self.assertEqual(report["acceptance"][0]["state"], "pending")
        self.assertEqual(report["acceptance"][0]["target_state"], "pending")

    def test_prepopulated_pass_without_trusted_verifier_remains_pending(self):
        report = acceptance_report(candidate_sha=SHA, traceability=criterion_catalog(), records=[record()])
        self.assertFalse(report["evidence"][0]["trusted"])
        self.assertEqual(report["acceptance"][0]["state"], "pending")
        self.assertIn("not been authenticated", report["acceptance"][0]["blocker"])
        requirement = next(row for row in report["requirements"] if row["requirement_id"] == "R0169")
        self.assertEqual(requirement["evidence_state"], "pending")

    def test_candidate_mismatch_and_empty_catalog_fail_closed(self):
        with self.assertRaisesRegex(ValueError, "different candidate"):
            acceptance_report(candidate_sha=SHA, traceability=criterion_catalog(), records=[record(candidate_sha="c" * 40)], required_acceptance_ids=["AC01"])
        with self.assertRaisesRegex(ValueError, "catalog is incomplete"):
            acceptance_report(candidate_sha=SHA, traceability={"acceptance": [], "additional_acceptance": []}, records=[])

    def test_report_redacts_secret_fields_and_values(self):
        from tempfile import TemporaryDirectory
        from pathlib import Path
        with TemporaryDirectory() as directory:
            blocked = record(state="blocked", exit_code=None, assertions={}, artifact_sha256=None, blocker="token=canary-secret")
            report = acceptance_report(candidate_sha=SHA, traceability=criterion_catalog(), records=[blocked])
            digest = write_report(str(Path(directory) / "evidence.json"), report)
            saved = (Path(directory) / "evidence.json").read_text()
            self.assertNotIn("canary-secret", saved)
            self.assertIn("[REDACTED]", saved)
            self.assertEqual(len(digest), 64)
            with self.assertRaisesRegex(ValueError, "public evidence schema"):
                write_report(str(Path(directory) / "bad.json"), {**report, "api_token": "canary-secret"})

    def test_amendment_loader_builds_acceptance_16_to_18_from_task_graph(self):
        import json
        from pathlib import Path
        from tempfile import TemporaryDirectory
        with TemporaryDirectory() as directory:
            root = Path(directory)
            traceability = criterion_catalog()
            traceability["additional_acceptance"] = [row for row in traceability["additional_acceptance"] if row["id"] < "AC16"]
            traceability["additional_acceptance"].append({"id": "AC16", "text": "existing Sol row", "requirement_ids": ["RB01"], "task_ids": ["RB-T01"], "evidence_ids": ["EV-RB01"]})
            (root / "traceability.json").write_text(json.dumps(traceability))
            manifests = {
                "resources-bundle-amendment.json": {"requirements": [{"id": "RB01"}], "tasks": [{"id": "RB-T01", "requirement": "RB01", "evidence": "EV-RB01"}], "acceptance": [{"id": "AC16", "requirements": ["RB01"], "tasks": ["RB-T01"], "method": "offline native source bundle"}]},
                "remote-policy-read-amendment.json": {"requirements": [{"id": "RP01", "evidence_id": "EV-RP01"}], "tasks": [{"id": "RP-T01", "requirement": "RP01"}], "acceptance": [{"id": "AC17", "requirements": ["RP01"], "method": "fresh account policy and revocation"}]},
                "host-principal-custody-amendment.json": {"requirements": [{"id": "HI01", "evidence_id": "EV-HI01"}], "tasks": [{"id": "HI-T01", "requirement_ids": ["HI01"]}], "acceptance": [{"id": "AC18", "requirement_ids": ["HI01"], "method": "native host custody"}]},
            }
            for name, value in manifests.items():
                (root / name).write_text(json.dumps(value))
            catalog = load_acceptance_catalog(root)
            additions = {row["id"]: row for row in catalog["additional_acceptance"] if row["id"] in {"AC16", "AC17", "AC18"}}
            self.assertEqual(set(additions), {"AC16", "AC17", "AC18"})
            self.assertEqual(additions["AC16"]["evidence_ids"], ["EV-RB01"])
            self.assertEqual(additions["AC16"]["text"], "existing Sol row")
            self.assertEqual(additions["AC17"]["task_ids"], ["RP-T01"])
            self.assertEqual(additions["AC18"]["evidence_ids"], ["EV-HI01"])
            self.assertIn("RB01", {row["id"] for row in catalog["requirements"]})
            self.assertIn("EV-HI01", {row["id"] for row in catalog["evidence"]})


if __name__ == "__main__":
    unittest.main()
