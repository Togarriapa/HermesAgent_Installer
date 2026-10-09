"""Evidence aggregation must never convert a fixture or skipped run to acceptance."""

from datetime import datetime, timezone
import json

import pytest

from hermes_installer.evidence import EvidenceRecord, acceptance_report, write_report


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
        "command": "python -m pytest tests/contracts/test_evidence.py",
        "exit_code": 0,
        "assertions": {"unrelated_bytes_preserved": True, "owned_generation_activated": True},
        "artifact_sha256": "b" * 64,
        "blocker": None,
        "resume_command": None,
    }
    value.update(overrides)
    return EvidenceRecord.from_dict(value)


def criterion_catalog():
    return {"acceptance": [{"id": f"AC{i:02d}", "text": f"criterion {i}", "evidence_ids": [f"EV-R{168+i:04d}"]} for i in range(1, 13)], "additional_acceptance": [{"id": f"AC{i:02d}", "text": f"criterion {i}", "evidence_ids": []} for i in range(13, 16)]}


def test_fixture_pass_is_reported_but_never_full_target_acceptance():
    report = acceptance_report(candidate_sha=SHA, traceability=criterion_catalog(), records=[record()])
    assert report["state"] == "pending"
    assert report["acceptance"][0]["fixture_state"] == "pass"
    assert report["acceptance"][0]["target_state"] == "pending"


def test_skip_and_config_only_cannot_be_pass_evidence():
    with pytest.raises(ValueError, match="pass requires"):
        record(evidence_class="configuration")
    skipped = record(state="skipped", exit_code=None, assertions={}, artifact_sha256=None, blocker="hardware lane not enrolled")
    report = acceptance_report(candidate_sha=SHA, traceability=criterion_catalog(), records=[skipped])
    assert report["acceptance"][0]["state"] == "pending"


def test_candidate_mismatch_and_empty_catalog_fail_closed():
    with pytest.raises(ValueError, match="different candidate"):
        acceptance_report(candidate_sha=SHA, traceability=criterion_catalog(), records=[record(candidate_sha="c" * 40)])
    with pytest.raises(ValueError, match="catalog is incomplete"):
        acceptance_report(candidate_sha=SHA, traceability={"acceptance": [], "additional_acceptance": []}, records=[])


def test_report_redacts_secret_fields_and_values(tmp_path):
    data = record().__dict__ if hasattr(record(), "__dict__") else None
    report = {"summary": "Authorization Bearer abcdefghijklmnop token=canary-secret", "api_token": "canary-secret"}
    digest = write_report(str(tmp_path / "evidence.json"), report)
    saved = (tmp_path / "evidence.json").read_text()
    assert "canary-secret" not in saved
    assert "[REDACTED]" in saved
    assert len(digest) == 64
