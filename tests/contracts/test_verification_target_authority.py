"""Receipt-journal regressions; these fixtures are not target acceptance."""
from __future__ import annotations

from dataclasses import asdict
import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import time

import pytest

from hermes_installer.authority.runtime_composition import RootAuthorityRuntime
from hermes_installer.evidence import EvidenceClass, EvidenceRecord, EvidenceState
from hermes_installer.verification.profiles import profile_for
from hermes_installer.verification.target_authority import (
    InstalledCandidateReceipt,
    RootObservationReceiptRegistry,
    RootTargetWorkflowAdmission,
    TargetAuthorityError,
    _SEAL,
    _RootReceiptJournal,
)


class _Service:
    key_id = "fixture-root-key"
    service_generation_digest = "a" * 64
    authority_epoch = "fixture-epoch"

    def __init__(self):
        self._key = b"fixture-only-key-material-which-is-32-bytes-long"

    @staticmethod
    def monotonic():
        return time.monotonic()

    def _sign(self, claims):
        return hmac.new(self._key, json.dumps(
            {"key_id": self.key_id, **claims}, sort_keys=True,
            separators=(",", ":"), ensure_ascii=True,
        ).encode("ascii"), hashlib.sha256).hexdigest()

    def _verify_signature(self, claims, signature):
        expected = self._sign(claims)
        if not hmac.compare_digest(expected, signature):
            raise ValueError("bad fixture signature")


class _Bindings:
    def __init__(self, path):
        info = path.stat()
        self.path = path
        self.device, self.inode = info.st_dev, info.st_ino

    def resolve_root_journal(self, root_id, *, expected_active_generation_digest):
        assert root_id == "authority-journal"
        assert expected_active_generation_digest == "a" * 64
        return type("Selection", (), {
            "path": self.path, "device": self.device, "inode": self.inode,
        })()


def _runtime(path):
    path.mkdir(mode=0o700)
    service = _Service()
    enrollment = type("Enrollment", (), {
        "protected_enrollment_digest": "a" * 64,
        "root_journal_root_records": ({"root_id": "authority-journal", "purpose": "authority-journal"},),
    })()
    bindings = _Bindings(path)
    return RootAuthorityRuntime(
        service=service, enrollment=enrollment, bindings=bindings,
        artifact_catalog=object(), vault=object(), boot_epoch="fixture-boot",
        backend_enrollments={}, body_recipes={}, scope_bindings={}, validators={},
        job_enrollments={}, job_authority=None,
    )


def _admission(candidate: InstalledCandidateReceipt) -> RootTargetWorkflowAdmission:
    now = time.monotonic()
    return RootTargetWorkflowAdmission(
        1, "admission_" + "a" * 32, "AC16", "host-fixture", "raspberry-pi-5-arm64", "b" * 64,
        candidate.candidate_git_sha, candidate.candidate_artifact_closure_sha256,
        "generation-fixture", "a" * 64, "principal-fixture", "intent-fixture",
        "nonce_" + "b" * 32, now, now + 60, "c" * 64,
    )


def _record(candidate_sha: str, target_id: str, artifact_sha: str) -> EvidenceRecord:
    profile = profile_for("EV-RB01", "AC16")
    return EvidenceRecord(
        evidence_id="EV-RB01", candidate_sha=candidate_sha,
        evidence_class=EvidenceClass.PHYSICAL_PI, state=EvidenceState.PENDING,
        platform="raspberry-pi-5-arm64", target_id=target_id,
        started_at="2026-10-09T00:00:00Z", finished_at="2026-10-09T00:00:01Z",
        command="installer.native_bundle_probe", exit_code=0,
        assertions={key: None for key in profile.assertions},
        artifact_sha256=artifact_sha, blocker="fixture only; no target acceptance",
    )


def test_root_receipt_journal_signs_once_and_rejects_tampering(tmp_path):
    runtime = _runtime(tmp_path / "root-journal")
    journal = _RootReceiptJournal(runtime, test_uid=os.getuid())
    handle = "admission_" + "a" * 32
    claims = {"schema": 1, "workflow_handle": handle, "candidate_git_sha": "d" * 40}
    digest = journal.put_once("admissions", handle, claims)
    actual, actual_digest = journal.get("admissions", handle)
    assert actual == claims
    assert actual_digest == digest
    with pytest.raises(TargetAuthorityError, match="already used"):
        journal.put_once("admissions", handle, claims)

    receipt = journal.directory / "admissions" / f"{handle}.json"
    receipt.write_bytes(receipt.read_bytes().replace(b'"candidate_git_sha":"' + b"d" * 40,
                                                      b'"candidate_git_sha":"' + b"e" * 40))
    with pytest.raises(TargetAuthorityError, match="signature is invalid"):
        journal.get("admissions", handle)


def test_signed_pending_root_observation_round_trips_and_is_not_promoted(tmp_path):
    runtime = _runtime(tmp_path / "root-journal")
    journal = _RootReceiptJournal(runtime, test_uid=os.getuid())
    candidate = InstalledCandidateReceipt(
        "candidate_" + "d" * 40, "d" * 40, "e" * 64, "f" * 64,
        "a" * 64, "b" * 64, "c" * 64, "selected-plan", "1" * 64, time.monotonic(),
    )

    class Candidates:
        def get_current(self, sha):
            assert sha == candidate.candidate_git_sha
            return candidate

    observations = RootObservationReceiptRegistry(runtime, journal, Candidates(), _seal=_SEAL)
    admission = _admission(candidate)
    admission_claims = asdict(admission)
    admission_claims.pop("signature_sha256")
    journal.put_once("admissions", admission.workflow_handle, admission_claims)
    artifact = {
        "schema_version": 1, "candidate_sha": candidate.candidate_git_sha,
        "target_id": admission.target_id, "platform": admission.platform,
        "evidence_id": "EV-RB01",
        "assertions": {key: None for key in profile_for("EV-RB01", "AC16").assertions},
    }
    artifact_bytes = json.dumps(artifact, sort_keys=True, separators=(",", ":")).encode()
    record = _record(candidate.candidate_git_sha, admission.target_id,
                     hashlib.sha256(artifact_bytes).hexdigest())
    journal.consume_once("admissions", admission.workflow_handle)
    false_artifact = dict(artifact)
    false_values = dict(artifact["assertions"])
    false_values[next(iter(false_values))] = False
    false_artifact["assertions"] = false_values
    false_bytes = json.dumps(false_artifact, sort_keys=True, separators=(",", ":")).encode()
    false_record = _record(candidate.candidate_git_sha, admission.target_id,
                           hashlib.sha256(false_bytes).hexdigest())
    false_record = EvidenceRecord(
        **{**asdict(false_record), "assertions": false_values},
    )
    with pytest.raises(TargetAuthorityError, match="false assertion"):
        observations._issue(observations._issuer, admission, false_record, false_bytes)
    result_handle = observations._issue(observations._issuer, admission, record, artifact_bytes)

    class Authorizer:
        target_id = admission.target_id
        platform_id = admission.platform

        def __init__(self):
            self.runtime = runtime

        @staticmethod
        def _ensure_current():
            # The fixture does not simulate kernel identity or enrollment.
            return None

    verified = observations.verify_result(admission.workflow_handle, result_handle,
                                          authorizer=Authorizer())
    assert verified.record.state is EvidenceState.PENDING
    assert all(value is None for value in verified.record.assertions.values())
    assert len(verified.assertion_receipt_handles) == len(profile_for("EV-RB01", "AC16").assertions)
    first = verified.assertion_receipt_handles[0]
    assertion_path = journal.directory / "assertions" / f"{first}.json"
    row = json.loads(assertion_path.read_text())
    row["claims"]["observed_value"] = True
    assertion_path.write_text(json.dumps(row, sort_keys=True, separators=(",", ":")))
    assertion_path.chmod(0o600)
    with pytest.raises(TargetAuthorityError, match="signature is invalid"):
        observations.verify_result(admission.workflow_handle, result_handle,
                                   authorizer=Authorizer())


def test_consumption_refuses_an_admission_without_a_signed_record(tmp_path):
    runtime = _runtime(tmp_path / "root-journal")
    journal = _RootReceiptJournal(runtime, test_uid=os.getuid())
    with pytest.raises(TargetAuthorityError, match="receipt is absent"):
        journal.consume_once("admissions", "admission_" + "f" * 32)


def test_signed_observation_envelope_allows_maximum_bounded_result(tmp_path):
    runtime = _runtime(tmp_path / "root-journal")
    journal = _RootReceiptJournal(runtime, test_uid=os.getuid())
    handle = "result_" + "c" * 32
    # Base64 storage must not make a valid, independently bounded result
    # impossible to retain in the same journal.
    result = b"{" + b"\"padding\":\"" + b"x" * 1_100_000 + b"\"}"
    claims = {
        "schema": 1,
        "bytes_b64": base64.b64encode(result).decode("ascii"),
        "sha256": hashlib.sha256(result).hexdigest(),
    }
    journal.put_once("observed-results", handle, claims)
    restored, _ = journal.get("observed-results", handle)
    assert base64.b64decode(restored["bytes_b64"]) == result
