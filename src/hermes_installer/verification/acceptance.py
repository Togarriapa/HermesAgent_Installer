"""Authorized target workflow interface. It never turns a plan into a pass."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import re
from typing import Callable, Mapping

from ..evidence import EvidenceRecord, EvidenceState
from ..state import OwnedRoot


@dataclass(frozen=True, slots=True)
class AuthorizedTarget:
    target_id: str
    platform: str
    owner: str
    authorization_reference: str
    expires_at: str
    allowed_acceptance: tuple[str, ...]
    manifest_sha256: str

    def ensure_current(self) -> None:
        """Recheck the signed enrollment expiry at each point of use."""
        if not isinstance(self.expires_at, str):
            raise ValueError("target authorization expiry is invalid")
        try:
            expiry = datetime.fromisoformat(self.expires_at.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("target authorization expiry is invalid") from exc
        if expiry.tzinfo is None or expiry <= datetime.now(timezone.utc):
            raise PermissionError("target authorization is expired or has no timezone")

    def validate(self) -> None:
        """Validate even directly constructed objects before authorization or effects."""
        if not isinstance(self.target_id, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{2,127}", self.target_id):
            raise ValueError("target_id must identify an enrolled target")
        if self.platform not in {"fixture-x86_64", "linux-arm64", "raspberry-pi-5-arm64"}:
            raise ValueError("target platform is not supported by the acceptance runner")
        if not isinstance(self.owner, str) or not self.owner.strip() or not isinstance(self.authorization_reference, str) or not self.authorization_reference.strip():
            raise ValueError("owner and authorization_reference are required")
        if not isinstance(self.manifest_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", self.manifest_sha256):
            raise ValueError("target manifest digest is required")
        if not isinstance(self.allowed_acceptance, tuple) or not self.allowed_acceptance or any(
            not isinstance(item, str) or not re.fullmatch(r"AC\d{2}", item)
            for item in self.allowed_acceptance
        ):
            raise ValueError("explicit acceptance scope is required")
        self.ensure_current()

    @classmethod
    def parse(cls, value: Mapping[str, object], *, manifest_sha256: str) -> "AuthorizedTarget":
        target = cls(
            target_id=str(value.get("target_id", "")),
            platform=str(value.get("platform", "")),
            owner=str(value.get("owner", "")),
            authorization_reference=str(value.get("authorization_reference", "")),
            expires_at=str(value.get("expires_at", "")),
            allowed_acceptance=tuple(str(item) for item in value.get("allowed_acceptance", ())),
            manifest_sha256=manifest_sha256,
        )
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{2,127}", target.target_id):
            raise ValueError("target_id must identify an enrolled target")
        if target.platform not in {"fixture-x86_64", "linux-arm64", "raspberry-pi-5-arm64"}:
            raise ValueError("target platform is not supported by the acceptance runner")
        if not target.owner.strip() or not target.authorization_reference.strip():
            raise ValueError("owner and authorization_reference are required")
        if not re.fullmatch(r"[0-9a-f]{64}", manifest_sha256):
            raise ValueError("target manifest digest is required")
        target.ensure_current()
        if not target.allowed_acceptance or any(not re.fullmatch(r"AC\d{2}", item) for item in target.allowed_acceptance):
            raise ValueError("explicit acceptance scope is required")
        return target


@dataclass(frozen=True, slots=True)
class WorkflowResult:
    acceptance_id: str
    state: EvidenceState
    message: str
    record: EvidenceRecord | None = None


class TargetWorkflowRunner:
    """Authorize targets and retain owner-run proof; never execute callback workflows."""

    def __init__(self, *, authorize: Callable[[AuthorizedTarget], bool]) -> None:
        self._authorize = authorize

    def run(self, acceptance_id: str, target: AuthorizedTarget, candidate_sha: str, output_dir: str) -> WorkflowResult:
        target.validate()
        if not self._authorize(target):
            raise PermissionError("target enrollment or owner authorization could not be verified")
        # Authorization callbacks may perform bounded remote checks. Recheck
        # expiry immediately before dispatch so those checks cannot consume the lease.
        target.ensure_current()
        if acceptance_id not in target.allowed_acceptance:
            raise PermissionError(f"target authorization does not include {acceptance_id}")
        if not re.fullmatch(r"AC\d{2}", acceptance_id):
            raise ValueError("invalid acceptance id")
        if not re.fullmatch(r"[0-9a-f]{40}", candidate_sha):
            raise ValueError("candidate_sha must be a full lowercase Git SHA")
        if not isinstance(output_dir, str) or not output_dir.strip():
            raise ValueError("an evidence output directory is required")
        return WorkflowResult(acceptance_id, EvidenceState.PENDING,
            "No structured owner-run result was supplied; no target effects were started.")

    def collect_result(
        self, request_value: Mapping[str, object], result_value: Mapping[str, object],
        target: AuthorizedTarget, candidate_sha: str, evidence_root: OwnedRoot,
    ) -> WorkflowResult:
        """Validate and retain a bounded owner-run observation without executing it."""
        from .operator_evidence import ProbeRequest, verify_operator_result

        target.validate()
        if not self._authorize(target):
            raise PermissionError("target enrollment or owner authorization could not be verified")
        target.ensure_current()
        request = ProbeRequest.from_dict(request_value)
        if request.acceptance_id not in target.allowed_acceptance:
            raise PermissionError(f"target authorization does not include {request.acceptance_id}")
        if request.candidate_sha != candidate_sha:
            raise ValueError("probe request is not bound to the selected candidate SHA")
        verified = verify_operator_result(request.to_dict(), result_value, target)
        record = verified.retain(evidence_root)
        return WorkflowResult(
            request.acceptance_id, record.state,
            "Structured target observation retained; an enrolled evidence verifier must authenticate the artifact before acceptance.",
            record,
        )
