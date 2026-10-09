"""Authorized target workflow interface. It never turns a plan into a pass."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
import re
from typing import Callable, Mapping

from ..evidence import EvidenceRecord, EvidenceState


@dataclass(frozen=True, slots=True)
class AuthorizedTarget:
    target_id: str
    platform: str
    owner: str
    authorization_reference: str
    expires_at: str
    allowed_acceptance: tuple[str, ...]
    manifest_sha256: str

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
        expiry = datetime.fromisoformat(target.expires_at.replace("Z", "+00:00"))
        if expiry.tzinfo is None or expiry <= datetime.now(timezone.utc):
            raise ValueError("target authorization is expired or has no timezone")
        if not target.allowed_acceptance or any(not re.fullmatch(r"AC\d{2}", item) for item in target.allowed_acceptance):
            raise ValueError("explicit acceptance scope is required")
        return target


@dataclass(frozen=True, slots=True)
class WorkflowResult:
    acceptance_id: str
    state: EvidenceState
    message: str
    record: EvidenceRecord | None = None


Workflow = Callable[[AuthorizedTarget, str], EvidenceRecord]


class TargetWorkflowRunner:
    """Dispatch only explicitly registered, target-scoped probes; no shell strings."""

    def __init__(self, workflows: Mapping[str, Workflow], authorize: Callable[[AuthorizedTarget], bool]) -> None:
        self._workflows = dict(workflows)
        self._authorize = authorize

    def run(self, acceptance_id: str, target: AuthorizedTarget, candidate_sha: str, output_dir: str) -> WorkflowResult:
        if not self._authorize(target):
            raise PermissionError("target enrollment or owner authorization could not be verified")
        if acceptance_id not in target.allowed_acceptance:
            raise PermissionError(f"target authorization does not include {acceptance_id}")
        if not re.fullmatch(r"AC\d{2}", acceptance_id):
            raise ValueError("invalid acceptance id")
        if not re.fullmatch(r"[0-9a-f]{40}", candidate_sha):
            raise ValueError("candidate_sha must be a full lowercase Git SHA")
        workflow = self._workflows.get(acceptance_id)
        if workflow is None:
            return WorkflowResult(acceptance_id, EvidenceState.PENDING, "No functional probe is registered; no target effects occurred.")
        record = workflow(target, str(Path(output_dir)))
        record.validate()
        if record.candidate_sha != candidate_sha or record.target_id != target.target_id:
            raise ValueError("probe evidence is not bound to the selected candidate and target")
        return WorkflowResult(acceptance_id, record.state, record.blocker or "Workflow evidence recorded.", record)
