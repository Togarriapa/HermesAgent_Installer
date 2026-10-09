"""Evidence validation and acceptance aggregation for an exact installer candidate."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
import hashlib
import json
import re
from typing import Any, Callable, Iterable, Mapping
from pathlib import Path


class EvidenceState(StrEnum):
    PASS = "pass"
    FAIL = "fail"
    PENDING = "pending"
    BLOCKED = "blocked"
    SKIPPED = "skipped"


class EvidenceClass(StrEnum):
    FIXTURE = "fixture"
    NATIVE_ARM64 = "native-arm64"
    PHYSICAL_PI = "physical-pi"
    ACCOUNT = "account"
    SOURCE = "source"
    CONFIGURATION = "configuration"
    INVENTORY = "inventory"
    DOWNLOAD = "download"


@dataclass(frozen=True, slots=True)
class EvidenceRecord:
    evidence_id: str
    candidate_sha: str
    evidence_class: EvidenceClass
    state: EvidenceState
    platform: str
    target_id: str | None
    started_at: str
    finished_at: str
    command: str
    exit_code: int | None
    assertions: Mapping[str, bool] = field(default_factory=dict)
    artifact_sha256: str | None = None
    blocker: str | None = None
    resume_command: str | None = None

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "EvidenceRecord":
        try:
            record = cls(
                evidence_id=str(value["evidence_id"]),
                candidate_sha=str(value["candidate_sha"]),
                evidence_class=EvidenceClass(value["evidence_class"]),
                state=EvidenceState(value["state"]),
                platform=str(value["platform"]),
                target_id=_optional_text(value.get("target_id")),
                started_at=str(value["started_at"]),
                finished_at=str(value["finished_at"]),
                command=str(value["command"]),
                exit_code=value.get("exit_code"),
                assertions={str(k): v for k, v in value.get("assertions", {}).items()},
                artifact_sha256=_optional_text(value.get("artifact_sha256")),
                blocker=_optional_text(value.get("blocker")),
                resume_command=_optional_text(value.get("resume_command")),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError(f"invalid evidence record: {exc}") from exc
        record.validate()
        return record

    def validate(self) -> None:
        if not re.fullmatch(r"[0-9a-f]{40}", self.candidate_sha):
            raise ValueError("candidate_sha must be a full lowercase Git SHA")
        if not re.fullmatch(r"[A-Z0-9][A-Z0-9-]{2,63}", self.evidence_id):
            raise ValueError("evidence_id has invalid syntax")
        if not self.platform.strip() or not self.command.strip():
            raise ValueError("platform and command are required")
        start = _parse_time(self.started_at)
        end = _parse_time(self.finished_at)
        if end < start:
            raise ValueError("finished_at precedes started_at")
        if self.state == EvidenceState.PASS:
            if self.exit_code != 0 or not self.assertions or not all(self.assertions.values()):
                raise ValueError("pass requires exit_code 0 and non-empty all-true observed assertions")
            if not self.artifact_sha256 or not re.fullmatch(r"[0-9a-f]{64}", self.artifact_sha256):
                raise ValueError("pass requires a SHA-256 digest of retained evidence")
        if self.state in {EvidenceState.PENDING, EvidenceState.BLOCKED, EvidenceState.SKIPPED} and not self.blocker:
            raise ValueError("pending, blocked, and skipped evidence require an exact blocker")
        if self.evidence_class in {EvidenceClass.PHYSICAL_PI, EvidenceClass.ACCOUNT} and not self.target_id:
            raise ValueError("physical Pi and account evidence require an enrolled target identity")


def load_acceptance_catalog(planning_dir: str | Path) -> dict[str, Any]:
    """Load the baseline catalog and Sol-owned append-only acceptance amendments."""
    root = Path(planning_dir)
    baseline = json.loads((root / "traceability.json").read_text(encoding="utf-8"))
    additions = []
    amendment_files = (
        "resources-bundle-amendment.json",
        "remote-policy-read-amendment.json",
        "host-principal-custody-amendment.json",
    )
    for filename in amendment_files:
        path = root / filename
        if not path.exists():
            continue
        manifest = json.loads(path.read_text(encoding="utf-8"))
        requirements = {str(row["id"]): row for row in manifest.get("requirements", ()) if isinstance(row, Mapping) and row.get("id")}
        tasks = [row for row in manifest.get("tasks", ()) if isinstance(row, Mapping)]
        for item in manifest.get("acceptance", ()):
            if not isinstance(item, Mapping) or not item.get("id"):
                raise ValueError(f"invalid acceptance entry in {filename}")
            requirement_ids = list(item.get("requirement_ids", item.get("requirements", ())))
            if not requirement_ids:
                raise ValueError(f"acceptance {item['id']} has no linked requirements")
            task_ids = list(item.get("tasks", item.get("task_ids", ())))
            if not task_ids:
                wanted_requirements = set(requirement_ids)
                task_ids = [str(row["id"]) for row in tasks if wanted_requirements.intersection(row.get("requirement_ids", ())) or row.get("requirement") in wanted_requirements]
            evidence_ids = set()
            for requirement_id in requirement_ids:
                requirement = requirements.get(str(requirement_id), {})
                evidence_id = requirement.get("evidence_id")
                if isinstance(evidence_id, str) and evidence_id.startswith("EV-"):
                    evidence_ids.add(evidence_id)
            for task in tasks:
                if task.get("id") not in task_ids:
                    continue
                for key in ("evidence", "evidence_id"):
                    evidence_id = task.get(key)
                    if isinstance(evidence_id, str) and evidence_id.startswith("EV-"):
                        evidence_ids.add(evidence_id)
            if not evidence_ids:
                raise ValueError(f"acceptance {item['id']} has no linked evidence IDs")
            additions.append({
                "id": str(item["id"]),
                "text": str(item.get("method", item.get("text", ""))),
                "requirement_ids": requirement_ids,
                "task_ids": task_ids,
                "evidence_ids": sorted(evidence_ids),
                "workflow": f"hermes-installer verify --acceptance {item['id']} --target <authorized-target.json> --output <evidence-dir>",
            })
    combined = dict(baseline)
    combined["acceptance"] = list(baseline.get("acceptance", ()))
    existing_additional = {str(row.get("id")): dict(row) for row in baseline.get("additional_acceptance", ())}
    for addition in additions:
        acceptance_id = addition["id"]
        if acceptance_id in existing_additional:
            current = existing_additional[acceptance_id]
            for key in ("requirement_ids", "task_ids", "evidence_ids"):
                current[key] = sorted(set(current.get(key, ())) | set(addition.get(key, ())))
            current.setdefault("text", addition["text"])
            current.setdefault("workflow", addition["workflow"])
        else:
            existing_additional[acceptance_id] = addition
    combined["additional_acceptance"] = list(existing_additional.values())
    ids = [str(item.get("id")) for item in combined["acceptance"] + combined["additional_acceptance"]]
    if len(ids) != len(set(ids)):
        raise ValueError("acceptance catalog contains duplicate IDs")
    return combined


def acceptance_report(
    *, candidate_sha: str, traceability: Mapping[str, Any],
    records: Iterable[EvidenceRecord], required_acceptance_ids: Iterable[str] | None = None,
    verify_record: Callable[[EvidenceRecord], bool] | None = None,
) -> dict[str, Any]:
    """Build a report that keeps fixture and live target evidence in separate lanes."""
    if not re.fullmatch(r"[0-9a-f]{40}", candidate_sha):
        raise ValueError("candidate_sha must be a full lowercase Git SHA")
    criteria = list(traceability.get("acceptance", ())) + list(traceability.get("additional_acceptance", ()))
    by_id = {str(item["id"]): item for item in criteria}
    required = set(required_acceptance_ids or (f"AC{i:02d}" for i in range(1, 19)))
    if not required.issubset(by_id):
        raise ValueError(f"acceptance catalog is incomplete: {', '.join(sorted(required - by_id.keys()))}")
    accepted_records: dict[str, EvidenceRecord] = {}
    trusted_ids: set[str] = set()
    for item in records:
        item.validate()
        if item.candidate_sha != candidate_sha:
            raise ValueError(f"evidence {item.evidence_id} belongs to a different candidate")
        if item.evidence_id in accepted_records:
            raise ValueError(f"duplicate evidence id: {item.evidence_id}")
        accepted_records[item.evidence_id] = item
        if verify_record is not None:
            try:
                if verify_record(item):
                    trusted_ids.add(item.evidence_id)
            except Exception:
                # An unavailable or malfunctioning trust adapter never promotes evidence.
                pass

    workflows = []
    for acceptance_id in sorted(required):
        criterion = by_id[acceptance_id]
        wanted = set(criterion.get("evidence_ids", ()))
        related = [row for row in accepted_records.values() if row.evidence_id in wanted]
        trusted_related = [row for row in related if row.evidence_id in trusted_ids]
        functional = [row for row in trusted_related if row.evidence_class in {EvidenceClass.FIXTURE, EvidenceClass.NATIVE_ARM64, EvidenceClass.PHYSICAL_PI, EvidenceClass.ACCOUNT} and row.state == EvidenceState.PASS]
        target = [row for row in functional if row.evidence_class in {EvidenceClass.PHYSICAL_PI, EvidenceClass.ACCOUNT}]
        failures = [row for row in trusted_related if row.state == EvidenceState.FAIL]
        if failures:
            state = EvidenceState.FAIL
        elif wanted and wanted.issubset({row.evidence_id for row in functional}) and _target_requirements_met(acceptance_id, functional):
            state = EvidenceState.PASS
        else:
            state = EvidenceState.PENDING
        blocker = None if state == EvidenceState.PASS else _blocker(trusted_related, wanted)
        workflows.append({
            "acceptance_id": acceptance_id,
            "description": _safe_text(str(criterion.get("text", ""))),
            "state": state.value,
            "requirement_ids": list(criterion.get("requirement_ids", ())),
            "task_ids": list(criterion.get("task_ids", ())),
            "evidence_ids": sorted(wanted),
            "observed_evidence_ids": sorted(row.evidence_id for row in related),
            "fixture_state": _lane_state(trusted_related, EvidenceClass.FIXTURE),
            "native_arm64_state": _lane_state(trusted_related, EvidenceClass.NATIVE_ARM64),
            "target_state": _lane_state(trusted_related, EvidenceClass.PHYSICAL_PI, EvidenceClass.ACCOUNT),
            "blocker": blocker if not related or trusted_related else "Evidence artifacts have not been authenticated by an enrolled verifier",
            "resume_command": next((row.resume_command for row in related if row.resume_command), None),
        })
    full = all(item["state"] == EvidenceState.PASS.value for item in workflows)
    return {
        "schema_version": 1,
        "candidate_sha": candidate_sha,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "state": "pass" if full else "pending",
        "full_acceptance": full,
        "acceptance": workflows,
        "evidence": [_record_public_dict(row, trusted=row.evidence_id in trusted_ids) for row in sorted(accepted_records.values(), key=lambda row: row.evidence_id)],
    }


def write_report(path: str, report: Mapping[str, Any]) -> str:
    """Write only the allow-listed report model and return its content digest."""
    top_keys = {"schema_version", "candidate_sha", "generated_at", "state", "full_acceptance", "acceptance", "evidence"}
    if set(report) != top_keys:
        raise ValueError("report does not match the public evidence schema")
    acceptance_keys = {"acceptance_id", "description", "state", "requirement_ids", "task_ids", "evidence_ids", "observed_evidence_ids", "fixture_state", "native_arm64_state", "target_state", "blocker", "resume_command"}
    record_keys = {"evidence_id", "candidate_sha", "evidence_class", "state", "platform", "target_id", "started_at", "finished_at", "command", "exit_code", "assertions", "artifact_sha256", "blocker", "resume_command", "trusted"}
    if any(set(row) != acceptance_keys for row in report.get("acceptance", ())):
        raise ValueError("acceptance row does not match the public evidence schema")
    if any(set(row) != record_keys for row in report.get("evidence", ())):
        raise ValueError("evidence row does not match the public evidence schema")
    payload = json.dumps(_redact_secrets(dict(report)), sort_keys=True, indent=2).encode()
    digest = hashlib.sha256(payload).hexdigest()
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(payload + b"\n")
    return digest


def _record_public_dict(row: EvidenceRecord, *, trusted: bool) -> dict[str, Any]:
    data = asdict(row)
    data["evidence_class"] = row.evidence_class.value
    data["state"] = row.state.value
    data["trusted"] = trusted
    return _redact_secrets(data)


def _target_requirements_met(acceptance_id: str, rows: list[EvidenceRecord]) -> bool:
    required = {EvidenceClass.PHYSICAL_PI}
    if acceptance_id in {"AC13", "AC14", "AC15", "AC17"}:
        required.add(EvidenceClass.ACCOUNT)
    return all(any(row.evidence_class == kind for row in rows) for kind in required)


def _lane_state(rows: list[EvidenceRecord], *classes: EvidenceClass) -> str:
    lane = [row for row in rows if row.evidence_class in classes]
    if any(row.state == EvidenceState.FAIL for row in lane):
        return "fail"
    if any(row.state == EvidenceState.PASS for row in lane):
        return "pass"
    if lane and all(row.state == EvidenceState.SKIPPED for row in lane):
        return "skipped"
    return "pending"


def _blocker(rows: list[EvidenceRecord], wanted: set[str]) -> str:
    messages = [row.blocker for row in rows if row.blocker]
    if messages:
        return "; ".join(sorted(set(_safe_text(message) for message in messages)))
    missing = sorted(wanted - {row.evidence_id for row in rows})
    return "Required evidence is absent" + (f": {', '.join(missing)}" if missing else "; fixture-only evidence does not establish target acceptance")


def _safe_text(value: str) -> str:
    return _redact_secrets(value).strip()[:1000]


def _redact_secrets(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k): ("[REDACTED]" if re.search(r"secret|token|credential|password|api[_-]?key", str(k), re.I) else _redact_secrets(v)) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact_secrets(v) for v in value]
    if isinstance(value, str):
        value = re.sub(r"(?i)\b(Bearer\s+)[A-Za-z0-9._~+/-]+=*", r"\1[REDACTED]", value)
        return re.sub(r"(?i)(token|secret|password|api[_-]?key)=([^\s&,;]+)", r"\1=[REDACTED]", value)
    return value


def _optional_text(value: Any) -> str | None:
    return None if value is None else str(value)


def _parse_time(value: str) -> datetime:
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("timestamps must be ISO-8601") from exc
    if result.tzinfo is None:
        raise ValueError("timestamps must include a timezone")
    return result
