"""Strict request/result contract for owner-run target acceptance probes.

This module does not execute commands or claim that an operator transcript is
authentic by itself. It binds a bounded probe request to a structured operator
result, verifies exact candidate/target/command/assertion metadata, and emits a
retained evidence record. Promotion to trusted acceptance still requires an
enrolled verifier in :mod:`hermes_installer.evidence`.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
import re
import stat
from typing import Any, Mapping
from uuid import UUID

from ..evidence import EvidenceClass, EvidenceRecord, EvidenceState
from .acceptance import AuthorizedTarget
from ..state import OwnedRoot
from .profiles import profile_for


_SHA40 = re.compile(r"[0-9a-f]{40}\Z")
_SHA64 = re.compile(r"[0-9a-f]{64}\Z")
_EVIDENCE_ID = re.compile(r"[A-Z0-9][A-Z0-9-]{2,63}\Z")
_ACCEPTANCE_ID = re.compile(r"AC\d{2}\Z")
_SHELLS = {"sh", "bash", "dash", "zsh", "fish", "csh", "tcsh"}
_SECRET_NAME = re.compile(r"secret|token|credential|password|passwd|api[_-]?key|authorization", re.I)


_PLATFORM_CLASS = {
    "fixture-x86_64": EvidenceClass.FIXTURE,
    "linux-arm64": EvidenceClass.NATIVE_ARM64,
    "raspberry-pi-5-arm64": EvidenceClass.PHYSICAL_PI,
}


def _canonical(value: Mapping[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _timestamp(value: object, label: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be an ISO-8601 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{label} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{label} must include a timezone")
    return parsed.astimezone(timezone.utc)


@dataclass(frozen=True, slots=True)
class ProbeRequest:
    """One bounded, target-owner-executed command; values never include secrets."""

    request_id: str
    acceptance_id: str
    evidence_id: str
    candidate_sha: str
    target_id: str
    platform: str
    authorization_reference: str
    target_manifest_sha256: str
    argv: tuple[str, ...]
    cwd: str
    environment_allowlist: tuple[str, ...]
    timeout_seconds: int
    stdout_limit_bytes: int
    stderr_limit_bytes: int
    expected_assertions: tuple[str, ...]
    evidence_class: EvidenceClass
    schema_version: int = 1

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ProbeRequest":
        if not isinstance(value, Mapping):
            raise ValueError("probe request must be a JSON object")
        allowed = {
            "schema_version", "request_id", "acceptance_id", "evidence_id", "candidate_sha",
            "target_id", "platform", "authorization_reference", "target_manifest_sha256",
            "argv", "cwd", "environment_allowlist", "timeout_seconds", "stdout_limit_bytes",
            "stderr_limit_bytes", "expected_assertions", "evidence_class",
        }
        if set(value) != allowed:
            raise ValueError("probe request fields do not match the versioned schema")
        for name in ("argv", "environment_allowlist", "expected_assertions"):
            if not isinstance(value[name], list) or any(not isinstance(item, str) for item in value[name]):
                raise ValueError(f"{name} must be a JSON string array")
        for name in ("request_id", "acceptance_id", "evidence_id", "candidate_sha", "target_id", "platform", "authorization_reference", "target_manifest_sha256", "cwd", "evidence_class"):
            if not isinstance(value[name], str):
                raise ValueError(f"{name} must be a string")
        try:
            request = cls(
                request_id=value["request_id"], acceptance_id=value["acceptance_id"],
                evidence_id=value["evidence_id"], candidate_sha=value["candidate_sha"],
                target_id=value["target_id"], platform=value["platform"],
                authorization_reference=value["authorization_reference"],
                target_manifest_sha256=value["target_manifest_sha256"],
                argv=tuple(value["argv"]), cwd=value["cwd"],
                environment_allowlist=tuple(value["environment_allowlist"]),
                timeout_seconds=value["timeout_seconds"], stdout_limit_bytes=value["stdout_limit_bytes"],
                stderr_limit_bytes=value["stderr_limit_bytes"],
                expected_assertions=tuple(value["expected_assertions"]),
                evidence_class=EvidenceClass(value["evidence_class"]), schema_version=value["schema_version"],
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError(f"invalid probe request: {exc}") from exc
        request.validate()
        return request

    def validate(self) -> None:
        if self.schema_version != 1:
            raise ValueError("unsupported probe request schema_version")
        try:
            if str(UUID(self.request_id)) != self.request_id:
                raise ValueError
        except (ValueError, TypeError, AttributeError):
            raise ValueError("request_id must be a UUID") from None
        if not _ACCEPTANCE_ID.fullmatch(self.acceptance_id):
            raise ValueError("acceptance_id is invalid")
        if not _EVIDENCE_ID.fullmatch(self.evidence_id):
            raise ValueError("evidence_id is invalid")
        profile = profile_for(self.evidence_id, self.acceptance_id)
        if self.expected_assertions != profile.assertions:
            raise ValueError("expected_assertions must exactly match the installer-owned evidence profile")
        if not _SHA40.fullmatch(self.candidate_sha):
            raise ValueError("candidate_sha must be a full lowercase Git SHA")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{2,127}", self.target_id):
            raise ValueError("target_id must identify an enrolled target")
        if self.platform not in {"fixture-x86_64", "linux-arm64", "raspberry-pi-5-arm64"}:
            raise ValueError("platform is unsupported")
        if self.evidence_class != _PLATFORM_CLASS[self.platform]:
            raise ValueError("evidence_class is determined by the enrolled target platform")
        if (not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/-]{2,127}", self.authorization_reference)
                or _SECRET_NAME.search(self.authorization_reference)
                or not _SHA64.fullmatch(self.target_manifest_sha256)):
            raise ValueError("authorization reference and target manifest digest are required")
        if not self.argv or len(self.argv) > 64 or any(not isinstance(part, str) or not part or "\x00" in part for part in self.argv):
            raise ValueError("argv must contain 1 to 64 non-empty NUL-free arguments")
        if any(len(part.encode("utf-8")) > 4096 for part in self.argv) or sum(len(part.encode("utf-8")) for part in self.argv) > 32768:
            raise ValueError("argv exceeds the bounded request size")
        if not self.argv[0].startswith("/") or ".." in self.argv[0].split("/"):
            raise ValueError("probe executable must be an absolute normalized target path")
        if self.argv[0].rsplit("/", 1)[-1].lower() in _SHELLS:
            raise ValueError("shell interpreters are not accepted in target probe requests")
        if any(re.search(r"(?i)(?:^|\s)(?:--?)(?:token|secret|password|passwd|api[-_]?key|authorization)(?:=|\s|$)", part)
               or re.search(r"(?i)\bBearer\s+", part)
               or re.search(r"(?i)(?:token|secret|password|passwd|api[-_]?key|authorization)\s*[:=]", part)
               for part in self.argv):
            raise ValueError("credential values and credential-bearing arguments are forbidden")
        if not self.cwd.startswith("/") or "\x00" in self.cwd or any(part == ".." for part in self.cwd.split("/")):
            raise ValueError("cwd must be an absolute normalized target path")
        if len(set(self.environment_allowlist)) != len(self.environment_allowlist) or any(
            not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key) or _SECRET_NAME.search(key)
            for key in self.environment_allowlist
        ):
            raise ValueError("environment_allowlist contains a secret-like or invalid variable name")
        if not 1 <= self.timeout_seconds <= 1800:
            raise ValueError("timeout_seconds must be within 1..1800")
        if not 1 <= self.stdout_limit_bytes <= 262144 or not 1 <= self.stderr_limit_bytes <= 262144:
            raise ValueError("stdout/stderr limits must be within 1..262144 bytes")
        if not self.expected_assertions or len(set(self.expected_assertions)) != len(self.expected_assertions) or any(
            not re.fullmatch(r"[a-z][a-z0-9_.-]{1,95}", name) for name in self.expected_assertions
        ):
            raise ValueError("expected_assertions must contain unique stable assertion IDs")
        if self.evidence_class not in {EvidenceClass.PHYSICAL_PI, EvidenceClass.ACCOUNT, EvidenceClass.NATIVE_ARM64, EvidenceClass.FIXTURE}:
            raise ValueError("probe evidence class is not a functional verification lane")
        if not isinstance(self.timeout_seconds, int) or isinstance(self.timeout_seconds, bool):
            raise ValueError("timeout_seconds must be an integer")
        if any(not isinstance(value, int) or isinstance(value, bool) for value in (self.stdout_limit_bytes, self.stderr_limit_bytes, self.schema_version)):
            raise ValueError("schema version and output limits must be integers")
    def to_dict(self) -> dict[str, Any]:
        self.validate()
        return {
            "schema_version": self.schema_version, "request_id": self.request_id,
            "acceptance_id": self.acceptance_id, "evidence_id": self.evidence_id,
            "candidate_sha": self.candidate_sha, "target_id": self.target_id,
            "platform": self.platform, "authorization_reference": self.authorization_reference,
            "target_manifest_sha256": self.target_manifest_sha256, "argv": list(self.argv),
            "cwd": self.cwd, "environment_allowlist": list(self.environment_allowlist),
            "timeout_seconds": self.timeout_seconds, "stdout_limit_bytes": self.stdout_limit_bytes,
            "stderr_limit_bytes": self.stderr_limit_bytes, "expected_assertions": list(self.expected_assertions),
            "evidence_class": self.evidence_class.value,
        }

    @property
    def request_sha256(self) -> str:
        return _sha(_canonical(self.to_dict()))


def build_probe_request(
    *, request_id: str, acceptance_id: str, evidence_id: str, candidate_sha: str,
    target_id: str, platform: str, authorization_reference: str,
    target_manifest_sha256: str, argv: tuple[str, ...], cwd: str,
    environment_allowlist: tuple[str, ...], timeout_seconds: int,
    stdout_limit_bytes: int, stderr_limit_bytes: int,
) -> ProbeRequest:
    """Build a request using the immutable assertion profile for its evidence ID."""
    profile = profile_for(evidence_id, acceptance_id)
    try:
        evidence_class = _PLATFORM_CLASS[platform]
    except KeyError as exc:
        raise ValueError("platform is unsupported") from exc
    request = ProbeRequest(
        request_id=request_id, acceptance_id=acceptance_id, evidence_id=evidence_id,
        candidate_sha=candidate_sha, target_id=target_id, platform=platform,
        authorization_reference=authorization_reference,
        target_manifest_sha256=target_manifest_sha256, argv=argv, cwd=cwd,
        environment_allowlist=environment_allowlist, timeout_seconds=timeout_seconds,
        stdout_limit_bytes=stdout_limit_bytes, stderr_limit_bytes=stderr_limit_bytes,
        expected_assertions=profile.assertions, evidence_class=evidence_class,
    )
    request.validate()
    return request


@dataclass(frozen=True, slots=True)
class VerifiedProbe:
    request: ProbeRequest
    state: EvidenceState
    started_at: str
    finished_at: str
    exit_code: int
    assertions: Mapping[str, bool | None]
    blocker: str | None
    request_sha256: str
    result_sha256: str
    result_json: bytes

    def retain(self, root: OwnedRoot) -> EvidenceRecord:
        """Persist the exact request/result in a private owned root before emitting proof."""
        root.ensure()
        request_value = self.request.to_dict()
        payload = _canonical({"schema_version": 1, "request": request_value, "result": json.loads(self.result_json)}) + b"\n"
        digest = _sha(payload)
        relative = f"evidence/operator/{self.request.target_id}/{self.request.acceptance_id}/{self.request.evidence_id}-{self.request.request_id}.json"
        destination = root.path(relative)
        current = root.root
        for part in destination.relative_to(root.root).parts[:-1]:
            current = current / part
            if current.exists() and (current.is_symlink() or not current.is_dir()):
                raise PermissionError("evidence bundle path contains a non-owned or unsafe directory")
            current.mkdir(mode=0o700, exist_ok=True)
            if stat.S_IMODE(current.stat().st_mode) & 0o077:
                raise PermissionError("evidence bundle directories must be private")
        fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
        except BaseException:
            destination.unlink(missing_ok=True)
            raise
        directory_fd = os.open(destination.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        record = EvidenceRecord(
            evidence_id=self.request.evidence_id, candidate_sha=self.request.candidate_sha,
            evidence_class=self.request.evidence_class, state=self.state,
            platform=self.request.platform, target_id=self.request.target_id,
            started_at=self.started_at, finished_at=self.finished_at,
            command=f"{self.request.argv[0].rsplit('/', 1)[-1]} [arguments redacted; {len(self.request.argv) - 1} args]",
            exit_code=self.exit_code, assertions=dict(self.assertions), artifact_sha256=digest,
            blocker=self.blocker,
        )
        record.validate()
        return record


def verify_operator_result(
    request_value: Mapping[str, Any], result_value: Mapping[str, Any], target: AuthorizedTarget,
) -> VerifiedProbe:
    """Bind an owner-run structured result to its exact request and target.

    The result schema deliberately carries digests and assertion outcomes, not
    stdout/stderr or environment values. `target` must already have been
    checked by the configured enrolled-target authority before this call.
    """
    request = ProbeRequest.from_dict(request_value)
    target.validate()
    if (request.target_id != target.target_id or request.platform != target.platform
            or request.authorization_reference != target.authorization_reference
            or request.target_manifest_sha256 != target.manifest_sha256):
        raise PermissionError("probe request does not match the authorized target manifest")
    if request.acceptance_id not in target.allowed_acceptance:
        raise PermissionError("target authorization does not include the requested acceptance criterion")

    required = {
        "schema_version", "request_id", "request_sha256", "acceptance_id", "evidence_id",
        "candidate_sha", "target_id", "platform", "owner", "authorization_reference",
        "started_at", "finished_at", "exit_code", "argv_sha256", "cwd_sha256",
        "environment_names", "stdout_sha256", "stderr_sha256", "stdout_bytes", "stderr_bytes",
        "output_truncated", "assertions", "effects",
    }
    if set(result_value) != required:
        raise ValueError("operator result fields do not match the versioned schema")
    if not isinstance(result_value["schema_version"], int) or isinstance(result_value["schema_version"], bool) or result_value["schema_version"] != 1:
        raise ValueError("unsupported operator result schema_version")
    expected = request.to_dict()
    bindings = {
        "request_id": expected["request_id"], "request_sha256": request.request_sha256,
        "acceptance_id": request.acceptance_id, "evidence_id": request.evidence_id,
        "candidate_sha": request.candidate_sha, "target_id": target.target_id,
        "platform": target.platform, "owner": target.owner,
        "authorization_reference": target.authorization_reference,
        "argv_sha256": _sha(_canonical({"argv": list(request.argv)})),
        "cwd_sha256": _sha(request.cwd.encode("utf-8")),
    }
    if any(result_value[key] != value for key, value in bindings.items()):
        raise ValueError("operator result is not bound to the exact request, candidate, or enrolled target")
    for key in ("stdout_sha256", "stderr_sha256"):
        if not isinstance(result_value[key], str) or not _SHA64.fullmatch(result_value[key]):
            raise ValueError(f"{key} must be a SHA-256 digest; raw output is not accepted")
    for key, limit in (("stdout_bytes", request.stdout_limit_bytes), ("stderr_bytes", request.stderr_limit_bytes)):
        count = result_value[key]
        if not isinstance(count, int) or isinstance(count, bool) or count < 0 or count > limit:
            raise ValueError(f"{key} is invalid or exceeds its requested output limit")
    if not isinstance(result_value["output_truncated"], bool) or result_value["output_truncated"]:
        raise ValueError("truncated target output cannot prove acceptance")
    environment_names = result_value["environment_names"]
    if (not isinstance(environment_names, list) or len(set(environment_names)) != len(environment_names)
            or not set(environment_names).issubset(request.environment_allowlist)):
        raise ValueError("operator result environment exceeds the request allowlist")
    assertions = result_value["assertions"]
    if not isinstance(assertions, dict) or set(assertions) != set(request.expected_assertions) or any(
        value is not None and not isinstance(value, bool) for value in assertions.values()
    ):
        raise ValueError("operator result does not contain the exact tri-state assertion set")
    effects = result_value["effects"]
    if not isinstance(effects, list) or any(not isinstance(item, str) or not re.fullmatch(r"[a-z][a-z0-9_.:-]{1,79}", item) for item in effects):
        raise ValueError("effects must be a bounded list of stable effect IDs, never free-form output")
    if result_value["owner"] != target.owner:
        raise PermissionError("operator attestation does not match the enrolled target owner")
    if not isinstance(result_value["exit_code"], int) or isinstance(result_value["exit_code"], bool):
        raise ValueError("exit_code must be an integer")

    started = _timestamp(result_value["started_at"], "started_at")
    finished = _timestamp(result_value["finished_at"], "finished_at")
    duration = (finished - started).total_seconds()
    if duration < 0 or duration > request.timeout_seconds:
        raise ValueError("operator result duration is negative or exceeded its requested timeout")
    if finished > datetime.now(timezone.utc):
        raise ValueError("operator result finished_at is in the future")

    result_json = _canonical(dict(result_value))
    result_sha = _sha(result_json)
    state = EvidenceState.PASS
    blocker = None
    exit_code = result_value["exit_code"]
    if exit_code != 0:
        state, blocker = EvidenceState.FAIL, f"Target probe exited with status {exit_code}"
    elif any(value is False for value in assertions.values()):
        state, blocker = EvidenceState.FAIL, "One or more required target assertions were observed false"
    elif any(value is None for value in assertions.values()):
        state, blocker = EvidenceState.PENDING, "One or more required target assertions were not observed"
    elif not effects:
        state, blocker = EvidenceState.PENDING, "No observed target effects were supplied"
    

    return VerifiedProbe(
        request=request, state=state,
        started_at=str(result_value["started_at"]), finished_at=str(result_value["finished_at"]),
        exit_code=exit_code, assertions={str(key): value for key, value in assertions.items()},
        blocker=blocker, request_sha256=request.request_sha256, result_sha256=result_sha,
        result_json=result_json,
    )
