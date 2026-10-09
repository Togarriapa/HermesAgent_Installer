"""Short-lived scope for explicitly authorized, non-privileged Pi probes.

This is a reviewable scope descriptor, not a signature, enrollment credential,
or cryptographic authorization grant. It cannot authorize installation,
profile/model invocation, account access, or arbitrary mutation. Its only
non-staging effect is a named temporary symlink to the pinned Hermes checkout,
which must be absent before the probe and removed immediately afterward.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import PurePosixPath
import re
from typing import Any, Mapping
from uuid import NAMESPACE_URL, uuid5


AUTHORIZATION_REFERENCE = "codex-user-request:pi-connect:48dfbc75-8877-40bb-b391-9b08301911ad"
RETAINED_HUMAN_INSTRUCTION = (
    "User explicitly identified Pi Connect device "
    "48dfbc75-8877-40bb-b391-9b08301911ad and authorized independent Pi deployments/tests without approvals."
)
DEVICE_ID = "48dfbc75-8877-40bb-b391-9b08301911ad"
STAGING_PARENT = "/home/admin/HermesInstaller/data/devtest-luna-resource-wire-51d3883/native-resources-8b806b49/acceptance"
PINNED_HERMES_SOURCE = "/home/admin/HermesInstaller/data/generations/hermes-agent-7085fbf77532"
PINNED_HERMES_SOURCE_SHA = "7085fbf7753266fc4943c55ac04926186bc90005"
TEMPORARY_SOURCE_FIXTURE_LINK = "/tmp/hermes-agent-hi08"
_SHA40 = re.compile(r"[0-9a-f]{40}\Z")


def _canonical(value: Mapping[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


@dataclass(frozen=True, slots=True)
class PiObservation:
    device_id: str
    observed_at: str
    uid: int
    gid: int
    owner: str
    architecture: str
    model: str
    staging_root: str
    staging_uid: int
    staging_gid: int
    staging_mode: int
    staging_is_symlink: bool
    temporary_source_link_absent: bool
    checkout_sha: str

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "PiObservation":
        required = {field for field in cls.__dataclass_fields__}
        if set(value) != required:
            raise ValueError("Pi observation fields do not match the scoped schema")
        observation = cls(**value)
        observation.validate()
        return observation

    def validate(self) -> datetime:
        if self.device_id != DEVICE_ID:
            raise PermissionError("Pi Connect device does not match the user-identified target")
        try:
            observed = datetime.fromisoformat(self.observed_at.replace("Z", "+00:00"))
        except (ValueError, AttributeError) as exc:
            raise ValueError("observation timestamp must be ISO-8601") from exc
        if observed.tzinfo is None:
            raise ValueError("observation timestamp must include a timezone")
        observed = observed.astimezone(timezone.utc)
        if (self.uid, self.gid, self.owner, self.architecture) != (1000, 1000, "admin", "aarch64"):
            raise PermissionError("target owner or architecture differs from the observed Pi")
        if not self.model.startswith("Raspberry Pi 5 Model B"):
            raise PermissionError("target model is not the observed Raspberry Pi 5 Model B")
        expected_staging = f"{STAGING_PARENT}/ev-rb08-{self.checkout_sha[:12]}"
        if self.staging_root != expected_staging:
            raise PermissionError("staging root is not the exact candidate-scoped acceptance checkout")
        if (self.staging_uid, self.staging_gid, self.staging_mode, self.staging_is_symlink) != (1000, 1000, 0o700, False):
            raise PermissionError("staging root is not a nonsymlink, owner-only directory")
        if self.temporary_source_link_absent is not True:
            raise PermissionError("the fixed temporary source fixture path must be absent before the probe")
        if not _SHA40.fullmatch(self.checkout_sha):
            raise ValueError("observed checkout SHA must be a full Git SHA")
        return observed


@dataclass(frozen=True, slots=True)
class PiReadOnlyLease:
    schema_version: int
    request_id: str
    target_id: str
    device_id: str
    platform: str
    owner: str
    uid: int
    gid: int
    model: str
    candidate_sha: str
    observed_checkout_sha: str
    staging_root: str
    authorization_reference: str
    retained_human_instruction: str
    cryptographic_grant: bool
    authorization_signature_verified: bool
    allowed_acceptance: tuple[str, ...]
    allowed_actions: tuple[str, ...]
    allowed_auxiliary_effects: tuple[str, ...]
    temporary_source_link_absent_at_observation: bool
    denied_actions: tuple[str, ...]
    observed_at: str
    expires_at: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_manifest(self) -> dict[str, Any]:
        """Return the immutable descriptor plus its canonical content digest."""
        value = self.to_dict()
        value["manifest_sha256"] = hashlib.sha256(_canonical(value)).hexdigest()
        return value

    @property
    def manifest_sha256(self) -> str:
        return hashlib.sha256(_canonical(self.to_dict())).hexdigest()


def build_pi_read_only_lease(
    observation: PiObservation,
    *,
    candidate_sha: str,
    now: datetime | None = None,
    max_observation_age: timedelta = timedelta(minutes=5),
    lease_duration: timedelta = timedelta(minutes=10),
) -> PiReadOnlyLease:
    """Bind a fresh observation and human authorization to a narrow probe scope.

    The checkout observed on Pi is recorded separately from ``candidate_sha``;
    a stale checkout can never stand in for the requested candidate.
    """
    observed = observation.validate()
    issued_at = now or datetime.now(timezone.utc)
    if issued_at.tzinfo is None or issued_at.utcoffset() is None:
        raise ValueError("lease issuance time must include a timezone")
    current = issued_at.astimezone(timezone.utc)
    if not _SHA40.fullmatch(candidate_sha):
        raise ValueError("candidate_sha must be a full lowercase commit SHA")
    if max_observation_age <= timedelta(0) or lease_duration <= timedelta(0) or lease_duration > timedelta(minutes=10):
        raise ValueError("observation age and lease duration must be positive; lease is capped at ten minutes")
    age = current - observed
    if age < timedelta(0) or age > max_observation_age:
        raise PermissionError("Pi observation is future-dated or stale; reobserve the target before issuing a lease")
    expires = current + lease_duration
    return PiReadOnlyLease(
        schema_version=1,
        request_id=str(uuid5(NAMESPACE_URL, f"{observation.device_id}:{candidate_sha}:{observation.observed_at}")),
        target_id="PI-HERMES", device_id=observation.device_id,
        platform="raspberry-pi-5-arm64", owner=observation.owner,
        uid=observation.uid, gid=observation.gid, model=observation.model,
        candidate_sha=candidate_sha, observed_checkout_sha=observation.checkout_sha,
        staging_root=observation.staging_root,
        authorization_reference=AUTHORIZATION_REFERENCE,
        retained_human_instruction=RETAINED_HUMAN_INSTRUCTION,
        cryptographic_grant=False, authorization_signature_verified=False,
        allowed_acceptance=("AC16",),
        allowed_actions=("bounded_read_only_discovery", "isolated_contract_tests"),
        allowed_auxiliary_effects=(
            f"temporary_symlink:{TEMPORARY_SOURCE_FIXTURE_LINK}->{PINNED_HERMES_SOURCE}@{PINNED_HERMES_SOURCE_SHA}",
            "remove_temporary_source_fixture_link_and_verify_absent",
        ),
        temporary_source_link_absent_at_observation=observation.temporary_source_link_absent,
        denied_actions=("managed_install", "profile_invocation", "model_inference", "account_or_cloud_mutation", "host_service_mutation", "outbound_test_message", "arbitrary_shell"),
        observed_at=observation.observed_at,
        expires_at=expires.isoformat().replace("+00:00", "Z"),
    )


def build_pi_contract_test_request(
    lease: PiReadOnlyLease,
    *,
    python_executable: str,
    now: datetime | None = None,
):
    """Build the fixed, non-shell native resource contract-suite request.

    This request only runs the three read-only contract suites already used by
    the Pi operator. The checkout must itself equal the candidate SHA; it may
    not silently test another native branch or the development Mac.
    """
    from .operator_evidence import build_probe_request

    issued_at = now or datetime.now(timezone.utc)
    if issued_at.tzinfo is None or issued_at.utcoffset() is None:
        raise ValueError("request time must include a timezone")
    issued_at = issued_at.astimezone(timezone.utc)
    expires = datetime.fromisoformat(lease.expires_at.replace("Z", "+00:00"))
    if issued_at >= expires:
        raise PermissionError("Pi probe lease has expired")
    if lease.candidate_sha != lease.observed_checkout_sha:
        raise PermissionError("target checkout does not match the candidate SHA")
    if python_executable not in {
        "/usr/bin/python3", "/usr/bin/python3.13", "/usr/bin/python3.14",
        "/home/admin/HermesInstaller/data/installs/dbd62d2bc9a23cac/environments/2be4b41371094d1c9745c2cfbd0f3fe0/venv/bin/python",
    }:
        raise PermissionError("test interpreter is not one of the observed fixed Python runtimes")
    cwd = lease.staging_root
    if str(PurePosixPath(cwd)) != cwd:
        raise ValueError("test working directory must be normalized")
    timeout = min(120, int((expires - issued_at).total_seconds()))
    if timeout < 1:
        raise PermissionError("Pi probe lease has insufficient time remaining")
    return build_probe_request(
        request_id=lease.request_id, acceptance_id="AC16", evidence_id="EV-RB08",
        candidate_sha=lease.candidate_sha, target_id=lease.target_id,
        platform=lease.platform, authorization_reference=lease.authorization_reference,
        target_manifest_sha256=lease.manifest_sha256,
        argv=(
            python_executable, "-m", "unittest",
            "tests.contracts.test_registry_resources_runtime",
            "tests.contracts.test_registry_native",
            "tests.native.test_native_boundary_adapter", "-v",
        ),
        cwd=cwd,
        environment_allowlist=("PATH", "PYTHONPATH", "PYTHONDONTWRITEBYTECODE"),
        timeout_seconds=timeout, stdout_limit_bytes=262144, stderr_limit_bytes=262144,
    )
