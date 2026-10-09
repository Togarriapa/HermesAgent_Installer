"""Fixed production composition for the CLI acceptance-verification lane.

The target document is a private, owner-authored scope manifest, not a signed
enrollment credential. Results produced here remain untrusted until an
enrolled verifier authenticates their retained artifacts.
"""

from __future__ import annotations

from dataclasses import dataclass, fields
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import pwd
import re
import stat
import subprocess
from typing import Any, Mapping
from uuid import UUID, uuid4, uuid5, NAMESPACE_URL

from ..evidence import (
    EvidenceState,
    acceptance_report,
    load_acceptance_catalog,
    write_report,
)
from ..results import CommandResult, Finding, OutcomeState
from ..state import OwnedRoot
from .acceptance import AuthorizedTarget, TargetWorkflowRunner
from .operator_evidence import ProbeRequest, verify_operator_result
from .pi_lease import (
    AUTHORIZATION_REFERENCE,
    DEVICE_ID,
    PINNED_HERMES_SOURCE,
    PINNED_HERMES_SOURCE_SHA,
    RETAINED_HUMAN_INSTRUCTION,
    STAGING_PARENT,
    TEMPORARY_SOURCE_FIXTURE_LINK,
    PiReadOnlyLease,
)
from .registry_workflows import build_fixed_workflows


_MANIFEST_FIELDS = {
    *(field.name for field in fields(PiReadOnlyLease)), "manifest_sha256",
}
_MAX_MANIFEST_BYTES = 16_384
_MAX_RESULT_BYTES = 131_072


@dataclass(frozen=True, slots=True)
class TargetScope:
    target: AuthorizedTarget
    lease: PiReadOnlyLease
    manifest_path: Path
    manifest_digest: str


def _canonical(value: Mapping[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _read_json(path: Path, *, maximum: int, private_owner: bool = False) -> tuple[dict[str, Any], bytes]:
    path = path.expanduser().absolute()
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or path.is_symlink() or info.st_size > maximum:
        raise ValueError("verification input must be a bounded regular file, not a symlink")
    if private_owner and (info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600):
        raise PermissionError("target scope manifest must be owned by the current user and mode 0600")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(path, flags)
    try:
        opened = os.fstat(fd)
        if (not stat.S_ISREG(opened.st_mode) or opened.st_ino != info.st_ino
                or opened.st_dev != info.st_dev or opened.st_size > maximum):
            raise ValueError("verification input changed while it was opened")
        raw = bytearray()
        while len(raw) <= maximum:
            chunk = os.read(fd, min(8192, maximum + 1 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
    finally:
        os.close(fd)
    if len(raw) > maximum:
        raise ValueError("verification input exceeds its byte limit")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        raise ValueError("verification input is not valid UTF-8 JSON") from None
    if not isinstance(value, dict):
        raise ValueError("verification input must be a JSON object")
    return value, bytes(raw)


def load_target_scope(path: Path) -> TargetScope:
    """Load the existing Pi lease format; its digest does not prove authenticity."""
    value, _raw = _read_json(path, maximum=_MAX_MANIFEST_BYTES, private_owner=True)
    if set(value) != _MANIFEST_FIELDS or type(value.get("schema_version")) is not int or value["schema_version"] != 1:
        raise ValueError("Pi target lease does not match its exact schema")
    unsigned = {key: value[key] for key in sorted(_MANIFEST_FIELDS - {"manifest_sha256"})}
    digest = hashlib.sha256(_canonical(unsigned)).hexdigest()
    if value["manifest_sha256"] != digest:
        raise ValueError("Pi target lease digest does not match its contents")
    tuple_fields = {"allowed_acceptance", "allowed_actions", "allowed_auxiliary_effects", "denied_actions"}
    for key in tuple_fields:
        if not isinstance(value[key], list) or any(not isinstance(item, str) for item in value[key]):
            raise ValueError(f"Pi target lease {key} must be a string array")
    raw_lease = dict(value)
    raw_lease.pop("manifest_sha256")
    raw_lease.update({key: tuple(raw_lease[key]) for key in tuple_fields})
    expected_types = {
        "schema_version": int, "request_id": str, "target_id": str, "device_id": str,
        "platform": str, "owner": str, "uid": int, "gid": int, "model": str,
        "candidate_sha": str, "observed_checkout_sha": str, "staging_root": str,
        "authorization_reference": str, "retained_human_instruction": str,
        "cryptographic_grant": bool, "authorization_signature_verified": bool,
        "temporary_source_link_absent_at_observation": bool, "observed_at": str,
        "expires_at": str,
    }
    if any(type(raw_lease[key]) is not expected for key, expected in expected_types.items()):
        raise ValueError("Pi target lease contains fields with invalid types")
    lease = PiReadOnlyLease(**raw_lease)
    expected_staging = f"{STAGING_PARENT}/ev-rb08-{lease.candidate_sha[:12]}"
    if (not isinstance(lease.candidate_sha, str) or len(lease.candidate_sha) != 40
            or any(ch not in "0123456789abcdef" for ch in lease.candidate_sha)
            or lease.target_id != "PI-HERMES" or lease.device_id != DEVICE_ID
            or lease.platform != "raspberry-pi-5-arm64" or lease.owner != "admin"
            or (lease.uid, lease.gid) != (1000, 1000)
            or not lease.model.startswith("Raspberry Pi 5 Model B")
            or lease.staging_root != expected_staging
            or lease.candidate_sha != lease.observed_checkout_sha
            or lease.authorization_reference != AUTHORIZATION_REFERENCE
            or lease.retained_human_instruction != RETAINED_HUMAN_INSTRUCTION
            or lease.cryptographic_grant is not False
            or lease.authorization_signature_verified is not False
            or lease.allowed_acceptance != ("AC16",)
            or lease.allowed_actions != ("bounded_read_only_discovery", "isolated_contract_tests")
            or lease.allowed_auxiliary_effects != (
                f"temporary_symlink:{TEMPORARY_SOURCE_FIXTURE_LINK}->{PINNED_HERMES_SOURCE}@{PINNED_HERMES_SOURCE_SHA}",
                "remove_temporary_source_fixture_link_and_verify_absent",
            )
            or lease.denied_actions != (
                "managed_install", "profile_invocation", "model_inference", "account_or_cloud_mutation",
                "host_service_mutation", "outbound_test_message", "arbitrary_shell",
            )
            or lease.temporary_source_link_absent_at_observation is not True):
        raise PermissionError("Pi target lease does not match the authorized bounded-test scope")
    try:
        UUID(lease.request_id)
        observed_at = datetime.fromisoformat(lease.observed_at.replace("Z", "+00:00"))
        expires_at = datetime.fromisoformat(lease.expires_at.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        raise ValueError("Pi target lease identifier or timestamps are invalid") from None
    now = datetime.now(timezone.utc)
    expected_request_id = str(uuid5(NAMESPACE_URL, f"{lease.device_id}:{lease.candidate_sha}:{lease.observed_at}"))
    if (lease.request_id != expected_request_id
            or observed_at.tzinfo is None or observed_at.utcoffset() is None
            or expires_at.tzinfo is None or expires_at.utcoffset() is None
            or observed_at > now or expires_at <= now
            or expires_at - observed_at > timedelta(minutes=15)
            or expires_at <= observed_at
            or not isinstance(lease.allowed_auxiliary_effects, tuple)):
        raise ValueError("Pi target lease action bounds are invalid")
    target = AuthorizedTarget.parse({
        "target_id": lease.target_id, "platform": lease.platform, "owner": lease.owner,
        "authorization_reference": lease.authorization_reference,
        "expires_at": lease.expires_at, "allowed_acceptance": list(lease.allowed_acceptance),
    }, manifest_sha256=digest)
    return TargetScope(target, lease, path.expanduser().absolute(), digest)


def _current_candidate_sha(checkout: Path) -> str:
    checkout = checkout.expanduser().absolute()
    if checkout.is_symlink() or not checkout.is_dir() or checkout.resolve(strict=True) != checkout:
        raise PermissionError("candidate checkout must be a nonsymlink normalized directory")
    executable = next((path for path in (Path("/usr/bin/git"), Path("/usr/local/bin/git"))
                       if path.is_file() and not path.is_symlink()), None)
    if executable is None:
        raise RuntimeError("fixed Git is unavailable; exact candidate identity cannot be verified")
    env = {
        "PATH": "/usr/bin:/bin:/usr/local/bin", "HOME": str(checkout),
        "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_TERMINAL_PROMPT": "0", "GIT_OPTIONAL_LOCKS": "0",
    }
    try:
        result = subprocess.run(
            [str(executable), "-C", str(checkout), "rev-parse", "--verify", "HEAD^{commit}"],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            env=env, timeout=5, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise RuntimeError("exact candidate SHA could not be read from this checkout") from None
    try:
        candidate = result.stdout.decode("ascii", errors="strict").strip()
    except UnicodeDecodeError:
        raise RuntimeError("fixed Git returned a non-ASCII candidate identity") from None
    if result.returncode != 0 or len(candidate) != 40 or any(ch not in "0123456789abcdef" for ch in candidate):
        raise RuntimeError("checkout did not yield a full candidate commit SHA")
    return candidate


def _local_owner_scope_matches(scope: TargetScope, checkout: Path, candidate_sha: str) -> bool:
    """Check local operator scope, not cryptographic enrollment or target attestation."""
    target, lease = scope.target, scope.lease
    try:
        actual_owner = pwd.getpwuid(os.getuid()).pw_name
    except KeyError:
        return False
    if (target.owner != actual_owner or os.getuid() != lease.uid or os.getgid() != lease.gid
            or target.platform != "raspberry-pi-5-arm64"):
        return False
    if platform.system() != "Linux" or platform.machine().lower() not in {"aarch64", "arm64"}:
        return False
    try:
        model = Path("/proc/device-tree/model").read_text(encoding="utf-8", errors="replace").replace("\x00", "").strip()
    except OSError:
        return False
    return (model == lease.model and checkout.resolve(strict=True) == Path(lease.staging_root)
            and candidate_sha == lease.candidate_sha == lease.observed_checkout_sha)


def _read_operator_result(path: Path) -> dict[str, Any]:
    value, _raw = _read_json(path, maximum=_MAX_RESULT_BYTES)
    return value


def _retain_report(root: OwnedRoot, report: Mapping[str, Any]) -> tuple[Path, str]:
    root.ensure()
    directory = root.path("reports")
    directory.mkdir(mode=0o700, exist_ok=True)
    info = directory.lstat()
    if (directory.is_symlink() or not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) & 0o077):
        raise PermissionError("verification report directory must be private and owned")
    name = f"verify-{uuid4()}.json"
    destination = root.path(f"reports/{name}")
    # write_report applies the public allow-list and redaction. The random
    # name plus a private, owner-only directory prevents replacement of an
    # existing report; O_EXCL is used to reserve it before serialization.
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(destination, flags, 0o600)
    os.close(fd)
    try:
        digest = write_report(str(destination), report)
        destination.chmod(0o600)
    except BaseException:
        destination.unlink(missing_ok=True)
        raise
    return destination, digest


def run_verify_cli(*, target_path: Path, output_path: Path, checkout: Path,
                   requested_acceptance: tuple[str, ...] = (),
                   request_path: Path | None = None, result_path: Path | None = None) -> CommandResult:
    """Run fixed local workflows or structurally verify one bounded operator result."""
    if (request_path is None) != (result_path is None):
        return CommandResult("verify", OutcomeState.FAILED,
            "--request and --result must be provided together; no verification work ran.", exit_code=2)
    try:
        scope = load_target_scope(target_path)
        candidate_sha = _current_candidate_sha(checkout)
        output_root = OwnedRoot(output_path)
    except (OSError, PermissionError, RuntimeError, ValueError) as exc:
        return CommandResult("verify", OutcomeState.FAILED, f"Verification scope could not be established: {exc}", exit_code=2)

    target = scope.target
    selected = requested_acceptance or target.allowed_acceptance
    if len(set(selected)) != len(selected) or any(item not in target.allowed_acceptance for item in selected):
        return CommandResult("verify", OutcomeState.FAILED,
            "Requested acceptance IDs must be unique and explicitly listed in the owner scope manifest.", exit_code=2)
    if request_path is not None:
        if requested_acceptance:
            return CommandResult("verify", OutcomeState.FAILED,
                "Choose either a request/result pair or local workflow dispatch, not both.", exit_code=2)
        try:
            request_value, _ = _read_json(request_path, maximum=_MAX_MANIFEST_BYTES)
            request = ProbeRequest.from_dict(request_value)
            if (request.candidate_sha != scope.lease.candidate_sha
                    or request.candidate_sha != scope.lease.observed_checkout_sha
                    or request.target_manifest_sha256 != scope.manifest_digest
                    or request.cwd != scope.lease.staging_root
                    or request.request_id != scope.lease.request_id):
                raise ValueError("operator request is not bound to this exact Pi lease, checkout, or staging root")
            if request.candidate_sha != candidate_sha:
                raise ValueError("operator request candidate SHA does not match this exact checkout")
            result_value = _read_operator_result(result_path)
            # This is structural result validation against the private scope
            # manifest. It does not authenticate the operator or target.
            verified = verify_operator_result(request_value, result_value, target)
            record = verified.retain(output_root)
            records = [record]
            message = "Operator result bindings were validated and retained; target authentication and acceptance remain pending."
            result_findings = [Finding("verify.operator-result", message, OutcomeState.PENDING, {
                "acceptance_id": request.acceptance_id,
                "evidence_id": request.evidence_id,
                "request_sha256": request.request_sha256,
                "result_sha256": verified.result_sha256,
                "artifact_sha256": record.artifact_sha256,
                "operator_authenticated": False,
            })]
        except (OSError, RuntimeError, ValueError, PermissionError) as exc:
            return CommandResult("verify", OutcomeState.FAILED, f"Operator result was rejected: {exc}", exit_code=2)
    else:
        if not _local_owner_scope_matches(scope, checkout, candidate_sha):
            return CommandResult("verify", OutcomeState.FAILED,
                "Local workflow dispatch requires the scoped owner and supported local target platform; no probe ran.",
                exit_code=2)
        output_root.ensure()
        workflows = build_fixed_workflows(checkout=checkout, candidate_sha=candidate_sha)
        # The mode-0600 scope manifest is a local invocation boundary only;
        # it is not a signed target enrollment. The runner's evidence remains
        # pending until the real enrolled-verifier trust path is available.
        def authorize_local_scope(observed: AuthorizedTarget) -> bool:
            try:
                current = load_target_scope(scope.manifest_path)
            except (OSError, PermissionError, RuntimeError, ValueError):
                return False
            return (
                observed == target and current.target == target
                and current.manifest_digest == scope.manifest_digest
                and _local_owner_scope_matches(current, checkout, candidate_sha)
            )

        runner = TargetWorkflowRunner(
            workflows=workflows,
            authorize=authorize_local_scope,
        )
        records = []
        result_findings = []
        for acceptance_id in selected:
            observed = runner.run(acceptance_id, target, candidate_sha, str(output_root.root))
            if observed.record is not None:
                records.append(observed.record)
            result_findings.append(Finding(
                f"verify.{acceptance_id.lower()}", observed.message, OutcomeState.PENDING,
                {"acceptance_id": acceptance_id,
                 "evidence_id": observed.record.evidence_id if observed.record else None,
                 "observation_state": observed.record.state.value if observed.record else "not-run",
                 "target_authenticated": False},
            ))
        message = "Fixed local probes completed; all acceptance remains pending enrolled-verifier authentication."

    try:
        catalog = load_acceptance_catalog(checkout / "planning")
        report = acceptance_report(candidate_sha=candidate_sha, traceability=catalog, records=records)
        report_path, report_digest = _retain_report(output_root, report)
    except (OSError, RuntimeError, ValueError, PermissionError) as exc:
        return CommandResult("verify", OutcomeState.FAILED, f"Verification report could not be retained: {exc}", exit_code=1)
    result_findings.append(Finding("verify.report", "Redacted acceptance report retained; no record was authenticated by an enrolled verifier.", OutcomeState.PENDING, {
        "path": str(report_path), "sha256": report_digest,
        "candidate_sha": candidate_sha, "full_acceptance": False,
    }))
    return CommandResult("verify", OutcomeState.PENDING, message, tuple(result_findings),
                         resume_command=f"hermes-installer verify --target {target_path} --output {output_path}")


def run_root_verify_cli(*, output_path: Path, requested_acceptance: tuple[str, ...] = (),
                        request_path: Path | None = None,
                        result_path: Path | None = None) -> CommandResult:
    """Execute fixed workflows using the installed root runtime and its receipts."""
    if os.geteuid() != 0:
        return CommandResult("verify", OutcomeState.FAILED,
                             "Root verification requires the installed root authority process.", exit_code=2)
    if request_path is not None or result_path is not None:
        return CommandResult("verify", OutcomeState.FAILED,
                             "Root verification does not ingest operator-authored request/result files.", exit_code=2)
    if (output_path.name in {"", ".", ".."}
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", output_path.name)):
        return CommandResult("verify", OutcomeState.FAILED,
                             "Root verification output must use a simple directory name.", exit_code=2)
    selected = requested_acceptance or tuple(f"AC{i:02d}" for i in range(1, 19))
    if len(set(selected)) != len(selected):
        return CommandResult("verify", OutcomeState.FAILED,
                             "Acceptance IDs must be unique; no probe ran.", exit_code=2)

    from .target_authority import RootAcceptanceWorkflowRuntime, TargetAuthorityError

    authority_service = None
    accepted_runtime = None
    root_runtime = None
    try:
        from ..authority.daemon import build_enrolled_authority_service
        authority_service, _enrollment = build_enrolled_authority_service()
        root_runtime = getattr(authority_service, "root_authority_runtime", None)
        if root_runtime is None:
            return CommandResult("verify", OutcomeState.PENDING,
                "No protected root authority runtime is active; no acceptance workflow ran.",
                (Finding("verify.root-runtime", "Protected enrollment did not produce a complete root runtime.",
                         OutcomeState.PENDING, {"runtime_composed": False}),),
                resume_command="hermes-installer verify --output <private-output-name>")
        accepted_runtime = RootAcceptanceWorkflowRuntime.from_current_root_runtime(root_runtime)
        candidate_sha = accepted_runtime.candidate_receipts.release.release_commit
        destination = Path("/tmp/hermes-installer-verify") / output_path.name
        output_root = OwnedRoot(destination)
        output_root.ensure()
        records = []
        findings = []
        for acceptance_id in selected:
            observed = accepted_runtime.runner.run(acceptance_id, candidate_sha)
            if observed.record is not None:
                records.append(observed.record)
            state = observed.state
            findings.append(Finding(
                f"verify.{acceptance_id.lower()}", observed.message,
                OutcomeState.FAILED if state == EvidenceState.FAIL else OutcomeState.PENDING,
                {"acceptance_id": acceptance_id,
                 "evidence_id": observed.record.evidence_id if observed.record else None,
                 "observation_state": state.value,
                 "target_id": observed.record.target_id if observed.record else None,
                 "candidate_sha": candidate_sha,
                 "root_receipt_verified": observed.record is not None},
            ))
        catalog = load_acceptance_catalog(Path(__file__).resolve().parents[3] / "planning")
        report = acceptance_report(candidate_sha=candidate_sha, traceability=catalog, records=records)
        report_path, report_digest = _retain_report(output_root, report)
        findings.append(Finding("verify.report", "Root-authenticated evidence report retained; full acceptance remains pending.",
            OutcomeState.PENDING, {"path": str(report_path), "sha256": report_digest,
                                   "candidate_sha": candidate_sha, "full_acceptance": False}))
        failed = any(item.state == OutcomeState.FAILED for item in findings)
        return CommandResult("verify", OutcomeState.FAILED if failed else OutcomeState.PENDING,
            "Root fixed workflows completed; every unobserved requirement remains pending.",
            tuple(findings), resume_command=f"hermes-installer verify --output {output_path.name}",
            exit_code=1 if failed else 0)
    except (OSError, PermissionError, RuntimeError, ValueError, TargetAuthorityError) as exc:
        # Keep the blocker precise while avoiding traceback or environment disclosure.
        message = str(exc).replace("\n", " ")[:256] or type(exc).__name__
        return CommandResult("verify", OutcomeState.PENDING,
            f"Root verification is not available: {message}",
            (Finding("verify.root-prerequisite", message, OutcomeState.PENDING,
                     {"exception_type": type(exc).__name__}),),
            resume_command=f"hermes-installer verify --output {output_path.name}")
    finally:
        if accepted_runtime is not None:
            try:
                accepted_runtime.close()
            except Exception:
                pass
        if root_runtime is not None:
            try:
                root_runtime.close()
            except Exception:
                pass
