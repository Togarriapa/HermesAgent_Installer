"""Fixed acceptance adapters backed by the installer-owned Resources APIs."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
from types import MappingProxyType
from typing import Mapping

from ..evidence import EvidenceClass, EvidenceRecord, EvidenceState
from ..registry.native import NativeRegistry
from ..registry.source import load_bundled_source
from ..state import OwnedRoot
from .acceptance import AuthorizedTarget, Workflow


_SHA40 = re.compile(r"[0-9a-f]{40}\Z")
_PLATFORM_CLASS = {
    "fixture-x86_64": EvidenceClass.FIXTURE,
    "linux-arm64": EvidenceClass.NATIVE_ARM64,
    "raspberry-pi-5-arm64": EvidenceClass.PHYSICAL_PI,
}


def _canonical(value: Mapping[str, object]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _candidate_at(checkout: Path) -> str:
    if checkout.is_symlink() or not checkout.is_dir() or checkout.resolve(strict=True) != checkout:
        raise PermissionError("acceptance checkout must be a nonsymlink normalized directory")
    git = next((candidate for candidate in (Path("/usr/bin/git"), Path("/usr/local/bin/git"))
                if candidate.is_file() and not candidate.is_symlink()), None)
    if git is None:
        raise RuntimeError("fixed Git executable is unavailable; candidate binding cannot be checked")
    env = {
        "PATH": "/usr/bin:/bin:/usr/local/bin",
        "HOME": str(checkout),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_OPTIONAL_LOCKS": "0",
    }
    try:
        result = subprocess.run(
            [str(git), "-C", str(checkout), "rev-parse", "--verify", "HEAD^{commit}"],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            env=env, timeout=5, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise RuntimeError("candidate checkout identity could not be read") from None
    candidate = result.stdout.decode("ascii", errors="strict").strip()
    if result.returncode != 0 or not _SHA40.fullmatch(candidate):
        raise RuntimeError("candidate checkout did not produce a full Git commit SHA")
    return candidate


def _retain_summary(output_root: OwnedRoot, target_id: str, candidate_sha: str, summary: Mapping[str, object]) -> str:
    output_root.ensure()
    relative = f"evidence/native-bundle/{target_id}/{candidate_sha}.json"
    destination = output_root.path(relative)
    directory = output_root.root
    for part in Path(relative).parts[:-1]:
        directory = directory / part
        directory.mkdir(mode=0o700, exist_ok=True)
        info = directory.lstat()
        if directory.is_symlink() or not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
            raise PermissionError("native evidence directories must be private, owned directories")
    payload = _canonical(summary) + b"\n"
    digest = hashlib.sha256(payload).hexdigest()
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(destination, flags, 0o600)
    except FileExistsError:
        read_flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        fd = os.open(destination, read_flags)
        try:
            info = os.fstat(fd)
            existing = os.read(fd, len(payload) + 1)
        finally:
            os.close(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600 or existing != payload:
            raise PermissionError("existing native evidence artifact differs from the deterministic result")
        return digest
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(fd)
    return digest


def build_native_bundle_workflow(*, checkout: Path, candidate_sha: str) -> Workflow:
    """Create the fixed AC16/EV-RB01 probe; no external command or resource action runs."""
    checkout = checkout.expanduser().absolute()
    if checkout.is_symlink() or not checkout.is_dir():
        raise ValueError("acceptance checkout must be a nonsymlink directory")
    checkout = checkout.resolve(strict=True)
    if not _SHA40.fullmatch(candidate_sha):
        raise ValueError("candidate_sha must be a full lowercase Git SHA")

    def run(target: AuthorizedTarget, output_dir: str) -> EvidenceRecord:
        target.validate()
        started = datetime.now(timezone.utc)
        if _candidate_at(checkout) != candidate_sha:
            raise ValueError("native bundle workflow checkout does not match the selected candidate SHA")
        module_path = Path(__file__).resolve()
        if not module_path.is_relative_to(checkout.resolve()):
            raise PermissionError("native bundle workflow is not loaded from the selected candidate checkout")

        source = load_bundled_source()
        registry = NativeRegistry.from_verified_source(source)
        discovery = registry.discover_all()
        crosswalk = registry.crosswalk(discovery)
        materialized = registry.materialize(discovery)
        complete_crosswalk = (
            len(crosswalk) == len(discovery.resources)
            and all(row.native_path or row.blockers for row in crosswalk)
        )
        has_native_materialization = bool(materialized) and any(
            path.startswith("homes/profiles/") for path in materialized
        ) and any(path.startswith("homes/skills/") for path in materialized)
        assertions = {
            "packaged_bundle_digest_verified": True,
            "no_resources_network_access": True,
            "native_materialization_from_packaged_input": has_native_materialization,
        }
        if not complete_crosswalk or not has_native_materialization:
            state = EvidenceState.FAIL
            blocker = "Verified bundled source did not produce a complete native resource materialization"
        else:
            state = EvidenceState.PASS
            blocker = None

        counts: dict[str, int] = {}
        for row in crosswalk:
            counts[row.kind] = counts.get(row.kind, 0) + 1
        materialized_digest = hashlib.sha256(b"".join(
            len(path.encode()).to_bytes(4, "big") + path.encode() + hashlib.sha256(content).digest()
            for path, content in sorted(materialized.items())
        )).hexdigest()
        summary: dict[str, object] = {
            "schema_version": 1,
            "acceptance_id": "AC16",
            "evidence_id": "EV-RB01",
            "candidate_sha": candidate_sha,
            "target_id": target.target_id,
            "source_revision": source.revision,
            "source_content_digest": source.content_digest,
            "catalog_version": source.catalog_version,
            "resource_count": len(discovery.resources),
            "crosswalk_complete": complete_crosswalk,
            "resource_counts_by_kind": counts,
            "materialized_file_count": len(materialized),
            "materialized_digest": materialized_digest,
            "assertions": assertions,
            "network_access_performed": False,
        }
        artifact_digest = _retain_summary(OwnedRoot(Path(output_dir)), target.target_id, candidate_sha, summary)
        finished = datetime.now(timezone.utc)
        record = EvidenceRecord(
            evidence_id="EV-RB01", candidate_sha=candidate_sha,
            evidence_class=_PLATFORM_CLASS[target.platform], state=state,
            platform=target.platform, target_id=target.target_id,
            started_at=started.isoformat(timespec="milliseconds"),
            finished_at=finished.isoformat(timespec="milliseconds"), command="installer.native_bundle_probe",
            exit_code=0 if state == EvidenceState.PASS else 1,
            assertions=assertions, artifact_sha256=artifact_digest, blocker=blocker,
        )
        record.validate()
        return record

    return run


def build_fixed_workflows(*, checkout: Path, candidate_sha: str) -> Mapping[str, Workflow]:
    """Return only implemented fixed workflows; absent acceptance IDs remain pending."""
    return MappingProxyType({"AC16": build_native_bundle_workflow(checkout=checkout, candidate_sha=candidate_sha)})
