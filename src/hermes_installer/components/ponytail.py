"""PonyTail portable review skill routed through the registry coordinator.

The adapter exposes the pinned prompt and a bounded repository snapshot. It
does not install PonyTail's host hooks or create a competing orchestrator.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Mapping, Protocol

from hermes_installer.components.adapters import ComponentAdapterContract, resolve_component_adapter
from hermes_installer.components.skill_handlers import HookReview, discover_component_skills, review_host_hooks
from hermes_installer.components.source_bundle import VerifiedComponentSource


COMPONENT_ID = "ponytail"
REVIEW_SKILL = "ponytail-review"
_SEVERITIES = frozenset({"critical", "high", "medium", "low", "info"})
_MAX_REPOSITORY_BYTES = 512 * 1024


class PonyTailAdapterError(ValueError):
    """The pinned PonyTail source or review result is invalid."""


@dataclass(frozen=True, slots=True)
class PonyTailReviewRequest:
    component_id: str
    source_url: str
    revision: str
    skill_name: str
    instructions: str
    repository_files: tuple[tuple[str, str], ...]


@dataclass(frozen=True, slots=True)
class PonyTailFinding:
    path: str
    severity: str
    problem: str
    fix: str
    impact: str


@dataclass(frozen=True, slots=True)
class PonyTailReview:
    summary: str
    findings: tuple[PonyTailFinding, ...]
    coordinator: str = "registry"
    live_provider_status: str = "pending_configured_provider_and_target_verification"


class RegistryReviewCoordinator(Protocol):
    def __call__(self, request: PonyTailReviewRequest) -> Mapping[str, object]: ...


def _pinned_source(source: VerifiedComponentSource) -> tuple[ComponentAdapterContract, Mapping[str, bytes]]:
    if not isinstance(source, VerifiedComponentSource):
        raise PonyTailAdapterError("PonyTail requires a verified pinned source archive")
    contract = resolve_component_adapter(COMPONENT_ID)
    if (source.component_id != COMPONENT_ID or source.source_identity != contract.source_identity
            or source.revision != contract.revision):
        raise PonyTailAdapterError("PonyTail source identity or revision does not match the reviewed pin")
    if (source.license != contract.license
            or source.redistribution_license_review_required != contract.redistribution_license_review_required):
        raise PonyTailAdapterError("PonyTail license evidence differs from the reviewed contract")
    return contract, source.files


def _review_instructions(source: VerifiedComponentSource) -> tuple[ComponentAdapterContract, str]:
    contract, files = _pinned_source(source)
    discovery = discover_component_skills(COMPONENT_ID, files)
    # PonyTail carries host mirrors, including a compact OpenClaw copy. The
    # canonical portable tree is `skills/`; do not let a mirror shadow it.
    selected = [item for item in discovery.skills
                if item.name.casefold() == REVIEW_SKILL
                and item.skill_file == f"skills/{REVIEW_SKILL}/SKILL.md"]
    if len(selected) != 1:
        raise PonyTailAdapterError("the pinned PonyTail review skill is missing or ambiguous")
    record = selected[0]
    try:
        instructions = files[record.skill_file].decode("utf-8")
    except (KeyError, UnicodeError):
        raise PonyTailAdapterError("the pinned PonyTail review skill is unreadable") from None
    if len(instructions.encode("utf-8")) > 256 * 1024:
        raise PonyTailAdapterError("the pinned PonyTail review skill exceeds 256 KiB")
    return contract, instructions


def _repository_snapshot(repository_files: Mapping[str, str]) -> tuple[tuple[str, str], ...]:
    if not repository_files or len(repository_files) > 128:
        raise PonyTailAdapterError("repository review requires 1 to 128 scoped files")
    total = 0
    result = []
    for name, body in sorted(repository_files.items()):
        if not isinstance(name, str) or not isinstance(body, str):
            raise PonyTailAdapterError("repository snapshot contains an unsafe path or non-text file")
        path = PurePosixPath(name)
        if ("\\" in name or path.is_absolute() or not path.parts
                or ".." in path.parts or path.as_posix() != name):
            raise PonyTailAdapterError("repository snapshot contains an unsafe path or non-text file")
        encoded = body.encode("utf-8")
        total += len(encoded)
        if total > _MAX_REPOSITORY_BYTES:
            raise PonyTailAdapterError("repository review snapshot exceeds 512 KiB")
        result.append((name, body))
    return tuple(result)


def _parse_review(value: Mapping[str, object], files: tuple[tuple[str, str], ...]) -> PonyTailReview:
    if not isinstance(value, Mapping) or set(value) != {"summary", "findings"}:
        raise PonyTailAdapterError("registry coordinator returned an invalid review envelope")
    summary = value["summary"]
    findings = value["findings"]
    if not isinstance(summary, str) or not summary.strip() or len(summary) > 2000:
        raise PonyTailAdapterError("review summary must be non-empty text of at most 2000 characters")
    if not isinstance(findings, list) or len(findings) > 100:
        raise PonyTailAdapterError("review findings must be a list of at most 100 items")
    paths = {name for name, _ in files}
    parsed = []
    for item in findings:
        if not isinstance(item, Mapping) or set(item) != {"path", "severity", "problem", "fix", "impact"}:
            raise PonyTailAdapterError("review finding has an invalid shape")
        path, severity = item["path"], item["severity"]
        if not isinstance(path, str) or not isinstance(severity, str) or path not in paths or severity not in _SEVERITIES:
            raise PonyTailAdapterError("review finding path or severity is outside the repository snapshot")
        text_fields = (item["problem"], item["fix"], item["impact"])
        if not all(isinstance(field, str) and field.strip() and len(field) <= 2000 for field in text_fields):
            raise PonyTailAdapterError("review finding text fields must be non-empty and bounded")
        parsed.append(PonyTailFinding(path, severity, *text_fields))
    return PonyTailReview(summary.strip(), tuple(parsed))


def review_repository(
    source: VerifiedComponentSource,
    repository_files: Mapping[str, str],
    *,
    registry_coordinator: RegistryReviewCoordinator,
) -> PonyTailReview:
    """Send one scoped review request through the caller's registry coordinator."""
    contract, instructions = _review_instructions(source)
    source_revision = source.revision
    snapshot = _repository_snapshot(repository_files)
    if not callable(registry_coordinator):
        raise PonyTailAdapterError("the user registry review coordinator is unavailable")
    request = PonyTailReviewRequest(
        COMPONENT_ID, contract.selected_source_url, source_revision, REVIEW_SKILL,
        instructions, snapshot,
    )
    return _parse_review(registry_coordinator(request), snapshot)


def inspect_host_hooks(source: VerifiedComponentSource) -> HookReview:
    """Return static hook candidates; lifecycle hooks remain uninstalled."""
    _, files = _pinned_source(source)
    return review_host_hooks(COMPONENT_ID, files)
