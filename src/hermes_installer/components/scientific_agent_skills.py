"""Pinned, task-scoped Scientific Agent Skills with feature-only runtimes.

The selected upstream tree is large, so source acquisition and native skill
registration use the shared complete-tree importer. Scientific packages stay
in separate, opt-in feature environments; this module does not install them.
"""
from __future__ import annotations

import importlib.resources
import hashlib
import json
import posixpath
import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Mapping

from hermes_installer.components.adapters import ComponentAdapterContract, resolve_component_adapter
from hermes_installer.components.skill_handlers import DiscoveredSkill, SkillAdapterError, discover_component_skills
from hermes_installer.components.skill_binding import ComponentSkillBinding
from hermes_installer.components.source_bundle import (
    GitHubComponentSourceFetcher,
    SourceTransport,
    VerifiedComponentSource,
)
from hermes_installer.registry.generation import GenerationStore


COMPONENT_ID = "scientific-agent-skills"
SOURCE_IDENTITY = "K-Dense-AI/scientific-agent-skills"
SOURCE_REVISION = "92ace75ac21efe19a620434e0ca4e356081fe807"
SOURCE_TREE_SHA = "9a2d8a9b7d7cf9a89fcf31a25e826838f735d764"
SELECTED_SKILL = "polars"
POLARS_VERSION = "1.44.2"
POLARS_REQUIREMENTS = f"polars=={POLARS_VERSION}\npolars-runtime-32=={POLARS_VERSION}\n"
SOURCE_ARCHIVE_MAX_BYTES = 320 * 1024 * 1024
SOURCE_UNPACKED_MAX_BYTES = 2 * 1024 * 1024 * 1024
_INLINE_SOURCE_PATH = re.compile(r"`((?:\./)?(?:references|scripts|assets|data|templates)/[^`\s]+)`")


class ScientificSkillError(ValueError):
    """The pinned scientific skill or its feature runtime is incomplete."""


def _source_closure(files: Mapping[str, bytes], skill: DiscoveredSkill) -> tuple[str, ...]:
    """Include Markdown links plus source paths named as inline code."""
    from hermes_installer.components.skill_refs import audit_skill_file_map

    audit = audit_skill_file_map(dict(files), skill_files=(skill.skill_file,))
    if not audit.complete:
        first = audit.problems[0]
        raise ScientificSkillError(
            f"pinned scientific skill source is incomplete: {first.source_path}:{first.line}: {first.reason}"
        )
    references = dict(audit.skill_resolved_targets).get(skill.skill_file, ())
    closure = {skill.skill_file}
    pending = [skill.skill_file]
    queued = set(pending)

    def include(path: str) -> None:
        normalized = posixpath.normpath(path)
        if normalized in {"", ".", ".."} or normalized.startswith("../") or normalized.startswith("/"):
            raise ScientificSkillError(f"scientific skill source path escapes its pinned tree: {path}")
        if normalized in files:
            found = (normalized,)
        else:
            found = tuple(name for name in files if name.startswith(normalized.rstrip("/") + "/"))
        if not found:
            raise ScientificSkillError(f"pinned scientific skill source is missing a referenced file: {path}")
        for name in found:
            closure.add(name)
            if name.casefold().endswith(".md") and name not in queued:
                pending.append(name)
                queued.add(name)

    for target in references:
        include(target)

    # Some upstream instructions name reference pages in inline code rather
    # than Markdown links; preserve and check those files as part of the skill.
    while pending:
        source_file = pending.pop()
        try:
            text = files[source_file].decode("utf-8")
        except (KeyError, UnicodeDecodeError):
            raise ScientificSkillError(f"pinned scientific reference is not UTF-8: {source_file}") from None
        parent = PurePosixPath(source_file).parent.as_posix()
        for match in _INLINE_SOURCE_PATH.finditer(text):
            include(posixpath.join(parent, match.group(1)))
    return tuple(sorted(closure))


@dataclass(frozen=True, slots=True)
class ScientificSkillSelection:
    component_id: str
    source_identity: str
    revision: str
    skill: DiscoveredSkill
    source_closure: tuple[str, ...]
    environment_name: str | None
    requirements: str | None
    readiness: str


class ScientificAgentSkillsComponent:
    """Discover an upstream skill closure and describe only its runtime need."""

    component_id = COMPONENT_ID
    source_identity = SOURCE_IDENTITY
    source_revision = SOURCE_REVISION
    selected_skill = SELECTED_SKILL

    def __init__(self, contract: ComponentAdapterContract | None = None):
        contract = contract or resolve_component_adapter(COMPONENT_ID)
        if (contract.component_id != COMPONENT_ID or contract.source_identity != SOURCE_IDENTITY
                or contract.revision != SOURCE_REVISION):
            raise ScientificSkillError("Scientific Agent Skills source does not match the reviewed immutable pin")
        self.contract = contract

    def source_fetcher(self, transport: SourceTransport | None = None) -> GitHubComponentSourceFetcher:
        """Allow the observed 241 MB archive while retaining hard unpack bounds."""
        return GitHubComponentSourceFetcher(
            transport=transport,
            max_archive_bytes=SOURCE_ARCHIVE_MAX_BYTES,
            max_unpacked_bytes=SOURCE_UNPACKED_MAX_BYTES,
            max_file_bytes=64 * 1024 * 1024,
            max_files=50_000,
            timeout_seconds=120,
        )

    def fetch_source(self, fetcher: GitHubComponentSourceFetcher | None = None) -> VerifiedComponentSource:
        """Fetch the complete immutable tree; shared verification checks the Git tree and references."""
        source = (fetcher or self.source_fetcher()).fetch(
            self.contract, skill_files=(f"skills/{SELECTED_SKILL}/SKILL.md",),
        )
        if source.source_tree_sha != SOURCE_TREE_SHA:
            raise ScientificSkillError("pinned scientific source Git tree differs from the reviewed tree SHA")
        return source

    def stage_for_profile(
        self,
        source: VerifiedComponentSource,
        store: GenerationStore,
        *,
        profile_id: str,
        profile_data_root: Path,
    ) -> ComponentSkillBinding:
        """Preinstall the complete pinned skill tree in one profile's owned root."""
        if (source.component_id != COMPONENT_ID or source.source_identity != SOURCE_IDENTITY
                or source.revision != SOURCE_REVISION):
            raise ScientificSkillError("refusing to stage a source outside the Scientific Agent Skills pin")
        if not isinstance(profile_id, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", profile_id):
            raise ScientificSkillError("profile id is not a safe native profile identifier")
        try:
            profile_root = profile_data_root.resolve(strict=True)
            owned_root = store.owned.root.resolve(strict=True)
        except (OSError, AttributeError):
            raise ScientificSkillError("profile data root is not initialized") from None
        if (profile_data_root.is_symlink() or owned_root != profile_root
                or not store.root.resolve(strict=True).is_relative_to(profile_root)):
            raise ScientificSkillError("generation store is not rooted in this profile's installer-owned data")

        upstream_files = {
            name: body for name, body in source.files.items()
            if name != "INSTALLER-SOURCE-PROVENANCE.json"
        }
        upstream_modes = {name: mode for name, mode in source.file_modes.items() if name in upstream_files}
        try:
            from hermes_installer.registry.source import _git_tree
            source_tree, _ = _git_tree(upstream_files, upstream_modes)
        except Exception as exc:
            raise ScientificSkillError(f"pinned source tree is invalid: {exc}") from None
        if source_tree != SOURCE_TREE_SHA or source_tree != source.source_tree_sha:
            raise ScientificSkillError("pinned source files differ from the verified Git tree")
        selection = self.discover(source.files)
        files = {name: source.files[name] for name in selection.source_closure}
        modes = {name: source.file_modes[name] for name in selection.source_closure}
        provenance_name = "INSTALLER-SCIENTIFIC-SKILL-PROVENANCE.json"
        if provenance_name in files:
            raise ScientificSkillError("pinned source conflicts with the installer provenance path")
        closure_digest = hashlib.sha256()
        for name in sorted(files):
            closure_digest.update(name.encode("utf-8") + b"\0")
            closure_digest.update(hashlib.sha256(files[name]).digest())
        provenance = {
            "schema": 1,
            "component_id": COMPONENT_ID,
            "source_identity": SOURCE_IDENTITY,
            "source_revision": SOURCE_REVISION,
            "source_tree_sha": source.source_tree_sha,
            "selected_skill": SELECTED_SKILL,
            "closure_sha256": closure_digest.hexdigest(),
            "closure_files": sorted(files),
        }
        files[provenance_name] = json.dumps(provenance, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        modes[provenance_name] = 0o644
        generation_id = f"scientific-agent-skills-polars-{SOURCE_REVISION[:12]}"
        target = store.root / generation_id
        if target.exists() or target.is_symlink():
            try:
                existing, manifest, _ = store._verify(generation_id)
            except Exception as exc:
                raise ScientificSkillError("existing scientific skill generation is not verified") from exc
            expected = {
                name: {"sha256": hashlib.sha256(body).hexdigest(),
                       "mode": store._private_mode(modes[name])}
                for name, body in files.items()
            }
            if manifest.get("files") != expected:
                raise ScientificSkillError("existing scientific skill generation conflicts with the pinned closure")
            staged = existing
        else:
            staged = store.stage(generation_id, files, file_modes=modes)
        staged = staged.resolve(strict=True)
        if staged.is_symlink() or not staged.is_relative_to(profile_root):
            raise ScientificSkillError("staged scientific skill escaped the selected profile data root")
        return ComponentSkillBinding(
            profile_id=profile_id,
            component_id=COMPONENT_ID,
            source_identity=SOURCE_IDENTITY,
            revision=SOURCE_REVISION,
            external_dir=staged,
            skill_files=(selection.skill.skill_file,),
            names=(selection.skill.name,),
            source_sha256=closure_digest.hexdigest(),
            redistribution_license_review_required=self.contract.redistribution_license_review_required,
        )

    @staticmethod
    def _polars_lock() -> str:
        root = importlib.resources.files("hermes_installer.components")
        lock = root.joinpath("runtime_locks", COMPONENT_ID, SELECTED_SKILL, "requirements.lock")
        try:
            content = lock.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            raise ScientificSkillError("Polars feature lock is missing or unreadable") from None
        if content != POLARS_REQUIREMENTS:
            raise ScientificSkillError("Polars feature lock differs from its reviewed exact dependency pin")
        return content

    def discover(self, files: Mapping[str, bytes], *, skill_name: str = SELECTED_SKILL) -> ScientificSkillSelection:
        """Resolve the selected skill and every transitively linked local file.

        ``files`` is the verified pinned source tree from GitHubComponentSourceFetcher,
        or a bounded fixture with the same source paths. That importer already
        checks commit identity, Git tree identity, unsafe paths and broken links.
        """
        try:
            discovery = discover_component_skills(
                COMPONENT_ID, files, skill_files=(f"skills/{skill_name}/SKILL.md",),
            )
        except (SkillAdapterError, ValueError, KeyError) as exc:
            raise ScientificSkillError(f"pinned scientific skill source is incomplete: {exc}") from None
        selected = next((item for item in discovery.skills
                         if item.skill_file == f"skills/{skill_name}/SKILL.md"), None)
        if selected is None:
            raise ScientificSkillError(f"selected scientific skill is not present: {skill_name}")
        closure = _source_closure(files, selected)
        if skill_name == SELECTED_SKILL:
            requirements = self._polars_lock()
            skill_text = files[selected.skill_file].decode("utf-8")
            if f'polars=={POLARS_VERSION}' not in skill_text:
                raise ScientificSkillError("pinned Polars skill and feature environment versions do not match")
            return ScientificSkillSelection(
                COMPONENT_ID, SOURCE_IDENTITY, SOURCE_REVISION, selected, closure,
                "scientific-agent-skills/polars", requirements, "runtime_pin_available_host_arm64_pending",
            )
        return ScientificSkillSelection(
            COMPONENT_ID, SOURCE_IDENTITY, SOURCE_REVISION, selected, closure,
            None, None, "skill_content_available_runtime_readiness_required",
        )

    def available_feature_environments(self) -> Mapping[str, str]:
        """Return pinned per-feature packages without implying installation/readiness."""
        return {SELECTED_SKILL: self._polars_lock()}


def run_polars_fixture(polars_module=None) -> dict[str, object]:
    """Run a tiny deterministic grouped-measurement calculation with Polars."""
    if polars_module is None:
        try:
            import polars as polars_module
        except ImportError:
            raise ScientificSkillError(
                "Polars fixture needs the isolated scientific-agent-skills/polars environment"
            ) from None
    version = getattr(polars_module, "__version__", None)
    if version != POLARS_VERSION:
        raise ScientificSkillError(f"Polars fixture requires {POLARS_VERSION}; got {version!r}")
    data = polars_module.DataFrame({
        "condition": ["control", "control", "treated", "treated"],
        "measurement": [1.0, 3.0, 4.0, 6.0],
    })
    result = (
        data.group_by("condition")
        .agg(polars_module.col("measurement").mean().alias("mean"))
        .sort("condition")
        .to_dicts()
    )
    expected = [{"condition": "control", "mean": 2.0}, {"condition": "treated", "mean": 5.0}]
    if result != expected:
        raise ScientificSkillError("Polars deterministic grouped-data fixture returned an unexpected result")
    return {"skill": SELECTED_SKILL, "package_version": version, "groups": result}
