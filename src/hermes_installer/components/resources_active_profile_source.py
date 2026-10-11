"""Root-current profile source bytes selected by one sealed Jarvis plan.

This module verifies provenance and source custody only. Declared skill and
plugin dependencies are metadata, never grants; effect authorization remains
with the separately reviewed native child adapter.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import time
from dataclasses import dataclass, field
from typing import Any

MAX_PROMPT_BYTES = 64 * 1024
MAX_PROFILE_MANIFEST_BYTES = 64 * 1024
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_ID = re.compile(r"[a-z0-9][a-z0-9_-]{0,95}\Z")
_SOURCE_SEAL = object()
_MASTER_SOURCE_SEAL = object()


@dataclass(frozen=True, slots=True)
class SourceMember:
    path: str
    sha256: str
    size: int


@dataclass(frozen=True, slots=True)
class RootSelectedActiveProfileSource:
    """Exact selected internal profile bytes under a fresh root source proof."""

    profile_id: str
    source_revision: str
    generation_sha256: str
    profile_manifest: bytes
    profile_manifest_sha256: str
    profile_member_manifest: bytes
    profile_member_manifest_sha256: str
    effective_prompt: bytes
    effective_prompt_sha256: str
    source_member_manifest: tuple[SourceMember, ...]
    source_member_manifest_sha256: str
    required_skill_ids: frozenset[str]
    required_plugin_ids: frozenset[str]
    profile_tool_names: frozenset[str]
    profile_privacy_requirements: frozenset[str]
    interaction_policy_sha256: str
    overlay_sha256: str
    core_source_generation: str
    expires_monotonic: float
    _decision: Any = field(repr=False, compare=False)
    _config: Any = field(repr=False, compare=False)
    _seal: object = field(repr=False, compare=False)

    @classmethod
    def resolve_selected(cls, decision: Any, custody: Any, *, config: Any
                         ) -> tuple["RootSelectedActiveProfileSource", ...]:
        """Resolve only the IDs sealed in a current root-verified plan decision."""
        from ..remote.core_gateway_inspector import CoreNativeObserverCustody
        from ..remote.jarvis_master_planning import CoreVerifiedJarvisMasterPlanDecision

        if (os.geteuid() != 0 or type(custody) is not CoreNativeObserverCustody
                or type(decision) is not CoreVerifiedJarvisMasterPlanDecision
                or decision.is_current_sealed(config, custody=custody) is not True
                or decision.core_source_generation != custody.core_source_generation):
            return ()
        catalog = _read_catalog(decision.core_source_generation)
        if catalog is None:
            return ()
        selected = decision.selected_source_ids
        sources = catalog["sources"]
        if (type(selected) is not tuple or not 1 <= len(selected) <= 16
                or len(set(selected)) != len(selected)
                or any(source_id not in sources for source_id in selected)):
            return ()
        result = []
        for source_id in selected:
            row = sources[source_id]
            issued = time.monotonic()
            expiry = min(issued + 5.0, decision.expires_monotonic)
            if expiry <= issued:
                return ()
            result.append(cls(
                profile_id=source_id,
                source_revision=catalog["resources_revision"],
                generation_sha256=catalog["artifact_sha256"],
                profile_manifest=row["profile_manifest"],
                profile_manifest_sha256=row["profile_manifest_sha256"],
                profile_member_manifest=row["profile_member_manifest"],
                profile_member_manifest_sha256=row["profile_member_manifest_sha256"],
                effective_prompt=row["prompt"],
                effective_prompt_sha256=row["prompt_sha256"],
                source_member_manifest=row["members"],
                source_member_manifest_sha256=row["source_member_manifest_sha256"],
                required_skill_ids=row["required_skill_ids"],
                required_plugin_ids=row["required_plugin_ids"],
                profile_tool_names=frozenset(),
                profile_privacy_requirements=frozenset(),
                interaction_policy_sha256=row["interaction_policy_sha256"],
                overlay_sha256=catalog["overlay_sha256"],
                core_source_generation=decision.core_source_generation,
                expires_monotonic=expiry,
                _decision=decision, _config=config, _seal=_SOURCE_SEAL,
            ))
        return tuple(result) if _catalog_still_current(catalog) else ()

    def is_current_sealed(self, custody: Any, *, now: float | None = None) -> bool:
        """Re-read decision, root receipt, CAS bytes and every installed member."""
        try:
            from ..remote.core_gateway_inspector import CoreNativeObserverCustody
            from ..remote.jarvis_master_planning import CoreVerifiedJarvisMasterPlanDecision

            current = time.monotonic() if now is None else now
            if (type(self) is not RootSelectedActiveProfileSource
                    or self._seal is not _SOURCE_SEAL
                    or type(custody) is not CoreNativeObserverCustody
                    or type(self._decision) is not CoreVerifiedJarvisMasterPlanDecision
                    or custody.core_source_generation != self.core_source_generation
                    or current >= self.expires_monotonic
                    or self.profile_id not in self._decision.selected_source_ids
                    or self._decision.core_source_generation != self.core_source_generation
                    or self._decision.is_current_sealed(
                        self._config, custody=custody, now=current) is not True):
                return False
            fresh_catalog = _read_catalog(self.core_source_generation)
            if fresh_catalog is None:
                return False
            fresh = fresh_catalog["sources"].get(self.profile_id)
            return bool(fresh is not None and _source_matches(self, fresh, fresh_catalog)
                        and current < self.expires_monotonic
                        and _catalog_still_current(fresh_catalog))
        except Exception:
            return False

    def resolve_current(self, custody: Any) -> "RootSelectedActiveProfileSource | None":
        """Refresh this selected source from its retained sealed plan, never a raw ID."""
        if (type(self) is not RootSelectedActiveProfileSource or self._seal is not _SOURCE_SEAL
                or self.is_current_sealed(custody) is not True):
            return None
        return next((item for item in type(self).resolve_selected(
            self._decision, custody, config=self._config)
            if item.profile_id == self.profile_id), None)


@dataclass(frozen=True, slots=True)
class RootVerifiedJarvisMasterSource:
    """Current Jarvis primary source gated by the full native managed-block readback.

    `active_soul` preserves the owner's complete current primary prompt bytes;
    `profile_prompt` and `managed_block` identify the reviewed bundled addition.
    `native_effective_prompt_*` are the pinned loader's independent, non-content
    digest/length proof. This source is not a claim that Jarvis is functional.
    """

    profile_id: str
    native_profile_key: str
    display_name: str
    source_revision: str
    resources_tree: str
    artifact_sha256: str
    ownership_manifest_sha256: str
    overlay_sha256: str
    profile_prompt: bytes
    profile_prompt_sha256: str
    profile_manifest: bytes
    profile_manifest_sha256: str
    profile_member_manifest: bytes
    profile_member_manifest_sha256: str
    source_member_manifest: tuple[SourceMember, ...]
    source_member_manifest_sha256: str
    active_soul: bytes
    active_soul_sha256: str
    managed_block_sha256: str
    native_effective_prompt_sha256: str
    native_effective_prompt_chars: int
    core_source_generation: str
    core_generation: str
    observed_monotonic: float
    expires_monotonic: float
    _config: Any = field(repr=False, compare=False)
    _seal: object = field(repr=False, compare=False)

    @classmethod
    def current_master_source(cls, custody: Any, config: Any
                              ) -> "RootVerifiedJarvisMasterSource | None":
        """Read the one fixed Hermes/Jarvis source only after real adoption proof."""
        fresh_custody = None
        try:
            from .. import core_runtime as core
            from .. import primary_prompt_manager as primary
            from ..registry.manual_jarvis_skills import _canonical_json
            from ..remote.core_gateway_inspector import (
                CoreGatewayConfig, CoreNativeObserverCustody,
                _NATIVE_CUSTODY_SEAL,
                capture_current_core_native_custody,
            )

            if (os.geteuid() != core.ROOT_UID
                    or type(config) is not CoreGatewayConfig
                    or type(custody) is not CoreNativeObserverCustody
                    or custody._seal is not _NATIVE_CUSTODY_SEAL
                    or custody.core_source_generation != core._core_source_generation()):
                return None
            fresh_custody = capture_current_core_native_custody(config)
            if not _same_core_custody(custody, fresh_custody):
                return None
            primary._check_root_context(core)
            record = primary._read_record(core)
            if not isinstance(record, dict) or record.get("state") != "adopted":
                return None
            status = primary.primary_prompt_status()
            if (status.get("state") != "adopted"
                    or status.get("managed_primary_block_verified") is not True
                    or status.get("effective_prompt_contains_full_block") is not True
                    or status.get("effective_prompt_truncated") is not False
                    or status.get("functional") is not False):
                return None
            (source_generation, discovery, artifact_sha, manifest, files,
             bundled_prompt) = primary._fixed_bundle(core)
            active_soul, active_signature = primary._read_soul(core)
            receipt = primary._record_matches_current(
                core, record, active_soul, manifest, files)
            if (source_generation != custody.core_source_generation
                    or record.get("core_source_generation") != source_generation
                    or record.get("artifact_sha256") != artifact_sha
                    or record.get("source_prompt_sha256") != hashlib.sha256(bundled_prompt).hexdigest()
                    or record.get("result_soul_sha256") != hashlib.sha256(active_soul).hexdigest()
                    or record.get("result_soul_signature") != active_signature
                    or status.get("artifact_sha256") != artifact_sha
                    or status.get("source_prompt_sha256") != record.get("source_prompt_sha256")
                    or status.get("managed_block_sha256") != record.get("managed_block_sha256")
                    or status.get("native_effective_prompt_sha256")
                        != receipt.get("native_effective_prompt_sha256")
                    or status.get("native_effective_prompt_chars")
                        != receipt.get("native_effective_prompt_chars")
                    or receipt.get("effective_prompt_contains_managed_block") is not True
                    or receipt.get("effective_prompt_truncated") is not False
                    or receipt.get("managed_prompt_block_sha256") != record.get("managed_block_sha256")):
                return None
            row = next((item for item in manifest.get("profile_members", ())
                        if item.get("source_id") == "hermes"), None)
            profile_yaml = files.get("registry/profiles/hermes/profile.yaml")
            if (not isinstance(row, dict) or not isinstance(profile_yaml, bytes)
                    or hashlib.sha256(bundled_prompt).hexdigest() != row.get("identity_sha256")
                    or hashlib.sha256(profile_yaml).hexdigest() != row.get("profile_yaml_sha256")):
                return None
            profile_yaml.decode("utf-8", errors="strict")
            block = active_soul[record["owner_prefix_length"]:]
            members = (
                SourceMember("registry/profiles/hermes/SOUL.md",
                             hashlib.sha256(bundled_prompt).hexdigest(), len(bundled_prompt)),
                SourceMember("registry/profiles/hermes/profile.yaml",
                             hashlib.sha256(profile_yaml).hexdigest(), len(profile_yaml)),
            )
            members_bytes = json.dumps(
                [{"path": item.path, "sha256": item.sha256, "size": item.size}
                 for item in members], sort_keys=True, separators=(",", ":")).encode("utf-8")
            row_bytes = _canonical_json(row)
            owner_sha = record.get("ownership_manifest_sha256")
            if not isinstance(owner_sha, str) or _HEX64.fullmatch(owner_sha) is None:
                # The transaction journal intentionally binds the prompt receipt;
                # the full generation ownership digest comes from discovery.
                owner_sha = discovery.get("ownership_manifest_sha256")
            if not isinstance(owner_sha, str) or _HEX64.fullmatch(owner_sha) is None:
                owner_record = json.loads(core._projection_file(
                    core.RESOURCES_RECORD, owner=core.ROOT_UID, group=core.ROOT_UID,
                    mode=0o600, maximum=16 * 1024))
                owner_sha = owner_record.get("ownership_manifest_sha256")
            if not isinstance(owner_sha, str) or _HEX64.fullmatch(owner_sha) is None:
                return None
            issued = time.monotonic()
            # Repeat native effect readback plus fixed source currentness after
            # constructing the projection, before sealing it for the caller.
            journal_bytes = core._projection_file(
                core.PRIMARY_PROMPT_JOURNAL, owner=core.ROOT_UID,
                group=core.ROOT_UID, mode=0o600, maximum=64 * 1024)
            final_soul, final_signature = primary._read_soul(core)
            final_receipt = primary._record_matches_current(
                core, record, final_soul, manifest, files)
            final_discovery = core.read_current_resources_discovery(
                core_source_generation=source_generation)
            if (primary._read_record(core) != record or final_soul != active_soul
                    or final_signature != active_signature
                    or final_receipt != receipt or final_discovery != discovery
                    or core._projection_file(core.PRIMARY_PROMPT_JOURNAL,
                        owner=core.ROOT_UID, group=core.ROOT_UID, mode=0o600,
                        maximum=64 * 1024) != journal_bytes
                    or not _current_core_matches(custody, config,
                        capture_current_core_native_custody)):
                return None
            overlay = manifest.get("effective_overlay")
            if not isinstance(overlay, dict):
                return None
            return cls(
                profile_id="hermes", native_profile_key="default", display_name="Jarvis",
                source_revision=manifest["source"]["revision"],
                resources_tree=manifest["source"]["git_tree"], artifact_sha256=artifact_sha,
                ownership_manifest_sha256=owner_sha,
                overlay_sha256=overlay["sha256"], profile_prompt=bytes(bundled_prompt),
                profile_prompt_sha256=hashlib.sha256(bundled_prompt).hexdigest(),
                profile_manifest=bytes(profile_yaml),
                profile_manifest_sha256=hashlib.sha256(profile_yaml).hexdigest(),
                profile_member_manifest=row_bytes,
                profile_member_manifest_sha256=hashlib.sha256(row_bytes).hexdigest(),
                source_member_manifest=members,
                source_member_manifest_sha256=hashlib.sha256(members_bytes).hexdigest(),
                active_soul=bytes(active_soul),
                active_soul_sha256=hashlib.sha256(active_soul).hexdigest(),
                managed_block_sha256=record["managed_block_sha256"],
                native_effective_prompt_sha256=receipt["native_effective_prompt_sha256"],
                native_effective_prompt_chars=receipt["native_effective_prompt_chars"],
                core_source_generation=source_generation, core_generation=custody.core_generation,
                observed_monotonic=issued, expires_monotonic=issued + 5.0,
                _config=config, _seal=_MASTER_SOURCE_SEAL,
            )
        except Exception:
            return None
        finally:
            if fresh_custody is not None:
                try:
                    os.close(fresh_custody._core_pidfd)
                except OSError:
                    pass

    def is_current_sealed(self, custody: Any, *, now: float | None = None) -> bool:
        try:
            from ..remote.core_gateway_inspector import CoreNativeObserverCustody, _NATIVE_CUSTODY_SEAL
            current = time.monotonic() if now is None else now
            if (type(self) is not RootVerifiedJarvisMasterSource
                    or self._seal is not _MASTER_SOURCE_SEAL
                    or current >= self.expires_monotonic
                    or type(custody) is not CoreNativeObserverCustody
                    or custody._seal is not _NATIVE_CUSTODY_SEAL
                    or custody.core_generation != self.core_generation
                    or custody.core_source_generation != self.core_source_generation):
                return False
            fresh = type(self).current_master_source(custody, self._config)
            return bool(fresh is not None and _master_source_matches(self, fresh)
                        and current < self.expires_monotonic)
        except Exception:
            return False


def _same_core_custody(left: Any, right: Any) -> bool:
    names = ("core_pid", "core_uid", "core_gid", "core_start_ticks", "core_generation",
             "core_invocation_id", "core_listener_inode", "core_source_generation",
             "core_unit_sha256", "core_executable_sha256", "boot_id", "config_sha256")
    return all(getattr(left, name, None) == getattr(right, name, object()) for name in names)


def _current_core_matches(custody: Any, config: Any, capture: Any) -> bool:
    latest = None
    try:
        latest = capture(config)
        return _same_core_custody(custody, latest)
    except Exception:
        return False
    finally:
        if latest is not None:
            try:
                os.close(latest._core_pidfd)
            except OSError:
                pass


def _master_source_matches(left: RootVerifiedJarvisMasterSource,
                           right: RootVerifiedJarvisMasterSource) -> bool:
    fields = (
        "profile_id", "native_profile_key", "display_name", "source_revision",
        "resources_tree", "artifact_sha256", "ownership_manifest_sha256", "overlay_sha256",
        "profile_prompt_sha256", "profile_manifest_sha256", "profile_member_manifest_sha256",
        "source_member_manifest_sha256", "active_soul_sha256", "managed_block_sha256",
        "native_effective_prompt_sha256", "native_effective_prompt_chars",
        "core_source_generation", "core_generation",
    )
    return all(getattr(left, name) == getattr(right, name) for name in fields)


def _read_catalog(core_source_generation: str) -> dict[str, Any] | None:
    from .. import core_runtime
    if (os.geteuid() != core_runtime.ROOT_UID
            or not isinstance(core_source_generation, str)
            or _HEX64.fullmatch(core_source_generation) is None):
        return None
    before = core_runtime.read_current_resources_discovery(
        core_source_generation=core_source_generation)
    if before.get("resources_state") != "discovered":
        return None
    record_bytes = core_runtime._projection_file(
        core_runtime.RESOURCES_RECORD, owner=core_runtime.ROOT_UID,
        group=core_runtime.ROOT_UID, mode=0o600, maximum=16 * 1024)
    record = json.loads(record_bytes)
    artifact_sha = record.get("artifact_sha256")
    if (record.get("core_source_generation") != core_source_generation
            or artifact_sha != before.get("artifact_sha256")
            or not isinstance(artifact_sha, str) or _HEX64.fullmatch(artifact_sha) is None):
        return None
    archive = core_runtime._projection_file(
        core_runtime.RESOURCES_CAS / (artifact_sha + ".zip"), owner=core_runtime.ROOT_UID,
        group=core_runtime.ROOT_UID, mode=0o600, maximum=16 * 1024 * 1024)
    if hashlib.sha256(archive).hexdigest() != artifact_sha:
        return None
    from ..registry import manual_jarvis_skills as native
    manifest, files = native._read_artifact(archive, artifact_sha)
    profile_rows = manifest.get("profile_members")
    if not isinstance(profile_rows, list) or len(profile_rows) != 208:
        return None
    sources: dict[str, dict[str, Any]] = {}
    for member_row in profile_rows:
        source = _profile_source(member_row, files)
        if source is None or source["profile_id"] in sources:
            return None
        sources[source["profile_id"]] = source
    if len(sources) != 208:
        return None
    overlay = manifest.get("effective_overlay")
    if (not isinstance(overlay, dict) or overlay.get("overlay_id") != "jarvis-master-semantics-v2"
            or not isinstance(overlay.get("sha256"), str)
            or _HEX64.fullmatch(overlay["sha256"]) is None):
        return None
    owner_sha = core_runtime._hash_generation_tree(
        core_runtime.HERMES_HOME, manifest, files, artifact_sha)
    if owner_sha != record.get("ownership_manifest_sha256"):
        return None
    snapshot = {
        "before": before, "record_bytes": record_bytes, "record": record,
        "manifest": manifest, "files": files, "artifact_sha256": artifact_sha,
        "ownership_sha256": owner_sha, "resources_revision": manifest["source"]["revision"],
        "overlay_sha256": overlay["sha256"], "sources": sources,
    }
    return snapshot if _catalog_still_current(snapshot) else None


def _profile_source(row: Any, files: dict[str, bytes]) -> dict[str, Any] | None:
    if not isinstance(row, dict):
        return None
    profile_id = row.get("source_id")
    if not isinstance(profile_id, str) or _ID.fullmatch(profile_id) is None:
        return None
    base = f"registry/profiles/{profile_id}/"
    prompt, profile_yaml = files.get(base + "SOUL.md"), files.get(base + "profile.yaml")
    if (not isinstance(prompt, bytes) or not 0 < len(prompt) <= MAX_PROMPT_BYTES
            or not isinstance(profile_yaml, bytes)
            or not 0 < len(profile_yaml) <= MAX_PROFILE_MANIFEST_BYTES
            or hashlib.sha256(prompt).hexdigest() != row.get("identity_sha256")
            or hashlib.sha256(profile_yaml).hexdigest() != row.get("profile_yaml_sha256")):
        return None
    prompt.decode("utf-8", errors="strict")
    profile_yaml.decode("utf-8", errors="strict")
    document = _parse_profile(profile_yaml, profile_id)
    if document is None:
        return None
    members = (
        SourceMember(base + "SOUL.md", hashlib.sha256(prompt).hexdigest(), len(prompt)),
        SourceMember(base + "profile.yaml", hashlib.sha256(profile_yaml).hexdigest(), len(profile_yaml)),
    )
    canonical_member_rows = [{"path": item.path, "sha256": item.sha256, "size": item.size}
                             for item in members]
    member_bytes = json.dumps(canonical_member_rows, sort_keys=True,
                              separators=(",", ":")).encode("utf-8")
    profile_member_bytes = json.dumps(row, ensure_ascii=False, sort_keys=True,
                                      separators=(",", ":")).encode("utf-8")
    interaction_bytes = json.dumps(document["interaction"], ensure_ascii=False,
                                   sort_keys=True, separators=(",", ":")).encode("utf-8")
    return {
        "profile_id": profile_id, "profile_manifest": profile_yaml,
        "profile_manifest_sha256": hashlib.sha256(profile_yaml).hexdigest(),
        "profile_member_manifest": profile_member_bytes,
        "profile_member_manifest_sha256": hashlib.sha256(profile_member_bytes).hexdigest(),
        "prompt": prompt, "prompt_sha256": hashlib.sha256(prompt).hexdigest(),
        "members": members, "source_member_manifest_sha256": hashlib.sha256(member_bytes).hexdigest(),
        "required_skill_ids": frozenset(document["required_skill_ids"]),
        "required_plugin_ids": frozenset(document["required_plugin_ids"]),
        "interaction_policy_sha256": hashlib.sha256(interaction_bytes).hexdigest(),
    }


def _parse_profile(raw: bytes, profile_id: str) -> dict[str, Any] | None:
    try:
        import yaml
        value = yaml.safe_load(raw.decode("utf-8", errors="strict"))
        if (not isinstance(value, dict) or value.get("kind") != "Profile"
                or not isinstance(value.get("metadata"), dict)
                or value["metadata"].get("name") != profile_id
                or not isinstance(value.get("spec"), dict)):
            return None
        spec = value["spec"]
        requires = spec.get("requires", {})
        if not isinstance(requires, dict):
            return None
        def dependencies(kind: str) -> tuple[str, ...] | None:
            entries = requires.get(kind, [])
            if not isinstance(entries, list) or len(entries) > 256:
                return None
            result = []
            for entry in entries:
                if not isinstance(entry, str) or "@" not in entry:
                    return None
                identity, version = entry.split("@", 1)
                if (_ID.fullmatch(identity) is None
                        or re.fullmatch(r"\^[0-9]+\.[0-9]+\.[0-9]+", version) is None):
                    return None
                result.append(identity)
            if len(set(result)) != len(result):
                return None
            return tuple(sorted(result))
        skills, plugins = dependencies("skills"), dependencies("plugins")
        interaction = spec.get("interaction", {})
        if skills is None or plugins is None or not isinstance(interaction, dict):
            return None
        return {"required_skill_ids": skills, "required_plugin_ids": plugins,
                "interaction": interaction}
    except Exception:
        return None


def _catalog_still_current(snapshot: dict[str, Any]) -> bool:
    try:
        from .. import core_runtime
        record = core_runtime._projection_file(
            core_runtime.RESOURCES_RECORD, owner=core_runtime.ROOT_UID,
            group=core_runtime.ROOT_UID, mode=0o600, maximum=16 * 1024)
        generation = snapshot["record"]["core_source_generation"]
        projection = core_runtime.read_current_resources_discovery(
            core_source_generation=generation)
        archive = core_runtime._projection_file(
            core_runtime.RESOURCES_CAS / (snapshot["artifact_sha256"] + ".zip"),
            owner=core_runtime.ROOT_UID, group=core_runtime.ROOT_UID,
            mode=0o600, maximum=16 * 1024 * 1024)
        if (record != snapshot["record_bytes"] or projection != snapshot["before"]
                or hashlib.sha256(archive).hexdigest() != snapshot["artifact_sha256"]):
            return False
        if snapshot.get("manifest") is not None:
            owner_sha = core_runtime._hash_generation_tree(
                core_runtime.HERMES_HOME, snapshot["manifest"], snapshot["files"],
                snapshot["artifact_sha256"])
            if owner_sha != snapshot["ownership_sha256"]:
                return False
        return True
    except Exception:
        return False


def _source_matches(source: RootSelectedActiveProfileSource,
                    current: dict[str, Any], catalog: dict[str, Any]) -> bool:
    return bool(source.profile_id == current["profile_id"]
                and source.source_revision == catalog["resources_revision"]
                and source.generation_sha256 == catalog["artifact_sha256"]
                and source.profile_manifest == current["profile_manifest"]
                and source.profile_manifest_sha256 == current["profile_manifest_sha256"]
                and source.profile_member_manifest == current["profile_member_manifest"]
                and source.profile_member_manifest_sha256 == current["profile_member_manifest_sha256"]
                and source.effective_prompt == current["prompt"]
                and source.effective_prompt_sha256 == current["prompt_sha256"]
                and source.source_member_manifest == current["members"]
                and source.source_member_manifest_sha256 == current["source_member_manifest_sha256"]
                and source.required_skill_ids == current["required_skill_ids"]
                and source.required_plugin_ids == current["required_plugin_ids"]
                and source.profile_tool_names == frozenset()
                and source.profile_privacy_requirements == frozenset()
                and source.interaction_policy_sha256 == current["interaction_policy_sha256"]
                and source.overlay_sha256 == catalog["overlay_sha256"])
