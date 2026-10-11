"""Sealed, current readback of the bundled internal orchestrator profile.

This module exposes only the fixed ``orchestrator`` identity. It binds exact
profile bytes and their source-manifest member rows to the root-owned current
Resources receipt. It does not activate plugins, grant tools, or establish an
isolation boundary.
"""
from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import dataclass, field
from typing import Any


PROFILE_ID = "orchestrator"
MAX_PROMPT_BYTES = 64 * 1024
MAX_PROFILE_MANIFEST_BYTES = 64 * 1024
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_SOURCE_SEAL = object()


@dataclass(frozen=True, slots=True)
class SourceMember:
    """One immutable path/hash/size row from the fixed retained profile."""

    path: str
    sha256: str
    size: int


@dataclass(frozen=True, slots=True)
class RootSelectedActiveProfileSource:
    """Root-read, short-lived source snapshot for the one internal profile."""

    profile_id: str
    source_revision: str
    generation_sha256: str
    profile_manifest_sha256: str
    effective_prompt: bytes
    effective_prompt_sha256: str
    source_member_manifest: tuple[SourceMember, ...]
    source_member_manifest_sha256: str
    required_skill_ids: frozenset[str]
    required_plugin_ids: frozenset[str]
    profile_tool_names: frozenset[str]
    privacy_requirements: frozenset[str]
    interaction_policy_sha256: str
    core_source_generation: str
    expires_monotonic: float
    _verified_source: object = field(repr=False, compare=False)
    _seal: object = field(repr=False, compare=False)

    @classmethod
    def resolve_current(cls, custody: object) -> "RootSelectedActiveProfileSource | None":
        """Resolve only from the fixed root readback and an exact sealed custody."""
        try:
            from ..core_runtime import read_current_resources_profile_source
            from ..remote.core_gateway_inspector import CoreNativeObserverCustody

            if type(custody) is not CoreNativeObserverCustody:
                return None
            core_generation = getattr(custody, "core_source_generation", None)
            if not isinstance(core_generation, str) or not _HEX64.fullmatch(core_generation):
                return None
            source = read_current_resources_profile_source(
                core_source_generation=core_generation
            )
            if (source is None or source.profile_id != PROFILE_ID
                    or not source.is_current_sealed(custody)):
                return None
            prompt = bytes(source.profile_prompt)
            profile_yaml = bytes(source.profile_manifest)
            member_row = json.loads(source.profile_member_manifest)
            profile_doc = _load_profile_manifest(profile_yaml)
            members = _source_members(member_row, prompt, profile_yaml)
            if not members:
                return None
            now = time.monotonic()
            if not now < source.expires_monotonic <= now + 5.0:
                return None
            result = cls(
                profile_id=PROFILE_ID,
                source_revision=source.resources_revision,
                generation_sha256=source.artifact_sha256,
                profile_manifest_sha256=source.profile_manifest_sha256,
                effective_prompt=prompt,
                effective_prompt_sha256=source.profile_prompt_sha256,
                source_member_manifest=members,
                source_member_manifest_sha256=source.profile_member_manifest_sha256,
                required_skill_ids=frozenset(profile_doc["required_skill_ids"]),
                required_plugin_ids=frozenset(profile_doc["required_plugin_ids"]),
                profile_tool_names=frozenset(profile_doc["profile_tool_names"]),
                privacy_requirements=frozenset(),
                interaction_policy_sha256=profile_doc["interaction_policy_sha256"],
                core_source_generation=core_generation,
                expires_monotonic=source.expires_monotonic,
                _verified_source=source,
                _seal=_SOURCE_SEAL,
            )
            return result
        except Exception:
            return None

    def is_current_sealed(self, custody: object, *, now: float | None = None) -> bool:
        """Re-read the fixed protected source and reject stale or forged values."""
        try:
            from ..core_runtime import VerifiedResourcesProfileSource
            from ..remote.core_gateway_inspector import CoreNativeObserverCustody

            current = time.monotonic() if now is None else now
            if (type(self) is not RootSelectedActiveProfileSource
                    or self._seal is not _SOURCE_SEAL
                    or type(custody) is not CoreNativeObserverCustody
                    or custody.core_source_generation != self.core_source_generation
                    or current >= self.expires_monotonic
                    or type(self._verified_source) is not VerifiedResourcesProfileSource
                    or not self._verified_source.verify_current(
                        core_source_generation=self.core_source_generation, now=current
                    )):
                return False
            from ..core_runtime import read_current_resources_profile_source
            fresh_source = read_current_resources_profile_source(
                core_source_generation=self.core_source_generation
            )
            if (fresh_source is None or fresh_source.profile_id != PROFILE_ID
                    or not fresh_source.verify_current(
                        core_source_generation=self.core_source_generation, now=current
                    )):
                return False
            fresh = self._from_verified_source(custody, fresh_source)
            return bool(
                fresh is not None
                and fresh._seal is _SOURCE_SEAL
                and fresh.profile_id == self.profile_id
                and fresh.source_revision == self.source_revision
                and fresh.generation_sha256 == self.generation_sha256
                and fresh.profile_manifest_sha256 == self.profile_manifest_sha256
                and fresh.effective_prompt == self.effective_prompt
                and fresh.effective_prompt_sha256 == self.effective_prompt_sha256
                and fresh.source_member_manifest == self.source_member_manifest
                and fresh.source_member_manifest_sha256 == self.source_member_manifest_sha256
                and fresh.required_skill_ids == self.required_skill_ids
                and fresh.required_plugin_ids == self.required_plugin_ids
                and fresh.profile_tool_names == self.profile_tool_names
                and fresh.privacy_requirements == self.privacy_requirements
                and fresh.interaction_policy_sha256 == self.interaction_policy_sha256
                and current < self.expires_monotonic
            )
        except Exception:
            return False

    @classmethod
    def _from_verified_source(cls, custody: object, source: object):
        """Reconstruct an immutable comparison value from a sealed source read."""
        from ..remote.core_gateway_inspector import CoreNativeObserverCustody
        if (type(custody) is not CoreNativeObserverCustody
                or getattr(custody, "core_source_generation", None)
                != getattr(source, "core_source_generation", None)):
            return None
        if not source.is_current_sealed(custody):
            return None
        prompt = bytes(source.profile_prompt)
        profile_yaml = bytes(source.profile_manifest)
        row = json.loads(source.profile_member_manifest)
        doc = _load_profile_manifest(profile_yaml)
        members = _source_members(row, prompt, profile_yaml)
        if not members:
            return None
        return cls(
            profile_id=PROFILE_ID,
            source_revision=source.resources_revision,
            generation_sha256=source.artifact_sha256,
            profile_manifest_sha256=source.profile_manifest_sha256,
            effective_prompt=prompt,
            effective_prompt_sha256=source.profile_prompt_sha256,
            source_member_manifest=members,
            source_member_manifest_sha256=source.profile_member_manifest_sha256,
            required_skill_ids=frozenset(doc["required_skill_ids"]),
            required_plugin_ids=frozenset(doc["required_plugin_ids"]),
            profile_tool_names=frozenset(doc["profile_tool_names"]),
            privacy_requirements=frozenset(),
            interaction_policy_sha256=doc["interaction_policy_sha256"],
            core_source_generation=source.core_source_generation,
            expires_monotonic=source.expires_monotonic,
            _verified_source=source,
            _seal=_SOURCE_SEAL,
        )


def _source_members(row: Any, prompt: bytes, profile_yaml: bytes) -> tuple[SourceMember, ...]:
    if not isinstance(row, dict) or row.get("source_id") != PROFILE_ID:
        return ()
    expected = {
        "registry/profiles/orchestrator/SOUL.md": row.get("identity_sha256"),
        "registry/profiles/orchestrator/profile.yaml": row.get("profile_yaml_sha256"),
    }
    if len(prompt) > MAX_PROMPT_BYTES or len(profile_yaml) > MAX_PROFILE_MANIFEST_BYTES:
        return ()
    members = (
        SourceMember("registry/profiles/orchestrator/SOUL.md", hashlib.sha256(prompt).hexdigest(), len(prompt)),
        SourceMember("registry/profiles/orchestrator/profile.yaml", hashlib.sha256(profile_yaml).hexdigest(), len(profile_yaml)),
    )
    for member in members:
        if (expected.get(member.path) != member.sha256 or not _HEX64.fullmatch(member.sha256)
                or member.size <= 0 or member.size > MAX_PROFILE_MANIFEST_BYTES):
            return ()
    return members


def _load_profile_manifest(payload: bytes) -> dict[str, Any]:
    if not isinstance(payload, bytes) or not payload or len(payload) > MAX_PROFILE_MANIFEST_BYTES:
        raise ValueError("profile manifest missing or oversized")
    import yaml

    value = yaml.safe_load(payload.decode("utf-8", errors="strict"))
    if (not isinstance(value, dict) or value.get("kind") != "Profile"
            or not isinstance(value.get("metadata"), dict)
            or value["metadata"].get("name") != PROFILE_ID):
        raise ValueError("source profile identity is not the fixed orchestrator")
    spec = value.get("spec")
    if not isinstance(spec, dict):
        raise ValueError("source profile spec is missing")
    required = spec.get("requires", {})
    if not isinstance(required, dict):
        raise ValueError("source requirements have an invalid shape")

    def ids(kind: str) -> tuple[str, ...]:
        entries = required.get(kind, [])
        if not isinstance(entries, list):
            raise ValueError("source requirements have an invalid member list")
        result: list[str] = []
        for entry in entries:
            if not isinstance(entry, str) or not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,95}@\^[0-9]+\.[0-9]+\.[0-9]+", entry):
                raise ValueError("source requirement identity is malformed")
            result.append(entry.split("@", 1)[0])
        if len(result) != len(set(result)):
            raise ValueError("source requirements contain duplicate identities")
        return tuple(sorted(result))

    interaction = spec.get("interaction", {})
    if not isinstance(interaction, dict):
        raise ValueError("source interaction policy has an invalid shape")
    expected_interaction = {
        "userFacing": False,
        "directUserContact": "deny",
        "userChannelBinding": "deny",
        "acceptRequestsFrom": ["hermes"],
        "returnResultsTo": ["hermes"],
        "clarificationVia": ["hermes"],
    }
    if interaction != expected_interaction:
        raise ValueError("source interaction policy differs from the reviewed internal-only contract")
    return {
        "required_skill_ids": ids("skills"),
        "required_plugin_ids": ids("plugins"),
        # The pinned profile source has no tool-grant key. Required skill and
        # plugin IDs describe dependencies, not executable authorization.
        "profile_tool_names": (),
        "interaction_policy_sha256": hashlib.sha256(
            json.dumps(interaction, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest(),
    }
