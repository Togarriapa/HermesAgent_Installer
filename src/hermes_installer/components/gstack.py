"""Pinned gstack profile instructions for Hermes.

The selected gstack revision explicitly marks Hermes as instruction-only.
This adapter preserves its exact generated digest for profile composition and
does not enable gstack's executable browser, build, or host hooks.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Mapping

from hermes_installer.components.adapters import resolve_component_adapter


_DIGEST = "agents-digest/gstack-AGENTS.md"
_HERMES_HOST = "hosts/hermes.ts"
_PACKAGE = "package.json"
_PROFILE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")


class GstackAdapterError(ValueError):
    """Pinned Hermes instructions are missing or no longer match their source."""


@dataclass(frozen=True, slots=True)
class GstackProfileInstructionBinding:
    profile_id: str
    source_revision: str
    source_path: str
    instructions: bytes
    sha256: str
    native_invocation_available: bool = False
    native_invocation_reason: str = "upstream declares Hermes tier instruction-only"

    def append_to(self, existing_instructions: str) -> str:
        """Compose the exact digest into a selected profile's instruction text."""
        try:
            digest = self.instructions.decode("utf-8")
            existing_instructions.encode("utf-8")
        except (UnicodeDecodeError, UnicodeEncodeError):
            raise GstackAdapterError("profile instructions and gstack digest must be UTF-8") from None
        prefix = existing_instructions.rstrip()
        heading = f"## gstack instructions ({self.source_revision})\n\n"
        section = heading + digest
        return f"{prefix}\n\n{section}" if prefix else section


def bind_gstack_profile_instructions(
    profile_id: str,
    files: Mapping[str, bytes],
) -> GstackProfileInstructionBinding:
    """Bind the selected source's exact Hermes digest without executing setup."""
    contract = resolve_component_adapter("gstack")
    if not _PROFILE_ID.fullmatch(profile_id):
        raise GstackAdapterError("selected profile id is malformed")
    package_bytes, host_bytes, digest = (files.get(_PACKAGE), files.get(_HERMES_HOST), files.get(_DIGEST))
    if not all(isinstance(value, bytes) and value for value in (package_bytes, host_bytes, digest)):
        raise GstackAdapterError("pinned gstack package, Hermes host contract, and instruction digest are required")
    try:
        package = json.loads(package_bytes)
        host = host_bytes.decode("utf-8")
        digest.decode("utf-8")
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise GstackAdapterError("pinned gstack source metadata is malformed") from None
    if not isinstance(package, dict):
        raise GstackAdapterError("pinned gstack package metadata is malformed")
    if (package.get("name"), package.get("version"), package.get("license")) != ("gstack", "1.91.68", "MIT"):
        raise GstackAdapterError("gstack package metadata does not match the reviewed source pin")
    if not re.search(r"name:\s*'hermes'[\s\S]{0,220}?tier:\s*'instruction-only'", host):
        raise GstackAdapterError("pinned gstack source no longer declares Hermes instruction-only")
    if contract.revision != "20eb6202fa8ea83a882e7c0463b722cd8a31af1e":
        raise GstackAdapterError("gstack adapter pin differs from the selected source contract")
    return GstackProfileInstructionBinding(
        profile_id=profile_id,
        source_revision=contract.revision,
        source_path=_DIGEST,
        instructions=digest,
        sha256=hashlib.sha256(digest).hexdigest(),
    )
