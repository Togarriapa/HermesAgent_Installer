"""Deterministic, non-authoritative owner overlays for pinned Resources skills.

The checked-in Resources artifact remains immutable. An effective artifact is
derived from it by changing only one already-pinned ``SKILL.md`` member and its
manifest digest/length. Root owns the durable overlay journal and native
materialization transaction; this module only validates and constructs bytes.
"""
from __future__ import annotations

import hashlib
import io
import re
import zipfile
from typing import Any

from . import manual_jarvis_skills as native


class ResourcesSkillOverlayError(ValueError):
    """An owner overlay does not fit the immutable Resources contract."""


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def build_effective_artifact(base_archive: bytes, skill_id: str, content: bytes) -> tuple[bytes, str]:
    """Return canonical effective archive and its digest, changing one pinned skill."""
    if (not isinstance(skill_id, str) or re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", skill_id) is None
            or not isinstance(content, bytes) or not content or len(content) > native._MEMBER_LIMIT
            or b"\x00" in content):
        raise ResourcesSkillOverlayError("owner skill content or identity is invalid")
    try:
        content.decode("utf-8")
    except UnicodeDecodeError:
        raise ResourcesSkillOverlayError("owner skill content must be UTF-8") from None
    if not content.startswith(f"---\nname: {skill_id}\n".encode("ascii")):
        raise ResourcesSkillOverlayError("owner content must preserve the pinned native skill identity")
    base_sha = sha256(base_archive)
    manifest, files = native._read_artifact(base_archive, base_sha)
    row = next((item for item in manifest["skill_members"] if item["skill_id"] == skill_id), None)
    if row is None:
        raise ResourcesSkillOverlayError("skill is not a member of the pinned Resources artifact")
    files[row["archive_path"]] = content
    row["size_bytes"] = len(content)
    row["sha256"] = sha256(content)
    # Provenance describes the immutable bundle. Overlay metadata is added only
    # in the root journal, never to the pinned source declarations.
    with io.BytesIO() as stream:
        with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_STORED) as archive:
            native._zip_write(archive, "manifest.json", native._canonical_json(manifest))
            for name in sorted(files):
                native._zip_write(archive, name, files[name])
            with zipfile.ZipFile(io.BytesIO(base_archive)) as original:
                native._zip_write(archive, "manual_stage_jarvis_skills.py",
                                  original.read("manual_stage_jarvis_skills.py"))
        result = stream.getvalue()
    result_sha = sha256(result)
    # _read_artifact validates every immutable declaration and all member hashes.
    native._read_artifact(result, result_sha)
    return result, result_sha


def pinned_skill_bytes(archive: bytes, skill_id: str) -> bytes:
    """Read one validated pinned member from an artifact."""
    manifest, files = native._read_artifact(archive, sha256(archive))
    row = next((item for item in manifest["skill_members"] if item["skill_id"] == skill_id), None)
    if row is None:
        raise ResourcesSkillOverlayError("skill is not a member of the pinned Resources artifact")
    return files[row["archive_path"]]


def compose_overlays(base_archive: bytes, overlays: dict[str, bytes]) -> tuple[bytes, dict[str, str]]:
    """Compose validated active member overrides in stable ID order."""
    current = base_archive
    archive_digests: dict[str, str] = {}
    for skill_id, content in sorted(overlays.items()):
        current, digest = build_effective_artifact(current, skill_id, content)
        archive_digests[skill_id] = digest
    return current, archive_digests
