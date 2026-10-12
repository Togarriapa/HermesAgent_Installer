"""Deterministic, non-authoritative owner overlays for pinned Resources skills.

The checked-in Resources artifact remains immutable. An effective artifact is
derived from it by changing only one already-pinned ``SKILL.md`` member and its
manifest digest/length. Root owns the durable overlay journal and native
materialization transaction; this module only validates and constructs bytes.
"""
from __future__ import annotations

import hashlib
import io
import json
import re
import zipfile
from dataclasses import dataclass
from typing import Any, Mapping

from . import manual_jarvis_skills as native


class ResourcesSkillOverlayError(ValueError):
    """An owner overlay does not fit the immutable Resources contract."""


@dataclass(frozen=True, slots=True)
class HelperOnlyOverlayReconstruction:
    """Non-authoritative bytes and digests derived from exact retained inputs."""
    new_composed_archive: bytes
    old_base_artifact_sha256: str
    new_base_artifact_sha256: str
    old_composed_artifact_sha256: str
    new_composed_artifact_sha256: str
    overlay_journal_sha256: str
    overlay_contents: tuple[tuple[str, str], ...]
    base_non_installer_manifest_sha256: str
    composed_non_installer_manifest_sha256: str
    materialized_tree_sha256: str
    shared_member_count: int
    verified_intermediate_archive_sha256: tuple[tuple[str, str], ...]


_HELPER_PATH = "manual_stage_jarvis_skills.py"
_OVERLAY_JOURNAL_KEYS = {"schema", "base_artifact_sha256", "skills"}


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _strict_json(raw: bytes):
    return json.loads(raw, object_pairs_hook=_unique_object)


def _strict_archive(archive_bytes: bytes):
    """Run strict duplicate-key checks before the full pinned parser."""
    if (type(archive_bytes) is not bytes or not archive_bytes
            or len(archive_bytes) > native._ARTIFACT_LIMIT):
        raise ResourcesSkillOverlayError("overlay reconstruction archive is outside its bound")
    try:
        with zipfile.ZipFile(io.BytesIO(archive_bytes), "r") as archive:
            infos = archive.infolist()
            names = [info.filename for info in infos]
            if len(names) != len(set(names)) or "manifest.json" not in names:
                raise ValueError
            raw_manifest = archive.read("manifest.json")
            manifest = _strict_json(raw_manifest)
            if type(manifest) is not dict:
                raise ValueError
            return native._read_artifact(archive_bytes, sha256(archive_bytes))
    except (OSError, ValueError, TypeError, KeyError, zipfile.BadZipFile,
            json.JSONDecodeError, native.ManualJarvisSkillsError):
        raise ResourcesSkillOverlayError("overlay reconstruction archive is malformed") from None


def _helper_bytes(archive_bytes: bytes, manifest: dict[str, Any]) -> bytes:
    row = manifest.get("installer")
    if (type(row) is not dict or set(row) != {"archive_path", "size_bytes", "sha256"}
            or row.get("archive_path") != _HELPER_PATH
            or type(row.get("size_bytes")) is not int or not 0 < row["size_bytes"] <= 1024 * 1024
            or not isinstance(row.get("sha256"), str)
            or re.fullmatch(r"[0-9a-f]{64}", row["sha256"]) is None):
        raise ResourcesSkillOverlayError("overlay reconstruction helper metadata differs")
    try:
        with zipfile.ZipFile(io.BytesIO(archive_bytes), "r") as archive:
            value = archive.read(_HELPER_PATH)
    except (OSError, KeyError, zipfile.BadZipFile):
        raise ResourcesSkillOverlayError("overlay reconstruction helper is missing") from None
    if len(value) != row["size_bytes"] or sha256(value) != row["sha256"]:
        raise ResourcesSkillOverlayError("overlay reconstruction helper bytes differ")
    return value


def _non_installer_manifest_sha256(manifest: Mapping[str, Any]) -> str:
    value = dict(manifest)
    value.pop("installer", None)
    return sha256(native._canonical_json(value))


def _materialization_digest(manifest: Mapping[str, Any], files: Mapping[str, bytes]):
    rows = [{"path": name, "size_bytes": len(content), "sha256": sha256(content)}
            for name, content in sorted(files.items())]
    return sha256(native._canonical_json(rows)), len(rows)


def _require_helper_only_pair(old_manifest, old_files, new_manifest, new_files):
    classifier = getattr(native, "verify_same_materialization_transition", None)
    if not callable(classifier) or not classifier(old_manifest, old_files, new_manifest, new_files):
        raise ResourcesSkillOverlayError("archives are not the reviewed helper-only pair")


def _derive_helper_replacement(old_composed: bytes, new_base: bytes,
                               old_manifest: dict[str, Any], old_files: dict[str, bytes],
                               new_manifest: dict[str, Any], new_files: dict[str, bytes]) -> bytes:
    # This pair is intentionally not sent through the base classifier: A0
    # contains owner-edited skill bytes while B1 is pristine. B0→B1 and the
    # derived A0→A1 pair are independently checked by the caller. Here A0 is
    # copied byte-for-byte except for B1's verified installer row/helper.
    new_helper = _helper_bytes(new_base, new_manifest)
    changed_manifest = dict(old_manifest)
    changed_manifest["installer"] = dict(new_manifest["installer"])
    with io.BytesIO() as stream:
        with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_STORED) as out:
            native._zip_write(out, "manifest.json", native._canonical_json(changed_manifest))
            for name in sorted(old_files):
                native._zip_write(out, name, old_files[name])
            native._zip_write(out, _HELPER_PATH, new_helper)
        return stream.getvalue()


def reconstruct_helper_only_overlay_transition(
    old_base_archive: bytes, new_base_archive: bytes, old_composed_archive: bytes,
    overlay_record_bytes: bytes, overlay_contents: Mapping[str, bytes],
) -> HelperOnlyOverlayReconstruction:
    """Rebuild exact B0→A0 history, then derive A1 by only helper replacement.

    Every value is caller-supplied data and this result carries no authority.
    Root must derive each input from protected current CAS/journal custody and
    bind the returned digests inside its sealed cohort transaction.
    """
    if (type(overlay_record_bytes) is not bytes or not overlay_record_bytes
            or len(overlay_record_bytes) > 256 * 1024
            or type(overlay_contents) is not dict or len(overlay_contents) > 396
            or any(type(name) is not str or type(data) is not bytes
                   for name, data in overlay_contents.items())):
        raise ResourcesSkillOverlayError("overlay reconstruction inputs are outside their bound")
    try:
        journal = _strict_json(overlay_record_bytes)
    except (ValueError, TypeError, json.JSONDecodeError):
        raise ResourcesSkillOverlayError("overlay reconstruction journal is malformed") from None
    if (type(journal) is not dict or set(journal) != _OVERLAY_JOURNAL_KEYS
            or type(journal.get("schema")) is not int or journal["schema"] != 1
            or type(journal.get("base_artifact_sha256")) is not str
            or re.fullmatch(r"[0-9a-f]{64}", journal["base_artifact_sha256"]) is None
            or type(journal.get("skills")) is not dict
            or len(journal["skills"]) != len(overlay_contents)):
        raise ResourcesSkillOverlayError("overlay reconstruction journal schema differs")

    b0_manifest, b0_files = _strict_archive(old_base_archive)
    b1_manifest, b1_files = _strict_archive(new_base_archive)
    a0_manifest, a0_files = _strict_archive(old_composed_archive)
    b0_sha, b1_sha, a0_sha = map(sha256, (old_base_archive, new_base_archive, old_composed_archive))
    if journal["base_artifact_sha256"] != b0_sha:
        raise ResourcesSkillOverlayError("overlay journal does not retain the supplied original base")
    _require_helper_only_pair(b0_manifest, b0_files, b1_manifest, b1_files)
    helper_b0 = _helper_bytes(old_base_archive, b0_manifest)
    _helper_bytes(new_base_archive, b1_manifest)
    _helper_bytes(old_composed_archive, a0_manifest)
    if _helper_bytes(old_composed_archive, a0_manifest) != helper_b0:
        raise ResourcesSkillOverlayError("old composed helper differs from its retained base")

    rows_by_skill = {row["skill_id"]: row for row in b0_manifest["skill_members"]}
    if set(journal["skills"]) != set(overlay_contents):
        raise ResourcesSkillOverlayError("overlay journal and content set differ")
    for skill_id, row in journal["skills"].items():
        content = overlay_contents[skill_id]
        if (re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", skill_id) is None
                or type(row) is not dict or set(row) != {"content_sha256", "archive_sha256"}
                or type(row.get("content_sha256")) is not str
                or type(row.get("archive_sha256")) is not str
                or re.fullmatch(r"[0-9a-f]{64}", row["content_sha256"]) is None
                or re.fullmatch(r"[0-9a-f]{64}", row["archive_sha256"]) is None
                or len(content) == 0 or len(content) > native._MEMBER_LIMIT
                or b"\x00" in content or sha256(content) != row["content_sha256"]
                or skill_id not in rows_by_skill
                or not content.startswith(f"---\nname: {skill_id}\n".encode("ascii"))):
            raise ResourcesSkillOverlayError("overlay content does not match its retained journal row")
        try:
            content.decode("utf-8", "strict")
        except UnicodeDecodeError:
            raise ResourcesSkillOverlayError("overlay content is not UTF-8") from None

    # Compose in the existing stable ID order. Verify each historic output
    # hash, then the complete canonical A0 bytes, not merely a final alias.
    current = old_base_archive
    intermediate = []
    for skill_id, content in sorted(overlay_contents.items()):
        current, current_sha = build_effective_artifact(current, skill_id, content)
        intermediate.append((skill_id, current_sha))
        if current_sha != journal["skills"][skill_id]["archive_sha256"]:
            raise ResourcesSkillOverlayError("retained overlay intermediate archive digest differs")
    if current != old_composed_archive or sha256(current) != a0_sha:
        raise ResourcesSkillOverlayError("retained overlay chain does not reproduce exact old composed bytes")

    a1_archive = _derive_helper_replacement(
        old_composed_archive, new_base_archive, a0_manifest, a0_files, b1_manifest, b1_files)
    a1_manifest, a1_files = _strict_archive(a1_archive)
    a1_sha = sha256(a1_archive)
    _require_helper_only_pair(a0_manifest, a0_files, a1_manifest, a1_files)
    if _helper_bytes(a1_archive, a1_manifest) != _helper_bytes(new_base_archive, b1_manifest):
        raise ResourcesSkillOverlayError("derived composed helper differs from reviewed new base")
    base_manifest_sha = _non_installer_manifest_sha256(b1_manifest)
    composed_manifest_sha = _non_installer_manifest_sha256(a1_manifest)
    base_tree_sha, base_count = _materialization_digest(b1_manifest, b1_files)
    composed_tree_sha, composed_count = _materialization_digest(a1_manifest, a1_files)
    old_base_tree_sha, old_base_count = _materialization_digest(b0_manifest, b0_files)
    old_composed_tree_sha, old_composed_count = _materialization_digest(a0_manifest, a0_files)
    if (base_manifest_sha != _non_installer_manifest_sha256(b0_manifest)
            or composed_manifest_sha != _non_installer_manifest_sha256(a0_manifest)
            or base_tree_sha != old_base_tree_sha or base_count != old_base_count
            or composed_tree_sha != old_composed_tree_sha
            or composed_count != old_composed_count or base_count != composed_count):
        raise ResourcesSkillOverlayError("helper-only reconstruction changed non-installer materialization")
    return HelperOnlyOverlayReconstruction(
        new_composed_archive=a1_archive,
        old_base_artifact_sha256=b0_sha,
        new_base_artifact_sha256=b1_sha,
        old_composed_artifact_sha256=a0_sha,
        new_composed_artifact_sha256=a1_sha,
        overlay_journal_sha256=sha256(overlay_record_bytes),
        overlay_contents=tuple((name, sha256(value)) for name, value in sorted(overlay_contents.items())),
        base_non_installer_manifest_sha256=base_manifest_sha,
        composed_non_installer_manifest_sha256=composed_manifest_sha,
        materialized_tree_sha256=composed_tree_sha,
        shared_member_count=composed_count,
        verified_intermediate_archive_sha256=tuple(intermediate),
    )


def verify_committed_helper_only_overlay_reconstruction(
    reconstruction: HelperOnlyOverlayReconstruction,
    cohort_row: Mapping[str, Any], *, current_context: Mapping[str, Any],
) -> bool:
    """Join typed reconstruction data to one exact committed root cohort row.

    The caller must obtain ``cohort_row`` and ``current_context`` from held
    protected Root records and separately prove current discovery, CAS, source,
    overlay bytes, installed journal/tree and service custody before using the
    result. This pure comparison never turns caller data into authority.
    """
    row_fields = {
        "schema", "purpose", "cohort_transaction_id", "owner_uid", "home_role",
        "old_base_artifact_sha256", "new_base_artifact_sha256",
        "old_composed_artifact_sha256", "new_composed_artifact_sha256",
        "overlay_journal_sha256", "overlay_contents",
        "base_non_installer_manifest_sha256", "composed_non_installer_manifest_sha256",
        "materialized_tree_sha256", "old_installed_journal_sha256",
        "new_installed_journal_sha256", "old_discovery_sha256", "new_discovery_sha256",
        "old_core_source_generation", "new_core_source_generation",
        "old_source_recipe_sha256", "new_source_recipe_sha256", "phase",
    }
    context_fields = {
        "cohort_transaction_id", "owner_uid", "home_role", "old_installed_journal_sha256",
        "new_installed_journal_sha256", "old_discovery_sha256", "new_discovery_sha256",
        "old_core_source_generation", "new_core_source_generation",
        "old_source_recipe_sha256", "new_source_recipe_sha256", "phase",
    }
    if (type(reconstruction) is not HelperOnlyOverlayReconstruction
            or type(cohort_row) is not dict or set(cohort_row) != row_fields
            or type(current_context) is not dict or set(current_context) != context_fields):
        return False
    digest_fields = row_fields - {
        "schema", "purpose", "owner_uid", "home_role", "overlay_contents", "phase",
    }
    if any(type(cohort_row.get(key)) is not str
           or re.fullmatch(r"[0-9a-f]{64}", cohort_row[key]) is None
           for key in digest_fields):
        return False
    if (type(cohort_row.get("cohort_transaction_id")) is not str
            or re.fullmatch(r"[0-9a-f]{64}", cohort_row["cohort_transaction_id"]) is None
            or type(cohort_row.get("overlay_contents")) is not list
            or any(type(item) is not dict or set(item) != {"skill_id", "content_sha256"}
                   or type(item.get("skill_id")) is not str
                   or type(item.get("content_sha256")) is not str
                   or re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", item["skill_id"]) is None
                   or re.fullmatch(r"[0-9a-f]{64}", item["content_sha256"]) is None
                   for item in cohort_row["overlay_contents"])):
        return False
    expected = {
        "schema": 1, "purpose": "helper-only-overlay-reconstruction",
        "old_base_artifact_sha256": reconstruction.old_base_artifact_sha256,
        "new_base_artifact_sha256": reconstruction.new_base_artifact_sha256,
        "old_composed_artifact_sha256": reconstruction.old_composed_artifact_sha256,
        "new_composed_artifact_sha256": reconstruction.new_composed_artifact_sha256,
        "overlay_journal_sha256": reconstruction.overlay_journal_sha256,
        "overlay_contents": [{"skill_id": name, "content_sha256": digest}
                              for name, digest in reconstruction.overlay_contents],
        "base_non_installer_manifest_sha256": reconstruction.base_non_installer_manifest_sha256,
        "composed_non_installer_manifest_sha256": reconstruction.composed_non_installer_manifest_sha256,
        "materialized_tree_sha256": reconstruction.materialized_tree_sha256,
    }
    return (all(cohort_row.get(key) == value for key, value in expected.items())
            and all(cohort_row.get(key) == value for key, value in current_context.items())
            and current_context.get("phase") == "committed"
            and type(current_context.get("owner_uid")) is int
            and current_context.get("owner_uid") == 1000
            and current_context.get("home_role") == "jarvis-primary-home")


def resolve_committed_helper_only_overlay_reconstruction(
    old_base_archive: bytes, new_base_archive: bytes, old_composed_archive: bytes,
    overlay_record_bytes: bytes, overlay_contents: Mapping[str, bytes],
    cohort_row: Mapping[str, Any], *, current_context: Mapping[str, Any],
) -> HelperOnlyOverlayReconstruction:
    """Reconstruct from current held bytes and require one committed row.

    Root discovery and overlay consumers should call this on each current read,
    passing current protected CAS/journal bytes and independently verified
    installed/discovery/source context. It deliberately has no alias/cache path.
    """
    result = reconstruct_helper_only_overlay_transition(
        old_base_archive, new_base_archive, old_composed_archive,
        overlay_record_bytes, overlay_contents)
    if not verify_committed_helper_only_overlay_reconstruction(
            result, cohort_row, current_context=current_context):
        raise ResourcesSkillOverlayError("committed helper-only overlay cohort differs")
    return result


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
