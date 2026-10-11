"""Separate, ownership-journaled offline import of bundled Hermes Resources.

This importer makes all 396 bundled native skill cards visible to Hermes and
retains all 208 effective profile identities under a private registry namespace.
Only the primary Jarvis home stays user-selectable. It does not activate plugins,
copy credentials, or claim delegated profile/tool effects.
"""
from __future__ import annotations

import hashlib
import argparse
import io
import json
import os
import re
import shutil
import stat
import tempfile
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any


PINNED_REVISION = "113f42d33be9e0c8f0f47f5ca998e687323dec83"
PINNED_TREE = "c0c994b5e0b96b90cfd2fc564ea8632dff124308"
PINNED_VERSION = "2.3.1"
PRIMARY_PROFILE = "hermes"
PRIMARY_SKILLS = (
    "conversation-gateway",
    "hermes-response-contract",
    "speech-input-routing",
    "spoken-response-delivery",
)
PLUGIN_PENDING = {
    "resource_id": "voice-pipeline",
    "state": "not-imported",
    "reason": (
        "The vendored Resources bundle contains only a voice-pipeline declaration, not an "
        "executable Hermes plugin adapter. No separately authorized local Wyoming/Piper "
        "endpoints are enrolled, so voice effects remain unavailable."
    ),
}
_ARTIFACT_LIMIT = 16 * 1024 * 1024
_MEMBER_LIMIT = 256 * 1024
_PACKAGE_MEMBER_LIMIT = 2 * 1024 * 1024
_BUNDLE_SKILL_COUNT = 396
_BUNDLE_PROFILE_COUNT = 208
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_GENERATION = f"installer-resources-{PINNED_REVISION[:12]}"
_OWNER_FILE = ".hermes-installer-resource-ownership.json"
PINNED_HERMES_REVISION = "7085fbf7753266fc4943c55ac04926186bc90005"


class ManualJarvisSkillsError(RuntimeError):
    """The manual MVP skill stage cannot safely create or verify this generation."""


def _canonical_json(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                        ensure_ascii=True) + "\n").encode("ascii")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def build_manual_jarvis_skills_artifact() -> bytes:
    """Build a deterministic import package from the checked-in verified source."""
    from .native import NativeRegistry
    from .source import load_bundled_source

    source = load_bundled_source()
    if source.revision != PINNED_REVISION or source.source_tree != PINNED_TREE:
        raise ManualJarvisSkillsError("verified Resources source differs from the manual stage pin")
    registry = NativeRegistry.from_verified_source(source)
    discovery = registry.discover_all()
    rows = [item for item in discovery.resources if item.resource.kind.value == "skills"]
    profiles = [item for item in discovery.resources if item.resource.kind.value == "profiles"]
    by_id = {item.resource.id: item for item in rows}
    if (len(by_id) != _BUNDLE_SKILL_COUNT or len(profiles) != _BUNDLE_PROFILE_COUNT
            or not set(PRIMARY_SKILLS).issubset(by_id)):
        raise ManualJarvisSkillsError("verified Resources identities differ from the reviewed full bundle")

    compiled = registry.materialize(discovery)
    members: list[dict[str, Any]] = []
    profile_members: list[dict[str, Any]] = []
    files: dict[str, bytes] = {}
    try:
        import yaml
    except ImportError:
        raise ManualJarvisSkillsError("PyYAML is required to retain native profile aliases") from None
    helper_bytes = Path(__file__).read_bytes()
    for skill_id in sorted(by_id):
        staged_path = f"homes/skills/{skill_id}/SKILL.md"
        content = compiled.get(staged_path)
        if not isinstance(content, bytes) or not content or len(content) > _MEMBER_LIMIT:
            raise ManualJarvisSkillsError("verified Jarvis skill output is missing or exceeds its size bound")
        if not content.startswith(f"---\nname: {skill_id}\n".encode("utf-8")):
            raise ManualJarvisSkillsError("compiled native skill identity differs from its pinned source")
        item = by_id[skill_id]
        key = f"skills/{skill_id}@{item.resource.version}"
        raw = registry.resolver.raw[key]
        zip_path = f"skills/{skill_id}/SKILL.md"
        files[zip_path] = content
        members.append({
            "skill_id": skill_id,
            "version": item.resource.version,
            "source_path": registry.paths[key],
            "source_document_sha256": raw.content_digest,
            "effective_spec_sha256": _sha256(_canonical_json(dict(item.effective_spec or item.resource.body))),
            "archive_path": zip_path,
            "size_bytes": len(content),
            "sha256": _sha256(content),
        })

    for item in sorted(profiles, key=lambda value: value.resource.id):
        profile_id = item.resource.id
        for suffix in ("SOUL.md", "profile.yaml"):
            staged_path = f"homes/profiles/{profile_id}/{suffix}"
            content = compiled.get(staged_path)
            if not isinstance(content, bytes) or not content or len(content) > _MEMBER_LIMIT:
                raise ManualJarvisSkillsError("compiled internal profile prompt is missing or oversized")
            archive_path = f"registry/profiles/{profile_id}/{suffix}"
            files[archive_path] = content
        raw_key = f"profiles/{profile_id}@{item.resource.version}"
        raw = registry.resolver.raw[raw_key]
        profile_meta = yaml.safe_load(files[f"registry/profiles/{profile_id}/profile.yaml"])
        alias = profile_meta.get("display_name") if isinstance(profile_meta, dict) else None
        if not isinstance(alias, str) or not alias:
            raise ManualJarvisSkillsError("compiled internal profile alias is missing")
        profile_members.append({
            "source_id": profile_id,
            "version": item.resource.version,
            "source_path": registry.paths[raw_key],
            "source_document_sha256": raw.content_digest,
            "identity_sha256": _sha256(files[f"registry/profiles/{profile_id}/SOUL.md"]),
            "profile_yaml_sha256": _sha256(files[f"registry/profiles/{profile_id}/profile.yaml"]),
            "native_alias": alias,
        })

    # Keep the complete generated resource declaration/catalog/adapter bundle
    # beside the private profile records. Hermes only scans `skills/`; this
    # registry namespace remains data until a separately reviewed dispatcher
    # activates a concrete adapter.
    package_members: list[dict[str, Any]] = []
    for relative, content in compiled.items():
        if relative.startswith("homes/"):
            continue
        archive_path = f"registry/package/{relative}"
        files[archive_path] = content
        package_members.append({"archive_path": archive_path, "size_bytes": len(content),
                                "sha256": _sha256(content)})

    selected = [
        {"kind": row.resource.kind.value, "id": row.resource.id, "version": row.resource.version}
        for row in discovery.resources
    ]
    manifest = {
        "schema": 1,
        "stage": "manual-owned-bundled-resources-import",
        "managed_installer_authority": False,
        "target_home_role": "jarvis-primary-home",
        "target_profile": {"source_id": PRIMARY_PROFILE, "native_key": "default", "display_name": "Jarvis"},
        "source": {
            "repository": source.repository,
            "revision": source.revision,
            "git_tree": source.source_tree,
            "catalog_version": source.catalog_version,
            "content_digest": source.content_digest,
            "archive_sha256": "b09459b609676cff30f151ac7db1fc405039b8871486b483af563ba7f63e7cd1",
        },
        "bundled_resource_inventory": sorted(selected, key=lambda row: (row["kind"], row["id"])),
        "skill_members": members,
        "profile_members": profile_members,
        "package_members": package_members,
        "installer": {"archive_path": "manual_stage_jarvis_skills.py",
                      "size_bytes": len(helper_bytes), "sha256": _sha256(helper_bytes)},
        "reference_closure": {
            "status": "complete-for-bundled-native-skill-files-and-profile-prompt-records",
            "external_files": [],
            "explanation": (
                "All 396 native skills and all 208 effective profile prompts/aliases are "
                "compiled from the vendored offline source. Profile prompt material is "
                "retained below a private registry namespace and is not copied into "
                "Hermes' selectable profile roster. The pinned declarations contain no "
                "external support-file closure."
            ),
        },
        "plugin": PLUGIN_PENDING,
        "readiness": {
            "bundled": True, "validated": True, "materialized": False,
            "discovered": False, "authenticated": False, "functional": False,
            "enabled": False, "target_verified": False,
        },
    }
    buffer = tempfile.SpooledTemporaryFile(max_size=_ARTIFACT_LIMIT)
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_STORED) as archive:
        _zip_write(archive, "manifest.json", _canonical_json(manifest))
        for name in sorted(files):
            _zip_write(archive, name, files[name])
        _zip_write(archive, "manual_stage_jarvis_skills.py", helper_bytes)
    buffer.seek(0)
    result = buffer.read(_ARTIFACT_LIMIT + 1)
    buffer.close()
    if len(result) > _ARTIFACT_LIMIT:
        raise ManualJarvisSkillsError("manual Jarvis skill artifact exceeds its bound")
    return result


def _zip_write(archive: zipfile.ZipFile, name: str, data: bytes) -> None:
    info = zipfile.ZipInfo(name, date_time=(2020, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_STORED
    info.create_system = 3
    info.external_attr = (stat.S_IFREG | 0o644) << 16
    archive.writestr(info, data)


def _read_artifact(archive_bytes: bytes, expected_sha256: str) -> tuple[dict[str, Any], dict[str, bytes]]:
    if (not isinstance(expected_sha256, str) or not _HEX64.fullmatch(expected_sha256)
            or not isinstance(archive_bytes, bytes) or not archive_bytes
            or len(archive_bytes) > _ARTIFACT_LIMIT or _sha256(archive_bytes) != expected_sha256):
        raise ManualJarvisSkillsError("manual stage artifact digest or size is invalid")
    try:
        with zipfile.ZipFile(io.BytesIO(archive_bytes), "r") as archive:
            infos = archive.infolist()
            names = [info.filename for info in infos]
            if len(names) != len(set(names)) or "manifest.json" not in names:
                raise ValueError
            members_by_name = {info.filename: info for info in infos}
            if any(PurePosixPath(name).is_absolute() or "\\" in name
                   or any(part in {"", ".", ".."} for part in PurePosixPath(name).parts)
                   for name in names):
                raise ValueError
            if any(
                info.file_size > (
                    1024 * 1024 if info.filename == "manifest.json" else
                    _PACKAGE_MEMBER_LIMIT if info.filename.startswith("registry/package/") else
                    _MEMBER_LIMIT
                )
                or info.compress_type != zipfile.ZIP_STORED
                or (info.create_system == 3 and not stat.S_ISREG(info.external_attr >> 16))
                for info in members_by_name.values()
            ):
                raise ValueError
            manifest_bytes = archive.read("manifest.json")
            if len(manifest_bytes) > 1024 * 1024:
                raise ValueError
            manifest = json.loads(manifest_bytes)
            members = manifest["skill_members"]
            profiles = manifest["profile_members"]
            package_members = manifest["package_members"]
            expected_paths = {row["archive_path"] for row in members}
            profile_paths = {f"registry/profiles/{row['source_id']}/{suffix}"
                             for row in profiles for suffix in ("SOUL.md", "profile.yaml")}
            package_paths = {row["archive_path"] for row in package_members}
            skill_ids = [row["skill_id"] for row in members]
            profile_ids = [row["source_id"] for row in profiles]
            if (set(names) != expected_paths | profile_paths | package_paths |
                    {"manifest.json", "manual_stage_jarvis_skills.py"}):
                raise ValueError
            if (not package_paths or len(expected_paths) != len(members)
                    or len(profile_paths) != 2 * len(profiles)
                    or len(package_paths) != len(package_members)
                    or any(PurePosixPath(name).name == "SKILL.md" for name in package_paths)
                    or len(set(skill_ids)) != _BUNDLE_SKILL_COUNT
                    or len(set(profile_ids)) != _BUNDLE_PROFILE_COUNT
                    or PRIMARY_PROFILE not in profile_ids):
                raise ValueError
            if (manifest["schema"] != 1 or manifest["stage"] != "manual-owned-bundled-resources-import"
                    or manifest["managed_installer_authority"] is not False
                    or manifest["source"]["repository"] !=
                    "https://github.com/Togarriapa/HermesAgent_Resources"
                    or manifest["source"]["revision"] != PINNED_REVISION
                    or manifest["source"]["git_tree"] != PINNED_TREE
                    or manifest["source"]["catalog_version"] != PINNED_VERSION
                    or manifest["target_home_role"] != "jarvis-primary-home"
                    or manifest["target_profile"] != {
                        "source_id": "hermes", "native_key": "default", "display_name": "Jarvis"}
                    or manifest["source"]["archive_sha256"] !=
                    "b09459b609676cff30f151ac7db1fc405039b8871486b483af563ba7f63e7cd1"
                    or manifest["reference_closure"].get("external_files") != []
                    or len(members) != _BUNDLE_SKILL_COUNT or len(profiles) != _BUNDLE_PROFILE_COUNT
                    or not set(PRIMARY_SKILLS).issubset(set(skill_ids))):
                raise ValueError
            files = {}
            helper = archive.read("manual_stage_jarvis_skills.py")
            if (len(helper) != manifest["installer"]["size_bytes"]
                    or _sha256(helper) != manifest["installer"]["sha256"]):
                raise ValueError
            for row in members:
                name = row["archive_path"]
                if (name not in expected_paths or row["size_bytes"] > _MEMBER_LIMIT
                        or not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,95}", row["skill_id"])
                        or name != f"skills/{row['skill_id']}/SKILL.md"):
                    raise ValueError
                content = archive.read(name)
                if (len(content) != row["size_bytes"] or _sha256(content) != row["sha256"]
                        or not content.startswith(f"---\nname: {row['skill_id']}\n".encode())):
                    raise ValueError
                files[name] = content
            for row in profiles:
                if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", row["source_id"]):
                    raise ValueError
                for suffix in ("SOUL.md", "profile.yaml"):
                    name = f"registry/profiles/{row['source_id']}/{suffix}"
                    content = archive.read(name)
                    expected_hash = row["identity_sha256"] if suffix == "SOUL.md" else row["profile_yaml_sha256"]
                    if not content or len(content) > _MEMBER_LIMIT or _sha256(content) != expected_hash:
                        raise ValueError
                    files[name] = content
            for name in package_paths:
                content = archive.read(name)
                row = next(row for row in package_members if row["archive_path"] == name)
                if (len(content) != row["size_bytes"]
                        or len(content) > _PACKAGE_MEMBER_LIMIT or _sha256(content) != row["sha256"]
                        or not name.startswith("registry/package/")
                        or PurePosixPath(name).name == "SKILL.md"):
                    raise ValueError
                files[name] = content
            if manifest["plugin"].get("state") != "not-imported":
                raise ValueError
            return manifest, files
    except (OSError, KeyError, TypeError, ValueError, zipfile.BadZipFile, json.JSONDecodeError):
        raise ManualJarvisSkillsError("manual stage artifact contents are malformed or do not match its pin") from None


def _regular_owned(path: Path, *, directory: bool) -> os.stat_result:
    try:
        info = path.lstat()
    except FileNotFoundError:
        raise
    mode_ok = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
    if path.is_symlink() or not mode_ok or info.st_uid != os.geteuid():
        raise ManualJarvisSkillsError("manual stage path is linked, non-regular, or not owned by this Hermes user")
    return info


def _hash_regular_file(path: Path, *, max_bytes: int) -> str:
    info = _regular_owned(path, directory=False)
    if info.st_nlink != 1 or info.st_size > max_bytes:
        raise ManualJarvisSkillsError("manual stage member has an unexpected link count or size")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    try:
        digest = hashlib.sha256()
        total = 0
        while block := os.read(fd, 65536):
            total += len(block)
            if total > max_bytes:
                raise ManualJarvisSkillsError("manual stage member exceeds its read bound")
            digest.update(block)
        return digest.hexdigest()
    finally:
        os.close(fd)


def _rename_noreplace(source: Path, destination: Path) -> None:
    """Publish one complete directory without replacing even an empty conflict."""
    import ctypes
    import errno
    import sys

    libc = ctypes.CDLL(None, use_errno=True)
    if sys.platform.startswith("linux") and hasattr(libc, "renameat2"):
        function = libc.renameat2
        function.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
        function.restype = ctypes.c_int
        result = function(-100, os.fsencode(source), -100, os.fsencode(destination), 1)
    elif sys.platform == "darwin" and hasattr(libc, "renamex_np"):
        function = libc.renamex_np
        function.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
        function.restype = ctypes.c_int
        result = function(os.fsencode(source), os.fsencode(destination), 0x00000004)
    else:
        raise ManualJarvisSkillsError("atomic no-replace directory publication is unavailable on this OS")
    if result != 0:
        error = ctypes.get_errno()
        if error in {errno.EEXIST, errno.ENOTEMPTY}:
            raise ManualJarvisSkillsError("the revision-owned Jarvis skill generation path already exists")
        raise OSError(error, os.strerror(error), str(destination))


def install_manual_jarvis_skills(
    archive_bytes: bytes, *, hermes_home: str | Path, expected_sha256: str,
) -> dict[str, Any]:
    """Atomically add one revision-namespaced skill generation to a user's Hermes home.

    Existing home state and skill files are never overwritten or adopted. The
    manifest inside the generation is the manual-stage ownership journal.
    Run as the existing Hermes home owner, without sudo.
    """
    manifest, files = _read_artifact(archive_bytes, expected_sha256)
    home_input = Path(hermes_home)
    if not home_input.is_absolute():
        raise ManualJarvisSkillsError("Hermes home must be an explicit absolute path")
    if home_input.resolve(strict=True) != home_input:
        raise ManualJarvisSkillsError("Hermes home path contains a symbolic-link component")
    home = home_input.lstat()
    if (not stat.S_ISDIR(home.st_mode) or stat.S_ISLNK(home.st_mode)
            or home.st_uid != os.geteuid()):
        raise ManualJarvisSkillsError("Hermes home must be a real directory owned by the current user")
    soul = home_input / "SOUL.md"
    soul_info = _regular_owned(soul, directory=False)
    if soul_info.st_size == 0:
        raise ManualJarvisSkillsError("Jarvis primary SOUL.md is empty")

    skills_root = home_input / "skills"
    try:
        _regular_owned(skills_root, directory=True)
    except FileNotFoundError:
        skills_root.mkdir(mode=0o755)
        _regular_owned(skills_root, directory=True)
    target = skills_root / _GENERATION
    journal_bytes = _canonical_json({
        "schema": 1,
        "stage": "manual-owned-bundled-resources-import",
        "artifact_sha256": expected_sha256,
        "source_revision": PINNED_REVISION,
        "source_tree": PINNED_TREE,
            "profile_source_id": PRIMARY_PROFILE,
            "user_visible_profile": {"source_id": PRIMARY_PROFILE, "native_key": "default", "display_name": "Jarvis"},
            "internal_profile_count": _BUNDLE_PROFILE_COUNT - 1,
        "target_home_role": "jarvis-primary-home",
        "members": [
            {"path": f"{_GENERATION}/{name}", "sha256": _sha256(content), "size_bytes": len(content)}
            for name, content in sorted(files.items())
        ],
    })

    try:
        target_info = target.lstat()
    except FileNotFoundError:
        target_info = None
    if target_info is not None:
        _regular_owned(target, directory=True)
        owner_path = target / _OWNER_FILE
        try:
            owner_digest = _hash_regular_file(owner_path, max_bytes=2 * 1024 * 1024)
        except FileNotFoundError:
            owner_digest = None
        if owner_digest != _sha256(journal_bytes):
            raise ManualJarvisSkillsError("existing skill generation is unowned or its ownership journal changed")
        expected_files = set(files) | {_OWNER_FILE}
        actual_files: set[str] = set()
        for base, dirs, names in os.walk(target, followlinks=False):
            base_path = Path(base)
            for dirname in dirs:
                _regular_owned(base_path / dirname, directory=True)
            for filename in names:
                candidate = base_path / filename
                _regular_owned(candidate, directory=False)
                actual_files.add(candidate.relative_to(target).as_posix())
        if actual_files != expected_files:
            raise ManualJarvisSkillsError(
                "owned Resources generation contains missing or untracked files; preserving it")
        for name, content in files.items():
            destination = target / name
            if _hash_regular_file(destination, max_bytes=_MEMBER_LIMIT) != _sha256(content):
                raise ManualJarvisSkillsError("an owned skill changed after staging; preserving it as a user edit")
        return {
            "state": "already-staged",
            "materialized": True,
            "discovered": False,
            "artifact_sha256": expected_sha256,
            "generation_path": str(target),
            "skills": sorted(row["skill_id"] for row in manifest["skill_members"]),
            "profiles_preserved_internal": sorted(row["source_id"] for row in manifest["profile_members"]),
        }

    temp = Path(tempfile.mkdtemp(prefix=".jarvis-resources-skills-", dir=home_input))
    try:
        for relative, content in sorted(files.items()):
            path = PurePosixPath(relative)
            is_skill = (len(path.parts) == 3 and path.parts[0] == "skills"
                        and path.parts[2] == "SKILL.md")
            is_internal_profile = (len(path.parts) == 4
                                   and path.parts[:2] == ("registry", "profiles")
                                   and path.parts[3] in {"SOUL.md", "profile.yaml"})
            is_registry_package = (len(path.parts) >= 3 and path.parts[:2] == ("registry", "package"))
            if not (is_skill or is_internal_profile or is_registry_package):
                raise ManualJarvisSkillsError("package contains an unsupported native skill path")
            out = temp.joinpath(*path.parts)
            out.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
            fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o644)
            try:
                view = memoryview(content)
                while view:
                    written = os.write(fd, view)
                    view = view[written:]
                os.fsync(fd)
            finally:
                os.close(fd)
        marker = temp / _OWNER_FILE
        fd = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            view = memoryview(journal_bytes)
            while view:
                written = os.write(fd, view)
                view = view[written:]
            os.fsync(fd)
        finally:
            os.close(fd)
        directories = [Path(base) for base, _dirs, _names in os.walk(temp, topdown=False)]
        for directory in directories:
            child_fd = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(child_fd)
            finally:
                os.close(child_fd)
        temp_fd = os.open(temp, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(temp_fd)
        finally:
            os.close(temp_fd)
        _rename_noreplace(temp, target)
        skills_fd = os.open(skills_root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(skills_fd)
        finally:
            os.close(skills_fd)
    except BaseException:
        if temp.exists() and not temp.is_symlink():
            shutil.rmtree(temp)
        raise
    return {
        "state": "staged",
        "materialized": True,
        "discovered": False,
        "artifact_sha256": expected_sha256,
        "generation_path": str(target),
        "skills": sorted(row["skill_id"] for row in manifest["skill_members"]),
        "profiles_preserved_internal": sorted(row["source_id"] for row in manifest["profile_members"]),
        "next_step": "Run the pinned Hermes skill list/view probe; qualify model-selected use and non-skill integrations separately.",
    }


def install_and_verify_manual_jarvis_skills(
    archive_bytes: bytes, *, hermes_home: str | Path, expected_sha256: str,
    hermes_source: str | Path, python: str | Path,
) -> dict[str, Any]:
    """Stage bundled skills/internal identities, then prove Hermes reads the skills.

    This read-back is intentionally separate from the ownership-safe file write:
    a failure leaves the verified, namespaced files available for a later retry,
    but does not issue a discovery receipt or claim functional tool effects.
    """
    staged = install_manual_jarvis_skills(
        archive_bytes, hermes_home=hermes_home, expected_sha256=expected_sha256)
    manifest, package_files = _read_artifact(archive_bytes, expected_sha256)
    skill_ids = tuple(sorted(row["skill_id"] for row in manifest["skill_members"]))
    try:
        from .native_install import NativeInstallError, discover_and_load_selected

        receipt = discover_and_load_selected(
            hermes_source=hermes_source,
            python=python,
            hermes_root=hermes_home,
            profile_id="default",
            skill_ids=skill_ids,
            timeout=300.0,
        )
    except (NativeInstallError, OSError, ValueError) as exc:
        # Avoid returning local exception text or path/environment details.
        raise ManualJarvisSkillsError(
            "Hermes did not discover and load the staged Jarvis Resources skills; "
            "the owned files remain staged for verification retry"
        ) from None
    if (receipt.hermes_revision != PINNED_HERMES_REVISION
            or not receipt.discovered_profile or not receipt.profile_identity_loaded
            or set(receipt.loaded_skills) != set(skill_ids)
            or any(receipt.content_digests.get(f"skill:{name}") !=
                   _sha256(package_files[f"skills/{name}/SKILL.md"]) for name in skill_ids)):
        raise ManualJarvisSkillsError(
            "Hermes discovery receipt did not cover the pinned primary Resources closure"
        )
    loaded_skill_digests = [
        {"skill_id": name, "sha256": receipt.content_digests[f"skill:{name}"]}
        for name in sorted(skill_ids)
    ]
    other_declarations = len(manifest["bundled_resource_inventory"]) - len(skill_ids) - len(manifest["profile_members"])
    return {
        "state": "discovered",
        "materialized": True,
        "discovered": True,
        "artifact_sha256": expected_sha256,
        "generation_path": staged["generation_path"],
        "primary_native_home": "default",
        "selectable_profile_mutations": [],
        "resource_counts": {
            "native_skills": len(skill_ids),
            "internal_profiles": len(manifest["profile_members"]) - 1,
            "source_profiles_preserved": len(manifest["profile_members"]),
            "other_declarations_preserved": other_declarations,
        },
        "native_receipt": {
            "hermes_revision": receipt.hermes_revision,
            "python_version": receipt.python_version,
            "profile_id": receipt.profile_id,
            "profile_identity_loaded": receipt.profile_identity_loaded,
            "loaded_skill_count": len(receipt.loaded_skills),
            "loaded_skill_inventory_sha256": _sha256(_canonical_json(loaded_skill_digests)),
            "active_primary_prompt_sha256": receipt.content_digests.get("profile:default"),
            "bundled_primary_prompt_sha256": _sha256(package_files["registry/profiles/hermes/SOUL.md"]),
            "active_prompt_matches_bundled_primary": (
                receipt.content_digests.get("profile:default") ==
                _sha256(package_files["registry/profiles/hermes/SOUL.md"])),
        },
        "functional": False,
        "enabled": False,
        "target_verified": False,
        "pending": [
            "Native discovery and content loading are verified; actual model-selected skill use and external effects remain unverified.",
            "The 207 secondary identities and all 208 compiled prompt records are retained under the private registry namespace; only the existing default profile remains selectable.",
            "The user's existing SOUL.md is preserved; a false active_prompt_matches_bundled_primary means the source Jarvis prompt remains internal until a safe ownership-aware prompt integration is reviewed.",
            "Non-skill adapters are retained as offline declarations/artifacts but dispatch, enrichment, authentication, and functional effects remain pending.",
        ],
    }


def install_bundled_resources(*, hermes_home: str | Path, hermes_source: str | Path,
                              python: str | Path) -> dict[str, Any]:
    """Build from the checked-in offline bundle and install through the owned importer."""
    artifact = build_manual_jarvis_skills_artifact()
    return install_and_verify_manual_jarvis_skills(
        artifact,
        hermes_home=hermes_home,
        expected_sha256=_sha256(artifact),
        hermes_source=hermes_source,
        python=python,
    )


def build_to_file(destination: str | Path) -> str:
    data = build_manual_jarvis_skills_artifact()
    path = Path(destination)
    if not path.is_absolute():
        raise ManualJarvisSkillsError("artifact output path must be absolute")
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() or path.is_symlink():
        raise ManualJarvisSkillsError("refusing to overwrite an existing manual stage artifact")
    temp = path.with_name(path.name + f".tmp-{os.getpid()}")
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)
    try:
        _rename_noreplace(temp, path)
    except BaseException:
        temp.unlink(missing_ok=True)
        raise
    return _sha256(data)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    build = sub.add_parser("build", help="build the verified manual Jarvis skill artifact")
    build.add_argument("--output", required=True)
    install = sub.add_parser("install", help="stage the artifact into an existing Jarvis Hermes home")
    install.add_argument("--bundle", required=True)
    install.add_argument("--home", required=True)
    install.add_argument("--expected-sha256", required=True)
    install.add_argument("--hermes-source", required=True,
                         help="Exact pinned Hermes source checkout used for native read-back")
    install.add_argument("--python", required=True,
                         help="Official PM-managed Python 3.14 interpreter used for native read-back")
    bundled = sub.add_parser("import-bundled", help="build offline from the checked-in bundle and import as the Hermes home owner")
    bundled.add_argument("--home", required=True)
    bundled.add_argument("--hermes-source", required=True)
    bundled.add_argument("--python", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "build":
            digest = build_to_file(args.output)
            print(json.dumps({"state": "built", "path": str(Path(args.output)),
                              "sha256": digest}, sort_keys=True))
        elif args.command == "install":
            bundle = Path(args.bundle)
            if bundle.is_symlink() or not bundle.is_file() or bundle.stat().st_size > _ARTIFACT_LIMIT:
                raise ManualJarvisSkillsError("bundle path is not a bounded regular file")
            result = install_and_verify_manual_jarvis_skills(
                bundle.read_bytes(), hermes_home=args.home,
                expected_sha256=args.expected_sha256,
                hermes_source=args.hermes_source, python=args.python,
            )
        else:
            result = install_bundled_resources(
                hermes_home=args.home,
                hermes_source=args.hermes_source,
                python=args.python,
            )
        if args.command != "build":
            print(json.dumps(result, sort_keys=True))
    except (ManualJarvisSkillsError, OSError) as exc:
        parser.exit(2, f"manual Jarvis skill stage refused: {exc}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
