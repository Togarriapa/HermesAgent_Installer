"""Separate, user-owned manual MVP stage for Jarvis' portable Resources skills.

This is deliberately not a managed-installer authority adapter. It materializes
only the four instruction-only skills in the verified primary Jarvis closure;
it does not enable the related voice plugin or touch profile state/credentials.
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
        "The bundled Resources plugin has no Hermes Desktop plugin module/native path; "
        "the installer PluginContext loader and enrolled local Wyoming/Piper effects "
        "are still required."
    ),
}
_ARTIFACT_LIMIT = 256 * 1024
_MEMBER_LIMIT = 64 * 1024
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_GENERATION = f"installer-resources-{PINNED_REVISION[:12]}"
_OWNER_FILE = ".hermes-installer-resource-ownership.json"


class ManualJarvisSkillsError(RuntimeError):
    """The manual MVP skill stage cannot safely create or verify this generation."""


def _canonical_json(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                        ensure_ascii=True) + "\n").encode("ascii")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def build_manual_jarvis_skills_artifact() -> bytes:
    """Build a deterministic ZIP from the checked-in, integrity-verified source."""
    from .native import NativeRegistry
    from .source import load_bundled_source

    source = load_bundled_source()
    if source.revision != PINNED_REVISION or source.source_tree != PINNED_TREE:
        raise ManualJarvisSkillsError("verified Resources source differs from the manual stage pin")
    registry = NativeRegistry.from_verified_source(source)
    discovery = registry.discover(["profiles/hermes@*"])
    rows = [item for item in discovery.resources if item.resource.kind.value == "skills"]
    by_id = {item.resource.id: item for item in rows}
    if tuple(sorted(by_id)) != tuple(sorted(PRIMARY_SKILLS)):
        raise ManualJarvisSkillsError("verified Jarvis profile skill closure differs from the reviewed stage")

    compiled = registry.materialize(discovery)
    members: list[dict[str, Any]] = []
    files: dict[str, bytes] = {}
    helper_bytes = Path(__file__).read_bytes()
    for skill_id in PRIMARY_SKILLS:
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

    selected = [
        {"kind": row.resource.kind.value, "id": row.resource.id, "version": row.resource.version}
        for row in discovery.resources
    ]
    manifest = {
        "schema": 1,
        "stage": "manual-owned-mvp-only",
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
        "selected_primary_closure": sorted(selected, key=lambda row: (row["kind"], row["id"])),
        "skill_members": members,
        "installer": {"archive_path": "manual_stage_jarvis_skills.py",
                      "size_bytes": len(helper_bytes), "sha256": _sha256(helper_bytes)},
        "reference_closure": {
            "status": "complete-for-selected-skill-files",
            "external_files": [],
            "explanation": (
                "These four declarations contain portable instruction fields only; "
                "the pinned Resources snapshot has no nested asset tree and the "
                "compiled skills declare no helper/reference/template/script members."
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
            members_by_name = {info.filename: info for info in archive.infolist()}
            names = list(members_by_name)
            if len(names) != len(set(names)) or "manifest.json" not in names:
                raise ValueError
            if any(PurePosixPath(name).is_absolute() or "\\" in name
                   or any(part in {"", ".", ".."} for part in PurePosixPath(name).parts)
                   for name in names):
                raise ValueError
            if any(
                info.file_size > (32 * 1024 if info.filename == "manifest.json" else
                                  64 * 1024 if info.filename.startswith("skills/") else
                                  128 * 1024)
                or info.compress_type != zipfile.ZIP_STORED
                or (info.create_system == 3 and not stat.S_ISREG(info.external_attr >> 16))
                for info in members_by_name.values()
            ):
                raise ValueError
            manifest_bytes = archive.read("manifest.json")
            if len(manifest_bytes) > 32 * 1024:
                raise ValueError
            manifest = json.loads(manifest_bytes)
            expected_paths = {f"skills/{skill_id}/SKILL.md" for skill_id in PRIMARY_SKILLS}
            if set(names) != expected_paths | {"manifest.json", "manual_stage_jarvis_skills.py"}:
                raise ValueError
            members = manifest["skill_members"]
            if (manifest["schema"] != 1 or manifest["stage"] != "manual-owned-mvp-only"
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
                    or manifest["plugin"].get("resource_id") != "voice-pipeline"
                    or [row.get("skill_id") for row in members] != list(PRIMARY_SKILLS)):
                raise ValueError
            files = {}
            helper = archive.read("manual_stage_jarvis_skills.py")
            if (len(helper) != manifest["installer"]["size_bytes"]
                    or _sha256(helper) != manifest["installer"]["sha256"]):
                raise ValueError
            for row in members:
                name = row["archive_path"]
                if name not in expected_paths or row["size_bytes"] > _MEMBER_LIMIT:
                    raise ValueError
                content = archive.read(name)
                if (len(content) != row["size_bytes"] or _sha256(content) != row["sha256"]
                        or not content.startswith(f"---\nname: {row['skill_id']}\n".encode())):
                    raise ValueError
                files[name.removeprefix("skills/")] = content
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
        "stage": "manual-owned-mvp-only",
        "artifact_sha256": expected_sha256,
        "source_revision": PINNED_REVISION,
        "source_tree": PINNED_TREE,
        "profile_source_id": PRIMARY_PROFILE,
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
            owner_digest = _hash_regular_file(owner_path, max_bytes=32 * 1024)
        except FileNotFoundError:
            owner_digest = None
        if owner_digest != _sha256(journal_bytes):
            raise ManualJarvisSkillsError("existing skill generation is unowned or its ownership journal changed")
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
            "skills": list(PRIMARY_SKILLS),
            "plugin": PLUGIN_PENDING,
        }

    temp = Path(tempfile.mkdtemp(prefix=".jarvis-resources-skills-", dir=home_input))
    try:
        for relative, content in sorted(files.items()):
            path = PurePosixPath(relative)
            if len(path.parts) != 2 or path.parts[-1] != "SKILL.md":
                raise ManualJarvisSkillsError("package contains an unsupported native skill path")
            skill_dir = temp / path.parts[0]
            skill_dir.mkdir(mode=0o755)
            out = skill_dir / path.parts[1]
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
        for child in temp.iterdir():
            if child.is_dir():
                child_fd = os.open(child, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
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
        "skills": list(PRIMARY_SKILLS),
        "plugin": PLUGIN_PENDING,
        "next_step": "Run the pinned Hermes skill list/view probe and separately read Desktop Capabilities.",
    }


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
    args = parser.parse_args(argv)
    try:
        if args.command == "build":
            digest = build_to_file(args.output)
            print(json.dumps({"state": "built", "path": str(Path(args.output)),
                              "sha256": digest}, sort_keys=True))
        else:
            bundle = Path(args.bundle)
            if bundle.is_symlink() or not bundle.is_file() or bundle.stat().st_size > _ARTIFACT_LIMIT:
                raise ManualJarvisSkillsError("bundle path is not a bounded regular file")
            result = install_manual_jarvis_skills(
                bundle.read_bytes(), hermes_home=args.home,
                expected_sha256=args.expected_sha256,
            )
            print(json.dumps(result, sort_keys=True))
    except (ManualJarvisSkillsError, OSError) as exc:
        parser.exit(2, f"manual Jarvis skill stage refused: {exc}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
