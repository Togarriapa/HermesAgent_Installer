"""Source-copy helpers remain unavailable until native adapter proofs are wired."""
from __future__ import annotations
import hashlib
import json
import os
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Callable, Iterable
from hermes_installer.state import OwnedRoot, process_lock
from hermes_installer.components.skill_refs import audit_skill_references


@dataclass(frozen=True, slots=True)
class ComponentSpec:
    id: str
    source_url: str
    revision: str
    aliases: tuple[str, ...] = ()
    kind: str = "skill"
    license: str | None = None
    mode: str = "on_demand"
    executable_hooks: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ImportedSkill:
    component_id: str
    destination: Path
    files: tuple[str, ...]
    sha256: str
    source_resolved: bool
    discoverable: bool
    hook_status: str
    license: str | None


class ComponentCatalog:
    def __init__(self, specs: Iterable[ComponentSpec]):
        specs = tuple(specs)
        self.by_name: dict[str, ComponentSpec] = {}
        self.by_id = {spec.id: spec for spec in specs}
        for spec in specs:
            self._valid_id(spec.id)
            for alias in (spec.id, *spec.aliases):
                key = alias.casefold()
                prior = self.by_name.get(key)
                if prior and prior.id != spec.id:
                    raise ValueError(f"component alias collision: {alias}")
                self.by_name[key] = spec

    @staticmethod
    def _valid_id(value: str) -> str:
        if not value or len(value) > 96 or any(ch not in "abcdefghijklmnopqrstuvwxyz0123456789-_" for ch in value):
            raise ValueError("component id must be lowercase slug")
        return value

    def resolve(self, name: str) -> ComponentSpec:
        try:
            return self.by_name[name.casefold()]
        except KeyError as exc:
            raise KeyError(f"unknown component {name!r}; provide explicit source override") from exc

    @staticmethod
    def manifest(source: Path) -> tuple[tuple[str, ...], str]:
        names: list[str] = []
        digest = hashlib.sha256()
        for path in sorted(source.rglob("*")):
            relative = path.relative_to(source).as_posix()
            if path.is_symlink():
                raise ValueError(f"source symlink is not imported: {relative}")
            if not path.is_file():
                continue
            rel = PurePosixPath(relative)
            if rel.is_absolute() or ".." in rel.parts:
                raise ValueError("source path escapes component root")
            names.append(relative)
            digest.update(relative.encode("utf-8") + b"\0")
            with path.open("rb") as stream:
                for block in iter(lambda: stream.read(65536), b""):
                    digest.update(block)
        if not names:
            raise ValueError("refusing empty source tree")
        return tuple(names), digest.hexdigest()

    def import_skill(self, name: str, source: Path, owned: OwnedRoot) -> ImportedSkill:
        spec = self.resolve(name)
        if spec.kind not in {"skill", "instruction_collection", "reference"}:
            raise ValueError("component is not a portable skill tree")
        source = source.resolve(strict=True)
        files, digest = self.manifest(source)
        reference_audit = audit_skill_references(source)
        if reference_audit.problems:
            first = reference_audit.problems[0]
            raise ValueError(
                f"broken skill reference in {first.source_path}:{first.line}: "
                f"{first.target!r} ({first.reason})"
            )
        owned.ensure()
        root = owned.path(f"sources/{spec.id}")
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        revision = spec.revision.lower()
        if not revision or len(revision) > 128 or any(ch not in "abcdefghijklmnopqrstuvwxyz0123456789._-" for ch in revision):
            raise ValueError("invalid pinned source revision")
        target = root / revision
        with process_lock(owned.path("installer.lock")):
            if target.exists() or target.is_symlink():
                if target.is_symlink() or not (target / "import-manifest.json").is_file():
                    raise PermissionError("existing source generation is foreign or incomplete")
                prior = json.loads((target / "import-manifest.json").read_text(encoding="utf-8"))
                if prior.get("sha256") != digest or tuple(prior.get("files", ())) != files:
                    raise PermissionError("pinned source generation conflicts with existing owned data")
                return ImportedSkill(spec.id, target, files, digest, False, False, "pending_source_revision_and_hook_verification", spec.license)
            stage = Path(tempfile.mkdtemp(prefix=".import-", dir=root))
            os.chmod(stage, 0o700)
            try:
                for relative in files:
                    src = source / relative
                    dst = stage / relative
                    dst.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                    if dst.parent.is_symlink() or not dst.parent.resolve().is_relative_to(stage.resolve()):
                        raise PermissionError("source path escaped staging directory")
                    with src.open("rb") as reader:
                        content = reader.read()
                    mode = 0o555 if src.stat().st_mode & 0o111 else 0o444
                    fd = os.open(dst, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), mode)
                    with os.fdopen(fd, "wb") as writer:
                        writer.write(content)
                        writer.flush()
                        os.fsync(writer.fileno())
                metadata = {
                    "schema": 1, "component": spec.id, "source_url": spec.source_url,
                    "revision": spec.revision, "license": spec.license,
                    "sha256": digest, "files": files,
                    "redistribution_allowed": bool(spec.license),
                }
                manifest_path = stage / "import-manifest.json"
                fd = os.open(manifest_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o444)
                with os.fdopen(fd, "w", encoding="utf-8") as stream:
                    json.dump(metadata, stream, sort_keys=True)
                    stream.write("\n")
                    stream.flush()
                    os.fsync(stream.fileno())
                stage.rename(target)
                directory_fd = os.open(root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
            except BaseException:
                shutil.rmtree(stage, ignore_errors=True)
                raise
        # Copying content alone is not native discovery or hook verification.
        return ImportedSkill(spec.id, target, files, digest, False, False, "pending_source_revision_and_hook_verification", spec.license)

    @staticmethod
    def mark_discovered(imported: ImportedSkill, native_discovery: Callable[[Path], bool]) -> ImportedSkill:
        if not imported.source_resolved or imported.hook_status != "verified":
            raise RuntimeError("native discovery is unavailable until source revision and hooks are verified")
        if not native_discovery(imported.destination):
            raise RuntimeError("Hermes did not discover the imported skill")
        from dataclasses import replace
        return replace(imported, discoverable=True)

    def application_gate(self, name: str, requested: set[str], granted: set[str], *, dependencies_verified: bool, arm64_verified: bool, isolation_verified: bool) -> tuple[bool, str]:
        spec = self.resolve(name)
        if spec.kind != "application":
            return False, "not an application"
        denied = sorted(requested - granted)
        if denied:
            return False, "missing grants: " + ", ".join(denied)
        if spec.mode != "on_demand":
            return False, "application must remain on demand"
        missing = [label for label, ok in (("dependencies", dependencies_verified), ("ARM64 runtime", arm64_verified), ("process isolation", isolation_verified)) if not ok]
        if missing:
            return False, "verification pending: " + ", ".join(missing)
        return False, "pending native ARM64 dependency, process isolation, and runtime discovery adapters"
