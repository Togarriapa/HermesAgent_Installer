"""Journaled, owned and digest-verified immutable runtime generations."""
from __future__ import annotations
import hashlib
import json
import os
import shutil
import tempfile
from pathlib import Path
from typing import Mapping
from hermes_installer.state import Journal, OwnedRoot, process_lock


class GenerationError(RuntimeError):
    """A generation is incomplete, foreign or failed validation."""


class GenerationStore:
    def __init__(self, owned_root: OwnedRoot, journal: Journal | None = None):
        self.owned = owned_root
        self.owned.ensure()
        self.root = self.owned.path("generations")
        self.root.mkdir(mode=0o700, exist_ok=True)
        self.journal = journal or Journal(self.owned.path("installer-state.sqlite3"))

    @staticmethod
    def _validate_id(value: str) -> str:
        if not value or len(value) > 96 or any(ch not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_" for ch in value):
            raise ValueError("invalid generation id")
        return value

    def _fsync_directory(self, directory: Path) -> None:
        fd = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def stage(self, generation_id: str, files: Mapping[str, bytes]) -> Path:
        generation_id = self._validate_id(generation_id)
        if not files:
            raise GenerationError("refusing empty generation")
        with process_lock(self.owned.path("installer.lock")):
            target = self.root / generation_id
            if target.exists() or target.is_symlink():
                raise GenerationError("generation already exists and is immutable")
            temporary = Path(tempfile.mkdtemp(prefix=".stage-", dir=self.root))
            os.chmod(temporary, 0o700)
            manifest: dict[str, str] = {}
            try:
                for name, content in sorted(files.items()):
                    rel = Path(name)
                    if rel.is_absolute() or not rel.parts or ".." in rel.parts or name == "manifest.json":
                        raise ValueError("invalid generation relative path")
                    output = temporary / rel
                    output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                    if output.parent.is_symlink() or not output.parent.resolve().is_relative_to(temporary.resolve()):
                        raise GenerationError("generation path escapes staging root")
                    if not isinstance(content, bytes):
                        raise TypeError("generation content must be bytes")
                    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
                    fd = os.open(output, flags, 0o600)
                    with os.fdopen(fd, "wb") as stream:
                        stream.write(content)
                        stream.flush()
                        os.fsync(stream.fileno())
                    manifest[rel.as_posix()] = hashlib.sha256(content).hexdigest()
                manifest_bytes = json.dumps({"schema": 1, "generation": generation_id, "files": manifest}, sort_keys=True, separators=(",", ":")).encode() + b"\n"
                fd = os.open(temporary / "manifest.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
                with os.fdopen(fd, "wb") as stream:
                    stream.write(manifest_bytes)
                    stream.flush()
                    os.fsync(stream.fileno())
                self._fsync_directory(temporary)
                temporary.rename(target)
                self._fsync_directory(self.root)
                self.journal.record_owned("generation", generation_id, "staged")
                self.journal.checkpoint("registry-activate", "staged", {"generation": generation_id})
                return target
            except BaseException:
                shutil.rmtree(temporary, ignore_errors=True)
                raise

    def _verified_path(self, generation_id: str) -> Path:
        generation_id = self._validate_id(generation_id)
        target = self.root / generation_id
        if target.is_symlink() or not target.is_dir():
            raise GenerationError("generation is missing or is a symlink")
        manifest_path = target / "manifest.json"
        if manifest_path.is_symlink() or not manifest_path.is_file():
            raise GenerationError("generation manifest is missing")
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            raise GenerationError("generation manifest is invalid") from None
        if manifest.get("schema") != 1 or manifest.get("generation") != generation_id or not isinstance(manifest.get("files"), dict):
            raise GenerationError("generation manifest identity mismatch")
        expected = manifest["files"]
        actual: dict[str, str] = {}
        for path in target.rglob("*"):
            if path.is_symlink():
                raise GenerationError("generation contains a symlink")
            if path.is_file() and path.name != "manifest.json":
                rel = path.relative_to(target).as_posix()
                if not path.resolve().is_relative_to(target.resolve()):
                    raise GenerationError("generation file escapes its root")
                actual[rel] = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != expected:
            raise GenerationError("generation files do not match the immutable digest manifest")
        return target

    def activate(self, generation_id: str) -> str | None:
        generation_id = self._validate_id(generation_id)
        with process_lock(self.owned.path("installer.lock")):
            target = self._verified_path(generation_id)
            pointer = self.owned.path("active-generation")
            previous = pointer.read_text(encoding="utf-8").strip() if pointer.exists() else None
            if previous:
                self._validate_id(previous)
            fd, name = tempfile.mkstemp(prefix=".active-generation-", dir=self.owned.root)
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as stream:
                    stream.write(generation_id + "\n")
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(name, pointer)
                self._fsync_directory(self.owned.root)
            finally:
                if os.path.exists(name):
                    os.unlink(name)
            self.journal.record_owned("generation", generation_id, "active")
            self.journal.checkpoint("registry-activate", "activated", {"generation": generation_id, "previous": previous})
            return previous

    def rollback(self, previous: str | None) -> None:
        if previous is not None:
            previous = self._validate_id(previous)
            self._verified_path(previous)
        with process_lock(self.owned.path("installer.lock")):
            pointer = self.owned.path("active-generation")
            if previous is None:
                pointer.unlink(missing_ok=True)
                self._fsync_directory(self.owned.root)
            else:
                fd, name = tempfile.mkstemp(prefix=".active-generation-", dir=self.owned.root)
                try:
                    with os.fdopen(fd, "w", encoding="utf-8") as stream:
                        stream.write(previous + "\n")
                        stream.flush()
                        os.fsync(stream.fileno())
                    os.replace(name, pointer)
                    self._fsync_directory(self.owned.root)
                finally:
                    if os.path.exists(name):
                        os.unlink(name)
            self.journal.checkpoint("registry-activate", "rolled_back", {"generation": previous})
