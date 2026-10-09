"""Recoverable generation activation, backup, restore and uninstall effects.

This module keeps installer-owned effects explicit and restartable.  It does not
install packages itself: reviewed bootstrap/component adapters stage immutable
files, while this module owns the filesystem transaction and its journal.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import sqlite3
import tarfile
import tempfile
import time
import uuid
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Callable, Mapping

from .state import Journal, OwnedRoot, OwnershipError, _atomic_write, process_lock


class LifecycleError(RuntimeError):
    """A safe operation failure with a journaled recovery path."""


_IDENTITY = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}\Z")
_CURRENT = "active-generation.json"
_MARKER = ".hermes-generation-owned.json"
_MANIFEST = ".hermes-generation-manifest.json"


@dataclass(frozen=True, slots=True)
class Generation:
    identity: str
    path: Path
    digest: str
    files: int


class GenerationStore:
    """Stage immutable generations and atomically switch a verified pointer."""

    def __init__(self, data_root: OwnedRoot, journal: Journal):
        self.data_root = data_root
        self.journal = journal
        self.data_root.ensure()
        self.generations = self.data_root.path("generations")
        self.generations.mkdir(parents=True, exist_ok=True, mode=0o700)

    def stage(self, identity: str, files: Mapping[str, bytes], *, file_modes: Mapping[str, int] | None = None) -> Path:
        if not _IDENTITY.fullmatch(identity):
            raise LifecycleError("Generation identity contains unsupported characters")
        if not files:
            raise LifecycleError("Cannot stage an empty generation")
        target = self.generations / identity
        expected_files: dict[str, str] = {}
        for relative, content in files.items():
            if relative in {_MARKER, _MANIFEST}:
                raise LifecycleError("Generation input cannot replace reserved integrity metadata")
            if not isinstance(content, bytes):
                raise LifecycleError("Generation file content must be bytes")
            # Validate path shape before considering an existing checkpoint.
            self._safe_relative(self.generations, relative)
            expected_files[relative] = hashlib.sha256(content).hexdigest()
        if target.exists() or target.is_symlink():
            existing = self.inspect(target)
            manifest = json.loads((target / _MANIFEST).read_text(encoding="utf-8"))["files"]
            if existing.identity == identity and manifest == expected_files:
                self.journal.record_owned("generation", identity, "staged")
                self.journal.event("lifecycle:generation", identity, "stage_recovered", {"digest": existing.digest, "files": existing.files})
                return target
            raise OwnershipError("Generation already exists with different contents; it was preserved")
        stage = self.generations / (".stage-" + uuid.uuid4().hex)
        stage.mkdir(mode=0o700)
        manifest: dict[str, str] = {}
        try:
            for relative, content in sorted(files.items()):
                destination = self._safe_relative(stage, relative)
                destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                mode = (file_modes or {}).get(relative, 0o444)
                if mode & ~0o555 or mode & 0o022 or not mode & 0o444:
                    raise LifecycleError("Generation files must be readable and immutable to their owner and group")
                fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), mode)
                with os.fdopen(fd, "wb") as stream:
                    stream.write(content)
                    stream.flush()
                    os.fsync(stream.fileno())
                manifest[relative] = hashlib.sha256(content).hexdigest()
            digest = hashlib.sha256(json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            payload = {"schema": 1, "identity": identity, "digest": digest, "files": manifest}
            _atomic_write(stage / _MANIFEST, (json.dumps(payload, sort_keys=True) + "\n").encode(), 0o600)
            _atomic_write(stage / _MARKER, (json.dumps({"schema": 1, "identity": identity, "digest": digest}) + "\n").encode(), 0o600)
            dir_fd = os.open(stage, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
            os.rename(stage, target)
            self._fsync_directory(self.generations)
            self.journal.record_owned("generation", identity, "staged")
            self.journal.event("lifecycle:generation", identity, "staged", {"digest": digest, "files": len(manifest)})
            return target
        except BaseException:
            shutil.rmtree(stage, ignore_errors=True)
            raise

    def inspect(self, generation: Path | str) -> Generation:
        path = Path(generation).absolute()
        if path.is_symlink() or not path.is_relative_to(self.generations.absolute()):
            raise OwnershipError("Generation path is outside the owned generations directory")
        if not path.is_dir():
            raise LifecycleError("Generation directory is unavailable")
        try:
            marker = json.loads((path / _MARKER).read_text(encoding="utf-8"))
            manifest = json.loads((path / _MANIFEST).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            raise LifecycleError("Generation ownership or manifest metadata is invalid") from None
        if marker.get("schema") != 1 or manifest.get("schema") != 1 or marker.get("identity") != manifest.get("identity") or marker.get("digest") != manifest.get("digest"):
            raise LifecycleError("Generation ownership metadata does not match its manifest")
        files = manifest.get("files")
        if not isinstance(files, dict) or not files:
            raise LifecycleError("Generation manifest has no files")
        for relative, expected in files.items():
            item = self._safe_relative(path, relative)
            if item.is_symlink() or not item.is_file():
                raise LifecycleError("Generation file is missing or is a symlink")
            digest = hashlib.sha256(item.read_bytes()).hexdigest()
            if digest != expected:
                raise LifecycleError("Generation file failed digest verification")
        actual_files: set[str] = set()
        for base, dirs, names in os.walk(path, followlinks=False):
            base_path = Path(base)
            for name in dirs:
                if (base_path / name).is_symlink():
                    raise LifecycleError("Generation contains a symlink directory")
            for name in names:
                item = base_path / name
                if item.is_symlink() or not item.is_file():
                    raise LifecycleError("Generation contains an unsupported file type")
                relative = item.relative_to(path).as_posix()
                if relative not in {_MARKER, _MANIFEST}:
                    actual_files.add(relative)
        if actual_files != set(files):
            raise LifecycleError("Generation contents do not exactly match the sealed manifest")
        actual = hashlib.sha256(json.dumps(files, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        if actual != marker["digest"]:
            raise LifecycleError("Generation manifest digest is invalid")
        return Generation(str(marker["identity"]), path, actual, len(files))

    def activate(self, generation: Path | str, *, health_check: Callable[[Generation], bool]) -> Generation:
        candidate = self.inspect(generation)
        operation = "lifecycle:activate:" + candidate.identity
        current = self.current()
        previous = current.identity if current else None
        self.journal.checkpoint(operation, "health_check", {"candidate": candidate.identity, "previous": previous})
        self.journal.event(operation, "health", "started", {"candidate": candidate.identity, "previous": previous})
        try:
            healthy = health_check(candidate)
        except BaseException as exc:
            self.journal.checkpoint(operation, "health_failed", {"candidate": candidate.identity, "error_type": type(exc).__name__, "previous": previous})
            self.journal.event(operation, "health", "failed", {"candidate": candidate.identity, "error_type": type(exc).__name__})
            raise LifecycleError("Candidate health probe failed; the active generation was preserved") from None
        if healthy is not True:
            self.journal.checkpoint(operation, "health_failed", {"candidate": candidate.identity, "previous": previous})
            self.journal.event(operation, "health", "failed", {"candidate": candidate.identity})
            raise LifecycleError("Candidate health probe did not pass; the active generation was preserved")
        pointer = {"schema": 1, "identity": candidate.identity, "digest": candidate.digest, "previous": previous}
        _atomic_write(self.data_root.path(_CURRENT), (json.dumps(pointer, sort_keys=True) + "\n").encode(), 0o600)
        self.journal.record_owned("generation", candidate.identity, "active")
        self.journal.checkpoint(operation, "active", pointer)
        self.journal.event(operation, "activation", "committed", {"candidate": candidate.identity, "previous": previous, "digest": candidate.digest})
        return candidate

    def materialize(self, generation: Path | str, mapping: Mapping[str, str], *,
                    file_modes: Mapping[str, int] | None = None) -> dict[str, list[str]]:
        """Install declared generation files while preserving unowned/user-edited files.

        `mapping` is source-relative path to destination-relative path. A file is
        updated only when its current digest still matches the last installer
        digest; otherwise it remains in place as a user overlay.
        """
        candidate = self.inspect(generation)
        manifest = json.loads((candidate.path / _MANIFEST).read_text(encoding="utf-8"))["files"]
        outcome: dict[str, list[str]] = {"installed": [], "updated": [], "preserved": []}
        operation = "lifecycle:materialize:" + candidate.identity
        for source_relative, destination_relative in sorted(mapping.items()):
            if source_relative not in manifest:
                raise LifecycleError("Materialization source is not in the verified generation manifest")
            source = self._safe_relative(candidate.path, source_relative)
            if source.is_symlink() or not source.is_file():
                raise OwnershipError("Materialization source must be a verified regular file")
            content = source.read_bytes()
            source_digest = hashlib.sha256(content).hexdigest()
            target = self.data_root.path(destination_relative)
            prior = self.journal.managed_file(destination_relative)
            existed = target.exists()
            current_digest = None
            if existed:
                if target.is_symlink() or not target.is_file():
                    raise OwnershipError("Materialization destination is not a regular file")
                current_digest = self._file_hash(target)
            if existed and (prior is None or prior.get("state") == "overlay-preserved" or current_digest != prior.get("installed_digest")):
                outcome["preserved"].append(destination_relative)
                if prior is not None and prior.get("state") != "overlay-preserved":
                    self.journal.record_managed_file(destination_relative, str(prior["source_digest"]), str(prior["installed_digest"]), "overlay-preserved")
                self.journal.event(operation, destination_relative, "overlay_preserved", {"source_digest": source_digest,
                    "existing_digest": current_digest, "reason": "unowned or modified user file"})
                continue
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            # Recheck ancestors after mkdir and never follow a user-created link.
            checked = self.data_root.path(destination_relative)
            if checked != target or target.is_symlink():
                raise OwnershipError("Materialization destination changed during update")
            temp = target.with_name("." + target.name + ".stage-" + uuid.uuid4().hex)
            mode = (file_modes or {}).get(source_relative, 0o644)
            if mode & ~0o755 or mode & 0o022 or not mode & 0o444:
                raise LifecycleError("Materialized files must be readable and not writable by other users")
            fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), mode)
            with os.fdopen(fd, "wb") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temp, target)
            self._fsync_directory(target.parent)
            self.journal.record_managed_file(destination_relative, source_digest, source_digest, "installed")
            category = "updated" if existed else "installed"
            outcome[category].append(destination_relative)
            self.journal.event(operation, destination_relative, category, {"source_digest": source_digest})
        self.journal.checkpoint(operation, "complete", {"generation": candidate.identity,
            "installed": len(outcome["installed"]), "updated": len(outcome["updated"]),
            "preserved": len(outcome["preserved"])})
        return outcome

    def apply_registry_materialization(self, generation: Path | str) -> dict[str, list[str]]:
        """Apply only the explicit, preserve-existing native mapping in a registry ledger."""
        candidate = self.inspect(generation)
        ledger = candidate.path / "installer-registry" / "crosswalk.json"
        if ledger.is_symlink() or not ledger.is_file():
            raise LifecycleError("Verified generation does not include a native materialization ledger")
        try:
            value = json.loads(ledger.read_text(encoding="utf-8"))
            policy = value["native_materialization"]
            rows = policy["files"]
        except (OSError, ValueError, KeyError, TypeError):
            raise LifecycleError("Native materialization ledger is invalid") from None
        if policy.get("schema") != 1 or policy.get("destination_root") != "data_root" or policy.get("preserve_existing") is not True or not isinstance(rows, list):
            raise LifecycleError("Native materialization ledger has an unsupported destination policy")
        mapping: dict[str, str] = {}
        for row in rows:
            if not isinstance(row, dict) or row.get("conflict_policy") != "preserve-existing":
                raise LifecycleError("Native materialization row must preserve existing files")
            source, destination = row.get("staged"), row.get("target")
            if not isinstance(source, str) or not isinstance(destination, str) or source in mapping:
                raise LifecycleError("Native materialization row has invalid paths")
            mapping[source] = destination
        return self.materialize(candidate.path, mapping)

    def current(self) -> Generation | None:
        path = self.data_root.path(_CURRENT)
        if path.is_symlink():
            raise OwnershipError("Active generation pointer cannot be a symlink")
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return None
        except (OSError, ValueError):
            raise LifecycleError("Active generation pointer is invalid") from None
        if value.get("schema") != 1 or not isinstance(value.get("identity"), str):
            raise LifecycleError("Active generation pointer has an unsupported schema")
        generation = self.inspect(self.generations / value["identity"])
        if generation.digest != value.get("digest"):
            raise LifecycleError("Active generation no longer matches its recorded digest")
        return generation

    def rollback(self, *, health_check: Callable[[Generation], bool]) -> Generation:
        current = self.current()
        if current is None:
            raise LifecycleError("There is no active generation to roll back")
        pointer = json.loads(self.data_root.path(_CURRENT).read_text(encoding="utf-8"))
        previous = pointer.get("previous")
        if not isinstance(previous, str):
            raise LifecycleError("No previous generation is recorded")
        candidate = self.inspect(self.generations / previous)
        if health_check(candidate) is not True:
            raise LifecycleError("Previous generation failed its recovery health check")
        _atomic_write(self.data_root.path(_CURRENT), (json.dumps({"schema": 1, "identity": candidate.identity,
            "digest": candidate.digest, "previous": current.identity}, sort_keys=True) + "\n").encode(), 0o600)
        self.journal.record_owned("generation", current.identity, "rollback-retained")
        self.journal.record_owned("generation", candidate.identity, "active")
        self.journal.event("lifecycle:rollback", candidate.identity, "committed", {"from": current.identity, "to": candidate.identity})
        return candidate

    def _safe_relative(self, root: Path, relative: str) -> Path:
        if not isinstance(relative, str) or not relative or "\\" in relative:
            raise OwnershipError("Generation path must be a non-empty POSIX relative path")
        path = PurePosixPath(relative)
        if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts) or relative.startswith("/"):
            raise OwnershipError("Generation path escapes its root")
        target = root.joinpath(*path.parts)
        current = root
        for part in path.parts[:-1]:
            current = current / part
            if current.is_symlink():
                raise OwnershipError("Generation path contains a symlink parent")
        if target.is_symlink():
            raise OwnershipError("Generation path is a symlink")
        return target

    @staticmethod
    def _fsync_directory(path: Path) -> None:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    @staticmethod
    def _file_hash(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            while block := stream.read(1024 * 1024):
                digest.update(block)
        return digest.hexdigest()


class LifecycleRecovery:
    """Versioned consistent backups and preserve-by-default uninstall/restore."""

    def __init__(self, data_root: OwnedRoot, state_root: OwnedRoot, journal: Journal):
        self.data_root = data_root
        self.state_root = state_root
        self.journal = journal
        self.data_root.ensure()
        self.state_root.ensure()
        self.backups = self.state_root.path("backups")
        self.backups.mkdir(parents=True, exist_ok=True, mode=0o700)

    def backup(self, *, database: Path | None = None, schema_version: int = 1) -> Path:
        if schema_version < 1:
            raise LifecycleError("Backup schema version must be positive")
        identity = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()) + "-" + uuid.uuid4().hex[:8]
        target = self.backups / identity
        stage = self.backups / (".stage-" + uuid.uuid4().hex)
        stage.mkdir(mode=0o700)
        operation = "lifecycle:backup:" + identity
        self.journal.checkpoint(operation, "running", {"schema_version": schema_version})
        try:
            entries: list[dict[str, object]] = []
            archive_path = stage / "user-data.tar"
            with tarfile.open(archive_path, "w") as archive:
                for rel in ("profiles", "overlays", "memory", "config", "runtime/user-data", "runtime/desktop-user-data"):
                    source = self.data_root.path(rel)
                    if source.exists():
                        self._add_tree(archive, source, "data/" + rel, entries)
                if database is not None and database.exists():
                    snapshot = stage / "journal-consistent.sqlite3"
                    self._sqlite_backup(database, snapshot)
                    archive.add(snapshot, arcname="state/journal.sqlite3", recursive=False)
                    entries.append({"path": "state/journal.sqlite3", "sha256": self._hash(snapshot), "size": snapshot.stat().st_size})
                    snapshot.unlink()
            manifest = {"schema_version": schema_version, "created_at": time.time(), "archive_sha256": self._hash(archive_path),
                "entries": entries, "secret_values_included": False,
                "note": "Credential references are preserved as references; credential values remain in their configured secure store."}
            _atomic_write(stage / "manifest.json", (json.dumps(manifest, sort_keys=True, indent=2) + "\n").encode(), 0o600)
            os.rename(stage, target)
            GenerationStore._fsync_directory(self.backups)
            self.journal.record_owned("backup", identity, "active")
            self.journal.checkpoint(operation, "complete", {"backup": str(target), "schema_version": schema_version,
                "archive_sha256": manifest["archive_sha256"], "entries": len(entries)})
            self.journal.event(operation, "backup", "complete", {"backup": identity, "entries": len(entries), "archive_sha256": manifest["archive_sha256"]})
            return target
        except BaseException as exc:
            shutil.rmtree(stage, ignore_errors=True)
            self.journal.checkpoint(operation, "failed", {"error_type": type(exc).__name__, "resume": "hermes-installer data backup"})
            self.journal.event(operation, "backup", "failed", {"error_type": type(exc).__name__})
            raise

    def restore(self, backup: Path, *, expected_schema_version: int = 1, overwrite: bool = False,
                database_destination: Path | None = None) -> dict[str, object]:
        candidate = backup.absolute()
        if candidate.is_symlink() or not candidate.is_dir() or not candidate.is_relative_to(self.backups.absolute()):
            raise OwnershipError("Restore source must be an installer-owned backup directory")
        manifest_path = candidate / "manifest.json"
        archive_path = candidate / "user-data.tar"
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            raise LifecycleError("Backup manifest is unavailable or invalid") from None
        if manifest.get("schema_version") != expected_schema_version:
            raise LifecycleError("Backup schema version is incompatible with this installer")
        if self._hash(archive_path) != manifest.get("archive_sha256"):
            raise LifecycleError("Backup archive failed integrity verification")
        identity = candidate.name
        operation = "lifecycle:restore:" + identity
        self.journal.checkpoint(operation, "running", {"backup": identity, "schema_version": expected_schema_version})
        conflicts: list[str] = []
        restored: list[str] = []
        restored_database: str | None = None
        stage = Path(tempfile.mkdtemp(prefix="hermes-restore-", dir=self.data_root.root))
        try:
            with tarfile.open(archive_path, "r") as archive:
                for member in archive.getmembers():
                    posix = PurePosixPath(member.name)
                    if member.issym() or member.islnk() or member.isdev() or posix.is_absolute() or ".." in posix.parts:
                        raise LifecycleError("Backup contains an unsafe filesystem entry")
            with tarfile.open(archive_path, "r") as archive:
                for member in archive.getmembers():
                    if member.isdir():
                        continue
                    if not member.isfile():
                        raise LifecycleError("Backup contains an unsupported filesystem entry")
                    source = archive.extractfile(member)
                    if source is None:
                        raise LifecycleError("Backup entry could not be read")
                    destination = stage.joinpath(*PurePosixPath(member.name).parts)
                    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                    if not destination.resolve(strict=False).is_relative_to(stage.resolve()):
                        raise LifecycleError("Backup entry escapes the restore staging root")
                    fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
                    with os.fdopen(fd, "wb") as output, source:
                        shutil.copyfileobj(source, output)
                        output.flush()
                        os.fsync(output.fileno())
            for source in stage.rglob("*"):
                if source.is_dir():
                    continue
                if source.is_symlink() or not source.is_file():
                    raise LifecycleError("Restored backup contains an unsafe file")
                relative = source.relative_to(stage)
                if relative.parts[:1] != ("data",):
                    if relative.parts[:1] == ("state",):
                        if relative.parts == ("state", "journal.sqlite3") and database_destination is not None:
                            restored_database = str(self._restore_database(source, database_destination))
                        continue
                    raise LifecycleError("Backup contains an unsupported destination")
                target = self.data_root.path(str(Path(*relative.parts[1:])))
                if target.exists() and not overwrite:
                    if self._hash(target) == self._hash(source):
                        restored.append(str(relative))
                        continue
                    conflicts.append(str(relative))
                    continue
                target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                temp = target.with_name("." + target.name + ".restore-" + uuid.uuid4().hex)
                shutil.copyfile(source, temp, follow_symlinks=False)
                os.chmod(temp, 0o600)
                os.replace(temp, target)
                restored.append(str(relative))
            result = {"backup": identity, "restored": restored, "conflicts_preserved": conflicts,
                "database_snapshot_present": any(str(row.get("path", "")).startswith("state/") for row in manifest.get("entries", [])),
                "database_restored_to": restored_database}
            self.journal.checkpoint(operation, "complete" if not conflicts else "complete_with_conflicts", result)
            self.journal.event(operation, "restore", "complete", {"backup": identity, "restored_count": len(restored), "conflict_count": len(conflicts)})
            return result
        except BaseException as exc:
            self.journal.checkpoint(operation, "failed", {"backup": identity, "error_type": type(exc).__name__, "resume": "hermes-installer data restore"})
            self.journal.event(operation, "restore", "failed", {"backup": identity, "error_type": type(exc).__name__})
            raise
        finally:
            shutil.rmtree(stage, ignore_errors=True)

    def _restore_database(self, source: Path, destination: Path) -> Path:
        target = destination.expanduser().absolute()
        if target.is_symlink() or not target.is_relative_to(self.state_root.root.absolute()):
            raise OwnershipError("Database restore destination must remain inside the owned state root")
        if not target.parent.is_dir() or target.parent.is_symlink():
            raise OwnershipError("Database restore destination parent is unavailable or unsafe")
        check = sqlite3.connect(f"file:{source}?mode=ro", uri=True, timeout=5)
        try:
            tables = {row[0] for row in check.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if not {"operations", "owned_resources"}.issubset(tables):
                raise LifecycleError("Backed-up SQLite database does not match the installer state schema")
            if check.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                raise LifecycleError("Backed-up SQLite database failed integrity verification")
        finally:
            check.close()
        lock = self.state_root.path("installer.lock")
        with process_lock(lock):
            previous: Path | None = None
            if target.exists():
                previous = self.backups / ("pre-restore-" + time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()) + "-" + uuid.uuid4().hex[:8] + ".sqlite3")
                self._sqlite_backup(target, previous)
                previous.chmod(0o600)
            temp = target.with_name("." + target.name + ".restore-" + uuid.uuid4().hex)
            self._sqlite_backup(source, temp)
            temp.chmod(0o600)
            for suffix in ("-wal", "-shm"):
                sidecar = Path(str(target) + suffix)
                if sidecar.exists() and (sidecar.is_symlink() or not sidecar.is_file()):
                    temp.unlink(missing_ok=True)
                    raise OwnershipError("Live SQLite sidecar is unsafe")
            os.replace(temp, target)
            for suffix in ("-wal", "-shm"):
                Path(str(target) + suffix).unlink(missing_ok=True)
            GenerationStore._fsync_directory(target.parent)
        self.journal = Journal(target)
        self.journal.event("lifecycle:database-restore", target.name, "committed", {
            "database": target.name, "previous_snapshot": previous.name if previous else None})
        return target

    def uninstall(self, *, stop_owned: Callable[[], None] | None = None) -> dict[str, object]:
        """Remove only ledger-owned software artifacts and retain all user data."""
        operation = "lifecycle:uninstall"
        self.journal.checkpoint(operation, "running", {"data_retained": True})
        try:
            if stop_owned is not None:
                stop_owned()
            removed: list[str] = []
            for row in self.journal.owned():
                if row["kind"] == "generation" and row["state"] in {"active", "staged", "rollback-retained"}:
                    name = str(row["resource_id"])
                    if not _IDENTITY.fullmatch(name):
                        continue
                    path = self.data_root.path("generations/" + name)
                    if path.exists() and not path.is_symlink():
                        marker = path / _MARKER
                        if marker.is_file() and not marker.is_symlink():
                            try:
                                value = json.loads(marker.read_text(encoding="utf-8"))
                            except (OSError, ValueError):
                                continue
                            if value.get("identity") != name:
                                continue
                            shutil.rmtree(path)
                            removed.append(name)
                    self.journal.record_owned("generation", name, "uninstalled")
                if row["kind"] == "hermes-generation" and row["state"] == "active":
                    candidate = Path(str(row["resource_id"])).absolute()
                    expected_root = self.data_root.path("generations").absolute()
                    if candidate.is_symlink() or not candidate.is_relative_to(expected_root) or not candidate.is_dir():
                        continue
                    marker = candidate.parent / ("." + candidate.name + ".owned")
                    if marker.is_symlink() or not marker.is_file():
                        continue
                    try:
                        marker_data = marker.read_text(encoding="ascii")
                    except OSError:
                        continue
                    from .bootstrap import HERMES_COMMIT
                    if marker_data != f"schema=1\ncommit={HERMES_COMMIT}\n":
                        continue
                    shutil.rmtree(candidate)
                    marker.unlink()
                    removed.append(candidate.name)
                    self.journal.record_owned("hermes-generation", str(candidate), "uninstalled")
            pointer = self.data_root.path(_CURRENT)
            if pointer.exists() and not pointer.is_symlink():
                pointer.unlink()
            result = {"removed_generations": removed, "data_retained": True,
                "preserved_paths": ["profiles", "models", "overlays", "memory", "runtime", "backups", "source-snapshots"]}
            self.journal.checkpoint(operation, "complete", result)
            self.journal.event(operation, "uninstall", "complete", {"removed_count": len(removed), "data_retained": True})
            return result
        except BaseException as exc:
            self.journal.checkpoint(operation, "failed", {"error_type": type(exc).__name__, "data_retained": True})
            self.journal.event(operation, "uninstall", "failed", {"error_type": type(exc).__name__})
            raise

    @staticmethod
    def _add_tree(archive: tarfile.TarFile, source: Path, arcname: str, entries: list[dict[str, object]]) -> None:
        if source.is_symlink():
            raise OwnershipError("Backup source contains a symlink and was not followed")
        if source.is_file():
            LifecycleRecovery._add_file(archive, source, arcname, entries)
            return
        for base, dirs, files in os.walk(source, followlinks=False):
            base_path = Path(base)
            dirs[:] = [name for name in dirs if not (base_path / name).is_symlink()]
            for name in files:
                item = base_path / name
                if item.is_symlink():
                    raise OwnershipError("Backup source contains a symlink and was not followed")
                if re.search(r"(?i)(?:^\.env$|credential|secret|token|auth\.json)", name):
                    continue
                if item.is_file():
                    LifecycleRecovery._add_file(archive, item, arcname + "/" + item.relative_to(source).as_posix(), entries)

    @staticmethod
    def _add_file(archive: tarfile.TarFile, source: Path, arcname: str, entries: list[dict[str, object]]) -> None:
        archive.add(source, arcname=arcname, recursive=False)
        entries.append({"path": arcname, "sha256": LifecycleRecovery._hash(source), "size": source.stat().st_size})

    @staticmethod
    def _sqlite_backup(source: Path, destination: Path) -> None:
        if source.is_symlink() or not source.is_file():
            raise OwnershipError("SQLite backup source must be a regular file")
        source_db = sqlite3.connect(f"file:{source}?mode=ro", uri=True, timeout=5)
        try:
            target_db = sqlite3.connect(destination)
            try:
                source_db.backup(target_db, pages=256, sleep=0.02)
                target_db.commit()
            finally:
                target_db.close()
        finally:
            source_db.close()

    @staticmethod
    def _hash(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            while block := stream.read(1024 * 1024):
                digest.update(block)
        return digest.hexdigest()
