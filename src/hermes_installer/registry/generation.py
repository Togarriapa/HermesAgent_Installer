"""Immutable registry generations bound to the installer journal."""
from __future__ import annotations
import hashlib, json, os, shutil, stat, tempfile
from pathlib import Path
from typing import Mapping
from hermes_installer.state import Journal, OwnedRoot

class GenerationError(RuntimeError):
    """Generation ownership, integrity, or recovery check failed."""

class GenerationStore:
    """Must be constructed and used under the installer's outer process_lock."""
    def __init__(self, owned_root: OwnedRoot, journal: Journal, *, mutation_locked: bool):
        if mutation_locked is not True:
            raise RuntimeError("GenerationStore requires the outer installer mutation lease")
        self.owned, self.journal = owned_root, journal
        marker = owned_root.root / ".hermes-installer-owned"
        if owned_root.root.is_symlink() or marker.is_symlink() or not marker.is_file():
            raise GenerationError("installer root is not initialized")
        self._private_file(marker)
        if marker.read_bytes() != b"schema=1\n":
            raise GenerationError("installer ownership marker is invalid")
        self.root = owned_root.path("generations")
        self.root.mkdir(mode=0o700, exist_ok=True)
        self._private_dir(self.root)

    @staticmethod
    def _id(value: str) -> str:
        if not value or len(value) > 96 or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_" for c in value):
            raise ValueError("invalid generation id")
        return value

    @staticmethod
    def _private_file(path: Path) -> None:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
            raise GenerationError(f"file is not private and installer-owned: {path.name}")

    @staticmethod
    def _private_dir(path: Path) -> None:
        info = path.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise GenerationError(f"directory is not private and installer-owned: {path.name}")

    @staticmethod
    def _fsync_dir(path: Path) -> None:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
        try: os.fsync(fd)
        finally: os.close(fd)

    @staticmethod
    def _digest(manifest: dict) -> str:
        raw = json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
        return hashlib.sha256(b"registry-manifest-v1\0" + len(raw).to_bytes(8, "big") + raw).hexdigest()

    @staticmethod
    def _hash(path: Path) -> str:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
        digest = hashlib.sha256()
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
                raise GenerationError(f"file changed while verifying: {path.name}")
            with os.fdopen(fd, "rb", closefd=False) as stream:
                for block in iter(lambda: stream.read(65536), b""): digest.update(block)
        finally: os.close(fd)
        return digest.hexdigest()

    def _op(self, identity): return self.journal.operation("registry-generation:" + identity)
    def _owned(self, identity):
        return any(row.get("resource_id") == identity for row in self.journal.owned("generation"))

    def _verify(self, identity: str, *, require_owned=True):
        identity = self._id(identity)
        root = self.root / identity
        if root.is_symlink() or not root.is_dir(): raise GenerationError("generation missing or symlinked")
        self._private_dir(root)
        manifest_path = root / "manifest.json"
        if manifest_path.is_symlink() or not manifest_path.is_file(): raise GenerationError("generation manifest missing")
        self._private_file(manifest_path)
        try: manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, ValueError): raise GenerationError("invalid generation manifest") from None
        if not isinstance(manifest, dict) or manifest.get("schema") != 1 or manifest.get("generation") != identity or not isinstance(manifest.get("files"), dict):
            raise GenerationError("generation manifest identity mismatch")
        actual = {}
        for path in root.rglob("*"):
            if path.is_symlink(): raise GenerationError("generation contains symlink")
            if path.is_dir(): self._private_dir(path); continue
            if not path.is_file(): raise GenerationError("generation contains special file")
            if path != manifest_path: actual[path.relative_to(root).as_posix()] = self._hash(path)
        if actual != manifest["files"]: raise GenerationError("generation differs from content manifest")
        digest = self._digest(manifest)
        op = self._op(identity)
        if require_owned and not self._owned(identity): raise GenerationError("generation has no owner ledger entry")
        if op is None or op.get("payload", {}).get("manifest_digest") != digest:
            raise GenerationError("manifest digest is not bound to journal intent")
        return root, manifest, digest

    def stage(self, identity: str, files: Mapping[str, bytes]) -> Path:
        identity = self._id(identity)
        if not files: raise GenerationError("refusing empty generation")
        target = self.root / identity
        if target.exists() or target.is_symlink(): raise GenerationError("immutable generation already exists")
        staging = Path(tempfile.mkdtemp(prefix=".stage-", dir=self.root))
        os.chmod(staging, 0o700)
        try:
            hashes = {}
            for name, content in sorted(files.items()):
                rel = Path(name)
                if not isinstance(name, str) or rel.is_absolute() or not rel.parts or ".." in rel.parts or rel.as_posix() != name or name == "manifest.json":
                    raise ValueError("invalid generation path")
                if not isinstance(content, bytes): raise TypeError("generation content must be bytes")
                output = staging / rel
                output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                for directory in (output.parent, *output.parent.parents):
                    if directory.is_relative_to(staging): self._private_dir(directory)
                digest = hashlib.sha256()
                fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
                with os.fdopen(fd, "wb") as stream:
                    view = memoryview(content)
                    for offset in range(0, len(view), 65536):
                        block = view[offset:offset+65536]; stream.write(block); digest.update(block)
                    stream.flush(); os.fsync(stream.fileno())
                hashes[name] = digest.hexdigest()
            manifest = {"schema": 1, "generation": identity, "files": hashes}
            raw = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode() + b"\n"
            fd = os.open(staging / "manifest.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
            with os.fdopen(fd, "wb") as stream: stream.write(raw); stream.flush(); os.fsync(stream.fileno())
            digest = self._digest(manifest)
            op = "registry-generation:" + identity
            self.journal.checkpoint(op, "stage_prepared", {"manifest_digest": digest})
            self._fsync_dir(staging); staging.rename(target); self._fsync_dir(self.root)
            self.journal.record_owned("generation", identity, "staged")
            self.journal.checkpoint(op, "staged", {"manifest_digest": digest})
            return target
        except BaseException:
            shutil.rmtree(staging, ignore_errors=True)
            raise

    def reconcile_staging(self):
        count = 0
        for path in self.root.iterdir():
            if path.is_symlink() or not path.is_dir() or path.name.startswith(".stage-") or self._owned(path.name): continue
            try: identity = self._id(path.name)
            except ValueError: continue
            op = self._op(identity)
            if not op or op.get("status") != "stage_prepared": continue
            _, _, digest = self._verify(identity, require_owned=False)
            if op.get("payload", {}).get("manifest_digest") != digest: raise GenerationError("staging intent digest mismatch")
            self.journal.record_owned("generation", identity, "staged")
            self.journal.checkpoint("registry-generation:" + identity, "staged", {"manifest_digest": digest})
            count += 1
        return count

    def _pointer_record(self): return self.journal.operation("registry-active-pointer")

    def _read_pointer(self):
        pointer = self.owned.path("active-generation")
        record = self._pointer_record()
        if not pointer.exists() and not pointer.is_symlink():
            if record and record.get("status") == "active": raise GenerationError("owned active pointer is missing")
            return None
        if pointer.is_symlink(): raise GenerationError("active pointer is symlinked")
        self._private_file(pointer)
        identity = self._id(pointer.read_text(encoding="utf-8").strip())
        _, _, digest = self._verify(identity)
        if not record or record.get("status") != "active" or record.get("payload", {}).get("generation") != identity or record.get("payload", {}).get("manifest_digest") != digest:
            raise GenerationError("active pointer lacks matching journal owner and digest")
        return identity

    def _write_pointer(self, identity):
        pointer = self.owned.path("active-generation")
        if pointer.exists() or pointer.is_symlink():
            if pointer.is_symlink(): raise GenerationError("active pointer is symlinked")
            self._private_file(pointer)
            record = self._pointer_record()
            if not record or record.get("status") not in {"active", "activation_prepared", "rollback_prepared"}:
                raise GenerationError("refusing to replace foreign pointer")
            actual = self._id(pointer.read_text(encoding="utf-8").strip())
            payload = record.get("payload", {})
            status = record.get("status")
            expected = payload.get("previous") if status == "activation_prepared" else payload.get("generation")
            if actual != expected: raise GenerationError("pointer differs from journaled transition")
        if identity is None:
            pointer.unlink(missing_ok=True); self._fsync_dir(self.owned.root); return
        fd, name = tempfile.mkstemp(prefix=".active-generation-", dir=self.owned.root)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                stream.write(identity + "\n"); stream.flush(); os.fsync(stream.fileno())
            os.replace(name, pointer); self._fsync_dir(self.owned.root)
        finally:
            if os.path.exists(name): os.unlink(name)

    def activate(self, identity: str):
        identity = self._id(identity)
        _, _, digest = self._verify(identity)
        previous = self._read_pointer()
        previous_digest = self._verify(previous)[2] if previous else None
        payload = {"generation": identity, "manifest_digest": digest, "previous": previous, "previous_digest": previous_digest}
        self.journal.checkpoint("registry-active-pointer", "activation_prepared", payload)
        self._write_pointer(identity)
        self.journal.record_owned("generation", identity, "active")
        self.journal.checkpoint("registry-active-pointer", "active", payload)
        self.journal.checkpoint("registry-generation:" + identity, "active", {"manifest_digest": digest, "previous": previous})
        return previous

    def rollback(self, previous):
        current, record = self._read_pointer(), self._pointer_record()
        if current is None or not record: raise GenerationError("no active generation to roll back")
        payload = record.get("payload", {})
        if previous != payload.get("previous"): raise GenerationError("rollback target differs from journal")
        if previous is not None and self._verify(self._id(previous))[2] != payload.get("previous_digest"):
            raise GenerationError("rollback target digest changed")
        self.journal.checkpoint("registry-active-pointer", "rollback_prepared", payload)
        self._write_pointer(previous)
        if previous is None: self.journal.checkpoint("registry-active-pointer", "inactive", {"generation": None})
        else: self.journal.checkpoint("registry-active-pointer", "active", {"generation": previous, "manifest_digest": payload["previous_digest"], "previous": None, "previous_digest": None})
        self.journal.record_owned("generation", current, "rolled_back")

    def recover_pointer_transaction(self):
        record = self._pointer_record()
        if not record or record.get("status") not in {"activation_prepared", "rollback_prepared"}: return "clean"
        payload, pointer = record.get("payload", {}), self.owned.path("active-generation")
        if pointer.is_symlink(): raise GenerationError("cannot recover symlinked pointer")
        if pointer.exists():
            self._private_file(pointer); actual = self._id(pointer.read_text(encoding="utf-8").strip())
        else: actual = None
        if record["status"] == "activation_prepared":
            identity = self._id(payload.get("generation", ""))
            _, _, digest = self._verify(identity)
            if actual == identity and digest == payload.get("manifest_digest"):
                self.journal.record_owned("generation", identity, "active")
                self.journal.checkpoint("registry-active-pointer", "active", payload); return "activation_reconciled"
            if actual == payload.get("previous"):
                self.journal.checkpoint("registry-active-pointer", "inactive" if actual is None else "active",
                    {"generation": actual, "manifest_digest": payload.get("previous_digest"), "previous": None, "previous_digest": None})
                return "activation_not_applied"
        else:
            target = payload.get("previous")
            if actual == target:
                if target is None: self.journal.checkpoint("registry-active-pointer", "inactive", {"generation": None})
                else:
                    _, _, digest = self._verify(self._id(target))
                    if digest != payload.get("previous_digest"): raise GenerationError("rollback digest changed")
                    self.journal.checkpoint("registry-active-pointer", "active", {"generation": target, "manifest_digest": digest, "previous": None, "previous_digest": None})
                return "rollback_reconciled"
        return "intent_pending_operator_review"
