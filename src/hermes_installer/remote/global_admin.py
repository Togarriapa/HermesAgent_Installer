"""Fixed, protected registry for the explicitly enrolled original administrator.

The registry is policy state, not a credential store.  Only this module's
finite operations can address it; callers cannot select a path or supply a
role.  Native readers hold the shared lock across their transaction, while
Root enrollment and revocation hold the exclusive lock.
"""
from __future__ import annotations

from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any, Iterator

GLOBAL_ADMIN_DIRECTORY = Path("/var/lib/hermes-installer/core-runtime")
GLOBAL_ADMIN_PATH = GLOBAL_ADMIN_DIRECTORY / "global-admin.json"
GLOBAL_ADMIN_LOCK_PATH = GLOBAL_ADMIN_DIRECTORY / "global-admin.lock"
MAX_RECORD_BYTES = 4096
_EMAIL = re.compile(r"[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+\Z")
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_KEYS = frozenset({"schema", "state", "revision", "hostname", "issuer", "audience",
    "admin_email_sha256", "admin_subject_sha256", "home_uid", "home_realpath"})


class GlobalAdminError(PermissionError):
    """Fixed global-administrator operation failed closed."""


def normalize_email(value: str) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 254:
        raise GlobalAdminError("administrator identity is invalid")
    normalized = value.strip().casefold()
    if not _EMAIL.fullmatch(normalized):
        raise GlobalAdminError("administrator identity is invalid")
    return normalized


def _validate_record(value: Any) -> dict[str, Any]:
    if (type(value) is not dict or set(value) != _KEYS
            or type(value["schema"]) is not int or value["schema"] != 1
            or value["state"] not in {"active", "revoked"}
            or type(value["revision"]) is not int or value["revision"] < 1
            or type(value["home_uid"]) is not int or value["home_uid"] != 1000
            or value["home_realpath"] != "/home/admin/.hermes"
            or not all(isinstance(value[k], str) and 1 <= len(value[k]) <= 512
                       for k in ("hostname", "issuer", "audience"))
            or not _HASH.fullmatch(value["admin_email_sha256"])
            or not _HASH.fullmatch(value["admin_subject_sha256"])):
        raise GlobalAdminError("administrator registry is invalid")
    return value


def record_sha256(record: dict[str, Any]) -> str:
    canonical = json.dumps(_validate_record(record), sort_keys=True,
        separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")
    return hashlib.sha256(canonical).hexdigest()


def _verify_directory() -> None:
    if not sys.platform.startswith("linux") or os.getuid() != 0 or os.geteuid() != 0:
        raise GlobalAdminError("administrator registry requires the installed Linux Root actor")
    info = os.lstat(GLOBAL_ADMIN_DIRECTORY)
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
            or stat.S_IMODE(info.st_mode) != 0o700):
        raise GlobalAdminError("administrator registry custody is unavailable")


@contextmanager
def locked(*, exclusive: bool) -> Iterator[int]:
    """Hold the fixed root-owned lock; yield its descriptor for CAS work."""
    _verify_directory()
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(GLOBAL_ADMIN_LOCK_PATH, flags, 0o600)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
                or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600):
            raise GlobalAdminError("administrator lock custody is unavailable")
        fcntl.flock(fd, fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
        _verify_directory()
        yield fd
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


def read_locked() -> tuple[dict[str, Any] | None, str | None]:
    """Read and authenticate the exact fixed record while caller holds lock."""
    try:
        fd = os.open(GLOBAL_ADMIN_PATH, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                     | getattr(os, "O_CLOEXEC", 0))
    except FileNotFoundError:
        return None, None
    except OSError:
        # Only an actually absent record selects the legacy fallback. Symlinks,
        # permission failures and other open errors deny through the typed API.
        raise GlobalAdminError("administrator registry custody is unavailable") from None
    try:
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
                    or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600
                    or info.st_size > MAX_RECORD_BYTES):
                raise GlobalAdminError("administrator registry custody is unavailable")
            raw = bytearray()
            while len(raw) <= MAX_RECORD_BYTES:
                part = os.read(fd, min(2048, MAX_RECORD_BYTES + 1 - len(raw)))
                if not part:
                    break
                raw.extend(part)
            if not raw or len(raw) > MAX_RECORD_BYTES:
                raise GlobalAdminError("administrator registry is invalid")
        except OSError:
            raise GlobalAdminError("administrator registry custody is unavailable") from None
    finally:
        os.close(fd)
    try:
        value = json.loads(bytes(raw), object_pairs_hook=_unique_pairs)
        record = _validate_record(value)
    except Exception:
        raise GlobalAdminError("administrator registry is invalid") from None
    return record, record_sha256(record)


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _replace_locked(record: dict[str, Any], *, expected_sha256: str | None) -> str:
    current, current_sha = read_locked()
    if current_sha != expected_sha256:
        raise GlobalAdminError("administrator registry changed; inspect current status")
    _verify_directory()
    raw = json.dumps(_validate_record(record), sort_keys=True,
        separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")
    if len(raw) > MAX_RECORD_BYTES:
        raise GlobalAdminError("administrator registry exceeds its bound")
    temp = GLOBAL_ADMIN_DIRECTORY / f".global-admin-{os.urandom(16).hex()}.tmp"
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        info = os.fstat(fd)
        if info.st_uid != 0 or info.st_gid != 0 or stat.S_IMODE(info.st_mode) != 0o600:
            raise GlobalAdminError("administrator registry custody is unavailable")
        written = 0
        while written < len(raw):
            written += os.write(fd, raw[written:])
        os.fsync(fd)
    except BaseException:
        os.close(fd)
        try:
            os.unlink(temp)
        except OSError:
            pass
        raise
    else:
        os.close(fd)
    os.replace(temp, GLOBAL_ADMIN_PATH)
    dirfd = os.open(GLOBAL_ADMIN_DIRECTORY, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(dirfd)
    finally:
        os.close(dirfd)
    persisted, persisted_sha = read_locked()
    canonical_sha = record_sha256(record)
    if persisted != record or persisted_sha != canonical_sha:
        raise GlobalAdminError("administrator registry readback is uncertain")
    return canonical_sha


def current_status() -> dict[str, Any]:
    with locked(exclusive=False):
        record, sha = read_locked()
        if record is None:
            return {"state": "unconfigured", "revision": 0, "record_sha256": None}
        return {"state": record["state"], "revision": record["revision"], "record_sha256": sha}


def enroll(*, hostname: str, issuer: str, audience: str, email: str, subject: str,
           expected_sha256: str | None, reactivate_revision: int | None = None,
           reactivate_sha256: str | None = None) -> dict[str, Any]:
    normalized = normalize_email(email)
    if not all(isinstance(v, str) and 1 <= len(v) <= 512 for v in (hostname, issuer, audience, subject)):
        raise GlobalAdminError("verified administrator identity is invalid")
    email_sha = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
    subject_sha = hashlib.sha256(subject.encode("utf-8", "strict")).hexdigest()
    with locked(exclusive=True):
        old, old_sha = read_locked()
        if old is None:
            if expected_sha256 is not None or reactivate_revision is not None:
                raise GlobalAdminError("administrator registry changed; inspect current status")
            revision = 1
        else:
            same = (old["hostname"], old["issuer"], old["audience"], old["home_uid"],
                    old["home_realpath"], old["admin_email_sha256"], old["admin_subject_sha256"])
            wanted = (hostname, issuer, audience, 1000, "/home/admin/.hermes", email_sha, subject_sha)
            if (same == wanted and old["state"] == "active" and old_sha == expected_sha256
                    and reactivate_revision is None and reactivate_sha256 is None):
                return {"state": "active", "revision": old["revision"], "record_sha256": old_sha}
            if (same != wanted or old["state"] != "revoked"
                    or old["revision"] != reactivate_revision or old_sha != reactivate_sha256
                    or expected_sha256 != old_sha):
                raise GlobalAdminError("administrator reactivation requires the exact revoked identity and revision")
            revision = old["revision"] + 1
        new = {"schema": 1, "state": "active", "revision": revision,
            "hostname": hostname, "issuer": issuer, "audience": audience,
            "admin_email_sha256": email_sha, "admin_subject_sha256": subject_sha,
            "home_uid": 1000, "home_realpath": "/home/admin/.hermes"}
        digest = _replace_locked(new, expected_sha256=old_sha)
        return {"state": "active", "revision": revision, "record_sha256": digest}


def revoke(*, expected_sha256: str) -> dict[str, Any]:
    if not _HASH.fullmatch(expected_sha256 or ""):
        raise GlobalAdminError("exact current administrator revision is required")
    with locked(exclusive=True):
        old, old_sha = read_locked()
        if old is None or old_sha != expected_sha256:
            raise GlobalAdminError("administrator registry changed; inspect current status")
        if old["state"] == "revoked":
            return {"state": "revoked", "revision": old["revision"], "record_sha256": old_sha}
        new = dict(old, state="revoked", revision=old["revision"] + 1)
        digest = _replace_locked(new, expected_sha256=old_sha)
        return {"state": "revoked", "revision": new["revision"], "record_sha256": digest}


@contextmanager
def authorize_native(*, hostname: str, issuer: str, audience: str, email: str, subject: str,
                     expected_revision: int, expected_sha256: str) -> Iterator[dict[str, Any]]:
    """Validate exact current identity and hold shared lock through native work."""
    if (type(expected_revision) is not int or expected_revision < 1
            or not _HASH.fullmatch(expected_sha256 or "")):
        raise GlobalAdminError("current original administrator proof is required")
    with locked(exclusive=False):
        record, digest = read_locked()
        if (record is None or record["state"] != "active"
                or record["revision"] != expected_revision or digest != expected_sha256
                or record["hostname"] != hostname or record["issuer"] != issuer
                or record["audience"] != audience
                or record["home_uid"] != 1000 or record["home_realpath"] != "/home/admin/.hermes"
                or record["admin_email_sha256"] != hashlib.sha256(normalize_email(email).encode()).hexdigest()
                or record["admin_subject_sha256"] != hashlib.sha256(subject.encode("utf-8", "strict")).hexdigest()):
            raise GlobalAdminError("original administrator is unavailable or changed")
        yield {"revision": record["revision"], "record_sha256": digest}
