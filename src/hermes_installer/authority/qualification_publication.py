"""Source-owned publication receipts for the finite local qualification run.

The manifest is deliberately narrower than a normal policy publication.  It
can name only the six flat fixture outputs under a run root already retained by
``RootOwnedQualificationFixtureRegistry``.  It is not a path selector or an
authority input.
"""
from __future__ import annotations

import hashlib
import hmac
import math
import os
import re
import secrets
import stat
import time
from dataclasses import InitVar, dataclass
from typing import Any, Literal


_PUBLICATION_SEAL = object()
_KEY_OBSERVATION_SEAL = object()
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_HEX_ID = re.compile(r"[A-Za-z0-9_-]{16,128}\Z")
_ENTRIES = {
    "fixture-authority.json": ("file", 0o600),
    "fixture-key.bin": ("file", 0o600),
    "fixture-session.json": ("file", 0o600),
    "fixture-policy": ("directory", 0o700),
    "fixture-policy/generation.json": ("file", 0o600),
    "fixture-policy/selection.json": ("file", 0o600),
}
_ENROLLMENT_DOMAIN = b"hermes-installer.qualification-enrollment.v1\x00"
_PUBLICATION_FIELDS = frozenset({
    "schema", "publication_receipt_handle", "fixture_selection_handle", "fixture_run_id",
    "authority_root_id", "fixture_generation_id", "policy_sha256", "catalog_sha256",
    "source_recipe_sha256", "key_id", "controller_lease_handle", "issued_monotonic",
    "expires_monotonic",
})


@dataclass(frozen=True, slots=True)
class RootQualificationOwnedEntry:
    """One held, root-owned file or directory from the fixed cleanup set."""

    name: str
    kind: Literal["file", "directory"]
    device: int
    inode: int
    sha256: str | None
    mode: int

    def __post_init__(self) -> None:
        expected = _ENTRIES.get(self.name)
        if (expected is None or expected != (self.kind, self.mode)
                or type(self.device) is not int or self.device < 0
                or type(self.inode) is not int or self.inode <= 0):
            raise ValueError("qualification publication entry is outside its fixed namespace")
        if self.kind == "file":
            if not isinstance(self.sha256, str) or not _SHA256.fullmatch(self.sha256):
                raise ValueError("qualification publication file digest is malformed")
        elif self.sha256 is not None:
            raise ValueError("qualification publication directory cannot carry a file digest")


@dataclass(frozen=True, slots=True, repr=False)
class RootQualificationOwnedPublication:
    """Sealed manifest used once to verify and remove one fixture publication."""

    selection_handle: str
    fixture_root_identity: tuple[int, int]
    generation_digest: str
    key_id: str
    authority_epoch: str
    entries: tuple[RootQualificationOwnedEntry, ...]
    _seal: InitVar[object] = None

    def __post_init__(self, _seal: object) -> None:
        if _seal is not _PUBLICATION_SEAL:
            raise TypeError("qualification publication manifests are publisher-issued")
        if (not _HEX_ID.fullmatch(self.selection_handle)
                or not isinstance(self.fixture_root_identity, tuple)
                or len(self.fixture_root_identity) != 2
                or any(type(part) is not int or part < 0 for part in self.fixture_root_identity)
                or not _SHA256.fullmatch(self.generation_digest)
                or not _HEX_ID.fullmatch(self.key_id)
                or not _HEX_ID.fullmatch(self.authority_epoch)
                or type(self.entries) is not tuple
                or any(type(entry) is not RootQualificationOwnedEntry for entry in self.entries)):
            raise ValueError("qualification publication identity is malformed")
        names = [entry.name for entry in self.entries]
        if len(names) != len(set(names)) or set(names) != set(_ENTRIES):
            raise ValueError("qualification publication must contain the exact fixed entry set")

    def verify_current(self, lease: object) -> bool:
        """Revalidate the selected lease and every physical entry before cleanup."""
        from .installed_qualification import RootOwnedQualificationFixtureLease

        if type(lease) is not RootOwnedQualificationFixtureLease:
            raise ValueError("qualification publication requires its exact held fixture lease")
        lease.verify_current()
        root = os.fstat(lease.fixture_root_fd)
        if (self.selection_handle != lease.selection.selection_handle
                or (root.st_dev, root.st_ino) != self.fixture_root_identity
                or (root.st_dev, root.st_ino) != (lease.fixture_device, lease.fixture_inode)
                or root.st_uid != 0 or stat.S_IMODE(root.st_mode) != 0o700):
            raise ValueError("qualification publication no longer matches its held fixture root")
        policy_fd = os.open("fixture-policy", os.O_RDONLY | os.O_DIRECTORY
                            | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=lease.fixture_root_fd)
        try:
            policy_info = os.fstat(policy_fd)
            policy_entry = next(entry for entry in self.entries if entry.name == "fixture-policy")
            if ((policy_info.st_dev, policy_info.st_ino) != (policy_entry.device, policy_entry.inode)
                    or policy_info.st_uid != 0 or stat.S_IMODE(policy_info.st_mode) != 0o700
                    or set(os.listdir(policy_fd)) != {"generation.json", "selection.json"}):
                raise ValueError("qualification policy directory identity or membership changed")
            for entry in self.entries:
                if entry.kind == "directory":
                    continue
                parent_fd, leaf = ((policy_fd, entry.name.partition("/")[2])
                                   if entry.name.startswith("fixture-policy/")
                                   else (lease.fixture_root_fd, entry.name))
                info = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
                expected_kind = stat.S_ISDIR(info.st_mode) if entry.kind == "directory" else stat.S_ISREG(info.st_mode)
                if (not expected_kind or info.st_uid != 0
                        or (info.st_dev, info.st_ino) != (entry.device, entry.inode)
                        or stat.S_IMODE(info.st_mode) != entry.mode):
                    raise ValueError("qualification publication entry identity changed")
                if entry.kind == "file":
                    fd = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                 dir_fd=parent_fd)
                    try:
                        if _hash_fd(fd) != entry.sha256:
                            raise ValueError("qualification publication entry bytes changed")
                    finally:
                        os.close(fd)
        finally:
            os.close(policy_fd)
        return True

    def __repr__(self) -> str:
        return "RootQualificationOwnedPublication(<root-private>)"


def _hash_fd(fd: int) -> str:
    digest = hashlib.sha256()
    offset = os.lseek(fd, 0, os.SEEK_CUR)
    try:
        os.lseek(fd, 0, os.SEEK_SET)
        while True:
            block = os.read(fd, 1024 * 1024)
            if not block:
                break
            digest.update(block)
    finally:
        os.lseek(fd, offset, os.SEEK_SET)
    return digest.hexdigest()


@dataclass(frozen=True, slots=True, repr=False)
class RootQualificationAuthorityKeyObservation:
    """Current key-file evidence. Key bytes remain in the owning registry."""

    schema: int
    key_observation_handle: str
    key_id: str
    fixture_selection_handle: str
    fixture_run_id: str
    authority_root_id: str
    source_recipe_sha256: str
    device: int
    inode: int
    mode: int
    owner_uid: int
    issued_monotonic: float
    expires_monotonic: float
    _registry: Any = None
    _seal: InitVar[object] = None

    def __post_init__(self, _seal: object) -> None:
        if _seal is not _KEY_OBSERVATION_SEAL:
            raise TypeError("qualification key observations are minted by the held key registry")
        if (self.schema != 1 or not _HEX_ID.fullmatch(self.key_observation_handle)
                or not _HEX_ID.fullmatch(self.key_id)
                or not _HEX_ID.fullmatch(self.fixture_selection_handle)
                or not _HEX_ID.fullmatch(self.fixture_run_id)
                or not _HEX_ID.fullmatch(self.authority_root_id)
                or not _SHA256.fullmatch(self.source_recipe_sha256)
                or type(self.device) is not int or self.device < 0
                or type(self.inode) is not int or self.inode <= 0
                or self.mode != 0o600 or self.owner_uid != 0
                or type(self.issued_monotonic) not in (float, int)
                or type(self.expires_monotonic) not in (float, int)
                or not math.isfinite(self.issued_monotonic)
                or not math.isfinite(self.expires_monotonic)
                or self.issued_monotonic <= 0
                or self.expires_monotonic <= self.issued_monotonic
                or not callable(getattr(self._registry, "verify_current", None))):
            raise ValueError("qualification key observation is malformed")

    def verify_current(self) -> bool:
        return self._registry.verify_current(self) is True

    def _service_key_bytes(self, service_type: type, *, enrollment: object,
                           runtime_registry: object) -> bytes:
        from .service import AuthorityService
        if (service_type is not AuthorityService
                or not callable(getattr(service_type, "from_root_qualification", None))):
            raise ValueError("only the reviewed root-qualification AuthorityService may consume this key")
        if self.verify_current() is not True:
            raise ValueError("qualification key observation is stale")
        return self._registry._key_bytes_for_service(
            self, enrollment=enrollment, runtime_registry=runtime_registry,
        )

    def __repr__(self) -> str:
        return "RootQualificationAuthorityKeyObservation(<root-private>)"


class RootQualificationAuthorityKeyRegistry:
    """Create one ephemeral signer key beneath a held qualification run root."""

    def __init__(self, selection: object, fixture_registry: object, root_journal: object):
        from .installed_qualification import (
            RootOwnedQualificationFixtureRegistry,
            RootOwnedQualificationFixtureSelection,
        )
        from hermes_installer.protected_enrollment import RootJournalSelection

        if (type(selection) is not RootOwnedQualificationFixtureSelection
                or type(fixture_registry) is not RootOwnedQualificationFixtureRegistry
                or type(root_journal) is not RootJournalSelection
                or fixture_registry.root_journal is not root_journal):
            raise ValueError("qualification key registry requires the exact held fixture and root journal")
        self.selection = selection
        self.fixture_registry = fixture_registry
        self.root_journal = root_journal
        self._observations: dict[str, tuple[RootQualificationAuthorityKeyObservation, object, int, bytearray, str]] = {}
        self._closed = False

    @classmethod
    def from_owned_fixture(cls, fixture_selection: object, root_journal: object,
                           fixture_registry: object) -> "RootQualificationAuthorityKeyRegistry":
        return cls(fixture_selection, fixture_registry, root_journal)

    def observe_selected_fixture_key(self) -> RootQualificationAuthorityKeyObservation:
        if self._closed or self._observations:
            raise ValueError("qualification run permits exactly one live signer key")
        lease = self.fixture_registry.resolve_current_selection(self.selection)
        selection = lease.selection
        if (selection.suite_id != "resource-cron-task-v1"
                or selection.fixture_root_observation_handle != selection.selection_handle):
            raise ValueError("qualification key is outside the fixed source-owned fixture")
        key_fd = -1
        key = bytearray(secrets.token_bytes(32))
        try:
            key_fd = os.open("fixture-key.bin", os.O_RDWR | os.O_CREAT | os.O_EXCL
                             | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600,
                             dir_fd=lease.fixture_root_fd)
            info = os.fstat(key_fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
                raise ValueError("ephemeral qualification signer key has unsafe ownership")
            view = memoryview(key)
            while view:
                written = os.write(key_fd, view)
                if written <= 0:
                    raise OSError("short write while creating qualification signer key")
                view = view[written:]
            os.fsync(key_fd)
            os.fsync(lease.fixture_root_fd)
            os.lseek(key_fd, 0, os.SEEK_SET)
            recipe_row = lease.source_catalog._rows[selection.fixture_recipe_artifact_id]
            key_id = "qualification-key-" + secrets.token_hex(16)
            handle = secrets.token_urlsafe(32)
            now = time.monotonic()
            observation = RootQualificationAuthorityKeyObservation(
                schema=1, key_observation_handle=handle, key_id=key_id,
                fixture_selection_handle=selection.selection_handle,
                fixture_run_id=lease.run_name,
                authority_root_id=self.root_journal.root_id,
                source_recipe_sha256=recipe_row.sha256,
                device=info.st_dev, inode=info.st_ino, mode=0o600, owner_uid=0,
                issued_monotonic=now,
                expires_monotonic=min(selection.expires_monotonic, now + 300.0),
                _registry=self, _seal=_KEY_OBSERVATION_SEAL,
            )
            digest = hashlib.sha256(key).hexdigest()
            self._observations[handle] = (observation, lease, key_fd, key, digest)
            key_fd = -1
            key = bytearray()
            return observation
        except BaseException:
            if key_fd >= 0:
                os.close(key_fd)
            _zero(key)
            try:
                os.unlink("fixture-key.bin", dir_fd=lease.fixture_root_fd)
            except OSError:
                pass
            raise

    def sign_qualification_enrollment(
        self, observation: RootQualificationAuthorityKeyObservation, *,
        publication_fields: dict[str, object], authority_sha256: str,
        catalog_sha256: str, generation_sha256: str,
    ) -> str:
        """Sign only the closed v164 fixture enrollment envelope.

        This is intentionally the sole signing operation exposed for an
        ephemeral qualification key.  It cannot sign effect grants, generic
        payloads, or normal authority publication records.
        """
        self.verify_current(observation)
        if (not isinstance(publication_fields, dict)
                or set(publication_fields) != _PUBLICATION_FIELDS
                or publication_fields.get("schema") != 1
                or publication_fields.get("fixture_selection_handle") != self.selection.selection_handle
                or publication_fields.get("fixture_run_id") != observation.fixture_run_id
                or publication_fields.get("authority_root_id") != observation.authority_root_id
                or publication_fields.get("source_recipe_sha256") != observation.source_recipe_sha256
                or publication_fields.get("key_id") != observation.key_id
                or publication_fields.get("controller_lease_handle")
                != self.selection.controller_unit_observation_handle
                or any(not isinstance(value, str) or not _SHA256.fullmatch(value)
                       for value in (authority_sha256, catalog_sha256, generation_sha256))
                or publication_fields.get("policy_sha256") != authority_sha256
                or publication_fields.get("catalog_sha256") != catalog_sha256):
            raise ValueError("qualification publication is outside the fixed enrolled source and key")
        issued = publication_fields.get("issued_monotonic")
        expires = publication_fields.get("expires_monotonic")
        if (type(issued) not in (int, float) or type(expires) not in (int, float)
                or not math.isfinite(issued) or not math.isfinite(expires)
                or issued < observation.issued_monotonic
                or expires > observation.expires_monotonic or expires <= time.monotonic()):
            raise ValueError("qualification enrollment signature lifetime is outside its held key lease")
        envelope = {
            "schema": 1,
            "publication": publication_fields,
            "authority_sha256": authority_sha256,
            "catalog_sha256": catalog_sha256,
            "generation_sha256": generation_sha256,
        }
        payload = _canonical_json(envelope)
        self.verify_current(observation)
        key = self._observations[observation.key_observation_handle][3]
        return hmac.new(bytes(key), _ENROLLMENT_DOMAIN + payload, hashlib.sha256).hexdigest()

    def verify_current(self, observation: RootQualificationAuthorityKeyObservation) -> bool:
        if self._closed or type(observation) is not RootQualificationAuthorityKeyObservation:
            raise ValueError("qualification key registry is closed or proof malformed")
        retained = self._observations.get(observation.key_observation_handle)
        if retained is None or retained[0] is not observation:
            raise ValueError("qualification key observation is not retained by this registry")
        _, lease, fd, key, expected_digest = retained
        lease.verify_current()
        if (time.monotonic() >= observation.expires_monotonic
                or observation.expires_monotonic > lease.selection.expires_monotonic):
            raise ValueError("qualification key observation expired")
        info = os.fstat(fd)
        if (info.st_dev, info.st_ino, info.st_uid, stat.S_IMODE(info.st_mode), info.st_nlink) != (
                observation.device, observation.inode, 0, 0o600, 1):
            raise ValueError("held qualification key identity changed")
        path_info = os.stat("fixture-key.bin", dir_fd=lease.fixture_root_fd,
                            follow_symlinks=False)
        if ((path_info.st_dev, path_info.st_ino) != (info.st_dev, info.st_ino)
                or _hash_fd(fd) != expected_digest
                or hashlib.sha256(key).hexdigest() != expected_digest):
            raise ValueError("qualification key bytes or selected name changed")
        return True

    def _key_bytes_for_service(self, observation: RootQualificationAuthorityKeyObservation,
                               *, enrollment: object, runtime_registry: object) -> bytes:
        self.verify_current(observation)
        verify = getattr(runtime_registry, "verify_key_enrollment_join", None)
        if (not callable(verify)
                or verify(observation, enrollment) is not True):
            raise ValueError("qualification runtime did not attest the exact key/enrollment join")
        return bytes(self._observations[observation.key_observation_handle][3])

    def close(self) -> None:
        if self._closed:
            return
        for _observation, _lease, fd, key, _digest in self._observations.values():
            os.close(fd)
            _zero(key)
        self._observations.clear()
        self._closed = True


def _zero(value: bytearray) -> None:
    for index in range(len(value)):
        value[index] = 0


def _canonical_json(value: object) -> bytes:
    import json
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")
