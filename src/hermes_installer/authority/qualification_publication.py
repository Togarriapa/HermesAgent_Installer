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
from dataclasses import InitVar, dataclass, field
from typing import Any, Literal, Mapping


_PUBLICATION_SEAL = object()
_KEY_OBSERVATION_SEAL = object()
_COMPILED_POLICY_SEAL = object()
_PUBLICATION_RECEIPT_SEAL = object()
_SESSION_SEAL = object()
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
_SESSION_FIELD_NAMES = frozenset({
    "schema", "session_handle", "fixture_selection_handle", "publication_receipt_handle",
    "fixture_run_id", "authority_root_id", "fixture_generation_id",
    "source_recipe_sha256", "controller_lease_handle", "issued_monotonic",
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
    generation_sha256: str
    key_id: str
    entries: tuple[RootQualificationOwnedEntry, ...]
    _seal: InitVar[object] = None

    def __post_init__(self, _seal: object) -> None:
        if _seal is not _PUBLICATION_SEAL:
            raise TypeError("qualification publication manifests are publisher-issued")
        if (not _HEX_ID.fullmatch(self.selection_handle)
                or not isinstance(self.fixture_root_identity, tuple)
                or len(self.fixture_root_identity) != 2
                or any(type(part) is not int or part < 0 for part in self.fixture_root_identity)
                or not _SHA256.fullmatch(self.generation_sha256)
                or not _HEX_ID.fullmatch(self.key_id)
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


@dataclass(frozen=True, slots=True, repr=False)
class RootQualificationCompiledPolicy:
    """Compiler output with documents retained only inside the root runtime."""

    schema: int
    fixture_selection_handle: str
    fixture_run_id: str
    suite_id: str
    authority_root_id: str
    fixture_generation_id: str
    fixture_profile_id: str
    fixture_namespace_id: str
    source_recipe_sha256: str
    source_closure_sha256: str
    policy_sha256: str
    catalog_sha256: str
    controller_lease_handle: str
    issued_monotonic: float
    expires_monotonic: float
    _authority: Mapping[str, Any] = field(repr=False, compare=False)
    _catalog: Mapping[str, Any] = field(repr=False, compare=False)
    _projection: Any = field(repr=False, compare=False)
    _seal: InitVar[object] = None

    def __post_init__(self, _seal: object) -> None:
        if _seal is not _COMPILED_POLICY_SEAL:
            raise TypeError("qualification policies are minted by the fixed source compiler")
        if (self.schema != 1 or self.suite_id != "resource-cron-task-v1"
                or not _HEX_ID.fullmatch(self.fixture_selection_handle)
                or not _HEX_ID.fullmatch(self.fixture_run_id)
                or not _HEX_ID.fullmatch(self.authority_root_id)
                or not _HEX_ID.fullmatch(self.fixture_generation_id)
                or not _HEX_ID.fullmatch(self.fixture_profile_id)
                or not _HEX_ID.fullmatch(self.fixture_namespace_id)
                or not _HEX_ID.fullmatch(self.controller_lease_handle)
                or any(not _SHA256.fullmatch(value) for value in (
                    self.source_recipe_sha256, self.source_closure_sha256,
                    self.policy_sha256, self.catalog_sha256,
                ))
                or type(self._authority) is not dict or type(self._catalog) is not dict
                or not callable(getattr(self._projection, "verify_current", None))
                or type(self.issued_monotonic) not in (int, float)
                or type(self.expires_monotonic) not in (int, float)
                or not math.isfinite(self.issued_monotonic)
                or not math.isfinite(self.expires_monotonic)
                or self.expires_monotonic <= self.issued_monotonic):
            raise ValueError("compiled fixture policy identity is malformed")

    def verify_current(self, lease: object) -> bool:
        from .installed_qualification import RootOwnedQualificationFixtureLease
        if type(lease) is not RootOwnedQualificationFixtureLease:
            raise ValueError("compiled qualification policy requires its exact held fixture lease")
        lease.verify_current()
        if (lease.selection.selection_handle != self.fixture_selection_handle
                or lease.run_name != self.fixture_run_id
                or lease.selection.suite_id != self.suite_id
                or lease.selection.fixture_generation_id != self.fixture_generation_id
                or lease.selection.fixture_profile_id != self.fixture_profile_id
                or lease.selection.fixture_namespace_id != self.fixture_namespace_id
                or lease.selection.controller_unit_observation_handle != self.controller_lease_handle
                or self._projection.verify_current(lease) is not True):
            raise ValueError("compiled fixture policy is stale or belongs to another selection")
        authority = _canonical_json(dict(self._authority))
        catalog = _canonical_json(dict(self._catalog))
        if (hashlib.sha256(authority).hexdigest() != self.policy_sha256
                or hashlib.sha256(catalog).hexdigest() != self.catalog_sha256):
            raise ValueError("compiled fixture policy or catalog bytes changed")
        return True

    def __repr__(self) -> str:
        return "RootQualificationCompiledPolicy(<root-private>)"


@dataclass(frozen=True, slots=True, repr=False)
class RootQualificationPublicationReceipt:
    """Sealed proof of one current fixture-local policy publication."""

    schema: int
    publication_receipt_handle: str
    fixture_selection_handle: str
    fixture_run_id: str
    authority_root_id: str
    fixture_generation_id: str
    policy_sha256: str
    catalog_sha256: str
    source_recipe_sha256: str
    key_id: str
    controller_lease_handle: str
    issued_monotonic: float
    expires_monotonic: float
    _runtime: Any = field(repr=False, compare=False)
    _seal: InitVar[object] = None

    def __post_init__(self, _seal: object) -> None:
        if _seal is not _PUBLICATION_RECEIPT_SEAL:
            raise TypeError("qualification publication receipts are publisher-issued")
        if (self.schema != 1
                or any(not _HEX_ID.fullmatch(value) for value in (
                    self.publication_receipt_handle, self.fixture_selection_handle,
                    self.fixture_run_id, self.authority_root_id, self.fixture_generation_id,
                    self.key_id, self.controller_lease_handle,
                ))
                or any(not _SHA256.fullmatch(value) for value in (
                    self.policy_sha256, self.catalog_sha256, self.source_recipe_sha256,
                ))
                or type(self.issued_monotonic) not in (int, float)
                or type(self.expires_monotonic) not in (int, float)
                or not math.isfinite(self.issued_monotonic)
                or not math.isfinite(self.expires_monotonic)
                or self.expires_monotonic <= self.issued_monotonic
                or not callable(getattr(self._runtime, "verify_receipt_current", None))):
            raise ValueError("qualification publication receipt is malformed")

    def verify_current(self) -> "RootQualificationPublicationReceipt":
        if self._runtime.verify_receipt_current(self) is not True:
            raise ValueError("qualification publication is stale")
        return self

    def open_member(self, member_name: str) -> int:
        return self._runtime.open_receipt_member(self, member_name)

    def __repr__(self) -> str:
        return "RootQualificationPublicationReceipt(<root-private>)"


@dataclass(frozen=True, slots=True, repr=False)
class RootQualificationSessionHandle:
    schema: int
    session_handle: str
    fixture_selection_handle: str
    publication_receipt_handle: str
    fixture_run_id: str
    authority_root_id: str
    fixture_generation_id: str
    source_recipe_sha256: str
    controller_lease_handle: str
    issued_monotonic: float
    expires_monotonic: float
    _store: Any = field(repr=False, compare=False)
    _seal: InitVar[object] = None

    def __post_init__(self, _seal: object) -> None:
        if _seal is not _SESSION_SEAL:
            raise TypeError("qualification sessions are minted by the current fixture session store")
        if (self.schema != 1 or any(not _HEX_ID.fullmatch(value) for value in (
                    self.session_handle, self.fixture_selection_handle,
                    self.publication_receipt_handle, self.fixture_run_id,
                    self.authority_root_id, self.fixture_generation_id,
                    self.controller_lease_handle,
                ))
                or not _SHA256.fullmatch(self.source_recipe_sha256)
                or type(self.issued_monotonic) not in (float, int)
                or type(self.expires_monotonic) not in (float, int)
                or not math.isfinite(self.issued_monotonic)
                or not math.isfinite(self.expires_monotonic)
                or self.expires_monotonic <= self.issued_monotonic
                or type(self._store) is not RootQualificationSessionStore):
            raise ValueError("qualification session identity is malformed")

    def verify_current(self) -> "RootQualificationSessionHandle":
        return self._store.resolve_current_fixture_session(self)

    def __repr__(self) -> str:
        return "RootQualificationSessionHandle(<root-private>)"


class RootQualificationSessionStore:
    """One-run in-memory session membership backed by current held proofs.

    The root-owned JSON file is historical diagnostic metadata only.  The
    store never reads it to restore a handle; every use must present the exact
    sealed object retained by this live store and revalidate the publisher's
    receipt, signer, source, actor and fixture lease.
    """

    def __init__(self, fixture_selection: object, publication_runtime: object,
                 fixture_registry: object):
        from .installed_qualification import (
            RootOwnedQualificationFixtureRegistry,
            RootOwnedQualificationFixtureSelection,
        )
        if (type(fixture_selection) is not RootOwnedQualificationFixtureSelection
                or type(fixture_registry) is not RootOwnedQualificationFixtureRegistry
                or type(publication_runtime) is not RootQualificationPolicyPublisher
                or publication_runtime.selection is not fixture_selection
                or publication_runtime.fixture_registry is not fixture_registry):
            raise ValueError("qualification session requires its exact fixture publisher and lease registry")
        self.selection = fixture_selection
        self.publication_runtime = publication_runtime
        self.fixture_registry = fixture_registry
        self._sessions: dict[str, RootQualificationSessionHandle] = {}
        self._closed = False
        if publication_runtime._session_store is not None:
            raise ValueError("qualification publication already has a live session store")
        publication_runtime._session_store = self

    @classmethod
    def from_owned_fixture(cls, fixture_selection: object, publication_runtime: object,
                           fixture_registry: object) -> "RootQualificationSessionStore":
        return cls(fixture_selection, publication_runtime, fixture_registry)

    def begin_selected_fixture_session(self, publication_receipt_handle: str
                                       ) -> RootQualificationSessionHandle:
        if self._closed or not _HEX_ID.fullmatch(publication_receipt_handle):
            raise ValueError("qualification session store is closed or receipt handle malformed")
        receipt = self.publication_runtime._receipts.get(publication_receipt_handle)
        if type(receipt) is not RootQualificationPublicationReceipt:
            raise ValueError("qualification session requires a retained current publication")
        receipt.verify_current()
        lease = self.fixture_registry.resolve_current_selection(self.selection)
        self.publication_runtime.key_observation.verify_current()
        issued = time.monotonic()
        expires = min(receipt.expires_monotonic, lease.selection.expires_monotonic,
                      self.publication_runtime.key_observation.expires_monotonic)
        if expires <= issued:
            raise ValueError("qualification fixture session lease has expired")
        session = RootQualificationSessionHandle(
            schema=1, session_handle=secrets.token_urlsafe(32),
            fixture_selection_handle=receipt.fixture_selection_handle,
            publication_receipt_handle=receipt.publication_receipt_handle,
            fixture_run_id=receipt.fixture_run_id,
            authority_root_id=receipt.authority_root_id,
            fixture_generation_id=receipt.fixture_generation_id,
            source_recipe_sha256=receipt.source_recipe_sha256,
            controller_lease_handle=receipt.controller_lease_handle,
            issued_monotonic=issued, expires_monotonic=expires,
            _store=self, _seal=_SESSION_SEAL,
        )
        session_bytes = _canonical_json({
            "schema": 1,
            "session_handle": session.session_handle,
            "fixture_selection_handle": session.fixture_selection_handle,
            "publication_receipt_handle": session.publication_receipt_handle,
            "fixture_run_id": session.fixture_run_id,
            "authority_root_id": session.authority_root_id,
            "fixture_generation_id": session.fixture_generation_id,
            "source_recipe_sha256": session.source_recipe_sha256,
            "controller_lease_handle": session.controller_lease_handle,
            "issued_monotonic": session.issued_monotonic,
            "expires_monotonic": session.expires_monotonic,
        })
        # No restore path exists.  This file records the issued handle only;
        # authority remains membership in this in-memory store.
        _write_new_member(lease.fixture_root_fd, "fixture-session.json", session_bytes)
        os.fsync(lease.fixture_root_fd)
        self._sessions[session.session_handle] = session
        self.publication_runtime._sessions[session.session_handle] = session
        session.verify_current()
        return session

    def resolve_current_fixture_session(self, session: RootQualificationSessionHandle
                                        ) -> RootQualificationSessionHandle:
        if (self._closed or type(session) is not RootQualificationSessionHandle
                or self._sessions.get(session.session_handle) is not session):
            raise ValueError("qualification session is not current retained registry membership")
        receipt = self.publication_runtime._receipts.get(session.publication_receipt_handle)
        if type(receipt) is not RootQualificationPublicationReceipt:
            raise ValueError("qualification session publication is no longer retained")
        receipt.verify_current()
        lease = self.fixture_registry.resolve_current_selection(self.selection)
        self.publication_runtime.key_observation.verify_current()
        if (time.monotonic() >= session.expires_monotonic
                or session.expires_monotonic > receipt.expires_monotonic
                or session.fixture_selection_handle != lease.selection.selection_handle
                or session.fixture_run_id != lease.run_name
                or session.authority_root_id != self.publication_runtime.root_journal.root_id
                or session.fixture_generation_id != receipt.fixture_generation_id
                or session.source_recipe_sha256 != receipt.source_recipe_sha256
                or session.controller_lease_handle != lease.selection.controller_unit_observation_handle
                or _read_fixed_member(lease.fixture_root_fd, "fixture-session.json")
                != _canonical_json(_session_fields(session))):
            raise ValueError("qualification session no longer matches its held current proofs")
        return session

    def verify_historical_session(self, lease: object,
                                  receipt: RootQualificationPublicationReceipt,
                                  session_doc: object) -> bool:
        """Validate metadata against live membership; never reconstruct it."""
        from .installed_qualification import RootOwnedQualificationFixtureLease
        if (self._closed or type(lease) is not RootOwnedQualificationFixtureLease
                or type(receipt) is not RootQualificationPublicationReceipt
                or not isinstance(session_doc, dict)
                or set(session_doc) != set(_SESSION_FIELD_NAMES)):
            return False
        handle = session_doc.get("session_handle")
        session = self._sessions.get(handle) if isinstance(handle, str) else None
        if session is None or session.publication_receipt_handle != receipt.publication_receipt_handle:
            return False
        try:
            self.resolve_current_fixture_session(session)
            return (session_doc == _session_fields(session)
                    and lease.selection.selection_handle == session.fixture_selection_handle
                    and lease.run_name == session.fixture_run_id)
        except (OSError, ValueError, TypeError):
            return False

    def close(self) -> None:
        self._sessions.clear()
        self._closed = True


class RootQualificationPolicyPublisher:
    """Publish one compiler-issued fixture policy below its held run root."""

    def __init__(self, selection: object, key_observation: RootQualificationAuthorityKeyObservation,
                 root_journal: object, fixture_registry: object):
        from .installed_qualification import (
            RootOwnedQualificationFixtureRegistry,
            RootOwnedQualificationFixtureSelection,
        )
        from hermes_installer.protected_enrollment import RootJournalSelection

        if (type(selection) is not RootOwnedQualificationFixtureSelection
                or type(fixture_registry) is not RootOwnedQualificationFixtureRegistry
                or type(root_journal) is not RootJournalSelection
                or fixture_registry.root_journal is not root_journal
                or type(key_observation) is not RootQualificationAuthorityKeyObservation
                or key_observation.fixture_selection_handle != selection.selection_handle):
            raise ValueError("qualification publisher requires exact retained fixture capabilities")
        if key_observation._registry.root_journal is not root_journal:
            raise ValueError("qualification signer belongs to another held root journal")
        self.selection = selection
        self.key_observation = key_observation
        self.root_journal = root_journal
        self.fixture_registry = fixture_registry
        self.key_registry = key_observation._registry
        self.signer = self.key_registry.resolve_enrollment_signer(key_observation)
        self._receipts: dict[str, RootQualificationPublicationReceipt] = {}
        self._sessions: dict[str, RootQualificationSessionHandle] = {}
        self._session_store: RootQualificationSessionStore | None = None
        self._documents: dict[str, tuple[bytes, bytes, bytes]] = {}
        self._policy_fd = -1
        self._policy_identity: tuple[int, int] | None = None
        self._closed = False

    @classmethod
    def from_owned_fixture(cls, fixture_selection: object,
                           key_observation: RootQualificationAuthorityKeyObservation,
                           root_journal: object, fixture_registry: object
                           ) -> "RootQualificationPolicyPublisher":
        return cls(fixture_selection, key_observation, root_journal, fixture_registry)

    def publish_compiled_fixture(self, compiled_policy: RootQualificationCompiledPolicy
                                 ) -> RootQualificationPublicationReceipt:
        if self._closed or type(compiled_policy) is not RootQualificationCompiledPolicy:
            raise ValueError("qualification publisher requires the fixed compiler output")
        lease = self.fixture_registry.resolve_current_selection(self.selection)
        compiled_policy.verify_current(lease)
        self.key_observation.verify_current()
        selection = lease.selection
        if (compiled_policy.fixture_selection_handle != selection.selection_handle
                or compiled_policy.fixture_run_id != lease.run_name
                or compiled_policy.authority_root_id != self.root_journal.root_id
                or compiled_policy.source_recipe_sha256 != self.key_observation.source_recipe_sha256
                or compiled_policy.controller_lease_handle != selection.controller_unit_observation_handle
                or compiled_policy.expires_monotonic > self.key_observation.expires_monotonic):
            raise ValueError("compiled fixture output differs from current key, source, or controller")

        authority_bytes = _canonical_json(dict(compiled_policy._authority))
        catalog_bytes = _canonical_json(dict(compiled_policy._catalog))
        generation_bytes = _canonical_json({
            "schema": 1, "authority": dict(compiled_policy._authority),
            "catalog": dict(compiled_policy._catalog),
        })
        authority_sha = hashlib.sha256(authority_bytes).hexdigest()
        catalog_sha = hashlib.sha256(catalog_bytes).hexdigest()
        generation_sha = hashlib.sha256(generation_bytes).hexdigest()
        if (authority_sha != compiled_policy.policy_sha256
                or catalog_sha != compiled_policy.catalog_sha256):
            raise ValueError("compiled policy changed before publication")

        issued = time.monotonic()
        expires = min(compiled_policy.expires_monotonic,
                      self.key_observation.expires_monotonic,
                      selection.expires_monotonic)
        if expires <= issued:
            raise ValueError("qualification publication lease has expired")
        publication = {
            "schema": 1,
            "publication_receipt_handle": secrets.token_urlsafe(32),
            "fixture_selection_handle": selection.selection_handle,
            "fixture_run_id": lease.run_name,
            "authority_root_id": self.root_journal.root_id,
            "fixture_generation_id": compiled_policy.fixture_generation_id,
            "policy_sha256": authority_sha,
            "catalog_sha256": catalog_sha,
            "source_recipe_sha256": compiled_policy.source_recipe_sha256,
            "key_id": self.key_observation.key_id,
            "controller_lease_handle": compiled_policy.controller_lease_handle,
            "issued_monotonic": issued,
            "expires_monotonic": expires,
        }
        signature = self.signer.sign_qualification_enrollment(
            publication, authority_sha, catalog_sha, generation_sha,
        )
        envelope = {
            "schema": 1, "publication": publication,
            "authority_sha256": authority_sha,
            "catalog_sha256": catalog_sha,
            "generation_sha256": generation_sha,
            "signature": signature,
        }
        envelope_bytes = _canonical_json(envelope)
        selection_bytes = _canonical_json({
            "schema": 1,
            "publication_receipt_handle": publication["publication_receipt_handle"],
            "fixture_generation_id": compiled_policy.fixture_generation_id,
            "policy_sha256": authority_sha,
            "catalog_sha256": catalog_sha,
        })
        # The run-root is unique and initially empty. Generation and signed
        # envelope are durable before selection.json becomes visible; every
        # reader verifies the closed pointer and all three member digests.
        os.mkdir("fixture-policy", 0o700, dir_fd=lease.fixture_root_fd)
        policy_fd = os.open("fixture-policy", os.O_RDONLY | os.O_DIRECTORY
                            | os.O_NOFOLLOW | os.O_CLOEXEC,
                            dir_fd=lease.fixture_root_fd)
        policy_identity = os.fstat(policy_fd)
        if (policy_identity.st_uid != 0 or stat.S_IMODE(policy_identity.st_mode) != 0o700):
            os.close(policy_fd)
            raise ValueError("qualification policy directory is not root-private")
        self._policy_fd = policy_fd
        self._policy_identity = (policy_identity.st_dev, policy_identity.st_ino)
        created: dict[str, tuple[int, int]] = {}
        try:
            generation_identity = _write_new_member(policy_fd, "generation.json", generation_bytes)
            created["fixture-policy/generation.json"] = generation_identity[:2]
            authority_identity = _write_new_member(
                lease.fixture_root_fd, "fixture-authority.json", envelope_bytes)
            created["fixture-authority.json"] = authority_identity[:2]
            self.key_observation.verify_current()
            selection_identity = _write_new_member(policy_fd, "selection.json", selection_bytes)
            created["fixture-policy/selection.json"] = selection_identity[:2]
            os.fsync(policy_fd)
            os.fsync(lease.fixture_root_fd)
        except BaseException:
            self._rollback_partial_publication(lease, created)
            raise
        lease.verify_current()
        receipt = RootQualificationPublicationReceipt(
            schema=1,
            publication_receipt_handle=publication["publication_receipt_handle"],
            fixture_selection_handle=selection.selection_handle,
            fixture_run_id=lease.run_name,
            authority_root_id=self.root_journal.root_id,
            fixture_generation_id=compiled_policy.fixture_generation_id,
            policy_sha256=authority_sha, catalog_sha256=catalog_sha,
            source_recipe_sha256=compiled_policy.source_recipe_sha256,
            key_id=self.key_observation.key_id,
            controller_lease_handle=compiled_policy.controller_lease_handle,
            issued_monotonic=issued, expires_monotonic=expires,
            _runtime=self, _seal=_PUBLICATION_RECEIPT_SEAL,
        )
        self._receipts[receipt.publication_receipt_handle] = receipt
        self._documents[receipt.publication_receipt_handle] = (
            envelope_bytes, generation_bytes, selection_bytes,
        )
        return receipt

    def verify_receipt_current(self, receipt: RootQualificationPublicationReceipt) -> bool:
        if (self._closed or type(receipt) is not RootQualificationPublicationReceipt
                or self._receipts.get(receipt.publication_receipt_handle) is not receipt):
            raise ValueError("qualification publication receipt is not retained")
        lease = self.fixture_registry.resolve_current_selection(self.selection)
        lease.verify_current()
        self.key_observation.verify_current()
        if (time.monotonic() >= receipt.expires_monotonic
                or receipt.expires_monotonic > lease.selection.expires_monotonic
                or receipt.fixture_selection_handle != lease.selection.selection_handle
                or receipt.fixture_run_id != lease.run_name
                or receipt.authority_root_id != self.root_journal.root_id
                or receipt.key_id != self.key_observation.key_id
                or receipt.source_recipe_sha256 != self.key_observation.source_recipe_sha256
                or receipt.controller_lease_handle != lease.selection.controller_unit_observation_handle):
            raise ValueError("qualification publication no longer matches its source lease")
        if self._policy_fd < 0 or self._policy_identity is None:
            raise ValueError("qualification policy directory lease is unavailable")
        held_policy = os.fstat(self._policy_fd)
        named_policy = os.stat("fixture-policy", dir_fd=lease.fixture_root_fd,
                               follow_symlinks=False)
        if ((held_policy.st_dev, held_policy.st_ino) != self._policy_identity
                or (named_policy.st_dev, named_policy.st_ino) != self._policy_identity
                or held_policy.st_uid != 0 or stat.S_IMODE(held_policy.st_mode) != 0o700
                or named_policy.st_uid != 0 or stat.S_IMODE(named_policy.st_mode) != 0o700):
            raise ValueError("qualification policy directory custody changed")
        envelope_bytes, generation_bytes, selection_bytes = self._documents[
            receipt.publication_receipt_handle]
        if (_read_fixed_member(lease.fixture_root_fd, "fixture-authority.json") != envelope_bytes
                or _read_fixed_member(lease.fixture_root_fd, "fixture-policy/generation.json")
                != generation_bytes
                or _read_fixed_member(lease.fixture_root_fd, "fixture-policy/selection.json")
                != selection_bytes):
            raise ValueError("qualification publication bytes or current pointer changed")
        import json
        envelope = json.loads(envelope_bytes.decode("utf-8"))
        if (self.signer.verify_qualification_enrollment(envelope) is not True
                or hashlib.sha256(generation_bytes).hexdigest() != envelope["generation_sha256"]
                or receipt.policy_sha256 != envelope["authority_sha256"]
                or receipt.catalog_sha256 != envelope["catalog_sha256"]):
            raise ValueError("qualification publication signature or generation digest is invalid")
        return True

    def open_receipt_member(self, receipt: RootQualificationPublicationReceipt,
                            member_name: str) -> int:
        self.verify_receipt_current(receipt)
        lease = self.fixture_registry.resolve_current_selection(self.selection)
        parent_fd, leaf = _fixed_member_parent(lease.fixture_root_fd, member_name)
        try:
            return os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                           dir_fd=parent_fd)
        finally:
            if parent_fd != lease.fixture_root_fd:
                os.close(parent_fd)

    def verify_key_enrollment_join(self, observation: RootQualificationAuthorityKeyObservation,
                                   enrollment: object) -> bool:
        if observation is not self.key_observation:
            raise ValueError("qualification enrollment uses another key observation")
        self.key_observation.verify_current()
        verify = getattr(enrollment, "verify_current", None)
        if not callable(verify) or verify() is not enrollment:
            raise ValueError("qualification enrollment is not current")
        return True

    def verify_historical_session(self, lease: object,
                                  receipt: RootQualificationPublicationReceipt,
                                  session_doc: object) -> bool:
        if (self._closed or type(receipt) is not RootQualificationPublicationReceipt
                or receipt._runtime is not self or not isinstance(session_doc, dict)):
            return False
        store = self._session_store
        return (store is not None
                and store.verify_historical_session(lease, receipt, session_doc) is True)

    def owned_publication(self, receipt: RootQualificationPublicationReceipt
                          ) -> RootQualificationOwnedPublication:
        self.verify_receipt_current(receipt)
        store = self._session_store
        sessions = [s for s in self._sessions.values()
                    if s.publication_receipt_handle == receipt.publication_receipt_handle]
        if store is None or len(sessions) != 1:
            raise ValueError("cleanup publication requires one retained live fixture session")
        sessions[0].verify_current()
        lease = self.fixture_registry.resolve_current_selection(self.selection)
        root = os.fstat(lease.fixture_root_fd)
        entries: list[RootQualificationOwnedEntry] = []
        for name, kind, mode in (
            ("fixture-authority.json", "file", 0o600),
            ("fixture-key.bin", "file", 0o600),
            ("fixture-session.json", "file", 0o600),
            ("fixture-policy", "directory", 0o700),
            ("fixture-policy/generation.json", "file", 0o600),
            ("fixture-policy/selection.json", "file", 0o600),
        ):
            parent_fd, leaf = _fixed_member_parent(lease.fixture_root_fd, name)
            try:
                info = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
                is_expected = stat.S_ISDIR(info.st_mode) if kind == "directory" else stat.S_ISREG(info.st_mode)
                if (not is_expected or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != mode):
                    raise ValueError("qualification cleanup member has unsafe identity")
                digest = None
                if kind == "file":
                    fd = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                 dir_fd=parent_fd)
                    try:
                        if info.st_nlink != 1:
                            raise ValueError("qualification cleanup member is linked elsewhere")
                        digest = _hash_fd(fd)
                    finally:
                        os.close(fd)
                entries.append(RootQualificationOwnedEntry(
                    name, kind, info.st_dev, info.st_ino, digest, mode,
                ))
            finally:
                if parent_fd != lease.fixture_root_fd:
                    os.close(parent_fd)
        if set(os.listdir(lease.fixture_root_fd)) != {
                "fixture-authority.json", "fixture-key.bin", "fixture-session.json", "fixture-policy"}:
            raise ValueError("qualification run root contains an unowned path")
        policy_fd = os.open("fixture-policy", os.O_RDONLY | os.O_DIRECTORY
                            | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=lease.fixture_root_fd)
        try:
            if set(os.listdir(policy_fd)) != {"generation.json", "selection.json"}:
                raise ValueError("qualification policy root contains an unowned path")
        finally:
            os.close(policy_fd)
        return RootQualificationOwnedPublication(
            selection_handle=receipt.fixture_selection_handle,
            fixture_root_identity=(root.st_dev, root.st_ino),
            generation_sha256=hashlib.sha256(
                self._documents[receipt.publication_receipt_handle][1]).hexdigest(),
            key_id=receipt.key_id, entries=tuple(entries), _seal=_PUBLICATION_SEAL,
        )

    def close(self) -> None:
        if self._closed:
            return
        self.signer.close()
        self._sessions.clear()
        self._receipts.clear()
        self._documents.clear()
        if self._policy_fd >= 0:
            os.close(self._policy_fd)
            self._policy_fd = -1
        self._closed = True

    def _rollback_partial_publication(self, lease: object,
                                      created: Mapping[str, tuple[int, int]]) -> None:
        # Roll back only names created in the fresh, unique run root. The
        # fixture registry still owns final run-root cleanup and verifies it.
        if self._policy_fd >= 0:
            for name in ("generation.json", "selection.json"):
                identity = created.get("fixture-policy/" + name)
                if identity is not None:
                    try:
                        current = os.stat(name, dir_fd=self._policy_fd, follow_symlinks=False)
                        if (current.st_dev, current.st_ino) == identity and stat.S_ISREG(current.st_mode):
                            os.unlink(name, dir_fd=self._policy_fd)
                    except OSError:
                        pass
            policy_identity = self._policy_identity
            try:
                current_policy = os.stat("fixture-policy", dir_fd=lease.fixture_root_fd,
                                        follow_symlinks=False)
                if (policy_identity is not None
                        and (current_policy.st_dev, current_policy.st_ino) == policy_identity
                        and stat.S_ISDIR(current_policy.st_mode)
                        and not os.listdir(self._policy_fd)):
                    os.rmdir("fixture-policy", dir_fd=lease.fixture_root_fd)
            except OSError:
                pass
            os.close(self._policy_fd)
            self._policy_fd = -1
            self._policy_identity = None
        authority_identity = created.get("fixture-authority.json")
        if authority_identity is not None:
            try:
                current = os.stat("fixture-authority.json", dir_fd=lease.fixture_root_fd,
                                  follow_symlinks=False)
                if ((current.st_dev, current.st_ino) == authority_identity
                        and stat.S_ISREG(current.st_mode)):
                    os.unlink("fixture-authority.json", dir_fd=lease.fixture_root_fd)
            except OSError:
                pass


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

    def resolve_enrollment_signer(
        self, key_observation: RootQualificationAuthorityKeyObservation,
    ) -> "RootQualificationEnrollmentSigner":
        if (self._closed or type(key_observation) is not RootQualificationAuthorityKeyObservation
                or self._observations.get(key_observation.key_observation_handle, (None,))[0]
                is not key_observation):
            raise ValueError("qualification key observation is not retained by this registry")
        self.verify_current(key_observation)
        return RootQualificationEnrollmentSigner(
            self, key_observation, _seal=_KEY_OBSERVATION_SEAL,
        )

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


class RootQualificationEnrollmentSigner:
    """Restricted signer for the one canonical v164 fixture envelope."""

    __slots__ = ("_registry", "_observation", "_closed")

    def __init__(self, registry: RootQualificationAuthorityKeyRegistry,
                 observation: RootQualificationAuthorityKeyObservation, *, _seal: object):
        if (_seal is not _KEY_OBSERVATION_SEAL
                or type(registry) is not RootQualificationAuthorityKeyRegistry
                or type(observation) is not RootQualificationAuthorityKeyObservation):
            raise TypeError("qualification enrollment signer is minted by its held key registry")
        self._registry, self._observation, self._closed = registry, observation, False

    def sign_qualification_enrollment(
        self, publication_fields: dict[str, object], authority_sha256: str,
        catalog_sha256: str, generation_sha256: str,
    ) -> str:
        if self._closed:
            raise ValueError("qualification enrollment signer is closed")
        return self._registry.sign_qualification_enrollment(
            self._observation, publication_fields=publication_fields,
            authority_sha256=authority_sha256, catalog_sha256=catalog_sha256,
            generation_sha256=generation_sha256,
        )

    def verify_qualification_enrollment(self, envelope: object) -> bool:
        if self._closed or not isinstance(envelope, dict) or set(envelope) != {
            "schema", "publication", "authority_sha256", "catalog_sha256",
            "generation_sha256", "signature",
        }:
            return False
        signature = envelope.get("signature")
        if not isinstance(signature, str) or not _SHA256.fullmatch(signature):
            return False
        try:
            expected = self.sign_qualification_enrollment(
                envelope["publication"], envelope["authority_sha256"],
                envelope["catalog_sha256"], envelope["generation_sha256"],
            )
        except (TypeError, ValueError, KeyError):
            return False
        return hmac.compare_digest(expected, signature)

    def close(self) -> None:
        self._closed = True

    def __repr__(self) -> str:
        return "RootQualificationEnrollmentSigner(<root-private>)"


def _zero(value: bytearray) -> None:
    for index in range(len(value)):
        value[index] = 0


def _canonical_json(value: object) -> bytes:
    import json
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _session_fields(session: RootQualificationSessionHandle) -> dict[str, object]:
    return {
        "schema": 1,
        "session_handle": session.session_handle,
        "fixture_selection_handle": session.fixture_selection_handle,
        "publication_receipt_handle": session.publication_receipt_handle,
        "fixture_run_id": session.fixture_run_id,
        "authority_root_id": session.authority_root_id,
        "fixture_generation_id": session.fixture_generation_id,
        "source_recipe_sha256": session.source_recipe_sha256,
        "controller_lease_handle": session.controller_lease_handle,
        "issued_monotonic": session.issued_monotonic,
        "expires_monotonic": session.expires_monotonic,
    }


def _fixed_member_parent(root_fd: int, member_name: str) -> tuple[int, str]:
    if member_name == "fixture-authority.json":
        return root_fd, member_name
    if member_name not in {
        "fixture-policy/generation.json", "fixture-policy/selection.json",
        "fixture-session.json",
    }:
        raise ValueError("qualification publication member is outside the fixed catalog")
    parent_fd = os.open("fixture-policy", os.O_RDONLY | os.O_DIRECTORY
                        | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=root_fd) \
        if member_name.startswith("fixture-policy/") else root_fd
    return parent_fd, member_name.partition("/")[2] if member_name.startswith("fixture-policy/") else member_name


def _read_fixed_member(root_fd: int, member_name: str, *, maximum: int = 16 * 1024 * 1024) -> bytes:
    parent_fd, leaf = _fixed_member_parent(root_fd, member_name)
    try:
        fd = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent_fd)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
                    or info.st_size > maximum):
                raise ValueError("qualification publication member has unsafe identity or size")
            chunks: list[bytes] = []
            total = 0
            while True:
                block = os.read(fd, min(1024 * 1024, maximum + 1 - total))
                if not block:
                    break
                total += len(block)
                if total > maximum:
                    raise ValueError("qualification publication member exceeds its fixed bound")
                chunks.append(block)
            return b"".join(chunks)
        finally:
            os.close(fd)
    finally:
        if parent_fd != root_fd:
            os.close(parent_fd)


def _write_new_member(parent_fd: int, name: str, value: bytes) -> tuple[int, int, str]:
    if (name not in {"fixture-authority.json", "fixture-key.bin", "fixture-session.json",
                     "generation.json", "selection.json"}
            or type(value) is not bytes):
        raise ValueError("qualification publisher member is outside the fixed output set")
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                 | os.O_CLOEXEC, 0o600, dir_fd=parent_fd)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
            raise ValueError("qualification publisher created an unsafe member")
        offset = 0
        while offset < len(value):
            written = os.write(fd, value[offset:])
            if written <= 0:
                raise OSError("short write while publishing qualification member")
            offset += written
        os.fsync(fd)
        return info.st_dev, info.st_ino, hashlib.sha256(value).hexdigest()
    except BaseException:
        try:
            current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            held = os.fstat(fd)
            if ((current.st_dev, current.st_ino) == (held.st_dev, held.st_ino)
                    and stat.S_ISREG(current.st_mode)):
                os.unlink(name, dir_fd=parent_fd)
        except OSError:
            pass
        raise
    finally:
        os.close(fd)
