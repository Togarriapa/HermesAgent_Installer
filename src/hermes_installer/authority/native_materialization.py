"""Root-only materialization of one protected Hermes resource profile.

The factory constructs this operation from its sealed installation binding and
the fixed service-root selections in the installed bootstrap policy.  Callers
provide identifiers only; none of the root paths are part of an RPC or receipt.
Materialization creates native profile/skill files, but does not activate tools,
credentials, accounts, or external effects.
"""
from __future__ import annotations

import base64
from contextlib import contextmanager
import hashlib
import json
import os
import re
import secrets
import sqlite3
import stat
import time
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Protocol

from hermes_installer.authority.pm_runtime import NativePMRuntimeResolver
from hermes_installer.authority.native_output_receipts import (
    RootMaterializationReceiptRegistry,
    RuntimeArtifactReceipt,
)
from hermes_installer.registry.native import NativeRegistry
from hermes_installer.registry.native import (
    PRIMARY_NATIVE_PROFILE_KEY,
    PRIMARY_USER_SOURCE_PROFILE_ID,
    effective_native_profile_spec,
)
from hermes_installer.registry.native_install import (
    PINNED_HERMES_REVISION,
    NativeInstallError,
    NativeInstallReceipt,
    discover_profile_names,
    discover_and_load_selected,
)

PINNED_RESOURCES_REVISION = "113f42d33be9e0c8f0f47f5ca998e687323dec83"

class NativeMaterializationDenied(PermissionError):
    """A root-selected native materialization could not be proven safe."""


@dataclass(frozen=True, slots=True)
class NativeMaterializationSelection:
    """Scalar selection proof returned by the sealed setup binding."""

    enrollment_id: str
    service_generation: str
    service_profile_id: str
    protected_enrollment_digest: str
    service_uid: int
    service_gid: int
    home_root_id: str
    data_root_id: str
    source_artifact_id: str
    source_receipt_handle: str
    pm_runtime_handle: str
    resource_profile_id: str
    resource_manifest_path: str
    resource_manifest_sha256: str
    resources_revision: str


class RootSelectedInstallationBinding(Protocol):
    """Private factory capability. Implementations must re-resolve current state."""

    def authorize_native_materialization(
        self, *, enrollment_id: str, service_generation: str,
        resource_profile_id: str,
    ) -> NativeMaterializationSelection: ...


@dataclass(frozen=True, slots=True)
class NativeMaterializedItem:
    kind: str
    resource_id: str
    content_sha256: str
    state: str


@dataclass(frozen=True, slots=True)
class NativeMaterializedMember:
    """Path-free identity for bytes retained in one selected generation."""

    relative_path: str
    sha256: str
    size_bytes: int


@dataclass(frozen=True, slots=True)
class NativeMaterializedResourceDefinition:
    """Source and transformed declaration join held by a materialization receipt."""

    kind: str
    resource_id: str
    version: str
    source_path: str
    source_revision: str
    source_document_sha256: str
    effective_spec_sha256: str
    native_path: str | None
    members: tuple[NativeMaterializedMember, ...]


@dataclass(frozen=True, slots=True)
class NativeMaterializationReceipt:
    """Path-free receipt for native profile/skill materialization only."""

    schema: int
    receipt_handle: str
    enrollment_id: str
    service_generation: str
    protected_enrollment_digest: str
    service_profile_id: str
    resource_profile_id: str
    resources_revision: str
    resources_content_digest: str
    selected_closure_digest: str
    hermes_revision: str
    python_version: str
    items: tuple[NativeMaterializedItem, ...]
    resource_definitions: tuple[NativeMaterializedResourceDefinition, ...]
    state: str
    expires_monotonic: float


class RootNativeMaterialization:
    """Materialize profiles and their resolved skills using fixed roots.

    ``home_root``, ``data_root`` and ``journal_root`` are supplied only by the
    root bootstrap factory after it resolves the installed policy and root
    journal selection. They are never accepted by ``stage_selected``.
    """

    def __init__(self, binding: RootSelectedInstallationBinding, *,
                 registry: NativeRegistry, home_root: Path, data_root: Path,
                 journal_root: Path, hermes_source: Path,
                 pm_runtime_resolver: NativePMRuntimeResolver,
                 output_registry: RootMaterializationReceiptRegistry | None = None,
                 delegate_profile_id: str | None = None,
                 authority_uid: int = 0,
                 monotonic=time.monotonic):
        if (not isinstance(registry, NativeRegistry)
                or not callable(getattr(binding, "authorize_native_materialization", None))
                or not callable(getattr(pm_runtime_resolver, "resolve_python", None))
                or authority_uid != 0):
            raise NativeMaterializationDenied("root native materializer inputs are not factory-selected")
        if (registry.source.repository != "https://github.com/Togarriapa/HermesAgent_Resources"
                or registry.source.revision != PINNED_RESOURCES_REVISION):
            raise NativeMaterializationDenied("native resources are not from the verified bundled source")
        self._binding = binding
        self._registry = registry
        self._home_root = _absolute_root(home_root)
        self._data_root = _absolute_root(data_root)
        self._journal_root = _absolute_root(journal_root)
        self._hermes_source = _absolute_root(hermes_source)
        self._pm_runtime_resolver = pm_runtime_resolver
        self._output_registry = output_registry
        if (delegate_profile_id is not None
                and (not isinstance(delegate_profile_id, str)
                     or not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", delegate_profile_id)
                     or delegate_profile_id == PRIMARY_USER_SOURCE_PROFILE_ID)):
            raise NativeMaterializationDenied("delegate source profile identity is malformed")
        self._delegate_profile_id = delegate_profile_id
        if len({self._home_root, self._data_root, self._journal_root}) != 3:
            raise NativeMaterializationDenied("selected home, data, and journal roots must be distinct")
        self._authority_uid = authority_uid
        self._monotonic = monotonic
        self._database = self._journal_root / "native-materialization.sqlite3"
        self._initialize_journal()

    def compile_selected(self, selection: Any) -> tuple[RuntimeArtifactReceipt, ...]:
        """Compile current root-selected definitions into the five output roles.

        ``selection`` must be factory-issued. The assembler re-resolves it and
        every retained member through the sealed binding before publishing.
        """
        self._require_authority()
        if self._output_registry is None:
            raise NativeMaterializationDenied("root native output receipt registry is unavailable")
        from hermes_installer.authority.native_assembler import (
            NativeAssemblyDenied,
            RootNativePackageAssembler,
        )
        try:
            assembler = RootNativePackageAssembler(self._binding, self._output_registry)
            return assembler.compile_selected(selection)
        except NativeAssemblyDenied as exc:
            raise NativeMaterializationDenied(str(exc)) from None

    def stage_selected(self, enrollment_id: str, service_generation: str,
                       resource_profile_id: str) -> NativeMaterializationReceipt:
        """Compile and atomically write one current profile and its skill closure."""
        self._require_authority()
        # The installer backend is always the one user-facing profile. A
        # specialist materializer is separately constructed with its fixed
        # source ID and its own HERMES_HOME; it cannot redirect this primary
        # materializer by passing another profile ID.
        is_primary = resource_profile_id == PRIMARY_USER_SOURCE_PROFILE_ID
        if (is_primary and self._delegate_profile_id is not None
                or not is_primary and resource_profile_id != self._delegate_profile_id):
            raise NativeMaterializationDenied(
                "selected Resources profile does not match this fixed native home"
            )
        selection = self._selection(enrollment_id, service_generation, resource_profile_id)
        _verify_root(self._home_root, owner_uid=selection.service_uid, owner_gid=selection.service_gid)
        _verify_root(self._data_root, owner_uid=selection.service_uid, owner_gid=selection.service_gid)
        if is_primary:
            self._migrate_owned_legacy_primary(selection)
        discovery = self._registry.discover([f"profiles/{resource_profile_id}@*"])
        profile_items = [item for item in discovery.resources
                         if item.resource.kind.value == "profiles"]
        if (len(profile_items) != 1
                or profile_items[0].resource.id != resource_profile_id):
            raise NativeMaterializationDenied("selected resource profile is absent or ambiguous")
        compiled = self._registry.materialize(discovery)
        native_profile_key = PRIMARY_NATIVE_PROFILE_KEY
        mapping = _selected_files(compiled, resource_profile_id,
                                  native_profile_key=native_profile_key)
        hermes_python = self._resolve_hermes_python(selection)
        try:
            existing_profiles = discover_profile_names(
                hermes_source=self._hermes_source, python=hermes_python,
                hermes_root=self._home_root, timeout=20.0,
            )
        except NativeInstallError as exc:
            raise NativeMaterializationDenied(
                "pinned Hermes cannot verify the existing Desktop profile listing"
            ) from exc
        if existing_profiles != (native_profile_key,):
            raise NativeMaterializationDenied(
                "the selected Desktop home already exposes other Hermes profiles; "
                "preserve them and complete an ownership-journaled home migration before Jarvis setup"
            )
        resource_definitions = _retained_resource_definitions(
            self._registry, discovery, compiled,
        )
        closure_digest = _closure_digest(mapping)
        operation_id = secrets.token_hex(16)
        plan = {
            "schema": 1,
            "operation_id": operation_id,
            "enrollment_id": selection.enrollment_id,
            "service_generation": selection.service_generation,
            "protected_enrollment_digest": selection.protected_enrollment_digest,
            "service_profile_id": selection.service_profile_id,
            "resource_profile_id": resource_profile_id,
            "resources_revision": self._registry.source.revision,
            "resources_content_digest": self._registry.source.content_digest,
            "selected_closure_digest": closure_digest,
            "files": {path: base64.b64encode(data).decode("ascii")
                      for path, data in sorted(mapping.items())},
        }
        self._resume_pending(selection, resource_profile_id)
        self._persist_plan(plan)
        results = self._apply_plan(plan, selection)
        conflicting = [relative for relative, _kind, _id, _digest, state in results
                       if state == "preserved" and relative != "config.yaml"]
        if conflicting:
            raise NativeMaterializationDenied(
                "native profile/skill bytes conflict with preserved user overlays; "
                "no discovery or activation receipt was issued"
            )
        items = _receipt_items(results)
        # No receipt usable for activation is issued until all required profile
        # identity and selected skill files match the compiled generation.
        required = {("profile", native_profile_key)} | {
            ("skill", skill_id) for skill_id in _skill_ids(mapping)
        }
        if {(item.kind, item.resource_id) for item in items} != required:
            raise NativeMaterializationDenied("native profile or skill closure was not fully materialized")
        try:
            discovery = discover_and_load_selected(
                hermes_source=self._hermes_source,
                python=hermes_python,
                hermes_root=self._home_root,
                profile_id=native_profile_key,
                skill_ids=tuple(sorted(_skill_ids(mapping))),
                require_sole_profile=True,
                timeout=60.0,
            )
        except NativeInstallError as exc:
            raise NativeMaterializationDenied(
                "pinned Hermes did not discover and load the selected native profile/skills"
            ) from exc
        if (discovery.hermes_revision != PINNED_HERMES_REVISION
                or not discovery.python_version.startswith("3.14.")
                or discovery.profile_id != native_profile_key
                or not discovery.discovered_profile or not discovery.profile_identity_loaded
                or set(discovery.loaded_skills) != _skill_ids(mapping)):
            raise NativeMaterializationDenied("native Hermes discovery receipt does not match the selected closure")
        handle = secrets.token_urlsafe(32)
        expires = self._monotonic() + 600.0
        self._record_receipt(handle, selection, resource_profile_id, closure_digest,
                             items, expires, operation_id, discovery,
                             resource_definitions)
        return NativeMaterializationReceipt(
            1, handle, selection.enrollment_id, selection.service_generation,
            selection.protected_enrollment_digest, selection.service_profile_id,
            resource_profile_id, self._registry.source.revision,
            self._registry.source.content_digest, closure_digest, items,
            resource_definitions,
            "native-discovered-awaiting-health", expires,
        )

    def resolve_durable_home_identity(self, receipt_handle: str) -> Mapping[str, Any]:
        """Return the protected home observation joined to one discovered receipt.

        This is a materialization fact for the active compiler. It is not a
        task grant and the setup receipt's monotonic expiry is not extended.
        """
        self._require_authority()
        if not _opaque_handle(receipt_handle):
            raise NativeMaterializationDenied("native home receipt handle is malformed")
        with self._connect() as db:
            receipt = db.execute("SELECT * FROM receipts WHERE handle=?", (receipt_handle,)).fetchone()
            identity = db.execute(
                "SELECT * FROM native_home_identities WHERE receipt_handle=?", (receipt_handle,)
            ).fetchone()
        if (receipt is None or identity is None or receipt["state"] not in {"discovered", "consumed"}
                or receipt["resource_profile_id"] != identity["resource_profile_id"]
                or receipt["resources_revision"] != identity["resources_revision"]
                or receipt["resources_content_digest"] != identity["resources_content_digest"]
                or receipt["service_generation"] != identity["home_generation"]
                or receipt["expires"] <= self._monotonic()):
            raise NativeMaterializationDenied("native home identity is not joined to a discovered receipt")
        try:
            manifest = json.loads(identity["behavioral_manifest"])
            info = self._home_root.lstat()
            if (not isinstance(manifest, dict) or not manifest
                    or (info.st_dev, info.st_ino, info.st_uid, info.st_gid,
                        stat.S_IMODE(info.st_mode)) !=
                    (identity["device"], identity["inode"], identity["owner_uid"],
                     identity["owner_gid"], identity["mode"])):
                raise ValueError
            expected_sha = hashlib.sha256(
                _json(dict(sorted(manifest.items()))).encode("utf-8")).hexdigest()
            if expected_sha != identity["behavioral_manifest_sha256"]:
                raise ValueError
            for relative, digest in manifest.items():
                if (not isinstance(relative, str) or not isinstance(digest, str)
                        or not re.fullmatch(r"[0-9a-f]{64}", digest)
                        or self._read_home_member(relative) != digest):
                    raise ValueError
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            raise NativeMaterializationDenied("native home identity or behavioral members changed") from None
        return {
            "receipt_handle": receipt_handle,
            "resource_profile_id": identity["resource_profile_id"],
            "resources_revision": identity["resources_revision"],
            "resources_content_digest": identity["resources_content_digest"],
            "home_generation": identity["home_generation"],
            "device": identity["device"], "inode": identity["inode"],
            "owner_uid": identity["owner_uid"], "owner_gid": identity["owner_gid"],
            "mode": identity["mode"],
            "behavioral_manifest_sha256": identity["behavioral_manifest_sha256"],
            "behavioral_manifest": dict(sorted(manifest.items())),
        }


    def resolve_resource_definition(
        self, receipt_handle: str, *, enrollment_id: str,
        service_generation: str, resource_profile_id: str,
        kind: str, resource_id: str, version: str,
    ) -> NativeMaterializedResourceDefinition:
        """Resolve one retained declaration from a current discovered receipt.

        This accessor is root-private and returns only identity/digests/member
        names. It proves which transformed source declaration was included in
        the Hermes-discovered selected profile generation; it does not grant
        runtime execution or expose filesystem paths.
        """
        self._require_authority()
        self._selection(enrollment_id, service_generation, resource_profile_id)
        record = self._receipt(receipt_handle)
        if (record["enrollment_id"] != enrollment_id
                or record["service_generation"] != service_generation
                or record["resource_profile_id"] != resource_profile_id
                or record["resources_revision"] != self._registry.source.revision
                or record["resources_content_digest"] != self._registry.source.content_digest
                or record["state"] not in {"discovered", "consumed"}
                or record["expires"] <= self._monotonic()):
            raise NativeMaterializationDenied("resource definition receipt is stale or outside its selection")
        matches = [NativeMaterializedResourceDefinition(
            row["kind"], row["resource_id"], row["version"], row["source_path"],
            row["source_revision"], row["source_document_sha256"],
            row["effective_spec_sha256"], row["native_path"],
            tuple(NativeMaterializedMember(**member) for member in row["members"]),
        ) for row in record["discovery"].get("resource_definitions", [])
            if row.get("kind") == kind and row.get("resource_id") == resource_id
            and row.get("version") == version]
        if len(matches) != 1:
            raise NativeMaterializationDenied("resource is not uniquely selected by this materialization receipt")
        definition = matches[0]
        for member in definition.members:
            if not self._verify_materialized_member(member, record):
                raise NativeMaterializationDenied("retained resource member differs from its materialization receipt")
        return definition

    def resolve_resource_definition_document(
        self, receipt_handle: str, *, enrollment_id: str,
        service_generation: str, resource_profile_id: str,
        kind: str, resource_id: str, version: str,
    ) -> bytes:
        """Return the exact transformed source YAML joined to a current receipt.

        The resource identity is the selector; there is no caller path. The
        returned bytes are the compiler-produced declaration with the verified
        effective ``spec`` and provenance annotations, not an independently
        parsed caller document.
        """
        definition = self.resolve_resource_definition(
            receipt_handle, enrollment_id=enrollment_id,
            service_generation=service_generation,
            resource_profile_id=resource_profile_id,
            kind=kind, resource_id=resource_id, version=version,
        )
        record = self._receipt(receipt_handle)
        current = self._registry.materialize(
            self._registry.discover([f"profiles/{resource_profile_id}@*"])
        )
        content = current.get(definition.source_path)
        source_member = next((member for member in definition.members
                              if member.relative_path == definition.source_path), None)
        if (not isinstance(content, bytes) or source_member is None
                or len(content) != source_member.size_bytes
                or hashlib.sha256(content).hexdigest() != source_member.sha256
                or record["resources_content_digest"] != self._registry.source.content_digest):
            raise NativeMaterializationDenied("transformed resource document differs from its retained receipt")
        return content

    def _verify_materialized_member(
        self, member: NativeMaterializedMember, record: Mapping[str, Any],
    ) -> bool:
        if (not isinstance(member.relative_path, str)
                or not member.relative_path
                or member.relative_path.startswith("/")
                or ".." in Path(member.relative_path).parts
                or "\\" in member.relative_path):
            return False
        try:
            if (self._registry.source.content_digest != record["resources_content_digest"]
                    or self._registry.source.revision != record["resources_revision"]):
                return False
            current = self._registry.materialize(
                self._registry.discover([f"profiles/{record['resource_profile_id']}@*"])
            )
            content = current.get(member.relative_path)
            if (not isinstance(content, bytes) or len(content) != member.size_bytes
                    or hashlib.sha256(content).hexdigest() != member.sha256):
                return False
            target = _hermes_target_path(
                member.relative_path, record["resource_profile_id"],
                PRIMARY_NATIVE_PROFILE_KEY,
            )
            return target is None or self._read_home_member(target) == member.sha256
        except (OSError, sqlite3.Error):
            return False

    def _read_home_member(self, relative_path: str) -> str | None:
        try:
            with _open_parent(self._home_root, relative_path, uid=None, gid=None,
                              create_parents=False) as (parent_fd, leaf):
                info = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                    return None
                fd = os.open(leaf, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=parent_fd)
                try:
                    digest = hashlib.sha256()
                    size = 0
                    while block := os.read(fd, 65536):
                        size += len(block)
                        digest.update(block)
                        if size > 32 * 1024 * 1024:
                            return None
                    return digest.hexdigest()
                finally:
                    os.close(fd)
        except (OSError, NativeMaterializationDenied):
            return None

    def consume_for_activation(self, receipt_handle: str, *, enrollment_id: str,
                               service_generation: str,
                               resource_profile_id: str) -> NativeMaterializationReceipt:
        """Consume the discovered receipt once, for the exact current selection."""
        self._require_authority()
        selection = self._selection(enrollment_id, service_generation, resource_profile_id)
        record = self._receipt(receipt_handle)
        now = self._monotonic()
        if (record["enrollment_id"] != enrollment_id
                or record["service_generation"] != service_generation
                or record["resource_profile_id"] != resource_profile_id
                or record["protected_enrollment_digest"] != selection.protected_enrollment_digest
                or record["state"] != "discovered" or record["expires"] <= now):
            raise NativeMaterializationDenied("native receipt is stale, undiscovered, or outside its selection")
        with self._connect() as db:
            changed = db.execute(
                "UPDATE receipts SET state='consumed' WHERE handle=? AND state='discovered' AND expires>?",
                (receipt_handle, now),
            ).rowcount
        if changed != 1:
            raise NativeMaterializationDenied("native activation receipt has already been consumed")
        return self._public_receipt(record, "consumed-for-activation")

    def _selection(self, enrollment_id: str, generation: str,
                   resource_profile_id: str) -> NativeMaterializationSelection:
        selection = self._binding.authorize_native_materialization(
            enrollment_id=enrollment_id, service_generation=generation,
            resource_profile_id=resource_profile_id,
        )
        if (not isinstance(selection, NativeMaterializationSelection)
                or selection.enrollment_id != enrollment_id
                or selection.service_generation != generation
                or not selection.service_profile_id
                or len(selection.protected_enrollment_digest) != 64
                or any(ch not in "0123456789abcdef" for ch in selection.protected_enrollment_digest)
                or type(selection.service_uid) is not int or selection.service_uid <= 0
                or type(selection.service_gid) is not int or selection.service_gid <= 0
                or not selection.home_root_id or not selection.data_root_id
                or not selection.source_artifact_id or not _opaque_handle(selection.source_receipt_handle)
                or not _opaque_handle(selection.pm_runtime_handle)
                or selection.resource_profile_id != resource_profile_id
                or not isinstance(selection.resource_manifest_path, str)
                or not selection.resource_manifest_path.startswith("profiles/")
                or not selection.resource_manifest_path.endswith(".yaml")
                or not re.fullmatch(r"[0-9a-f]{64}", selection.resource_manifest_sha256)
                or not selection.resources_revision):
            raise NativeMaterializationDenied("root setup binding did not authorize this selected generation")
        return selection

    def _require_authority(self) -> None:
        if os.geteuid() != self._authority_uid or self._authority_uid != 0:
            raise NativeMaterializationDenied("native materialization requires the root setup authority")
        _verify_root(self._home_root, owner_uid=None)
        _verify_root(self._data_root, owner_uid=None)
        _verify_root(self._journal_root, owner_uid=self._authority_uid)

    def _initialize_journal(self) -> None:
        _verify_root(self._journal_root, owner_uid=self._authority_uid)
        if self._database.exists() or self._database.is_symlink():
            info = self._database.lstat()
            if (stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode)
                    or info.st_uid != self._authority_uid
                    or stat.S_IMODE(info.st_mode) != 0o600):
                raise NativeMaterializationDenied("native receipt journal has invalid custody")
        with self._connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS plans(
                    operation_id TEXT PRIMARY KEY, payload TEXT NOT NULL,
                    state TEXT NOT NULL, updated REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS managed_files(
                    relative_path TEXT PRIMARY KEY, source_digest TEXT NOT NULL,
                    installed_digest TEXT NOT NULL, resource_profile_id TEXT NOT NULL,
                    state TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS home_migration_members(
                    migration_id TEXT NOT NULL, source_path TEXT NOT NULL,
                    archive_path TEXT NOT NULL, sha256 TEXT NOT NULL,
                    device INTEGER NOT NULL, inode INTEGER NOT NULL,
                    owner_uid INTEGER NOT NULL, owner_gid INTEGER NOT NULL,
                    mode INTEGER NOT NULL, state TEXT NOT NULL,
                    PRIMARY KEY(migration_id,source_path));
                CREATE TABLE IF NOT EXISTS receipts(
                    handle TEXT PRIMARY KEY, enrollment_id TEXT NOT NULL,
                    service_generation TEXT NOT NULL, protected_enrollment_digest TEXT NOT NULL,
                    service_profile_id TEXT NOT NULL, resource_profile_id TEXT NOT NULL,
                    resources_revision TEXT NOT NULL, resources_content_digest TEXT NOT NULL,
                    selected_closure_digest TEXT NOT NULL, items TEXT NOT NULL,
                    skill_ids TEXT NOT NULL, state TEXT NOT NULL, expires REAL NOT NULL,
                    discovery TEXT);
                CREATE TABLE IF NOT EXISTS native_home_identities(
                    receipt_handle TEXT PRIMARY KEY, resource_profile_id TEXT NOT NULL,
                    resources_revision TEXT NOT NULL, resources_content_digest TEXT NOT NULL,
                    home_generation TEXT NOT NULL, device INTEGER NOT NULL, inode INTEGER NOT NULL,
                    owner_uid INTEGER NOT NULL, owner_gid INTEGER NOT NULL, mode INTEGER NOT NULL,
                    behavioral_manifest_sha256 TEXT NOT NULL, behavioral_manifest TEXT NOT NULL);
            """)
        if self._database.exists():
            self._database.chmod(0o600)

    @contextmanager
    def _connect(self):
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        fd = os.open(self._database, flags, 0o600)
        os.close(fd)
        db = sqlite3.connect(self._database, timeout=10)
        db.row_factory = sqlite3.Row
        try:
            db.execute("PRAGMA journal_mode=DELETE")
            db.execute("PRAGMA synchronous=FULL")
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def _persist_plan(self, plan: Mapping[str, Any]) -> None:
        with self._connect() as db:
            db.execute("INSERT INTO plans VALUES(?,?,?,?)",
                       (plan["operation_id"], _json(plan), "applying", self._monotonic()))

    def _apply_plan(self, plan: Mapping[str, Any],
                    selection: NativeMaterializationSelection) -> list[tuple[str, str, str, str, str]]:
        results: list[tuple[str, str, str, str, str]] = []
        files = plan["files"]
        decoded = {relative: base64.b64decode(content, validate=True)
                   for relative, content in files.items()}
        # Write identity last: until SOUL.md is present, Hermes cannot discover
        # a partially published new profile after a process or power failure.
        order = sorted(decoded, key=lambda path: (path.endswith("/SOUL.md"), path))
        for relative in order:
            content = decoded[relative]
            digest = hashlib.sha256(content).hexdigest()
            with self._connect() as db:
                prior = db.execute("SELECT * FROM managed_files WHERE relative_path=?",
                                   (relative,)).fetchone()
            state = "installed"
            with _open_parent(self._home_root, relative, uid=selection.service_uid,
                              gid=selection.service_gid, create_parents=True) as (parent_fd, leaf):
                try:
                    info = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
                except FileNotFoundError:
                    info = None
                if info is not None:
                    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or info.st_uid != selection.service_uid:
                        raise NativeMaterializationDenied("native destination is not a service-owned regular file")
                    current = _hash_file_at(parent_fd, leaf)
                    if current == digest:
                        state = "installed" if prior is None else "updated"
                    elif prior is None or prior["state"] == "overlay-preserved" or current != prior["installed_digest"]:
                        state = "preserved"
                    else:
                        state = "updated"
                if state != "preserved" and (info is None or _hash_file_at(parent_fd, leaf) != digest):
                    _atomic_service_write_at(parent_fd, leaf, content,
                                             uid=selection.service_uid, gid=selection.service_gid)
                installed_digest = digest if state != "preserved" else (
                    _hash_file_at(parent_fd, leaf) if info is not None else digest
                )
            with self._connect() as db:
                db.execute("""INSERT INTO managed_files VALUES(?,?,?,?,?)
                    ON CONFLICT(relative_path) DO UPDATE SET source_digest=excluded.source_digest,
                    installed_digest=excluded.installed_digest,
                    resource_profile_id=excluded.resource_profile_id, state=excluded.state""",
                    (relative, digest, installed_digest, plan["resource_profile_id"],
                     "overlay-preserved" if state == "preserved" else "installed"))
            kind, item_id = _native_identity(relative)
            results.append((relative, kind, item_id, digest, state))
        return results

    def _record_receipt(self, handle: str, selection: NativeMaterializationSelection,
                        profile_id: str, closure_digest: str,
                        items: tuple[NativeMaterializedItem, ...], expires: float,
                        operation_id: str, discovery: NativeInstallReceipt,
                        resource_definitions: tuple[NativeMaterializedResourceDefinition, ...] = ()) -> None:
        expected_skills = sorted(item.resource_id for item in items if item.kind == "skill")
        if (discovery.hermes_revision != PINNED_HERMES_REVISION
                or not discovery.python_version.startswith("3.14.")
                or discovery.profile_id != profile_id or not discovery.discovered_profile
                or not discovery.profile_identity_loaded
                or list(discovery.loaded_skills) != expected_skills
                or list(discovery.discovered_skills) != expected_skills):
            raise NativeMaterializationDenied("pinned Hermes discovery result does not match the selected closure")
        skill_ids = expected_skills
        with self._connect() as db:
            db.execute("""INSERT INTO receipts VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (handle, selection.enrollment_id, selection.service_generation,
                 selection.protected_enrollment_digest, selection.service_profile_id,
                 profile_id, self._registry.source.revision,
                 self._registry.source.content_digest, closure_digest,
                 _json([_item_dict(item) for item in items]), _json(skill_ids),
                 "discovered", expires,
                _json({"schema": 1, "hermes_revision": discovery.hermes_revision,
                        "python_version": discovery.python_version,
                        "content_digests": discovery.content_digests,
                        "resource_definitions": [_definition_dict(item) for item in resource_definitions]})))
            if hasattr(self, "_home_root"):
                home_info = self._home_root.lstat()
                if stat.S_ISLNK(home_info.st_mode) or not stat.S_ISDIR(home_info.st_mode):
                    raise NativeMaterializationDenied("native profile home identity changed before receipt")
                manifest = discovery.content_digests
                if (not isinstance(manifest, Mapping) or not manifest
                        or any(not isinstance(path, str) or not isinstance(digest, str)
                               or not re.fullmatch(r"[0-9a-f]{64}", digest)
                               for path, digest in manifest.items())):
                    raise NativeMaterializationDenied("native behavioral manifest is malformed")
                behavioral_sha = hashlib.sha256(
                    _json(dict(sorted(manifest.items()))).encode("utf-8")).hexdigest()
                db.execute("""INSERT INTO native_home_identities VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (handle, profile_id, self._registry.source.revision,
                     self._registry.source.content_digest, selection.service_generation,
                     home_info.st_dev, home_info.st_ino, home_info.st_uid, home_info.st_gid,
                     stat.S_IMODE(home_info.st_mode), behavioral_sha,
                     _json(dict(sorted(manifest.items())))))
            db.execute("UPDATE plans SET state='complete',updated=? WHERE operation_id=? AND state='applying'",
                       (self._monotonic(), operation_id))

    def _resume_pending(self, selection: NativeMaterializationSelection,
                        resource_profile_id: str) -> None:
        with self._connect() as db:
            pending = db.execute("SELECT payload FROM plans WHERE state='applying' ORDER BY updated").fetchall()
        for row in pending:
            plan = json.loads(row["payload"])
            if (plan.get("enrollment_id") != selection.enrollment_id
                    or plan.get("service_generation") != selection.service_generation
                    or plan.get("protected_enrollment_digest") != selection.protected_enrollment_digest
                    or plan.get("resource_profile_id") != resource_profile_id
                    or plan.get("resources_revision") != self._registry.source.revision
                    or plan.get("resources_content_digest") != self._registry.source.content_digest):
                raise NativeMaterializationDenied(
                    "an interrupted native materialization belongs to a different selected generation; "
                    "reconcile it under its original setup binding before retry"
                )
            self._apply_plan(plan, selection)
            with self._connect() as db:
                db.execute("UPDATE plans SET state='recovered',updated=? WHERE operation_id=? AND state='applying'",
                           (self._monotonic(), plan["operation_id"]))

    def _migrate_owned_legacy_primary(self, selection: NativeMaterializationSelection) -> None:
        """Move only journal-owned legacy Hermes identity files into a hidden archive.

        The rename preserves bytes and inode; no credentials are copied into the
        new Jarvis identity. Unowned, modified, linked, or conflicting files
        stop the migration before any move. The root journal makes interrupted
        moves idempotently resumable and records exact custody observations.
        """
        legacy = self._home_root / "profiles" / PRIMARY_USER_SOURCE_PROFILE_ID
        if not legacy.exists() and not legacy.is_symlink():
            return
        info = legacy.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise NativeMaterializationDenied("legacy Hermes profile identity is not a directory")

        def member_digest(relative: str) -> str:
            with _open_parent(self._home_root, relative, uid=selection.service_uid,
                              gid=selection.service_gid, create_parents=False) as (fd, leaf):
                return _hash_file_at(fd, leaf)
        candidates = [f"profiles/hermes/{name}" for name in
                      ("SOUL.md", "profile.yaml", "config.yaml")]
        skills_root = legacy / "skills"
        if skills_root.exists() or skills_root.is_symlink():
            if skills_root.is_symlink() or not skills_root.is_dir():
                raise NativeMaterializationDenied("legacy Hermes skill directory is unsafe")
            for directory, dirs, names in os.walk(skills_root, followlinks=False):
                base = Path(directory)
                if any((base / name).is_symlink() for name in dirs):
                    raise NativeMaterializationDenied("legacy Hermes skill tree contains linked directories")
                for name in names:
                    path = base / name
                    if path.is_symlink():
                        raise NativeMaterializationDenied("legacy Hermes skill tree contains linked files")
                    if name == "SKILL.md":
                        candidates.append(path.relative_to(self._home_root).as_posix())
        present = [relative for relative in candidates
                   if (self._home_root / relative).exists() or (self._home_root / relative).is_symlink()]
        migration_id = hashlib.sha256(
            ("jarvis-v205-legacy-home\0" + selection.service_generation + "\0"
             + selection.protected_enrollment_digest).encode("utf-8")
        ).hexdigest()
        with self._connect() as db:
            prior_migrations = [dict(row) for row in db.execute(
                "SELECT * FROM home_migration_members WHERE migration_id=?", (migration_id,)
            ).fetchall()]
        for saved in prior_migrations:
            source_exists = os.path.lexists(self._home_root / saved["source_path"])
            archive_exists = os.path.lexists(self._home_root / saved["archive_path"])
            if not source_exists and archive_exists:
                archived = (self._home_root / saved["archive_path"]).lstat()
                if ((archived.st_dev, archived.st_ino) != (saved["device"], saved["inode"])
                        or member_digest(saved["archive_path"]) != saved["sha256"]):
                    raise NativeMaterializationDenied("archived Hermes migration member changed after interruption")
            elif not source_exists and not archive_exists:
                raise NativeMaterializationDenied("journaled legacy Hermes bytes are missing from source and archive")
        if not present:
            return
        plans: list[tuple[str, str, str, os.stat_result]] = []
        with self._connect() as db:
            managed = {row["relative_path"]: dict(row) for row in db.execute(
                "SELECT relative_path,installed_digest,resource_profile_id,state FROM managed_files"
            ).fetchall()}
        for source_path in sorted(set(present)):
            row = managed.get(source_path)
            path = self._home_root / source_path
            current = path.lstat()
            if (row is None or row["resource_profile_id"] != PRIMARY_USER_SOURCE_PROFILE_ID
                    or stat.S_ISLNK(current.st_mode) or not stat.S_ISREG(current.st_mode)
                    or current.st_uid != selection.service_uid or current.st_gid != selection.service_gid
                    or stat.S_IMODE(current.st_mode) & 0o077
                    or member_digest(source_path) != row["installed_digest"]):
                raise NativeMaterializationDenied(
                    "legacy Hermes identity is unowned or modified; preserve it and resolve ownership before migration"
                )
            archive = (f"native-migration/{migration_id}/"
                       + source_path.removeprefix("profiles/hermes/"))
            plans.append((source_path, archive, row["installed_digest"], current))

        with self._connect() as db:
            prior = {row["source_path"]: dict(row) for row in db.execute(
                "SELECT * FROM home_migration_members WHERE migration_id=?", (migration_id,)
            ).fetchall()}
            for source_path, archive, digest, current in plans:
                saved = prior.get(source_path)
                expected = (archive, digest, current.st_dev, current.st_ino,
                            current.st_uid, current.st_gid, stat.S_IMODE(current.st_mode))
                if saved is None:
                    db.execute("INSERT INTO home_migration_members VALUES(?,?,?,?,?,?,?,?,?,?)",
                               (migration_id, source_path, archive, digest, current.st_dev,
                                current.st_ino, current.st_uid, current.st_gid,
                                stat.S_IMODE(current.st_mode), "planned"))
                elif (saved["archive_path"], saved["sha256"], saved["device"], saved["inode"],
                      saved["owner_uid"], saved["owner_gid"], saved["mode"]) != expected:
                    # A moved member is no longer in its source location; its
                    # durable inode/hash entry is checked in the apply pass.
                    if os.path.lexists(self._home_root / source_path):
                        raise NativeMaterializationDenied("legacy migration journal conflicts with current file identity")

        moved: list[tuple[str, str, dict[str, Any]]] = []
        try:
            for source_path, archive, digest, _current in plans:
                with self._connect() as db:
                    saved_row = db.execute(
                        "SELECT * FROM home_migration_members WHERE migration_id=? AND source_path=?",
                        (migration_id, source_path)).fetchone()
                if saved_row is None:
                    raise NativeMaterializationDenied("legacy migration journal row disappeared")
                saved = dict(saved_row)
                source_exists = os.path.lexists(self._home_root / source_path)
                archive_exists = os.path.lexists(self._home_root / archive)
                if not source_exists and archive_exists:
                    archived = (self._home_root / archive).lstat()
                    if ((archived.st_dev, archived.st_ino) != (saved["device"], saved["inode"])
                            or member_digest(archive) != digest):
                        raise NativeMaterializationDenied("archived Hermes identity changed after interruption")
                    moved.append((source_path, archive, saved))
                    continue
                if not source_exists or archive_exists:
                    raise NativeMaterializationDenied("legacy Hermes source/archive path conflicts")
                current = (self._home_root / source_path).lstat()
                if ((current.st_dev, current.st_ino) != (saved["device"], saved["inode"])
                        or current.st_uid != saved["owner_uid"] or current.st_gid != saved["owner_gid"]
                        or stat.S_IMODE(current.st_mode) != saved["mode"]
                        or member_digest(source_path) != digest):
                    raise NativeMaterializationDenied("legacy Hermes identity changed before migration")
                with _open_parent(self._home_root, source_path, uid=selection.service_uid,
                                  gid=selection.service_gid, create_parents=False) as (source_fd, source_name):
                    with _open_parent(self._home_root, archive, uid=selection.service_uid,
                                      gid=selection.service_gid, create_parents=True) as (archive_fd, archive_name):
                        os.rename(source_name, archive_name, src_dir_fd=source_fd, dst_dir_fd=archive_fd)
                        os.fsync(source_fd)
                        os.fsync(archive_fd)
                with self._connect() as db:
                    db.execute("UPDATE home_migration_members SET state='moved' WHERE migration_id=? AND source_path=?",
                               (migration_id, source_path))
                moved.append((source_path, archive, saved))
        except BaseException:
            for source_path, archive, saved in reversed(moved):
                try:
                    with _open_parent(self._home_root, archive, uid=selection.service_uid,
                                      gid=selection.service_gid, create_parents=False) as (archive_fd, archive_name):
                        current = os.stat(archive_name, dir_fd=archive_fd, follow_symlinks=False)
                    if ((current.st_dev, current.st_ino) != (saved["device"], saved["inode"])
                            or member_digest(archive) != saved["sha256"]):
                        continue
                    with _open_parent(self._home_root, source_path, uid=selection.service_uid,
                                      gid=selection.service_gid, create_parents=True) as (source_fd, source_name):
                        with _open_parent(self._home_root, archive, uid=selection.service_uid,
                                          gid=selection.service_gid, create_parents=False) as (archive_fd, archive_name):
                            os.rename(archive_name, source_name, src_dir_fd=archive_fd, dst_dir_fd=source_fd)
                            os.fsync(archive_fd)
                            os.fsync(source_fd)
                    with self._connect() as db:
                        db.execute("UPDATE home_migration_members SET state='rolled-back' WHERE migration_id=? AND source_path=?",
                                   (migration_id, source_path))
                except (OSError, NativeMaterializationDenied):
                    pass
            # Remove only the now-empty directories this interrupted attempt
            # created.  The migration journal remains as the recovery record.
            for directory in (
                self._home_root / "native-migration" / migration_id,
                self._home_root / "native-migration",
            ):
                try:
                    directory.rmdir()
                except OSError:
                    pass
            raise

    def _receipt(self, handle: str) -> dict[str, Any]:
        if not isinstance(handle, str) or len(handle) < 32:
            raise NativeMaterializationDenied("native receipt handle is malformed")
        with self._connect() as db:
            row = db.execute("SELECT * FROM receipts WHERE handle=?", (handle,)).fetchone()
        if row is None:
            raise NativeMaterializationDenied("native materialization receipt is unknown")
        result = dict(row)
        result["items"] = json.loads(result["items"])
        result["skill_ids"] = json.loads(result["skill_ids"])
        result["discovery"] = json.loads(result["discovery"])
        return result

    def _public_receipt(self, record: Mapping[str, Any], state: str) -> NativeMaterializationReceipt:
        return NativeMaterializationReceipt(
            1, record["handle"], record["enrollment_id"], record["service_generation"],
            record["protected_enrollment_digest"], record["service_profile_id"],
            record["resource_profile_id"], record["resources_revision"],
            record["resources_content_digest"], record["selected_closure_digest"],
            record["discovery"]["hermes_revision"], record["discovery"]["python_version"],
            tuple(NativeMaterializedItem(**item) for item in record["items"]),
            tuple(_definition_from_dict(item) for item in record["discovery"].get("resource_definitions", [])),
            state, record["expires"],
        )

    def _resolve_hermes_python(self, selection: NativeMaterializationSelection) -> Path:
        try:
            candidate = self._pm_runtime_resolver.resolve_python(
                pm_runtime_handle=selection.pm_runtime_handle,
                enrollment_id=selection.enrollment_id,
                service_generation=selection.service_generation,
                source_artifact_id=selection.source_artifact_id,
            )
        except NativeInstallError:
            raise
        except Exception:
            raise NativeMaterializationDenied(
                "official Hermes PM runtime receipt could not be resolved"
            ) from None
        if (not isinstance(candidate, Path) or not candidate.is_absolute()
                or not candidate.is_file() or not os.access(candidate, os.X_OK)):
            raise NativeMaterializationDenied(
                "verified Hermes PM runtime did not resolve an executable"
            )
        return candidate


_NATIVE_HOME_REGISTRY_SEAL = object()


@dataclass(slots=True, repr=False)
class RootOwnedNativeProfileHome:
    """Path-free retained FD for one row of the active published home map."""

    source_profile_id: str
    source_revision: str
    source_manifest_sha256: str
    role: str
    native_profile_key: str
    display_name: str
    materialization_receipt_handle: str
    home_generation: str
    behavioral_manifest_sha256: str
    device: int
    inode: int
    owner_uid: int
    owner_gid: int
    mode: int
    _directory_fd: int = field(repr=False)
    _row: Any = field(repr=False)
    _registry: Any = field(repr=False)
    _seal: object = field(repr=False)
    _closed: bool = field(default=False, repr=False)

    @property
    def identity(self) -> Mapping[str, Any]:
        return {
            "source_profile_id": self.source_profile_id,
            "source_revision": self.source_revision,
            "source_manifest_sha256": self.source_manifest_sha256,
            "role": self.role, "native_profile_key": self.native_profile_key,
            "display_name": self.display_name,
            "materialization_receipt_handle": self.materialization_receipt_handle,
            "home_generation": self.home_generation,
            "behavioral_manifest_sha256": self.behavioral_manifest_sha256,
            "device": self.device, "inode": self.inode,
            "owner_uid": self.owner_uid, "owner_gid": self.owner_gid,
            "mode": self.mode,
        }

    def verify_current(self, row: Any | None = None) -> bool:
        return self._registry.verify_current(self, self._row if row is None else row)

    def duplicate_home_fd(self) -> int:
        if not self.verify_current():
            raise NativeMaterializationDenied("published native profile home is no longer current")
        return os.dup(self._directory_fd)

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            try:
                os.close(self._directory_fd)
            except OSError:
                pass

    def __repr__(self) -> str:
        return "RootOwnedNativeProfileHome(<held directory capability>)"


class RootOwnedNativeProfileHomeRegistry:
    """Reopen and retain only fixed-root homes present in the current core map."""

    def __init__(self, *, service_parent_root: Path, root_journal: Path,
                 authority_core: Any, _seal: object):
        if (_seal is not _NATIVE_HOME_REGISTRY_SEAL or os.geteuid() != 0
                or not service_parent_root.is_absolute() or not root_journal.is_absolute()
                or type(authority_core).__name__ != "RootPublishedAuthorityCore"
                or not callable(getattr(authority_core, "resolve_current_native_profile_home_crosswalk", None))):
            raise NativeMaterializationDenied("native home registry lacks current root authority")
        self._service_parent_root = service_parent_root
        self._root_journal = root_journal
        self._authority_core = authority_core
        self._seal = _seal
        self._held: dict[str, RootOwnedNativeProfileHome] = {}

    @classmethod
    def from_root_runtime(cls, root_runtime: Any, authority_core: Any
                          ) -> "RootOwnedNativeProfileHomeRegistry":
        from .bootstrap_runtime_factory import RootBootstrapRuntimeFactory
        if type(root_runtime) is not RootBootstrapRuntimeFactory:
            raise NativeMaterializationDenied("native home registry requires the current root bootstrap runtime")
        journal = root_runtime.resolver.journal_root
        parent = Path("/var/lib/hermes-installer/services/hermes-agent-native-v1")
        result = cls(service_parent_root=parent, root_journal=journal,
                     authority_core=authority_core, _seal=_NATIVE_HOME_REGISTRY_SEAL)
        result._current_rows()
        return result

    def open_current_profile_home(self, row: Any) -> RootOwnedNativeProfileHome:
        """Open only an exact currently published source identity; accept no path."""
        self._require_root()
        current = self._row_for_source(getattr(row, "source_profile_id", None))
        if _published_home_row(current) != _published_home_row(row):
            raise NativeMaterializationDenied("native home row is not in the current publication member")
        binding_id = getattr(row, "home_binding_id", None)
        if not isinstance(binding_id, str) or not re.fullmatch(r"[0-9a-f]{64}", binding_id):
            raise NativeMaterializationDenied("published native home binding identity is malformed")
        prior = self._held.get(binding_id)
        if prior is not None:
            if prior.verify_current(row):
                return prior
            prior.close()
            self._held.pop(binding_id, None)
        source_id = row.source_profile_id
        if (not isinstance(source_id, str)
                or not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", source_id)
                or row.role != ("jarvis-primary-home" if source_id == "hermes" else "resource-delegate-home")
                or row.native_profile_key != "default"):
            raise NativeMaterializationDenied("published native home source identity is unsupported")
        home_path = (self._service_parent_root / "home" if source_id == "hermes"
                     else self._service_parent_root / "native-profiles" / source_id)
        _verify_private_root_chain(home_path)
        flags = (os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
                 | getattr(os, "O_CLOEXEC", 0))
        try:
            fd = os.open(home_path, flags)
        except OSError:
            raise NativeMaterializationDenied("published native profile home cannot be opened safely") from None
        try:
            identity = self._verify_home_journal(row, fd)
            info = os.fstat(fd)
            home = RootOwnedNativeProfileHome(
                row.source_profile_id, row.source_revision, row.source_manifest_sha256,
                row.role, row.native_profile_key, row.display_name,
                row.materialization_receipt_handle, row.home_generation,
                row.behavioral_manifest_sha256, info.st_dev, info.st_ino,
                info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode),
                fd, row, self, self._seal,
            )
            if (identity["device"], identity["inode"], identity["owner_uid"],
                    identity["owner_gid"], identity["mode"]) != (
                    home.device, home.inode, home.owner_uid, home.owner_gid, home.mode):
                raise NativeMaterializationDenied("published home directory identity differs from its journal")
            if not home.verify_current(row):
                raise NativeMaterializationDenied("published home changed while its held descriptor was opened")
            self._held[binding_id] = home
            return home
        except BaseException:
            os.close(fd)
            raise

    def verify_current(self, home: RootOwnedNativeProfileHome, row: Any) -> bool:
        self._require_root()
        if (type(home) is not RootOwnedNativeProfileHome or home._registry is not self
                or home._seal is not self._seal or home._closed
                or _published_home_row(home._row) != _published_home_row(row)):
            return False
        try:
            current = self._row_for_source(row.source_profile_id)
            if _published_home_row(current) != _published_home_row(row):
                return False
            info = os.fstat(home._directory_fd)
            if (not stat.S_ISDIR(info.st_mode) or info.st_nlink < 1
                    or (info.st_dev, info.st_ino, info.st_uid, info.st_gid,
                        stat.S_IMODE(info.st_mode)) !=
                    (home.device, home.inode, home.owner_uid, home.owner_gid, home.mode)):
                return False
            identity = self._verify_home_journal(row, home._directory_fd)
            return (identity["device"], identity["inode"], identity["owner_uid"],
                    identity["owner_gid"], identity["mode"],
                    identity["behavioral_manifest_sha256"]) == (
                    home.device, home.inode, home.owner_uid, home.owner_gid, home.mode,
                    row.behavioral_manifest_sha256)
        except (OSError, sqlite3.Error, NativeMaterializationDenied, AttributeError, ValueError):
            return False

    def close(self) -> None:
        for home in tuple(self._held.values()):
            home.close()
        self._held.clear()

    def _current_rows(self) -> tuple[Any, ...]:
        crosswalk = self._authority_core.resolve_current_native_profile_home_crosswalk()
        rows = tuple(getattr(crosswalk, "rows", ()))
        if (len(rows) != 208
                or len({getattr(row, "source_profile_id", None) for row in rows}) != 208
                or sum(getattr(row, "source_profile_id", None) == "hermes" for row in rows) != 1
                or sum(getattr(row, "role", None) == "resource-delegate-home" for row in rows) != 207):
            raise NativeMaterializationDenied("current native home publication map is not the exact 208-profile set")
        for row in rows:
            _published_home_row(row)
            source_id = row.source_profile_id
            expected_role = "jarvis-primary-home" if source_id == "hermes" else "resource-delegate-home"
            expected_display = ("Jarvis" if source_id == "hermes"
                                else source_id.replace("-", " ").replace("_", " ").title())
            if (not isinstance(source_id, str)
                    or not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", source_id)
                    or row.role != expected_role or row.native_profile_key != "default"
                    or row.display_name != expected_display):
                raise NativeMaterializationDenied("current native home row changes its protected source identity")
        return rows

    def _row_for_source(self, source_profile_id: Any) -> Any:
        matches = [row for row in self._current_rows()
                   if getattr(row, "source_profile_id", None) == source_profile_id]
        if len(matches) != 1:
            raise NativeMaterializationDenied("source profile is absent from the current published home map")
        return matches[0]

    def _verify_home_journal(self, row: Any, home_fd: int) -> Mapping[str, Any]:
        source_id = row.source_profile_id
        if (not isinstance(source_id, str)
                or not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", source_id)):
            raise NativeMaterializationDenied("native home source identity is malformed")
        journal_dir = (self._root_journal / "native-materialization"
                       if source_id == "hermes" else
                       self._root_journal / "native-materialization" / source_id)
        database = journal_dir / "native-materialization.sqlite3"
        _verify_private_root_chain(database.parent)
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        try:
            db_fd = os.open(database, flags)
        except OSError:
            raise NativeMaterializationDenied("native home materialization journal is unavailable") from None
        try:
            db_info = os.fstat(db_fd)
            path_info = database.lstat()
            if (not stat.S_ISREG(db_info.st_mode) or db_info.st_uid != 0 or db_info.st_gid != 0
                    or stat.S_IMODE(db_info.st_mode) != 0o600
                    or (db_info.st_dev, db_info.st_ino) != (path_info.st_dev, path_info.st_ino)):
                raise NativeMaterializationDenied("native home materialization journal custody changed")
            uri = f"file:/proc/self/fd/{db_fd}?mode=ro&immutable=1"
            db = sqlite3.connect(uri, uri=True)
            db.row_factory = sqlite3.Row
            try:
                record = db.execute("SELECT * FROM receipts WHERE handle=?",
                                    (row.materialization_receipt_handle,)).fetchone()
                identity = db.execute("SELECT * FROM native_home_identities WHERE receipt_handle=?",
                                      (row.materialization_receipt_handle,)).fetchone()
                if record is None or identity is None:
                    raise NativeMaterializationDenied("native home has no durable materialization identity")
                discovery = json.loads(record["discovery"] or "{}")
            finally:
                db.close()
            definitions = discovery.get("resource_definitions", []) if isinstance(discovery, dict) else None
            source_definitions = [item for item in definitions if isinstance(item, dict)
                                  and item.get("kind") == "profiles"
                                  and item.get("resource_id") == row.source_profile_id]
            if (record["resource_profile_id"] != row.source_profile_id
                    or record["resources_revision"] != row.source_revision
                    or record["service_generation"] != row.home_generation
                    or record["state"] not in {"discovered", "consumed"}
                    or len(source_definitions) != 1
                    or source_definitions[0].get("source_revision") != row.source_revision
                    or source_definitions[0].get("source_document_sha256") != row.source_manifest_sha256
                    or identity["resource_profile_id"] != row.source_profile_id
                    or identity["resources_revision"] != row.source_revision
                    or identity["resources_content_digest"] != record["resources_content_digest"]
                    or identity["home_generation"] != record["service_generation"]
                    or identity["behavioral_manifest_sha256"] != row.behavioral_manifest_sha256):
                raise NativeMaterializationDenied("native home receipt differs from the published source row")
            manifest = json.loads(identity["behavioral_manifest"])
            if (not isinstance(manifest, dict) or not manifest
                    or hashlib.sha256(_json(dict(sorted(manifest.items()))).encode()).hexdigest()
                       != row.behavioral_manifest_sha256):
                raise NativeMaterializationDenied("native home behavioral manifest digest is invalid")
            home_info = os.fstat(home_fd)
            if (home_info.st_dev, home_info.st_ino, home_info.st_uid, home_info.st_gid,
                    stat.S_IMODE(home_info.st_mode)) != (
                    identity["device"], identity["inode"], identity["owner_uid"],
                    identity["owner_gid"], identity["mode"]
                    ) or home_info.st_uid <= 0 or stat.S_IMODE(home_info.st_mode) != 0o700:
                raise NativeMaterializationDenied("native home held directory differs from its journal")
            for relative, digest in manifest.items():
                if (not isinstance(relative, str) or not isinstance(digest, str)
                        or not re.fullmatch(r"[0-9a-f]{64}", digest)
                        or _hash_relative_member(home_fd, relative) != digest):
                    raise NativeMaterializationDenied("native home behavioral member changed")
            return dict(identity)
        finally:
            os.close(db_fd)

    @staticmethod
    def _require_root() -> None:
        if os.geteuid() != 0 or os.getuid() != 0:
            raise NativeMaterializationDenied("current native profile homes require the installed root authority")


def _selected_files(compiled: Mapping[str, bytes], profile_id: str, *,
                    native_profile_key: str | None = None) -> dict[str, bytes]:
    try:
        crosswalk = json.loads(compiled["installer-registry/crosswalk.json"])
        items = crosswalk["items"]
        rows = crosswalk["native_materialization"]["files"]
    except (KeyError, TypeError, ValueError):
        raise NativeMaterializationDenied("compiled native crosswalk is missing or malformed") from None
    profiles = [row for row in items if isinstance(row, dict) and row.get("kind") == "profiles"]
    selected_profiles = [row for row in profiles if row.get("id") == profile_id]
    if len(selected_profiles) != 1:
        raise NativeMaterializationDenied("compiled closure does not contain exactly one selected profile")
    target_profile_id = native_profile_key or profile_id
    mapping: dict[str, bytes] = {}
    for row in rows:
        if (not isinstance(row, dict) or row.get("conflict_policy") != "preserve-existing"
                or not isinstance(row.get("staged"), str) or not isinstance(row.get("target"), str)):
            raise NativeMaterializationDenied("compiled native crosswalk has an unsafe materialization row")
        staged, target = row["staged"], row["target"]
        if staged.startswith(f"homes/profiles/{profile_id}/"):
            expected_source_target = "profiles/" + staged.removeprefix("homes/profiles/")
            relative = staged.removeprefix(f"homes/profiles/{profile_id}/")
            destination = (relative if target_profile_id == "default"
                           else f"profiles/{target_profile_id}/{relative}")
        elif staged.startswith("homes/skills/"):
            parts = staged.split("/")
            if len(parts) != 4 or parts[-1] != "SKILL.md":
                raise NativeMaterializationDenied("selected skill path is malformed")
            expected_source_target = f"skills/{parts[2]}/SKILL.md"
            destination = (f"skills/{parts[2]}/SKILL.md" if target_profile_id == "default"
                           else f"profiles/{target_profile_id}/skills/{parts[2]}/SKILL.md")
        else:
            continue
        if target != expected_source_target or staged not in compiled:
            raise NativeMaterializationDenied("compiled native path differs from its selected Hermes destination")
        if destination in mapping:
            raise NativeMaterializationDenied("compiled native closure maps multiple files to one Hermes destination")
        mapping[destination] = compiled[staged]
    required = ({"SOUL.md", "profile.yaml", "config.yaml"} if target_profile_id == "default"
                else {f"profiles/{target_profile_id}/SOUL.md",
                      f"profiles/{target_profile_id}/profile.yaml",
                      f"profiles/{target_profile_id}/config.yaml"})
    if not required.issubset(mapping):
        raise NativeMaterializationDenied("selected profile is missing required native identity files")
    if not mapping:
        raise NativeMaterializationDenied("selected resource closure has no native profile files")
    return mapping


def _deny_legacy_user_profile_identity(home_root: Path) -> None:
    """Avoid serving both the legacy ``hermes`` and canonical ``default`` rows.

    Removal or adoption of an existing identity requires the ownership journal
    migration specified by v205. Until that migration is available, fail before
    writing the Jarvis profile rather than leaving two user-facing identities.
    """
    legacy = home_root / "profiles" / PRIMARY_USER_SOURCE_PROFILE_ID
    if legacy.exists() or legacy.is_symlink():
        raise NativeMaterializationDenied(
            "legacy Hermes profile is present in the Desktop home; preserve it and "
            "resume only after an ownership-journaled Jarvis migration is available"
        )


def _retained_resource_definitions(
    registry: NativeRegistry, discovery: Any, compiled: Mapping[str, bytes],
) -> tuple[NativeMaterializedResourceDefinition, ...]:
    bindings = {(row.kind, row.resource_id, row.version): row for row in registry.crosswalk(discovery)}
    definitions: list[NativeMaterializedResourceDefinition] = []
    for resolved in discovery.resources:
        resource = resolved.resource
        kind = resource.kind.value
        key = f"{kind}/{resource.id}@{resource.version}"
        raw = registry.resolver.raw.get(key)
        source_path = registry.paths.get(key)
        binding = bindings.get((kind, resource.id, resource.version))
        if raw is None or source_path is None or binding is None:
            raise NativeMaterializationDenied("selected resource lacks its verified source projection")
        effective = (effective_native_profile_spec(resource.id,
                     resolved.effective_spec or resource.body)
                     if kind == "profiles"
                     else dict(resolved.effective_spec or resource.body))
        effective_bytes = json.dumps(
            effective, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False,
        ).encode("utf-8")
        member_paths = {source_path,
                        f"installer-registry/declarations/{kind}/{resource.id}.yaml"}
        if kind == "profiles":
            member_paths.update(path for path in compiled if path.startswith(f"homes/profiles/{resource.id}/"))
        elif kind == "skills":
            member_paths.add(f"homes/skills/{resource.id}/SKILL.md")
        if binding.native_path and binding.native_path in compiled:
            member_paths.add(binding.native_path)
        members = tuple(
            NativeMaterializedMember(path, hashlib.sha256(compiled[path]).hexdigest(), len(compiled[path]))
            for path in sorted(member_paths) if path in compiled
        )
        if not members:
            raise NativeMaterializationDenied("selected resource has no retained transformed bytes")
        definitions.append(NativeMaterializedResourceDefinition(
            kind, resource.id, resource.version, source_path, registry.source.revision,
            raw.content_digest, hashlib.sha256(effective_bytes).hexdigest(),
            binding.native_path, members,
        ))
    return tuple(sorted(definitions, key=lambda row: (row.kind, row.resource_id, row.version)))


def _hermes_target_path(relative_path: str, profile_id: str,
                        native_profile_key: str | None = None) -> str | None:
    if relative_path.startswith(f"homes/profiles/{profile_id}/"):
        relative = relative_path.removeprefix(f"homes/profiles/{profile_id}/")
        return (relative if native_profile_key == "default"
                else f"profiles/{native_profile_key or profile_id}/{relative}")
    if relative_path.startswith("homes/skills/"):
        parts = PurePosixPath(relative_path).parts
        if len(parts) == 4 and parts[-1] == "SKILL.md":
            return (f"skills/{parts[2]}/SKILL.md" if native_profile_key == "default"
                    else f"profiles/{native_profile_key or profile_id}/skills/{parts[2]}/SKILL.md")
    return None


def _definition_dict(row: NativeMaterializedResourceDefinition) -> dict[str, Any]:
    return {
        "kind": row.kind, "resource_id": row.resource_id, "version": row.version,
        "source_path": row.source_path, "source_revision": row.source_revision,
        "source_document_sha256": row.source_document_sha256,
        "effective_spec_sha256": row.effective_spec_sha256, "native_path": row.native_path,
        "members": [{"relative_path": item.relative_path, "sha256": item.sha256,
                     "size_bytes": item.size_bytes} for item in row.members],
    }


def _definition_from_dict(row: Mapping[str, Any]) -> NativeMaterializedResourceDefinition:
    return NativeMaterializedResourceDefinition(
        row["kind"], row["resource_id"], row["version"], row["source_path"],
        row["source_revision"], row["source_document_sha256"], row["effective_spec_sha256"],
        row["native_path"], tuple(NativeMaterializedMember(**member) for member in row["members"]),
    )


def _skill_ids(mapping: Mapping[str, bytes]) -> set[str]:
    result = set()
    for path in mapping:
        parts = PurePosixPath(path).parts
        if (len(parts) == 5 and parts[0] == "profiles" and parts[2] == "skills"
                and parts[4] == "SKILL.md"):
            result.add(parts[3])
        elif len(parts) == 3 and parts[0] == "skills" and parts[2] == "SKILL.md":
            result.add(parts[1])
    return result


def _closure_digest(mapping: Mapping[str, bytes]) -> str:
    digest = hashlib.sha256()
    for path, content in sorted(mapping.items()):
        encoded = path.encode("utf-8")
        digest.update(len(encoded).to_bytes(4, "big"))
        digest.update(encoded)
        digest.update(hashlib.sha256(content).digest())
    return digest.hexdigest()


def _receipt_items(results: list[tuple[str, str, str, str, str]]) -> tuple[NativeMaterializedItem, ...]:
    states: dict[tuple[str, str], str] = {}
    digests: dict[tuple[str, str], list[tuple[str, str]]] = {}
    for path, kind, resource_id, digest, state in results:
        key = (kind, resource_id)
        digests.setdefault(key, []).append((path, digest))
        if state == "preserved":
            states[key] = "preserved-overlay"
        elif key not in states:
            states[key] = state
    folded = {key: _path_digest(values) for key, values in digests.items()}
    return tuple(NativeMaterializedItem(kind, resource_id, folded[(kind, resource_id)],
                                        states[(kind, resource_id)])
                 for kind, resource_id in sorted(folded))


def _native_identity(relative: str) -> tuple[str, str]:
    parts = PurePosixPath(relative).parts
    if relative in {"SOUL.md", "profile.yaml", "config.yaml"}:
        return "profile", "default"
    if len(parts) == 3 and parts[0] == "profiles":
        return "profile", parts[1]
    if len(parts) == 5 and parts[0] == "profiles" and parts[2] == "skills" and parts[4] == "SKILL.md":
        return "skill", parts[3]
    if len(parts) == 3 and parts[0] == "skills" and parts[2] == "SKILL.md":
        return "skill", parts[1]
    raise NativeMaterializationDenied("native output path has no supported Hermes identity")


def _absolute_root(root: Path, *, allow_file: bool = False) -> Path:
    if (not isinstance(root, Path) or not root.is_absolute() or root.is_symlink()
            or (root.exists() and (root.is_file() is not allow_file))):
        raise NativeMaterializationDenied("root-selected native materialization directory is invalid")
    return root


def _verify_root(root: Path, *, owner_uid: int | None, owner_gid: int | None = None) -> None:
    try:
        info = root.lstat()
    except OSError:
        raise NativeMaterializationDenied("root-selected native materialization directory is unavailable") from None
    if (stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode)
            or (owner_uid is not None and info.st_uid != owner_uid)
            or (owner_gid is not None and info.st_gid != owner_gid)
            or stat.S_IMODE(info.st_mode) & 0o077):
        raise NativeMaterializationDenied("root-selected native materialization directory custody is invalid")
    cursor = root.parent
    while cursor != Path(cursor.anchor):
        try:
            parent = cursor.lstat()
        except OSError:
            raise NativeMaterializationDenied("root-selected native parent is unavailable") from None
        if (stat.S_ISLNK(parent.st_mode) or parent.st_uid != 0
                or parent.st_mode & 0o022):
            raise NativeMaterializationDenied("root-selected native parent is writable or linked")
        cursor = cursor.parent


def _published_home_row(row: Any) -> dict[str, Any]:
    """Extract the closed public v214 row without accepting caller paths."""
    names = (
        "home_binding_id", "source_profile_id", "source_revision",
        "source_manifest_sha256", "role", "native_profile_key", "display_name",
        "home_selection_handle", "materialization_receipt_handle", "mapping_sha256",
        "home_generation", "principal_id", "namespace_id", "runtime_receipt_handle",
        "runtime_identity_sha256", "behavioral_manifest_sha256",
    )
    if type(row).__name__ != "RootPublishedNativeProfileHomeRow":
        raise NativeMaterializationDenied("native home row is not a typed published row")
    try:
        output = {name: getattr(row, name) for name in names}
    except AttributeError:
        raise NativeMaterializationDenied("published native home row is incomplete") from None
    if (any(not isinstance(value, str) or not value for value in output.values())
            or any(not re.fullmatch(r"[0-9a-f]{64}", output[name]) for name in (
                "home_binding_id", "source_manifest_sha256", "mapping_sha256",
                "runtime_identity_sha256", "behavioral_manifest_sha256"))):
        raise NativeMaterializationDenied("published native home row has malformed identities")
    return output


def _verify_private_root_chain(target: Path) -> None:
    """Verify a fixed absolute target without following symlinks.

    Ancestors must be root-owned and not group/other writable. The final home
    is separately joined to its root-journal owner/mode identity.
    """
    if not isinstance(target, Path) or not target.is_absolute():
        raise NativeMaterializationDenied("native home path is not root-derived")
    cursor = Path(target.anchor)
    try:
        root_info = cursor.lstat()
        if stat.S_ISLNK(root_info.st_mode) or not stat.S_ISDIR(root_info.st_mode):
            raise OSError
        for part in target.parts[1:]:
            cursor = cursor / part
            info = cursor.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                raise OSError
            if cursor != target and (info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o022):
                raise OSError
    except OSError:
        raise NativeMaterializationDenied("native home root chain is missing, linked, or writable") from None


def _hash_relative_member(home_fd: int, relative: str) -> str:
    """Hash one bounded regular member through a held home FD with no links."""
    path = PurePosixPath(relative)
    if (path.is_absolute() or not path.parts
            or any(part in {"", ".", ".."} for part in path.parts)
            or "\\" in relative):
        raise NativeMaterializationDenied("native behavioral member path is invalid")
    dir_flags = (os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                 | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    home_info = os.fstat(home_fd)
    current_fd = os.dup(home_fd)
    try:
        for part in path.parts[:-1]:
            child_fd = os.open(part, dir_flags, dir_fd=current_fd)
            child_info = os.fstat(child_fd)
            if (not stat.S_ISDIR(child_info.st_mode)
                    or (child_info.st_uid, child_info.st_gid) != (home_info.st_uid, home_info.st_gid)
                    or stat.S_IMODE(child_info.st_mode) & 0o022):
                os.close(child_fd)
                raise NativeMaterializationDenied("native behavioral member parent custody is invalid")
            os.close(current_fd)
            current_fd = child_fd
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        fd = os.open(path.parts[-1], flags, dir_fd=current_fd)
        try:
            before = os.fstat(fd)
            if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                    or before.st_size > 32 * 1024 * 1024
                    or (before.st_uid, before.st_gid) != (home_info.st_uid, home_info.st_gid)):
                raise NativeMaterializationDenied("native behavioral member custody is invalid")
            digest = hashlib.sha256()
            size = 0
            while block := os.read(fd, 65536):
                size += len(block)
                if size > 32 * 1024 * 1024:
                    raise NativeMaterializationDenied("native behavioral member exceeds its bound")
                digest.update(block)
            after = os.fstat(fd)
            if ((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
                    != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
                    or size != before.st_size):
                raise NativeMaterializationDenied("native behavioral member changed while read")
            return digest.hexdigest()
        finally:
            os.close(fd)
    except OSError:
        raise NativeMaterializationDenied("native behavioral member could not be opened without following links") from None
    finally:
        os.close(current_fd)


@contextmanager
def _open_parent(root: Path, relative: str, *, uid: int | None, gid: int | None,
                 create_parents: bool):
    path = PurePosixPath(relative)
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        raise NativeMaterializationDenied("native output path escapes its fixed HERMES_HOME")
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        parent_fd = os.open(root, flags)
    except OSError:
        raise NativeMaterializationDenied("selected HERMES_HOME could not be opened safely") from None
    try:
        info = os.fstat(parent_fd)
        if (not stat.S_ISDIR(info.st_mode) or (uid is not None and info.st_uid != uid)
                or (gid is not None and info.st_gid != gid)
                or stat.S_IMODE(info.st_mode) != 0o700):
            raise NativeMaterializationDenied("selected HERMES_HOME custody changed during materialization")
        for part in path.parts[:-1]:
            try:
                child_fd = os.open(part, flags, dir_fd=parent_fd)
            except FileNotFoundError:
                if not create_parents:
                    raise NativeMaterializationDenied("native output parent is unavailable") from None
                try:
                    os.mkdir(part, 0o700, dir_fd=parent_fd)
                    os.chown(part, uid, gid, dir_fd=parent_fd, follow_symlinks=False)
                    child_fd = os.open(part, flags, dir_fd=parent_fd)
                    os.fsync(parent_fd)
                except OSError:
                    raise NativeMaterializationDenied("native output parent could not be created safely") from None
            except OSError:
                raise NativeMaterializationDenied("native output parent cannot be opened without following links") from None
            child_info = os.fstat(child_fd)
            if (not stat.S_ISDIR(child_info.st_mode)
                    or (uid is not None and child_info.st_uid != uid)
                    or (gid is not None and child_info.st_gid != gid)
                    or stat.S_IMODE(child_info.st_mode) & 0o022):
                os.close(child_fd)
                raise NativeMaterializationDenied("native output parent custody is invalid")
            os.close(parent_fd)
            parent_fd = child_fd
        yield parent_fd, path.parts[-1]
    finally:
        os.close(parent_fd)


def _atomic_service_write_at(parent_fd: int, leaf: str, content: bytes, *, uid: int, gid: int) -> None:
    temporary = "." + leaf + ".native-stage-" + secrets.token_hex(12)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    fd = -1
    try:
        fd = os.open(temporary, flags, 0o600, dir_fd=parent_fd)
        os.fchown(fd, uid, gid)
        os.fchmod(fd, 0o644)
        with os.fdopen(fd, "wb") as stream:
            fd = -1
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, leaf, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        os.fsync(parent_fd)
    except OSError:
        raise NativeMaterializationDenied("native file publication failed") from None
    finally:
        if fd >= 0:
            os.close(fd)
        try:
            os.unlink(temporary, dir_fd=parent_fd)
        except OSError:
            pass


def _hash_file_at(parent_fd: int, leaf: str) -> str:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(leaf, flags, dir_fd=parent_fd)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                raise NativeMaterializationDenied("native file changed to a non-regular object")
            digest = hashlib.sha256()
            while True:
                block = os.read(fd, 65536)
                if not block:
                    break
                digest.update(block)
            return digest.hexdigest()
        finally:
            os.close(fd)
    except OSError:
        raise NativeMaterializationDenied("native file could not be verified") from None


def _item_dict(item: NativeMaterializedItem) -> dict[str, str]:
    return {"kind": item.kind, "resource_id": item.resource_id,
            "content_sha256": item.content_sha256, "state": item.state}


def _json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _path_digest(values: list[tuple[str, str]]) -> str:
    digest = hashlib.sha256()
    for path, item_digest in sorted(values):
        raw = path.encode("utf-8")
        digest.update(len(raw).to_bytes(4, "big"))
        digest.update(raw)
        digest.update(bytes.fromhex(item_digest))
    return digest.hexdigest()


def _opaque_handle(value: Any) -> bool:
    return (isinstance(value, str) and 16 <= len(value) <= 256
            and all(ch.isascii() and (ch.isalnum() or ch in "_-.") for ch in value))
