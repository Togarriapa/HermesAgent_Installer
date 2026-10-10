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
import secrets
import sqlite3
import stat
import time
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Protocol

from hermes_installer.authority.pm_runtime import NativePMRuntimeResolver
from hermes_installer.authority.native_output_receipts import (
    RootMaterializationReceiptRegistry,
    RuntimeArtifactReceipt,
)
from hermes_installer.registry.native import NativeRegistry
from hermes_installer.registry.native_install import (
    PINNED_HERMES_REVISION,
    NativeInstallError,
    NativeInstallReceipt,
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
        selection = self._selection(enrollment_id, service_generation, resource_profile_id)
        _verify_root(self._home_root, owner_uid=selection.service_uid, owner_gid=selection.service_gid)
        _verify_root(self._data_root, owner_uid=selection.service_uid, owner_gid=selection.service_gid)
        discovery = self._registry.discover([f"profiles/{resource_profile_id}@*"])
        profile_items = [item for item in discovery.resources
                         if item.resource.kind.value == "profiles"]
        if (len(profile_items) != 1
                or profile_items[0].resource.id != resource_profile_id):
            raise NativeMaterializationDenied("selected resource profile is absent or ambiguous")
        compiled = self._registry.materialize(discovery)
        mapping = _selected_files(compiled, resource_profile_id)
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
                       if state == "preserved"
                       and relative != f"profiles/{resource_profile_id}/config.yaml"]
        if conflicting:
            raise NativeMaterializationDenied(
                "native profile/skill bytes conflict with preserved user overlays; "
                "no discovery or activation receipt was issued"
            )
        items = _receipt_items(results)
        # No receipt usable for activation is issued until all required profile
        # identity and selected skill files match the compiled generation.
        required = {("profile", resource_profile_id)} | {
            ("skill", skill_id) for skill_id in _skill_ids(mapping)
        }
        if {(item.kind, item.resource_id) for item in items} != required:
            raise NativeMaterializationDenied("native profile or skill closure was not fully materialized")
        try:
            hermes_python = self._resolve_hermes_python(selection)
            discovery = discover_and_load_selected(
                hermes_source=self._hermes_source,
                python=hermes_python,
                hermes_root=self._home_root,
                profile_id=resource_profile_id,
                skill_ids=tuple(sorted(_skill_ids(mapping))),
                timeout=60.0,
            )
        except NativeInstallError as exc:
            raise NativeMaterializationDenied(
                "pinned Hermes did not discover and load the selected native profile/skills"
            ) from exc
        if (discovery.hermes_revision != PINNED_HERMES_REVISION
                or not discovery.python_version.startswith("3.14.")
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
            target = _hermes_target_path(member.relative_path, record["resource_profile_id"])
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
                or not _opaque_handle(selection.pm_runtime_handle)):
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
                CREATE TABLE IF NOT EXISTS receipts(
                    handle TEXT PRIMARY KEY, enrollment_id TEXT NOT NULL,
                    service_generation TEXT NOT NULL, protected_enrollment_digest TEXT NOT NULL,
                    service_profile_id TEXT NOT NULL, resource_profile_id TEXT NOT NULL,
                    resources_revision TEXT NOT NULL, resources_content_digest TEXT NOT NULL,
                    selected_closure_digest TEXT NOT NULL, items TEXT NOT NULL,
                    skill_ids TEXT NOT NULL, state TEXT NOT NULL, expires REAL NOT NULL,
                    discovery TEXT);
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


def _selected_files(compiled: Mapping[str, bytes], profile_id: str) -> dict[str, bytes]:
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
    mapping: dict[str, str] = {}
    for row in rows:
        if (not isinstance(row, dict) or row.get("conflict_policy") != "preserve-existing"
                or not isinstance(row.get("staged"), str) or not isinstance(row.get("target"), str)):
            raise NativeMaterializationDenied("compiled native crosswalk has an unsafe materialization row")
        staged, target = row["staged"], row["target"]
        if staged.startswith(f"homes/profiles/{profile_id}/"):
            expected_source_target = "profiles/" + staged.removeprefix("homes/profiles/")
            destination = expected_source_target
        elif staged.startswith("homes/skills/"):
            parts = staged.split("/")
            if len(parts) != 4 or parts[-1] != "SKILL.md":
                raise NativeMaterializationDenied("selected skill path is malformed")
            expected_source_target = f"skills/{parts[2]}/SKILL.md"
            destination = f"profiles/{profile_id}/skills/{parts[2]}/SKILL.md"
        else:
            continue
        if target != expected_source_target or staged not in compiled:
            raise NativeMaterializationDenied("compiled native path differs from its selected Hermes destination")
        if destination in mapping:
            raise NativeMaterializationDenied("compiled native closure maps multiple files to one Hermes destination")
        mapping[destination] = compiled[staged]
    required = {f"profiles/{profile_id}/SOUL.md", f"profiles/{profile_id}/profile.yaml",
                f"profiles/{profile_id}/config.yaml"}
    if not required.issubset(mapping):
        raise NativeMaterializationDenied("selected profile is missing required native identity files")
    if not mapping:
        raise NativeMaterializationDenied("selected resource closure has no native profile files")
    return mapping


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
        effective = dict(resolved.effective_spec or resource.body)
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


def _hermes_target_path(relative_path: str, profile_id: str) -> str | None:
    if relative_path.startswith(f"homes/profiles/{profile_id}/"):
        return "profiles/" + relative_path.removeprefix("homes/")
    if relative_path.startswith("homes/skills/"):
        parts = PurePosixPath(relative_path).parts
        if len(parts) == 4 and parts[-1] == "SKILL.md":
            return f"profiles/{profile_id}/skills/{parts[2]}/SKILL.md"
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
        if len(parts) == 5 and parts[0] == "profiles" and parts[2] == "skills" and parts[4] == "SKILL.md":
            result.add(parts[3])
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
    if len(parts) == 3 and parts[0] == "profiles":
        return "profile", parts[1]
    if len(parts) == 5 and parts[0] == "profiles" and parts[2] == "skills" and parts[4] == "SKILL.md":
        return "skill", parts[3]
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


@contextmanager
def _open_parent(root: Path, relative: str, *, uid: int, gid: int,
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
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != uid or info.st_gid != gid
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
            if (not stat.S_ISDIR(child_info.st_mode) or child_info.st_uid != uid
                    or child_info.st_gid != gid or stat.S_IMODE(child_info.st_mode) & 0o022):
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
