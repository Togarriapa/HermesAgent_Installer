"""Root-owned, pre-active application source and lock preparation receipts.

These receipts are setup-scoped inputs to runtime qualification. They do not
require or create an active application-runtime row and grant no application
workload authority.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import stat
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping

from hermes_installer.components.adapters import resolve_component_adapter
from hermes_installer.components.application_handlers import (
    ISOLATED_RUNTIME_PROFILES, review_isolated_runtime,
)
from hermes_installer.components.runtime_source import (
    VerifiedComponentGeneration, bind_component_runtime_source,
)
from hermes_installer.components.source_bundle import (
    GitHubComponentSourceFetcher, VerifiedComponentSource,
)
from hermes_installer.protected_enrollment import RootJournalSelection
from hermes_installer.registry.generation import GenerationStore


_PROFILES: Mapping[str, tuple[str, str, tuple[str, ...], tuple[str, ...], str]] = {
    "graphify": ("Graphify-Labs/graphify", "5b74d7d74911cf435c8f1636b6f96ea202cc6246", ("pyproject.toml",), ("uv.lock",), "qualify-graphify-v1"),
    "browser-use": ("browser-use/browser-use", "c75e8476e26d18b7617643bc2ae082fae8eae431", ("pyproject.toml",), ("uv.lock",), "qualify-browser-use-v1"),
    "hyperframes": ("heygen-com/hyperframes", "46f6cb356785bed79e1ce7b79d7e7accc697786a", ("package.json",), ("bun.lock",), "qualify-hyperframes-v1"),
    "scrapegraph-ai": ("ScrapeGraphAI/Scrapegraph-ai", "194055e203afce41ed4e70365dbc416bad756115", ("pyproject.toml",), ("uv.lock",), "qualify-scrapegraph-v1"),
}
_SOURCE_CATALOG_ARTIFACT_ID = "selected-application-source-profile-v117"
_SEAL = object()
_MAX_TTL = 1800.0


class ApplicationSourcePreparationDenied(PermissionError):
    """A source, lock, or setup choice is absent, stale, or changed."""


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


_SOURCE_CATALOG_SHA256 = hashlib.sha256(_canonical({
    application_id: {
        "source_identity": row[0], "source_revision": row[1],
        "manifest_paths": row[2], "lock_paths": row[3], "workflow_id": row[4],
    }
    for application_id, row in sorted(_PROFILES.items())
})).hexdigest()


@dataclass(frozen=True, slots=True)
class ReviewedApplicationSourceProfile:
    application_id: str
    source_identity: str
    source_revision: str
    manifest_paths: tuple[str, ...]
    lock_paths: tuple[str, ...]
    workflow_id: str
    source_catalog_artifact_id: str
    source_catalog_sha256: str


def reviewed_application_source_profile(application_id: str) -> ReviewedApplicationSourceProfile:
    """Return the finite code-reviewed v117 source profile for factory minting."""
    row = _PROFILES.get(application_id)
    if row is None:
        raise ApplicationSourcePreparationDenied("application is outside the four reviewed source profiles")
    return ReviewedApplicationSourceProfile(
        application_id, row[0], row[1], row[2], row[3], row[4],
        _SOURCE_CATALOG_ARTIFACT_ID, _SOURCE_CATALOG_SHA256,
    )


def _sha(value: Any, name: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        raise ApplicationSourcePreparationDenied(f"{name} digest is malformed")
    return value


def _handle(value: Any, name: str) -> str:
    if (not isinstance(value, str) or not 32 <= len(value) <= 128
            or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-" for c in value)):
        raise ApplicationSourcePreparationDenied(f"{name} handle is malformed")
    return value


def _member_record(path: str, body: bytes, mode: int) -> Mapping[str, Any]:
    return {"path": path, "sha256": hashlib.sha256(body).hexdigest(),
            "size_bytes": len(body), "mode": mode}


@dataclass(frozen=True, slots=True, repr=False)
class RootApplicationSourcePreparationSelection:
    schema: int
    selection_handle: str
    setup_session_id: str
    transaction_handle: str
    plan_sha256: str
    prepared_generation_id: str
    prepared_generation_digest: str
    qualification_choice_handle: str
    qualification_consent_receipt_handle: str
    application_id: str
    workflow_id: str
    source_identity: str
    source_revision: str
    source_catalog_artifact_id: str
    source_catalog_sha256: str
    manifest_paths: tuple[str, ...]
    lock_paths: tuple[str, ...]
    target_profile_id: str
    namespace_selection_receipt_handle: str
    principal_selection_receipt_handle: str | None
    controller_binding_handle: str
    expires_monotonic: float
    _seal: object = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._seal is not _SEAL:
            raise TypeError("application source selections are minted by the root setup binding")

    @classmethod
    def _mint(cls, **claims: Any) -> "RootApplicationSourcePreparationSelection":
        """Internal factory bridge; callers must already hold the root setup binding."""
        return cls(**claims, _seal=_SEAL)


@dataclass(frozen=True, slots=True, repr=False)
class RootPreparedApplicationSourceReceipt:
    schema: int
    receipt_handle: str
    selection_handle: str
    application_id: str
    source_identity: str
    source_revision: str
    source_archive_artifact_id: str
    source_archive_sha256: str
    git_tree_id: str
    source_tree_sha256: str
    source_generation_id: str
    source_generation_manifest_sha256: str
    manifest_member_records: tuple[Mapping[str, Any], ...]
    lock_member_records: tuple[Mapping[str, Any], ...]
    prepared_generation_id: str
    prepared_generation_digest: str
    target_profile_id: str
    namespace_selection_receipt_handle: str
    principal_selection_receipt_handle: str | None
    controller_binding_handle: str
    qualification_consent_receipt_handle: str
    issued_monotonic: float
    expires_monotonic: float
    _seal: object = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._seal is not _SEAL:
            raise TypeError("prepared application sources are minted by the root source registry")


@dataclass(frozen=True, slots=True, repr=False)
class RootApplicationLockReceipt:
    schema: int
    receipt_handle: str
    selection_handle: str
    prepared_source_receipt_handle: str
    application_id: str
    lock_member_path: str
    lock_sha256: str
    size_bytes: int
    mode: int
    issued_monotonic: float
    expires_monotonic: float
    signature: str
    _seal: object = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._seal is not _SEAL:
            raise TypeError("application lock receipts are minted by the root source registry")


@dataclass(frozen=True, slots=True, repr=False)
class RootApplicationRuntimePreparationSelection:
    """Finite pre-active environment/probe selection; it is not a runtime receipt."""

    schema: int
    handle: str
    application_id: str
    source_receipt_handle: str
    selected_lock_receipt_handle: str
    lock_sha256: str
    runtime_id: str
    runtime_manifest_sha256: str
    toolchain_artifact_receipt_handles: tuple[str, ...]
    probe_recipe_id: str
    probe_artifact_id: str
    probe_artifact_sha256: str
    probe_module_ids: tuple[str, ...]
    controller_binding_handle: str
    service_selection_digest: str
    profile_id: str
    profile_generation: str
    operation_id: str
    issued_monotonic: float
    expires_monotonic: float
    signature: str
    _seal: object = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._seal is not _SEAL:
            raise TypeError("runtime preparation selections are minted by the root source registry")


@dataclass(slots=True)
class _SourceEntry:
    selection: RootApplicationSourcePreparationSelection
    source: VerifiedComponentSource
    generation: VerifiedComponentGeneration
    receipt: RootPreparedApplicationSourceReceipt
    runtime_review: Any
    journal_source_root: Path


@dataclass(slots=True)
class _LockEntry:
    source_entry: _SourceEntry
    receipt: RootApplicationLockReceipt
    lock_bytes: bytes
    generation_id: str


class RootApplicationSourcePreparationRegistry:
    """Reopen setup selections and immutable source generations before receipt use."""

    def __init__(self, *, selected_installation_binding: Any,
                 root_component_source_verifier: GitHubComponentSourceFetcher,
                 root_generation_store: GenerationStore,
                 root_journal: RootJournalSelection,
                 expected_uid: int = 0, monotonic: Callable[[], float] = time.monotonic,
                 ttl_seconds: float = 900.0) -> None:
        if (not callable(getattr(selected_installation_binding, "resolve_application_setup_choice", None))
                or type(root_component_source_verifier) is not GitHubComponentSourceFetcher
                or type(root_generation_store) is not GenerationStore
                or not isinstance(root_journal, RootJournalSelection)
                or type(expected_uid) is not int or expected_uid < 0
                or not 0 < ttl_seconds <= _MAX_TTL):
            raise ValueError("root application source preparation registry configuration is invalid")
        self.binding = selected_installation_binding
        self.verifier = root_component_source_verifier
        self.store = root_generation_store
        self.journal = root_journal
        self.expected_uid = expected_uid
        self.monotonic = monotonic
        self.ttl_seconds = float(ttl_seconds)
        self._key = secrets.token_bytes(32)
        self._selections: dict[str, RootApplicationSourcePreparationSelection] = {}
        self._sources: dict[str, _SourceEntry] = {}
        self._locks: dict[str, _LockEntry] = {}
        self._preparations: dict[str, RootApplicationRuntimePreparationSelection] = {}

    @classmethod
    def from_root_setup(cls, selected_installation_binding: Any,
                        root_component_source_verifier: GitHubComponentSourceFetcher,
                        root_generation_store: GenerationStore,
                        root_journal: RootJournalSelection, **kwargs: Any) -> "RootApplicationSourcePreparationRegistry":
        return cls(selected_installation_binding=selected_installation_binding,
                   root_component_source_verifier=root_component_source_verifier,
                   root_generation_store=root_generation_store,
                   root_journal=root_journal, **kwargs)

    def _sign(self, claims: Mapping[str, Any]) -> str:
        return hmac.new(self._key, _canonical(claims), hashlib.sha256).hexdigest()

    def resolve_selection(self, selection_handle: str) -> RootApplicationSourcePreparationSelection:
        _handle(selection_handle, "source preparation selection")
        stored = self._selections.get(selection_handle)
        if stored is None or stored.expires_monotonic <= self.monotonic():
            raise ApplicationSourcePreparationDenied("source preparation selection is absent or expired")
        resolver = getattr(self.binding, "resolve_application_source_preparation", None)
        if not callable(resolver):
            raise ApplicationSourcePreparationDenied("root setup has no current source preparation resolver")
        current = resolver(stored.qualification_choice_handle, stored.application_id)
        if (type(current) is not RootApplicationSourcePreparationSelection
                or current != stored or current.selection_handle != selection_handle):
            raise ApplicationSourcePreparationDenied("source preparation selection is stale or changed")
        self._verify_selection_authority(current)
        return current

    def resolve_application_source_preparation(
        self, qualification_choice_handle: str, application_id: str,
    ) -> RootApplicationSourcePreparationSelection:
        """Resolve and retain the exact factory-minted finite source selection."""
        _handle(qualification_choice_handle, "qualification choice")
        if application_id not in _PROFILES:
            raise ApplicationSourcePreparationDenied("application is outside the four reviewed source profiles")
        resolver = getattr(self.binding, "resolve_application_source_preparation", None)
        if not callable(resolver):
            raise ApplicationSourcePreparationDenied("root setup has no source preparation selector")
        selection = resolver(qualification_choice_handle, application_id)
        if type(selection) is not RootApplicationSourcePreparationSelection:
            raise ApplicationSourcePreparationDenied("root setup returned no sealed source preparation selection")
        if selection.application_id != application_id or selection.qualification_choice_handle != qualification_choice_handle:
            raise ApplicationSourcePreparationDenied("root source selection does not match its finite request")
        self._selections[selection.selection_handle] = selection
        self._verify_selection_authority(selection)
        return selection

    def _verify_selection_authority(self, selection: RootApplicationSourcePreparationSelection) -> None:
        choice = self.binding.resolve_application_setup_choice(selection.qualification_choice_handle)
        if (getattr(choice, "selection_handle", None) != selection.qualification_choice_handle
                or getattr(choice, "setup_session_id", None) != selection.setup_session_id
                or getattr(choice, "transaction_handle", None) != selection.transaction_handle
                or getattr(choice, "prepared_generation_id", None) != selection.prepared_generation_id
                or getattr(choice, "workflow_id", None) != selection.workflow_id
                or getattr(choice, "application_id", None) != selection.application_id
                or selection.target_profile_id != "hermes-agent-native-v1"
                or selection.namespace_selection_receipt_handle is None):
            raise ApplicationSourcePreparationDenied("source preparation selection differs from current root setup")
        session = getattr(self.binding, "_session", None)
        namespace_resolver = getattr(self.binding, "resolve_adopted_namespace_selection", None)
        if not callable(namespace_resolver):
            namespace_resolver = getattr(session, "resolve_adopted_namespace_selection", None)
        if not callable(namespace_resolver):
            raise ApplicationSourcePreparationDenied("current root namespace receipt resolver is unavailable")
        namespace = namespace_resolver()
        if (getattr(namespace, "receipt_handle", None) != selection.namespace_selection_receipt_handle
                or getattr(namespace, "target_profile_id", None) != selection.target_profile_id
                or getattr(namespace, "setup_session_id", None) != selection.setup_session_id
                or getattr(namespace, "transaction_handle", None) != selection.transaction_handle
                or getattr(namespace, "prepared_generation_id", None) != selection.prepared_generation_id
                or getattr(namespace, "prepared_generation_digest", None) != selection.prepared_generation_digest
                or getattr(namespace, "expires_monotonic", 0) <= self.monotonic()):
            raise ApplicationSourcePreparationDenied("source preparation namespace receipt is stale or mismatched")
        if selection.principal_selection_receipt_handle is not None:
            principal_resolver = getattr(self.binding, "resolve_adopted_principal_selection", None)
            if not callable(principal_resolver):
                principal_resolver = getattr(session, "resolve_adopted_principal_selection", None)
            if not callable(principal_resolver):
                raise ApplicationSourcePreparationDenied("current adopted principal resolver is unavailable")
            principal = principal_resolver()
            if (getattr(principal, "receipt_id", None) != selection.principal_selection_receipt_handle
                    or getattr(namespace, "principal_selection_receipt_id", None)
                    != selection.principal_selection_receipt_handle
                    or getattr(principal, "expires_monotonic", 0) <= self.monotonic()):
                raise ApplicationSourcePreparationDenied("source preparation principal receipt is stale or mismatched")
        consent_resolver = getattr(self.binding, "resolve_application_qualification_consent", None)
        if not callable(consent_resolver):
            consent_resolver = getattr(getattr(self.binding, "_session", None),
                                       "resolve_application_qualification_consent", None)
        if not callable(consent_resolver):
            raise ApplicationSourcePreparationDenied("setup qualification consent resolver is unavailable")
        consent = consent_resolver(selection.qualification_choice_handle, "stage-pinned-source-locks")
        if (getattr(consent, "receipt_handle", None) != selection.qualification_consent_receipt_handle
                or getattr(consent, "purpose", None) != "installer-application-local-qualification"
                or getattr(consent, "qualification_choice_handle", None) != selection.qualification_choice_handle
                or getattr(consent, "setup_session_id", None) != selection.setup_session_id
                or getattr(consent, "transaction_handle", None) != selection.transaction_handle
                or getattr(consent, "plan_sha256", None) != selection.plan_sha256
                or getattr(consent, "prepared_generation_id", None) != selection.prepared_generation_id
                or getattr(consent, "prepared_generation_digest", None) != selection.prepared_generation_digest
                or getattr(consent, "application_id", None) != selection.application_id
                or getattr(consent, "workflow_id", None) != selection.workflow_id
                or getattr(consent, "target_profile_id", None) != selection.target_profile_id
                or getattr(consent, "namespace_selection_receipt_handle", None)
                != selection.namespace_selection_receipt_handle
                or getattr(consent, "controller_binding_handle", None) != selection.controller_binding_handle
                or "stage-pinned-source-locks" not in getattr(consent, "allowed_phase_ids", ())
                or getattr(consent, "expires_monotonic", 0) <= self.monotonic()):
            raise ApplicationSourcePreparationDenied("source preparation consent is stale or mismatched")

    def prepare_selected_source(self, selection_handle: str) -> RootPreparedApplicationSourceReceipt:
        self._verify_journal_selection()
        selection = self.resolve_selection(selection_handle)
        existing = self._sources.get(selection_handle)
        if existing is not None:
            self._reopen_source(existing)
            return existing.receipt
        profile = _PROFILES.get(selection.application_id)
        contract = resolve_component_adapter(selection.application_id)
        if (profile is None or selection.source_identity != profile[0]
                or selection.source_revision != profile[1]
                or selection.manifest_paths != profile[2]
                or selection.lock_paths != profile[3]
                or selection.workflow_id != profile[4]
                or selection.source_catalog_artifact_id != _SOURCE_CATALOG_ARTIFACT_ID
                or selection.source_catalog_sha256 != _SOURCE_CATALOG_SHA256
                or contract.source_identity != profile[0] or contract.revision != profile[1]):
            raise ApplicationSourcePreparationDenied("selected application differs from the reviewed source and lock pin")
        source = self.verifier.fetch(contract)
        if type(source) is not VerifiedComponentSource:
            raise ApplicationSourcePreparationDenied("source verifier returned no verified pinned source")
        generation = bind_component_runtime_source(source, self.store, component_id=selection.application_id)
        journal_source_root = self._stage_root_source_tree(source, selection)
        review = review_isolated_runtime(selection.application_id, source.files)
        if review.blockers:
            raise ApplicationSourcePreparationDenied("pinned application source or lock is not reviewable")
        for path in (*profile[2], *profile[3]):
            if path not in source.files and not (selection.application_id == "browser-use" and path == "uv.lock"):
                raise ApplicationSourcePreparationDenied(f"pinned source is missing reviewed member: {path}")
        members = self._member_records(source, (*profile[2], *profile[3]))
        now = self.monotonic()
        handle = secrets.token_urlsafe(32)
        receipt_claims = {
            "schema": 1, "receipt_handle": handle, "selection_handle": selection_handle,
            "application_id": selection.application_id, "source_identity": source.source_identity,
            "source_revision": source.revision,
            "source_archive_artifact_id": f"component-source-archive:{selection.application_id}:{selection.source_revision}:{source.archive_sha256}",
            "source_archive_sha256": source.archive_sha256, "git_tree_id": self._git_tree_id(source),
            "source_tree_sha256": source.source_tree_sha,
            "source_generation_id": source.generation_id,
            "source_generation_manifest_sha256": generation.generation_digest,
            "manifest_member_records": tuple(row for row in members if row["path"] in profile[2]),
            "lock_member_records": tuple(row for row in members if row["path"] in profile[3]),
            "prepared_generation_id": selection.prepared_generation_id,
            "prepared_generation_digest": selection.prepared_generation_digest,
            "target_profile_id": selection.target_profile_id,
            "namespace_selection_receipt_handle": selection.namespace_selection_receipt_handle,
            "principal_selection_receipt_handle": selection.principal_selection_receipt_handle,
            "controller_binding_handle": selection.controller_binding_handle,
            "qualification_consent_receipt_handle": selection.qualification_consent_receipt_handle,
            "issued_monotonic": now, "expires_monotonic": min(now + self.ttl_seconds, selection.expires_monotonic),
        }
        receipt = RootPreparedApplicationSourceReceipt(**receipt_claims, _seal=_SEAL)
        entry = _SourceEntry(selection, source, generation, receipt, review, journal_source_root)
        lock_record = next((row for row in receipt.lock_member_records), None)
        if lock_record is None:
            raise ApplicationSourcePreparationDenied("selected application has no verified lock member")
        profile_lock_path = profile[3][0]
        lock_bytes = source.files.get(profile_lock_path)
        if lock_bytes is None and selection.application_id == "browser-use":
            from hermes_installer.components.locked_runtime import load_browser_use_lock_bundle
            lock_bytes = load_browser_use_lock_bundle(source_pyproject=source.files.get("pyproject.toml")).uv_lock
        if not isinstance(lock_bytes, bytes) or hashlib.sha256(lock_bytes).hexdigest() != lock_record["sha256"]:
            raise ApplicationSourcePreparationDenied("selected lock bytes differ from verified lock member")
        lock_generation_id = f"application-lock-{selection.application_id}-{lock_record['sha256'][:16]}"
        lock_generation = self.store.root / lock_generation_id
        if lock_generation.exists() or lock_generation.is_symlink():
            try:
                _root, manifest, _digest = self.store._verify(lock_generation_id)
            except Exception as exc:
                raise ApplicationSourcePreparationDenied("existing isolated lock generation is not root-verified") from exc
            if manifest.get("files", {}).get(profile_lock_path, {}).get("sha256") != lock_record["sha256"]:
                raise ApplicationSourcePreparationDenied("existing isolated lock generation has different bytes")
        else:
            self.store.stage(lock_generation_id, {profile_lock_path: lock_bytes},
                             file_modes={profile_lock_path: lock_record["mode"]})
        lock_handle = secrets.token_urlsafe(32)
        lock_now = self.monotonic()
        lock_claims = {
            "schema": 1, "receipt_handle": lock_handle,
            "selection_handle": selection_handle,
            "prepared_source_receipt_handle": receipt.receipt_handle,
            "application_id": selection.application_id,
            "lock_member_path": profile_lock_path,
            "lock_sha256": lock_record["sha256"],
            "size_bytes": lock_record["size_bytes"], "mode": lock_record["mode"],
            "issued_monotonic": lock_now,
            "expires_monotonic": min(lock_now + self.ttl_seconds, selection.expires_monotonic),
        }
        lock_receipt = RootApplicationLockReceipt(
            **lock_claims, signature=self._sign(lock_claims), _seal=_SEAL)
        self._locks[lock_handle] = _LockEntry(entry, lock_receipt, lock_bytes, lock_generation_id)
        self._sources[selection_handle] = entry
        self._reopen_source(entry)
        return receipt

    @staticmethod
    def _git_tree_id(source: VerifiedComponentSource) -> str:
        from hermes_installer.registry.source import _git_tree
        upstream = {name: body for name, body in source.files.items() if name != "INSTALLER-SOURCE-PROVENANCE.json"}
        modes = {name: source.file_modes[name] for name in upstream}
        return _git_tree(upstream, modes)[0]

    def _member_records(self, source: VerifiedComponentSource, members: tuple[str, ...]) -> tuple[Mapping[str, Any], ...]:
        result = []
        for path in members:
            body = source.files.get(path)
            mode = source.file_modes.get(path)
            if not isinstance(body, bytes) or type(mode) is not int:
                if source.component_id == "browser-use" and path == "uv.lock":
                    from hermes_installer.components.locked_runtime import load_browser_use_lock_bundle
                    bundle = load_browser_use_lock_bundle(source_pyproject=source.files.get("pyproject.toml"))
                    body, mode = bundle.uv_lock, 0o644
                else:
                    raise ApplicationSourcePreparationDenied(f"verified source member is unavailable: {path}")
            # Receipt modes describe the immutable generation, not upstream
            # checkout permissions (GenerationStore maps them to private modes).
            result.append(_member_record(path, body, self.store._private_mode(mode)))
        return tuple(result)

    def _reopen_source(self, entry: _SourceEntry) -> None:
        self._verify_journal_selection()
        current = self.resolve_selection(entry.selection.selection_handle)
        if current != entry.selection:
            raise ApplicationSourcePreparationDenied("source preparation selection changed")
        try:
            root = entry.generation.verify()
            _actual, manifest, digest = self.store._verify(entry.generation.generation_id if hasattr(entry.generation, "generation_id") else f"component-{entry.selection.application_id}-{entry.selection.source_revision[:12]}")
        except Exception as exc:
            raise ApplicationSourcePreparationDenied("source generation failed currentness verification") from exc
        if (root != entry.generation.root or digest != entry.receipt.source_generation_manifest_sha256
                or entry.source.source_tree_sha != entry.receipt.source_tree_sha256
                or entry.source.archive_sha256 != entry.receipt.source_archive_sha256):
            raise ApplicationSourcePreparationDenied("prepared source bytes changed after receipt issuance")
        profile = _PROFILES[entry.selection.application_id]
        if self._member_records(entry.source, (*profile[2], *profile[3])) != (
                entry.receipt.manifest_member_records + entry.receipt.lock_member_records):
            raise ApplicationSourcePreparationDenied("prepared manifest or lock member changed")
        self._verify_journal_source_tree(entry.journal_source_root, entry.source)

    def _verify_journal_selection(self) -> None:
        try:
            info = self.journal.path.lstat()
        except OSError:
            raise ApplicationSourcePreparationDenied("selected root setup journal is unavailable") from None
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != self.expected_uid
                or stat.S_IMODE(info.st_mode) != 0o700
                or info.st_dev != self.journal.device or info.st_ino != self.journal.inode):
            raise ApplicationSourcePreparationDenied("selected root setup journal identity changed")

    def _stage_root_source_tree(self, source: VerifiedComponentSource,
                                selection: RootApplicationSourcePreparationSelection) -> Path:
        self._verify_journal_selection()
        base = self.journal.path / "application-source-staging"
        txn = base / hashlib.sha256(selection.transaction_handle.encode("utf-8")).hexdigest()
        target = txn / selection.application_id
        for directory in (base, txn, target):
            try:
                directory.mkdir(mode=0o700)
            except FileExistsError:
                pass
            try:
                info = directory.lstat()
            except OSError:
                raise ApplicationSourcePreparationDenied("private source staging directory disappeared") from None
            if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
                    or info.st_uid != self.expected_uid or stat.S_IMODE(info.st_mode) != 0o700):
                raise ApplicationSourcePreparationDenied("private source staging directory is not root-owned")
        compiled, modes = source.compiled_files()
        identity = f"{hashlib.sha256(selection.transaction_handle.encode()).hexdigest()}:{selection.application_id}"
        operation = "application-source-staging:" + hashlib.sha256(identity.encode()).hexdigest()
        expected = {
            name: {"sha256": hashlib.sha256(body).hexdigest(),
                   "mode": self.store._private_mode(modes[name])}
            for name, body in compiled.items()
        }
        self.store.journal.checkpoint(operation, "stage_prepared", {
            "application_id": selection.application_id,
            "source_revision": selection.source_revision,
            "files_sha256": hashlib.sha256(_canonical(expected)).hexdigest(),
        })
        if any(target.iterdir()):
            self._verify_journal_source_tree(target, source)
        else:
            for name, body in sorted(compiled.items()):
                output = target / name
                if output.is_symlink() or output.exists():
                    raise ApplicationSourcePreparationDenied("source staging contains an unexpected file")
                output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                current = output.parent
                while current != target:
                    info = current.lstat()
                    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != self.expected_uid
                            or stat.S_IMODE(info.st_mode) != 0o700):
                        raise ApplicationSourcePreparationDenied("source staging path contains an unsafe directory")
                    current = current.parent
                mode = self.store._private_mode(modes[name])
                fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                             | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0), mode)
                try:
                    os.fchmod(fd, mode)
                    with os.fdopen(fd, "wb", closefd=False) as stream:
                        stream.write(body)
                        stream.flush()
                        os.fsync(stream.fileno())
                finally:
                    os.close(fd)
            self.store.journal.record_owned("application-source", identity, "staged")
            self.store.journal.checkpoint(operation, "staged", {
                "application_id": selection.application_id,
                "source_revision": selection.source_revision,
                "files_sha256": hashlib.sha256(_canonical(expected)).hexdigest(),
            })
        return target

    def _verify_journal_source_tree(self, target: Path, source: VerifiedComponentSource) -> None:
        self._verify_journal_selection()
        if target.is_symlink() or not target.is_dir():
            raise ApplicationSourcePreparationDenied("private staged application source is unavailable")
        compiled, modes = source.compiled_files()
        expected = {
            name: (hashlib.sha256(body).hexdigest(), self.store._private_mode(modes[name]))
            for name, body in compiled.items()
        }
        actual: dict[str, tuple[str, int]] = {}
        for base, dirs, files in os.walk(target, followlinks=False):
            parent = Path(base)
            for name in dirs:
                path = parent / name
                info = path.lstat()
                if (not stat.S_ISDIR(info.st_mode) or info.st_uid != self.expected_uid
                        or stat.S_IMODE(info.st_mode) != 0o700):
                    raise ApplicationSourcePreparationDenied("private staged source has an unsafe directory")
            for name in files:
                path = parent / name
                info = path.lstat()
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != self.expected_uid
                        or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) not in {0o400, 0o500}):
                    raise ApplicationSourcePreparationDenied("private staged source has an unsafe file")
                fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
                digest = hashlib.sha256()
                try:
                    with os.fdopen(fd, "rb") as stream:
                        for block in iter(lambda: stream.read(65536), b""):
                            digest.update(block)
                finally:
                    pass
                actual[path.relative_to(target).as_posix()] = (digest.hexdigest(), stat.S_IMODE(info.st_mode))
        if actual != expected:
            raise ApplicationSourcePreparationDenied("private staged source bytes differ from verified source")

    def resolve_prepared_source(self, receipt_handle: str) -> RootPreparedApplicationSourceReceipt:
        _handle(receipt_handle, "prepared source receipt")
        entry = next((row for row in self._sources.values() if row.receipt.receipt_handle == receipt_handle), None)
        if entry is None or entry.receipt.expires_monotonic <= self.monotonic():
            raise ApplicationSourcePreparationDenied("prepared source receipt is absent or expired")
        self._reopen_source(entry)
        return entry.receipt

    def resolve_application_lock_receipt(self, handle: str, *,
                                         preparation_selection_handle: str,
                                         prepared_source_receipt_handle: str) -> RootApplicationLockReceipt:
        _handle(handle, "application lock receipt")
        selection = self.resolve_selection(preparation_selection_handle)
        source = self.resolve_prepared_source(prepared_source_receipt_handle)
        entry = self._sources[selection.selection_handle]
        lock_entry = self._locks.get(handle)
        if (lock_entry is None or lock_entry.source_entry is not entry
                or source.receipt_handle != prepared_source_receipt_handle):
            raise ApplicationSourcePreparationDenied("lock receipt is not joined to the selected source")
        if lock_entry.receipt.expires_monotonic <= self.monotonic():
            raise ApplicationSourcePreparationDenied("application lock receipt expired")
        expected_signature = self._sign(self._lock_claims(lock_entry.receipt))
        if not hmac.compare_digest(expected_signature, lock_entry.receipt.signature):
            raise ApplicationSourcePreparationDenied("application lock receipt signature changed")
        self._reopen_source(entry)
        body = lock_entry.lock_bytes
        if hashlib.sha256(body).hexdigest() != lock_entry.receipt.lock_sha256 or len(body) != lock_entry.receipt.size_bytes:
            raise ApplicationSourcePreparationDenied("application lock bytes changed")
        try:
            root, manifest, _digest = self.store._verify(lock_entry.generation_id)
            digest, mode = self.store._hash(root / lock_entry.receipt.lock_member_path)
        except Exception as exc:
            raise ApplicationSourcePreparationDenied("isolated lock generation failed currentness verification") from exc
        if digest != lock_entry.receipt.lock_sha256 or mode != lock_entry.receipt.mode:
            raise ApplicationSourcePreparationDenied("isolated lock generation differs from its receipt")
        return lock_entry.receipt

    def resolve_application_lock_for_prepared_source(
        self, preparation_selection_handle: str,
        prepared_source_receipt_handle: str,
    ) -> RootApplicationLockReceipt:
        """Resolve the sole lock minted by the selected source preparation."""
        source = self.resolve_prepared_source(prepared_source_receipt_handle)
        selection = self.resolve_selection(preparation_selection_handle)
        if source.selection_handle != selection.selection_handle:
            raise ApplicationSourcePreparationDenied("lock lookup source does not match setup selection")
        candidates = [row for row in self._locks.values()
                     if row.source_entry.receipt is source]
        if len(candidates) != 1:
            raise ApplicationSourcePreparationDenied("selected setup source has no unique lock receipt")
        return self.resolve_application_lock_receipt(
            candidates[0].receipt.receipt_handle,
            preparation_selection_handle=preparation_selection_handle,
            prepared_source_receipt_handle=prepared_source_receipt_handle,
        )

    def record_prepared_verified_generation(self, prepared_source_receipt_handle: str,
                                            source_preparation_selection_handle: str) -> RootPreparedApplicationSourceReceipt:
        """Return the current typed pre-active source receipt; never consult an active row."""
        source = self.resolve_prepared_source(prepared_source_receipt_handle)
        selection = self.resolve_selection(source_preparation_selection_handle)
        if source.selection_handle != selection.selection_handle:
            raise ApplicationSourcePreparationDenied("prepared source does not belong to the selected setup choice")
        return source

    @staticmethod
    def _lock_claims(receipt: RootApplicationLockReceipt) -> Mapping[str, Any]:
        return {name: getattr(receipt, name) for name in receipt.__dataclass_fields__
                if name not in {"signature", "_seal"}}
