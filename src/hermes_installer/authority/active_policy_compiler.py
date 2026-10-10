"""Root-owned compilation claims for active bootstrap policy publication.

The compiler does not accept policy JSON, paths, identities, or hashes from a
setup client.  It reuses the currently verified strict installed policy,
catalog, and selection documents and binds those bytes to the current prepared
transaction, adopted principal, PM runtime receipts, and native output closure.
The publisher remains the only component that changes the selected generation.
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import secrets
import stat
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Sequence

from .bootstrap_enrollment import (
    BootstrapEnrollmentError,
    BootstrapEnrollmentPending,
    EnrollmentReceipt,
    RootSetupSessionHandle,
    VerifiedCommittedEnrollment,
)

_JOURNAL = Path("/var/lib/hermes-installer/authority-journal")
_CLAIM_DIR = "active-policy-compilation"
_HANDLE = re.compile(r"[A-Za-z0-9_-]{32,128}\Z")
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_MAX_DOCUMENT = 2 * 1024 * 1024
_SETUP_CHOICE_PURPOSES = frozenset({
    "memory-service-enablement", "memory-capture-configuration", "private-input-routes",
    "public-free-web-read", "existing-model-selection", "native-policy-preparation",
    "application-qualification",
})


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _ordered_unique_receipt_handles(handles: Sequence[str], label: str) -> tuple[str, ...]:
    """Return one stable receipt order while rejecting malformed source handles."""
    result: list[str] = []
    seen: set[str] = set()
    for handle in handles:
        if not isinstance(handle, str) or not _HANDLE.fullmatch(handle):
            raise BootstrapEnrollmentPending(f"{label} receipt closure contains a malformed handle")
        if handle not in seen:
            seen.add(handle)
            result.append(handle)
    return tuple(result)


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON member")
        result[key] = value
    return result


def _read_json(path: Path, *, maximum: int = 64 * 1024) -> Mapping[str, Any]:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(path, flags)
    try:
        info = os.fstat(fd)
        path_info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
                or stat.S_IMODE(info.st_mode) != 0o600 or stat.S_ISLNK(path_info.st_mode)
                or info.st_dev != path_info.st_dev or info.st_ino != path_info.st_ino
                or info.st_size > maximum):
            raise BootstrapEnrollmentPending("active compilation journal custody is invalid")
        chunks = bytearray()
        while len(chunks) <= maximum:
            block = os.read(fd, min(65536, maximum + 1 - len(chunks)))
            if not block:
                break
            chunks.extend(block)
        if len(chunks) > maximum:
            raise BootstrapEnrollmentPending("active compilation journal record exceeds its bound")
        value = json.loads(chunks.decode("utf-8"), object_pairs_hook=_unique_pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        if not isinstance(value, dict):
            raise ValueError("journal record must be an object")
        return value
    except (UnicodeError, ValueError, json.JSONDecodeError):
        raise BootstrapEnrollmentPending("active compilation journal record is malformed") from None
    finally:
        os.close(fd)


def _write_json(path: Path, value: Mapping[str, Any], *, exclusive: bool = False) -> None:
    payload = _canonical(dict(value))
    if len(payload) > 64 * 1024:
        raise BootstrapEnrollmentError("active compilation journal record exceeds its bound")
    target = path
    if not exclusive:
        target = path.with_name("." + path.name + "." + secrets.token_hex(12) + ".tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(target, flags, 0o600)
    try:
        os.fchown(fd, 0, 0)
        os.fchmod(fd, 0o600)
        with os.fdopen(os.dup(fd), "wb", closefd=True) as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.fsync(fd)
    finally:
        os.close(fd)
    if not exclusive:
        try:
            os.replace(target, path)
        except Exception:
            try:
                target.unlink()
            except OSError:
                pass
            raise
    directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _write_immutable_bytes(path: Path, payload: bytes) -> None:
    if not isinstance(payload, bytes) or not payload or len(payload) > _MAX_DOCUMENT:
        raise BootstrapEnrollmentError("compiled active policy output is empty or oversized")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
                 | getattr(os, "O_NOFOLLOW", 0), 0o400)
    try:
        os.fchown(fd, 0, 0)
        os.fchmod(fd, 0o400)
        view = memoryview(payload)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise OSError("short active compilation output write")
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)
    directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _read_immutable_bytes(path: Path) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0))
    try:
        info = os.fstat(fd)
        path_info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
                or stat.S_IMODE(info.st_mode) != 0o400 or stat.S_ISLNK(path_info.st_mode)
                or (info.st_dev, info.st_ino) != (path_info.st_dev, path_info.st_ino)
                or info.st_size <= 0 or info.st_size > _MAX_DOCUMENT):
            raise BootstrapEnrollmentPending("persisted compiled policy output custody is invalid")
        chunks = bytearray()
        while len(chunks) <= _MAX_DOCUMENT:
            block = os.read(fd, min(131072, _MAX_DOCUMENT + 1 - len(chunks)))
            if not block:
                break
            chunks.extend(block)
        if len(chunks) > _MAX_DOCUMENT:
            raise BootstrapEnrollmentPending("persisted compiled policy output exceeds its bound")
        return bytes(chunks)
    finally:
        os.close(fd)


def _ensure_private_directory(path: Path) -> None:
    if os.geteuid() != 0 or path != _JOURNAL / _CLAIM_DIR:
        raise BootstrapEnrollmentPending("active compilation registry is available only to the fixed root journal")
    try:
        path.mkdir(mode=0o700)
        os.chown(path, 0, 0)
        parent = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    except FileExistsError:
        pass
    info = path.lstat()
    if (stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode)
            or info.st_uid != 0 or info.st_gid != 0 or stat.S_IMODE(info.st_mode) != 0o700):
        raise BootstrapEnrollmentPending("active compilation journal directory custody is invalid")


def _manifest(claim: "RootActivePolicyCompilationClaim") -> dict[str, Any]:
    """Public immutable claim domain. Private live objects and byte bodies are excluded."""
    return {
        "schema": claim.schema,
        "publication_handle": claim.publication_handle,
        "setup_session_id": claim.setup_session_id,
        "transaction_handle": claim.transaction_handle,
        "plan_sha256": claim.plan_sha256,
        "prepared_generation_id": claim.prepared_generation_id,
        "expected_selection_catalog_sha256": claim.expected_selection_catalog_sha256,
        "expected_service_generation_digest": claim.expected_service_generation_digest,
        "policy_template_artifact_id": claim.policy_template_artifact_id,
        "policy_template_sha256": claim.policy_template_sha256,
        "principal_selection_receipt_handle": claim.principal_selection_receipt_handle,
        "runtime_receipt_handles": list(claim.runtime_receipt_handles),
        "materialization_receipt_handles": list(claim.materialization_receipt_handles),
        "compiled_policy_sha256": claim.compiled_policy_sha256,
        "compiled_artifact_catalog_sha256": claim.compiled_artifact_catalog_sha256,
        "compiled_selection_sha256": claim.compiled_selection_sha256,
        "selection_catalog_sha256": claim.selection_catalog_sha256,
        "observed_root_receipt_handle": claim.observed_root_receipt_handle,
        "plan_artifact_id": claim.plan_artifact_id,
        "release_commit": claim.release_commit,
        "source_receipt_handles": list(claim.source_receipt_handles),
        "choice_adoptions": [_choice_projection_record(row) for row in claim.choice_adoptions],
        "issued_monotonic": claim.issued_monotonic,
        "expires_monotonic": claim.expires_monotonic,
    }


def _choice_projection_record(row: "ActiveSetupChoiceProjection") -> dict[str, Any]:
    return {
        "selection_handle": row.selection_handle,
        "purpose": row.purpose,
        "key_id": row.key_id,
        "signed_record_sha256": row.signed_record_sha256,
        "choice_payload_sha256": row.choice_payload_sha256,
        "choice_epoch": row.choice_epoch,
        "revocation_epoch": row.revocation_epoch,
        "issued_at_unix": row.issued_at_unix,
        "setup_deadline_unix": row.setup_deadline_unix,
        "release_deployment_receipt_sha256": row.release_deployment_receipt_sha256,
        "setup_session_handle": row.setup_session_handle,
        "transaction_handle": row.transaction_handle,
        "plan_id": row.plan_id,
        "prepared_generation": row.prepared_generation,
        "principal_selection_handle": row.principal_selection_handle,
        "namespace_selection_handle": row.namespace_selection_handle,
        "private_profile_selection_handle": row.private_profile_selection_handle,
        "source_member_receipt_handles": list(row.source_member_receipt_handles),
        "principal_id": row.principal_id,
        "profile_id": row.profile_id,
        "namespace_id": row.namespace_id,
        "principal_binding_sha256": row.principal_binding_sha256,
        "namespace_binding_sha256": row.namespace_binding_sha256,
        "service_generation_id": row.service_generation_id,
        "service_generation_digest": row.service_generation_digest,
        "selection_catalog_sha256": row.selection_catalog_sha256,
    }


@dataclass(frozen=True, slots=True, repr=False)
class ActiveSetupChoiceProjection:
    """Typed source projection for one root-signed setup choice.

    This contains no choice payload or runtime authority. Its private seal ties
    the normalized projection to the exact active compiler claim.
    """

    selection_handle: str
    purpose: str
    key_id: str
    signed_record_sha256: str
    choice_payload_sha256: str
    choice_epoch: int
    revocation_epoch: int
    issued_at_unix: float
    setup_deadline_unix: float
    release_deployment_receipt_sha256: str
    setup_session_handle: str
    transaction_handle: str
    plan_id: str
    prepared_generation: str
    principal_selection_handle: str
    namespace_selection_handle: str
    private_profile_selection_handle: str | None
    source_member_receipt_handles: tuple[str, ...]
    principal_id: str
    profile_id: str
    namespace_id: str
    principal_binding_sha256: str
    namespace_binding_sha256: str
    service_generation_id: str
    service_generation_digest: str
    selection_catalog_sha256: str
    _compiler_seal: object = field(repr=False, compare=False)


def _validate_claim_output_hashes(claim: "RootActivePolicyCompilationClaim") -> None:
    if (not isinstance(claim.policy_bytes, bytes) or _sha(claim.policy_bytes) != claim.compiled_policy_sha256
            or not isinstance(claim.artifact_catalog_bytes, bytes)
            or _sha(claim.artifact_catalog_bytes) != claim.compiled_artifact_catalog_sha256
            or not isinstance(claim.selection_document, Mapping)
            or not isinstance(claim.source_receipt_handles, tuple)
            or _ordered_unique_receipt_handles(claim.source_receipt_handles, "active claim")
            != claim.source_receipt_handles
            or not set(claim.runtime_receipt_handles).issubset(claim.source_receipt_handles)
            or not set(claim.materialization_receipt_handles).issubset(claim.source_receipt_handles)
            or claim.principal_selection_receipt_handle not in claim.source_receipt_handles):
        raise BootstrapEnrollmentPending("active policy claim output bytes changed")
    document = dict(claim.selection_document)
    catalog_digest = document.get("catalog_sha256")
    unsigned = {key: value for key, value in document.items() if key != "catalog_sha256"}
    if (not isinstance(catalog_digest, str) or catalog_digest != claim.selection_catalog_sha256
            or not _HEX.fullmatch(catalog_digest)
            or _sha(_canonical(unsigned)) != catalog_digest
            or _sha(_canonical(document)) != claim.compiled_selection_sha256):
        raise BootstrapEnrollmentPending("active policy selection output hashes changed")


@dataclass(frozen=True, slots=True, repr=False)
class RootActivePolicyCompilationClaim:
    """Sealed output DTO consumed only by the active policy publisher."""

    schema: int
    plan_artifact_id: str
    release_commit: str
    publication_handle: str
    setup_session_id: str
    transaction_handle: str
    plan_sha256: str
    prepared_generation_id: str
    expected_selection_catalog_sha256: str | None
    expected_service_generation_digest: str
    policy_template_artifact_id: str
    policy_template_sha256: str
    principal_selection_receipt_handle: str
    runtime_receipt_handles: tuple[str, ...]
    materialization_receipt_handles: tuple[str, ...]
    source_receipt_handles: tuple[str, ...]
    compiled_policy_sha256: str
    compiled_artifact_catalog_sha256: str
    compiled_selection_sha256: str
    selection_catalog_sha256: str
    issued_monotonic: float
    expires_monotonic: float
    claim_digest: str
    policy_bytes: bytes
    artifact_catalog_bytes: bytes
    selection_document: Mapping[str, Any]
    observed_root_receipt_handle: str
    _root_journal_root: Path = field(repr=False, compare=False)
    _root_setup_session: Any = field(repr=False, compare=False)
    _reservation_handle: str = field(repr=False, compare=False)
    _seal: object = field(repr=False, compare=False)
    _root_prepared_native_bundle: Any = field(default=None, repr=False, compare=False)
    choice_adoptions: tuple[ActiveSetupChoiceProjection, ...] = ()


class RootActivePolicyTemplateResolver:
    """Typed join of the installed strict policy resolver and principal issuer."""

    def __init__(self, policy_resolver: Any, principal_registry: Any):
        from .bootstrap_runtime_factory import InstalledBootstrapPolicyResolver
        from .setup_principal import RootSetupPrincipalSelectionRegistry
        if (not isinstance(policy_resolver, InstalledBootstrapPolicyResolver)
                or not isinstance(principal_registry, RootSetupPrincipalSelectionRegistry)):
            raise ValueError("active policy templates require the installed resolver and principal registry")
        self.policy_resolver = policy_resolver
        self.principal_registry = principal_registry


class RootActivePolicyCompilationRegistry:
    """Compile and hold one active-policy publication for a live prepared session.

    The first dependency is the concrete installed root runtime factory rather
    than the lower-level session store: only the factory retains the typed
    ``RootBootstrapSession`` facade and can resolve its live PIDFD-backed
    handle. Its ``session_store`` is checked by identity and is used for the
    primitive journal/proof operations.
    """

    def __init__(self, setup_runtime_factory: Any, verified_policy_template_resolver: Any,
                 runtime_receipt_registry: Any, materialization_receipt_registry: Any,
                 root_journal: Path):
        from .bootstrap_runtime_factory import RootBootstrapRuntimeFactory
        from .setup_principal import RootSetupPrincipalSelectionRegistry
        from .native_output_receipts import RootMaterializationReceiptRegistry
        from .pm_runtime import RootPMRuntimeReceiptRegistry
        if (not isinstance(setup_runtime_factory, RootBootstrapRuntimeFactory)
                or not isinstance(root_journal, Path) or root_journal != _JOURNAL
                or setup_runtime_factory.session_store is None
                or not isinstance(verified_policy_template_resolver, RootActivePolicyTemplateResolver)
                or verified_policy_template_resolver.policy_resolver is not setup_runtime_factory.resolver
                or not isinstance(runtime_receipt_registry, RootPMRuntimeReceiptRegistry)
                or not isinstance(materialization_receipt_registry, RootMaterializationReceiptRegistry)):
            raise ValueError("active compiler requires the concrete root runtime, selected policy, PM and output registries")
        principal_registry = verified_policy_template_resolver.principal_registry
        if not isinstance(principal_registry, RootSetupPrincipalSelectionRegistry):
            raise ValueError("active compiler requires the root-owned adopted-principal registry")
        if (principal_registry.setup_session_store is not setup_runtime_factory.session_store
                or principal_registry.root_journal != root_journal):
            raise ValueError("active compiler principal registry is outside this root setup custody")
        if (getattr(runtime_receipt_registry, "setup_session", None) is not None
                and runtime_receipt_registry.setup_session._factory is not setup_runtime_factory):
            raise ValueError("PM receipt registry belongs to another live root setup factory")
        if getattr(materialization_receipt_registry, "_journal_root", root_journal) != root_journal:
            raise ValueError("native output receipts belong to another authority journal")
        self.factory = setup_runtime_factory
        self.sessions = setup_runtime_factory.session_store
        self.resolver = verified_policy_template_resolver.policy_resolver
        self.template_resolver = verified_policy_template_resolver
        self.runtime_receipts = runtime_receipt_registry
        self.materialization_receipts = materialization_receipt_registry
        self.principal_registry = principal_registry
        self.root_journal = root_journal
        self._claim_root = root_journal / _CLAIM_DIR
        self._seal = object()
        self._claims: dict[str, RootActivePolicyCompilationClaim] = {}
        self._states: dict[str, str] = {}
        self._locks: dict[str, int] = {}

    @classmethod
    def from_root_setup(cls, setup_runtime_factory: Any,
                        verified_policy_template_resolver: Any,
                        runtime_receipt_registry: Any,
                        materialization_receipt_registry: Any,
                        root_journal: Path) -> "RootActivePolicyCompilationRegistry":
        return cls(setup_runtime_factory, verified_policy_template_resolver,
                   runtime_receipt_registry, materialization_receipt_registry,
                   root_journal)

    def compile_active_policy(
            self, setup_session_handle: RootSetupSessionHandle,
            prepared_bundle: Any,
            materialization_receipt_handles: Sequence[str]) -> str:
        self._require_root()
        session = self.factory.resolve_live_session(setup_session_handle)
        prepared = self._verify_prepared_native_bundle(session, prepared_bundle)
        if getattr(self.runtime_receipts, "setup_session", None) is not session:
            raise BootstrapEnrollmentPending("PM runtime registry is not bound to this exact live setup session")
        output_binding = getattr(self.materialization_receipts, "_binding", None)
        if getattr(output_binding, "_session", None) is not session:
            raise BootstrapEnrollmentPending("native output registry is not bound to this exact live setup session")
        session._refresh_authorization()
        runtime_handles = (prepared_bundle.pm_runtime_receipt_handle,)
        output_handles = self._handles(materialization_receipt_handles, "native output receipt")
        if len(runtime_handles) != 1 or not output_handles:
            raise BootstrapEnrollmentPending("active policy compilation requires selected PM runtime and complete native outputs")
        resolved_runtime = tuple(self.runtime_receipts.resolve_runtime(
            handle, session._authorization.transaction_handle, prepared.generation_id)
            for handle in runtime_handles)
        if any(not self._runtime_joins(item, session, prepared) for item in resolved_runtime):
            raise BootstrapEnrollmentPending("PM runtime receipt does not match the current prepared session")

        principal = self.principal_registry.resolve_adopted_initial_principal(
            self.sessions, setup_session_handle)
        principal_handle = getattr(principal, "receipt_id", None)
        if not isinstance(principal_handle, str) or not re.fullmatch(r"[0-9a-f]{64}", principal_handle):
            raise BootstrapEnrollmentPending("adopted principal registry returned an invalid root receipt")
        policy_bytes, catalog_bytes, selection_document, selection_digest = self._compile_documents(session)
        choice_adoptions = self._compile_choice_adoptions(
            session, prepared, selection_document["catalog_sha256"])
        issued = time.monotonic()
        live = self.sessions._live(setup_session_handle)
        expires = min(issued + 120.0, float(live.expires_monotonic))
        if expires <= issued:
            raise BootstrapEnrollmentPending("active policy compilation lease expired")
        publication_handle = secrets.token_urlsafe(36)
        observed_handle = self._mint_actor_observation(session, prepared, expires)
        source_receipt_handles = _ordered_unique_receipt_handles((
            prepared_bundle.hermes_source_receipt_handle,
            prepared_bundle.pm_runtime_receipt_handle,
            prepared_bundle.resources_source_receipt_handle,
            prepared_bundle.resource_profile_selection_receipt_handle,
            prepared_bundle.materialization_receipt_handle,
            *runtime_handles, *output_handles, principal_handle,
            *(handle for row in choice_adoptions
              for handle in row.source_member_receipt_handles)),
            "active source")
        provisional = RootActivePolicyCompilationClaim(
            1, session._authorization.plan_artifact_id,
            session._factory._release.release_commit,
            publication_handle, setup_session_handle.session_id,
            session._authorization.transaction_handle, session._authorization.plan_digest,
            prepared.generation_id, selection_digest, prepared.generation_digest,
            session._policy.artifact_id, session._policy.sha256, principal_handle,
            runtime_handles, output_handles,
            source_receipt_handles,
            _sha(policy_bytes), _sha(catalog_bytes),
            _sha(_canonical(dict(selection_document))), selection_document["catalog_sha256"],
            issued, expires, "0" * 64, policy_bytes, catalog_bytes,
            selection_document, observed_handle, self.root_journal, session,
            "", self._seal, prepared_bundle, choice_adoptions,
        )
        claim_digest = _sha(_canonical(_manifest(provisional)))
        reservation = self.materialization_receipts.reserve_for_active_compilation(
            output_handles, prepared_generation_id=prepared.generation_id,
            publication_handle=publication_handle, claim_digest=claim_digest)
        claim = RootActivePolicyCompilationClaim(
            schema=provisional.schema, plan_artifact_id=provisional.plan_artifact_id,
            release_commit=provisional.release_commit,
            publication_handle=provisional.publication_handle,
            setup_session_id=provisional.setup_session_id,
            transaction_handle=provisional.transaction_handle, plan_sha256=provisional.plan_sha256,
            prepared_generation_id=provisional.prepared_generation_id,
            expected_selection_catalog_sha256=provisional.expected_selection_catalog_sha256,
            expected_service_generation_digest=provisional.expected_service_generation_digest,
            policy_template_artifact_id=provisional.policy_template_artifact_id,
            policy_template_sha256=provisional.policy_template_sha256,
            principal_selection_receipt_handle=provisional.principal_selection_receipt_handle,
            runtime_receipt_handles=provisional.runtime_receipt_handles,
            materialization_receipt_handles=provisional.materialization_receipt_handles,
            source_receipt_handles=provisional.source_receipt_handles,
            compiled_policy_sha256=provisional.compiled_policy_sha256,
            compiled_artifact_catalog_sha256=provisional.compiled_artifact_catalog_sha256,
            compiled_selection_sha256=provisional.compiled_selection_sha256,
            selection_catalog_sha256=provisional.selection_catalog_sha256,
            issued_monotonic=provisional.issued_monotonic,
            expires_monotonic=provisional.expires_monotonic, claim_digest=claim_digest,
            policy_bytes=provisional.policy_bytes,
            artifact_catalog_bytes=provisional.artifact_catalog_bytes,
            selection_document=provisional.selection_document,
            observed_root_receipt_handle=provisional.observed_root_receipt_handle,
            _root_journal_root=provisional._root_journal_root,
            _root_setup_session=provisional._root_setup_session,
            _reservation_handle=reservation.reservation_handle, _seal=self._seal,
            _root_prepared_native_bundle=provisional._root_prepared_native_bundle,
            choice_adoptions=provisional.choice_adoptions,
        )
        # Durable claim record reserves the transaction before the publisher can
        # create any generation. Same-transaction replay remains denied until
        # explicit release or committed active state.
        lock_fd = -1
        state_path = self._claim_root / ("transaction-" + session._authorization.transaction_handle + ".json")
        try:
            _ensure_private_directory(self._claim_root)
            lock_path = self._claim_root / ("transaction-" + session._authorization.transaction_handle + ".lock")
            lock_fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
            os.fchown(lock_fd, 0, 0)
            os.fchmod(lock_fd, 0o600)
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            if state_path.exists():
                state = _read_json(state_path)
                if state.get("state") not in {"released"}:
                    raise BootstrapEnrollmentPending("prepared transaction already has an active policy claim")
            self._persist_claim_bundle(claim)
            record = self._claim_record(claim, "claimed")
            _write_json(state_path, record)
            self._claims[publication_handle] = claim
            self._states[publication_handle] = "claimed"
            self._locks[publication_handle] = lock_fd
            lock_fd = -1
            return publication_handle
        except Exception:
            # If persistence failed after some immutable files were written,
            # remove only artifacts whose names are derived from this fresh
            # unreturned handle. Keep the reservation if durable cleanup itself
            # fails; that is the safe outcome after an uncertain interruption.
            try:
                if state_path.exists():
                    state = _read_json(state_path)
                    if (state.get("publication_handle") == publication_handle
                            and state.get("claim_digest") == claim_digest):
                        state_path.unlink()
                for suffix in (".policy", ".catalog", ".selection", ".claim.json"):
                    path = self._claim_root / (publication_handle + suffix)
                    try:
                        path.unlink()
                    except FileNotFoundError:
                        pass
                if self._claim_root.exists():
                    directory = os.open(self._claim_root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
                    try:
                        os.fsync(directory)
                    finally:
                        os.close(directory)
                self.materialization_receipts.release_active_compilation(
                    reservation.reservation_handle, prepared_generation_id=prepared.generation_id,
                    publication_handle=publication_handle, claim_digest=claim_digest)
            except Exception:
                pass
            raise
        finally:
            if lock_fd >= 0:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
                os.close(lock_fd)

    def claim_active_policy(self, publication_handle: str,
                            expected_selection_catalog_sha256: str | None = None
                            ) -> RootActivePolicyCompilationClaim:
        claim = self._get_claim(publication_handle)
        if expected_selection_catalog_sha256 != claim.expected_selection_catalog_sha256:
            raise BootstrapEnrollmentPending("active policy predecessor does not match the sealed claim")
        self.verify_current_active_policy_claim(claim)
        return claim

    def resolve_current_active_policy_predecessor(self, publication_handle: str) -> str:
        """Return the predecessor only from a fully revalidated retained claim."""
        claim = self._get_claim(publication_handle)
        self.verify_current_active_policy_claim(claim)
        if (not isinstance(claim.expected_selection_catalog_sha256, str)
                or not _HEX.fullmatch(claim.expected_selection_catalog_sha256)):
            raise BootstrapEnrollmentPending("active claim has no canonical predecessor selection digest")
        return claim.expected_selection_catalog_sha256

    def verify_current_active_policy_claim(
            self, claim: RootActivePolicyCompilationClaim) -> RootActivePolicyCompilationClaim:
        if (not isinstance(claim, RootActivePolicyCompilationClaim)
                or claim._seal is not self._seal
                or self._claims.get(claim.publication_handle) is not claim
                or self._states.get(claim.publication_handle) != "claimed"
                or claim.expires_monotonic <= time.monotonic()
                or not secrets.compare_digest(claim.claim_digest, _sha(_canonical(_manifest(claim))))):
            raise BootstrapEnrollmentPending("active policy claim is stale, altered, replayed, or unsealed")
        _validate_claim_output_hashes(claim)
        self._verify_claim_bundle(claim)
        self._verify_choice_projection_seals(claim)
        session = self.factory.resolve_live_session(claim._root_setup_session._handle)
        session._refresh_authorization()
        retained = session._last_receipt
        if retained is None or not isinstance(retained.provision_receipt_handle, str):
            raise BootstrapEnrollmentPending("prepared receipt was lost during active policy compilation")
        prepared = session.resolve_prepared_receipt(retained.provision_receipt_handle)
        self._validate_prepared(session, prepared)
        bundle = claim._root_prepared_native_bundle
        if bundle is None or self._verify_prepared_native_bundle(session, bundle) is not prepared:
            raise BootstrapEnrollmentPending("prepared native bundle changed during active policy publication")
        if (session is not claim._root_setup_session
                or session._handle.session_id != claim.setup_session_id
                or session._authorization.transaction_handle != claim.transaction_handle
                or session._authorization.plan_digest != claim.plan_sha256
                or prepared.generation_id != claim.prepared_generation_id
                or prepared.generation_digest != claim.expected_service_generation_digest):
            raise BootstrapEnrollmentPending("active policy claim no longer matches the live prepared session")
        current = self.resolver._load_selection()
        if current.selection_digest != claim.expected_selection_catalog_sha256:
            raise BootstrapEnrollmentPending("root selection changed during active policy compilation")
        self.principal_registry.resolve_adopted_initial_principal(
            self.sessions, session._handle)
        for handle in claim.runtime_receipt_handles:
            resolved = self.runtime_receipts.resolve_runtime(
                handle, claim.transaction_handle, claim.prepared_generation_id)
            if not self._runtime_joins(resolved, session, prepared):
                raise BootstrapEnrollmentPending("PM runtime closure changed during active policy compilation")
        outputs = self.materialization_receipts.verify_active_compilation(
            claim._reservation_handle, prepared_generation_id=claim.prepared_generation_id,
            publication_handle=claim.publication_handle, claim_digest=claim.claim_digest)
        if {item.receipt_id for item in outputs} != set(claim.materialization_receipt_handles):
            raise BootstrapEnrollmentPending("native output closure changed during active policy compilation")
        self._verify_actor_observation(claim.observed_root_receipt_handle, claim)
        policy_bytes, catalog_bytes, selection, predecessor = self._compile_documents(session)
        if (predecessor != claim.expected_selection_catalog_sha256
                or policy_bytes != claim.policy_bytes or catalog_bytes != claim.artifact_catalog_bytes
                or _canonical(dict(selection)) != _canonical(dict(claim.selection_document))):
            raise BootstrapEnrollmentPending("active policy compiler inputs changed after claim issuance")
        if self._compile_choice_adoptions(session, prepared, claim.selection_catalog_sha256) != claim.choice_adoptions:
            raise BootstrapEnrollmentPending("signed setup-choice projection changed after claim issuance")
        return claim

    def complete_active_publication(self, receipt: Any) -> None:
        from .setup_policy_publication import (
            PolicyPublicationReceiptResolver,
            RootSetupPublicationReceipt,
        )
        if not isinstance(receipt, RootSetupPublicationReceipt):
            raise BootstrapEnrollmentError("active compilation completion requires the typed root publication receipt")
        publication_handle = getattr(receipt, "publication_handle", None)
        claim_digest = getattr(receipt, "claim_digest", None)
        claim = self._get_claim(publication_handle)
        self._verify_postpublication_claim(claim)
        current_receipt = PolicyPublicationReceiptResolver.verify_current_active_claim(
            publication_handle=claim.publication_handle,
            claim_digest=claim.claim_digest,
            prepared_generation_id=claim.prepared_generation_id,
            transaction_handle=claim.transaction_handle,
            expected_materialization_receipt_handles=claim.materialization_receipt_handles,
        )
        if (receipt.state != "active-committed"
                or receipt != current_receipt
                or receipt.transaction_handle != claim.transaction_handle
                or receipt.publication_handle != claim.publication_handle
                or receipt.prepared_generation_id != claim.prepared_generation_id
                or claim_digest != claim.claim_digest
                or receipt.service_generation_digest != claim.expected_service_generation_digest
                or receipt.previous_selection_catalog_sha256 != claim.expected_selection_catalog_sha256
                or receipt.policy_sha256 != claim.compiled_policy_sha256
                or receipt.artifact_catalog_sha256 != claim.compiled_artifact_catalog_sha256
                or receipt.runtime_receipt_handles != claim.runtime_receipt_handles
                or receipt.materialization_receipt_handles != claim.materialization_receipt_handles
                or receipt.input_receipt_handles != _ordered_unique_receipt_handles(
                    (claim.observed_root_receipt_handle, *claim.source_receipt_handles),
                    "published input")):
            raise BootstrapEnrollmentPending("active publication receipt does not bind the compiled claim outputs")
        # Publication is already the atomic externally visible commit. Persist
        # that fact before consuming output capabilities so a later local CAS
        # failure cannot make the selected generation look releasable/replayable.
        self._write_state(claim, "active-committed", receipt.receipt_handle)
        state_path = self._claim_root / ("transaction-" + claim.transaction_handle + ".json")
        state_record = dict(_read_json(state_path))
        state_record["active_selection_catalog_sha256"] = receipt.current_selection_catalog_sha256
        state_record["publication_sha256"] = receipt.publication_sha256
        state_record["descriptor_sha256"] = receipt.descriptor_sha256
        state_record["publication_generation_id"] = receipt.generation_id
        state_record["publication_generation_device"] = receipt.generation_device
        state_record["publication_generation_inode"] = receipt.generation_inode
        _write_json(state_path, state_record)
        self._states[publication_handle] = "active-committed"
        self._close_lock(publication_handle)
        self.materialization_receipts.complete_active_compilation(
            claim._reservation_handle, receipt,
            prepared_generation_id=claim.prepared_generation_id,
            publication_handle=claim.publication_handle, claim_digest=claim.claim_digest)

    def release_active_policy(self, publication_handle: str) -> None:
        claim = self._get_claim(publication_handle)
        if self._states.get(publication_handle) in {"released", "active-committed"}:
            return
        if self._states.get(publication_handle) != "claimed":
            raise BootstrapEnrollmentPending("only an uncommitted active policy claim can be released")
        self.materialization_receipts.release_active_compilation(
            claim._reservation_handle, prepared_generation_id=claim.prepared_generation_id,
            publication_handle=claim.publication_handle, claim_digest=claim.claim_digest)
        self._write_state(claim, "released", None)
        self._states[publication_handle] = "released"
        self._close_lock(publication_handle)

    def resolve_active_state(self, setup_session_handle: RootSetupSessionHandle) -> Mapping[str, Any]:
        from .setup_policy_publication import PolicyPublicationReceiptResolver
        session = self.factory.resolve_live_session(setup_session_handle)
        transaction_handle = session._authorization.transaction_handle
        path = self._claim_root / ("transaction-" + transaction_handle + ".json")
        row = _read_json(path)
        if row.get("state") != "active-committed":
            raise BootstrapEnrollmentPending("active policy publication is not committed for this transaction")
        handles = row.get("materialization_receipt_handles")
        if not isinstance(handles, list) or not handles:
            raise BootstrapEnrollmentPending("active policy journal lacks its native output receipt closure")
        receipt = PolicyPublicationReceiptResolver.verify_current_active_claim(
            publication_handle=row.get("publication_handle"),
            claim_digest=row.get("claim_digest"),
            prepared_generation_id=row.get("prepared_generation_id"),
            transaction_handle=transaction_handle,
            expected_materialization_receipt_handles=tuple(handles),
        )
        if (receipt.state != "active-committed"
                or receipt.current_selection_catalog_sha256 != row.get("active_selection_catalog_sha256")
                or receipt.publication_sha256 != row.get("publication_sha256")
                or receipt.descriptor_sha256 != row.get("descriptor_sha256")
                or receipt.generation_id != row.get("publication_generation_id")
                or receipt.generation_device != row.get("publication_generation_device")
                or receipt.generation_inode != row.get("publication_generation_inode")):
            raise BootstrapEnrollmentPending("active policy journal differs from the current selected publication")
        return row

    def _compile_documents(self, session: Any) -> tuple[bytes, bytes, dict[str, Any], str]:
        # Re-read and revalidate the exact current loader inputs. This avoids
        # serializing caller objects or reconstructing source facts from IDs.
        path = self.resolver.selection_path
        # The fixed root selection has its own secure reader; release-file
        # readers are only used for the pinned policy and catalog artifacts.
        from .bootstrap_runtime_factory import _read_secure_root_bytes
        raw = _read_secure_root_bytes(path, _MAX_DOCUMENT, 0o600)
        current_doc = self.resolver._json(raw, "current active selection")
        current = self.resolver._load_selection()
        if (not isinstance(current_doc, dict) or raw != _canonical(current_doc)
                or current_doc.get("catalog_sha256") != current.selection_digest
                or current_doc.get("installer_release_commit") != session._factory._release.release_commit):
            raise BootstrapEnrollmentPending("current root selection changed or differs from the verified release")
        policy_rows = [row for row in current.bootstrap_policies
                       if row.get("artifact_id") == "installer-bootstrap-policy-v1"]
        if len(policy_rows) != 1:
            raise BootstrapEnrollmentPending("current root policy selection is absent or ambiguous")
        policy_row = policy_rows[0]
        policy_fd = self.resolver._open_policy_generation(current)
        try:
            policy_path = self.resolver._verified_relative(
                policy_row, "installer-bootstrap-policy-v1", current.policy_root, policy_fd)
        finally:
            os.close(policy_fd)
        policy_bytes = self.resolver._read_release_file(
            policy_path, maximum=_MAX_DOCUMENT, expected_sha256=policy_row["sha256"])
        policy_doc = self.resolver._json(policy_bytes, "current selected bootstrap policy")
        if policy_bytes != _canonical(policy_doc):
            raise BootstrapEnrollmentPending("current selected policy bytes are not canonical")
        verified_policy = self.resolver.resolve_policy(session._authorization.plan_artifact_id)
        if (verified_policy.artifact_id != policy_row["artifact_id"]
                or verified_policy.sha256 != policy_row["sha256"]
                or verified_policy != session._policy):
            raise BootstrapEnrollmentPending("live setup policy differs from the selected strict policy bytes")
        from .bootstrap_enrollment import _open_immutable_release_root
        release_fd = _open_immutable_release_root(
            current.release_root, current.release_device, current.release_inode)
        try:
            catalog_path = self.resolver._verified_relative(
                current.artifact_catalog, "installer-protected-artifact-catalog-v1",
                Path(current.release_root), release_fd)
        finally:
            os.close(release_fd)
        catalog_bytes = self.resolver._read_release_file(
            catalog_path, maximum=_MAX_DOCUMENT, expected_sha256=current.artifact_catalog["sha256"])
        catalog_doc = self.resolver._json(catalog_bytes, "current artifact catalog")
        if catalog_bytes != _canonical(catalog_doc):
            raise BootstrapEnrollmentPending("current artifact catalog bytes are not canonical")

        selection = {key: value for key, value in current_doc.items()
                     if key not in {"policy_generation", "catalog_sha256"}}
        selection["artifact_catalog"] = dict(current_doc["artifact_catalog"])
        selection["artifact_catalog"]["relative_path"] = "catalog/artifacts.json"
        selection["bootstrap_policies"] = [dict(row) for row in current_doc["bootstrap_policies"]]
        for row in selection["bootstrap_policies"]:
            if row["artifact_id"] == "installer-bootstrap-policy-v1":
                row["relative_path"] = "plans/bootstrap-policy-v1.json"
                row["sha256"] = _sha(policy_bytes)
        unsigned_digest = _sha(_canonical(selection))
        selection["catalog_sha256"] = unsigned_digest
        return policy_bytes, catalog_bytes, selection, current.selection_digest

    def _compile_choice_adoptions(
            self, session: Any, prepared: EnrollmentReceipt,
            selection_catalog_sha256: str) -> tuple[ActiveSetupChoiceProjection, ...]:
        """Project only current signed choices retained by the root registry."""
        from .root_setup_choices import RootSetupChoiceRegistry, RootSetupChoiceSnapshot

        binding = session.selected_installation
        registry = binding.resolve_setup_choice_registry()
        if type(registry) is not RootSetupChoiceRegistry:
            raise BootstrapEnrollmentPending("current setup has no concrete root signed-choice registry")
        snapshots = registry.resolve_current_session_choices(binding)
        if not isinstance(snapshots, tuple) or len(snapshots) > len(_SETUP_CHOICE_PURPOSES):
            raise BootstrapEnrollmentPending("root setup-choice registry returned an unbounded choice set")

        identity = binding.resolve_current_setup_identity()
        principal_selector = binding.resolve_adopted_principal_selector()
        namespace_selector = binding.resolve_adopted_namespace_selector()
        session_handle = binding.resolve_current_setup_session_handle()
        release = session._factory._release
        release.verify_current()
        release_digest = getattr(release, "deployment_receipt_sha256", None)
        principal_id = getattr(identity.principal, "principal_id", None)
        namespace_id = getattr(identity.namespace, "namespace_id", None)
        if (getattr(identity, "expires_monotonic", 0) <= time.monotonic()
                or identity.principal_selection_handle != principal_selector.selection_handle
                or identity.namespace_selection_handle != namespace_selector.selection_handle
                or principal_selector.setup_session_id != session_handle.session_id
                or namespace_selector.setup_session_id != session_handle.session_id
                or principal_selector.transaction_handle != session._authorization.transaction_handle
                or namespace_selector.transaction_handle != session._authorization.transaction_handle
                or principal_selector.plan_sha256 != session._authorization.plan_digest
                or namespace_selector.plan_sha256 != session._authorization.plan_digest
                or namespace_selector.prepared_generation_id != prepared.generation_id
                or namespace_selector.prepared_generation_digest != prepared.generation_digest
                or not isinstance(release_digest, str) or not _HEX.fullmatch(release_digest)
                or not isinstance(principal_id, str) or not principal_id
                or not isinstance(namespace_id, str) or not namespace_id):
            raise BootstrapEnrollmentPending("fresh setup identity does not match active choice projection")

        projections: list[ActiveSetupChoiceProjection] = []
        for snapshot in snapshots:
            if type(snapshot) is not RootSetupChoiceSnapshot:
                raise BootstrapEnrollmentPending("choice registry returned an untyped signed choice")
            purpose = snapshot.purpose
            if purpose not in _SETUP_CHOICE_PURPOSES:
                raise BootstrapEnrollmentPending("signed setup choice purpose is outside the finite contract")
            payload = dict(snapshot.choice_payload)
            expected = {
                "setup_session_handle": session_handle.session_id,
                "transaction_handle": session._authorization.transaction_handle,
                "plan_id": session._authorization.plan_artifact_id,
                "prepared_generation": prepared.generation_id,
                "principal_selection_handle": principal_selector.selection_handle,
                "namespace_selection_handle": namespace_selector.selection_handle,
                "principal_id": principal_id,
                "namespace_id": namespace_id,
                "principal_binding_sha256": principal_selector.binding_sha256,
                "namespace_binding_sha256": namespace_selector.binding_sha256,
                "release_deployment_receipt_sha256": release_digest,
            }
            if any(getattr(snapshot, name, None) != value for name, value in expected.items()):
                raise BootstrapEnrollmentPending("signed setup choice belongs to another active subject or generation")
            if (not isinstance(snapshot.selection_handle, str)
                    or not _HANDLE.fullmatch(snapshot.selection_handle)
                    or not isinstance(snapshot.key_id, str)
                    or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", snapshot.key_id)
                    or not _HEX.fullmatch(snapshot.signed_record_sha256)
                    or not _HEX.fullmatch(snapshot.choice_payload_sha256)
                    or snapshot.choice_payload_sha256 != _sha(_canonical(payload))
                    or type(snapshot.choice_epoch) is not int or snapshot.choice_epoch < 1
                    or type(snapshot.revocation_epoch) is not int or snapshot.revocation_epoch != 1
                    or type(snapshot.issued_at_unix) not in (int, float)
                    or type(snapshot.setup_deadline_unix) not in (int, float)
                    or snapshot.issued_at_unix >= snapshot.setup_deadline_unix
                    or snapshot.adoption_publication_receipt_handle is not None):
                raise BootstrapEnrollmentPending("signed setup choice digest, epoch, or lease is invalid")
            if (not isinstance(snapshot.source_member_receipt_handles, tuple)
                    or not snapshot.source_member_receipt_handles
                    or len(set(snapshot.source_member_receipt_handles)) != len(snapshot.source_member_receipt_handles)
                    or any(not isinstance(handle, str) or not _HANDLE.fullmatch(handle)
                           for handle in snapshot.source_member_receipt_handles)):
                raise BootstrapEnrollmentPending("signed setup choice source receipt closure is invalid")

            private_profile_id: str | None = None
            if snapshot.private_profile_selection_handle is not None:
                if purpose not in {"memory-service-enablement", "existing-model-selection"}:
                    raise BootstrapEnrollmentPending("choice purpose cannot use a private profile selector")
                private_profile = binding.resolve_current_private_profile(
                    snapshot.private_profile_selection_handle, purpose)
                private_profile_id = getattr(private_profile, "profile_id", None)
                if not isinstance(private_profile_id, str) or not private_profile_id:
                    raise BootstrapEnrollmentPending("current private profile selector has no profile identity")

            if purpose == "memory-service-enablement":
                profile_id = payload.get("profile_id")
                if (private_profile_id is None or profile_id != private_profile_id
                        or not isinstance(payload.get("enabled"), bool)):
                    raise BootstrapEnrollmentPending("memory choice profile differs from its current private selection")
            elif purpose == "existing-model-selection":
                profile_id = payload.get("profile_id", private_profile_id)
                if private_profile_id is None or profile_id != private_profile_id:
                    raise BootstrapEnrollmentPending("model choice profile differs from its current private selection")
            elif purpose == "native-policy-preparation":
                profile_id = payload.get("service_profile_id")
                if (not isinstance(profile_id, str)
                        or profile_id != getattr(identity.principal, "service_profile_id", None)):
                    raise BootstrapEnrollmentPending("native policy choice profile differs from the current principal")
            elif purpose == "application-qualification":
                profile_id = payload.get("target_profile_id")
                if (not isinstance(profile_id, str)
                        or profile_id != getattr(identity.namespace, "target_profile_id", None)):
                    raise BootstrapEnrollmentPending("application choice profile differs from the current namespace")
            else:
                # The signed choice registry may eventually issue the other
                # v143 purposes, but each needs a dedicated typed selector join
                # before it can enter a published generation.
                raise BootstrapEnrollmentPending("setup-choice purpose has no installed root profile join")
            if (not isinstance(profile_id, str) or not profile_id
                    or profile_id != principal_selector.service_profile_id
                    or profile_id != namespace_selector.target_profile_id):
                raise BootstrapEnrollmentPending("signed setup choice profile differs from current principal/namespace selectors")

            projections.append(ActiveSetupChoiceProjection(
                selection_handle=snapshot.selection_handle,
                purpose=purpose,
                key_id=snapshot.key_id,
                signed_record_sha256=snapshot.signed_record_sha256,
                choice_payload_sha256=snapshot.choice_payload_sha256,
                choice_epoch=snapshot.choice_epoch,
                revocation_epoch=snapshot.revocation_epoch,
                issued_at_unix=snapshot.issued_at_unix,
                setup_deadline_unix=snapshot.setup_deadline_unix,
                release_deployment_receipt_sha256=snapshot.release_deployment_receipt_sha256,
                setup_session_handle=snapshot.setup_session_handle,
                transaction_handle=snapshot.transaction_handle,
                plan_id=snapshot.plan_id,
                prepared_generation=snapshot.prepared_generation,
                principal_selection_handle=snapshot.principal_selection_handle,
                namespace_selection_handle=snapshot.namespace_selection_handle,
                private_profile_selection_handle=snapshot.private_profile_selection_handle,
                source_member_receipt_handles=tuple(sorted(snapshot.source_member_receipt_handles)),
                principal_id=principal_id,
                profile_id=profile_id,
                namespace_id=namespace_id,
                principal_binding_sha256=principal_selector.binding_sha256,
                namespace_binding_sha256=namespace_selector.binding_sha256,
                service_generation_id=prepared.generation_id,
                service_generation_digest=prepared.generation_digest,
                selection_catalog_sha256=selection_catalog_sha256,
                _compiler_seal=self._seal,
            ))
        projections.sort(key=lambda row: (row.purpose, row.selection_handle))
        return tuple(projections)

    def _verify_choice_projection_seals(self, claim: RootActivePolicyCompilationClaim) -> None:
        rows = claim.choice_adoptions
        if (not isinstance(rows, tuple) or len(rows) > len(_SETUP_CHOICE_PURPOSES)
                or any(type(row) is not ActiveSetupChoiceProjection
                       or row._compiler_seal is not self._seal
                       or row.selection_catalog_sha256 != claim.selection_catalog_sha256
                       or row.service_generation_id != claim.prepared_generation_id
                       or row.service_generation_digest != claim.expected_service_generation_digest
                       for row in rows)
                or rows != tuple(sorted(rows, key=lambda row: (row.purpose, row.selection_handle)))):
            raise BootstrapEnrollmentPending("active setup-choice projection is stale, altered, or unsealed")

    def _mint_actor_observation(self, session: Any, prepared: EnrollmentReceipt,
                                expires: float) -> str:
        session._check_live()
        session._factory._actor.verify_current(session._factory._release)
        handle = secrets.token_hex(32)
        _ensure_private_directory(self._claim_root)
        actor = session._authorization.root_actor_identity
        actor_digest = _sha(_canonical(dict(actor)))
        _write_json(self._claim_root / ("actor-" + handle + ".json"), {
            "schema": 1, "receipt_handle": handle,
            "setup_session_id": session._handle.session_id,
            "transaction_handle": session._authorization.transaction_handle,
            "plan_sha256": session._authorization.plan_digest,
            "prepared_generation_id": prepared.generation_id,
            "prepared_generation_digest": prepared.generation_digest,
            "actor_identity_sha256": actor_digest,
            "issued_monotonic": time.monotonic(), "expires_monotonic": expires,
        }, exclusive=True)
        return handle

    def _verify_actor_observation(self, handle: str,
                                  claim: RootActivePolicyCompilationClaim) -> None:
        if not isinstance(handle, str) or not re.fullmatch(r"[0-9a-f]{64}", handle):
            raise BootstrapEnrollmentPending("root actor observation handle is malformed")
        row = _read_json(self._claim_root / ("actor-" + handle + ".json"))
        session = claim._root_setup_session
        session._check_live()
        session._factory._actor.verify_current(session._factory._release)
        expected = {
            "schema": 1, "receipt_handle": handle,
            "setup_session_id": claim.setup_session_id,
            "transaction_handle": claim.transaction_handle,
            "plan_sha256": claim.plan_sha256,
            "prepared_generation_id": claim.prepared_generation_id,
            "prepared_generation_digest": claim.expected_service_generation_digest,
            "actor_identity_sha256": _sha(_canonical(dict(session._authorization.root_actor_identity))),
        }
        if (any(row.get(key) != value for key, value in expected.items())
                or row.get("expires_monotonic", 0) <= time.monotonic()
                or row.get("expires_monotonic") != claim.expires_monotonic):
            raise BootstrapEnrollmentPending("root actor observation receipt is stale or mismatched")

    def _validate_prepared(self, session: Any, receipt: EnrollmentReceipt) -> None:
        live = self.sessions._live(session._handle)
        proof = self.sessions._proof(live)
        if (not isinstance(receipt, EnrollmentReceipt) or receipt.state != "prepared"
                or receipt.enrollment_ids or receipt.setup_session_id != proof.setup_session_id
                or receipt.transaction_handle != proof.transaction_handle
                or receipt.plan_digest != proof.plan_digest
                or receipt.generation_digest is None or not _HEX.fullmatch(receipt.generation_digest)
                or receipt.expires_monotonic <= time.monotonic()):
            raise BootstrapEnrollmentPending("active policy compiler requires the live empty prepared-generation receipt")
        committed = self.sessions.verify_committed_receipt(receipt, proof)
        if (not isinstance(committed, VerifiedCommittedEnrollment)
                or committed.receipt != receipt
                or committed.setup_session_id != proof.setup_session_id
                or committed.plan_digest != proof.plan_digest):
            raise BootstrapEnrollmentPending("prepared receipt is not the exact durable root commit")

    def _verify_prepared_native_bundle(self, session: Any, bundle: Any) -> EnrollmentReceipt:
        """Use the factory's typed currentness resolver for the prepared bundle."""
        from .bootstrap_runtime_factory import RootPreparedNativeBundle
        if (type(bundle) is not RootPreparedNativeBundle
                or not isinstance(getattr(bundle, "_session_seal", None), str)
                or not secrets.compare_digest(bundle._session_seal, session._seal)):
            raise BootstrapEnrollmentPending("active compilation requires the root-prepared native bundle")
        session._check_live()
        session._refresh_authorization()
        retained = session._last_receipt
        if (not isinstance(retained, EnrollmentReceipt) or retained.state != "prepared"
                or not retained.provision_receipt_handle or retained.enrollment_ids):
            raise BootstrapEnrollmentPending("prepared native bundle no longer has an empty current generation")
        prepared = session.resolve_prepared_receipt(retained.provision_receipt_handle)
        self._validate_prepared(session, prepared)
        current = session.selected_installation.resolve_current_prepared_native_bundle(bundle)
        if (current is not bundle
                or (bundle.setup_session_id, bundle.transaction_handle,
                    bundle.prepared_generation_id, bundle.prepared_generation_digest)
                != (session._handle.session_id, session._authorization.transaction_handle,
                    prepared.generation_id, prepared.generation_digest)):
            raise BootstrapEnrollmentPending("prepared native bundle belongs to another setup transaction")
        pm_runtime = session.selected_installation.resolve_current_pm_runtime()
        if (getattr(pm_runtime, "receipt_handle", None) != bundle.pm_runtime_receipt_handle
                or getattr(pm_runtime, "prepared_generation_id", None) != prepared.generation_id
                or getattr(pm_runtime, "transaction_handle", None) != session._authorization.transaction_handle):
            raise BootstrapEnrollmentPending("prepared native bundle PM receipt is stale")
        source = session.selected_installation.resolve_current_hermes_source()
        if getattr(source, "receipt_handle", None) != bundle.hermes_source_receipt_handle:
            raise BootstrapEnrollmentPending("prepared native bundle Hermes source receipt is stale")
        return prepared

    def _verify_postpublication_claim(self,
                                      claim: RootActivePolicyCompilationClaim) -> None:
        if (not isinstance(claim, RootActivePolicyCompilationClaim)
                or claim._seal is not self._seal
                or self._claims.get(claim.publication_handle) is not claim
                or self._states.get(claim.publication_handle) != "claimed"
                or claim.expires_monotonic <= time.monotonic()
                or not secrets.compare_digest(claim.claim_digest, _sha(_canonical(_manifest(claim))))):
            raise BootstrapEnrollmentPending("active policy claim is stale, altered, replayed, or unsealed")
        _validate_claim_output_hashes(claim)
        self._verify_claim_bundle(claim)
        session = self.factory.resolve_live_session(claim._root_setup_session._handle)
        session._refresh_authorization()
        retained = session._last_receipt
        if (retained is None or not isinstance(retained.provision_receipt_handle, str)):
            raise BootstrapEnrollmentPending("prepared receipt was lost after active publication")
        prepared = session.resolve_prepared_receipt(retained.provision_receipt_handle)
        self._validate_prepared(session, prepared)
        bundle = claim._root_prepared_native_bundle
        if bundle is None or self._verify_prepared_native_bundle(session, bundle) is not prepared:
            raise BootstrapEnrollmentPending("prepared native bundle changed after active publication")
        if (session is not claim._root_setup_session
                or session._authorization.transaction_handle != claim.transaction_handle
                or session._authorization.plan_digest != claim.plan_sha256
                or prepared.generation_id != claim.prepared_generation_id
                or prepared.generation_digest != claim.expected_service_generation_digest):
            raise BootstrapEnrollmentPending("active publication no longer joins the prepared setup session")
        self._verify_choice_projection_seals(claim)
        if self._compile_choice_adoptions(session, prepared, claim.selection_catalog_sha256) != claim.choice_adoptions:
            raise BootstrapEnrollmentPending("signed setup-choice projection changed during active publication")
        self.principal_registry.resolve_adopted_initial_principal(self.sessions, session._handle)
        self._verify_actor_observation(claim.observed_root_receipt_handle, claim)
        for handle in claim.runtime_receipt_handles:
            runtime = self.runtime_receipts.resolve_runtime(
                handle, claim.transaction_handle, claim.prepared_generation_id)
            if not self._runtime_joins(runtime, session, prepared):
                raise BootstrapEnrollmentPending("PM runtime receipt changed after active publication")
        outputs = self.materialization_receipts.verify_active_compilation(
            claim._reservation_handle, prepared_generation_id=claim.prepared_generation_id,
            publication_handle=claim.publication_handle, claim_digest=claim.claim_digest)
        if {item.receipt_id for item in outputs} != set(claim.materialization_receipt_handles):
            raise BootstrapEnrollmentPending("native output reservation changed after active publication")

    @staticmethod
    def _runtime_joins(receipt: Any, session: Any, prepared: EnrollmentReceipt) -> bool:
        return (getattr(receipt, "setup_session_id", None) == session._handle.session_id
                and getattr(receipt, "transaction_handle", None) == session._authorization.transaction_handle
                and getattr(receipt, "prepared_generation_id", None) == prepared.generation_id
                and getattr(receipt, "source_artifact_id", None) == session._policy.source_artifact_id
                and getattr(receipt, "expires_monotonic", 0) > time.monotonic())

    @staticmethod
    def _handles(values: Sequence[str], label: str) -> tuple[str, ...]:
        if (not isinstance(values, (tuple, list)) or not values or len(values) > 128
                or any(not isinstance(item, str) or not _HANDLE.fullmatch(item) for item in values)
                or len(set(values)) != len(values)):
            raise BootstrapEnrollmentError(f"{label} handles are malformed or duplicated")
        return tuple(sorted(values))

    def _get_claim(self, handle: str) -> RootActivePolicyCompilationClaim:
        if not isinstance(handle, str) or not _HANDLE.fullmatch(handle):
            raise BootstrapEnrollmentError("active policy publication handle is malformed")
        claim = self._claims.get(handle)
        if claim is None:
            raise BootstrapEnrollmentPending("active policy compilation claim is absent or belongs to another registry")
        return claim

    @staticmethod
    def _claim_record(claim: RootActivePolicyCompilationClaim, state: str,
                      publication_receipt_handle: str | None = None) -> dict[str, Any]:
        return {"schema": 1, "publication_handle": claim.publication_handle,
                "claim_digest": claim.claim_digest, "transaction_handle": claim.transaction_handle,
                "setup_session_id": claim.setup_session_id,
                "prepared_generation_id": claim.prepared_generation_id,
                "expected_selection_catalog_sha256": claim.expected_selection_catalog_sha256,
                "expected_service_generation_digest": claim.expected_service_generation_digest,
                "policy_sha256": claim.compiled_policy_sha256,
                "artifact_catalog_sha256": claim.compiled_artifact_catalog_sha256,
                "selection_sha256": claim.compiled_selection_sha256,
                "selection_catalog_sha256": claim.selection_catalog_sha256,
                "observed_root_receipt_handle": claim.observed_root_receipt_handle,
                "principal_selection_receipt_handle": claim.principal_selection_receipt_handle,
                "runtime_receipt_handles": list(claim.runtime_receipt_handles),
                "materialization_receipt_handles": list(claim.materialization_receipt_handles),
                "publication_receipt_handle": publication_receipt_handle,
                "issued_monotonic": claim.issued_monotonic,
                "expires_monotonic": claim.expires_monotonic,
                "state": state}

    def _persist_claim_bundle(self, claim: RootActivePolicyCompilationClaim) -> None:
        prefix = self._claim_root / claim.publication_handle
        selection_bytes = _canonical(dict(claim.selection_document))
        self._write_immutable_bytes(prefix.with_suffix(".policy"), claim.policy_bytes)
        self._write_immutable_bytes(prefix.with_suffix(".catalog"), claim.artifact_catalog_bytes)
        self._write_immutable_bytes(prefix.with_suffix(".selection"), selection_bytes)
        _write_json(prefix.with_suffix(".claim.json"), {
            "schema": 1,
            "publication_handle": claim.publication_handle,
            "claim_digest": claim.claim_digest,
            "manifest": _manifest(claim),
            "policy_sha256": claim.compiled_policy_sha256,
            "artifact_catalog_sha256": claim.compiled_artifact_catalog_sha256,
            "selection_sha256": claim.compiled_selection_sha256,
        }, exclusive=True)

    def _verify_claim_bundle(self, claim: RootActivePolicyCompilationClaim) -> None:
        prefix = self._claim_root / claim.publication_handle
        policy = _read_immutable_bytes(prefix.with_suffix(".policy"))
        catalog = _read_immutable_bytes(prefix.with_suffix(".catalog"))
        selection = _read_immutable_bytes(prefix.with_suffix(".selection"))
        record = _read_json(prefix.with_suffix(".claim.json"))
        expected = {
            "schema": 1, "publication_handle": claim.publication_handle,
            "claim_digest": claim.claim_digest, "manifest": _manifest(claim),
            "policy_sha256": _sha(policy), "artifact_catalog_sha256": _sha(catalog),
            "selection_sha256": _sha(selection),
        }
        if (policy != claim.policy_bytes or catalog != claim.artifact_catalog_bytes
                or selection != _canonical(dict(claim.selection_document)) or record != expected):
            raise BootstrapEnrollmentPending("durable active compilation claim or output bytes changed")

    def _write_state(self, claim: RootActivePolicyCompilationClaim, state: str,
                     publication_receipt_handle: str | None) -> None:
        path = self._claim_root / ("transaction-" + claim.transaction_handle + ".json")
        prior = _read_json(path)
        if (prior.get("publication_handle") != claim.publication_handle
                or prior.get("claim_digest") != claim.claim_digest
                or prior.get("state") != "claimed"):
            raise BootstrapEnrollmentPending("durable active policy claim state changed")
        _write_json(path, self._claim_record(claim, state, publication_receipt_handle))

    def _close_lock(self, handle: str) -> None:
        fd = self._locks.pop(handle, None)
        if fd is not None:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    @staticmethod
    def _require_root() -> None:
        if os.geteuid() != 0 or os.getuid() != 0 or not sys_platform_linux():
            raise BootstrapEnrollmentPending("active policy compilation requires installed Linux root authority")


def sys_platform_linux() -> bool:
    import sys
    return sys.platform.startswith("linux") and Path("/proc/sys/kernel/ostype").exists()
