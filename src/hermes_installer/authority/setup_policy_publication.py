"""Root-owned immutable publication of compiled first-stage policy generations.

The compiler supplies canonical bytes and opaque, transaction-bound handles.
This module owns filesystem publication and the final selection CAS. No input
path, policy row, file digest, or receipt is accepted from a worker request.
"""
from __future__ import annotations

import fcntl
import ctypes
import errno
import hashlib
import json
import math
import os
import re
import secrets
import stat
import sys
import time
from dataclasses import dataclass, field, replace as dataclass_replace
from pathlib import Path
from typing import TYPE_CHECKING, Any, Mapping

from .bootstrap_enrollment import BootstrapEnrollmentError, BootstrapEnrollmentPending

if TYPE_CHECKING:
    from .bootstrap_runtime_factory import CompiledRootSetupPublication


POLICY_GENERATIONS = Path("/var/lib/hermes-installer/policy-generations")
SELECTION_PATH = Path("/etc/hermes-installer/root-setup-selection.json")
POLICY_GENERATION_ID = "installer-bootstrap-policy-generation-v1"
POLICY_ARTIFACT_ID = "installer-bootstrap-policy-v1"
CATALOG_ARTIFACT_ID = "installer-protected-artifact-catalog-v1"
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_HANDLE = re.compile(r"[A-Za-z0-9_-]{32,128}\Z")
_GENERATION_NAME = re.compile(r"[A-Za-z0-9_.:-]{1,128}\Z")
_CHOICE_PURPOSES = frozenset({
    "memory-service-enablement", "memory-capture-configuration", "private-input-routes",
    "public-free-web-read", "existing-model-selection", "native-policy-preparation",
    "application-qualification",
})
_MAX_FILE = 16 * 1024 * 1024
_SEAL = object()
_CHOICE_ADOPTION_FIELDS = (
    "selection_handle", "purpose", "key_id", "signed_record_sha256",
    "choice_payload_sha256", "choice_epoch", "revocation_epoch", "issued_at_unix",
    "setup_deadline_unix", "adopted_at_unix", "release_deployment_receipt_sha256", "setup_session_handle",
    "transaction_handle", "plan_id", "prepared_generation", "principal_selection_handle",
    "namespace_selection_handle", "private_profile_selection_handle",
    "source_member_receipt_handles", "principal_id", "profile_id", "namespace_id",
    "principal_binding_sha256", "namespace_binding_sha256", "service_generation_id",
    "service_generation_digest", "selection_catalog_sha256", "publication_receipt_handle",
    "publication_sha256", "generation_id",
)
_CHOICE_PROJECTION_FIELDS = tuple(
    name for name in _CHOICE_ADOPTION_FIELDS
    if name not in {"adopted_at_unix", "publication_receipt_handle", "publication_sha256", "generation_id"}
)


def _expected_gid(uid: int) -> int:
    return 0 if uid == 0 else os.getgid()


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json_bytes(data: bytes, label: str, *, canonical: bool = True) -> Any:
    if not isinstance(data, bytes) or not data or len(data) > _MAX_FILE:
        raise BootstrapEnrollmentError(f"compiled {label} bytes are empty or oversized")
    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=_unique_pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (UnicodeError, ValueError, json.JSONDecodeError):
        raise BootstrapEnrollmentError(f"compiled {label} is not strict UTF-8 JSON") from None
    if canonical and _canonical(value) != data:
        raise BootstrapEnrollmentError(f"compiled {label} is not canonical JSON")
    return value


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


@dataclass(frozen=True, slots=True, repr=False)
class PublishedSetupChoiceAdoption:
    """Publisher-sealed proof that one signed setup choice entered this active generation."""

    selection_handle: str
    purpose: str
    key_id: str
    signed_record_sha256: str
    choice_payload_sha256: str
    choice_epoch: int
    revocation_epoch: int
    issued_at_unix: float
    setup_deadline_unix: float
    adopted_at_unix: float
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
    publication_receipt_handle: str
    publication_sha256: str
    generation_id: str
    _seal: object = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._seal is not _SEAL:
            raise TypeError("published setup choice adoptions are minted by the root publisher")
        object.__setattr__(self, "source_member_receipt_handles",
                           tuple(self.source_member_receipt_handles))

    def verify_current(self, root_setup_choice_registry: Any) -> "PublishedSetupChoiceAdoption":
        """Revalidate both the active publisher projection and its signed source row.

        The source registry must be the exact root runtime/setup choice registry
        already attached to the composing authority. A caller-provided verifier
        callback or a policy-generation-only match is insufficient.
        """
        from .root_setup_choices import RootSetupChoiceRegistry
        if type(root_setup_choice_registry) is not RootSetupChoiceRegistry:
            raise BootstrapEnrollmentPending("current root setup choice registry is required")
        current = PolicyPublicationReceiptResolver.resolve_current_choice_adoption(
            self.selection_handle)
        if _choice_adoption_value(current) != _choice_adoption_value(self):
            raise BootstrapEnrollmentPending("published setup choice is no longer in the active generation")
        verifier = getattr(root_setup_choice_registry, "verify_published_adoption_current", None)
        if not callable(verifier):
            raise BootstrapEnrollmentPending("root setup choice source-currentness verifier is unavailable")
        verifier(self)
        return self

    def __repr__(self) -> str:
        return "PublishedSetupChoiceAdoption(<root-private>)"


@dataclass(frozen=True, slots=True, repr=False)
class RootSetupPublicationReceipt:
    schema: int
    receipt_handle: str
    transaction_handle: str
    generation_id: str
    publication_sha256: str
    generation_root: Path
    generation_device: int
    generation_inode: int
    policy_sha256: str
    artifact_catalog_sha256: str
    selection_sha256: str
    descriptor_sha256: str
    previous_selection_catalog_sha256: str | None
    current_selection_catalog_sha256: str
    input_receipt_handles: tuple[str, ...]
    state: str
    _seal: object = field(default=None, repr=False, compare=False)
    publication_handle: str | None = None
    claim_digest: str | None = None
    prepared_generation_id: str | None = None
    service_generation_digest: str | None = None
    runtime_receipt_handles: tuple[str, ...] = ()
    materialization_receipt_handles: tuple[str, ...] = ()
    choice_adoptions: tuple[PublishedSetupChoiceAdoption, ...] = ()
    owner_overlay_adoption_records: tuple[Mapping[str, Any], ...] = ()
    owner_overlay_observer_records: tuple[Mapping[str, Any], ...] = ()

    def __post_init__(self) -> None:
        if self._seal is not _SEAL:
            raise TypeError("root setup publication receipts are minted by the publisher")
        object.__setattr__(self, "choice_adoptions", tuple(self.choice_adoptions))
        object.__setattr__(self, "owner_overlay_adoption_records",
                           tuple(dict(row) for row in self.owner_overlay_adoption_records))
        object.__setattr__(self, "owner_overlay_observer_records",
                           tuple(dict(row) for row in self.owner_overlay_observer_records))


class RootSetupPolicyGenerationPublisher:
    """Publish an immutable generation, then atomically CAS root selection."""

    def __init__(self, release: Any, session_store: Any, root_journal: Any,
                 compiler_publication_registry: Any):
        from .bootstrap_runtime_factory import RootInitialCompilationRegistry
        from .active_policy_compiler import RootActivePolicyCompilationRegistry
        if not isinstance(compiler_publication_registry,
                          (RootInitialCompilationRegistry, RootActivePolicyCompilationRegistry)):
            raise ValueError("typed initial or active policy compilation registry is required")
        self.release = release
        self.session_store = session_store
        self.root_journal = root_journal
        self.registry = compiler_publication_registry
        self._active = isinstance(compiler_publication_registry, RootActivePolicyCompilationRegistry)

    @classmethod
    def from_root_setup(cls, verified_installer_release_receipt: Any,
                        session_store: Any, root_journal: Any,
                        compiler_publication_registry: Any
                        ) -> "RootSetupPolicyGenerationPublisher":
        if not callable(getattr(verified_installer_release_receipt, "verify_current", None)):
            raise ValueError("verified installed release receipt is required")
        from .bootstrap_runtime_factory import RootInitialCompilationRegistry
        from .active_policy_compiler import RootActivePolicyCompilationRegistry
        if not isinstance(compiler_publication_registry,
                          (RootInitialCompilationRegistry, RootActivePolicyCompilationRegistry)):
            raise ValueError("publication requires a typed initial or active compiler registry")
        return cls(verified_installer_release_receipt, session_store, root_journal,
                   compiler_publication_registry)

    def publish(self, publication_handle: str,
                expected_selection_catalog_sha256: str | None) -> RootSetupPublicationReceipt:
        _require_root_linux()
        if self._active:
            compiled = self.registry.claim_active_policy(publication_handle,
                                                         expected_selection_catalog_sha256)
        else:
            compiled = self.registry.claim_compilation(publication_handle,
                                                       expected_selection_catalog_sha256)
        publication_started = False
        receipt: RootSetupPublicationReceipt | None = None
        try:
            self.release.verify_current()
            if self._active:
                self.registry.verify_current_active_policy_claim(compiled)
                predecessor = compiled.expected_selection_catalog_sha256
                if (compiled.compiled_policy_sha256 != _sha(compiled.policy_bytes)
                        or compiled.compiled_artifact_catalog_sha256 != _sha(compiled.artifact_catalog_bytes)
                        or compiled.compiled_selection_sha256 != _sha(_canonical(compiled.selection_document))
                        or compiled.selection_catalog_sha256 != compiled.selection_document.get("catalog_sha256")
                        or not isinstance(compiled.claim_digest, str)
                        or not _SHA.fullmatch(compiled.claim_digest)):
                    raise BootstrapEnrollmentError("active compiler claim digests differ from its canonical bytes")
            else:
                self.registry.verify_current_compilation(compiled)
                predecessor = compiled.expected_predecessor_catalog_sha256
            if predecessor != expected_selection_catalog_sha256:
                raise BootstrapEnrollmentError("publication predecessor differs from the sealed stage-zero session")
            policy_sha256 = getattr(compiled, "bootstrap_policy_sha256",
                                    getattr(compiled, "compiled_policy_sha256", None))
            policy_id = getattr(compiled, "bootstrap_policy_artifact_id", POLICY_ARTIFACT_ID)
            plan_artifact_id = getattr(compiled, "plan_artifact_id",
                                       self.release.selected_plan_artifact_id)
            _validate_compiled_documents(
                compiled.policy_bytes, compiled.artifact_catalog_bytes,
                compiled.selection_document, compiled.selection_catalog_sha256,
                plan_artifact_id, compiled.plan_sha256,
                policy_id, policy_sha256,
                getattr(compiled, "release_commit", self.release.release_commit), self.release,
            )
            # Validate the exact ordered closure before creating immutable
            # generations or a journal row. The active compiler owns this
            # canonical ordering; the publisher must never silently dedupe it.
            _receipt_input_handles(compiled, active=self._active)
            publication_started = True
            receipt = self._publish_compiled(compiled, expected_selection_catalog_sha256,
                                             state="active-committed" if self._active else "prepared")
            if self._active:
                self.registry.complete_active_publication(receipt)
            else:
                self.registry.complete_publication(receipt)
            return receipt
        except Exception as exc:
            if self._active and publication_started:
                # The selection replacement is the externally visible commit.
                # A failure after that point must not release the native output
                # reservation or mark the compiler claim releasable. Recover a
                # receipt from the fixed root journal when _publish_compiled
                # raised after its atomic replacement but before returning.
                if receipt is None:
                    try:
                        receipt = PolicyPublicationReceiptResolver.resolve_current()
                    except Exception:
                        receipt = None
                if receipt is not None and _receipt_matches_active_claim(receipt, compiled):
                    try:
                        self.registry.complete_active_publication(receipt)
                        return receipt
                    except Exception as completion_error:
                        raise BootstrapEnrollmentPending(
                            "active policy selection is committed; compiler claim and output reservation "
                            "are retained for publication finalization recovery"
                        ) from completion_error
                raise BootstrapEnrollmentPending(
                    "active policy publication may have crossed its durable selection commit; "
                    "compiler claim and output reservation are retained for recovery"
                ) from exc
            if self._active:
                self.registry.release_active_policy(publication_handle)
            else:
                self.registry.release_compilation(publication_handle)
            raise

    def recover_active_publication(self, publication_handle: str) -> RootSetupPublicationReceipt:
        """Finish a previously committed active publication from durable current state.

        This deliberately accepts no receipt or claim fields from the caller. It
        resolves the fixed root selection and journal, checks the opaque handle,
        then asks the typed compiler registry to reconcile its retained claim and
        output reservation. It cannot recover a superseded or merely prepared
        generation.
        """
        _require_root_linux()
        if not self._active:
            raise BootstrapEnrollmentError("active publication recovery requires the active compiler registry")
        if not isinstance(publication_handle, str) or not _HANDLE.fullmatch(publication_handle):
            raise BootstrapEnrollmentError("active publication recovery handle is malformed")
        receipt = PolicyPublicationReceiptResolver.resolve_current()
        if receipt.publication_handle != publication_handle or receipt.state != "active-committed":
            raise BootstrapEnrollmentPending("the requested active publication is not the durable current selection")
        recovery = getattr(self.registry, "recover_active_publication_receipt", None)
        if callable(recovery):
            recovery(receipt)
        else:
            # Compatibility for a registry retaining the original in-memory
            # claim. A fresh registry must implement the durable typed recovery
            # API rather than reconstructing claims from caller input.
            self.registry.complete_active_publication(receipt)
        return receipt

    def _publish_compiled(self, compiled: CompiledRootSetupPublication,
                          expected_selection_catalog_sha256: str | None,
                          *, state: str) -> RootSetupPublicationReceipt:
        # Filesystem core also powers nonprivileged fault-injection tests.
        session = getattr(compiled, "session", getattr(compiled, "initial_session",
                            getattr(compiled, "_root_setup_session", None)))
        journal_row = getattr(compiled, "_root_journal_root", None)
        if journal_row is None:
            journal_row = getattr(session, "_root_journal_root", None)
        if journal_row is None:
            journal_row = getattr(session, "root_journal_root", None)
        if isinstance(journal_row, Path):
            expected_path = Path("/var/lib/hermes-installer/authority-journal")
            supplied_path = self.root_journal if isinstance(self.root_journal, Path) else None
            identity = getattr(self.root_journal, "identity", None)
            if supplied_path is None and isinstance(identity, Mapping):
                supplied_path = Path(str(identity.get("absolute_path", "")))
            if journal_row != expected_path or supplied_path != journal_row:
                raise BootstrapEnrollmentError("active compiler journal differs from fixed root setup journal")
            fd = os.open(journal_row, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                info = os.fstat(fd)
                journal_row = {
                    "root_id": "installer-authority-journal-v1",
                    "absolute_path": str(journal_row),
                    "owner_uid": info.st_uid,
                    "owner_gid": info.st_gid,
                    "mode": stat.S_IMODE(info.st_mode),
                    "device": info.st_dev,
                    "inode": info.st_ino,
                }
            finally:
                os.close(fd)
        if not isinstance(journal_row, Mapping) or not isinstance(journal_row.get("absolute_path"), str):
            raise BootstrapEnrollmentError("stage-zero compilation has no observed root journal selection")
        receipt = _publish_policy_generation(
            policy_root=POLICY_GENERATIONS,
            selection_path=SELECTION_PATH,
            journal_root=Path(journal_row["absolute_path"]),
            compiled=compiled,
            release=self.release,
            expected_selection_catalog_sha256=expected_selection_catalog_sha256,
            expected_uid=0,
            root_journal=journal_row,
            publication_state=state,
        )
        return receipt


class PolicyPublicationReceiptResolver:
    """Resolve only the currently selected root-owned publication receipt."""

    @classmethod
    def resolve_current(cls) -> RootSetupPublicationReceipt:
        _require_root_linux()
        journal_root = Path("/var/lib/hermes-installer/authority-journal")
        _verify_root_directory(journal_root, 0, create=False, mode=0o700)
        selection, selection_stat = _read_current_selection(SELECTION_PATH, 0)
        if selection is None or selection_stat is None:
            raise BootstrapEnrollmentPending("no root policy generation is currently selected")
        generation = selection.get("policy_generation")
        if not isinstance(generation, dict):
            raise BootstrapEnrollmentPending("current root selection has no policy generation")
        receipt_handle = generation.get("publication_receipt_handle")
        if not isinstance(receipt_handle, str) or not _HANDLE.fullmatch(receipt_handle):
            raise BootstrapEnrollmentError("current policy publication receipt handle is malformed")
        publications = journal_root / "policy-publications"
        _verify_root_directory(publications, 0, create=False, mode=0o700)
        matches: list[dict[str, Any]] = []
        record_count = 0
        dir_fd = os.open(publications, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            with os.scandir(dir_fd) as entries:
                for entry in entries:
                    record_count += 1
                    if record_count > 128:
                        raise BootstrapEnrollmentPending("policy publication journal exceeds its bounded record count")
                    if not entry.name.endswith(".json") or not _SHA.fullmatch(entry.name[:-5]):
                        raise BootstrapEnrollmentError("policy publication journal contains an unexpected entry")
                    info = entry.stat(follow_symlinks=False)
                    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                            or info.st_gid != 0 or info.st_nlink != 1):
                        raise BootstrapEnrollmentError("policy publication journal contains an unsafe entry")
                    record = _read_owned_json(publications / entry.name, 0,
                                              maximum=64 * 1024, required_mode=0o600)
                    if record.get("publication_receipt_handle") == receipt_handle:
                        matches.append(record)
        finally:
            os.close(dir_fd)
        if len(matches) != 1:
            raise BootstrapEnrollmentPending("current policy publication has no unique root journal receipt")
        record = matches[0]
        receipt = _receipt_from_record(record)
        if receipt.state != "active-committed":
            raise BootstrapEnrollmentPending("current root policy publication is prepared, not active")
        expected_root = POLICY_GENERATIONS / receipt.publication_sha256
        if (generation != {
                "id": receipt.generation_id,
                "publication_sha256": receipt.publication_sha256,
                "root_path": str(expected_root),
                "device": receipt.generation_device,
                "inode": receipt.generation_inode,
                "publication_receipt_handle": receipt.receipt_handle,
        } or receipt.generation_root != expected_root
                or receipt.current_selection_catalog_sha256 != selection["catalog_sha256"]):
            raise BootstrapEnrollmentError("current policy selection differs from its root publication receipt")
        raw_selection, _ = _read_fixed(SELECTION_PATH, 0, 0o600, 2 * 1024 * 1024)
        if _sha(raw_selection) != receipt.selection_sha256:
            raise BootstrapEnrollmentError("current root selection bytes differ from the committed publication")
        descriptor, files, file_bytes = _read_generation_descriptor(receipt, 0)
        if (_sha(_canonical(descriptor)) != receipt.publication_sha256
                or _sha(_canonical(descriptor)) != receipt.descriptor_sha256
                or descriptor.get("inputs", {}).get("source_receipt_handles")
                    != [handle for handle in receipt.input_receipt_handles
                        if handle != descriptor.get("inputs", {}).get("observed_root_receipt_handle")]):
            raise BootstrapEnrollmentError("current generation descriptor differs from its receipt closure")
        from .owner_overlay_publication import validate_owner_overlay_adoption_row
        try:
            adoption_rows = tuple(validate_owner_overlay_adoption_row(row)
                                  for row in descriptor.get("owner_overlay_adoption_records", []))
            expected_observers = tuple(sorted(
                (dict(observer) for adoption in adoption_rows
                 for observer in adoption["owner_overlay_observer_records"]),
                key=lambda row: (row["registration_id"], row["observer_enrollment_id"]),
            ))
            raw_observers = descriptor.get("owner_overlay_observer_records")
            if (not isinstance(raw_observers, list)
                    or raw_observers != list(expected_observers)):
                raise ValueError
        except (TypeError, ValueError):
            raise BootstrapEnrollmentError(
                "current signed owner-overlay observer table differs from its adoption rows",
            ) from None
        receipt = dataclass_replace(receipt, owner_overlay_observer_records=expected_observers)
        _verify_active_receipt_descriptor(receipt, descriptor)
        if (files["plans/bootstrap-policy-v1.json"] != receipt.policy_sha256
                or files["catalog/artifacts.json"] != receipt.artifact_catalog_sha256):
            raise BootstrapEnrollmentError("current generation file hashes differ from the receipt")
        current_release = _verify_live_release_and_selection(descriptor, selection, file_bytes)
        try:
            current_release.verify_current()
            # Re-read the fixed current pointer after joining the policy documents to
            # the release closure. This closes the window where a deployment switch
            # could otherwise leave the just-checked selection bound to stale code.
            from .installer_release import InstalledRootReleaseVerifier
            latest_release = InstalledRootReleaseVerifier.verify_installed_release()
            try:
                if (latest_release.release_commit != current_release.release_commit
                        or latest_release.deployment_receipt_sha256
                            != current_release.deployment_receipt_sha256
                        or latest_release.closure_manifest_sha256
                            != current_release.closure_manifest_sha256):
                    raise BootstrapEnrollmentPending(
                        "installed release changed while resolving the current policy publication"
                    )
                latest_release.verify_current()
            finally:
                latest_release.close()
        finally:
            current_release.close()
        return receipt

    @classmethod
    def verify_current_active_claim(cls, *, publication_handle: str, claim_digest: str,
                                    prepared_generation_id: str, transaction_handle: str,
                                    expected_materialization_receipt_handles: tuple[str, ...]
                                    ) -> RootSetupPublicationReceipt:
        """Re-resolve the active selection and bind a native reservation to it."""
        receipt = cls.resolve_current()
        if (receipt.publication_handle != publication_handle
                or receipt.claim_digest != claim_digest
                or receipt.prepared_generation_id != prepared_generation_id
                or receipt.transaction_handle != transaction_handle
                or receipt.materialization_receipt_handles != expected_materialization_receipt_handles):
            raise BootstrapEnrollmentPending("native output reservation differs from current active publication")
        return receipt

    @classmethod
    def resolve_current_choice_adoption(cls, selection_handle: str
                                        ) -> PublishedSetupChoiceAdoption:
        """Resolve choice adoption only from the currently selected active generation."""
        receipt = cls.resolve_current()
        matches = [row for row in receipt.choice_adoptions
                   if row.selection_handle == selection_handle]
        if len(matches) != 1:
            raise BootstrapEnrollmentPending("setup choice has no unique current active publication projection")
        return matches[0]


def _receipt_from_record(record: Mapping[str, Any]) -> RootSetupPublicationReceipt:
    required = {"schema", "transaction_handle", "publication_sha256", "publication_receipt_handle",
                "generation_id", "generation_root", "generation_device", "generation_inode",
                "policy_sha256", "artifact_catalog_sha256", "selection_sha256", "descriptor_sha256",
                "previous_selection_catalog_sha256", "current_selection_catalog_sha256",
                "input_receipt_handles", "state", "updated_monotonic"}
    active_fields = {"publication_handle", "claim_digest", "prepared_generation_id",
                     "service_generation_digest", "runtime_receipt_handles",
                     "materialization_receipt_handles"}
    has_choice_adoptions = isinstance(record, Mapping) and "choice_adoptions" in record
    expected = (required | active_fields | ({"choice_adoptions"} if has_choice_adoptions else set())
                if isinstance(record, Mapping) and record.get("state") == "active-committed" else required)
    if not isinstance(record, Mapping) or set(record) != expected or record.get("schema") != 1:
        raise BootstrapEnrollmentError("root policy publication receipt record has an invalid schema")
    sha_fields = ("publication_sha256", "policy_sha256", "artifact_catalog_sha256",
                  "selection_sha256", "descriptor_sha256", "current_selection_catalog_sha256")
    if any(not isinstance(record.get(name), str) or not _SHA.fullmatch(record[name]) for name in sha_fields):
        raise BootstrapEnrollmentError("root policy publication receipt digest is malformed")
    previous = record.get("previous_selection_catalog_sha256")
    if previous is not None and (not isinstance(previous, str) or not _SHA.fullmatch(previous)):
        raise BootstrapEnrollmentError("root policy publication predecessor digest is malformed")
    handles = record.get("input_receipt_handles")
    if (not isinstance(handles, list) or not handles
            or any(not isinstance(item, str) or not _HANDLE.fullmatch(item) for item in handles)
            or len(set(handles)) != len(handles)):
        raise BootstrapEnrollmentError("root policy publication input receipt closure is malformed")
    if (not isinstance(record.get("transaction_handle"), str)
            or not isinstance(record.get("publication_receipt_handle"), str)
            or not _HANDLE.fullmatch(record["publication_receipt_handle"])
            or record.get("generation_id") != POLICY_GENERATION_ID
            or record.get("generation_root") != str(POLICY_GENERATIONS / record["publication_sha256"])
            or type(record.get("generation_device")) is not int or record["generation_device"] < 0
            or type(record.get("generation_inode")) is not int or record["generation_inode"] <= 0
            or record.get("state") not in {"prepared", "active-committed"}):
        raise BootstrapEnrollmentError("root policy publication receipt identity is malformed")
    if record["state"] == "active-committed":
        for key in ("claim_digest", "service_generation_digest"):
            if not isinstance(record.get(key), str) or not _SHA.fullmatch(record[key]):
                raise BootstrapEnrollmentError("active policy publication digest is malformed")
        if (not isinstance(record.get("publication_handle"), str)
                or not _HANDLE.fullmatch(record["publication_handle"])
                or not isinstance(record.get("prepared_generation_id"), str)
                or not _GENERATION_NAME.fullmatch(record["prepared_generation_id"])):
            raise BootstrapEnrollmentError("active policy publication claim identity is malformed")
        for key in ("runtime_receipt_handles", "materialization_receipt_handles"):
            values = record.get(key)
            if (not isinstance(values, list) or not values
                    or any(not isinstance(item, str) or not _HANDLE.fullmatch(item) for item in values)
                    or len(set(values)) != len(values)):
                raise BootstrapEnrollmentError("active policy input receipt handles are malformed")
    choice_adoptions: tuple[PublishedSetupChoiceAdoption, ...] = ()
    if has_choice_adoptions:
        raw_adoptions = record["choice_adoptions"]
        if not isinstance(raw_adoptions, list) or len(raw_adoptions) > 128:
            raise BootstrapEnrollmentError("active publication choice adoption list is malformed")
        parsed = tuple(_choice_adoption_from_record(row) for row in raw_adoptions)
        choice_adoptions = parsed
        identities = [(row.purpose, row.selection_handle) for row in parsed]
        if identities != sorted(set(identities)):
            raise BootstrapEnrollmentError("active publication choice adoptions are duplicated or unordered")
        for row in parsed:
            if (record["state"] != "active-committed"
                    or row.publication_receipt_handle != record["publication_receipt_handle"]
                    or row.publication_sha256 != record["publication_sha256"]
                    or row.generation_id != record["generation_id"]
                    or row.transaction_handle != record["transaction_handle"]
                    or row.prepared_generation != record.get("prepared_generation_id")
                    or row.service_generation_digest != record.get("service_generation_digest")):
                raise BootstrapEnrollmentError("setup choice adoption differs from its active publication")
            if not set(row.source_member_receipt_handles).issubset(handles):
                raise BootstrapEnrollmentError("setup choice source receipts are outside the publication input closure")
    return RootSetupPublicationReceipt(
        1, record["publication_receipt_handle"], record["transaction_handle"],
        record["generation_id"], record["publication_sha256"], Path(record["generation_root"]),
        record["generation_device"], record["generation_inode"], record["policy_sha256"],
        record["artifact_catalog_sha256"], record["selection_sha256"], record["descriptor_sha256"],
        previous, record["current_selection_catalog_sha256"], tuple(handles), record["state"], _SEAL,
        record.get("publication_handle"), record.get("claim_digest"),
        record.get("prepared_generation_id"), record.get("service_generation_digest"),
        tuple(record.get("runtime_receipt_handles", ())),
        tuple(record.get("materialization_receipt_handles", ())), choice_adoptions)


def _choice_adoption_from_record(record: Mapping[str, Any]) -> PublishedSetupChoiceAdoption:
    if not isinstance(record, Mapping) or set(record) != set(_CHOICE_ADOPTION_FIELDS):
        raise BootstrapEnrollmentError("published setup choice adoption has an invalid schema")
    for name in ("signed_record_sha256", "choice_payload_sha256",
                 "release_deployment_receipt_sha256", "principal_binding_sha256",
                 "namespace_binding_sha256", "service_generation_digest",
                 "selection_catalog_sha256", "publication_sha256"):
        if not isinstance(record[name], str) or not _SHA.fullmatch(record[name]):
            raise BootstrapEnrollmentError("published setup choice adoption digest is malformed")
    for name in ("selection_handle", "setup_session_handle", "transaction_handle",
                 "principal_selection_handle", "namespace_selection_handle",
                 "publication_receipt_handle"):
        if not isinstance(record[name], str) or not _HANDLE.fullmatch(record[name]):
            raise BootstrapEnrollmentError("published setup choice adoption handle is malformed")
    for name in ("key_id", "principal_id", "profile_id", "namespace_id", "service_generation_id"):
        value = record[name]
        if (not isinstance(value, str) or not value or len(value) > 256
                or any(ord(char) < 0x20 or ord(char) == 0x7f for char in value)):
            raise BootstrapEnrollmentError("published setup choice adoption identity is malformed")
    if (record["purpose"] not in _CHOICE_PURPOSES
            or not isinstance(record["plan_id"], str) or not record["plan_id"]
            or not isinstance(record["prepared_generation"], str)
            or not _GENERATION_NAME.fullmatch(record["prepared_generation"])
            or record["generation_id"] != POLICY_GENERATION_ID
            or (record["private_profile_selection_handle"] is not None
                and (not isinstance(record["private_profile_selection_handle"], str)
                     or not _HANDLE.fullmatch(record["private_profile_selection_handle"])))
            or type(record["choice_epoch"]) is not int or record["choice_epoch"] < 1
            or type(record["revocation_epoch"]) is not int or record["revocation_epoch"] < 1
            or type(record["issued_at_unix"]) not in {int, float}
            or type(record["setup_deadline_unix"]) not in {int, float}
            or type(record["adopted_at_unix"]) not in {int, float}
            or not math.isfinite(record["issued_at_unix"])
            or not math.isfinite(record["setup_deadline_unix"])
            or not math.isfinite(record["adopted_at_unix"])
            or record["issued_at_unix"] <= 0
            or record["setup_deadline_unix"] <= record["issued_at_unix"]
            or record["adopted_at_unix"] < record["issued_at_unix"]
            or record["adopted_at_unix"] > record["setup_deadline_unix"]):
        raise BootstrapEnrollmentError("published setup choice adoption fields are malformed")
    handles = record["source_member_receipt_handles"]
    if (not isinstance(handles, list) or not handles
            or any(not isinstance(handle, str) or not _HANDLE.fullmatch(handle) for handle in handles)
            or handles != sorted(set(handles))):
        raise BootstrapEnrollmentError("published setup choice source receipt closure is malformed")
    return PublishedSetupChoiceAdoption(
        *(tuple(handles) if name == "source_member_receipt_handles" else record[name]
          for name in _CHOICE_ADOPTION_FIELDS), _SEAL)


def _choice_adoption_value(adoption: PublishedSetupChoiceAdoption) -> dict[str, Any]:
    return {name: list(getattr(adoption, name)) if name == "source_member_receipt_handles"
            else getattr(adoption, name) for name in _CHOICE_ADOPTION_FIELDS}


def _choice_projection_value(projection: Any) -> dict[str, Any]:
    """Copy the compiler's sealed digest-only choice projection into the descriptor."""
    values: dict[str, Any] = {}
    for name in _CHOICE_PROJECTION_FIELDS:
        if name in {"publication_receipt_handle", "publication_sha256", "generation_id"}:
            continue
        if not hasattr(projection, name):
            raise BootstrapEnrollmentError(f"active compiler choice projection is missing {name}")
        value = getattr(projection, name)
        values[name] = list(value) if name == "source_member_receipt_handles" else value
    if values["purpose"] not in _CHOICE_PURPOSES:
        raise BootstrapEnrollmentError("active compiler choice projection has an invalid purpose")
    return values


def _choice_adoption_record(adoption: PublishedSetupChoiceAdoption) -> dict[str, Any]:
    return _choice_adoption_value(adoption)


def _verify_active_receipt_descriptor(receipt: RootSetupPublicationReceipt,
                                      descriptor: Mapping[str, Any]) -> None:
    if receipt.state != "active-committed":
        return
    inputs = descriptor.get("inputs")
    from .owner_overlay_publication import validate_owner_overlay_adoption_row
    raw_owner_rows = descriptor.get("owner_overlay_adoption_records", [])
    try:
        owner_rows = [validate_owner_overlay_adoption_row(row) for row in raw_owner_rows]
    except (TypeError, ValueError):
        raise BootstrapEnrollmentError("committed local-owner adoption rows are malformed") from None
    if (descriptor.get("schema") != 2
            or not isinstance(inputs, Mapping)
            or inputs.get("publication_handle") != receipt.publication_handle
            or inputs.get("claim_digest") != receipt.claim_digest
            or inputs.get("prepared_generation_id") != receipt.prepared_generation_id
            or inputs.get("expected_service_generation_digest") != receipt.service_generation_digest
            or inputs.get("transaction_handle") != receipt.transaction_handle
            or tuple(inputs.get("runtime_receipt_handles", ())) != receipt.runtime_receipt_handles
            or tuple(inputs.get("materialization_receipt_handles", ())) != receipt.materialization_receipt_handles
            or inputs.get("choice_projections", []) != [
                {key: value for key, value in _choice_adoption_value(row).items()
                 if key not in {"publication_receipt_handle", "publication_sha256", "generation_id"}}
                for row in receipt.choice_adoptions]
            or owner_rows != [dict(row) for row in receipt.owner_overlay_adoption_records]
            or not isinstance(descriptor.get("owner_overlay_observer_records"), list)
            or descriptor.get("owner_overlay_observer_records") != sorted(
                (dict(observer) for row in owner_rows
                 for observer in row["owner_overlay_observer_records"]),
                key=lambda row: (row["registration_id"], row["observer_enrollment_id"]),
            )
            or [dict(row) for row in receipt.owner_overlay_observer_records]
               != descriptor.get("owner_overlay_observer_records")
            or inputs.get("owner_overlay_adoption_sha256") != _sha(_canonical(owner_rows))
            or descriptor.get("policy_sha256") != receipt.policy_sha256
            or descriptor.get("artifact_catalog_sha256") != receipt.artifact_catalog_sha256
            or descriptor.get("selection_sha256") != receipt.selection_sha256
            or descriptor.get("inputs", {}).get("claim_digest") != receipt.claim_digest):
        raise BootstrapEnrollmentError("committed active publication descriptor differs from its sealed receipt")


def _read_generation_descriptor(receipt: RootSetupPublicationReceipt, uid: int
                                ) -> tuple[dict[str, Any], dict[str, str], dict[str, bytes]]:
    try:
        root_fd = os.open(receipt.generation_root,
                          os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        raise BootstrapEnrollmentError("current policy generation cannot be opened safely") from None
    try:
        info = os.fstat(root_fd)
        if (info.st_uid != uid or info.st_gid != _expected_gid(uid) or stat.S_IMODE(info.st_mode) != 0o555
                or (info.st_dev, info.st_ino) != (receipt.generation_device, receipt.generation_inode)):
            raise BootstrapEnrollmentError("current policy generation custody differs from its selection")
        descriptor_bytes, descriptor_info = _readat(root_fd, "publication.json", uid, 0o444)
        if descriptor_info.st_nlink != 1:
            raise BootstrapEnrollmentError("policy publication descriptor has unsafe link count")
        descriptor = _json_bytes(descriptor_bytes, "publication descriptor")
        if not isinstance(descriptor, dict):
            raise BootstrapEnrollmentError("policy publication descriptor is malformed")
        result: dict[str, str] = {}
        contents: dict[str, bytes] = {}
        verified_files = [_FileSpec("publication.json", descriptor_bytes)]
        for relative, expected in (("plans/bootstrap-policy-v1.json", receipt.policy_sha256),
                                   ("catalog/artifacts.json", receipt.artifact_catalog_sha256)):
            raw, info = _readat(root_fd, relative, uid, 0o444)
            digest = _sha(raw)
            if info.st_nlink != 1 or digest != expected:
                raise BootstrapEnrollmentError("current policy file digest differs from the journal receipt")
            result[relative] = digest
            contents[relative] = raw
            verified_files.append(_FileSpec(relative, raw))
        _verify_generation(receipt.generation_root, receipt.publication_sha256,
                           _canonical(descriptor), tuple(verified_files), uid)
        return descriptor, result, contents
    finally:
        os.close(root_fd)


def _restore_compiled_selection(descriptor: Mapping[str, Any],
                                selected_document: Mapping[str, Any]) -> dict[str, Any]:
    """Recover the exact pre-publication selection bytes from current root state."""
    inputs = descriptor.get("inputs")
    if not isinstance(inputs, Mapping):
        raise BootstrapEnrollmentError("published policy descriptor lacks durable input bindings")
    compiled_selection_sha = inputs.get("selection_catalog_sha256")
    if not isinstance(compiled_selection_sha, str) or not _SHA.fullmatch(compiled_selection_sha):
        raise BootstrapEnrollmentError("published policy lacks its compiled selection catalog digest")
    selection = dict(selected_document)
    selection.pop("policy_generation", None)
    selection["catalog_sha256"] = compiled_selection_sha
    unsigned = {key: value for key, value in selection.items() if key != "catalog_sha256"}
    if (_sha(_canonical(unsigned)) != compiled_selection_sha
            or _sha(_canonical(selection)) != descriptor.get("selection_sha256")):
        raise BootstrapEnrollmentError("current selection cannot be reconstructed from the durable compiler digest")
    return selection


def _verify_live_release_and_selection(descriptor: Mapping[str, Any],
                                      selected_document: Mapping[str, Any],
                                      generation_files: Mapping[str, bytes]) -> Any:
    """Rejoin durable published bytes to the currently installed release closure."""
    from .installer_release import InstalledRootReleaseVerifier
    inputs = descriptor.get("inputs")
    if not isinstance(inputs, Mapping):
        raise BootstrapEnrollmentError("published policy descriptor lacks durable input bindings")
    release = InstalledRootReleaseVerifier.verify_installed_release()
    try:
        if (release.release_commit != inputs.get("release_commit")
                or release.deployment_receipt_sha256 != inputs.get("release_deployment_receipt_sha256")
                or release.closure_manifest_sha256 != inputs.get("release_closure_manifest_sha256")):
            raise BootstrapEnrollmentPending("published policy no longer matches the fixed installed release receipt")
        plan_id, plan_sha = inputs.get("plan_artifact_id"), inputs.get("plan_sha256")
        template_id, template_sha = inputs.get("template_artifact_id"), inputs.get("template_sha256")
        plans = [row for row in release.files if "plan" in row.roles and row.artifact_id == plan_id]
        templates = [row for row in release.files if "template" in row.roles and row.artifact_id == template_id]
        if (len(plans) != 1 or plans[0].sha256 != plan_sha
                or len(templates) != 1 or templates[0].sha256 != template_sha):
            raise BootstrapEnrollmentError("published policy plan or template differs from installed release bytes")
        selection = _restore_compiled_selection(descriptor, selected_document)
        compiled_selection_sha = inputs["selection_catalog_sha256"]
        policy_bytes = generation_files.get("plans/bootstrap-policy-v1.json")
        catalog_bytes = generation_files.get("catalog/artifacts.json")
        if not isinstance(policy_bytes, bytes) or not isinstance(catalog_bytes, bytes):
            raise BootstrapEnrollmentError("current policy generation is missing exact compiled document bytes")
        policy_doc = _json_bytes(policy_bytes, "current bootstrap policy")
        _validate_compiled_documents(
            policy_bytes, catalog_bytes, selection, compiled_selection_sha,
            plan_id, plan_sha, policy_doc.get("id"), _sha(policy_bytes),
            release.release_commit, release,
        )
        release.verify_current()
        return release
    except Exception:
        release.close()
        raise


@dataclass(frozen=True, slots=True)
class _FileSpec:
    path: str
    data: bytes
    mode: int = 0o444


def _validate_compiled_documents(policy_bytes: bytes, catalog_bytes: bytes,
                                 selection_document: Mapping[str, Any], selection_sha: str,
                                 plan_id: str, plan_sha: str, policy_id: str,
                                 policy_sha: str, release_commit: str,
                                 release: Any) -> None:
    policy = _json_bytes(policy_bytes, "bootstrap policy")
    catalog = _json_bytes(catalog_bytes, "artifact catalog")
    policy_fields = {"schema", "id", "source_artifact_id", "identity_policy", "root_policy",
                     "authority_base_template", "service_record_templates", "catalog_selections",
                     "receipt_binding_rules"}
    if (not isinstance(policy, dict) or set(policy) != policy_fields
            or type(policy.get("schema")) is not int or policy["schema"] != 1
            or _sha(policy_bytes) != policy_sha or policy.get("id") != policy_id):
        raise BootstrapEnrollmentError("compiled policy bytes differ from the pinned policy artifact")
    if (not isinstance(catalog, dict) or set(catalog) != {"schema", "artifacts", "packages"}
            or type(catalog["schema"]) is not int or catalog["schema"] != 1
            or not isinstance(catalog["artifacts"], list) or not isinstance(catalog["packages"], list)):
        raise BootstrapEnrollmentError("compiled artifact catalog does not match its strict envelope")
    try:
        from ..artifacts import ArtifactCatalog, _artifact_from_record, _package_from_record
        catalog_model = ArtifactCatalog.from_records(
            tuple(_artifact_from_record(row) for row in catalog["artifacts"]),
            tuple(_package_from_record(row) for row in catalog["packages"]))
    except (ValueError, TypeError, KeyError):
        raise BootstrapEnrollmentError("compiled artifact catalog rows failed strict parsing") from None
    doc = dict(selection_document)
    selection_fields = {"schema", "selection_id", "installer_release_commit", "release_root",
                        "launcher", "interpreter", "module_closure", "plans", "catalog_sha256",
                        "artifact_catalog", "artifact_store", "bootstrap_policies"}
    if set(doc) != selection_fields:
        raise BootstrapEnrollmentError("compiler selection must be the canonical pre-publication selection")
    if (type(doc.get("schema")) is not int or doc["schema"] != 1
            or doc.get("selection_id") != "installer-root-setup-selection-v1"
            or doc.get("installer_release_commit") != release_commit
            or not isinstance(doc.get("plans"), list)
            or not any(isinstance(row, dict) and row.get("artifact_id") == plan_id
                       and row.get("sha256") == plan_sha for row in doc["plans"])):
        raise BootstrapEnrollmentError("compiled selection does not select the verified installer plan")
    supplied = doc.get("catalog_sha256")
    unsigned = {key: value for key, value in doc.items() if key != "catalog_sha256"}
    if (supplied != selection_sha
            or _sha(_canonical(unsigned)) != selection_sha):
        raise BootstrapEnrollmentError("compiled selection digest differs from canonical selection bytes")
    _validate_selection_rows(doc, release, plan_id, plan_sha, policy_id, policy_sha)
    catalog_row = doc.get("artifact_catalog")
    if (not isinstance(catalog_row, dict)
            or set(catalog_row) != {"artifact_id", "relative_path", "sha256"}
            or catalog_row["artifact_id"] != CATALOG_ARTIFACT_ID
            or catalog_row["relative_path"] != "catalog/artifacts.json"
            or catalog_row["sha256"] != _sha(catalog_bytes)
            or not catalog_model.artifacts):
        raise BootstrapEnrollmentError("compiled selection does not join the exact root artifact catalog bytes")
    plan_row = next(row for row in doc["plans"]
                    if isinstance(row, dict) and row.get("artifact_id") == plan_id)
    plan_fields = {"artifact_id", "relative_path", "sha256", "baseline_tag_object",
                   "baseline_commit", "baseline_tree_sha256", "amendment_manifest_sha256",
                   "allowed_artifact_ids", "bootstrap_policy_artifact_id"}
    if (set(plan_row) != plan_fields or plan_row["bootstrap_policy_artifact_id"] != policy_id
            or not isinstance(plan_row["allowed_artifact_ids"], list)
            or not plan_row["allowed_artifact_ids"]
            or len(plan_row["allowed_artifact_ids"]) > 256
            or any(not isinstance(item, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", item)
                   for item in plan_row["allowed_artifact_ids"])
            or plan_row["allowed_artifact_ids"] != sorted(set(plan_row["allowed_artifact_ids"]))
            or any(item not in catalog_model.artifacts for item in plan_row["allowed_artifact_ids"])):
        raise BootstrapEnrollmentError("compiled plan row or artifact allowlist is malformed")
    try:
        from .bootstrap_runtime_factory import InstalledBootstrapPolicyResolver
        # Reuse the installed loader's full nested-schema validation before the
        # bytes are written. The method validates the policy and selected plan
        # row; its selection parameter is intentionally not read by the parser.
        InstalledBootstrapPolicyResolver()._parse_policy(
            policy, policy_sha, plan_row, None)
    except BootstrapEnrollmentError:
        raise
    except Exception:
        raise BootstrapEnrollmentError("compiled policy failed installed-loader validation") from None
    release_plan = [row for row in release.files if row.artifact_id == plan_id and "plan" in row.roles]
    if (len(release_plan) != 1 or plan_row["relative_path"] != release_plan[0].relative_path
            or plan_row["sha256"] != release_plan[0].sha256 or plan_row["sha256"] != plan_sha
            or plan_row["baseline_tag_object"] != release.baseline_tag_object
            or plan_row["baseline_commit"] != release.baseline_commit
            or plan_row["baseline_tree_sha256"] != release.baseline_tree_sha256
            or plan_row["amendment_manifest_sha256"] != release.amendment_manifest_sha256):
        raise BootstrapEnrollmentError("compiled plan row differs from the verified release closure")
    policy_rows = doc.get("bootstrap_policies")
    if (not isinstance(policy_rows, list)
            or not any(isinstance(row, dict) and row.get("artifact_id") == policy_id
                       and row.get("sha256") == policy_sha
                       and row.get("relative_path") == "plans/bootstrap-policy-v1.json"
                       for row in policy_rows)):
        raise BootstrapEnrollmentError("compiled selection does not join the exact bootstrap policy bytes")


def _validate_selection_rows(doc: Mapping[str, Any], release: Any, plan_id: str,
                             plan_sha: str, policy_id: str, policy_sha: str) -> None:
    """Validate the full loader row closure before the generation is written."""
    try:
        from .bootstrap_runtime_factory import InstalledBootstrapPolicyResolver
        row = InstalledBootstrapPolicyResolver._selection_row
        release_row = doc["release_root"]
        if (not isinstance(release_row, dict)
                or set(release_row) != {"root_id", "absolute_path", "device", "inode",
                                        "deployment_receipt_sha256"}
                or release_row["absolute_path"] != str(release.release_root)
                or release_row["device"] != release.root_device
                or release_row["inode"] != release.root_inode
                or release_row["deployment_receipt_sha256"] != release.deployment_receipt_sha256):
            raise BootstrapEnrollmentError("compiled selection release custody differs from verified release")
        launcher = row(doc["launcher"], {"artifact_id", "relative_path", "sha256"})
        interpreter = row(doc["interpreter"], {"artifact_id", "relative_path", "sha256"})
        if (launcher["artifact_id"] != "installer-root-setup-launcher-v1"
                or interpreter["artifact_id"] != "installer-root-setup-interpreter-v1"):
            raise BootstrapEnrollmentError("compiled selection lacks the fixed launcher and interpreter")
        modules = doc["module_closure"]
        plans = doc["plans"]
        policies = doc["bootstrap_policies"]
        if (not isinstance(modules, list) or not 1 <= len(modules) <= 1024
                or not isinstance(plans, list) or not 1 <= len(plans) <= 16
                or not isinstance(policies, list) or not 1 <= len(policies) <= 16):
            raise BootstrapEnrollmentError("compiled selection row bounds are invalid")
        module_rows = []
        for item in modules:
            entry = row(item, {"module_name", "artifact_id", "relative_path", "sha256"})
            if (not isinstance(entry["module_name"], str)
                    or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.]{0,191}", entry["module_name"])):
                raise BootstrapEnrollmentError("compiled selection module identity is malformed")
            module_rows.append(entry)
        plan_fields = {"artifact_id", "relative_path", "sha256", "baseline_tag_object",
                       "baseline_commit", "baseline_tree_sha256", "amendment_manifest_sha256",
                       "allowed_artifact_ids", "bootstrap_policy_artifact_id"}
        checked_plans = [row(item, plan_fields) for item in plans]
        if len(checked_plans) != 1:
            raise BootstrapEnrollmentError("compiled selection must contain exactly one selected root plan")
        checked_policies = [row(item, {"artifact_id", "relative_path", "sha256"}) for item in policies]
        catalog_row = row(doc["artifact_catalog"], {"artifact_id", "relative_path", "sha256"})
        if (catalog_row["artifact_id"] != CATALOG_ARTIFACT_ID
                or catalog_row["relative_path"] != "catalog/artifacts.json"):
            raise BootstrapEnrollmentError("compiled selection catalog row is not the fixed catalog")
        store = doc["artifact_store"]
        if (not isinstance(store, dict)
                or set(store) != {"root_id", "journal_root_id", "relative_path", "owner_uid", "owner_gid", "mode"}
                or store != {"root_id": "installer-bootstrap-artifact-store-v1",
                             "journal_root_id": "installer-authority-journal-v1",
                             "relative_path": "bootstrap-artifacts", "owner_uid": 0,
                             "owner_gid": 0, "mode": 0o700}):
            raise BootstrapEnrollmentError("compiled selection artifact-store row differs from fixed root custody")
        all_rows = [launcher, interpreter, *module_rows, *checked_plans, *checked_policies]
        if (len({item["artifact_id"] for item in all_rows}) != len(all_rows)
                or len({item["relative_path"] for item in all_rows}) != len(all_rows)):
            raise BootstrapEnrollmentError("compiled selection contains duplicate artifact identities or paths")
        fixed_release_rows = {entry.artifact_id: entry for entry in release.files}
        for selected in (launcher, interpreter, *module_rows, *checked_plans, catalog_row):
            actual = fixed_release_rows.get(selected["artifact_id"])
            if (actual is None or actual.relative_path != selected["relative_path"]
                    or actual.sha256 != selected["sha256"]):
                raise BootstrapEnrollmentError("compiled selection row differs from verified release closure")
        if (fixed_release_rows[launcher["artifact_id"]].roles != ("launcher",)
                or launcher["relative_path"] != "bin/hermes-installer-root-setup"
                or fixed_release_rows[interpreter["artifact_id"]].roles != ("interpreter",)
                or interpreter["relative_path"] != "runtime/bin/python"
                or fixed_release_rows[catalog_row["artifact_id"]].roles != ("artifact-catalog",)
                or fixed_release_rows[plan_id].roles != ("plan",)):
            raise BootstrapEnrollmentError("compiled selection joins a non-fixed release role")
        from .installer_release import _module_name
        for selected in module_rows:
            actual = fixed_release_rows[selected["artifact_id"]]
            if (actual.roles != ("module",)
                    or selected["module_name"] != _module_name(actual.relative_path)
                    or selected["artifact_id"] != "installer-module:" + selected["module_name"]):
                raise BootstrapEnrollmentError("compiled module row does not join its fixed module role")
        target_plan = [item for item in checked_plans if item["artifact_id"] == plan_id]
        if (len(target_plan) != 1 or target_plan[0]["sha256"] != plan_sha
                or target_plan[0]["bootstrap_policy_artifact_id"] != policy_id
                or target_plan[0]["baseline_tag_object"] != release.baseline_tag_object
                or target_plan[0]["baseline_commit"] != release.baseline_commit
                or target_plan[0]["baseline_tree_sha256"] != release.baseline_tree_sha256
                or target_plan[0]["amendment_manifest_sha256"] != release.amendment_manifest_sha256
                or target_plan[0]["allowed_artifact_ids"] != sorted(set(target_plan[0]["allowed_artifact_ids"]))
                or not target_plan[0]["allowed_artifact_ids"]):
            raise BootstrapEnrollmentError("compiled root plan provenance or allowlist is malformed")
        target_policy = [item for item in checked_policies if item["artifact_id"] == policy_id]
        if (len(target_policy) != 1 or target_policy[0]["relative_path"] != "plans/bootstrap-policy-v1.json"
                or target_policy[0]["sha256"] != policy_sha):
            raise BootstrapEnrollmentError("compiled selection policy row differs from selected policy bytes")
    except BootstrapEnrollmentError:
        raise
    except Exception:
        raise BootstrapEnrollmentError("compiled selection failed installed-loader row validation") from None


def _publish_policy_generation(*, policy_root: Path, selection_path: Path,
                               journal_root: Path, compiled: CompiledRootSetupPublication,
                               release: Any, expected_selection_catalog_sha256: str | None,
                               expected_uid: int, root_journal: Any,
                               publication_state: str = "prepared") -> RootSetupPublicationReceipt:
    """Filesystem publication core. All paths must be supplied by trusted caller."""
    if not policy_root.is_absolute() or not selection_path.is_absolute() or not journal_root.is_absolute():
        raise BootstrapEnrollmentError("policy publication roots must be absolute")
    policy_sha = getattr(compiled, "bootstrap_policy_sha256",
                         getattr(compiled, "compiled_policy_sha256", None))
    if (publication_state not in {"prepared", "active-committed"} or not _SHA.fullmatch(compiled.plan_sha256)
            or not isinstance(policy_sha, str) or not _SHA.fullmatch(policy_sha)):
        raise BootstrapEnrollmentError("compiler artifact digest is malformed")
    if publication_state == "active-committed" and (
            not isinstance(getattr(compiled, "publication_handle", None), str)
            or not isinstance(getattr(compiled, "claim_digest", None), str)
            or not isinstance(getattr(compiled, "prepared_generation_id", None), str)
            or not isinstance(getattr(compiled, "expected_service_generation_digest", None), str)):
        raise BootstrapEnrollmentError("active compiler claim is missing committed identity fields")
    _verify_deployment_parent(policy_root.parent, expected_uid)
    _verify_root_directory(policy_root, expected_uid, create=True, mode=0o700)
    _verify_root_directory(selection_path.parent, expected_uid, create=False, mode=0o755)
    _verify_root_directory(journal_root, expected_uid, create=False, mode=0o700)
    _verify_journal_identity(root_journal, journal_root, expected_uid)
    lock_path = journal_root / "policy-publication.lock"
    lock_fd = _open_owned_file(lock_path, os.O_RDWR | os.O_CREAT, expected_uid, 0o600)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        current, current_selection = _read_current_selection(selection_path, expected_uid)
        if expected_selection_catalog_sha256 is None:
            if current is not None:
                raise BootstrapEnrollmentPending("root selection exists; restart with its current catalog digest")
        elif (not _SHA.fullmatch(expected_selection_catalog_sha256) or current is None
              or current["catalog_sha256"] != expected_selection_catalog_sha256):
            raise BootstrapEnrollmentPending("root selection changed before publication; prior generation preserved")
        choice_projections = tuple(getattr(compiled, "choice_adoptions", ()))
        adopted_at_unix = time.time() if publication_state == "active-committed" and choice_projections else None
        if adopted_at_unix is not None:
            _validate_choice_adoption_time(choice_projections, adopted_at_unix)
        descriptor, files = _build_descriptor(
            compiled, expected_selection_catalog_sha256, release,
            adopted_at_unix=adopted_at_unix)
        descriptor_bytes = _canonical(descriptor)
        publication_sha = _sha(descriptor_bytes)
        generation_path = policy_root / publication_sha
        receipt_handle = _journal_receipt_handle(journal_root, compiled.transaction_handle,
                                                  publication_sha, descriptor_bytes, expected_uid)
        _ensure_generation(policy_root, generation_path, publication_sha,
                           descriptor_bytes, files, expected_uid)
        generation_info = os.stat(generation_path, follow_symlinks=False)
        if (not stat.S_ISDIR(generation_info.st_mode) or generation_info.st_uid != expected_uid
                or stat.S_IMODE(generation_info.st_mode) != 0o555):
            raise BootstrapEnrollmentError("published policy generation custody changed")
        final_selection = dict(compiled.selection_document)
        final_selection.pop("policy_generation", None)
        final_selection["policy_generation"] = {
            "id": POLICY_GENERATION_ID,
            "publication_sha256": publication_sha,
            "root_path": str(generation_path),
            "device": generation_info.st_dev,
            "inode": generation_info.st_ino,
            "publication_receipt_handle": receipt_handle,
        }
        existing_policies = list(final_selection.get("bootstrap_policies", []))
        policy_row = {
            "artifact_id": POLICY_ARTIFACT_ID,
            "relative_path": "plans/bootstrap-policy-v1.json",
            "sha256": getattr(compiled, "bootstrap_policy_sha256",
                               getattr(compiled, "compiled_policy_sha256", None)),
        }
        policy_positions = [index for index, row in enumerate(existing_policies)
                            if isinstance(row, dict) and row.get("artifact_id") == POLICY_ARTIFACT_ID]
        if len(policy_positions) > 1:
            raise BootstrapEnrollmentError("compiled selection has duplicate bootstrap policy rows")
        if policy_positions:
            existing_policies[policy_positions[0]] = policy_row
        else:
            existing_policies.append(policy_row)
        final_selection["bootstrap_policies"] = existing_policies
        final_unsigned = {key: value for key, value in final_selection.items() if key != "catalog_sha256"}
        final_selection["catalog_sha256"] = _sha(_canonical(final_unsigned))
        final_selection_bytes = _canonical(final_selection)
        receipt_inputs = _receipt_input_handles(
            compiled, active=publication_state == "active-committed")
        receipt = RootSetupPublicationReceipt(
            1, receipt_handle, compiled.transaction_handle, POLICY_GENERATION_ID,
            publication_sha, generation_path, generation_info.st_dev, generation_info.st_ino,
            _sha(compiled.policy_bytes), _sha(compiled.artifact_catalog_bytes),
            _sha(final_selection_bytes), _sha(descriptor_bytes),
            expected_selection_catalog_sha256, final_selection["catalog_sha256"],
            receipt_inputs, publication_state, _SEAL,
            getattr(compiled, "publication_handle", None),
            getattr(compiled, "claim_digest", None),
            getattr(compiled, "prepared_generation_id", None),
            getattr(compiled, "expected_service_generation_digest", None),
            tuple(getattr(compiled, "runtime_receipt_handles", ())),
            tuple(getattr(compiled, "materialization_receipt_handles", ())),
            _mint_choice_adoptions(compiled, receipt_handle, publication_sha,
                                   POLICY_GENERATION_ID, publication_state,
                                   adopted_at_unix=adopted_at_unix),
            tuple(descriptor.get("owner_overlay_adoption_records", ())),
            tuple(descriptor.get("owner_overlay_observer_records", ())))
        _write_publication_record(journal_root, compiled.transaction_handle, receipt,
                                  descriptor_bytes, expected_uid)
        # Recheck CAS under the stable transaction lock immediately before replace.
        current_again, _ = _read_current_selection(selection_path, expected_uid)
        if (current_again is not None
                and isinstance(current_again.get("policy_generation"), dict)
                and current_again["policy_generation"].get("publication_sha256") == publication_sha
                and current_again.get("catalog_sha256") == receipt.current_selection_catalog_sha256):
            return receipt
        if ((current_again is None) != (current is None)
                or current_again is not None and current_again["catalog_sha256"] != current["catalog_sha256"]):
            raise BootstrapEnrollmentPending("root selection changed during publication; prior selection preserved")
        if adopted_at_unix is not None and any(
                time.time() > row["setup_deadline_unix"]
                for row in (_choice_projection_value(item) for item in choice_projections)):
            raise BootstrapEnrollmentPending(
                "signed setup choice expired before active publication; prior selection preserved")
        _atomic_replace(selection_path, final_selection_bytes, expected_uid, 0o600,
                        compare_inode=current_selection)
        _fsync_dir(selection_path.parent)
        return receipt
    finally:
        os.close(lock_fd)


def _mint_choice_adoptions(compiled: Any, receipt_handle: str, publication_sha: str,
                           generation_id: str, publication_state: str, *,
                           adopted_at_unix: float | None
                           ) -> tuple[PublishedSetupChoiceAdoption, ...]:
    projections = tuple(getattr(compiled, "choice_adoptions", ()))
    if publication_state != "active-committed":
        if projections:
            raise BootstrapEnrollmentError("prepared publication cannot adopt setup choices")
        return ()
    rows = [_choice_projection_value(projection) for projection in projections]
    if projections and adopted_at_unix is None:
        raise BootstrapEnrollmentError("active setup choices require a publisher adoption timestamp")
    if adopted_at_unix is not None:
        _validate_choice_adoption_time(projections, adopted_at_unix)
    minted: list[PublishedSetupChoiceAdoption] = []
    for row in rows:
        row.update({"adopted_at_unix": adopted_at_unix,
                    "publication_receipt_handle": receipt_handle,
                    "publication_sha256": publication_sha,
                    "generation_id": generation_id})
        minted.append(_choice_adoption_from_record(row))
    return tuple(minted)


def _validate_choice_adoption_time(projections: tuple[Any, ...], adopted_at_unix: float) -> None:
    if type(adopted_at_unix) not in {int, float} or not math.isfinite(adopted_at_unix):
        raise BootstrapEnrollmentError("publisher setup choice adoption timestamp is malformed")
    for projection in projections:
        row = _choice_projection_value(projection)
        if not (row["issued_at_unix"] <= adopted_at_unix <= row["setup_deadline_unix"]):
            raise BootstrapEnrollmentPending(
                "signed setup choice cannot be adopted outside its original setup deadline")


def _build_descriptor(compiled: CompiledRootSetupPublication,
                      predecessor_sha256: str | None, release: Any, *,
                      adopted_at_unix: float | None = None
                      ) -> tuple[dict[str, Any], tuple[_FileSpec, ...]]:
    policy_doc = _json_bytes(compiled.policy_bytes, "bootstrap policy")
    catalog_doc = _json_bytes(compiled.artifact_catalog_bytes, "artifact catalog")
    policy_sha256 = getattr(compiled, "bootstrap_policy_sha256",
                            getattr(compiled, "compiled_policy_sha256", None))
    if _sha(compiled.policy_bytes) != policy_sha256:
        raise BootstrapEnrollmentError("bootstrap policy digest changed after compilation")
    catalog_sha = _sha(compiled.artifact_catalog_bytes)
    selection_bytes = _canonical(dict(compiled.selection_document))
    release.verify_current()
    template_artifact_id = getattr(compiled, "template_artifact_id",
                                   getattr(compiled, "policy_template_artifact_id", None))
    template_sha256 = getattr(compiled, "template_sha256",
                              getattr(compiled, "policy_template_sha256", None))
    template_rows = [row for row in release.files if "template" in row.roles
                     and row.artifact_id == template_artifact_id]
    plan_id = getattr(compiled, "plan_artifact_id", release.selected_plan_artifact_id)
    plan_rows = [row for row in release.files if "plan" in row.roles and row.artifact_id == plan_id]
    if (len(template_rows) != 1 or len(plan_rows) != 1
            or template_rows[0].sha256 != template_sha256):
        raise BootstrapEnrollmentError("verified release lacks one compiler template and selected plan")
    source_receipts = list(_receipt_source_handles(compiled))
    session = getattr(compiled, "session", getattr(compiled, "initial_session",
                        getattr(compiled, "_root_setup_session", None)))
    if session is None:
        raise BootstrapEnrollmentError("compiled publication lacks its sealed initial session")
    session_handle = getattr(compiled, "setup_session_id", None)
    if session_handle is None:
        session_handle = getattr(session, "compilation_session_handle", None)
    if session_handle is None:
        session_handle = getattr(compiled, "setup_session_id", None)
    if session_handle is None:
        session_handle = getattr(session, "session_handle", None)
    if session_handle is None:
        session_handle = getattr(getattr(session, "_handle", None), "session_id", None)
    input_receipt_handles = list(source_receipts)
    for name in ("runtime_receipt_handles", "materialization_receipt_handles"):
        for handle in getattr(compiled, name, ()):
            if handle not in input_receipt_handles:
                input_receipt_handles.append(handle)
    observed_handle = getattr(compiled, "observed_root_receipt_handle",
                              getattr(session, "actor_observation_receipt_handle", None))
    if observed_handle is None:
        observed_handle = getattr(session, "observed_root_receipt_handle", None)
    input_doc = {
        "release_commit": getattr(compiled, "release_commit", release.release_commit),
        "release_deployment_receipt_sha256": release.deployment_receipt_sha256,
        "release_closure_manifest_sha256": release.closure_manifest_sha256,
        "template_artifact_id": template_rows[0].artifact_id,
        "template_sha256": template_rows[0].sha256,
        "session_handle": session_handle,
        "transaction_handle": compiled.transaction_handle,
        "plan_artifact_id": getattr(compiled, "plan_artifact_id", release.selected_plan_artifact_id),
        "plan_sha256": compiled.plan_sha256,
        "selection_catalog_sha256": compiled.selection_catalog_sha256,
        "source_receipt_handles": input_receipt_handles,
        "observed_root_receipt_handle": observed_handle,
        "choices_sha256": getattr(compiled, "choices_sha256", None),
        "source_catalog_sha256": getattr(compiled, "source_catalog_sha256", None),
        "principal_selection_receipt_handle": getattr(
            compiled, "principal_selection_receipt_handle",
            getattr(session, "principal_selection_receipt_handle", None)),
        "predecessor_selection_catalog_sha256": predecessor_sha256,
    }
    if hasattr(compiled, "prepared_generation_id"):
        input_doc["prepared_generation_id"] = compiled.prepared_generation_id
        input_doc["expected_service_generation_digest"] = compiled.expected_service_generation_digest
        input_doc["runtime_receipt_handles"] = list(compiled.runtime_receipt_handles)
        input_doc["materialization_receipt_handles"] = list(compiled.materialization_receipt_handles)
        input_doc["policy_template_artifact_id"] = compiled.policy_template_artifact_id
        input_doc["policy_template_sha256"] = compiled.policy_template_sha256
        input_doc["publication_handle"] = compiled.publication_handle
        input_doc["claim_digest"] = compiled.claim_digest
        from .active_policy_compiler import ActiveSetupChoiceProjection
        projections = tuple(getattr(compiled, "choice_adoptions", ()))
        if any(type(row) is not ActiveSetupChoiceProjection
               or getattr(row, "_compiler_seal", None) is not getattr(compiled, "_seal", None)
               for row in projections):
            raise BootstrapEnrollmentError("active compiler choice projection is not sealed to its claim")
        projection_rows = [_choice_projection_value(row) for row in projections]
        if projection_rows:
            if adopted_at_unix is None:
                raise BootstrapEnrollmentError("active choice descriptor has no publisher adoption timestamp")
            _validate_choice_adoption_time(projections, adopted_at_unix)
            for row in projection_rows:
                row["adopted_at_unix"] = adopted_at_unix
        identities = [(row["purpose"], row["selection_handle"]) for row in projection_rows]
        if identities != sorted(set(identities)):
            raise BootstrapEnrollmentError("active compiler choice projections are duplicated or unordered")
        for row in projection_rows:
            if (row["setup_session_handle"] != compiled.setup_session_id
                    or row["transaction_handle"] != compiled.transaction_handle
                    or row["prepared_generation"] != compiled.prepared_generation_id
                    or row["service_generation_digest"] != compiled.expected_service_generation_digest
                    or row["selection_catalog_sha256"] != compiled.selection_catalog_sha256):
                raise BootstrapEnrollmentError("active compiler choice projection differs from its claim")
        input_doc["choice_projections"] = projection_rows
        from .owner_overlay_publication import (
            RootPublishedLocalOwnerAdoption, validate_owner_overlay_adoption_row,
        )
        owner_projections = tuple(getattr(compiled, "owner_overlay_adoptions", ()))
        if (len(owner_projections) > 4
                or any(type(row) is not RootPublishedLocalOwnerAdoption for row in owner_projections)):
            raise BootstrapEnrollmentError("active local-owner adoption projection is untyped or exceeds its finite bound")
        owner_rows: list[dict[str, Any]] = []
        if owner_projections:
            if adopted_at_unix is None:
                raise BootstrapEnrollmentError("local-owner adoption requires an active publisher CAS timestamp")
            signed_by_handle = {row["selection_handle"]: row for row in projection_rows}
            for projection in owner_projections:
                row = projection.to_claim_row(include_digest=False)
                signed = signed_by_handle.get(row["signed_choice"].get("selection_handle"))
                if (signed is None or signed != row["signed_choice"]
                        or row["signed_choice"].get("purpose") != "native-policy-preparation"
                        or row["setup_deadline_unix"] != row["signed_choice"]["setup_deadline_unix"]
                        or not (row["signed_choice"]["issued_at_unix"] <= adopted_at_unix
                                <= row["setup_deadline_unix"])):
                    raise BootstrapEnrollmentError("local-owner adoption differs from its signed choice or deadline")
                row["adopted_at_unix"] = adopted_at_unix
                row["adoption_sha256"] = _sha(_canonical(row))
                try:
                    owner_rows.append(validate_owner_overlay_adoption_row(row))
                except (TypeError, ValueError):
                    raise BootstrapEnrollmentError("local-owner adoption projection is incomplete or altered") from None
            handles = [row["adoption_handle"] for row in owner_rows]
            if handles != sorted(set(handles)):
                raise BootstrapEnrollmentError("local-owner adoption handles are duplicated or unordered")
        input_doc["owner_overlay_adoption_sha256"] = _sha(_canonical(owner_rows))
    else:
        owner_rows = []
    observer_rows = sorted(
        (dict(observer) for row in owner_rows
         for observer in row["owner_overlay_observer_records"]),
        key=lambda row: (row["registration_id"], row["observer_enrollment_id"]),
    )
    if len(observer_rows) > 4 or len({row["registration_id"] for row in observer_rows}) != len(observer_rows):
        raise BootstrapEnrollmentError("active owner-overlay observer table exceeds its exact registration bound")
    descriptor = {
        "schema": 2 if hasattr(compiled, "prepared_generation_id") else 1,
        "id": "installer-bootstrap-policy-publication-v1",
        "policy_sha256": _sha(compiled.policy_bytes),
        "artifact_catalog_sha256": catalog_sha,
        "selection_sha256": _sha(selection_bytes),
        "inputs": input_doc,
        "owner_overlay_adoption_records": owner_rows,
    }
    if hasattr(compiled, "prepared_generation_id"):
        descriptor["owner_overlay_observer_records"] = observer_rows
    files = (
        _FileSpec("plans/bootstrap-policy-v1.json", compiled.policy_bytes),
        _FileSpec("catalog/artifacts.json", compiled.artifact_catalog_bytes),
        _FileSpec("publication.json", _canonical(descriptor)),
    )
    return descriptor, files


def _journal_receipt_handle(journal_root: Path, transaction: str, publication_sha: str,
                            descriptor_bytes: bytes, expected_uid: int) -> str:
    name_digest = _sha((transaction + ":" + publication_sha).encode("utf-8"))
    path = journal_root / "policy-publications" / f"{name_digest}.json"
    _verify_root_directory(path.parent, expected_uid, create=True, mode=0o700)
    if path.exists():
        value = _read_owned_json(path, expected_uid, maximum=64 * 1024, required_mode=0o600)
        if (value.get("transaction_handle") != transaction
                or value.get("publication_sha256") != publication_sha
                or value.get("descriptor_sha256") != _sha(descriptor_bytes)):
            raise BootstrapEnrollmentPending("a different policy publication is journaled for this transaction")
        handle = value.get("publication_receipt_handle")
        if not isinstance(handle, str) or not _HANDLE.fullmatch(handle):
            raise BootstrapEnrollmentError("journaled publication receipt handle is malformed")
        return handle
    handle = secrets.token_urlsafe(32)
    record = {"schema": 1, "transaction_handle": transaction,
              "publication_sha256": publication_sha,
              "descriptor_sha256": _sha(descriptor_bytes),
              "publication_receipt_handle": handle,
              "state": "prepared", "updated_monotonic": time.monotonic()}
    _atomic_create(path, _canonical(record), expected_uid, 0o600)
    _fsync_dir(path.parent)
    return handle


def _write_publication_record(journal_root: Path, transaction: str,
                              receipt: RootSetupPublicationReceipt,
                              descriptor_bytes: bytes, uid: int) -> None:
    name_digest = _sha((transaction + ":" + receipt.publication_sha256).encode("utf-8"))
    path = journal_root / "policy-publications" / f"{name_digest}.json"
    existing = _read_owned_json(path, uid, maximum=64 * 1024, required_mode=0o600)
    if (existing.get("transaction_handle") != transaction
            or existing.get("publication_sha256") != receipt.publication_sha256
            or existing.get("descriptor_sha256") != _sha(descriptor_bytes)
            or existing.get("publication_receipt_handle") != receipt.receipt_handle):
        raise BootstrapEnrollmentPending("policy publication journal identity conflicts with the compiled receipt")
    record = {
        "schema": 1,
        "transaction_handle": transaction,
        "publication_sha256": receipt.publication_sha256,
        "publication_receipt_handle": receipt.receipt_handle,
        "generation_id": receipt.generation_id,
        "generation_root": str(receipt.generation_root),
        "generation_device": receipt.generation_device,
        "generation_inode": receipt.generation_inode,
        "policy_sha256": receipt.policy_sha256,
        "artifact_catalog_sha256": receipt.artifact_catalog_sha256,
        "selection_sha256": receipt.selection_sha256,
        "descriptor_sha256": receipt.descriptor_sha256,
        "previous_selection_catalog_sha256": receipt.previous_selection_catalog_sha256,
        "current_selection_catalog_sha256": receipt.current_selection_catalog_sha256,
        "input_receipt_handles": list(receipt.input_receipt_handles),
        "state": receipt.state,
        "updated_monotonic": time.monotonic(),
    }
    if receipt.state == "active-committed":
        record.update({
            "publication_handle": receipt.publication_handle,
            "claim_digest": receipt.claim_digest,
            "prepared_generation_id": receipt.prepared_generation_id,
            "service_generation_digest": receipt.service_generation_digest,
            "runtime_receipt_handles": list(receipt.runtime_receipt_handles),
            "materialization_receipt_handles": list(receipt.materialization_receipt_handles),
            "choice_adoptions": [_choice_adoption_record(row)
                                 for row in receipt.choice_adoptions],
        })
    _, info = _read_fixed(path, uid, 0o600, 64 * 1024)
    _atomic_replace(path, _canonical(record), uid, 0o600, (info.st_dev, info.st_ino))
    _fsync_dir(path.parent)


def _receipt_input_handles(compiled: Any, *, active: bool = False) -> tuple[str, ...]:
    observed = getattr(compiled, "observed_root_receipt_handle", None)
    if active:
        source = tuple(getattr(compiled, "source_receipt_handles", ()))
        handles = (observed, *source)
        if (not observed or len(set(source)) != len(source)
                or observed in source):
            raise BootstrapEnrollmentError(
                "active compiler receipt closure is not in canonical unique order"
            )
        if any(not isinstance(item, str) or not _HANDLE.fullmatch(item) for item in handles):
            raise BootstrapEnrollmentError("publication input receipt closure contains a malformed handle")
        # Every explicitly named runtime/materialization/principal/adopted-choice
        # input must be represented in the canonical compiler-owned closure.
        required = set(getattr(compiled, "runtime_receipt_handles", ()))
        required.update(getattr(compiled, "materialization_receipt_handles", ()))
        principal = getattr(compiled, "principal_selection_receipt_handle", None)
        if principal:
            required.add(principal)
        for adoption in getattr(compiled, "choice_adoptions", ()):
            required.update(getattr(adoption, "source_member_receipt_handles", ()))
        if not required.issubset(set(source)):
            raise BootstrapEnrollmentError(
                "active compiler receipt closure omits an explicit runtime, materialization, "
                "principal, or choice-source input"
            )
        return handles
    handles = ([observed] if observed is not None else []) + list(_receipt_source_handles(compiled))
    if any(not isinstance(item, str) or not _HANDLE.fullmatch(item) for item in handles):
        raise BootstrapEnrollmentError("publication input receipt closure contains a malformed handle")
    return tuple(dict.fromkeys(handles))


def _receipt_matches_active_claim(receipt: RootSetupPublicationReceipt,
                                  compiled: Any) -> bool:
    """Return true only for the exact committed receipt represented by a claim."""
    try:
        expected_inputs = _receipt_input_handles(compiled, active=True)
        return (
            receipt.state == "active-committed"
            and receipt.publication_handle == compiled.publication_handle
            and receipt.claim_digest == compiled.claim_digest
            and receipt.prepared_generation_id == compiled.prepared_generation_id
            and receipt.transaction_handle == compiled.transaction_handle
            and receipt.service_generation_digest == compiled.expected_service_generation_digest
            and receipt.input_receipt_handles == expected_inputs
            and receipt.runtime_receipt_handles == tuple(compiled.runtime_receipt_handles)
            and receipt.materialization_receipt_handles == tuple(compiled.materialization_receipt_handles)
            and receipt.policy_sha256 == compiled.compiled_policy_sha256
            and receipt.artifact_catalog_sha256 == compiled.compiled_artifact_catalog_sha256
        )
    except (AttributeError, TypeError, ValueError, BootstrapEnrollmentError):
        return False


def _receipt_source_handles(compiled: Any) -> tuple[str, ...]:
    handles = list(getattr(compiled, "source_receipt_handles", ()))
    for name in ("runtime_receipt_handles", "materialization_receipt_handles"):
        handles.extend(getattr(compiled, name, ()))
    principal_handle = getattr(compiled, "principal_selection_receipt_handle", None)
    if principal_handle:
        handles.append(principal_handle)
    session = getattr(compiled, "session", getattr(compiled, "_root_setup_session", None))
    choices = getattr(session, "_choices", None)
    principal = (None if choices is None else
                 getattr(choices, "selected_principal_binding_receipt_handle", None))
    if principal:
        handles.append(principal)
    if any(not isinstance(item, str) or not _HANDLE.fullmatch(item) for item in handles):
        raise BootstrapEnrollmentError("publication input receipt closure contains a malformed handle")
    return tuple(dict.fromkeys(handles))


def _ensure_generation(parent: Path, generation: Path, publication_sha: str,
                       descriptor: bytes, files: tuple[_FileSpec, ...], uid: int) -> None:
    try:
        generation.lstat()
    except FileNotFoundError:
        pass
    else:
        _verify_generation(generation, publication_sha, descriptor, files, uid)
        return
    stage = parent / (".stage-" + publication_sha + "-" + secrets.token_hex(12))
    os.mkdir(stage, 0o700)
    try:
        stage_fd = os.open(stage, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            for directory in ("plans", "catalog"):
                _mkdirat(stage_fd, directory, 0o700, uid)
            for spec in files:
                _write_relative(stage_fd, spec.path, spec.data, uid, spec.mode)
            _fsync_tree_dirs(stage_fd, ("plans", "catalog"))
            os.fchmod(stage_fd, 0o555)
            os.fsync(stage_fd)
            stage_info = os.fstat(stage_fd)
        finally:
            os.close(stage_fd)
        try:
            _rename_noreplace(stage, generation)
        except FileExistsError:
            _verify_generation(generation, publication_sha, descriptor, files, uid)
            _remove_tree_owned(stage, uid)
        else:
            _fsync_dir(parent)
            info = os.stat(generation, follow_symlinks=False)
            if info.st_ino != stage_info.st_ino or info.st_dev != stage_info.st_dev:
                raise BootstrapEnrollmentError("policy generation identity changed during rename")
    except Exception:
        if stage.exists():
            _remove_tree_owned(stage, uid)
        raise


def _verify_generation(path: Path, publication_sha: str, descriptor: bytes,
                       files: tuple[_FileSpec, ...], uid: int) -> None:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        raise BootstrapEnrollmentError("existing policy generation is not a safe owned directory") from None
    try:
        info = os.fstat(fd)
        if (info.st_uid != uid or info.st_gid != _expected_gid(uid) or stat.S_IMODE(info.st_mode) != 0o555
                or path.name != publication_sha):
            raise BootstrapEnrollmentError("existing policy generation identity or mode differs")
        for spec in files:
            raw, file_info = _readat(fd, spec.path, uid, spec.mode)
            if raw != spec.data or file_info.st_nlink != 1:
                raise BootstrapEnrollmentError("existing policy generation bytes differ from compilation")
        expected = {spec.path for spec in files}
        found: set[str] = set()

        def walk(directory_fd: int, prefix: str) -> None:
            scan_fd = os.dup(directory_fd)
            try:
                with os.scandir(scan_fd) as entries:
                    for entry in entries:
                        relative = f"{prefix}/{entry.name}" if prefix else entry.name
                        info = entry.stat(follow_symlinks=False)
                        if stat.S_ISLNK(info.st_mode):
                            raise BootstrapEnrollmentError("existing policy generation contains a symlink")
                        if stat.S_ISDIR(info.st_mode):
                            if (info.st_uid != uid or info.st_gid != _expected_gid(uid)
                                    or stat.S_IMODE(info.st_mode) != 0o555):
                                raise BootstrapEnrollmentError("existing policy generation directory custody differs")
                            child_fd = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                               dir_fd=directory_fd)
                            try:
                                walk(child_fd, relative)
                            finally:
                                os.close(child_fd)
                        elif (stat.S_ISREG(info.st_mode) and info.st_uid == uid
                              and info.st_gid == _expected_gid(uid) and info.st_nlink == 1):
                            found.add(relative)
                        else:
                            raise BootstrapEnrollmentError("existing policy generation contains an unsafe entry")
            finally:
                os.close(scan_fd)

        walk(fd, "")
        if found != expected:
            raise BootstrapEnrollmentError("existing policy generation contains an unlisted file")
    finally:
        os.close(fd)


def _read_current_selection(path: Path, uid: int) -> tuple[dict[str, Any] | None, tuple[int, int] | None]:
    try:
        raw, info = _read_fixed(path, uid, 0o600, 2 * 1024 * 1024)
    except FileNotFoundError:
        return None, None
    value = _json_bytes(raw, "root selection", canonical=True)
    if (not isinstance(value, dict) or value.get("schema") != 1
            or value.get("selection_id") != "installer-root-setup-selection-v1"
            or not isinstance(value.get("catalog_sha256"), str)):
        raise BootstrapEnrollmentError("existing root selection has an invalid strict envelope")
    digest = value["catalog_sha256"]
    unsigned = {key: entry for key, entry in value.items() if key != "catalog_sha256"}
    if not _SHA.fullmatch(digest) or _sha(_canonical(unsigned)) != digest:
        raise BootstrapEnrollmentError("existing root selection catalog digest is invalid")
    return value, (info.st_dev, info.st_ino)


def _atomic_replace(path: Path, data: bytes, uid: int, mode: int,
                    compare_inode: tuple[int, int] | None) -> None:
    parent_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    name = "." + path.name + ".stage-" + secrets.token_hex(12)
    try:
        _write_at_fd(parent_fd, name, data, uid, mode)
        os.fsync(parent_fd)
        try:
            current = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            current = None
        if compare_inode is None:
            if current is not None:
                raise BootstrapEnrollmentPending("selection appeared during initial publication")
        elif (current is None or current.st_dev != compare_inode[0]
              or current.st_ino != compare_inode[1] or not stat.S_ISREG(current.st_mode)
              or current.st_uid != uid or current.st_gid != _expected_gid(uid)
              or stat.S_IMODE(current.st_mode) != mode):
            raise BootstrapEnrollmentPending("selection inode changed during publication")
        if compare_inode is None:
            try:
                os.link(name, path.name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd,
                        follow_symlinks=False)
            except FileExistsError:
                raise BootstrapEnrollmentPending("selection appeared during initial publication") from None
            os.unlink(name, dir_fd=parent_fd)
        else:
            os.replace(name, path.name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        os.fsync(parent_fd)
    finally:
        try:
            os.unlink(name, dir_fd=parent_fd)
        except FileNotFoundError:
            pass
        os.close(parent_fd)


def _atomic_create(path: Path, data: bytes, uid: int, mode: int) -> None:
    parent_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        _write_at_fd(parent_fd, path.name, data, uid, mode, exclusive=True)
        os.fsync(parent_fd)
    except FileExistsError:
        raise BootstrapEnrollmentPending("policy transaction journal record already exists") from None
    finally:
        os.close(parent_fd)


def _write_relative(root_fd: int, relative: str, data: bytes, uid: int, mode: int) -> None:
    if not isinstance(relative, str) or not relative or relative.startswith("/") or "\\" in relative:
        raise BootstrapEnrollmentError("policy generation path is not a safe relative path")
    parts = relative.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise BootstrapEnrollmentError("policy generation path is not a safe relative path")
    parent_fd = os.dup(root_fd)
    try:
        for part in parts[:-1]:
            child_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                               dir_fd=parent_fd)
            os.close(parent_fd)
            parent_fd = child_fd
        _write_at_fd(parent_fd, parts[-1], data, uid, mode, exclusive=True)
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)


def _write_at_fd(parent_fd: int, name: str, data: bytes, uid: int, mode: int,
                 exclusive: bool = True) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC
    flags |= os.O_EXCL if exclusive else os.O_TRUNC
    fd = os.open(name, flags, mode, dir_fd=parent_fd)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != uid
                or info.st_gid != _expected_gid(uid) or info.st_nlink != 1):
            raise BootstrapEnrollmentError("publication target is not a single-link owned regular file")
        view = memoryview(data)
        while view:
            count = os.write(fd, view)
            if count <= 0:
                raise OSError("short write")
            view = view[count:]
        os.fchmod(fd, mode)
        os.fsync(fd)
    finally:
        os.close(fd)


def _readat(root_fd: int, relative: str, uid: int, mode: int) -> tuple[bytes, os.stat_result]:
    if not isinstance(relative, str) or not relative or relative.startswith("/") or "\\" in relative:
        raise BootstrapEnrollmentError("published policy path is not a safe relative path")
    parts = relative.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise BootstrapEnrollmentError("published policy path is not a safe relative path")
    parent_fd = os.dup(root_fd)
    try:
        for part in parts[:-1]:
            child_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                               dir_fd=parent_fd)
            os.close(parent_fd)
            parent_fd = child_fd
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent_fd)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != uid
                    or info.st_gid != _expected_gid(uid)
                    or stat.S_IMODE(info.st_mode) != mode or info.st_nlink != 1
                    or info.st_size > _MAX_FILE):
                raise BootstrapEnrollmentError("published policy file custody is unsafe")
            chunks = []
            while True:
                block = os.read(fd, 65536)
                if not block:
                    break
                chunks.append(block)
            return b"".join(chunks), info
        finally:
            os.close(fd)
    finally:
        os.close(parent_fd)


def _read_fixed(path: Path, uid: int, mode: int, maximum: int) -> tuple[bytes, os.stat_result]:
    parent_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent_fd)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != uid
                    or info.st_gid != _expected_gid(uid)
                    or stat.S_IMODE(info.st_mode) != mode or info.st_nlink != 1
                    or info.st_size > maximum):
                raise BootstrapEnrollmentError("root selection custody is unsafe")
            chunks = []
            while True:
                block = os.read(fd, 65536)
                if not block:
                    break
                chunks.append(block)
            return b"".join(chunks), info
        finally:
            os.close(fd)
    finally:
        os.close(parent_fd)


def _read_owned_json(path: Path, uid: int, *, maximum: int, required_mode: int) -> dict[str, Any]:
    raw, _ = _read_fixed(path, uid, required_mode, maximum)
    value = _json_bytes(raw, "publication journal")
    if not isinstance(value, dict):
        raise BootstrapEnrollmentError("publication journal record is malformed")
    return value


def _open_owned_file(path: Path, flags: int, uid: int, mode: int) -> int:
    parent_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        fd = os.open(path.name, flags | os.O_NOFOLLOW | os.O_CLOEXEC, mode, dir_fd=parent_fd)
    finally:
        os.close(parent_fd)
    info = os.fstat(fd)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != uid
            or info.st_gid != _expected_gid(uid)
            or stat.S_IMODE(info.st_mode) != mode or info.st_nlink != 1):
        os.close(fd)
        raise BootstrapEnrollmentError("policy publication lock is not root owned")
    return fd


def _mkdirat(parent_fd: int, name: str, mode: int, uid: int) -> None:
    os.mkdir(name, mode, dir_fd=parent_fd)
    fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                 dir_fd=parent_fd)
    try:
        info = os.fstat(fd)
        if (info.st_uid != uid or info.st_gid != _expected_gid(uid)
                or stat.S_IMODE(info.st_mode) != mode):
            raise BootstrapEnrollmentError("policy generation staging directory custody is unsafe")
        os.fsync(fd)
    finally:
        os.close(fd)


def _verify_root_directory(path: Path, uid: int, *, create: bool, mode: int) -> None:
    if create and not path.exists():
        path.mkdir(mode=mode)
        os.chown(path, uid, -1)
        os.chmod(path, mode)
        _fsync_dir(path.parent)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        raise BootstrapEnrollmentError("required policy publication directory is unavailable") from None
    try:
        info = os.fstat(fd)
        if (info.st_uid != uid or info.st_gid != _expected_gid(uid)
                or stat.S_IMODE(info.st_mode) != mode
                or bool(stat.S_IMODE(info.st_mode) & 0o022)):
            raise BootstrapEnrollmentError("policy publication directory ownership or mode is unsafe")
    finally:
        os.close(fd)


def _verify_deployment_parent(path: Path, uid: int) -> None:
    """The fixed /var/lib parent may be 0755; it must remain root-owned and non-writable."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        raise BootstrapEnrollmentError("installer state parent is unavailable") from None
    try:
        info = os.fstat(fd)
        if (info.st_uid != uid or info.st_gid != 0 or stat.S_IMODE(info.st_mode) & 0o022):
            raise BootstrapEnrollmentError("installer state parent directory custody is unsafe")
    finally:
        os.close(fd)


def _verify_journal_identity(root_journal: Any, journal_root: Path, uid: int) -> None:
    if isinstance(root_journal, Mapping):
        row = root_journal
    else:
        row = getattr(root_journal, "identity", None)
    if not isinstance(row, Mapping):
        raise BootstrapEnrollmentError("verified root journal identity is required")
    info = os.stat(journal_root, follow_symlinks=False)
    if (row.get("root_id") != "installer-authority-journal-v1"
            or row.get("absolute_path") != str(journal_root)
            or row.get("owner_uid") != uid or row.get("owner_gid") != os.getgid()
            or row.get("mode") != 0o700
            or row.get("device") != info.st_dev or row.get("inode") != info.st_ino):
        raise BootstrapEnrollmentError("root journal identity changed after compilation")


def _fsync_tree_dirs(root_fd: int, dirs: tuple[str, ...]) -> None:
    for name in dirs:
        fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                     dir_fd=root_fd)
        try:
            os.fchmod(fd, 0o555)
            os.fsync(fd)
        finally:
            os.close(fd)


def _fsync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _remove_tree_owned(path: Path, uid: int) -> None:
    info = os.stat(path, follow_symlinks=False)
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != uid
            or info.st_gid != _expected_gid(uid)):
        raise BootstrapEnrollmentError("refusing to remove unowned publication staging path")
    os.chmod(path, 0o700)
    for child in path.iterdir():
        child_info = os.stat(child, follow_symlinks=False)
        if stat.S_ISDIR(child_info.st_mode):
            _remove_tree_owned(child, uid)
        elif (stat.S_ISREG(child_info.st_mode) and child_info.st_uid == uid
              and child_info.st_gid == _expected_gid(uid)):
            os.chmod(child, 0o600)
            child.unlink()
        else:
            raise BootstrapEnrollmentError("refusing to remove foreign path from publication staging")
    path.rmdir()


def _rename_noreplace(source: Path, destination: Path) -> None:
    """Atomically install a generation without replacing any existing name."""
    if sys.platform.startswith("linux"):
        libc = ctypes.CDLL(None, use_errno=True)
        renameat2 = getattr(libc, "renameat2", None)
        if renameat2 is None:
            raise BootstrapEnrollmentPending("atomic no-replace directory rename is unavailable")
        renameat2.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p,
                              ctypes.c_uint)
        renameat2.restype = ctypes.c_int
        result = renameat2(-100, os.fsencode(source), -100, os.fsencode(destination), 1)
        if result == 0:
            return
        error = ctypes.get_errno()
        if error == errno.EEXIST:
            raise FileExistsError(error, os.strerror(error), str(destination))
        raise OSError(error, os.strerror(error), str(destination))
    # Non-Linux fixtures run in private temporary directories. Production
    # publication is rejected before this fallback can be used.
    if destination.exists() or destination.is_symlink():
        raise FileExistsError(errno.EEXIST, os.strerror(errno.EEXIST), str(destination))
    os.rename(source, destination)


def _session_id_from_transaction(transaction: str) -> str:
    # The setup store already binds the transaction to its session. Avoid
    # copying unrelated session state into the public policy document.
    if not isinstance(transaction, str) or not transaction:
        raise BootstrapEnrollmentError("setup transaction identity is missing")
    return hashlib.sha256(transaction.encode("utf-8")).hexdigest()


def _require_root_linux() -> None:
    if not sys_platform_linux() or os.getuid() != 0 or os.geteuid() != 0:
        raise BootstrapEnrollmentPending("root policy publication requires the installed Linux root process")


def sys_platform_linux() -> bool:
    return sys.platform.startswith("linux")
