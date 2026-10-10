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
import os
import re
import secrets
import stat
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

from .bootstrap_enrollment import BootstrapEnrollmentError, BootstrapEnrollmentPending


POLICY_GENERATIONS = Path("/var/lib/hermes-installer/policy-generations")
SELECTION_PATH = Path("/etc/hermes-installer/root-setup-selection.json")
POLICY_GENERATION_ID = "installer-bootstrap-policy-generation-v1"
POLICY_ARTIFACT_ID = "installer-bootstrap-policy-v1"
CATALOG_ARTIFACT_ID = "installer-protected-artifact-catalog-v1"
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_HANDLE = re.compile(r"[A-Za-z0-9_-]{32,128}\Z")
_GENERATION_NAME = re.compile(r"[A-Za-z0-9_.:-]{1,128}\Z")
_MAX_FILE = 16 * 1024 * 1024
_SEAL = object()


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

    def __post_init__(self) -> None:
        if self._seal is not _SEAL:
            raise TypeError("root setup publication receipts are minted by the publisher")


class RootSetupPolicyGenerationPublisher:
    """Publish an immutable generation, then atomically CAS root selection."""

    def __init__(self, release: Any, session_store: Any, root_journal: Any,
                 compiler_publication_registry: Any):
        if (not callable(getattr(compiler_publication_registry, "claim_compilation", None))
                or not callable(getattr(compiler_publication_registry, "complete_publication", None))
                or not callable(getattr(compiler_publication_registry, "release_compilation", None))):
            raise ValueError("typed root initial-compilation registry is required")
        self.release = release
        self.session_store = session_store
        self.root_journal = root_journal
        self.registry = compiler_publication_registry

    @classmethod
    def from_root_setup(cls, verified_installer_release_receipt: Any,
                        session_store: Any, root_journal: Any,
                        compiler_publication_registry: Any
                        ) -> "RootSetupPolicyGenerationPublisher":
        if not callable(getattr(verified_installer_release_receipt, "verify_current", None)):
            raise ValueError("verified installed release receipt is required")
        from .bootstrap_runtime_factory import RootInitialCompilationRegistry
        if not isinstance(compiler_publication_registry, RootInitialCompilationRegistry):
            raise ValueError("initial publication requires the typed root stage-zero registry")
        return cls(verified_installer_release_receipt, session_store, root_journal,
                   compiler_publication_registry)

    def publish(self, publication_handle: str,
                expected_selection_catalog_sha256: str | None) -> RootSetupPublicationReceipt:
        _require_root_linux()
        compiled = self.registry.claim_compilation(publication_handle, expected_selection_catalog_sha256)
        try:
            self.release.verify_current()
            self.registry.verify_current_compilation(compiled)
            if compiled.expected_predecessor_catalog_sha256 != expected_selection_catalog_sha256:
                raise BootstrapEnrollmentError("publication predecessor differs from the sealed stage-zero session")
            _validate_compiled_documents(
                compiled.policy_bytes, compiled.artifact_catalog_bytes,
                compiled.selection_document, compiled.selection_catalog_sha256,
                compiled.plan_artifact_id, compiled.plan_sha256,
                compiled.bootstrap_policy_artifact_id,
                compiled.bootstrap_policy_sha256, compiled.release_commit,
            )
            receipt = self._publish_compiled(compiled, expected_selection_catalog_sha256)
            self.registry.complete_publication(receipt)
            return receipt
        except Exception:
            self.registry.release_compilation(publication_handle)
            raise

    def _publish_compiled(self, compiled: CompiledRootSetupPublication,
                          expected_selection_catalog_sha256: str | None) -> RootSetupPublicationReceipt:
        # Filesystem core also powers nonprivileged fault-injection tests.
        session = getattr(compiled, "session", getattr(compiled, "initial_session", None))
        journal_row = getattr(session, "_root_journal_root", None)
        if journal_row is None:
            journal_row = getattr(session, "root_journal_root", None)
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
        dir_fd = os.open(publications, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            with os.scandir(dir_fd) as entries:
                for entry in entries:
                    if len(matches) > 128:
                        raise BootstrapEnrollmentPending("policy publication journal exceeds its bounded record count")
                    if not entry.name.endswith(".json") or not _SHA.fullmatch(entry.name[:-5]):
                        raise BootstrapEnrollmentError("policy publication journal contains an unexpected entry")
                    info = entry.stat(follow_symlinks=False)
                    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1:
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
        descriptor, files = _read_generation_descriptor(receipt, 0)
        if (_sha(_canonical(descriptor)) != receipt.publication_sha256
                or _sha(_canonical(descriptor)) != receipt.descriptor_sha256
                or descriptor.get("inputs", {}).get("source_receipt_handles")
                    != [handle for handle in receipt.input_receipt_handles
                        if handle != descriptor.get("inputs", {}).get("observed_root_receipt_handle")]):
            raise BootstrapEnrollmentError("current generation descriptor differs from its receipt closure")
        if (files["plans/bootstrap-policy-v1.json"] != receipt.policy_sha256
                or files["catalog/artifacts.json"] != receipt.artifact_catalog_sha256):
            raise BootstrapEnrollmentError("current generation file hashes differ from the receipt")
        return receipt


def _receipt_from_record(record: Mapping[str, Any]) -> RootSetupPublicationReceipt:
    required = {"schema", "transaction_handle", "publication_sha256", "publication_receipt_handle",
                "generation_id", "generation_root", "generation_device", "generation_inode",
                "policy_sha256", "artifact_catalog_sha256", "selection_sha256", "descriptor_sha256",
                "previous_selection_catalog_sha256", "current_selection_catalog_sha256",
                "input_receipt_handles", "state", "updated_monotonic"}
    if not isinstance(record, Mapping) or set(record) != required or record.get("schema") != 1:
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
            or record.get("state") not in {"prepared", "active"}):
        raise BootstrapEnrollmentError("root policy publication receipt identity is malformed")
    return RootSetupPublicationReceipt(
        1, record["publication_receipt_handle"], record["transaction_handle"],
        record["generation_id"], record["publication_sha256"], Path(record["generation_root"]),
        record["generation_device"], record["generation_inode"], record["policy_sha256"],
        record["artifact_catalog_sha256"], record["selection_sha256"], record["descriptor_sha256"],
        previous, record["current_selection_catalog_sha256"], tuple(handles), record["state"], _SEAL)


def _read_generation_descriptor(receipt: RootSetupPublicationReceipt, uid: int
                                ) -> tuple[dict[str, Any], dict[str, str]]:
    try:
        root_fd = os.open(receipt.generation_root,
                          os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        raise BootstrapEnrollmentError("current policy generation cannot be opened safely") from None
    try:
        info = os.fstat(root_fd)
        if (info.st_uid != uid or info.st_gid != 0 or stat.S_IMODE(info.st_mode) != 0o555
                or (info.st_dev, info.st_ino) != (receipt.generation_device, receipt.generation_inode)):
            raise BootstrapEnrollmentError("current policy generation custody differs from its selection")
        descriptor_bytes, descriptor_info = _readat(root_fd, "publication.json", uid, 0o444)
        if descriptor_info.st_nlink != 1:
            raise BootstrapEnrollmentError("policy publication descriptor has unsafe link count")
        descriptor = _json_bytes(descriptor_bytes, "publication descriptor")
        if not isinstance(descriptor, dict):
            raise BootstrapEnrollmentError("policy publication descriptor is malformed")
        result: dict[str, str] = {}
        verified_files = [_FileSpec("publication.json", descriptor_bytes)]
        for relative, expected in (("plans/bootstrap-policy-v1.json", receipt.policy_sha256),
                                   ("catalog/artifacts.json", receipt.artifact_catalog_sha256)):
            raw, info = _readat(root_fd, relative, uid, 0o444)
            digest = _sha(raw)
            if info.st_nlink != 1 or digest != expected:
                raise BootstrapEnrollmentError("current policy file digest differs from the journal receipt")
            result[relative] = digest
            verified_files.append(_FileSpec(relative, raw))
        _verify_generation(receipt.generation_root, receipt.publication_sha256,
                           _canonical(descriptor), tuple(verified_files), uid)
        return descriptor, result
    finally:
        os.close(root_fd)


@dataclass(frozen=True, slots=True)
class _FileSpec:
    path: str
    data: bytes
    mode: int = 0o444


def _validate_compiled_documents(policy_bytes: bytes, catalog_bytes: bytes,
                                 selection_document: Mapping[str, Any], selection_sha: str,
                                 plan_id: str, plan_sha: str, policy_id: str,
                                 policy_sha: str, release_commit: str) -> None:
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
            or any(item not in catalog_model.artifacts for item in plan_row["allowed_artifact_ids"])):
        raise BootstrapEnrollmentError("compiled plan row or artifact allowlist is malformed")
    policy_rows = doc.get("bootstrap_policies")
    if (not isinstance(policy_rows, list)
            or not any(isinstance(row, dict) and row.get("artifact_id") == policy_id
                       and row.get("sha256") == policy_sha
                       and row.get("relative_path") == "plans/bootstrap-policy-v1.json"
                       for row in policy_rows)):
        raise BootstrapEnrollmentError("compiled selection does not join the exact bootstrap policy bytes")


def _publish_policy_generation(*, policy_root: Path, selection_path: Path,
                               journal_root: Path, compiled: CompiledRootSetupPublication,
                               release: Any, expected_selection_catalog_sha256: str | None,
                               expected_uid: int, root_journal: Any) -> RootSetupPublicationReceipt:
    """Filesystem publication core. All paths must be supplied by trusted caller."""
    if not policy_root.is_absolute() or not selection_path.is_absolute() or not journal_root.is_absolute():
        raise BootstrapEnrollmentError("policy publication roots must be absolute")
    if not _SHA.fullmatch(compiled.plan_sha256) or not _SHA.fullmatch(compiled.bootstrap_policy_sha256):
        raise BootstrapEnrollmentError("compiler artifact digest is malformed")
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
        descriptor, files = _build_descriptor(compiled, expected_selection_catalog_sha256, release)
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
        existing_policies = [row for row in final_selection.get("bootstrap_policies", [])
                             if not isinstance(row, dict)
                             or row.get("artifact_id") != POLICY_ARTIFACT_ID]
        existing_policies.append({
            "artifact_id": POLICY_ARTIFACT_ID,
            "relative_path": "plans/bootstrap-policy-v1.json",
            "sha256": compiled.bootstrap_policy_sha256,
        })
        final_selection["bootstrap_policies"] = existing_policies
        final_unsigned = {key: value for key, value in final_selection.items() if key != "catalog_sha256"}
        final_selection["catalog_sha256"] = _sha(_canonical(final_unsigned))
        final_selection_bytes = _canonical(final_selection)
        receipt_inputs = _receipt_input_handles(compiled)
        receipt = RootSetupPublicationReceipt(
            1, receipt_handle, compiled.transaction_handle, POLICY_GENERATION_ID,
            publication_sha, generation_path, generation_info.st_dev, generation_info.st_ino,
            _sha(compiled.policy_bytes), _sha(compiled.artifact_catalog_bytes),
            _sha(final_selection_bytes), _sha(descriptor_bytes),
            expected_selection_catalog_sha256, final_selection["catalog_sha256"],
            receipt_inputs, "prepared", _SEAL)
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
        _atomic_replace(selection_path, final_selection_bytes, expected_uid, 0o600,
                        compare_inode=current_selection)
        _fsync_dir(selection_path.parent)
        return receipt
    finally:
        os.close(lock_fd)


def _build_descriptor(compiled: CompiledRootSetupPublication,
                      predecessor_sha256: str | None, release: Any
                      ) -> tuple[dict[str, Any], tuple[_FileSpec, ...]]:
    policy_doc = _json_bytes(compiled.policy_bytes, "bootstrap policy")
    catalog_doc = _json_bytes(compiled.artifact_catalog_bytes, "artifact catalog")
    if _sha(compiled.policy_bytes) != compiled.bootstrap_policy_sha256:
        raise BootstrapEnrollmentError("bootstrap policy digest changed after compilation")
    catalog_sha = _sha(compiled.artifact_catalog_bytes)
    selection_bytes = _canonical(dict(compiled.selection_document))
    release.verify_current()
    template_rows = [row for row in release.files if "template" in row.roles]
    plan_rows = [row for row in release.files if "plan" in row.roles and row.artifact_id == compiled.plan_artifact_id]
    if len(template_rows) != 1 or len(plan_rows) != 1:
        raise BootstrapEnrollmentError("verified release lacks one compiler template and selected plan")
    source_receipts = list(_receipt_source_handles(compiled))
    session = getattr(compiled, "session", getattr(compiled, "initial_session", None))
    if session is None:
        raise BootstrapEnrollmentError("compiled publication lacks its sealed initial session")
    session_handle = getattr(session, "compilation_session_handle", None)
    if session_handle is None:
        session_handle = getattr(session, "session_handle", None)
    input_doc = {
        "release_commit": compiled.release_commit,
        "release_deployment_receipt_sha256": release.deployment_receipt_sha256,
        "release_closure_manifest_sha256": release.closure_manifest_sha256,
        "template_artifact_id": template_rows[0].artifact_id,
        "template_sha256": template_rows[0].sha256,
        "session_handle": session_handle,
        "transaction_handle": compiled.transaction_handle,
        "plan_artifact_id": compiled.plan_artifact_id,
        "plan_sha256": compiled.plan_sha256,
        "selection_catalog_sha256": compiled.selection_catalog_sha256,
        "source_receipt_handles": source_receipts,
        "observed_root_receipt_handle": compiled.observed_root_receipt_handle,
        "choices_sha256": getattr(compiled, "choices_sha256", None),
        "source_catalog_sha256": getattr(compiled, "source_catalog_sha256", None),
        "principal_selection_receipt_handle": getattr(session, "principal_selection_receipt_handle", None),
        "predecessor_selection_catalog_sha256": predecessor_sha256,
    }
    descriptor = {
        "schema": 1,
        "id": "installer-bootstrap-policy-publication-v1",
        "policy_sha256": _sha(compiled.policy_bytes),
        "artifact_catalog_sha256": catalog_sha,
        "selection_sha256": _sha(selection_bytes),
        "inputs": input_doc,
    }
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
    _, info = _read_fixed(path, uid, 0o600, 64 * 1024)
    _atomic_replace(path, _canonical(record), uid, 0o600, (info.st_dev, info.st_ino))
    _fsync_dir(path.parent)


def _receipt_input_handles(compiled: Any) -> tuple[str, ...]:
    handles = [compiled.observed_root_receipt_handle, *_receipt_source_handles(compiled)]
    if any(not isinstance(item, str) or not _HANDLE.fullmatch(item) for item in handles):
        raise BootstrapEnrollmentError("publication input receipt closure contains a malformed handle")
    return tuple(dict.fromkeys(handles))


def _receipt_source_handles(compiled: Any) -> tuple[str, ...]:
    handles = list(compiled.source_receipt_handles)
    session = getattr(compiled, "session", None)
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
        if (info.st_uid != uid or stat.S_IMODE(info.st_mode) != 0o555
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
                            if info.st_uid != uid or stat.S_IMODE(info.st_mode) != 0o555:
                                raise BootstrapEnrollmentError("existing policy generation directory custody differs")
                            child_fd = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                               dir_fd=directory_fd)
                            try:
                                walk(child_fd, relative)
                            finally:
                                os.close(child_fd)
                        elif stat.S_ISREG(info.st_mode) and info.st_uid == uid and info.st_nlink == 1:
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
              or current.st_uid != uid or stat.S_IMODE(current.st_mode) != mode):
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
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != uid or info.st_nlink != 1):
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
        if info.st_uid != uid or stat.S_IMODE(info.st_mode) != mode:
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
        if (info.st_uid != uid or stat.S_IMODE(info.st_mode) != mode
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
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != uid:
        raise BootstrapEnrollmentError("refusing to remove unowned publication staging path")
    os.chmod(path, 0o700)
    for child in path.iterdir():
        child_info = os.stat(child, follow_symlinks=False)
        if stat.S_ISDIR(child_info.st_mode):
            _remove_tree_owned(child, uid)
        elif stat.S_ISREG(child_info.st_mode) and child_info.st_uid == uid:
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
