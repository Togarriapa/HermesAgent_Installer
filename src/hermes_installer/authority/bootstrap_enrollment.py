"""Transactional root bootstrap for a dedicated Hermes service identity.

This module is the sole writer for a new protected service-generation snapshot.
All selection policy and artifact receipt resolution are supplied by root-owned
adapters; callers submit only opaque artifact receipt handles and an intent.
"""
from __future__ import annotations

import hashlib
import json
import os
import pwd
import grp
import secrets
import stat
import subprocess
import re
import fcntl
import time
import sys
import select
from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol


MAX_AUTHORITY_BYTES = 8 * 1024 * 1024
SERVICE_NAME = "hermes-installer"


class BootstrapEnrollmentError(RuntimeError):
    """Bootstrap failed safely; message text is suitable for a diagnostic."""


class BootstrapEnrollmentPending(BootstrapEnrollmentError):
    """A required root-enrolled artifact or account prerequisite is absent."""


@dataclass(frozen=True, slots=True)
class BootstrapEnrollmentRequest:
    artifact_receipt_handles: tuple[str, ...]
    operation_intent: str


@dataclass(frozen=True, slots=True)
class ServiceIdentity:
    name: str
    uid: int
    gid: int
    created: bool = False


@dataclass(frozen=True, slots=True)
class VerifiedArtifactReceipt:
    """Root resolver output. ``source`` is never accepted from a request."""
    receipt_id: str
    artifact_id: str
    sha256: str
    source: Path
    maximum_bytes: int


@dataclass(frozen=True, slots=True)
class EnrollmentPolicy:
    """Root-selected complete protected service catalog and private root layout."""
    service_profile_id: str
    principal_id: str
    generation_id: str
    source_artifact_id: str
    records: tuple[Mapping[str, Any], ...]
    # These active root catalogs must be selected explicitly, even when the
    # selected generation declares a capability unavailable with an empty list.
    resource_controller_roles: tuple[Mapping[str, Any], ...]
    native_mcp_tool_bindings: tuple[Mapping[str, Any], ...]
    remote_observation_enrollments: tuple[Mapping[str, Any], ...]
    native_schema_artifacts: tuple[Mapping[str, Any], ...] = ()
    composio_channel_enrollments: tuple[Mapping[str, Any], ...] = ()
    channel_delivery_bindings: tuple[Mapping[str, Any], ...] = ()
    protected_devices: tuple[Mapping[str, Any], ...] = ()
    protected_build_records: tuple[Mapping[str, Any], ...] = ()
    native_packages: tuple[Mapping[str, Any], ...] = ()
    memory_enrollments: tuple[Mapping[str, Any], ...] = ()
    operation_parameter_schemas: tuple[Mapping[str, Any], ...] = ()
    source_issuers: tuple[Mapping[str, Any], ...] = ()
    resource_jobs: tuple[Mapping[str, Any], ...] = ()
    remote_session_enrollments: tuple[Mapping[str, Any], ...] = ()
    resource_backend_enrollments: tuple[Mapping[str, Any], ...] = ()
    resource_body_recipes: tuple[Mapping[str, Any], ...] = ()
    resource_scope_bindings: tuple[Mapping[str, Any], ...] = ()
    resource_validators: tuple[Mapping[str, Any], ...] = ()
    root_journal_roots: tuple[Mapping[str, Any], ...] = ()
    # These active runtime selections are populated only from root-selected
    # receipts and catalog joins. Empty means the corresponding capability is
    # not selected in this generation.
    remote_startup_enrollments: tuple[Mapping[str, Any], ...] = ()
    private_loopback_networks: tuple[Mapping[str, Any], ...] = ()
    # v184 finite native AF_UNIX startup projection. These catalogs are empty
    # until their root-held source, endpoint and active-generation producer is
    # composed; callers do not get to submit them through an enrollment request.
    native_worker_network_records: tuple[Mapping[str, Any], ...] = ()
    active_network_generation_records: tuple[Mapping[str, Any], ...] = ()
    native_worker_runtime_records: tuple[Mapping[str, Any], ...] = ()
    selected_resource_executions: tuple[Mapping[str, Any], ...] = ()
    selected_application_runtimes: tuple[Mapping[str, Any], ...] = ()
    # Public network scopes become active only after their source-specific
    # target configuration receipt is selected and joined by root.
    public_web_scopes: tuple[Mapping[str, Any], ...] = ()
    memory_service_enablement_projections: tuple[Mapping[str, Any], ...] = ()
    native_schema_artifacts: tuple[Mapping[str, Any], ...] = ()
    composio_channel_enrollments: tuple[Mapping[str, Any], ...] = ()
    channel_delivery_bindings: tuple[Mapping[str, Any], ...] = ()
    activation_state: str = "active"
    authority_base: Mapping[str, Any] | None = None
    home_root: Path = Path("/var/lib/hermes-installer/services/default/home")
    work_root: Path = Path("/var/lib/hermes-installer/services/default/work")
    data_root: Path = Path("/var/lib/hermes-installer/services/default/data")


@dataclass(frozen=True, slots=True)
class EnrollmentReceipt:
    schema: int
    transaction_handle: str
    provision_receipt_handle: str
    generation_id: str
    generation_digest: str
    previous_generation_digest: str | None
    state: str
    enrollment_ids: tuple[str, ...]
    issued_monotonic: float
    expires_monotonic: float


@dataclass(frozen=True, slots=True, repr=False)
class VerifiedCommittedEnrollment:
    """Store-issued proof that a caller receipt matches the current durable CAS."""

    receipt: EnrollmentReceipt
    setup_session_id: str
    plan_digest: str
    target_id: str
    journal_transaction_id: str
    _store_seal: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class VerifiedRootSetupAuthorization:
    """Root-local proof returned only by the installed setup-session verifier."""
    target_id: str
    setup_session_id: str
    plan_digest: str
    operator_uid: int
    transaction_handle: str
    target_uid: int = 0
    target_gid: int = 0
    mode: str = "install"
    plan_artifact_id: str = ""
    launcher_artifact_id: str = ""
    launcher_sha256: str = ""
    root_actor_identity: Mapping[str, Any] = field(default_factory=dict)
    expected_previous_generation_digest: str | None = None
    root_journal_root: Mapping[str, Any] = field(default_factory=dict)
    operation_target_id: str = "service-generation:bootstrap:install"


class RootSetupAuthorizer(Protocol):
    def authorize(self, *, peer_uid: int, peer_gid: int,
                  request: BootstrapEnrollmentRequest) -> VerifiedRootSetupAuthorization: ...


class RootBootstrapProvisionOperation:
    """Fixed first-snapshot root-local entrypoint, separate from worker RPC.

    The socket acceptor must pass kernel SO_PEERCRED values. ``authorizer`` is
    assembled by the reviewed setup service and verifies a live local setup
    session plus target/plan admission; it must never be built from RPC fields.
    """
    operation = "enrollment.provision"
    capability = "installer-bootstrap-enrollment"
    target = "service-generation:bootstrap:install"

    def __init__(self, transaction: RootBootstrapEnrollment,
                 authorizer: RootSetupAuthorizer, *,
                 source_receipt_provider: Callable[[VerifiedRootSetupAuthorization], str] | None = None):
        self.transaction = transaction
        self.authorizer = authorizer
        self.source_receipt_provider = source_receipt_provider

    def handle(self, payload: Mapping[str, Any], *, peer_uid: int, peer_gid: int) -> dict[str, Any]:
        if type(peer_uid) is not int or peer_uid != 0 or type(peer_gid) is not int:
            raise BootstrapEnrollmentError("initial enrollment requires the root-local setup endpoint")
        if (not isinstance(payload, Mapping)
                or set(payload) != {"schema", "artifact_receipt_handles", "operation_intent"}
                or type(payload.get("schema")) is not int or payload["schema"] != 1
                or not isinstance(payload.get("artifact_receipt_handles"), list)):
            raise BootstrapEnrollmentError("bootstrap provision payload is malformed")
        request = BootstrapEnrollmentRequest(tuple(payload["artifact_receipt_handles"]),
                                             payload.get("operation_intent"))
        _validate_request(request)
        proof = self.authorizer.authorize(peer_uid=peer_uid, peer_gid=peer_gid, request=request)
        if (not isinstance(proof, VerifiedRootSetupAuthorization)
                or proof.operation_target_id != self.target
                or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", proof.setup_session_id)
                or not re.fullmatch(r"[0-9a-f]{64}", proof.plan_digest)
                or type(proof.operator_uid) is not int or proof.operator_uid < 0
                or proof.transaction_handle != request.operation_intent):
            raise BootstrapEnrollmentError("root-local setup admission is absent or invalid")
        if proof.mode == "resume":
            self.transaction.recover_for_setup(proof)
        if self.source_receipt_provider is not None:
            # Source acquisition is root-owned and fixed to the protected
            # Hermes pin. Only the transaction-scoped opaque handle crosses
            # into enrollment; archive/tree paths remain private to the
            # provider and verifier.
            source_handle = self.source_receipt_provider(proof)
            if not isinstance(source_handle, str) or not re.fullmatch(
                    r"[A-Za-z0-9_-]{32,128}", source_handle):
                raise BootstrapEnrollmentPending("pinned source receipt provider returned no valid opaque handle")
            if source_handle in request.artifact_receipt_handles:
                raise BootstrapEnrollmentError("root source provider reused a caller-supplied receipt handle")
            request = replace(request, artifact_receipt_handles=(
                *request.artifact_receipt_handles, source_handle))
        receipt = self.transaction.enroll(request, setup_authorization=proof)
        return _receipt_wire(receipt)


class BootstrapEnrollmentClient:
    """Typed client for the dedicated authenticated root setup transport."""
    def __init__(self, rpc: Callable[[str, Mapping[str, Any]], Mapping[str, Any]]):
        if not callable(rpc):
            raise ValueError("authenticated root setup RPC callable is required")
        self._rpc = rpc

    def provision(self, artifact_receipt_handles: tuple[str, ...],
                  operation_intent: str) -> EnrollmentReceipt:
        request = BootstrapEnrollmentRequest(artifact_receipt_handles, operation_intent)
        _validate_request(request)
        response = self._rpc("enrollment.provision", {
            "schema": 1,
            "artifact_receipt_handles": list(artifact_receipt_handles),
            "operation_intent": operation_intent,
        })
        return _receipt_from_wire(response)


def _receipt_wire(receipt: EnrollmentReceipt) -> dict[str, Any]:
    return {"schema": receipt.schema, "transaction_handle": receipt.transaction_handle,
            "provision_receipt_handle": receipt.provision_receipt_handle,
            "generation_id": receipt.generation_id, "generation_digest": receipt.generation_digest,
            "previous_generation_digest": receipt.previous_generation_digest,
            "state": receipt.state, "enrollment_ids": list(receipt.enrollment_ids),
            "issued_monotonic": receipt.issued_monotonic,
            "expires_monotonic": receipt.expires_monotonic}


def _receipt_from_wire(value: Mapping[str, Any]) -> EnrollmentReceipt:
    required = {"schema", "transaction_handle", "provision_receipt_handle", "generation_id",
                "generation_digest", "previous_generation_digest", "state", "enrollment_ids",
                "issued_monotonic", "expires_monotonic"}
    if not isinstance(value, Mapping) or set(value) != required:
        raise BootstrapEnrollmentError("root setup authority returned a malformed provision receipt")
    if (type(value["schema"]) is not int or value["schema"] != 1
            or not all(isinstance(value[name], str) and value[name] for name in
                       ("transaction_handle", "provision_receipt_handle", "generation_id"))
            or not re.fullmatch(r"[0-9a-f]{64}", str(value["generation_digest"]))
            or value["previous_generation_digest"] is not None
                and not re.fullmatch(r"[0-9a-f]{64}", str(value["previous_generation_digest"]))
            or value["state"] not in {"prepared", "committed", "incomplete", "rolled-back", "rolled_back"}
            or not isinstance(value["enrollment_ids"], list)
            or any(not isinstance(item, str) or not item for item in value["enrollment_ids"])
            or any(isinstance(value[key], bool) or not isinstance(value[key], (int, float))
                   for key in ("issued_monotonic", "expires_monotonic"))
            or value["expires_monotonic"] <= value["issued_monotonic"]
            or not time.monotonic() < value["expires_monotonic"] <= time.monotonic() + 300.0):
        raise BootstrapEnrollmentError("root setup authority returned an invalid provision receipt")
    return EnrollmentReceipt(1, value["transaction_handle"], value["provision_receipt_handle"],
                             value["generation_id"], value["generation_digest"],
                             value["previous_generation_digest"], value["state"],
                             tuple(value["enrollment_ids"]), float(value["issued_monotonic"]),
                             float(value["expires_monotonic"]))


class IdentityAdapter(Protocol):
    def ensure(self) -> ServiceIdentity: ...
    def remove_if_created(self, identity: ServiceIdentity) -> None: ...


class ReceiptResolver(Protocol):
    def resolve(self, handle: str, *,
                setup_authorization: VerifiedRootSetupAuthorization) -> VerifiedArtifactReceipt: ...


class ArtifactStoreReceiptResolver:
    """Resolve setup-issued opaque handles through the protected artifact CAS.

    ``lookup`` is a root-owned receipt-registry lookup. It returns a CAS store
    ID only after checking the current setup transaction/target; no RPC caller
    may provide the store ID, digest, or path as artifact proof.
    """
    def __init__(self, *, catalog: Any, artifact_root: Path,
                 lookup: Callable[[str, VerifiedRootSetupAuthorization], tuple[str, str]]):
        if not artifact_root.is_absolute() or not callable(lookup):
            raise ValueError("root artifact store and opaque receipt lookup are required")
        self.catalog = catalog
        self.artifact_root = artifact_root
        self.lookup = lookup

    def resolve(self, handle: str, *,
                setup_authorization: VerifiedRootSetupAuthorization) -> VerifiedArtifactReceipt:
        if not isinstance(handle, str) or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", handle):
            raise BootstrapEnrollmentError("artifact receipt handle is malformed")
        try:
            artifact_id, digest = self.lookup(handle, setup_authorization)
            resolved = self.catalog.resolve(artifact_id, digest, self.artifact_root, expected_uid=0)
            spec = self.catalog._artifact(artifact_id, digest)
        except Exception:
            raise BootstrapEnrollmentPending("artifact receipt is absent from the root receipt registry or CAS") from None
        if (resolved.path.is_symlink() or resolved.path.stat().st_uid != 0
                or resolved.sha256 != digest or resolved.artifact_id != artifact_id
                or not 1 <= spec.max_bytes <= 8 * 1024**3):
            raise BootstrapEnrollmentError("root artifact receipt no longer matches protected catalog custody")
        return VerifiedArtifactReceipt(handle, artifact_id, digest, resolved.path, spec.max_bytes)


class RootArtifactReceiptRegistry:
    """Durable opaque handles scoped to the root-issued setup transaction."""
    def __init__(self, root: Path = Path("/var/lib/hermes-installer/authority-journal/bootstrap-receipts"),
                 *, catalog: Any | None = None,
                 artifact_root: Path = Path("/var/lib/hermes-installer/artifacts")):
        if not root.is_absolute() or not artifact_root.is_absolute():
            raise ValueError("root receipt registry and artifact CAS roots must be absolute")
        self.root = root
        self.catalog = catalog
        self.artifact_root = artifact_root

    def mint(self, *, store_id: str, receipt_id: str,
             setup_authorization: VerifiedRootSetupAuthorization) -> str:
        if os.geteuid() != 0:
            raise BootstrapEnrollmentError("artifact receipt registration requires root")
        _validate_setup_authorization(setup_authorization)
        match = re.fullmatch(r"artifact:([A-Za-z0-9_.-]{1,128}):([0-9a-f]{64})", store_id)
        if (match is None or not isinstance(receipt_id, str)
                or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", receipt_id)):
            raise BootstrapEnrollmentError("verified artifact-store receipt is malformed")
        if self.catalog is None:
            raise BootstrapEnrollmentPending("root receipt registry requires its selected artifact catalog")
        try:
            artifact_spec = self.catalog._artifact(match.group(1), match.group(2))
            verified = self.catalog.resolve(match.group(1), match.group(2),
                                             self.artifact_root, expected_uid=0)
        except Exception:
            raise BootstrapEnrollmentError("receipt artifact is absent from the selected root catalog or CAS") from None
        if (artifact_spec.size_bytes is None or verified.size_bytes != artifact_spec.size_bytes
                or verified.sha256 != match.group(2)):
            raise BootstrapEnrollmentError("root catalog artifact receipt bytes do not match the verified CAS")
        _ensure_root_directory(self.root)
        handle = secrets.token_urlsafe(32)
        record = {"schema": 1, "handle": handle, "receipt_id": receipt_id,
                  "setup_session_id": setup_authorization.setup_session_id,
                  "transaction_handle": setup_authorization.transaction_handle,
                  "target_id": setup_authorization.target_id,
                  "operation_target_id": setup_authorization.operation_target_id,
                  "plan_digest": setup_authorization.plan_digest,
                  "operator_uid": setup_authorization.operator_uid,
                  "artifact_role": match.group(1), "artifact_id": match.group(1),
                  "sha256": match.group(2), "size_bytes": artifact_spec.size_bytes}
        _atomic_root_file(self.root / f"{handle}.json", _canonical(record), 0o600)
        return handle

    def lookup(self, handle: str, setup_authorization: VerifiedRootSetupAuthorization) -> tuple[str, str]:
        if os.geteuid() != 0:
            raise BootstrapEnrollmentError("artifact receipt lookup requires root")
        _validate_setup_authorization(setup_authorization)
        if not isinstance(handle, str) or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", handle):
            raise BootstrapEnrollmentPending("artifact receipt handle is malformed")
        path = self.root / f"{handle}.json"
        value = _read_json_if_owned(path)
        if (not isinstance(value, dict)
                or set(value) != {"schema", "handle", "receipt_id", "setup_session_id",
                                  "transaction_handle", "target_id", "operation_target_id",
                                  "plan_digest", "operator_uid", "artifact_role",
                                  "artifact_id", "sha256", "size_bytes"}
                or value.get("schema") != 1 or value.get("handle") != handle
                or value.get("setup_session_id") != setup_authorization.setup_session_id
                or value.get("transaction_handle") != setup_authorization.transaction_handle
                or value.get("target_id") != setup_authorization.target_id
                or value.get("plan_digest") != setup_authorization.plan_digest
                or value.get("operator_uid") != setup_authorization.operator_uid
                or value.get("operation_target_id") != RootBootstrapProvisionOperation.target
                or value.get("artifact_role") != value.get("artifact_id")
                or type(value.get("size_bytes")) is not int
                or not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", str(value.get("artifact_id", "")))
                or not re.fullmatch(r"[0-9a-f]{64}", str(value.get("sha256", "")))):
            raise BootstrapEnrollmentPending("artifact receipt is absent or belongs to another setup transaction")
        if self.catalog is None:
            raise BootstrapEnrollmentPending("root receipt registry catalog is unavailable")
        try:
            spec = self.catalog._artifact(value["artifact_id"], value["sha256"])
        except Exception:
            raise BootstrapEnrollmentPending("root receipt artifact is no longer cataloged") from None
        if spec.size_bytes != value["size_bytes"]:
            raise BootstrapEnrollmentError("root artifact receipt size differs from its selected catalog")
        return value["artifact_id"], value["sha256"]


@dataclass(frozen=True, slots=True, repr=False)
class RootSetupSessionHandle:
    """In-memory handle bound to the PIDFD-owning root setup store instance."""
    session_id: str
    _instance_seal: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class VerifiedRootSetupPlan:
    """Root catalog resolver output; none of these fields come from worker RPC."""
    artifact_id: str
    digest: str
    launcher_artifact_id: str
    launcher_sha256: str
    launcher_path: Path
    interpreter_path: Path
    interpreter_sha256: str
    module_closure: tuple[tuple[str, Path, str], ...]
    allowed_artifact_ids: tuple[str, ...] = ()


class InstalledRootSetupPlanResolver:
    """Load the strict root-deployed selection catalog and resolve one plan."""
    selection_path = Path("/etc/hermes-installer/root-setup-selection.json")
    selection_id = "installer-root-setup-selection-v1"
    plan_artifact_id = "installer-root-setup-plan-v1"
    launcher_artifact_id = "installer-root-setup-launcher-v1"
    interpreter_artifact_id = "installer-root-setup-interpreter-v1"

    def resolve(self, artifact_id: str) -> VerifiedRootSetupPlan:
        if artifact_id != self.plan_artifact_id or os.geteuid() != 0 or not _linux():
            raise BootstrapEnrollmentError("selected root setup plan is unavailable")
        raw = _read_secure_root_bytes(self.selection_path, 2 * 1024 * 1024, 0o600)
        try:
            value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_pairs)
        except (UnicodeError, json.JSONDecodeError, ValueError):
            raise BootstrapEnrollmentError("root setup selection catalog is malformed") from None
        required = {"schema", "selection_id", "installer_release_commit", "launcher",
                    "interpreter", "module_closure", "plans", "catalog_sha256", "release_root"}
        if (not isinstance(value, dict) or set(value) != required or value.get("schema") != 1
                or value.get("selection_id") != self.selection_id
                or not isinstance(value.get("installer_release_commit"), str)
                or not re.fullmatch(r"[0-9a-f]{40}", value["installer_release_commit"])
                or not isinstance(value.get("module_closure"), list)
                or not 1 <= len(value["module_closure"]) <= 1024
                or not isinstance(value.get("plans"), list)
                or not 1 <= len(value["plans"]) <= 16
                or not re.fullmatch(r"[0-9a-f]{64}", str(value.get("catalog_sha256", "")))):
            raise BootstrapEnrollmentError("root setup selection catalog has an invalid schema")
        digest_input = {key: item for key, item in value.items() if key != "catalog_sha256"}
        if not secrets.compare_digest(hashlib.sha256(_canonical(digest_input, ensure_ascii=False)).hexdigest(),
                                      value["catalog_sha256"]):
            raise BootstrapEnrollmentError("root setup selection catalog digest is invalid")
        release = value["release_root"]
        if (not isinstance(release, dict) or set(release) !=
                {"root_id", "absolute_path", "device", "inode", "deployment_receipt_sha256"}
                or not isinstance(release["root_id"], str)
                or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", release["root_id"])
                or not isinstance(release["absolute_path"], str)
                or not Path(release["absolute_path"]).is_absolute()
                or "\x00" in release["absolute_path"]
                or type(release["device"]) is not int or release["device"] < 0
                or type(release["inode"]) is not int or release["inode"] <= 0):
            raise BootstrapEnrollmentError("root selection release-root custody row is malformed")
        _validate_sha256(release["deployment_receipt_sha256"], "deployment receipt")
        root = Path(release["absolute_path"])
        root_fd = _open_immutable_release_root(root, release["device"], release["inode"])
        try:
            rows = [value["launcher"], value["interpreter"], *value["module_closure"], *value["plans"]]
            ids: set[str] = set()
            paths: set[str] = set()
            for row in rows:
                if (not isinstance(row, dict) or not isinstance(row.get("artifact_id"), str)
                        or not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", row["artifact_id"])
                        or not isinstance(row.get("relative_path"), str)):
                    raise BootstrapEnrollmentError("root setup catalog row is malformed")
                if row["artifact_id"] in ids or row.get("relative_path") in paths:
                    raise BootstrapEnrollmentError("root setup catalog contains duplicate IDs or paths")
                ids.add(row["artifact_id"]); paths.add(row.get("relative_path"))
            plan_fields = {"artifact_id", "relative_path", "sha256", "baseline_tag_object",
                           "baseline_commit", "baseline_tree_sha256", "amendment_manifest_sha256",
                           "allowed_artifact_ids"}
            for candidate in value["plans"]:
                if (set(candidate) != plan_fields
                        or candidate["baseline_tag_object"] != "c47c90cf2e0a6b1cd5779257fdcba9e487ee08f8"
                        or candidate["baseline_commit"] != "653ac5fbc7a02613c9951859a7d794599603459b"
                        or not isinstance(candidate["allowed_artifact_ids"], list)
                        or not candidate["allowed_artifact_ids"]
                        or len(candidate["allowed_artifact_ids"]) > 256
                        or len(set(candidate["allowed_artifact_ids"])) != len(candidate["allowed_artifact_ids"])):
                    raise BootstrapEnrollmentError("root setup plan provenance binding is malformed")
                _validate_sha256(candidate["sha256"], "root setup plan")
                _validate_sha256(candidate["baseline_tree_sha256"], "baseline tree")
                _validate_sha256(candidate["amendment_manifest_sha256"], "amendment manifest")
                for allowed in candidate["allowed_artifact_ids"]:
                    _validate_catalog_id(allowed, "selected allowed artifact")
            launcher_path, launcher_sha = self._fixed_file(value["launcher"], self.launcher_artifact_id,
                                                           root, root_fd)
            interpreter_path, interpreter_sha = self._fixed_file(
                value["interpreter"], self.interpreter_artifact_id, root, root_fd)
            modules: list[tuple[str, Path, str]] = []
            names: set[str] = set()
            for row in value["module_closure"]:
                if (not isinstance(row, dict) or set(row) != {"module_name", "artifact_id", "relative_path", "sha256"}
                        or not isinstance(row.get("module_name"), str)
                        or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.]{0,191}", row["module_name"])):
                    raise BootstrapEnrollmentError("root setup module selection is malformed")
                if row["module_name"] in names:
                    raise BootstrapEnrollmentError("root setup module selection contains duplicate names")
                path = self._resolve_file(row, row["artifact_id"], root, root_fd)
                names.add(row["module_name"])
                modules.append((row["module_name"], path, row["sha256"]))
            selected = [row for row in value["plans"] if isinstance(row, dict) and row.get("artifact_id") == artifact_id]
            if len(selected) != 1:
                raise BootstrapEnrollmentError("root setup plan is absent or ambiguous in the selection catalog")
            planrow = selected[0]
            self._resolve_file(planrow, artifact_id, root, root_fd)
            return VerifiedRootSetupPlan(
                artifact_id=artifact_id, digest=planrow["sha256"],
                launcher_artifact_id=self.launcher_artifact_id, launcher_sha256=launcher_sha,
                launcher_path=launcher_path, interpreter_path=interpreter_path,
                interpreter_sha256=interpreter_sha, module_closure=tuple(modules),
                allowed_artifact_ids=tuple(planrow["allowed_artifact_ids"]))
        finally:
            os.close(root_fd)

    @staticmethod
    def _fixed_file(value: Any, artifact_id: str, root: Path, root_fd: int) -> tuple[Path, str]:
        if not isinstance(value, dict) or set(value) != {"artifact_id", "relative_path", "sha256"}:
            raise BootstrapEnrollmentError("root setup executable selection is malformed")
        path = InstalledRootSetupPlanResolver._resolve_file(value, artifact_id, root, root_fd)
        info = _verified_installed_file(path, value["sha256"])
        if not info.st_mode & 0o111:
            raise BootstrapEnrollmentError("selected root setup launcher or interpreter is not executable")
        return path, value["sha256"]

    @staticmethod
    def _resolve_file(row: Mapping[str, Any], artifact_id: str, root: Path, root_fd: int) -> Path:
        if row.get("artifact_id") != artifact_id:
            raise BootstrapEnrollmentError("root setup catalog role does not match its fixed artifact")
        relative = row.get("relative_path")
        if (not isinstance(relative, str) or not relative or relative.startswith("/")
                or "\\" in relative or any(part in {"", ".", ".."} for part in relative.split("/"))):
            raise BootstrapEnrollmentError("root setup catalog path is not a normalized relative path")
        _validate_sha256(row.get("sha256"), "installed file")
        path = root.joinpath(*relative.split("/"))
        _verify_release_file_at(root_fd, relative, row["sha256"])
        return path


class RootSetupPlanResolver(Protocol):
    def resolve(self, artifact_id: str) -> VerifiedRootSetupPlan: ...


class RootSetupActorVerifier(Protocol):
    def verify_current(self, plan: VerifiedRootSetupPlan) -> Mapping[str, Any]: ...


class InstalledRootSetupActorVerifier:
    """Verify the executing Linux root CLI against one root-selected plan."""
    def verify_current(self, plan: VerifiedRootSetupPlan) -> Mapping[str, Any]:
        if (os.name != "posix" or not Path("/proc/sys/kernel/ostype").exists()
                or os.getuid() != 0 or os.geteuid() != 0):
            raise BootstrapEnrollmentPending("root setup requires the installed Linux root launcher")
        launcher = _verified_installed_file(plan.launcher_path, plan.launcher_sha256)
        interpreter = _verified_installed_file(plan.interpreter_path, plan.interpreter_sha256)
        actual_entrypoint = Path(sys.argv[0])
        if not actual_entrypoint.is_absolute():
            actual_entrypoint = Path.cwd() / actual_entrypoint
        if actual_entrypoint != plan.launcher_path:
            raise BootstrapEnrollmentError("current process is not the selected installed root setup launcher")
        if Path(sys.executable) != plan.interpreter_path:
            raise BootstrapEnrollmentError("current interpreter is outside the selected root setup plan")
        modules = []
        for module_name, path, digest in plan.module_closure:
            info = _verified_installed_file(path, digest)
            module = sys.modules.get(module_name)
            origin = getattr(getattr(module, "__spec__", None), "origin", None)
            if module is None or not isinstance(origin, str) or Path(origin) != path:
                raise BootstrapEnrollmentError("imported root setup module origin differs from the selected release closure")
            modules.append({"path": str(path), "sha256": digest,
                            "module_name": module_name,
                            "device": info.st_dev, "inode": info.st_ino})
        if not modules:
            raise BootstrapEnrollmentError("root setup plan has no reviewed Python module closure")
        if (os.environ.get("PYTHONPATH") or os.environ.get("PYTHONHOME")
                or not sys.flags.no_user_site or sys.flags.isolated == 0
                or any(not isinstance(entry, str) or not entry or not Path(entry).is_absolute()
                       for entry in sys.path)):
            raise BootstrapEnrollmentError("root setup Python import environment is not isolated")
        for entry in sys.path:
            _verify_import_search_path(Path(entry))
        cwd = Path.cwd()
        if cwd in {Path(entry) for entry in sys.path}:
            raise BootstrapEnrollmentError("root setup current directory is an import path")
        start = _process_start_time(os.getpid())
        return {"pid": os.getpid(), "process_start_time": start,
                "launcher_path": str(plan.launcher_path), "launcher_device": launcher.st_dev,
                "launcher_inode": launcher.st_ino, "launcher_sha256": plan.launcher_sha256,
                "interpreter_path": str(plan.interpreter_path),
                "interpreter_device": interpreter.st_dev, "interpreter_inode": interpreter.st_ino,
                "interpreter_sha256": plan.interpreter_sha256,
                "module_closure": modules}


@dataclass(slots=True)
class _LiveSetupSession:
    handle: RootSetupSessionHandle
    record: dict[str, Any]
    plan: VerifiedRootSetupPlan
    pidfd: int
    instance_seal: str


class RootSetupSessionStore:
    """Root-private first-snapshot session/intent store for installed CLI use.

    Production construction requires the verified plan resolver, installed
    actor verifier, and the same registry used by source/runtime importers.
    Session handles are valid only in this store instance and process; saved
    JSON cannot restore a capability after restart.
    """
    def __init__(self, *, plan_resolver: RootSetupPlanResolver,
                 actor_verifier: RootSetupActorVerifier,
                 receipt_registry: RootArtifactReceiptRegistry,
                 initial_compilation_registry: Any | None = None,
                 session_root: Path = Path("/var/lib/hermes-installer/authority-journal/setup-sessions"),
                 transaction_root: Path = Path("/var/lib/hermes-installer/authority-journal/bootstrap-transactions"),
                 authority_path: Path = Path("/etc/hermes-installer/authority.json")):
        if (not session_root.is_absolute() or not transaction_root.is_absolute()
                or not authority_path.is_absolute()
                or not callable(getattr(plan_resolver, "resolve", None))
                or not callable(getattr(actor_verifier, "verify_current", None))
                or not callable(getattr(receipt_registry, "lookup", None))):
            raise ValueError("root setup session dependencies are incomplete")
        if (transaction_root.parent != session_root.parent
                or receipt_registry.root != session_root.parent / "bootstrap-receipts"):
            raise ValueError("setup sessions, receipts, and transactions must share the selected root journal")
        self.plan_resolver = plan_resolver
        self.actor_verifier = actor_verifier
        self.receipt_registry = receipt_registry
        self.initial_compilation_registry = initial_compilation_registry
        self.session_root = session_root
        self.transaction_root = transaction_root
        self.authority_path = authority_path
        self._instance_seal = secrets.token_hex(32)
        self._sessions: dict[str, _LiveSetupSession] = {}

    def begin_from_initial_publication(self, handoff_handle: str) -> RootSetupSessionHandle:
        """Adopt the published stage-zero choices into a new live setup session.

        The registry owns the publication proof and consumes the handoff once. The
        only values used to construct the normal session are read from that sealed
        root DTO; callers cannot supply a target account, plan, or operation intent.
        """
        registry = self.initial_compilation_registry
        if registry is None or not callable(getattr(registry, "resolve_handoff", None)):
            raise BootstrapEnrollmentPending("initial root publication handoff registry is unavailable")
        from .bootstrap_runtime_factory import RootInitialPublicationHandoff
        handoff = registry.resolve_handoff(handoff_handle)
        if not isinstance(handoff, RootInitialPublicationHandoff) or handoff._initial_session is None:
            raise BootstrapEnrollmentPending("initial publication handoff is not registry-issued")
        initial = handoff._initial_session
        if (initial.phase != "initial-compilation"
                or handoff.expires_monotonic <= time.monotonic()
                or handoff.principal_identity_kind
                   != initial._choices.selected_principal_identity_kind
                or handoff.principal_identity_kind not in {"authentik-subject-v1", "linux-local-owner-v1"}
                or not re.fullmatch(r"[0-9a-f]{64}", handoff.plan_sha256)):
            raise BootstrapEnrollmentPending("initial publication handoff is stale or malformed")
        verify_initial = getattr(registry, "verify_initial_session", None)
        if not callable(verify_initial):
            raise BootstrapEnrollmentPending("initial compilation registry cannot revalidate the stage-zero session")
        verify_initial(initial)
        choices = initial._choices
        if choices is None:
            raise BootstrapEnrollmentPending("published stage-zero choices are unavailable")
        handle = self.begin_local(
            mode=choices.mode,
            selected_plan_artifact_id=initial.plan_artifact_id,
            target_account_name=choices.target_account_name,
        )
        live = self._live(handle)
        if live.record["plan_digest"] != handoff.plan_sha256:
            self.close_session(handle)
            raise BootstrapEnrollmentPending("installed setup plan changed after initial publication")
        # Persist a recoverable intent before the registry's one-use transition.
        live.record["initial_publication"] = {
            "handoff_handle": handoff_handle,
            "publication_receipt_handle": handoff.publication_receipt_handle,
            "publication_sha256": handoff.publication_sha256,
            "compilation_session_handle": handoff.compilation_session_handle,
            "compilation_transaction_handle": handoff.compilation_transaction_handle,
            "choices_sha256": handoff.choices_sha256,
            "principal_selection_receipt_handle": handoff.principal_selection_receipt_handle,
            "principal_identity_kind": handoff.principal_identity_kind,
            "artifact_receipt_handles": list(handoff.artifact_receipt_handles),
            "adoption_state": "pending",
        }
        _atomic_root_file(self.session_root / f"{handle.session_id}.json",
                          _canonical(live.record), 0o600)
        try:
            adopted = registry.adopt_handoff(handoff_handle, handle, self)
            proof = self._proof(live)
            if (adopted.normal_setup_session_id != handle.session_id
                    or adopted.normal_transaction_handle != proof.transaction_handle):
                raise BootstrapEnrollmentPending("adopted publication handoff does not join the new session")
            live.record["initial_publication"]["adoption_state"] = "adopted"
            live.record["initial_publication"]["normal_setup_session_id"] = handle.session_id
            live.record["initial_publication"]["normal_transaction_handle"] = proof.transaction_handle
            _atomic_root_file(self.session_root / f"{handle.session_id}.json",
                              _canonical(live.record), 0o600)
            return handle
        except Exception:
            # A consumed handoff is never silently recreated. Keep the durable
            # pending record for root reconciliation and invalidate this process handle.
            self.close_session(handle)
            raise

    def begin_local(self, *, mode: str, selected_plan_artifact_id: str,
                    target_account_name: str) -> RootSetupSessionHandle:
        if os.getuid() != 0 or os.geteuid() != 0 or not _linux():
            raise BootstrapEnrollmentPending("root-local setup sessions require the installed Linux root CLI")
        if mode not in {"install", "repair", "resume"}:
            raise BootstrapEnrollmentError("root setup mode is not a reviewed lifecycle intent")
        _validate_catalog_id(selected_plan_artifact_id, "selected plan artifact")
        if not isinstance(target_account_name, str) or not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", target_account_name):
            raise BootstrapEnrollmentError("target account name is malformed")
        try:
            target = pwd.getpwnam(target_account_name)
        except KeyError:
            raise BootstrapEnrollmentPending("selected local target account does not exist") from None
        if target.pw_uid <= 0 or target.pw_gid <= 0:
            raise BootstrapEnrollmentError("root service setup cannot target the superuser account")
        plan = self.plan_resolver.resolve(selected_plan_artifact_id)
        if (not isinstance(plan, VerifiedRootSetupPlan)
                or plan.artifact_id != selected_plan_artifact_id
                or not re.fullmatch(r"[0-9a-f]{64}", plan.digest)
                or not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", plan.launcher_artifact_id)
                or not re.fullmatch(r"[0-9a-f]{64}", plan.launcher_sha256)):
            raise BootstrapEnrollmentError("selected root setup plan is not catalog verified")
        actor = dict(self.actor_verifier.verify_current(plan))
        if actor.get("pid") != os.getpid() or not actor.get("process_start_time"):
            raise BootstrapEnrollmentError("root setup launcher identity does not match the current process")
        machine_id = _read_machine_id()
        target_id = "local-target-" + hashlib.sha256(
            f"{machine_id}:{target.pw_uid}:{target.pw_gid}".encode("utf-8")).hexdigest()[:32]
        _ensure_root_directory(self.session_root)
        journal_root = self.session_root.parent
        journal_info = _secure_directory_identity(journal_root)
        authority = self.authority_loader_for_session()
        previous = authority.get("service_generations", {}).get("generation_digest") if authority else None
        session_id = "setup-" + secrets.token_hex(16)
        transaction_handle = self._resume_transaction(target_id, plan.artifact_id) if mode == "resume" else None
        transaction_handle = transaction_handle or ("transaction-" + secrets.token_hex(32))
        issued = time.monotonic()
        record = {
            "schema": 1, "setup_session_id": session_id, "target_id": target_id,
            "operator_uid": os.getuid(), "target_uid": target.pw_uid, "target_gid": target.pw_gid,
            "mode": mode, "plan_artifact_id": plan.artifact_id, "plan_digest": plan.digest,
            "launcher_artifact_id": plan.launcher_artifact_id,
            "launcher_sha256": plan.launcher_sha256,
            "root_actor_identity": actor, "transaction_handle": transaction_handle,
            "expected_previous_generation_digest": previous,
            "issued_monotonic": issued, "expires_monotonic": issued + 600.0,
            "boot_id": _read_boot_id(),
            "root_journal_root": {
                "root_id": "installer-authority-journal-v1",
                "absolute_path": str(journal_root), "owner_uid": 0, "owner_gid": 0,
                "mode": 0o700, "device": journal_info.st_dev, "inode": journal_info.st_ino,
                "generation": "journal-" + secrets.token_hex(16),
                "purpose": "authority-journal",
            },
        }
        active_sessions = [item for item in self.session_root.glob("setup-*.json")
                           if _read_json_if_owned(item) is not None]
        if len(active_sessions) >= 64:
            raise BootstrapEnrollmentPending("root setup session journal is full; reconcile expired sessions first")
        _atomic_root_file(self.session_root / f"{session_id}.json", _canonical(record), 0o600)
        if not hasattr(os, "pidfd_open"):
            (self.session_root / f"{session_id}.json").unlink(missing_ok=True)
            raise BootstrapEnrollmentPending("this Linux kernel does not support PIDFD-bound root setup")
        pidfd = os.pidfd_open(os.getpid(), 0)
        seal = secrets.token_hex(32)
        handle = RootSetupSessionHandle(session_id, seal)
        self._sessions[session_id] = _LiveSetupSession(handle, record, plan, pidfd, seal)
        return handle

    def operation_intent(self, session_handle: RootSetupSessionHandle) -> str:
        return self._live(session_handle).record["transaction_handle"]

    def close_session(self, session_handle: RootSetupSessionHandle) -> None:
        if (not isinstance(session_handle, RootSetupSessionHandle)
                or not secrets.compare_digest(session_handle._instance_seal, self._instance_seal)):
            raise BootstrapEnrollmentError("root setup session handle is not owned by this store instance")
        live = self._sessions.pop(session_handle.session_id, None)
        if live is None or not secrets.compare_digest(live.instance_seal, session_handle._instance_seal):
            raise BootstrapEnrollmentError("root setup session is not live in this store")
        os.close(live.pidfd)

    def record_receipt(self, session_handle: RootSetupSessionHandle,
                       receipt: EnrollmentReceipt) -> None:
        live = self._live(session_handle)
        if (not isinstance(receipt, EnrollmentReceipt)
                or receipt.transaction_handle != live.record["transaction_handle"]
                or receipt.state not in {"prepared", "committed"}):
            raise BootstrapEnrollmentError("root setup receipt does not join the live transaction")
        live.record["expected_previous_generation_digest"] = receipt.generation_digest
        _atomic_root_file(self.session_root / f"{live.record['setup_session_id']}.json",
                          _canonical(live.record), 0o600)

    def verify_committed_receipt(
        self, receipt: EnrollmentReceipt, authorization: VerifiedRootSetupAuthorization,
    ) -> VerifiedCommittedEnrollment:
        """Verify an enrollment DTO against its root transaction journal and CAS."""
        if not isinstance(receipt, EnrollmentReceipt) or not isinstance(authorization, VerifiedRootSetupAuthorization):
            raise BootstrapEnrollmentPending("committed enrollment verification requires typed root proofs")
        live = self._sessions.get(authorization.setup_session_id)
        if live is None:
            raise BootstrapEnrollmentPending("committed enrollment session is no longer live")
        current = self._proof(self._live(live.handle))
        if current != authorization:
            raise BootstrapEnrollmentPending("committed enrollment authorization is stale")
        if (receipt.schema != 1 or receipt.state != "committed"
                or type(receipt.issued_monotonic) not in (int, float)
                or type(receipt.expires_monotonic) not in (int, float)
                or receipt.expires_monotonic <= time.monotonic()
                or receipt.expires_monotonic <= receipt.issued_monotonic
                or receipt.expires_monotonic - receipt.issued_monotonic > 300.001
                or receipt.transaction_handle != current.transaction_handle
                or not re.fullmatch(r"[0-9a-f]{48}", receipt.provision_receipt_handle)
                or not re.fullmatch(r"[0-9a-f]{64}", receipt.generation_digest)
                or (receipt.previous_generation_digest is not None
                    and not re.fullmatch(r"[0-9a-f]{64}", receipt.previous_generation_digest))
                or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", receipt.generation_id)):
            raise BootstrapEnrollmentPending("enrollment receipt is not a current committed receipt")
        matches: list[tuple[str, Mapping[str, Any]]] = []
        for path in self.transaction_root.glob("[0-9a-f]" * 32 + ".json"):
            row = _read_json_if_owned(path)
            if not isinstance(row, dict):
                continue
            setup = row.get("setup_authorization")
            if (row.get("state") == "committed" and isinstance(setup, dict)
                    and setup.get("transaction_handle") == receipt.transaction_handle
                    and setup.get("setup_session_id") == current.setup_session_id
                    and setup.get("plan_digest") == current.plan_digest
                    and setup.get("target_id") == current.target_id
                    and setup.get("expected_previous_generation_digest") == receipt.previous_generation_digest
                    and row.get("generation_digest") == receipt.generation_digest
                    and row.get("previous_generation_digest") == receipt.previous_generation_digest
                    and live.record["expected_previous_generation_digest"] in {
                        receipt.previous_generation_digest, receipt.generation_digest}
                    and row.get("provision_receipt_handle") == receipt.provision_receipt_handle):
                matches.append((path.stem, row))
        if len(matches) != 1:
            raise BootstrapEnrollmentPending("committed enrollment does not match one durable setup transaction")
        transaction_id, journal = matches[0]
        authority = self.authority_loader_for_session()
        snapshot = authority.get("service_generations") if isinstance(authority, Mapping) else None
        if (not isinstance(snapshot, Mapping)
                or snapshot.get("generation_id") != receipt.generation_id
                or snapshot.get("generation_digest") != receipt.generation_digest
                or snapshot.get("generation_digest") != journal.get("generation_digest")):
            raise BootstrapEnrollmentPending("committed enrollment CAS is no longer the selected authority generation")
        return VerifiedCommittedEnrollment(
            receipt, current.setup_session_id, current.plan_digest, current.target_id,
            transaction_id, self._instance_seal,
        )

    def bootstrap_client(self, session_handle: RootSetupSessionHandle,
                         transaction: RootBootstrapEnrollment, *,
                         source_receipt_provider: Callable[[VerifiedRootSetupAuthorization], str] | None = None
                         ) -> BootstrapEnrollmentClient:
        live = self._live(session_handle)
        if (transaction.transaction_root != self.transaction_root
                or transaction.root_journal_path != self.session_root.parent
                or getattr(transaction.receipt_resolver, "artifact_root", None)
                != self.receipt_registry.artifact_root):
            raise BootstrapEnrollmentError("root bootstrap transaction does not share the setup session custody roots")
        if source_receipt_provider is None:
            if self.receipt_registry.catalog is None:
                raise BootstrapEnrollmentPending("root setup has no pinned artifact catalog for source acquisition")
            from ..hermes_source import PinnedHermesSourceProvisioner
            fetcher = RootLocalCatalogArtifactFetcher(
                catalog=self.receipt_registry.catalog,
                artifact_root=self.receipt_registry.artifact_root,
                session_store=self, session_handle=session_handle)
            source_receipt_provider = PinnedHermesSourceProvisioner(
                fetcher=fetcher, catalog=self.receipt_registry.catalog,
                artifact_root=fetcher.artifact_root, receipt_registry=self.receipt_registry,
                expected_uid=0)
        authorizer = _LiveRootSetupAuthorizer(self, live)
        operation = RootBootstrapProvisionOperation(
            transaction, authorizer, source_receipt_provider=source_receipt_provider)
        transport = RootLocalBootstrapTransport(self, live.handle, operation)
        return BootstrapEnrollmentClient(transport.invoke)

    def _live(self, session_handle: RootSetupSessionHandle) -> _LiveSetupSession:
        if (not isinstance(session_handle, RootSetupSessionHandle)
                or not secrets.compare_digest(session_handle._instance_seal, self._instance_seal)):
            raise BootstrapEnrollmentError("root setup session handle is not owned by this store instance")
        live = self._sessions.get(session_handle.session_id)
        if (live is None or not secrets.compare_digest(live.instance_seal, session_handle._instance_seal)
                or live.record["root_actor_identity"].get("pid") != os.getpid()
                or live.record["boot_id"] != _read_boot_id()
                or not time.monotonic() < live.record["expires_monotonic"]):
            raise BootstrapEnrollmentPending("root setup session expired, restarted, or belongs to another process")
        poller = select.poll()
        poller.register(live.pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
        if poller.poll(0):
            raise BootstrapEnrollmentPending("root setup actor exited")
        current_actor = dict(self.actor_verifier.verify_current(live.plan))
        if current_actor != live.record["root_actor_identity"]:
            raise BootstrapEnrollmentError("root setup launcher or module closure changed during session")
        current_journal = _secure_directory_identity(Path(live.record["root_journal_root"]["absolute_path"]))
        selection = live.record["root_journal_root"]
        if (current_journal.st_dev != selection["device"] or current_journal.st_ino != selection["inode"]
                or current_journal.st_uid != 0 or current_journal.st_gid != 0
                or stat.S_IMODE(current_journal.st_mode) != 0o700):
            raise BootstrapEnrollmentError("root authority journal directory identity changed")
        return live

    def current_deadline(self, session_handle: RootSetupSessionHandle) -> float:
        """Return the monotonic expiry of a fully revalidated live setup session."""
        live = self._live(session_handle)
        deadline = live.record.get("expires_monotonic")
        if type(deadline) not in (int, float) or deadline <= time.monotonic():
            raise BootstrapEnrollmentPending("root setup session deadline is unavailable or expired")
        return float(deadline)

    def _handle_for_session(self, session_id: str) -> RootSetupSessionHandle:
        live = self._sessions.get(session_id)
        if live is None:
            raise BootstrapEnrollmentPending("root setup session is not live in this process")
        return live.handle

    def _resume_transaction(self, target_id: str, plan_artifact_id: str) -> str | None:
        candidates: list[tuple[int, str, bool]] = []
        for path in self.session_root.glob("setup-*.json"):
            record = _read_json_if_owned(path)
            if (not isinstance(record, dict) or record.get("schema") != 1
                    or record.get("target_id") != target_id
                    or record.get("plan_artifact_id") != plan_artifact_id
                    or not isinstance(record.get("transaction_handle"), str)):
                continue
            transaction_handle = record["transaction_handle"]
            has_checkpoint = bool(record.get("artifact_fetch_actions"))
            journal_time = path.stat().st_mtime_ns
            for journal_path in self.transaction_root.glob("[0-9a-f]" * 32 + ".json"):
                journal = _read_json_if_owned(journal_path)
                setup = journal.get("setup_authorization") if isinstance(journal, dict) else None
                if (isinstance(setup, dict) and setup.get("transaction_handle") == transaction_handle
                        and setup.get("target_id") == target_id
                        and setup.get("plan_artifact_id") == plan_artifact_id):
                    has_checkpoint = True
                    journal_time = max(journal_time, journal_path.stat().st_mtime_ns)
            if has_checkpoint:
                candidates.append((journal_time, transaction_handle, True))
        if not candidates:
            raise BootstrapEnrollmentPending("no root-owned transaction checkpoint matches the selected local target and plan")
        candidates.sort(reverse=True)
        return candidates[0][1]

    def _load_authority_for_session(self) -> Mapping[str, Any] | None:
        if not self.authority_path.exists():
            return None
        if not _root_file_ok(self.authority_path):
            raise BootstrapEnrollmentError("existing authority file is not root-owned mode 0600")
        from .enrollment import read_protected_file
        return json.loads(read_protected_file(self.authority_path, expected_uid=0,
                                              maximum=MAX_AUTHORITY_BYTES).decode("utf-8"),
                          object_pairs_hook=_unique_pairs)

    def record_artifact_fetch(self, session_handle: RootSetupSessionHandle, *,
                              artifact_id: str, sha256: str, size_bytes: int,
                              receipt_id: str) -> None:
        live = self._live(session_handle)
        _validate_catalog_id(artifact_id, "fetched artifact ID")
        if (not re.fullmatch(r"[0-9a-f]{64}", sha256) or type(size_bytes) is not int
                or size_bytes < 1 or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", receipt_id)):
            raise BootstrapEnrollmentError("root source fetch receipt is malformed")
        rows = live.record.setdefault("artifact_fetch_receipts", [])
        if len(rows) >= 64:
            raise BootstrapEnrollmentPending("root setup artifact receipt journal is full")
        rows.append({"receipt_id": receipt_id, "artifact_id": artifact_id,
                     "sha256": sha256, "size_bytes": size_bytes})
        _atomic_root_file(self.session_root / f"{live.record['setup_session_id']}.json",
                          _canonical(live.record), 0o600)

    # Kept as a method so tests can substitute no host state only by replacing
    # the store class, never by passing caller-selected authority paths.
    def authority_loader_for_session(self) -> Mapping[str, Any] | None:
        return self._load_authority_for_session()


class _LiveRootSetupAuthorizer:
    def __init__(self, store: RootSetupSessionStore, live: _LiveSetupSession):
        self.store = store
        self.session_id = live.record["setup_session_id"]

    def authorize(self, *, peer_uid: int, peer_gid: int,
                  request: BootstrapEnrollmentRequest) -> VerifiedRootSetupAuthorization:
        if (type(peer_uid) is not int or peer_uid != os.getuid() or peer_uid != 0
                or type(peer_gid) is not int or peer_gid != os.getgid()):
            raise BootstrapEnrollmentError("root setup actor does not match kernel process identity")
        handle = self.store._handle_for_session(self.session_id)
        live = self.store._live(handle)
        if request.operation_intent != live.record["transaction_handle"]:
            raise BootstrapEnrollmentError("root setup intent is not current for this session")
        for artifact_handle in request.artifact_receipt_handles:
            self.store.receipt_registry.lookup(artifact_handle, self._proof(live))
        return self._proof(live)

    @staticmethod
    def _proof(live: _LiveSetupSession) -> VerifiedRootSetupAuthorization:
        row = live.record["root_journal_root"]
        return VerifiedRootSetupAuthorization(
            target_id=live.record["target_id"], setup_session_id=live.record["setup_session_id"],
            plan_digest=live.record["plan_digest"], operator_uid=live.record["operator_uid"],
            transaction_handle=live.record["transaction_handle"],
            target_uid=live.record["target_uid"], target_gid=live.record["target_gid"],
            mode=live.record["mode"], plan_artifact_id=live.record["plan_artifact_id"],
            launcher_artifact_id=live.record["launcher_artifact_id"],
            launcher_sha256=live.record["launcher_sha256"],
            root_actor_identity=live.record["root_actor_identity"],
            expected_previous_generation_digest=live.record["expected_previous_generation_digest"],
            root_journal_root=row)


class RootLocalBootstrapTransport:
    """Private in-process fixed-verb transport created by one live setup store."""
    def __init__(self, store: RootSetupSessionStore, session_handle: RootSetupSessionHandle,
                 operation: RootBootstrapProvisionOperation):
        self.store = store
        self.session_handle = session_handle
        self.operation = operation

    def invoke(self, operation: str, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        live = self.store._live(self.session_handle)
        if operation != RootBootstrapProvisionOperation.operation:
            raise BootstrapEnrollmentError("root setup transport exposes only enrollment.provision")
        if (not isinstance(payload, Mapping)
                or payload.get("operation_intent") != live.record["transaction_handle"]):
            raise BootstrapEnrollmentError("root setup transport received a stale or foreign session intent")
        response = self.operation.handle(payload, peer_uid=os.getuid(), peer_gid=os.getgid())
        self.store.record_receipt(self.session_handle, _receipt_from_wire(response))
        return response


class RootLocalCatalogArtifactFetcher:
    """Fetch root-selected installer artifacts under a live local setup."""
    def __init__(self, *, catalog: Any, artifact_root: Path,
                 session_store: RootSetupSessionStore,
                 session_handle: RootSetupSessionHandle):
        if not artifact_root.is_absolute():
            raise ValueError("root artifact CAS path must be absolute")
        self.catalog = catalog
        self.artifact_root = artifact_root
        self.session_store = session_store
        self.session_handle = session_handle

    def fetch_artifact(self, *, artifact_id: str, sha256: str, max_bytes: int,
                       timeout: float = 120.0, cancelled: Callable[[], bool] | None = None
                       ) -> tuple[str, str]:
        from ..hermes_source import HERMES_SOURCE_ARTIFACT_ID, HERMES_SOURCE_SHA256

        live = self.session_store._live(self.session_handle)
        if (os.getuid() != 0 or os.geteuid() != 0 or not _linux()
                or artifact_id != HERMES_SOURCE_ARTIFACT_ID or sha256 != HERMES_SOURCE_SHA256
                or max_bytes != 100_663_296):
            raise BootstrapEnrollmentError("root source provider attempted to change its fixed Hermes selection")
        if artifact_id not in live.plan.allowed_artifact_ids:
            raise BootstrapEnrollmentError("Hermes source is not allowed by the selected root setup plan")
        return self._fetch_catalog_artifact(live, artifact_id, sha256, max_bytes,
                                            timeout=timeout, cancelled=cancelled)

    def fetch_selected_artifact(self, session_handle: RootSetupSessionHandle,
                                artifact_id: str) -> str:
        """Root CLI-only selected fetch; callers receive an opaque registry handle."""
        if os.getuid() != 0 or os.geteuid() != 0 or not _linux():
            raise BootstrapEnrollmentPending("first-setup artifacts are fetched only by the installed Linux root CLI")
        live = self.session_store._live(session_handle)
        _validate_catalog_id(artifact_id, "selected setup artifact")
        if artifact_id not in live.plan.allowed_artifact_ids:
            raise BootstrapEnrollmentError("artifact is not selected by the active root setup plan")
        try:
            spec = self.catalog.artifacts[artifact_id]
        except Exception:
            raise BootstrapEnrollmentPending("selected setup artifact is absent from the protected catalog") from None
        store_id, receipt_id = self._fetch_catalog_artifact(
            live, artifact_id, spec.sha256, min(spec.max_bytes, 8 * 1024**3))
        proof = _LiveRootSetupAuthorizer._proof(live)
        return self.session_store.receipt_registry.mint(
            store_id=store_id, receipt_id=receipt_id, setup_authorization=proof)

    def _fetch_catalog_artifact(self, live: _LiveSetupSession, artifact_id: str,
                                sha256: str, max_bytes: int, *, timeout: float = 120.0,
                                cancelled: Callable[[], bool] | None = None) -> tuple[str, str]:
        from ..artifacts import _fetch_artifact, _open_url
        if os.getuid() != 0 or os.geteuid() != 0 or not _linux():
            raise BootstrapEnrollmentPending("first-setup artifacts are fetched only by the installed Linux root CLI")
        proof = _LiveRootSetupAuthorizer._proof(live)
        if live.record["transaction_handle"] != proof.transaction_handle:
            raise BootstrapEnrollmentError("root source fetch does not match the live setup transaction")
        try:
            spec = self.catalog._artifact(artifact_id, sha256)
        except Exception:
            raise BootstrapEnrollmentPending("pinned Hermes source artifact is absent from the protected catalog") from None
        if (spec.sha256 != sha256 or spec.max_bytes > max_bytes or spec.size_bytes is None
                or spec.size_bytes > max_bytes or max_bytes < 1):
            raise BootstrapEnrollmentError("cataloged setup artifact exceeds its selected byte bound")
        actions = live.record.setdefault("artifact_fetch_actions", [])
        if len(actions) >= 64:
            raise BootstrapEnrollmentPending("root setup artifact-fetch action limit is exhausted")
        action = {"nonce": secrets.token_urlsafe(24), "artifact_id": artifact_id,
                  "sha256": sha256, "state": "reserved"}
        actions.append(action)
        _atomic_root_file(self.session_store.session_root /
                          f"{live.record['setup_session_id']}.json", _canonical(live.record), 0o600)
        _ensure_root_directory(self.artifact_root)
        def live_cancelled() -> bool:
            if cancelled is not None and cancelled():
                return True
            try:
                self.session_store._live(self.session_handle)
                return False
            except BootstrapEnrollmentError:
                return True

        def before_connect() -> None:
            if live_cancelled():
                raise BootstrapEnrollmentPending("root setup source fetch was cancelled or its session expired")

        try:
            resolved = _fetch_artifact(spec, self.artifact_root, 0, _open_url,
                                       min(float(timeout), 120.0), live_cancelled,
                                       before_connect)
        except Exception:
            raise BootstrapEnrollmentPending("pinned source download or root CAS verification failed") from None
        if resolved.sha256 != sha256 or resolved.size_bytes != spec.size_bytes:
            raise BootstrapEnrollmentError("root setup source bytes differ from the exact catalog pin")
        if spec.archive_format is not None:
            if not spec.tree_files or spec.max_tree_bytes < 1:
                raise BootstrapEnrollmentError("selected setup archive has no bounded protected content-tree manifest")
            try:
                self.catalog.materialize_tree(artifact_id, sha256, self.artifact_root, expected_uid=0)
            except Exception:
                raise BootstrapEnrollmentPending("selected setup archive tree did not match its protected manifest") from None
        receipt_id = "root-fetch-" + secrets.token_hex(24)
        action.update({"state": "verified", "receipt_id": receipt_id,
                       "size_bytes": resolved.size_bytes})
        _atomic_root_file(self.session_store.session_root /
                          f"{live.record['setup_session_id']}.json", _canonical(live.record), 0o600)
        self.session_store.record_artifact_fetch(
            self.session_handle, artifact_id=artifact_id, sha256=sha256,
            size_bytes=resolved.size_bytes, receipt_id=receipt_id)
        return f"artifact:{artifact_id}:{sha256}", receipt_id


class RootSetupArtifactFetcher:
    """Public installed-CLI fetch facade; it returns only a scoped handle."""
    def __init__(self, *, session_store: RootSetupSessionStore,
                 receipt_registry: RootArtifactReceiptRegistry,
                 protected_artifact_catalog: Any, owned_store_root: Path):
        if (not owned_store_root.is_absolute()
                or session_store.receipt_registry is not receipt_registry
                or receipt_registry.catalog is not protected_artifact_catalog
                or receipt_registry.artifact_root != owned_store_root):
            raise ValueError("root setup artifact fetch dependencies are not one selected custody set")
        self.session_store = session_store
        self.receipt_registry = receipt_registry
        self.catalog = protected_artifact_catalog
        self.artifact_root = owned_store_root

    def fetch_selected_artifact(self, session_handle: RootSetupSessionHandle,
                                artifact_id: str) -> str:
        fetcher = RootLocalCatalogArtifactFetcher(
            catalog=self.catalog, artifact_root=self.artifact_root,
            session_store=self.session_store, session_handle=session_handle)
        return fetcher.fetch_selected_artifact(session_handle, artifact_id)


class SystemIdentityAdapter:
    """Create an unprivileged system account, accepting reuse only with our marker."""
    def __init__(self, marker: Path, *, name: str = SERVICE_NAME):
        self.marker = marker
        self.name = name

    def ensure(self) -> ServiceIdentity:
        if os.geteuid() != 0 or not _linux():
            raise BootstrapEnrollmentPending("dedicated service identity enrollment requires Linux root")
        marker = _read_json_if_owned(self.marker)
        try:
            account = pwd.getpwnam(self.name)
        except KeyError:
            account = None
        try:
            group = grp.getgrnam(self.name)
        except KeyError:
            group = None
        if account is not None or group is not None:
            if (marker is None or account is None or group is None
                    or marker != {"schema": 1, "name": self.name,
                                  "uid": account.pw_uid, "gid": account.pw_gid}
                    or account.pw_gid != group.gr_gid or account.pw_dir not in {"/nonexistent", "/"}
                    or account.pw_shell not in {"/usr/sbin/nologin", "/sbin/nologin"}):
                raise BootstrapEnrollmentError("existing service account conflicts with installer ownership")
            return ServiceIdentity(self.name, account.pw_uid, account.pw_gid)
        _ensure_root_chain(self.marker.parent, ceiling=Path("/var/lib/hermes-installer"))
        try:
            subprocess.run(["/usr/sbin/groupadd", "--system", self.name], check=True,
                           stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=15)
            subprocess.run(["/usr/sbin/useradd", "--system", "--gid", self.name,
                            "--no-create-home", "--home-dir", "/nonexistent",
                            "--shell", "/usr/sbin/nologin", self.name], check=True,
                           stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=15)
            account = pwd.getpwnam(self.name)
            group = grp.getgrnam(self.name)
            if account.pw_gid != group.gr_gid:
                raise BootstrapEnrollmentError("created service account has an unexpected group")
            _atomic_root_file(self.marker, _canonical({"schema": 1, "name": self.name,
                                                       "uid": account.pw_uid, "gid": account.pw_gid}), 0o600)
            return ServiceIdentity(self.name, account.pw_uid, account.pw_gid, True)
        except Exception:
            # Preserve partial/ambiguous OS account state for explicit recovery.
            raise BootstrapEnrollmentError("dedicated service account creation failed; inspect the root transaction journal") from None

    def remove_if_created(self, identity: ServiceIdentity) -> None:
        if not identity.created:
            return
        try:
            current = pwd.getpwnam(identity.name)
            group = grp.getgrnam(identity.name)
        except KeyError:
            return
        marker = _read_json_if_owned(self.marker)
        expected = {"schema": 1, "name": identity.name, "uid": identity.uid, "gid": identity.gid}
        if (marker != expected or current.pw_uid != identity.uid or current.pw_gid != identity.gid
                or group.gr_gid != identity.gid):
            raise BootstrapEnrollmentError("service identity ownership changed; rollback refused")
        subprocess.run(["/usr/sbin/userdel", identity.name], check=True,
                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, timeout=15)
        subprocess.run(["/usr/sbin/groupdel", identity.name], check=True,
                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, timeout=15)
        self.marker.unlink()


class RootBootstrapEnrollment:
    """Prepare service-owned roots and atomically publish a digest-bound snapshot."""
    def __init__(self, *, policy_resolver: Callable[[BootstrapEnrollmentRequest, VerifiedRootSetupAuthorization], EnrollmentPolicy],
                 receipt_resolver: ReceiptResolver, identity: IdentityAdapter,
                 record_builder: Callable[[EnrollmentPolicy, ServiceIdentity], tuple[Mapping[str, Any], ...]] | None = None,
                 authority_builder: Callable[[Mapping[str, Any] | None, EnrollmentPolicy, ServiceIdentity], Mapping[str, Any]] | None = None,
                 authority_path: Path = Path("/etc/hermes-installer/authority.json"),
                 transaction_root: Path = Path("/var/lib/hermes-installer/authority-journal/bootstrap-transactions"),
                 artifact_root: Path = Path("/var/lib/hermes-installer/artifacts"),
                 root_journal_path: Path = Path("/var/lib/hermes-installer/authority-journal"),
                 authority_loader: Callable[[Path], Mapping[str, Any]] | None = None,
                 authority_writer: Callable[[Path, bytes], None] | None = None):
        self.policy_resolver = policy_resolver
        self.receipt_resolver = receipt_resolver
        self.identity = identity
        self.record_builder = record_builder
        self.authority_builder = authority_builder
        self.authority_path = authority_path
        self.transaction_root = transaction_root
        self.artifact_root = artifact_root
        if not root_journal_path.is_absolute():
            raise ValueError("authority journal selection must be absolute")
        self.root_journal_path = root_journal_path
        self.authority_loader = authority_loader or _load_authority
        self.authority_writer = authority_writer or _atomic_root_file

    def enroll(self, request: BootstrapEnrollmentRequest, *,
               setup_authorization: VerifiedRootSetupAuthorization | None = None) -> EnrollmentReceipt:
        _validate_request(request)
        if os.geteuid() != 0:
            raise BootstrapEnrollmentPending("service-generation enrollment requires the root authority process")
        if (not isinstance(setup_authorization, VerifiedRootSetupAuthorization)
                or setup_authorization.operation_target_id != RootBootstrapProvisionOperation.target
                or setup_authorization.transaction_handle != request.operation_intent):
            raise BootstrapEnrollmentPending("root-local setup admission is required for first-snapshot enrollment")
        _ensure_root_directory(self.transaction_root)
        with _transaction_lock(self.transaction_root / "enrollment.lock"):
            return self._enroll_locked(request, setup_authorization)

    def _enroll_locked(self, request: BootstrapEnrollmentRequest,
                       setup_authorization: VerifiedRootSetupAuthorization) -> EnrollmentReceipt:
        _validate_request(request)
        if os.geteuid() != 0:
            raise BootstrapEnrollmentPending("service-generation enrollment requires the root authority process")
        policy = self.policy_resolver(request, setup_authorization)
        _validate_policy(policy, records_required=(policy.activation_state == "active"
                                                     and self.record_builder is None))
        if (not setup_authorization.root_journal_root
                or len(policy.root_journal_roots) != 1
                or dict(policy.root_journal_roots[0]) != dict(setup_authorization.root_journal_root)):
            raise BootstrapEnrollmentPending("root-selected authority journal identity is missing from the generation")
        _verify_root_journal_selection(setup_authorization.root_journal_root, self.root_journal_path)
        if policy.activation_state == "prepared":
            _validate_prepared_policy(policy)
        receipts = tuple(self.receipt_resolver.resolve(
            handle, setup_authorization=setup_authorization)
            for handle in request.artifact_receipt_handles)
        _validate_receipts(receipts)
        if not receipts or not any(item.artifact_id == policy.source_artifact_id for item in receipts):
            raise BootstrapEnrollmentPending("verified pinned Hermes source artifact receipt is not enrolled")
        if self.authority_path.exists():
            if not _root_file_ok(self.authority_path):
                raise BootstrapEnrollmentError("existing authority file is not root-owned mode 0600")
            from .enrollment import read_protected_file
            previous = read_protected_file(self.authority_path, expected_uid=0, maximum=MAX_AUTHORITY_BYTES)
            authority = dict(self.authority_loader(self.authority_path))
            _validate_authority_base(authority)
        else:
            previous = None
            if policy.authority_base is None and self.authority_builder is None:
                raise BootstrapEnrollmentPending("root-selected base authority enrollment policy is required")
            authority = None if policy.authority_base is None else dict(policy.authority_base)
            if authority is not None:
                _validate_authority_base(authority)
        previous_generation_digest = (
            authority.get("service_generations", {}).get("generation_digest")
            if previous is not None and isinstance(authority.get("service_generations"), dict) else None
        )
        if (setup_authorization.expected_previous_generation_digest is not None
                and setup_authorization.expected_previous_generation_digest != previous_generation_digest):
            raise BootstrapEnrollmentPending("root setup generation compare-and-swap predecessor changed")
        if (setup_authorization.expected_previous_generation_digest is None
                and previous_generation_digest is not None):
            raise BootstrapEnrollmentPending("root setup generation compare-and-swap predecessor changed")
        if policy.activation_state == "prepared" and previous is not None:
            raise BootstrapEnrollmentPending("prepared first-snapshot enrollment cannot replace an existing authority generation")
        if "service_generations" not in authority:
            raise BootstrapEnrollmentError("root authority file does not accept service-generation publication")
        transaction_id = secrets.token_hex(16)
        candidate_roots = tuple(root for root in (policy.home_root, policy.work_root, policy.data_root)
                                if not _exists_without_following(root))
        _ensure_root_directory(self.transaction_root)
        journal = self.transaction_root / f"{transaction_id}.json"
        backup = self.transaction_root / f"{transaction_id}.authority.previous"
        identity: ServiceIdentity | None = None
        identity_attempted = False
        created_roots: list[Path] = []
        staged_artifacts: list[Path] = []
        previous_authority: bytes | None = None
        published_generation_digest: str | None = None
        provision_receipt_handle = secrets.token_hex(24)
        request_digest = hashlib.sha256(_canonical({
            "schema": 1, "artifact_receipt_handles": list(request.artifact_receipt_handles),
            "operation_intent": request.operation_intent,
        })).hexdigest()
        artifact_receipt_digests = tuple(hashlib.sha256(_canonical({
            "receipt_id": item.receipt_id, "artifact_id": item.artifact_id,
            "sha256": item.sha256, "maximum_bytes": item.maximum_bytes,
        })).hexdigest() for item in receipts)
        if previous is not None:
            _atomic_root_file(backup, previous, 0o600)
        _write_journal(journal, transaction_id, "preparing", created_roots, staged_artifacts,
                       roots=candidate_roots,
                       backup=backup if previous is not None else None, identity=identity,
                       provision_receipt_handle=provision_receipt_handle,
                       request_digest=request_digest, artifact_receipt_digests=artifact_receipt_digests,
                       setup_authorization=setup_authorization,
                       previous_generation_digest=previous_generation_digest)
        try:
            identity_attempted = True
            _write_journal(journal, transaction_id, "preparing", created_roots, staged_artifacts,
                           roots=candidate_roots,
                           backup=backup if previous is not None else None, identity=identity,
                           provision_receipt_handle=provision_receipt_handle,
                           request_digest=request_digest, artifact_receipt_digests=artifact_receipt_digests,
                           setup_authorization=setup_authorization, identity_attempted=True)
            identity = self.identity.ensure()
            _write_journal(journal, transaction_id, "preparing", created_roots, staged_artifacts,
                           roots=candidate_roots,
                           backup=backup if previous is not None else None, identity=identity,
                           provision_receipt_handle=provision_receipt_handle,
                           request_digest=request_digest, artifact_receipt_digests=artifact_receipt_digests,
                           setup_authorization=setup_authorization)
            for root in (policy.home_root, policy.work_root, policy.data_root):
                if root in created_roots or not root.is_absolute():
                    raise BootstrapEnrollmentError("service roots are invalid or duplicated")
                if _create_service_root(root, identity):
                    created_roots.append(root)
                _verify_service_root(root, identity)
                _write_journal(journal, transaction_id, "preparing", created_roots, staged_artifacts,
                               roots=candidate_roots,
                               backup=backup if previous is not None else None,
                               identity=identity, provision_receipt_handle=provision_receipt_handle,
                               request_digest=request_digest, artifact_receipt_digests=artifact_receipt_digests,
                               setup_authorization=setup_authorization)
            if policy.activation_state == "active" and self.record_builder is not None:
                policy = replace(policy, records=tuple(self.record_builder(policy, identity)))
                _validate_policy(policy)
            service = None if policy.activation_state == "prepared" else _verify_service_records(policy, identity)
            if self.authority_builder is not None:
                authority = dict(self.authority_builder(authority, policy, identity))
                _validate_authority_base(authority)
            if authority is None:
                raise BootstrapEnrollmentPending("root-selected base authority enrollment policy is required")
            if policy.activation_state == "prepared":
                _validate_prepared_authority(authority)
            # Artifacts remain root-owned and content-addressed. Receipt source paths
            # come only from the root resolver; bytes are rehashed during copy.
            _ensure_root_directory(self.artifact_root)
            installed = []
            for receipt in receipts:
                target = self.artifact_root / receipt.sha256
                if target.exists():
                    _verify_root_artifact(target, receipt)
                else:
                    _copy_verified_artifact(receipt, target)
                    staged_artifacts.append(target)
                    _write_journal(journal, transaction_id, "preparing", created_roots, staged_artifacts,
                                   roots=candidate_roots,
                                   backup=backup if previous is not None else None,
                                   identity=identity, provision_receipt_handle=provision_receipt_handle,
                                   request_digest=request_digest, artifact_receipt_digests=artifact_receipt_digests,
                                   setup_authorization=setup_authorization)
                installed.append({"receipt_id": receipt.receipt_id,
                                  "artifact_id": receipt.artifact_id,
                                  "sha256": receipt.sha256,
                                  "size_bytes": target.stat().st_size,
                                  "store_id": f"artifact:{receipt.artifact_id}:{receipt.sha256}"})
            service_generations = _generation(policy)
            previous_authority = previous
            authority["service_generations"] = service_generations
            encoded = _canonical(authority)
            if len(encoded) > MAX_AUTHORITY_BYTES:
                raise BootstrapEnrollmentError("authority snapshot exceeds the protected file size limit")
            published_generation_digest = service_generations["generation_digest"]
            _write_journal(journal, transaction_id, "committing", created_roots, staged_artifacts,
                           roots=candidate_roots,
                           backup=backup if previous is not None else None,
                           identity=identity, generation_digest=published_generation_digest,
                           provision_receipt_handle=provision_receipt_handle,
                           request_digest=request_digest, artifact_receipt_digests=artifact_receipt_digests,
                           setup_authorization=setup_authorization)
            self.authority_writer(self.authority_path, encoded)
            _write_journal(journal, transaction_id, "committed", created_roots, staged_artifacts,
                           roots=candidate_roots,
                           backup=backup if previous is not None else None,
                           identity=identity, generation_digest=published_generation_digest,
                           provision_receipt_handle=provision_receipt_handle,
                           request_digest=request_digest, artifact_receipt_digests=artifact_receipt_digests,
                           setup_authorization=setup_authorization)
            issued = time.monotonic()
            return EnrollmentReceipt(
                    schema=1, transaction_handle=request.operation_intent,
                    provision_receipt_handle=provision_receipt_handle,
                    generation_id=service_generations["generation_id"],
                    generation_digest=service_generations["generation_digest"],
                    previous_generation_digest=previous_generation_digest,
                state="prepared" if service is None else "committed",
                enrollment_ids=() if service is None else (service.enrollment_id,),
                    issued_monotonic=issued, expires_monotonic=issued + 300.0,
                )
        except Exception:
            if identity_attempted and identity is None:
                _write_journal(journal, transaction_id, "incomplete", created_roots, staged_artifacts,
                               roots=candidate_roots,
                               backup=backup if previous is not None else None,
                               identity=None, generation_digest=published_generation_digest,
                               provision_receipt_handle=provision_receipt_handle,
                               request_digest=request_digest,
                               artifact_receipt_digests=artifact_receipt_digests,
                               setup_authorization=setup_authorization, identity_attempted=True)
                raise BootstrapEnrollmentPending(
                    "service identity creation has an ambiguous partial effect; root reconciliation is required"
                ) from None
            if (published_generation_digest is not None
                    and _current_generation_digest(self.authority_path) == published_generation_digest):
                if previous_authority is not None:
                    self.authority_writer(self.authority_path, previous_authority)
                else:
                    self.authority_path.unlink()
            for path in reversed(staged_artifacts):
                _unlink_only_owned(path, uid=0, expected_sha256=path.name)
            roots_removed = True
            for root in reversed(created_roots):
                roots_removed = _remove_empty_service_root(root, identity) and roots_removed
            if identity is not None and roots_removed:
                self.identity.remove_if_created(identity)
            _write_journal(journal, transaction_id, "rolled_back", created_roots, staged_artifacts,
                           roots=candidate_roots,
                           backup=backup if previous is not None else None,
                           identity=identity, generation_digest=published_generation_digest,
                           provision_receipt_handle=provision_receipt_handle,
                           request_digest=request_digest, artifact_receipt_digests=artifact_receipt_digests,
                           setup_authorization=setup_authorization)
            if backup.exists() and _root_file_ok(backup):
                backup.unlink()
            raise

    def rollback(self, provision_receipt_handle: str, *,
                 expected_generation_digest: str) -> str:
        """CAS-rollback a committed snapshot after a failed selected health check."""
        if (os.geteuid() != 0 or not isinstance(provision_receipt_handle, str)
                or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", provision_receipt_handle)
                or not re.fullmatch(r"[0-9a-f]{64}", expected_generation_digest)):
            raise BootstrapEnrollmentError("rollback requires a root-issued receipt and generation digest")
        _ensure_root_directory(self.transaction_root)
        with _transaction_lock(self.transaction_root / "enrollment.lock"):
            journals = tuple(self.transaction_root.glob("[0-9a-f]" * 32 + ".json"))
            selected = None
            for path in journals:
                if not _root_file_ok(path):
                    continue
                try:
                    candidate = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_unique_pairs)
                except (OSError, ValueError, UnicodeError):
                    continue
                if candidate.get("provision_receipt_handle") == provision_receipt_handle:
                    selected = (path, candidate)
                    break
            if selected is None:
                raise BootstrapEnrollmentError("provision receipt is not present in the root transaction journal")
            path, journal = selected
            transaction_id = journal.get("transaction_id")
            if (journal.get("schema") != 1 or journal.get("state") != "committed"
                    or not isinstance(transaction_id, str)
                    or path.name != f"{transaction_id}.json"
                    or journal.get("generation_digest") != expected_generation_digest):
                raise BootstrapEnrollmentError("committed provision receipt does not match rollback request")
            current = _current_generation_digest(self.authority_path)
            if current != expected_generation_digest:
                raise BootstrapEnrollmentError("active generation changed; rollback compare-and-swap refused")
            backup_text = journal.get("backup", "")
            if backup_text:
                backup = Path(backup_text)
                if backup.parent != self.transaction_root or not _root_file_ok(backup):
                    raise BootstrapEnrollmentError("prior authority snapshot is unavailable; rollback stopped")
                self.authority_writer(self.authority_path, backup.read_bytes())
            else:
                self.authority_path.unlink()
            for artifact in journal.get("artifacts", []):
                candidate = Path(artifact)
                if candidate.parent != self.artifact_root or candidate.name != candidate.stem:
                    raise BootstrapEnrollmentError("journal artifact path is outside the enrolled store")
                if candidate.exists() and hashlib.sha256(candidate.read_bytes()).hexdigest() != candidate.name:
                    raise BootstrapEnrollmentError("journal artifact changed; rollback preserved it")
                _unlink_only_owned(candidate, uid=0, expected_sha256=candidate.name)
            identity_value = journal.get("identity")
            identity = None
            if isinstance(identity_value, dict) and set(identity_value) == {"name", "uid", "gid", "created"}:
                identity = ServiceIdentity(identity_value["name"], identity_value["uid"],
                                           identity_value["gid"], identity_value["created"])
            roots_removed = True
            for root in reversed(journal.get("created_roots", [])):
                roots_removed = _remove_empty_service_root(Path(root), identity) and roots_removed
            if identity is not None and roots_removed:
                self.identity.remove_if_created(identity)
            _write_journal(path, transaction_id, "rolled_back", [], [],
                           roots=tuple(Path(p) for p in journal.get("roots", [])),
                           backup=Path(backup_text) if backup_text else None,
                           identity=identity,
                           generation_digest=expected_generation_digest,
                           provision_receipt_handle=provision_receipt_handle,
                           request_digest=journal.get("request_digest"),
                           artifact_receipt_digests=tuple(journal.get("artifact_receipt_digests", [])),
                           setup_authorization=journal.get("setup_authorization"))
            if backup_text:
                backup.unlink()
            return "rolled_back"

    def recover_for_setup(self, setup_authorization: VerifiedRootSetupAuthorization) -> str | None:
        """Recover only the newest journal bound to this freshly admitted session."""
        _validate_setup_authorization(setup_authorization)
        if os.geteuid() != 0:
            raise BootstrapEnrollmentPending("transaction recovery requires the root authority process")
        _ensure_root_directory(self.transaction_root)
        candidates: list[tuple[int, Path, Mapping[str, Any]]] = []
        for path in self.transaction_root.glob("[0-9a-f]" * 32 + ".json"):
            if not _root_file_ok(path):
                continue
            value = _read_json_if_owned(path)
            setup = value.get("setup_authorization") if isinstance(value, dict) else None
            if (not isinstance(setup, dict)
                    or setup.get("transaction_handle") != setup_authorization.transaction_handle
                    or setup.get("target_id") != setup_authorization.target_id
                    or setup.get("plan_digest") != setup_authorization.plan_digest):
                continue
            candidates.append((path.stat().st_mtime_ns, path, value))
        if not candidates:
            return None
        _, path, journal = max(candidates, key=lambda row: row[0])
        state = journal.get("state")
        transaction_id = journal.get("transaction_id")
        if not isinstance(transaction_id, str):
            raise BootstrapEnrollmentError("matching root transaction checkpoint is malformed")
        if state in {"preparing", "committing"}:
            state = self.recover(transaction_id)
        if state == "incomplete":
            raise BootstrapEnrollmentPending("root transaction has an ambiguous partial identity effect; inspect and reconcile it before resuming")
        if state not in {"committed", "rolled_back", "rolled_back"}:
            raise BootstrapEnrollmentPending("root transaction checkpoint is not resumable")
        return str(state)

    def recover(self, transaction_id: str) -> str:
        """Roll back an interrupted transaction using its root-owned recovery journal."""
        if (os.geteuid() != 0 or not re.fullmatch(r"[0-9a-f]{32}", transaction_id)):
            raise BootstrapEnrollmentError("recovery requires root and a valid transaction ID")
        path = self.transaction_root / f"{transaction_id}.json"
        with _transaction_lock(self.transaction_root / "enrollment.lock"):
            try:
                if not _root_file_ok(path):
                    raise BootstrapEnrollmentError("transaction journal is absent or not root-owned")
                journal = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_unique_pairs)
            except (OSError, ValueError, UnicodeError):
                raise BootstrapEnrollmentError("transaction journal is malformed") from None
            if (not isinstance(journal, dict) or journal.get("schema") != 1
                    or journal.get("transaction_id") != transaction_id
                    or journal.get("state") not in {"preparing", "committing", "committed", "incomplete", "rolled_back"}):
                raise BootstrapEnrollmentError("transaction journal does not match recovery request")
            if journal["state"] in {"committed", "incomplete", "rolled_back"}:
                return journal["state"]
            identity_value = journal.get("identity")
            if journal["state"] == "preparing" and journal.get("identity_attempted") is True and identity_value is None:
                _write_journal(path, transaction_id, "incomplete", [], [],
                               roots=tuple(Path(p) for p in journal.get("roots", [])),
                               backup=Path(journal["backup"]) if journal.get("backup") else None,
                               request_digest=journal.get("request_digest"),
                               provision_receipt_handle=journal.get("provision_receipt_handle"),
                               artifact_receipt_digests=tuple(journal.get("artifact_receipt_digests", [])),
                               setup_authorization=journal.get("setup_authorization"),
                               identity_attempted=True)
                return "incomplete"
            if journal["state"] == "committing":
                backup_text = journal.get("backup", "")
                expected = journal.get("generation_digest")
                current = _current_generation_digest(self.authority_path)
                if current == expected:
                    if backup_text:
                        backup = Path(backup_text)
                        if backup.parent != self.transaction_root or not _root_file_ok(backup):
                            raise BootstrapEnrollmentError("prior authority snapshot is unavailable; recovery stopped")
                        self.authority_writer(self.authority_path, backup.read_bytes())
                    else:
                        self.authority_path.unlink()
                elif current != journal.get("previous_generation_digest"):
                    raise BootstrapEnrollmentError("authority state changed during interrupted enrollment")
            identity = None
            if isinstance(identity_value, dict) and set(identity_value) == {"name", "uid", "gid", "created"}:
                identity = ServiceIdentity(identity_value["name"], identity_value["uid"],
                                           identity_value["gid"], identity_value["created"])
            for artifact in journal.get("artifacts", []):
                candidate = Path(artifact)
                if candidate.parent != self.artifact_root or candidate.name != candidate.stem:
                    raise BootstrapEnrollmentError("journal artifact path is outside the enrolled store")
                if candidate.exists() and hashlib.sha256(candidate.read_bytes()).hexdigest() != candidate.name:
                    raise BootstrapEnrollmentError("journal artifact content changed; recovery preserved it")
                _unlink_only_owned(candidate, uid=0, expected_sha256=candidate.name)
            if identity is not None:
                roots_removed = True
                for root in journal.get("roots", []):
                    candidate = Path(root)
                    if candidate.is_absolute():
                        roots_removed = _remove_empty_service_root(candidate, identity) and roots_removed
                if roots_removed:
                    self.identity.remove_if_created(identity)
            _write_journal(path, transaction_id, "rolled_back", [], [],
                           roots=tuple(Path(p) for p in journal.get("roots", [])),
                           backup=Path(journal["backup"]) if journal.get("backup") else None,
                           identity=identity,
                           generation_digest=journal.get("generation_digest"),
                           provision_receipt_handle=journal.get("provision_receipt_handle"),
                           request_digest=journal.get("request_digest"),
                           artifact_receipt_digests=tuple(journal.get("artifact_receipt_digests", [])),
                           setup_authorization=journal.get("setup_authorization"))
            backup_text = journal.get("backup", "")
            if backup_text:
                backup = Path(backup_text)
                if backup.parent == self.transaction_root and _root_file_ok(backup):
                    backup.unlink()
            return "rolled_back"


def _generation(policy: EnrollmentPolicy) -> dict[str, Any]:
    value = {"schema": 2, "generation_id": policy.generation_id,
             "service_records": [dict(row) for row in policy.records],
             "protected_devices": [dict(row) for row in policy.protected_devices],
             "protected_build_records": [dict(row) for row in policy.protected_build_records],
             "native_packages": [dict(row) for row in policy.native_packages],
             "memory_enrollments": [dict(row) for row in policy.memory_enrollments],
             "memory_service_enablement_projections": [dict(row) for row in getattr(
                 policy, "memory_service_enablement_projections", ())],
             "operation_parameter_schemas": [dict(row) for row in policy.operation_parameter_schemas],
             "source_issuers": [dict(row) for row in policy.source_issuers],
             "resource_jobs": [dict(row) for row in policy.resource_jobs],
             "remote_session_enrollments": [dict(row) for row in policy.remote_session_enrollments],
             "resource_backend_enrollments": [dict(row) for row in policy.resource_backend_enrollments],
             "resource_body_recipes": [dict(row) for row in policy.resource_body_recipes],
             "resource_scope_bindings": [dict(row) for row in policy.resource_scope_bindings],
             "resource_validators": [dict(row) for row in policy.resource_validators],
             "root_journal_roots": [dict(row) for row in policy.root_journal_roots],
             "remote_startup_enrollments": [dict(row) for row in policy.remote_startup_enrollments],
             "private_loopback_networks": [dict(row) for row in policy.private_loopback_networks],
             "native_worker_network_records": [dict(row) for row in policy.native_worker_network_records],
             "active_network_generation_records": [dict(row) for row in policy.active_network_generation_records],
             "native_worker_runtime_records": [dict(row) for row in policy.native_worker_runtime_records],
             "selected_resource_executions": [dict(row) for row in policy.selected_resource_executions],
             "selected_application_runtimes": [dict(row) for row in policy.selected_application_runtimes],
             "public_web_scopes": [dict(row) for row in policy.public_web_scopes],
             "native_schema_artifacts": [dict(row) for row in policy.native_schema_artifacts],
             "composio_channel_enrollments": [dict(row) for row in policy.composio_channel_enrollments],
             "channel_delivery_bindings": [dict(row) for row in policy.channel_delivery_bindings],
             "resource_controller_roles": [dict(row) for row in policy.resource_controller_roles],
             "native_mcp_tool_bindings": [dict(row) for row in policy.native_mcp_tool_bindings],
             "remote_observation_enrollments": [dict(row) for row in policy.remote_observation_enrollments],
             "native_schema_artifacts": [dict(row) for row in policy.native_schema_artifacts],
             "composio_channel_enrollments": [dict(row) for row in policy.composio_channel_enrollments],
             "channel_delivery_bindings": [dict(row) for row in policy.channel_delivery_bindings],
             # v128 selections exist only after root-verified observation and
             # explicit selection. Enrollment never infers either from policy
             # aliases, model lists, or the prepared setup transaction.
             "private_memory_endpoint_selections": [],
             "private_memory_model_selections": [],
             "public_web_scopes": [dict(row) for row in getattr(policy, "public_web_scopes", ())]}
    value["generation_digest"] = hashlib.sha256(_canonical(value, ensure_ascii=False)).hexdigest()
    from .enrollment import _validate_service_generations
    try:
        return _validate_service_generations(value)
    except Exception:
        raise BootstrapEnrollmentError("root-selected protected service catalog failed schema or digest validation") from None


def _verify_service_records(policy: EnrollmentPolicy, identity: ServiceIdentity):
    """Parse and join the selected record through the same decoder as runtime."""
    snapshot = _generation(policy)
    from .protected_enrollment import ProtectedEnrollmentCatalog
    from hermes_installer.memory.enrollment import MemoryServiceEnrollment
    try:
        catalog = ProtectedEnrollmentCatalog.from_verified_records(
            snapshot["service_records"], protected_digest=snapshot["generation_digest"],
            expected_uid=0, native_packages=snapshot["native_packages"],
            parameter_schemas=snapshot["operation_parameter_schemas"],
            memory_enrollments={
                (row.service_enrollment_id, row.service_generation): row
                for row in (
                    MemoryServiceEnrollment.from_protected_record(raw)
                    for raw in snapshot["memory_enrollments"]
                )
            },
            memory_service_enablement_projections=snapshot["memory_service_enablement_projections"],
        )
        matches = [record for record in catalog._records.values()
                   if record.profile_id == policy.service_profile_id]
        if len(matches) != 1:
            raise ValueError("selected service profile is not unique")
        service = matches[0]
        if (service.generation != policy.generation_id or service.principal_id != policy.principal_id
                or service.service_uid != identity.uid
                or service.service_gid != identity.gid or service.service_user != identity.name
                or service.roots.home != policy.home_root or service.roots.work != policy.work_root
                or service.roots.data != policy.data_root):
            raise ValueError("selected service identity or roots do not match root bootstrap")
        return service
    except Exception:
        raise BootstrapEnrollmentError("root-selected service records do not bind the verified identity and private roots") from None


def _canonical(value: Any, *, ensure_ascii: bool = True) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=ensure_ascii, allow_nan=False).encode("utf-8")


@contextmanager
def _transaction_lock(path: Path):
    _assert_secure_parent(path.parent)
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(path, flags, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o600:
            raise BootstrapEnrollmentError("bootstrap lock ownership or mode is invalid")
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


def _current_generation_digest(path: Path) -> str | None:
    try:
        value = _load_authority(path)
        generation = value.get("service_generations")
        return generation.get("generation_digest") if isinstance(generation, dict) else None
    except BootstrapEnrollmentError:
        return None


def _validate_catalog_id(value: str, label: str) -> None:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", value):
        raise BootstrapEnrollmentError(f"{label} is malformed")


def _verified_installed_file(path: Path, expected_sha256: str) -> os.stat_result:
    if (not isinstance(path, Path) or not path.is_absolute()
            or not re.fullmatch(r"[0-9a-f]{64}", expected_sha256)):
        raise BootstrapEnrollmentError("selected root setup file binding is malformed")
    _assert_secure_parent(path.parent)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags)
    except OSError:
        raise BootstrapEnrollmentError("selected root setup executable or module is unavailable") from None
    try:
        info = os.fstat(fd)
        current = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1
                or info.st_mode & 0o022
                or stat.S_ISLNK(current.st_mode) or (current.st_dev, current.st_ino) != (info.st_dev, info.st_ino)):
            raise BootstrapEnrollmentError("selected root setup file has unsafe ownership or path custody")
        digest = hashlib.sha256()
        while True:
            block = os.read(fd, 65536)
            if not block:
                break
            digest.update(block)
        after = os.fstat(fd)
        if (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns) != (
                after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            raise BootstrapEnrollmentError("selected root setup file changed while it was verified")
        if not secrets.compare_digest(digest.hexdigest(), expected_sha256):
            raise BootstrapEnrollmentError("installed root setup file differs from its selected plan")
        return info
    finally:
        os.close(fd)


def _read_secure_root_bytes(path: Path, maximum: int, mode: int) -> bytes:
    if not path.is_absolute() or type(maximum) is not int or maximum < 1:
        raise BootstrapEnrollmentError("root selection file binding is malformed")
    _assert_secure_parent(path.parent)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags)
    except OSError:
        raise BootstrapEnrollmentPending("installed root setup selection catalog is unavailable") from None
    try:
        info = os.fstat(fd)
        current = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != mode or info.st_size > maximum
                or stat.S_ISLNK(current.st_mode)
                or (current.st_dev, current.st_ino) != (info.st_dev, info.st_ino)):
            raise BootstrapEnrollmentError("root selection catalog ownership, mode, or inode is invalid")
        chunks = bytearray()
        while len(chunks) <= maximum:
            block = os.read(fd, min(65536, maximum + 1 - len(chunks)))
            if not block:
                break
            chunks.extend(block)
        if len(chunks) > maximum:
            raise BootstrapEnrollmentError("root selection catalog exceeds its reviewed byte limit")
        after = os.fstat(fd)
        if (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) != (
                info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns):
            raise BootstrapEnrollmentError("root selection catalog changed while it was read")
        return bytes(chunks)
    finally:
        os.close(fd)


def _verify_import_search_path(path: Path) -> None:
    if not path.is_absolute():
        raise BootstrapEnrollmentError("root setup import path must be absolute")
    try:
        info = path.lstat()
    except FileNotFoundError:
        _assert_secure_parent(path.parent)
        return
    except OSError:
        raise BootstrapEnrollmentError("root setup import path cannot be inspected") from None
    if stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise BootstrapEnrollmentError("root setup import path has unsafe owner or write permissions")
    if stat.S_ISDIR(info.st_mode):
        _assert_secure_parent(path)
    elif not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise BootstrapEnrollmentError("root setup import path is not an owned directory or archive")
    else:
        _assert_secure_parent(path.parent)


def _open_immutable_release_root(path: Path, expected_device: int, expected_inode: int) -> int:
    if not path.is_absolute():
        raise BootstrapEnrollmentError("selected installer release root must be absolute")
    _assert_secure_parent(path.parent)
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                     | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    except OSError:
        raise BootstrapEnrollmentError("selected installer release root cannot be opened safely") from None
    info = os.fstat(fd)
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022
            or info.st_dev != expected_device or info.st_ino != expected_inode):
        os.close(fd)
        raise BootstrapEnrollmentError("selected installer release root device/inode custody changed")
    return fd


def _verify_release_file_at(root_fd: int, relative: str, expected_sha256: str) -> os.stat_result:
    parts = relative.split("/")
    root_info = os.fstat(root_fd)
    parent_fd = os.dup(root_fd)
    try:
        for part in parts[:-1]:
            next_fd = os.open(part, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                              | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
                              dir_fd=parent_fd)
            info = os.fstat(next_fd)
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0
                    or info.st_dev != root_info.st_dev or info.st_mode & 0o022):
                os.close(next_fd)
                raise BootstrapEnrollmentError("selected release path parent is not immutable root custody")
            os.close(parent_fd)
            parent_fd = next_fd
        file_fd = os.open(parts[-1], os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                          | getattr(os, "O_CLOEXEC", 0), dir_fd=parent_fd)
        try:
            before = os.fstat(file_fd)
            if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_nlink != 1
                    or before.st_dev != root_info.st_dev or before.st_mode & 0o022):
                raise BootstrapEnrollmentError("selected release file is not immutable root custody")
            digest = hashlib.sha256()
            while True:
                block = os.read(file_fd, 65536)
                if not block:
                    break
                digest.update(block)
            after = os.fstat(file_fd)
            if ((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) !=
                    (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
                    or not secrets.compare_digest(digest.hexdigest(), expected_sha256)):
                raise BootstrapEnrollmentError("selected release file bytes or inode changed")
            return before
        finally:
            os.close(file_fd)
    except OSError:
        raise BootstrapEnrollmentError("selected release path cannot be opened without following links") from None
    finally:
        os.close(parent_fd)


def _validate_sha256(value: Any, label: str) -> None:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise BootstrapEnrollmentError(f"{label} digest is malformed")


def _process_start_time(pid: int) -> int:
    try:
        statline = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
        fields = statline[statline.rfind(")") + 2:].split()
        value = int(fields[19])
    except (OSError, ValueError, IndexError):
        raise BootstrapEnrollmentPending("root setup process identity cannot be verified") from None
    if value <= 0:
        raise BootstrapEnrollmentPending("root setup process identity is invalid")
    return value


def _read_machine_id() -> str:
    path = Path("/etc/machine-id")
    info = _verified_owned_readonly(path)
    del info
    try:
        value = path.read_text(encoding="ascii").strip()
    except (OSError, UnicodeError):
        raise BootstrapEnrollmentPending("local machine identity is unavailable") from None
    if not re.fullmatch(r"[0-9a-f]{32}", value):
        raise BootstrapEnrollmentError("local machine identity is malformed")
    return value


def _read_boot_id() -> str:
    path = Path("/proc/sys/kernel/random/boot_id")
    try:
        value = path.read_text(encoding="ascii").strip()
    except (OSError, UnicodeError):
        raise BootstrapEnrollmentPending("kernel boot identity is unavailable") from None
    if not re.fullmatch(r"[0-9a-f-]{36}", value):
        raise BootstrapEnrollmentError("kernel boot identity is malformed")
    return value


def _verified_owned_readonly(path: Path) -> os.stat_result:
    _assert_secure_parent(path.parent)
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise BootstrapEnrollmentError("local root identity file has unsafe ownership or mode")
        return info
    finally:
        os.close(fd)


def _secure_directory_identity(path: Path) -> os.stat_result:
    if not path.is_absolute():
        raise BootstrapEnrollmentError("root journal directory must be absolute")
    _assert_secure_parent(path.parent)
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) |
                 getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    try:
        info = os.fstat(fd)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
                or stat.S_IMODE(info.st_mode) != 0o700):
            raise BootstrapEnrollmentError("root journal directory owner, group, or mode is invalid")
        current = path.lstat()
        if stat.S_ISLNK(current.st_mode) or (current.st_dev, current.st_ino) != (info.st_dev, info.st_ino):
            raise BootstrapEnrollmentError("root journal directory changed during verification")
        return info
    finally:
        os.close(fd)


def _verify_root_journal_selection(value: Mapping[str, Any], expected_path: Path) -> None:
    fields = {"root_id", "absolute_path", "owner_uid", "owner_gid", "mode",
              "device", "inode", "generation", "purpose"}
    if (not isinstance(value, Mapping) or set(value) != fields
            or value.get("root_id") != "installer-authority-journal-v1"
            or value.get("absolute_path") != str(expected_path)
            or value.get("owner_uid") != 0 or value.get("owner_gid") != 0
            or value.get("mode") != 0o700 or value.get("purpose") != "authority-journal"
            or type(value.get("device")) is not int or type(value.get("inode")) is not int
            or value.get("device") < 0 or value.get("inode") <= 0):
        raise BootstrapEnrollmentError("root journal selection does not match the fixed reviewed root")
    if not isinstance(value.get("generation"), str) or not re.fullmatch(
            r"[A-Za-z0-9_.:-]{1,128}", value["generation"]):
        raise BootstrapEnrollmentError("root journal generation is malformed")
    info = _secure_directory_identity(expected_path)
    if (info.st_uid != value["owner_uid"] or info.st_gid != value["owner_gid"]
            or stat.S_IMODE(info.st_mode) != value["mode"]
            or info.st_dev != value["device"] or info.st_ino != value["inode"]):
        raise BootstrapEnrollmentError("root journal directory no longer matches its selected inode")


def _validate_request(request: BootstrapEnrollmentRequest) -> None:
    if (not isinstance(request, BootstrapEnrollmentRequest)
            or not isinstance(request.artifact_receipt_handles, tuple)
            or len(request.artifact_receipt_handles) > 64
            or any(not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,256}", value)
                   for value in request.artifact_receipt_handles)
            or not isinstance(request.operation_intent, str)
            or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,256}", request.operation_intent)):
        raise BootstrapEnrollmentError("bootstrap enrollment request is malformed")


def _validate_setup_authorization(value: VerifiedRootSetupAuthorization) -> None:
    if (not isinstance(value, VerifiedRootSetupAuthorization)
            or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", value.target_id)
            or value.operation_target_id != RootBootstrapProvisionOperation.target
            or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", value.setup_session_id)
            or not re.fullmatch(r"[0-9a-f]{64}", value.plan_digest)
            or type(value.operator_uid) is not int or value.operator_uid < 0
            or type(value.target_uid) is not int or value.target_uid < 0
            or type(value.target_gid) is not int or value.target_gid < 0
            or value.mode not in {"install", "repair", "resume"}
            or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,256}", value.transaction_handle)):
        raise BootstrapEnrollmentError("verified root setup authorization is malformed")


def _validate_policy(policy: EnrollmentPolicy, *, records_required: bool = True) -> None:
    if (not isinstance(policy, EnrollmentPolicy) or not policy.service_profile_id
            or not policy.principal_id or not policy.generation_id
            or policy.activation_state not in {"prepared", "active"}
            or records_required and not policy.records
            or not policy.source_artifact_id
            or len(policy.records) > 1024 or len({policy.home_root, policy.work_root, policy.data_root}) != 3):
        raise BootstrapEnrollmentError("root service enrollment policy is missing or malformed")


def _validate_authority_base(value: Mapping[str, Any]) -> None:
    required = {"schema", "key_id", "principals", "rules", "authentik", "process_profiles",
                "provider_enrollments", "mcp_services", "mcp_http_bindings", "memory_providers",
                "native_bridges", "normalization_policies", "delegations", "service_generations"}
    if not isinstance(value, Mapping) or set(value) != required or value.get("schema") != 1:
        raise BootstrapEnrollmentError("root-selected base authority document does not match the strict authority schema")
    from .enrollment import _reject_secret_material
    try:
        _reject_secret_material(dict(value))
    except Exception:
        raise BootstrapEnrollmentError("base authority documents may contain credential references only") from None


def _validate_prepared_policy(policy: EnrollmentPolicy) -> None:
    if policy.records:
        raise BootstrapEnrollmentError("prepared generation cannot publish runnable service records")
    catalog_names = ("protected_devices", "protected_build_records", "native_packages",
                     "memory_enrollments", "operation_parameter_schemas", "source_issuers",
                     "resource_jobs", "remote_session_enrollments", "resource_backend_enrollments",
                     "resource_body_recipes", "resource_scope_bindings", "resource_validators")
    if any(getattr(policy, name) for name in catalog_names):
        raise BootstrapEnrollmentError("prepared generation cannot activate dependent catalogs")


def _validate_prepared_authority(authority: Mapping[str, Any]) -> None:
    inactive_maps = ("principals", "rules", "process_profiles", "provider_enrollments",
                     "mcp_services", "mcp_http_bindings", "memory_providers", "native_bridges",
                     "normalization_policies", "delegations")
    if any(authority.get(name) != {} for name in inactive_maps):
        raise BootstrapEnrollmentError("prepared authority snapshot cannot expose active worker effects")


def _validate_receipts(receipts: tuple[VerifiedArtifactReceipt, ...]) -> None:
    seen = set()
    for item in receipts:
        if (not isinstance(item, VerifiedArtifactReceipt) or not item.receipt_id
                or not item.artifact_id or len(item.sha256) != 64
                or any(char not in "0123456789abcdef" for char in item.sha256)
                or type(item.maximum_bytes) is not int or not 1 <= item.maximum_bytes <= 8 * 1024**3
                or item.receipt_id in seen):
            raise BootstrapEnrollmentError("root artifact receipt is invalid or duplicated")
        seen.add(item.receipt_id)


def _linux() -> bool:
    return os.name == "posix" and Path("/proc/sys/kernel/ostype").exists()


def _assert_secure_parent(path: Path) -> None:
    if not path.is_absolute():
        raise BootstrapEnrollmentError("protected path must be absolute")
    cursor = Path(path.anchor)
    for part in path.parts[1:]:
        cursor /= part
        info = cursor.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise BootstrapEnrollmentError("protected parent directory ownership or mode is invalid")


def _ensure_root_chain(path: Path, *, ceiling: Path) -> None:
    """Create only root-owned parents under an explicit fixed data-area prefix."""
    try:
        suffix = path.relative_to(ceiling)
    except ValueError:
        raise BootstrapEnrollmentError("protected directory is outside the enrolled data area") from None
    _assert_secure_parent(ceiling.parent)
    cursor = ceiling.parent
    for part in (ceiling.name, *suffix.parts):
        cursor = cursor / part
        try:
            cursor.mkdir(mode=0o700)
        except FileExistsError:
            info = cursor.lstat()
            if (stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode)
                    or info.st_uid != 0 or info.st_mode & 0o022):
                raise BootstrapEnrollmentError("protected directory ancestor has foreign ownership or unsafe mode")
        else:
            os.chown(cursor, 0, 0)
            os.chmod(cursor, 0o700)


def _ensure_root_directory(path: Path) -> None:
    _ensure_root_chain(path.parent, ceiling=Path("/var/lib/hermes-installer"))
    try:
        path.mkdir(mode=0o700)
    except FileExistsError:
        info = path.lstat()
        if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
                or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700):
            raise BootstrapEnrollmentError("root-private transaction directory conflicts with existing data")
    os.chown(path, 0, 0)
    os.chmod(path, 0o700)


def _create_service_root(path: Path, identity: ServiceIdentity) -> bool:
    _ensure_root_chain(path.parent, ceiling=Path("/var/lib/hermes-installer/services"))
    try:
        path.mkdir(mode=0o700)
    except FileExistsError:
        return False
    os.chown(path, identity.uid, identity.gid)
    os.chmod(path, 0o700)
    return True


def _verify_service_root(path: Path, identity: ServiceIdentity) -> None:
    info = path.lstat()
    if (stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode)
            or info.st_uid != identity.uid or info.st_gid != identity.gid
            or stat.S_IMODE(info.st_mode) != 0o700):
        raise BootstrapEnrollmentError("existing service root has foreign ownership or unsafe mode")


def _copy_verified_artifact(receipt: VerifiedArtifactReceipt, target: Path) -> None:
    _assert_secure_parent(target.parent)
    source_info = receipt.source.lstat()
    if stat.S_ISLNK(source_info.st_mode) or not stat.S_ISREG(source_info.st_mode):
        raise BootstrapEnrollmentError("artifact receipt source is not a regular file")
    if source_info.st_size > receipt.maximum_bytes:
        raise BootstrapEnrollmentError("artifact receipt exceeds its enrolled size bound")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(receipt.source, flags)
    temp = target.with_name("." + target.name + "." + secrets.token_hex(8) + ".tmp")
    out = -1
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (source_info.st_dev, source_info.st_ino):
            raise BootstrapEnrollmentError("artifact receipt source changed during verification")
        out = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        digest = hashlib.sha256()
        total = 0
        while True:
            block = os.read(fd, 65536)
            if not block:
                break
            total += len(block)
            if total > receipt.maximum_bytes:
                raise BootstrapEnrollmentError("artifact receipt exceeds its enrolled size bound")
            digest.update(block)
            offset = 0
            while offset < len(block):
                offset += os.write(out, block[offset:])
        if digest.hexdigest() != receipt.sha256:
            raise BootstrapEnrollmentError("artifact receipt bytes do not match the enrolled digest")
        os.fchmod(out, 0o444)
        os.fchown(out, 0, 0)
        os.fsync(out)
        os.close(out)
        out = -1
        os.replace(temp, target)
        directory_fd = os.open(target.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        os.close(fd)
        if out >= 0:
            os.close(out)
        try:
            temp.unlink()
        except FileNotFoundError:
            pass


def _verify_root_artifact(path: Path, receipt: VerifiedArtifactReceipt) -> None:
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o444:
        raise BootstrapEnrollmentError("content-addressed artifact store has foreign content")
    if info.st_size > receipt.maximum_bytes or hashlib.sha256(path.read_bytes()).hexdigest() != receipt.sha256:
        raise BootstrapEnrollmentError("content-addressed artifact store digest is invalid")


def _atomic_root_file(path: Path, data: bytes, mode: int = 0o600) -> None:
    if os.geteuid() != 0:
        raise BootstrapEnrollmentPending("protected authority updates require Linux root")
    _assert_secure_parent(path.parent)
    if path.exists() and not _root_file_ok(path):
        raise BootstrapEnrollmentError("existing protected file ownership or mode is invalid")
    temp = path.with_name("." + path.name + "." + secrets.token_hex(8) + ".tmp")
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), mode)
    try:
        os.fchmod(fd, mode)
        os.fchown(fd, 0, 0)
        offset = 0
        while offset < len(data):
            offset += os.write(fd, data[offset:])
        os.fsync(fd)
    finally:
        os.close(fd)
    try:
        os.replace(temp, path)
        directory_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        try:
            temp.unlink()
        except FileNotFoundError:
            pass


def _root_file_ok(path: Path) -> bool:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return False
    return stat.S_ISREG(info.st_mode) and not stat.S_ISLNK(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o600


def _exists_without_following(path: Path) -> bool:
    try:
        path.lstat()
        return True
    except FileNotFoundError:
        return False


def _load_authority(path: Path) -> Mapping[str, Any]:
    from .enrollment import read_protected_file
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result
    try:
        raw = read_protected_file(path, expected_uid=0, maximum=MAX_AUTHORITY_BYTES)
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique)
    except (OSError, ValueError, UnicodeError):
        raise BootstrapEnrollmentError("existing root authority file is malformed") from None
    if not isinstance(value, dict):
        raise BootstrapEnrollmentError("existing root authority file is malformed")
    return value


def _read_json_if_owned(path: Path):
    try:
        if not _root_file_ok(path) or path.stat().st_size > 65_536:
            return None
        return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_unique_pairs)
    except (OSError, ValueError, UnicodeError):
        return None


def _write_journal(path: Path, transaction_id: str, state: str,
                   created_roots: list[Path], artifacts: list[Path], *,
                   roots: tuple[Path, ...] = (),
                   backup: Path | None = None, identity: ServiceIdentity | None = None,
                   generation_digest: str | None = None,
                   provision_receipt_handle: str | None = None,
                   request_digest: str | None = None,
                   artifact_receipt_digests: tuple[str, ...] = (),
                   setup_authorization: VerifiedRootSetupAuthorization | Mapping[str, Any] | None = None,
                   identity_attempted: bool | None = None,
                   previous_generation_digest: str | None = None) -> None:
    if identity_attempted is None:
        prior_journal = _read_json_if_owned(path)
        identity_attempted = bool(prior_journal.get("identity_attempted", False)) if isinstance(prior_journal, dict) else False
    prior_journal = _read_json_if_owned(path)
    if previous_generation_digest is None and isinstance(prior_journal, dict):
        previous_generation_digest = prior_journal.get("previous_generation_digest")
    if isinstance(setup_authorization, VerifiedRootSetupAuthorization):
        setup = {"target_id": setup_authorization.target_id,
                 "operation_target_id": setup_authorization.operation_target_id,
                 "setup_session_id": setup_authorization.setup_session_id,
                 "plan_digest": setup_authorization.plan_digest,
                 "plan_artifact_id": setup_authorization.plan_artifact_id,
                 "operator_uid": setup_authorization.operator_uid,
                 "target_uid": setup_authorization.target_uid,
                 "target_gid": setup_authorization.target_gid,
                 "mode": setup_authorization.mode,
                 "launcher_artifact_id": setup_authorization.launcher_artifact_id,
                 "launcher_sha256": setup_authorization.launcher_sha256,
                 "root_actor_identity": dict(setup_authorization.root_actor_identity),
                 "root_journal_root": dict(setup_authorization.root_journal_root),
                 "transaction_handle": setup_authorization.transaction_handle,
                 "expected_previous_generation_digest": setup_authorization.expected_previous_generation_digest}
    elif isinstance(setup_authorization, Mapping):
        setup = dict(setup_authorization)
    else:
        setup = None
    _atomic_root_file(path, _canonical({"schema": 1, "transaction_id": transaction_id,
                                        "state": state, "created_roots": [str(p) for p in created_roots],
                                        "roots": [str(p) for p in roots],
                                        "artifacts": [str(p) for p in artifacts],
                                        "backup": str(backup) if backup else "",
                                        "identity": None if identity is None else {
                                            "name": identity.name, "uid": identity.uid,
                                            "gid": identity.gid, "created": identity.created},
                                        "generation_digest": generation_digest,
                                        "provision_receipt_handle": provision_receipt_handle,
                                        "request_digest": request_digest,
                                        "artifact_receipt_digests": list(artifact_receipt_digests),
                                        "setup_authorization": setup,
                                        "identity_attempted": identity_attempted,
                                        "previous_generation_digest": previous_generation_digest}))


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _unlink_only_owned(path: Path, *, uid: int, expected_sha256: str | None = None) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return
    if (stat.S_ISREG(info.st_mode) and info.st_uid == uid
            and (expected_sha256 is None or hashlib.sha256(path.read_bytes()).hexdigest() == expected_sha256)):
        path.unlink()
    else:
        raise BootstrapEnrollmentError("rollback encountered a changed artifact; preserved it")


def _remove_empty_service_root(path: Path, identity: ServiceIdentity | None) -> bool:
    if identity is None:
        return False
    try:
        _verify_service_root(path, identity)
        path.rmdir()
        return True
    except FileNotFoundError:
        return True
    except OSError:
        # Preserve nonempty user data; the journal remains the recovery record.
        return False
