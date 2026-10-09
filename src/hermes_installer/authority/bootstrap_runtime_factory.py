"""Installed root setup assembly for the first Hermes service generation.

The selection file, release tree, artifact catalog and bootstrap-policy document
are all read from the root deployment trust source. This module deliberately
does not accept caller supplied policy rows, paths, hashes or ``EnrollmentPolicy``
objects. Runtime activation accepts only setup-scoped receipt handles that the
same root registry resolves to immutable CAS objects.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import secrets
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

from ..artifacts import ArtifactCatalog, load_protected_catalog
from ..hermes_source import HERMES_SOURCE_ARTIFACT_ID
from .bootstrap_enrollment import (
    BootstrapEnrollmentError,
    BootstrapEnrollmentPending,
    BootstrapEnrollmentRequest,
    EnrollmentPolicy,
    EnrollmentReceipt,
    InstalledRootSetupActorVerifier,
    RootArtifactReceiptRegistry,
    RootBootstrapEnrollment,
    RootSetupActorVerifier,
    RootSetupSessionHandle,
    RootSetupSessionStore,
    ServiceIdentity,
    SystemIdentityAdapter,
    VerifiedArtifactReceipt,
    VerifiedRootSetupAuthorization,
    VerifiedRootSetupPlan,
    _canonical,
    _ensure_root_directory,
    _open_immutable_release_root,
    _read_secure_root_bytes,
    _unique_pairs,
    _validate_sha256,
    _verify_release_file_at,
)


_SELECTION_PATH = Path("/etc/hermes-installer/root-setup-selection.json")
_SELECTION_ID = "installer-root-setup-selection-v1"
_PLAN_ID = "installer-root-setup-plan-v1"
_LAUNCHER_ID = "installer-root-setup-launcher-v1"
_INTERPRETER_ID = "installer-root-setup-interpreter-v1"
_CATALOG_ID = "installer-protected-artifact-catalog-v1"
_POLICY_ID = "installer-bootstrap-policy-v1"
_STORE_ID = "installer-bootstrap-artifact-store-v1"
_JOURNAL_ID = "installer-authority-journal-v1"
_GEN = re.compile(r"[A-Za-z0-9_.:-]{1,128}\Z")
_ID = re.compile(r"[A-Za-z0-9_.-]{1,128}\Z")
_SHA = re.compile(r"[0-9a-f]{64}\Z")


def _fail(message: str) -> None:
    raise BootstrapEnrollmentPending(message)


@dataclass(frozen=True, slots=True)
class _Selection:
    release_root: Path
    release_root_id: str
    release_device: int
    release_inode: int
    selection_digest: str
    launcher: Mapping[str, Any]
    interpreter: Mapping[str, Any]
    modules: tuple[Mapping[str, Any], ...]
    plans: tuple[Mapping[str, Any], ...]
    artifact_catalog: Mapping[str, Any]
    artifact_store: Mapping[str, Any]
    bootstrap_policies: tuple[Mapping[str, Any], ...]


@dataclass(frozen=True, slots=True)
class VerifiedRootBootstrapPolicy:
    """Parsed policy bytes pinned by the installed selection catalog."""

    artifact_id: str
    sha256: str
    plan_artifact_id: str
    source_artifact_id: str
    identity_policy: Mapping[str, Any]
    root_policy: Mapping[str, Any]
    authority_base_template: Mapping[str, Any]
    service_record_templates: tuple[Mapping[str, Any], ...]
    catalog_selections: Mapping[str, tuple[Mapping[str, Any], ...]]
    receipt_binding_rules: tuple[Mapping[str, Any], ...]


@dataclass(frozen=True, slots=True, repr=False)
class RootRuntimeArtifactReceipt:
    """Opaque root-minted reference to one verified setup CAS object."""

    role: str
    artifact_id: str
    sha256: str
    generation: str
    receipt_handle: str
    size_bytes: int
    _seal: str = field(repr=False)


@dataclass(frozen=True, slots=True, repr=False)
class RootSelectedInstallationBinding:
    """Opaque session binding; never exposes service or journal paths."""

    _session: "RootBootstrapSession" = field(repr=False)
    _seal: str = field(repr=False)

    def authorize_native_materialization(
            self, *, enrollment_id: str, service_generation: str,
            resource_profile_id: str) -> NativeMaterializationSelection:
        if not secrets.compare_digest(self._seal, self._session._seal):
            raise BootstrapEnrollmentError("installation binding does not belong to its root setup session")
        selected = self._session._authorize_native_materialization(
            enrollment_id=enrollment_id, service_generation=service_generation,
            resource_profile_id=resource_profile_id)
        from .native_materialization import NativeMaterializationSelection
        return NativeMaterializationSelection(
            enrollment_id=selected.enrollment_id,
            service_generation=selected.service_generation,
            service_profile_id=selected.service_profile_id,
            protected_enrollment_digest=selected.protected_enrollment_digest,
            service_uid=selected.service_uid, service_gid=selected.service_gid,
            home_root_id=selected.home_root_id, data_root_id=selected.data_root_id,
            source_artifact_id=selected.source_artifact_id,
            source_receipt_handle=selected.source_receipt_handle)

    def resolve_private_roots(self, selection: Any) -> "_RootPrivateInstallationRoots":
        if not secrets.compare_digest(self._seal, self._session._seal):
            raise BootstrapEnrollmentError("installation binding does not belong to its root setup session")
        return self._session._resolve_private_installation_roots(selection)


@dataclass(frozen=True, slots=True, repr=False)
class _BoundNativeSelection:
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
    _session_id: str = field(repr=False)
    _seal: str = field(repr=False)


@dataclass(frozen=True, slots=True, repr=False)
class _RootPrivateInstallationRoots:
    home_root: Path
    data_root: Path
    journal_root: Path
    hermes_source_tree: Path


class InstalledBootstrapPolicyResolver:
    """Resolve the strict extended selection and its exact deployed policy."""

    def __init__(self, selection_path: Path = _SELECTION_PATH):
        if not selection_path.is_absolute():
            raise ValueError("installed root selection path must be absolute")
        self.selection_path = selection_path
        self._selection: _Selection | None = None
        self._catalog: ArtifactCatalog | None = None
        self._plans: dict[str, VerifiedRootSetupPlan] = {}
        self._policies: dict[str, VerifiedRootBootstrapPolicy] = {}

    @property
    def catalog(self) -> ArtifactCatalog:
        if self._catalog is None:
            self._load_selection()
        assert self._catalog is not None
        return self._catalog

    @property
    def artifact_root(self) -> Path:
        selection = self._load_selection()
        journal = Path("/var/lib/hermes-installer/authority-journal")
        if selection.artifact_store["journal_root_id"] != _JOURNAL_ID:
            _fail("selected bootstrap artifact store names an unsupported journal root")
        if (selection.artifact_store["root_id"] != _STORE_ID
                or selection.artifact_store["relative_path"] != "bootstrap-artifacts"
                or selection.artifact_store["owner_uid"] != 0
                or selection.artifact_store["owner_gid"] != 0
                or selection.artifact_store["mode"] != 0o700):
            _fail("installed root selection has no fixed root-owned bootstrap artifact store")
        return journal / "bootstrap-artifacts"

    @property
    def journal_root(self) -> Path:
        selection = self._load_selection()
        if selection.artifact_store["journal_root_id"] != _JOURNAL_ID:
            _fail("installed root selection has no fixed authority journal root")
        return Path("/var/lib/hermes-installer/authority-journal")

    def resolve(self, artifact_id: str) -> VerifiedRootSetupPlan:
        if artifact_id != _PLAN_ID:
            _fail("root setup plan is not the fixed reviewed installer plan")
        selection = self._load_selection()
        if artifact_id in self._plans:
            return self._plans[artifact_id]
        plan_rows = [row for row in selection.plans if row["artifact_id"] == artifact_id]
        if len(plan_rows) != 1:
            _fail("fixed root setup plan is absent or ambiguous in the installed selection")
        row = plan_rows[0]
        root_fd = _open_immutable_release_root(selection.release_root,
                                               selection.release_device,
                                               selection.release_inode)
        try:
            launcher_path, launcher_sha = self._fixed_file(
                selection.launcher, _LAUNCHER_ID, selection.release_root, root_fd)
            interpreter_path, interpreter_sha = self._fixed_file(
                selection.interpreter, _INTERPRETER_ID, selection.release_root, root_fd)
            modules: list[tuple[str, Path, str]] = []
            for module in selection.modules:
                path = self._verified_relative(module, module["artifact_id"], selection.release_root, root_fd)
                modules.append((module["module_name"], path, module["sha256"]))
            plan_path = self._verified_relative(row, artifact_id, selection.release_root, root_fd)
            del plan_path
            plan = VerifiedRootSetupPlan(
                artifact_id=artifact_id, digest=row["sha256"],
                launcher_artifact_id=_LAUNCHER_ID, launcher_sha256=launcher_sha,
                launcher_path=launcher_path, interpreter_path=interpreter_path,
                interpreter_sha256=interpreter_sha, module_closure=tuple(modules),
                allowed_artifact_ids=tuple(row["allowed_artifact_ids"]),
            )
        finally:
            os.close(root_fd)
        self._plans[artifact_id] = plan
        return plan

    def resolve_policy(self, plan_artifact_id: str) -> VerifiedRootBootstrapPolicy:
        if plan_artifact_id != _PLAN_ID:
            _fail("bootstrap policy requires the fixed selected root setup plan")
        selection = self._load_selection()
        if plan_artifact_id in self._policies:
            return self._policies[plan_artifact_id]
        plan_rows = [row for row in selection.plans if row["artifact_id"] == plan_artifact_id]
        policy_rows = [row for row in selection.bootstrap_policies if row["artifact_id"] == _POLICY_ID]
        if len(plan_rows) != 1 or len(policy_rows) != 1:
            _fail("installed root selection lacks one selected bootstrap policy")
        plan_row, policy_row = plan_rows[0], policy_rows[0]
        if (plan_row.get("bootstrap_policy_artifact_id") != _POLICY_ID
                or policy_row["relative_path"] != "plans/bootstrap-policy-v1.json"):
            _fail("selected root plan does not join the fixed bootstrap policy source")
        self.resolve(_PLAN_ID)
        root_fd = _open_immutable_release_root(selection.release_root,
                                               selection.release_device,
                                               selection.release_inode)
        try:
            policy_path = self._verified_relative(policy_row, _POLICY_ID,
                                                  selection.release_root, root_fd)
        finally:
            os.close(root_fd)
        raw = self._read_release_file(policy_path, maximum=2 * 1024 * 1024,
                                      expected_sha256=policy_row["sha256"])
        doc = self._json(raw, "installed bootstrap policy")
        if raw != _canonical(doc, ensure_ascii=False):
            _fail("installed bootstrap policy bytes are not canonical UTF-8 JSON")
        policy = self._parse_policy(doc, policy_row["sha256"], plan_row, selection)
        self._policies[plan_artifact_id] = policy
        return policy

    def _load_selection(self) -> _Selection:
        if self._selection is not None:
            return self._selection
        if os.geteuid() != 0 or not self._linux():
            _fail("installed root bootstrap selection is available only to the Linux root launcher")
        raw = _read_secure_root_bytes(self.selection_path, 2 * 1024 * 1024, 0o600)
        doc = self._json(raw, "installed root selection")
        fields = {"schema", "selection_id", "installer_release_commit", "release_root",
                  "launcher", "interpreter", "module_closure", "plans", "catalog_sha256",
                  "artifact_catalog", "artifact_store", "bootstrap_policies"}
        if (set(doc) != fields or type(doc["schema"]) is not int or doc["schema"] != 1
                or doc["selection_id"] != _SELECTION_ID
                or not isinstance(doc["installer_release_commit"], str)
                or not re.fullmatch(r"[0-9a-f]{40}", doc["installer_release_commit"])):
            _fail("installed root setup selection has an unsupported strict schema")
        digest = doc["catalog_sha256"]
        _validate_sha256(digest, "root setup selection")
        unsigned = {key: item for key, item in doc.items() if key != "catalog_sha256"}
        if not secrets.compare_digest(hashlib.sha256(_canonical(unsigned, ensure_ascii=False)).hexdigest(), digest):
            _fail("installed root setup selection catalog digest is invalid")
        release = doc["release_root"]
        if (not isinstance(release, dict)
                or set(release) != {"root_id", "absolute_path", "device", "inode", "deployment_receipt_sha256"}
                or not isinstance(release["root_id"], str) or not _GEN.fullmatch(release["root_id"])
                or not isinstance(release["absolute_path"], str)
                or not Path(release["absolute_path"]).is_absolute()
                or type(release["device"]) is not int or release["device"] < 0
                or type(release["inode"]) is not int or release["inode"] < 1):
            _fail("installed root release custody identity is malformed")
        _validate_sha256(release["deployment_receipt_sha256"], "release deployment receipt")
        root = Path(release["absolute_path"])
        if (not isinstance(doc["module_closure"], list) or not doc["module_closure"]
                or len(doc["module_closure"]) > 1024
                or not isinstance(doc["plans"], list) or not 1 <= len(doc["plans"]) <= 16
                or not isinstance(doc["bootstrap_policies"], list)
                or not 1 <= len(doc["bootstrap_policies"]) <= 16):
            _fail("installed root setup selection row bounds are invalid")
        launcher = self._selection_row(doc["launcher"], {"artifact_id", "relative_path", "sha256"})
        interpreter = self._selection_row(doc["interpreter"], {"artifact_id", "relative_path", "sha256"})
        if launcher["artifact_id"] != _LAUNCHER_ID or interpreter["artifact_id"] != _INTERPRETER_ID:
            _fail("installed launcher or interpreter has an unsupported fixed role")
        modules = []
        for row in doc["module_closure"]:
            item = self._selection_row(row, {"module_name", "artifact_id", "relative_path", "sha256"})
            if not isinstance(item["module_name"], str) or not re.fullmatch(
                    r"[A-Za-z_][A-Za-z0-9_.]{0,191}", item["module_name"]):
                _fail("installed root module closure contains an invalid module name")
            modules.append(item)
        plans = []
        plan_fields = {"artifact_id", "relative_path", "sha256", "baseline_tag_object",
                       "baseline_commit", "baseline_tree_sha256", "amendment_manifest_sha256",
                       "allowed_artifact_ids", "bootstrap_policy_artifact_id"}
        for row in doc["plans"]:
            item = self._selection_row(row, plan_fields)
            if (item["baseline_tag_object"] != "c47c90cf2e0a6b1cd5779257fdcba9e487ee08f8"
                    or item["baseline_commit"] != "653ac5fbc7a02613c9951859a7d794599603459b"
                    or not isinstance(item["allowed_artifact_ids"], list)
                    or not item["allowed_artifact_ids"] or len(item["allowed_artifact_ids"]) > 256
                    or len(set(item["allowed_artifact_ids"])) != len(item["allowed_artifact_ids"])):
                _fail("installed root plan provenance or artifact allowlist is malformed")
            for artifact in item["allowed_artifact_ids"]:
                if not isinstance(artifact, str) or not _ID.fullmatch(artifact):
                    _fail("selected plan artifact allowlist contains an invalid ID")
            plans.append(item)
        policies = []
        for row in doc["bootstrap_policies"]:
            policies.append(self._selection_row(row, {"artifact_id", "relative_path", "sha256"}))
        if len({row["artifact_id"] for row in [launcher, interpreter, *modules, *plans, *policies]}) != 2 + len(modules) + len(plans) + len(policies):
            _fail("installed root setup selection contains duplicate artifact IDs")
        if len({row["relative_path"] for row in [launcher, interpreter, *modules, *plans, *policies]}) != 2 + len(modules) + len(plans) + len(policies):
            _fail("installed root setup selection contains duplicate relative paths")
        artifact_catalog = self._selection_row(doc["artifact_catalog"], {"artifact_id", "relative_path", "sha256"})
        if (artifact_catalog["artifact_id"] != _CATALOG_ID
                or artifact_catalog["relative_path"] != "catalog/artifacts.json"):
            _fail("installed root artifact catalog is not the fixed selected catalog")
        store = doc["artifact_store"]
        store_fields = {"root_id", "journal_root_id", "relative_path", "owner_uid", "owner_gid", "mode"}
        if not isinstance(store, dict) or set(store) != store_fields:
            _fail("installed root bootstrap artifact store row is malformed")
        self._load_catalog(root, release["device"], release["inode"], artifact_catalog, tuple(plans))
        self._selection = _Selection(root, release["root_id"], release["device"], release["inode"],
                                     digest, launcher, interpreter, tuple(modules), tuple(plans),
                                     artifact_catalog, store, tuple(policies))
        return self._selection

    def _load_catalog(self, root: Path, device: int, inode: int,
                      row: Mapping[str, Any], plans: tuple[Mapping[str, Any], ...]) -> None:
        root_fd = _open_immutable_release_root(root, device, inode)
        try:
            path = self._verified_relative(row, _CATALOG_ID, root, root_fd)
        finally:
            os.close(root_fd)
        raw = self._read_release_file(path, maximum=16 * 1024 * 1024,
                                      expected_sha256=row["sha256"])
        if not secrets.compare_digest(hashlib.sha256(raw).hexdigest(), row["sha256"]):
            _fail("installed artifact catalog bytes do not match the root selection pin")
        try:
            self._catalog = load_protected_catalog(path, expected_uid=0)
        except Exception:
            _fail("installed protected artifact catalog failed strict parsing")
        for plan in plans:
            if any(artifact_id not in self._catalog.artifacts for artifact_id in plan["allowed_artifact_ids"]):
                _fail("selected root plan allows an artifact absent from the exact protected catalog")

    def _parse_policy(self, doc: Any, digest: str, plan_row: Mapping[str, Any],
                      selection: _Selection) -> VerifiedRootBootstrapPolicy:
        fields = {"schema", "id", "source_artifact_id", "identity_policy", "root_policy",
                  "authority_base_template", "service_record_templates", "catalog_selections",
                  "receipt_binding_rules"}
        if (not isinstance(doc, dict) or set(doc) != fields or type(doc["schema"]) is not int
                or doc["schema"] != 1 or doc["id"] != _POLICY_ID
                or plan_row["bootstrap_policy_artifact_id"] != _POLICY_ID):
            _fail("installed bootstrap policy document does not match the selected strict schema")
        _validate_sha256(digest, "installed bootstrap policy")
        source_id = doc["source_artifact_id"]
        if source_id != HERMES_SOURCE_ARTIFACT_ID or source_id not in plan_row["allowed_artifact_ids"]:
            _fail("bootstrap policy does not select the pinned official Hermes source")
        identity_fields = {"service_profile_id", "principal_id", "service_account_name",
                           "exclusive_group_name", "uid_allocation"}
        identity = doc["identity_policy"]
        if (not isinstance(identity, dict) or set(identity) != identity_fields
                or any(not isinstance(identity[key], str) or not _ID.fullmatch(identity[key])
                       for key in identity_fields)
                or identity["uid_allocation"] != "root-dedicated-account"
                or identity["service_account_name"] != identity["exclusive_group_name"]):
            _fail("bootstrap service identity policy is incomplete or unsupported")
        root_fields = {"journal_root_id", "service_home_root_id", "service_work_root_id",
                       "service_data_root_id", "service_parent_root"}
        roots = doc["root_policy"]
        root_ids = ("journal_root_id", "service_home_root_id", "service_work_root_id", "service_data_root_id")
        if (not isinstance(roots, dict) or set(roots) != root_fields
                or any(not isinstance(roots[key], str) or not _ID.fullmatch(roots[key])
                       for key in root_ids)
                or len({roots[key] for key in root_ids}) != len(root_ids)
                or roots["journal_root_id"] != _JOURNAL_ID
                or roots["service_parent_root"] != "/var/lib/hermes-installer/services"):
            _fail("bootstrap service root policy does not use the selected private root layout")
        base = doc["authority_base_template"]
        self._validate_authority_base_template(base)
        templates = doc["service_record_templates"]
        if not isinstance(templates, list) or not 1 <= len(templates) <= 64:
            _fail("bootstrap service-record template list is empty or oversized")
        normalized_templates = []
        for row in templates:
            if not isinstance(row, dict) or set(row) != {"id", "record", "receipt_bindings"}:
                _fail("bootstrap service-record template envelope is malformed")
            if not isinstance(row["id"], str) or not _ID.fullmatch(row["id"]):
                _fail("bootstrap service-record template ID is malformed")
            record = row["record"]
            if not isinstance(record, dict):
                _fail("bootstrap service-record template body is malformed")
            if (record.get("profile_id") != identity["service_profile_id"]
                    or record.get("principal_id") != identity["principal_id"]
                    or record.get("service_user") != identity["service_account_name"]):
                _fail("bootstrap service template does not join its selected identity policy")
            bindings = row["receipt_bindings"]
            if not isinstance(bindings, list) or len(bindings) > 256:
                _fail("bootstrap receipt-binding list is malformed")
            normalized = []
            seen_paths: set[tuple[Any, ...]] = set()
            for binding in bindings:
                if not isinstance(binding, dict) or set(binding) != {"field_path", "receipt_role", "receipt_field"}:
                    _fail("bootstrap receipt binding does not match the strict binding schema")
                path = binding["field_path"]
                if (not isinstance(path, list) or not path
                        or any(type(part) not in {str, int} or type(part) is int and part < 0 for part in path)
                        or not isinstance(binding["receipt_role"], str)
                        or binding["receipt_role"] not in {
                            "official-agent-source", "official-installer-script", "official-pm-lock",
                            "official-pm-runtime", "native-launcher", "installed-agent-closure",
                            "resources-source-bundle", "native-compiled-closure",
                            "native-entrypoint-manifest", "native-action-resolver",
                            "native-boundary-overlay", "native-health"}
                        or not isinstance(binding["receipt_field"], str)
                        or binding["receipt_field"] not in {"artifact_id", "sha256", "generation", "receipt_handle"}):
                    _fail("bootstrap receipt binding role, path, or field is unsupported")
                frozen_path = tuple(path)
                if frozen_path in seen_paths:
                    _fail("bootstrap receipt bindings target a duplicate field")
                seen_paths.add(frozen_path)
                normalized.append({**binding, "field_path": list(path)})
            normalized_templates.append({"id": row["id"], "record": copy.deepcopy(record),
                                         "receipt_bindings": tuple(normalized)})
        selection_fields = {"protected_devices", "protected_build_records", "native_packages",
                            "memory_enrollments", "operation_parameter_schemas", "source_issuers",
                            "resource_jobs", "remote_session_enrollments", "resource_backend_enrollments",
                            "resource_body_recipes", "resource_scope_bindings", "resource_validators",
                            "root_journal_roots"}
        catalogs = doc["catalog_selections"]
        if not isinstance(catalogs, dict) or set(catalogs) != selection_fields:
            _fail("bootstrap catalog selections do not cover the exact enrollment schema")
        clean_catalogs = {}
        for name, rows in catalogs.items():
            if not isinstance(rows, list) or len(rows) > 1024 or any(not isinstance(row, dict) for row in rows):
                _fail("bootstrap catalog selection rows are malformed")
            clean_catalogs[name] = tuple(copy.deepcopy(rows))
        if any(clean_catalogs[name] for name in selection_fields - {"root_journal_roots"}):
            # Nonempty secondary catalogs need their own exact nested-schema
            # validator and selected policy receipts. The current bootstrap
            # policy supports only the finite service profile and source set.
            _fail("bootstrap policy requests an unimplemented protected catalog enrollment")
        binding_rules = self._validate_receipt_binding_rules(
            doc["receipt_binding_rules"], plan_row["allowed_artifact_ids"])
        return VerifiedRootBootstrapPolicy(
            artifact_id=_POLICY_ID, sha256=digest, plan_artifact_id=plan_row["artifact_id"],
            source_artifact_id=source_id, identity_policy=dict(identity), root_policy=dict(roots),
            authority_base_template=copy.deepcopy(base),
            service_record_templates=tuple(normalized_templates),
            catalog_selections=clean_catalogs, receipt_binding_rules=tuple(copy.deepcopy(binding_rules)),
        )

    @staticmethod
    def _validate_receipt_binding_rules(value: Any,
                                        allowed_plan_artifacts: list[str]) -> list[dict[str, Any]]:
        """Validate the finite role/output/phase join before any receipt is used."""
        roles = {
            "official-agent-source", "official-installer-script", "official-pm-lock",
            "official-pm-runtime", "resources-source-bundle", "native-compiled-closure",
            "native-entrypoint-manifest", "native-action-resolver", "native-boundary-overlay",
            "native-health",
        }
        outputs = {"source-archive", "compiled-closure", "entrypoint-json",
                   "resolver-json", "boundary-overlay"}
        phases = {"prepared-source", "runnable", "functional-health"}
        if not isinstance(value, list) or len(value) > 256:
            _fail("bootstrap receipt binding rules are malformed")
        result: list[dict[str, Any]] = []
        seen_roles: set[str] = set()
        for row in value:
            if not isinstance(row, dict) or set(row) != {
                    "receipt_role", "allowed_artifact_ids", "allowed_output_kinds",
                    "required_phase", "field_bindings"}:
                _fail("bootstrap receipt binding rule has unknown or missing fields")
            role = row["receipt_role"]
            ids, kinds, phase, bindings = (row["allowed_artifact_ids"],
                                           row["allowed_output_kinds"],
                                           row["required_phase"], row["field_bindings"])
            if (not isinstance(role, str) or role not in roles or role in seen_roles or not isinstance(ids, list)
                    or not ids or len(ids) > 256
                    or any(not isinstance(item, str) or not _ID.fullmatch(item) for item in ids)
                    or len(set(ids)) != len(ids)
                    or not isinstance(kinds, list) or not kinds
                    or any(not isinstance(item, str) or item not in outputs for item in kinds)
                    or len(set(kinds)) != len(kinds)
                    or not isinstance(phase, str) or phase not in phases
                    or not isinstance(bindings, list) or len(bindings) > 256):
                _fail("bootstrap receipt binding rule values are malformed")
            if role in {"official-agent-source", "official-installer-script", "official-pm-lock",
                        "official-pm-runtime", "resources-source-bundle"}:
                if any(item not in allowed_plan_artifacts for item in ids):
                    _fail("source receipt rule allows an artifact outside the selected plan")
            if role == "native-health" and phase != "functional-health":
                _fail("native health receipt can bind only functional-health fields")
            if role != "native-health" and phase == "functional-health":
                _fail("functional-health phase is reserved for native health receipts")
            clean_bindings = []
            for binding in bindings:
                if (not isinstance(binding, dict)
                        or set(binding) != {"field_path", "receipt_role", "receipt_field"}
                        or binding["receipt_role"] != role
                        or not isinstance(binding["field_path"], list) or not binding["field_path"]
                        or any(type(part) not in {str, int} or type(part) is int and part < 0
                               for part in binding["field_path"])
                        or not isinstance(binding["receipt_field"], str)
                        or binding["receipt_field"] not in {"artifact_id", "sha256", "generation", "receipt_handle"}):
                    _fail("bootstrap receipt rule field binding is malformed or cross-role")
                clean_bindings.append(copy.deepcopy(binding))
            result.append({"receipt_role": role, "allowed_artifact_ids": list(ids),
                           "allowed_output_kinds": list(kinds), "required_phase": phase,
                           "field_bindings": clean_bindings})
            seen_roles.add(role)
        return result

    @staticmethod
    def _validate_authority_base_template(value: Any) -> None:
        required = {"schema", "key_id", "principals", "rules", "authentik", "process_profiles",
                    "provider_enrollments", "mcp_services", "mcp_http_bindings", "memory_providers",
                    "native_bridges", "normalization_policies", "delegations", "service_generations"}
        if (not isinstance(value, dict) or set(value) != required or type(value["schema"]) is not int
                or value["schema"] != 1 or not isinstance(value["key_id"], str) or not value["key_id"]
                or any(not isinstance(value[name], dict) for name in required - {"schema", "key_id"})):
            _fail("bootstrap authority-base template does not match the protected authority schema")
        if any(value[name] for name in ("principals", "rules", "process_profiles", "provider_enrollments",
                                        "mcp_services", "mcp_http_bindings", "memory_providers", "native_bridges",
                                        "normalization_policies", "delegations", "service_generations")):
            _fail("bootstrap authority base cannot pre-enable services or worker authority")

    @staticmethod
    def _selection_row(value: Any, keys: set[str]) -> dict[str, Any]:
        if not isinstance(value, dict) or set(value) != keys:
            _fail("installed root selection row has unknown or missing fields")
        if "artifact_id" in value and (not isinstance(value["artifact_id"], str) or not _ID.fullmatch(value["artifact_id"])):
            _fail("installed root selection artifact ID is malformed")
        if "sha256" in value:
            _validate_sha256(value["sha256"], "installed root selection file")
        if "relative_path" in value:
            path = value["relative_path"]
            if (not isinstance(path, str) or not path or path.startswith("/") or "\\" in path
                    or any(part in {"", ".", ".."} for part in path.split("/"))):
                _fail("installed root selection path is not normalized and relative")
        return dict(value)

    @classmethod
    def _verified_relative(cls, row: Mapping[str, Any], artifact_id: str, root: Path, root_fd: int) -> Path:
        if row.get("artifact_id") != artifact_id:
            _fail("installed root selection row has the wrong fixed artifact role")
        cls._selection_row(dict(row), set(row))
        relative = row["relative_path"]
        _verify_release_file_at(root_fd, relative, row["sha256"])
        return root.joinpath(*relative.split("/"))

    @classmethod
    def _fixed_file(cls, row: Mapping[str, Any], artifact_id: str, root: Path, root_fd: int) -> tuple[Path, str]:
        if set(row) != {"artifact_id", "relative_path", "sha256"}:
            _fail("installed root launcher or interpreter row is malformed")
        path = cls._verified_relative(row, artifact_id, root, root_fd)
        info = path.stat(follow_symlinks=False)
        if not info.st_mode & 0o111:
            _fail("installed root launcher or interpreter is not executable")
        return path, row["sha256"]

    @staticmethod
    def _read_release_file(path: Path, *, maximum: int,
                           expected_sha256: str | None = None) -> bytes:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                    or info.st_mode & 0o222 or info.st_size > maximum):
                _fail("installed release artifact is not an immutable root-owned regular file")
            chunks = []
            total = 0
            while True:
                block = os.read(fd, min(131072, maximum + 1 - total))
                if not block:
                    break
                chunks.append(block)
                total += len(block)
                if total > maximum:
                    _fail("installed release artifact exceeds its read bound")
            after = os.fstat(fd)
            if (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) != (
                    info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns):
                _fail("installed release artifact changed during read")
            raw = b"".join(chunks)
            if (expected_sha256 is not None
                    and not secrets.compare_digest(hashlib.sha256(raw).hexdigest(), expected_sha256)):
                _fail("installed release bytes changed after the selected pin was verified")
            return raw
        finally:
            os.close(fd)

    @staticmethod
    def _json(raw: bytes, label: str) -> Any:
        try:
            return json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_pairs,
                              parse_constant=lambda _x: (_ for _ in ()).throw(ValueError()))
        except (UnicodeError, json.JSONDecodeError, ValueError):
            _fail(f"{label} is malformed JSON")

    @staticmethod
    def _linux() -> bool:
        return os.name == "posix" and Path("/proc/sys/kernel/ostype").exists()


class RootSetupPolicyFactory:
    """Construct prepared and runnable EnrollmentPolicy values from pinned bytes."""

    def __init__(self, resolver: InstalledBootstrapPolicyResolver):
        self.resolver = resolver

    def prepare(self, authorization: VerifiedRootSetupAuthorization) -> EnrollmentPolicy:
        policy = self.resolver.resolve_policy(authorization.plan_artifact_id)
        roots = policy.root_policy
        parent = Path(roots["service_parent_root"])
        self._root_journal_join(authorization)
        return EnrollmentPolicy(
            service_profile_id=policy.identity_policy["service_profile_id"],
            principal_id=policy.identity_policy["principal_id"],
            generation_id="prepared-" + secrets.token_hex(16),
            source_artifact_id=policy.source_artifact_id,
            records=(), activation_state="prepared",
            authority_base=copy.deepcopy(policy.authority_base_template),
            home_root=parent / "home", work_root=parent / "work", data_root=parent / "data",
            root_journal_roots=(dict(authorization.root_journal_root),),
        )

    def activate_runnable(self, authorization: VerifiedRootSetupAuthorization,
                          identity: ServiceIdentity,
                          receipts: Mapping[str, RootRuntimeArtifactReceipt], *,
                          seal: str) -> EnrollmentPolicy:
        policy = self.resolver.resolve_policy(authorization.plan_artifact_id)
        self._root_journal_join(authorization)
        if not receipts:
            _fail("runnable activation requires actual root-resolved runtime and launcher receipts")
        rows = []
        generation = "active-" + secrets.token_hex(16)
        parent = Path(policy.root_policy["service_parent_root"])
        roots = (parent / "home", parent / "work", parent / "data")
        for template in policy.service_record_templates:
            record = copy.deepcopy(template["record"])
            record["generation"] = generation
            record["service_uid"] = identity.uid
            record["service_gid"] = identity.gid
            record["service_user"] = identity.name
            record["roots"] = {
                "home_id": policy.root_policy["service_home_root_id"],
                "work_id": policy.root_policy["service_work_root_id"],
                "data_id": policy.root_policy["service_data_root_id"],
                "home": str(roots[0]), "work": str(roots[1]), "data": str(roots[2]),
            }
            for binding in template["receipt_bindings"]:
                role = binding["receipt_role"]
                receipt = receipts.get(role)
                rule = next((item for item in policy.receipt_binding_rules
                             if item["receipt_role"] == role), None)
                if (rule is None or rule["required_phase"] != "runnable"
                        or not isinstance(receipt, RootRuntimeArtifactReceipt)
                        or not secrets.compare_digest(receipt._seal, seal)
                        or receipt.role != role or not _ID.fullmatch(receipt.artifact_id)
                        or receipt.artifact_id not in rule["allowed_artifact_ids"]
                        or not _SHA.fullmatch(receipt.sha256)
                        or receipt.generation != authorization.transaction_handle):
                    _fail(f"required root runtime receipt for {role} is absent or not transaction-bound")
                value = getattr(receipt, binding["receipt_field"])
                self._set_template_field(record, binding["field_path"], value)
            rows.append(record)
        selection = policy.catalog_selections
        return EnrollmentPolicy(
            service_profile_id=policy.identity_policy["service_profile_id"],
            principal_id=policy.identity_policy["principal_id"],
            generation_id=generation, source_artifact_id=policy.source_artifact_id,
            records=tuple(rows),
            protected_devices=selection["protected_devices"],
            protected_build_records=selection["protected_build_records"],
            native_packages=selection["native_packages"],
            memory_enrollments=selection["memory_enrollments"],
            operation_parameter_schemas=selection["operation_parameter_schemas"],
            source_issuers=selection["source_issuers"], resource_jobs=selection["resource_jobs"],
            remote_session_enrollments=selection["remote_session_enrollments"],
            resource_backend_enrollments=selection["resource_backend_enrollments"],
            resource_body_recipes=selection["resource_body_recipes"],
            resource_scope_bindings=selection["resource_scope_bindings"],
            resource_validators=selection["resource_validators"],
            root_journal_roots=(dict(authorization.root_journal_root),), activation_state="active",
            authority_base=copy.deepcopy(policy.authority_base_template),
            home_root=roots[0], work_root=roots[1], data_root=roots[2],
        )

    @staticmethod
    def record_functional_health(_active_receipt: EnrollmentReceipt, _health_receipt: Any) -> None:
        # Functional enablement is intentionally delegated to the lifecycle's
        # root health-receipt journal consumer; this factory never turns a
        # caller status or run exit code into health authority.
        _fail("functional-health receipt consumption belongs to the installed root lifecycle observer")

    @staticmethod
    def _root_journal_join(authorization: VerifiedRootSetupAuthorization) -> None:
        row = authorization.root_journal_root
        if (not isinstance(row, Mapping) or row.get("root_id") != _JOURNAL_ID
                or row.get("absolute_path") != "/var/lib/hermes-installer/authority-journal"
                or row.get("owner_uid") != 0 or row.get("owner_gid") != 0
                or row.get("mode") != 0o700 or type(row.get("device")) is not int
                or type(row.get("inode")) is not int or not row.get("generation")
                or row.get("purpose") != "authority-journal"):
            _fail("setup session has no current selected root journal identity")

    @staticmethod
    def _set_template_field(record: Any, path: list[str | int], value: Any) -> None:
        current = record
        for segment in path[:-1]:
            if isinstance(segment, int):
                if not isinstance(current, list) or segment >= len(current):
                    _fail("receipt binding path does not resolve inside the reviewed service template")
                current = current[segment]
            else:
                if not isinstance(current, dict) or segment not in current:
                    _fail("receipt binding path does not resolve inside the reviewed service template")
                current = current[segment]
        final = path[-1]
        if isinstance(final, int):
            if not isinstance(current, list) or final >= len(current):
                _fail("receipt binding index is outside the reviewed service template")
            current[final] = value
        else:
            if not isinstance(current, dict) or final not in current or current[final] is not None:
                _fail("receipt binding must replace one explicit null template slot")
            current[final] = value


class RootBootstrapRuntimeFactory:
    """Production root-owned assembly for setup, prepared enrollment and activation."""

    def __init__(self):
        if os.getuid() != 0 or os.geteuid() != 0 or not InstalledBootstrapPolicyResolver._linux():
            raise BootstrapEnrollmentPending("root bootstrap runtime exists only in the installed Linux root process")
        self.resolver = InstalledBootstrapPolicyResolver(_SELECTION_PATH)
        # Resolving the catalog authenticates the installed catalog bytes before
        # any root store or session object is constructed.
        catalog = self.resolver.catalog
        self.resolver.resolve_policy(_PLAN_ID)
        journal_root = self.resolver.journal_root
        artifact_root = self.resolver.artifact_root
        _ensure_root_directory(journal_root)
        _ensure_root_directory(artifact_root)
        store_policy = self.resolver._load_selection().artifact_store
        artifact_info = artifact_root.lstat()
        if (artifact_info.st_uid != store_policy["owner_uid"]
                or artifact_info.st_gid != store_policy["owner_gid"]
                or stat.S_IMODE(artifact_info.st_mode) != store_policy["mode"]):
            raise BootstrapEnrollmentError("selected root artifact CAS directory ownership or mode is invalid")
        receipt_registry = RootArtifactReceiptRegistry(
            journal_root / "bootstrap-receipts", catalog=catalog, artifact_root=artifact_root)
        self.session_store = RootSetupSessionStore(
            plan_resolver=self.resolver,
            actor_verifier=InstalledRootSetupActorVerifier(),
            receipt_registry=receipt_registry,
            session_root=journal_root / "setup-sessions",
            transaction_root=journal_root / "bootstrap-transactions",
            authority_path=Path("/etc/hermes-installer/authority.json"),
        )
        self.policy_factory = RootSetupPolicyFactory(self.resolver)
        self._catalog = catalog
        self._receipt_registry = receipt_registry
        self._seal = secrets.token_hex(32)
        self._sessions: dict[str, RootBootstrapSession] = {}

    @classmethod
    def from_installed(cls) -> "RootBootstrapRuntimeFactory":
        return cls()

    def begin(self, mode: str, target_account_name: str) -> "RootBootstrapSession":
        handle = self.session_store.begin_local(mode=mode, selected_plan_artifact_id=_PLAN_ID,
                                                target_account_name=target_account_name)
        try:
            live = self.session_store._live(handle)
            authorization = self.session_store._proof(live)
            policy = self.resolver.resolve_policy(authorization.plan_artifact_id)
            identity_policy = policy.identity_policy
            marker = Path("/var/lib/hermes-installer/identities") / f"{identity_policy['service_account_name']}.json"
            identity = SystemIdentityAdapter(marker, name=identity_policy["service_account_name"])
            transaction = RootBootstrapEnrollment(
                policy_resolver=lambda _request, proof: self.policy_factory.prepare(proof),
                receipt_resolver=self._receipt_resolver,
                identity=identity,
                authority_path=Path("/etc/hermes-installer/authority.json"),
                transaction_root=self.session_store.transaction_root,
                artifact_root=self.session_store.receipt_registry.artifact_root,
                root_journal_path=self.session_store.session_root.parent,
            )
            session = RootBootstrapSession(self, handle, authorization, policy, identity,
                                           transaction, seal=self._seal)
            self._sessions[handle.session_id] = session
            return session
        except Exception:
            self.session_store.close_session(handle)
            raise

    def _receipt_resolver(self, handle: str, *, setup_authorization: VerifiedRootSetupAuthorization) -> VerifiedArtifactReceipt:
        artifact_id, digest = self._receipt_registry.lookup(handle, setup_authorization)
        selected_plan = self.resolver.resolve(setup_authorization.plan_artifact_id)
        if artifact_id not in selected_plan.allowed_artifact_ids:
            raise BootstrapEnrollmentPending("root setup receipt artifact is outside the selected plan allowlist")
        value = self._read_receipt(handle)
        try:
            spec = self._catalog._artifact(artifact_id, digest)
            resolved = self._catalog.resolve(artifact_id, digest,
                                             self._receipt_registry.artifact_root, expected_uid=0)
        except Exception:
            raise BootstrapEnrollmentPending("root setup receipt no longer resolves to its selected immutable CAS object") from None
        if (set(value) != {"schema", "handle", "receipt_id", "setup_session_id",
                           "transaction_handle", "target_id", "operation_target_id",
                           "plan_digest", "operator_uid", "artifact_role", "artifact_id",
                           "sha256", "size_bytes"}
                or value.get("schema") != 1 or value.get("handle") != handle
                or value.get("setup_session_id") != setup_authorization.setup_session_id
                or value.get("transaction_handle") != setup_authorization.transaction_handle
                or value.get("target_id") != setup_authorization.target_id
                or value.get("plan_digest") != setup_authorization.plan_digest
                or value.get("operator_uid") != setup_authorization.operator_uid
                or value.get("artifact_id") != artifact_id or value.get("sha256") != digest
                or value.get("size_bytes") != resolved.size_bytes
                or not isinstance(value.get("receipt_id"), str) or not value["receipt_id"]):
            raise BootstrapEnrollmentError("root setup receipt does not match its CAS object")
        return VerifiedArtifactReceipt(value["receipt_id"], artifact_id, digest,
                                       resolved.path, spec.max_bytes)

    def _read_receipt(self, handle: str) -> Mapping[str, Any]:
        path = self._receipt_registry.root / f"{handle}.json"
        raw = _read_secure_root_bytes(path, 16 * 1024, 0o600)
        value = self.resolver._json(raw, "root artifact receipt")
        if not isinstance(value, dict) or value.get("handle") != handle:
            raise BootstrapEnrollmentError("root artifact receipt record is malformed")
        return value


class RootBootstrapSession:
    """Live root session facade; close always releases its PIDFD."""

    def __init__(self, factory: RootBootstrapRuntimeFactory, handle: RootSetupSessionHandle,
                 authorization: VerifiedRootSetupAuthorization, policy: VerifiedRootBootstrapPolicy,
                 identity: SystemIdentityAdapter, transaction: RootBootstrapEnrollment, *, seal: str):
        self._factory = factory
        self._handle = handle
        self._authorization = authorization
        self._policy = policy
        self._identity = identity
        self._transaction = transaction
        self._seal = seal
        self._runtime_receipts: dict[str, RootRuntimeArtifactReceipt] = {}
        self._last_receipt: EnrollmentReceipt | None = None
        self._closed = False
        self._source_receipt_handle: str | None = None
        self._source_handoff: Any | None = None
        self._source_provisioner = self._make_source_provisioner()
        self._selected_installation = RootSelectedInstallationBinding(self, seal)
        self._client = factory.session_store.bootstrap_client(
            handle, transaction, source_receipt_provider=self._source_receipt)

    @property
    def policy(self) -> VerifiedRootBootstrapPolicy:
        return self._policy

    @property
    def selected_installation(self) -> RootSelectedInstallationBinding:
        self._check_live()
        if self._last_receipt is None or self._last_receipt.state != "prepared":
            raise BootstrapEnrollmentPending("selected installation binding requires committed prepared custody")
        return self._selected_installation

    def provision(self) -> EnrollmentReceipt:
        self._check_live()
        if self._last_receipt is not None:
            raise BootstrapEnrollmentError("root setup preparation has already been published")
        receipt = self._client.provision((), self._authorization.transaction_handle)
        if receipt.state != "prepared" or receipt.enrollment_ids:
            raise BootstrapEnrollmentError("first setup did not publish the required empty prepared generation")
        self._last_receipt = receipt
        self._refresh_authorization()
        return receipt

    def resolve_runtime_receipt(self, role: str, receipt_handle: str,
                                generation: str) -> RootRuntimeArtifactReceipt:
        """Mint a runtime receipt only from a current transaction-scoped CAS handle."""
        self._check_live()
        rule = next((item for item in self._policy.receipt_binding_rules
                     if item["receipt_role"] == role), None)
        if rule is None or rule["required_phase"] != "runnable":
            raise BootstrapEnrollmentError("runtime receipt role is not a reviewed first-setup role")
        if not isinstance(generation, str) or generation != self._authorization.transaction_handle:
            raise BootstrapEnrollmentError("runtime receipt generation is not bound to this setup transaction")
        artifact_id, digest = self._factory._receipt_registry.lookup(receipt_handle, self._authorization)
        if artifact_id not in rule["allowed_artifact_ids"]:
            raise BootstrapEnrollmentError("runtime receipt artifact is outside its exact selected role")
        resolved = self._factory._catalog.resolve(artifact_id, digest,
                                                  self._factory._receipt_registry.artifact_root, expected_uid=0)
        receipt = RootRuntimeArtifactReceipt(role, artifact_id, digest, generation, receipt_handle,
                                             resolved.size_bytes, self._factory._seal)
        self._runtime_receipts[role] = receipt
        return receipt

    def activate_runnable(self, receipts: Mapping[str, RootRuntimeArtifactReceipt]) -> EnrollmentReceipt:
        self._check_live()
        self._refresh_authorization()
        if self._last_receipt is None or self._last_receipt.state != "prepared":
            raise BootstrapEnrollmentPending("runnable activation requires the committed prepared transaction")
        if set(receipts) != set(self._runtime_receipts) or any(
                receipts.get(role) is not self._runtime_receipts[role] for role in self._runtime_receipts):
            raise BootstrapEnrollmentError("activation receipts were not minted by this live root setup session")
        policy = self._factory.policy_factory.activate_runnable(
            self._authorization, self._identity.ensure(), receipts, seal=self._factory._seal)
        self._runtime_receipts = dict(receipts)
        # Root policy and record construction remain captured in this trusted
        # transaction. The phase switch occurs only after verified receipts.
        self._transaction.policy_resolver = lambda _request, proof: policy
        self._transaction.record_builder = None
        receipt = self._client.provision(tuple(item.receipt_handle for item in receipts.values()),
                                        self._authorization.transaction_handle)
        if receipt.state != "committed" or not receipt.enrollment_ids:
            raise BootstrapEnrollmentPending("root selected runtime receipts did not create a runnable generation")
        self._last_receipt = receipt
        self._refresh_authorization()
        return receipt

    def _authorize_native_materialization(
            self, *, enrollment_id: str, service_generation: str,
            resource_profile_id: str) -> _BoundNativeSelection:
        self._check_live()
        if self._last_receipt is None or self._last_receipt.state != "prepared":
            raise BootstrapEnrollmentPending("native materialization requires a committed prepared generation")
        if (not isinstance(enrollment_id, str) or not _ID.fullmatch(enrollment_id)
                or not isinstance(service_generation, str)
                or not isinstance(resource_profile_id, str) or not _ID.fullmatch(resource_profile_id)):
            raise BootstrapEnrollmentError("native materialization selection identifiers are malformed")
        if (service_generation != self._last_receipt.generation_id
                or resource_profile_id != self._policy.identity_policy["service_profile_id"]):
            raise BootstrapEnrollmentError("native materialization does not match the current prepared policy")
        matches = [item["record"] for item in self._policy.service_record_templates
                   if item["record"].get("enrollment_id") == enrollment_id]
        if len(matches) != 1:
            raise BootstrapEnrollmentError("native materialization enrollment is not uniquely selected by policy")
        identity = self._identity.ensure()
        source_receipt = self._source_receipt(self._authorization)
        return _BoundNativeSelection(
            enrollment_id=enrollment_id, service_generation=self._last_receipt.generation_id,
            service_profile_id=resource_profile_id,
            protected_enrollment_digest=self._last_receipt.generation_digest,
            service_uid=identity.uid, service_gid=identity.gid,
            home_root_id=self._policy.root_policy["service_home_root_id"],
            data_root_id=self._policy.root_policy["service_data_root_id"],
            source_artifact_id=self._policy.source_artifact_id,
            source_receipt_handle=source_receipt,
            _session_id=self._handle.session_id, _seal=self._seal,
        )

    def _resolve_private_installation_roots(
            self, selection: Any) -> _RootPrivateInstallationRoots:
        self._check_live()
        if (not isinstance(selection, _BoundNativeSelection)
                or selection._session_id != self._handle.session_id
                or not secrets.compare_digest(selection._seal, self._seal)
                or self._last_receipt is None
                or selection.protected_enrollment_digest != self._last_receipt.generation_digest
                or self._last_receipt.state != "prepared"):
            raise BootstrapEnrollmentError("native materialization authorization is stale or belongs to another session")
        if self._source_handoff is None:
            raise BootstrapEnrollmentPending("verified Hermes source tree is not provisioned for this session")
        parent = Path(self._policy.root_policy["service_parent_root"])
        return _RootPrivateInstallationRoots(
            home_root=parent / "home", data_root=parent / "data",
            journal_root=self._factory.session_store.session_root.parent / "native-materialization",
            hermes_source_tree=self._source_handoff.source.tree_path,
        )

    def record_functional_health(self, _active_receipt: EnrollmentReceipt, _health_receipt: Any) -> None:
        self._check_live()
        raise BootstrapEnrollmentPending("functional health requires the root-native health observer receipt consumer")

    def _make_source_provisioner(self) -> Any:
        from ..hermes_source import PinnedHermesSourceProvisioner
        from .bootstrap_enrollment import RootLocalCatalogArtifactFetcher
        fetcher = RootLocalCatalogArtifactFetcher(
            catalog=self._factory._catalog,
            artifact_root=self._factory._receipt_registry.artifact_root,
            session_store=self._factory.session_store, session_handle=self._handle,
        )
        return PinnedHermesSourceProvisioner(
            fetcher=fetcher, catalog=self._factory._catalog,
            artifact_root=self._factory._receipt_registry.artifact_root,
            receipt_registry=self._factory._receipt_registry, expected_uid=0,
        )

    def _source_receipt(self, proof: VerifiedRootSetupAuthorization) -> str:
        self._check_live()
        if proof != self._authorization:
            raise BootstrapEnrollmentError("source request does not match this live root setup authorization")
        if self._source_receipt_handle is None:
            self._source_handoff = self._source_provisioner.provision(proof)
            self._source_receipt_handle = self._source_handoff.receipt_handle
        return self._source_receipt_handle

    def _refresh_authorization(self) -> None:
        live = self._factory.session_store._live(self._handle)
        self._authorization = self._factory.session_store._proof(live)

    def close(self) -> None:
        if self._closed:
            return
        self._factory.session_store.close_session(self._handle)
        self._factory._sessions.pop(self._handle.session_id, None)
        self._closed = True

    def _check_live(self) -> None:
        if self._closed:
            raise BootstrapEnrollmentPending("root setup session is closed")
        self._factory.session_store._live(self._handle)

    def __enter__(self) -> "RootBootstrapSession":
        self._check_live()
        return self

    def __exit__(self, *_exc: Any) -> None:
        self.close()
