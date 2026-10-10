"""Root-held source derivation for native PluginActionSchema documents.

These records prove the exact schema bytes derived from the five imported
reviewed schema modules. A finite private CAS write precedes every child
artifact and derivation receipt; those receipts authenticate schema bytes only,
never effects, targets, or permissions.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import stat
import time
from dataclasses import dataclass, field, replace
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping

_BUNDLE_SEAL = object()
_TTL_SECONDS = 300.0
_MAX_JOURNAL_BYTES = 4 * 1024 * 1024
_ID = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")
_MODULE_PINS = (
    ("src/hermes_installer/components/plugin_accounts_schemas.py",
     "7608bddb4206156f179f18dd5418cea7e5807003295017a26acbb4a6c7d9d9c4"),
    ("src/hermes_installer/components/plugin_document_schemas.py",
     "710d2f1877d2e5a40ddbf0e5ce83f2b14243bf1a459183065143a18aa55c2d25"),
    ("src/hermes_installer/components/plugin_finance_schemas.py",
     "e379719b684d85bb467b567ac9f69664db8028688e131e9ba3401c80b277a8a6"),
    ("src/hermes_installer/components/plugin_homelab_schemas.py",
     "c8438dac1ca54dfddbee8d9d3140466e8c075a6a46084edd0385438b82188111"),
    ("src/hermes_installer/components/plugin_local_voice_web_schemas.py",
     "35ed72ffbc516c20d447685481cc4b49850a71c11b892ce085e57bb0e946ee84"),
)
_MODULE_SIZES = {
    "src/hermes_installer/components/plugin_accounts_schemas.py": 6_766,
    "src/hermes_installer/components/plugin_document_schemas.py": 7_281,
    "src/hermes_installer/components/plugin_finance_schemas.py": 8_687,
    "src/hermes_installer/components/plugin_homelab_schemas.py": 8_932,
    "src/hermes_installer/components/plugin_local_voice_web_schemas.py": 10_880,
}


class NativeSchemaDerivationDenied(PermissionError):
    """The current root-held source cannot derive a finite schema set."""


@dataclass(frozen=True, slots=True)
class RootPreparedNativeActionSchemaDefinition:
    native_policy_selection_handle: str
    package_id: str
    native_package_generation: str
    service_profile_id: str
    service_generation: str
    resource_profile_selection_handle: str | None
    selected_action_binding_id: str
    target_selection_handles: tuple[str, ...]
    adapter_id: str
    action_id: str
    schema_id: str
    schema_kind: str
    canonical_schema_sha256: str
    size_bytes: int
    source_module_artifact_id: str
    source_module_path: str
    source_module_sha256: str
    source_module_receipt_handle: str
    source_definition_sha256: str
    catalog_subset_supported: bool
    artifact_receipt_handle: str | None
    derivation_receipt_handle: str | None


@dataclass(frozen=True, slots=True, repr=False)
class RootNativeSchemaArtifactReceipt:
    artifact_receipt_handle: str
    derivation_receipt_handle: str
    artifact_id: str
    schema_id: str
    schema_kind: str
    sha256: str
    size_bytes: int
    native_policy_selection_handle: str
    selection_sha256: str
    setup_session_id: str
    transaction_handle: str
    plan_sha256: str
    prepared_generation_id: str
    package_id: str
    native_package_generation: str
    service_profile_id: str
    service_generation: str
    resource_profile_selection_handle: str | None
    selected_action_binding_id: str
    target_selection_handles: tuple[str, ...]
    adapter_id: str
    action_id: str
    source_receipt_handle: str
    relative_path: str
    device: int
    inode: int
    issued_monotonic: float
    expires_monotonic: float
    _seal: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._seal is not _BUNDLE_SEAL:
            raise TypeError("native schema artifact receipts are issued by the root schema registry")


@dataclass(frozen=True, slots=True, repr=False)
class RootNativeSchemaDerivationReceipt:
    derivation_receipt_handle: str
    artifact_receipt_handle: str
    artifact_id: str
    schema_id: str
    schema_kind: str
    schema_sha256: str
    size_bytes: int
    source_module_artifact_id: str
    source_module_path: str
    source_module_sha256: str
    source_module_receipt_handle: str
    source_definition_sha256: str
    native_policy_selection_handle: str
    selection_sha256: str
    setup_session_id: str
    transaction_handle: str
    plan_sha256: str
    prepared_generation_id: str
    package_id: str
    native_package_generation: str
    service_profile_id: str
    service_generation: str
    resource_profile_selection_handle: str | None
    selected_action_binding_id: str
    target_selection_handles: tuple[str, ...]
    adapter_id: str
    action_id: str
    relative_path: str
    device: int
    inode: int
    _seal: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._seal is not _BUNDLE_SEAL:
            raise TypeError("native schema derivation receipts are issued by the root schema registry")


@dataclass(frozen=True, slots=True, repr=False)
class RootPreparedNativeActionSchemaDefinitions:
    """Non-executable root source derivation, bound to one current selection."""

    definition_handle: str
    native_policy_selection_handle: str
    selection_sha256: str
    package_id: str
    native_package_generation: str
    service_profile_id: str
    service_generation: str
    module_receipt_handles: tuple[str, ...]
    definition_records: tuple[RootPreparedNativeActionSchemaDefinition, ...]
    schema_artifact_receipts: tuple[RootNativeSchemaArtifactReceipt, ...]
    schema_derivation_receipts: tuple[RootNativeSchemaDerivationReceipt, ...]
    native_schema_records: tuple[Mapping[str, Any], ...]
    schema_bytes: tuple[tuple[str, bytes], ...]
    missing_prerequisite_ids: tuple[str, ...]
    definitions_sha256: str
    issued_monotonic: float
    expires_monotonic: float
    _seal: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._seal is not _BUNDLE_SEAL:
            raise TypeError("native action schema definitions are root registry issued")


class RootNativeSchemaDerivationRegistry:
    """Derive actual action schemas from current held schema-module receipts."""

    def __init__(self, selected_installation_binding: Any, root_journal: Path):
        from .bootstrap_runtime_factory import RootSelectedInstallationBinding

        if (type(selected_installation_binding) is not RootSelectedInstallationBinding
                or not isinstance(root_journal, Path) or not root_journal.is_absolute()
                or not callable(getattr(selected_installation_binding,
                                        "resolve_prepared_native_action_schema_module_receipts", None))
                or not callable(getattr(selected_installation_binding,
                                        "resolve_current_native_policy_selection", None))):
            raise ValueError("native schema derivation requires the exact setup binding and held-module getter")
        self._binding = selected_installation_binding
        self._journal = root_journal
        self._bundles: dict[str, RootPreparedNativeActionSchemaDefinitions] = {}
        self._artifact_receipts: dict[str, RootNativeSchemaArtifactReceipt] = {}
        self._derivation_receipts: dict[str, RootNativeSchemaDerivationReceipt] = {}
        self._store = _NativeSchemaContentStore(root_journal)

    @classmethod
    def from_root_setup(cls, selected_installation_binding: Any,
                        root_journal: Path) -> "RootNativeSchemaDerivationRegistry":
        return cls(selected_installation_binding, root_journal)

    def derive_for_selection(self, selection: Any) -> RootPreparedNativeActionSchemaDefinitions:
        from .bootstrap_runtime_factory import RootReleaseModuleReceipt
        from .native_policy_preparation import RootNativePolicyPreparationSelection

        if (type(selection) is not RootNativePolicyPreparationSelection
                or selection.expires_monotonic <= time.monotonic()
                or selection.package_id != "hermes-agent-native-package-v1"
                or not isinstance(selection.native_package_generation, str)
                or len(selection.native_package_generation) != 64):
            raise NativeSchemaDerivationDenied("selected native package identity is absent or expired")
        resolve_selection = getattr(self._binding, "resolve_current_native_policy_selection", None)
        if (not callable(resolve_selection)
                or resolve_selection(selection.selection_handle) is not selection):
            raise NativeSchemaDerivationDenied("native schema selection is not the current retained root choice")
        receipts = self._current_module_receipts()
        if len(receipts) != len(_MODULE_PINS):
            raise NativeSchemaDerivationDenied("held action schema module receipt set is incomplete")
        by_path = {receipt.relative_path: receipt for receipt in receipts}
        if len(by_path) != len(_MODULE_PINS):
            raise NativeSchemaDerivationDenied("held action schema module receipt set is ambiguous")
        for relative_path, expected_sha in _MODULE_PINS:
            receipt = by_path.get(relative_path)
            if (type(receipt) is not RootReleaseModuleReceipt or receipt.sha256 != expected_sha
                    or receipt.size_bytes != _MODULE_SIZES[relative_path]
                    or not isinstance(receipt.artifact_id, str) or not receipt.artifact_id):
                raise NativeSchemaDerivationDenied("held action schema module differs from its reviewed pin")
            raw = receipt.read_current()
            if (not isinstance(raw, bytes) or len(raw) != receipt.size_bytes
                    or hashlib.sha256(raw).hexdigest() != expected_sha):
                raise NativeSchemaDerivationDenied("held action schema module bytes are no longer current")

        expected_pairs = _selected_action_pairs(selection)
        if not expected_pairs:
            raise NativeSchemaDerivationDenied("no reviewed source action bindings were selected")
        definitions = _derive_definitions(selection, by_path, expected_pairs)
        if (not definitions or {(row.adapter_id, row.action_id) for row, _ in definitions}
                != expected_pairs):
            raise NativeSchemaDerivationDenied("selected source action bindings do not resolve to the reviewed schema map")
        documents: dict[str, bytes] = {}
        for row, content in definitions:
            prior = documents.get(row.schema_id)
            if prior is not None and prior != content:
                raise NativeSchemaDerivationDenied("one reviewed schema ID maps to conflicting bytes")
            documents[row.schema_id] = content
        module_handles = tuple(by_path[path].source_receipt_handle for path, _ in _MODULE_PINS)
        retained_definitions: list[RootPreparedNativeActionSchemaDefinition] = []
        artifact_receipts: list[RootNativeSchemaArtifactReceipt] = []
        derivation_receipts: list[RootNativeSchemaDerivationReceipt] = []
        schema_records: list[Mapping[str, Any]] = []
        publishable_bytes: dict[str, bytes] = {}
        missing_values: set[str] = set()
        now = time.monotonic()
        expiry = min(now + _TTL_SECONDS, selection.expires_monotonic)
        for row, content in definitions:
            if not row.catalog_subset_supported:
                missing_values.add(f"native-schema-catalog-subset:{row.schema_id}")
                retained_definitions.append(row)
                continue
            if not _ID.fullmatch(row.schema_id):
                raise NativeSchemaDerivationDenied("reviewed schema ID cannot be used as a finite catalog identity")
            storage = self._store.put(content, row.canonical_schema_sha256)
            artifact_handle = secrets.token_urlsafe(32)
            derivation_handle = secrets.token_urlsafe(32)
            artifact_receipt = RootNativeSchemaArtifactReceipt(
                artifact_handle, derivation_handle, row.schema_id, row.schema_id,
                row.schema_kind, row.canonical_schema_sha256, row.size_bytes,
                selection.selection_handle, selection.selection_sha256,
                selection.setup_session_id, selection.transaction_handle,
                selection.plan_sha256, selection.prepared_generation_id,
                selection.package_id, selection.native_package_generation,
                selection.service_profile_id, selection.service_generation,
                selection.resource_profile_selection_handle,
                f"{row.adapter_id}:action:{row.action_id}",
                tuple(selection.target_selection_handles),
                row.adapter_id, row.action_id, row.source_module_receipt_handle,
                storage.relative_path, storage.device, storage.inode, now, expiry,
                _BUNDLE_SEAL,
            )
            derivation = RootNativeSchemaDerivationReceipt(
                derivation_handle, artifact_handle, row.schema_id, row.schema_id,
                row.schema_kind, row.canonical_schema_sha256, row.size_bytes,
                row.source_module_artifact_id, row.source_module_path,
                row.source_module_sha256, row.source_module_receipt_handle,
                row.source_definition_sha256, selection.selection_handle,
                selection.selection_sha256, selection.setup_session_id,
                selection.transaction_handle, selection.plan_sha256,
                selection.prepared_generation_id, selection.package_id,
                selection.native_package_generation, selection.service_profile_id,
                selection.service_generation, selection.resource_profile_selection_handle,
                f"{row.adapter_id}:action:{row.action_id}",
                tuple(selection.target_selection_handles),
                row.adapter_id, row.action_id,
                storage.relative_path, storage.device, storage.inode, _BUNDLE_SEAL,
            )
            row = replace(row, artifact_receipt_handle=artifact_handle,
                          derivation_receipt_handle=derivation_handle)
            artifact_receipts.append(artifact_receipt)
            derivation_receipts.append(derivation)
            retained_definitions.append(row)
            schema_records.append(MappingProxyType({
                "id": row.schema_id, "artifact_id": row.schema_id,
                "sha256": row.canonical_schema_sha256, "schema_kind": row.schema_kind,
                "native_package_id": selection.package_id,
                "native_package_generation": selection.native_package_generation,
                "adapter_id": row.adapter_id, "action_id": row.action_id,
                "source_receipt_handle": row.source_module_receipt_handle,
                "size_bytes": row.size_bytes,
                "derivation_receipt_handle": derivation_handle,
            }))
            prior = publishable_bytes.get(row.schema_id)
            if prior is not None and prior != content:
                raise NativeSchemaDerivationDenied("published schema ID has conflicting current bytes")
            publishable_bytes[row.schema_id] = content
        missing = tuple(sorted(missing_values))
        body = {
            "selection": selection.selection_sha256,
            "package_id": selection.package_id,
            "native_package_generation": selection.native_package_generation,
            "service_profile_id": selection.service_profile_id,
            "service_generation": selection.service_generation,
            "module_receipt_handles": module_handles,
            "definitions": [_definition_source_payload(row) for row in retained_definitions],
            "schema_artifacts": [_artifact_payload(row) for row in artifact_receipts],
            "schema_derivations": [_derivation_payload(row) for row in derivation_receipts],
            "native_schema_records": [dict(row) for row in schema_records],
            "schema_bytes": [(key, value.decode("utf-8")) for key, value in sorted(publishable_bytes.items())],
            "missing_prerequisite_ids": missing,
        }
        digest = hashlib.sha256(_canonical(body)).hexdigest()
        handle = secrets.token_urlsafe(32)
        now = time.monotonic()
        bundle = RootPreparedNativeActionSchemaDefinitions(
            handle, selection.selection_handle, selection.selection_sha256,
            selection.package_id, selection.native_package_generation,
            selection.service_profile_id, selection.service_generation,
            module_handles, tuple(retained_definitions), tuple(artifact_receipts),
            tuple(derivation_receipts), tuple(schema_records),
            tuple(sorted(publishable_bytes.items())), missing, digest, now,
            min(now + _TTL_SECONDS, selection.expires_monotonic), _BUNDLE_SEAL,
        )
        self._persist(bundle, body)
        self._bundles[handle] = bundle
        for row in artifact_receipts:
            self._artifact_receipts[row.artifact_receipt_handle] = row
        for row in derivation_receipts:
            self._derivation_receipts[row.derivation_receipt_handle] = row
        return bundle

    def resolve_current(self, bundle: RootPreparedNativeActionSchemaDefinitions,
                        selection: Any) -> RootPreparedNativeActionSchemaDefinitions:
        from .native_policy_preparation import RootNativePolicyPreparationSelection

        if (type(bundle) is not RootPreparedNativeActionSchemaDefinitions
                or type(selection) is not RootNativePolicyPreparationSelection
                or self._bundles.get(bundle.definition_handle) is not bundle
                or bundle.expires_monotonic <= time.monotonic()
                or bundle.native_policy_selection_handle != getattr(selection, "selection_handle", None)
                or bundle.selection_sha256 != getattr(selection, "selection_sha256", None)):
            raise NativeSchemaDerivationDenied("native action schema definitions are absent or stale")
        if self._binding.resolve_current_native_policy_selection(selection.selection_handle) is not selection:
            raise NativeSchemaDerivationDenied("native schema policy selection is no longer current")
        from .bootstrap_runtime_factory import RootReleaseModuleReceipt
        receipts = self._current_module_receipts()
        if (len(receipts) != len(_MODULE_PINS)
                or any(type(row) is not RootReleaseModuleReceipt for row in receipts)):
            raise NativeSchemaDerivationDenied("held schema source receipt set changed")
        by_path = {row.relative_path: row for row in receipts}
        if (len(by_path) != len(_MODULE_PINS)
                or tuple(by_path[path].source_receipt_handle for path, _ in _MODULE_PINS)
                   != bundle.module_receipt_handles):
            raise NativeSchemaDerivationDenied("held schema source receipt identity changed")
        for path, expected_sha in _MODULE_PINS:
            source = by_path[path]
            raw = source.read_current()
            if (source.sha256 != expected_sha or source.size_bytes != _MODULE_SIZES[path]
                    or len(raw) != source.size_bytes
                    or hashlib.sha256(raw).hexdigest() != expected_sha):
                raise NativeSchemaDerivationDenied("held schema module bytes changed")
        current_defs = _derive_definitions(selection, by_path, _selected_action_pairs(selection))
        if (tuple(_definition_source_payload(row) for row, _ in current_defs)
                != tuple(_definition_source_payload(row) for row in bundle.definition_records)):
            raise NativeSchemaDerivationDenied("native action schema source derivation changed")
        if sum(row.catalog_subset_supported for row, _ in current_defs) != len(bundle.schema_artifact_receipts):
            raise NativeSchemaDerivationDenied("native schema child receipts do not cover supported source schemas")
        parent_by_handle = {row.source_receipt_handle: row for row in receipts}
        for receipt in bundle.schema_artifact_receipts:
            self._check_artifact_receipt(receipt, selection, parent_by_handle)
        return bundle

    def resolve_current_schema_artifact(
            self, artifact_receipt_handle: str, selection: Any
    ) -> RootNativeSchemaArtifactReceipt:
        receipt = self._artifact_receipts.get(artifact_receipt_handle)
        if (type(receipt) is not RootNativeSchemaArtifactReceipt
                or receipt.expires_monotonic <= time.monotonic()
                or receipt.native_policy_selection_handle != getattr(selection, "selection_handle", None)
                or receipt.selection_sha256 != getattr(selection, "selection_sha256", None)):
            raise NativeSchemaDerivationDenied("native schema artifact receipt is absent or stale")
        current = self._binding.resolve_current_native_policy_selection(selection.selection_handle)
        if current is not selection:
            raise NativeSchemaDerivationDenied("native schema selection is no longer the exact retained object")
        parent = self._current_module_receipts()
        parent_by_handle = {row.source_receipt_handle: row for row in parent}
        return self._check_artifact_receipt(receipt, selection, parent_by_handle)

    def _check_artifact_receipt(self, receipt: RootNativeSchemaArtifactReceipt,
                                selection: Any,
                                parent_by_handle: Mapping[str, Any]
                                ) -> RootNativeSchemaArtifactReceipt:
        source = parent_by_handle.get(receipt.source_receipt_handle)
        if source is None:
            raise NativeSchemaDerivationDenied("native schema parent module receipt is no longer selected")
        raw = self._store.read(receipt.relative_path, receipt.device, receipt.inode,
                               receipt.sha256, receipt.size_bytes)
        derivation = self._derivation_receipts.get(receipt.derivation_receipt_handle)
        if (type(derivation) is not RootNativeSchemaDerivationReceipt
                or derivation.artifact_receipt_handle != receipt.artifact_receipt_handle
                or derivation.artifact_id != receipt.artifact_id
                or derivation.schema_id != receipt.schema_id
                or derivation.schema_kind != receipt.schema_kind
                or derivation.size_bytes != receipt.size_bytes
                or derivation.source_module_receipt_handle != source.source_receipt_handle
                or derivation.source_module_artifact_id != source.artifact_id
                or derivation.source_module_path != source.relative_path
                or derivation.source_module_sha256 != source.sha256
                or derivation.native_policy_selection_handle != selection.selection_handle
                or derivation.selection_sha256 != selection.selection_sha256
                or derivation.setup_session_id != selection.setup_session_id
                or derivation.transaction_handle != selection.transaction_handle
                or derivation.plan_sha256 != selection.plan_sha256
                or derivation.prepared_generation_id != selection.prepared_generation_id
                or derivation.package_id != selection.package_id
                or derivation.native_package_generation != selection.native_package_generation
                or derivation.service_profile_id != selection.service_profile_id
                or derivation.service_generation != selection.service_generation
                or derivation.resource_profile_selection_handle != selection.resource_profile_selection_handle
                or derivation.target_selection_handles != tuple(selection.target_selection_handles)
                or derivation.selected_action_binding_id != f"{receipt.adapter_id}:action:{receipt.action_id}"
                or receipt.setup_session_id != selection.setup_session_id
                or receipt.transaction_handle != selection.transaction_handle
                or receipt.plan_sha256 != selection.plan_sha256
                or receipt.prepared_generation_id != selection.prepared_generation_id
                or receipt.service_profile_id != selection.service_profile_id
                or receipt.service_generation != selection.service_generation
                or receipt.resource_profile_selection_handle != selection.resource_profile_selection_handle
                or receipt.target_selection_handles != tuple(selection.target_selection_handles)
                or receipt.selected_action_binding_id != f"{receipt.adapter_id}:action:{receipt.action_id}"
                or derivation.adapter_id != receipt.adapter_id
                or derivation.action_id != receipt.action_id
                or derivation.relative_path != receipt.relative_path
                or derivation.device != receipt.device or derivation.inode != receipt.inode
                or hashlib.sha256(raw).hexdigest() != derivation.schema_sha256):
            raise NativeSchemaDerivationDenied("native schema child derivation no longer matches its source")
        source_bytes = source.read_current()
        if (not isinstance(source_bytes, bytes) or len(source_bytes) != source.size_bytes
                or hashlib.sha256(source_bytes).hexdigest() != source.sha256):
            raise NativeSchemaDerivationDenied("native schema parent module could not be re-read")
        return receipt

    def read_current_schema_bytes(self, artifact_receipt_handle: str,
                                  selection: Any) -> bytes:
        receipt = self.resolve_current_schema_artifact(artifact_receipt_handle, selection)
        return self._store.read(receipt.relative_path, receipt.device, receipt.inode,
                                receipt.sha256, receipt.size_bytes)

    def _current_module_receipts(self) -> tuple[Any, ...]:
        try:
            rows = self._binding.resolve_prepared_native_action_schema_module_receipts()
        except Exception:
            raise NativeSchemaDerivationDenied("current imported action schema module receipts are unavailable") from None
        if not isinstance(rows, tuple):
            raise NativeSchemaDerivationDenied("held action schema module getter returned malformed records")
        return rows

    def _persist(self, bundle: RootPreparedNativeActionSchemaDefinitions,
                 body: Mapping[str, Any]) -> None:
        if os.geteuid() != 0:
            return
        root = self._journal / "native-schema-definitions"
        self._store._ensure_private_directory(root)
        raw = _canonical({"schema": 1, "definition_handle": bundle.definition_handle,
                          "definitions_sha256": bundle.definitions_sha256, "body": dict(body)})
        if len(raw) > _MAX_JOURNAL_BYTES:
            raise NativeSchemaDerivationDenied("native schema derivation exceeds its journal bound")
        path = root / f"definitions-{bundle.definition_handle}.json"
        temporary = root / f".definitions-{bundle.definition_handle}.{secrets.token_hex(12)}.tmp"
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                     | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            os.link(temporary, path, follow_symlinks=False)
            temporary.unlink()
            directory_fd = os.open(root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except BaseException:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
            raise


@dataclass(frozen=True, slots=True)
class _StoredSchemaContent:
    relative_path: str
    device: int
    inode: int


class _NativeSchemaContentStore:
    """Finite nofollow immutable CAS for canonical child schema bytes."""

    def __init__(self, root_journal: Path):
        self._root = root_journal / "native-action-schema-cas"

    def put(self, content: bytes, expected_sha256: str) -> _StoredSchemaContent:
        if (not isinstance(content, bytes) or not 1 <= len(content) <= 262_144
                or not re.fullmatch(r"[a-f0-9]{64}", expected_sha256)
                or hashlib.sha256(content).hexdigest() != expected_sha256):
            raise NativeSchemaDerivationDenied("child schema bytes exceed bounds or fail their digest")
        self._ensure_private_directory(self._root)
        objects = self._root / "objects"
        self._ensure_private_directory(objects)
        relative = f"objects/{expected_sha256[:2]}/{expected_sha256}"
        shard = objects / expected_sha256[:2]
        self._ensure_private_directory(shard)
        destination = shard / expected_sha256
        try:
            existing = self._read_path(destination, expected_sha256, len(content), None, None)
            if existing != content:
                raise NativeSchemaDerivationDenied("immutable child schema CAS digest collision")
            info = destination.lstat()
            return _StoredSchemaContent(relative, info.st_dev, info.st_ino)
        except FileNotFoundError:
            pass

        temporary = shard / f".{expected_sha256}.{secrets.token_hex(12)}.tmp"
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                     | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            try:
                os.link(temporary, destination, follow_symlinks=False)
            except FileExistsError:
                current = self._read_path(destination, expected_sha256, len(content), None, None)
                if current != content:
                    raise NativeSchemaDerivationDenied("immutable child schema CAS object was replaced")
            temporary.unlink()
            directory_fd = os.open(shard, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                                   | getattr(os, "O_NOFOLLOW", 0))
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except BaseException:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
            raise
        info = destination.lstat()
        self._verify_info(info, expected_sha256, len(content), None, None)
        return _StoredSchemaContent(relative, info.st_dev, info.st_ino)

    def read(self, relative_path: str, device: int, inode: int,
             expected_sha256: str, size_bytes: int) -> bytes:
        if (not isinstance(relative_path, str)
                or not re.fullmatch(r"objects/[a-f0-9]{2}/[a-f0-9]{64}", relative_path)
                or relative_path.rsplit("/", 1)[-1] != expected_sha256):
            raise NativeSchemaDerivationDenied("child schema CAS locator is malformed")
        path = self._root.joinpath(*relative_path.split("/"))
        return self._read_path(path, expected_sha256, size_bytes, device, inode)

    def _read_path(self, path: Path, expected_sha256: str, size_bytes: int,
                   device: int | None, inode: int | None) -> bytes:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            info = os.fstat(fd)
            self._verify_info(info, expected_sha256, size_bytes, device, inode)
            with os.fdopen(fd, "rb") as stream:
                fd = -1
                data = stream.read(size_bytes + 1)
        finally:
            if fd >= 0:
                os.close(fd)
        if len(data) != size_bytes or hashlib.sha256(data).hexdigest() != expected_sha256:
            raise NativeSchemaDerivationDenied("current child schema CAS bytes differ from the receipt")
        return data

    @staticmethod
    def _verify_info(info: os.stat_result, expected_sha256: str, size_bytes: int,
                     device: int | None, inode: int | None) -> None:
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size != size_bytes
                or (device is not None and info.st_dev != device)
                or (inode is not None and info.st_ino != inode)):
            raise NativeSchemaDerivationDenied("child schema CAS object identity or permissions changed")

    @staticmethod
    def _ensure_private_directory(path: Path) -> None:
        try:
            path.mkdir(mode=0o700)
        except FileExistsError:
            pass
        else:
            parent_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                                | getattr(os, "O_NOFOLLOW", 0))
            try:
                os.fsync(parent_fd)
            finally:
                os.close(parent_fd)
        info = path.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o700):
            raise NativeSchemaDerivationDenied("child schema CAS directory is not private and owned")
        directory_fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                               | getattr(os, "O_NOFOLLOW", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)


def _derive_definitions(selection: Any, receipts: Mapping[str, Any],
                        selected_pairs: frozenset[tuple[str, str]]) -> list[tuple[RootPreparedNativeActionSchemaDefinition, bytes]]:
    from hermes_installer.components import plugin_accounts_schemas as accounts
    from hermes_installer.components import plugin_document_schemas as documents
    from hermes_installer.components import plugin_finance_schemas as finance
    from hermes_installer.components import plugin_homelab_schemas as homelab
    from hermes_installer.components import plugin_local_voice_web_schemas as local_voice
    from hermes_installer.authority.artifacts import _valid_native_schema_bytes
    from hermes_installer.components.plugin_effects import PluginActionSchema

    # Run the production catalog's adapter-source, manifest, and completeness
    # checks before turning imported definitions into retained source facts.
    from hermes_installer.components.plugin_effects import component_plugin_action_schema_registry
    checked_catalog = component_plugin_action_schema_registry()

    module_maps = (
        (_MODULE_PINS[0], accounts.PLUGIN_ACTION_SCHEMAS),
        (_MODULE_PINS[1], documents.PLUGIN_ACTION_SCHEMAS),
        (_MODULE_PINS[2], finance.PLUGIN_ACTION_SCHEMAS),
        (_MODULE_PINS[3], homelab.PLUGIN_ACTION_SCHEMAS),
        (_MODULE_PINS[4], local_voice.PLUGIN_ACTION_SCHEMAS),
    )
    result: list[tuple[RootPreparedNativeActionSchemaDefinition, bytes]] = []
    keys: set[tuple[str, str]] = set()
    for (relative_path, module_sha), schemas in module_maps:
        receipt = receipts[relative_path]
        for key, schema in sorted(schemas.items()):
            if key not in selected_pairs:
                continue
            if (not isinstance(key, tuple) or len(key) != 2
                    or type(schema) is not PluginActionSchema
                    or key != (schema.adapter_id, schema.action_id)
                    or schema.adapter_id != key[0] or schema.action_id != key[1]
                    or schema.adapter_sha256 == "" or key in keys
                    or checked_catalog.resolve(schema.adapter_id, schema.action_id,
                                               schema.argument_schema_id) != schema):
                raise NativeSchemaDerivationDenied("reviewed action schema source map is malformed or duplicated")
            keys.add(key)
            for schema_id, kind, value in (
                    (schema.argument_schema_id, "arguments", schema.argument_schema),
                    (schema.result_schema_id, "result", schema.result_schema)):
                document = _plain(value)
                content = _canonical(document)
                if not isinstance(schema_id, str) or not schema_id or len(content) > 262_144:
                    raise NativeSchemaDerivationDenied("reviewed action schema ID or size is invalid")
                row = RootPreparedNativeActionSchemaDefinition(
                    selection.selection_handle, selection.package_id,
                    selection.native_package_generation, selection.service_profile_id,
                    selection.service_generation, selection.resource_profile_selection_handle,
                    f"{schema.adapter_id}:action:{schema.action_id}",
                    tuple(selection.target_selection_handles), schema.adapter_id, schema.action_id,
                    schema_id, kind, hashlib.sha256(content).hexdigest(), len(content),
                    receipt.artifact_id, relative_path, module_sha,
                    receipt.source_receipt_handle, module_sha,
                    bool(_valid_native_schema_bytes(content)),
                    None, None,
                )
                result.append((row, content))
    # Keep separately defined local-voice variants. They reuse action IDs with
    # distinct argument schema IDs and are a real part of the reviewed catalog.
    variants = getattr(local_voice, "PLUGIN_ACTION_SCHEMA_VARIANTS", {})
    for key, schema in sorted(variants.items()):
        if key[:2] not in selected_pairs:
            continue
        if (not isinstance(key, tuple) or len(key) != 3
                or type(schema) is not PluginActionSchema
                or key != (schema.adapter_id, schema.action_id, schema.argument_schema_id)
                or schema.adapter_sha256 == ""
                or checked_catalog.resolve(schema.adapter_id, schema.action_id,
                                           schema.argument_schema_id) != schema):
            raise NativeSchemaDerivationDenied("reviewed action schema variant is malformed")
        receipt = receipts[_MODULE_PINS[4][0]]
        for schema_id, kind, value in (
                (schema.argument_schema_id, "arguments", schema.argument_schema),
                (schema.result_schema_id, "result", schema.result_schema)):
            content = _canonical(_plain(value))
            row = RootPreparedNativeActionSchemaDefinition(
                selection.selection_handle, selection.package_id,
                selection.native_package_generation, selection.service_profile_id,
                selection.service_generation, selection.resource_profile_selection_handle,
                f"{schema.adapter_id}:action:{schema.action_id}",
                tuple(selection.target_selection_handles), schema.adapter_id, schema.action_id,
                schema_id, kind, hashlib.sha256(content).hexdigest(), len(content),
                receipt.artifact_id, _MODULE_PINS[4][0], _MODULE_PINS[4][1],
                receipt.source_receipt_handle, _MODULE_PINS[4][1],
                bool(_valid_native_schema_bytes(content)),
                None, None,
            )
            result.append((row, content))
    unique: dict[tuple[str, str, str, str], tuple[RootPreparedNativeActionSchemaDefinition, bytes]] = {}
    for row, content in result:
        key = (row.schema_id, row.schema_kind, row.adapter_id, row.action_id)
        prior = unique.get(key)
        if prior is not None and prior[1] != content:
            raise NativeSchemaDerivationDenied("selected source schema key maps to conflicting bytes")
        unique[key] = (row, content)
    return [unique[key] for key in sorted(unique)]


def _selected_action_pairs(selection: Any) -> frozenset[tuple[str, str]]:
    values = getattr(selection, "selected_action_binding_ids", None)
    if not isinstance(values, tuple) or not values:
        return frozenset()
    pairs: set[tuple[str, str]] = set()
    for binding_id in values:
        if not isinstance(binding_id, str) or binding_id.count(":action:") != 1:
            raise NativeSchemaDerivationDenied("selected action binding is not the exact reviewed adapter/action key")
        adapter_id, action_id = binding_id.split(":action:", 1)
        if (not adapter_id or not action_id or ":" in action_id
                or not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", adapter_id)
                or not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", action_id)):
            raise NativeSchemaDerivationDenied("selected action binding identity is malformed")
        pair = (adapter_id, action_id)
        if pair in pairs:
            raise NativeSchemaDerivationDenied("selected action binding is duplicated")
        pairs.add(pair)
    return frozenset(pairs)


def _plain(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _plain(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_plain(item) for item in value]
    if value is None or type(value) in {str, int, bool, float}:
        return value
    raise NativeSchemaDerivationDenied("action schema contains a non-JSON value")


def _definition_payload(row: RootPreparedNativeActionSchemaDefinition) -> dict[str, Any]:
    return {name: getattr(row, name) for name in row.__dataclass_fields__}


def _definition_source_payload(row: RootPreparedNativeActionSchemaDefinition) -> dict[str, Any]:
    return {name: getattr(row, name) for name in row.__dataclass_fields__
            if name not in {"artifact_receipt_handle", "derivation_receipt_handle"}}


def _artifact_payload(row: RootNativeSchemaArtifactReceipt) -> dict[str, Any]:
    return {name: getattr(row, name) for name in row.__dataclass_fields__
            if name != "_seal"}


def _derivation_payload(row: RootNativeSchemaDerivationReceipt) -> dict[str, Any]:
    return {name: getattr(row, name) for name in row.__dataclass_fields__
            if name != "_seal"}


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError):
        raise NativeSchemaDerivationDenied("native schema derivation is not canonical JSON") from None


__all__ = ["NativeSchemaDerivationDenied", "RootPreparedNativeActionSchemaDefinition",
           "RootPreparedNativeActionSchemaDefinitions", "RootNativeSchemaArtifactReceipt",
           "RootNativeSchemaDerivationReceipt", "RootNativeSchemaDerivationRegistry"]
