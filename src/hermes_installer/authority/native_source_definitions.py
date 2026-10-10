"""Finite source-role declarations for the pinned native invocation boundary.

These declarations describe reviewed call sites; they do not mint active role,
observer, package, or process evidence. A definition becomes usable only after
the selected installed release supplies exact held receipts for the definition
module and both role modules, and the remaining selected schema/action joins
are available.
"""
from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from typing import Any


class NativeSourceDefinitionUnavailable(PermissionError):
    """The source-role declaration lacks current held-release evidence."""


_REGISTRY_SEAL = object()


@dataclass(frozen=True, slots=True)
class NativeSourceRoleDeclaration:
    role_id: str
    module_name: str
    closure_member_path: str
    module_sha256: str
    call_sites: tuple[str, ...]
    source_kinds: tuple[str, ...]
    capture_schema_ids: tuple[str, ...]
    source_action_ids: tuple[str, ...]


# These are code facts from the pinned installer hooks. The action and capture
# schema identifiers remain empty until their reviewed receipts are selected;
# the implementation must never synthesize those joins from tool names.
_ROLE_DECLARATIONS = (
    NativeSourceRoleDeclaration(
        role_id="hermes-native-invocations-v1",
        module_name="hermes_installer.native_invocations",
        closure_member_path="hermes_installer/native_invocations.py",
        module_sha256="78a3452289df5b7343e5c650ea8620d51b3aa1056e2eedea02cc3a0bff7b8226",
        call_sites=(
            "read_selected_native_input",
            "prepare_native_provider_request",
            "dispatch_native_mcp_tool_call",
            "record_native_tool_result",
            "finish_selected_native_turn",
        ),
        source_kinds=("native-input", "tool-result"),
        capture_schema_ids=(),
        source_action_ids=(),
    ),
    NativeSourceRoleDeclaration(
        role_id="hermes-native-boundary-v1",
        module_name="hermes_installer.native_boundary",
        closure_member_path="hermes_installer/native_boundary.py",
        module_sha256="ac18137d35fee29db635eb4f91327c3d02d5b5a563353acf60ad020085043cdb",
        call_sites=("prepare_provider_request", "capture_provider_response"),
        source_kinds=("tool-result",),
        capture_schema_ids=(),
        source_action_ids=(),
    ),
)


@dataclass(frozen=True, slots=True, repr=False)
class RootPreparedSourceDefinitionBundle:
    selection_handle: str
    selection_sha256: str
    definition_source_receipt: Any = field(repr=False, compare=False)
    role_module_receipts: tuple[Any, ...] = field(repr=False, compare=False)
    declarations: tuple[NativeSourceRoleDeclaration, ...]
    missing_prerequisite_ids: tuple[str, ...]
    issued_monotonic: float
    expires_monotonic: float
    _registry_token: object = field(repr=False, compare=False)


class RootNativeSourceDefinitionRegistry:
    """Reads only exact current module receipts from a selected installation.

    ``receipt_resolver`` is a root assembly dependency. It must resolve a
    previously held RootReleaseModuleReceipt by artifact ID; arbitrary paths,
    bytes, and caller-created receipt-shaped objects are rejected.
    """

    def __init__(self, installation_binding: Any, receipt_provider: Any,
                 *, monotonic=time.monotonic, _seal: object | None = None):
        if (installation_binding is None or not callable(receipt_provider)
                or not callable(monotonic) or _seal is not _REGISTRY_SEAL):
            raise TypeError("root source definition registry dependencies are invalid")
        self._binding = installation_binding
        self._receipt_provider = receipt_provider
        self._monotonic = monotonic
        self._token = object()
        self._bundles: dict[str, RootPreparedSourceDefinitionBundle] = {}

    @classmethod
    def from_selected_installation(cls, binding: Any, *, monotonic=time.monotonic):
        from hermes_installer.authority.bootstrap_runtime_factory import RootSelectedInstallationBinding

        provider = getattr(binding, "resolve_prepared_release_module_receipts", None)
        if type(binding) is not RootSelectedInstallationBinding or not callable(provider):
            raise NativeSourceDefinitionUnavailable("selected installation cannot resolve held release receipts")
        # Calling the exact guarded resolver here proves that this binding is
        # still attached to its live selected setup session.
        provider()
        return cls(binding, provider, monotonic=monotonic, _seal=_REGISTRY_SEAL)

    def prepare_for_policy(self, selection: Any) -> RootPreparedSourceDefinitionBundle:
        from hermes_installer.authority.bootstrap_runtime_factory import RootReleaseModuleReceipt
        selection_handle = getattr(selection, "selection_handle", None)
        selection_digest = getattr(selection, "selection_sha256", None)
        if (not isinstance(selection_handle, str) or not selection_handle
                or not isinstance(selection_digest, str) or len(selection_digest) != 64
                or getattr(selection, "package_id", None) is None):
            raise NativeSourceDefinitionUnavailable("native policy selection is malformed")

        try:
            receipts = self._receipt_provider()
        except Exception:
            receipts = ()
        if not isinstance(receipts, tuple) or any(type(item) is not RootReleaseModuleReceipt for item in receipts):
            raise NativeSourceDefinitionUnavailable("release resolver returned non-held module evidence")
        by_path = {item.relative_path: item for item in receipts}
        missing: list[str] = []
        definition_receipt = by_path.get("hermes_installer/authority/native_source_definitions.py")
        if definition_receipt is None:
            missing.append("hermes-installer.native-source-definitions.v1")
        elif not self._check_receipt(definition_receipt, "hermes_installer/authority/native_source_definitions.py"):
            raise NativeSourceDefinitionUnavailable("source definition module receipt is stale or mismatched")
        role_receipts = []
        for declaration in _ROLE_DECLARATIONS:
            receipt = by_path.get(declaration.closure_member_path)
            if receipt is None:
                missing.append(declaration.module_name)
                continue
            if not self._check_receipt(receipt, declaration.closure_member_path,
                                       declaration.module_sha256):
                raise NativeSourceDefinitionUnavailable("native source role module differs from reviewed bytes")
            role_receipts.append(receipt)
        # The source files deliberately do not assign action or schema IDs.
        # Exact selected action/schema receipts are a separate preparation join.
        if any(not row.capture_schema_ids or not row.source_action_ids
               for row in _ROLE_DECLARATIONS):
            missing.extend(("selected-source-capture-schema", "selected-source-action-binding"))
        now = self._monotonic()
        bundle = RootPreparedSourceDefinitionBundle(
            selection_handle, selection_digest, definition_receipt,
            tuple(role_receipts), _ROLE_DECLARATIONS, tuple(dict.fromkeys(missing)),
            now, min(now + 30.0, getattr(selection, "expires_monotonic", now)), self._token,
        )
        if bundle.expires_monotonic <= now:
            raise NativeSourceDefinitionUnavailable("native source-definition selection expired")
        self._bundles[selection_handle] = bundle
        return bundle

    def resolve_current(self, bundle: RootPreparedSourceDefinitionBundle) -> RootPreparedSourceDefinitionBundle:
        if (type(bundle) is not RootPreparedSourceDefinitionBundle
                or bundle._registry_token is not self._token
                or self._bundles.get(bundle.selection_handle) is not bundle
                or bundle.expires_monotonic <= self._monotonic()):
            raise NativeSourceDefinitionUnavailable("prepared source-definition bundle is stale")
        for receipt in ((bundle.definition_source_receipt,) + bundle.role_module_receipts):
            if receipt is None:
                continue
            receipt.read_current()
        return bundle

    @staticmethod
    def _check_receipt(receipt: Any, path: str, expected_digest: str | None = None) -> bool:
        raw = receipt.read_current()
        digest = hashlib.sha256(raw).hexdigest()
        return (receipt.relative_path == path and receipt.sha256 == digest
                and receipt.size_bytes == len(raw)
                and (expected_digest is None or digest == expected_digest))


__all__ = [
    "NativeSourceDefinitionUnavailable", "NativeSourceRoleDeclaration",
    "RootPreparedSourceDefinitionBundle", "RootNativeSourceDefinitionRegistry",
]
