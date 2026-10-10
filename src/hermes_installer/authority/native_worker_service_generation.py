"""Root-issued schema-2 service-generation rows for a selected native worker.

This producer accepts only current sealed source choices and recipe handles.
It never accepts row mappings or turns a static recipe into authority.  Until
the selected runtime tree has actual root-owned member receipts, issuance stays
pending rather than emitting incomplete catalogs.
"""
from __future__ import annotations

import hashlib
import json
import re
import secrets
import time
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Mapping

from .bootstrap_enrollment import BootstrapEnrollmentPending
from .native_worker_recipes import (
    NativeWorkerRecipeUnavailable, RootPreparedNativeWorkerRecipe,
    RootSetupNativeWorkerRecipeRegistry,
)

_MAX_TTL = 300.0
_HEX = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)


class NativeServiceGenerationUnavailable(BootstrapEnrollmentPending):
    """Selected worker rows lack exact current source/runtime custody."""


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _freeze_json(value: Any) -> Any:
    if value is None or type(value) in (str, int, float, bool):
        return value
    if isinstance(value, Mapping):
        if any(not isinstance(key, str) for key in value):
            raise NativeServiceGenerationUnavailable("generation row has a non-string JSON key")
        return MappingProxyType({key: _freeze_json(item) for key, item in value.items()})
    if isinstance(value, (tuple, list)):
        return tuple(_freeze_json(item) for item in value)
    raise NativeServiceGenerationUnavailable("generation row contains a non-JSON value")


def _plain(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _plain(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_plain(item) for item in value]
    return value


@dataclass(frozen=True, slots=True, repr=False)
class RootPreparedNativeServiceGeneration:
    """Immutable five-catalog generation payload; no container digest is embedded."""

    schema: int
    receipt_handle: str
    setup_session_id: str
    transaction_handle: str
    plan_sha256: str
    prepared_generation_id: str
    prepared_generation_digest: str
    source_choice_selection_handle: str
    source_choice_signed_record_sha256: str
    worker_recipe_receipt_handle: str
    worker_recipe_sha256: str
    service_generation_id: str
    generation_id: str
    service_records: tuple[Mapping[str, Any], ...]
    process_profile_records: tuple[Mapping[str, Any], ...]
    native_worker_network_records: tuple[Mapping[str, Any], ...]
    active_network_generation_records: tuple[Mapping[str, Any], ...]
    native_worker_runtime_records: tuple[Mapping[str, Any], ...]
    source_member_receipt_handles: tuple[str, ...]
    root_journal_id: str
    root_journal_generation: str
    output_sha256: str
    issued_monotonic: float
    expires_monotonic: float
    _issuer: object = field(repr=False, compare=False)
    _recipe: RootPreparedNativeWorkerRecipe = field(repr=False, compare=False)
    _selection: Any = field(repr=False, compare=False)

    def __repr__(self) -> str:
        return "RootPreparedNativeServiceGeneration(<root-held>)"


class RootPreparedNativeServiceGenerationProducer:
    """Join one signed source recipe to actual generated runtime member rows."""

    def __init__(self, binding: Any, recipe_registry: RootSetupNativeWorkerRecipeRegistry,
                 active_compiler: Any, prepared_enrollment_store: Any):
        from .active_policy_compiler import RootActivePolicyCompilationRegistry
        from .bootstrap_runtime_factory import RootSelectedInstallationBinding
        from .bootstrap_enrollment import RootBootstrapEnrollment
        if (type(binding) is not RootSelectedInstallationBinding
                or type(recipe_registry) is not RootSetupNativeWorkerRecipeRegistry
                or recipe_registry.binding is not binding
                or type(active_compiler) is not RootActivePolicyCompilationRegistry
                or active_compiler.factory is not binding._session._factory
                or type(prepared_enrollment_store) is not RootBootstrapEnrollment
                or prepared_enrollment_store is not binding._session._transaction):
            raise ValueError("native service-generation producer requires exact retained setup authorities")
        self.binding = binding
        self.recipe_registry = recipe_registry
        self.active_compiler = active_compiler
        self.prepared_enrollment_store = prepared_enrollment_store
        self._issuer = object()
        self._issued: dict[str, RootPreparedNativeServiceGeneration] = {}

    @classmethod
    def from_root_setup(cls, current_binding: Any,
                        recipe_registry: RootSetupNativeWorkerRecipeRegistry,
                        active_compiler: Any,
                        prepared_enrollment_store: Any) -> "RootPreparedNativeServiceGenerationProducer":
        return cls(current_binding, recipe_registry, active_compiler,
                   prepared_enrollment_store)

    def build_selected(self, recipe_handles: tuple[str, ...],
                       native_policy_selection: Any) -> RootPreparedNativeServiceGeneration:
        session = self.binding._session
        session._check_live()
        from .native_policy_preparation import RootNativePolicyPreparationSelection
        if type(native_policy_selection) is not RootNativePolicyPreparationSelection:
            raise NativeServiceGenerationUnavailable("a current signed native policy selection is required")
        if (not isinstance(recipe_handles, tuple) or len(recipe_handles) != 1
                or any(not isinstance(handle, str) or not handle for handle in recipe_handles)):
            raise NativeServiceGenerationUnavailable("first native worker generation requires one selected recipe")
        current_handle = getattr(session, "_current_native_policy_selection_handle", None)
        if current_handle != native_policy_selection.selection_handle:
            raise NativeServiceGenerationUnavailable("native policy selection handle is not current")
        current_selection = self.binding.resolve_current_native_policy_selection(current_handle)
        if current_selection is not native_policy_selection:
            raise NativeServiceGenerationUnavailable("native policy selection changed before generation build")
        signed_handles = getattr(current_selection, "selected_worker_recipe_handles", None)
        signed_records = getattr(current_selection, "selected_worker_recipe_records", None)
        signed_digests = getattr(current_selection, "selected_worker_recipe_digests", None)
        if (not isinstance(signed_handles, tuple) or signed_handles != recipe_handles
                or not isinstance(signed_records, tuple) or len(signed_records) != 1
                or not isinstance(signed_digests, tuple) or len(signed_digests) != 1):
            raise NativeServiceGenerationUnavailable(
                "signed native-policy choice lacks the closed selected worker recipe projection")
        recipe = self.recipe_registry.resolve_current_recipe(recipe_handles[0])
        signed_record = signed_records[0]
        if not isinstance(signed_record, Mapping) or _plain(recipe.public_projection()) != _plain(signed_record):
            raise NativeServiceGenerationUnavailable("selected source recipe differs from signed choice bytes")
        if signed_digests[0] != recipe.complete_recipe_sha256:
            raise NativeServiceGenerationUnavailable("signed recipe digest differs from current held source recipe")
        # Current registries retain CAS payloads and hashes, but none issues the
        # required root-owned materialized native-runtime member receipts yet.
        # Those receipts must include file owner/device/inode after extraction;
        # a tar manifest or future output digest is not a substitute.
        raise NativeServiceGenerationUnavailable(
            "selected native output runtime has no current root-owned member receipts for schema-2 generation rows")

    def verify_current(self, generation: RootPreparedNativeServiceGeneration) -> RootPreparedNativeServiceGeneration:
        if (type(generation) is not RootPreparedNativeServiceGeneration
                or generation._issuer is not self._issuer
                or self._issued.get(generation.receipt_handle) is not generation
                or generation.expires_monotonic <= time.monotonic()):
            raise NativeServiceGenerationUnavailable("prepared native generation is foreign, stale, or expired")
        recipe = self.recipe_registry.verify_current(generation._recipe)
        selection = self.binding.resolve_current_native_policy_selection(
            generation.source_choice_selection_handle)
        if (selection is not generation._selection
                or selection.selection_handle != generation.source_choice_selection_handle
                or getattr(selection, "selected_worker_recipe_handles", None)
                   != (recipe.receipt_handle,)
                or recipe.complete_recipe_sha256 != generation.worker_recipe_sha256):
            self._issued.pop(generation.receipt_handle, None)
            raise NativeServiceGenerationUnavailable("prepared generation source selection changed")
        body = {
            "service_generation_id": generation.service_generation_id,
            "generation_id": generation.generation_id,
            "service_records": _plain(generation.service_records),
            "process_profile_records": _plain(generation.process_profile_records),
            "native_worker_network_records": _plain(generation.native_worker_network_records),
            "active_network_generation_records": _plain(generation.active_network_generation_records),
            "native_worker_runtime_records": _plain(generation.native_worker_runtime_records),
            "source_choice_selection_handle": generation.source_choice_selection_handle,
            "source_choice_signed_record_sha256": generation.source_choice_signed_record_sha256,
            "worker_recipe_receipt_handle": generation.worker_recipe_receipt_handle,
            "worker_recipe_sha256": generation.worker_recipe_sha256,
            "source_member_receipt_handles": list(generation.source_member_receipt_handles),
        }
        if _digest(body) != generation.output_sha256:
            self._issued.pop(generation.receipt_handle, None)
            raise NativeServiceGenerationUnavailable("prepared generation projection digest changed")
        return generation


__all__ = ["NativeServiceGenerationUnavailable", "RootPreparedNativeServiceGeneration",
           "RootPreparedNativeServiceGenerationProducer"]
