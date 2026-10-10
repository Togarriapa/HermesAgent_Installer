"""Peer-bound native package binding and immutable selected-effect metadata.

This module is the worker-side half of HI08/HI09/RB08's root-owned native
package catalog.  It accepts only the fixed authority DTOs documented in
``planning/native-package-binding-contract.json``.  Resolver rows describe
what can be discovered and registered; they are never effect authorization.
The root must re-resolve current package, schema, identity, source closure and
one-use authorization at every effect boundary.

The API is deliberately unavailable until the protected root AuthorityClient
and host process enrollment implement ``bind_selected_native_package`` and
``read_native_resolver``.  In particular, caller-controlled profile paths,
environment variables, resource YAML, plugin files, and generic
``capture_source`` are not substitutes for these methods.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import hashlib
import json
import math
import re
import time
from typing import Protocol


_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}\Z", re.ASCII)
_OPAQUE = re.compile(r"[A-Za-z0-9_-]{32,128}\Z", re.ASCII)
_SHA256 = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_OPERATION = re.compile(r"plugin\.([A-Za-z0-9][A-Za-z0-9_.-]{0,127})\.([a-z][A-Za-z0-9_.-]{0,95})\Z", re.ASCII)
_MAX_ADAPTERS = 692
_MAX_RESOLVER_BYTES = 2 * 1024 * 1024
_MAX_PROCESS_ROLE_RECORDS = 256
_MAX_BINDING_LEASE_SECONDS = 600.0


class NativePluginBindingUnavailable(PermissionError):
    """Root-selected native package binding or resolver is unavailable."""


@dataclass(frozen=True, slots=True)
class NativePackageBinding:
    """Short-lived peer-bound lookup handle returned by root authority."""

    opaque_binding_handle: str
    package_id: str
    profile_id: str
    generation: str
    compiled_closure_sha256: str
    entrypoint_sha256: str
    resolver_digest: str
    expires_monotonic: float


@dataclass(frozen=True, slots=True)
class SelectedPluginEffect:
    """Exact immutable resolver row; presentation metadata, never a grant."""

    adapter_id: str
    manifest_sha256: str
    adapter_sha256: str
    action_id: str
    argument_schema_id: str
    result_schema_id: str
    effect_enrollment_id: str
    operation: str
    capability: str
    target_id: str
    recipient: str | None
    generation: str


class SelectedPluginEffectsResolver(Protocol):
    """Immutable selected adapter/action view consumed by plugin facades."""

    @property
    def package_id(self) -> str: ...

    @property
    def profile_id(self) -> str: ...

    @property
    def generation(self) -> str: ...

    def resolve(self, adapter_id: str, action_id: str) -> SelectedPluginEffect | None: ...


class NativePackageAuthority(Protocol):
    """The protected AuthorityClient methods required by the binder contract."""

    def bind_selected_native_package(self) -> object: ...

    def read_native_resolver(self, binding_handle: str) -> object: ...


def _valid_id(value: object, label: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise NativePluginBindingUnavailable(f"root returned invalid {label}")
    return value


def _binding_from_wire(raw: object, *, now: float) -> NativePackageBinding:
    if not isinstance(raw, Mapping) or set(raw) != {
        "schema", "opaque_binding_handle", "package_id", "profile_id", "generation",
        "resolver_digest", "compiled_closure_sha256", "entrypoint_sha256", "expires_monotonic",
    }:
        raise NativePluginBindingUnavailable("root returned an invalid native package binding")
    if type(raw["schema"]) is not int or raw["schema"] != 1:
        raise NativePluginBindingUnavailable("root returned an unsupported native package binding")
    returned_package = _valid_id(raw["package_id"], "package identity")
    returned_profile = _valid_id(raw["profile_id"], "profile identity")
    returned_generation = _valid_id(raw["generation"], "package generation")
    handle = raw["opaque_binding_handle"]
    digest = raw["resolver_digest"]
    closure_digest = raw["compiled_closure_sha256"]
    entrypoint_digest = raw["entrypoint_sha256"]
    expiry = raw["expires_monotonic"]
    if (not isinstance(handle, str) or not _OPAQUE.fullmatch(handle)
            or not isinstance(digest, str) or not _SHA256.fullmatch(digest)
            or not isinstance(closure_digest, str) or not _SHA256.fullmatch(closure_digest)
            or not isinstance(entrypoint_digest, str) or not _SHA256.fullmatch(entrypoint_digest)
            or isinstance(expiry, bool) or not isinstance(expiry, (int, float))
            or not math.isfinite(float(expiry))
            or not now < float(expiry) <= now + _MAX_BINDING_LEASE_SECONDS):
        raise NativePluginBindingUnavailable("root returned an invalid native package lease")
    return NativePackageBinding(handle, returned_package, returned_profile,
                                returned_generation, closure_digest, entrypoint_digest, digest,
                                float(expiry))


def _effect_from_wire(raw: object, *, package_generation: str) -> SelectedPluginEffect:
    fields = {
        "adapter_id", "manifest_sha256", "adapter_sha256", "action_id",
        "argument_schema_id", "result_schema_id", "effect_enrollment_id",
        "operation", "capability", "target_id", "recipient", "generation",
    }
    if not isinstance(raw, Mapping) or set(raw) != fields:
        raise NativePluginBindingUnavailable("root resolver row has missing or extra fields")
    adapter = _valid_id(raw["adapter_id"], "adapter ID")
    action = _valid_id(raw["action_id"], "action ID")
    argument_schema = _valid_id(raw["argument_schema_id"], "argument schema ID")
    result_schema = _valid_id(raw["result_schema_id"], "result schema ID")
    enrollment = _valid_id(raw["effect_enrollment_id"], "effect enrollment ID")
    generation = _valid_id(raw["generation"], "effect generation")
    manifest_digest, adapter_digest = raw["manifest_sha256"], raw["adapter_sha256"]
    operation, capability, target = raw["operation"], raw["capability"], raw["target_id"]
    recipient = raw["recipient"]
    if (not isinstance(manifest_digest, str) or not _SHA256.fullmatch(manifest_digest)
            or not isinstance(adapter_digest, str) or not _SHA256.fullmatch(adapter_digest)
            or not isinstance(operation, str) or not _OPERATION.fullmatch(operation)
            or _OPERATION.fullmatch(operation).group(1) != adapter
            or not isinstance(capability, str) or capability != f"plugin:{adapter}"
            or not isinstance(target, str) or not _ID.fullmatch(target)
            or (recipient is not None and (not isinstance(recipient, str)
                                            or not recipient or len(recipient) > 512
                                            or any(ord(c) < 0x20 for c in recipient)))
            or generation != package_generation):
        raise NativePluginBindingUnavailable("root resolver row conflicts with selected package enrollment")
    return SelectedPluginEffect(
        adapter, manifest_digest, adapter_digest, action, argument_schema,
        result_schema, enrollment, operation, capability, target, recipient, generation,
    )


class RootSelectedPluginEffects:
    """Validated immutable projection from one active root package binding."""

    __slots__ = ("_binding", "_profile_id", "_effects", "_clock",
                 "_process_role_records_sha256", "_process_role_records")

    def __init__(self, authority: NativePackageAuthority, *, clock=time.monotonic) -> None:
        bind = getattr(authority, "bind_selected_native_package", None)
        read = getattr(authority, "read_native_resolver", None)
        if not callable(bind) or not callable(read):
            raise NativePluginBindingUnavailable("root native package binder is not installed")
        try:
            # Root chooses exactly the live package for this authenticated
            # process/profile/generation. No caller-selected package, profile,
            # generation, mount, or file path enters this query.
            raw_binding = bind()
            binding = _binding_from_wire(raw_binding, now=clock())
            raw = read(binding.opaque_binding_handle)
        except NativePluginBindingUnavailable:
            raise
        except Exception:
            # Socket paths, identity details and source data are never surfaced
            # through plugin discovery logs or tool errors.
            raise NativePluginBindingUnavailable("root native package binding is unavailable") from None
        if not isinstance(raw, Mapping) or set(raw) != {
            "schema", "package_id", "profile_id", "generation",
            "resolver_sha256", "process_role_records_sha256", "adapters",
        }:
            raise NativePluginBindingUnavailable("root returned an invalid native package resolver")
        try:
            digest_preimage = {
                key: raw[key] for key in (
                    "schema", "package_id", "profile_id", "generation",
                    "process_role_records_sha256", "adapters",
                )
            }
            canonical_resolver = json.dumps(
                digest_preimage, ensure_ascii=False, sort_keys=True,
                separators=(",", ":"), allow_nan=False,
            ).encode("utf-8")
        except (TypeError, ValueError, UnicodeError):
            raise NativePluginBindingUnavailable("root resolver is not canonical JSON") from None
        if (not canonical_resolver or len(canonical_resolver) > _MAX_RESOLVER_BYTES
                or hashlib.sha256(canonical_resolver).hexdigest() != raw["resolver_sha256"]):
            raise NativePluginBindingUnavailable("root resolver digest or byte bound is invalid")
        process_role_digest = raw["process_role_records_sha256"]
        if (type(raw["schema"]) is not int or raw["schema"] != 1
                or _valid_id(raw["package_id"], "resolver package ID") != binding.package_id
                or _valid_id(raw["generation"], "resolver generation") != binding.generation
                or not isinstance(raw["resolver_sha256"], str)
                or raw["resolver_sha256"] != binding.resolver_digest
                or not _SHA256.fullmatch(raw["resolver_sha256"])
                or not isinstance(process_role_digest, str)
                or not _SHA256.fullmatch(process_role_digest)):
            raise NativePluginBindingUnavailable("root resolver does not match its package binding")
        profile_id = _valid_id(raw["profile_id"], "resolver profile ID")
        if profile_id != binding.profile_id:
            raise NativePluginBindingUnavailable("root package and resolver profile do not match")
        adapters = raw["adapters"]
        if not isinstance(adapters, list) or len(adapters) > _MAX_ADAPTERS:
            raise NativePluginBindingUnavailable("root resolver exceeds its selected adapter bound")
        effects: dict[tuple[str, str], SelectedPluginEffect] = {}
        adapter_digests: dict[str, tuple[str, str]] = {}
        for row in adapters:
            effect = _effect_from_wire(row, package_generation=binding.generation)
            key = (effect.adapter_id, effect.action_id)
            if key in effects:
                raise NativePluginBindingUnavailable("root resolver contains a duplicate adapter action")
            identity = (effect.manifest_sha256, effect.adapter_sha256)
            previous = adapter_digests.setdefault(effect.adapter_id, identity)
            if previous != identity:
                raise NativePluginBindingUnavailable("root resolver splits one adapter across source digests")
            effects[key] = effect
        self._binding = binding
        self._profile_id = profile_id
        self._effects = effects
        self._clock = clock
        self._process_role_records_sha256 = process_role_digest
        self._process_role_records: tuple[Mapping[str, object], ...] = ()

    @property
    def package_id(self) -> str:
        return self._binding.package_id

    @property
    def profile_id(self) -> str:
        return self._profile_id

    @property
    def generation(self) -> str:
        return self._binding.generation

    @property
    def binding_handle(self) -> str:
        """Return the opaque non-bearer binder reference for same-process RPCs."""
        self._require_live()
        return self._binding.opaque_binding_handle

    @property
    def resolver_digest(self) -> str:
        return self._binding.resolver_digest

    @property
    def compiled_closure_sha256(self) -> str:
        """Root-selected closure digest used only to derive its fixed mount."""
        self._require_live()
        return self._binding.compiled_closure_sha256

    @property
    def entrypoint_sha256(self) -> str:
        """Root-pinned native assembly entrypoint manifest digest."""
        self._require_live()
        return self._binding.entrypoint_sha256

    @property
    def process_role_records(self) -> tuple[Mapping[str, object], ...]:
        """Root-pinned role selection from the verified mounted entrypoint manifest.

        This is loader metadata only. Root custody independently joins every
        emitted import origin to the active role record and current process.
        """
        self._require_live()
        return self._process_role_records

    @property
    def process_roles(self) -> tuple[Mapping[str, object], ...]:
        """Loader-facing alias for the verified selected role record tuple."""
        return self.process_role_records

    @property
    def process_role_records_sha256(self) -> str:
        self._require_live()
        return self._process_role_records_sha256

    def _accept_verified_process_role_records(
        self, rows: tuple[Mapping[str, object], ...], digest: str,
    ) -> None:
        """Attach rows only after the pinned manifest and closure were verified."""
        self._require_live()
        if (not isinstance(rows, tuple) or not 1 <= len(rows) <= _MAX_PROCESS_ROLE_RECORDS
                or digest != self._process_role_records_sha256):
            raise NativePluginBindingUnavailable("native process-role selection is unavailable")
        if self._process_role_records:
            if self._process_role_records != rows:
                raise NativePluginBindingUnavailable("native process-role selection changed during its lease")
            return
        self._process_role_records = rows

    @property
    def adapter_rows(self) -> tuple[SelectedPluginEffect, ...]:
        """Immutable presentation rows; effect authority is re-resolved per call."""
        self._require_live()
        return tuple(self._effects.values())

    def resolve(self, adapter_id: str, action_id: str) -> SelectedPluginEffect | None:
        self._require_live()
        if not isinstance(adapter_id, str) or not isinstance(action_id, str):
            return None
        return self._effects.get((adapter_id, action_id))

    def manifest_digest_for_adapter(self, adapter_id: str) -> str | None:
        """Return the protected source-resource digest for one selected adapter."""
        self._require_live()
        if not isinstance(adapter_id, str):
            return None
        digests = {effect.manifest_sha256 for effect in self._effects.values()
                   if effect.adapter_id == adapter_id}
        if len(digests) > 1:
            raise NativePluginBindingUnavailable("root resolver splits an adapter across source manifests")
        return next(iter(digests), None)

    def _require_live(self) -> None:
        if self._clock() >= self._binding.expires_monotonic:
            raise NativePluginBindingUnavailable("root native package binding expired")


def bind_selected_plugin_effects(authority: NativePackageAuthority, *,
                                 clock=time.monotonic) -> RootSelectedPluginEffects:
    """Bind this authenticated process to its sole root-selected package.

    There are no caller selectors. The authority denies zero or ambiguous
    active package selections after joining peer UID/PIDFD/starttime,
    executable/cgroup, profile, and current generation. The returned rows are
    only display/registration metadata, never authority to cause an effect.
    """
    return RootSelectedPluginEffects(authority, clock=clock)
