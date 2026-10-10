"""Production selected-application factory over root-issued workload authority.

The fixture scheduler in :mod:`workloads` remains a test harness. Product
callers receive only a root-selected adapter and may submit bounded canonical
arguments; they cannot supply roots, grants, runners, argv, or account state.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Mapping

from hermes_installer.authority.application_runtime import (
    RootApplicationRunReceipt,
    RootSelectedApplicationRuntime,
    SelectedApplicationUnavailable,
)


def _canonical_arguments(arguments: Mapping[str, Any]) -> bytes:
    if not isinstance(arguments, Mapping) or len(arguments) > 128:
        raise ValueError("selected application arguments must be a bounded object")
    try:
        encoded = json.dumps(dict(arguments), sort_keys=True, separators=(",", ":"),
                             ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError):
        raise ValueError("selected application arguments are not canonical JSON values") from None
    if not 1 <= len(encoded) <= 2 * 1024 * 1024:
        raise ValueError("selected application arguments exceed the request bound")
    return encoded


@dataclass(frozen=True, slots=True)
class SelectedApplicationWorkload:
    """A single root-selected app binding; no host paths cross this object."""
    runtime: RootSelectedApplicationRuntime
    authority: Any

    def invoke(self, invocation_context_handle: str,
               arguments: Mapping[str, Any]) -> RootApplicationRunReceipt:
        canonical = _canonical_arguments(arguments)
        dispatch = getattr(self.authority, "dispatch_selected_application", None)
        if not callable(dispatch):
            raise SelectedApplicationUnavailable("root selected-application authority is unavailable")
        result = dispatch(invocation_context_handle, self.runtime.application_id, canonical)
        if type(result) is not RootApplicationRunReceipt:
            raise SelectedApplicationUnavailable("root did not return a typed selected workload receipt")
        if (result.application_id != self.runtime.application_id
                or result.profile_id != self.runtime.profile_id
                or result.profile_generation != self.runtime.profile_generation
                or result.service_generation_digest != self.runtime.service_generation_digest
                or result.source_receipt_handle != self.runtime.source_generation_receipt_handle
                or result.runtime_receipt_handle != self.runtime.runtime_receipt_handle
                or result.operation_id != self.runtime.operation_id
                or result.request_sha256 != hashlib.sha256(canonical).hexdigest()
                or result.state not in {"complete", "failed", "cancelled", "ambiguous"}):
            raise SelectedApplicationUnavailable("root workload receipt does not bind this request and selection")
        return result


class SelectedApplicationWorkloadFactory:
    """Build selected application handles from root-selected runtime bindings."""

    def __init__(self, *, bindings: Any, authority: Any) -> None:
        if not callable(getattr(bindings, "resolve_selected_application_runtime", None)):
            raise ValueError("workload factory requires root selected-application bindings")
        if not callable(getattr(authority, "dispatch_selected_application", None)):
            raise ValueError("workload factory requires the typed root application dispatch API")
        self.bindings = bindings
        self.authority = authority

    def build(self, application_id: str, profile_id: str) -> SelectedApplicationWorkload:
        """Resolve current receipts and produce the only production workload adapter."""
        runtime = self.bindings.resolve_selected_application_runtime(application_id, profile_id)
        if type(runtime) is not RootSelectedApplicationRuntime:
            raise SelectedApplicationUnavailable("root returned an untyped selected application runtime")
        if runtime.application_id != application_id or runtime.profile_id != profile_id or runtime.enabled is not True:
            raise SelectedApplicationUnavailable("selected application is not enabled for this profile")
        return SelectedApplicationWorkload(runtime, self.authority)
