"""Root-selected production adapter for the finite component workload set.

``WorkloadScheduler`` remains the local fixture harness. This factory exposes
only registered workload IDs and routes their bounded argument objects through
the root-selected application authority; it never accepts process roots,
commands, runner callbacks, budgets, or account claims.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Callable, Mapping

from hermes_installer.authority.application_runtime import (
    RootApplicationRunReceipt,
    SelectedApplicationUnavailable,
)
from hermes_installer.components.workloads import _REGISTERED


def _canonical_request(workload_id: str, arguments: Mapping[str, Any]) -> bytes:
    if (not isinstance(workload_id, str) or workload_id not in _REGISTERED
            or not isinstance(arguments, Mapping) or len(arguments) > 128):
        raise ValueError("workload request must use a finite installer-registered ID and bounded arguments")
    if set(arguments) != _REGISTERED[workload_id].argument_names:
        raise ValueError("workload arguments do not match the fixed registered recipe")
    try:
        encoded = json.dumps(
            {"id": workload_id, "arguments": dict(arguments)},
            sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError):
        raise ValueError("selected workload arguments are not canonical JSON values") from None
    if not 1 <= len(encoded) <= 2 * 1024 * 1024:
        raise ValueError("selected workload request exceeds the protected request bound")
    return encoded


@dataclass(frozen=True, slots=True)
class SelectedApplicationWorkload:
    """One registered workload adapter backed by the exact root router."""
    workload_id: str
    router: Any

    def invoke(self, invocation_handle: str, arguments: Mapping[str, Any], *,
               peer_uid: int, peer_pid: int, peer_pidfd: int,
               cancelled: Callable[[], bool]) -> RootApplicationRunReceipt:
        canonical = _canonical_request(self.workload_id, arguments)
        dispatch = getattr(self.router, "dispatch_workload", None)
        if not callable(dispatch):
            raise SelectedApplicationUnavailable("root selected-workload router is unavailable")
        receipt = dispatch(
            invocation_handle, canonical, peer_uid=peer_uid, peer_pid=peer_pid,
            peer_pidfd=peer_pidfd, cancelled=cancelled,
        )
        if (type(receipt) is not RootApplicationRunReceipt
                or receipt.request_sha256 != hashlib.sha256(canonical).hexdigest()
                or receipt.state not in {"complete", "failed", "cancelled", "ambiguous"}):
            raise SelectedApplicationUnavailable("root result receipt does not bind the selected workload request")
        return receipt


class SelectedApplicationWorkloadFactory:
    """Build selected-only adapters from the sealed root workload router."""

    def __init__(self, *, router: Any) -> None:
        from hermes_installer.authority.application_runtime import RootSelectedApplicationRuntimeRouter
        if type(router) is not RootSelectedApplicationRuntimeRouter:
            raise ValueError("workload factory requires the concrete root-selected workload router")
        self.router = router

    def build(self, workload_id: str) -> SelectedApplicationWorkload:
        if not isinstance(workload_id, str) or workload_id not in _REGISTERED:
            raise SelectedApplicationUnavailable("workload ID is not in the fixed installer-owned workload registry")
        return SelectedApplicationWorkload(workload_id, self.router)
