"""Root-selected production adapter for finite application workloads.

``WorkloadScheduler`` remains the local fixture harness. This factory exposes
no caller-selected workload ID; it passes original bounded native action
arguments through the root-selected application authority. The protected root
mapping chooses a finite installer workload or denies dispatch. This factory
never accepts process roots, commands, runner callbacks, budgets, or account
claims.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Callable

from hermes_installer.authority.application_runtime import (
    RootApplicationRunReceipt,
    SelectedApplicationUnavailable,
)


@dataclass(frozen=True, slots=True)
class SelectedApplicationWorkload:
    """Dispatch original native action arguments through the root router."""
    router: Any

    def invoke(self, invocation_handle: str, canonical_arguments: bytes, *,
               peer_uid: int, peer_pid: int, peer_pidfd: int,
               cancelled: Callable[[], bool]) -> RootApplicationRunReceipt:
        if (not isinstance(canonical_arguments, bytes)
                or not 1 <= len(canonical_arguments) <= 2 * 1024 * 1024):
            raise ValueError("selected action arguments must be bounded canonical JSON bytes")
        dispatch = getattr(self.router, "dispatch_workload", None)
        if not callable(dispatch):
            raise SelectedApplicationUnavailable("root selected-workload router is unavailable")
        receipt = dispatch(
            invocation_handle, canonical_arguments, peer_uid=peer_uid, peer_pid=peer_pid,
            peer_pidfd=peer_pidfd, cancelled=cancelled,
        )
        if (type(receipt) is not RootApplicationRunReceipt
                or receipt.request_sha256 != hashlib.sha256(canonical_arguments).hexdigest()
                or receipt.state not in {"complete", "failed", "cancelled", "ambiguous"}):
            raise SelectedApplicationUnavailable("root result receipt does not bind the selected workload request")
        return receipt


class SelectedApplicationWorkloadFactory:
    """Build a selector-free adapter from the sealed root workload router."""

    def __init__(self, *, router: Any) -> None:
        from hermes_installer.authority.application_runtime import RootSelectedApplicationRuntimeRouter
        if type(router) is not RootSelectedApplicationRuntimeRouter:
            raise ValueError("workload factory requires the concrete root-selected workload router")
        self.router = router

    def build(self) -> SelectedApplicationWorkload:
        return SelectedApplicationWorkload(self.router)
