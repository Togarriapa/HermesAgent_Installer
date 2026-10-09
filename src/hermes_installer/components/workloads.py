"""Bounded, on-demand scheduling for optional component runtimes.

The injected runner must be the installer managed-process supervisor. This
module never creates a subprocess, worker, coordinator, or credential channel.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from decimal import Decimal
from threading import Lock
from typing import Callable, Mapping


@dataclass(frozen=True, slots=True)
class Workload:
    id: str
    argv: tuple[str, ...]
    environment: Mapping[str, str] = field(default_factory=dict)
    capabilities: frozenset[str] = frozenset()
    memory_mb: int = 512
    timeout_seconds: int = 120
    mode: str = "on_demand"
    network_scope: str = "deny"
    metered_cost_usd: Decimal = Decimal("0")
    account_requirement: str | None = None
    credential_references: tuple[str, ...] = ()
    starts_at_boot: bool = False
    replaces_coordinator: bool = False


class WorkloadScheduler:
    """Check capabilities, accounts, resource bounds, and spend before launch."""

    def __init__(
        self,
        run: Callable,
        granted: frozenset[str],
        *,
        memory_budget_mb: int,
        max_workers: int = 1,
        metered_budget_usd: Decimal = Decimal("0"),
        eligible_accounts: frozenset[str] = frozenset(),
    ) -> None:
        if memory_budget_mb <= 0 or max_workers <= 0:
            raise ValueError("scheduler resource limits must be positive")
        if not metered_budget_usd.is_finite() or metered_budget_usd < 0:
            raise ValueError("metered budget must be a finite non-negative amount")
        self.run = run
        self.granted = granted
        self.memory_budget_mb = memory_budget_mb
        self.max_workers = max_workers
        self.metered_budget_usd = metered_budget_usd
        self.eligible_accounts = eligible_accounts
        self._active = 0
        self._metered_spend = Decimal("0")
        self._lock = Lock()

    @property
    def metered_spend_usd(self) -> Decimal:
        with self._lock:
            return self._metered_spend

    def execute(self, work: Workload) -> object:
        if work.mode != "on_demand" or work.starts_at_boot:
            raise PermissionError("component workloads must start only on explicit demand")
        if work.replaces_coordinator:
            raise PermissionError("component workloads cannot replace the Hermes coordinator")
        if not work.id or not work.argv or any(not value or "\x00" in value for value in work.argv):
            raise ValueError("workload requires a fixed, NUL-free argv")
        if work.timeout_seconds <= 0 or work.timeout_seconds > 3600:
            raise TimeoutError("workload timeout is outside the one-hour policy ceiling")
        if work.memory_mb <= 0 or work.memory_mb > self.memory_budget_mb:
            raise MemoryError("workload exceeds the reserved memory budget")
        if work.network_scope != "deny":
            network_capability = f"network:{work.network_scope}"
            if network_capability not in work.capabilities:
                raise PermissionError("network-enabled work requires an explicit scoped capability")
        missing = work.capabilities - self.granted
        if missing:
            raise PermissionError("capability denied: " + ", ".join(sorted(missing)))
        if work.account_requirement and work.account_requirement not in self.eligible_accounts:
            raise PermissionError("required account is not eligible for this workload")
        if not work.metered_cost_usd.is_finite() or work.metered_cost_usd < 0:
            raise ValueError("workload metered cost must be finite and non-negative")
        for key, value in work.environment.items():
            if not key.isidentifier() or not isinstance(value, str) or "\x00" in value:
                raise ValueError("workload environment contains an invalid entry")
            normalized = key.casefold()
            if any(marker in normalized for marker in ("token", "secret", "password", "api_key", "credential")):
                raise ValueError("workload secrets must be supplied by protected credential reference")
        if any(not reference or "\x00" in reference for reference in work.credential_references):
            raise ValueError("credential references must be non-empty opaque identifiers")

        with self._lock:
            if self._active >= self.max_workers:
                raise RuntimeError("workload concurrency limit reached")
            if self._metered_spend + work.metered_cost_usd > self.metered_budget_usd:
                raise PermissionError("workload exceeds the remaining metered budget")
            self._active += 1
            # Reserve the estimate before launch, and retain it after failures
            # because the remote provider may already have charged the request.
            self._metered_spend += work.metered_cost_usd
        try:
            return self.run(
                work.argv,
                dict(work.environment),
                timeout=work.timeout_seconds,
                memory_mb=work.memory_mb,
                network_scope=work.network_scope,
                credential_references=work.credential_references,
            )
        finally:
            with self._lock:
                self._active -= 1
