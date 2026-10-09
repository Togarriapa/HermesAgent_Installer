"""Fail-closed provider routing and aggregate metered budget gate (PR-F02).

Callers must derive labels from trusted host/profile policy and propagate the
most restrictive label to auxiliary, extracted, retried, and background work.
"""
from __future__ import annotations

import math
import sqlite3
import threading
import time
import uuid
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import Callable, Mapping, Protocol


class PolicyDenied(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


class Sensitivity(IntEnum):
    PUBLIC = 0
    PRIVATE = 1
    CONFIDENTIAL = 2
    UNKNOWN = 3


@dataclass(frozen=True, slots=True)
class DispatchContext:
    profile_id: str
    purpose: str
    sensitivity: Sensitivity
    derived_from: tuple[Sensitivity, ...] = ()
    trace_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    deadline: float | None = None
    cancelled: Callable[[], bool] = field(default=lambda: False, compare=False, repr=False)

    def __post_init__(self) -> None:
        if not self.profile_id or not self.purpose or not self.trace_id:
            raise PolicyDenied("context.missing", "Trusted dispatch context is incomplete")
        if not isinstance(self.sensitivity, Sensitivity) or any(not isinstance(x, Sensitivity) for x in self.derived_from):
            raise PolicyDenied("context.classification", "Sensitivity must be assigned by trusted host policy")
        if not callable(self.cancelled):
            raise PolicyDenied("context.cancel", "Cancellation hook must be callable")

    @property
    def effective_sensitivity(self) -> Sensitivity:
        return max((self.sensitivity, *self.derived_from))


@dataclass(frozen=True, slots=True)
class Route:
    name: str
    endpoint: str
    models: frozenset[str]
    maximum_sensitivity: Sensitivity
    free_only: bool
    supports_tools: bool
    input_usd_per_million: float = 0.0
    output_usd_per_million: float = 0.0

    def __post_init__(self) -> None:
        if not self.name or not self.endpoint or not self.models:
            raise ValueError("route name, endpoint, and model allowlist are required")
        costs = (self.input_usd_per_million, self.output_usd_per_million)
        if any(not math.isfinite(x) or x < 0 for x in costs):
            raise ValueError("route prices must be finite and non-negative")


@dataclass(frozen=True, slots=True)
class DispatchPolicy:
    routes: Mapping[str, Route]
    public_route: str
    private_route: str | None = None
    fallbacks: Mapping[str, tuple[str, ...]] = field(default_factory=dict)
    metered_budget_usd: float = 0.0
    max_attempts: int = 3
    max_retry_after_seconds: float = 15.0

    def __post_init__(self) -> None:
        if self.public_route not in self.routes or (self.private_route and self.private_route not in self.routes):
            raise ValueError("selected route is not configured")
        if not math.isfinite(self.metered_budget_usd) or self.metered_budget_usd < 0:
            raise ValueError("metered budget must be finite and non-negative")
        if not 1 <= self.max_attempts <= 3:
            raise ValueError("attempt limit must be one to three")
        if any(src not in self.routes or any(dst not in self.routes for dst in dsts) for src, dsts in self.fallbacks.items()):
            raise ValueError("fallback refers to an unknown route")


@dataclass(frozen=True, slots=True)
class ProviderResponse:
    status: int
    body: bytes
    headers: Mapping[str, str] = field(default_factory=dict)
    input_tokens: int = 0
    output_tokens: int = 0


class Transport(Protocol):
    def __call__(self, route: Route, model: str, payload: bytes, *, timeout: float, trace_id: str) -> ProviderResponse: ...


class BudgetLedger:
    """SQLite budget reservations shared by all agents and auxiliary workers."""

    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if path.is_symlink():
            raise ValueError("budget ledger cannot be a symlink")
        self.path = path
        self.path.touch(mode=0o600, exist_ok=True)
        self.path.chmod(0o600)
        with self._connect() as db:
            db.execute("CREATE TABLE IF NOT EXISTS spend(period TEXT PRIMARY KEY, amount REAL NOT NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS reservations(id TEXT PRIMARY KEY, period TEXT NOT NULL, amount REAL NOT NULL, state TEXT NOT NULL)")

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=FULL")
        return db

    def reserve(self, amount: float, limit: float) -> str:
        if not math.isfinite(amount) or amount < 0 or not math.isfinite(limit) or limit < 0:
            raise PolicyDenied("budget.invalid", "Invalid metered budget")
        period = time.strftime("%Y-%m", time.gmtime())
        key = str(uuid.uuid4())
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT COALESCE((SELECT amount FROM spend WHERE period=?),0)+COALESCE((SELECT SUM(amount) FROM reservations WHERE period=? AND state='reserved'),0)", (period, period)).fetchone()
            if float(row[0]) + amount > limit + 1e-12:
                db.rollback()
                raise PolicyDenied("budget.exhausted", "Aggregate metered budget would be exceeded")
            db.execute("INSERT INTO reservations VALUES(?,?,?,'reserved')", (key, period, amount))
            db.commit()
        return key

    def settle(self, key: str, actual: float | None = None) -> None:
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT period,amount,state FROM reservations WHERE id=?", (key,)).fetchone()
            if row is None or row[2] != "reserved":
                db.rollback()
                return
            amount = float(row[1] if actual is None else max(float(row[1]), actual))
            db.execute("INSERT INTO spend VALUES(?,?) ON CONFLICT(period) DO UPDATE SET amount=amount+excluded.amount", (row[0], amount))
            db.execute("UPDATE reservations SET amount=?,state='settled' WHERE id=?", (amount, key))
            db.commit()

    def release(self, key: str) -> None:
        with self._connect() as db:
            db.execute("UPDATE reservations SET state='released' WHERE id=? AND state='reserved'", (key,))

    def spent(self) -> float:
        period = time.strftime("%Y-%m", time.gmtime())
        with self._connect() as db:
            row = db.execute("SELECT amount FROM spend WHERE period=?", (period,)).fetchone()
        return 0.0 if row is None else float(row[0])


class Dispatcher:
    """Shared gate for primary inference, tools, memory extraction, and retries."""

    def __init__(self, policy: DispatchPolicy, ledger: BudgetLedger, transport: Transport, *, clock: Callable[[], float] = time.monotonic, sleep: Callable[[float], None] = time.sleep):
        self.policy, self.ledger, self.transport = policy, ledger, transport
        self.clock, self.sleep = clock, sleep
        self._lock = threading.Lock()
        self._active: set[str] = set()

    def dispatch(self, context: DispatchContext, model: str, payload: bytes, *, input_tokens: int, output_token_limit: int, tool_request: bool = False) -> ProviderResponse:
        if not isinstance(payload, bytes) or len(payload) > 4 * 1024 * 1024:
            raise PolicyDenied("request.bounds", "Serialized request must be bytes and at most 4 MiB")
        if not isinstance(input_tokens, int) or not isinstance(output_token_limit, int) or not 0 <= input_tokens <= 1_000_000 or not 0 <= output_token_limit <= 65_536:
            raise PolicyDenied("request.bounds", "Token bounds are outside the supported limits")
        with self._lock:
            if context.trace_id in self._active:
                raise PolicyDenied("dispatch.loop", "Repeated trace indicates a provider routing loop")
            self._active.add(context.trace_id)
        try:
            if context.cancelled():
                raise PolicyDenied("dispatch.cancelled", "Request was cancelled")
            if context.deadline is not None and self.clock() >= context.deadline:
                raise PolicyDenied("dispatch.deadline", "Request deadline has elapsed")
            sensitivity = context.effective_sensitivity
            if sensitivity == Sensitivity.PUBLIC:
                first = self.policy.public_route
            else:
                if self.policy.private_route is None:
                    raise PolicyDenied("route.private_unavailable", f"No private-capable route is configured for {context.purpose}")
                first = self.policy.private_route
            candidates = (first, *self.policy.fallbacks.get(first, ()))
            visited: set[str] = set()
            last_status = 0
            for name in candidates:
                if name in visited:
                    raise PolicyDenied("dispatch.loop", "Provider fallback loop was detected")
                visited.add(name)
                route = self.policy.routes[name]
                if sensitivity > route.maximum_sensitivity or model not in route.models:
                    continue
                if route.free_only and not model.endswith(":free"):
                    continue
                if tool_request and not route.supports_tools:
                    continue
                if (route.input_usd_per_million or route.output_usd_per_million) and self.policy.metered_budget_usd <= 0:
                    continue
                # Request bytes provide a conservative upper bound on encoded input tokens.
                input_bound = max(input_tokens, len(payload))
                estimate = (input_bound * route.input_usd_per_million + output_token_limit * route.output_usd_per_million) / 1_000_000
                reservation = self.ledger.reserve(estimate, self.policy.metered_budget_usd)
                settled = False
                try:
                    for attempt in range(self.policy.max_attempts):
                        if context.cancelled():
                            raise PolicyDenied("dispatch.cancelled", "Request was cancelled before retry")
                        timeout = self.policy.max_retry_after_seconds
                        if context.deadline is not None:
                            timeout = min(timeout, context.deadline - self.clock())
                        if timeout <= 0:
                            raise PolicyDenied("dispatch.deadline", "Request deadline has elapsed")
                        try:
                            response = self.transport(route, model, payload, timeout=timeout, trace_id=context.trace_id)
                        except TimeoutError:
                            last_status = 0
                            response = ProviderResponse(0, b"")
                        if 200 <= response.status < 300:
                            actual = (response.input_tokens * route.input_usd_per_million + response.output_tokens * route.output_usd_per_million) / 1_000_000
                            self.ledger.settle(reservation, actual)
                            settled = True
                            return response
                        last_status = response.status
                        retryable = response.status in {0, 408, 425, 429, 500, 502, 503, 504}
                        if not retryable or attempt + 1 >= self.policy.max_attempts:
                            break
                        if response.status == 429:
                            try:
                                delay = min(max(float(response.headers.get("Retry-After", "1")), 0.0), self.policy.max_retry_after_seconds)
                            except ValueError:
                                delay = 1.0
                        else:
                            delay = min(float(attempt + 1), self.policy.max_retry_after_seconds)
                        if context.deadline is not None:
                            delay = min(delay, max(0.0, context.deadline - self.clock()))
                        self.sleep(delay)
                finally:
                    if not settled:
                        self.ledger.release(reservation)
            if last_status == 429:
                raise PolicyDenied("provider.rate_limited", "Provider rate limit persisted after bounded retries")
            raise PolicyDenied("route.unavailable", "No eligible provider route completed this request")
        finally:
            with self._lock:
                self._active.discard(context.trace_id)


def default_public_route() -> Route:
    return Route(
        "openrouter-nemotron-free", "https://openrouter.ai/api/v1",
        frozenset({"nvidia/nemotron-3-ultra-550b-a55b:free"}),
        Sensitivity.PUBLIC, True, True,
    )
