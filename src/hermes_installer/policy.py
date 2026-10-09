"""Fail-closed provider routing and aggregate metered budget gate (PR-F02).

This module is a policy engine. It becomes an enforcement boundary only when
all Hermes primary and auxiliary provider traffic is routed through its managed
transport and direct provider credentials/routes are unavailable.
"""
from __future__ import annotations

import contextlib
import json
import math
import os
import re
import sqlite3
import stat
import threading
import time
import uuid
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import Callable, Mapping, Protocol

from .state import OwnedRoot, OwnershipError

DISABLED_PUBLIC_PLUGINS = [
    {"id": ident, "enabled": False}
    for ident in ("web", "file-parser", "response-healing", "pareto-router", "context-compression")
]


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
    principal_id: str = ""
    namespace: str = ""
    provenance: str = ""
    capabilities: frozenset[str] = frozenset()
    policy_revision: str = ""
    grant_id: str = ""
    lease_expires_at: float = 0.0

    def __post_init__(self) -> None:
        if not self.profile_id or not self.purpose or not self.trace_id:
            raise PolicyDenied("context.missing", "Trusted dispatch context is incomplete")
        if (not isinstance(self.principal_id, str) or not isinstance(self.namespace, str)
                or not isinstance(self.provenance, str) or not isinstance(self.capabilities, frozenset)
                or any(not isinstance(item, str) or not item for item in self.capabilities)
                or not isinstance(self.policy_revision, str) or not isinstance(self.grant_id, str)):
            raise PolicyDenied("context.claims", "Host dispatch claims have invalid structure")
        if self.provenance and not re.fullmatch(r"sha256:[0-9a-f]{64}", self.provenance):
            raise PolicyDenied("context.provenance", "Host provenance must be a canonical SHA-256 digest")
        if (isinstance(self.lease_expires_at, bool) or not isinstance(self.lease_expires_at, (int, float))
                or not math.isfinite(self.lease_expires_at)):
            raise PolicyDenied("context.lease", "Host lease expiry must be a finite monotonic timestamp")
        if not isinstance(self.sensitivity, Sensitivity) or any(not isinstance(x, Sensitivity) for x in self.derived_from):
            raise PolicyDenied("context.classification", "Sensitivity must be assigned by trusted host policy")
        if not callable(self.cancelled):
            raise PolicyDenied("context.cancel", "Cancellation hook must be callable")
        if self.deadline is not None and (isinstance(self.deadline, bool) or not isinstance(self.deadline, (int, float)) or not math.isfinite(self.deadline)):
            raise PolicyDenied("context.deadline", "Deadline must be a finite monotonic timestamp")

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
    input_usd_per_million: float | None = None
    output_usd_per_million: float | None = None

    def __post_init__(self) -> None:
        if not self.name or not self.endpoint or not self.models:
            raise ValueError("route name, endpoint, and model allowlist are required")
        costs = (self.input_usd_per_million, self.output_usd_per_million)
        if (costs[0] is None) != (costs[1] is None):
            raise ValueError("both route prices must be known, or both must be unknown")
        if any(x is not None and (not math.isfinite(x) or x < 0) for x in costs):
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
    max_fallbacks: int = 3
    max_dispatch_seconds: float = 120.0

    def __post_init__(self) -> None:
        if self.public_route not in self.routes or (self.private_route and self.private_route not in self.routes):
            raise ValueError("selected route is not configured")
        if not math.isfinite(self.metered_budget_usd) or self.metered_budget_usd < 0:
            raise ValueError("metered budget must be finite and non-negative")
        if not 1 <= self.max_attempts <= 3:
            raise ValueError("attempt limit must be one to three")
        if not math.isfinite(self.max_retry_after_seconds) or not 0 <= self.max_retry_after_seconds <= 60:
            raise ValueError("retry-after bound must be finite and at most 60 seconds")
        if not math.isfinite(self.max_dispatch_seconds) or not 1 <= self.max_dispatch_seconds <= 600:
            raise ValueError("dispatch deadline must be finite and at most 600 seconds")
        if not 0 <= self.max_fallbacks <= 3:
            raise ValueError("fallback limit must be zero to three")
        if any(src not in self.routes or any(dst not in self.routes for dst in dsts) for src, dsts in self.fallbacks.items()):
            raise ValueError("fallback refers to an unknown route")
        if any(len(dsts) > self.max_fallbacks or len(set(dsts)) != len(dsts) for dsts in self.fallbacks.values()):
            raise ValueError("fallback list exceeds its bound or contains duplicates")


@dataclass(frozen=True, slots=True)
class DispatchAuthorization:
    """Short-lived host-issued authority for one provider dispatch.

    A verifier must derive principal, namespace and effective sensitivity from
    its trusted host/broker state. Values supplied by a DispatchContext are only
    correlation claims and never grant access by themselves.
    """
    principal_id: str
    profile_id: str
    namespace: str
    trace_id: str
    capabilities: frozenset[str]
    effective_sensitivity: Sensitivity
    policy_revision: str
    purpose: str
    capability: str
    intent_id: str
    lineage_sha256: str
    grant_id: str
    expires_at_monotonic: float


ContextAuthorizer = Callable[[DispatchContext, str, str, float, float, Callable[[], bool]], DispatchAuthorization | None]


@dataclass(frozen=True, slots=True)
class ProviderResponse:
    status: int
    body: bytes
    headers: Mapping[str, str] = field(default_factory=dict)
    input_tokens: int = 0
    output_tokens: int = 0


class Transport(Protocol):
    def __call__(self, route: Route, model: str, payload: bytes, *, output_token_limit: int,
                 timeout: float, trace_id: str, cancelled: Callable[[], bool]) -> ProviderResponse: ...


def request_requires_tools(payload: bytes) -> bool:
    """Inspect the chat envelope so a caller flag cannot hide tool use."""
    try:
        value = json.loads(payload)
    except (TypeError, ValueError, UnicodeDecodeError):
        raise PolicyDenied("request.format", "Provider request must be valid JSON") from None
    if not isinstance(value, dict) or not isinstance(value.get("messages"), list):
        raise PolicyDenied("request.format", "Provider request must contain a messages array")
    if value.get("tools") not in (None, []):
        return True
    if value.get("tool_choice") not in (None, "none"):
        return True
    return any(isinstance(message, dict) and bool(message.get("tool_calls"))
               for message in value["messages"])


def normalize_chat_request(payload: bytes, model: str, output_token_limit: int) -> bytes:
    """Override caller-controlled model/token fields before any provider transport."""
    if not isinstance(payload, bytes) or len(payload) > 1_048_576:
        raise PolicyDenied("request.bounds", "Serialized request must be bytes and at most 1 MiB")
    try:
        value = json.loads(payload)
    except (ValueError, UnicodeDecodeError):
        raise PolicyDenied("request.format", "Provider request must be valid JSON") from None
    if not isinstance(value, dict) or not isinstance(value.get("messages"), list):
        raise PolicyDenied("request.format", "Provider request must contain a messages array")
    allowed = {"model", "messages", "max_tokens", "max_completion_tokens", "max_output_tokens",
               "temperature", "top_p", "n", "stream", "stream_options", "stop",
               "presence_penalty", "frequency_penalty", "seed", "tools", "tool_choice",
               "parallel_tool_calls", "user", "metadata", "logit_bias", "logprobs", "top_logprobs",
               "plugins", "provider", "response_format"}
    forbidden = {"models", "fallbacks", "route", "transforms", "modalities", "audio", "video",
                 "images", "response_format"}
    if set(value) - allowed or set(value) & forbidden:
        raise PolicyDenied("request.features", "Request contains an unsupported routing, plugin, format or modality feature")
    messages = value["messages"]
    if not 1 <= len(messages) <= 2048:
        raise PolicyDenied("request.bounds", "Message count is outside the supported range")
    for message in messages:
        if not isinstance(message, dict) or message.get("role") not in {"system", "developer", "user", "assistant", "tool"}:
            raise PolicyDenied("request.format", "Message role or structure is unsupported")
        content = message.get("content")
        if content is not None and not isinstance(content, str):
            if not isinstance(content, list) or any(not isinstance(part, dict) or part.get("type") != "text" or not isinstance(part.get("text"), str) for part in content):
                raise PolicyDenied("request.modality", "Only text message content is eligible for the public route")
        if content is None and not (message.get("role") == "assistant" and isinstance(message.get("tool_calls"), list)):
            raise PolicyDenied("request.format", "Message content is missing")
        calls = message.get("tool_calls", [])
        if not isinstance(calls, list) or any(not isinstance(call, dict) or call.get("type") != "function" or not isinstance(call.get("function"), dict) for call in calls):
            raise PolicyDenied("request.tools", "Only ordinary function tool calls are eligible")
    tools = value.get("tools", [])
    if not isinstance(tools, list) or len(tools) > 64 or any(not isinstance(tool, dict) or tool.get("type") != "function" or not isinstance(tool.get("function"), dict) for tool in tools):
        raise PolicyDenied("request.tools", "Only ordinary function tools are eligible; provider server tools are disabled")
    if value.get("tool_choice") not in (None, "none", "auto", "required") and not (
        isinstance(value.get("tool_choice"), dict) and value["tool_choice"].get("type") == "function"
        and isinstance(value["tool_choice"].get("function"), dict)
    ):
        raise PolicyDenied("request.tools", "Tool choice must select an ordinary function tool")
    if "n" in value and (not isinstance(value["n"], int) or value["n"] < 1):
        raise PolicyDenied("request.bounds", "Completion count must be a positive integer")
    # Dispatcher and endpoint adapter normalize at independent trust boundaries.
    # Accept exactly our canonical disabled list so normalization is idempotent.
    supplied_plugins = value.get("plugins")
    if supplied_plugins not in (None, []) and supplied_plugins != DISABLED_PUBLIC_PLUGINS:
        raise PolicyDenied("request.plugins", "Caller-selected provider plugins are disabled")
    value["n"] = 1
    value["model"] = model
    value.pop("max_completion_tokens", None)
    value.pop("max_output_tokens", None)
    # Explicitly turn off every currently documented account-default plugin.
    # Provider-side prevent-overrides may reject this request; that remains a
    # closed failure and must not be bypassed with a fallback.
    value["plugins"] = [dict(plugin) for plugin in DISABLED_PUBLIC_PLUGINS]
    value["provider"] = {"allow_fallbacks": False, "require_parameters": True, "data_collection": "deny"}
    value["max_tokens"] = output_token_limit
    value["stream"] = bool(value.get("stream", False))
    value.pop("stream_options", None)
    try:
        normalized = json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError):
        raise PolicyDenied("request.format", "Provider request could not be serialized safely") from None
    if len(normalized) > 1_048_576:
        raise PolicyDenied("request.bounds", "Normalized request exceeds its 1 MiB byte limit")
    return normalized


class BudgetLedger:
    """SQLite reservations under a verified installer-owned root."""

    def __init__(self, root: OwnedRoot, relative: str = "runtime/provider-budget.sqlite3"):
        if not isinstance(root, OwnedRoot):
            raise TypeError("budget ledger requires an OwnedRoot")
        root.ensure()
        self.root = root
        self.relative = relative
        path = root.path(relative)
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        fd = os.open(path, flags, 0o600)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
                raise OwnershipError("Budget ledger must be a private regular file owned by this user")
            os.fchmod(fd, 0o600)
        finally:
            os.close(fd)
        self.path = path
        with self._transaction() as db:
            db.execute("CREATE TABLE IF NOT EXISTS spend(period TEXT PRIMARY KEY, amount REAL NOT NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS reservations(id TEXT PRIMARY KEY, period TEXT NOT NULL, amount REAL NOT NULL, state TEXT NOT NULL)")

    def _connect(self) -> sqlite3.Connection:
        path = self.root.path(self.relative)
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
            raise OwnershipError("Budget ledger changed to an unsafe file")
        db = sqlite3.connect(path, timeout=10, isolation_level=None)
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=FULL")
        return db

    @contextlib.contextmanager
    def _transaction(self):
        db = self._connect()
        try:
            with db:
                yield db
        finally:
            db.close()

    def reserve(self, amount: float, limit: float) -> str:
        if not math.isfinite(amount) or amount < 0 or not math.isfinite(limit) or limit < 0:
            raise PolicyDenied("budget.invalid", "Invalid metered budget")
        period = time.strftime("%Y-%m", time.gmtime())
        key = str(uuid.uuid4())
        with self._transaction() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT COALESCE((SELECT amount FROM spend WHERE period=?),0)+COALESCE((SELECT SUM(amount) FROM reservations WHERE period=? AND state='reserved'),0)", (period, period)).fetchone()
            if float(row[0]) + amount > limit + 1e-12:
                db.rollback()
                raise PolicyDenied("budget.exhausted", "Aggregate metered budget would be exceeded")
            db.execute("INSERT INTO reservations VALUES(?,?,?,'reserved')", (key, period, amount))
            db.commit()
        return key

    def settle(self, key: str, actual: float | None = None) -> None:
        if actual is not None and (not math.isfinite(actual) or actual < 0):
            actual = None
        with self._transaction() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT period,amount,state FROM reservations WHERE id=?", (key,)).fetchone()
            if row is None or row[2] != "reserved":
                db.rollback()
                return
            amount = max(float(row[1]), float(actual)) if actual is not None else float(row[1])
            db.execute("INSERT INTO spend VALUES(?,?) ON CONFLICT(period) DO UPDATE SET amount=amount+excluded.amount", (row[0], amount))
            db.execute("UPDATE reservations SET amount=?,state='settled' WHERE id=?", (amount, key))
            db.commit()

    def release(self, key: str) -> None:
        with self._transaction() as db:
            db.execute("UPDATE reservations SET state='released' WHERE id=? AND state='reserved'", (key,))

    def spent(self) -> float:
        period = time.strftime("%Y-%m", time.gmtime())
        with self._transaction() as db:
            row = db.execute("SELECT amount FROM spend WHERE period=?", (period,)).fetchone()
        return 0.0 if row is None else float(row[0])


class Dispatcher:
    """Bounded shared gate for primary inference, tools, memory extraction and retries."""

    def __init__(self, policy: DispatchPolicy, ledger: BudgetLedger, transport: Transport, *,
                 context_authorizer: ContextAuthorizer | None = None,
                 clock: Callable[[], float] = time.monotonic, sleep: Callable[[float], None] = time.sleep):
        if not callable(clock) or not callable(sleep):
            raise TypeError("dispatcher clock and sleeper must be callable")
        self.policy, self.ledger, self.transport = policy, ledger, transport
        # Missing host authorization intentionally makes this dispatcher unusable.
        # Test fixtures must inject an explicit synthetic authorizer.
        self.context_authorizer = context_authorizer
        self.clock, self.sleep = clock, sleep
        self._lock = threading.Lock()
        self._active: set[str] = set()

    def _now(self) -> float:
        value = self.clock()
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
            raise PolicyDenied("authorization.clock", "Host monotonic clock is invalid")
        return float(value)

    def _authorize(self, context: DispatchContext, capability: str, intent_id: str,
                   deadline: float) -> DispatchAuthorization:
        authorizer = self.context_authorizer
        now = self._now()
        if authorizer is None:
            raise PolicyDenied("authorization.unavailable", "Trusted host provider authorization is unavailable")
        if context.cancelled():
            raise PolicyDenied("dispatch.cancelled", "Request was cancelled before provider authorization")
        remaining = deadline - now
        if remaining <= 0:
            raise PolicyDenied("dispatch.deadline", "Request deadline elapsed before provider authorization")
        def authorization_cancelled() -> bool:
            return context.cancelled() or self._now() >= deadline
        try:
            # The injected host adapter must implement bounded, cancellable reads
            # and join any helper it starts before returning or raising.
            grant = authorizer(context, capability, intent_id, now, remaining, authorization_cancelled)
        except Exception:
            if context.cancelled():
                raise PolicyDenied("dispatch.cancelled", "Request was cancelled during provider authorization") from None
            if self._now() >= deadline:
                raise PolicyDenied("dispatch.deadline", "Provider authorization exceeded the request deadline") from None
            raise PolicyDenied("authorization.failed", "Trusted host provider authorization failed") from None
        finished = self._now()
        if context.cancelled():
            raise PolicyDenied("dispatch.cancelled", "Request was cancelled during provider authorization")
        if finished >= deadline:
            raise PolicyDenied("dispatch.deadline", "Provider authorization exceeded the request deadline")
        if not isinstance(grant, DispatchAuthorization):
            raise PolicyDenied("authorization.denied", "Trusted host denied this provider capability")
        if (not grant.principal_id or not grant.profile_id or not grant.namespace
                or not grant.trace_id or not grant.policy_revision or not grant.purpose
                or not grant.capability or not grant.intent_id or not grant.grant_id
                or grant.profile_id != context.profile_id or grant.trace_id != context.trace_id
                or grant.purpose != context.purpose or grant.capability != capability
                or grant.intent_id != intent_id or capability not in grant.capabilities
                or not isinstance(grant.effective_sensitivity, Sensitivity)
                or isinstance(grant.expires_at_monotonic, bool)
                or not isinstance(grant.expires_at_monotonic, (int, float))
                or not math.isfinite(grant.expires_at_monotonic)
                or grant.expires_at_monotonic <= finished
                or grant.expires_at_monotonic - finished > 3600
                or not isinstance(grant.lineage_sha256, str)
                or len(grant.lineage_sha256) != 64
                or any(ch not in "0123456789abcdef" for ch in grant.lineage_sha256)):
            raise PolicyDenied("authorization.stale", "Host provider authorization is stale, mismatched, or insufficient")
        return grant

    def _wait(self, context: DispatchContext, delay: float, deadline: float) -> None:
        remaining = min(max(0.0, delay), max(0.0, deadline - self.clock()))
        while remaining > 0:
            if context.cancelled():
                raise PolicyDenied("dispatch.cancelled", "Request was cancelled during retry delay")
            step = min(0.25, remaining)
            self.sleep(step)
            remaining -= step
            if self.clock() >= deadline:
                raise PolicyDenied("dispatch.deadline", "Request deadline elapsed during retry delay")
        if context.cancelled():
            raise PolicyDenied("dispatch.cancelled", "Request was cancelled during retry delay")

    def dispatch(self, context: DispatchContext, model: str, payload: bytes, *, input_tokens: int,
                 output_token_limit: int, tool_request: bool = False) -> ProviderResponse:
        if not isinstance(payload, bytes) or len(payload) > 4 * 1024 * 1024:
            raise PolicyDenied("request.bounds", "Serialized request must be bytes and at most 4 MiB")
        if not isinstance(input_tokens, int) or not isinstance(output_token_limit, int) or not 0 <= input_tokens <= 1_000_000 or not 0 <= output_token_limit <= 65_536:
            raise PolicyDenied("request.bounds", "Token bounds are outside the supported limits")
        with self._lock:
            if context.trace_id in self._active:
                raise PolicyDenied("dispatch.loop", "Repeated trace indicates a provider routing loop")
            self._active.add(context.trace_id)
        try:
            started = self.clock()
            deadline = started + self.policy.max_dispatch_seconds
            if context.deadline is not None:
                deadline = min(deadline, context.deadline)
            if context.cancelled():
                raise PolicyDenied("dispatch.cancelled", "Request was cancelled")
            if started >= deadline:
                raise PolicyDenied("dispatch.deadline", "Request deadline has elapsed")
            requires_tools = request_requires_tools(payload)
            if not isinstance(tool_request, bool) or tool_request != requires_tools:
                raise PolicyDenied("authorization.request_mismatch", "Tool capability flag does not match the request body")
            capability = "tool-call" if requires_tools else "inference"
            payload_sha256 = __import__("hashlib").sha256(payload).hexdigest()
            lineage_claim = ",".join(value.name for value in context.derived_from)
            intent_material = chr(31).join((context.profile_id, context.trace_id, context.purpose,
                context.sensitivity.name, lineage_claim, capability, model, payload_sha256))
            intent_id = __import__("hashlib").sha256(intent_material.encode("utf-8")).hexdigest()
            initial_authorization = self._authorize(context, capability, intent_id, deadline)
            sensitivity = initial_authorization.effective_sensitivity
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
                if len(visited) > self.policy.max_fallbacks + 1:
                    raise PolicyDenied("dispatch.loop", "Provider fallback count exceeded its bound")
                if self.clock() >= deadline:
                    raise PolicyDenied("dispatch.deadline", "Request deadline has elapsed")
                route = self.policy.routes[name]
                if sensitivity > route.maximum_sensitivity or model not in route.models:
                    continue
                if route.free_only and (not model.endswith(":free") or route.input_usd_per_million != 0 or route.output_usd_per_million != 0):
                    continue
                if tool_request and not route.supports_tools:
                    continue
                if route.input_usd_per_million is None or route.output_usd_per_million is None:
                    continue
                if (route.input_usd_per_million > 0 or route.output_usd_per_million > 0) and self.policy.metered_budget_usd <= 0:
                    continue
                # Validate and normalize only after trusted route, sensitivity,
                # cancellation and deadline eligibility have passed. Costing uses
                # the exact canonical bytes that the transport will send.
                normalized_payload = normalize_chat_request(payload, model, output_token_limit)
                input_bound = max(input_tokens, len(normalized_payload))
                estimate = (input_bound * route.input_usd_per_million + output_token_limit * route.output_usd_per_million) / 1_000_000
                if estimate > 0 and self.policy.metered_budget_usd <= 0:
                    continue
                for attempt in range(self.policy.max_attempts):
                    if context.cancelled():
                        raise PolicyDenied("dispatch.cancelled", "Request was cancelled before attempt")
                    remaining = deadline - self.clock()
                    if remaining <= 0:
                        raise PolicyDenied("dispatch.deadline", "Request deadline has elapsed")
                    current_authorization = self._authorize(context, capability, intent_id, deadline)
                    if (current_authorization.principal_id != initial_authorization.principal_id
                            or current_authorization.profile_id != initial_authorization.profile_id
                            or current_authorization.namespace != initial_authorization.namespace
                            or current_authorization.trace_id != initial_authorization.trace_id
                            or current_authorization.policy_revision != initial_authorization.policy_revision
                            or current_authorization.purpose != initial_authorization.purpose
                            or current_authorization.capability != initial_authorization.capability
                            or current_authorization.intent_id != initial_authorization.intent_id
                            or current_authorization.lineage_sha256 != initial_authorization.lineage_sha256
                            or current_authorization.effective_sensitivity != sensitivity):
                        raise PolicyDenied("authorization.changed", "Host authorization changed during provider routing")
                    if current_authorization.expires_at_monotonic <= self.clock() or self.clock() >= deadline:
                        raise PolicyDenied("authorization.expired", "Host authorization expired before provider dispatch")
                    reservation = self.ledger.reserve(estimate, self.policy.metered_budget_usd)
                    authorization_remaining = current_authorization.expires_at_monotonic - self.clock()
                    timeout = min(self.policy.max_retry_after_seconds or remaining, remaining, authorization_remaining)
                    if timeout <= 0:
                        self.ledger.release(reservation)
                        raise PolicyDenied("dispatch.deadline", "Request deadline has elapsed")
                    try:
                        try:
                            def dispatch_cancelled() -> bool:
                                return context.cancelled() or self.clock() >= current_authorization.expires_at_monotonic
                            response = self.transport(route, model, normalized_payload, output_token_limit=output_token_limit, timeout=timeout, trace_id=context.trace_id, cancelled=dispatch_cancelled)
                        except PolicyDenied:
                            self.ledger.settle(reservation)
                            raise
                        except TimeoutError:
                            response = ProviderResponse(0, b"")
                        except Exception:
                            self.ledger.settle(reservation)
                            raise PolicyDenied("provider.transport", "Provider transport failed; reserved spend was retained") from None
                        actual = None
                        if 200 <= response.status < 300 and response.input_tokens >= 0 and response.output_tokens >= 0:
                            actual = (response.input_tokens * route.input_usd_per_million + response.output_tokens * route.output_usd_per_million) / 1_000_000
                        self.ledger.settle(reservation, actual)
                        if context.cancelled():
                            raise PolicyDenied("dispatch.cancelled", "Request was cancelled during provider dispatch")
                        if self.clock() >= current_authorization.expires_at_monotonic:
                            raise PolicyDenied("authorization.expired", "Host authorization expired during provider dispatch")
                        if self.clock() >= deadline:
                            raise PolicyDenied("dispatch.deadline", "Request deadline elapsed during provider dispatch")
                    except BaseException:
                        self.ledger.settle(reservation)
                        raise
                    if 200 <= response.status < 300:
                        return response
                    last_status = response.status
                    retryable = response.status in {0, 408, 425, 429, 500, 502, 503, 504}
                    if not retryable or attempt + 1 >= self.policy.max_attempts:
                        break
                    if response.status == 429:
                        try:
                            candidate_delay = float(response.headers.get("Retry-After", "1"))
                            delay = min(max(candidate_delay, 0.0), self.policy.max_retry_after_seconds)
                            if not math.isfinite(candidate_delay):
                                delay = min(1.0, self.policy.max_retry_after_seconds)
                        except (TypeError, ValueError, OverflowError):
                            delay = min(1.0, self.policy.max_retry_after_seconds)
                    else:
                        delay = min(float(attempt + 1), self.policy.max_retry_after_seconds)
                    self._wait(context, delay, deadline)
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
        Sensitivity.PUBLIC, True, True, 0.0, 0.0,
    )
