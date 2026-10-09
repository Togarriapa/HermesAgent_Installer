"""Fresh host-policy gate directly before any specialist side effect."""
from __future__ import annotations
import asyncio, math, time
from numbers import Real
from dataclasses import dataclass
from typing import Awaitable, Callable
from hermes_installer.policy import DispatchContext

class BrokerDenied(PermissionError):
    """Trusted dispatch context or live host authorization is insufficient."""

@dataclass(frozen=True, slots=True)
class CapabilityLease:
    profile_id: str
    namespace: str
    trace_id: str
    capabilities: frozenset[str]
    policy_revision: str
    grant_id: str
    expires_at: float

@dataclass(frozen=True, slots=True)
class SpecialistCall:
    specialist: str
    request_id: str
    child_id: str
    operation: str
    capabilities: frozenset[str]

Authorizer = Callable[[DispatchContext, SpecialistCall], Awaitable[CapabilityLease]]
Operation = Callable[[], Awaitable[object]]

class DispatchBroker:
    """The roster declaration is not authority; every child gets a fresh lease."""
    def __init__(self, *, authorize: Authorizer, now=time.time, timeout=120):
        if not 0 < timeout <= 600: raise ValueError("broker timeout must be bounded")
        self.authorize, self.now, self.timeout = authorize, now, timeout

    @staticmethod
    def _finite_time(value, label: str) -> float:
        if isinstance(value, bool) or not isinstance(value, Real) or not math.isfinite(value):
            raise BrokerDenied(f"{label} must be a finite timestamp")
        return float(value)

    async def call(self, context: DispatchContext, call: SpecialistCall, operation: Operation):
        # Missing trusted fields fail closed; caller-declared sensitivity is never
        # a substitute for the gateway's effective (including derived) label.
        classification = getattr(context, "effective_sensitivity", "UNKNOWN")
        sensitivity = getattr(classification, "name", str(classification)).upper()
        namespace = getattr(context, "namespace", None)
        capabilities = frozenset(getattr(context, "capabilities", ()))
        trace_id = getattr(context, "trace_id", None)
        provenance = getattr(context, "provenance", ())
        cancelled = getattr(context, "cancelled", lambda: False)
        if (
            not context.profile_id
            or not namespace
            or not trace_id
            or not provenance
            or sensitivity not in {"PUBLIC", "PRIVATE", "CONFIDENTIAL"}
            or context.purpose != "native-hermes-chat"
        ):
            raise BrokerDenied("trusted dispatch context is incomplete or unknown")
        if cancelled():
            raise BrokerDenied("request cancelled before authorization")
        if not call.specialist or not call.request_id or not call.child_id or not call.operation:
            raise BrokerDenied("specialist call identity is incomplete")
        if not call.capabilities or "delegate" not in call.capabilities:
            raise BrokerDenied("specialist call has no delegation capability")
        if not call.capabilities.issubset(capabilities):
            raise BrokerDenied("context does not grant all requested specialist capabilities")
        if sensitivity == "PRIVATE" and "private-context" not in call.capabilities:
            raise BrokerDenied("private context requires an explicit private-context grant")
        if sensitivity == "CONFIDENTIAL" and "confidential-context" not in call.capabilities:
            raise BrokerDenied("confidential context requires an explicit confidential-context grant")

        current_time = self._finite_time(self.now(), "host clock")
        deadline = getattr(context, "deadline", None)
        if deadline is not None:
            deadline = self._finite_time(deadline, "request deadline")
        if deadline is not None and deadline <= current_time:
            raise BrokerDenied("dispatch deadline expired before authorization")
        authorization_timeout = self.timeout
        if deadline is not None:
            authorization_timeout = min(authorization_timeout, deadline - current_time)
        try:
            lease = await asyncio.wait_for(
                self.authorize(context, call), timeout=authorization_timeout
            )
        except asyncio.TimeoutError as exc:
            raise TimeoutError("host authorization exceeded dispatch deadline") from exc
        current_time = self._finite_time(self.now(), "host clock")
        expires_at = self._finite_time(lease.expires_at, "authorization expiry")
        if (
            lease.profile_id != context.profile_id
            or lease.namespace != namespace
            or lease.trace_id != trace_id
            or not lease.policy_revision
            or not lease.grant_id
            or expires_at <= current_time
            or expires_at - current_time > 3600
            or not call.capabilities.issubset(lease.capabilities)
        ):
            raise BrokerDenied("host authorization lease is stale, mismatched, or insufficient")
        if cancelled():
            raise BrokerDenied("request cancelled before specialist execution")

        current_time = self._finite_time(self.now(), "host clock")
        wall_budget = min(self.timeout, expires_at - current_time)
        if deadline is not None:
            wall_budget = min(wall_budget, deadline - current_time)
        if wall_budget <= 0:
            raise BrokerDenied("authorization expired before specialist execution")
        loop = asyncio.get_running_loop()
        monotonic_deadline = loop.time() + wall_budget
        task = asyncio.create_task(operation())
        try:
            while not task.done():
                if cancelled():
                    task.cancel()
                    await asyncio.gather(task, return_exceptions=True)
                    raise asyncio.CancelledError
                remaining = monotonic_deadline - loop.time()
                current_time = self._finite_time(self.now(), "host clock")
                if remaining <= 0 or current_time >= expires_at:
                    task.cancel()
                    await asyncio.gather(task, return_exceptions=True)
                    if current_time >= expires_at:
                        raise BrokerDenied("host authorization expired during dispatch")
                    raise TimeoutError("specialist dispatch exceeded authorization deadline")
                done, _ = await asyncio.wait({task}, timeout=min(0.05, remaining))
                if not done and deadline is not None and current_time >= deadline:
                    task.cancel()
                    await asyncio.gather(task, return_exceptions=True)
                    raise TimeoutError("specialist dispatch exceeded request deadline")
            # Recheck trust at the completion boundary before exposing the result.
            if cancelled():
                raise asyncio.CancelledError
            current_time = self._finite_time(self.now(), "host clock")
            if current_time >= expires_at:
                raise BrokerDenied("host authorization expired before result delivery")
            if deadline is not None and current_time >= deadline:
                raise TimeoutError("specialist dispatch exceeded request deadline")
            return task.result()
        except asyncio.CancelledError:
            if not task.done():
                task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            raise
