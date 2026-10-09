"""Fresh host-policy gate directly before any specialist side effect."""
from __future__ import annotations
import asyncio, time
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

    async def call(self, context: DispatchContext, call: SpecialistCall, operation: Operation):
        sensitivity = getattr(context.sensitivity, "name", str(context.sensitivity)).upper()
        namespace = getattr(context, "namespace", None)
        capabilities = frozenset(getattr(context, "capabilities", ()))
        trace_id = getattr(context, "trace_id", None)
        provenance = getattr(context, "provenance", ())
        if (not context.profile_id or not namespace or not trace_id or not provenance
            or sensitivity == "UNKNOWN" or context.purpose != "native-hermes-chat"):
            raise BrokerDenied("trusted dispatch context is incomplete or unknown")
        if getattr(context, "cancelled", lambda: False)(): raise BrokerDenied("request cancelled before authorization")
        if not call.specialist or not call.request_id or not call.child_id or not call.operation:
            raise BrokerDenied("specialist call identity is incomplete")
        if not call.capabilities or "delegate" not in call.capabilities or not call.capabilities.issubset(capabilities):
            raise BrokerDenied("context does not grant all requested specialist capabilities")
        if sensitivity == "PRIVATE" and "private-context" not in call.capabilities:
            raise BrokerDenied("private context requires an explicit private-context grant")
        lease = await asyncio.wait_for(self.authorize(context, call), timeout=self.timeout)
        if (lease.profile_id != context.profile_id or lease.namespace != namespace or lease.trace_id != trace_id
            or not lease.policy_revision or not lease.grant_id or lease.expires_at <= self.now()
            or not call.capabilities.issubset(lease.capabilities)):
            raise BrokerDenied("host authorization lease is stale, mismatched, or insufficient")
        task = asyncio.create_task(operation())
        deadline = min(self.timeout, lease.expires_at - self.now())
        try:
            while not task.done():
                if getattr(context, "cancelled", lambda: False)():
                    task.cancel(); await asyncio.gather(task, return_exceptions=True)
                    raise asyncio.CancelledError
                if self.now() >= lease.expires_at:
                    task.cancel(); await asyncio.gather(task, return_exceptions=True)
                    raise BrokerDenied("host authorization expired during dispatch")
                done, _ = await asyncio.wait({task}, timeout=min(0.05, deadline))
                if not done and deadline <= 0:
                    task.cancel(); await asyncio.gather(task, return_exceptions=True)
                    raise TimeoutError("specialist dispatch exceeded authorization deadline")
                deadline -= 0.05
            return task.result()
        except asyncio.CancelledError:
            if not task.done(): task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            raise
