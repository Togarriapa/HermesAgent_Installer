"""Correlated specialist tasks gated by the runtime authorization broker."""
from __future__ import annotations
import asyncio, uuid
from dataclasses import dataclass, field
from typing import Awaitable, Callable, Mapping, Sequence
from .broker import DispatchBroker, SpecialistCall
from hermes_installer.policy import DispatchContext

class RecruitmentDenied(PermissionError):
    """A requested roster is unknown or lacks effective authorization."""

@dataclass(frozen=True, slots=True)
class WorkRequest:
    request_id: str
    child_id: str
    user_id: str
    task: str
    parent_id: str | None = None

@dataclass(frozen=True, slots=True)
class WorkResult:
    request_id: str
    specialist: str
    content: str
    evidence: tuple[str, ...] = ()
    dissent: tuple[str, ...] = ()
    child_id: str = ""

@dataclass(frozen=True, slots=True)
class RecruitmentReport:
    request_id: str
    results: tuple[WorkResult, ...]

Specialist = Callable[[WorkRequest], Awaitable[WorkResult]]
ContextFactory = Callable[[WorkRequest], DispatchContext]

@dataclass
class Orchestrator:
    specialists: Mapping[str, Specialist]
    grants: Mapping[str, frozenset[str]]
    broker: DispatchBroker | None = None
    context_factory: ContextFactory | None = None
    max_concurrency: int = 3
    _active: dict[str, asyncio.Task] = field(default_factory=dict, init=False)
    _children: dict[str, dict[str, asyncio.Task]] = field(default_factory=dict, init=False)

    async def recruit_report(self, user_id: str, task: str, roster: Sequence[str], *, parent_id=None, request_id=None):
        if not user_id or not task or not roster: raise RecruitmentDenied("user, task and nonempty roster required")
        if self.broker is None or self.context_factory is None:
            raise RecruitmentDenied("runtime host-authorization broker is unavailable")
        rid = request_id or str(uuid.uuid4())
        try: uuid.UUID(rid)
        except ValueError: raise RecruitmentDenied("request id must be a UUID") from None
        names = tuple(roster)
        if len(set(names)) != len(names): raise RecruitmentDenied("duplicate roster entries are denied")
        denied = [name for name in names if name not in self.specialists or "delegate" not in self.grants.get(name, frozenset())]
        if denied: raise RecruitmentDenied("unknown or ungranted specialists: " + ", ".join(denied))
        if not 1 <= self.max_concurrency <= 32: raise RecruitmentDenied("concurrency limit is invalid")
        owner = asyncio.current_task()
        if owner is None: raise RuntimeError("recruitment requires an asyncio task")
        semaphore = asyncio.Semaphore(self.max_concurrency)
        children: dict[str, asyncio.Task] = {}
        self._active[rid], self._children[rid] = owner, children

        async def invoke(name):
            child = str(uuid.uuid4())
            request = WorkRequest(rid, child, user_id, task, parent_id)
            context = self.context_factory(request)
            call = SpecialistCall(name, rid, child, "delegate", frozenset({"delegate"}))
            async def execute():
                async with semaphore:
                    return await self.specialists[name](request)
            result = await self.broker.call(context, call, execute)
            if not isinstance(result, WorkResult) or result.request_id != rid or result.specialist != name or result.child_id not in {"", child}:
                raise RuntimeError(f"specialist correlation mismatch for child {child}")
            if result.child_id: return result
            return WorkResult(result.request_id, result.specialist, result.content, result.evidence, result.dissent, child)

        try:
            for name in names: children[name] = asyncio.create_task(invoke(name), name=f"specialist:{rid}:{name}")
            values = await asyncio.gather(*children.values(), return_exceptions=True)
            failures = [value for value in values if isinstance(value, BaseException)]
            if failures:
                for child in children.values():
                    if not child.done(): child.cancel()
                await asyncio.gather(*children.values(), return_exceptions=True)
                error = failures[0]
                if isinstance(error, asyncio.CancelledError): raise error
                raise RuntimeError("specialist failed; siblings cancelled and joined") from error
            return RecruitmentReport(rid, tuple(values))
        except asyncio.CancelledError:
            for child in children.values():
                if not child.done(): child.cancel()
            await asyncio.gather(*children.values(), return_exceptions=True)
            raise
        finally:
            self._active.pop(rid, None); self._children.pop(rid, None)

    async def recruit(self, user_id, task, roster, *, parent_id=None, request_id=None):
        report = await self.recruit_report(user_id, task, roster, parent_id=parent_id, request_id=request_id)
        return report.results

    async def cancel(self, request_id: str) -> bool:
        parent = self._active.get(request_id)
        if parent is None: return False
        parent.cancel()
        children = self._children.get(request_id, {})
        for child in children.values():
            if not child.done(): child.cancel()
        await asyncio.gather(*children.values(), return_exceptions=True)
        return True
