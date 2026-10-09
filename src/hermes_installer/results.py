"""Structured command outcomes shared by CLI and component adapters."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any


class OutcomeState(StrEnum):
    READY = "ready"
    PENDING = "pending"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class Finding:
    code: str
    message: str
    state: OutcomeState = OutcomeState.PENDING
    details: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class CommandResult:
    command: str
    state: OutcomeState
    message: str
    findings: tuple[Finding, ...] = ()
    resume_command: str | None = None
    exit_code: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
