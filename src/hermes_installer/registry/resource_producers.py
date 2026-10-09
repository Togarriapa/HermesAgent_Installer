"""Typed inputs for root-owned resource source producers.

These value objects describe observations only. Constructing one does not
authenticate a sender, issue a source receipt, select a profile, or authorize an
effect. Root controller adapters must resolve the active protected enrollment,
verify the live controller/connector identity, and mint the source context.
They are deliberately not worker RPC request types.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from typing import Sequence


class ResourceObservationError(ValueError):
    """A producer observation is malformed or exceeds its finite input bound."""


_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_HEADER = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]{1,128}\Z")


def _identifier(value: object, field: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise ResourceObservationError(f"{field} is invalid")
    return value


def _instant(value: object, field: str) -> datetime:
    if not isinstance(value, str) or len(value) > 64:
        raise ResourceObservationError(f"{field} must be an explicit timezone-aware instant")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise ResourceObservationError(f"{field} must be an explicit timezone-aware instant") from None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ResourceObservationError(f"{field} must be an explicit timezone-aware instant")
    return parsed


@dataclass(frozen=True, slots=True)
class CronTickObservation:
    """A scheduler's due/fired observation, pending root role verification."""

    resource_id: str
    schedule_id: str
    sequence: int
    due_at: str
    fired_at: str

    def __post_init__(self) -> None:
        _identifier(self.resource_id, "cron resource ID")
        _identifier(self.schedule_id, "selected schedule ID")
        if type(self.sequence) is not int or self.sequence < 1:
            raise ResourceObservationError("cron tick sequence must be positive")
        due, fired = _instant(self.due_at, "cron due_at"), _instant(self.fired_at, "cron fired_at")
        if fired < due:
            raise ResourceObservationError("cron fire time cannot precede its due time")


@dataclass(frozen=True, slots=True)
class WebhookRequestObservation:
    """Raw HTTP request values for verification inside root ingress custody."""

    resource_id: str
    headers: tuple[tuple[str, str], ...]
    body: bytes

    def __post_init__(self) -> None:
        _identifier(self.resource_id, "webhook resource ID")
        if (not isinstance(self.headers, tuple) or len(self.headers) > 128
                or any(not isinstance(row, tuple) or len(row) != 2 for row in self.headers)):
            raise ResourceObservationError("webhook headers must be a bounded immutable sequence")
        seen: set[str] = set()
        for name, value in self.headers:
            if (not isinstance(name, str) or not _HEADER.fullmatch(name)
                    or not isinstance(value, str) or len(value) > 16_384
                    or any(ord(char) < 0x20 and char != "\t" for char in value)
                    or any(ord(char) == 0x7f for char in value)):
                raise ResourceObservationError("webhook header is malformed")
            normalized = name.casefold()
            if normalized in seen:
                raise ResourceObservationError("duplicate webhook header names are rejected")
            seen.add(normalized)
        if not isinstance(self.body, bytes) or len(self.body) > 4 * 1024 * 1024:
            raise ResourceObservationError("webhook body exceeds the root ingress bound")

    @classmethod
    def from_headers(cls, resource_id: str, headers: Sequence[tuple[str, str]], body: bytes) -> "WebhookRequestObservation":
        if not isinstance(headers, (tuple, list)):
            raise ResourceObservationError("webhook headers must be an ordered sequence")
        return cls(resource_id, tuple(headers), body)


@dataclass(frozen=True, slots=True)
class AuthenticatedChannelIngress:
    """Connector observation values; the type itself is not authentication proof.

    The root source controller must additionally verify that this call came
    from the current selected connector/account process and that the account
    binding matches the protected source issuer. No boolean authentication
    claim is accepted here.
    """

    resource_id: str
    connector_id: str
    account_binding_id: str
    event_id: str
    conversation_id: str
    content: bytes

    def __post_init__(self) -> None:
        for field, value in (
            ("channel resource ID", self.resource_id),
            ("channel connector ID", self.connector_id),
            ("channel account binding ID", self.account_binding_id),
            ("channel event ID", self.event_id),
            ("channel conversation ID", self.conversation_id),
        ):
            _identifier(value, field)
        if not isinstance(self.content, bytes) or not 1 <= len(self.content) <= 1_048_576:
            raise ResourceObservationError("channel content is empty or exceeds the one MiB bound")

