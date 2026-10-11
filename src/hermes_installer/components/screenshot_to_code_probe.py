"""Strict fixture result contract for the pinned screenshot-to-code WebSocket.

This is fixture evidence only. It does not represent provider/account readiness,
managed runtime preparation, target acceptance, or permission to dispatch metered
requests.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from hermes_installer.components.screenshot_to_code import SOURCE_REVISION


RESULT_SCHEMA = "hermes-screenshot-to-code-probe-result-v1"
MAX_CODE_BYTES = 1_048_576
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_KNOWN_EVENTS = frozenset({
    "chunk", "status", "setCode", "error", "variantComplete", "variantError",
    "variantCount", "variantModels", "thinking", "assistant", "toolStart", "toolResult",
})


class ProbeResultError(ValueError):
    """Pinned upstream output did not satisfy the bounded fixture result schema."""


@dataclass(frozen=True, slots=True)
class ScreenshotToCodeProbeResult:
    schema: str
    evidence_kind: str
    source_revision: str
    route_id: str
    fixture_image_sha256: str
    generated_code_sha256: str
    generated_code: str
    completed_variants: tuple[int, ...]


def validate_upstream_events(
    events: Sequence[Mapping[str, Any]], *, fixture_image: bytes, route_id: str,
) -> ScreenshotToCodeProbeResult:
    """Turn actual upstream WebSocket events into one strict fixture result."""
    if not isinstance(fixture_image, bytes) or not fixture_image.startswith(b"\x89PNG\r\n\x1a\n"):
        raise ProbeResultError("fixture input must be PNG bytes")
    if route_id != "openai-gpt-5.5":
        raise ProbeResultError("fixture result route is not the reviewed vision route")
    if not isinstance(events, Sequence) or isinstance(events, (str, bytes)) or not events:
        raise ProbeResultError("upstream event list is empty or malformed")
    codes: dict[int, str] = {}
    completed: set[int] = set()
    for event in events:
        if not isinstance(event, Mapping) or set(event) - {"type", "value", "variantIndex", "data", "eventId"}:
            raise ProbeResultError("upstream event has unexpected shape")
        kind = event.get("type")
        if kind not in _KNOWN_EVENTS:
            raise ProbeResultError("upstream event type is not recognized")
        index = event.get("variantIndex", 0)
        if type(index) is not int or not 0 <= index < 8:
            raise ProbeResultError("upstream variant index is outside the bound")
        if kind in {"error", "variantError"}:
            raise ProbeResultError("upstream reported a generation error")
        if kind == "setCode":
            code = event.get("value")
            if not isinstance(code, str) or not code.strip() or len(code.encode("utf-8")) > MAX_CODE_BYTES:
                raise ProbeResultError("generated code is empty or exceeds the byte bound")
            codes[index] = code
        elif kind == "variantComplete":
            completed.add(index)
    usable = tuple(sorted(index for index in completed if index in codes))
    if not usable:
        raise ProbeResultError("no completed variant contains generated code")
    code = codes[usable[0]]
    return ScreenshotToCodeProbeResult(
        schema=RESULT_SCHEMA,
        evidence_kind="local-synthetic-fixture-with-mocked-provider-transport",
        source_revision=SOURCE_REVISION,
        route_id=route_id,
        fixture_image_sha256=hashlib.sha256(fixture_image).hexdigest(),
        generated_code_sha256=hashlib.sha256(code.encode("utf-8")).hexdigest(),
        generated_code=code,
        completed_variants=usable,
    )
