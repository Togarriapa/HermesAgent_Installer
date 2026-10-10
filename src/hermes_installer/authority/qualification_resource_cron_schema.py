"""Closed request/result schemas for the installed cron task fixture.

This module is deliberately data-only.  The IDs below select one reviewed
request shape; they never name a path, module, command, source, or authority.
The release receipt supplies the measured module digest at runtime.
"""
from __future__ import annotations

import json
from types import MappingProxyType


SCHEMA_ID = "hermes-installed-resource-cron-task-schema-v1"
REQUEST_SCHEMA_ID = "hermes-installed-resource-cron-task-request-v1"
RESULT_SCHEMA_ID = "hermes-installed-resource-cron-task-result-v1"
MAX_PROMPT_BYTES = 256

REQUEST_FIELDS = MappingProxyType({
    "schema": 1,
    "prompt": "bounded-utf8-text",
})
RESULT_FIELDS = MappingProxyType({
    "schema": 1,
    "bytes": "unsigned-integer",
    "sha256": "lowercase-sha256",
})


def canonical_request(prompt: str) -> bytes:
    """Encode the single fixed request envelope accepted by this fixture."""
    if type(prompt) is not str:
        raise ValueError("fixture prompt must be text")
    encoded = prompt.encode("utf-8", errors="strict")
    if not encoded or len(encoded) > MAX_PROMPT_BYTES or b"\x00" in encoded:
        raise ValueError("fixture prompt is outside its bounded UTF-8 schema")
    return json.dumps(
        {"prompt": prompt, "schema": 1},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")

