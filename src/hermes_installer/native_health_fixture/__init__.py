"""Source-owned, bounded assets for the selected Hermes native health check.

The assets describe one real pinned Hermes tool registration. Root selection and
artifact verification remain outside this package; these helpers only expose
bytes and validate the observed tool result against the fixed fixture.
"""
from __future__ import annotations

import hashlib
import json
from importlib.resources import files
from typing import Any


FIXTURE_ID = "hermes-agent-health-v1"
FIXTURE_ARTIFACT_ID = "hermes-agent-health-fixture-v1"
RESULT_SCHEMA_ID = "hermes-agent-health-overlay-read-result-v1"
ACTION_ID = "resource-overlay-store:tool:resource_overlay_read"
TOOL_NAME = "resource_overlay_read"
RECORD_ID = "hermes-health-probe-v1"
PROVIDER_REQUIRED = True
PROVIDER_ROUTE_CLASS = "private-zero-additional-budget"
MAX_FIXTURE_BYTES = 16_384


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("health result contains a duplicate JSON key")
        result[key] = value
    return result


def _reject_constant(_value: str) -> None:
    raise ValueError("health result contains a non-finite number")


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def read_asset(name: str) -> bytes:
    """Read one fixed package asset; never accept a caller path or resource ID."""
    if name not in {
        "request.txt", "seed-value.txt", "expected-tool-result.json",
        "tool-result.schema.json", "recipe.json",
    }:
        raise ValueError("unknown native health fixture asset")
    raw = files(__package__).joinpath(name).read_bytes()
    if not raw or len(raw) > MAX_FIXTURE_BYTES:
        raise ValueError("native health fixture asset is empty or exceeds its fixed bound")
    return raw


def fixture_asset_digests() -> dict[str, str]:
    """Return measured digests for root-side packaging; this is not authority."""
    return {name: hashlib.sha256(read_asset(name)).hexdigest() for name in (
        "request.txt", "seed-value.txt", "expected-tool-result.json",
        "tool-result.schema.json", "recipe.json",
    )}


def validate_tool_result(result_schema_id: str, result_bytes: bytes):
    """Accept only the byte-equivalent result of the reviewed local read fixture."""
    if result_schema_id != RESULT_SCHEMA_ID or not isinstance(result_bytes, bytes):
        raise ValueError("native health result schema is not selected")
    if not 1 <= len(result_bytes) <= MAX_FIXTURE_BYTES:
        raise ValueError("native health result exceeds its fixed bound")
    expected = json.loads(read_asset("expected-tool-result.json"))
    try:
        actual = json.loads(result_bytes.decode("utf-8"), object_pairs_hook=_strict_object,
                            parse_constant=_reject_constant)
    except (UnicodeError, ValueError, json.JSONDecodeError):
        raise ValueError("native health result is not strict JSON") from None
    if type(actual) is not dict or actual != expected or _canonical(actual) != result_bytes:
        raise ValueError("native health result differs from the selected overlay read")
    # Delayed import keeps fixture asset inspection independent from authority
    # service bootstrap while returning the exact typed result required by the
    # root health observer.
    from hermes_installer.authority.native_health_observer import RootValidatedNativeHealthResult
    return RootValidatedNativeHealthResult(
        result_schema_id=result_schema_id,
        result_sha256=hashlib.sha256(result_bytes).hexdigest(),
        semantic_outcome="passed",
    )
