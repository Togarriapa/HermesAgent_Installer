from __future__ import annotations

import hashlib
import json

from hermes_installer.authority.owner_overlay_capture_schemas import (
    CAPTURE_SCHEMAS, INVOCATION_SCHEMA_ID, RESULT_SCHEMA_ID,
    INVOCATION_SCHEMA_BYTES, RESULT_SCHEMA_BYTES,
    INVOCATION_SCHEMA_SHA256, RESULT_SCHEMA_SHA256,
    verify_held_capture_schema,
)
from hermes_installer.authority.bootstrap_runtime_factory import RootReleaseModuleReceipt


def test_capture_schemas_are_canonical_and_match_v185_closed_fields():
    invocation = json.loads(INVOCATION_SCHEMA_BYTES)
    result = json.loads(RESULT_SCHEMA_BYTES)
    assert tuple(invocation["required"]) == (
        "schema", "invocation_handle", "observed_call_handle", "response_observation_handle",
        "response_receipt_handle", "turn_handle", "native_request_handle", "registration_id",
        "method", "arguments_sha256", "canonical_arguments_b64", "parent_source_receipt_handles",
    )
    assert tuple(result["required"]) == (
        "schema", "invocation_handle", "registration_id", "result_schema_id", "result_sha256",
        "canonical_result_b64", "parent_source_receipt_handles",
    )
    for body, schema_id, digest in (
        (INVOCATION_SCHEMA_BYTES, INVOCATION_SCHEMA_ID, INVOCATION_SCHEMA_SHA256),
        (RESULT_SCHEMA_BYTES, RESULT_SCHEMA_ID, RESULT_SCHEMA_SHA256),
    ):
        parsed = json.loads(body)
        assert json.dumps(parsed, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False, allow_nan=False).encode() == body
        assert hashlib.sha256(body).hexdigest() == digest
        assert CAPTURE_SCHEMAS[schema_id] == (body, digest)
    assert invocation["additionalProperties"] is False
    assert result["additionalProperties"] is False


def test_capture_schema_reader_requires_exact_current_held_release_bytes(tmp_path):
    source = (__import__("pathlib").Path(__file__).parents[2]
              / "src/hermes_installer/authority/owner_overlay_capture_schemas.py").read_bytes()

    class _HeldSession:
        def __init__(self, body):
            self.body = body

        def _read_release_member_receipt(self, _receipt):
            return self.body

    session = _HeldSession(source)
    receipt = RootReleaseModuleReceipt(
        "installer-module:hermes_installer.authority.owner_overlay_capture_schemas",
        "lib/python/hermes_installer/authority/owner_overlay_capture_schemas.py",
        hashlib.sha256(source).hexdigest(), len(source), "a" * 40, "b" * 64,
        "c" * 43, "setup-session", "session-seal", session, "generation",
    )
    body, digest = verify_held_capture_schema(receipt, INVOCATION_SCHEMA_ID)
    assert body == INVOCATION_SCHEMA_BYTES
    assert digest == INVOCATION_SCHEMA_SHA256
    session.body = source + b"# changed\n"
    import pytest
    with pytest.raises(ValueError):
        verify_held_capture_schema(receipt, INVOCATION_SCHEMA_ID)
