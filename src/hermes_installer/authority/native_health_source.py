"""Source-owned health definition for the fixed Hermes native worker.

The health definition is an input to the signed worker recipe.  It contains
only held installer-release fixture/schema identities; it deliberately has no
native output, active generation, or future publication hash.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Mapping

from .types import AuthorityDenied, canonical_bytes

_OPAQUE = re.compile(r"[A-Za-z0-9_-]{32,128}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_HEALTH_OPERATION = "hermes-agent-health-v1"
_PARAMETER_SCHEMA = "no-caller-parameters-v1"

# These are the five finite release members already reviewed by v159/v163.
# They are used to check an issuer-held receipt, never to stand in for one.
_MEMBERS = {
    "hermes-agent-health-fixture-v1": (
        "fixtures/native-health/recipe.json",
        "ba7486d3070f725d125ed0e8c42aa986969bc8a597c2473024705d6fd8ac05a7", 845),
    "hermes-agent-health-request-v1": (
        "fixtures/native-health/request.txt",
        "a8ff376fd03484db8c7dc0af141e8e894671467cdc5833ee50a08571d0ee3e7c", 182),
    "hermes-agent-health-seed-v1": (
        "fixtures/native-health/seed-value.txt",
        "b7cf82519f80550d09ae0ef0f183ad6be9543cc4c15873982cea91819e9a962a", 67),
    "hermes-agent-health-expected-result-v1": (
        "fixtures/native-health/expected-tool-result.json",
        "23a5b879d3b43b985c468917f34bdd7b592ab35cfd72e767287f16764436523a", 240),
    "hermes-agent-health-overlay-read-result-v1": (
        "fixtures/native-health/tool-result.schema.json",
        "6b89864f728e6e3e65b34d935c486bad0bc3c0a57bcee92dde5eec33fb1286f5", 526),
}


def _strict_json(raw: bytes) -> Any:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        output: dict[str, Any] = {}
        for key, value in items:
            if key in output:
                raise ValueError("duplicate JSON member")
            output[key] = value
        return output

    return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
                      parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("nonfinite JSON")))


@dataclass(frozen=True, slots=True, repr=False)
class RootPreparedNativeHealthSourceDefinition:
    """Sealed-to-issuer projection of source-held v159 health inputs."""

    operation_id: str
    parameter_schema_id: str
    parameter_schema_sha256: str
    health_recipe_artifact_id: str
    health_recipe_sha256: str
    health_recipe_receipt_handle: str
    health_request_artifact_id: str
    health_request_sha256: str
    health_request_receipt_handle: str
    health_seed_artifact_id: str
    health_seed_sha256: str
    health_seed_receipt_handle: str
    health_expected_result_artifact_id: str
    health_expected_result_sha256: str
    health_expected_result_receipt_handle: str
    health_result_schema_id: str
    health_result_schema_sha256: str
    health_result_schema_receipt_handle: str
    health_action_id: str
    provider_required: bool
    _receipts: tuple[Any, ...] = field(repr=False, compare=False)
    _issuer: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        for name in ("parameter_schema_sha256", "health_recipe_sha256",
                     "health_request_sha256", "health_seed_sha256",
                     "health_expected_result_sha256", "health_result_schema_sha256"):
            if not _SHA256.fullmatch(getattr(self, name)):
                raise ValueError(f"health source {name} is malformed")
        for name in ("health_recipe_receipt_handle", "health_request_receipt_handle",
                     "health_seed_receipt_handle", "health_expected_result_receipt_handle",
                     "health_result_schema_receipt_handle"):
            if not _OPAQUE.fullmatch(getattr(self, name)):
                raise ValueError(f"health source {name} is malformed")
        if (self.operation_id != _HEALTH_OPERATION or self.parameter_schema_id != _PARAMETER_SCHEMA
                or self.health_recipe_artifact_id != "hermes-agent-health-fixture-v1"
                or self.health_request_artifact_id != "hermes-agent-health-request-v1"
                or self.health_seed_artifact_id != "hermes-agent-health-seed-v1"
                or self.health_expected_result_artifact_id != "hermes-agent-health-expected-result-v1"
                or self.health_result_schema_id != "hermes-agent-health-overlay-read-result-v1"
                or not isinstance(self.health_action_id, str) or not self.health_action_id
                or type(self.provider_required) is not bool
                or len(self._receipts) != 5 or self._issuer is None):
            raise ValueError("health source definition is not the exact fixed fixture recipe")

    @classmethod
    def from_held_release_members(cls, receipts: tuple[Any, ...]) -> "RootPreparedNativeHealthSourceDefinition":
        """Parse the fixed recipe only from five exact release-held receipts."""
        from .bootstrap_runtime_factory import RootInstalledReleaseMemberReceipt
        if type(receipts) is not tuple or len(receipts) != len(_MEMBERS):
            raise AuthorityDenied("native.health.source", "exact held health fixture member set is required")
        by_id: dict[str, Any] = {}
        body_by_id: dict[str, bytes] = {}
        session_id: str | None = None
        release_commit: str | None = None
        deployment_receipt_sha256: str | None = None
        for receipt in receipts:
            if type(receipt) is not RootInstalledReleaseMemberReceipt:
                raise AuthorityDenied("native.health.source", "health fixture member lacks an installed-release receipt")
            expected = _MEMBERS.get(receipt.artifact_id)
            if (expected is None or receipt.artifact_id in by_id
                    or receipt.relative_path != expected[0] or receipt.sha256 != expected[1]
                    or receipt.size_bytes != expected[2]
                    or receipt.role != "native-health-fixture"):
                raise AuthorityDenied("native.health.source", "health fixture receipt differs from its fixed release member")
            if session_id is None:
                session_id = receipt._session_id
                release_commit = receipt.release_commit
                deployment_receipt_sha256 = receipt.deployment_receipt_sha256
            elif (receipt._session_id != session_id
                  or receipt.release_commit != release_commit
                  or receipt.deployment_receipt_sha256 != deployment_receipt_sha256):
                raise AuthorityDenied("native.health.source", "health fixture receipts do not share one held release")
            body = receipt.read_current()
            if (not isinstance(body, bytes) or len(body) != expected[2]
                    or hashlib.sha256(body).hexdigest() != expected[1]):
                raise AuthorityDenied("native.health.source", "held health fixture bytes changed")
            by_id[receipt.artifact_id] = receipt
            body_by_id[receipt.artifact_id] = body
        if set(by_id) != set(_MEMBERS):
            raise AuthorityDenied("native.health.source", "held health fixture set is incomplete")

        recipe = _strict_json(body_by_id["hermes-agent-health-fixture-v1"])
        expected_recipe_keys = {
            "action_id", "artifact_id", "fixture_id", "provider", "request_asset",
            "result_schema_asset", "result_schema_id", "result_source_asset", "schema",
            "seed", "tool_name",
        }
        if (type(recipe) is not dict or set(recipe) != expected_recipe_keys
                or recipe["schema"] != 1 or recipe["artifact_id"] != "hermes-agent-health-fixture-v1"
                or recipe["fixture_id"] != _HEALTH_OPERATION
                or recipe["request_asset"] != "request.txt"
                or recipe["result_schema_asset"] != "tool-result.schema.json"
                or recipe["result_source_asset"] != "expected-tool-result.json"
                or recipe["result_schema_id"] != "hermes-agent-health-overlay-read-result-v1"
                or recipe["tool_name"] != "resource_overlay_read"):
            raise AuthorityDenied("native.health.source", "held recipe does not describe the reviewed health operation")
        provider = recipe["provider"]
        if (type(provider) is not dict
                or set(provider) != {"additional_budget", "required", "route_class"}
                or type(provider["required"]) is not bool
                or provider["required"] is not True
                or type(provider["additional_budget"]) is not int
                or provider["additional_budget"] != 0
                or provider["route_class"] != "private-zero-additional-budget"):
            raise AuthorityDenied("native.health.source", "health provider requirement differs from the reviewed recipe")
        seed = recipe["seed"]
        if (type(seed) is not dict
                or set(seed) != {"cleanup_policy", "conflict_policy", "record_id", "revision",
                                 "sha256", "size_bytes", "source_asset"}
                or seed["cleanup_policy"] != "journal-owned-fixture-generation-only"
                or seed["conflict_policy"] != "deny-preexisting-unowned-record"
                or seed["record_id"] != "hermes-health-probe-v1"
                or seed["source_asset"] != "seed-value.txt"
                or seed["sha256"] != by_id["hermes-agent-health-seed-v1"].sha256
                or seed["size_bytes"] != by_id["hermes-agent-health-seed-v1"].size_bytes):
            raise AuthorityDenied("native.health.source", "health seed metadata does not join the held seed member")
        schema = _strict_json(body_by_id["hermes-agent-health-overlay-read-result-v1"])
        expected_schema = {
            "additionalProperties": False,
            "properties": {
                "found": {"const": True, "type": "boolean"},
                "record_id": {"const": "hermes-health-probe-v1", "maxLength": 96, "type": "string"},
                "revision": {"const": seed["revision"], "pattern": "^[a-f0-9]{64}$", "type": "string"},
                "value_base64": {"const": "SGVybWVzIG5hdGl2ZSBoZWFsdGggcHJvYmUgdjE6IGxvY2FsIHNlbGVjdGVkIG92ZXJsYXkgaXMgcmVhZGFibGUuCg==", "maxLength": 1398104, "type": "string"},
            },
            "required": ["found", "record_id", "revision", "value_base64"],
            "type": "object",
        }
        if schema != expected_schema:
            raise AuthorityDenied("native.health.source", "held result schema differs from the fixed health semantics")
        expected_result = _strict_json(body_by_id["hermes-agent-health-expected-result-v1"])
        if (type(expected_result) is not dict
                or set(expected_result) != {"found", "record_id", "revision", "value_base64"}
                or expected_result != {
                    "found": True, "record_id": "hermes-health-probe-v1",
                    "revision": seed["revision"],
                    "value_base64": schema["properties"]["value_base64"]["const"],
                }):
            raise AuthorityDenied("native.health.source", "expected health result does not match its held schema")
        request = body_by_id["hermes-agent-health-request-v1"]
        if not request or b"\x00" in request:
            raise AuthorityDenied("native.health.source", "held health request is empty or malformed")
        empty_schema = {"id": _PARAMETER_SCHEMA, "fields": []}
        handles = {artifact_id: by_id[artifact_id].receipt_handle for artifact_id in _MEMBERS}
        if any(not isinstance(handle, str) or not _OPAQUE.fullmatch(handle)
               for handle in handles.values()):
            raise AuthorityDenied("native.health.source", "health fixture receipt handle is invalid")
        issuer = object()
        return cls(
            operation_id=_HEALTH_OPERATION,
            parameter_schema_id=_PARAMETER_SCHEMA,
            parameter_schema_sha256=hashlib.sha256(canonical_bytes(empty_schema)).hexdigest(),
            health_recipe_artifact_id="hermes-agent-health-fixture-v1",
            health_recipe_sha256=by_id["hermes-agent-health-fixture-v1"].sha256,
            health_recipe_receipt_handle=handles["hermes-agent-health-fixture-v1"],
            health_request_artifact_id="hermes-agent-health-request-v1",
            health_request_sha256=by_id["hermes-agent-health-request-v1"].sha256,
            health_request_receipt_handle=handles["hermes-agent-health-request-v1"],
            health_seed_artifact_id="hermes-agent-health-seed-v1",
            health_seed_sha256=by_id["hermes-agent-health-seed-v1"].sha256,
            health_seed_receipt_handle=handles["hermes-agent-health-seed-v1"],
            health_expected_result_artifact_id="hermes-agent-health-expected-result-v1",
            health_expected_result_sha256=by_id["hermes-agent-health-expected-result-v1"].sha256,
            health_expected_result_receipt_handle=handles["hermes-agent-health-expected-result-v1"],
            health_result_schema_id=recipe["result_schema_id"],
            health_result_schema_sha256=by_id["hermes-agent-health-overlay-read-result-v1"].sha256,
            health_result_schema_receipt_handle=handles["hermes-agent-health-overlay-read-result-v1"],
            health_action_id=recipe["action_id"], provider_required=provider["required"],
            _receipts=tuple(by_id[key] for key in sorted(by_id)), _issuer=issuer,
        )

    def public_projection(self) -> Mapping[str, Any]:
        return MappingProxyType({
            "schema": 1,
            "operation_id": self.operation_id,
            "parameter_schema_id": self.parameter_schema_id,
            "parameter_schema_sha256": self.parameter_schema_sha256,
            "health_recipe_artifact_id": self.health_recipe_artifact_id,
            "health_recipe_sha256": self.health_recipe_sha256,
            "health_recipe_receipt_handle": self.health_recipe_receipt_handle,
            "health_request_artifact_id": self.health_request_artifact_id,
            "health_request_sha256": self.health_request_sha256,
            "health_request_receipt_handle": self.health_request_receipt_handle,
            "health_seed_artifact_id": self.health_seed_artifact_id,
            "health_seed_sha256": self.health_seed_sha256,
            "health_seed_receipt_handle": self.health_seed_receipt_handle,
            "health_expected_result_artifact_id": self.health_expected_result_artifact_id,
            "health_expected_result_sha256": self.health_expected_result_sha256,
            "health_expected_result_receipt_handle": self.health_expected_result_receipt_handle,
            "health_result_schema_id": self.health_result_schema_id,
            "health_result_schema_sha256": self.health_result_schema_sha256,
            "health_result_schema_receipt_handle": self.health_result_schema_receipt_handle,
            "health_action_id": self.health_action_id,
            "provider_required": self.provider_required,
        })

    @property
    def definition_sha256(self) -> str:
        return hashlib.sha256(canonical_bytes(dict(self.public_projection()))).hexdigest()

    def verify_current(self) -> bool:
        from .bootstrap_runtime_factory import RootInstalledReleaseMemberReceipt
        if self._issuer is None or len(self._receipts) != 5:
            return False
        for receipt in self._receipts:
            if type(receipt) is not RootInstalledReleaseMemberReceipt:
                return False
            expected = _MEMBERS.get(receipt.artifact_id)
            if (expected is None or receipt.relative_path != expected[0]
                    or receipt.sha256 != expected[1] or receipt.size_bytes != expected[2]
                    or receipt.role != "native-health-fixture"):
                return False
            body = receipt.read_current()
            if len(body) != expected[2] or hashlib.sha256(body).hexdigest() != expected[1]:
                return False
        return True
