"""Selection-only client for the enrolled ARM64 native build recipes.

The root broker owns source staging, compiler argv, output custody, target
fact inspection and receipt signing. This adapter can name only one of the
two reviewed builds and accepts only a fresh broker-returned output receipt.
It deliberately does not run a local compiler or accept paths from callers.
"""
from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import dataclass
from typing import Any, Callable, Mapping

from hermes_installer.authority.types import AuthorityDenied, BrokeredEffectResponse

COLIBRI_BUILD = "colibri-source-build-v1"
CORAL_CPYTHON_BUILD = "coral-cpython39-source-build-v1"
_BUILD_SOURCE_PINS = {
    COLIBRI_BUILD: ("colibri-source", "7cc79d4bfdc851efb27b67295ceac1370312b5cd414d869887715d30b2d13174"),
    CORAL_CPYTHON_BUILD: ("coral-python39-source", "00e07d7c0f2f0cc002432d1ee84d2a40dae404a99303e3f97701c10966c91834"),
}
_BUILD_TARGETS = {
    COLIBRI_BUILD: "colibri-source-build:start",
    CORAL_CPYTHON_BUILD: "coral-cpython-build:start",
}
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_RECEIPT_FIELDS = {
    "schema", "receipt_id", "build_target_id", "build_generation",
    "service_generation_digest", "recipe_digest", "source_artifact_id",
    "source_sha256", "toolchain_artifact_id", "toolchain_sha256",
    "builder_artifact_id", "builder_sha256", "process_identity_digest",
    "terminal_success_record_id", "output_records", "issued_monotonic",
    "expires_monotonic", "receipt_digest", "root_signature",
}


@dataclass(frozen=True, slots=True)
class BuiltOutput:
    relative_path: str
    kind: str
    sha256: str
    size_bytes: int
    executable_role: str
    observed_target_facts: Mapping[str, Any]
    tree_file_manifest_sha256: str | None


@dataclass(frozen=True, slots=True)
class NativeBuildReceipt:
    operation_id: str
    target_id: str
    enrollment_id: str
    generation: str
    source_artifact_id: str
    source_sha256: str
    toolchain_sha256: str
    builder_sha256: str
    recipe_digest: str
    receipt_digest: str
    root_signature: str
    issued_monotonic: float
    expires_monotonic: float
    outputs: tuple[BuiltOutput, ...]
    broker_receipt_id: str


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _SHA.fullmatch(value):
        raise AuthorityDenied("model-build.receipt", f"root build receipt has an invalid {label}")
    return value


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _expected_outputs(operation_id: str) -> Mapping[str, tuple[str, str, Mapping[str, Any]]]:
    if operation_id == COLIBRI_BUILD:
        return {
            "c/colibri": ("file", "colibri-engine", {
            "elf_class": 64, "elf_machine": "EM_AARCH64", "os": "linux",
            "required_runtime_dependencies": ["libgomp.so.1", "libm", "libc"],
            "instruction_policy": "actual target compatible ARM64 flags; no x86 default or unmeasured CPUflags",
        }),
        }
    return {
        "runtime/bin/python3.9": ("file", "coral-cpython39", {
            "elf_class": 64, "elf_machine": "EM_AARCH64", "python_version": "3.9.25",
            "soabi": "cpython-39-aarch64-linux-gnu", "debug": False,
            "glibc_minimum": "2.34 for selected TFLite wheel",
        }),
        "runtime/lib/python3.9": ("tree", "cpython-stdlib-and-extension-closure", {
            "python_version": "3.9.25", "target": "linux-aarch64",
        }),
    }


def _version_tuple(value: Any, label: str) -> tuple[int, ...]:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9]+(?:\.[0-9]+){1,3}", value):
        raise AuthorityDenied("model-build.target-facts", f"root output has an invalid {label}")
    return tuple(int(part) for part in value.split("."))


def _validate_observed_facts(operation_id: str, item: Mapping[str, Any]) -> None:
    name = item["relative_path"]
    facts = item["observed_target_facts"]
    spec = _expected_outputs(operation_id).get(name)
    if spec is None or item["kind"] != spec[0] or item["executable_role"] != spec[1]:
        raise AuthorityDenied("model-build.target-facts", "native output role differs from its reviewed contract")
    if not isinstance(facts, dict) or any(facts.get(key) != expected for key, expected in spec[2].items()):
        raise AuthorityDenied("model-build.target-facts", "native output does not meet the reviewed target facts")
    if operation_id == COLIBRI_BUILD:
        closure = facts.get("resolved_dependency_closure")
        if (not isinstance(closure, list) or not closure
                or not {row.get("name") for row in closure if isinstance(row, dict)}
                    >= {"libgomp.so.1", "libm", "libc"}):
            raise AuthorityDenied("model-build.target-facts", "Colibri runtime dependency closure is incomplete")
        for row in closure:
            if (not isinstance(row, dict) or set(row) != {"name", "path", "sha256", "owner_uid", "mode"}
                    or not isinstance(row["name"], str) or not row["name"]
                    or not isinstance(row["path"], str) or not row["path"].startswith("/")
                    or type(row["owner_uid"]) is not int or row["owner_uid"] < 0):
                raise AuthorityDenied("model-build.target-facts", "Colibri dependency custody facts are incomplete")
            _digest(row["sha256"], "resolved runtime dependency")
        for row in closure:
            if type(row.get("mode")) is not int or row["mode"] & 0o111:
                raise AuthorityDenied("model-build.target-facts", "Colibri dependency mode is not a reviewed runtime file")
    elif name == "runtime/bin/python3.9":
        minimum = (2, 34)
        if facts.get("glibc_minimum") != "2.34 for selected TFLite wheel":
            raise AuthorityDenied("model-build.target-facts", "selected TFLite wheel glibc constraint changed")
        observed = _version_tuple(facts.get("observed_glibc_version"), "observed glibc version")
        if observed < minimum:
            raise AuthorityDenied("model-build.target-facts", "target glibc does not satisfy the pinned wheel ABI")
    else:
        extensions = facts.get("native_extension_manifest")
        if (facts.get("all_native_extensions") != "ELF64EM_AARCH64, actual dependency closure verified"
                or not isinstance(extensions, list) or not extensions):
            raise AuthorityDenied("model-build.target-facts", "CPython native extension closure is unverified")
        for extension in extensions:
            if (not isinstance(extension, dict) or set(extension) != {"path", "sha256", "dependencies"}
                    or not isinstance(extension["path"], str) or extension["path"].startswith("/")
                    or ".." in extension["path"].split("/")
                    or not isinstance(extension["dependencies"], list)):
                raise AuthorityDenied("model-build.target-facts", "CPython extension record is malformed")
            _digest(extension["sha256"], "native extension")
            for dependency in extension["dependencies"]:
                if (not isinstance(dependency, dict)
                        or set(dependency) != {"name", "path", "sha256"}
                        or not isinstance(dependency["name"], str)
                        or not isinstance(dependency["path"], str)
                        or not dependency["path"].startswith("/")):
                    raise AuthorityDenied("model-build.target-facts", "CPython dependency closure record is malformed")
                _digest(dependency["sha256"], "native dependency")


def parse_native_build_receipt(response: BrokeredEffectResponse, *, operation_id: str,
                               enrollment_id: str, generation: str,
                               now: Callable[[], float] = time.monotonic) -> NativeBuildReceipt:
    """Check a fixed recipe's complete root receipt and target facts.

    Signature verification and output custody belong to the root broker; this
    checks its authenticated response binding and refuses incomplete facts.
    """
    if operation_id not in _BUILD_TARGETS:
        raise AuthorityDenied("model-build.selection", "native build operation is not enrolled")
    if not isinstance(response, BrokeredEffectResponse) or response.status != 200:
        raise AuthorityDenied("model-build.receipt", "root did not report successful terminal build completion")
    try:
        value = json.loads(response.body)
    except (TypeError, ValueError, UnicodeDecodeError):
        raise AuthorityDenied("model-build.receipt", "root build receipt is malformed") from None
    if not isinstance(value, dict) or set(value) != _RECEIPT_FIELDS or value.get("schema") != 1:
        raise AuthorityDenied("model-build.receipt", "root build receipt fields are incomplete or unexpected")
    source_id, source_sha = _BUILD_SOURCE_PINS[operation_id]
    target = _BUILD_TARGETS[operation_id]
    if (value.get("build_target_id") != target or value.get("build_generation") != generation
            or value.get("source_artifact_id") != source_id or value.get("source_sha256") != source_sha
            or value.get("receipt_id") != response.receipt_id
            or not isinstance(response.receipt_id, str) or not response.receipt_id):
        raise AuthorityDenied("model-build.binding", "build receipt does not match the selected pinned source and generation")
    for key in ("service_generation_digest", "recipe_digest", "source_sha256", "toolchain_sha256",
                "builder_sha256", "process_identity_digest", "receipt_digest"):
        _digest(value.get(key), key)
    for key in ("toolchain_artifact_id", "builder_artifact_id", "terminal_success_record_id",
                "root_signature"):
        if not isinstance(value.get(key), str) or not value[key] or len(value[key]) > 512:
            raise AuthorityDenied("model-build.receipt", f"root build receipt has an invalid {key}")
    issued, expires = value.get("issued_monotonic"), value.get("expires_monotonic")
    current = now()
    if (type(issued) not in (int, float) or type(expires) not in (int, float)
            or not 0 < issued <= current < expires or expires - issued > 600):
        raise AuthorityDenied("model-build.expired", "root build receipt is expired or outside its bounded lease")
    records = value.get("output_records")
    expected = _expected_outputs(operation_id)
    if not isinstance(records, list) or len(records) != len(expected):
        raise AuthorityDenied("model-build.outputs", "root build receipt does not contain the exact enrolled output set")
    outputs: list[BuiltOutput] = []
    for item in records:
        fields = {"relative_path", "kind", "sha256", "size_bytes", "executable_role",
                  "observed_target_facts", "tree_file_manifest_sha256"}
        if not isinstance(item, dict) or set(item) != fields:
            raise AuthorityDenied("model-build.outputs", "root build output record is malformed")
        name = item["relative_path"]
        if name not in expected:
            raise AuthorityDenied("model-build.outputs", "root output path is outside the reviewed finite set")
        _validate_observed_facts(operation_id, item)
        _digest(item["sha256"], "output SHA-256")
        if type(item["size_bytes"]) is not int or item["size_bytes"] < 1:
            raise AuthorityDenied("model-build.outputs", "root build output size is invalid")
        maximum_size = 64 * 1024 * 1024 if operation_id == COLIBRI_BUILD or name.endswith("python3.9") else 256 * 1024 * 1024
        if item["size_bytes"] > maximum_size:
            raise AuthorityDenied("model-build.outputs", "root output exceeds its reviewed size bound")
        tree_digest = item["tree_file_manifest_sha256"]
        if item["kind"] == "tree":
            _digest(tree_digest, "tree manifest SHA-256")
        elif tree_digest is not None:
            raise AuthorityDenied("model-build.outputs", "file output unexpectedly carries a tree manifest")
        outputs.append(BuiltOutput(name, item["kind"], item["sha256"], item["size_bytes"],
                                   item["executable_role"], dict(facts), tree_digest))
    if {item.relative_path for item in outputs} != set(expected):
        raise AuthorityDenied("model-build.outputs", "root build output set is incomplete")
    unsigned = {key: val for key, val in value.items() if key not in {"receipt_digest", "root_signature"}}
    computed = hashlib.sha256(_canonical(unsigned)).hexdigest()
    if computed != value["receipt_digest"]:
        raise AuthorityDenied("model-build.receipt", "root receipt digest does not match its fields")
    return NativeBuildReceipt(operation_id, target, enrollment_id, generation,
        source_id, source_sha, value["toolchain_sha256"], value["builder_sha256"],
        value["recipe_digest"], value["receipt_digest"], value["root_signature"],
        float(issued), float(expires), tuple(outputs), response.receipt_id)


def run_fixed_native_build(authority_client: Any, *, operation_id: str,
                           enrollment_id: str, generation: str,
                           timeout: float = 600,
                           cancelled: Callable[[], bool] | None = None,
                           now: Callable[[], float] = time.monotonic) -> NativeBuildReceipt:
    """Ask the protected root executor to build exactly one enrolled target."""
    if operation_id not in _BUILD_TARGETS:
        raise ValueError("only the two fixed enrolled model build recipes may be selected")
    if (not isinstance(enrollment_id, str) or not enrollment_id
            or not isinstance(generation, str) or not generation
            or isinstance(timeout, bool) or not isinstance(timeout, (int, float))
            or not 0 < timeout <= 600):
        raise ValueError("selected enrollment, generation, and bounded build timeout are required")
    execute = getattr(authority_client, "start_enrolled_build_operation", None)
    if not callable(execute):
        raise AuthorityDenied("model-build.client", "typed terminal build client is unavailable")
    if cancelled is not None and cancelled():
        raise AuthorityDenied("model-build.cancelled", "native build was cancelled before dispatch")
    response = execute(enrollment_id=enrollment_id, generation=generation,
        operation_id=operation_id, parameters={}, timeout=min(float(timeout), 600),
        cancelled=cancelled)
    return parse_native_build_receipt(response, operation_id=operation_id,
        enrollment_id=enrollment_id, generation=generation, now=now)
