"""Typed client helper for root-enrolled offline package sets.

The caller names only an enrolled set and service generation. All runtime,
wheel, destination, and installer choices remain in the signed root manifest.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Callable

from .types import (
    AuthorityDenied, BrokeredEffectResponse, EffectAuthorization,
    canonical_bytes, canonical_digest,
)

_ID = re.compile(r"[A-Za-z0-9_.-]{1,128}\Z")
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_CORAL_WHEELS = (
    "be198b7dc4401204be54a15884d9e336389790eb707439524540f5a9329fdd02",
    "d5241e0a80d808d70546c697135da2c613f30e28251ff8307eb72ba696945764",
)


@dataclass(frozen=True, slots=True)
class PackageSetInstallReceipt:
    package_set_id: str
    manifest_sha256: str
    enrollment_id: str
    generation: str
    runtime_build_attestation_digest: str
    wheel_sha256: tuple[str, str]
    installed_tree_sha256: str
    status: str
    broker_receipt_id: str


def package_set_request(*, package_set_id: str, manifest_sha256: str,
                        enrollment_id: str, generation: str) -> tuple[str, bytes, str]:
    """Return fixed target, canonical payload, and digest for grant issuance."""
    for value, name in ((package_set_id, "package set ID"),
                        (enrollment_id, "enrollment ID"), (generation, "generation")):
        if not isinstance(value, str) or not _ID.fullmatch(value):
            raise AuthorityDenied("package-set.binding", f"{name} is invalid")
    if not isinstance(manifest_sha256, str) or not _SHA.fullmatch(manifest_sha256):
        raise AuthorityDenied("package-set.binding", "package-set manifest digest is invalid")
    target = f"package-set:{package_set_id}:{manifest_sha256}"
    payload = canonical_bytes({"schema": 1, "package_set_id": package_set_id,
                              "enrollment_id": enrollment_id, "generation": generation})
    return target, payload, canonical_digest(payload)


def install_package_set(client: Any, authorization: EffectAuthorization, *,
                        package_set_id: str, manifest_sha256: str,
                        enrollment_id: str, generation: str,
                        timeout: float = 600.0,
                        cancelled: Callable[[], bool] | None = None) -> PackageSetInstallReceipt:
    """Consume a host grant for one signed package set and validate its receipt."""
    if not isinstance(authorization, EffectAuthorization):
        raise AuthorityDenied("package-set.binding", "host-issued package-set grant is required")
    target, _payload, digest = package_set_request(
        package_set_id=package_set_id, manifest_sha256=manifest_sha256,
        enrollment_id=enrollment_id, generation=generation,
    )
    if (authorization.target != target or authorization.request_digest != digest
            or authorization.operation != "package.install"
            or authorization.enrollment_id != enrollment_id
            or authorization.generation != generation):
        raise AuthorityDenied("package-set.binding", "package-set request does not match its host grant")
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 0 < timeout <= 600:
        raise AuthorityDenied("package-set.bounds", "package-set timeout exceeds its fixed bound")
    if cancelled is not None and cancelled():
        raise AuthorityDenied("effect.cancelled", "package-set install was cancelled before dispatch")
    client_method = getattr(client, "install_package_set", None)
    if not callable(client_method):
        raise AuthorityDenied("package-set.client", "typed package-set authority client is unavailable")
    response = client_method(
        authorization, package_set_id=package_set_id,
        manifest_sha256=manifest_sha256, enrollment_id=enrollment_id,
        generation=generation, timeout=min(float(timeout), 600.0),
        cancelled=cancelled,
    )
    return parse_package_set_receipt(
        response, package_set_id=package_set_id,
        manifest_sha256=manifest_sha256, enrollment_id=enrollment_id,
        generation=generation,
    )


def parse_package_set_receipt(response: BrokeredEffectResponse, *,
                              package_set_id: str, manifest_sha256: str,
                              enrollment_id: str, generation: str) -> PackageSetInstallReceipt:
    """Validate the exact broker receipt; it carries no filesystem path."""
    if not isinstance(response, BrokeredEffectResponse) or response.status != 200:
        raise AuthorityDenied("package-set.receipt", "package-set install did not return success")
    try:
        value = json.loads(response.body)
    except (TypeError, ValueError, UnicodeDecodeError):
        raise AuthorityDenied("package-set.receipt", "package-set receipt is malformed") from None
    expected = {
        "package_set_id": package_set_id,
        "manifest_sha256": manifest_sha256,
        "enrollment_id": enrollment_id,
        "generation": generation,
        "wheel_sha256": list(_CORAL_WHEELS),
        "status": "installed",
    }
    required = set(expected) | {"runtime_build_attestation_digest", "installed_tree_sha256"}
    if not isinstance(value, dict) or set(value) != required or any(value.get(k) != v for k, v in expected.items()):
        raise AuthorityDenied("package-set.receipt", "package-set receipt does not match the enrolled set")
    runtime_digest = value["runtime_build_attestation_digest"]
    tree_digest = value["installed_tree_sha256"]
    if (not isinstance(runtime_digest, str) or not _SHA.fullmatch(runtime_digest)
            or not isinstance(tree_digest, str) or not _SHA.fullmatch(tree_digest)
            or not isinstance(response.receipt_id, str) or not response.receipt_id):
        raise AuthorityDenied("package-set.receipt", "package-set receipt digest is invalid")
    return PackageSetInstallReceipt(
        package_set_id, manifest_sha256, enrollment_id, generation,
        runtime_digest, tuple(_CORAL_WHEELS), tree_digest, "installed",
        response.receipt_id,
    )
