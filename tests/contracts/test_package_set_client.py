from __future__ import annotations

import json
import unittest
from unittest.mock import Mock

from hermes_installer.authority.package_sets import (
    install_package_set, package_set_request, parse_package_set_receipt,
)
from hermes_installer.authority.types import (
    AuthorityDenied, BrokeredEffectResponse, EffectAuthorization, Sensitivity,
)


MANIFEST = "1" * 64
RUNTIME = "2" * 64
TREE = "3" * 64
WHEELS = (
    "be198b7dc4401204be54a15884d9e336389790eb707439524540f5a9329fdd02",
    "d5241e0a80d808d70546c697135da2c613f30e28251ff8307eb72ba696945764",
)


def receipt(**updates):
    value = {
        "package_set_id": "coral-cp39-runtime-v1",
        "manifest_sha256": MANIFEST,
        "enrollment_id": "pi-main",
        "generation": "generation-1",
        "runtime_build_attestation_digest": RUNTIME,
        "wheel_sha256": list(WHEELS),
        "installed_tree_sha256": TREE,
        "status": "installed",
    }
    value.update(updates)
    return BrokeredEffectResponse(200, json.dumps(value).encode(),
                                  {"content-type": "application/json"}, "package-install-1")


def grant(*, target=None, digest=None):
    target = target or f"package-set:coral-cp39-runtime-v1:{MANIFEST}"
    digest = digest or package_set_request(
        package_set_id="coral-cp39-runtime-v1", manifest_sha256=MANIFEST,
        enrollment_id="pi-main", generation="generation-1",
    )[2]
    return EffectAuthorization(
        principal_id="installer", profile_id="profile", namespace_id="ns", uid=1001,
        purpose="hermes-bootstrap", sensitivity=Sensitivity.PRIVATE,
        trace_id="trace", policy_revision="policy-1", lineage_hash="a" * 64,
        capability="hermes-bootstrap", intent_id="install-set", target=target,
        recipient=None, request_digest=digest, retry_index=0,
        issued_at_monotonic=1.0, monotonic_expires_at=100.0,
        grant_id="grant-1", nonce="nonce-1", context_digest="b" * 64,
        signature="signature", enrollment_id="pi-main", generation="generation-1",
        operation="package.install",
    )


class PackageSetClientTests(unittest.TestCase):
    def test_request_is_fixed_and_canonical(self):
        target, payload, digest = package_set_request(
            package_set_id="coral-cp39-runtime-v1", manifest_sha256=MANIFEST,
            enrollment_id="pi-main", generation="generation-1",
        )
        self.assertEqual(target, f"package-set:coral-cp39-runtime-v1:{MANIFEST}")
        self.assertEqual(json.loads(payload), {
            "schema": 1, "package_set_id": "coral-cp39-runtime-v1",
            "enrollment_id": "pi-main", "generation": "generation-1",
        })
        self.assertEqual(len(digest), 64)
        with self.assertRaises(AuthorityDenied):
            package_set_request(package_set_id="../escape", manifest_sha256=MANIFEST,
                                enrollment_id="pi-main", generation="generation-1")

    def test_install_dispatches_only_bound_fixed_payload(self):
        client = Mock()
        client.install_package_set.return_value = receipt()
        result = install_package_set(
            client, grant(), package_set_id="coral-cp39-runtime-v1",
            manifest_sha256=MANIFEST, enrollment_id="pi-main", generation="generation-1",
        )
        self.assertEqual(result.status, "installed")
        self.assertEqual(result.wheel_sha256, WHEELS)
        client.install_package_set.assert_called_once()
        kwargs = client.install_package_set.call_args.kwargs
        self.assertEqual(kwargs["manifest_sha256"], MANIFEST)
        self.assertEqual(kwargs["generation"], "generation-1")
        self.assertEqual(kwargs["timeout"], 600.0)

    def test_wrong_generation_grant_rejected_before_dispatch(self):
        client = Mock()
        with self.assertRaises(AuthorityDenied):
            install_package_set(
                client, grant(), package_set_id="coral-cp39-runtime-v1",
                manifest_sha256=MANIFEST, enrollment_id="pi-main", generation="generation-2",
            )
        client.install_package_set.assert_not_called()

    def test_receipt_rejects_wrong_manifest_or_wheel_hash(self):
        with self.assertRaises(AuthorityDenied):
            parse_package_set_receipt(receipt(manifest_sha256="4" * 64),
                package_set_id="coral-cp39-runtime-v1", manifest_sha256=MANIFEST,
                enrollment_id="pi-main", generation="generation-1")
        with self.assertRaises(AuthorityDenied):
            parse_package_set_receipt(receipt(wheel_sha256=["5" * 64, WHEELS[1]]),
                package_set_id="coral-cp39-runtime-v1", manifest_sha256=MANIFEST,
                enrollment_id="pi-main", generation="generation-1")


if __name__ == "__main__":
    unittest.main()
