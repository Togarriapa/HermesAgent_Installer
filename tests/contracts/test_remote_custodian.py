"""Schema and secret-exclusion tests for the isolated verifier service descriptor."""
from __future__ import annotations

import json
import os
from dataclasses import replace
import tempfile
import unittest
from pathlib import Path

from hermes_installer.remote.custodian import VerifierManagedServiceDescriptor, VerifierServiceConfig
from hermes_installer.remote.policy import AccessPolicyIdentity


def _payload(service_uid: int, gateway_uid: int) -> dict:
    return {
        "version": 1,
        "socket_path": "/run/hermes-installer/remote/verifier.sock",
        "gateway_uid": gateway_uid,
        "service_uid": service_uid,
        "service_gid": service_uid,
        "identity": {
            "account_id": "acct-1", "application_id": "app-1", "policy_id": "policy-1",
            "identity_provider_id": "idp-1", "hostname": "desktop.example.net",
            "application_name": "HermesInstaller:op:desktop",
            "policy_name": "HermesInstaller:op:allowed-emails",
            "identity_provider_name": "HermesInstaller:op:otp",
            "allowed_emails": ["owner@example.net"], "audience": "audience-tag",
        },
        "issuer": "https://team.cloudflareaccess.com",
        "jwks": {"key-1": {"kty": "RSA", "kid": "key-1", "alg": "RS256", "n": "AQ", "e": "AQAB"}},
        "credential_ref": "file:///var/lib/hermes-installer/remote/access-read-token",
        "profile_id": "hermes-desktop",
    }


class VerifierCustodianConfigTests(unittest.TestCase):
    def test_nonsecret_exact_config_loads_and_digest_identity_is_separate(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "verifier.json"
            path.write_text(json.dumps(_payload(os.geteuid(), os.geteuid() + 17)), encoding="utf-8")
            path.chmod(0o600)
            config = VerifierServiceConfig.load(path)
            self.assertEqual(config.identity.audience, "audience-tag")
            self.assertEqual(config.credential_ref, "file:///var/lib/hermes-installer/remote/access-read-token")
            self.assertEqual(config.profile_id, "hermes-desktop")

    def test_secret_values_and_unknown_fields_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            payload = _payload(os.geteuid(), os.geteuid() + 17)
            payload["management_token"] = "must-never-be-stored"
            path = Path(directory) / "verifier.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            path.chmod(0o600)
            with self.assertRaises(ValueError):
                VerifierServiceConfig.load(path)

    def test_group_or_world_readable_config_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "verifier.json"
            path.write_text(json.dumps(_payload(os.geteuid(), os.geteuid() + 17)), encoding="utf-8")
            path.chmod(0o644)
            with self.assertRaises(PermissionError):
                VerifierServiceConfig.load(path)

    def test_managed_service_descriptor_is_bounded_and_secret_free(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            descriptor = VerifierManagedServiceDescriptor(
                service_id="hermes-remote-policy-verifier",
                executable=root / "venv/bin/python", executable_sha256="a" * 64,
                owned_root=root, cwd=root / "runtime",
                config_path=root / "config/verifier.json",
                socket_path=Path("/run/hermes-installer/remote/verifier.sock"),
                gateway_uid=os.geteuid() + 17, verifier_uid=os.geteuid() + 18,
                verifier_gid=os.geteuid() + 19,
            )
            descriptor.validate()
            with self.assertRaises(ValueError):
                replace(descriptor, service_id="arbitrary-command").validate()
