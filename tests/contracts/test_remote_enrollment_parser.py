"""HI-T13 active-enrollment join and fail-closed parser tests."""
from __future__ import annotations

import unittest
from types import SimpleNamespace

from hermes_installer.authority.remote_enrollment import parse_remote_session_enrollments
from hermes_installer.authority.types import AuthorityDenied


class RemoteEnrollmentParserTests(unittest.TestCase):
    def setUp(self):
        self.profiles = {
            "remote-gateway": SimpleNamespace(
                profile_id="remote-gateway", generation="gateway-gen", owner_uid=1201,
                process_role_artifact_hashes={"gateway-role-v1": "a" * 64},
            ),
            "native-desktop": SimpleNamespace(
                profile_id="native-desktop", generation="desktop-gen", owner_uid=1202,
                process_role_artifact_hashes={},
            ),
            "cloudflared": SimpleNamespace(
                profile_id="cloudflared", generation="tunnel-gen", owner_uid=1203,
                process_role_artifact_hashes={},
            ),
            "remote-setup": SimpleNamespace(
                profile_id="remote-setup", generation="setup-gen", owner_uid=1205,
                process_role_artifact_hashes={},
            ),
            "owner-profile": SimpleNamespace(
                profile_id="owner-profile", generation="owner-gen", owner_uid=1204,
                process_role_artifact_hashes={},
            ),
        }
        self.row = {
            "id": "remote-enrollment",
            "gateway_profile_id": "remote-gateway",
            "gateway_role_artifact_id": "gateway-role-v1",
            "gateway_role_sha256": "a" * 64,
            "native_desktop_profile_id": "native-desktop",
            "native_generation": "desktop-gen",
            "connector_target_id": "xpra-native",
            "approved_asset_routes": ["xpra-http"],
            "approved_websocket_route": "xpra-websocket",
            "expected_hostname": "desk.example.org",
            "expected_origin": "https://desk.example.org",
            "jwt_issuer": "https://team.cloudflareaccess.com",
            "jwt_audience": "app-aud",
            "jwks_origin": "https://team.cloudflareaccess.com",
            "jwt_algorithm_allowlist": ["RS256"],
            "allowed_email_reference_id": "allowed-email-record",
            "policy_verifier_enrollment_id": "policy-verifier",
            "policy_config_digest": "b" * 64,
            "maximum_lease_seconds": 60,
            "watchdog_interval_seconds": 5,
            "policy_revision": "policy-epoch-4",
            "principal_bindings_by_subject": {
                "access-subject-1": {
                    "principal_id": "principal-1", "profile_id": "owner-profile",
                    "email": "owner@example.org",
                },
            },
            "access_policy_binding": {
                "verifier_enrollment_id": "policy-verifier",
                "account_id": "account-1", "application_id": "app-1",
                "policy_id": "policy-1", "otp_identity_provider_id": "otp-1",
                "otp_provider_type": "onetimepin", "verifier_config_digest": "b" * 64,
                "read_credential_reference_id": "minimum-read-token",
            },
            "tunnel_runtime_binding": {
                "tunnel_enrollment_id": "tunnel-enrollment",
                "tunnel_id": "tunnel-1", "cloudflared_profile_id": "cloudflared",
                "tunnel_token_reference_id": "tunnel-token-ref", "token_sink_id": "sink-1",
                "origin_readiness_policy_id": "origin-policy-1",
            },
            "setup_writer_binding": {
                "setup_profile_id": "remote-setup", "setup_generation": "setup-gen",
                "setup_role_artifact_id": "setup-role-v1", "setup_role_sha256": "d" * 64,
                "setup_enrollment_id": "setup-enrollment",
                "setup_transaction_policy_id": "setup-transaction-policy",
                "allowed_tunnel_enrollment_ids": ["tunnel-enrollment"],
                "token_writer_enrollment_id": "token-writer-enrollment",
                "origin_probe_enrollment_id": "origin-probe-enrollment",
            },
        }
        self.role_artifacts = {"gateway-role-v1": "a" * 64, "setup-role-v1": "d" * 64}
        self.principals = {
            "access-subject-1": {
                "principal_id": "principal-1", "profile_id": "owner-profile",
                "email": "owner@example.org",
            },
        }

    def test_parses_only_exactly_joined_active_record(self):
        result = parse_remote_session_enrollments(
            [self.row], principal_bindings=self.principals,
            process_profiles=self.profiles,
            role_artifacts=self.role_artifacts,
        )
        enrolled = result["remote-enrollment"]
        self.assertEqual(enrolled.session.gateway_generation, "gateway-gen")
        self.assertEqual(enrolled.session.principal_bindings_by_subject[
            "access-subject-1"].profile_generation, "owner-gen")
        self.assertEqual(enrolled.access_policy.read_credential_reference_id,
                         "minimum-read-token")
        self.assertEqual(enrolled.tunnel_runtime.tunnel_id, "tunnel-1")
        self.assertEqual(enrolled.setup_writer.setup_profile_id, "remote-setup")
        self.assertEqual(enrolled.setup_writer.allowed_tunnel_enrollment_ids,
                         ("tunnel-enrollment",))
        self.assertEqual(enrolled.tunnel_runtime.cloudflared_generation, "tunnel-gen")

    def test_rejects_caller_or_stale_principal_mapping(self):
        row = {**self.row, "principal_bindings_by_subject": {
            "access-subject-1": {"principal_id": "other", "profile_id": "owner-profile",
                                  "email": "owner@example.org"},
        }}
        with self.assertRaises(AuthorityDenied):
            parse_remote_session_enrollments(
                [row], principal_bindings=self.principals,
                process_profiles=self.profiles,
                role_artifacts=self.role_artifacts,
            )

    def test_rejects_wrong_gateway_role_and_non_xpra_target(self):
        for changes in ({"gateway_role_sha256": "c" * 64},
                        {"connector_target_id": "arbitrary-loopback"}):
            with self.subTest(changes=changes), self.assertRaises(AuthorityDenied):
                parse_remote_session_enrollments(
                    [{**self.row, **changes}], principal_bindings=self.principals,
                    process_profiles=self.profiles,
                    role_artifacts=self.role_artifacts,
                )

    def test_rejects_extra_fields_and_duplicate_email_mapping(self):
        with self.assertRaises(AuthorityDenied):
            parse_remote_session_enrollments(
                [{**self.row, "caller_policy_grant": "forbidden"}],
                principal_bindings=self.principals, process_profiles=self.profiles,
                role_artifacts=self.role_artifacts,
            )
        ambiguous = {
            **self.row,
            "principal_bindings_by_subject": {
                "access-subject-1": self.row["principal_bindings_by_subject"]["access-subject-1"],
                "access-subject-2": {"principal_id": "principal-2", "profile_id": "owner-profile",
                                      "email": "owner@example.org"},
            },
        }
        with self.assertRaises(AuthorityDenied):
            parse_remote_session_enrollments(
                [ambiguous], principal_bindings={
                    **self.principals,
                    "access-subject-2": {"principal_id": "principal-2", "profile_id": "owner-profile",
                                          "email": "owner@example.org"},
                }, process_profiles=self.profiles,
                role_artifacts=self.role_artifacts,
            )

    def test_empty_active_catalog_is_unavailable_without_principal_rows(self):
        self.assertEqual(parse_remote_session_enrollments(
            [], principal_bindings={}, process_profiles={}), {})


if __name__ == "__main__":
    unittest.main()
