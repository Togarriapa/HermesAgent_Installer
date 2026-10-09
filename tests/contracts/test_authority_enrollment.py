from __future__ import annotations

import json
import hashlib
import os
import tempfile
import unittest
from pathlib import Path

from hermes_installer.authority.enrollment import (
    AUTHORITY_CONFIG_PATH, CREDENTIAL_DIRECTORY, RootCredentialVault,
    _reject_secret_material, _unique_pairs, _verify_active_process_rules, write_authority_config,
    write_protected_file, _validate_service_generations,
)
from hermes_installer.authority.types import AuthorityDenied


class ProtectedEnrollmentContracts(unittest.TestCase):
    def test_process_rules_are_joined_to_active_generation_targets_for_every_handler(self):
        from types import SimpleNamespace
        from hermes_installer.authority.service import EffectRule, PrincipalBinding

        operations = (
            ("hermes-profile-invoke", "process.start"),
            ("hermes-process-control", "process.status"),
            ("hermes-process-control", "process.read"),
            ("hermes-process-control", "process.write"),
            ("hermes-process-control", "process.stop"),
            ("hermes-process-control", "process.inspect"),
        )
        targets = {operation: f"protected:{operation}" for _, operation in operations}
        service = SimpleNamespace(
            profile_id="profile-a", principal_id="principal-a", generation="generation-a",
            service_uid=1201, service_gid=1202, namespace_identity="ns-a",
            operation_targets=targets,
        )
        authority_profile = SimpleNamespace(
            owner_uid=1201, owner_gid=1202, generation="generation-a",
        )
        binding = PrincipalBinding(
            uid=1201, principal_id="principal-a", profile_id="profile-a",
            namespace_id="ns-a", capabilities=frozenset(cap for cap, _ in operations),
        )
        rules = {(cap, operation, targets[operation]): EffectRule(
            capability=cap, operation=operation, target=targets[operation],
        ) for cap, operation in operations}

        _verify_active_process_rules(
            {"profile-a": service}, {"profile-a": authority_profile},
            {1201: binding}, rules,
        )
        rules.pop(("hermes-profile-invoke", "process.start", targets["process.start"]))
        with self.assertRaisesRegex(ValueError, "no exact authority rule"):
            _verify_active_process_rules(
                {"profile-a": service}, {"profile-a": authority_profile},
                {1201: binding}, rules,
            )

    def test_service_generation_snapshot_is_one_digest_bound_strict_catalog(self):
        snapshot = {
            "schema": 1, "generation_id": "root-generation-a",
            "service_records": [{"profile": "café"}], "protected_devices": [],
            "protected_build_records": [], "native_packages": [],
            "memory_enrollments": [], "operation_parameter_schemas": [],
            "source_issuers": [], "resource_jobs": [],
            "remote_session_enrollments": [],
            "resource_backend_enrollments": [], "resource_body_recipes": [],
            "resource_scope_bindings": [], "resource_validators": [],
            "root_journal_roots": [{"root_id": "journal-a", "absolute_path": "/var/lib/hermes-installer/authority-journal",
                                    "owner_uid": 0, "owner_gid": 0, "mode": 448,
                                    "device": 1, "inode": 2, "generation": "journal-gen-a",
                                    "purpose": "authority-journal"}],
        }
        snapshot["generation_digest"] = hashlib.sha256(json.dumps(
            snapshot, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        ).encode("utf-8")).hexdigest()
        self.assertEqual(_validate_service_generations(snapshot)["generation_id"], "root-generation-a")
        changed = dict(snapshot)
        changed["service_records"] = [{"profile": "cafe"}]
        with self.assertRaises(AuthorityDenied):
            _validate_service_generations(changed)
        malformed = dict(snapshot)
        malformed["unreviewed_catalog"] = []
        with self.assertRaises(AuthorityDenied):
            _validate_service_generations(malformed)

    def test_active_source_issuers_are_strict_and_part_of_the_generation_digest(self):
        from hermes_installer.authority.enrollment import _parse_source_issuers

        source = {
            "issuer_channel_id": "tool-result",
            "producer_profile_id": "profile-a",
            "producer_role_artifact_id": "role-a",
            "producer_role_sha256": "a" * 64,
            "capture_schema_id": "capture-a",
            "allowed_parent_channels": ["native-input"],
            "generation": "service-generation-a",
            "observer_enrollment_id": "observer-a",
            "source_action_ids": ["registered-tool-result"],
        }
        parsed = _parse_source_issuers([source])
        self.assertEqual(parsed[0].observer_enrollment_id, "observer-a")
        self.assertEqual(parsed[0].source_action_ids, ("registered-tool-result",))
        with self.assertRaises(AuthorityDenied):
            _parse_source_issuers([{**source, "source_action_ids": ["root-timer-event"]}])
        with self.assertRaises(AuthorityDenied):
            _parse_source_issuers([source, source])

        snapshot = {
            "schema": 1, "generation_id": "root-generation-a",
            "service_records": [], "protected_devices": [],
            "protected_build_records": [], "native_packages": [],
            "memory_enrollments": [], "operation_parameter_schemas": [],
            "source_issuers": [source], "resource_jobs": [],
            "remote_session_enrollments": [],
            "resource_backend_enrollments": [], "resource_body_recipes": [],
            "resource_scope_bindings": [], "resource_validators": [],
            "root_journal_roots": [{"root_id": "journal-a", "absolute_path": "/var/lib/hermes-installer/authority-journal",
                                    "owner_uid": 0, "owner_gid": 0, "mode": 448,
                                    "device": 1, "inode": 2, "generation": "journal-gen-a",
                                    "purpose": "authority-journal"}],
        }
        snapshot["generation_digest"] = hashlib.sha256(json.dumps(
            snapshot, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        ).encode("utf-8")).hexdigest()
        self.assertEqual(len(_validate_service_generations(snapshot)["source_issuers"]), 1)
        changed = dict(snapshot)
        changed["source_issuers"] = []
        with self.assertRaises(AuthorityDenied):
            _validate_service_generations(changed)

    def test_active_remote_session_catalog_rejects_unknown_or_duplicate_records(self):
        fields = {
            "id": "remote-a", "gateway_profile_id": "gateway-a",
            "gateway_role_artifact_id": "gateway-role-a", "gateway_role_sha256": "a" * 64,
            "native_desktop_profile_id": "desktop-a", "native_generation": "desktop-generation-a",
            "connector_target_id": "connector-a", "approved_asset_routes": ["asset-index"],
            "approved_websocket_route": "desktop-ws", "expected_hostname": "desktop.example.test",
            "expected_origin": "https://desktop.example.test", "jwt_issuer": "https://issuer.example.test",
            "jwt_audience": "desktop-audience", "jwks_origin": "https://issuer.example.test",
            "jwt_algorithm_allowlist": ["RS256"], "allowed_email_reference_id": "vault:email-a",
            "policy_verifier_enrollment_id": "verifier-a", "policy_config_digest": "b" * 64,
            "maximum_lease_seconds": 60, "watchdog_interval_seconds": 5,
            "policy_revision": "policy-a",
            "principal_bindings_by_subject": {
                "subject-a": {"principal_id": "principal-a", "profile_id": "desktop-a",
                               "email": "user@example.test"},
            },
            "access_policy_binding": {
                "verifier_enrollment_id": "verifier-a", "account_id": "account-a",
                "application_id": "application-a", "policy_id": "access-policy-a",
                "otp_identity_provider_id": "otp-a", "otp_provider_type": "onetimepin",
                "verifier_config_digest": "c" * 64,
                "read_credential_reference_id": "vault:read-policy-a",
            },
            "tunnel_runtime_binding": {
                "tunnel_enrollment_id": "tunnel-a", "tunnel_id": "tunnel-id-a",
                "cloudflared_profile_id": "cloudflared-a",
                "tunnel_token_reference_id": "vault:tunnel-token-a",
                "token_sink_id": "sink-a", "origin_readiness_policy_id": "origin-policy-a",
            },
        }

        def snapshot_with(rows):
            value = {
                "schema": 1, "generation_id": "root-generation-a",
                "service_records": [], "protected_devices": [],
                "protected_build_records": [], "native_packages": [],
                "memory_enrollments": [], "operation_parameter_schemas": [],
                "source_issuers": [], "resource_jobs": [],
                "remote_session_enrollments": rows,
                "resource_backend_enrollments": [], "resource_body_recipes": [],
                "resource_scope_bindings": [], "resource_validators": [],
                "root_journal_roots": [{"root_id": "journal-a", "absolute_path": "/var/lib/hermes-installer/authority-journal",
                                        "owner_uid": 0, "owner_gid": 0, "mode": 448,
                                        "device": 1, "inode": 2, "generation": "journal-gen-a",
                                        "purpose": "authority-journal"}],
            }
            value["generation_digest"] = hashlib.sha256(json.dumps(
                value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
            ).encode("utf-8")).hexdigest()
            return value

        self.assertEqual(len(_validate_service_generations(snapshot_with([fields]))[
            "remote_session_enrollments"]), 1)
        with self.assertRaises(AuthorityDenied):
            _validate_service_generations(snapshot_with([fields, fields]))
        with self.assertRaises(AuthorityDenied):
            _validate_service_generations(snapshot_with([{**fields, "unreviewed": True}]))

    def test_active_resource_backend_and_body_recipe_rows_are_strict(self):
        backend = {
            "id": "backend-a", "resource_id": "resource-a", "profile_id": "profile-a",
            "principal_id": "principal-a", "generation": "service-generation-a",
            "consent_revision": "consent-a", "source_issuer_channel_id": "tool-result",
            "observer_enrollment_id": "observer-a", "native_package_id": "package-a",
            "native_package_generation": "service-generation-a", "handler_artifact_id": "handler-a",
            "handler_sha256": "a" * 64, "approved_action_ids": ["action-a"],
            "operation": "plugin.adapter.call", "target_id": "target-a", "recipient": None,
            "credential_reference_ids": [], "request_schema_id": "request-a",
            "result_schema_id": "result-a", "body_recipe_id": "body-a",
            "scope_binding_id": "scope-a", "maximum_request_bytes": 1024,
            "maximum_response_bytes": 2048, "maximum_seconds": 30,
        }
        body = {
            "id": "body-a", "schema_id": "request-a", "source_artifact_id": "recipe-source-a",
            "source_sha256": "b" * 64,
            "output_fields": [{"name": "query", "source": "literal", "value": "fixed",
                               "validator_id": "string-v1"}],
            "scope_bindings": {"profile_id": "scope-a"}, "maximum_bytes": 1024,
        }
        snapshot = {
            "schema": 1, "generation_id": "root-generation-a",
            "service_records": [], "protected_devices": [], "protected_build_records": [],
            "native_packages": [], "memory_enrollments": [], "operation_parameter_schemas": [],
            "source_issuers": [], "resource_jobs": [], "remote_session_enrollments": [],
            "resource_backend_enrollments": [backend], "resource_body_recipes": [body],
            "resource_scope_bindings": [], "resource_validators": [],
            "root_journal_roots": [{"root_id": "journal-a", "absolute_path": "/var/lib/hermes-installer/authority-journal",
                                    "owner_uid": 0, "owner_gid": 0, "mode": 448,
                                    "device": 1, "inode": 2, "generation": "journal-gen-a",
                                    "purpose": "authority-journal"}],
        }
        snapshot["generation_digest"] = hashlib.sha256(json.dumps(
            snapshot, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        ).encode("utf-8")).hexdigest()
        parsed = _validate_service_generations(snapshot)
        self.assertEqual(parsed["resource_backend_enrollments"][0]["id"], "backend-a")
        malformed = dict(snapshot)
        malformed["resource_body_recipes"] = [{**body, "unreviewed": True}]
        with self.assertRaises(AuthorityDenied):
            _validate_service_generations(malformed)

    def test_resource_scope_and_validator_catalogs_are_digest_bound_and_strict(self):
        scope = {
            "id": "scope-a", "resource_id": "resource-a", "profile_id": "profile-a",
            "principal_id": "principal-a", "resource_generation": "resource-gen-a",
            "profile_generation": "profile-gen-a", "backend_enrollment_id": "backend-a",
            "fixed_fields": {"region": "eu"}, "credential_reference_ids": ["credential-key-a"],
            "recipient": None,
        }
        validator = {
            "id": "string-v1", "kind": "utf8-string", "maximum_bytes": 1024,
            "minimum": None, "maximum": None, "allowed_values": None,
            "schema_artifact_id": None, "schema_sha256": None,
        }
        snapshot = {
            "schema": 1, "generation_id": "root-generation-a",
            "service_records": [], "protected_devices": [], "protected_build_records": [],
            "native_packages": [], "memory_enrollments": [], "operation_parameter_schemas": [],
            "source_issuers": [], "resource_jobs": [], "remote_session_enrollments": [],
            "resource_backend_enrollments": [], "resource_body_recipes": [],
            "resource_scope_bindings": [scope], "resource_validators": [validator],
            "root_journal_roots": [{"root_id": "journal-a", "absolute_path": "/var/lib/hermes-installer/authority-journal",
                                    "owner_uid": 0, "owner_gid": 0, "mode": 448,
                                    "device": 1, "inode": 2, "generation": "journal-gen-a",
                                    "purpose": "authority-journal"}],
        }
        snapshot["generation_digest"] = hashlib.sha256(json.dumps(
            snapshot, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        ).encode("utf-8")).hexdigest()
        parsed = _validate_service_generations(snapshot)
        self.assertEqual(parsed["resource_scope_bindings"][0]["fixed_fields"], {"region": "eu"})
        self.assertEqual(parsed["resource_validators"][0]["kind"], "utf8-string")

        for field, value in (("recipient", {"path": "/etc/passwd"}),
                             ("fixed_fields", {"api_key": "secret"}),):
            malformed = dict(snapshot)
            malformed["resource_scope_bindings"] = [{**scope, field: value}]
            malformed["generation_digest"] = hashlib.sha256(json.dumps(
                {key: item for key, item in malformed.items() if key != "generation_digest"},
                sort_keys=True, separators=(",", ":"), ensure_ascii=False,
            ).encode("utf-8")).hexdigest()
            with self.assertRaises(AuthorityDenied):
                _validate_service_generations(malformed)
        malformed_validator = dict(snapshot)
        malformed_validator["resource_validators"] = [{**validator, "maximum_bytes": 0}]
        malformed_validator["generation_digest"] = hashlib.sha256(json.dumps(
            {key: item for key, item in malformed_validator.items() if key != "generation_digest"},
            sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        ).encode("utf-8")).hexdigest()
        with self.assertRaises(AuthorityDenied):
            _validate_service_generations(malformed_validator)

    def test_duplicate_json_keys_and_secret_values_are_rejected(self):
        with self.assertRaises(ValueError):
            json.loads('{"schema":1,"schema":2}', object_pairs_hook=_unique_pairs)
        with self.assertRaises(AuthorityDenied):
            _reject_secret_material({"provider": {"access_token": "never-store"}})
        with self.assertRaises(AuthorityDenied):
            write_authority_config({"schema": 1, "bearer_token": "not-a-reference"})

    def test_writer_rejects_non_enrolled_path_before_writing(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "unrelated"
            target.write_bytes(b"keep")
            with self.assertRaises(AuthorityDenied):
                write_protected_file(target, b"replace")
            self.assertEqual(target.read_bytes(), b"keep")

    def test_loaders_and_vault_cannot_be_repointed_to_worker_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):
                RootCredentialVault(Path(tmp), expected_uid=0)
            with self.assertRaises(ValueError):
                from hermes_installer.authority.enrollment import load_protected_enrollment
                load_protected_enrollment(Path(tmp) / "authority.json")
        self.assertEqual(AUTHORITY_CONFIG_PATH, Path("/etc/hermes-installer/authority.json"))
        self.assertEqual(CREDENTIAL_DIRECTORY, Path("/etc/hermes-installer/credentials"))


if __name__ == "__main__":
    unittest.main()
