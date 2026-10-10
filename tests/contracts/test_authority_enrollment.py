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
    write_protected_file, _validate_service_generations, _parse_observer_delivery_bindings,
    _parse_source_issuers, _parse_native_schema_artifact_records,
    _parse_composio_channel_enrollment_records, _parse_channel_delivery_binding_records,
    _validate_root_key_selection,
)
from hermes_installer.authority.types import AuthorityDenied


class ProtectedEnrollmentContracts(unittest.TestCase):
    def test_composio_channel_enrollment_is_exact_and_bounded(self):
        row = {
            "id": "channel-enrollment", "channel_resource_id": "resource-a",
            "resource_generation": "resource-generation", "profile_id": "profile-a",
            "controller_role_id": "controller-a", "source_issuer_id": "observer-a",
            "composio_enrollment_id": "composio-a", "composio_user_id": "user-a",
            "connected_account_id": "account-a", "auth_config_id": "auth-a",
            "toolkit_version": "20260721_00", "trigger_artifact_id": "trigger-a",
            "trigger_artifact_sha256": "a" * 64, "trigger_slug": "messages.received",
            "trigger_instance_id": "instance-a", "webhook_subscription_id": "subscription-a",
            "webhook_route_enrollment_id": "route-a", "webhook_secret_reference_id": "secret-a",
            "allowed_user_numbers": ["+14155550123"],
            "payload_field_bindings": {name: [name] for name in
                                        ("sender_number", "message_id", "message_text", "event_timestamp")},
            "max_event_age_seconds": 120, "account_receipt_handle": "account-receipt-a",
            "setup_receipt_handle": "setup-receipt-a",
        }
        parsed = _parse_composio_channel_enrollment_records([row])
        self.assertEqual(parsed[0]["account_receipt_handle"], "account-receipt-a")
        self.assertEqual(parsed[0]["allowed_user_numbers"], ("+14155550123",))
        with self.assertRaises(AuthorityDenied):
            _parse_composio_channel_enrollment_records([{**row, "toolkit_version": "latest"}])
        with self.assertRaises(AuthorityDenied):
            _parse_composio_channel_enrollment_records([{**row, "allowed_user_numbers": ["*"]}])
        with self.assertRaises(AuthorityDenied):
            _parse_composio_channel_enrollment_records([{**row, "extra": "caller claim"}])

    def test_channel_delivery_binding_is_exact_and_bounded(self):
        row = {
            "id": "delivery-a", "profile_id": "profile-a", "process_generation": "process-a",
            "native_package_id": "package-a", "native_package_generation": "package-generation-a",
            "authority_endpoint_id": "authority-a", "allowed_channel_ingress_ids": ["channel-a"],
            "source_observer_enrollment_ids": ["observer-a"], "generation": "root-generation-a",
        }
        parsed = _parse_channel_delivery_binding_records([row])
        self.assertEqual(parsed[0]["allowed_channel_ingress_ids"], ("channel-a",))
        with self.assertRaises(AuthorityDenied):
            _parse_channel_delivery_binding_records([{**row, "source_observer_enrollment_ids": []}])
        with self.assertRaises(AuthorityDenied):
            _parse_channel_delivery_binding_records([{**row, "extra": True}])

    def test_native_schema_artifact_rows_are_exact_bounded_and_unique_per_action_kind(self):
        row = {
            "id": "arguments-v1", "artifact_id": "schema-arguments-v1",
            "sha256": "a" * 64, "schema_kind": "arguments",
            "native_package_id": "package-a", "native_package_generation": "generation-a",
            "adapter_id": "adapter-a", "action_id": "action-a",
            "source_receipt_handle": "receipt-handle-a",
        }
        parsed = _parse_native_schema_artifact_records([row])
        self.assertEqual(parsed[0]["source_receipt_handle"], "receipt-handle-a")
        self.assertEqual(parsed[0]["sha256"], "a" * 64)
        with self.assertRaises(AuthorityDenied):
            _parse_native_schema_artifact_records([{**row, "unreviewed": True}])
        with self.assertRaises(AuthorityDenied):
            _parse_native_schema_artifact_records([row, dict(row)])
        with self.assertRaises(AuthorityDenied):
            _parse_native_schema_artifact_records([{**row, "schema_kind": "discovery"}])
    def test_authority_key_selection_receipt_is_exact_and_digest_independent(self):
        row = {
            "schema": 1, "receipt_handle": "a" * 64,
            "key_id": "authority-key-" + "b" * 32,
            "algorithm": "HMAC-SHA256", "key_device": 1, "key_inode": 2,
            "key_uid": 0, "key_mode": 0o600,
            "release_receipt_handle": "c" * 64,
            "initial_compilation_session_handle": "d" * 64,
            "issued_monotonic": 10.0, "expires_monotonic": 40.0,
        }
        self.assertEqual(_validate_root_key_selection(row), row)
        for invalid in (
            {**row, "key_id": "caller-key"},
            {**row, "key_uid": True},
            {**row, "expires_monotonic": float("inf")},
            {**row, "unreviewed": "field"},
        ):
            with self.subTest(invalid=invalid), self.assertRaises(AuthorityDenied):
                _validate_root_key_selection(invalid)

    def test_native_observer_delivery_rows_join_current_peer_generation_and_exact_role(self):
        issuer = _parse_source_issuers([{
            "issuer_channel_id": "tool-result", "producer_profile_id": "producer-profile",
            "producer_role_artifact_id": "adapter-a", "producer_role_sha256": "a" * 64,
            "capture_schema_id": "capture-a", "allowed_parent_channels": [],
            "generation": "producer-generation", "observer_enrollment_id": "observer-a",
            "source_action_ids": ["registered-tool-result"],
        }])
        rows = _parse_observer_delivery_bindings(
            [{"observer_enrollment_id": "observer-a", "delivery_role": "gateway"}],
            source_issuers=issuer,
            peer_generations={"producer-profile": "producer-generation",
                              "gateway-profile": "gateway-generation"},
        )
        self.assertEqual((rows[0].observer_enrollment_id, rows[0].delivery_role),
                         ("observer-a", "gateway"))
        with self.assertRaises(AuthorityDenied):
            _parse_observer_delivery_bindings(
                [{"observer_enrollment_id": "observer-a", "delivery_role": "other"}],
                source_issuers=issuer,
                peer_generations={"producer-profile": "producer-generation"},
            )
        with self.assertRaises(AuthorityDenied):
            _parse_observer_delivery_bindings(
                [{"observer_enrollment_id": "observer-a", "delivery_role": "producer"},
                 {"observer_enrollment_id": "observer-a", "delivery_role": "gateway"}],
                source_issuers=issuer,
                peer_generations={"producer-profile": "producer-generation"},
            )
        with self.assertRaises(AuthorityDenied):
            _parse_observer_delivery_bindings(
                [{"observer_enrollment_id": "observer-a", "delivery_role": "producer"}],
                source_issuers=issuer,
                peer_generations={"producer-profile": "stale-generation"},
            )

    def test_active_native_mcp_tool_rows_are_digest_bound_and_strict(self):
        row = {
            "id": "mcp-action-a", "profile_id": "profile-a",
            "process_generation": "generation-a", "native_package_id": "package-a",
            "native_package_generation": "generation-a", "native_server_name": "hermes",
            "native_tool_name": "search", "native_schema_sha256": "a" * 64,
            "mcp_enrollment_id": "mcp-service-a", "mcp_generation": "mcp-generation-a",
            "mcp_tool_name": "search", "request_schema_id": "request-a",
            "result_schema_id": "result-a", "effect_operation": "mcp.request",
            "effect_target": "mcp:mcp-service-a:http", "capability": "mcp:mcp-service-a:read",
            "recipient": None,
            "scope_bindings": [{"argument_field": "resource", "selected_resource_id": "resource-a"}],
            "handler_artifact_id": "hermes-installer.native-mcp-dispatch.v1",
            "handler_artifact_sha256": "b" * 64,
        }

        def snapshot(bindings):
            value = {
                "schema": 1, "generation_id": "generation-root-a",
                "service_records": [], "protected_devices": [], "protected_build_records": [],
                "native_packages": [], "memory_enrollments": [], "operation_parameter_schemas": [],
                "source_issuers": [], "resource_jobs": [], "remote_session_enrollments": [],
                "resource_backend_enrollments": [], "resource_body_recipes": [],
                "resource_scope_bindings": [], "resource_validators": [], "root_journal_roots": [],
                "resource_controller_roles": [], "native_mcp_tool_bindings": bindings,
                "remote_observation_enrollments": [], "native_schema_artifacts": [], "composio_channel_enrollments": [], "channel_delivery_bindings": [],
            }
            value["generation_digest"] = hashlib.sha256(json.dumps(
                value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
            ).encode("utf-8")).hexdigest()
            return value

        self.assertEqual(len(_validate_service_generations(snapshot([row]))[
            "native_mcp_tool_bindings"]), 1)
        with self.assertRaises(AuthorityDenied):
            _validate_service_generations(snapshot([{**row, "effect_operation": "http.get"}]))
        with self.assertRaises(AuthorityDenied):
            _validate_service_generations(snapshot([{**row, "scope_bindings": [
                row["scope_bindings"][0], row["scope_bindings"][0]]}]))
        with self.assertRaises(AuthorityDenied):
            _validate_service_generations(snapshot([{**row, "extra": True}]))

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
            "root_journal_roots": [],
            "resource_controller_roles": [], "native_mcp_tool_bindings": [],
            "remote_observation_enrollments": [], "native_schema_artifacts": [], "composio_channel_enrollments": [], "channel_delivery_bindings": [],
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
        same_channel_other_adapter = {**source, "observer_enrollment_id": "observer-b",
                                      "producer_role_artifact_id": "role-b",
                                      "producer_role_sha256": "b" * 64}
        self.assertEqual(len(_parse_source_issuers([source, same_channel_other_adapter])), 2)
        with self.assertRaises(AuthorityDenied):
            _parse_source_issuers([source, {**source, "source_action_ids": ["registered-tool-result"]}])

        snapshot = {
            "schema": 1, "generation_id": "root-generation-a",
            "service_records": [], "protected_devices": [],
            "protected_build_records": [], "native_packages": [],
            "memory_enrollments": [], "operation_parameter_schemas": [],
            "source_issuers": [source], "resource_jobs": [],
            "remote_session_enrollments": [],
            "resource_backend_enrollments": [], "resource_body_recipes": [],
            "resource_scope_bindings": [], "resource_validators": [],
            "root_journal_roots": [],
            "resource_controller_roles": [], "native_mcp_tool_bindings": [],
            "remote_observation_enrollments": [], "native_schema_artifacts": [], "composio_channel_enrollments": [], "channel_delivery_bindings": [],
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
            "setup_writer_binding": {
                "setup_profile_id": "setup-a", "setup_generation": "setup-generation-a",
                "setup_role_artifact_id": "setup-role-a", "setup_role_sha256": "d" * 64,
                "setup_enrollment_id": "setup-enrollment-a",
                "setup_transaction_policy_id": "setup-policy-a",
                "allowed_tunnel_enrollment_ids": ["tunnel-a"],
                "token_writer_enrollment_id": "writer-a", "origin_probe_enrollment_id": "probe-a",
            },
        }

        def snapshot_with(rows):
            value = {
                "schema": 1, "generation_id": "root-generation-a",
                "service_records": [
                    {"enrollment_id": "desktop-enrollment-a", "profile_id": "desktop-a",
                     "generation": "desktop-generation-a"},
                    {"enrollment_id": "display-enrollment-a", "profile_id": "display-a",
                     "generation": "display-generation"},
                ], "protected_devices": [],
                "protected_build_records": [], "native_packages": [],
                "memory_enrollments": [], "operation_parameter_schemas": [],
                "source_issuers": [], "resource_jobs": [],
                "remote_session_enrollments": rows,
                "resource_backend_enrollments": [], "resource_body_recipes": [],
                "resource_scope_bindings": [], "resource_validators": [],
                "root_journal_roots": [],
            "resource_controller_roles": [], "native_mcp_tool_bindings": [],
            "remote_observation_enrollments": [], "native_schema_artifacts": [], "composio_channel_enrollments": [], "channel_delivery_bindings": [],
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
        observation = {
            "id": "observation-a", "remote_enrollment_id": "remote-a",
            "gateway_listener_port": 8743, "native_window_enrollment_id": "desktop-enrollment-a",
            "display_server_profile_id": "display-a", "display_server_generation": "display-generation",
            "display_name": ":0", "xauthority_receipt_handle": "xauth-receipt-a",
        }
        valid_with_observation = snapshot_with([fields])
        valid_with_observation["remote_observation_enrollments"] = [observation]
        valid_with_observation["generation_digest"] = hashlib.sha256(json.dumps(
            {key: value for key, value in valid_with_observation.items() if key != "generation_digest"},
            sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        ).encode("utf-8")).hexdigest()
        self.assertEqual(len(_validate_service_generations(valid_with_observation)[
            "remote_observation_enrollments"]), 1)
        malformed_observation = dict(valid_with_observation)
        malformed_observation["remote_observation_enrollments"] = [
            {**observation, "native_window_enrollment_id": "desktop-a"},
        ]
        malformed_observation["generation_digest"] = hashlib.sha256(json.dumps(
            {key: value for key, value in malformed_observation.items() if key != "generation_digest"},
            sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        ).encode("utf-8")).hexdigest()
        with self.assertRaises(AuthorityDenied):
            _validate_service_generations(malformed_observation)

    def test_active_resource_backend_and_body_recipe_rows_are_strict(self):
        backend = {
            "id": "backend-a", "resource_id": "resource-a", "profile_id": "profile-a",
            "principal_id": "principal-a", "generation": "service-generation-a",
            "consent_revision": "consent-a", "source_issuer_channel_id": "tool-result",
            "observer_enrollment_id": "observer-a", "native_package_id": "package-a",
            "native_package_generation": "service-generation-a", "handler_artifact_id": "handler-a",
            "handler_sha256": "a" * 64, "approved_action_ids": ["action-a"],
            "operation": "plugin.adapter.call", "target_id": "target-a", "recipient": None,
            "credential_reference_ids": ["vault-ref-a"], "request_schema_id": "request-a",
            "result_schema_id": "result-a", "body_recipe_id": "body-a",
            "scope_binding_id": "scope-a", "maximum_request_bytes": 1024,
            "maximum_response_bytes": 2048, "maximum_seconds": 30,
            "profile_generation": "profile-generation-a", "execution_binding": None,
            "credential_bindings": [{"source_placeholder": "${BACKEND_TOKEN}",
                                      "credential_reference_id": "vault-ref-a",
                                      "usage": "backend-account"}],
        }
        body = {
            "id": "body-a", "schema_id": "request-a", "source_artifact_id": "recipe-source-a",
            "source_sha256": "b" * 64,
            "output_fields": [{"name": "query", "source": "literal", "value": "fixed",
                               "validator_id": "string-v1"}],
            "scope_bindings": [{"name": "profile_id", "scope_binding_id": "scope-a",
                                "field": "profile_id", "validator_id": "opaque-id-v1"}],
            "maximum_bytes": 1024,
        }
        snapshot = {
            "schema": 1, "generation_id": "root-generation-a",
            "service_records": [], "protected_devices": [], "protected_build_records": [],
            "native_packages": [], "memory_enrollments": [], "operation_parameter_schemas": [],
            "source_issuers": [], "resource_jobs": [], "remote_session_enrollments": [],
            "resource_backend_enrollments": [backend], "resource_body_recipes": [body],
            "resource_scope_bindings": [], "resource_validators": [],
            "root_journal_roots": [],
            "resource_controller_roles": [], "native_mcp_tool_bindings": [],
            "remote_observation_enrollments": [], "native_schema_artifacts": [], "composio_channel_enrollments": [], "channel_delivery_bindings": [],
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
        for changed_binding in (
            {"source_placeholder": "${BACKEND_TOKEN}", "credential_reference_id": "not-enrolled",
             "usage": "backend-account"},
            {"source_placeholder": "${BACKEND_TOKEN}", "credential_reference_id": "vault-ref-a",
             "usage": "environment"},
            {"source_placeholder": "${BACKEND_TOKEN}", "credential_reference_id": "vault-ref-a",
             "usage": "backend-account", "extra": True},
        ):
            malformed = dict(snapshot)
            malformed["resource_backend_enrollments"] = [{**backend, "credential_bindings": [changed_binding]}]
            malformed["generation_digest"] = hashlib.sha256(json.dumps(
                {key: value for key, value in malformed.items() if key != "generation_digest"},
                sort_keys=True, separators=(",", ":"), ensure_ascii=False,
            ).encode("utf-8")).hexdigest()
            with self.assertRaises(AuthorityDenied):
                _validate_service_generations(malformed)

    def test_active_resource_scope_and_validator_catalogs_are_strict_and_digest_bound(self):
        scope = {
            "id": "scope-a", "resource_id": "resource-a", "profile_id": "profile-a",
            "principal_id": "principal-a", "resource_generation": "resource-gen-a",
            "profile_generation": "profile-gen-a", "backend_enrollment_id": "backend-a",
            "fixed_fields": {"project_id": "project-a"},
            "credential_reference_ids": ["provider-a"], "recipient": "recipient-a",
        }
        validator = {
            "id": "opaque-id-v1", "kind": "opaque-id", "maximum_bytes": 128,
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
            "root_journal_roots": [],
            "resource_controller_roles": [], "native_mcp_tool_bindings": [],
            "remote_observation_enrollments": [], "native_schema_artifacts": [], "composio_channel_enrollments": [], "channel_delivery_bindings": [],
        }

        def sign(value):
            unsigned = {key: child for key, child in value.items() if key != "generation_digest"}
            value["generation_digest"] = hashlib.sha256(json.dumps(
                unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
            ).encode("utf-8")).hexdigest()
            return value

        parsed = _validate_service_generations(sign(dict(snapshot)))
        self.assertEqual(parsed["resource_scope_bindings"][0]["backend_enrollment_id"], "backend-a")
        self.assertEqual(parsed["resource_validators"][0]["kind"], "opaque-id")

        bad_scope = dict(snapshot)
        bad_scope["resource_scope_bindings"] = [{**scope, "extra": "not-reviewed"}]
        with self.assertRaises(AuthorityDenied):
            _validate_service_generations(sign(bad_scope))
        bad_validator = dict(snapshot)
        bad_validator["resource_validators"] = [{**validator, "maximum_bytes": True}]
        with self.assertRaises(AuthorityDenied):
            _validate_service_generations(sign(bad_validator))

    def test_resource_dag_uses_per_node_backend_and_verified_dag_digest(self):
        node = {
            "node_id": "node-a", "resource_id": "resource-a", "action_id": "action-a",
            "operation": "plugin.adapter.call", "target_id": "target-a", "recipient": None,
            "request_schema_id": "request-a", "body_recipe_id": "body-a",
            "depends_on": [], "maximum_attempts": 1, "backend_enrollment_id": "backend-a",
            "result_schema_id": "result-a", "scope_binding_id": "scope-a",
        }
        dag = {"dag_sha256": hashlib.sha256(json.dumps(
            [node], sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        ).encode("utf-8")).hexdigest(), "nodes": [node]}
        resource = {
            "resource_id": "resource-a", "kind": "bundle", "selected_enabled": True,
            "profile_id": "profile-a", "principal_id": "principal-a", "generation": "resource-gen-a",
            "consent_revision": "consent-a", "approved_action_ids": ["action-a"],
            "fixed_target_ids": ["target-a"], "credential_reference_ids": [],
            "recipient_scope": {}, "source_policy": {}, "schedule_or_route_id": None,
            "max_children": 2, "max_concurrency": 1, "max_runtime_seconds": 60,
            "max_payload_bytes": 4096, "max_replay_entries": 0,
            "enrollment_id": "enrollment-a", "source_issuer_channel_id": "tool-result",
            "observer_enrollment_id": "observer-a", "approved_dag": dag,
        }
        snapshot = {
            "schema": 1, "generation_id": "root-generation-a",
            "service_records": [], "protected_devices": [], "protected_build_records": [],
            "native_packages": [], "memory_enrollments": [], "operation_parameter_schemas": [],
            "source_issuers": [], "resource_jobs": [resource], "remote_session_enrollments": [],
            "resource_backend_enrollments": [], "resource_body_recipes": [],
            "resource_scope_bindings": [], "resource_validators": [],
            "root_journal_roots": [],
            "resource_controller_roles": [], "native_mcp_tool_bindings": [],
            "remote_observation_enrollments": [], "native_schema_artifacts": [], "composio_channel_enrollments": [], "channel_delivery_bindings": [],
        }

        def sign(value):
            unsigned = {key: child for key, child in value.items() if key != "generation_digest"}
            value["generation_digest"] = hashlib.sha256(json.dumps(
                unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
            ).encode("utf-8")).hexdigest()
            return value

        assert len(_validate_service_generations(sign(dict(snapshot)))["resource_jobs"]) == 1
        bad_dag = dict(snapshot)
        bad_dag["resource_jobs"] = [{**resource, "approved_dag": {**dag, "dag_sha256": "f" * 64}}]
        with self.assertRaises(AuthorityDenied):
            _validate_service_generations(sign(bad_dag))

    def test_root_journal_roots_are_generation_bound_and_fixed_owner(self):
        root = {
            "root_id": "installer-authority-journal-v1",
            "absolute_path": "/var/lib/hermes-installer/authority-journal",
            "owner_uid": 0, "owner_gid": 0, "mode": 448,
            "device": 10, "inode": 20, "generation": "journal-generation-a",
            "purpose": "authority-journal",
        }
        snapshot = {
            "schema": 1, "generation_id": "root-generation-a",
            "service_records": [], "protected_devices": [], "protected_build_records": [],
            "native_packages": [], "memory_enrollments": [], "operation_parameter_schemas": [],
            "source_issuers": [], "resource_jobs": [], "remote_session_enrollments": [],
            "resource_backend_enrollments": [], "resource_body_recipes": [],
            "resource_scope_bindings": [], "resource_validators": [],
            "root_journal_roots": [root],
            "resource_controller_roles": [], "native_mcp_tool_bindings": [],
            "remote_observation_enrollments": [], "native_schema_artifacts": [], "composio_channel_enrollments": [], "channel_delivery_bindings": [],
        }
        unsigned = dict(snapshot)
        snapshot["generation_digest"] = hashlib.sha256(json.dumps(
            unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        ).encode("utf-8")).hexdigest()
        parsed = _validate_service_generations(snapshot)
        self.assertEqual(parsed["root_journal_roots"][0]["root_id"], root["root_id"])
        malformed = dict(snapshot)
        malformed["root_journal_roots"] = [{**root, "owner_uid": 1001}]
        malformed["generation_digest"] = hashlib.sha256(json.dumps(
            {key: value for key, value in malformed.items() if key != "generation_digest"},
            sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        ).encode("utf-8")).hexdigest()
        with self.assertRaises(AuthorityDenied):
            _validate_service_generations(malformed)

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
