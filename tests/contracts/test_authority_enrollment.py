from __future__ import annotations

import json
import hashlib
import os
import stat
import tempfile
import time
import unittest
from types import SimpleNamespace
from pathlib import Path
from unittest import mock

from hermes_installer.authority.enrollment import (
    AUTHORITY_CONFIG_PATH, CREDENTIAL_DIRECTORY, RootCredentialVault,
    _reject_secret_material, _unique_pairs, _verify_active_process_rules, write_authority_config,
    write_protected_file, _validate_service_generations, _parse_observer_delivery_bindings,
    _parse_source_issuers, _parse_native_schema_artifact_records,
    _parse_composio_channel_enrollment_records, _parse_channel_delivery_binding_records,
    _validate_root_key_selection,
    RootSetupChoiceSigner,
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
            "size_bytes": 123, "derivation_receipt_handle": None,
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
        with self.assertRaises(AuthorityDenied):
            _parse_native_schema_artifact_records([{**row, "size_bytes": 262145}])
        dynamic = {**row, "artifact_id": "native-mcp-schema:" + "a" * 64,
                   "derivation_receipt_handle": "derived-schema-receipt"}
        self.assertEqual(_parse_native_schema_artifact_records([dynamic])[0]["size_bytes"], 123)
        with self.assertRaises(AuthorityDenied):
            _parse_native_schema_artifact_records([{**dynamic, "derivation_receipt_handle": None}])

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

    def test_source_issuer_private_provider_route_ceiling_is_optional_finite_and_protected(self):
        row = {
            "issuer_channel_id": "native-input", "producer_profile_id": "producer-profile",
            "producer_role_artifact_id": "role-artifact", "producer_role_sha256": "a" * 64,
            "capture_schema_id": "capture-schema", "allowed_parent_channels": [],
            "generation": "process-g1", "observer_enrollment_id": "observer-a",
            "source_action_ids": ["authenticated-input"],
        }
        legacy = _parse_source_issuers([row])[0]
        self.assertEqual(legacy.private_provider_route_ids, ())
        selected = _parse_source_issuers([{**row, "private_provider_route_ids": ["provider-route-a"]}])[0]
        self.assertEqual(selected.private_provider_route_ids, ("provider-route-a",))
        with self.assertRaises(AuthorityDenied):
            _parse_source_issuers([{**row, "private_provider_route_ids": ["provider-route-a"] * 2}])
        with self.assertRaises(AuthorityDenied):
            _parse_source_issuers([{**row, "private_provider_route_ids": ["route\nunsafe"]}])
    @unittest.skipUnless(os.geteuid() == 0, "root-key signer fixture requires uid 0")
    def test_setup_choice_signer_binds_finite_purpose_and_live_key_bytes(self):
        class Issuer:
            checks = 0
            def _verify_normal_choice_signer(self, signer):
                self.checks += 1

        with tempfile.TemporaryDirectory(prefix="setup-choice-key-") as temp:
            key_path = Path(temp) / "key"
            key_path.write_bytes(b"k" * 32)
            key_path.chmod(0o600)
            fd = os.open(key_path, os.O_RDONLY)
            try:
                info = os.fstat(fd)
                issuer = Issuer()
                from hermes_installer.authority.enrollment import RootSetupChoiceSigner
                signer = RootSetupChoiceSigner(
                    issuer, key_fd=fd, session_handle=object(), key_id="authority-key-fixture",
                    key_device=info.st_dev, key_inode=info.st_ino,
                    key_digest=hashlib.sha256(b"k" * 32).hexdigest(), adoption_record={},
                )
                payload = b'{"schema":1,"choice":"private"}'
                signature = signer.sign_choice("existing-model-selection", payload)
                self.assertTrue(signer.verify_choice("existing-model-selection", payload, signature))
                self.assertFalse(signer.verify_choice("memory-service-enablement", payload, signature))
                self.assertFalse(signer.verify_choice("existing-model-selection", payload + b" ", signature))
                with self.assertRaises(AuthorityDenied):
                    signer.sign_choice("unbounded-purpose", payload)
                self.assertGreaterEqual(issuer.checks, 4)
            finally:
                os.close(fd)

    @unittest.skipUnless(os.geteuid() == 0, "root-key adoption fixture requires uid 0")
    def test_normal_setup_adopts_and_reopens_same_durable_key_signer(self):
        from hermes_installer.authority import enrollment
        from hermes_installer.authority.bootstrap_enrollment import RootSetupSessionHandle, RootSetupSessionStore

        class LiveStore(RootSetupSessionStore):
            def _live(self, handle):
                if handle != session_handle or self.revoked:
                    raise AuthorityDenied("setup.choice", "fixture session is revoked")
                return object()

            @staticmethod
            def _proof(_live):
                return proof

        class CurrentVerifier:
            def verify_current(self, _plan):
                if self.revoked:
                    raise AuthorityDenied("setup.choice", "fixture actor is revoked")

            revoked = False

        with tempfile.TemporaryDirectory(prefix="normal-setup-key-adoption-") as temp:
            root = Path(temp)
            root.chmod(0o700)
            key_path = root / "authority.key"
            key_path.write_bytes(b"z" * 32)
            key_path.chmod(0o600)
            key_info = key_path.stat()
            key_digest = hashlib.sha256(b"z" * 32).hexdigest()
            session_handle = RootSetupSessionHandle("setup-" + "a" * 32, "session-seal")
            proof = SimpleNamespace(
                setup_session_id=session_handle.session_id, transaction_handle="transaction-current",
                plan_digest="1" * 64, plan_artifact_id="setup-plan", expires_monotonic=time.monotonic() + 300,
            )
            handoff = SimpleNamespace(
                handoff_handle="handoff-current", compilation_session_handle="b" * 64,
                compilation_transaction_handle="c" * 64, plan_sha256=proof.plan_digest,
                publication_receipt_handle="publication-receipt", publication_sha256="2" * 64,
                normal_transaction_handle=proof.transaction_handle,
            )
            actor = CurrentVerifier()
            plan = object()
            store = object.__new__(LiveStore)
            store.revoked = False
            store.plan_resolver = SimpleNamespace(resolve=lambda _artifact: plan)
            store.actor_verifier = actor
            stage0 = SimpleNamespace(
                compilation_session_handle="b" * 64, compilation_transaction_handle="c" * 64,
                plan_sha256=proof.plan_digest, verified_release_receipt_handle="release-receipt",
            )
            initial = SimpleNamespace(
                resolve_adopted_handoff=lambda _handle: handoff,
                actor=actor,
                _session_store=store,
            )
            receipt = enrollment.RootAuthorityKeyReceipt(
                1, "d" * 64, "authority-key-" + "e" * 32, "HMAC-SHA256",
                key_info.st_dev, key_info.st_ino, 0, 0o600, "release-receipt",
                stage0.compilation_session_handle, time.monotonic(), time.monotonic() + 30, "issuer-seal",
            )
            registry = object.__new__(enrollment.RootAuthorityKeySelectionRegistry)
            registry.release = SimpleNamespace(receipt_handle="release-receipt")
            registry.actor_verifier = actor
            registry.root_journal = root
            registry.initial_compilation_registry = initial
            registry.private_root_name = "authority-key-receipts"
            registry._normal_signers = {}
            registry._key_fds = {receipt.receipt_handle: os.open(key_path, os.O_RDONLY)}
            registry._key_digests = {receipt.receipt_handle: key_digest}
            registry._resolve_stage0 = lambda _handle: stage0
            registry.resolve_selected_key = lambda *_args: receipt
            registry._normal_signer_path = lambda _session_id: root / "normal-signer.json"
            registry._open_key = lambda: (os.open(key_path, os.O_RDONLY), key_path.stat(), key_path.read_bytes())
            registry._read_selection = lambda: {
                "key_id": receipt.key_id, "key_device": receipt.key_device,
                "key_inode": receipt.key_inode, "release_receipt_handle": receipt.release_receipt_handle,
                "receipt_handle": receipt.receipt_handle,
                "initial_compilation_session_handle": stage0.compilation_session_handle,
            }
            registry._verify_private_binding = lambda *_args: None
            (root / "authority-key-receipts").mkdir(mode=0o700)
            private_binding = {"schema": 1, "receipt_handle": receipt.receipt_handle,
                               "key_device": key_info.st_dev, "key_inode": key_info.st_ino,
                               "key_sha256": key_digest}
            (root / "authority-key-receipts" / f"{receipt.receipt_handle}.json").write_text(
                json.dumps(private_binding, sort_keys=True, separators=(",", ":")), encoding="ascii")
            (root / "authority-key-receipts" / f"{receipt.receipt_handle}.json").chmod(0o600)

            def write_fixture(path, document, *, exclusive=False):
                payload = json.dumps(dict(document), sort_keys=True, separators=(",", ":"), ensure_ascii=True)
                flags = os.O_WRONLY | os.O_CREAT | (os.O_EXCL if exclusive else os.O_TRUNC)
                fd = os.open(path, flags, 0o600)
                try:
                    os.write(fd, payload.encode("ascii"))
                    os.fsync(fd)
                finally:
                    os.close(fd)

            def read_fixture(path, _maximum):
                info = path.lstat()
                if info.st_uid != 0 or info.st_gid != 0 or stat.S_IMODE(info.st_mode) != 0o600:
                    raise AuthorityDenied("setup.choice", "fixture custody changed")
                return path.read_bytes()

            try:
                with mock.patch.object(enrollment, "_write_root_selection", write_fixture), \
                     mock.patch.object(enrollment, "_read_root_selection_bytes", read_fixture):
                    signer = registry.adopt_for_normal_setup(
                        receipt.receipt_handle, stage0.compilation_session_handle,
                        session_handle, handoff.handoff_handle,
                    )
                    payload = b'{"choice":"keep-existing-store","schema":1}'
                    signature = signer.sign_choice("existing-model-selection", payload)
                    self.assertTrue(signer.verify_choice("existing-model-selection", payload, signature))
                    retried = registry.adopt_for_normal_setup(
                        receipt.receipt_handle, stage0.compilation_session_handle,
                        session_handle, handoff.handoff_handle,
                    )
                    self.assertIs(retried, signer)

                    # Simulate a caller losing its in-memory signer and resolving the
                    # durable setup binding again without minting or rotating the key.
                    registry._normal_signers.clear()
                    reopened = registry.resolve_normal_setup_choice_signer(session_handle)
                    self.assertEqual(reopened.key_id, receipt.key_id)
                    self.assertTrue(reopened.verify_choice("existing-model-selection", payload, signature))

                    with self.assertRaises(AuthorityDenied):
                        registry.adopt_for_normal_setup(
                            receipt.receipt_handle, stage0.compilation_session_handle,
                            session_handle, "forged-handoff",
                        )

                    actor.revoked = True
                    with self.assertRaises(AuthorityDenied):
                        reopened.sign_choice("existing-model-selection", payload)
            finally:
                os.close(registry._key_fds[receipt.receipt_handle])

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
                "remote_observation_enrollments": [], "native_schema_artifacts": [], "composio_channel_enrollments": [], "channel_delivery_bindings": [], "remote_startup_enrollments": [], "private_loopback_networks": [], "selected_resource_executions": [], "selected_application_runtimes": [], "private_memory_endpoint_selections": [], "private_memory_model_selections": [], "public_web_scopes": [],
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
            "remote_observation_enrollments": [], "native_schema_artifacts": [], "composio_channel_enrollments": [], "channel_delivery_bindings": [], "remote_startup_enrollments": [], "private_loopback_networks": [], "selected_resource_executions": [], "selected_application_runtimes": [], "private_memory_endpoint_selections": [], "private_memory_model_selections": [], "public_web_scopes": [],
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
        public = _parse_source_issuers([{**source, "public_web_scope_ids": ["scope-a", "scope-b"]}])[0]
        self.assertEqual(public.public_web_scope_ids, ("scope-a", "scope-b"))
        for bad_scopes in (["scope-b", "scope-a"], ["scope-a", "scope-a"], ["bad\nidentifier"]):
            with self.subTest(bad_scopes=bad_scopes), self.assertRaises(AuthorityDenied):
                _parse_source_issuers([{**source, "public_web_scope_ids": bad_scopes}])
        with self.assertRaises(AuthorityDenied):
            _parse_source_issuers([{**source, "public_web_scope_ids": [f"scope-{i:02d}" for i in range(33)]}])
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
            "remote_observation_enrollments": [], "native_schema_artifacts": [], "composio_channel_enrollments": [], "channel_delivery_bindings": [], "remote_startup_enrollments": [], "private_loopback_networks": [], "selected_resource_executions": [], "selected_application_runtimes": [], "private_memory_endpoint_selections": [], "private_memory_model_selections": [], "public_web_scopes": [],
        }
        snapshot["generation_digest"] = hashlib.sha256(json.dumps(
            snapshot, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        ).encode("utf-8")).hexdigest()
        self.assertEqual(len(_validate_service_generations(snapshot)["source_issuers"]), 1)
        changed = dict(snapshot)
        changed["source_issuers"] = []
        with self.assertRaises(AuthorityDenied):
            _validate_service_generations(changed)
        public_snapshot = dict(snapshot)
        public_snapshot["source_issuers"] = [{**source, "public_web_scope_ids": ["scope-a"]}]
        public_snapshot["generation_digest"] = hashlib.sha256(json.dumps(
            {key: value for key, value in public_snapshot.items() if key != "generation_digest"},
            sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        ).encode("utf-8")).hexdigest()
        _validate_service_generations(public_snapshot)
        public_snapshot["source_issuers"][0]["public_web_scope_ids"] = ["scope-b"]
        with self.assertRaises(AuthorityDenied):
            _validate_service_generations(public_snapshot)

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
                    {"enrollment_id": "gateway-enrollment-a", "profile_id": "gateway-a",
                     "generation": "gateway-generation-a"},
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
            "remote_observation_enrollments": [], "native_schema_artifacts": [], "composio_channel_enrollments": [], "channel_delivery_bindings": [], "remote_startup_enrollments": [], "private_loopback_networks": [], "selected_resource_executions": [], "selected_application_runtimes": [], "private_memory_endpoint_selections": [], "private_memory_model_selections": [], "public_web_scopes": [],
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

        network = {
            "id": "loopback-a", "generation": "network-generation-a",
            "namespace_identity": "namespace-a",
            "member_enrollment_ids": ["display-enrollment-a", "gateway-enrollment-a",
                                      "desktop-enrollment-a"],
            "listener_bindings": [{"enrollment_id": "gateway-enrollment-a", "role": "gateway",
                                   "ipv4": "127.0.0.1", "port": 8743}],
            "client_bindings": [{"enrollment_id": "desktop-enrollment-a",
                                 "listener_enrollment_id": "gateway-enrollment-a", "port": 8743}],
            "policy_artifact_id": "loopback-policy-a", "policy_sha256": "e" * 64,
        }
        startup = {
            "id": "startup-a", "remote_enrollment_id": "remote-a",
            "display_enrollment_id": "display-enrollment-a", "display_generation": "display-generation",
            "display_operation_id": "native-display-start-v1",
            "gateway_enrollment_id": "gateway-enrollment-a", "gateway_generation": "gateway-generation-a",
            "gateway_operation_id": "native-remote-gateway-start-v1",
            "desktop_enrollment_id": "desktop-enrollment-a", "desktop_generation": "desktop-generation-a",
            "desktop_operation_id": "native-desktop-app-start-v1",
            "network_enrollment_id": "loopback-a", "xauthority_mount_id": "xauthority-mount-a",
            "xpra_xauthority_overlay_artifact_id": "xpra-overlay-a",
            "xpra_xauthority_overlay_sha256": "f" * 64,
            "xpra_xauthority_patch_receipt_handle": "patch-receipt-a",
        }
        valid_startup = snapshot_with([fields])
        valid_startup["private_loopback_networks"] = [network]
        valid_startup["remote_startup_enrollments"] = [startup]
        valid_startup["remote_observation_enrollments"] = [observation]
        valid_startup["generation_digest"] = hashlib.sha256(json.dumps(
            {key: value for key, value in valid_startup.items() if key != "generation_digest"},
            sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        ).encode("utf-8")).hexdigest()
        self.assertEqual(len(_validate_service_generations(valid_startup)["remote_startup_enrollments"]), 1)
        invalid_startup = dict(valid_startup)
        invalid_startup["remote_startup_enrollments"] = [{**startup, "gateway_operation_id": "process.start"}]
        invalid_startup["generation_digest"] = hashlib.sha256(json.dumps(
            {key: value for key, value in invalid_startup.items() if key != "generation_digest"},
            sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        ).encode("utf-8")).hexdigest()
        with self.assertRaises(AuthorityDenied):
            _validate_service_generations(invalid_startup)

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
            "remote_observation_enrollments": [], "native_schema_artifacts": [], "composio_channel_enrollments": [], "channel_delivery_bindings": [], "remote_startup_enrollments": [], "private_loopback_networks": [], "selected_resource_executions": [], "selected_application_runtimes": [], "private_memory_endpoint_selections": [], "private_memory_model_selections": [], "public_web_scopes": [],
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

    def test_selected_resource_execution_row_uses_enclosing_digest_without_self_reference(self):
        resource_generation = "3" * 64
        backend = {
            "id": "backend-a", "resource_id": "resource-a", "profile_id": "profile-a",
            "principal_id": "principal-a", "generation": resource_generation,
            "consent_revision": "consent-a", "source_issuer_channel_id": "tool-result",
            "observer_enrollment_id": "observer-a", "native_package_id": "package-a",
            "native_package_generation": "package-generation-a", "handler_artifact_id": "handler-a",
            "handler_sha256": "a" * 64, "approved_action_ids": ["action-a"],
            "operation": "resource.webhook.deliver", "target_id": "resource:webhooks/hook-a@1.0.0",
            "recipient": "recipient-a", "credential_reference_ids": [], "request_schema_id": "request-a",
            "result_schema_id": "result-a", "body_recipe_id": "body-a", "scope_binding_id": "scope-a",
            "maximum_request_bytes": 1024, "maximum_response_bytes": 2048, "maximum_seconds": 30,
            "profile_generation": "profile-generation-a", "execution_binding": None,
            "credential_bindings": [],
        }
        scope = {
            "id": "scope-a", "resource_id": "resource-a", "profile_id": "profile-a",
            "principal_id": "principal-a", "resource_generation": resource_generation,
            "profile_generation": "profile-generation-a", "backend_enrollment_id": "backend-a",
            "fixed_fields": {}, "credential_reference_ids": [], "recipient": "recipient-a",
        }
        selected = {
            "resource_id": "resource-a", "resource_kind": "webhooks",
            "source_revision": "1" * 40, "source_manifest_sha256": "2" * 64,
            "resource_generation": resource_generation, "profile_id": "profile-a",
            "profile_generation": "profile-generation-a", "materialization_receipt_handle": "receipt-a",
            "materialized_member_path": "webhooks/hook-a.yaml", "materialized_member_sha256": "4" * 64,
            "materialized_member_size_bytes": 512, "effective_spec_sha256": "5" * 64,
            "backend_enrollment_id": "backend-a", "operation": backend["operation"],
            "capability": "webhook:deliver", "target_id": backend["target_id"],
            "recipient": "recipient-a", "delegation_id": "delegation-a", "enabled": True,
        }
        snapshot = {
            "schema": 1, "generation_id": "generation-a",
            "service_records": [{"enrollment_id": "service-a", "generation": "profile-generation-a",
                                 "profile_id": "profile-a", "principal_id": "principal-a"}],
            "protected_devices": [], "protected_build_records": [], "native_packages": [],
            "memory_enrollments": [], "operation_parameter_schemas": [], "source_issuers": [],
            "resource_jobs": [], "remote_session_enrollments": [],
            "resource_backend_enrollments": [backend], "resource_body_recipes": [],
            "resource_scope_bindings": [scope], "resource_validators": [], "root_journal_roots": [],
            "resource_controller_roles": [], "native_mcp_tool_bindings": [],
            "remote_observation_enrollments": [], "native_schema_artifacts": [],
            "composio_channel_enrollments": [], "channel_delivery_bindings": [],
            "remote_startup_enrollments": [], "private_loopback_networks": [],
            "selected_resource_executions": [selected], "selected_application_runtimes": [], "private_memory_endpoint_selections": [], "private_memory_model_selections": [], "public_web_scopes": [],
        }
        snapshot["generation_digest"] = hashlib.sha256(json.dumps(
            snapshot, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        ).encode("utf-8")).hexdigest()
        parsed = _validate_service_generations(snapshot)
        self.assertEqual(parsed["selected_resource_executions"][0], selected)
        malformed = dict(snapshot)
        malformed["selected_resource_executions"] = [{**selected, "service_generation_digest": "f" * 64}]
        malformed["generation_digest"] = hashlib.sha256(json.dumps(
            {key: value for key, value in malformed.items() if key != "generation_digest"},
            sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        ).encode("utf-8")).hexdigest()
        with self.assertRaises(AuthorityDenied):
            _validate_service_generations(malformed)

    def test_selected_application_runtime_row_is_strict_and_joins_current_service(self):
        row = {
            "application_id": "application-a", "profile_id": "profile-a",
            "profile_generation": "profile-generation-a", "principal_id": "principal-a",
            "adapter_id": "adapter-a", "source_identity": "https://github.com/example/app",
            "source_revision": "1" * 40, "source_tree_sha256": "2" * 64,
            "source_generation_receipt_handle": "source-receipt-a",
            "source_generation_manifest_sha256": "3" * 64, "runtime_id": "runtime-a",
            "runtime_receipt_handle": "runtime-receipt-a", "runtime_manifest_sha256": "4" * 64,
            "lock_sha256": "5" * 64, "work_root_id": "work-a", "data_root_id": "data-a",
            "operation_id": "application-run-v1", "process_start_target": "application:start",
            "request_schema_id": "request-schema-a", "request_schema_sha256": "6" * 64,
            "result_schema_id": "result-schema-a", "result_validator_artifact_id": "result-validator-a",
            "result_validator_sha256": "7" * 64, "capability_ids": ["application:run"],
            "provider_route_ids": [], "credential_reference_ids": [],
            "account_eligibility_receipt_handle": None, "memory_owner_generation": None,
            "max_lifetime_seconds": 60, "max_memory_bytes": 1024 * 1024,
            "max_workers": 1, "metered_budget_usd": 0, "enabled": False,
        }
        service = {
            "enrollment_id": "service-a", "generation": "profile-generation-a",
            "profile_id": "profile-a", "principal_id": "principal-a",
            "roots": {"work_id": "work-a", "data_id": "data-a"},
            "operation_targets": {"process.start": "application:start"},
            "operation_recipes": {"application-run-v1": {}},
        }
        snapshot = {
            "schema": 1, "generation_id": "generation-a", "service_records": [service],
            "protected_devices": [], "protected_build_records": [], "native_packages": [],
            "memory_enrollments": [], "operation_parameter_schemas": [], "source_issuers": [],
            "resource_jobs": [], "remote_session_enrollments": [], "resource_backend_enrollments": [],
            "resource_body_recipes": [], "resource_scope_bindings": [], "resource_validators": [],
            "root_journal_roots": [], "resource_controller_roles": [], "native_mcp_tool_bindings": [],
            "remote_observation_enrollments": [], "native_schema_artifacts": [],
            "composio_channel_enrollments": [], "channel_delivery_bindings": [],
            "remote_startup_enrollments": [], "private_loopback_networks": [],
            "selected_resource_executions": [], "selected_application_runtimes": [row],
            "private_memory_endpoint_selections": [], "private_memory_model_selections": [], "public_web_scopes": [],
        }

        def sign(value):
            value["generation_digest"] = hashlib.sha256(json.dumps(
                {key: child for key, child in value.items() if key != "generation_digest"},
                sort_keys=True, separators=(",", ":"), ensure_ascii=False,
            ).encode("utf-8")).hexdigest()
            return value

        parsed = _validate_service_generations(sign(dict(snapshot)))
        self.assertEqual(parsed["selected_application_runtimes"], [row])
        stale = dict(snapshot)
        stale["selected_application_runtimes"] = [{**row, "process_start_target": "other:start"}]
        with self.assertRaises(AuthorityDenied):
            _validate_service_generations(sign(stale))
        recursive = dict(snapshot)
        recursive["selected_application_runtimes"] = [{**row, "service_generation_digest": "8" * 64}]
        with self.assertRaises(AuthorityDenied):
            _validate_service_generations(sign(recursive))

    def test_private_memory_selection_rows_are_digest_bound_exact_and_fk_checked(self):
        endpoint = {
            "binding_id": "endpoint-a", "profile_id": "profile-a",
            "namespace_id": "namespace-a", "principal_id": "principal-a",
            "service_enrollment_id": "service-a", "service_generation": "service-gen-a",
            "process_profile_id": "process-profile-a", "process_profile_generation": "process-gen-a",
            "endpoint_target_id": "memory-openviking:profile-a",
            "connector_route_ids": ["memory-search-v1"], "recipient_id": "recipient-a",
            "credential_reference_id": "credential-a", "server_config_artifact_id": "config-a",
            "server_config_sha256": "a" * 64, "runtime_artifact_ids": ["runtime-a"],
            "network_binding_handle": "network-receipt-a",
        }
        model = {
            "binding_id": "model-a", "endpoint_binding_id": "endpoint-a",
            "served_model_id": "served-a", "source_model_id": "source-a",
            "source_revision": "revision-a", "license_artifact_id": "license-a",
            "license_sha256": "b" * 64, "model_artifact_id": "model-artifact-a",
            "model_artifact_sha256": "c" * 64, "model_tree_manifest_sha256": "d" * 64,
            "runtime_artifact_id": "model-runtime-a", "runtime_artifact_sha256": "e" * 64,
            "load_config_artifact_id": "load-config-a", "load_config_sha256": "f" * 64,
            "capability": "extraction-text", "dimensions": None,
        }

        def snapshot(endpoint_rows, model_rows):
            value = {
                "schema": 1, "generation_id": "snapshot-a", "service_records": [],
                "protected_devices": [], "protected_build_records": [], "native_packages": [],
                "memory_enrollments": [], "operation_parameter_schemas": [], "source_issuers": [],
                "resource_jobs": [], "remote_session_enrollments": [], "resource_backend_enrollments": [],
                "resource_body_recipes": [], "resource_scope_bindings": [], "resource_validators": [],
                "root_journal_roots": [], "resource_controller_roles": [], "native_mcp_tool_bindings": [],
                "remote_observation_enrollments": [], "native_schema_artifacts": [],
                "composio_channel_enrollments": [], "channel_delivery_bindings": [],
                "remote_startup_enrollments": [], "private_loopback_networks": [],
                "selected_resource_executions": [], "selected_application_runtimes": [],
                "private_memory_endpoint_selections": endpoint_rows,
                "private_memory_model_selections": model_rows,
                "public_web_scopes": [],
            }
            value["generation_digest"] = hashlib.sha256(json.dumps(
                value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
            ).encode("utf-8")).hexdigest()
            return value

        parsed = _validate_service_generations(snapshot([endpoint], [model]))
        self.assertEqual(parsed["private_memory_endpoint_selections"], [endpoint])
        self.assertEqual(parsed["private_memory_model_selections"], [model])
        for bad_endpoint in ({**endpoint, "extra": True},
                             {**endpoint, "service_generation_digest": "1" * 64},
                             {**endpoint, "connector_route_ids": ["memory-search-v1"] * 2}):
            with self.assertRaises(AuthorityDenied):
                _validate_service_generations(snapshot([bad_endpoint], [model]))
        with self.assertRaises(AuthorityDenied):
            _validate_service_generations(snapshot([endpoint], [{**model, "endpoint_binding_id": "missing"}]))
        with self.assertRaises(AuthorityDenied):
            _validate_service_generations(snapshot([endpoint], [{**model, "capability": "embedding", "dimensions": None}]))

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
            "remote_observation_enrollments": [], "native_schema_artifacts": [], "composio_channel_enrollments": [], "channel_delivery_bindings": [], "remote_startup_enrollments": [], "private_loopback_networks": [], "selected_resource_executions": [], "selected_application_runtimes": [], "private_memory_endpoint_selections": [], "private_memory_model_selections": [], "public_web_scopes": [],
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
            "remote_observation_enrollments": [], "native_schema_artifacts": [], "composio_channel_enrollments": [], "channel_delivery_bindings": [], "remote_startup_enrollments": [], "private_loopback_networks": [], "selected_resource_executions": [], "selected_application_runtimes": [], "private_memory_endpoint_selections": [], "private_memory_model_selections": [], "public_web_scopes": [],
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
            "remote_observation_enrollments": [], "native_schema_artifacts": [], "composio_channel_enrollments": [], "channel_delivery_bindings": [], "remote_startup_enrollments": [], "private_loopback_networks": [], "selected_resource_executions": [], "selected_application_runtimes": [], "private_memory_endpoint_selections": [], "private_memory_model_selections": [], "public_web_scopes": [],
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
