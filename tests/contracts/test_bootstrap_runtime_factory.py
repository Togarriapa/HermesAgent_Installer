from __future__ import annotations

import unittest
import os
from pathlib import Path

from hermes_installer.authority.bootstrap_enrollment import (
    BootstrapEnrollmentPending, EnrollmentPolicy, ServiceIdentity, VerifiedRootSetupAuthorization, _generation,
)
from hermes_installer.authority.bootstrap_runtime_factory import (
    InstalledBootstrapPolicyResolver,
    RootComposioSetupSelectionAuthority,
    RootBootstrapRuntimeFactory,
    RootSetupPolicyFactory,
    RootRuntimeArtifactReceipt,
    VerifiedRootBootstrapPolicy,
)


class RootBootstrapRuntimeFactoryContracts(unittest.TestCase):
    def test_prepared_authority_base_accepts_only_exact_empty_root_snapshot(self):
        root = {"root_id": "installer-authority-journal-v1",
                "absolute_path": "/var/lib/hermes-installer/authority-journal",
                "owner_uid": 0, "owner_gid": 0, "mode": 0o700, "device": 1,
                "inode": 2, "generation": "journal-fixture", "purpose": "authority-journal"}
        generation = _generation(EnrollmentPolicy(
            service_profile_id="profile", principal_id="principal", generation_id="prepared-fixture",
            source_artifact_id="source", records=(), resource_controller_roles=(),
            native_mcp_tool_bindings=(), remote_observation_enrollments=(),
            root_journal_roots=(root,), activation_state="prepared"))
        base = {"schema": 1, "key_id": "authority-key-fixture", "principals": {}, "rules": {},
                "authentik": {}, "process_profiles": {}, "provider_enrollments": {},
                "mcp_services": {}, "mcp_http_bindings": {}, "memory_providers": {},
                "native_bridges": {}, "normalization_policies": {}, "delegations": {},
                "service_generations": generation}
        InstalledBootstrapPolicyResolver._validate_authority_base_template(base)
        empty_template = dict(base)
        empty_template["key_id"] = {"root_binding": "authority_key.key_id"}
        empty_template["service_generations"] = {
            "root_binding": "prepared_service_generation.exact_empty_snapshot"}
        InstalledBootstrapPolicyResolver._validate_authority_base_template(empty_template)
        for mutate in (
                lambda value: value.update(service_generations={}),
                lambda value: value["service_generations"].update(service_records=[{"enabled": True}]),
                lambda value: value["service_generations"].update(root_journal_roots=[]),
                lambda value: value.update(authentik={"token": "must-not-exist"})):
            invalid = {**base, "service_generations": dict(generation), "authentik": {}}
            mutate(invalid)
            with self.subTest(invalid=invalid), self.assertRaises(BootstrapEnrollmentPending):
                InstalledBootstrapPolicyResolver._validate_authority_base_template(invalid)

    def test_composio_catalog_projection_is_pinned_version_and_strictly_bounded(self):
        authority = object.__new__(RootComposioSetupSelectionAuthority)
        authority._SLUG = RootComposioSetupSelectionAuthority._SLUG
        row = {"slug": "WHATSAPP_MESSAGE", "name": "Send message", "description": "Send",
               "type": "trigger", "toolkit": {"slug": "whatsapp", "name": "WhatsApp"},
               "version": "20260721_00", "config": {}, "payload": {}}
        projected = authority._trigger_projection(row, "20260721_00")
        self.assertEqual(projected["toolkit"], {"slug": "whatsapp", "version": "20260721_00"})
        self.assertNotIn("instructions", projected)
        with self.assertRaises(BootstrapEnrollmentPending):
            authority._trigger_projection({**row, "version": "other"}, "20260721_00")
        with self.assertRaises(BootstrapEnrollmentPending):
            authority._trigger_projection({**row, "unreviewed": "field"}, "20260721_00")

    def test_installed_factory_has_no_caller_selected_trust_paths(self):
        with self.assertRaises(TypeError):
            RootBootstrapRuntimeFactory(selection_path="/tmp/caller-selection.json")

    def test_factory_refuses_non_linux_or_uninstalled_root_trust(self):
        if os.geteuid() == 0 and Path("/proc/sys/kernel/ostype").exists() \
                and Path("/etc/hermes-installer/root-setup-selection.json").exists():
            self.skipTest("real installed root selection is outside this source-checkout fixture")
        with self.assertRaises(BootstrapEnrollmentPending):
            RootBootstrapRuntimeFactory.from_installed()

    def test_prepared_policy_is_concrete_empty_and_journal_bound(self):
        policy = VerifiedRootBootstrapPolicy(
            artifact_id="installer-bootstrap-policy-v1", sha256="a" * 64,
            plan_artifact_id="installer-root-setup-plan-v1", source_artifact_id="hermes-source-v1",
            identity_policy={"service_profile_id": "hermes-profile", "principal_id": "hermes-service",
                             "service_account_name": "hermes-service", "exclusive_group_name": "hermes-service",
                             "uid_allocation": "root-dedicated-account"},
            root_policy={"journal_root_id": "installer-authority-journal-v1",
                         "service_home_root_id": "hermes-home-v1", "service_work_root_id": "hermes-work-v1",
                         "service_data_root_id": "hermes-data-v1",
                         "service_parent_root": "/var/lib/hermes-installer/services/hermes-agent-native-v1"},
            authority_base_template={"schema": 1, "key_id": "root-key", "principals": {}, "rules": {},
                                     "authentik": {}, "process_profiles": {}, "provider_enrollments": {},
                                     "mcp_services": {}, "mcp_http_bindings": {}, "memory_providers": {},
                                     "native_bridges": {}, "normalization_policies": {}, "delegations": {},
                                     "service_generations": {}},
            service_record_templates=(),
            catalog_selections={name: () for name in (
                "protected_devices", "protected_build_records", "native_packages", "memory_enrollments",
                "operation_parameter_schemas", "source_issuers", "resource_jobs", "remote_session_enrollments",
                "resource_backend_enrollments", "resource_body_recipes", "resource_scope_bindings",
                "resource_validators", "root_journal_roots", "resource_controller_roles",
                "native_mcp_tool_bindings", "remote_observation_enrollments",
                "native_schema_artifacts", "composio_channel_enrollments", "channel_delivery_bindings")},
            receipt_binding_rules=(),
        )

        class Resolver:
            @staticmethod
            def resolve_policy(_plan_id, **_kwargs):
                return policy

        authorization = VerifiedRootSetupAuthorization(
            target_id="local-target-fixture", setup_session_id="setup-fixture", plan_digest="b" * 64,
            operator_uid=501, transaction_handle="transaction-fixture",
            plan_artifact_id="installer-root-setup-plan-v1",
            root_journal_root={"root_id": "installer-authority-journal-v1",
                               "absolute_path": "/var/lib/hermes-installer/authority-journal",
                               "owner_uid": 0, "owner_gid": 0, "mode": 0o700, "device": 1,
                               "inode": 2, "generation": "journal-fixture", "purpose": "authority-journal"},
        )
        prepared = RootSetupPolicyFactory(Resolver()).prepare(authorization)
        self.assertEqual(prepared.activation_state, "prepared")
        self.assertEqual(prepared.records, ())
        self.assertEqual(prepared.root_journal_roots, (dict(authorization.root_journal_root),))
        self.assertEqual(prepared.home_root.as_posix(), "/var/lib/hermes-installer/services/hermes-agent-native-v1/home")
        self.assertEqual(prepared.data_root.as_posix(), "/var/lib/hermes-installer/services/hermes-agent-native-v1/data")

    def test_prepared_policy_can_activate_only_after_a_root_runtime_receipt(self):
        record = {"generation": "template-generation", "service_uid": 0, "service_gid": 0,
                  "runtime_artifact_id": None}
        policy = VerifiedRootBootstrapPolicy(
            artifact_id="installer-bootstrap-policy-v1", sha256="a" * 64,
            plan_artifact_id="installer-root-setup-plan-v1", source_artifact_id="hermes-source-v1",
            identity_policy={"service_profile_id": "hermes-profile", "principal_id": "selected-principal",
                             "service_account_name": "hermes-service", "exclusive_group_name": "hermes-service",
                             "uid_allocation": "root-dedicated-account"},
            root_policy={"journal_root_id": "installer-authority-journal-v1",
                         "service_home_root_id": "hermes-home-v1", "service_work_root_id": "hermes-work-v1",
                         "service_data_root_id": "hermes-data-v1",
                         "service_parent_root": "/var/lib/hermes-installer/services/hermes-agent-native-v1"},
            authority_base_template={"schema": 1, "key_id": "root-key", "principals": {}, "rules": {},
                                     "authentik": {}, "process_profiles": {}, "provider_enrollments": {},
                                     "mcp_services": {}, "mcp_http_bindings": {}, "memory_providers": {},
                                     "native_bridges": {}, "normalization_policies": {}, "delegations": {},
                                     "service_generations": {}},
            service_record_templates=({"id": "selected-template", "record": record,
                                      "receipt_bindings": ({"field_path": ["runtime_artifact_id"],
                                                            "receipt_role": "official-pm-runtime",
                                                            "receipt_field": "artifact_id"},)},),
            catalog_selections={name: () for name in (
                "protected_devices", "protected_build_records", "native_packages", "memory_enrollments",
                "operation_parameter_schemas", "source_issuers", "resource_jobs", "remote_session_enrollments",
                "resource_backend_enrollments", "resource_body_recipes", "resource_scope_bindings",
                "resource_validators", "root_journal_roots", "resource_controller_roles",
                "native_mcp_tool_bindings", "remote_observation_enrollments",
                "native_schema_artifacts", "composio_channel_enrollments", "channel_delivery_bindings")},
            receipt_binding_rules=({"receipt_role": "official-pm-runtime",
                                    "allowed_artifact_ids": ["pm-runtime-fixture"],
                                    "allowed_output_kinds": ["source-archive"],
                                    "required_phase": "runnable",
                                    "field_bindings": [{"field_path": ["runtime_artifact_id"],
                                                        "receipt_role": "official-pm-runtime",
                                                        "receipt_field": "artifact_id"}]},),
        )

        class Resolver:
            @staticmethod
            def resolve_policy(_plan_id, **_kwargs):
                return policy

        authorization = VerifiedRootSetupAuthorization(
            target_id="local-target-fixture", setup_session_id="setup-fixture", plan_digest="b" * 64,
            operator_uid=501, transaction_handle="transaction-fixture",
            plan_artifact_id="installer-root-setup-plan-v1",
            root_journal_root={"root_id": "installer-authority-journal-v1",
                               "absolute_path": "/var/lib/hermes-installer/authority-journal",
                               "owner_uid": 0, "owner_gid": 0, "mode": 0o700, "device": 1,
                               "inode": 2, "generation": "journal-fixture", "purpose": "authority-journal"},
        )
        factory = RootSetupPolicyFactory(Resolver())
        prepared = factory.prepare(authorization)
        self.assertEqual((prepared.activation_state, prepared.records), ("prepared", ()))
        identity = ServiceIdentity("hermes-service", 1001, 1001)
        receipt = RootRuntimeArtifactReceipt(
            "official-pm-runtime", "pm-runtime-fixture", "c" * 64,
            authorization.transaction_handle, "d" * 64, 10, "test-seal")
        with self.assertRaises(BootstrapEnrollmentPending):
            factory.activate_runnable(authorization, identity, {}, seal="test-seal")
        unsealed = RootRuntimeArtifactReceipt(
            "official-pm-runtime", "pm-runtime-fixture", "c" * 64,
            authorization.transaction_handle, "d" * 64, 10, "other-session-seal")
        with self.assertRaises(BootstrapEnrollmentPending):
            factory.activate_runnable(authorization, identity,
                                      {"official-pm-runtime": unsealed}, seal="test-seal")
        active = factory.activate_runnable(
            authorization, identity, {"official-pm-runtime": receipt}, seal="test-seal")
        self.assertEqual(active.activation_state, "active")
        self.assertEqual(len(active.records), 1)
        self.assertEqual(active.records[0]["service_uid"], 1001)
        self.assertEqual(active.records[0]["runtime_artifact_id"], "pm-runtime-fixture")
        self.assertEqual(active.root_journal_roots, (dict(authorization.root_journal_root),))
        malformed = dict(authorization.root_journal_root)
        malformed["unreviewed_path"] = "/tmp/journal"
        with self.assertRaises(BootstrapEnrollmentPending):
            RootSetupPolicyFactory._root_journal_join(
                VerifiedRootSetupAuthorization(
                    target_id="local-target-fixture", setup_session_id="setup-fixture",
                    plan_digest="b" * 64, operator_uid=501, transaction_handle="transaction-fixture",
                    plan_artifact_id="installer-root-setup-plan-v1", root_journal_root=malformed))

    def test_receipt_rules_bind_one_exact_role_artifact_phase_and_output_kind(self):
        row = {"receipt_role": "official-pm-runtime",
               "allowed_artifact_ids": ["pm-runtime-314"],
               "allowed_output_kinds": ["pm-runtime"],
               "required_phase": "runnable", "field_bindings": []}
        parsed = InstalledBootstrapPolicyResolver._validate_receipt_binding_rules(
            [row], ["pm-runtime-314"])
        self.assertEqual(parsed, [row])
        for mutate in (
                lambda value: value.update(allowed_artifact_ids=["unselected-runtime"]),
                lambda value: value.update(required_phase="functional-health"),
                lambda value: value.update(allowed_output_kinds=["native-health"]),
                lambda value: value.update(receipt_role=["official-pm-runtime"]),
                lambda value: value.update(allowed_artifact_ids=[{}]),
                lambda value: value.update(allowed_output_kinds=[{}]),
                lambda value: value.update(unreviewed=True)):
            invalid = dict(row)
            mutate(invalid)
            with self.subTest(invalid=invalid), self.assertRaises(BootstrapEnrollmentPending):
                InstalledBootstrapPolicyResolver._validate_receipt_binding_rules(
                    [invalid], ["pm-runtime-314"])

    def test_receipt_rules_reject_cross_role_field_binding(self):
        row = {"receipt_role": "official-pm-runtime",
               "allowed_artifact_ids": ["pm-runtime-314"],
               "allowed_output_kinds": ["source-archive"],
               "required_phase": "runnable",
               "field_bindings": [{"field_path": ["executable_sha256"],
                                    "receipt_role": "official-agent-source",
                                    "receipt_field": "sha256"}]}
        with self.assertRaises(BootstrapEnrollmentPending):
            InstalledBootstrapPolicyResolver._validate_receipt_binding_rules(
                [row], ["pm-runtime-314"])

    def test_receipt_rules_require_role_specific_output_kind(self):
        for role, output in (("official-pm-runtime", "pm-runtime"),
                             ("native-compiled-closure", "compiled-closure"),
                             ("native-entrypoint-manifest", "entrypoint-json"),
                             ("native-action-resolver", "resolver-json"),
                             ("native-boundary-overlay", "boundary-overlay"),
                             ("native-candidate-index", "candidate-index-json"),
                             ("native-health", "native-health")):
            row = {"receipt_role": role, "allowed_artifact_ids": ["selected-output"],
                   "allowed_output_kinds": [output],
                   "required_phase": "functional-health" if role == "native-health" else "runnable",
                   "field_bindings": []}
            parsed = InstalledBootstrapPolicyResolver._validate_receipt_binding_rules(
                [row], ["selected-output"])
            self.assertEqual(parsed, [row])
            invalid = {**row, "allowed_output_kinds": ["source-archive"]}
            with self.subTest(role=role), self.assertRaises(BootstrapEnrollmentPending):
                InstalledBootstrapPolicyResolver._validate_receipt_binding_rules(
                    [invalid], ["selected-output"])

    def test_empty_runtime_receipt_ids_only_allowed_for_prepared_dormant_roles(self):
        row = {"receipt_role": "native-compiled-closure", "allowed_artifact_ids": [],
               "allowed_output_kinds": ["compiled-closure"], "required_phase": "runnable",
               "field_bindings": []}
        self.assertEqual(
            InstalledBootstrapPolicyResolver._validate_receipt_binding_rules(
                [row], [], dormant_prepared=True), [row])
        with self.assertRaises(BootstrapEnrollmentPending):
            InstalledBootstrapPolicyResolver._validate_receipt_binding_rules([row], [])


if __name__ == "__main__":
    unittest.main()
