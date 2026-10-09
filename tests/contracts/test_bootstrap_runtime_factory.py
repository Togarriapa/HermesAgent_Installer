from __future__ import annotations

import unittest
import os
from pathlib import Path

from hermes_installer.authority.bootstrap_enrollment import BootstrapEnrollmentPending, VerifiedRootSetupAuthorization
from hermes_installer.authority.bootstrap_runtime_factory import (
    RootBootstrapRuntimeFactory,
    RootSetupPolicyFactory,
    VerifiedRootBootstrapPolicy,
)


class RootBootstrapRuntimeFactoryContracts(unittest.TestCase):
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
                         "service_parent_root": "/var/lib/hermes-installer/services"},
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
                "resource_validators", "root_journal_roots")},
            receipt_binding_rules=(),
        )

        class Resolver:
            @staticmethod
            def resolve_policy(_plan_id):
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
        self.assertEqual(prepared.home_root.as_posix(), "/var/lib/hermes-installer/services/home")
        self.assertEqual(prepared.data_root.as_posix(), "/var/lib/hermes-installer/services/data")


if __name__ == "__main__":
    unittest.main()
