from __future__ import annotations

import unittest

from hermes_installer.authority.root_controller_custody import (
    RootControllerRoleModuleRegistry,
)
from hermes_installer.authority.resource_controller_runtime import RootControllerRoleRuntime
from hermes_installer.authority.types import AuthorityDenied


class RootControllerRuntimeConstructorTests(unittest.TestCase):
    def test_module_loader_rejects_non_receipt_source(self):
        registry = RootControllerRoleModuleRegistry()
        with self.assertRaises(AuthorityDenied):
            registry.load_from_installed_release(
                release_receipt=object(), module_name="_untrusted_role_module",
                artifact_id="role-module", expected_sha256="a" * 64,
                service_generation_digest="b" * 64, controller_generation="release-1",
            )
        self.assertEqual(registry._proofs, {})

    def test_production_factory_rejects_untyped_or_missing_host_authority(self):
        with self.assertRaises(AuthorityDenied):
            RootControllerRoleRuntime.from_root_runtime(
                service=object(), enrollment=object(), bindings=object(),
                release_receipt=object(), actor_observation=object(), inspector=object(),
                job_enrollments={}, selected_resources=object(), source_observers=object(),
            )
