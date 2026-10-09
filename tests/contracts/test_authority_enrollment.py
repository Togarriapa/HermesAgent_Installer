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
