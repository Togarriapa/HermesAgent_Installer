from __future__ import annotations

import hashlib
import json
import os
import secrets
import stat
import shutil
import unittest
import pwd
import grp
from pathlib import Path
from hermes_installer.authority.bootstrap_enrollment import (
    BootstrapEnrollmentError,
    BootstrapEnrollmentRequest,
    EnrollmentPolicy,
    RootBootstrapEnrollment,
    ServiceIdentity,
    SystemIdentityAdapter,
    VerifiedArtifactReceipt,
    _copy_verified_artifact,
    _create_service_root,
    _atomic_root_file,
    _generation,
    _validate_authority_base,
    _validate_policy,
    _validate_request,
    _verify_service_root,
    _write_journal,
)
from hermes_installer.authority.enrollment import _validate_service_generations


class BootstrapEnrollmentContracts(unittest.TestCase):
    def test_generation_uses_complete_utf8_canonical_snapshot_digest(self):
        snapshot = _generation(EnrollmentPolicy(
            service_profile_id="hermes-profile", principal_id="hermes-service",
            generation_id="root-generation-1", source_artifact_id="hermes-source",
            records=({"label": "café"},),
        ))
        self.assertEqual(_validate_service_generations(snapshot), snapshot)
        expected = hashlib.sha256(json.dumps(
            {key: value for key, value in snapshot.items() if key != "generation_digest"},
            sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        ).encode("utf-8")).hexdigest()
        self.assertEqual(snapshot["generation_digest"], expected)
        changed = dict(snapshot)
        changed["service_records"] = [{"label": "cafe"}]
        with self.assertRaises(Exception):
            _validate_service_generations(changed)

    def test_request_accepts_only_opaque_bounded_handles_and_intent(self):
        _validate_request(BootstrapEnrollmentRequest(("receipt:opaque-1",), "transaction:opaque-1"))
        with self.assertRaises(BootstrapEnrollmentError):
            _validate_request(BootstrapEnrollmentRequest(("/etc/passwd",), "transaction:opaque-1"))
        # Caller path/executable/UID fields are deliberately not part of the DTO.
        self.assertEqual(set(BootstrapEnrollmentRequest.__dataclass_fields__),
                         {"artifact_receipt_handles", "operation_intent"})

    def test_incomplete_root_policy_is_rejected(self):
        policy = EnrollmentPolicy("profile", "principal", "generation", "source", ())
        with self.assertRaises(BootstrapEnrollmentError):
            _validate_policy(policy)
        without_source = EnrollmentPolicy("profile", "principal", "generation", "", ({"row": 1},))
        with self.assertRaises(BootstrapEnrollmentError):
            _validate_policy(without_source)

    def test_new_authority_requires_full_root_selected_base_document(self):
        base = {key: {} for key in (
            "key_id", "principals", "rules", "authentik", "process_profiles",
            "provider_enrollments", "mcp_services", "mcp_http_bindings", "memory_providers",
            "native_bridges", "normalization_policies", "delegations", "service_generations",
        )}
        base["schema"] = 1
        _validate_authority_base(base)
        invalid = dict(base)
        invalid["authentik"] = {"password": "secret"}
        with self.assertRaises(BootstrapEnrollmentError):
            _validate_authority_base(invalid)


@unittest.skipUnless(os.name == "posix" and os.geteuid() == 0 and Path("/proc/sys/kernel/ostype").exists(),
                     "requires an isolated Linux root test runner")
class LinuxRootBootstrapFixtures(unittest.TestCase):
    """Uses a uniquely named disposable system account and real root-owned files."""
    def test_identity_roots_artifact_verification_and_foreign_conflict(self):
        base = Path("/var/lib/hermes-installer")
        base.mkdir(mode=0o700, exist_ok=True)
        fixture_id = secrets.token_hex(6)
        fixture = base / (".bootstrap-fixture-" + fixture_id)
        fixture.mkdir(mode=0o700)
        service_name = "hinst-" + fixture_id
        identity = None
        try:
            adapter = SystemIdentityAdapter(fixture / "identity.json", name=service_name)
            identity = adapter.ensure()
            self.assertTrue(identity.created)
            self.assertEqual(pwd.getpwnam(service_name).pw_uid, identity.uid)
            self.assertEqual(grp.getgrnam(service_name).gr_gid, identity.gid)

            roots = Path("/var/lib/hermes-installer/services") / fixture_id
            service_home = roots / "home"
            self.assertTrue(_create_service_root(service_home, identity))
            _verify_service_root(service_home, identity)
            conflict = roots / "foreign"
            conflict.mkdir(mode=0o700)
            with self.assertRaises(BootstrapEnrollmentError):
                _verify_service_root(conflict, identity)

            source = fixture / "source.tar"
            source.write_bytes(b"pinned fixture source")
            digest = hashlib.sha256(source.read_bytes()).hexdigest()
            store = fixture / "artifact-store"
            store.mkdir(mode=0o700)
            receipt = VerifiedArtifactReceipt("fixture-receipt", "fixture-source", digest, source, 1024)
            target = store / digest
            _copy_verified_artifact(receipt, target)
            self.assertEqual(hashlib.sha256(target.read_bytes()).hexdigest(), digest)
            self.assertEqual(target.stat().st_uid, 0)
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o444)

            link = fixture / "source-link"
            link.symlink_to(source)
            with self.assertRaises(BootstrapEnrollmentError):
                _copy_verified_artifact(VerifiedArtifactReceipt(
                    "bad", "fixture-source", digest, link, 1024), store / ("f" * 64))
            self.assertEqual(source.read_bytes(), b"pinned fixture source")
        finally:
            # Test-owned service data is empty and the OS account has no home.
            if identity is not None:
                service_home = Path("/var/lib/hermes-installer/services") / fixture_id / "home"
                try:
                    _verify_service_root(service_home, identity)
                    service_home.rmdir()
                except OSError:
                    pass
                adapter.remove_if_created(identity)
            shutil.rmtree(fixture, ignore_errors=True)
            try:
                (Path("/var/lib/hermes-installer/services") / fixture_id / "foreign").rmdir()
                (Path("/var/lib/hermes-installer/services") / fixture_id).rmdir()
                Path("/var/lib/hermes-installer/services").rmdir()
                base.rmdir()
            except OSError:
                pass

    def test_interrupted_commit_restores_snapshot_and_only_removes_owned_empty_root(self):
        base = Path("/var/lib/hermes-installer")
        base.mkdir(mode=0o700, exist_ok=True)
        fixture_id = secrets.token_hex(6)
        fixture = base / (".bootstrap-recovery-" + fixture_id)
        fixture.mkdir(mode=0o700)
        txroot = fixture / "transactions"
        txroot.mkdir(mode=0o700)
        account_name = "hrec-" + fixture_id
        adapter = SystemIdentityAdapter(fixture / "identity.json", name=account_name)
        identity = adapter.ensure()
        transaction_id = secrets.token_hex(16)
        authority_path = fixture / "authority.json"
        old = {"schema": 1, "service_generations": {"schema": 1, "generation_id": "old",
              "service_records": [], "protected_devices": [], "protected_build_records": [],
              "native_packages": [], "memory_enrollments": [], "operation_parameter_schemas": []}}
        old["service_generations"]["generation_digest"] = hashlib.sha256(json.dumps(
            {key: value for key, value in old["service_generations"].items() if key != "generation_digest"},
            sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        ).encode()).hexdigest()
        new = json.loads(json.dumps(old))
        new["service_generations"]["generation_id"] = "new"
        new["service_generations"].pop("generation_digest")
        new["service_generations"]["generation_digest"] = hashlib.sha256(json.dumps(
            {key: value for key, value in new["service_generations"].items() if key != "generation_digest"},
            sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        ).encode()).hexdigest()
        old_bytes = json.dumps(old, sort_keys=True, separators=(",", ":")).encode()
        new_bytes = json.dumps(new, sort_keys=True, separators=(",", ":")).encode()
        backup = txroot / f"{transaction_id}.authority.previous"
        _atomic_root_file(backup, old_bytes)
        _atomic_root_file(authority_path, new_bytes)
        service_root = Path("/var/lib/hermes-installer/services") / fixture_id / "home"
        _create_service_root(service_root, identity)
        digest = new["service_generations"]["generation_digest"]
        journal = txroot / f"{transaction_id}.json"
        _write_journal(journal, transaction_id, "committing", [service_root], [],
                       roots=(service_root,), backup=backup, identity=identity,
                       generation_digest=digest)
        transaction = RootBootstrapEnrollment(
            policy_resolver=lambda _request: None,
            receipt_resolver=lambda _handle: None,
            identity=adapter, authority_path=authority_path,
            transaction_root=txroot, artifact_root=fixture / "artifacts",
        )
        self.assertEqual(transaction.recover(transaction_id), "rolled_back")
        self.assertEqual(authority_path.read_bytes(), old_bytes)
        self.assertFalse(service_root.exists())
        with self.assertRaises(KeyError):
            pwd.getpwnam(account_name)
        shutil.rmtree(fixture, ignore_errors=True)
        try:
            (Path("/var/lib/hermes-installer/services") / fixture_id).rmdir()
            Path("/var/lib/hermes-installer/services").rmdir()
            base.rmdir()
        except OSError:
            pass


if __name__ == "__main__":
    unittest.main()
