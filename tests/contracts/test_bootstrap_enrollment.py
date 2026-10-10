from __future__ import annotations

import hashlib
import json
import os
import secrets
import stat
import shutil
import time
import unittest
import pwd
import grp
from pathlib import Path
from hermes_installer.authority.bootstrap_enrollment import (
    BootstrapEnrollmentError,
    BootstrapEnrollmentRequest,
    BootstrapEnrollmentClient,
    EnrollmentReceipt,
    EnrollmentPolicy,
    RootBootstrapProvisionOperation,
    VerifiedRootSetupAuthorization,
    RootBootstrapEnrollment,
    RootSetupSessionHandle,
    RootSetupSessionStore,
    ServiceIdentity,
    SystemIdentityAdapter,
    VerifiedArtifactReceipt,
    VerifiedRootSetupPlan,
    _LiveSetupSession,
    _process_start_time,
    _read_boot_id,
    _copy_verified_artifact,
    _create_service_root,
    _atomic_root_file,
    _generation,
    _validate_authority_base,
    _validate_policy,
    _validate_prepared_policy,
    _validate_request,
    _verify_service_root,
    _write_journal,
)
from hermes_installer.authority.enrollment import _validate_service_generations


class BootstrapEnrollmentContracts(unittest.TestCase):
    def test_prepared_policy_keeps_root_journal_selection_without_enabling_catalogs(self):
        policy = EnrollmentPolicy(
            service_profile_id="hermes-profile", principal_id="hermes-service",
            generation_id="prepared-fixture", source_artifact_id="hermes-source",
            records=(), activation_state="prepared",
            resource_controller_roles=(), native_mcp_tool_bindings=(),
            remote_observation_enrollments=(),
            root_journal_roots=({"root_id": "installer-authority-journal-v1"},),
        )
        _validate_prepared_policy(policy)
        with self.assertRaises(BootstrapEnrollmentError):
            _validate_prepared_policy(EnrollmentPolicy(
                service_profile_id="hermes-profile", principal_id="hermes-service",
                generation_id="prepared-fixture", source_artifact_id="hermes-source",
                records=(), activation_state="prepared",
                resource_controller_roles=(), native_mcp_tool_bindings=(),
                remote_observation_enrollments=(),
                root_journal_roots=policy.root_journal_roots,
                native_packages=({"id": "must-not-enable"},),
            ))

    def test_generation_uses_complete_utf8_canonical_snapshot_digest(self):
        snapshot = _generation(EnrollmentPolicy(
            service_profile_id="hermes-profile", principal_id="hermes-service",
            generation_id="root-generation-1", source_artifact_id="hermes-source",
            records=({"label": "café"},),
            resource_controller_roles=(), native_mcp_tool_bindings=(),
            remote_observation_enrollments=(),
        ))
        self.assertEqual(_validate_service_generations(snapshot), snapshot)
        self.assertEqual(set(snapshot), {
            "schema", "generation_id", "service_records", "protected_devices",
            "protected_build_records", "native_packages", "memory_enrollments",
            "operation_parameter_schemas", "source_issuers", "resource_jobs",
            "remote_session_enrollments", "resource_backend_enrollments",
            "resource_body_recipes", "resource_scope_bindings", "resource_validators",
            "root_journal_roots",
            "remote_startup_enrollments", "private_loopback_networks", "selected_resource_executions",
            "selected_application_runtimes",
            "native_schema_artifacts", "composio_channel_enrollments", "channel_delivery_bindings",
            "resource_controller_roles", "native_mcp_tool_bindings",
            "remote_observation_enrollments",
            "native_schema_artifacts", "composio_channel_enrollments",
            "channel_delivery_bindings",
            "generation_digest",
        })
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

    def test_root_provision_uses_kernel_peer_and_independent_setup_admission(self):
        receipt = EnrollmentReceipt(1, "transaction:root-issued", "receipt:root-issued",
                                    "generation-1", "a" * 64, None, "committed",
                                    ("enrollment-1",), time.monotonic(), time.monotonic() + 30.0)

        class Transaction:
            def enroll(self, request, *, setup_authorization):
                self.request = request
                self.proof = setup_authorization
                return receipt

        class SetupAuthorizer:
            def authorize(self, *, peer_uid, peer_gid, request):
                return VerifiedRootSetupAuthorization(
                    "service-generation:bootstrap:install", "setup-session-1",
                    "b" * 64, 501, request.operation_intent)

        transaction = Transaction()
        operation = RootBootstrapProvisionOperation(transaction, SetupAuthorizer())
        payload = {"schema": 1, "artifact_receipt_handles": ["source:opaque"],
                   "operation_intent": "transaction:root-issued"}
        response = operation.handle(payload, peer_uid=0, peer_gid=0)
        self.assertEqual(response["generation_digest"], "a" * 64)
        self.assertEqual(transaction.request.artifact_receipt_handles, ("source:opaque",))
        self.assertEqual(transaction.proof.operator_uid, 501)
        with self.assertRaises(BootstrapEnrollmentError):
            operation.handle(payload, peer_uid=501, peer_gid=501)

    def test_root_source_provider_runs_after_admission_and_only_handle_reaches_transaction(self):
        receipt = EnrollmentReceipt(1, "transaction:root-issued", "receipt:root-issued",
                                    "generation-1", "a" * 64, None, "prepared",
                                    ("enrollment-1",), time.monotonic(), time.monotonic() + 30.0)

        class Transaction:
            def enroll(self, request, *, setup_authorization):
                self.request = request
                self.proof = setup_authorization
                return receipt

        class SetupAuthorizer:
            def authorize(self, *, peer_uid, peer_gid, request):
                return VerifiedRootSetupAuthorization(
                    "service-generation:bootstrap:install", "setup-session-1",
                    "b" * 64, 501, request.operation_intent)

        calls = []
        def source_provider(proof):
            calls.append(proof)
            return "opaque-source-receipt-handle-0123456789"

        transaction = Transaction()
        operation = RootBootstrapProvisionOperation(transaction, SetupAuthorizer(),
                                                   source_receipt_provider=source_provider)
        response = operation.handle({"schema": 1, "artifact_receipt_handles": [],
                                     "operation_intent": "transaction:root-issued"},
                                    peer_uid=0, peer_gid=0)
        self.assertEqual(response["state"], "prepared")
        self.assertEqual(len(calls), 1)
        self.assertIs(transaction.proof, calls[0])
        self.assertEqual(transaction.request.artifact_receipt_handles,
                         ("opaque-source-receipt-handle-0123456789",))
        self.assertNotIn("source", transaction.request.__dataclass_fields__)

    def test_root_source_provider_is_not_called_before_setup_admission(self):
        class Transaction:
            def enroll(self, *_args, **_kwargs):
                raise AssertionError("must not reach transaction")

        class SetupAuthorizer:
            def authorize(self, **_kwargs):
                raise BootstrapEnrollmentError("setup admission denied")

        def source_provider(_proof):
            raise AssertionError("must not fetch before setup admission")

        operation = RootBootstrapProvisionOperation(Transaction(), SetupAuthorizer(),
                                                   source_receipt_provider=source_provider)
        with self.assertRaises(BootstrapEnrollmentError):
            operation.handle({"schema": 1, "artifact_receipt_handles": [],
                              "operation_intent": "transaction:root-issued"},
                             peer_uid=0, peer_gid=0)

    def test_root_provision_rejects_caller_selected_paths_and_unissued_intent(self):
        class Transaction:
            def enroll(self, *_args, **_kwargs):
                raise AssertionError("must not reach transaction")

        class SetupAuthorizer:
            def authorize(self, *, peer_uid, peer_gid, request):
                return VerifiedRootSetupAuthorization(
                    "service-generation:bootstrap:install", "setup-session-1",
                    "b" * 64, 501, "transaction:another")

        operation = RootBootstrapProvisionOperation(Transaction(), SetupAuthorizer())
        with self.assertRaises(BootstrapEnrollmentError):
            operation.handle({"schema": 1, "artifact_receipt_handles": ["source:1"],
                              "operation_intent": "transaction:invented", "path": "/tmp/x"},
                             peer_uid=0, peer_gid=0)

    def test_typed_root_client_sends_exact_fixed_verb_and_parses_pathless_receipt(self):
        calls = []
        def rpc(operation, payload):
            calls.append((operation, dict(payload)))
            return {"schema": 1, "transaction_handle": "transaction:1",
                    "provision_receipt_handle": "receipt:1", "generation_id": "gen-1",
                    "generation_digest": "c" * 64, "previous_generation_digest": None,
                    "state": "committed", "enrollment_ids": ["enrollment-1"],
                    "issued_monotonic": time.monotonic(),
                    "expires_monotonic": time.monotonic() + 30.0}

        result = BootstrapEnrollmentClient(rpc).provision(("source:opaque",), "transaction:1")
        self.assertEqual(calls[0][0], "enrollment.provision")
        self.assertEqual(set(calls[0][1]), {"schema", "artifact_receipt_handles", "operation_intent"})
        self.assertEqual(result.generation_id, "gen-1")
        self.assertFalse(hasattr(result, "path"))

    def test_incomplete_root_policy_is_rejected(self):
        policy = EnrollmentPolicy("profile", "principal", "generation", "source", (),
                                  resource_controller_roles=(), native_mcp_tool_bindings=(),
                                  remote_observation_enrollments=())
        with self.assertRaises(BootstrapEnrollmentError):
            _validate_policy(policy)
        without_source = EnrollmentPolicy(
            "profile", "principal", "generation", "", (),
            resource_controller_roles=(), native_mcp_tool_bindings=(),
            remote_observation_enrollments=(),
        )
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

    def test_committed_receipt_requires_unique_durable_current_cas_match(self):
        base = Path("/var/lib/hermes-installer")
        base.mkdir(mode=0o700, exist_ok=True)
        fixture_id = secrets.token_hex(6)
        fixture = base / (".bootstrap-cas-" + fixture_id)
        journal = fixture / "journal"
        session_root = journal / "setup-sessions"
        transaction_root = journal / "bootstrap-transactions"
        fixture.mkdir(mode=0o700)
        journal.mkdir(mode=0o700)
        session_root.mkdir(mode=0o700)
        transaction_root.mkdir(mode=0o700)
        authority_path = fixture / "authority.json"
        generation = {"generation_id": "generation-" + fixture_id,
                      "generation_digest": "d" * 64}
        try:
            plan = VerifiedRootSetupPlan(
                "installer-root-setup-plan-v1", "a" * 64,
                "installer-root-setup-launcher-v1", "b" * 64,
                Path("/usr/bin/true"), Path("/usr/bin/python3"), "c" * 64, (), (),
            )
            actor = {"pid": os.getpid(), "process_start_time": _process_start_time(os.getpid())}

            class ActorVerifier:
                def verify_current(self, _plan):
                    return actor

            actor_verifier = ActorVerifier()
            handle = RootSetupSessionHandle("setup-" + fixture_id, "s" * 64)
            journal_info = journal.lstat()
            root_record = {
                "root_id": "installer-authority-journal-v1", "absolute_path": str(journal),
                "owner_uid": 0, "owner_gid": 0, "mode": 0o700,
                "device": journal_info.st_dev, "inode": journal_info.st_ino,
                "generation": "journal-" + fixture_id, "purpose": "authority-journal",
            }
            record = {
                "setup_session_id": handle.session_id, "target_id": "target-" + fixture_id,
                "operator_uid": 0, "target_uid": 1000, "target_gid": 1000,
                "mode": "install", "plan_artifact_id": plan.artifact_id,
                "plan_digest": plan.digest, "launcher_artifact_id": plan.launcher_artifact_id,
                "launcher_sha256": plan.launcher_sha256, "root_actor_identity": actor,
                "transaction_handle": "transaction-" + fixture_id,
                "expected_previous_generation_digest": "f" * 64,
                "issued_monotonic": time.monotonic(), "expires_monotonic": time.monotonic() + 300,
                "boot_id": _read_boot_id(), "root_journal_root": root_record,
            }
            live = _LiveSetupSession(handle, record, plan, os.pidfd_open(os.getpid()), "s" * 64)
            store = RootSetupSessionStore.__new__(RootSetupSessionStore)
            store.plan_resolver = object()
            store.actor_verifier = actor_verifier
            store.receipt_registry = object()
            store.session_root = session_root
            store.transaction_root = transaction_root
            store.authority_path = authority_path
            store._instance_seal = "store-seal-" + fixture_id
            store._sessions = {handle.session_id: live}

            receipt = EnrollmentReceipt(
                1, record["transaction_handle"], "e" * 48,
                generation["generation_id"], generation["generation_digest"],
                "f" * 64, "committed", (), time.monotonic(), time.monotonic() + 120,
            )
            _atomic_root_file(authority_path, json.dumps({"service_generations": generation}).encode())
            transaction_id = secrets.token_hex(16)
            transaction_authorization = store._proof(live)
            _write_journal(
                transaction_root / f"{transaction_id}.json", transaction_id, "committed", [], [],
                generation_digest=receipt.generation_digest,
                provision_receipt_handle=receipt.provision_receipt_handle,
                previous_generation_digest=receipt.previous_generation_digest,
                setup_authorization=transaction_authorization,
            )
            record["expected_previous_generation_digest"] = receipt.generation_digest
            authorization = store._proof(live)
            verified = store.verify_committed_receipt(receipt, authorization)
            self.assertEqual(verified.journal_transaction_id, transaction_id)
            self.assertEqual(verified.receipt, receipt)
            forged = EnrollmentReceipt(
                1, receipt.transaction_handle, receipt.provision_receipt_handle,
                receipt.generation_id, "a" * 64, receipt.previous_generation_digest,
                "committed", (), receipt.issued_monotonic, receipt.expires_monotonic,
            )
            with self.assertRaises(BootstrapEnrollmentPending):
                store.verify_committed_receipt(forged, authorization)
            second_id = secrets.token_hex(16)
            _write_journal(
                transaction_root / f"{second_id}.json", second_id, "committed", [], [],
                generation_digest=receipt.generation_digest,
                provision_receipt_handle=receipt.provision_receipt_handle,
                previous_generation_digest=receipt.previous_generation_digest,
                setup_authorization=transaction_authorization,
            )
            with self.assertRaises(BootstrapEnrollmentPending):
                store.verify_committed_receipt(receipt, authorization)
        finally:
            try:
                os.close(live.pidfd)
            except (NameError, OSError):
                pass
            shutil.rmtree(fixture, ignore_errors=True)
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

    def test_first_snapshot_provision_then_health_rollback_uses_real_account_and_custody(self):
        base = Path("/var/lib/hermes-installer")
        base.mkdir(mode=0o700, exist_ok=True)
        fixture_id = secrets.token_hex(6)
        fixture = base / (".bootstrap-first-" + fixture_id)
        fixture.mkdir(mode=0o700)
        txroot = fixture / "transactions"
        store = fixture / "artifact-store"
        txroot.mkdir(mode=0o700)
        store.mkdir(mode=0o700)
        service_parent = Path("/var/lib/hermes-installer/services") / fixture_id
        roots = tuple(service_parent / name for name in ("home", "work", "data"))
        service_name = "hboot" + fixture_id
        adapter = SystemIdentityAdapter(fixture / "identity.json", name=service_name)
        source = fixture / "official-fixture-source.tar"
        source.write_bytes(b"owned root enrollment fixture payload")
        digest = hashlib.sha256(source.read_bytes()).hexdigest()
        base_authority = {key: {} for key in (
            "key_id", "principals", "rules", "authentik", "process_profiles",
            "provider_enrollments", "mcp_services", "mcp_http_bindings", "memory_providers",
            "native_bridges", "normalization_policies", "delegations", "service_generations",
        )}
        base_authority["schema"] = 1
        phase = {"value": "prepared"}

        def policy_resolver(request, proof):
            self.assertEqual(request.operation_intent, proof.transaction_handle)
            return EnrollmentPolicy(
                service_profile_id="hermes-profile", principal_id="hermes-service",
                generation_id="fixture-generation-" + phase["value"] + "-" + fixture_id,
                source_artifact_id="hermes-fixture-source", records=(),
                resource_controller_roles=(), native_mcp_tool_bindings=(),
                remote_observation_enrollments=(),
                authority_base=base_authority,
                activation_state=phase["value"],
                home_root=roots[0], work_root=roots[1], data_root=roots[2],
                root_journal_roots=(dict(proof.root_journal_root),),
            )

        def record_builder(policy, identity):
            executable = Path("/usr/bin/true")
            executable_sha = hashlib.sha256(executable.read_bytes()).hexdigest()
            root_ids = ["fixture-home-" + fixture_id, "fixture-work-" + fixture_id,
                        "fixture-data-" + fixture_id]
            return ({
                "enrollment_id": "fixture-enrollment-" + fixture_id,
                "generation": policy.generation_id, "profile_id": policy.service_profile_id,
                "principal_id": policy.principal_id, "service_uid": identity.uid,
                "service_gid": identity.gid, "service_user": identity.name,
                "device_enrollment_id": None, "expected_device_generation": None,
                "executable": str(executable), "executable_sha256": executable_sha,
                "runtime_artifact_ids": ["hermes-fixture-source"],
                "package_runtime_records": {},
                "roots": {"home_id": root_ids[0], "work_id": root_ids[1],
                          "data_id": root_ids[2], "home": str(policy.home_root),
                          "work": str(policy.work_root), "data": str(policy.data_root)},
                "authority_endpoint_id": "fixture-authority-endpoint",
                "namespace_identity": "fixture-namespace-" + fixture_id,
                "socket_policy_id": "fixture-socket-policy", "target_route_ids": [],
                "operation_targets": {},
                "operation_recipes": {"fixture-health": {
                    "executable_artifact_id": "hermes-fixture-source",
                    "executable_sha256": executable_sha,
                    "argv_recipe": [{"literal": str(executable)}],
                    "cwd_root_id": root_ids[0], "cwd_subpath": "work",
                    "environment": {}, "child_artifact_refs": {},
                    "max_lifetime_seconds": 60, "max_output_bytes": 1024,
                    "stdin_mode": "closed", "parameter_schema_id": "fixture-parameters",
                }},
                "argv_recipe": [str(executable)], "environment": {},
                "max_lifetime_seconds": 60, "memory_max_bytes": 1_073_741_824,
                "cpu_quota_percent": 100, "io_weight": 100,
            },)

        class FixtureResolver:
            def resolve(self, handle, *, setup_authorization):
                self.assert_setup(setup_authorization)
                if handle != "source-fixture":
                    raise BootstrapEnrollmentError("fixture handle is not enrolled")
                return VerifiedArtifactReceipt("fixture-receipt", "hermes-fixture-source",
                                               digest, source, 1024)

            @staticmethod
            def assert_setup(proof):
                if proof.target_id != "service-generation:bootstrap:install":
                    raise BootstrapEnrollmentError("fixture setup scope does not match")

        transaction = RootBootstrapEnrollment(
            policy_resolver=policy_resolver, receipt_resolver=FixtureResolver(),
            identity=adapter, record_builder=record_builder,
            authority_path=fixture / "authority.json", transaction_root=txroot,
            artifact_root=store, root_journal_path=fixture,
        )
        journal_info = fixture.lstat()
        setup_proof = VerifiedRootSetupAuthorization(
            "service-generation:bootstrap:install", "fixture-setup-" + fixture_id,
            "a" * 64, os.getuid(), "transaction:fixture-" + fixture_id,
            root_journal_root={
                "root_id": "installer-authority-journal-v1", "absolute_path": str(fixture),
                "owner_uid": 0, "owner_gid": 0, "mode": 0o700,
                "device": journal_info.st_dev, "inode": journal_info.st_ino,
                "generation": "journal-fixture-" + fixture_id,
                "purpose": "authority-journal",
            })
        request = BootstrapEnrollmentRequest(("source-fixture",), setup_proof.transaction_handle)
        try:
            prepared = transaction.enroll(request, setup_authorization=setup_proof)
            self.assertEqual(prepared.state, "prepared")
            self.assertEqual(prepared.enrollment_ids, ())
            prepared_snapshot = json.loads((fixture / "authority.json").read_text())
            self.assertEqual(prepared_snapshot["service_generations"]["service_records"], [])
            self.assertEqual(prepared_snapshot["service_generations"]["root_journal_roots"],
                             [dict(setup_proof.root_journal_root)])
            phase["value"] = "active"
            result = transaction.enroll(request, setup_authorization=setup_proof)
            self.assertEqual(result.state, "committed")
            snapshot = json.loads((fixture / "authority.json").read_text())
            self.assertEqual(snapshot["service_generations"]["generation_digest"], result.generation_digest)
            self.assertEqual(set(snapshot["service_generations"]), {
                "schema", "generation_id", "service_records", "protected_devices",
                "protected_build_records", "native_packages", "memory_enrollments",
                "operation_parameter_schemas", "source_issuers", "resource_jobs",
                "remote_session_enrollments", "resource_backend_enrollments",
                "resource_body_recipes", "resource_scope_bindings", "resource_validators",
                "root_journal_roots",
                "generation_digest",
            })
            for root in roots:
                info = root.lstat()
                self.assertEqual((info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)),
                                 (pwd.getpwnam(service_name).pw_uid, grp.getgrnam(service_name).gr_gid, 0o700))
            stored = store / digest
            self.assertEqual(hashlib.sha256(stored.read_bytes()).hexdigest(), digest)
            self.assertEqual((stored.stat().st_uid, stat.S_IMODE(stored.stat().st_mode)), (0, 0o444))

            self.assertEqual(transaction.rollback(result.provision_receipt_handle,
                                                  expected_generation_digest=result.generation_digest),
                             "rolled_back")
            self.assertEqual(json.loads((fixture / "authority.json").read_text())
                             ["service_generations"]["generation_digest"], prepared.generation_digest)
            self.assertEqual(transaction.rollback(prepared.provision_receipt_handle,
                                                  expected_generation_digest=prepared.generation_digest),
                             "rolled_back")
            self.assertFalse((fixture / "authority.json").exists())
            self.assertFalse(any(root.exists() for root in roots))
            with self.assertRaises(KeyError):
                pwd.getpwnam(service_name)
            self.assertFalse(stored.exists())
        finally:
            try:
                adapter.remove_if_created(ServiceIdentity(
                    service_name, pwd.getpwnam(service_name).pw_uid,
                    grp.getgrnam(service_name).gr_gid, True))
            except KeyError:
                pass
            shutil.rmtree(fixture, ignore_errors=True)
            try:
                service_parent.rmdir()
            except OSError:
                pass


if __name__ == "__main__":
    unittest.main()
