from __future__ import annotations

import json
import os
import platform
import pwd
import grp
import secrets
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest
from dataclasses import dataclass, replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest.mock import patch

from hermes_installer.authority.bootstrap_enrollment import (
    BootstrapEnrollmentError,
    BootstrapEnrollmentPending,
    EnrollmentReceipt,
    RootSetupSessionHandle,
    SystemIdentityAdapter,
    VerifiedRootSetupAuthorization,
)
from hermes_installer.authority.enrollment import RootCredentialVault
from hermes_installer.authority.setup_principal import (
    AuthentikIdentityReceipt,
    RootSetupLocalOwnerIdentityRegistry,
    RootSetupAuthentikIdentityObserver,
    RootSetupIdentityIntake,
    RootSetupIdentityIntake,
    RootSetupPrincipalSelectionRegistry,
    ReviewedPrincipalCapabilities,
    VerifiedAuthentikPolicySelection,
    _validate_origin_and_groups,
)
from hermes_installer.authority.types import AuthorityDenied


class _HTTPSAuthentikFixture:
    def __init__(self, directory: Path):
        self.calls: list[tuple[str, str]] = []
        self.current_user = {
            "pk": "subject-17", "username": "fixture-operator",
            "email": "operator@example.test", "is_active": True,
            "groups": ["members"],
        }
        self.groups = {
            "members": {"pk": "members", "parents": ["system"]},
            "system": {"pk": "system", "parents": []},
        }
        cert, key = directory / "cert.pem", directory / "key.pem"
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(key), "-out", str(cert), "-days", "1",
            "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost",
        ], check=True, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, timeout=10)
        fixture = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                fixture.calls.append((self.path, self.headers.get("Authorization", "")))
                if self.headers.get("Authorization") != "Bearer fixture-only-token":
                    self.send_error(401)
                    return
                if self.path == "/api/v3/core/users/me/":
                    body = {"user": fixture.current_user}
                elif self.path.startswith("/api/v3/core/groups/"):
                    group_id = self.path.rsplit("/", 2)[-2]
                    body = fixture.groups.get(group_id)
                    if body is None:
                        self.send_error(404)
                        return
                else:
                    self.send_error(404)
                    return
                encoded = json.dumps(body).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(encoded)))
                self.end_headers()
                self.wfile.write(encoded)

            def log_message(self, *_args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.origin = f"https://localhost:{self.server.server_port}"
        self.cert = cert

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)


def _policy(origin: str) -> VerifiedAuthentikPolicySelection:
    row = {
        "id": "authentik-setup-v1", "https_origin": origin,
        "system_group_id": "system", "recipient_group_id": "operators",
        "policy_revision": "authentik-policy-v1",
        "actor_credential_ref": "setup-authentik-actor",
    }
    import hashlib
    digest = hashlib.sha256(json.dumps(row, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return VerifiedAuthentikPolicySelection(
        selection_id=row["id"], https_origin=row["https_origin"],
        system_group_id=row["system_group_id"], recipient_group_id=row["recipient_group_id"],
        policy_revision=row["policy_revision"], actor_credential_ref=row["actor_credential_ref"],
        selection_digest=digest,
    )


class _PolicyResolver:
    def __init__(self, policy):
        self.policy = policy

    def resolve_policy_selection(self, _session, handle):
        if handle != "a" * 64:
            raise BootstrapEnrollmentPending("unknown setup policy handle")
        return self.policy

    def resolve_policy_selection_by_digest(self, _session, digest):
        if digest != self.policy.selection_digest:
            raise BootstrapEnrollmentPending("stale setup policy digest")
        return self.policy


class _Vault:
    def resolve_reference(self, reference, *, peer_uid, required_scope):
        assert reference == "setup-authentik-actor"
        assert peer_uid == 0
        assert required_scope == "authentik-system-read"
        return "fixture-only-token"


class _Capabilities:
    def select_for_identity(self, identity, _proof):
        assert identity.authentik_subject_id == "subject-17"
        return ReviewedPrincipalCapabilities(
            "hermes-agent-native-v1", "namespace:hermes-agent-native-v1",
            ("local-runtime",),
        )


class _LiveStore:
    def __init__(self, journal: Path):
        self.session_root = journal / "setup-sessions"
        self.handle = RootSetupSessionHandle("setup-fixture-1", "s" * 64)
        self.record = {
            "setup_session_id": "setup-fixture-1", "target_id": "target-fixture-1",
            "plan_digest": "b" * 64, "operator_uid": 0,
            "transaction_handle": "transaction-fixture-1", "target_uid": 1000,
            "target_gid": 1000, "mode": "install",
            "plan_artifact_id": "installer-root-setup-plan-v1",
            "launcher_artifact_id": "installer-root-setup-launcher-v1",
            "launcher_sha256": "l" * 64, "root_actor_identity": {"pid": 100},
            "expected_previous_generation_digest": None,
            "expires_monotonic": __import__("time").monotonic() + 300,
            "root_journal_root": {
                "root_id": "installer-authority-journal-v1",
                "absolute_path": str(journal), "owner_uid": 0, "owner_gid": 0,
                "mode": 0o700, "device": journal.stat().st_dev,
                "inode": journal.stat().st_ino, "generation": "journal-fixture-1",
                "purpose": "authority-journal",
            },
        }
        self.live = SimpleNamespace(handle=self.handle, record=self.record)

    def _live(self, handle):
        if handle != self.handle:
            raise ValueError("unknown session")
        if self.record["expires_monotonic"] <= __import__("time").monotonic():
            raise ValueError("expired")
        return self.live


class SetupPrincipalHTTPContract(unittest.TestCase):
    def test_policy_choices_reject_unsafe_origin_and_ambiguous_groups(self):
        for origin in ("http://auth.example.test", "https://auth.example.test/path",
                       "https://user@auth.example.test", "https://auth.example.test/?next=x"):
            with self.subTest(origin=origin), self.assertRaises(BootstrapEnrollmentPending):
                _validate_origin_and_groups(origin, "system", "operators")
        with self.assertRaises(BootstrapEnrollmentPending):
            _validate_origin_and_groups("https://auth.example.test", "same", "same")

    def test_stage0_observer_rejects_untyped_registry(self):
        with self.assertRaises(ValueError):
            RootSetupAuthentikIdentityObserver.from_initial_compilation(
                object(), _PolicyResolver(_policy("https://auth.example.test")),
                _Vault(), Path("/var/lib/hermes-installer/authority-journal"),
            )

    def test_stage0_intake_rejects_untyped_registry(self):
        with self.assertRaises(ValueError):
            RootSetupIdentityIntake.from_initial_compilation(
                object(), object(), object(),
                Path("/var/lib/hermes-installer/authority-journal"),
            )

    def test_adopted_policy_requires_current_normal_session_and_publication_join(self):
        import hermes_installer.authority.setup_principal as principal_module

        with tempfile.TemporaryDirectory(prefix="setup-principal-adoption-") as temp:
            journal = Path(temp)
            store = _LiveStore(journal)
            handoff = SimpleNamespace(
                normal_setup_session_id=store.record["setup_session_id"],
                normal_transaction_handle=store.record["transaction_handle"],
                compilation_session_handle="compile-fixture",
                compilation_transaction_handle="compile-tx-fixture",
                plan_sha256="c" * 64,
                principal_selection_receipt_handle="a" * 64,
            )

            class InitialRegistry:
                def resolve_adopted_handoff(self, handle):
                    if handle != store.handle:
                        raise ValueError("foreign session")
                    return handoff

            class PrincipalRegistry:
                def _read_selection(self, _handle):
                    return SimpleNamespace(
                        setup_session_id="compile-fixture",
                        transaction_handle="compile-tx-fixture",
                        plan_digest="c" * 64,
                        authentik_subject_id="subject-17",
                        actor_credential_ref="setup-authentik-actor",
                    )

            policy = _policy("https://auth.example.test")
            resolver = principal_module._AdoptedNormalPolicyResolver(
                store=store, handle=store.handle, initial_registry=InitialRegistry(),
                principal_registry=PrincipalRegistry(),
                principal_selection_receipt_handle="a" * 64, policy=policy,
                initial_subject="subject-17", initial_credential_ref="setup-authentik-actor",
                normal_session_id=store.record["setup_session_id"],
                normal_transaction_handle=store.record["transaction_handle"],
                normal_plan_digest=store.record["plan_digest"],
            )
            with (patch.object(principal_module.os, "geteuid", return_value=0),
                  patch.object(principal_module.sys, "platform", "linux")):
                self.assertEqual(
                    resolver.resolve_policy_selection(store.handle, resolver.selection_handle), policy)
                store.record["transaction_handle"] = "transaction-replaced"
                with self.assertRaises(BootstrapEnrollmentPending):
                    resolver.resolve_policy_selection(store.handle, resolver.selection_handle)
                store.record["transaction_handle"] = "transaction-fixture-1"
                handoff.normal_transaction_handle = "transaction-replaced"
                with self.assertRaises(BootstrapEnrollmentPending):
                    resolver.resolve_policy_selection(store.handle, resolver.selection_handle)

    def test_namespace_receipt_is_distinct_and_generation_bound(self):
        import hermes_installer.authority.setup_principal as principal_module

        receipt = principal_module.VerifiedRootNamespaceSelection(
            1, "a" * 64, "setup-fixture-1", "transaction-fixture-1", "c" * 64,
            "generation-fixture-1", "d" * 64, "b" * 64,
            "hermes-agent-native-v1", "hermes-native-fixture", 10.0, 20.0, "seal",
        )
        encoded = principal_module._namespace_json(receipt)
        restored = principal_module._namespace_from_json(encoded, "seal")
        self.assertEqual(restored, receipt)
        self.assertNotEqual(restored.receipt_handle, restored.namespace_id)
        encoded["prepared_generation_digest"] = "e" * 64
        altered = principal_module._namespace_from_json(encoded, "seal")
        validator = object.__new__(RootSetupPrincipalSelectionRegistry)
        validator._seal = "seal"
        authorization = SimpleNamespace(
            setup_session_id="setup-fixture-1", transaction_handle="transaction-fixture-1",
            plan_digest="c" * 64,
        )
        principal = SimpleNamespace(
            receipt_id="b" * 64, service_profile_id="hermes-agent-native-v1",
            namespace_id="hermes-native-fixture",
        )
        with self.assertRaises(BootstrapEnrollmentPending):
            validator._validate_namespace_receipt(
                altered, authorization, principal,
                "generation-fixture-1", "d" * 64,
            )

    def test_fixed_tls_reads_use_current_identity_and_complete_group_hierarchy(self):
        if shutil.which("openssl") is None:
            self.skipTest("openssl is unavailable for the local TLS fixture")
        with tempfile.TemporaryDirectory(prefix="setup-authentik-http-") as temp:
            fixture = _HTTPSAuthentikFixture(Path(temp))
            try:
                policy = _policy(fixture.origin)
                store = _LiveStore(Path(temp))
                observer = RootSetupAuthentikIdentityObserver(
                    setup_session_store=store, policy_resolver=_PolicyResolver(policy),
                    vault=_Vault(), root_journal=Path(temp),
                )
                default_context = ssl.create_default_context
                with patch("ssl.create_default_context", side_effect=lambda *args, **kwargs:
                           default_context(cafile=str(fixture.cert))):
                    result = observer._observe(policy, "fixture-only-token")
                self.assertEqual(result["username"], "fixture-operator")
                self.assertEqual(result["subject"], "subject-17")
                self.assertEqual(result["direct"], frozenset({"members"}))
                self.assertEqual(result["effective"], frozenset({"members", "system"}))
                self.assertEqual([path for path, _ in fixture.calls], [
                    "/api/v3/core/users/me/",
                    "/api/v3/core/groups/members/",
                    "/api/v3/core/groups/system/",
                ])
                self.assertTrue(all(auth == "Bearer fixture-only-token" for _, auth in fixture.calls))
            finally:
                fixture.close()

    def test_group_cycle_is_rejected_before_identity_receipt(self):
        if shutil.which("openssl") is None:
            self.skipTest("openssl is unavailable for the local TLS fixture")
        with tempfile.TemporaryDirectory(prefix="setup-authentik-cycle-") as temp:
            fixture = _HTTPSAuthentikFixture(Path(temp))
            try:
                fixture.groups["system"] = {"pk": "system", "parents": ["members"]}
                policy = _policy(fixture.origin)
                observer = RootSetupAuthentikIdentityObserver(
                    setup_session_store=_LiveStore(Path(temp)),
                    policy_resolver=_PolicyResolver(policy), vault=_Vault(), root_journal=Path(temp),
                )
                default_context = ssl.create_default_context
                with patch("ssl.create_default_context", side_effect=lambda *args, **kwargs:
                           default_context(cafile=str(fixture.cert))):
                    with self.assertRaises(AuthorityDenied):
                        observer._observe(policy, "fixture-only-token")
                self.assertEqual(fixture.calls[-1][0], "/api/v3/core/groups/system/")
            finally:
                fixture.close()


@unittest.skipUnless(os.geteuid() == 0 and platform.system() == "Linux",
                     "root journal/NSS setup fixture runs only in disposable Linux CI")
class SetupPrincipalLinuxRootContract(unittest.TestCase):
    def test_stage0_policy_vault_and_identity_receipt_are_root_bound(self):
        if shutil.which("openssl") is None:
            self.skipTest("openssl is unavailable for the local TLS fixture")
        import time
        import hermes_installer.authority.enrollment as enrollment_module
        import hermes_installer.authority.setup_principal as principal_module
        from hermes_installer.authority.bootstrap_enrollment import EnrollmentPolicy, _generation
        from hermes_installer.authority.bootstrap_enrollment import InstalledRootSetupActorVerifier

        with tempfile.TemporaryDirectory(prefix="setup-principal-stage0-") as temp:
            journal = Path(temp) / "journal"
            journal.mkdir(mode=0o700)
            os.chown(journal, 0, 0)
            os.chmod(journal, 0o700)
            fixture = _HTTPSAuthentikFixture(Path(temp))
            session_handle = secrets.token_hex(32)
            transaction_handle = secrets.token_hex(32)
            plan_digest = "a" * 64
            clock = {"now": time.monotonic()}

            class InitialSession:
                phase = "initial-compilation"
                compilation_session_handle = session_handle
                compilation_transaction_handle = transaction_handle
                plan_sha256 = plan_digest
                choices_sha256 = "c" * 64
                expires_monotonic = time.monotonic() + 240
                _root_journal_root = {
                    "root_id": "installer-authority-journal-v1",
                    "absolute_path": str(journal), "owner_uid": 0,
                    "owner_gid": 0, "mode": 0o700,
                    "device": journal.stat().st_dev, "inode": journal.stat().st_ino,
                }

            actor = InstalledRootSetupActorVerifier()
            actor.verify_current = lambda _plan: {"pid": os.getpid()}

            class InitialRegistry:
                root_journal = journal
                actor_verifier = actor

                def resolve_initial_session(self, handle):
                    if handle != session_handle:
                        raise ValueError("unknown stage0 session")
                    return InitialSession()

                def verify_initial_session(self, session):
                    if session.compilation_session_handle != session_handle:
                        raise ValueError("stale stage0 session")

                def resolve_actor_plan(self, handle):
                    if handle != session_handle:
                        raise ValueError("unknown stage0 session")
                    return object()

                def resolve_identity_policy_template(self, handle):
                    if handle != session_handle:
                        raise ValueError("unknown stage0 session")
                    return VerifiedIdentityPolicyTemplate(
                        "installer-authentik-policy-template-v1",
                        "617f78fc4a692de6a22dd69456fd92b874c9bc82e0869f3817910c953bd2ceb8",
                        "authentik-policy-v1", False,
                        ("/api/v3/core/users/me/", "/api/v3/core/groups/{root_observed_group_id}/"),
                        30,
                    )

                def resolve_adopted_handoff(self, normal_handle):
                    if normal_handle != self.handoff.normal_session_handle:
                        raise ValueError("unknown normal setup session")
                    return self.handoff

            @dataclass(frozen=True)
            class VerifiedIdentityPolicyTemplate:
                artifact_id: str
                sha256: str
                policy_revision: str
                identity_effect_authority: bool
                identity_read_paths: tuple[str, ...]
                max_identity_lease_seconds: int

            factory_module = ModuleType("hermes_installer.authority.bootstrap_runtime_factory")
            factory_module.RootInitialCompilationRegistry = InitialRegistry
            factory_module.RootInitialCompilationSession = InitialSession
            factory_module.VerifiedIdentityPolicyTemplate = VerifiedIdentityPolicyTemplate
            registry = InitialRegistry()
            vault_root = journal / "credentials"
            vault_root.mkdir(mode=0o700)
            os.chown(vault_root, 0, 0)
            os.chmod(vault_root, 0o700)
            try:
                with (patch.dict(sys.modules, {factory_module.__name__: factory_module}),
                      patch.object(enrollment_module, "CREDENTIAL_DIRECTORY", vault_root),
                      patch.object(principal_module.os, "geteuid", return_value=0),
                      patch.object(principal_module.sys, "platform", "linux"),
                      patch.object(principal_module.sys, "stdin", SimpleNamespace(isatty=lambda: True)),
                      patch.object(principal_module.sys, "stderr", SimpleNamespace(isatty=lambda: True))):
                    vault = RootCredentialVault(vault_root)
                    intake = RootSetupIdentityIntake.from_initial_compilation(
                        registry, actor, vault, journal,
                        masked_secret_reader=lambda _prompt: "fixture-only-token")
                    policy_handle = intake.select_authentik_policy(
                        session_handle, https_origin=fixture.origin,
                        system_group_id="system", recipient_group_id="operators",
                    )
                    reference = intake.collect_authentik_actor_credential(
                        session_handle, policy_handle,
                    )
                    self.assertTrue(reference.startswith("setup-authentik-"))
                    observer = RootSetupAuthentikIdentityObserver.from_initial_compilation(
                        registry, intake, vault, journal,
                        monotonic=lambda: clock["now"],
                    )
                    # Trust the fixture certificate while retaining normal HTTPS verification.
                    default_context = ssl.create_default_context
                    with patch("ssl.create_default_context", side_effect=lambda *args, **kwargs:
                               default_context(cafile=str(fixture.cert))):
                        identity_handle = observer.observe_selected_authentik_identity(
                            session_handle, policy_handle)
                        identity = observer._read_identity_receipt(identity_handle)
                        principal_registry = RootSetupPrincipalSelectionRegistry.from_initial_compilation(
                            registry, observer, _Capabilities(), journal)
                        selection_handle = principal_registry.select_principal(
                            session_handle, identity_handle)
                        selected = principal_registry.resolve_selected_principal(
                            selection_handle, session_handle, transaction_handle, plan_digest)
                        normal_store = _LiveStore(journal)

                        class Handoff:
                            pass

                        handoff = Handoff()
                        handoff._initial_session = InitialSession()
                        handoff.compilation_session_handle = session_handle
                        handoff.compilation_transaction_handle = transaction_handle
                        handoff.plan_sha256 = plan_digest
                        handoff.choices_sha256 = "c" * 64
                        handoff.principal_selection_receipt_handle = selection_handle
                        handoff.normal_setup_session_id = normal_store.record["setup_session_id"]
                        handoff.normal_transaction_handle = normal_store.record["transaction_handle"]
                        handoff.expires_monotonic = time.monotonic() + 240
                        handoff.normal_session_handle = normal_store.handle
                        registry.handoff = handoff
                        selected_generation = _generation(EnrollmentPolicy(
                            "hermes-agent-native-v1", selected.principal_id,
                            "generation-fixture-1", "hermes-source-fixture", (), (), (), (),
                        ))
                        normal_store.record["expected_previous_generation_digest"] = selected_generation[
                            "generation_digest"]
                        normal_store.authority_loader_for_session = lambda: {
                            "service_generations": selected_generation,
                        }
                        factory_module.RootInitialPublicationHandoff = Handoff
                        with (patch.object(principal_module, "RootSetupSessionStore", _LiveStore),
                              patch.object(principal_module.os, "geteuid", return_value=0),
                              patch.object(principal_module.sys, "platform", "linux")):
                            normal_observer, normal_identity_handle = intake.rebind_published_policy(
                                normal_session_store=normal_store,
                                normal_session_handle=normal_store.handle,
                                initial_principal_registry=principal_registry,
                                initial_identity_observer=observer,
                            )
                            normal_registry, normal_selection_handle = principal_registry.adopt_initial_publication(
                                normal_session_store=normal_store,
                                normal_session_handle=normal_store.handle,
                                authenticated_identity_receipt_handle=normal_identity_handle,
                                normal_identity_resolver=normal_observer,
                            )
                            principal_selector = normal_registry.resolve_adopted_principal_selector(
                                normal_store, normal_store.handle)
                            namespace_selector = normal_registry.resolve_adopted_namespace_selector(
                                normal_store, normal_store.handle)
                            current_pair = normal_registry.resolve_current_setup_identity(
                                principal_selector.selection_handle,
                                namespace_selector.selection_handle, normal_store.handle)
                            first_current_principal = current_pair.principal.receipt_id
                            first_current_namespace = current_pair.namespace.receipt_handle
                            clock["now"] += 31.0
                            refreshed_pair = normal_registry.resolve_current_setup_identity(
                                principal_selector.selection_handle,
                                namespace_selector.selection_handle, normal_store.handle)
                            self.assertNotEqual(refreshed_pair.principal.receipt_id,
                                                first_current_principal)
                            self.assertNotEqual(refreshed_pair.namespace.receipt_handle,
                                                first_current_namespace)
                            self.assertEqual(refreshed_pair.principal_selection_handle,
                                             principal_selector.selection_handle)
                            self.assertEqual(refreshed_pair.namespace_selection_handle,
                                             namespace_selector.selection_handle)
                            self.assertLessEqual(refreshed_pair.expires_monotonic -
                                                 refreshed_pair.issued_monotonic, 30.0)
                            with self.assertRaises(BootstrapEnrollmentPending):
                                normal_registry.resolve_current_setup_identity(
                                    "0" * 64, namespace_selector.selection_handle, normal_store.handle)
                            fixture.current_user["pk"] = "subject-revoked"
                            with self.assertRaises(BootstrapEnrollmentPending):
                                normal_registry.resolve_current_setup_identity(
                                    principal_selector.selection_handle,
                                    namespace_selector.selection_handle, normal_store.handle)
                            fixture.current_user["pk"] = "subject-17"
                            fixture.groups["members"]["parents"] = []
                            with self.assertRaises(BootstrapEnrollmentPending):
                                normal_registry.resolve_current_setup_identity(
                                    principal_selector.selection_handle,
                                    namespace_selector.selection_handle, normal_store.handle)
                            fixture.groups["members"]["parents"] = ["system"]
                            original_policy = normal_observer.policy_resolver.policy
                            normal_observer.policy_resolver.policy = replace(
                                original_policy, policy_revision="revoked-policy")
                            with self.assertRaises(BootstrapEnrollmentPending):
                                normal_registry.resolve_current_setup_identity(
                                    principal_selector.selection_handle,
                                    namespace_selector.selection_handle, normal_store.handle)
                            normal_observer.policy_resolver.policy = original_policy
                            normal_store.record["expected_previous_generation_digest"] = "e" * 64
                            with self.assertRaises(BootstrapEnrollmentPending):
                                normal_registry.resolve_current_setup_identity(
                                    principal_selector.selection_handle,
                                    namespace_selector.selection_handle, normal_store.handle)
                            normal_store.record["expected_previous_generation_digest"] = selected_generation[
                                "generation_digest"]
                            clock["now"] += 31.0
                            final_pair = normal_registry.resolve_current_setup_identity(
                                principal_selector.selection_handle,
                                namespace_selector.selection_handle, normal_store.handle)
                            self.assertEqual(final_pair.principal_selection_handle,
                                             principal_selector.selection_handle)
                            self.assertNotEqual(final_pair.principal.receipt_id,
                                                refreshed_pair.principal.receipt_id)
                            self.assertNotEqual(final_pair.namespace.receipt_handle,
                                                refreshed_pair.namespace.receipt_handle)
                    self.assertEqual(identity.authentik_subject_id, "subject-17")
                    self.assertTrue(identity.system_member)
                    self.assertEqual(selected.principal_id,
                                     "authentik:" + __import__("hashlib").sha256(b"subject-17").hexdigest())
                    self.assertEqual(selected.principal_binding.bind(23001).uid, 23001)
                    self.assertEqual(final_pair.principal.authentik_subject_id, "subject-17")
                    self.assertNotEqual(final_pair.principal.receipt_id, normal_selection_handle)
                    self.assertEqual(normal_observer._read_identity_receipt(
                        normal_identity_handle).setup_session_id, normal_store.record["setup_session_id"])
                    self.assertEqual((vault_root / reference).stat().st_mode & 0o777, 0o600)
                    self.assertNotIn("fixture-only-token",
                                     (journal / "setup-principal-receipts" / f"{identity_handle}.json").read_text())
                    (vault_root / reference).unlink()
                    with self.assertRaises(BootstrapEnrollmentPending):
                        normal_registry.resolve_current_setup_identity(
                            principal_selector.selection_handle,
                            namespace_selector.selection_handle, normal_store.handle)
            finally:
                fixture.close()

    def test_identity_observation_selection_nss_join_and_one_use_activation(self):
        if shutil.which("openssl") is None:
            self.skipTest("openssl is unavailable for the local TLS fixture")
        with tempfile.TemporaryDirectory(prefix="setup-principal-root-") as temp:
            journal = Path(temp) / "journal"
            journal.mkdir(mode=0o700)
            os.chown(journal, 0, 0)
            os.chmod(journal, 0o700)
            fixture = _HTTPSAuthentikFixture(Path(temp))
            account_name = "hif" + secrets.token_hex(4)
            marker_dir = Path("/var/lib/hermes-installer/test/setup-principal")
            marker_dir.mkdir(parents=True, mode=0o700, exist_ok=True)
            adapter = SystemIdentityAdapter(marker_dir / (account_name + ".json"), name=account_name)
            identity = None
            try:
                store = _LiveStore(journal)
                policy = _policy(fixture.origin)
                import hermes_installer.authority.enrollment as enrollment_module
                vault_root = journal / "credentials"
                vault_root.mkdir(mode=0o700)
                os.chown(vault_root, 0, 0)
                os.chmod(vault_root, 0o700)
                with patch.object(enrollment_module, "CREDENTIAL_DIRECTORY", vault_root):
                    vault = RootCredentialVault(vault_root)
                    vault.write_credential(
                        "setup-authentik-actor", "fixture-only-token",
                        principal_id="root-setup-authentik", allowed_uids=[0],
                        scopes=["authentik-system-read"],
                    )
                observer = RootSetupAuthentikIdentityObserver(
                    setup_session_store=store, policy_resolver=_PolicyResolver(policy),
                    vault=vault, root_journal=journal,
                )
                registry = RootSetupPrincipalSelectionRegistry.from_root_setup(
                    store, observer, _Capabilities(), journal,
                )
                default_context = ssl.create_default_context
                with (patch.object(enrollment_module, "CREDENTIAL_DIRECTORY", vault_root),
                      patch("ssl.create_default_context", side_effect=lambda *args, **kwargs:
                            default_context(cafile=str(fixture.cert)))):
                    identity_handle = observer.observe_selected_authentik_identity(
                        store.handle, "a" * 64)
                    selection_handle = registry.select_principal(store.handle, identity_handle)
                    selected = registry.resolve_selected_principal(
                        selection_handle, store.handle, store.record["transaction_handle"],
                        store.record["plan_digest"],
                    )
                identity = adapter.ensure()
                account = pwd.getpwnam(account_name)
                group = grp.getgrnam(account_name)
                self.assertEqual((account.pw_uid, account.pw_gid), (identity.uid, identity.gid))
                self.assertEqual(group.gr_gid, identity.gid)
                self.assertEqual(selected.principal_id, "authentik:" + __import__("hashlib").sha256(b"subject-17").hexdigest())
                self.assertEqual(selected.principal_binding.bind(identity.uid).uid, identity.uid)
                fixture.current_user["pk"] = "subject-revoked"
                with self.assertRaises(BootstrapEnrollmentPending):
                    registry.resolve_selected_principal(
                        selection_handle, store.handle, store.record["transaction_handle"],
                        store.record["plan_digest"],
                    )
                fixture.current_user["pk"] = "subject-17"
                committed = EnrollmentReceipt(
                    1, store.record["transaction_handle"], "receipt-handle",
                    "generation-fixture-1", "d" * 64, None, "committed", (),
                    __import__("time").monotonic(), __import__("time").monotonic() + 30,
                )
                # A structurally valid caller DTO is not a durable CAS proof.
                # Consumption is now restricted to a concrete RootSetupSessionStore
                # that verifies the matching transaction journal and selected digest.
                with self.assertRaises(BootstrapEnrollmentPending):
                    registry.consume_selected_principal(
                        selection_handle, store.handle, store.record["transaction_handle"],
                        store.record["plan_digest"], committed,
                    )
                receipt_bytes = (journal / "setup-principal-receipts" / f"{identity_handle}.json").read_text()
                self.assertNotIn("fixture-only-token", receipt_bytes)
                link = journal / "setup-principal-receipts" / ("forged-" + "f" * 64 + ".json")
                external = Path(temp) / "outside.json"
                external.write_text("{}")
                link.symlink_to(external)
                with self.assertRaises(BootstrapEnrollmentPending):
                    observer._read_identity_receipt("f" * 64)
            finally:
                fixture.close()
                if identity is not None:
                    adapter.remove_if_created(identity)

    def test_local_owner_domain_uses_current_nss_and_exact_finite_capability_choice(self):
        import time
        import hermes_installer.authority.bootstrap_enrollment as enrollment_module
        import hermes_installer.authority.bootstrap_runtime_factory as factory_module
        import hermes_installer.authority.setup_principal as principal_module

        account = pwd.getpwuid(os.getuid())
        primary_group = SimpleNamespace(gr_name="fixture-primary", gr_gid=account.pw_gid)
        clock = {"now": time.monotonic()}

        class Release:
            def verify_current(self):
                return True

        class Actor:
            def verify_current(self, _release):
                return True

        class FakeInitialRegistry:
            root_journal = Path("/root/local-owner-fixture-journal")

            def __init__(self):
                self.session = SimpleNamespace(
                    compilation_session_handle="a" * 64,
                    compilation_transaction_handle="b" * 64,
                    plan_sha256="c" * 64, expires_monotonic=clock["now"] + 240,
                    verified_release_receipt_handle="d" * 64,
                    actor_observation_receipt_handle="e" * 64,
                    _choices=SimpleNamespace(target_account_name=account.pw_name),
                    _release=Release(), _actor=Actor())

            def resolve_initial_session(self, handle):
                if handle != self.session.compilation_session_handle:
                    raise BootstrapEnrollmentPending("foreign session")
                return self.session

            def verify_initial_session(self, session):
                if session is not self.session:
                    raise BootstrapEnrollmentPending("replaced session")

        with tempfile.TemporaryDirectory(prefix="local-owner-principal-") as temp:
            root_journal = Path(temp) / "journal"
            root_journal.mkdir(mode=0o700)
            os.chmod(root_journal, 0o700)
            initial = FakeInitialRegistry()
            initial.root_journal = root_journal
            with (patch.object(factory_module, "RootInitialCompilationRegistry", FakeInitialRegistry),
                  patch.object(principal_module.os, "getuid", return_value=0),
                  patch.object(principal_module.os, "geteuid", return_value=0),
                  patch.object(principal_module.sys, "platform", "linux"),
                  patch.object(principal_module.grp, "getgrgid", return_value=primary_group),
                  patch.object(principal_module.grp, "getgrnam", return_value=primary_group),
                  patch.object(enrollment_module, "_read_machine_id", return_value="f" * 32)):
                issuer = RootSetupLocalOwnerIdentityRegistry.from_initial_compilation(
                    initial, root_journal, monotonic=lambda: clock["now"])
                issuer._write_record = lambda *_args: None
                capability = issuer.select_capabilities(
                    "a" * 64, ("resource-overlay-store:tool:resource_overlay_read",))
                principal_handle = issuer.select_principal("a" * 64, capability.selection_handle)
                current = issuer.resolve_current_selection("a" * 64, principal_handle)
                self.assertEqual(current.principal.identity_kind, "linux-local-owner-v1")
                self.assertTrue(current.principal.principal_id.startswith("linux-local-owner:"))
                self.assertEqual(current.principal.selected_capability_ceiling,
                                 ("resource-overlay-store:tool:resource_overlay_read",))
                self.assertLessEqual(current.expires_monotonic - current.issued_monotonic, 30.0)
                with self.assertRaises(BootstrapEnrollmentError):
                    issuer.select_capabilities("a" * 64, ("host.write",))
                with self.assertRaises(BootstrapEnrollmentPending):
                    issuer.resolve_current_selection("0" * 64, principal_handle)
                clock["now"] += 31.0
                with self.assertRaises(BootstrapEnrollmentPending):
                    issuer.resolve_current_selection("a" * 64, principal_handle)

                clock["now"] = time.monotonic()
                capability = issuer.select_capabilities("a" * 64, ())
                principal_handle = issuer.select_principal("a" * 64, capability.selection_handle)
                rebound = SimpleNamespace(pw_name=account.pw_name, pw_uid=account.pw_uid + 10000,
                                          pw_gid=account.pw_gid)
                with patch.object(principal_module.pwd, "getpwnam", return_value=rebound):
                    with self.assertRaises(BootstrapEnrollmentPending):
                        issuer.resolve_current_selection("a" * 64, principal_handle)
                root_account = SimpleNamespace(pw_name=account.pw_name, pw_uid=0,
                                               pw_gid=account.pw_gid)
                with patch.object(principal_module.pwd, "getpwnam", return_value=root_account):
                    with self.assertRaises(BootstrapEnrollmentError):
                        issuer.select_principal("a" * 64, capability.selection_handle)

    def test_foreign_existing_root_account_is_preserved(self):
        with tempfile.TemporaryDirectory(prefix="setup-principal-conflict-") as temp:
            marker = Path(temp) / "foreign.json"
            before = pwd.getpwnam("root")
            adapter = SystemIdentityAdapter(marker, name="root")
            with self.assertRaises(BootstrapEnrollmentError):
                adapter.ensure()
            after = pwd.getpwnam("root")
            self.assertEqual((after.pw_uid, after.pw_gid), (before.pw_uid, before.pw_gid))
            self.assertFalse(marker.exists())


if __name__ == "__main__":
    unittest.main()
