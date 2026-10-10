"""Filesystem effect and conflict tests for root policy publication helpers."""
from __future__ import annotations

import os
import tempfile
import unittest
from types import SimpleNamespace
from pathlib import Path
from unittest.mock import patch

from hermes_installer.authority.bootstrap_enrollment import BootstrapEnrollmentError, BootstrapEnrollmentPending
from hermes_installer.authority.setup_policy_publication import (
    _FileSpec, _atomic_replace, _ensure_generation, _read_fixed,
    _receipt_from_record, _verify_active_receipt_descriptor, _restore_compiled_selection,
    _canonical, _sha, POLICY_GENERATIONS, _choice_adoption_from_record,
    _choice_adoption_value, PolicyPublicationReceiptResolver,
    RootSetupPolicyGenerationPublisher, RootSetupPublicationReceipt, _SEAL,
    _CHOICE_PROJECTION_FIELDS, _validate_choice_adoption_time, _mint_choice_adoptions,
)


class PolicyPublicationFilesystemTests(unittest.TestCase):
    def _publisher_for_active_claim(self, compiled, registry):
        publisher = object.__new__(RootSetupPolicyGenerationPublisher)
        publisher.registry = registry
        publisher._active = True
        publisher.release = SimpleNamespace(
            verify_current=lambda: None,
            selected_plan_artifact_id="installer-root-setup-plan-v1",
            release_commit="1" * 40,
        )
        return publisher

    def _active_claim(self, *, duplicate=False):
        observed, runtime, materialized = ("o" * 64, "r" * 64, "m" * 64)
        source = (runtime, materialized, runtime) if duplicate else (runtime, materialized)
        selection = {"catalog_sha256": "e" * 64}
        return SimpleNamespace(
            publication_handle="p" * 64, claim_digest="c" * 64,
            prepared_generation_id="prepared-v1", transaction_handle="t" * 64,
            expected_service_generation_digest="g" * 64,
            expected_selection_catalog_sha256=None,
            compiled_policy_sha256=_sha(b"{}"), compiled_artifact_catalog_sha256=_sha(b"{}"),
            compiled_selection_sha256=_sha(_canonical(selection)), selection_catalog_sha256="e" * 64,
            policy_bytes=b"{}", artifact_catalog_bytes=b"{}", selection_document=selection,
            plan_sha256="f" * 64, plan_artifact_id="installer-root-setup-plan-v1",
            release_commit="1" * 40, observed_root_receipt_handle=observed,
            source_receipt_handles=source,
            runtime_receipt_handles=(runtime,), materialization_receipt_handles=(materialized,),
            principal_selection_receipt_handle=None, choice_adoptions=(),
        )

    def _active_receipt(self, claim):
        source = (claim.observed_root_receipt_handle, *claim.source_receipt_handles)
        return RootSetupPublicationReceipt(
            1, "q" * 64, claim.transaction_handle,
            "installer-bootstrap-policy-generation-v1", "2" * 64,
            Path("/var/lib/hermes-installer/policy-generations") / ("2" * 64), 1, 2,
            claim.compiled_policy_sha256, claim.compiled_artifact_catalog_sha256,
            "3" * 64, "4" * 64, None, "5" * 64, source, "active-committed", _SEAL,
            claim.publication_handle, claim.claim_digest, claim.prepared_generation_id,
            claim.expected_service_generation_digest, claim.runtime_receipt_handles,
            claim.materialization_receipt_handles, (),
        )

    def test_active_pointer_cas_failure_reconciles_from_durable_journal_without_release(self):
        claim = self._active_claim()
        receipt = self._active_receipt(claim)
        completed = []
        released = []

        class Registry:
            def claim_active_policy(self, *_args): return claim
            def verify_current_active_policy_claim(self, _claim): return _claim
            def complete_active_publication(self, value): completed.append(value)
            def release_active_policy(self, value): released.append(value)

        publisher = self._publisher_for_active_claim(claim, Registry())
        with tempfile.TemporaryDirectory() as tmp:
            selection = Path(tmp) / "selection.json"
            journal = Path(tmp) / "publication.json"

            def cas_then_raise(*_args, **_kwargs):
                selection.write_text(receipt.receipt_handle)
                journal.write_text(receipt.publication_sha256)
                raise OSError("injected failure after selection CAS")

            publisher._publish_compiled = cas_then_raise

            def resolve_committed():
                self.assertEqual(selection.read_text(), receipt.receipt_handle)
                self.assertEqual(journal.read_text(), receipt.publication_sha256)
                return receipt

            with patch("hermes_installer.authority.setup_policy_publication._require_root_linux"), \
                 patch("hermes_installer.authority.setup_policy_publication._validate_compiled_documents"), \
                 patch.object(PolicyPublicationReceiptResolver, "resolve_current", side_effect=resolve_committed):
                result = publisher.publish(claim.publication_handle, None)

            self.assertIs(result, receipt)
            self.assertEqual(completed, [receipt])
            self.assertEqual(released, [])
            self.assertEqual(selection.read_text(), receipt.receipt_handle)
            self.assertEqual(journal.read_text(), receipt.publication_sha256)

    def test_active_completion_failure_retains_effect_and_explicit_recovery_finalizes(self):
        claim = self._active_claim()
        receipt = self._active_receipt(claim)
        completed = []
        released = []

        class Registry:
            attempts = 0
            def claim_active_policy(self, *_args): return claim
            def verify_current_active_policy_claim(self, _claim): return _claim
            def complete_active_publication(self, value):
                self.attempts += 1
                if self.attempts <= 2:
                    raise OSError("injected completion journal failure")
                completed.append(value)
            def recover_active_publication_receipt(self, value):
                self.complete_active_publication(value)
            def release_active_policy(self, value): released.append(value)

        registry = Registry()
        publisher = self._publisher_for_active_claim(claim, registry)
        with tempfile.TemporaryDirectory() as tmp:
            selection = Path(tmp) / "selection.json"
            journal = Path(tmp) / "publication.json"

            def commit(*_args, **_kwargs):
                selection.write_text(receipt.receipt_handle)
                journal.write_text(receipt.publication_sha256)
                return receipt

            publisher._publish_compiled = commit

            def resolve_committed():
                self.assertEqual(selection.read_text(), receipt.receipt_handle)
                self.assertEqual(journal.read_text(), receipt.publication_sha256)
                return receipt

            with patch("hermes_installer.authority.setup_policy_publication._require_root_linux"), \
                 patch("hermes_installer.authority.setup_policy_publication._validate_compiled_documents"), \
                 patch.object(PolicyPublicationReceiptResolver, "resolve_current", side_effect=resolve_committed):
                with self.assertRaisesRegex(BootstrapEnrollmentPending, "retained for publication finalization"):
                    publisher.publish(claim.publication_handle, None)
                self.assertEqual(released, [])
                self.assertEqual(completed, [])
                recovered = publisher.recover_active_publication(claim.publication_handle)

            self.assertIs(recovered, receipt)
            self.assertEqual(completed, [receipt])
            self.assertEqual(released, [])
            self.assertEqual(selection.read_text(), receipt.receipt_handle)
            self.assertEqual(journal.read_text(), receipt.publication_sha256)

    def test_duplicate_active_source_handle_is_rejected_before_publication(self):
        claim = self._active_claim(duplicate=True)
        released = []
        writes = []

        class Registry:
            def claim_active_policy(self, *_args): return claim
            def verify_current_active_policy_claim(self, _claim): return _claim
            def complete_active_publication(self, _receipt): self.fail("must not complete")
            def release_active_policy(self, value): released.append(value)

        publisher = self._publisher_for_active_claim(claim, Registry())
        publisher._publish_compiled = lambda *_args, **_kwargs: writes.append(True)
        with patch("hermes_installer.authority.setup_policy_publication._require_root_linux"), \
             patch("hermes_installer.authority.setup_policy_publication._validate_compiled_documents"):
            with self.assertRaisesRegex(BootstrapEnrollmentError, "canonical unique order"):
                publisher.publish(claim.publication_handle, None)
        self.assertEqual(writes, [])
        self.assertEqual(released, [claim.publication_handle])

    def test_generation_install_is_immutable_and_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp) / "generations"
            parent.mkdir(mode=0o700)
            generation = parent / ("a" * 64)
            files = (
                _FileSpec("plans/bootstrap-policy-v1.json", b"{}"),
                _FileSpec("catalog/artifacts.json", b"{}"),
                _FileSpec("publication.json", b"{}"),
            )
            _ensure_generation(parent, generation, "a" * 64, b"{}", files, os.getuid())
            before = os.stat(generation, follow_symlinks=False)
            _ensure_generation(parent, generation, "a" * 64, b"{}", files, os.getuid())
            after = os.stat(generation, follow_symlinks=False)
            self.assertEqual((before.st_dev, before.st_ino), (after.st_dev, after.st_ino))
            self.assertEqual(before.st_mode & 0o777, 0o555)
            self.assertEqual((generation / "plans/bootstrap-policy-v1.json").read_bytes(), b"{}")

    def test_generation_collision_with_foreign_or_extra_content_is_preserved(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp) / "generations"
            parent.mkdir(mode=0o700)
            generation = parent / ("b" * 64)
            generation.mkdir(mode=0o700)
            marker = generation / "foreign"
            marker.write_bytes(b"preserve")
            os.chmod(marker, 0o444)
            os.chmod(generation, 0o555)
            with self.assertRaises(BootstrapEnrollmentError):
                _ensure_generation(parent, generation, "b" * 64, b"{}", (), os.getuid())
            self.assertEqual(marker.read_bytes(), b"preserve")

    def test_selection_replace_is_cas_and_rejects_inode_change(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "selection.json"
            path.write_bytes(b"old")
            os.chmod(path, 0o600)
            info = os.stat(path)
            _atomic_replace(path, b"new", os.getuid(), 0o600, (info.st_dev, info.st_ino))
            self.assertEqual(_read_fixed(path, os.getuid(), 0o600, 100)[0], b"new")
            with self.assertRaises(BootstrapEnrollmentPending):
                _atomic_replace(path, b"stale", os.getuid(), 0o600, (info.st_dev, info.st_ino))
            self.assertEqual(path.read_bytes(), b"new")

    def test_selection_replace_rejects_symlink_and_does_not_touch_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "target"
            target.write_bytes(b"keep")
            os.chmod(target, 0o600)
            path = root / "selection.json"
            path.symlink_to(target)
            with self.assertRaises(BootstrapEnrollmentPending):
                _atomic_replace(path, b"replacement", os.getuid(), 0o600, (1, 1))
            self.assertEqual(target.read_bytes(), b"keep")
            self.assertTrue(path.is_symlink())

    def test_failed_atomic_replace_preserves_previous_selection_and_cleans_stage(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "selection.json"
            path.write_bytes(b"before")
            os.chmod(path, 0o600)
            info = os.stat(path)
            with patch("hermes_installer.authority.setup_policy_publication.os.replace",
                       side_effect=OSError("injected rename failure")):
                with self.assertRaises(OSError):
                    _atomic_replace(path, b"after", os.getuid(), 0o600,
                                    (info.st_dev, info.st_ino))
            self.assertEqual(path.read_bytes(), b"before")
            self.assertEqual(sorted(p.name for p in path.parent.iterdir()), ["selection.json"])

    def _active_record(self):
        digest = "a" * 64
        return {
            "schema": 1, "transaction_handle": "t" * 64,
            "publication_sha256": digest, "publication_receipt_handle": "r" * 64,
            "generation_id": "installer-bootstrap-policy-generation-v1",
            "generation_root": str(POLICY_GENERATIONS / digest),
            "generation_device": 1, "generation_inode": 2,
            "policy_sha256": "b" * 64, "artifact_catalog_sha256": "c" * 64,
            "selection_sha256": "d" * 64, "descriptor_sha256": "e" * 64,
            "previous_selection_catalog_sha256": "f" * 64,
            "current_selection_catalog_sha256": "0" * 64,
            "input_receipt_handles": ["i" * 64], "state": "active-committed",
            "updated_monotonic": 10.0, "publication_handle": "p" * 64,
            "claim_digest": "1" * 64, "prepared_generation_id": "prepared-v1",
            "service_generation_digest": "2" * 64,
            "runtime_receipt_handles": ["3" * 64],
            "materialization_receipt_handles": ["4" * 64],
        }

    def test_active_receipt_binds_claim_generation_and_native_receipts(self):
        receipt = _receipt_from_record(self._active_record())
        descriptor = {
            "schema": 2,
            "policy_sha256": receipt.policy_sha256,
            "artifact_catalog_sha256": receipt.artifact_catalog_sha256,
            "selection_sha256": receipt.selection_sha256,
            "inputs": {
                "publication_handle": receipt.publication_handle,
                "claim_digest": receipt.claim_digest,
                "prepared_generation_id": receipt.prepared_generation_id,
                "expected_service_generation_digest": receipt.service_generation_digest,
                "transaction_handle": receipt.transaction_handle,
                "runtime_receipt_handles": list(receipt.runtime_receipt_handles),
                "materialization_receipt_handles": list(receipt.materialization_receipt_handles),
                "owner_overlay_adoption_sha256": _sha(_canonical([])),
            },
            "owner_overlay_adoption_records": [],
            "owner_overlay_observer_records": [],
        }
        _verify_active_receipt_descriptor(receipt, descriptor)
        no_observer_table = dict(descriptor)
        no_observer_table.pop("owner_overlay_observer_records")
        with self.assertRaises(BootstrapEnrollmentError):
            _verify_active_receipt_descriptor(receipt, no_observer_table)
        descriptor["inputs"]["claim_digest"] = "9" * 64
        with self.assertRaises(BootstrapEnrollmentError):
            _verify_active_receipt_descriptor(receipt, descriptor)

    def test_active_receipt_rejects_empty_native_receipt_closure(self):
        record = self._active_record()
        record["materialization_receipt_handles"] = []
        with self.assertRaises(BootstrapEnrollmentError):
            _receipt_from_record(record)

    def _choice_adoption_record(self):
        return {
            "selection_handle": "s" * 64, "purpose": "memory-service-enablement",
            "key_id": "selected-key-1", "signed_record_sha256": "a" * 64,
            "choice_payload_sha256": "b" * 64, "choice_epoch": 1, "revocation_epoch": 2,
            "issued_at_unix": 1000.0, "setup_deadline_unix": 1100.0,
            "adopted_at_unix": 1050.0,
            "release_deployment_receipt_sha256": "c" * 64,
            "setup_session_handle": "d" * 64, "transaction_handle": "t" * 64,
            "plan_id": "installer-root-setup-plan-v1", "prepared_generation": "prepared-v1",
            "principal_selection_handle": "p" * 64, "namespace_selection_handle": "n" * 64,
            "private_profile_selection_handle": "q" * 64,
            "source_member_receipt_handles": ["1" * 64, "2" * 64],
            "principal_id": "principal-1", "profile_id": "memory-profile-1",
            "namespace_id": "namespace-1", "principal_binding_sha256": "3" * 64,
            "namespace_binding_sha256": "4" * 64, "service_generation_id": "service-v1",
            "service_generation_digest": "5" * 64, "selection_catalog_sha256": "6" * 64,
            "publication_receipt_handle": "r" * 64, "publication_sha256": "7" * 64,
            "generation_id": "installer-bootstrap-policy-generation-v1",
        }

    def test_published_choice_adoption_is_closed_and_digest_bound(self):
        record = self._choice_adoption_record()
        adoption = _choice_adoption_from_record(record)
        self.assertEqual(_choice_adoption_value(adoption), record)
        for mutate in (
            lambda row: row.update(signed_record_sha256="not-a-digest"),
            lambda row: row.update(source_member_receipt_handles=[]),
            lambda row: row.update(purpose="unplanned-purpose"),
            lambda row: row.update(publication_sha256="not-a-digest"),
        ):
            changed = dict(record)
            mutate(changed)
            with self.assertRaises(BootstrapEnrollmentError):
                _choice_adoption_from_record(changed)

    def test_active_record_rejects_adoption_from_another_publication(self):
        record = self._active_record()
        adoption = self._choice_adoption_record()
        adoption["publication_sha256"] = "9" * 64
        record["choice_adoptions"] = [adoption]
        with self.assertRaises(BootstrapEnrollmentError):
            _receipt_from_record(record)

    def test_active_descriptor_must_retain_exact_choice_projection(self):
        record = self._active_record()
        adoption = self._choice_adoption_record()
        adoption.update({"publication_receipt_handle": record["publication_receipt_handle"],
                         "publication_sha256": record["publication_sha256"],
                         "generation_id": record["generation_id"],
                         "transaction_handle": record["transaction_handle"],
                         "prepared_generation": record["prepared_generation_id"],
                         "service_generation_digest": record["service_generation_digest"]})
        record["input_receipt_handles"].extend(adoption["source_member_receipt_handles"])
        record["choice_adoptions"] = [adoption]
        receipt = _receipt_from_record(record)
        projection = {key: value for key, value in adoption.items()
                      if key not in {"publication_receipt_handle", "publication_sha256", "generation_id"}}
        descriptor = {"schema": 2, "policy_sha256": receipt.policy_sha256,
                      "artifact_catalog_sha256": receipt.artifact_catalog_sha256,
                      "selection_sha256": receipt.selection_sha256,
                      "inputs": {
                          "publication_handle": receipt.publication_handle,
                          "claim_digest": receipt.claim_digest,
                          "prepared_generation_id": receipt.prepared_generation_id,
                          "expected_service_generation_digest": receipt.service_generation_digest,
                          "transaction_handle": receipt.transaction_handle,
                          "runtime_receipt_handles": list(receipt.runtime_receipt_handles),
                          "materialization_receipt_handles": list(receipt.materialization_receipt_handles),
                          "owner_overlay_adoption_sha256": _sha(_canonical([])),
                          "choice_projections": [projection],
                      }, "owner_overlay_adoption_records": [],
                      "owner_overlay_observer_records": []}
        _verify_active_receipt_descriptor(receipt, descriptor)
        descriptor["inputs"]["choice_projections"][0]["signed_record_sha256"] = "8" * 64
        with self.assertRaises(BootstrapEnrollmentError):
            _verify_active_receipt_descriptor(receipt, descriptor)

    def test_choice_adoption_currentness_rejects_changed_signed_row_digest(self):
        adoption = _choice_adoption_from_record(self._choice_adoption_record())
        from hermes_installer.authority.root_setup_choices import RootSetupChoiceRegistry
        registry = object.__new__(RootSetupChoiceRegistry)
        checked = []
        registry.verify_published_adoption_current = lambda value: checked.append(value)
        with patch.object(PolicyPublicationReceiptResolver,
                          "resolve_current_choice_adoption", return_value=adoption):
            self.assertIs(adoption.verify_current(registry), adoption)
        self.assertEqual(checked, [adoption])
        changed_record = self._choice_adoption_record()
        changed_record["signed_record_sha256"] = "8" * 64
        changed = _choice_adoption_from_record(changed_record)
        with patch.object(PolicyPublicationReceiptResolver,
                          "resolve_current_choice_adoption", return_value=changed):
            with self.assertRaises(BootstrapEnrollmentPending):
                adoption.verify_current(registry)

    def test_choice_adoption_rejects_timestamp_after_original_setup_deadline(self):
        record = self._choice_adoption_record()
        record["adopted_at_unix"] = record["setup_deadline_unix"] + 0.001
        with self.assertRaises(BootstrapEnrollmentError):
            _choice_adoption_from_record(record)

    def test_publisher_rejects_choice_that_expires_while_generation_is_staged(self):
        record = self._choice_adoption_record()
        projection_values = {key: value for key, value in record.items()
                             if key in _CHOICE_PROJECTION_FIELDS}
        projection = SimpleNamespace(**projection_values)
        with self.assertRaisesRegex(BootstrapEnrollmentPending, "original setup deadline"):
            _validate_choice_adoption_time((projection,), record["setup_deadline_unix"] + 0.001)

    def test_publisher_persists_the_adoption_timestamp_on_the_sealed_receipt(self):
        record = self._choice_adoption_record()
        projection_values = {key: value for key, value in record.items()
                             if key in _CHOICE_PROJECTION_FIELDS}
        projection_values["source_member_receipt_handles"] = tuple(
            projection_values["source_member_receipt_handles"])
        compiled = SimpleNamespace(choice_adoptions=(SimpleNamespace(**projection_values),))
        minted, = _mint_choice_adoptions(
            compiled, "r" * 64, "7" * 64, "installer-bootstrap-policy-generation-v1",
            "active-committed", adopted_at_unix=1050.0)
        self.assertEqual(minted.adopted_at_unix, 1050.0)
        self.assertEqual(_choice_adoption_value(minted)["adopted_at_unix"], 1050.0)

    def test_choice_adoption_currentness_rechecks_signed_source_and_revocation_each_call(self):
        adoption = _choice_adoption_from_record(self._choice_adoption_record())
        from hermes_installer.authority.root_setup_choices import RootSetupChoiceRegistry
        registry = object.__new__(RootSetupChoiceRegistry)
        checks = []

        def verify_source(value):
            checks.append(value)
            if len(checks) == 2:
                raise BootstrapEnrollmentPending("signed source row was revoked or its epoch changed")

        registry.verify_published_adoption_current = verify_source
        with patch.object(PolicyPublicationReceiptResolver,
                          "resolve_current_choice_adoption", return_value=adoption):
            self.assertIs(adoption.verify_current(registry), adoption)
            with self.assertRaisesRegex(BootstrapEnrollmentPending, "revoked or its epoch changed"):
                adoption.verify_current(registry)
        self.assertEqual(checks, [adoption, adoption])

    def test_current_selection_reconstructs_exact_compiler_catalog_document(self):
        compiled = {
            "schema": 1, "selection_id": "selected",
            "bootstrap_policies": [{"artifact_id": "installer-bootstrap-policy-v1",
                                    "relative_path": "plans/bootstrap-policy-v1.json",
                                    "sha256": "a" * 64}],
        }
        compiled["catalog_sha256"] = _sha(_canonical(compiled))
        final = dict(compiled)
        final.pop("catalog_sha256")
        final["catalog_sha256"] = "b" * 64
        final["policy_generation"] = {"id": "installer-bootstrap-policy-generation-v1"}
        final_unsigned = {key: value for key, value in final.items() if key != "catalog_sha256"}
        final["catalog_sha256"] = _sha(_canonical(final_unsigned))
        descriptor = {"selection_sha256": _sha(_canonical(compiled)),
                      "inputs": {"selection_catalog_sha256": compiled["catalog_sha256"]}}
        self.assertEqual(_restore_compiled_selection(descriptor, final), compiled)
        final["bootstrap_policies"][0]["sha256"] = "c" * 64
        with self.assertRaises(BootstrapEnrollmentError):
            _restore_compiled_selection(descriptor, final)


if __name__ == "__main__":
    unittest.main()
