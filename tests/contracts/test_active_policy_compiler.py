from __future__ import annotations

import hashlib
import pytest
from dataclasses import replace

from hermes_installer.authority.active_policy_compiler import (
    ActiveSetupChoiceProjection,
    RootActivePolicyCompilationClaim,
    RootActivePolicyCompilationRegistry,
    _canonical,
    _manifest,
    _ordered_unique_receipt_handles,
    _validate_claim_output_hashes,
)
from hermes_installer.authority.bootstrap_enrollment import BootstrapEnrollmentError, BootstrapEnrollmentPending


def _claim() -> RootActivePolicyCompilationClaim:
    unsigned = {
        "schema": 1,
        "selection_id": "installer-root-setup-selection-v1",
        "installer_release_commit": "a" * 40,
        "release_root": {"root_id": "release", "absolute_path": "/usr/lib/hermes-installer/releases/r1",
                         "device": 1, "inode": 2, "deployment_receipt_sha256": "b" * 64},
        "launcher": {"artifact_id": "installer-root-setup-launcher-v1", "relative_path": "launcher", "sha256": "c" * 64},
        "interpreter": {"artifact_id": "installer-root-setup-interpreter-v1", "relative_path": "python", "sha256": "d" * 64},
        "module_closure": [{"module_name": "hermes_installer.authority", "artifact_id": "module:authority",
                             "relative_path": "src/authority.py", "sha256": "e" * 64}],
        "plans": [{"artifact_id": "installer-root-setup-plan-v1", "relative_path": "plans/plan.json",
                   "sha256": "f" * 64, "baseline_tag_object": "1" * 40, "baseline_commit": "2" * 40,
                   "baseline_tree_sha256": "3" * 64, "amendment_manifest_sha256": "4" * 64,
                   "allowed_artifact_ids": ["source"], "bootstrap_policy_artifact_id": "installer-bootstrap-policy-v1"}],
        "artifact_catalog": {"artifact_id": "installer-protected-artifact-catalog-v1",
                             "relative_path": "catalog/artifacts.json", "sha256": "5" * 64},
        "artifact_store": {"root_id": "installer-bootstrap-artifact-store-v1",
                           "journal_root_id": "installer-authority-journal-v1",
                           "relative_path": "bootstrap-artifacts", "owner_uid": 0,
                           "owner_gid": 0, "mode": 448},
        "bootstrap_policies": [{"artifact_id": "installer-bootstrap-policy-v1",
                                "relative_path": "plans/bootstrap-policy-v1.json", "sha256": "6" * 64}],
    }
    unsigned["catalog_sha256"] = hashlib.sha256(_canonical(unsigned)).hexdigest()
    selection = unsigned
    policy = b'{"schema":1}'
    catalog = b'{"schema":1,"artifacts":[],"packages":[]}'
    return RootActivePolicyCompilationClaim(
        schema=2, plan_artifact_id="installer-root-setup-plan-v1", release_commit="a" * 40,
        publication_handle="H" * 43, setup_session_id="S" * 64, transaction_handle="T" * 64,
        plan_sha256="f" * 64, prepared_generation_id="prepared-1",
        expected_selection_catalog_sha256="7" * 64, expected_service_generation_digest="8" * 64,
        policy_template_artifact_id="installer-bootstrap-policy-v1", policy_template_sha256="6" * 64,
        principal_selection_receipt_handle="9" * 64, runtime_receipt_handles=("A" * 43,),
        materialization_receipt_handles=("B" * 43,), source_receipt_handles=("A" * 43, "B" * 43, "9" * 64, "F" * 43),
        principal_identity_kind="authentik-subject-v1", principal_binding_sha256="a" * 64,
        namespace_selection_handle="F" * 43, namespace_binding_sha256="b" * 64,
        compiled_policy_sha256=hashlib.sha256(policy).hexdigest(),
        compiled_artifact_catalog_sha256=hashlib.sha256(catalog).hexdigest(),
        compiled_selection_sha256=hashlib.sha256(_canonical(selection)).hexdigest(),
        selection_catalog_sha256=selection["catalog_sha256"], issued_monotonic=1.0,
        expires_monotonic=100.0, claim_digest="0" * 64, policy_bytes=policy,
        artifact_catalog_bytes=catalog, selection_document=selection,
        observed_root_receipt_handle="C" * 64,
        _root_journal_root=__import__("pathlib").Path("/var/lib/hermes-installer/authority-journal"),
        _root_setup_session=object(), _reservation_handle="D" * 43, _seal=object(),
        role_closure_sha256="e" * 64,
    )


def test_active_claim_hashes_keep_predecessor_and_compiled_selection_domains_separate():
    claim = _claim()
    _validate_claim_output_hashes(claim)
    assert claim.expected_selection_catalog_sha256 != claim.selection_catalog_sha256
    assert claim.compiled_selection_sha256 == hashlib.sha256(_canonical(claim.selection_document)).hexdigest()
    manifest = _manifest(claim)
    assert "claim_digest" not in manifest
    assert manifest["expected_selection_catalog_sha256"] == claim.expected_selection_catalog_sha256
    assert manifest["selection_catalog_sha256"] == claim.selection_catalog_sha256
    assert manifest["choice_adoptions"] == []


def test_active_claim_commits_to_tagged_principal_and_current_namespace_bindings():
    claim = _claim()
    manifest = _manifest(claim)
    assert manifest["principal_identity_kind"] == "authentik-subject-v1"
    assert manifest["principal_binding_sha256"] == "a" * 64
    assert manifest["namespace_selection_handle"] == "F" * 43
    assert manifest["namespace_binding_sha256"] == "b" * 64
    changed_domain = replace(claim, principal_identity_kind="linux-local-owner-v1")
    changed_namespace = replace(claim, namespace_binding_sha256="c" * 64)
    assert hashlib.sha256(_canonical(_manifest(changed_domain))).hexdigest() != hashlib.sha256(
        _canonical(manifest)).hexdigest()
    assert hashlib.sha256(_canonical(_manifest(changed_namespace))).hexdigest() != hashlib.sha256(
        _canonical(manifest)).hexdigest()
    with pytest.raises(BootstrapEnrollmentPending, match="output bytes changed"):
        _validate_claim_output_hashes(replace(claim, namespace_selection_handle="G" * 43))


def _local_owner_adoption_for_claim(claim):
    from hermes_installer.authority.active_policy_compiler import ActiveSetupChoiceProjection
    from hermes_installer.authority.owner_overlay_publication import (
        _CHOICE_FIELDS, _OPERATION_FIELDS, _OWNER_FIELDS, _PACKAGE_FIELDS,
        _RESOURCE_FIELDS, _VIEW_FIELDS, _mint_published_local_owner_adoption,
    )

    handle, digest = "G" * 43, "a" * 64
    choice = {key: "value" for key in _CHOICE_FIELDS}
    choice.update({key: digest for key in (
        "signed_record_sha256", "choice_payload_sha256", "principal_binding_sha256",
        "namespace_binding_sha256", "service_generation_digest",
        "release_deployment_receipt_sha256", "selection_catalog_sha256")})
    choice.update({
        "selection_handle": "H" * 43, "purpose": "native-policy-preparation",
        "principal_id": "local-owner:fixture", "profile_id": "hermes-agent-native-v1",
        "namespace_id": "fixture-namespace", "service_generation_id": claim.prepared_generation_id,
        "principal_selection_handle": claim.principal_selection_receipt_handle,
        "namespace_selection_handle": claim.namespace_selection_handle,
        "principal_binding_sha256": claim.principal_binding_sha256,
        "namespace_binding_sha256": claim.namespace_binding_sha256,
        "service_generation_digest": claim.expected_service_generation_digest,
        "selection_catalog_sha256": claim.selection_catalog_sha256,
        "setup_session_handle": claim.setup_session_id,
        "transaction_handle": claim.transaction_handle,
        "choice_epoch": 1, "revocation_epoch": 1,
        "prepared_generation": claim.prepared_generation_id,
        "issued_at_unix": 1.0, "setup_deadline_unix": 100.0,
        "source_member_receipt_handles": ["I" * 43],
    })
    projection = ActiveSetupChoiceProjection(
        selection_handle=choice["selection_handle"], purpose=choice["purpose"],
        key_id=choice["key_id"], signed_record_sha256=choice["signed_record_sha256"],
        choice_payload_sha256=choice["choice_payload_sha256"], choice_epoch=1, revocation_epoch=1,
        issued_at_unix=1.0, setup_deadline_unix=100.0,
        release_deployment_receipt_sha256=choice["release_deployment_receipt_sha256"],
        setup_session_handle=claim.setup_session_id, transaction_handle=claim.transaction_handle,
        plan_id=choice["plan_id"], prepared_generation=claim.prepared_generation_id,
        principal_selection_handle=claim.principal_selection_receipt_handle,
        namespace_selection_handle=claim.namespace_selection_handle,
        private_profile_selection_handle=choice["private_profile_selection_handle"],
        source_member_receipt_handles=("I" * 43,), principal_id=choice["principal_id"],
        profile_id=choice["profile_id"], namespace_id=choice["namespace_id"],
        principal_binding_sha256=claim.principal_binding_sha256,
        namespace_binding_sha256=claim.namespace_binding_sha256,
        service_generation_id=claim.prepared_generation_id,
        service_generation_digest=claim.expected_service_generation_digest,
        selection_catalog_sha256=claim.selection_catalog_sha256, _compiler_seal=claim._seal)
    owner = {key: "value" for key in _OWNER_FIELDS}
    owner.update({"principal_id": choice["principal_id"], "profile_id": choice["profile_id"],
                  "namespace_id": choice["namespace_id"], "principal_binding_sha256": claim.principal_binding_sha256,
                  "namespace_binding_sha256": claim.namespace_binding_sha256, "account_name": "fixture-owner",
                  "account_uid": 1000, "primary_gid": 1000, "machine_target_sha256": digest,
                  "service_uid": 1001, "service_gid": 1001,
                  "service_generation_id": claim.prepared_generation_id,
                  "service_generation_digest": claim.expected_service_generation_digest})
    resources = {key: "value" for key in _RESOURCE_FIELDS}
    resources.update({"resources_profile_id": "fixture-resources", "source_receipt_handle": handle,
                      "source_sha256": digest, "member_receipt_handles": [handle],
                      "member_sha256s": [digest], "resource_profile_selection_handle": handle,
                      "resource_profile_selection_sha256": digest})
    package = {key: "value" for key in _PACKAGE_FIELDS}
    package.update({"package_id": "fixture-package", "profile_id": "hermes-agent-native-v1",
                    "generation": "fixture-package-generation", "compiled_closure_sha256": digest,
                    "entrypoint_sha256": digest, "resolver_sha256": digest,
                    "owner_overlay_operation_records_sha256": digest,
                    "native_cas_transition_receipt_handle": handle,
                    "native_cas_transition_sha256": digest})
    view = {key: "value" for key in _VIEW_FIELDS}
    view.update({"service_profile_id": "hermes-agent-native-v1", "resource_profile_id": "fixture-resources",
                 "data_root_id": "fixture-data-root", "data_root_selection_handle": handle,
                 "data_root_receipt_handle": handle, "data_root_device": 1, "data_root_inode": 2,
                 "data_root_owner_uid": 1001, "data_root_owner_gid": 1001,
                 "relative_path": "native-profile-overlays/hermes-agent-native-v1/fixture-resources",
                 "view_device": 1, "view_inode": 3, "view_owner_uid": 0, "view_owner_gid": 0,
                 "view_mode": 0o700, "ownership_marker_sha256": digest,
                 "profile_view_selection_handle": handle, "profile_view_receipt_handle": handle,
                 "target_id": "fixture-target", "target_selection_handle": handle,
                 "target_receipt_handle": handle, "effect_enrollment_ids": ["fixture-effect"]})
    operation = {key: None for key in _OPERATION_FIELDS}
    operation.update({"registration_id": "resource-overlay-store:tool:resource_overlay_read",
                      "method": "read", "operation": "plugin.resource-overlay-store.read",
                      "capability": "plugin:resource-overlay-store", "effect_enrollment_id": "fixture-effect",
                      "target_id": "fixture-target", "profile_id": "hermes-agent-native-v1",
                      "profile_generation": claim.prepared_generation_id,
                      "principal_id": choice["principal_id"], "namespace_id": choice["namespace_id"],
                      "package_id": "fixture-package", "package_generation": "fixture-package-generation",
                      "argument_schema_id": "fixture-args", "argument_schema_receipt_handle": handle,
                      "argument_schema_sha256": digest, "result_schema_id": "fixture-result",
                      "result_schema_sha256": digest, "result_schema_receipt_handle": handle,
                      "handler_artifact_id": "fixture-handler", "handler_sha256": digest,
                      "handler_source_receipt_handle": handle,
                      "profile_view_selection_handle": handle, "profile_view_receipt_handle": handle,
                      "data_root_selection_handle": handle, "data_root_receipt_handle": handle,
                      "target_selection_handle": handle, "target_receipt_handle": handle,
                      "prepared_source_observer_selection_handle": handle,
                      "process_role_id": "fixture-role", "source_issuer_id": "fixture-source",
                      "source_observer_enrollment_ids": ["fixture-observer"]})
    schema_member = {"role": "owner-overlay-capture-schema-source",
                     "artifact_id": "installer-module:hermes_installer.authority.owner_overlay_capture_schemas",
                     "receipt_handle": "C" * 43,
                     "relative_path": "lib/python/hermes_installer/authority/owner_overlay_capture_schemas.py",
                     "sha256": "7" * 64, "size_bytes": 5409, "mode": 0o444}
    observer = {
        "schema": 1, "observer_kind": "owner-overlay-registration-v1",
        "observer_enrollment_id": "fixture-observer", "profile_id": "hermes-agent-native-v1",
        "profile_generation": claim.prepared_generation_id,
        "principal_id": choice["principal_id"], "namespace_id": choice["namespace_id"],
        "service_enrollment_id": "fixture-service-enrollment", "package_id": "fixture-package",
        "package_generation": "fixture-package-generation",
        "registration_id": operation["registration_id"], "method": "read",
        "operation_row_sha256": hashlib.sha256(_canonical(operation)).hexdigest(),
        "source_choice_selection_handle": choice["selection_handle"],
        "source_choice_signed_record_sha256": choice["signed_record_sha256"],
        "choice_epoch": choice["choice_epoch"], "revocation_epoch": choice["revocation_epoch"],
        "role_id": "fixture-role", "role_artifact_id": "fixture-module", "role_sha256": digest,
        "role_source_receipt_handle": handle, "role_module_name": "fixture_role",
        "role_closure_member_path": "fixture.py", "role_source_revision": "f" * 40,
        "role_source_tree_sha256": digest, "source_issuer_id": "fixture-source",
        "channel_id": "fixture-channel", "invocation_capture_schema_id": "native-owner-overlay-invocation-v1",
        "result_capture_schema_id": "native-owner-overlay-result-v1",
        "argument_schema_id": "fixture-args", "argument_schema_sha256": digest,
        "result_schema_id": "fixture-result", "result_schema_sha256": digest,
        "lease_seconds": 30,
    }
    return projection, _mint_published_local_owner_adoption(
        adoption_handle=handle, identity_kind="linux-local-owner-v1", signed_choice=choice,
        adopted_at_unix=None, setup_deadline_unix=100.0, owner=owner, resources=resources,
        native_package=package, operation_records=(operation,), view_custody=view,
        source_members=({"role": "fixture-source", "artifact_id": "fixture-module",
                         "receipt_handle": handle, "relative_path": "fixture.py",
                         "sha256": digest, "size_bytes": 1, "mode": 0o400}, schema_member),
        owner_overlay_observer_records=(observer,))


def test_owner_overlay_claim_rows_bind_local_domain_namespace_and_receipt_closure():
    from hermes_installer.authority.active_policy_compiler import (
        _manifest, _owner_overlay_adoption_source_handles, _choice_projection_record,
    )

    base = _claim()
    claim = replace(base, principal_selection_receipt_handle="G" * 43,
                    principal_identity_kind="linux-local-owner-v1",
                    principal_binding_sha256="a" * 64,
                    namespace_selection_handle="F" * 43,
                    namespace_binding_sha256="b" * 64)
    choice, adoption = _local_owner_adoption_for_claim(claim)
    sources = _owner_overlay_adoption_source_handles((adoption,))
    claim = replace(claim, choice_adoptions=(choice,),
                    source_receipt_handles=tuple(dict.fromkeys((*claim.source_receipt_handles, *sources))),
                    owner_overlay_adoptions=(adoption,))
    manifest = _manifest(claim)
    assert manifest["owner_overlay_adoptions"] == [adoption.to_claim_row()]
    assert set(sources).issubset(set(manifest["source_receipt_handles"]))
    with pytest.raises(BootstrapEnrollmentPending, match="crossed the active identity domain"):
        _manifest(replace(claim, principal_identity_kind="authentik-subject-v1"))
    with pytest.raises(BootstrapEnrollmentPending, match="signed current claim identity"):
        _manifest(replace(claim, namespace_binding_sha256="c" * 64))


def test_recovered_owner_overlay_rows_join_claim_identity_and_publisher_timestamp():
    from hermes_installer.authority.active_policy_compiler import (
        _choice_projection_record, _owner_overlay_adoption_source_handles,
        _verify_recovered_owner_overlay_join,
    )

    claim = replace(_claim(), principal_selection_receipt_handle="G" * 43,
                    principal_identity_kind="linux-local-owner-v1",
                    principal_binding_sha256="a" * 64,
                    namespace_selection_handle="F" * 43,
                    namespace_binding_sha256="b" * 64)
    projection, adoption = _local_owner_adoption_for_claim(claim)
    source_handles = _ordered_unique_receipt_handles(
        (*claim.source_receipt_handles, *_owner_overlay_adoption_source_handles((adoption,))),
        "recovery test")
    claim = replace(claim, choice_adoptions=(projection,), source_receipt_handles=source_handles,
                    owner_overlay_adoptions=(adoption,))
    manifest = _manifest(claim)
    published = adoption.to_claim_row(include_digest=False)
    published["adopted_at_unix"] = 50.0
    published["adoption_sha256"] = hashlib.sha256(_canonical(published)).hexdigest()
    choice_row = _choice_projection_record(projection)
    choice_row["adopted_at_unix"] = 50.0
    inputs = {"owner_overlay_adoption_sha256": hashlib.sha256(
        _canonical([published])).hexdigest(), "choice_projections": [choice_row]}
    descriptor = {"owner_overlay_adoption_records": [published]}
    _verify_recovered_owner_overlay_join(manifest, inputs, descriptor)

    wrong_domain = dict(manifest, principal_identity_kind="authentik-subject-v1")
    with pytest.raises(BootstrapEnrollmentPending, match="crossed the active identity domain"):
        _verify_recovered_owner_overlay_join(wrong_domain, inputs, descriptor)
    crossed = dict(published)
    crossed["adopted_at_unix"] = 51.0
    crossed.pop("adoption_sha256")
    crossed["adoption_sha256"] = hashlib.sha256(_canonical(crossed)).hexdigest()
    bad_inputs = {**inputs, "owner_overlay_adoption_sha256": hashlib.sha256(
        _canonical([crossed])).hexdigest()}
    with pytest.raises(BootstrapEnrollmentPending, match="differs from its signed local-owner claim"):
        _verify_recovered_owner_overlay_join(manifest, bad_inputs,
                                             {"owner_overlay_adoption_records": [crossed]})


def test_active_source_receipt_closure_is_ordered_unique_and_covers_explicit_receipts():
    claim = _claim()
    raw = ("A" * 43, "B" * 43, "9" * 64, "F" * 43, "A" * 43, "B" * 43, "9" * 64, "F" * 43)
    canonical = _ordered_unique_receipt_handles(raw, "test")
    assert canonical == ("A" * 43, "B" * 43, "9" * 64, "F" * 43)
    from dataclasses import replace
    _validate_claim_output_hashes(replace(claim, source_receipt_handles=canonical))
    with pytest.raises(BootstrapEnrollmentPending, match="output bytes changed"):
        _validate_claim_output_hashes(replace(claim, source_receipt_handles=raw))


def test_complete_active_publication_accepts_publishers_deduplicated_input_closure(monkeypatch, tmp_path):
    from dataclasses import replace
    from hermes_installer.authority import active_policy_compiler as compiler
    from hermes_installer.authority.setup_policy_publication import (
        PolicyPublicationReceiptResolver,
        RootSetupPublicationReceipt,
        _receipt_input_handles,
        _SEAL,
    )

    claim = _claim()
    # These are the real source components: PM, native output and principal.
    # The PM/output handles also occur in the prepared-bundle source list.
    claim = replace(claim, source_receipt_handles=_ordered_unique_receipt_handles(
        ("A" * 43, "B" * 43, "9" * 64, "F" * 43,
         "A" * 43, "B" * 43, "9" * 64, "F" * 43), "test"))
    claim = replace(claim, claim_digest=hashlib.sha256(_canonical(_manifest(claim))).hexdigest())
    input_handles = _receipt_input_handles(claim)
    receipt = RootSetupPublicationReceipt(
        1, "R" * 43, claim.transaction_handle, "installer-bootstrap-policy-generation-v1",
        "c" * 64, tmp_path / "generation", 1, 2, claim.compiled_policy_sha256,
        claim.compiled_artifact_catalog_sha256, "d" * 64, "e" * 64,
        claim.expected_selection_catalog_sha256, claim.selection_catalog_sha256,
        input_handles, "active-committed", _SEAL, claim.publication_handle,
        claim.claim_digest, claim.prepared_generation_id,
        claim.expected_service_generation_digest, claim.runtime_receipt_handles,
        claim.materialization_receipt_handles)
    monkeypatch.setattr(PolicyPublicationReceiptResolver, "verify_current_active_claim",
                        lambda **_kwargs: receipt)
    registry = object.__new__(RootActivePolicyCompilationRegistry)
    registry._seal = claim._seal
    registry._claims = {claim.publication_handle: claim}
    registry._states = {claim.publication_handle: "claimed"}
    registry._locks = {}
    registry._verify_postpublication_claim = lambda _claim: None
    journal_record = {
        "state": "claimed", "transaction_handle": claim.transaction_handle,
        "publication_handle": claim.publication_handle, "claim_digest": claim.claim_digest,
    }
    def write_state(_claim, state, receipt_handle):
        journal_record.update({"state": state, "publication_receipt_handle": receipt_handle})
    registry._write_state = write_state
    registry._close_lock = lambda *_args: None
    registry._claim_root = tmp_path
    journal_record_written = []
    def write_journal(_path, value, **_kwargs):
        journal_record.update(value)
        journal_record_written.append(value)
    monkeypatch.setattr(compiler, "_write_json", write_journal)
    monkeypatch.setattr(compiler, "_read_json", lambda _path: dict(journal_record))
    registry._verify_claim_bundle = lambda _claim: None
    attempts = []
    def complete_outputs(self, *args, **kwargs):
        attempts.append((args, kwargs))
        if len(attempts) == 1:
            raise BootstrapEnrollmentPending("simulated native receipt completion interruption")
    registry.materialization_receipts = type("Outputs", (), {
        "complete_active_compilation": complete_outputs,
    })()

    with pytest.raises(BootstrapEnrollmentPending, match="completion interruption"):
        registry.complete_active_publication(receipt)
    assert registry._states[claim.publication_handle] == "active-committed"
    registry.complete_active_publication(receipt)
    assert registry._states[claim.publication_handle] == "active-committed"
    assert receipt.input_receipt_handles == (
        claim.observed_root_receipt_handle, *claim.source_receipt_handles)
    assert len(attempts) == 2
    assert journal_record_written[0]["publication_sha256"] == receipt.publication_sha256


def test_process_restart_recovers_only_from_durable_claim_and_current_typed_publication(monkeypatch, tmp_path):
    from hermes_installer.authority import active_policy_compiler as compiler
    from hermes_installer.authority.native_output_receipts import NativeOutputReservation
    from hermes_installer.authority.setup_policy_publication import (
        PolicyPublicationReceiptResolver,
        RootSetupPublicationReceipt,
        _SEAL,
    )
    import hermes_installer.authority.setup_policy_publication as publication

    original = _claim()
    output_handles = ("B" * 43, "C" * 43, "D" * 43, "E" * 43, "F" * 43)
    source_handles = _ordered_unique_receipt_handles(
        ("A" * 43, *output_handles, "9" * 64, "F" * 43), "fixture")
    original = replace(original, source_receipt_handles=source_handles,
                       materialization_receipt_handles=output_handles, claim_digest="0" * 64)
    original = replace(original, claim_digest=hashlib.sha256(_canonical(_manifest(original))).hexdigest())
    manifest = _manifest(original)
    receipt = RootSetupPublicationReceipt(
        1, "Q" * 43, original.transaction_handle, "installer-bootstrap-policy-generation-v1",
        "a" * 64, tmp_path / "generation", 1, 2, original.compiled_policy_sha256,
        original.compiled_artifact_catalog_sha256, "b" * 64, "c" * 64,
        original.expected_selection_catalog_sha256, "d" * 64,
        (original.observed_root_receipt_handle, *source_handles), "active-committed", _SEAL,
        original.publication_handle, original.claim_digest, original.prepared_generation_id,
        original.expected_service_generation_digest, original.runtime_receipt_handles,
        original.materialization_receipt_handles, ())
    persisted_claim = {
        "schema": 1, "publication_handle": original.publication_handle,
        "claim_digest": original.claim_digest, "manifest": manifest,
        "policy_sha256": original.compiled_policy_sha256,
        "artifact_catalog_sha256": original.compiled_artifact_catalog_sha256,
        "selection_sha256": original.compiled_selection_sha256,
    }
    state = {
        "schema": 1, "publication_handle": original.publication_handle,
        "claim_digest": original.claim_digest, "transaction_handle": original.transaction_handle,
        "setup_session_id": original.setup_session_id,
        "prepared_generation_id": original.prepared_generation_id,
        "expected_selection_catalog_sha256": original.expected_selection_catalog_sha256,
        "expected_service_generation_digest": original.expected_service_generation_digest,
        "policy_sha256": original.compiled_policy_sha256,
        "artifact_catalog_sha256": original.compiled_artifact_catalog_sha256,
        "selection_sha256": original.compiled_selection_sha256,
        "observed_root_receipt_handle": original.observed_root_receipt_handle,
        "principal_selection_receipt_handle": original.principal_selection_receipt_handle,
        "principal_identity_kind": original.principal_identity_kind,
        "principal_binding_sha256": original.principal_binding_sha256,
        "namespace_selection_handle": original.namespace_selection_handle,
        "namespace_binding_sha256": original.namespace_binding_sha256,
        "owner_overlay_adoptions": [],
        "runtime_receipt_handles": list(original.runtime_receipt_handles),
        "materialization_receipt_handles": list(original.materialization_receipt_handles),
        "publication_receipt_handle": None,
        "issued_monotonic": original.issued_monotonic,
        "expires_monotonic": original.expires_monotonic,
        "state": "claimed",
    }
    descriptor = {"owner_overlay_adoption_records": [], "inputs": {
        "source_receipt_handles": list(source_handles),
        "observed_root_receipt_handle": original.observed_root_receipt_handle,
        "selection_catalog_sha256": original.selection_catalog_sha256,
        "choice_projections": [], "publication_handle": original.publication_handle,
        "claim_digest": original.claim_digest,
        "prepared_generation_id": original.prepared_generation_id,
        "expected_service_generation_digest": original.expected_service_generation_digest,
        "transaction_handle": original.transaction_handle,
        "runtime_receipt_handles": list(original.runtime_receipt_handles),
        "materialization_receipt_handles": list(original.materialization_receipt_handles),
        "owner_overlay_adoption_sha256": hashlib.sha256(_canonical([])).hexdigest(),
    }}
    monkeypatch.setattr(PolicyPublicationReceiptResolver, "resolve_current", lambda: receipt)
    monkeypatch.setattr(publication, "_read_generation_descriptor", lambda *_args: (
        descriptor, {}, {
            "plans/bootstrap-policy-v1.json": original.policy_bytes,
            "catalog/artifacts.json": original.artifact_catalog_bytes,
        }))
    monkeypatch.setattr(compiler, "_read_immutable_bytes", lambda path: {
        ".policy": original.policy_bytes,
        ".catalog": original.artifact_catalog_bytes,
        ".selection": _canonical(original.selection_document),
    }[path.suffix])
    monkeypatch.setattr(compiler, "_read_json", lambda path: (
        persisted_claim if path.name.endswith(".claim.json") else dict(state)))
    state_writes = []
    monkeypatch.setattr(compiler, "_write_json", lambda _path, value, **_kwargs:
                        (state.update(value), state_writes.append(dict(value))))

    reservation = NativeOutputReservation(
        "W" * 43, original.publication_handle, original.claim_digest,
        original.prepared_generation_id, original.materialization_receipt_handles)
    recovered_rows = []
    class Outputs:
        def resolve_active_compilation_reservation(self, current_receipt):
            assert current_receipt is receipt
            return reservation

        def complete_active_compilation(self, reservation_handle, current_receipt, **kwargs):
            recovered_rows.append((reservation_handle, current_receipt, kwargs))
            if len(recovered_rows) == 1:
                raise BootstrapEnrollmentPending("simulated restart finalization interruption")
            return tuple(type("RecoveredReceipt", (), {"receipt_id": item})()
                         for item in original.materialization_receipt_handles)

    registry = object.__new__(RootActivePolicyCompilationRegistry)
    registry._require_root = lambda: None
    registry._claim_root = tmp_path
    registry._states = {}
    registry.materialization_receipts = Outputs()
    # Deliberately no in-memory claims/session, as after a compiler restart.
    registry._claims = {}

    # A matching publication and output tuple cannot substitute another
    # reservation handle; recovery must retain the exact precompile capability.
    with pytest.raises(BootstrapEnrollmentPending, match="another durable reservation"):
        registry.complete_active_publication(receipt)
    assert recovered_rows == []
    reservation = NativeOutputReservation(
        original._reservation_handle, original.publication_handle, original.claim_digest,
        original.prepared_generation_id, original.materialization_receipt_handles)

    with pytest.raises(BootstrapEnrollmentPending, match="finalization interruption"):
        registry.complete_active_publication(receipt)
    # A completion interruption must leave the durable claim recoverable and
    # must not falsely mark it complete or release its output reservation.
    assert registry._states == {}
    assert state["state"] == "claimed"
    assert state_writes == []
    assert len(recovered_rows) == 1

    assert registry.complete_active_publication(receipt) is receipt
    assert registry._claims == {}
    assert registry._states[original.publication_handle] == "active-committed"
    assert state["state"] == "active-committed"
    assert state["publication_receipt_handle"] == receipt.receipt_handle
    assert recovered_rows == [(
        reservation.reservation_handle, receipt, {
            "prepared_generation_id": receipt.prepared_generation_id,
            "publication_handle": receipt.publication_handle,
            "claim_digest": receipt.claim_digest,
        }), (
        reservation.reservation_handle, receipt, {
            "prepared_generation_id": receipt.prepared_generation_id,
            "publication_handle": receipt.publication_handle,
            "claim_digest": receipt.claim_digest,
        })]
    assert len(state_writes) == 1
    stale_receipt = replace(receipt, publication_sha256="f" * 64)
    monkeypatch.setattr(PolicyPublicationReceiptResolver, "resolve_current", lambda: stale_receipt)
    with pytest.raises(BootstrapEnrollmentPending, match="not the current selected publication"):
        registry.complete_active_publication(receipt)
    assert len(recovered_rows) == 2
    assert len(state_writes) == 1


def test_caller_constructed_choice_projection_fails_compiler_seal_check():
    from dataclasses import replace

    claim = _claim()
    projection = ActiveSetupChoiceProjection(
        selection_handle="H" * 43, purpose="memory-service-enablement", key_id="root-key-v1",
        signed_record_sha256="a" * 64, choice_payload_sha256="b" * 64,
        choice_epoch=1, revocation_epoch=1, issued_at_unix=1.0, setup_deadline_unix=2.0,
        release_deployment_receipt_sha256="c" * 64, setup_session_handle="d" * 64,
        transaction_handle="T" * 64, plan_id="installer-root-setup-plan-v1",
        prepared_generation="prepared-1", principal_selection_handle="e" * 43,
        namespace_selection_handle="f" * 43, private_profile_selection_handle="g" * 43,
        source_member_receipt_handles=("i" * 43,), principal_id="principal",
        profile_id="hermes-agent-native-v1", namespace_id="namespace",
        principal_binding_sha256="j" * 64, namespace_binding_sha256="k" * 64,
        service_generation_id="prepared-1", service_generation_digest="8" * 64,
        selection_catalog_sha256=claim.selection_catalog_sha256,
        _compiler_seal=object(),
    )
    registry = object.__new__(RootActivePolicyCompilationRegistry)
    registry._seal = claim._seal
    with pytest.raises(BootstrapEnrollmentPending, match="unsealed"):
        registry._verify_choice_projection_seals(
            replace(claim, choice_adoptions=(projection,)))


def test_predecessor_resolver_returns_only_the_verified_retained_claim_value():
    claim = _claim()
    registry = object.__new__(RootActivePolicyCompilationRegistry)
    registry._claims = {claim.publication_handle: claim}
    verified = []
    registry.verify_current_active_policy_claim = lambda actual: verified.append(actual) or actual
    assert registry.resolve_current_active_policy_predecessor(claim.publication_handle) == "7" * 64
    assert verified == [claim]

    with pytest.raises(BootstrapEnrollmentPending, match="claim is absent"):
        registry.resolve_current_active_policy_predecessor("Z" * 43)


def test_current_active_claim_resolver_revalidates_the_exact_retained_claim():
    claim = _claim()
    registry = object.__new__(RootActivePolicyCompilationRegistry)
    registry._claims = {claim.publication_handle: claim}
    verified = []
    registry.verify_current_active_policy_claim = lambda actual: verified.append(actual) or actual
    assert registry.resolve_current_active_policy_claim(claim.publication_handle) is claim
    assert verified == [claim]
    with pytest.raises(BootstrapEnrollmentPending, match="claim is absent"):
        registry.resolve_current_active_policy_claim("Z" * 43)


def test_mutated_selection_output_is_rejected_before_claim_can_be_published():
    claim = _claim()
    claim.selection_document["plans"][0]["sha256"] = "0" * 64
    with pytest.raises(BootstrapEnrollmentPending, match="selection output hashes changed"):
        _validate_claim_output_hashes(claim)


def test_mutated_policy_bytes_are_rejected_before_claim_can_be_published():
    claim = _claim()
    object.__setattr__(claim, "policy_bytes", b'{"schema":1,"changed":true}')
    with pytest.raises(BootstrapEnrollmentPending, match="output bytes changed"):
        _validate_claim_output_hashes(claim)


def test_release_releases_reserved_outputs_and_makes_handle_one_use():
    claim = _claim()
    registry = object.__new__(RootActivePolicyCompilationRegistry)
    registry._seal = claim._seal
    registry._claims = {claim.publication_handle: claim}
    registry._states = {claim.publication_handle: "claimed"}
    registry._locks = {}
    calls = []
    registry.materialization_receipts = type("Outputs", (), {
        "release_active_compilation": lambda self, *args, **kwargs: calls.append((args, kwargs))
    })()
    registry._write_state = lambda *_args: None
    registry._close_lock = lambda *_args: None
    registry.release_active_policy(claim.publication_handle)
    assert registry._states[claim.publication_handle] == "released"
    assert len(calls) == 1
    registry.release_active_policy(claim.publication_handle)
    assert len(calls) == 1
    with pytest.raises(BootstrapEnrollmentPending, match="stale, altered, replayed"):
        registry.verify_current_active_policy_claim(claim)


def test_failed_native_release_keeps_claim_reserved_and_retryable():
    claim = _claim()
    registry = object.__new__(RootActivePolicyCompilationRegistry)
    registry._claims = {claim.publication_handle: claim}
    registry._states = {claim.publication_handle: "claimed"}
    registry._locks = {}
    registry.materialization_receipts = type("Outputs", (), {
        "release_active_compilation": lambda *_args, **_kwargs: (_ for _ in ()).throw(
            BootstrapEnrollmentPending("simulated reservation journal failure"))
    })()
    registry._write_state = lambda *_args: pytest.fail("failed output release must not advance claim state")
    registry._close_lock = lambda *_args: None
    with pytest.raises(BootstrapEnrollmentPending, match="reservation journal failure"):
        registry.release_active_policy(claim.publication_handle)
    assert registry._states[claim.publication_handle] == "claimed"


def test_untyped_or_malformed_claim_handle_is_rejected():
    registry = object.__new__(RootActivePolicyCompilationRegistry)
    registry._claims = {}
    with pytest.raises(BootstrapEnrollmentError, match="malformed"):
        registry._get_claim("caller-controlled")


def test_active_state_resolution_rechecks_current_selected_publication(monkeypatch, tmp_path):
    from types import SimpleNamespace
    import hermes_installer.authority.active_policy_compiler as compiler
    from hermes_installer.authority.setup_policy_publication import PolicyPublicationReceiptResolver

    row = {
        "state": "active-committed", "transaction_handle": "T" * 64,
        "publication_handle": "H" * 43, "claim_digest": "a" * 64,
        "prepared_generation_id": "prepared-1",
        "materialization_receipt_handles": ["B" * 43],
        "active_selection_catalog_sha256": "b" * 64,
        "publication_sha256": "c" * 64, "descriptor_sha256": "d" * 64,
        "publication_generation_id": "installer-bootstrap-policy-generation-v1",
        "publication_generation_device": 1, "publication_generation_inode": 2,
    }
    selected = SimpleNamespace(
        state="active-committed", current_selection_catalog_sha256="b" * 64,
        publication_sha256="c" * 64, descriptor_sha256="d" * 64,
        generation_id="installer-bootstrap-policy-generation-v1",
        generation_device=1, generation_inode=2,
    )
    seen = []
    monkeypatch.setattr(compiler, "_read_json", lambda _path: row)
    monkeypatch.setattr(PolicyPublicationReceiptResolver, "verify_current_active_claim",
                        lambda **kwargs: (seen.append(kwargs), selected)[1])
    session = SimpleNamespace(_authorization=SimpleNamespace(transaction_handle="T" * 64))
    registry = object.__new__(RootActivePolicyCompilationRegistry)
    registry.factory = SimpleNamespace(resolve_live_session=lambda _handle: session)
    registry._claim_root = tmp_path

    assert registry.resolve_active_state(object()) is row
    assert seen == [{
        "publication_handle": "H" * 43, "claim_digest": "a" * 64,
        "prepared_generation_id": "prepared-1", "transaction_handle": "T" * 64,
        "expected_materialization_receipt_handles": ("B" * 43,),
    }]

    monkeypatch.setattr(PolicyPublicationReceiptResolver, "verify_current_active_claim",
                        lambda **_kwargs: SimpleNamespace(**{
                            **selected.__dict__, "descriptor_sha256": "e" * 64}))
    with pytest.raises(BootstrapEnrollmentPending, match="differs from the current selected publication"):
        registry.resolve_active_state(object())
