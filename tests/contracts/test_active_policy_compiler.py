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
        schema=1, plan_artifact_id="installer-root-setup-plan-v1", release_commit="a" * 40,
        publication_handle="H" * 43, setup_session_id="S" * 64, transaction_handle="T" * 64,
        plan_sha256="f" * 64, prepared_generation_id="prepared-1",
        expected_selection_catalog_sha256="7" * 64, expected_service_generation_digest="8" * 64,
        policy_template_artifact_id="installer-bootstrap-policy-v1", policy_template_sha256="6" * 64,
        principal_selection_receipt_handle="9" * 64, runtime_receipt_handles=("A" * 43,),
        materialization_receipt_handles=("B" * 43,), source_receipt_handles=("A" * 43, "B" * 43, "9" * 64),
        compiled_policy_sha256=hashlib.sha256(policy).hexdigest(),
        compiled_artifact_catalog_sha256=hashlib.sha256(catalog).hexdigest(),
        compiled_selection_sha256=hashlib.sha256(_canonical(selection)).hexdigest(),
        selection_catalog_sha256=selection["catalog_sha256"], issued_monotonic=1.0,
        expires_monotonic=100.0, claim_digest="0" * 64, policy_bytes=policy,
        artifact_catalog_bytes=catalog, selection_document=selection,
        observed_root_receipt_handle="C" * 64,
        _root_journal_root=__import__("pathlib").Path("/var/lib/hermes-installer/authority-journal"),
        _root_setup_session=object(), _reservation_handle="D" * 43, _seal=object(),
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


def test_active_source_receipt_closure_is_ordered_unique_and_covers_explicit_receipts():
    claim = _claim()
    raw = ("A" * 43, "B" * 43, "9" * 64, "A" * 43, "B" * 43, "9" * 64)
    canonical = _ordered_unique_receipt_handles(raw, "test")
    assert canonical == ("A" * 43, "B" * 43, "9" * 64)
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
        ("A" * 43, "B" * 43, "9" * 64, "A" * 43, "B" * 43, "9" * 64), "test"))
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
        ("A" * 43, *output_handles, "9" * 64), "fixture")
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
        "runtime_receipt_handles": list(original.runtime_receipt_handles),
        "materialization_receipt_handles": list(original.materialization_receipt_handles),
        "publication_receipt_handle": None,
        "issued_monotonic": original.issued_monotonic,
        "expires_monotonic": original.expires_monotonic,
        "state": "claimed",
    }
    descriptor = {"inputs": {
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
        "V" * 43, original.publication_handle, original.claim_digest,
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
