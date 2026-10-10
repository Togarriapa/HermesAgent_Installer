from __future__ import annotations

import hashlib
import pytest

from hermes_installer.authority.active_policy_compiler import (
    RootActivePolicyCompilationClaim,
    RootActivePolicyCompilationRegistry,
    _canonical,
    _manifest,
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
