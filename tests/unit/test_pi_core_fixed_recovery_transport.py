"""Contracts for the fixed two-function Core recovery transport.

These are source fixtures only. Pi qualification must still exercise the real
retained cohort and unchanged Core restore API before any recovery claim.
"""
from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest

TOOL = (Path(__file__).resolve().parents[2] / "tools"
        / "pi_core_fixed_recovery_transport.py")
SPEC = importlib.util.spec_from_file_location("pi_core_fixed_recovery_transport", TOOL)
assert SPEC is not None and SPEC.loader is not None
transport = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(transport)


def _source(check="def _check_adapter_cohort_rollback_currentness(cohort, prior, contents):\n    return ('checked', cohort, prior, contents)\n",
            helper="def _verify_absent_initial_primary_rollback(cohort, initial):\n    return ('absent', cohort, initial)\n"):
    return ("raise RuntimeError('PRIVATE_MODULE_EXECUTION')\n" + check + helper).encode()


def test_only_exact_fixed_definitions_compile_without_module_execution():
    raw = _source()
    code = transport._definition_code_objects(raw, expected_sha256=hashlib.sha256(raw).hexdigest())
    assert tuple(item.co_name for item in code) == tuple(
        name for name, _params in transport._FIX_FUNCTIONS)
    assert all(item.co_freevars == () for item in code)
    with pytest.raises(transport.RecoveryTransportDenied):
        transport._definition_code_objects(raw, expected_sha256="0" * 64)


@pytest.mark.parametrize("source", [
    _source(check="@property\ndef _check_adapter_cohort_rollback_currentness(cohort, prior, contents):\n    return None\n"),
    _source(check="def _check_adapter_cohort_rollback_currentness(cohort, prior, contents=None):\n    return None\n"),
    _source(check="def _check_adapter_cohort_rollback_currentness(cohort: object, prior, contents):\n    return None\n"),
    _source() + b"\ndef _verify_absent_initial_primary_rollback(cohort, initial):\n    return None\n",
])
def test_definition_shape_or_duplicate_denied(source):
    with pytest.raises(transport.RecoveryTransportDenied):
        transport._definition_code_objects(source, expected_sha256=hashlib.sha256(source).hexdigest())


def _core_module(*, fail=False):
    module = ModuleType("failed_core_fixture")
    namespace = module.__dict__
    namespace["events"] = []
    namespace["fail"] = fail
    exec("""
def _check_adapter_cohort_rollback_currentness(cohort, prior, contents):
    events.append(('old-check', cohort))
def restore_owned_core_adapter_update():
    events.append(('api', None))
    _check_adapter_cohort_rollback_currentness('cohort', 'prior', 'contents')
    _verify_absent_initial_primary_rollback('cohort', 'initial')
    if fail:
        raise LookupError('PRIVATE_FAILURE_TEXT')
    return 'restored'
""", namespace, namespace)
    return module


def test_bindings_are_replaced_only_for_one_call_and_restored_on_success():
    raw = _source()
    codes = transport._definition_code_objects(raw, expected_sha256=hashlib.sha256(raw).hexdigest())
    module = _core_module()
    old_check = module._check_adapter_cohort_rollback_currentness
    before = {key: id(value) for key, value in module.__dict__.items()
              if key not in {name for name, _params in transport._FIX_FUNCTIONS}}
    guarded = []
    result = transport._restore_with_transported_functions(
        module, codes, lambda *args: guarded.append(args))
    assert result == "restored"
    assert module._check_adapter_cohort_rollback_currentness is old_check
    assert "_verify_absent_initial_primary_rollback" not in module.__dict__
    assert {key: id(value) for key, value in module.__dict__.items()
            if key not in {name for name, _params in transport._FIX_FUNCTIONS}} == before
    assert guarded == [("cohort", "prior", "contents")]
    assert module.events == [("api", None)]


def test_bindings_and_helper_absence_restore_after_api_exception():
    raw = _source()
    codes = transport._definition_code_objects(raw, expected_sha256=hashlib.sha256(raw).hexdigest())
    module = _core_module(fail=True)
    old_check = module._check_adapter_cohort_rollback_currentness
    with pytest.raises(LookupError, match="PRIVATE_FAILURE_TEXT"):
        transport._restore_with_transported_functions(module, codes, lambda *_args: None)
    assert module._check_adapter_cohort_rollback_currentness is old_check
    assert "_verify_absent_initial_primary_rollback" not in module.__dict__
    assert module.events == [("api", None)]


def test_existing_helper_binding_is_restored_after_transport():
    raw = _source()
    codes = transport._definition_code_objects(raw, expected_sha256=hashlib.sha256(raw).hexdigest())
    module = _core_module()
    previous_helper = lambda *_args: "preexisting"
    module._verify_absent_initial_primary_rollback = previous_helper
    transport._restore_with_transported_functions(module, codes, lambda *_args: None)
    assert module._verify_absent_initial_primary_rollback is previous_helper


def test_recovery_target_accepts_only_null_or_complete_retained_joins(monkeypatch):
    cohort = {
        "phase": "rolling-back",
        "new_source": f"{transport._source_directory(transport._FAILED_COMMIT)}/src",
        "cohort_transaction_id": "a" * 32,
    }
    cohort_raw = b"exact-cohort"
    reference = "backup-reference"
    retained_hash = "b" * 64
    core = SimpleNamespace(
        ADAPTER_SOURCE=Path(cohort["new_source"]),
        _read_adapter_update_cohort=lambda: (cohort, cohort_raw),
        _adapter_update_backup_reference=lambda _cohort: reference,
        _retained_committed_adapter_cohort_sha256=lambda _cohort, _raw: retained_hash,
    )

    def capture(joins):
        ingress = {"state": "recovery-required", "candidate_sha": transport._FAILED_COMMIT,
                   "adapter_refresh": dict(zip(("core_update_backup_reference",
                                                 "core_update_cohort_transaction_id",
                                                 "core_update_cohort_sha256"), joins))}
        monkeypatch.setattr(transport, "_read_retained_ingress",
                            lambda _core: (b"exact-ingress", ingress))
        return transport._capture_exact_target(core)

    assert capture((None, None, None))["cohort"] is cohort
    assert capture((reference, "a" * 32, retained_hash))["cohort"] is cohort
    for partial in ((reference, None, None), (None, "a" * 32, retained_hash),
                    (reference, "a" * 32, None)):
        with pytest.raises(transport.RecoveryTransportDenied):
            capture(partial)


def test_failure_projection_contains_only_bounded_pinned_source_frames():
    filename = str(transport._source_directory(transport._FAILED_COMMIT)
                   / "src" / "hermes_installer" / "core_runtime.py")
    namespace = {}
    exec(compile("def pinned_failure():\n    raise RuntimeError('PRIVATE_TOKEN_VALUE')\n",
                 filename, "exec"), namespace)
    try:
        namespace["pinned_failure"]()
    except RuntimeError as error:
        projection = transport._safe_failure_projection(error)
    else:
        pytest.fail("fixture must raise")
    encoded = transport._canonical_json(projection)
    assert b"PRIVATE_TOKEN_VALUE" not in encoded
    assert projection["exceptions"][0]["exception_type"] == "RuntimeError"
    assert projection["exceptions"][0]["frames"]
    assert all(frame["source"] == "failed"
               and frame["relative_path"] == "hermes_installer/core_runtime.py"
               for item in projection["exceptions"] for frame in item["frames"])
    assert sum(len(item["frames"]) for item in projection["exceptions"]) <= 12


def test_authority_binding_drift_denies_and_restores_transported_names():
    raw = _source()
    codes = transport._definition_code_objects(raw, expected_sha256=hashlib.sha256(raw).hexdigest())
    module = _core_module()

    def drift(*_args):
        module.ADAPTER_SOURCE = "changed"

    with pytest.raises(transport.RecoveryTransportDenied, match="authority bindings changed"):
        transport._restore_with_transported_functions(module, codes, drift)
    assert module._check_adapter_cohort_rollback_currentness.__name__ == "_check_adapter_cohort_rollback_currentness"
    assert "_verify_absent_initial_primary_rollback" not in module.__dict__
