from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path

import pytest

from hermes_installer.registry.resource_jobs import (
    ResourceBackendEnrollment, ResourceBodyRecipe, ResourceBodyRecipeField,
    ResourceChildAdmission, ResourceJobDenied, ResourceJobEnrollment,
    ResourceJobLedger, ResourceJobNode, ResourceBodyRecipeScope,
    ResourceScopeBinding, ResourceValidator,
)


def _payload(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _node(node_id: str, *, deps: tuple[str, ...] = (), maximum_attempts: int = 1) -> ResourceJobNode:
    return ResourceJobNode(node_id, f"action-{node_id}", "resource.bundle.node.run",
                           f"resource:bundle/demo:{node_id}:g1", "recipient:owner",
                           _payload({"node": node_id}), deps, maximum_attempts)


def _enrollment(*nodes: ResourceJobNode, concurrency: int = 2) -> ResourceJobEnrollment:
    return ResourceJobEnrollment(
        resource_id="demo", kind="bundles", generation=hashlib.sha256(b"generation").hexdigest(),
        selected_enabled=True, profile_id="orchestrator", principal_id="root-hermes",
        consent_revision="consent-7", approved_action_ids=frozenset(n.action_id for n in nodes),
        fixed_target_ids=frozenset(n.target for n in nodes), recipient_scope=frozenset({"recipient:owner"}),
        source_policy=frozenset({"static-context"}), schedule_or_route_id="bundle:demo",
        nodes=tuple(nodes), max_children=8, max_concurrency=concurrency,
        max_runtime_seconds=300, max_payload_bytes=4096, max_replay_entries=100,
    )


def _ledger(tmp_path: Path, *, now: list[float] | None = None) -> ResourceJobLedger:
    parent = tmp_path / "private"
    parent.mkdir(mode=0o700)
    parent.chmod(0o700)
    return ResourceJobLedger(parent / "jobs.sqlite", monotonic=(lambda: now[0]) if now else __import__("time").monotonic)


def _admit(ledger: ResourceJobLedger, enrollment: ResourceJobEnrollment):
    return ledger.admit_job(enrollment, event_id="event-1", verified_source_receipt_ids=("root-receipt-1",),
                            current_generation=enrollment.generation, ttl_seconds=60,
                            parent_lineage_hash=hashlib.sha256(b"lineage").hexdigest(),
                            parent_sensitivity="private")


def test_job_and_child_admission_are_distinct_single_use_and_preserve_lineage(tmp_path: Path) -> None:
    enrollment = _enrollment(_node("root"), _node("leaf", deps=("root",)))
    ledger = _ledger(tmp_path)
    job = _admit(ledger, enrollment)

    first = ledger.admit_child(job, enrollment, node_id="root", parent_result_receipt_ids=(),
                               current_generation=enrollment.generation)
    assert first.effect == "resource.bundle.node.run"
    assert first.target == enrollment.node_map["root"].target
    assert first.canonical_payload_sha256 == hashlib.sha256(first.payload).hexdigest()
    assert first.source_receipt_ids == ("root-receipt-1",)
    with pytest.raises(ResourceJobDenied, match="already consumed"):
        ledger.admit_child(job, enrollment, node_id="root", parent_result_receipt_ids=(),
                           current_generation=enrollment.generation)

    ledger.start_child(first, current_generation=enrollment.generation)
    ledger.finish_child(first, result_receipt_ids=("result-root-1",), success=True,
                        current_generation=enrollment.generation)
    second = ledger.admit_child(job, enrollment, node_id="leaf", parent_result_receipt_ids=("result-root-1",),
                                current_generation=enrollment.generation)
    assert second.parent_result_receipt_ids == ("result-root-1",)


def test_replay_unselected_stale_generation_and_wrong_lineage_are_denied(tmp_path: Path) -> None:
    enrollment = _enrollment(_node("root"), _node("leaf", deps=("root",)))
    ledger = _ledger(tmp_path)
    job = _admit(ledger, enrollment)
    with pytest.raises(ResourceJobDenied, match="already admitted"):
        _admit(ledger, enrollment)
    with pytest.raises(ResourceJobDenied, match="already admitted"):
        ledger.admit_job(
            enrollment, event_id="event-1", verified_source_receipt_ids=("new-root-receipt",),
            current_generation=enrollment.generation, ttl_seconds=60,
            parent_lineage_hash=hashlib.sha256(b"lineage").hexdigest(),
            parent_sensitivity="private",
        )
    with pytest.raises(ResourceJobDenied, match="outside the admitted DAG"):
        ledger.admit_child(job, enrollment, node_id="unselected", parent_result_receipt_ids=(),
                           current_generation=enrollment.generation)
    first = ledger.admit_child(job, enrollment, node_id="root", parent_result_receipt_ids=(),
                               current_generation=enrollment.generation)
    ledger.start_child(first, current_generation=enrollment.generation)
    ledger.finish_child(first, result_receipt_ids=("result-root-1",), success=True,
                        current_generation=enrollment.generation)
    with pytest.raises(ResourceJobDenied, match="exact completed parent receipts"):
        ledger.admit_child(job, enrollment, node_id="leaf", parent_result_receipt_ids=(),
                           current_generation=enrollment.generation)
    with pytest.raises(ResourceJobDenied, match="revoked"):
        ledger.admit_child(job, enrollment, node_id="leaf", parent_result_receipt_ids=("result-root-1",),
                           current_generation=hashlib.sha256(b"new generation").hexdigest())


def test_cycle_scope_and_disabled_selection_fail_closed() -> None:
    with pytest.raises(ResourceJobDenied, match="cycle"):
        _enrollment(_node("a", deps=("b",)), _node("b", deps=("a",)))
    a = _node("a")
    with pytest.raises(ResourceJobDenied, match="action or target scope"):
        ResourceJobEnrollment("demo", "bundles", hashlib.sha256(b"g").hexdigest(), True,
                              "orchestrator", "root-hermes", "consent-7", frozenset(),
                              frozenset({a.target}), frozenset({"recipient:owner"}),
                              frozenset({"static-context"}), "bundle:demo", (a,), 8, 2, 30, 4096, 100)
    with pytest.raises(ResourceJobDenied, match="not selected and enabled"):
        ResourceJobEnrollment("demo", "bundles", hashlib.sha256(b"g").hexdigest(), False,
                              "orchestrator", "root-hermes", "consent-7", frozenset({a.action_id}),
                              frozenset({a.target}), frozenset({"recipient:owner"}),
                              frozenset({"static-context"}), "bundle:demo", (a,), 8, 2, 30, 4096, 100)


def test_concurrency_deadline_and_generation_revocation_block_effect_admission(tmp_path: Path) -> None:
    clock = [20.0]
    enrollment = _enrollment(_node("a"), _node("b"), concurrency=1)
    ledger = _ledger(tmp_path, now=clock)
    job = _admit(ledger, enrollment)
    first = ledger.admit_child(job, enrollment, node_id="a", parent_result_receipt_ids=(),
                               current_generation=enrollment.generation)
    with pytest.raises(ResourceJobDenied, match="concurrency limit"):
        ledger.admit_child(job, enrollment, node_id="b", parent_result_receipt_ids=(),
                           current_generation=enrollment.generation)
    ledger.revoke_generation(enrollment.resource_id, enrollment.generation)
    with pytest.raises(ResourceJobDenied, match="expired or stopped"):
        ledger.start_child(first, current_generation=enrollment.generation)


def test_failed_child_mint_cancels_dependents_but_keeps_independent_receipts(tmp_path: Path) -> None:
    enrollment = _enrollment(_node("a"), _node("a-child", deps=("a",)), _node("b"))
    ledger = _ledger(tmp_path)
    job = _admit(ledger, enrollment)
    a = ledger.admit_child(job, enrollment, node_id="a", parent_result_receipt_ids=(),
                           current_generation=enrollment.generation)
    ledger.fail_child_admission(a, current_generation=enrollment.generation)
    assert not ledger.is_active(a, current_generation=enrollment.generation)
    # Independent pending work remains available; only descendants are cancelled.
    b = ledger.admit_child(job, enrollment, node_id="b", parent_result_receipt_ids=(),
                           current_generation=enrollment.generation)
    assert b.node_id == "b"
    with pytest.raises(ResourceJobDenied, match="prerequisites are not complete"):
        ledger.admit_child(job, enrollment, node_id="a-child", parent_result_receipt_ids=(),
                           current_generation=enrollment.generation)


def test_each_retry_gets_new_admission_and_is_limited_by_child_quota(tmp_path: Path) -> None:
    root = _node("root", maximum_attempts=2)
    enrollment = _enrollment(root)
    enrollment = replace(enrollment, max_children=2)
    ledger = _ledger(tmp_path)
    job = _admit(ledger, enrollment)
    first = ledger.admit_child(job, enrollment, node_id="root", parent_result_receipt_ids=(),
                               current_generation=enrollment.generation)
    ledger.fail_child_admission(first, current_generation=enrollment.generation)
    retry = ledger.retry_child(job, first, enrollment, parent_result_receipt_ids=(),
                               current_generation=enrollment.generation)
    assert retry.admission_id != first.admission_id
    assert retry.retry_index == 1
    assert retry.canonical_payload_sha256 == first.canonical_payload_sha256
    ledger.fail_child_admission(retry, current_generation=enrollment.generation)
    with pytest.raises(ResourceJobDenied, match="attempt quota is exhausted"):
        ledger.retry_child(job, retry, enrollment, parent_result_receipt_ids=(),
                           current_generation=enrollment.generation)


def test_retry_exhaustion_and_effect_failure_close_only_dependent_nodes(tmp_path: Path) -> None:
    root = _node("root", maximum_attempts=2)
    enrollment = _enrollment(root, _node("dependent", deps=("root",)), _node("independent"))
    enrollment = replace(enrollment, max_children=5)
    ledger = _ledger(tmp_path)
    job = _admit(ledger, enrollment)

    first = ledger.claim_child(job, enrollment, node_id="root",
                               child_admission_id=job.child_admission_ids["root"],
                               parent_result_receipt_ids=(), current_generation=enrollment.generation)
    ledger.fail_child_admission(first, current_generation=enrollment.generation)
    retry = ledger.claim_child(job, enrollment, node_id="root",
                               child_admission_id=first.admission_id,
                               parent_result_receipt_ids=(), current_generation=enrollment.generation)
    assert retry.admission_id != first.admission_id
    ledger.fail_child_admission(retry, current_generation=enrollment.generation)
    with pytest.raises(ResourceJobDenied, match="attempt quota is exhausted"):
        ledger.claim_child(job, enrollment, node_id="root",
                           child_admission_id=retry.admission_id,
                           parent_result_receipt_ids=(), current_generation=enrollment.generation)
    with pytest.raises(ResourceJobDenied, match="prerequisites are not complete"):
        ledger.admit_child(job, enrollment, node_id="dependent", parent_result_receipt_ids=(),
                           current_generation=enrollment.generation)
    # A failed dependency does not prevent an independent node from running.
    independent = ledger.admit_child(job, enrollment, node_id="independent", parent_result_receipt_ids=(),
                                     current_generation=enrollment.generation)
    ledger.start_child(independent, current_generation=enrollment.generation)
    ledger.finish_child(independent, result_receipt_ids=(), success=False,
                        current_generation=enrollment.generation)
    assert not ledger.is_job_active(job.job_id, current_generation=enrollment.generation)


def test_webhook_runtime_receipt_cannot_be_used_as_a_root_verified_receipt_id(tmp_path: Path) -> None:
    from hermes_installer.registry.resources_runtime import WebhookReceipt

    enrollment = _enrollment(_node("root"))
    ledger = _ledger(tmp_path)
    receipt = WebhookReceipt("demo", "event-1", "changed", b"{}", hashlib.sha256(b"{}").hexdigest(), 1.0)
    with pytest.raises(ResourceJobDenied, match="receipt id is invalid"):
        ledger.admit_job(enrollment, event_id=receipt.event_id, verified_source_receipt_ids=(receipt,),
                         current_generation=enrollment.generation, ttl_seconds=10,
                         parent_lineage_hash=hashlib.sha256(b"lineage").hexdigest(),
                         parent_sensitivity="private")


def test_backend_and_literal_recipe_freeze_protected_values() -> None:
    digest = hashlib.sha256(b"handler").hexdigest()
    actions = {"fixed-action"}
    credentials = {"credential-ref"}
    backend = ResourceBackendEnrollment(
        "backend", "demo", "profile", "principal", hashlib.sha256(b"gen").hexdigest(),
        "consent", "source-channel", "observer", "native-package", "native-gen",
        "handler-artifact", digest, actions, "resource.cron.run", "resource:demo:run:g",
        "recipient:owner", credentials, "request-schema", "result-schema", "recipe",
        "scope", 4096, 4096, 30,
    )
    actions.add("later-mutation")
    credentials.clear()
    assert backend.approved_action_ids == frozenset({"fixed-action"})
    assert backend.credential_reference_ids == frozenset({"credential-ref"})

    recipe = ResourceBodyRecipe(
        "recipe", "request-schema", "recipe-artifact", digest,
        (ResourceBodyRecipeField("action", "literal", "run", "enum-run"),), {}, 512,
    )
    assert recipe.render_literals() == b'{"action":"run"}'
    with pytest.raises(ResourceJobDenied, match="protected event, result, or scope values"):
        ResourceBodyRecipe(
            "event-recipe", "request-schema", "recipe-artifact", digest,
            (ResourceBodyRecipeField("message", "observed-event-field", "message", "bounded-text"),),
            {}, 512,
        ).render_literals()


def test_bounded_json_validator_fails_closed_without_loaded_schema_artifact() -> None:
    validator = ResourceValidator(
        "schema-validator", "bounded-json", 1024, None, None, None,
        "artifact-schema", hashlib.sha256(b"schema").hexdigest(),
    )
    with pytest.raises(ResourceJobDenied, match="schema artifact validator is unavailable"):
        validator.validate_scalar({"selected": "value"})


def test_recipe_renders_only_exact_event_fields_and_backend_scope() -> None:
    digest = hashlib.sha256(b"recipe").hexdigest()
    backend = ResourceBackendEnrollment(
        "backend", "demo", "profile", "principal", hashlib.sha256(b"g").hexdigest(),
        "consent", "source", "observer", "package", "pkg-gen", "handler", digest,
        {"action"}, "resource.cron.run", "resource:demo:action:g", None, set(),
        "request", "result", "recipe", "scope", 1024, 2048, 20,
    )
    scope = ResourceScopeBinding(
        "scope", "demo", "profile", "principal", backend.generation, "profile-gen",
        "backend", {"channel": "fixed-channel"}, frozenset(), None,
    )
    validators = {
        "text": ResourceValidator("text", "utf8-string", 128, None, None, None, None, None),
        "id": ResourceValidator("id", "opaque-id", 128, None, None, None, None, None),
    }
    recipe = ResourceBodyRecipe(
        "recipe", "request", "recipe-artifact", digest,
        (ResourceBodyRecipeField("message", "observed-event-field", "message", "text"),),
        (ResourceBodyRecipeScope("channel", "scope", "channel", "id"),), 512,
    )
    rendered = recipe.render(
        backend=backend, scope_bindings={"scope": scope}, validators=validators,
        event_fields={"message": "hello"}, parent_results={},
    )
    assert rendered == b'{"channel":"fixed-channel","message":"hello"}'
    with pytest.raises(ResourceJobDenied, match="selected event field is absent"):
        recipe.render(backend=backend, scope_bindings={"scope": scope}, validators=validators,
                     event_fields={}, parent_results={})
    other_scope = ResourceScopeBinding(
        "other-scope", "demo", "profile", "principal", backend.generation, "profile-gen",
        "backend", {"channel": "attacker"}, frozenset(), None,
    )
    with pytest.raises(ResourceJobDenied, match="scope binding or validator"):
        recipe.render(backend=backend, scope_bindings={"scope": other_scope}, validators=validators,
                     event_fields={"message": "hello"}, parent_results={})
