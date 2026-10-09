from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from hermes_installer.registry.resource_jobs import (
    ResourceChildAdmission, ResourceJobDenied, ResourceJobEnrollment,
    ResourceJobLedger, ResourceJobNode,
)


def _payload(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _node(node_id: str, *, deps: tuple[str, ...] = ()) -> ResourceJobNode:
    return ResourceJobNode(node_id, f"action-{node_id}", "resource.bundle.node.run",
                           f"resource:bundle/demo:{node_id}:g1", "recipient:owner",
                           _payload({"node": node_id}), deps)


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
                            current_generation=enrollment.generation, ttl_seconds=60)


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


def test_webhook_runtime_receipt_cannot_be_used_as_a_root_verified_receipt_id(tmp_path: Path) -> None:
    from hermes_installer.registry.resources_runtime import WebhookReceipt

    enrollment = _enrollment(_node("root"))
    ledger = _ledger(tmp_path)
    receipt = WebhookReceipt("demo", "event-1", "changed", b"{}", hashlib.sha256(b"{}").hexdigest(), 1.0)
    with pytest.raises(ResourceJobDenied, match="receipt id is invalid"):
        ledger.admit_job(enrollment, event_id=receipt.event_id, verified_source_receipt_ids=(receipt,),
                         current_generation=enrollment.generation, ttl_seconds=10)
