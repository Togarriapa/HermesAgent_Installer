"""Bounded proposal parsing for the root-sealed Jarvis master turn adapter."""
import hashlib
import json
import time

import pytest

from hermes_installer.remote.jarvis_master_planning import (
    JarvisMasterPlanningDenied,
    build_master_plan_prompt,
    build_master_review_prompt,
    issue_master_plan_decision,
    parse_master_plan_output,
    parse_master_review_output,
)
from hermes_installer.remote import jarvis_master_planning as planning


MISSION_ID = "0123456789abcdefghijklmn"
SOURCE_IDS = ("orchestrator", "researcher")


def test_master_plan_parser_returns_exact_catalog_selection_and_canonical_digest():
    raw = json.dumps({
        "execution_mode": "kanban",
        "selected_source_ids": ["researcher"],
        "plan": {"summary": "Compare the two options", "steps": ["inspect", "summarize"]},
    })
    parsed = parse_master_plan_output(raw, allowed_source_ids=SOURCE_IDS)
    envelope = {
        "execution_mode": "kanban",
        "selected_source_ids": ["researcher"],
        "plan": {"summary": "Compare the two options", "steps": ["inspect", "summarize"]},
    }
    canonical = json.dumps(envelope, ensure_ascii=False, sort_keys=True,
                           separators=(",", ":"), allow_nan=False).encode()
    assert parsed["selected_source_ids"] == ("researcher",)
    assert parsed["plan_sha256"] == hashlib.sha256(canonical).hexdigest()
    assert parsed["response_sha256"] == hashlib.sha256(raw.encode()).hexdigest()


def test_jarvis_only_oneshot_plan_needs_no_selected_expert():
    raw = '{"execution_mode":"oneshot","selected_source_ids":[],"plan":{"steps":[]}}'
    parsed = parse_master_plan_output(raw, allowed_source_ids=SOURCE_IDS)
    assert parsed["execution_mode"] == "oneshot"
    assert parsed["selected_source_ids"] == ()


def test_master_plan_rejects_unverified_sources_and_authority_fields():
    unverified = '{"execution_mode":"oneshot","selected_source_ids":["outside"],"plan":{}}'
    authority = ('{"execution_mode":"oneshot","selected_source_ids":["researcher"],'
                 '"plan":{"autonomy_mode":"fully_autonomous"}}')
    with pytest.raises(JarvisMasterPlanningDenied):
        parse_master_plan_output(unverified, allowed_source_ids=SOURCE_IDS)
    with pytest.raises(JarvisMasterPlanningDenied):
        parse_master_plan_output(authority, allowed_source_ids=SOURCE_IDS)


def test_master_plan_rejects_duplicate_or_extra_top_level_fields():
    duplicate = ('{"execution_mode":"oneshot","execution_mode":"kanban",'
                 '"selected_source_ids":["researcher"],"plan":{}}')
    extra = ('{"execution_mode":"oneshot","selected_source_ids":["researcher"],'
             '"plan":{},"owner_approval":true}')
    with pytest.raises(JarvisMasterPlanningDenied):
        parse_master_plan_output(duplicate, allowed_source_ids=SOURCE_IDS)
    with pytest.raises(JarvisMasterPlanningDenied):
        parse_master_plan_output(extra, allowed_source_ids=SOURCE_IDS)


def test_team_selection_is_bound_to_exact_catalog_bundle_and_two_selected_members():
    team = {
        "version": "1.2.0", "source_revision": "a" * 40,
        "bundle_generation_sha256": "b" * 64,
        "bundle_member_path": "registry/package/bundles/research.yaml",
        "bundle_member_sha256": "c" * 64,
        "source_member_path": "registry/package/installer-registry/declarations/bundles/research.yaml",
        "source_member_sha256": "d" * 64, "source_path": "bundles/research.yaml",
        "ordered_member_ids": ["researcher", "analyst", "writer"],
    }
    selection = {"schema": 1, "team_id": "research",
        "bundle_generation_sha256": team["bundle_generation_sha256"],
        "bundle_member_sha256": team["bundle_member_sha256"],
        "ordered_member_ids": team["ordered_member_ids"],
        "selected_expert_ids": ["researcher", "analyst"]}
    raw = json.dumps({"execution_mode": "kanban",
        "selected_source_ids": ["researcher", "analyst"],
        "plan": {"team_selection": selection}})
    assert parse_master_plan_output(raw, allowed_source_ids=SOURCE_IDS + ("analyst",),
        verified_teams={"research": team})["plan"]["team_selection"] == selection

    stale = dict(selection, bundle_member_sha256="e" * 64)
    stale_raw = json.dumps({"execution_mode": "kanban",
        "selected_source_ids": ["researcher", "analyst"],
        "plan": {"team_selection": stale}})
    with pytest.raises(JarvisMasterPlanningDenied):
        parse_master_plan_output(stale_raw, allowed_source_ids=SOURCE_IDS + ("analyst",),
            verified_teams={"research": team})

    independent = json.dumps({"execution_mode": "kanban",
        "selected_source_ids": ["researcher", "analyst"],
        "plan": {"team_selection": selection}})
    with pytest.raises(JarvisMasterPlanningDenied):
        parse_master_plan_output(independent, allowed_source_ids=SOURCE_IDS + ("analyst",),
            verified_teams={"research": dict(team, ordered_member_ids=["researcher", "analyst"])})


def test_master_review_is_bound_to_exact_result_digest():
    result = "Private internal draft"
    result_sha = hashlib.sha256(result.encode()).hexdigest()
    raw = json.dumps({"decision": "approved", "result_sha256": result_sha,
                      "rationale": "The draft answers the requested question."})
    parsed = parse_master_review_output(raw, expected_result_sha256=result_sha)
    assert parsed["decision"] == "approved"
    assert parsed["rationale"] == "The draft answers the requested question."
    with pytest.raises(JarvisMasterPlanningDenied):
        parse_master_review_output(raw, expected_result_sha256="0" * 64)


@pytest.mark.parametrize("rationale", ["", "   ", "x" * 513])
def test_master_review_requires_a_bounded_nonempty_reason(rationale):
    result_sha = hashlib.sha256(b"draft").hexdigest()
    raw = json.dumps({"decision": "rejected", "result_sha256": result_sha,
                      "rationale": rationale})
    with pytest.raises(JarvisMasterPlanningDenied):
        parse_master_review_output(raw, expected_result_sha256=result_sha)


def test_review_decision_uses_only_a_current_root_review_completion_and_keeps_lineage(monkeypatch):
    from hermes_installer.remote.core_native_observer import (
        CoreVerifiedJarvisMasterReviewCompletion, _MASTER_REVIEW_COMPLETION_SEAL,
    )

    result_sha = hashlib.sha256(b"persisted exact result").hexdigest()
    raw = json.dumps({"decision": "approved", "result_sha256": result_sha,
                      "rationale": "The completed draft is accurate and relevant."})
    now = time.monotonic()

    class ObserverReceiptClient:
        def verify_master_review_completion(self, receipt, *, config=None, custody=None):
            return receipt.completion_handle == "opaque-root-review-handle"

    completion = CoreVerifiedJarvisMasterReviewCompletion(
        owner_subject_sha256="a" * 64, owner_turn_handle="b" * 32,
        gateway_turn_id="c" * 24, core_generation="d" * 64,
        core_source_generation="e" * 64, prompt_sha256="f" * 64,
        response_sha256=hashlib.sha256(raw.encode()).hexdigest(),
        mission_id=MISSION_ID, revision=3, run_id="run_review_03",
        result_sha256=result_sha, execution_core_generation="1" * 64,
        execution_core_source_generation="2" * 64, response_text=raw,
        completion_handle="opaque-root-review-handle", expires_monotonic=now + 20,
        owner_turn_expires_monotonic=now + 300, _client=ObserverReceiptClient(),
        _seal=_MASTER_REVIEW_COMPLETION_SEAL,
    )
    decision = planning.issue_master_review_decision(
        completion=completion, config=object(), custody=object(), raw_output=raw)
    assert decision.decision == "approved"
    assert decision.rationale == "The completed draft is accurate and relevant."
    assert decision.result_sha256 == result_sha
    assert decision.execution_core_generation == "1" * 64
    assert decision.core_generation == "d" * 64
    assert decision.is_current_sealed(object(), custody=object())
    with pytest.raises(JarvisMasterPlanningDenied):
        planning.issue_master_review_decision(
            completion=completion, config=object(), custody=object(),
            raw_output=json.dumps({"decision": "approved", "result_sha256": "0" * 64,
                                   "rationale": "Wrong result."}))


def test_server_prompt_builders_bind_mission_and_exact_result():
    prompt, prompt_sha = build_master_plan_prompt(
        mission_id=MISSION_ID, revision=2, title="Research",
        goal="Compare options", allowed_source_ids=SOURCE_IDS)
    assert MISSION_ID in prompt and "revision=2" in prompt
    assert prompt_sha == hashlib.sha256(prompt.encode()).hexdigest()

    review, review_sha, result_sha = build_master_review_prompt(
        mission_id=MISSION_ID, revision=2, run_id="run_123", result_text="draft bytes")
    assert "draft bytes" in review and result_sha == hashlib.sha256(b"draft bytes").hexdigest()
    assert review_sha == hashlib.sha256(review.encode()).hexdigest()


def test_decision_mint_fails_closed_without_bridge_completion_type():
    with pytest.raises(JarvisMasterPlanningDenied):
        issue_master_plan_decision(
            completion=object(), config=object(), custody=object(), raw_output="{}",
            mission_id=MISSION_ID, revision=1, title="Research", goal="Compare options",
            allowed_source_ids=SOURCE_IDS)


@pytest.mark.parametrize("selected", [[], ["researcher"]])
def test_typed_plan_decision_seals_zero_or_catalog_selected_sources(monkeypatch, selected):
    from dataclasses import replace
    raw = json.dumps({"execution_mode": "oneshot", "selected_source_ids": selected,
                      "plan": {"steps": []}})
    _prompt, prompt_digest = build_master_plan_prompt(
        mission_id=MISSION_ID, revision=1, title="Research", goal="Compare options",
        allowed_source_ids=SOURCE_IDS)

    fixture_state = {"current": True}

    class RootCompletionFixture:
        owner_subject_sha256 = "a" * 64
        owner_turn_handle = "b" * 32
        gateway_turn_id = "c" * 24
        core_generation = "d" * 64
        core_source_generation = "e" * 64
        prompt_sha256 = prompt_digest
        response_sha256 = hashlib.sha256(raw.encode()).hexdigest()
        expires_monotonic = time.monotonic() + 60
        owner_turn_expires_monotonic = time.monotonic() + 600

        def is_current_sealed(self, _config, *, custody, now=None):
            return (fixture_state["current"] and custody is fixture_custody
                    and (time.monotonic() if now is None else now) < self.expires_monotonic)

    fixture_custody = object()
    completion = RootCompletionFixture()
    monkeypatch.setattr(planning, "_completion_type", lambda: RootCompletionFixture)
    decision = issue_master_plan_decision(
        completion=completion, config=object(), custody=fixture_custody,
        raw_output=raw, mission_id=MISSION_ID, revision=1, title="Research",
        goal="Compare options", allowed_source_ids=SOURCE_IDS)
    assert decision.selected_source_ids == tuple(selected)
    assert decision.is_current_sealed(object(), custody=fixture_custody)
    assert not replace(decision, plan={"steps": ["changed"]}).is_current_sealed(
        object(), custody=fixture_custody)
    fixture_state["current"] = False
    assert not decision.is_current_sealed(object(), custody=fixture_custody)
    with pytest.raises(JarvisMasterPlanningDenied, match="current root planning completion"):
        issue_master_plan_decision(
            completion=completion, config=object(), custody=fixture_custody,
            raw_output=raw, mission_id=MISSION_ID, revision=1, title="Research",
            goal="Compare options", allowed_source_ids=SOURCE_IDS)
