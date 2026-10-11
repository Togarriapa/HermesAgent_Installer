"""Bounded proposal parsing for the root-sealed Jarvis master turn adapter."""
import hashlib
import json

import pytest

from hermes_installer.remote.jarvis_master_planning import (
    JarvisMasterPlanningDenied,
    build_master_plan_prompt,
    build_master_review_prompt,
    issue_master_plan_decision,
    parse_master_plan_output,
    parse_master_review_output,
)


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


def test_master_review_is_bound_to_exact_result_digest():
    result = "Private internal draft"
    result_sha = hashlib.sha256(result.encode()).hexdigest()
    raw = json.dumps({"decision": "approved", "result_sha256": result_sha})
    assert parse_master_review_output(raw, expected_result_sha256=result_sha)["decision"] == "approved"
    with pytest.raises(JarvisMasterPlanningDenied):
        parse_master_review_output(raw, expected_result_sha256="0" * 64)


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
