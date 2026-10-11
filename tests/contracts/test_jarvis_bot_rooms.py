from __future__ import annotations

import hashlib

import pytest

from hermes_installer.remote.jarvis_bot_rooms import (
    BotProfileEnrollmentBinding,
    FEATURE_ROUTES,
    project_bot_roster,
)
from hermes_installer.remote.jarvis_bots_ui import FEATURE_ASSETS


def _binding(subject: str, generation: str, profile: str, *, label: str = "Study Bot"):
    return BotProfileEnrollmentBinding(
        enrollment_id="enrollment_0123456789abcdef",
        owner_subject_sha256=hashlib.sha256(subject.encode()).hexdigest(),
        core_generation=generation,
        profile_name=profile,
        display_name=label,
    )


def test_unwired_root_enrollment_is_empty_pending_not_default_profile():
    snapshot = project_bot_roster(subject="owner@example.test", core_generation="core-1",
                                  enrollments=None)

    assert snapshot["status"] == "pending"
    assert snapshot["profiles"] == []
    assert any("No root-verified owner Bot-profile enrollment map" in item
               for item in snapshot["pending_reasons"])
    assert FEATURE_ROUTES == (("GET", "/chat/api/bot-rooms"),)
    assert ("GET", "/chat/api/bot-rooms") in FEATURE_ASSETS.api_routes
    assert 'data-bots-roster' in FEATURE_ASSETS.view_html
    assert not any(route[1] == "/chat/api/bot-rooms" and route[0] != "GET"
                   for route in FEATURE_ASSETS.api_routes)


def test_roster_projects_only_current_owner_generation_without_native_identity():
    enrollments = (
        _binding("owner@example.test", "core-1", "internal-bot-01"),
        _binding("other@example.test", "core-1", "foreign-bot"),
        _binding("owner@example.test", "core-0", "old-generation-bot"),
    )
    snapshot = project_bot_roster(subject="owner@example.test", core_generation="core-1",
                                  enrollments=enrollments)

    assert snapshot["status"] == "pending"
    assert snapshot["profiles"] == [{
        "label": "Study Bot",
        "enrollment_state": "root-enrolled",
        "canonical_dm_state": "pending",
        "reason": ("Canonical Bot DM is pending its fixed profile-scoped session adapter; "
                   "no session has been opened or read by this feature."),
    }]
    rendered = repr(snapshot)
    assert "internal-bot-01" not in rendered
    assert "foreign-bot" not in rendered
    assert "old-generation-bot" not in rendered
    assert "enrollment_0123456789abcdef" not in rendered


def test_ambiguous_root_enrollment_denies_roster_instead_of_merging_profiles():
    owner = "owner@example.test"
    rows = (_binding(owner, "core-1", "same-profile"),
            BotProfileEnrollmentBinding(
                enrollment_id="enrollment_abcdefghijklmnop",
                owner_subject_sha256=hashlib.sha256(owner.encode()).hexdigest(),
                core_generation="core-1", profile_name="same-profile", display_name="Other label"))

    with pytest.raises(ValueError, match="ambiguous"):
        project_bot_roster(subject=owner, core_generation="core-1", enrollments=rows)


def test_malformed_or_unbounded_root_enrollment_is_not_partially_rendered():
    owner = "owner@example.test"
    valid = _binding(owner, "core-1", "safe")
    malformed = BotProfileEnrollmentBinding(
        enrollment_id="short", owner_subject_sha256=valid.owner_subject_sha256,
        core_generation="core-1", profile_name="unsafe", display_name="Unsafe")
    with pytest.raises(ValueError, match="invalid"):
        project_bot_roster(subject=owner, core_generation="core-1", enrollments=(valid, malformed))

    with pytest.raises(ValueError, match="bound"):
        project_bot_roster(subject=owner, core_generation="core-1",
                           enrollments=(valid,) * 33)
