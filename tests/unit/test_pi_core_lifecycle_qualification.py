"""Pure result-classification contracts for the Pi-only Core adapter runner.

These fixtures verify the runner's evidence gate only; they do not represent a
live source update, protected backup, native process, or Pi acceptance result.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


TOOL = Path(__file__).resolve().parents[2] / "tools" / "pi_core_lifecycle_qualification.py"
SPEC = importlib.util.spec_from_file_location("pi_core_lifecycle_qualification", TOOL)
assert SPEC is not None and SPEC.loader is not None
qualification = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(qualification)


def _snapshots():
    before = {
        "adapter_source": "/opt/hermes-installer-core-aaaaaaaaa/src",
        "adapter_generation": "a" * 64,
        "core_source_generation": "b" * 64,
        "plugin_selection_sha256": "c" * 64,
        "overlay_content_count": 2,
        "overlay_contents_sha256": "d" * 64,
        "obsidian_registration_state": "registered",
        "obsidian_registration_sha256": "e" * 64,
        "obsidian_vault_tree_sha256": "f" * 64,
    }
    after = {
        **before,
        "adapter_source": "/opt/hermes-installer-core-bbbbbbbbb/src",
        "adapter_generation": "9" * 64,
        "adapter_update_state": "active",
        "adapter_update_previous_source": before["adapter_source"],
        "adapter_update_backup_source_generation": before["adapter_generation"],
    }
    return before, after


def test_candidate_identity_requires_full_lowercase_commit_sha():
    assert qualification._candidate_source("a" * 40) == Path(
        "/opt/hermes-installer-core-aaaaaaaaa/src")
    for invalid in ("a" * 39, "A" * 40, "../" + "a" * 37, "a" * 40 + "b"):
        with pytest.raises(ValueError, match="full lowercase SHA"):
            qualification._candidate_source(invalid)


def test_only_current_candidate_commit_and_preserved_bindings_qualify():
    before, after = _snapshots()
    checks = qualification._success_checks(
        before, after, "/opt/hermes-installer-core-bbbbbbbbb/src",
        cohort_phase="committed", listener_current=True)
    assert checks and all(checks.values())

    changed = dict(after, plugin_selection_sha256="0" * 64)
    checks = qualification._success_checks(
        before, changed, "/opt/hermes-installer-core-bbbbbbbbb/src",
        cohort_phase="committed", listener_current=True)
    assert checks["candidate_adapter_is_active"] is True
    assert checks["selected_plugin_preserved"] is False


@pytest.mark.parametrize("mutation,phase,listener", [
    ({"adapter_source": "/opt/hermes-installer-core-ccccccccc/src"}, "committed", True),
    ({"overlay_contents_sha256": "0" * 64}, "committed", True),
    ({"obsidian_vault_tree_sha256": "0" * 64}, "committed", True),
    ({}, "bindings-verified", True),
    ({}, "committed", False),
])
def test_partial_or_mismatched_update_readback_stays_pending(mutation, phase, listener):
    before, after = _snapshots()
    after.update(mutation)
    checks = qualification._success_checks(
        before, after, "/opt/hermes-installer-core-bbbbbbbbb/src",
        cohort_phase=phase, listener_current=listener)
    assert any(value is False for value in checks.values())
