from __future__ import annotations

from dataclasses import replace

import pytest

from hermes_installer.components.ponytail import (
    PonyTailAdapterError,
    inspect_host_hooks,
    review_repository,
)
from tests.fixtures.component_source import verified_component_source


def _source():
    return verified_component_source("ponytail", {
        "LICENSE": b"MIT fixture\n",
        "skills/ponytail-review/SKILL.md": (
            b"---\nname: ponytail-review\ndescription: Review a code change.\n---\n"
            b"Read the changed code, check correctness and security, and give each finding a fix and impact.\n"
        ),
        ".openclaw/skills/ponytail-review/SKILL.md": (
            b"---\nname: ponytail-review\ndescription: Host mirror, not canonical.\n---\n"
            b"Mirror instructions should not shadow the portable skill.\n"
        ),
        "plugin.json": b'{"name":"ponytail"}\n',
    })


def test_review_uses_pinned_skill_and_registry_coordinator_for_structured_finding() -> None:
    calls = []

    def coordinator(request):
        calls.append(request)
        return {
            "summary": "The fixture exposes a missing input check.",
            "findings": [{
                "path": "src/parse.py", "severity": "high",
                "problem": "Empty input reaches the parser and raises unexpectedly.",
                "fix": "Return a validation error before parsing.",
                "impact": "The request fails instead of producing the documented response.",
            }],
        }

    result = review_repository(
        _source(), {"src/parse.py": "def parse(value):\n    return value[0]\n"},
        registry_coordinator=coordinator,
    )

    assert result.coordinator == "registry"
    assert result.live_provider_status == "pending_configured_provider_and_target_verification"
    assert len(calls) == 1
    assert calls[0].component_id == "ponytail"
    assert calls[0].skill_name == "ponytail-review"
    assert "check correctness and security" in calls[0].instructions
    assert "Mirror instructions" not in calls[0].instructions
    assert calls[0].repository_files == (("src/parse.py", "def parse(value):\n    return value[0]\n"),)
    assert result.findings[0].path == "src/parse.py"
    assert result.findings[0].severity == "high"


def test_review_rejects_unpinned_source_unsafe_snapshot_and_out_of_scope_finding() -> None:
    coordinator = lambda _request: {"summary": "ok", "findings": []}
    with pytest.raises(PonyTailAdapterError, match="reviewed pin"):
        review_repository(replace(_source(), revision="0" * 40), {"a.py": "x"},
                          registry_coordinator=coordinator)
    with pytest.raises(PonyTailAdapterError, match="unsafe path"):
        review_repository(_source(), {"../secret.py": "x"}, registry_coordinator=coordinator)
    with pytest.raises(PonyTailAdapterError, match="outside the repository snapshot"):
        review_repository(
            _source(), {"src/parse.py": "pass"},
            registry_coordinator=lambda _request: {
                "summary": "invalid", "findings": [{
                    "path": "../secret.py", "severity": "high", "problem": "x", "fix": "y", "impact": "z",
                }],
            },
        )


def test_host_hook_inspection_is_inert_and_does_not_install_candidate() -> None:
    files = {
        "plugin.json": b'{"name":"ponytail"}',
        "hooks/activate.js": b"require('child_process').spawn('touch', ['marker']);",
    }
    source = verified_component_source("ponytail", {"LICENSE": b"MIT\n", **files})
    review = inspect_host_hooks(source)
    assert review.candidates
    assert review.may_install is False
    assert any("subprocess" in hook.effects for hook in review.candidates)
