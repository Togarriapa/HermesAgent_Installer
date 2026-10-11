from __future__ import annotations

import hashlib
import sys
import time
import types

import pytest

from hermes_installer.remote.jarvis_learning import (
    JarvisLearningUnavailable,
    build_learning_projection,
)


def candidate(diff="--- a/SKILL.md\n+++ b/SKILL.md\n+candidate\n", **overrides):
    row = {
        "opaque_id": "1" * 24,
        "revision_sha256": "2" * 64,
        "action": "create",
        "created_at": 1234.5,
        "skill_label": "jarvis-helper",
        "summary": "Add a reviewed helper",
        "diff_text": diff,
        "diff_sha256": hashlib.sha256(diff.encode()).hexdigest(),
        "truncated": False,
        "state": "pending-review",
    }
    row.update(overrides)
    return row


class Observation:
    readiness = "read-only-native-review"
    pending_reasons = ()
    candidates = (candidate(),)
    def __init__(self, valid=True):
        self.expires_monotonic = time.monotonic() + 10
        self.valid = valid
        self.verify_calls = []

    def verify_current(self, config, *, peer_pid, peer_uid, peer_gid, accepted_ingress, now=None):
        self.verify_calls.append((config, peer_pid, peer_uid, peer_gid, accepted_ingress, now))
        return self.valid


@pytest.fixture
def api_type(monkeypatch):
    module = types.ModuleType("hermes_installer.remote.core_gateway_inspector")
    module.CoreVerifiedSkillLearningObservation = Observation
    monkeypatch.setitem(sys.modules, module.__name__, module)
    return module


def project(observation):
    return build_learning_projection(
        observation, config=object(), peer_pid=44, peer_uid=996, peer_gid=981,
        accepted_ingress=object(),
    )


def test_projection_requires_and_rechecks_sealed_current_observation(api_type):
    observation = Observation()

    result = project(observation)

    assert len(observation.verify_calls) == 2
    assert result["state"] == "read-only-native-review"
    assert result["canApply"] is False and result["canRollback"] is False
    assert result["candidates"][0]["id"] == "1" * 24
    assert result["candidates"][0]["skillLabel"] == "jarvis-helper"
    assert result["candidates"][0]["diff"].startswith("--- a/SKILL.md")
    assert result["candidates"][0]["approvalRoute"].endswith("/skills pending.")
    assert "payload" not in result["candidates"][0]


def test_unsealed_observation_is_rejected_before_reading_candidate_fields(api_type):
    class Forged:
        readiness = "read-only-native-review"
        pending_reasons = ()
        candidates = (candidate(),)
        expires_monotonic = time.monotonic() + 10

    with pytest.raises(JarvisLearningUnavailable, match="current root"):
        project(Forged())


def test_stale_root_observation_is_rejected(api_type):
    observation = Observation(valid=False)
    with pytest.raises(JarvisLearningUnavailable, match="current root"):
        project(observation)
    assert len(observation.verify_calls) == 1


@pytest.mark.parametrize("bad", [
    candidate(opaque_id="../../etc"),
    candidate(diff_sha256="0" * 64),
    candidate(action="approve"),
    candidate(truncated="false"),
    candidate(extra="not-in-closed-schema"),
])
def test_malformed_or_mutation_shaped_candidate_is_rejected(api_type, bad):
    observation = Observation()
    observation.candidates = (bad,)
    with pytest.raises(JarvisLearningUnavailable):
        project(observation)


def test_expired_or_unrecognized_pending_state_is_rejected(api_type):
    observation = Observation()
    observation.expires_monotonic = 0
    with pytest.raises(JarvisLearningUnavailable, match="schema"):
        project(observation)

    observation.expires_monotonic = time.monotonic() + 10
    observation.pending_reasons = ("secret-path:/home/admin/.hermes",)
    with pytest.raises(JarvisLearningUnavailable, match="pending reasons"):
        project(observation)
