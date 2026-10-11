"""Typed results from root-observed, no-effect Jarvis master turns.

This module parses bounded model output, but parsing never grants authority. Decisions
can only be sealed from the root inspector's exact current no-effect completion receipt;
ordinary chat/UI payloads cannot construct a current decision.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
import time
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

_HASH = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_ID = re.compile(r"[a-z0-9][a-z0-9_-]{0,95}\Z", re.ASCII)
_MISSION_ID = re.compile(r"[A-Za-z0-9_-]{24,64}\Z", re.ASCII)
_DECISION_SEAL = object()
_MAX_OUTPUT_BYTES = 32 * 1024
_MAX_PLAN_BYTES = 16 * 1024
_MAX_NODES = 2048
_MAX_DEPTH = 12


class JarvisMasterPlanningDenied(PermissionError):
    """A bounded master planning/review decision is unavailable."""


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
                      allow_nan=False).encode("utf-8", errors="strict")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def goal_sha256(goal: str) -> str:
    """Digest the exact normalized owner brief used by mission custody."""
    if not isinstance(goal, str) or not goal or len(goal) > 8000:
        raise JarvisMasterPlanningDenied("master planning goal is invalid")
    return _sha256(_canonical({"goal": goal}))


def build_master_plan_prompt(*, mission_id: str, revision: int, title: str,
                             goal: str, allowed_source_ids: Iterable[str]) -> tuple[str, str]:
    """Build the exact server-owned planning prompt and its digest."""
    ids = tuple(sorted(set(allowed_source_ids)))
    if (_MISSION_ID.fullmatch(mission_id or "") is None or type(revision) is not int
            or revision < 1 or not isinstance(title, str) or not title or len(title) > 120
            or not isinstance(goal, str) or not goal or len(goal) > 8000
            or not 1 <= len(ids) <= 512
            or any(not isinstance(item, str) or _ID.fullmatch(item) is None for item in ids)):
        raise JarvisMasterPlanningDenied("master planning context is invalid")
    prompt = (
        "You are Jarvis, the sole master planner. Choose execution_mode as oneshot or kanban, "
        "and select zero or more source IDs only from the verified catalog below. Select no "
        "experts when Jarvis can complete the task directly. Experts are "
        "internal collaborators; their output remains a draft for Jarvis review. Do not grant "
        "autonomy, permissions, external effects, or owner approval. Return one JSON object with "
        "exactly execution_mode, selected_source_ids, and plan fields.\n"
        f"mission_id={mission_id}\nrevision={revision}\ntitle={title}\ngoal={goal}\n"
        f"verified_source_ids={json.dumps(ids, separators=(',', ':'))}"
    )
    if len(prompt.encode("utf-8")) > _MAX_OUTPUT_BYTES:
        raise JarvisMasterPlanningDenied("master planning prompt exceeds its bound")
    return prompt, _sha256(prompt.encode("utf-8"))


def build_master_review_prompt(*, mission_id: str, revision: int, run_id: str,
                               result_text: str) -> tuple[str, str, str]:
    """Build a review prompt over the exact completed internal draft bytes."""
    if (_MISSION_ID.fullmatch(mission_id or "") is None or type(revision) is not int
            or revision < 1 or not isinstance(run_id, str)
            or re.fullmatch(r"[A-Za-z0-9_-]{1,64}", run_id) is None
            or not isinstance(result_text, str) or not result_text
            or len(result_text.encode("utf-8", errors="strict")) > _MAX_OUTPUT_BYTES):
        raise JarvisMasterPlanningDenied("master review context is invalid")
    result_digest = _sha256(result_text.encode("utf-8", errors="strict"))
    prompt = (
        "You are Jarvis, reviewing one completed internal expert draft. Decide approved or "
        "rejected for internal mission progression only. This review is not owner approval and "
        "does not authorize external effects. Return one JSON object with exactly decision and "
        "result_sha256.\n"
        f"mission_id={mission_id}\nrevision={revision}\nrun_id={run_id}\n"
        f"result_sha256={result_digest}\ncompleted_draft:\n{result_text}"
    )
    if len(prompt.encode("utf-8")) > _MAX_OUTPUT_BYTES:
        raise JarvisMasterPlanningDenied("master review prompt exceeds its bound")
    return prompt, _sha256(prompt.encode("utf-8")), result_digest


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value


def _reject_constant(_value: str) -> Any:
    raise ValueError("non-finite JSON value")


def _validate_tree(value: Any, *, depth: int = 0, counter: list[int] | None = None) -> None:
    if counter is None:
        counter = [0]
    counter[0] += 1
    if counter[0] > _MAX_NODES or depth > _MAX_DEPTH:
        raise ValueError("master output exceeds structural bounds")
    if value is None or type(value) in (bool, int):
        return
    if type(value) is float:
        if not math.isfinite(value):
            raise ValueError("master output contains a non-finite number")
        return
    if isinstance(value, str):
        if len(value) > 4000 or any(ord(ch) < 0x20 and ch not in "\n\t" for ch in value):
            raise ValueError("master output contains invalid text")
        return
    if isinstance(value, list):
        if len(value) > 256:
            raise ValueError("master output list exceeds its bound")
        for child in value:
            _validate_tree(child, depth=depth + 1, counter=counter)
        return
    if isinstance(value, dict):
        if len(value) > 128 or any(not isinstance(k, str) or len(k) > 96 for k in value):
            raise ValueError("master output object exceeds its bound")
        forbidden = {"autonomy", "autonomy_mode", "authorization", "authorization_sha256",
                     "grant", "grants", "permission", "permissions", "approval",
                     "approved_by_owner", "final_effect_authority"}
        if any(key.casefold() in forbidden for key in value):
            raise ValueError("master output contains an authority field")
        for child in value.values():
            _validate_tree(child, depth=depth + 1, counter=counter)
        return
    raise ValueError("master output contains an unsupported value")


def _parse_json(raw: str) -> dict[str, Any]:
    if not isinstance(raw, str):
        raise JarvisMasterPlanningDenied("master output is unavailable")
    try:
        encoded = raw.encode("utf-8", errors="strict")
        if not encoded or len(encoded) > _MAX_OUTPUT_BYTES:
            raise ValueError
        value = json.loads(raw, object_pairs_hook=_unique_pairs, parse_constant=_reject_constant)
        if type(value) is not dict:
            raise ValueError
        _validate_tree(value)
        return value
    except (UnicodeError, ValueError, TypeError, RecursionError):
        raise JarvisMasterPlanningDenied("master output is invalid or exceeds its bound") from None


def parse_master_plan_output(raw: str, *, allowed_source_ids: Iterable[str]) -> dict[str, Any]:
    """Parse a model proposal; source IDs must already come from a verified offline catalog."""
    value = _parse_json(raw)
    if set(value) != {"execution_mode", "selected_source_ids", "plan"}:
        raise JarvisMasterPlanningDenied("master plan fields are invalid")
    mode, selected, plan = value["execution_mode"], value["selected_source_ids"], value["plan"]
    allowed = frozenset(allowed_source_ids)
    if (not allowed or any(not isinstance(item, str) or _ID.fullmatch(item) is None for item in allowed)
            or mode not in {"oneshot", "kanban"}
            or type(selected) is not list or len(selected) > 16
            or any(not isinstance(item, str) or _ID.fullmatch(item) is None for item in selected)
            or len(set(selected)) != len(selected) or any(item not in allowed for item in selected)
            or type(plan) is not dict):
        raise JarvisMasterPlanningDenied("master plan selection is invalid")
    try:
        encoded_plan = _canonical(plan)
        encoded_result = _canonical(value)
    except (TypeError, ValueError, UnicodeError):
        raise JarvisMasterPlanningDenied("master plan is not canonical") from None
    if len(encoded_plan) > _MAX_PLAN_BYTES or len(encoded_result) > _MAX_OUTPUT_BYTES:
        raise JarvisMasterPlanningDenied("master plan exceeds its bound")
    return {
        "execution_mode": mode,
        "selected_source_ids": tuple(selected),
        "plan": json.loads(encoded_plan.decode("utf-8")),
        "plan_sha256": _sha256(encoded_result),
        "response_sha256": _sha256(raw.encode("utf-8", errors="strict")),
    }


def parse_master_review_output(raw: str, *, expected_result_sha256: str) -> dict[str, Any]:
    """Parse Jarvis's review of one exact, already-completed internal result."""
    value = _parse_json(raw)
    if (set(value) != {"decision", "result_sha256"}
            or value.get("decision") not in {"approved", "rejected"}
            or not isinstance(value.get("result_sha256"), str)
            or _HASH.fullmatch(expected_result_sha256 or "") is None
            or value["result_sha256"] != expected_result_sha256):
        raise JarvisMasterPlanningDenied("master review result is invalid")
    return {"decision": value["decision"], "result_sha256": expected_result_sha256,
            "response_sha256": _sha256(raw.encode("utf-8", errors="strict"))}


def _completion_type() -> type:
    """Resolve the bridge-owned exact receipt lazily; absent support stays unavailable."""
    try:
        from .core_native_observer import CoreVerifiedJarvisMasterPlanningCompletion
        return CoreVerifiedJarvisMasterPlanningCompletion
    except (ImportError, AttributeError):
        raise JarvisMasterPlanningDenied("root no-effect completion proof is unavailable") from None


def _verify_completion(completion: Any, *, config: Any, custody: Any, now: float) -> bool:
    expected_type = _completion_type()
    if type(completion) is not expected_type:
        return False
    verifier = getattr(completion, "is_current_sealed", None)
    if not callable(verifier):
        return False
    try:
        return verifier(config, custody=custody, now=now) is True
    except Exception:
        return False


def _original_owner_deadline(completion: Any) -> float:
    """Read the inspector-bound original owner deadline; never derive a fresh lease."""
    deadline = getattr(completion, "owner_turn_expires_monotonic", None)
    if (isinstance(deadline, bool) or not isinstance(deadline, (int, float))
            or not math.isfinite(deadline)):
        raise JarvisMasterPlanningDenied("original owner-turn deadline is unavailable")
    return float(deadline)


@dataclass(frozen=True, slots=True)
class CoreVerifiedJarvisMasterPlanDecision:
    schema: int
    owner_subject_sha256: str
    mission_id: str
    revision: int
    gateway_turn_id: str
    owner_turn_handle: str
    core_generation: str
    core_source_generation: str
    goal_sha256: str
    execution_mode: str
    selected_source_ids: tuple[str, ...]
    plan: Mapping[str, Any]
    plan_sha256: str
    response_sha256: str
    expires_monotonic: float
    _completion: Any = field(repr=False, compare=False)
    _seal: object = field(repr=False, compare=False)

    def is_current_sealed(self, config: Any, *, custody: Any, now: float | None = None) -> bool:
        current = time.monotonic() if now is None else now
        try:
            return bool(self._seal is _DECISION_SEAL and self.schema == 1
                        and type(self.revision) is int and self.revision >= 1
                        and _HASH.fullmatch(self.owner_subject_sha256 or "")
                        and _MISSION_ID.fullmatch(self.mission_id or "")
                        and _HASH.fullmatch(self.core_generation or "")
                        and _HASH.fullmatch(self.core_source_generation or "")
                        and _HASH.fullmatch(self.goal_sha256 or "")
                        and self.execution_mode in {"oneshot", "kanban"}
                        and type(self.selected_source_ids) is tuple
                        and 0 <= len(self.selected_source_ids) <= 16
                        and len(set(self.selected_source_ids)) == len(self.selected_source_ids)
                        and all(_ID.fullmatch(item or "") for item in self.selected_source_ids)
                        and _HASH.fullmatch(self.plan_sha256 or "")
                        and _HASH.fullmatch(self.response_sha256 or "")
                        and isinstance(self.plan, Mapping)
                        and _sha256(_canonical({"execution_mode": self.execution_mode,
                                               "selected_source_ids": list(self.selected_source_ids),
                                               "plan": dict(self.plan)})) == self.plan_sha256
                        and math.isfinite(self.expires_monotonic)
                        and current < self.expires_monotonic
                        and self.expires_monotonic <= _original_owner_deadline(self._completion)
                        and self._completion.response_sha256 == self.response_sha256
                        and self._completion.owner_subject_sha256 == self.owner_subject_sha256
                        and self._completion.owner_turn_handle == self.owner_turn_handle
                        and self._completion.gateway_turn_id == self.gateway_turn_id
                        and self._completion.core_generation == self.core_generation
                        and self._completion.core_source_generation == self.core_source_generation
                        and _verify_completion(self._completion, config=config, custody=custody, now=current))
        except Exception:
            return False

    def matches(self, *, owner_subject_sha256: str, mission_id: str, revision: int,
                gateway_turn_id: str, owner_turn_handle: str, goal_sha256: str,
                core_generation: str, core_source_generation: str) -> bool:
        return bool(self.owner_subject_sha256 == owner_subject_sha256
                    and self.mission_id == mission_id and self.revision == revision
                    and self.gateway_turn_id == gateway_turn_id
                    and self.owner_turn_handle == owner_turn_handle
                    and self.goal_sha256 == goal_sha256 and self.core_generation == core_generation
                    and self.core_source_generation == core_source_generation)


@dataclass(frozen=True, slots=True)
class CoreVerifiedJarvisMasterReviewDecision:
    schema: int
    owner_subject_sha256: str
    mission_id: str
    revision: int
    gateway_turn_id: str
    owner_turn_handle: str
    core_generation: str
    core_source_generation: str
    run_id: str
    result_sha256: str
    decision: str
    response_sha256: str
    expires_monotonic: float
    _completion: Any = field(repr=False, compare=False)
    _seal: object = field(repr=False, compare=False)

    def is_current_sealed(self, config: Any, *, custody: Any, now: float | None = None) -> bool:
        current = time.monotonic() if now is None else now
        try:
            return bool(self._seal is _DECISION_SEAL and self.schema == 1
                        and _HASH.fullmatch(self.owner_subject_sha256 or "")
                        and _MISSION_ID.fullmatch(self.mission_id or "")
                        and type(self.revision) is int and self.revision >= 1
                        and _HASH.fullmatch(self.core_generation or "")
                        and _HASH.fullmatch(self.core_source_generation or "")
                        and isinstance(self.run_id, str) and 1 <= len(self.run_id) <= 64
                        and re.fullmatch(r"[A-Za-z0-9_-]+", self.run_id)
                        and _HASH.fullmatch(self.result_sha256 or "")
                        and self.decision in {"approved", "rejected"}
                        and _HASH.fullmatch(self.response_sha256 or "")
                        and math.isfinite(self.expires_monotonic)
                        and current < self.expires_monotonic
                        and self.expires_monotonic <= _original_owner_deadline(self._completion)
                        and self._completion.response_sha256 == self.response_sha256
                        and self._completion.owner_subject_sha256 == self.owner_subject_sha256
                        and self._completion.owner_turn_handle == self.owner_turn_handle
                        and self._completion.gateway_turn_id == self.gateway_turn_id
                        and self._completion.core_generation == self.core_generation
                        and self._completion.core_source_generation == self.core_source_generation
                        and _verify_completion(self._completion, config=config, custody=custody, now=current))
        except Exception:
            return False

    def matches(self, *, owner_subject_sha256: str, mission_id: str, revision: int,
                gateway_turn_id: str, owner_turn_handle: str, run_id: str,
                result_sha256: str, core_generation: str,
                core_source_generation: str) -> bool:
        return bool(self.owner_subject_sha256 == owner_subject_sha256
                    and self.mission_id == mission_id and self.revision == revision
                    and self.gateway_turn_id == gateway_turn_id
                    and self.owner_turn_handle == owner_turn_handle
                    and self.run_id == run_id and self.result_sha256 == result_sha256
                    and self.core_generation == core_generation
                    and self.core_source_generation == core_source_generation)


def issue_master_plan_decision(*, completion: Any, config: Any, custody: Any,
                               raw_output: str, mission_id: str, revision: int,
                               title: str, goal: str,
                               allowed_source_ids: Iterable[str],
                               now: float | None = None) -> CoreVerifiedJarvisMasterPlanDecision:
    """Root-side only mint: exact no-effect completion receipt + byte-matched model output."""
    current = time.monotonic() if now is None else now
    allowed_source_ids = tuple(allowed_source_ids)
    _prompt, exact_prompt_sha = build_master_plan_prompt(
        mission_id=mission_id, revision=revision, title=title, goal=goal,
        allowed_source_ids=allowed_source_ids)
    goal_sha256_value = goal_sha256(goal)
    if (not _verify_completion(completion, config=config, custody=custody, now=current)
            or completion.prompt_sha256 != exact_prompt_sha
            or _MISSION_ID.fullmatch(mission_id or "") is None
            or type(revision) is not int or revision < 1
            or _HASH.fullmatch(goal_sha256_value or "") is None):
        raise JarvisMasterPlanningDenied("current root planning completion is unavailable")
    parsed = parse_master_plan_output(raw_output, allowed_source_ids=allowed_source_ids)
    if _sha256(raw_output.encode("utf-8", errors="strict")) != completion.response_sha256:
        raise JarvisMasterPlanningDenied("planning output does not match the root completion")
    expiry = _original_owner_deadline(completion)
    if current >= expiry:
        raise JarvisMasterPlanningDenied("original owner turn has expired")
    return CoreVerifiedJarvisMasterPlanDecision(
        schema=1, owner_subject_sha256=completion.owner_subject_sha256,
        mission_id=mission_id, revision=revision, gateway_turn_id=completion.gateway_turn_id,
        owner_turn_handle=completion.owner_turn_handle, core_generation=completion.core_generation,
        core_source_generation=completion.core_source_generation, goal_sha256=goal_sha256_value,
        execution_mode=parsed["execution_mode"], selected_source_ids=parsed["selected_source_ids"],
        plan=parsed["plan"], plan_sha256=parsed["plan_sha256"],
        response_sha256=parsed["response_sha256"], expires_monotonic=expiry,
        _completion=completion, _seal=_DECISION_SEAL)


def issue_master_review_decision(*, completion: Any, config: Any, custody: Any,
                                 raw_output: str, mission_id: str, revision: int,
                                 run_id: str, result_text: str,
                                 now: float | None = None) -> CoreVerifiedJarvisMasterReviewDecision:
    """Root-side only mint for Jarvis review of one exact successful internal result."""
    current = time.monotonic() if now is None else now
    _prompt, exact_prompt_sha, result_sha256 = build_master_review_prompt(
        mission_id=mission_id, revision=revision, run_id=run_id, result_text=result_text)
    if (not _verify_completion(completion, config=config, custody=custody, now=current)
            or completion.prompt_sha256 != exact_prompt_sha
            or _MISSION_ID.fullmatch(mission_id or "") is None
            or type(revision) is not int or revision < 1
            or not isinstance(run_id, str) or re.fullmatch(r"[A-Za-z0-9_-]{1,64}", run_id) is None):
        raise JarvisMasterPlanningDenied("current root review completion is unavailable")
    parsed = parse_master_review_output(raw_output, expected_result_sha256=result_sha256)
    if _sha256(raw_output.encode("utf-8", errors="strict")) != completion.response_sha256:
        raise JarvisMasterPlanningDenied("review output does not match the root completion")
    expiry = _original_owner_deadline(completion)
    if current >= expiry:
        raise JarvisMasterPlanningDenied("original owner turn has expired")
    return CoreVerifiedJarvisMasterReviewDecision(
        schema=1, owner_subject_sha256=completion.owner_subject_sha256,
        mission_id=mission_id, revision=revision, gateway_turn_id=completion.gateway_turn_id,
        owner_turn_handle=completion.owner_turn_handle, core_generation=completion.core_generation,
        core_source_generation=completion.core_source_generation, run_id=run_id,
        result_sha256=result_sha256, decision=parsed["decision"],
        response_sha256=parsed["response_sha256"],
        expires_monotonic=expiry,
        _completion=completion, _seal=_DECISION_SEAL)
