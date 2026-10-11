"""Finite tool-surface adapter for root-authorized native child runs.

This module does not select a profile or issue authority. Callers must first
obtain a current root child authorization and source-selection receipt. The
adapter then constructs an official Hermes child and applies one of two fixed
post-construction tool closures before the official child lifecycle can run.
"""
from __future__ import annotations

import hashlib
import time
from enum import Enum
from typing import Any


class NativeChildMode(str, Enum):
    PLANNER = "planner"
    EXPERT_READ_RESEARCH = "expert-read-research"


_CLOSURES = {
    NativeChildMode.PLANNER: frozenset(),
    NativeChildMode.EXPERT_READ_RESEARCH: frozenset({
        "web_search", "web_extract", "todo_list", "skills_list", "skill_view",
    }),
}
_TOOLSETS = {
    NativeChildMode.PLANNER: (),
    NativeChildMode.EXPERT_READ_RESEARCH: ("web", "todo", "skills"),
}


class NativeChildDenied(PermissionError):
    """A child cannot be built or run with a stale or broader authority."""


def _mode(value: object) -> NativeChildMode:
    if type(value) is not NativeChildMode:
        raise NativeChildDenied("a fixed native child mode is required")
    return value


def apply_native_child_tool_closure(child: Any, mode: NativeChildMode) -> frozenset[str]:
    """Remove every tool outside the fixed mode from both schemas and executor gate.

    Hermes' builder may append inherited MCP tools and may re-add delegation
    for an orchestrator-role child. Applying this closure after construction
    makes both provider-visible schemas and ``valid_tool_names`` agree.
    """
    mode = _mode(mode)
    tools = getattr(child, "tools", None)
    valid_names = getattr(child, "valid_tool_names", None)
    if not isinstance(tools, list) or not isinstance(valid_names, (set, frozenset)):
        raise NativeChildDenied("constructed native child tool inventory is unavailable")
    parsed: list[tuple[str, dict[str, Any]]] = []
    for definition in tools:
        if not isinstance(definition, dict):
            raise NativeChildDenied("constructed native child tool schema is malformed")
        function = definition.get("function")
        name = function.get("name") if isinstance(function, dict) else None
        if not isinstance(name, str) or not name:
            raise NativeChildDenied("constructed native child tool name is malformed")
        parsed.append((name, definition))
    actual_names = {name for name, _ in parsed}
    if actual_names != set(valid_names) or len(actual_names) != len(parsed):
        raise NativeChildDenied("constructed tool schema and executor inventory differ")
    allowed = _CLOSURES[mode]
    retained = [(name, definition) for name, definition in parsed if name in allowed]
    retained_names = frozenset(name for name, _ in retained)
    child.tools = [definition for _, definition in retained]
    child.valid_tool_names = set(retained_names)
    # Prevent a later native MCP/toolset refresh from widening the selected
    # closure. The child starts from already-loaded schemas and no longer opts
    # into inherited or dynamically refreshed toolsets.
    child.enabled_toolsets = list(_TOOLSETS[mode])
    disabled = getattr(child, "disabled_toolsets", ())
    if not isinstance(disabled, (list, tuple, set, frozenset)):
        raise NativeChildDenied("constructed native child disabled-toolset state is malformed")
    child.disabled_toolsets = sorted(set(disabled) | {"delegation", "kanban"})
    child._jarvis_native_child_mode = mode.value
    child._jarvis_native_child_tool_names = retained_names
    return retained_names


def _route_value(agent: Any, name: str) -> Any:
    value = getattr(agent, name, None)
    if name == "api_key" and not value:
        client_kwargs = getattr(agent, "_client_kwargs", None)
        if isinstance(client_kwargs, dict):
            value = client_kwargs.get("api_key")
    return value


def build_native_child(*, parent_agent: Any, mode: NativeChildMode, source: Any,
                       goal: str, context: str, task_index: int = 0,
                       max_iterations: int = 8) -> Any:
    """Build an official child on the parent's exact route, then close its tools.

    The caller must independently validate root owner-turn and selected-source
    receipts and register the resulting child session with the root observer
    before calling ``run_native_child``. No credentials are returned or logged.
    """
    mode = _mode(mode)
    if (not isinstance(goal, str) or not goal or len(goal) > 1200
            or not isinstance(context, str) or len(context.encode("utf-8", "strict")) > 128 * 1024
            or type(task_index) is not int or not 0 <= task_index <= 31
            or type(max_iterations) is not int or not 1 <= max_iterations <= 32):
        raise NativeChildDenied("bounded child request is required")
    provider = _route_value(parent_agent, "provider")
    base_url = _route_value(parent_agent, "base_url")
    api_mode = _route_value(parent_agent, "api_mode")
    model = _route_value(parent_agent, "model")
    api_key = _route_value(parent_agent, "api_key")
    if (provider != "openai-codex" or api_mode != "codex_responses"
            or base_url != "https://chatgpt.com/backend-api/codex"
            or not isinstance(model, str) or not model or not isinstance(api_key, str) or not api_key):
        raise NativeChildDenied("parent is not on the enrolled Codex subscription route")
    try:
        prompt_bytes = getattr(source, "effective_prompt")
        source_id = getattr(source, "profile_id")
        if (not isinstance(prompt_bytes, bytes) or not prompt_bytes
                or len(prompt_bytes) > 128 * 1024
                or hashlib.sha256(prompt_bytes).hexdigest()
                    != getattr(source, "effective_prompt_sha256")
                or (mode is NativeChildMode.PLANNER and source_id != "hermes")
                or (mode is NativeChildMode.EXPERT_READ_RESEARCH and source_id in {"hermes", "orchestrator"})):
            raise ValueError
        profile_prompt = prompt_bytes.decode("utf-8", errors="strict")
    except Exception:
        raise NativeChildDenied("root-selected profile prompt is unavailable") from None
    try:
        from tools import delegate_tool
        child = delegate_tool._build_child_agent(
            task_index=task_index, goal=goal, context=context,
            toolsets=list(_TOOLSETS[mode]) or ["__jarvis_empty_child_closure__"],
            model=model, max_iterations=max_iterations, task_count=1,
            parent_agent=parent_agent, override_provider=provider,
            override_base_url=base_url, override_api_key=api_key,
            override_api_mode=api_mode,
            override_request_overrides=dict(getattr(parent_agent, "request_overrides", {}) or {}),
            routing_cfg={"fallback_providers": []}, role="leaf",
        )
        if (child is None or _route_value(child, "provider") != provider
                or _route_value(child, "base_url") != base_url
                or _route_value(child, "api_mode") != api_mode
                or _route_value(child, "model") != model
                or _route_value(child, "api_key") != api_key):
            raise NativeChildDenied("native child route differs from its owner")
        generated_prompt = getattr(child, "ephemeral_system_prompt", None)
        if not isinstance(generated_prompt, str) or not generated_prompt:
            raise NativeChildDenied("official child system prompt is unavailable")
        # Preserve Hermes' generated lifecycle/task instructions and append the
        # exact root-selected profile bytes as the final system specialization.
        child.ephemeral_system_prompt = generated_prompt + "\n\n" + profile_prompt
        # The selected existing subscription is pinned; child credential-pool
        # acquisition and rate-limit account rotation are not part of this path.
        child._credential_pool = None
        apply_native_child_tool_closure(child, mode)
        if (mode is NativeChildMode.PLANNER and child.valid_tool_names
                or "delegate_task" in child.valid_tool_names
                or any(name.startswith("mcp__") for name in child.valid_tool_names)):
            raise NativeChildDenied("native child closure retained an unapproved capability")
        return child
    except NativeChildDenied:
        raise
    except Exception:
        raise NativeChildDenied("official native child construction failed") from None


def run_native_child(*, child: Any, parent_agent: Any, goal: str,
                     authorization: Any, source: Any) -> dict[str, Any]:
    """Run only after root authorization/source checks and child-session admission.

    ``authorization`` must be the future fixed root-issued child receipt. Its
    exact type and ``matches_child`` verifier are checked here; it must bind the
    current parent object/session/turn, child session, selected source, route,
    closure mode, zero additional metered budget, and its original deadline.
    """
    from hermes_installer.remote.core_native_observer import RootVerifiedNativeChildAuthorization
    if type(authorization) is not RootVerifiedNativeChildAuthorization:
        raise NativeChildDenied("root child authorization is unavailable")
    now = time.monotonic()
    try:
        mode = NativeChildMode(getattr(child, "_jarvis_native_child_mode", ""))
        names = frozenset(getattr(child, "valid_tool_names"))
        expected_names = _CLOSURES[mode]
        child_session_id = getattr(child, "session_id")
        parent_session_id = getattr(parent_agent, "session_id")
        parent_turn_id = getattr(parent_agent, "_current_turn_id")
    except (AttributeError, TypeError, ValueError):
        raise NativeChildDenied("native child lineage is incomplete") from None
    if (child is None or not names.issubset(expected_names)
            or names != frozenset(getattr(child, "_jarvis_native_child_tool_names", ()))
            or not isinstance(child_session_id, str) or not child_session_id
            or not isinstance(parent_session_id, str) or not parent_session_id
            or not isinstance(parent_turn_id, str) or not parent_turn_id
            or authorization.matches_child(
                parent_agent=parent_agent, child=child, source=source,
                mode=mode, goal=goal, now=now) is not True):
        raise NativeChildDenied("root owner/source/child authorization is stale or mismatched")
    if mode is NativeChildMode.PLANNER and names:
        raise NativeChildDenied("planner child must have no callable tools")
    try:
        from tools.delegate_tool_results import _run_child_lifecycle
        return _run_child_lifecycle(0, goal, child=child, parent_agent=parent_agent)
    except Exception:
        raise NativeChildDenied("official native child lifecycle failed") from None


def planning_response_sha256(text: str) -> str:
    """Digest a bounded successful no-tools planner response without retaining it."""
    if not isinstance(text, str) or not text or len(text.encode("utf-8", "strict")) > 32 * 1024:
        raise NativeChildDenied("planner output is missing or outside its bound")
    return hashlib.sha256(text.encode("utf-8", errors="strict")).hexdigest()


__all__ = [
    "NativeChildDenied", "NativeChildMode", "apply_native_child_tool_closure",
    "build_native_child", "planning_response_sha256", "run_native_child",
]
