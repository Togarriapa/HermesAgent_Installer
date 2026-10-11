"""Closed, bounded projections for the pinned Hermes tools/skills read APIs.

This module does not call Hermes, inspect configuration, or return skill contents.
Its inputs are the two fixed, server-side CoreRpcClient projections. Free-form
metadata is intentionally excluded; toolset and skill labels are display-only.
"""
from __future__ import annotations

import re
import asyncio
from dataclasses import dataclass
from typing import Any

_TOOLSET_LABEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._:-]{0,79}$")
_TOOL_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,119}$")
_CATEGORY_LABEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$")
_SKILL_LABEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._()-]{0,99}$")
_MAX_TOOLSETS = 256
_MAX_TOOLS_PER_SET = 512
_MAX_TOOLS_TOTAL = 8_000
_MAX_SKILL_CATEGORIES = 128
_MAX_SKILLS_PER_CATEGORY = 512
_MAX_SKILLS_TOTAL = 4_000


def _exact_keys(value: Any, expected: frozenset[str]) -> bool:
    return isinstance(value, dict) and set(value) == expected


def _bounded_name(value: Any, pattern: re.Pattern[str]) -> str | None:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        return None
    if "//" in value or "://" in value or "\\" in value or value in {".", ".."}:
        return None
    return value


@dataclass(frozen=True, slots=True)
class ToolsetInventoryRow:
    name: str
    selection: bool | None
    tool_count: int
    tools: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return {"name": self.name, "selection": self.selection,
                "toolCount": self.tool_count, "tools": list(self.tools)}


@dataclass(frozen=True, slots=True)
class SkillCategory:
    name: str
    skills: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return {"name": self.name, "skills": list(self.skills)}


@dataclass(frozen=True, slots=True)
class NativeInventorySnapshot:
    tools_state: str
    tools_selection_state: str
    toolsets: tuple[ToolsetInventoryRow, ...]
    skills_state: str
    categories: tuple[SkillCategory, ...]
    skill_count: int

    def to_public_dict(self) -> dict[str, Any]:
        """Return a fresh closed DTO; no raw response object crosses this seam."""
        return {
            "schema": 1,
            "tools": {
                "state": self.tools_state,
                "selectionState": self.tools_selection_state,
                "items": [row.as_dict() for row in self.toolsets],
            },
            "skills": {
                "state": self.skills_state,
                "categories": [row.as_dict() for row in self.categories],
                "count": self.skill_count,
            },
        }


def _decode_toolsets(value: Any) -> tuple[str, str, tuple[ToolsetInventoryRow, ...]]:
    """Decode Activity's strict ``tools.list`` rows; never imply operational readiness.

    Hermes' native list marks enabled toolsets from the configured selection. Its
    pinned producer maps an all-true set both from unrestricted defaults and an
    empty selection, so that case is deliberately exposed as ambiguous.
    """
    if not isinstance(value, list) or not 1 <= len(value) <= _MAX_TOOLSETS:
        return "unknown", "unknown", ()
    decoded: list[ToolsetInventoryRow] = []
    names: set[str] = set()
    total_tools = 0
    has_not_selected = False
    expected = frozenset({"name", "tool_count", "enabled", "tools"})
    for row in value:
        if not _exact_keys(row, expected):
            return "unknown", "unknown", ()
        name = _bounded_name(row["name"], _TOOLSET_LABEL)
        count, enabled, tools = row["tool_count"], row["enabled"], row["tools"]
        if (name is None or name in names or type(count) is not int
                or not 0 <= count <= _MAX_TOOLS_PER_SET or type(enabled) is not bool
                or not isinstance(tools, list) or len(tools) != count
                or len(tools) > _MAX_TOOLS_PER_SET):
            return "unknown", "unknown", ()
        tool_names: list[str] = []
        seen_tools: set[str] = set()
        for raw_tool in tools:
            tool = _bounded_name(raw_tool, _TOOL_NAME)
            if tool is None or tool in seen_tools:
                return "unknown", "unknown", ()
            seen_tools.add(tool)
            tool_names.append(tool)
        total_tools += len(tool_names)
        if total_tools > _MAX_TOOLS_TOTAL:
            return "unknown", "unknown", ()
        names.add(name)
        has_not_selected = has_not_selected or not enabled
        decoded.append(ToolsetInventoryRow(name, enabled, count, tuple(tool_names)))
    if not has_not_selected:
        # Pinned tools.list reports true for every row both when no selection is
        # configured and when its resolved set is empty. Preserve that ambiguity.
        decoded = [ToolsetInventoryRow(row.name, None, row.tool_count, row.tools) for row in decoded]
        selection_state = "ambiguous"
    else:
        selection_state = "reported"
    return "observed", selection_state, tuple(decoded)


def _display_skill_name(value: Any) -> str | None:
    """Project relative duplicate names to the basename so no skill path is exposed."""
    if (not isinstance(value, str) or not value or "\\" in value or value.startswith("/")
            or "://" in value or any(part in {"", ".", ".."} for part in value.split("/"))):
        return None
    label = value.rsplit("/", 1)[-1]
    if "://" in label or _bounded_name(label, _SKILL_LABEL) is None:
        return None
    return label


def _decode_skills(value: Any) -> tuple[str, tuple[SkillCategory, ...], int]:
    """Decode current-profile category/name discovery only, never skill file text."""
    if not isinstance(value, list) or not 1 <= len(value) <= _MAX_SKILL_CATEGORIES:
        # An empty native result is also used when the local scan fails, so it is
        # not strong enough to claim that the profile has no skills.
        return "unknown", (), 0
    categories: list[SkillCategory] = []
    seen_categories: set[str] = set()
    total = 0
    expected = frozenset({"category", "names"})
    for row in value:
        if not _exact_keys(row, expected):
            return "unknown", (), 0
        category = _bounded_name(row["category"], _CATEGORY_LABEL)
        raw_names = row["names"]
        if (category is None or category in seen_categories or not isinstance(raw_names, list)
                or not 1 <= len(raw_names) <= _MAX_SKILLS_PER_CATEGORY):
            return "unknown", (), 0
        labels: list[str] = []
        for raw_name in raw_names:
            label = _display_skill_name(raw_name)
            if label is None:
                return "unknown", (), 0
            labels.append(label)
        total += len(labels)
        if total > _MAX_SKILLS_TOTAL:
            return "unknown", (), 0
        categories.append(SkillCategory(category, tuple(labels)))
        seen_categories.add(category)
    return "discovered", tuple(categories), total


def decode_native_inventory(*, toolsets: Any, skills: Any) -> NativeInventorySnapshot:
    """Return independent fail-closed sections from Activity's fixed list methods.

    ``toolsets`` is the normalized list from ``tools.list {}``; ``skills`` is the
    normalized category/name list from ``skills.manage {action: 'list'}``. Passing
    ``None`` for either source marks only that section unknown.
    """
    tools_state, selection_state, rows = _decode_toolsets(toolsets)
    skills_state, categories, count = _decode_skills(skills)
    return NativeInventorySnapshot(
        tools_state, selection_state, rows, skills_state, categories, count)


def install_jarvis_native_inventory_routes(app: Any, service: Any) -> None:
    """Install the one fixed owner/current-generation native inventory route."""
    from aiohttp import web
    from .jarvis_chat import JarvisChatService

    if not isinstance(service, JarvisChatService):
        raise TypeError("verified Jarvis chat service required")

    async def route(request: Any) -> Any:
        if request.path != "/chat/api/native-capabilities" or request.raw_path != request.path:
            raise web.HTTPNotFound(text="not found")
        principal = service._current(request)
        toolsets = None
        skills = None
        try:
            toolsets_result, skills_result = await asyncio.wait_for(
                asyncio.gather(
                    service.backend.toolsets_inventory(),
                    service.backend.skills_inventory(),
                    return_exceptions=True,
                ),
                timeout=2.0,
            )
        except asyncio.TimeoutError:
            # The read-only sections stay unknown; timeout never falls back to the
            # static bundled catalog or to another profile/process.
            toolsets_result, skills_result = None, None
        except Exception:
            toolsets_result, skills_result = None, None
        try:
            current = service._current(request)
        except Exception:
            raise web.HTTPForbidden(text="forbidden") from None
        if (current.subject != principal.subject
                or current.core_generation != principal.core_generation):
            raise web.HTTPForbidden(text="forbidden")
        if not isinstance(toolsets_result, BaseException):
            toolsets = toolsets_result
        if not isinstance(skills_result, BaseException):
            skills = skills_result
        snapshot = decode_native_inventory(toolsets=toolsets, skills=skills)
        return web.json_response(snapshot.to_public_dict(), headers={"Cache-Control": "no-store"})

    app.router.add_get("/chat/api/native-capabilities", route, allow_head=False)
