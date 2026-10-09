"""Source-reviewed action schemas for GitHub, Composio, and Codex Plugins.

The adapter digest is pinned in this companion catalog so the catalog itself
does not create a self-referential hash. Capabilities and guardrails follow the
vendored Resources manifests; the exact provider verbs follow the official
fixed API references and root-enrolled per-tool schemas.
"""
from __future__ import annotations

from types import MappingProxyType
from typing import Any

from hermes_installer.components.plugin_effects import PluginActionSchema

# SHA-256 of plugin_accounts_adapters.py; refresh with every adapter source edit.
PLUGIN_ACCOUNTS_ADAPTER_SHA256 = "03d2d19a64501e0d0673d620d9b8976639888612e32b9d54226d26551f629b35"


def _obj(properties: dict[str, Any], required: list[str]) -> dict[str, Any]:
    return {"type": "object", "properties": properties, "required": required,
            "additionalProperties": False}


def _str(maximum: int, minimum: int = 0, pattern: str | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {"type": "string", "minLength": minimum, "maxLength": maximum}
    if pattern is not None:
        result["pattern"] = pattern
    return result


def _freeze(value: Any) -> Any:
    if isinstance(value, dict):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    return value


def _schema(adapter: str, action: str, operation: str, arguments: dict[str, Any], *,
            expected_state: str = "read-complete", write: bool = False,
            confirmation: bool = False, request_limit: int = 262_144,
            response_limit: int = 2_097_152, deadline: float = 30.0,
            result: dict[str, Any] | None = None) -> PluginActionSchema:
    return PluginActionSchema(
        adapter_id=adapter, action_id=action,
        argument_schema_id=f"{adapter}.{action}.arguments.v1",
        result_schema_id=f"{adapter}.{action}.result.v1",
        operation=operation, adapter_sha256=PLUGIN_ACCOUNTS_ADAPTER_SHA256,
        argument_schema=_freeze(arguments), result_schema=_freeze(result or {"type": "object"}),
        request_bytes_limit=request_limit, response_bytes_limit=response_limit,
        deadline_seconds=deadline, requires_idempotency=write,
        requires_confirmation=confirmation, expected_state=expected_state,
    )


_REPOSITORY = _str(140, 3, r"^[A-Za-z0-9_.-]{1,39}/[A-Za-z0-9_.-]{1,100}$")
_PATH = _str(512, 1, r"^(?!/)(?!.*(?:^|/)\.\.?/)[^\\\x00-\x1f]+$")
_SHA = _str(40, 40, r"^[0-9a-f]{40}$")
_COMPOSIO_SLUG = _str(128, 2, r"^[A-Z][A-Z0-9_]{1,127}$")
_COMPOSIO_ARGS = {"type": "object"}
_REPO_RESULT = _obj({
    "full_name": _str(140, 3), "private": {"type": "boolean"},
    "default_branch": {"type": ["string", "null"], "maxLength": 256}, "html_url": _str(2048, 1),
    "description": {"type": ["string", "null"], "maxLength": 2048},
}, ["full_name", "private", "default_branch", "html_url"])
_ISSUE_RESULT = _obj({
    "number": {"type": "integer", "minimum": 1, "maximum": 2_147_483_647},
    "title": _str(256, 1), "state": {"type": "string", "enum": ["open", "closed"]},
    "html_url": _str(2048, 1), "body": {"type": ["string", "null"], "maxLength": 60_000},
}, ["number", "title", "state", "html_url"])
_CONTENT_RESULT = _obj({
    "path": _str(512, 1), "sha": _str(40, 40, r"^[0-9a-f]{40}$"),
    "size": {"type": "integer", "minimum": 0, "maximum": 1_000_000},
    "content_base64": _str(1_400_000), "encoding": {"type": "string", "enum": ["base64"]},
}, ["path", "sha", "size"])
_CONTENT_WRITE_RESULT = _obj({
    "path": _str(512, 1), "sha": _str(40, 40, r"^[0-9a-f]{40}$"),
    "size": {"type": "integer", "minimum": 0, "maximum": 1_000_000},
    "commit_sha": _str(40, 40, r"^[0-9a-f]{40}$"), "html_url": _str(2048, 1),
}, ["path", "sha", "size", "commit_sha"])
_ISSUE_CREATE_RESULT = _obj({
    "number": {"type": "integer", "minimum": 1, "maximum": 2_147_483_647},
    "title": _str(256, 1), "state": {"type": "string", "enum": ["open", "closed"]},
    "html_url": _str(2048, 1),
}, ["number", "title", "state", "html_url"])
_CODEX_RESULT = _obj({
    "workspace_id": _str(128, 1, r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$"),
    "receipt_id": _str(128, 8), "exit_code": {"type": "integer", "minimum": 0, "maximum": 255},
    "workspace_digest": _str(64, 64, r"^[0-9a-f]{64}$"),
}, ["workspace_id", "receipt_id", "exit_code", "workspace_digest"])

_rows = {
    ("github", "repo.get"): _schema("github", "repo.get", "plugin.github.read",
        _obj({"repository": _REPOSITORY}, ["repository"]), result=_REPO_RESULT),
    ("github", "issues.list"): _schema("github", "issues.list", "plugin.github.read",
        _obj({"repository": _REPOSITORY}, ["repository"]), response_limit=1_048_576,
        result=_obj({"items": {"type": "array", "maxItems": 30, "items": _ISSUE_RESULT}}, ["items"])),
    ("github", "content.get"): _schema("github", "content.get", "plugin.github.read",
        _obj({"repository": _REPOSITORY, "path": _PATH}, ["repository", "path"]), result=_CONTENT_RESULT),
    ("github", "content.put"): _schema("github", "content.put", "plugin.github.write",
        _obj({"repository": _REPOSITORY, "path": _PATH, "content": _str(700_000),
              "message": _str(256, 1), "sha": {"type": ["string", "null"], "pattern": "^[0-9a-f]{40}$", "maxLength": 40}},
             ["repository", "path", "content", "message"]), expected_state="committed", write=True,
        result=_CONTENT_WRITE_RESULT),
    ("github", "issue.create"): _schema("github", "issue.create", "plugin.github.write",
        _obj({"repository": _REPOSITORY, "title": _str(256, 1), "body": _str(60_000)},
             ["repository", "title"]), expected_state="committed", write=True, result=_ISSUE_CREATE_RESULT),
    ("composio", "invoke.read"): _schema("composio", "invoke.read", "plugin.composio.invoke",
        _obj({"tool_slug": _COMPOSIO_SLUG, "arguments": _COMPOSIO_ARGS}, ["tool_slug", "arguments"]),
        expected_state="read-complete", response_limit=1_048_576),
    ("composio", "invoke.write"): _schema("composio", "invoke.write", "plugin.composio.invoke",
        _obj({"tool_slug": _COMPOSIO_SLUG, "arguments": _COMPOSIO_ARGS}, ["tool_slug", "arguments"]),
        expected_state="committed", write=True, confirmation=True, response_limit=1_048_576),
    ("codex", "run"): _schema("codex", "run", "plugin.codex.run",
        _obj({"workspace_id": _str(128, 1, r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$"),
              "prompt": _str(32_768, 1)}, ["workspace_id", "prompt"]),
        expected_state="committed", write=True, request_limit=65_536, response_limit=1_048_576,
        result=_CODEX_RESULT),
}

PLUGIN_ACTION_SCHEMAS = MappingProxyType(_rows)
