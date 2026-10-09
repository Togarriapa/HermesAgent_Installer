"""Native typed wrappers for the preserved GitHub, Composio and Codex Plugins.

All effects pass through the trusted `plugin_effects` facade. No wrapper has a
provider client, vault resolver, URL, path, executable, or credential field.
"""
from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from typing import Any, Protocol

from hermes_installer.components.plugin_accounts_schemas import PLUGIN_ACTION_SCHEMAS


class PluginAccountAdapterUnavailable(RuntimeError):
    """The selected account action is unavailable or not verified."""


class PluginEffectFacade(Protocol):
    def invoke(self, *, adapter_id: str, action_id: str, arguments: Mapping[str, Any],
               idempotency_key: str | None = None,
               opaque_confirmation_attestation_id: str | None = None) -> Mapping[str, Any]: ...


class RegistrationContext(Protocol):
    def register_tool(self, name: str, toolset: str, schema: dict[str, Any],
                      handler: Any, **kwargs: Any) -> object: ...


_VERSIONS = {"github": "1.0.1", "composio": "1.0.0", "codex": "1.0.1"}
_ACTIONS = {
    "github": ("repo.get", "issues.list", "content.get", "content.put", "issue.create"),
    "composio": ("invoke.read", "invoke.write"),
    "codex": ("run",),
}
_MAX_EFFECT_RESULT = 2_097_152
_SECRET_KEYS = frozenset({"token", "access_token", "refresh_token", "api_key", "secret",
                          "password", "authorization", "cookie", "credential", "private_key"})


def _selected(runtime: object, adapter_id: str) -> PluginEffectFacade:
    identity = getattr(runtime, "identity", None)
    if (getattr(identity, "kind", None) != "plugins"
            or getattr(identity, "resource_id", None) != adapter_id
            or getattr(identity, "version", None) != _VERSIONS[adapter_id]):
        raise PluginAccountAdapterUnavailable("trusted context does not match the selected account Plugin")
    effects = getattr(runtime, "plugin_effects", None)
    if not callable(getattr(effects, "invoke", None)):
        raise PluginAccountAdapterUnavailable("root-selected Plugin effect enrollment is unavailable")
    return effects


def _fields(value: object, expected: set[str], required: set[str]) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) - expected or required - set(value):
        raise ValueError("tool arguments do not match the fixed Plugin action schema")
    return dict(value)


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                          allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, RecursionError):
        raise ValueError("Plugin arguments must be finite JSON values") from None


def _idempotency(adapter_id: str, action_id: str, arguments: Mapping[str, Any],
                 confirmation: str | None) -> str:
    body = {"adapter_id": adapter_id, "action_id": action_id,
            "arguments": dict(arguments), "confirmation": confirmation}
    return hashlib.sha256(_canonical(body)).hexdigest()


def _safe(value: Any, depth: int = 0) -> Any:
    if depth > 10:
        raise PluginAccountAdapterUnavailable("provider result is too deeply nested")
    if value is None or type(value) in {str, int, bool}:
        if isinstance(value, str) and len(value) > 1_000_000:
            raise PluginAccountAdapterUnavailable("provider result contains an oversized string")
        return value
    if type(value) is float:
        if value != value or value in {float("inf"), float("-inf")}:
            raise PluginAccountAdapterUnavailable("provider result contains a non-finite number")
        return value
    if isinstance(value, Mapping):
        if len(value) > 512:
            raise PluginAccountAdapterUnavailable("provider result has too many fields")
        out = {}
        for key, child in value.items():
            if not isinstance(key, str) or len(key) > 256:
                raise PluginAccountAdapterUnavailable("provider result contains an invalid field name")
            if key.casefold() in _SECRET_KEYS:
                continue
            out[key] = _safe(child, depth + 1)
        return out
    if isinstance(value, (list, tuple)):
        if len(value) > 512:
            raise PluginAccountAdapterUnavailable("provider result contains too many items")
        return [_safe(item, depth + 1) for item in value]
    raise PluginAccountAdapterUnavailable("provider result is not bounded JSON")


def _dispatch(effects: PluginEffectFacade, adapter_id: str, action_id: str,
              arguments: Mapping[str, Any], *, confirmation: str | None = None) -> dict[str, Any]:
    schema = PLUGIN_ACTION_SCHEMAS[(adapter_id, action_id)]
    if schema.requires_confirmation and (not isinstance(confirmation, str)
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{7,127}", confirmation)):
        raise PluginAccountAdapterUnavailable("fresh exact-action confirmation handle is required")
    if not schema.requires_confirmation and confirmation is not None:
        raise PluginAccountAdapterUnavailable("unexpected confirmation handle")
    key = _idempotency(adapter_id, action_id, arguments, confirmation) if schema.requires_idempotency else None
    try:
        response = effects.invoke(adapter_id=adapter_id, action_id=action_id,
            arguments=dict(arguments), idempotency_key=key,
            opaque_confirmation_attestation_id=confirmation)
    except Exception:
        raise PluginAccountAdapterUnavailable("root Plugin effect failed; protected details were withheld") from None
    required = {"schema", "operation_id", "state", "result", "verification_status", "resume_action_id"}
    if (not isinstance(response, Mapping) or set(response) != required
            or type(response.get("schema")) is not int or response["schema"] != 1
            or not isinstance(response.get("operation_id"), str)
            or not 1 <= len(response["operation_id"]) <= 128
            or response.get("state") not in {"read-complete", "committed", "pending", "ambiguous", "unavailable"}
            or not isinstance(response.get("verification_status"), str)
            or (response.get("resume_action_id") is not None
                and not isinstance(response.get("resume_action_id"), str))):
        raise PluginAccountAdapterUnavailable("root Plugin effect returned an invalid operation envelope")
    if response["state"] in {"pending", "ambiguous", "unavailable"}:
        return {"operation_id": response["operation_id"], "state": response["state"],
                "verification_status": response["verification_status"],
                "resume_action_id": response["resume_action_id"]}
    if response["state"] != schema.expected_state or not isinstance(response.get("result"), Mapping):
        raise PluginAccountAdapterUnavailable("root Plugin effect did not verify the enrolled action")
    if response["state"] == "committed" and response.get("verification_status") != "verified":
        raise PluginAccountAdapterUnavailable("committed account action lacks verified post-effect evidence")
    result = _safe(response["result"])
    if len(_canonical(result)) > min(_MAX_EFFECT_RESULT, schema.response_bytes_limit):
        raise PluginAccountAdapterUnavailable("provider result exceeds the fixed response bound")
    return result


def _plain(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _plain(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(item) for item in value]
    return value


class GitHubPluginImplementation:
    def register(self, ctx: RegistrationContext, runtime_context: object) -> None:
        effects = _selected(runtime_context, "github")
        tools = {
            "repo.get": ("github_repository", "Read allowlisted repository metadata."),
            "issues.list": ("github_list_issues", "List bounded open issues for an allowlisted repository."),
            "content.get": ("github_read_file", "Read one bounded file from an allowlisted repository."),
            "content.put": ("github_write_file", "Write one task-authorized file and verify it remotely."),
            "issue.create": ("github_create_issue", "Create one task-authorized issue and verify it remotely."),
        }
        for action_id, (name, description) in tools.items():
            schema = _plain(PLUGIN_ACTION_SCHEMAS[("github", action_id)].argument_schema)
            ctx.register_tool(name=name, toolset="github", schema=schema,
                handler=self._handler(effects, action_id), requires_env=None,
                is_async=False, description=description)

    @staticmethod
    def _handler(effects: PluginEffectFacade, action_id: str):
        def run(args: object) -> dict[str, Any]:
            schema = PLUGIN_ACTION_SCHEMAS[("github", action_id)].argument_schema
            fields = _fields(args, set(schema["properties"]), set(schema["required"]))
            result = _dispatch(effects, "github", action_id, fields)
            if "state" in result and "operation_id" in result:
                return result
            if action_id == "repo.get":
                if not isinstance(result.get("full_name"), str):
                    raise PluginAccountAdapterUnavailable("GitHub repository response is malformed")
                return {key: result[key] for key in ("full_name", "private", "default_branch", "html_url", "description") if key in result}
            if action_id == "issues.list":
                items = result.get("items", result.get("issues"))
                if not isinstance(items, list) or len(items) > 30:
                    raise PluginAccountAdapterUnavailable("GitHub issue response is malformed or exceeds 30 rows")
                return {"items": [_issue(item) for item in items]}
            if action_id in {"content.get", "content.put"}:
                if not isinstance(result.get("path"), str):
                    raise PluginAccountAdapterUnavailable("GitHub content response is malformed")
                return dict(result)
            if action_id == "issue.create":
                return _issue(result)
            raise PluginAccountAdapterUnavailable("GitHub action is not in the native adapter catalog")
        return run


def _issue(value: object) -> dict[str, Any]:
    if not isinstance(value, Mapping) or type(value.get("number")) is not int or not isinstance(value.get("title"), str):
        raise PluginAccountAdapterUnavailable("GitHub issue response is malformed")
    return {key: value[key] for key in ("number", "title", "state", "html_url", "body") if key in value}


class ComposioPluginImplementation:
    def register(self, ctx: RegistrationContext, runtime_context: object) -> None:
        effects = _selected(runtime_context, "composio")
        base = _plain(PLUGIN_ACTION_SCHEMAS[("composio", "invoke.read")].argument_schema)
        ctx.register_tool(name="composio_read", toolset="composio", schema=base,
            handler=self._handler(effects, "invoke.read", write=False), requires_env=None,
            is_async=False, description="Invoke one root-enrolled read-only Composio action.")
        write_schema = _plain(PLUGIN_ACTION_SCHEMAS[("composio", "invoke.write")].argument_schema)
        properties = dict(write_schema["properties"])
        properties["opaque_confirmation_attestation_id"] = {
            "type": "string", "minLength": 8, "maxLength": 128,
            "pattern": r"^[A-Za-z0-9][A-Za-z0-9_.:-]{7,127}$"}
        write_schema["properties"] = properties
        write_schema["required"] = [*write_schema["required"], "opaque_confirmation_attestation_id"]
        ctx.register_tool(name="composio_write", toolset="composio", schema=write_schema,
            handler=self._handler(effects, "invoke.write", write=True), requires_env=None,
            is_async=False, description="Invoke one root-enrolled Composio action with exact-payload confirmation.")

    @staticmethod
    def _handler(effects: PluginEffectFacade, action_id: str, *, write: bool):
        def run(args: object) -> dict[str, Any]:
            schema = PLUGIN_ACTION_SCHEMAS[("composio", action_id)].argument_schema
            allowed = set(schema["properties"])
            if write:
                allowed.add("opaque_confirmation_attestation_id")
            fields = _fields(args, allowed, set(schema["required"]) |
                             ({"opaque_confirmation_attestation_id"} if write else set()))
            confirmation = fields.pop("opaque_confirmation_attestation_id", None)
            return _dispatch(effects, "composio", action_id, fields, confirmation=confirmation)
        return run


class CodexPluginImplementation:
    def register(self, ctx: RegistrationContext, runtime_context: object) -> None:
        effects = _selected(runtime_context, "codex")
        schema = _plain(PLUGIN_ACTION_SCHEMAS[("codex", "run")].argument_schema)
        ctx.register_tool(name="codex_run", toolset="codex", schema=schema,
            handler=self._handler(effects), requires_env=None, is_async=False,
            description="Run a bounded task in the root-assigned workspace using the host-managed Codex CLI.")

    @staticmethod
    def _handler(effects: PluginEffectFacade):
        def run(args: object) -> dict[str, Any]:
            schema = PLUGIN_ACTION_SCHEMAS[("codex", "run")].argument_schema
            fields = _fields(args, set(schema["properties"]), set(schema["required"]))
            result = _dispatch(effects, "codex", "run", fields)
            if "state" in result and "operation_id" in result:
                return result
            return result
        return run


PLUGIN_IMPLEMENTATIONS = {
    "github": GitHubPluginImplementation(),
    "composio": ComposioPluginImplementation(),
    "codex": CodexPluginImplementation(),
}
