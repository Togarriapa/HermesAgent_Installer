"""Capture the actual Hermes ``register_tool`` source surface without effects.

This producer invokes only each reviewed implementation's registration method
with an inert context. Captured metadata is source evidence, not an authority
receipt: callers must join source, bounded result-schema and observer receipts
before converting these rows into executable native candidates.
"""
from __future__ import annotations

import hashlib
import inspect
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from hermes_installer.components.native_plugins import (
    _PLUGIN_IDS,
    _PLUGIN_VERSIONS,
    resolve_native_plugin_implementation,
)
from hermes_installer.registry.resources_runtime import (
    NativePluginRuntimeContext,
    ResourceIdentity,
    ReviewedPluginAdapterRegistry,
)


class NativeRegistrationCaptureDenied(ValueError):
    """The pinned component registration surface could not be captured safely."""


@dataclass(frozen=True, slots=True)
class CapturedHermesRegistration:
    adapter_id: str
    native_tool_name: str
    toolset: str
    argument_schema: Mapping[str, Any]
    description: str
    handler_id: str
    handler_module: str
    registration_source_path: str
    registration_source_sha256: str
    native_schema_sha256: str


@dataclass(frozen=True, slots=True)
class NativeRegistrationActionBinding:
    """One source-declared finite route from a registered tool to an action."""

    selector_values: Mapping[str, str]
    action_id: str
    argument_projection: tuple[tuple[str, str], ...]
    workflow_id: str | None = None


@dataclass(frozen=True, slots=True)
class ReviewedNativeRegistrationDefinition:
    """Source-reviewed routing facts for one actual Hermes registration.

    These definitions are deliberately separate from source capture and from
    executable projection rows.  They contain no receipts or readiness flags;
    the root factory must join current source, schema, and observer proofs.
    """

    adapter_id: str
    native_tool_name: str
    family: str
    handler_kind: str
    selector_fields: tuple[str, ...]
    action_bindings: tuple[NativeRegistrationActionBinding, ...]


class NativeRegistrationDefinitionDenied(ValueError):
    """Actual captured registrations do not match the reviewed finite map."""


def reviewed_native_registration_definitions(
        registrations: tuple[CapturedHermesRegistration, ...] | None = None,
) -> tuple[ReviewedNativeRegistrationDefinition, ...]:
    """Resolve the exact 42-tool source map from current register_tool calls.

    This is source evidence only.  It does not issue result schemas, source
    receipts, observer enrollments, or effect authority.
    """
    captured = registrations if registrations is not None else capture_actual_hermes_registrations()
    if not isinstance(captured, tuple) or len(captured) != 42:
        raise NativeRegistrationDefinitionDenied("all 42 reviewed Hermes registrations are required")

    def direct(adapter: str, tool: str, action: str, fields: tuple[str, ...],
               *, kind: str = "effect-action"):
        return ReviewedNativeRegistrationDefinition(
            adapter, tool, adapter, kind, (),
            (NativeRegistrationActionBinding({}, action, tuple((field, field) for field in fields)),),
        )

    definitions: dict[str, ReviewedNativeRegistrationDefinition] = {}
    direct_rows = (
        ("github", "github_repository", "repo.get", ("repository",)),
        ("github", "github_list_issues", "issues.list", ("repository",)),
        ("github", "github_read_file", "content.get", ("path", "repository")),
        ("github", "github_write_file", "content.put", ("content", "message", "path", "repository", "sha")),
        ("github", "github_create_issue", "issue.create", ("body", "repository", "title")),
        ("composio", "composio_read", "invoke.read", ("arguments", "tool_slug")),
        ("composio", "composio_write", "invoke.write", ("arguments", "tool_slug")),
        ("codex", "codex_run", "run", ("prompt", "workspace_id")),
        ("ebook-toolchain", "ebook_toolchain_build", "run", ("format", "recipe_id", "source_id", "title")),
        ("ebook-toolchain", "ebook_toolchain_inspect", "inspect", ("recipe_id", "source_id")),
        ("ebook-toolchain", "ebook_toolchain_validate", "validate", ("recipe_id", "source_id")),
        ("kobo-bridge", "kobo_bridge_deliver", "deliver", ("enrollment_id", "export_id")),
        ("kobo-bridge", "kobo_bridge_read_export", "read", ("book_id", "enrollment_id")),
        ("authentik-authorization", "authentik_current_principal", "resolve-session-principal-to-user", ()),
        ("authentik-authorization", "authentik_active_user_identity", "read-active-user-identity", ()),
        ("authentik-authorization", "authentik_effective_groups", "read-user-effective-groups", ()),
        ("authentik-authorization", "authentik_verify_system_membership", "verify-effective-System-membership", ()),
        ("authentik-authorization", "authentik_system_alarm_recipients", "list-current-effective-System-members-for-alarm-delivery", ()),
        ("cloudflare-homelab", "cloudflare_homelab_read_dns", "read-approved-dns-records", ("hostname",)),
        ("cloudflare-homelab", "cloudflare_homelab_read_tunnel", "read-approved-tunnel-state", ("tunnel",)),
        ("cloudflare-homelab", "cloudflare_homelab_read_tunnel_configuration", "read-approved-tunnel-configuration", ("tunnel",)),
        ("cloudflare-homelab", "cloudflare_homelab_read_tunnel_connectors", "read-approved-tunnel-connectors", ("tunnel",)),
        ("cloudflare-homelab", "cloudflare_homelab_update_dns", "update-approved-dns-record", ("content", "hostname", "proxied", "ttl")),
        ("cloudflare-homelab", "cloudflare_homelab_update_tunnel", "update-approved-tunnel-configuration", ("hostname", "tunnel")),
        ("mcp-registry", "mcp_registry_discover", "discover-servers", ("cursor", "latest_only", "limit", "search")),
        ("mcp-registry", "mcp_registry_inspect", "inspect-server-metadata", ("server_name", "version")),
        ("agent37-discovery", "agent37_discover_skills", "discover-skill-candidates", ("cursor", "limit", "minimum_stars", "owner", "recently_updated", "repo", "search", "sort")),
        ("agent37-discovery", "agent37_inspect_skill", "inspect-public-metadata", ("skill_id",)),
        ("resource-overlay-store", "resource_overlay_read", "read", ("record_id",)),
        ("resource-overlay-store", "resource_overlay_write", "write", ("expected_revision", "record_id", "value_base64")),
        ("resource-overlay-store", "resource_overlay_history", "history", ("record_id",)),
        ("resource-overlay-store", "resource_overlay_delete", "delete", ("expected_revision", "record_id")),
        ("web", "web_retrieve", "retrieve", ("url",)),
    )
    # The repeated GitHub row above is avoided below by keyed registration
    # definitions; the capture itself remains the authority for name coverage.
    for adapter, tool, action, fields in direct_rows:
        if tool in definitions:
            continue
        kind = ("public-registry-read" if adapter in {"mcp-registry", "agent37-discovery"}
                else "owner-overlay" if adapter == "resource-overlay-store" else "effect-action")
        if kind in {"public-registry-read", "owner-overlay"}:
            # The lexical action is the actual registered tool identity. Its
            # existing source handler owns the internal public/overlay route.
            action = f"{adapter}:tool:{tool}"
        definitions[tool] = direct(adapter, tool, action, fields, kind=kind)

    def finite(adapter: str, tool: str, family: str, kind: str, selector_fields: tuple[str, ...],
               rows: tuple[tuple[Mapping[str, str], str, tuple[tuple[str, str], ...]], ...]):
        definitions[tool] = ReviewedNativeRegistrationDefinition(
            adapter, tool, family, kind, selector_fields,
            tuple(NativeRegistrationActionBinding(dict(selector), action, projection)
                  for selector, action, projection in rows),
        )

    # Epic operation dispatch is explicit in LocalKanbanPlugin.invoke.
    epic_fields = {
        "create": ("epic-kanban", (("epic_id", "epic_id"), ("title", "title"))),
        "read": ("epic-kanban", (("board_id", "board_id"),)),
        "add_item": ("epic-kanban", (("board_id", "board_id"), ("description", "description"), ("item_type", "item_type"), ("title", "title"))),
        "move_item": ("epic-kanban", (("board_id", "board_id"), ("item_id", "item_id"), ("state", "state"))),
        "delete_accepted": ("epic-kanban", (("accepted_lifecycle_attestation_id", "accepted_lifecycle_attestation_id"), ("board_id", "board_id"))),
    }
    finite("epic-kanban", "epic_board", "epic-kanban", "finite-selector", ("operation",),
           tuple(({"operation": op}, action, projection) for op, (action, projection) in epic_fields.items()))

    # Financial data valid provider/operation pairs come from the exact source
    # scope table; invalid Cartesian combinations are intentionally absent.
    from hermes_installer.components.plugin_finance import _DATA_SCOPES
    finite("financial-data-hub", "financial_data_read", "financial-data-hub", "finite-selector",
           ("provider", "operation"), tuple(
               ({"provider": provider.value, "operation": operation.value}, "read",
                (("filters", "filters"), ("operation", "operation"), ("provider", "provider")))
               for provider, operations in sorted(_DATA_SCOPES.items(), key=lambda item: item[0].value)
               for operation in sorted(operations, key=lambda item: item.value)))

    from hermes_installer.components.plugin_finance import _EXECUTION_OPERATIONS, _LIVE_READS, _SANDBOX_READS
    finite("financial-execution-gateway", "financial_execute_one_order", "financial-execution-gateway",
           "finite-selector", ("provider", "operation"), tuple(
               ({"provider": provider, "operation": operation}, "execute",
                (("action", "action"), ("operation", "operation"), ("provider", "provider")))
               for provider, operations in sorted(_EXECUTION_OPERATIONS.items())
               for operation in sorted(operations)))
    finite("agent-live-wallet", "agent_live_wallet_action", "agent-live-wallet", "finite-selector",
           ("operation",), tuple(
               ({"operation": operation}, "read" if operation in _LIVE_READS else "execute",
                (("action", "action"), ("network", "network"), ("operation", "operation")))
               for operation in ("construct", "simulate", "estimate-fee", "inspect", "sign", "broadcast")))
    finite("agent-sandbox-wallet", "agent_sandbox_wallet_action", "agent-sandbox-wallet", "finite-selector",
           ("operation",), tuple(
               ({"operation": operation}, "read" if operation in _SANDBOX_READS else "execute",
                (("action", "action"), ("network", "network"), ("operation", "operation")))
               for operation in ("read-balance", "simulate", "inspect-receipt", "create-account", "reset-account",
                                 "sign-test-transaction", "send-test-asset", "deploy-test-contract", "reviewed-testnet-dapp")))

    from hermes_installer.components.plugin_homelab import _READ_QUERIES, _WRITE_ACTIONS
    finite("homelab-ops-broker", "homelab_ops_inspect", "homelab-ops-broker", "finite-selector",
           ("query",), tuple(({"query": value}, value, (("host", "host"), ("query", "query")))
                              for value in sorted(_READ_QUERIES)))
    finite("homelab-ops-broker", "homelab_ops_run", "homelab-ops-broker", "finite-selector",
           ("action",), tuple(({"action": value}, value, (("action", "action"), ("host", "host")))
                              for value in sorted(_WRITE_ACTIONS)))

    # These actual handlers invoke the fixed selected voice actions and return
    # source receipt/workflow records. The protected workflow identity is
    # joined later from the selected workflow catalog.
    for tool, action in (("voice_transcribe", "voice_transcribe"), ("voice_speak", "voice_speak")):
        definitions[tool] = ReviewedNativeRegistrationDefinition(
            "voice-pipeline", tool, "voice-pipeline", "finite-workflow", (),
            (NativeRegistrationActionBinding({}, action, (), None),),
        )

    captured_by_name = {row.native_tool_name: row for row in captured}
    if len(captured_by_name) != 42 or set(captured_by_name) != set(definitions):
        missing = sorted(set(captured_by_name) ^ set(definitions))
        raise NativeRegistrationDefinitionDenied(
            "reviewed source map does not cover the actual Hermes registration set: " + ", ".join(missing)
        )
    output = []
    for name, definition in definitions.items():
        source = captured_by_name[name]
        if source.adapter_id != definition.adapter_id:
            raise NativeRegistrationDefinitionDenied("captured registration adapter differs from its reviewed definition")
        properties = source.argument_schema.get("properties", {})
        if not isinstance(properties, Mapping):
            raise NativeRegistrationDefinitionDenied("captured registration argument properties are malformed")
        if any(field not in properties for field in definition.selector_fields):
            raise NativeRegistrationDefinitionDenied("reviewed selector field is absent from the actual source schema")
        for binding in definition.action_bindings:
            if any(field not in properties for _target, field in binding.argument_projection):
                raise NativeRegistrationDefinitionDenied("reviewed argument projection is absent from the actual source schema")
            for field, value in binding.selector_values.items():
                enum = properties.get(field, {}).get("enum") if isinstance(properties.get(field), Mapping) else None
                if not isinstance(enum, (tuple, list)) or value not in enum:
                    raise NativeRegistrationDefinitionDenied("reviewed selector literal is absent from the actual source enum")
        if definition.selector_fields:
            if any(not set(definition.selector_fields).issubset(binding.selector_values)
                   for binding in definition.action_bindings):
                raise NativeRegistrationDefinitionDenied("finite source selector coverage is incomplete")
            if len({tuple(sorted(binding.selector_values.items())) for binding in definition.action_bindings}) != len(definition.action_bindings):
                raise NativeRegistrationDefinitionDenied("finite source selector contains duplicate branches")
        output.append(definition)
    return tuple(sorted(output, key=lambda row: row.native_tool_name))


class _NoEffects:
    def invoke(self, *_args: Any, **_kwargs: Any) -> Any:
        raise NativeRegistrationCaptureDenied("registration capture attempted an effect")


class _NoAuthority:
    def __getattr__(self, _name: str) -> Any:
        raise NativeRegistrationCaptureDenied("registration capture attempted authority access")


class _OverlayFixture:
    def read(self, _record_id: str) -> None:
        return None

    def write(self, _record_id: str, _value: bytes, expected_revision: str | None = None) -> str:
        raise NativeRegistrationCaptureDenied("registration capture attempted an overlay write")

    def history(self, _record_id: str) -> tuple[str, ...]:
        return ()

    def delete(self, _record_id: str, expected_revision: str | None = None) -> str:
        raise NativeRegistrationCaptureDenied("registration capture attempted an overlay delete")


class _CaptureContext:
    def __init__(self, adapter_id: str):
        self.adapter_id = adapter_id
        self.rows: list[CapturedHermesRegistration] = []

    def register_tool(self, *args: Any, **kwargs: Any) -> None:
        if args:
            if len(args) not in {4, 5}:
                raise NativeRegistrationCaptureDenied("Hermes tool registration positional shape is unsupported")
            fields = {"name": args[0], "toolset": args[1], "schema": args[2], "handler": args[3]}
            if len(args) == 5:
                fields["description"] = args[4]
            if set(fields) & set(kwargs):
                raise NativeRegistrationCaptureDenied("Hermes tool registration duplicates a field")
            fields.update(kwargs)
        else:
            fields = dict(kwargs)
        required = {"name", "toolset", "schema", "handler", "description"}
        allowed = required | {"requires_env", "is_async"}
        if set(fields) - allowed or not required.issubset(fields):
            raise NativeRegistrationCaptureDenied("Hermes tool registration has an unreviewed shape")
        name, toolset = fields["name"], fields["toolset"]
        schema, description, handler = fields["schema"], fields["description"], fields["handler"]
        if (not isinstance(name, str) or not name or len(name) > 512
                or not isinstance(toolset, str) or not toolset or len(toolset) > 128
                or not isinstance(schema, Mapping) or schema.get("type") != "object"
                or not isinstance(description, str) or not description
                or not callable(handler) or fields.get("is_async", False) is not False
                or fields.get("requires_env") is not None):
            raise NativeRegistrationCaptureDenied("Hermes tool registration fields are invalid")
        handler_module = getattr(handler, "__module__", None)
        handler_id = getattr(handler, "__qualname__", None)
        if not isinstance(handler_module, str) or not isinstance(handler_id, str):
            raise NativeRegistrationCaptureDenied("captured tool handler has no stable source identity")
        code = getattr(handler, "__code__", None)
        source_filename = getattr(code, "co_filename", None)
        if not isinstance(source_filename, str):
            source_filename = inspect.getsourcefile(handler)
        source_path = _relative_component_path(source_filename)
        source_bytes = (Path(__file__).resolve().parents[2] / source_path).read_bytes()
        plain_schema = json.loads(json.dumps(schema, sort_keys=True, ensure_ascii=False, allow_nan=False))
        schema_bytes = _canonical(plain_schema)
        self.rows.append(CapturedHermesRegistration(
            self.adapter_id, name, toolset, plain_schema, description,
            handler_id, handler_module, source_path,
            hashlib.sha256(source_bytes).hexdigest(),
            hashlib.sha256(schema_bytes).hexdigest(),
        ))


def capture_actual_hermes_registrations() -> tuple[CapturedHermesRegistration, ...]:
    """Run all 18 implementation registration methods with an effect-denying context.

    The returned projection reflects actual ``PluginContext.register_tool``
    calls. It deliberately lacks result schemas, source receipt handles, and
    observer enrollment IDs, so it cannot itself qualify a candidate index.
    """
    result: list[CapturedHermesRegistration] = []
    identity_digest = "0" * 64
    for adapter_id in _PLUGIN_IDS:
        implementation = resolve_native_plugin_implementation(adapter_id)
        if implementation is None or not callable(getattr(implementation, "register", None)):
            raise NativeRegistrationCaptureDenied("one reviewed native plugin has no registration implementation")
        identity = ResourceIdentity(
            adapter_id, "plugins", _PLUGIN_VERSIONS[adapter_id],
            f"plugins/{adapter_id}.yaml", "source-capture", identity_digest,
        )
        runtime = NativePluginRuntimeContext(
            identity=identity, declared_capabilities=(), authority=_NoAuthority(),
            invocation_contexts=lambda **_kwargs: (),
            selected_adapters=ReviewedPluginAdapterRegistry(),
            plugin_effects=_NoEffects(), local_overlay_store=_OverlayFixture(),
            voice_session_enrollment_id="capture-only-voice-session",
        )
        context = _CaptureContext(adapter_id)
        try:
            implementation.register(context, runtime)
        except NativeRegistrationCaptureDenied:
            raise
        except Exception as exc:
            raise NativeRegistrationCaptureDenied(
                f"source registration capture failed for {adapter_id}: {type(exc).__name__}"
            ) from None
        if not context.rows:
            raise NativeRegistrationCaptureDenied("native plugin registered no Hermes tools")
        result.extend(context.rows)
    names = [row.native_tool_name for row in result]
    if len(names) != len(set(names)):
        raise NativeRegistrationCaptureDenied("actual Hermes registration names collide")
    return tuple(sorted(result, key=lambda row: row.native_tool_name))


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _relative_component_path(filename: str | None) -> str:
    if not isinstance(filename, str):
        raise NativeRegistrationCaptureDenied("registration source path is unavailable")
    root = Path(__file__).resolve().parents[2]
    try:
        relative = Path(filename).resolve(strict=True).relative_to(root).as_posix()
    except (OSError, ValueError):
        raise NativeRegistrationCaptureDenied("registration source is outside the installed component root") from None
    if not relative.startswith("hermes_installer/components/"):
        raise NativeRegistrationCaptureDenied("registration source is outside the reviewed component modules")
    return relative
