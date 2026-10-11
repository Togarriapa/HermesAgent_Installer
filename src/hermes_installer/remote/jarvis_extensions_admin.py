"""Owner-operated extensions setup backed by the pinned Hermes management RPCs.

Only catalog skill/plugin/MCP additions and the upstream-supported plugin settings,
toggle and removal actions are exposed. This is not a generic RPC or shell proxy.
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import math
import re
from typing import Any

FEATURE_ROUTES = (
    ("GET", "/chat/api/extensions"),
    ("POST", "/chat/api/extensions/skills/add"),
    ("POST", "/chat/api/extensions/plugins/add"),
    ("POST", "/chat/api/extensions/plugins/edit"),
    ("POST", "/chat/api/extensions/plugins/toggle"),
    ("POST", "/chat/api/extensions/plugins/remove"),
    ("POST", "/chat/api/extensions/mcps/add"),
    ("POST", "/chat/api/extensions/mcps/remove"),
)

_IDEMPOTENCY = re.compile(r"^[A-Za-z0-9_-]{22,128}$", re.ASCII)
_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@/-]{0,159}$", re.ASCII)
_MAX_SKILLS = 2000


def _valid_plugin_setting(field: dict[str, Any], value: Any) -> bool:
    kind = field.get("type")
    if kind == "string":
        return isinstance(value, str) and len(value) <= 2048
    if kind == "number":
        return type(value) in {int, float} and (type(value) is int or math.isfinite(value))
    if kind == "boolean":
        return type(value) is bool
    if kind == "enum":
        choices = field.get("choices", [])
        return isinstance(value, str) and isinstance(choices, list) and value in choices
    return False


def _slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.casefold()).strip("-")


def _safe_label(value: Any, *, maximum: int = 96) -> str | None:
    if (not isinstance(value, str) or not 1 <= len(value) <= maximum
            or any(ord(char) < 0x20 or ord(char) == 0x7f for char in value)):
        return None
    return value


def _source_label(source: str, name: str) -> tuple[str, str]:
    """Render provenance from observed native source fields only."""
    if source in {"bundled", "builtin", "built-in"}:
        return "builtin", f"Hermes {name}"
    if source in {"resources", "bundledResources", "bundled-resource", "plugin"}:
        return "bundledResources", name
    if source in {"user", "git", "config", "owner"}:
        return "useradded", name
    return "unknown", name


def build_extension_snapshot(*, skills: Any, plugins: Any, mcps: Any,
                             skill_catalog: set[str] | None = None) -> dict[str, Any]:
    """Build a closed, secret-free inventory. Missing source claims remain unknown."""
    rows: list[dict[str, Any]] = []
    if not isinstance(skills, list) or len(skills) > 256:
        skills = []
    catalog = skill_catalog or set()
    total = 0
    for group in skills:
        if not isinstance(group, dict) or not isinstance(group.get("names"), list):
            continue
        category = _safe_label(group.get("category"))
        if category is None:
            continue
        for raw_name in group["names"]:
            name = _safe_label(raw_name, maximum=128)
            if name is None:
                continue
            total += 1
            if total > _MAX_SKILLS:
                raise ValueError("native skill inventory exceeded its bound")
            source = "bundledResources" if _slug(name) in catalog else "unknown"
            rows.append({"kind": "skills", "name": name, "category": category,
                         "source": source, "label": name,
                         "editable": False, "removable": False,
                         "actionState": "catalog-install-supported"})
    for kind, values in (("plugins", plugins), ("mcps", mcps)):
        if not isinstance(values, list) or len(values) > 512:
            raise ValueError("native extension inventory exceeded its bound")
        for item in values:
            if not isinstance(item, dict):
                raise ValueError("native extension row was invalid")
            name = _safe_label(item.get("name") if kind == "plugins"
                               else (item.get("key") or item.get("name")), maximum=160)
            if name is None:
                raise ValueError("native extension name was invalid")
            key = _safe_label(item.get("key"), maximum=160) if kind == "plugins" else None
            if kind == "plugins" and key is None:
                raise ValueError("native plugin registry key was invalid")
            source = item.get("source") if isinstance(item.get("source"), str) else "unknown"
            provenance, label = _source_label(source, name)
            row = {"kind": kind, "name": name, "label": label,
                   "source": provenance, "editable": False,
                   "removable": (provenance == "useradded" if kind == "plugins"
                                 else source == "config")}
            if kind == "plugins":
                row.update({"key": key, "version": item.get("version", ""), "state": item.get("status", "unknown"),
                            "updateAvailable": item.get("update_available"),
                            "settings": item.get("settings_schema", []),
                            "settingsRevision": item.get("settings_revision")})
                row["editable"] = bool(item.get("settings_schema")) and provenance == "useradded"
            else:
                row.update({"transport": item.get("transport", "unknown"),
                            "enabled": item.get("enabled") is True,
                            "configRevision": item.get("config_revision")})
            rows.append(row)
    rows.sort(key=lambda item: (item["kind"], item["label"].casefold(), item["name"]))
    canonical = json.dumps(rows, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return {"schema": 1, "readiness": "observed", "revision": hashlib.sha256(canonical.encode()).hexdigest(),
            "items": rows,
            "availableActions": {
                "skills": {"add": True, "edit": False, "remove": False,
                           "reason": ("Pinned Hermes skills.manage supports install only; "
                                      "skill edit/remove has no profile-scoped RPC.")},
                "plugins": {"add": True, "edit": True, "remove": True,
                            "reason": ("Removal permanently deletes the plugin package and Hermes "
                                       "registration; the owner must explicitly confirm it.")},
                "mcps": {"add": True, "edit": False, "remove": True,
                         "reason": ("Pinned Hermes MCP setup supports catalog add/remove; "
                                    "connection edits have no atomic RPC.")},
            }}


def install_jarvis_extensions_admin_routes(app: Any, service: Any) -> None:
    """Install direct owner actions after core ingress has verified Access JWT and Origin."""
    from aiohttp import web
    from .core_client import CoreRpcClient
    from .core_gateway import CoreAcceptedIngressObservation
    from .jarvis_chat import JarvisChatDenied, JarvisChatService, _read_body, _secure_headers
    from .jarvis_dashboard import _native_id, _verified_bundle_inventory

    if not isinstance(service, JarvisChatService) or not isinstance(service.backend, CoreRpcClient):
        raise TypeError("verified Jarvis service and pinned Hermes RPC client required")

    def current_owner(request: Any, *, require_origin: bool = False):
        principal = service._current(request)
        accepted = request.get("core_ingress")
        launch = request.app.get("core_gateway_launch")
        if type(accepted) is not CoreAcceptedIngressObservation or launch is None:
            raise JarvisChatDenied("current protected core ingress is unavailable")
        hostname = getattr(launch.config, "hostname", None)
        allowed_emails = getattr(launch.config, "allowed_emails", frozenset())
        origins = request.headers.getall("Origin", [])
        if (not isinstance(hostname, str) or not isinstance(allowed_emails, (set, frozenset))
                or len(allowed_emails) != 1
                or accepted.principal.email.casefold() != next(iter(allowed_emails)).casefold()
                or (origins != [f"https://{hostname}"] if require_origin
                    else origins not in ([], [f"https://{hostname}"]))
                or request.headers.get("Sec-Fetch-Site") not in (None, "same-origin")):
            raise JarvisChatDenied("single-owner identity or action origin was not verified")
        return principal

    async def inventory() -> dict[str, Any]:
        skills, plugins, mcps = await asyncio.gather(
            service.backend.skills_inventory(), service.backend.list_managed_plugins(),
            service.backend.list_mcp_servers())
        bundle = _verified_bundle_inventory()
        skill_catalog = {_slug(row["name"]) for row in bundle["items"]
                         if row.get("kind") == "skills" and isinstance(row.get("name"), str)}
        return build_extension_snapshot(skills=skills, plugins=plugins, mcps=mcps,
                                        skill_catalog=skill_catalog)

    async def get_extensions(request: Any) -> Any:
        try:
            if request.raw_path != request.path:
                raise web.HTTPNotFound(text="not found", headers=_secure_headers())
            before = current_owner(request)
            payload = await asyncio.wait_for(inventory(), timeout=8.0)
            after = current_owner(request)
            if (after.subject != before.subject or after.core_generation != before.core_generation):
                raise JarvisChatDenied("owner or core generation changed during inventory")
            for item in payload["items"]:
                item["id"] = _native_id(before.subject, before.core_generation,
                                        item["kind"], item["name"])
            return web.json_response(payload, headers=_secure_headers())
        except web.HTTPException:
            raise
        except Exception:
            raise web.HTTPServiceUnavailable(text="current extension inventory is unavailable",
                                             headers=_secure_headers()) from None

    def confirm(body: dict[str, Any], expected: str) -> None:
        if body.get("confirmation") != expected:
            raise web.HTTPBadRequest(text="explicit owner confirmation required", headers=_secure_headers())
        if not isinstance(body.get("idempotency_key"), str) or not _IDEMPOTENCY.fullmatch(body["idempotency_key"]):
            raise web.HTTPBadRequest(text="invalid request", headers=_secure_headers())

    def resolve_item_id(body: dict[str, Any], items: list[dict[str, Any]], kind: str,
                        subject: str, generation: str) -> dict[str, Any]:
        opaque = body.get("item_id")
        if not isinstance(opaque, str):
            raise web.HTTPBadRequest(text="invalid request", headers=_secure_headers())
        row = next((item for item in items if item["kind"] == kind
                    and hmac.compare_digest(opaque, _native_id(subject, generation, kind, item["name"]))), None)
        if row is None:
            raise web.HTTPConflict(text="extension item is stale; refresh before retrying",
                                   headers=_secure_headers())
        return row

    def record_request(body: dict[str, Any], operation: str, subject: str) -> tuple[str, str]:
        idem_hash = hashlib.sha256((hashlib.sha256(subject.encode()).hexdigest() + ":"
                                    + body["idempotency_key"]).encode()).hexdigest()
        safe_body = {key: value for key, value in body.items()
                     if key not in {"confirmation", "idempotency_key"}}
        request_hash = hashlib.sha256(json.dumps([operation, safe_body], sort_keys=True,
                                                  separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()
        return idem_hash, request_hash

    def reserve_action(body: dict[str, Any], operation: str, subject: str) -> str:
        """Reserve once in the existing owner store; unknown outcomes stay pending forever."""
        idem_hash, request_hash = record_request(body, operation, subject)
        owner_hash = hashlib.sha256(subject.encode()).hexdigest()
        with service.store._connect() as db:
            db.execute("CREATE TABLE IF NOT EXISTS jarvis_extension_actions ("
                       "owner_hash TEXT NOT NULL, idem_hash TEXT NOT NULL, request_hash TEXT NOT NULL, "
                       "state TEXT NOT NULL CHECK(state IN ('pending','complete')), created REAL NOT NULL, "
                       "PRIMARY KEY(owner_hash, idem_hash))")
            db.execute("BEGIN IMMEDIATE")
            import time
            db.execute("DELETE FROM jarvis_extension_actions WHERE created<?", (time.time() - 30 * 86400,))
            existing = db.execute("SELECT request_hash,state FROM jarvis_extension_actions "
                                  "WHERE owner_hash=? AND idem_hash=?", (owner_hash, idem_hash)).fetchone()
            if existing is not None:
                db.execute("ROLLBACK")
                if existing["request_hash"] != request_hash:
                    raise web.HTTPConflict(text="idempotency key was already used",
                                           headers=_secure_headers())
                return existing["state"]
            db.execute("INSERT INTO jarvis_extension_actions VALUES(?,?,?,'pending',?)",
                       (owner_hash, idem_hash, request_hash, time.time()))
            db.execute("COMMIT")
        return "new"

    def complete_action(body: dict[str, Any], subject: str) -> None:
        idem_hash, _request_hash = record_request(body, "", subject)
        owner_hash = hashlib.sha256(subject.encode()).hexdigest()
        with service.store._connect() as db:
            db.execute("UPDATE jarvis_extension_actions SET state='complete' "
                       "WHERE owner_hash=? AND idem_hash=?", (owner_hash, idem_hash))

    async def mutate(request: Any, *, operation: str) -> Any:
        try:
            if request.raw_path != request.path:
                raise web.HTTPNotFound(text="not found", headers=_secure_headers())
            before = current_owner(request, require_origin=True)
            body = await _read_body(request, _BODY_FIELDS[operation])
            before_inventory = await asyncio.wait_for(inventory(), timeout=8.0)
            if not isinstance(body.get("revision"), str) or body["revision"] != before_inventory["revision"]:
                raise web.HTTPConflict(text="extension inventory changed; refresh before retrying",
                                       headers=_secure_headers())
            name = body.get("catalog_name") or body.get("identifier")
            target = None
            if operation in {"plugins:edit", "plugins:toggle", "plugins:remove", "mcps:remove"}:
                kind = "plugins" if operation.startswith("plugins:") else "mcps"
                target = resolve_item_id(body, before_inventory["items"], kind,
                                         before.subject, before.core_generation)
                name = target["name"]
            if not isinstance(name, str) or not _KEY.fullmatch(name) or ".." in name.split("/"):
                raise web.HTTPBadRequest(text="invalid request", headers=_secure_headers())
            confirm_words = {"skills:add": "ADD", "plugins:add": "ADD", "plugins:edit": "EDIT",
                             "plugins:toggle": "ENABLE" if body.get("enabled") is True else "DISABLE",
                             "plugins:remove": "DELETE PERMANENTLY",
                             "mcps:add": "ADD", "mcps:remove": "DELETE"}
            confirm(body, f"{confirm_words[operation]} {target['label'] if target else name}")
            if operation == "plugins:edit":
                if target.get("source") != "useradded":
                    raise web.HTTPConflict(text="plugin settings are unavailable for this item",
                                           headers=_secure_headers())
                settings = {field.get("key"): field for field in target.get("settings", [])
                            if isinstance(field, dict)
                            and field.get("type") in {"string", "number", "boolean", "enum"}}
                values = body.get("values")
                if (not isinstance(values, dict) or not values or len(values) > 32
                        or not set(values).issubset(settings)):
                    raise web.HTTPBadRequest(text="invalid plugin settings", headers=_secure_headers())
                for setting_key, value in values.items():
                    field = settings[setting_key]
                    if (not _valid_plugin_setting(field, value)
                            or (field.get("required") is True and value == "")):
                        raise web.HTTPBadRequest(text="invalid plugin setting value", headers=_secure_headers())
            if operation == "plugins:toggle" and (type(body.get("enabled")) is not bool
                                                   or target.get("source") != "useradded"):
                raise web.HTTPConflict(text="this plugin cannot be changed", headers=_secure_headers())
            if operation == "plugins:remove" and (target.get("source") != "useradded"
                                                    or target.get("removable") is not True):
                raise web.HTTPConflict(text="only an owner-added plugin can be permanently removed",
                                       headers=_secure_headers())
            if operation == "mcps:remove" and target.get("source") != "useradded":
                raise web.HTTPConflict(text="only an owner-configured MCP server can be removed",
                                       headers=_secure_headers())
            reserved = reserve_action(body, operation, before.subject)
            if reserved != "new":
                return web.json_response({"status": reserved}, status=202 if reserved == "pending" else 200,
                                         headers=_secure_headers())
            if operation == "skills:add":
                result = await service.backend.install_skill(body["identifier"])
                reload_result = await service.backend.reload_skills()
                result["reload"] = reload_result
                status = 201
            elif operation == "plugins:add":
                result = await service.backend.install_plugin(body["catalog_name"])
                status = 201
            elif operation == "plugins:edit":
                result = await service.backend.update_plugin_settings(target["key"], body["values"])
                status = 200
            elif operation == "plugins:toggle":
                result = await service.backend.set_plugin_enabled(target["key"], body["enabled"])
                status = 200
            elif operation == "plugins:remove":
                result = await service.backend.remove_plugin(target["name"])
                status = 200
            elif operation == "mcps:add":
                result = await service.backend.add_catalog_mcp(body["catalog_name"])
                status = 201
            elif operation == "mcps:remove":
                row = target
                result = await service.backend.remove_mcp(row["name"])
                status = 200
            else:
                raise web.HTTPNotFound(text="not found", headers=_secure_headers())
            after = current_owner(request, require_origin=True)
            if after.subject != before.subject or after.core_generation != before.core_generation:
                return web.json_response({"status": "pending", "reason": "owner or core generation changed"},
                                         status=202, headers=_secure_headers())
            complete_action(body, before.subject)
            return web.json_response({"status": "applied", "result": result}, status=status,
                                     headers=_secure_headers())
        except web.HTTPException:
            raise
        except JarvisChatDenied:
            raise web.HTTPConflict(text="extension action is unavailable or stale",
                                   headers=_secure_headers()) from None
        except Exception:
            return web.json_response({"status": "pending"}, status=202, headers=_secure_headers())

    async def skills_add(request: Any) -> Any:
        return await mutate(request, operation="skills:add")

    async def plugins_add(request: Any) -> Any:
        return await mutate(request, operation="plugins:add")

    async def plugins_edit(request: Any) -> Any:
        return await mutate(request, operation="plugins:edit")

    async def plugins_toggle(request: Any) -> Any:
        return await mutate(request, operation="plugins:toggle")

    async def plugins_remove(request: Any) -> Any:
        return await mutate(request, operation="plugins:remove")

    async def mcps_add(request: Any) -> Any:
        return await mutate(request, operation="mcps:add")

    async def mcps_remove(request: Any) -> Any:
        return await mutate(request, operation="mcps:remove")

    app.router.add_get("/chat/api/extensions", get_extensions, allow_head=False)
    for path, handler in (
        ("/chat/api/extensions/skills/add", skills_add),
        ("/chat/api/extensions/plugins/add", plugins_add),
        ("/chat/api/extensions/plugins/edit", plugins_edit),
        ("/chat/api/extensions/plugins/toggle", plugins_toggle),
        ("/chat/api/extensions/plugins/remove", plugins_remove),
        ("/chat/api/extensions/mcps/add", mcps_add),
        ("/chat/api/extensions/mcps/remove", mcps_remove),
    ):
        app.router.add_post(path, handler)


_BODY_FIELDS = {
    "skills:add": {"identifier", "confirmation", "idempotency_key", "revision"},
    "plugins:add": {"catalog_name", "confirmation", "idempotency_key", "revision"},
    "plugins:edit": {"item_id", "values", "confirmation", "idempotency_key", "revision"},
    "plugins:toggle": {"item_id", "enabled", "confirmation", "idempotency_key", "revision"},
    "plugins:remove": {"item_id", "confirmation", "idempotency_key", "revision"},
    "mcps:add": {"catalog_name", "confirmation", "idempotency_key", "revision"},
    "mcps:remove": {"item_id", "confirmation", "idempotency_key", "revision"},
}
