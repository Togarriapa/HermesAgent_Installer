"""Owner-operated extension management through pinned RPCs and native source custody.

Only catalog setup actions, upstream plugin settings/toggle/remove and fixed native
skill source edit/archive operations are exposed. There is no generic RPC or shell proxy.
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
    ("POST", "/chat/api/extensions/skills/read"),
    ("POST", "/chat/api/extensions/skills/edit"),
    ("POST", "/chat/api/extensions/skills/remove"),
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
                             native_skill_files: Any = (),
                             skill_catalog: set[str] | None = None) -> dict[str, Any]:
    """Build a closed, secret-free inventory. Missing source claims remain unknown."""
    rows: list[dict[str, Any]] = []
    if not isinstance(skills, list) or len(skills) > 256:
        skills = []
    catalog = skill_catalog or set()
    total = 0
    skill_categories: dict[str, str] = {}
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
            skill_categories[_slug(name)] = category
            rows.append({"kind": "skills", "name": name, "category": category,
                         "source": source, "label": name,
                         "editable": False, "removable": False,
                         "actionState": "catalog-install-supported"})
    if not isinstance(native_skill_files, (list, tuple)) or len(native_skill_files) > _MAX_SKILLS:
        raise ValueError("native skill source inventory exceeded its bound")
    seen_skill_ids: set[str] = set()
    for descriptor in native_skill_files:
        skill_id = getattr(descriptor, "skill_id", None)
        display_name = getattr(descriptor, "display_name", None)
        source_kind = getattr(descriptor, "source", None)
        sha256 = getattr(descriptor, "sha256", None)
        editable = getattr(descriptor, "editable", None)
        if (not isinstance(skill_id, str) or re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", skill_id) is None
                or skill_id in seen_skill_ids or not isinstance(display_name, str)
                or source_kind not in {"pinned", "owner-added"}
                or not isinstance(sha256, str) or re.fullmatch(r"[0-9a-f]{64}", sha256) is None
                or type(editable) is not bool or editable != (source_kind == "owner-added")):
            raise ValueError("native skill source row was invalid")
        seen_skill_ids.add(skill_id)
        rows = [row for row in rows if not (row.get("kind") == "skills"
                                             and _slug(row.get("name", "")) == skill_id)]
        loaded_name = next((name for group in skills if isinstance(group, dict)
                            for name in group.get("names", []) if isinstance(name, str)
                            and _slug(name) == skill_id), None)
        source = ("useradded" if source_kind == "owner-added" else
                  "bundledResources" if _slug(display_name) in catalog or skill_id in catalog else "builtin")
        label = f"Hermes {display_name}" if source == "builtin" else display_name
        rows.append({"kind": "skills", "name": skill_id, "label": label,
                     "category": skill_categories.get(skill_id, "native"), "source": source,
                     "editable": editable, "removable": editable, "sha256": sha256,
                     "loaded": loaded_name is not None,
                     "actionState": "loaded" if loaded_name is not None else "source-present-not-loaded"})
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
                "skills": {"add": True, "edit": True, "remove": True,
                           "reason": "Owner-added skill files use the root-journaled native source adapter; pinned skills are read-only."},
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

    def access_jwt(request: Any) -> str:
        values = request.headers.getall("Cf-Access-Jwt-Assertion", [])
        if (len(values) != 1 or not isinstance(values[0], str) or not 1 <= len(values[0]) <= 16_384
                or not values[0].isascii()):
            raise JarvisChatDenied("current Access token is unavailable")
        return values[0]

    def skill_provider(request: Any) -> Any:
        from .jarvis_profiles_admin import CoreGatewayProfileAdminProvider
        launch = request.app.get("core_gateway_launch")
        config = getattr(launch, "config", None)
        try:
            return CoreGatewayProfileAdminProvider(config)
        except Exception:
            raise JarvisChatDenied("current native skill source adapter is unavailable") from None

    async def inventory(request: Any) -> dict[str, Any]:
        skills, plugins, mcps = await asyncio.gather(
            service.backend.skills_inventory(), service.backend.list_managed_plugins(),
            service.backend.list_mcp_servers())
        accepted = request.get("core_ingress")
        principal = current_owner(request)
        skill_files = skill_provider(request).list_skills(core_generation=principal.core_generation,
            access_jwt=access_jwt(request), accepted_ingress=accepted)
        bundle = _verified_bundle_inventory()
        skill_catalog = {_slug(row["name"]) for row in bundle["items"]
                         if row.get("kind") == "skills" and isinstance(row.get("name"), str)}
        return build_extension_snapshot(skills=skills, plugins=plugins, mcps=mcps,
                                        native_skill_files=skill_files,
                                        skill_catalog=skill_catalog)

    async def get_extensions(request: Any) -> Any:
        try:
            if request.raw_path != request.path:
                raise web.HTTPNotFound(text="not found", headers=_secure_headers())
            before = current_owner(request)
            payload = await asyncio.wait_for(inventory(request), timeout=8.0)
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
            before_inventory = await asyncio.wait_for(inventory(request), timeout=8.0)
            if not isinstance(body.get("revision"), str) or body["revision"] != before_inventory["revision"]:
                raise web.HTTPConflict(text="extension inventory changed; refresh before retrying",
                                       headers=_secure_headers())
            name = body.get("catalog_name") or body.get("identifier")
            target = None
            if operation in {"skills:edit", "skills:remove", "plugins:edit", "plugins:toggle", "plugins:remove", "mcps:remove"}:
                kind = ("skills" if operation.startswith("skills:") else
                        "plugins" if operation.startswith("plugins:") else "mcps")
                target = resolve_item_id(body, before_inventory["items"], kind,
                                         before.subject, before.core_generation)
                name = target["name"]
            if not isinstance(name, str) or not _KEY.fullmatch(name) or ".." in name.split("/"):
                raise web.HTTPBadRequest(text="invalid request", headers=_secure_headers())
            confirm_words = {"skills:add": "ADD", "skills:edit": "EDIT", "skills:remove": "ARCHIVE (RECOVERABLE)",
                             "plugins:add": "ADD", "plugins:edit": "EDIT",
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
            if operation in {"skills:edit", "skills:remove"}:
                if target.get("source") != "useradded" or target.get("editable") is not True:
                    raise web.HTTPConflict(text="pinned Hermes and bundled skills are read-only",
                                           headers=_secure_headers())
                current_file = skill_provider(request).read_skill(core_generation=before.core_generation,
                    skill_id=target["name"], access_jwt=access_jwt(request),
                    accepted_ingress=request.get("core_ingress"))
                if current_file.source != "owner-added" or current_file.sha256 != target.get("sha256"):
                    raise web.HTTPConflict(text="skill source changed; refresh before editing",
                                           headers=_secure_headers())
                if operation == "skills:edit":
                    content = body.get("content")
                    try:
                        encoded_content = content.encode("utf-8", "strict") if isinstance(content, str) else b""
                    except UnicodeError:
                        encoded_content = b"x" * (64 * 1024 + 1)
                    if (not isinstance(content, str) or len(encoded_content) > 64 * 1024
                            or "\x00" in content or any(ord(char) < 0x20 and char not in "\n\r\t" for char in content)):
                        raise web.HTTPBadRequest(text="invalid skill content", headers=_secure_headers())
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
            elif operation == "skills:edit":
                write = skill_provider(request).write_skill(core_generation=before.core_generation,
                    skill_id=target["name"], expected_sha256=current_file.sha256,
                    content=body["content"], idempotency_key=body["idempotency_key"],
                    access_jwt=access_jwt(request), accepted_ingress=request.get("core_ingress"))
                if write.state == "conflict":
                    complete_action(body, before.subject)
                    raise web.HTTPConflict(text="skill source changed; refresh and retry",
                                           headers=_secure_headers())
                if (write.state != "active" or write.effective_readback is not True
                        or write.sha256 != hashlib.sha256(body["content"].encode("utf-8")).hexdigest()
                        or not isinstance(write.source_generation, str)
                        or not re.fullmatch(r"[0-9a-f]{64}", write.source_generation)
                        or not isinstance(write.recovery_id, str)
                        or not re.fullmatch(r"[A-Za-z0-9_-]{16,96}", write.recovery_id)):
                    return web.json_response({"status": "pending", "reason": "skill source was saved but active readback is pending"},
                                             status=202, headers=_secure_headers())
                result = {"state": write.state, "sha256": write.sha256,
                          "sourceGeneration": write.source_generation,
                          "reload": await service.backend.reload_skills()}
                status = 200
            elif operation == "skills:remove":
                archived = skill_provider(request).archive_skill(core_generation=before.core_generation,
                    skill_id=target["name"], expected_sha256=current_file.sha256,
                    idempotency_key=body["idempotency_key"], access_jwt=access_jwt(request),
                    accepted_ingress=request.get("core_ingress"))
                if archived.state == "conflict":
                    complete_action(body, before.subject)
                    raise web.HTTPConflict(text="skill source changed; refresh and retry",
                                           headers=_secure_headers())
                if (archived.state != "archived" or archived.effective_readback is not True
                        or archived.sha256 != current_file.sha256
                        or not isinstance(archived.recovery_id, str)
                        or not re.fullmatch(r"[A-Za-z0-9_-]{16,96}", archived.recovery_id)):
                    return web.json_response({"status": "pending", "reason": "skill archive outcome is pending"},
                                             status=202, headers=_secure_headers())
                reload_result = await service.backend.reload_skills()
                result = {"state": archived.state, "recoveryId": archived.recovery_id,
                          "sourceGeneration": archived.source_generation,
                          "reload": reload_result, "effectiveReadback": archived.effective_readback}
                status = 200
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

    async def skills_edit(request: Any) -> Any:
        return await mutate(request, operation="skills:edit")

    async def skills_remove(request: Any) -> Any:
        return await mutate(request, operation="skills:remove")

    async def skills_read(request: Any) -> Any:
        from aiohttp import web
        try:
            if request.raw_path != request.path:
                raise web.HTTPNotFound(text="not found", headers=_secure_headers())
            before = current_owner(request, require_origin=True)
            body = await _read_body(request, _BODY_FIELDS["skills:read"])
            snapshot = await asyncio.wait_for(inventory(request), timeout=8.0)
            if body.get("revision") != snapshot["revision"]:
                raise web.HTTPConflict(text="extension inventory changed; refresh before reading",
                                       headers=_secure_headers())
            row = resolve_item_id(body, snapshot["items"], "skills", before.subject, before.core_generation)
            if not row.get("editable"):
                raise web.HTTPConflict(text="only owner-added skill sources can be edited",
                                       headers=_secure_headers())
            value = skill_provider(request).read_skill(core_generation=before.core_generation,
                skill_id=row["name"], access_jwt=access_jwt(request),
                accepted_ingress=request.get("core_ingress"))
            after = current_owner(request, require_origin=True)
            if after.subject != before.subject or after.core_generation != before.core_generation:
                raise JarvisChatDenied("owner or core generation changed during skill read")
            return web.json_response({"name": value.skill_id, "content": value.content,
                "sha256": value.sha256, "sourceGeneration": value.source_generation,
                "effective": value.effective}, headers=_secure_headers())
        except web.HTTPException:
            raise
        except Exception:
            raise web.HTTPServiceUnavailable(text="current native skill source is unavailable",
                                             headers=_secure_headers()) from None

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
        ("/chat/api/extensions/skills/read", skills_read),
        ("/chat/api/extensions/skills/edit", skills_edit),
        ("/chat/api/extensions/skills/remove", skills_remove),
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
    "skills:read": {"item_id", "revision"},
    "skills:edit": {"item_id", "content", "confirmation", "idempotency_key", "revision"},
    "skills:remove": {"item_id", "confirmation", "idempotency_key", "revision"},
    "plugins:add": {"catalog_name", "confirmation", "idempotency_key", "revision"},
    "plugins:edit": {"item_id", "values", "confirmation", "idempotency_key", "revision"},
    "plugins:toggle": {"item_id", "enabled", "confirmation", "idempotency_key", "revision"},
    "plugins:remove": {"item_id", "confirmation", "idempotency_key", "revision"},
    "mcps:add": {"catalog_name", "confirmation", "idempotency_key", "revision"},
    "mcps:remove": {"item_id", "confirmation", "idempotency_key", "revision"},
}
