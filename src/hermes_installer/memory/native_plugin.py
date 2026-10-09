"""Source template staged as plugins/memory/<provider>/__init__.py in guarded HERMES_HOME."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
from typing import Any

try:
    from agent.memory_provider import MemoryProvider
except ImportError:  # only permits installer-side contract imports; never a runtime fallback
    class MemoryProvider:  # type: ignore[no-redef]
        pass

_PROVIDERS = {"openviking", "claude-mem", "agentmemory"}


class HermesMemoryProvider(MemoryProvider):
    """Native provider; all writes queue through the root-owned broker."""

    def __init__(self, authority: Any = None):
        self._authority = authority
        self._hermes_home: Path | None = None
        self._last_hook_status = "not_initialized"

    @property
    def name(self) -> str:
        name = Path(__file__).parent.name
        return name if name in _PROVIDERS else "unconfigured-memory-provider"

    def _client(self) -> Any:
        if self._authority is None:
            from hermes_installer.authority.client import AuthorityClient
            self._authority = AuthorityClient.for_current_process()
        return self._authority

    def is_available(self) -> bool:
        if self.name not in _PROVIDERS:
            return False
        try:
            client = self._client()
            return all(callable(getattr(client, method, None))
                       for method in ("context", "authorize_effect", "memory_request"))
        except Exception:
            return False

    def unavailable_reason(self) -> str:
        return "The fixed root-owned memory broker or enrolled provider target is unavailable."

    def initialize(self, session_id: str, **kwargs: Any) -> None:
        if self.name not in _PROVIDERS:
            raise RuntimeError("provider is not installed under a supported native name")
        home = kwargs.get("hermes_home")
        if not isinstance(home, str) or not home:
            raise PermissionError("guarded profile HERMES_HOME is required")
        path = Path(home)
        if path.is_symlink() or not path.is_dir():
            raise PermissionError("guarded profile HERMES_HOME is invalid")
        self._hermes_home = path.resolve(strict=True)
        if not self.is_available():
            raise RuntimeError(self.unavailable_reason())
        self._last_hook_status = "ready"

    def get_config_schema(self) -> list[dict[str, Any]]:
        return []

    def save_config(self, values: dict[str, Any], hermes_home: str) -> None:
        if values:
            raise ValueError("provider credentials and endpoints are enrolled by the host")

    def get_tool_schemas(self) -> list[dict[str, Any]]:
        return [{"name": "memory_search",
                 "description": "Search this profile's authorized persistent memory.",
                 "parameters": {"type": "object",
                     "properties": {"query": {"type": "string"},
                                    "limit": {"type": "integer", "minimum": 1, "maximum": 20}},
                     "required": ["query"], "additionalProperties": False}}]

    def _context(self, purpose: str, intent: str, operation: str,
                 body: bytes) -> tuple[Any, Any]:
        client = self._client()
        context = client.context(
            purpose=purpose, intent=intent, operation=operation,
            final_payload_digest=hashlib.sha256(body).hexdigest(), lease_seconds=30)
        return client, context

    @staticmethod
    def _decode(response: Any, action: str) -> dict[str, Any]:
        if not 200 <= int(response.status) < 300:
            raise RuntimeError(f"memory broker {action} denied or unavailable (status {response.status})")
        result = json.loads(response.body.decode("utf-8"))
        if not isinstance(result, dict):
            raise RuntimeError("memory broker returned an invalid object")
        return result

    def _effect(self, action: str, capability: str, payload: dict[str, Any],
                purpose: str, timeout: float = 1.0) -> dict[str, Any]:
        if action not in {"doctor", "extract", "embed", "capture", "search", "export", "delete"}:
            raise ValueError("unsupported fixed memory action")
        target = f"memory:{self.name}:{action}"
        body = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
        client, context = self._context(
            purpose, f"hermes-memory-{action}", f"memory.{action}", body)
        grant = client.authorize_effect(context, capability=capability, target=target, request_digest=hashlib.sha256(body).hexdigest())
        response = client.memory_request(grant, target=target,
            request_digest=hashlib.sha256(body).hexdigest(), payload=body, timeout=timeout)
        result = self._decode(response, action)
        if "records" in result:
            profile, namespace = getattr(context, "profile_id", None), getattr(context, "namespace_id", None)
            rows = result.get("records")
            if not isinstance(rows, list):
                raise RuntimeError("memory broker returned invalid records")
            if any(not isinstance(item, dict) or item.get("profile") != profile
                   or item.get("namespace") != namespace for item in rows):
                raise PermissionError("memory broker returned a record outside signed host scope")
        return result

    def sync_turn(self, user_content: str, assistant_content: str, *, session_id: str = "",
                  messages: list[dict[str, Any]] | None = None,
                  turn_author: dict[str, Any] | None = None) -> None:
        # These hook parameters are worker-side text, not a root-observed
        # whole-turn receipt. Keep capture unavailable until native custody
        # provides a one-use source event handle with verified ancestry.
        self._last_hook_status = "unavailable:source_event_missing"

    def prefetch(self, query: str, *, session_id: str = "") -> str:
        query = query[:4096]
        if not query.strip():
            return ""
        try:
            result = self._effect("search", "memory-retrieval",
                {"schema": 1, "query": query, "limit": 8, "session_id": session_id[:256]},
                "memory-retrieval", timeout=1.0)
            rows = result.get("records", [])
            if not isinstance(rows, list):
                return ""
            return "\n".join(item["text"][:1200] for item in rows[:8]
                              if isinstance(item.get("text"), str))
        except Exception:
            return ""

    def handle_tool_call(self, tool_name: str, args: dict[str, Any], **kwargs: Any) -> str:
        if tool_name != "memory_search":
            raise ValueError("unsupported memory tool")
        query, limit = args.get("query"), args.get("limit", 10)
        if not isinstance(query, str) or not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 20:
            raise ValueError("invalid memory search arguments")
        result = self._effect("search", "memory-retrieval",
            {"schema": 1, "query": query[:4096], "limit": limit}, "memory-retrieval", timeout=2.0)
        return json.dumps(result, ensure_ascii=False, sort_keys=True)

    def on_memory_write(self, action: str, target: str, content: str,
                        metadata: dict[str, Any] | None = None) -> None:
        # Target/content/metadata are caller-controlled native hook arguments;
        # they do not carry the root-issued source event receipt needed to
        # authorize capture or private extraction.
        self._last_hook_status = "unavailable:source_event_missing"

    def backup_paths(self) -> list[str]:
        # Broker-owned data is exported by the installer lifecycle manager.
        return []

    def shutdown(self) -> None:
        self._authority = None
        self._hermes_home = None


def register(ctx: Any) -> None:
    """Exact registration hook supported by pinned Hermes memory plugin loader."""
    ctx.register_memory_provider(HermesMemoryProvider())
