"""Fresh Authentik System identity, hierarchy and recipient checks (HI03).

The caller cannot provide membership labels. This adapter performs bounded GETs
through a protected authority process for every decision, resolves a complete
direct/indirect group graph, rejects cycles/incomplete pages and never caches an
allow. Targets and group IDs are supplied only by root-owned enrollment config.
"""
from __future__ import annotations

import json
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Protocol

from .service import AuthorityPolicy, EffectRule, PrincipalBinding
from .types import AuthorityDenied, HostContext, Sensitivity, canonical_digest

MAX_BODY = 1_048_576
MAX_GROUPS = 256
MAX_GROUP_DEPTH = 64
_GROUP_ID_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_")


@dataclass(frozen=True, slots=True)
class AuthentikResponse:
    status: int
    body: bytes
    headers: Mapping[str, str]


class AuthentikTransport(Protocol):
    def get(self, path: str, *, bearer_token: str, timeout: float) -> AuthentikResponse: ...


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class TLSAuthentikTransport:
    """Fixed-origin TLS GET transport with no redirects or unbounded bodies."""

    def __init__(self, base_url: str, *, timeout: float = 4.0, max_body: int = MAX_BODY):
        parsed = urllib.parse.urlsplit(base_url)
        if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
                or parsed.query or parsed.fragment):
            raise ValueError("Authentik authority must be a fixed HTTPS origin")
        if not 0.1 <= timeout <= 9 or not 1 <= max_body <= MAX_BODY:
            raise ValueError("Authentik transport bounds are invalid")
        self.origin = f"https://{parsed.netloc}{parsed.path.rstrip('/')}"
        self.timeout = timeout
        self.max_body = max_body
        self._opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), _NoRedirect(),
            urllib.request.HTTPSHandler(context=ssl.create_default_context()),
        )

    def get(self, path: str, *, bearer_token: str, timeout: float) -> AuthentikResponse:
        if not path.startswith("/api/v3/") or ".." in path or not bearer_token or "\r" in bearer_token or "\n" in bearer_token:
            raise AuthorityDenied("authentik.request", "fixed Authentik request is invalid")
        if not 0 < timeout <= self.timeout:
            raise AuthorityDenied("authentik.deadline", "Authentik read deadline is invalid")
        request = urllib.request.Request(
            self.origin + path,
            headers={"Accept": "application/json", "Authorization": f"Bearer {bearer_token}"},
            method="GET",
        )
        try:
            with self._opener.open(request, timeout=timeout) as response:
                if response.geturl() != self.origin + path:
                    raise AuthorityDenied("authentik.redirect", "Authentik authority redirected")
                body = response.read(self.max_body + 1)
                result = AuthentikResponse(response.status, body,
                                           {key.casefold(): value for key, value in response.headers.items()})
        except urllib.error.HTTPError as exc:
            # Never include request headers, response bodies or token-bearing URLs.
            raise AuthorityDenied("authentik.http", f"Authentik returned HTTP {exc.code}") from None
        except AuthorityDenied:
            raise
        except Exception:
            raise AuthorityDenied("authentik.unavailable", "fresh Authentik authority is unavailable") from None
        if result.status != 200 or len(result.body) > self.max_body:
            raise AuthorityDenied("authentik.response", "Authentik response is unsuccessful or oversized")
        if "json" not in result.headers.get("content-type", "").casefold():
            raise AuthorityDenied("authentik.response", "Authentik response is not JSON")
        return result


@dataclass(frozen=True, slots=True)
class PrincipalIdentity:
    username: str
    email: str
    subject_id: str | None = None

    def __post_init__(self) -> None:
        if (not self.username or not self.email or "@" not in self.email
                or self.subject_id is not None and (not isinstance(self.subject_id, str) or not self.subject_id)):
            raise ValueError("expected Authentik principal identity is incomplete")


@dataclass(frozen=True, slots=True)
class AuthentikEnrollment:
    """Protected configuration; values are immutable target/group identifiers."""

    principal_identities: Mapping[str, PrincipalIdentity]
    system_group_id: str
    write_group_by_target: Mapping[str, str]
    recipient_group_id: str
    recipient_email_by_id: Mapping[str, str]
    allowed_effects: frozenset[tuple[str, str]]
    public_profile_purposes: frozenset[tuple[str, str]] = frozenset()
    max_sensitivity_by_capability: Mapping[str, Sensitivity] | None = None
    policy_revision: str = "authentik-policy-v1"

    def __post_init__(self) -> None:
        if not self.system_group_id or not self.recipient_group_id or not self.policy_revision:
            raise ValueError("System and delivery-recipient group enrollment is required")
        if not self.allowed_effects:
            raise ValueError("fixed effect enrollment is required")
        if self.max_sensitivity_by_capability is None:
            object.__setattr__(self, "max_sensitivity_by_capability", {})
        if any("@" not in email for email in self.recipient_email_by_id.values()):
            raise ValueError("recipient directory entries must be email identities")


class AuthentikSystemPolicy(AuthorityPolicy):
    """AuthorityPolicy that freshly authenticates actor and delivery recipient."""

    def __init__(self, *, enrollment: AuthentikEnrollment,
                 actor_token: Callable[[str], str | None],
                 directory_token: Callable[[], str | None],
                 transport: AuthentikTransport,
                 timeout: float = 8.0):
        if not 0 < timeout <= 9:
            raise ValueError("Authentik aggregate lookup deadline must be at most nine seconds")
        self.enrollment = enrollment
        self.actor_token = actor_token
        self.directory_token = directory_token
        self.transport = transport
        self.timeout = timeout
        self.revision = enrollment.policy_revision
        self._deadline = threading.local()
        self._clock = time.monotonic

    def classify(self, *, purpose: str, intent: str,
                 source_contexts: tuple[HostContext, ...],
                 binding: PrincipalBinding) -> tuple[Sensitivity, str]:
        if source_contexts:
            ordered = (Sensitivity.PUBLIC, Sensitivity.PRIVATE, Sensitivity.CONFIDENTIAL, Sensitivity.UNKNOWN)
            sensitivity = max((item.sensitivity for item in source_contexts), key=ordered.index)
            lineage_hash = canonical_digest(sorted(_ctx_digest(item) for item in source_contexts))
            return sensitivity, lineage_hash
        # Purpose names are request metadata, not proof that a payload was
        # cleared for a public recipient. Empty lineage remains unknown; a
        # separate host-reviewed source/consent issuer must mint public data.
        return Sensitivity.UNKNOWN, canonical_digest({"unknown": True, "purpose": purpose, "policy": self.revision})

    def allow_effect(self, *, context: HostContext, rule: EffectRule,
                     request_digest: str, retry_index: int) -> bool:
        key = (rule.capability, rule.target)
        if key not in self.enrollment.allowed_effects:
            return False
        maximum = self.enrollment.max_sensitivity_by_capability.get(rule.capability, Sensitivity.PRIVATE)
        ordering = (Sensitivity.PUBLIC, Sensitivity.PRIVATE, Sensitivity.CONFIDENTIAL, Sensitivity.UNKNOWN)
        # The local root broker may safely handle unknown input: a pinned
        # artifact fetch has no user payload, and process I/O is contained by
        # the enrolled profile. Unknown/private input is still forbidden from
        # leaving the host or reaching an enrolled recipient.
        local_operations = frozenset({
            "process.start", "process.status", "process.read", "process.write",
            "process.stop", "artifact.fetch", "package.install",
            "memory.request", "memory.doctor", "memory.capture", "memory.search",
            "memory.export", "memory.delete", "memory.extract", "memory.embed",
            "memory.backup", "memory.restore", "memory.enqueue", "memory.result",
        })
        if (context.sensitivity is Sensitivity.UNKNOWN and rule.operation not in local_operations
                or ordering.index(context.sensitivity) > ordering.index(maximum)
                and not (context.sensitivity is Sensitivity.UNKNOWN and rule.operation in local_operations)):
            return False
        self._deadline.value = self._clock() + self.timeout
        try:
            # Authentik System is an authorization source for protected
            # homelab changes and alarms, not a prerequisite for local
            # bootstrap/runtime operations whose authority comes from the
            # root-enrolled SO_PEERCRED UID/profile binding and fixed rule.
            groups = None
            if rule.operation in {"host.write", "alert.deliver"}:
                groups = self._authorize_actor(context)
            if rule.operation == "host.write":
                required = self.enrollment.write_group_by_target.get(rule.target)
                if not required or groups is None or required not in groups:
                    raise AuthorityDenied("authentik.write-membership", "principal is not authorized for this enrolled host target")
            if rule.operation == "alert.deliver":
                self._authorize_recipient(rule.recipient)
            return True
        finally:
            self._deadline.value = None

    def _authorize_actor(self, context: HostContext) -> frozenset[str]:
        expected = self.enrollment.principal_identities.get(context.principal_id)
        token = self.actor_token(context.principal_id)
        if expected is None or not token:
            raise AuthorityDenied("authentik.principal", "fresh enrolled actor identity is unavailable")
        actor = self._current_user(token)
        if (actor["username"].casefold() != expected.username.casefold()
                or actor["email"].casefold() != expected.email.casefold()
                or expected.subject_id is not None and actor["subject"] != expected.subject_id):
            raise AuthorityDenied("authentik.mismatch", "fresh Authentik subject does not match the enrolled principal")
        groups = self._complete_groups(token, actor["groups"])
        if self.enrollment.system_group_id not in groups:
            raise AuthorityDenied("authentik.system-membership", "principal is not currently in the required System hierarchy")
        return groups

    def _authorize_recipient(self, recipient_id: str | None) -> None:
        if not recipient_id or recipient_id not in self.enrollment.recipient_email_by_id:
            raise AuthorityDenied("authentik.recipient", "delivery recipient is not enrolled")
        email = self.enrollment.recipient_email_by_id[recipient_id]
        token = self.directory_token()
        if not token:
            raise AuthorityDenied("authentik.recipient", "fresh recipient directory authority is unavailable")
        query = urllib.parse.urlencode({"email": email, "include_groups": "true", "page": 1, "page_size": 2})
        result = self._json(token, f"/api/v3/core/users/?{query}")
        if not isinstance(result, dict) or not isinstance(result.get("results"), list):
            raise AuthorityDenied("authentik.recipient", "recipient directory response is incomplete")
        pagination = result.get("pagination")
        if not isinstance(pagination, dict) or pagination.get("count") != 1 or pagination.get("next") not in (None, "") or len(result["results"]) != 1:
            raise AuthorityDenied("authentik.recipient", "recipient identity is missing or ambiguous")
        user = result["results"][0]
        if (not isinstance(user, dict) or user.get("is_active") is not True
                or not isinstance(user.get("email"), str) or user["email"].casefold() != email.casefold()):
            raise AuthorityDenied("authentik.recipient", "recipient identity is inactive or inconsistent")
        groups = self._complete_groups(token, _group_refs(user.get("groups")))
        if self.enrollment.system_group_id not in groups or self.enrollment.recipient_group_id not in groups:
            raise AuthorityDenied("authentik.recipient", "recipient no longer has delivery authorization")

    def _current_user(self, token: str) -> dict[str, Any]:
        result = self._json(token, "/api/v3/core/users/me/")
        if not isinstance(result, dict):
            raise AuthorityDenied("authentik.principal", "current user response is incomplete")
        candidates: list[dict[str, Any]] = []
        if isinstance(result.get("user"), dict):
            candidates.append(result["user"])
        elif isinstance(result.get("users"), list):
            candidates.extend(item for item in result["users"] if isinstance(item, dict) and item.get("is_current") is True)
        if not candidates and isinstance(result.get("users"), list) and len(result["users"]) == 1 and isinstance(result["users"][0], dict):
            candidates.append(result["users"][0])
        if len(candidates) != 1:
            raise AuthorityDenied("authentik.principal", "current Authentik subject is missing or ambiguous")
        user = candidates[0]
        username, email = user.get("username"), user.get("email")
        if (user.get("is_active") is not True or not isinstance(username, str) or not username
                or not isinstance(email, str) or "@" not in email
                or type(user.get("pk")) not in (str, int)):
            raise AuthorityDenied("authentik.principal", "current Authentik subject is inactive or malformed")
        return {"username": username, "email": email, "subject": str(user["pk"]), "groups": _group_refs(user.get("groups"))}

    def _complete_groups(self, token: str, direct: tuple[str, ...]) -> frozenset[str]:
        if len(direct) > MAX_GROUPS:
            raise AuthorityDenied("authentik.groups", "direct group membership exceeds its bound")
        pending = [(group_id, frozenset(), 1) for group_id in direct]
        seen: set[str] = set()
        while pending:
            group_id, ancestors, depth = pending.pop()
            if depth > MAX_GROUP_DEPTH:
                raise AuthorityDenied("authentik.groups", "group hierarchy exceeds its depth bound")
            if group_id in ancestors:
                raise AuthorityDenied("authentik.cycle", "Authentik group hierarchy contains a cycle")
            if group_id in seen:
                continue
            if len(seen) >= MAX_GROUPS:
                raise AuthorityDenied("authentik.groups", "group hierarchy exceeds its bound")
            seen.add(group_id)
            group = self._json(token, f"/api/v3/core/groups/{urllib.parse.quote(group_id, safe='')}/")
            if not isinstance(group, dict):
                raise AuthorityDenied("authentik.groups", "group hierarchy response is incomplete")
            response_id = group.get("pk", group.get("group_uuid"))
            if response_id is not None and str(response_id) != group_id:
                raise AuthorityDenied("authentik.groups", "group identity differs from the requested hierarchy node")
            if "parents" in group:
                parents = _group_refs(group["parents"])
            elif "parent" in group:
                parent = group["parent"]
                parents = () if parent is None else _group_refs([parent])
            else:
                raise AuthorityDenied("authentik.groups", "server group hierarchy semantics are unsupported")
            if len(seen) + len(pending) + len(parents) > MAX_GROUPS:
                raise AuthorityDenied("authentik.groups", "group hierarchy exceeds its bound")
            path = ancestors | {group_id}
            if any(parent in path for parent in parents):
                raise AuthorityDenied("authentik.cycle", "Authentik group hierarchy contains a cycle")
            pending.extend((parent, path, depth + 1) for parent in parents if parent not in seen)
        return frozenset(seen)

    def _json(self, token: str, path: str) -> Any:
        deadline = getattr(self._deadline, "value", None)
        remaining = self.timeout if deadline is None else deadline - self._clock()
        if remaining <= 0:
            raise AuthorityDenied("authentik.deadline", "complete Authentik authority check exceeded its deadline")
        response = self.transport.get(path, bearer_token=token, timeout=min(self.timeout, remaining))
        if response.status != 200 or len(response.body) > MAX_BODY:
            raise AuthorityDenied("authentik.response", "fresh Authentik response is unsuccessful or oversized")
        if "json" not in response.headers.get("content-type", "").casefold():
            raise AuthorityDenied("authentik.response", "fresh Authentik response is not JSON")
        try:
            return json.loads(response.body.decode("utf-8"), object_pairs_hook=_unique_object)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
            raise AuthorityDenied("authentik.response", "fresh Authentik response is malformed") from None


def _group_refs(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise AuthorityDenied("authentik.groups", "group references are incomplete")
    result: list[str] = []
    for group in value:
        if isinstance(group, (int, str)) and not isinstance(group, bool):
            group_id = str(group)
        elif isinstance(group, dict):
            group_id = str(group.get("pk", group.get("group_uuid", "")))
        else:
            group_id = ""
        if not group_id or any(char not in _GROUP_ID_CHARS for char in group_id):
            raise AuthorityDenied("authentik.groups", "group reference is malformed")
        if group_id in result:
            raise AuthorityDenied("authentik.groups", "group reference is duplicated")
        result.append(group_id)
    return tuple(result)


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _ctx_digest(context: HostContext) -> str:
    return canonical_digest({**context.claims(), "signature": context.signature})
