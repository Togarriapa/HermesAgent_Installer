"""Fresh Cloudflare Access policy reads for the isolated credential custodian.

This module must be imported and constructed only inside the verifier service. The
browser gateway uses verifier_ipc.PolicyVerifierClient and never resolves credentials.
"""
from __future__ import annotations

import re
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping
from urllib.parse import urlencode

from ..network import BoundedNetwork, NetworkError
from .cloudflare import CloudflareClient


class PolicyReadDenied(PermissionError):
    """Current policy cannot be proven within the bounded exact read."""


class _CancellableBoundedNetwork:
    """CloudflareClient-compatible adapter with a fresh hard deadline per GET."""

    def __init__(self, deadline: float, cancelled: threading.Event, clock: Callable[[], float]):
        self.deadline = deadline
        self.cancelled = cancelled
        self.clock = clock

    def request(self, url, *, method="GET", headers=None, body=None):
        if self.cancelled.is_set():
            raise NetworkError("policy read cancelled")
        remaining = self.deadline - self.clock()
        if remaining <= 0.05:
            raise NetworkError("policy read deadline expired")
        network = BoundedNetwork(
            deadline_seconds=min(8.0, remaining),
            socket_timeout=min(4.0, remaining),
            max_response_bytes=1_048_576,
        )
        return network.request(
            url, method=method, headers=headers, body=body,
            cancelled=self.cancelled.is_set,
        )


@dataclass(frozen=True, slots=True)
class AccessPolicyIdentity:
    account_id: str
    application_id: str
    policy_id: str
    identity_provider_id: str
    hostname: str
    application_name: str
    policy_name: str
    identity_provider_name: str
    allowed_emails: frozenset[str]
    audience: str


@dataclass(frozen=True, slots=True)
class PolicyReadOutcome:
    allowed: bool
    started_monotonic: float
    ended_monotonic: float


@dataclass(frozen=True, slots=True)
class FreshAccessPolicyAuthority:
    """No-cache current policy reader. Instantiate only inside the read custodian."""

    identity: AccessPolicyIdentity
    policy_read_token_ref: str = field(repr=False)
    resolve_secret: Callable[[str], str] = field(repr=False, compare=False)
    client_factory: Callable[[str], CloudflareClient] = field(repr=False, compare=False)
    clock: Callable[[], float] = field(default=time.monotonic, repr=False, compare=False)
    wall_clock: Callable[[], float] = field(default=time.time, repr=False, compare=False)

    MAX_READ_SECONDS = 9.0
    MAX_POLICY_PAGES = 5

    def __post_init__(self) -> None:
        i = self.identity
        if not self.policy_read_token_ref or not re.fullmatch(r"[A-Za-z0-9_.:/-]{1,256}", self.policy_read_token_ref):
            raise ValueError("verifier read-credential reference is required")
        if not all(isinstance(x, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,128}", x) for x in
                   (i.account_id, i.application_id, i.policy_id, i.identity_provider_id)):
            raise ValueError("invalid journal-owned Access resource ID")
        if not isinstance(i.hostname, str) or not re.fullmatch(
            r"(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))+",
            i.hostname,
        ):
            raise ValueError("canonical hostname is required")
        if not i.application_name or not i.policy_name or not i.identity_provider_name or not i.allowed_emails:
            raise ValueError("exact journal-owned Access identity is required")
        if not isinstance(i.audience, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,256}", i.audience):
            raise ValueError("exact Cloudflare Access application audience tag is required")
        normalized = frozenset(e.casefold() for e in i.allowed_emails)
        if len(normalized) != len(i.allowed_emails) or any(
            not re.fullmatch(r"[^@\s]{1,64}@[^@\s.]+(?:\.[^@\s.]+)+", e) for e in normalized
        ):
            raise ValueError("invalid exact Access email allowlist")
        object.__setattr__(self, "identity", AccessPolicyIdentity(
            i.account_id, i.application_id, i.policy_id, i.identity_provider_id,
            i.hostname.casefold(), i.application_name, i.policy_name,
            i.identity_provider_name, normalized, i.audience,
        ))

    def allows(self, email: str, *, cancel_event: threading.Event | None = None,
               deadline_monotonic: float | None = None) -> bool:
        """Freshly read app, every policy page and the selected OTP IdP; deny all uncertainty."""
        return self.inspect(email, cancel_event=cancel_event,
                            deadline_monotonic=deadline_monotonic).allowed

    def inspect(self, email: str, *, cancel_event: threading.Event | None = None,
                deadline_monotonic: float | None = None) -> PolicyReadOutcome:
        """Return the exact monotonic interval used by one bounded fresh read."""
        if not isinstance(email, str) or email.casefold() not in self.identity.allowed_emails:
            now = self.clock()
            return PolicyReadOutcome(False, now, now)
        cancel = cancel_event or threading.Event()
        started = self.clock()
        def denied() -> PolicyReadOutcome:
            return PolicyReadOutcome(False, started, self.clock())
        deadline = min(started + self.MAX_READ_SECONDS,
                       deadline_monotonic if deadline_monotonic is not None else started + self.MAX_READ_SECONDS)
        if deadline <= started or cancel.is_set() or self.clock() >= deadline:
            return denied()
        client = None
        try:
            token = self.resolve_secret(self.policy_read_token_ref)
            if not isinstance(token, str) or not token.strip():
                return denied()
            if cancel.is_set() or self.clock() >= deadline:
                return denied()
            client = self.client_factory(token)
            i = self.identity
            app_path = f"/accounts/{i.account_id}/access/apps/{i.application_id}"
            policies_path = app_path + "/policies"
            idp_path = f"/accounts/{i.account_id}/access/identity_providers/{i.identity_provider_id}"

            before_app = self._get(client, app_path, deadline, cancel)
            if not self._exact_application(before_app):
                return denied()
            first_policies = self._all_policies(client, policies_path, deadline, cancel)
            if not self._exact_policy_set(first_policies):
                return denied()
            idp = self._get(client, idp_path, deadline, cancel)
            if not self._exact_idp(idp):
                return denied()

            # Cloudflare has no atomic snapshot endpoint. Re-read the app, complete
            # policy set, and selected provider; deny any change observed in flight.
            after_policies = self._all_policies(client, policies_path, deadline, cancel)
            after_idp = self._get(client, idp_path, deadline, cancel)
            after_app = self._get(client, app_path, deadline, cancel)
            allowed = (
                not cancel.is_set()
                and self.clock() <= deadline
                and self._exact_application(after_app)
                and self._exact_policy_set(after_policies)
                and self._application_signature(before_app) == self._application_signature(after_app)
                and self._policy_signature(first_policies) == self._policy_signature(after_policies)
                and self._exact_idp(after_idp)
                and self._idp_signature(idp) == self._idp_signature(after_idp)
            )
            ended = self.clock()
            return PolicyReadOutcome(bool(allowed), started, ended)
        except Exception:
            return denied()
        finally:
            # Drop transient bearer-secret references as soon as this read ends.
            client = None
            token = None

    def _get(self, client, path: str, deadline: float, cancel: threading.Event) -> Mapping[str, Any]:
        self._set_network(client, deadline, cancel)
        if cancel.is_set() or self.clock() >= deadline:
            raise PolicyReadDenied("policy read deadline")
        result = client.request("GET", path)
        if cancel.is_set() or self.clock() > deadline or not isinstance(result, Mapping):
            raise PolicyReadDenied("policy read cancelled or malformed")
        return result

    def _all_policies(self, client, path: str, deadline: float, cancel: threading.Event) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for page in range(1, self.MAX_POLICY_PAGES + 1):
            self._set_network(client, deadline, cancel)
            if cancel.is_set() or self.clock() >= deadline:
                raise PolicyReadDenied("policy read deadline")
            result = client.request("GET", path + "?" + urlencode({"per_page": "100", "page": str(page)}))
            if cancel.is_set() or self.clock() > deadline or not isinstance(result, list) or any(not isinstance(x, dict) for x in result):
                raise PolicyReadDenied("policy page is missing or malformed")
            rows.extend(result)
            if len(result) < 100:
                return rows
        raise PolicyReadDenied("policy set exceeded the bounded page limit")

    def _set_network(self, client, deadline: float, cancel: threading.Event) -> None:
        client.network = _CancellableBoundedNetwork(deadline, cancel, self.clock)

    def _exact_application(self, app: Mapping[str, Any]) -> bool:
        i = self.identity
        domains = app.get("self_hosted_domains")
        return (
            app.get("id") == i.application_id
            and app.get("name") == i.application_name
            and app.get("aud") == i.audience
            and app.get("type") in {"self_hosted", "self_hosted_app"}
            and isinstance(app.get("domain"), str)
            and app["domain"].casefold() == i.hostname
            and app.get("allowed_idps") == [i.identity_provider_id]
            and domains in (None, [], [i.hostname])
            and app.get("enable_binding_cookie") is not True
        )

    def _exact_idp(self, idp: Mapping[str, Any]) -> bool:
        return (
            idp.get("id") == self.identity.identity_provider_id
            and idp.get("name") == self.identity.identity_provider_name
            and idp.get("type") == "onetimepin"
        )

    @classmethod
    def _idp_signature(cls, idp: Mapping[str, Any]) -> tuple[Any, ...]:
        # Compare the complete read-only representation to detect in-flight changes.
        return (cls._freeze(idp),)

    @staticmethod
    def _freeze(value: Any):
        if isinstance(value, Mapping):
            return tuple((key, FreshAccessPolicyAuthority._freeze(item))
                         for key, item in sorted(value.items(), key=lambda pair: str(pair[0])))
        if isinstance(value, list):
            return tuple(FreshAccessPolicyAuthority._freeze(item) for item in value)
        if isinstance(value, tuple):
            return tuple(FreshAccessPolicyAuthority._freeze(item) for item in value)
        if value is None or isinstance(value, (str, int, float, bool)):
            return value
        return repr(type(value))

    def _exact_policy_set(self, rows: list[dict[str, Any]]) -> bool:
        i = self.identity
        if len(rows) != 1:
            return False
        row = rows[0]
        try:
            include = row.get("include")
            emails = []
            for item in include:
                if not isinstance(item, dict) or set(item) != {"email"}:
                    return False
                email_clause = item["email"]
                if not isinstance(email_clause, dict) or set(email_clause) != {"email"} or not isinstance(email_clause["email"], str):
                    return False
                emails.append(email_clause["email"].casefold())
            if len(emails) != len(set(emails)):
                return False
            return (
                row.get("id") == i.policy_id
                and row.get("name") == i.policy_name
                and row.get("decision") == "allow"
                and frozenset(emails) == i.allowed_emails
                and row.get("exclude") in (None, [])
                and row.get("require") in (None, [])
                and row.get("approval_required") is not True
                and row.get("precedence") in (None, 1)
            )
        except (TypeError, KeyError):
            return False

    def _application_signature(self, app: Mapping[str, Any]) -> tuple[Any, ...]:
        return (self._freeze(app),)

    @staticmethod
    def _policy_signature(rows: list[dict[str, Any]]) -> tuple[Any, ...]:
        canonical = []
        for row in rows:
            def freeze(value):
                if isinstance(value, dict):
                    return tuple((k, freeze(v)) for k, v in sorted(value.items()))
                if isinstance(value, list):
                    return tuple(sorted((freeze(x) for x in value), key=repr))
                return value
            canonical.append(freeze(row))
        return tuple(sorted(canonical, key=repr))
