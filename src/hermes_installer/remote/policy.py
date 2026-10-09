"""Fresh, exact Cloudflare Access policy authority for live lease decisions.

This adapter deliberately does not cache successful membership reads. Its credential
reference is resolved for a bounded read and the client is discarded immediately;
it is never serialized into session state or passed to cloudflared/Desktop.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, Mapping, Any

from .cloudflare import CloudflareClient, CloudflareError


@dataclass(frozen=True, slots=True)
class AccessPolicyIdentity:
    account_id: str
    application_id: str
    policy_id: str
    identity_provider_id: str
    hostname: str
    application_name: str
    policy_name: str
    allowed_emails: frozenset[str]


@dataclass(frozen=True, slots=True)
class FreshAccessPolicyAuthority:
    """Read-only policy check requiring a separately scoped runtime secret reference.

    A missing/invalid reference, resolver failure, API failure, changed app, changed
    policy, or any extra/broad policy denies access. `client_factory` must create a
    CloudflareClient over the installer's bounded TLS transport. No successful
    decision is cached: session issuance, stream opening, and every renewal read
    current state.
    """

    identity: AccessPolicyIdentity
    credential_ref: str = field(repr=False)
    resolve_secret: Callable[[str], str] = field(repr=False, compare=False)
    client_factory: Callable[[str], CloudflareClient] = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        i = self.identity
        if not self.credential_ref or not re.fullmatch(r"[A-Za-z0-9_.:/-]{1,256}", self.credential_ref):
            raise ValueError("runtime Access policy credential reference is required")
        if not all(re.fullmatch(r"[A-Za-z0-9_-]{1,128}", x) for x in
                   (i.account_id, i.application_id, i.policy_id, i.identity_provider_id)):
            raise ValueError("invalid journal-owned Access resource ID")
        if not i.hostname or not i.application_name or not i.policy_name or not i.allowed_emails:
            raise ValueError("exact journal-owned Access identity is required")
        normalized = frozenset(e.casefold() for e in i.allowed_emails)
        if len(normalized) != len(i.allowed_emails) or any(not re.fullmatch(r"[^@\\s]{1,64}@[^@\\s.]+(?:\\.[^@\\s.]+)+", e) for e in normalized):
            raise ValueError("invalid exact Access email allowlist")
        object.__setattr__(self, "identity", AccessPolicyIdentity(
            i.account_id, i.application_id, i.policy_id, i.identity_provider_id,
            i.hostname.casefold(), i.application_name, i.policy_name, normalized))

    def _client(self) -> CloudflareClient:
        token = self.resolve_secret(self.credential_ref)
        if not isinstance(token, str) or not token.strip():
            raise CloudflareError("runtime Access policy credential is unavailable")
        return self.client_factory(token)

    def allows(self, email: str) -> bool:
        """Return True only for a fresh, exact protected-app policy snapshot."""
        normalized = email.casefold() if isinstance(email, str) else ""
        if normalized not in self.identity.allowed_emails:
            return False
        try:
            client = self._client()
            i = self.identity
            app = client.request("GET", f"/accounts/{i.account_id}/access/apps/{i.application_id}")
            if not self._exact_application(app):
                return False
            policies = client.pages(f"/accounts/{i.account_id}/access/apps/{i.application_id}/policies")
            if len(policies) != 1:
                return False
            policy = policies[0]
            include = [{"email": {"email": value}} for value in sorted(i.allowed_emails)]
            return (
                policy.get("id") == i.policy_id
                and policy.get("name") == i.policy_name
                and policy.get("decision") == "allow"
                and policy.get("include") == include
                and policy.get("exclude") in (None, [])
                and policy.get("require") in (None, [])
                and policy.get("approval_required") is not True
            )
        except Exception:
            # Policy authority is a hard gate. Errors, timeouts and malformed
            # responses never fall back to the JWT's already-issued allow claim.
            return False

    def __call__(self, email: str) -> bool:
        return self.allows(email)

    def _exact_application(self, app: Any) -> bool:
        i = self.identity
        return (
            isinstance(app, Mapping)
            and app.get("id") == i.application_id
            and app.get("name") == i.application_name
            and app.get("type") in {"self_hosted", "self_hosted_app"}
            and app.get("domain") == i.hostname
            and app.get("allowed_idps") == [i.identity_provider_id]
            and app.get("self_hosted_domains") in ([], None, [i.hostname])
            and app.get("enable_binding_cookie") is not True
        )
