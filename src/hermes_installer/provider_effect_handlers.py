"""Fixed, root-owned provider effect handlers (PR-F03, PR-R0126).

These handlers run only inside AuthorityService after it has verified and consumed
an exact one-use grant. They accept protected enrollment, account-policy, vault,
and network dependencies from the root service constructor. There is deliberately
no default enrollment, account evidence, token source, URL override, or direct
worker transport. The authority rule map must independently enroll each target.
"""
from __future__ import annotations

import hashlib
import json
import math
import secrets
import time
from dataclasses import dataclass
from typing import Callable, Mapping, Protocol

from .codex_responses import (
    CODEX_RECIPIENT,
    CODEX_TARGET,
    normalize_responses_request,
)
from .network import BoundedNetwork, NetworkError
from .policy import (
    DISABLED_PUBLIC_PLUGINS,
    PROVIDER_RECIPIENT,
    PolicyDenied,
    canonical_provider_target,
    normalize_chat_request,
    request_requires_tools,
)

OPENROUTER_MODEL = "nvidia/nemotron-3-ultra-550b-a55b:free"
OPENROUTER_ENDPOINT = "https://openrouter.ai/api/v1/chat/completions"
CODEX_ENDPOINT = "https://api.openai.com/v1/responses"
MAX_REQUEST_BYTES = 1_048_576
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
MAX_TIMEOUT_SECONDS = 30.0
_ALLOWED_SENSITIVITY = frozenset({"public", "private"})


class ProviderHandlerDenied(PermissionError):
    """Safe failure raised by a root handler without credential/request details."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


class HostCredentialVault(Protocol):
    """Root-only credential lookup. Implementations enforce owner and scope."""

    def resolve_reference(self, reference: str, *, peer_uid: int,
                          required_scope: str) -> str: ...


class ProviderAdmission(Protocol):
    """Fresh protected account, privacy and aggregate-budget admission."""

    def check_attempt(self, *, provider: str, account_id: str, profile_id: str,
                      principal_id: str, namespace_id: str, sensitivity: str,
                      capability: str, model: str, request_digest: str,
                      retry_index: int, additional_metered_fee_usd: float,
                      credential_reference: str) -> None: ...


@dataclass(frozen=True, slots=True)
class ProviderEnrollment:
    """Immutable non-secret root configuration for one account and exact route."""

    provider: str
    account_id: str
    target: str
    recipient: str
    credential_reference: str
    credential_scope: str
    models: frozenset[str]
    allowed_sensitivities: frozenset[str]
    additional_metered_fee_usd: float = 0.0

    def __post_init__(self) -> None:
        if self.provider not in {"openrouter", "codex"}:
            raise ValueError("provider enrollment is not supported")
        if not self.account_id or len(self.account_id) > 256:
            raise ValueError("an enrolled opaque account ID is required")
        if not self.credential_reference or len(self.credential_reference) > 2048:
            raise ValueError("a protected credential reference is required")
        if not self.credential_scope or len(self.credential_scope) > 128:
            raise ValueError("a protected credential scope is required")
        if (not self.models or any(not isinstance(model, str) or not model
                                   or len(model) > 128 for model in self.models)):
            raise ValueError("a nonempty model allowlist is required")
        if not self.allowed_sensitivities or not self.allowed_sensitivities <= _ALLOWED_SENSITIVITY:
            raise ValueError("only explicitly enrolled public/private classifications are supported")
        if (isinstance(self.additional_metered_fee_usd, bool)
                or not isinstance(self.additional_metered_fee_usd, (int, float))
                or not math.isfinite(self.additional_metered_fee_usd)
                or self.additional_metered_fee_usd != 0):
            raise ValueError("provider enrollment must have zero additional metered fee")
        if self.provider == "openrouter":
            if (self.target != canonical_provider_target(OPENROUTER_MODEL)
                    or self.recipient != PROVIDER_RECIPIENT
                    or self.models != frozenset({OPENROUTER_MODEL})
                    or self.allowed_sensitivities != frozenset({"public"})):
                raise ValueError("OpenRouter enrollment must be the exact public zero-price free route")
        elif (self.target != CODEX_TARGET or self.recipient != CODEX_RECIPIENT):
            raise ValueError("Codex enrollment must use its exact protected Responses target")


def _sensitivity(context: object) -> str:
    value = getattr(context, "sensitivity", None)
    if not isinstance(value, str):
        value = getattr(value, "value", None)
    return value if value in _ALLOWED_SENSITIVITY else "unknown"


def _validate_binding(context: object, authorization: object, *,
                      enrollment: ProviderEnrollment, payload: bytes,
                      capability: str, digest: str, retry_index: int) -> None:
    """Recheck claims at the last userspace boundary before opening HTTPS."""
    if not isinstance(payload, bytes) or not 1 <= len(payload) <= MAX_REQUEST_BYTES:
        raise ProviderHandlerDenied("provider.request_bounds", "Provider request exceeds its byte limit")
    if hashlib.sha256(payload).hexdigest() != digest:
        raise ProviderHandlerDenied("provider.digest", "Provider request digest does not match")
    fields = (
        ("principal_id", "principal_id"),
        ("profile_id", "profile_id"),
        ("namespace_id", "namespace_id"),
        ("uid", "uid"),
        ("purpose", "purpose"),
        ("intent_id", "intent_id"),
        ("trace_id", "trace_id"),
        ("policy_revision", "policy_revision"),
        ("lineage_hash", "lineage_hash"),
    )
    for name, grant_name in fields:
        if not getattr(context, name, None) or getattr(context, name) != getattr(authorization, grant_name, None):
            raise ProviderHandlerDenied("provider.context_binding", "Provider grant does not match its host context")
    sensitivity = _sensitivity(context)
    if sensitivity != getattr(getattr(authorization, "sensitivity", None), "value",
                              getattr(authorization, "sensitivity", None)):
        raise ProviderHandlerDenied("provider.context_binding", "Provider grant classification does not match its host context")
    now = time.monotonic()
    grant_expiry = getattr(authorization, "monotonic_expires_at", None)
    context_expiry = getattr(context, "monotonic_expires_at", None)
    if (isinstance(grant_expiry, bool) or not isinstance(grant_expiry, (int, float))
            or isinstance(context_expiry, bool) or not isinstance(context_expiry, (int, float))
            or not math.isfinite(grant_expiry) or not math.isfinite(context_expiry)
            or grant_expiry <= now or context_expiry <= now or grant_expiry > context_expiry):
        raise ProviderHandlerDenied("provider.expired", "Provider context or effect grant has expired")
    if (getattr(authorization, "target", None) != enrollment.target
            or getattr(authorization, "recipient", None) != enrollment.recipient
            or getattr(authorization, "request_digest", None) != digest
            or getattr(authorization, "capability", None) != capability
            or getattr(authorization, "retry_index", None) != retry_index):
        raise ProviderHandlerDenied("provider.grant_binding", "Provider effect grant does not match this attempt")
    capabilities = getattr(context, "capabilities", frozenset())
    if not isinstance(capabilities, frozenset) or capability not in capabilities:
        raise ProviderHandlerDenied("provider.capability", "Host context lacks the request-derived capability")
    if sensitivity not in enrollment.allowed_sensitivities:
        raise ProviderHandlerDenied("provider.sensitivity", "Account policy does not permit this data classification")
    if enrollment.additional_metered_fee_usd != 0:
        raise ProviderHandlerDenied("provider.budget", "Additional metered provider use is disabled")


def _canonical_request(enrollment: ProviderEnrollment, payload: bytes) -> tuple[bytes, str, str]:
    if enrollment.provider == "openrouter":
        try:
            decoded = json.loads(payload)
        except (TypeError, ValueError, UnicodeDecodeError, RecursionError):
            raise ProviderHandlerDenied("provider.request_format", "Provider request is invalid JSON") from None
        if not isinstance(decoded, dict):
            raise ProviderHandlerDenied("provider.request_format", "Provider request must be a JSON object")
        model = decoded.get("model", OPENROUTER_MODEL)
        if model != OPENROUTER_MODEL:
            raise ProviderHandlerDenied("provider.model", "Provider model is not the enrolled free model")
        max_tokens = decoded.get("max_tokens", decoded.get("max_completion_tokens", 4096))
        if isinstance(max_tokens, bool) or not isinstance(max_tokens, int) or not 1 <= max_tokens <= 65_536:
            raise ProviderHandlerDenied("provider.request_bounds", "Output token limit is invalid")
        capability = "provider-tool-call" if request_requires_tools(payload) else "provider-inference"
        body = normalize_chat_request(payload, OPENROUTER_MODEL, max_tokens)
        # Independent route enforcement: no provider fallbacks, optional plugins,
        # alternate formats, or modalities can survive canonicalization.
        normalized = json.loads(body)
        if (normalized.get("provider") != {
                "allow_fallbacks": False, "require_parameters": True,
                "data_collection": "deny"}
                or normalized.get("plugins") != DISABLED_PUBLIC_PLUGINS
                or normalized.get("stream") is True):
            raise ProviderHandlerDenied("provider.request_policy", "OpenRouter request exceeds its public route policy")
        return body, OPENROUTER_MODEL, capability
    try:
        body, model, uses_tools = normalize_responses_request(payload)
    except PolicyDenied as exc:
        raise ProviderHandlerDenied(exc.code, str(exc)) from None
    return body, model, "provider-tool-call" if uses_tools else "provider-inference"


def _safe_headers(headers: Mapping[str, str]) -> dict[str, str]:
    result = {"Content-Type": "application/json"}
    content_type = headers.get("Content-Type") or headers.get("content-type")
    if isinstance(content_type, str) and content_type in {"application/json", "text/event-stream"}:
        result["Content-Type"] = content_type
    retry_after = headers.get("Retry-After") or headers.get("retry-after")
    if isinstance(retry_after, str) and len(retry_after) <= 32:
        try:
            seconds = float(retry_after)
            if math.isfinite(seconds) and 0 <= seconds <= 60:
                result["Retry-After"] = str(seconds)
        except (ValueError, OverflowError):
            pass
    return result


class _FixedProviderHandler:
    def __init__(self, *, enrollment: ProviderEnrollment,
                 admission: ProviderAdmission, vault: HostCredentialVault,
                 network_factory: Callable[..., BoundedNetwork]):
        self._enrollment = enrollment
        self._admission = admission
        self._vault = vault
        self._network_factory = network_factory

    def __repr__(self) -> str:
        return f"_FixedProviderHandler(provider={self._enrollment.provider!r}, credential=<host-vault>)"

    def __call__(self, *, context: object, authorization: object, payload: bytes,
                 timeout: float, peer_pid: int,
                 cancelled: Callable[[], bool]) -> Mapping[str, object]:
        enrollment = self._enrollment
        if (isinstance(timeout, bool) or not isinstance(timeout, (int, float))
                or not math.isfinite(timeout) or not 0.1 <= timeout <= MAX_TIMEOUT_SECONDS
                or type(peer_pid) is not int or peer_pid <= 0 or not callable(cancelled)):
            raise ProviderHandlerDenied("provider.bounds", "Provider attempt bounds are invalid")
        if cancelled():
            raise ProviderHandlerDenied("provider.cancelled", "Provider request was cancelled")
        body, model, capability = _canonical_request(enrollment, payload)
        digest = hashlib.sha256(body).hexdigest()
        retry_index = getattr(authorization, "retry_index", None)
        if type(retry_index) is not int or not 0 <= retry_index < 3:
            raise ProviderHandlerDenied("provider.retry", "Provider retry index is outside its bound")
        if body != payload:
            raise ProviderHandlerDenied("provider.noncanonical", "Provider request was not normalized before grant issuance")
        _validate_binding(context, authorization, enrollment=enrollment, payload=body,
                          capability=capability, digest=digest, retry_index=retry_index)
        if model not in enrollment.models:
            raise ProviderHandlerDenied("provider.model", "Model is not enrolled for this provider account")
        if cancelled():
            raise ProviderHandlerDenied("provider.cancelled", "Provider request was cancelled")
        remaining = min(float(timeout),
                        float(authorization.monotonic_expires_at) - time.monotonic())
        if remaining < 0.1 or cancelled():
            raise ProviderHandlerDenied("provider.expired", "Provider grant expired before network dispatch")
        try:
            token = self._vault.resolve_reference(
                enrollment.credential_reference, peer_uid=context.uid,
                required_scope=enrollment.credential_scope)
        except Exception:
            raise ProviderHandlerDenied("provider.credential_unavailable", "Protected provider credential is unavailable") from None
        if (not isinstance(token, str) or not token or len(token) > 4096
                or any(ord(char) < 33 or ord(char) == 127 for char in token)):
            raise ProviderHandlerDenied("provider.credential_invalid", "Protected provider credential is invalid")
        if cancelled() or time.monotonic() >= authorization.monotonic_expires_at:
            raise ProviderHandlerDenied("provider.cancelled", "Provider request was cancelled or expired")
        # Re-read the protected account, terms, exact model endpoint and
        # aggregate budget after vault access and immediately before egress.
        self._admission.check_attempt(
            provider=enrollment.provider, account_id=enrollment.account_id,
            profile_id=context.profile_id, principal_id=context.principal_id,
            namespace_id=context.namespace_id, sensitivity=_sensitivity(context),
            capability=capability, model=model, request_digest=digest,
            retry_index=retry_index,
            additional_metered_fee_usd=enrollment.additional_metered_fee_usd,
            credential_reference=enrollment.credential_reference,
        )
        if cancelled() or time.monotonic() >= authorization.monotonic_expires_at:
            raise ProviderHandlerDenied("provider.expired", "Provider grant expired before network dispatch")
        endpoint = OPENROUTER_ENDPOINT if enrollment.provider == "openrouter" else CODEX_ENDPOINT
        try:
            network = self._network_factory(
                deadline_seconds=remaining, socket_timeout=min(4.0, remaining),
                max_response_bytes=MAX_RESPONSE_BYTES)
            result = network.request(
                endpoint, method="POST",
                headers={
                    "Authorization": "Bearer " + token,
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    "OpenRouter-Title": "Hermes Installer",
                } if enrollment.provider == "openrouter" else {
                    "Authorization": "Bearer " + token,
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                },
                body=body, cancelled=cancelled,
            )
        except (NetworkError, OSError, TimeoutError):
            if cancelled():
                raise ProviderHandlerDenied("provider.cancelled", "Provider request was cancelled") from None
            raise ProviderHandlerDenied("provider.network", "Bounded provider HTTPS request failed") from None
        if (isinstance(result.status, bool) or type(result.status) is not int
                or not 100 <= result.status <= 599 or not isinstance(result.body, bytes)
                or len(result.body) > MAX_RESPONSE_BYTES
                or not isinstance(result.headers, Mapping)):
            raise ProviderHandlerDenied("provider.response_bounds", "Provider response is invalid or oversized")
        if cancelled() or time.monotonic() >= authorization.monotonic_expires_at:
            raise ProviderHandlerDenied("provider.expired", "Provider attempt expired before its response was accepted")
        return {
            "status": result.status,
            "body": result.body,
            "headers": _safe_headers(result.headers),
            "receipt_id": "provider-" + secrets.token_urlsafe(24),
        }


def build_provider_handlers(*, enrollments: Mapping[tuple[str, str], ProviderEnrollment],
                            admission: ProviderAdmission | None,
                            vault: HostCredentialVault | None,
                            network_factory: Callable[..., BoundedNetwork] = BoundedNetwork
                            ) -> dict[tuple[str, str], _FixedProviderHandler]:
    """Build only handlers with explicit protected enrollment and dependencies.

    The caller passes this result to AuthorityService(handlers=...). A missing
    account-policy admission or root vault yields an empty map, while Authority
    rules remain a separate mandatory protected enrollment.
    """
    if admission is None or vault is None:
        return {}
    if not isinstance(enrollments, Mapping):
        raise TypeError("protected provider enrollments must be a mapping")
    handlers: dict[tuple[str, str], _FixedProviderHandler] = {}
    for key, enrollment in enrollments.items():
        if not isinstance(enrollment, ProviderEnrollment) or key != (enrollment.target, enrollment.recipient):
            raise ValueError("provider enrollment map key does not match its immutable target binding")
        if enrollment.provider == "openrouter":
            operation, expected_endpoint = "provider.dispatch", OPENROUTER_ENDPOINT
        else:
            operation, expected_endpoint = "provider.dispatch", CODEX_ENDPOINT
        if expected_endpoint not in {OPENROUTER_ENDPOINT, CODEX_ENDPOINT}:
            raise ValueError("provider endpoint is not an enrolled fixed endpoint")
        handlers[(operation, enrollment.target)] = _FixedProviderHandler(
            enrollment=enrollment, admission=admission, vault=vault,
            network_factory=network_factory)
    return handlers
