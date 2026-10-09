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
from decimal import Decimal, InvalidOperation
from datetime import datetime
from dataclasses import dataclass
from typing import Callable, Mapping, Protocol

from .codex_responses import (
    CODEX_RECIPIENT,
    CODEX_TARGET,
    normalize_responses_request,
    validate_responses_sse,
)
from .network import BoundedNetwork, NetworkError
from .policy import (
    DISABLED_PUBLIC_PLUGINS,
    PROVIDER_RECIPIENT,
    PolicyDenied,
    canonical_provider_target,
    normalize_chat_request,
    request_requires_tools,
    PUBLIC_PROVIDER_OUTPUT_TOKEN_CEILING,
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
                          required_scope: str, principal_id: str) -> str: ...


class ProviderAdmission(Protocol):
    """Fresh protected account, privacy and aggregate-budget admission."""

    def check_attempt(self, *, provider: str, account_id: str, profile_id: str,
                      principal_id: str, namespace_id: str, sensitivity: str,
                      capability: str, target: str, recipient: str, endpoint: str,
                      model: str, request_digest: str, retry_index: int,
                      additional_metered_fee_usd: float, credential_ref: str,
                      credential: str, payload: bytes, timeout: float,
                      cancelled: Callable[[], bool], expected_zero_price: bool,
                      allow_fallbacks: bool, plugins_enabled: bool,
                      data_collection: str) -> None: ...


@dataclass(frozen=True, slots=True)
class ProviderEnrollment:
    """Immutable non-secret root configuration for one account and exact route."""

    provider: str
    account_id: str
    principal_id: str
    target: str
    recipient: str
    credential_ref: str
    credential_scope: str
    models: frozenset[str]
    allowed_sensitivities: frozenset[str]
    additional_metered_fee_usd: float = 0.0

    def __post_init__(self) -> None:
        if self.provider not in {"openrouter", "codex"}:
            raise ValueError("provider enrollment is not supported")
        if not self.account_id or len(self.account_id) > 256 or not self.principal_id or len(self.principal_id) > 256:
            raise ValueError("an enrolled opaque account ID is required")
        if not self.credential_ref or len(self.credential_ref) > 2048:
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
    if (getattr(context, "principal_id", None) != enrollment.principal_id
            or getattr(authorization, "target", None) != enrollment.target
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


def _unique_json_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value


def _canonical_request(enrollment: ProviderEnrollment, payload: bytes) -> tuple[bytes, str, str]:
    if enrollment.provider == "openrouter":
        try:
            decoded = json.loads(payload, object_pairs_hook=_unique_json_pairs,
                                 parse_constant=lambda _item: (_ for _ in ()).throw(ValueError("constant")))
        except (TypeError, ValueError, UnicodeDecodeError, RecursionError):
            raise ProviderHandlerDenied("provider.request_format", "Provider request is invalid JSON") from None
        if not isinstance(decoded, dict):
            raise ProviderHandlerDenied("provider.request_format", "Provider request must be a JSON object")
        model = decoded.get("model", OPENROUTER_MODEL)
        if model != OPENROUTER_MODEL:
            raise ProviderHandlerDenied("provider.model", "Provider model is not the enrolled free model")
        output_aliases = [decoded[name] for name in
                          ("max_tokens", "max_completion_tokens", "max_output_tokens")
                          if name in decoded]
        if len(output_aliases) > 1:
            raise ProviderHandlerDenied("provider.request_bounds", "Output token aliases cannot be combined")
        max_tokens = output_aliases[0] if output_aliases else PUBLIC_PROVIDER_OUTPUT_TOKEN_CEILING
        if (isinstance(max_tokens, bool) or not isinstance(max_tokens, int)
                or not 1 <= max_tokens <= PUBLIC_PROVIDER_OUTPUT_TOKEN_CEILING):
            raise ProviderHandlerDenied("provider.request_bounds", "Output token limit exceeds the public route ceiling")
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


def canonical_provider_request(
    root_selected_enrollments: Mapping[tuple[str, str], ProviderEnrollment], payload: bytes,
) -> tuple[bytes, str, str, str, str]:
    """Purely normalize a request using one root-selected exact account route.

    The mapping is selected from protected root enrollment, never a provider
    catalog or caller configuration. This helper is not account eligibility,
    price, privacy or budget proof: the fixed effect handler rechecks each of
    those immediately before egress. It accepts no URL, credential, callback or
    route label and performs no network or vault operation. The explicit request
    model must resolve to one exact `(target, recipient)` entry; ambiguous or
    absent enrollment is denied.
    """
    if not isinstance(payload, bytes) or not 1 <= len(payload) <= MAX_REQUEST_BYTES:
        raise ProviderHandlerDenied("provider.request_bounds", "Provider request exceeds its byte limit")
    if not isinstance(root_selected_enrollments, Mapping) or not root_selected_enrollments:
        raise ProviderHandlerDenied("provider.not_enrolled", "No protected provider enrollment is available")
    try:
        decoded = json.loads(payload, object_pairs_hook=_unique_json_pairs,
                             parse_constant=lambda _item: (_ for _ in ()).throw(ValueError("constant")))
    except (TypeError, ValueError, UnicodeDecodeError, RecursionError):
        raise ProviderHandlerDenied("provider.request_format", "Provider request is invalid JSON") from None
    if not isinstance(decoded, dict) or not isinstance(decoded.get("model"), str):
        raise ProviderHandlerDenied("provider.model", "Provider request must name an enrolled model")
    model = decoded["model"]
    matches: list[ProviderEnrollment] = []
    for key, enrollment in root_selected_enrollments.items():
        if (not isinstance(enrollment, ProviderEnrollment)
                or not isinstance(key, tuple) or key != (enrollment.target, enrollment.recipient)):
            raise ProviderHandlerDenied("provider.enrollment", "Protected provider enrollment map is malformed")
        if model in enrollment.models:
            matches.append(enrollment)
    if len(matches) != 1:
        raise ProviderHandlerDenied("provider.not_enrolled", "Provider model is absent or ambiguous in protected enrollment")
    enrollment = matches[0]
    body, normalized_model, capability = _canonical_request(enrollment, payload)
    if normalized_model != model:
        raise ProviderHandlerDenied("provider.model", "Canonical request changed the selected model")
    return body, enrollment.target, enrollment.recipient, capability, normalized_model


def _safe_headers(headers: Mapping[str, str]) -> dict[str, str]:
    result = {"Content-Type": "application/json"}
    content_type = headers.get("Content-Type") or headers.get("content-type")
    if isinstance(content_type, str) and content_type.split(";", 1)[0].strip().casefold() in {"application/json", "text/event-stream"}:
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




class OpenRouterLiveAdmission:
    """Fresh, zero-cost OpenRouter account/model check for public-only effects.

    Uses documented read endpoints (/api/v1/key and /api/v1/model) and the
    protected credential already held by the root effect handler. It does not
    turn a public model catalog into a private-data or account-entitlement claim.
    """

    KEY_ENDPOINT = "https://openrouter.ai/api/v1/key"
    MODEL_ENDPOINT = "https://openrouter.ai/api/v1/model/nvidia/nemotron-3-ultra-550b-a55b:free"

    def __init__(self, *, network_factory: Callable[..., BoundedNetwork] = BoundedNetwork,
                 clock: Callable[[], float] = time.time):
        if not callable(network_factory) or not callable(clock):
            raise TypeError("live account admission requires bounded network and clock")
        self._network_factory = network_factory
        self._clock = clock

    @staticmethod
    def _read_json(network: BoundedNetwork, endpoint: str, credential: str,
                   cancelled: Callable[[], bool]) -> Mapping[str, object]:
        if cancelled():
            raise ProviderHandlerDenied("provider.cancelled", "Provider admission was cancelled")
        try:
            result = network.request(endpoint, method="GET", headers={
                "Authorization": "Bearer " + credential, "Accept": "application/json",
            }, cancelled=cancelled)
        except Exception:
            raise ProviderHandlerDenied("provider.account_check", "Fresh OpenRouter account eligibility check failed") from None
        if (type(getattr(result, "status", None)) is not int or result.status != 200
                or not isinstance(getattr(result, "body", None), bytes)
                or not 1 <= len(result.body) <= 1_048_576):
            raise ProviderHandlerDenied("provider.account_check", "Fresh OpenRouter eligibility response was invalid")
        try:
            value = json.loads(result.body)
        except (ValueError, UnicodeDecodeError, RecursionError):
            raise ProviderHandlerDenied("provider.account_check", "Fresh OpenRouter eligibility response was malformed") from None
        if not isinstance(value, dict) or not isinstance(value.get("data"), dict):
            raise ProviderHandlerDenied("provider.account_check", "Fresh OpenRouter eligibility response was malformed")
        return value["data"]

    def check_attempt(self, *, provider: str, account_id: str, profile_id: str,
                      principal_id: str, namespace_id: str, sensitivity: str,
                      capability: str, target: str, recipient: str, endpoint: str,
                      model: str, request_digest: str, retry_index: int,
                      additional_metered_fee_usd: float, credential_ref: str,
                      credential: str, payload: bytes, timeout: float,
                      cancelled: Callable[[], bool], expected_zero_price: bool,
                      allow_fallbacks: bool, plugins_enabled: bool,
                      data_collection: str) -> None:
        if (provider != "openrouter" or not account_id or not profile_id or not principal_id
                or not namespace_id or sensitivity != "public"
                or target != canonical_provider_target(OPENROUTER_MODEL)
                or recipient != PROVIDER_RECIPIENT or endpoint != OPENROUTER_ENDPOINT
                or model != OPENROUTER_MODEL or not isinstance(payload, bytes)
                or hashlib.sha256(payload).hexdigest() != request_digest
                or isinstance(retry_index, bool) or type(retry_index) is not int
                or not 0 <= retry_index < 3 or additional_metered_fee_usd != 0
                or not credential_ref or not isinstance(credential, str) or not credential
                or not math.isfinite(timeout) or timeout < 0.2 or not callable(cancelled)
                or not expected_zero_price or allow_fallbacks or plugins_enabled
                or data_collection != "deny"
                or capability not in {"provider-inference", "provider-tool-call"}):
            raise ProviderHandlerDenied("provider.account_policy", "OpenRouter effect is outside the enrolled public zero-cost route")
        try:
            request = json.loads(payload)
        except (ValueError, UnicodeDecodeError, RecursionError):
            raise ProviderHandlerDenied("provider.request_format", "Canonical OpenRouter request is invalid") from None
        if (not isinstance(request, dict) or request.get("model") != OPENROUTER_MODEL
                or request.get("provider") != {"allow_fallbacks": False, "require_parameters": True, "data_collection": "deny"}
                or request.get("plugins") != DISABLED_PUBLIC_PLUGINS
                or request.get("stream") is True
                or type(request.get("max_tokens")) is not int or not 1 <= request["max_tokens"] <= 65_536):
            raise ProviderHandlerDenied("provider.request_policy", "OpenRouter request does not satisfy the enrolled public route")
        now = self._clock()
        if isinstance(now, bool) or not isinstance(now, (int, float)) or not math.isfinite(now):
            raise ProviderHandlerDenied("provider.account_policy", "OpenRouter eligibility clock is invalid")
        per_check = min(10.0, float(timeout) / 2)
        if per_check < 0.1:
            raise ProviderHandlerDenied("provider.account_policy", "Provider grant has insufficient time for fresh account checks")
        try:
            network = self._network_factory(deadline_seconds=per_check,
                socket_timeout=min(4.0, per_check), max_response_bytes=1_048_576)
        except Exception:
            raise ProviderHandlerDenied("provider.account_check", "OpenRouter account check is unavailable") from None
        key = self._read_json(network, self.KEY_ENDPOINT, credential, cancelled)
        if (key.get("is_free_tier") is not True
                or key.get("is_management_key") is True
                or key.get("is_provisioning_key") is True
                or key.get("disabled") is True):
            raise ProviderHandlerDenied("provider.account_ineligible", "OpenRouter key is not an eligible free inference key")
        remaining = key.get("limit_remaining")
        if remaining is not None:
            try:
                if not math.isfinite(float(remaining)) or float(remaining) <= 0:
                    raise ValueError("invalid quota")
            except (TypeError, ValueError, OverflowError):
                raise ProviderHandlerDenied("provider.account_ineligible", "OpenRouter free-key quota is invalid or exhausted") from None
        expiry = key.get("expires_at")
        if expiry:
            try:
                parsed = datetime.fromisoformat(str(expiry).replace("Z", "+00:00"))
                if parsed.tzinfo is None or parsed.timestamp() <= now:
                    raise ValueError("expired")
            except (ValueError, TypeError, OverflowError):
                raise ProviderHandlerDenied("provider.account_ineligible", "OpenRouter key is expired or has an invalid expiry") from None
        if cancelled():
            raise ProviderHandlerDenied("provider.cancelled", "OpenRouter account check was cancelled")
        model_data = self._read_json(network, self.MODEL_ENDPOINT, credential, cancelled)
        try:
            pricing = model_data["pricing"]
            architecture = model_data["architecture"]
            top = model_data["top_provider"]
            prompt_price = Decimal(str(pricing["prompt"]))
            completion_price = Decimal(str(pricing["completion"]))
            max_completion = int(top["max_completion_tokens"])
            context_length = int(model_data["context_length"])
        except (TypeError, ValueError, KeyError, InvalidOperation, OverflowError):
            raise ProviderHandlerDenied("provider.model_ineligible", "OpenRouter model price or limits are unavailable") from None
        supported = model_data.get("supported_parameters")
        if (model_data.get("id") != OPENROUTER_MODEL
                or not prompt_price.is_finite() or not completion_price.is_finite()
                or prompt_price != 0 or completion_price != 0
                or not isinstance(architecture, dict) or architecture.get("input_modalities") != ["text"]
                or not isinstance(top, dict)
                or not isinstance(supported, list)
                or (capability == "provider-tool-call" and "tools" not in supported)
                or type(top.get("max_completion_tokens")) is not int
                or not 1 <= max_completion <= 65_536
                or type(model_data.get("context_length")) is not int
                or not len(payload) <= context_length):
            raise ProviderHandlerDenied("provider.model_ineligible", "Current OpenRouter model metadata does not meet the zero-cost text route")
        if request["max_tokens"] > min(max_completion, PUBLIC_PROVIDER_OUTPUT_TOKEN_CEILING) or cancelled():
            raise ProviderHandlerDenied("provider.model_ineligible", "OpenRouter request exceeds live model limits")


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
                 cancelled: Callable[[], bool], peer_pidfd: int | None = None) -> Mapping[str, object]:
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
                enrollment.credential_ref, peer_uid=context.uid,
                required_scope=enrollment.credential_scope,
                principal_id=enrollment.principal_id)
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
            capability=capability, target=enrollment.target,
            recipient=enrollment.recipient,
            endpoint=OPENROUTER_ENDPOINT if enrollment.provider == "openrouter" else CODEX_ENDPOINT,
            model=model, request_digest=digest,
            retry_index=retry_index,
            additional_metered_fee_usd=enrollment.additional_metered_fee_usd,
            credential_ref=enrollment.credential_ref, credential=token,
            payload=body, timeout=remaining, cancelled=cancelled,
            expected_zero_price=(enrollment.provider == "openrouter"),
            allow_fallbacks=False, plugins_enabled=False, data_collection="deny",
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
                    "Accept": "text/event-stream" if enrollment.provider == "codex" else "application/json",
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
        if enrollment.provider == "codex" and 200 <= result.status < 300:
            try:
                validate_responses_sse(result.body, _safe_headers(result.headers).get("Content-Type", ""))
            except PolicyDenied as exc:
                raise ProviderHandlerDenied(exc.code, str(exc)) from None
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
