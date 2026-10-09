"""Bounded OpenAI-compatible provider transport for PR-F02."""
from __future__ import annotations

import json
import math
from typing import Callable, Mapping
from urllib.parse import urlsplit

from .credentials import CredentialError, resolve_secret
from .network import BoundedNetwork, NetworkError
from .policy import (PolicyDenied, ProviderResponse, Route, normalize_chat_request,
    canonical_provider_target, PROVIDER_RECIPIENT)
from .eligibility import AccountEligibilityGate

OPENROUTER_ENDPOINT = "https://openrouter.ai/api/v1"
ALLOWED_MODELS = frozenset({"nvidia/nemotron-3-ultra-550b-a55b:free"})
MAX_REQUEST_BYTES = 1_048_576
MAX_RESPONSE_BYTES = 4 * 1024 * 1024


class OpenRouterTransport:
    """POST one normalized chat request to a fixed OpenRouter endpoint.

    Credentials are resolved lazily from an explicit private reference on first use;
    they are not accepted from request JSON, route metadata, argv, or Hermes env.
    BoundedNetwork isolates DNS/connect/read behind a killable hard-deadline worker.
    """

    def __init__(self, credential_ref: str, *,
                 secret_reader: Callable[[str], str] = resolve_secret,
                 network_factory: Callable[..., BoundedNetwork] = BoundedNetwork,
                 eligibility: AccountEligibilityGate | None = None,
                 authority_client: object | None = None,
                 allow_direct_fixture_transport: bool = False):
        if not isinstance(credential_ref, str) or not credential_ref.startswith(("file://", "keyring://", "secret://")):
            raise CredentialError("Provider credential must use a private file or secure store reference")
        self._credential_ref = credential_ref
        self._secret_reader = secret_reader
        self._api_key: str | None = None
        self._credential_lock = __import__("threading").Lock()
        self._network_factory = network_factory
        self._eligibility = eligibility or AccountEligibilityGate(model=next(iter(ALLOWED_MODELS)), credential_ref=credential_ref)
        self._authority_client = authority_client
        self._allow_direct_fixture_transport = allow_direct_fixture_transport

    def __repr__(self) -> str:
        return "OpenRouterTransport(credential_ref=<redacted>, key=<redacted>)"

    def _credential(self) -> str:
        # Resolve each dispatch so key rotation invalidates the policy snapshot.
        # Never cache a credential across a potentially rotated secret reference.
        try:
            value = self._secret_reader(self._credential_ref)
        except Exception:
            raise CredentialError("Provider credential reference could not be resolved") from None
        if not isinstance(value, str) or not value or len(value) > 4096 or any(ord(c) < 32 for c in value):
            raise CredentialError("Provider credential reference is invalid")
        return value

    def _verified_credential(self) -> str:
        value = self._credential()
        self._eligibility.verify_credential(value)
        return value

    @staticmethod
    def _request_body(payload: bytes, model: str, output_limit: int) -> bytes:
        if not isinstance(payload, bytes) or len(payload) > MAX_REQUEST_BYTES:
            raise PolicyDenied("request.bounds", "Provider request exceeds its byte limit")
        if model not in ALLOWED_MODELS:
            raise PolicyDenied("route.model", "Model is not approved for the public OpenRouter route")
        if not 0 <= output_limit <= 65_536:
            raise PolicyDenied("request.bounds", "Output token limit is outside the supported range")
        return normalize_chat_request(payload, model, output_limit)

    def __call__(self, route: Route, model: str, payload: bytes, *, output_token_limit: int, timeout: float, trace_id: str, cancelled: Callable[[], bool] = lambda: False,
                 effect_grant: object | None = None, target: str = "", recipient: str = "",
                 request_digest: str = "", retry_index: int = 0) -> ProviderResponse:
        # Direct HTTPS is reserved for explicit synthetic fixture injection. Live
        # traffic requires a signed one-use grant and the fixed host egress broker.
        if route.name != "openrouter-nemotron-free" or route.endpoint.rstrip("/") != OPENROUTER_ENDPOINT:
            raise PolicyDenied("route.endpoint", "Route is not the pinned public OpenRouter endpoint")
        if route.maximum_sensitivity.value != 0 or not route.free_only:
            raise PolicyDenied("route.sensitivity", "OpenRouter public route cannot receive non-public data")
        if route.input_usd_per_million != 0 or route.output_usd_per_million != 0:
            raise PolicyDenied("route.price", "Public OpenRouter route must have verified zero token prices")
        if not math.isfinite(timeout) or not 0.1 <= timeout <= 30:
            raise PolicyDenied("request.deadline", "Provider transport deadline is outside its hard bound")
        if not trace_id or len(trace_id) > 128 or any(ord(c) < 33 for c in trace_id):
            raise PolicyDenied("request.trace", "Provider trace identifier is invalid")
        body = self._request_body(payload, model, output_token_limit)
        if effect_grant is None:
            # Eligibility is checked before credentials or network setup. Valid
            # account evidence alone cannot enable direct worker networking.
            self._eligibility.require_eligible(model=model, credential_ref=self._credential_ref)
            if not self._allow_direct_fixture_transport:
                raise PolicyDenied("authorization.unavailable", "Direct provider network access is disabled; host broker is required")
        elif self._authority_client is None:
            raise PolicyDenied("authorization.unavailable", "Root-owned provider egress broker is unavailable")
        if effect_grant is not None:
            expected_target = canonical_provider_target(model)
            expected_digest = __import__("hashlib").sha256(body).hexdigest()
            if (target != expected_target or recipient != PROVIDER_RECIPIENT
                    or request_digest != expected_digest
                    or isinstance(retry_index, bool) or not isinstance(retry_index, int)
                    or retry_index < 0 or cancelled()):
                raise PolicyDenied("authorization.binding", "Provider effect does not match its canonical target or request")
            try:
                result = self._authority_client.dispatch_provider(
                    effect_grant, target=target, recipient=recipient,
                    request_digest=request_digest, payload=body, timeout=timeout,
                    cancelled=cancelled)
            except Exception:
                if cancelled():
                    raise PolicyDenied("dispatch.cancelled", "Provider request was cancelled") from None
                raise PolicyDenied("provider.broker", "Root-owned provider broker rejected the request") from None
            if (not isinstance(getattr(result, "status", None), int)
                    or not isinstance(getattr(result, "body", None), bytes)
                    or len(result.body) > MAX_RESPONSE_BYTES
                    or not isinstance(getattr(result, "headers", None), Mapping)):
                raise PolicyDenied("response.bounds", "Host broker returned an invalid provider response")
            input_tokens = output_tokens = 0
            try:
                decoded = json.loads(result.body)
                usage = decoded.get("usage", {}) if isinstance(decoded, dict) else {}
                if isinstance(usage, dict):
                    prompt = usage.get("prompt_tokens", 0)
                    completion = usage.get("completion_tokens", 0)
                    if isinstance(prompt, int) and prompt >= 0:
                        input_tokens = min(prompt, 1_000_000)
                    if isinstance(completion, int) and completion >= 0:
                        output_tokens = min(completion, 65_536)
            except (ValueError, UnicodeDecodeError):
                pass
            safe_headers = {"Content-Type": "application/json"}
            content_type = result.headers.get("Content-Type", "application/json")
            if content_type in {"application/json", "text/event-stream"}:
                safe_headers["Content-Type"] = content_type
            retry_after = result.headers.get("Retry-After")
            if retry_after is not None:
                try:
                    delay = float(retry_after)
                    if math.isfinite(delay) and 0 <= delay <= 60:
                        safe_headers["Retry-After"] = str(delay)
                except (TypeError, ValueError, OverflowError):
                    pass
            return ProviderResponse(result.status, result.body, safe_headers,
                                    input_tokens, output_tokens)
        # Provider policy/Dispatcher has already clamped max_tokens to the user's
        # approved output limit. This adapter applies an upper ceiling as a final
        # endpoint-level guard; per-request tighter limits remain in the JSON.
        # Compare the freshly resolved secret against the bound snapshot before
        # constructing any network client or opening a socket.
        credential = self._verified_credential()
        try:
            network = self._network_factory(deadline_seconds=timeout, socket_timeout=min(4.0, timeout),
                                            max_response_bytes=MAX_RESPONSE_BYTES)
            result = network.request(
                OPENROUTER_ENDPOINT + "/chat/completions",
                method="POST",
                headers={
                    "Authorization": "Bearer " + credential,
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    "X-Client-Request-Id": trace_id,
                },
                body=body,
                cancelled=cancelled,
            )
        except NetworkError:
            # No URL, header, body or provider response is exposed to logs.
            if cancelled():
                raise PolicyDenied("dispatch.cancelled", "Provider request was cancelled") from None
            raise TimeoutError("Provider request failed or exceeded its hard deadline") from None
        if len(result.body) > MAX_RESPONSE_BYTES:
            raise PolicyDenied("response.bounds", "Provider response exceeded its byte limit")
        input_tokens = output_tokens = 0
        try:
            decoded = json.loads(result.body)
            usage = decoded.get("usage", {}) if isinstance(decoded, dict) else {}
            if isinstance(usage, dict):
                prompt = usage.get("prompt_tokens", 0)
                completion = usage.get("completion_tokens", 0)
                if isinstance(prompt, int) and prompt >= 0:
                    input_tokens = min(prompt, 1_000_000)
                if isinstance(completion, int) and completion >= 0:
                    output_tokens = min(completion, 65_536)
        except (ValueError, UnicodeDecodeError):
            pass
        retry_after = result.headers.get("Retry-After") or result.headers.get("retry-after")
        content_type = result.headers.get("Content-Type") or result.headers.get("content-type") or "application/json"
        safe_headers = {"Content-Type": str(content_type)[:128]}
        if retry_after is not None and len(str(retry_after)) <= 128:
            safe_headers["Retry-After"] = str(retry_after)
        return ProviderResponse(result.status, result.body, safe_headers, input_tokens, output_tokens)
