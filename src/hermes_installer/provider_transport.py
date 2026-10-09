"""Bounded OpenAI-compatible provider transport for PR-F02."""
from __future__ import annotations

import json
import math
from typing import Callable, Mapping
from urllib.parse import urlsplit

from .credentials import CredentialError, resolve_secret
from .network import BoundedNetwork, NetworkError
from .policy import PolicyDenied, ProviderResponse, Route

OPENROUTER_ENDPOINT = "https://openrouter.ai/api/v1"
ALLOWED_MODELS = frozenset({"nvidia/nemotron-3-ultra-550b-a55b:free"})
MAX_REQUEST_BYTES = 4 * 1024 * 1024
MAX_RESPONSE_BYTES = 4 * 1024 * 1024


class OpenRouterTransport:
    """POST one normalized chat request to a fixed OpenRouter endpoint.

    Credentials are resolved from an explicit private reference at construction;
    they are not accepted from request JSON, route metadata, argv, or Hermes env.
    BoundedNetwork isolates DNS/connect/read behind a killable hard-deadline worker.
    """

    def __init__(self, credential_ref: str, *,
                 secret_reader: Callable[[str], str] = resolve_secret,
                 network_factory: Callable[..., BoundedNetwork] = BoundedNetwork):
        if not isinstance(credential_ref, str) or not credential_ref.startswith(("file://", "keyring://", "secret://")):
            raise CredentialError("Provider credential must use a private file or secure store reference")
        try:
            self._api_key = secret_reader(credential_ref)
        except Exception:
            raise CredentialError("Provider credential reference could not be resolved") from None
        if not isinstance(self._api_key, str) or not self._api_key or len(self._api_key) > 4096 or any(ord(c) < 32 for c in self._api_key):
            raise CredentialError("Provider credential reference is invalid")
        self._network_factory = network_factory

    def __repr__(self) -> str:
        return "OpenRouterTransport(credential_ref=<redacted>)"

    @staticmethod
    def _request_body(payload: bytes, model: str, output_limit: int) -> bytes:
        if not isinstance(payload, bytes) or len(payload) > MAX_REQUEST_BYTES:
            raise PolicyDenied("request.bounds", "Provider request exceeds its byte limit")
        if model not in ALLOWED_MODELS:
            raise PolicyDenied("route.model", "Model is not approved for the public OpenRouter route")
        if not 0 <= output_limit <= 65_536:
            raise PolicyDenied("request.bounds", "Output token limit is outside the supported range")
        try:
            value = json.loads(payload)
        except (ValueError, UnicodeDecodeError):
            raise PolicyDenied("request.format", "Provider request must be valid JSON") from None
        if not isinstance(value, dict) or not isinstance(value.get("messages"), list):
            raise PolicyDenied("request.format", "Provider request must contain a messages array")
        # Never trust caller-selected model/output fields from serialized JSON.
        value["model"] = model
        value.pop("max_completion_tokens", None)
        value.pop("max_output_tokens", None)
        value["max_tokens"] = output_limit
        try:
            encoded = json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        except (TypeError, ValueError, UnicodeEncodeError):
            raise PolicyDenied("request.format", "Provider request could not be serialized safely") from None
        if len(encoded) > MAX_REQUEST_BYTES:
            raise PolicyDenied("request.bounds", "Normalized provider request exceeds its byte limit")
        return encoded

    def __call__(self, route: Route, model: str, payload: bytes, *, timeout: float, trace_id: str) -> ProviderResponse:
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
        body = self._request_body(payload, model, 65_536)
        # Provider policy/Dispatcher has already clamped max_tokens to the user's
        # approved output limit. This adapter applies an upper ceiling as a final
        # endpoint-level guard; per-request tighter limits remain in the JSON.
        try:
            network = self._network_factory(deadline_seconds=timeout, socket_timeout=min(4.0, timeout),
                                            max_response_bytes=MAX_RESPONSE_BYTES)
            result = network.request(
                OPENROUTER_ENDPOINT + "/chat/completions",
                method="POST",
                headers={
                    "Authorization": "Bearer " + self._api_key,
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    "X-Client-Request-Id": trace_id,
                },
                body=body,
            )
        except NetworkError as exc:
            # No URL, header, body or provider response is exposed to logs.
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
        safe_headers = {"Retry-After": str(retry_after)} if retry_after is not None and len(str(retry_after)) <= 128 else {}
        return ProviderResponse(result.status, result.body, safe_headers, input_tokens, output_tokens)
