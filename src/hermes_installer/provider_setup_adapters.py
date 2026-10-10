"""Secret-safe provider setup probes (PR-F01, PR-F03, PR-R0106).

The setup probe authenticates against documented, read-only OpenRouter
endpoints and checks the exact catalog price/parameter record. It never makes
an inference request. Catalog and key metadata are deliberately insufficient
for route activation; a current protected host admission is still required.
"""
from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from typing import Any, Callable, Mapping

from .credentials import CredentialError, resolve_secret
from .network import BoundedNetwork, NetworkError
from .setup_wizard import AccountField, AdapterResult, CredentialStore, SetupAdapter

OPENROUTER_API = "https://openrouter.ai/api/v1"
OPENROUTER_MODEL = "nvidia/nemotron-3-ultra-550b-a55b:free"
_MAX_PROBE_RESPONSE = 4 * 1024 * 1024
_MAX_PROBE_SECONDS = 8.0


@dataclass(frozen=True, slots=True)
class OpenRouterProbeResult:
    """Safe account/model facts; contains no token, raw response, or account ID."""

    credential_authenticated: bool
    is_free_tier: bool | None
    model_catalog_listed: bool
    input_price_zero: bool
    output_price_zero: bool
    supports_function_tools: bool
    context_length: int | None
    output_limit: int | None
    account_fingerprint: str

    @property
    def catalog_probe_passed(self) -> bool:
        return (self.credential_authenticated and self.model_catalog_listed
                and self.input_price_zero and self.output_price_zero
                and self.supports_function_tools)


class OpenRouterAccountProbe:
    """Fixed-origin HTTPS GET checks with redirects/proxies disabled by BoundedNetwork."""

    def __init__(self, *, network_factory: Callable[..., BoundedNetwork] = BoundedNetwork,
                 timeout: float = _MAX_PROBE_SECONDS):
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or not 1 <= timeout <= _MAX_PROBE_SECONDS:
            raise ValueError("provider probe deadline is outside its fixed bound")
        self._network_factory = network_factory
        self._timeout = float(timeout)

    def check(self, credential: str) -> OpenRouterProbeResult:
        if (not isinstance(credential, str) or not credential or len(credential) > 4096
                or any(ord(char) < 32 for char in credential)):
            raise CredentialError("OpenRouter credential is invalid")
        network = self._network_factory(
            deadline_seconds=self._timeout, socket_timeout=min(4.0, self._timeout),
            max_response_bytes=_MAX_PROBE_RESPONSE)
        headers = {"Authorization": "Bearer " + credential,
                   "Accept": "application/json"}
        # These two fixed GETs only validate the key endpoint and public model
        # catalog. They do not test account-specific inference entitlement.
        key_reply = self._get_json(network, OPENROUTER_API + "/key", headers)
        key_data = key_reply.get("data")
        if not isinstance(key_data, dict):
            raise RuntimeError("OpenRouter key check returned an unrecognized response")
        account_id = key_data.get("creator_user_id")
        fingerprint = hashlib.sha256(account_id.encode("utf-8")).hexdigest()[:20] if isinstance(account_id, str) and account_id else ""
        free_flag = key_data.get("is_free_tier")
        if not isinstance(free_flag, bool):
            free_flag = None

        catalog = self._get_json(network, OPENROUTER_API + "/models", headers)
        rows = catalog.get("data")
        if not isinstance(rows, list) or len(rows) > 100_000:
            raise RuntimeError("OpenRouter model catalog response is invalid")
        model = next((row for row in rows if isinstance(row, dict) and row.get("id") == OPENROUTER_MODEL), None)
        if model is None:
            return OpenRouterProbeResult(True, free_flag, False, False, False,
                                         False, None, None, fingerprint)
        pricing = model.get("pricing")
        price_in = _zero_price(pricing.get("prompt")) if isinstance(pricing, dict) else False
        price_out = _zero_price(pricing.get("completion")) if isinstance(pricing, dict) else False
        params = model.get("supported_parameters")
        supports_tools = isinstance(params, list) and "tools" in params and "tool_choice" in params
        context = _bounded_int(model.get("context_length"), maximum=10_000_000)
        output = _bounded_int(model.get("max_completion_tokens"), maximum=1_000_000)
        return OpenRouterProbeResult(True, free_flag, True, price_in, price_out,
                                     supports_tools, context, output, fingerprint)

    def check_reference(self, credential_ref: str, *, secret_resolver: Callable[[str], str] = resolve_secret) -> OpenRouterProbeResult:
        try:
            credential = secret_resolver(credential_ref)
        except Exception:
            raise CredentialError("OpenRouter credential reference could not be resolved") from None
        return self.check(credential)

    @staticmethod
    def _get_json(network: BoundedNetwork, url: str, headers: Mapping[str, str]) -> dict[str, Any]:
        try:
            reply = network.request(url, method="GET", headers=headers)
        except NetworkError:
            raise RuntimeError("OpenRouter read-only connection probe failed") from None
        if reply.status != 200:
            # Never echo provider error bodies (they may contain account data).
            raise RuntimeError(f"OpenRouter read-only probe returned HTTP {reply.status}")
        content_type = next((value for key, value in reply.headers.items()
                             if key.casefold() == "content-type"), "")
        if not content_type.casefold().startswith("application/json") or len(reply.body) > _MAX_PROBE_RESPONSE:
            raise RuntimeError("OpenRouter read-only probe returned an unexpected response")
        try:
            value = json.loads(reply.body, object_pairs_hook=_unique_pairs)
        except (ValueError, UnicodeDecodeError):
            raise RuntimeError("OpenRouter read-only probe returned malformed JSON") from None
        if not isinstance(value, dict):
            raise RuntimeError("OpenRouter read-only probe returned an invalid JSON object")
        return value


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _zero_price(value: Any) -> bool:
    if not isinstance(value, (str, int, float)) or isinstance(value, bool):
        return False
    try:
        decimal = Decimal(str(value))
    except (InvalidOperation, ValueError):
        return False
    return decimal.is_finite() and decimal == 0


def _bounded_int(value: Any, *, maximum: int) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
        return None
    return value


class OpenRouterSetupAdapter:
    name = "providers"
    supported_providers = frozenset({"openrouter"})
    fields = (
        AccountField("openrouter_api_key", "An OpenRouter API key for the requested free model route.",
                     "Setup checks the key and exact public model catalog using read-only requests; it never sends a prompt.",
                     "https://openrouter.ai/docs/api/api-reference/api-keys/get-current-key",
                     ("Create or select an API key in your OpenRouter account.",
                      "The installer enters it without echo and stores it through the configured credential store.",
                      "Additional metered spend remains $0; only the exact `:free` model is eligible for later protected admission."),
                     "A valid OpenRouter account is required. Model catalog visibility is not account inference entitlement.", True),
    )

    def __init__(self, *, probe_factory: Callable[[], OpenRouterAccountProbe] = OpenRouterAccountProbe,
                 persist_reference: Callable[[str, str, OpenRouterProbeResult], None] | None = None,
                 credential_reference: str | None = None,
                 secret_resolver: Callable[[str], str] = resolve_secret):
        self._probe_factory = probe_factory
        # This callback must persist only the opaque reference and safe status
        # into installer-private setup state. It cannot enroll a root route.
        self._persist_reference = persist_reference
        self._credential_reference = credential_reference
        self._secret_resolver = secret_resolver

    def select_provider(self, name: str) -> None:
        if not isinstance(name, str) or name.casefold() not in self.supported_providers:
            raise ValueError("only the reviewed OpenRouter provider setup is available")

    def configure(self, config: Mapping[str, Any], *, input_fn: Callable[[str], str],
                  output_fn: Callable[[str], None], secret_reader: Callable[[str], str],
                  credential_store: CredentialStore, remote_journal: Any = None) -> AdapterResult:
        del remote_journal
        output_fn("Provider account setup (additional metered budget: $0)")
        for field in self.fields:
            output_fn(f"{field.name}: {field.what}")
            output_fn(f"  Why: {field.why}")
            output_fn(f"  Official setup: {field.official_url}")
            for index, step in enumerate(field.steps, 1):
                output_fn(f"  {index}. {step}")
        prior = self._credential_reference
        if prior:
            credential_ref = prior
            credential = None
        else:
            answer = input_fn("Configure OpenRouter now, or type 'later' to continue: ").strip().casefold()
            if answer == "later":
                return AdapterResult("pending", "OpenRouter setup was deferred; all remote model routes remain disabled.",
                                     {"privacy": _zero_budget(config)},
                                     ("Run the provider setup wizard in a terminal when ready.",))
            try:
                credential = secret_reader("OpenRouter API key (input hidden): ")
            except Exception:
                return AdapterResult("failed", "OpenRouter key could not be read through hidden input.",
                                     {"privacy": _zero_budget(config)},
                                     ("Use a terminal with hidden-input support, then rerun provider setup.",))
            if not isinstance(credential, str) or not credential or len(credential) > 4096 or any(ord(c) < 32 for c in credential):
                return AdapterResult("failed", "OpenRouter key input is invalid.",
                                     {"privacy": _zero_budget(config)},
                                     ("Provide a valid key through hidden terminal input.",))
        try:
            probe = self._probe_factory()
            observation = probe.check(credential) if credential is not None else probe.check_reference(
                credential_ref, secret_resolver=self._secret_resolver)
        except Exception as exc:
            del exc
            return AdapterResult("pending", "OpenRouter read-only account/model checks did not complete; no inference was sent and the route remains disabled.",
                                 {"privacy": _zero_budget(config)},
                                 ("Check network and key validity, then rerun provider setup. No model-generation request was made.",))

        if not observation.catalog_probe_passed:
            return AdapterResult("pending", "The OpenRouter key check passed, but the exact free-model price/tool catalog check did not; the route remains disabled.",
                                 {"privacy": _zero_budget(config)},
                                 ("Confirm the exact model remains listed at zero input/output price with function-tool support, then rerun setup.",))
        if credential is not None and self._persist_reference is None:
            return AdapterResult("pending", "Read-only OpenRouter checks passed, but private setup-state persistence is unavailable; the key was not stored and the route remains disabled.",
                                 {"privacy": _zero_budget(config)},
                                 ("Rerun provider setup after the private credential-reference journal is available. No inference was sent.",))
        if credential is not None:
            try:
                credential_ref = credential_store.put("openrouter-provider", credential)
            except Exception:
                return AdapterResult("failed", "OpenRouter key could not be stored by the configured secure credential store.",
                                     {"privacy": _zero_budget(config)},
                                     ("Check the installer credential-store permissions and rerun provider setup.",))
        if self._persist_reference is not None:
            try:
                self._persist_reference("openrouter", credential_ref, observation)
            except Exception:
                return AdapterResult("pending", "The read-only OpenRouter checks passed, but the opaque credential reference could not be saved in private setup state; the route remains disabled.",
                                     {"privacy": _zero_budget(config)},
                                     ("Repair private installer state storage and rerun provider setup.",))
        output_fn("OpenRouter key authentication and the exact free-model catalog checks passed. No inference was sent; account entitlement, effective privacy eligibility, protected host enrollment, and native dispatch remain pending.")
        return AdapterResult("pending", "Read-only key and catalog checks passed. No inference was sent; account-specific entitlement/privacy and root-enrolled native dispatch are still unverified.",
                             {"privacy": _zero_budget(config)},
                             ("Keep provider routes disabled until the protected host admission and native source-bound dispatch path are enrolled and verified.",))

    def configure_noninteractive(self, config: Mapping[str, Any], *, credential_store: CredentialStore) -> AdapterResult:
        del credential_store
        reference = self._credential_reference
        if not reference:
            return AdapterResult("pending", "No secure OpenRouter credential reference is configured; provider setup remains pending.",
                                 {"privacy": _zero_budget(config)},
                                 ("Run provider setup in a terminal and provide the key through hidden input.",))
        try:
            observation = self._probe_factory().check_reference(reference, secret_resolver=self._secret_resolver)
        except Exception:
            return AdapterResult("pending", "OpenRouter read-only account/model checks failed; provider routes remain disabled.",
                                 {"privacy": _zero_budget(config)},
                                 ("Check the secure credential reference and network, then rerun setup.",))
        if not observation.catalog_probe_passed:
            return AdapterResult("pending", "OpenRouter key or exact free-model catalog validation is incomplete; provider routes remain disabled.",
                                 {"privacy": _zero_budget(config)},
                                 ("Review the account key and exact model catalog, then rerun setup.",))
        return AdapterResult("pending", "Read-only checks passed; account-specific admission and native dispatch are not verified.",
                             {"privacy": _zero_budget(config)},
                             ("Keep provider routes disabled until protected account and native-boundary verification completes.",))

    def test_connection(self, config: Mapping[str, Any]) -> AdapterResult:
        """Run only the same bounded, GET-only probe against the saved ref."""
        return self.configure_noninteractive(config, credential_store=_ReferenceOnlyStore())


def _zero_budget(config: Mapping[str, Any]) -> Mapping[str, Any]:
    privacy = config.get("privacy")
    selected = dict(privacy) if isinstance(privacy, Mapping) else {}
    # The strict config only supports zero budget at this stage.
    selected["additional_metered_budget"] = 0
    return selected


class _ReferenceOnlyStore:
    """Sentinel store proving connection tests never write credentials."""

    def put(self, _name: str, _value: str) -> str:
        raise AssertionError("test-connection must not store a credential")


def build_provider_setup_adapter(*, probe_factory: Callable[[], OpenRouterAccountProbe] = OpenRouterAccountProbe,
                                 persist_reference: Callable[[str, str, OpenRouterProbeResult], None] | None = None,
                                 credential_reference: str | None = None,
                                 secret_resolver: Callable[[str], str] = resolve_secret) -> SetupAdapter:
    """Build the `providers` wizard adapter; no root route is enabled here."""
    return OpenRouterSetupAdapter(probe_factory=probe_factory, persist_reference=persist_reference,
                                  credential_reference=credential_reference,
                                  secret_resolver=secret_resolver)
