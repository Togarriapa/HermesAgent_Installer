"""Source-reviewed RB08 action schemas and source pins for finance Plugins.

Keep this catalog separate from plugin_finance.py so the adapter SHA pin is not
self-referential. Recompute the adapter digest and update all four manifest
pinned hashes if an adapter source or vendored manifest changes.
"""
from __future__ import annotations

from hashlib import sha256
from pathlib import Path
from types import MappingProxyType
from typing import Any

from hermes_installer.components.plugin_effects import PluginActionSchema


PLUGIN_FINANCE_ADAPTER_SHA256 = "54ca0bedad3a3d3ee03176c20f3ae7a71987b0992640e0647b0b702c51907c73"
_ROOT = Path(__file__).resolve().parents[3]
_PLUGIN_DIR = _ROOT / "resources/vendor/hermes-agent-resources-2.3.1/plugins"
FINANCIAL_PLUGIN_MANIFEST_SHA256 = MappingProxyType({
    "agent-live-wallet": "726ab3b7e8b6f3137310a125c8e7d18589105f20b3be859362390e2557f7e39d",
    "agent-sandbox-wallet": "c512f2c29d211ee8e407841a624d03a699114c59ea3204d94f303746510e30a1",
    "financial-data-hub": "37bbf84f32168b19df69d97296fbae09ca11d495d31d15daea159872c79b8b47",
    "financial-execution-gateway": "887192082ab9f8249cd860f00257d844fa417a74e59c30a90c94cdf88a16b133",
})


def _obj(properties: dict[str, Any], required: list[str]) -> dict[str, Any]:
    return {"type": "object", "properties": properties, "required": required,
            "additionalProperties": False}


def _str(maximum: int, minimum: int = 0, pattern: str | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {"type": "string", "minLength": minimum, "maxLength": maximum}
    if pattern is not None:
        result["pattern"] = pattern
    return result


def _freeze(value: Any) -> Any:
    if isinstance(value, dict):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    return value


def _schema(adapter: str, action_id: str, operation: str,
            arguments: dict[str, Any], result: dict[str, Any], *,
            write: bool = False, confirmation: bool = False,
            expected_state: str = "read-complete") -> PluginActionSchema:
    return PluginActionSchema(
        adapter_id=adapter, action_id=action_id,
        argument_schema_id=f"{adapter}.{action_id}.arguments.v1",
        result_schema_id=f"{adapter}.{action_id}.result.v1",
        operation=operation, adapter_sha256=PLUGIN_FINANCE_ADAPTER_SHA256,
        argument_schema=_freeze(arguments), result_schema=_freeze(result),
        request_bytes_limit=262_144, response_bytes_limit=2_097_152,
        deadline_seconds=30.0, requires_idempotency=write,
        requires_confirmation=confirmation, expected_state=expected_state,
    )


_PROVIDER = {"type": "string", "enum": ["bank-aisp", "trading212-read", "pionex-read", "ledger-read"]}
_DATA_OPERATIONS = {"type": "string", "enum": ["accounts", "balances", "transactions", "positions", "history", "dividends", "open-orders", "fills", "public-account-metadata"]}
_FILTERS = _obj({
    "from": _str(256, pattern=r"^[^\x00-\x1f]*$"), "to": _str(256, pattern=r"^[^\x00-\x1f]*$"),
    "cursor": _str(256, pattern=r"^[^\x00-\x1f]*$"), "asset": _str(256, pattern=r"^[^\x00-\x1f]*$"),
    "instrument": _str(256, pattern=r"^[^\x00-\x1f]*$"),
    "limit": {"type": "integer", "minimum": 1, "maximum": 1000},
}, [])
_DATA_RESULT = _obj({
    "items": {"type": "array", "maxItems": 1000, "items": {"type": "object"}},
    "account_alias": _str(128, 1, r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"),
}, ["items"])

_EXEC_PROVIDER = {"type": "string", "enum": ["trading212", "pionex", "regulated-pisp", "ledger-wallet-api"]}
_EXEC_OPERATIONS = {"type": "string", "enum": [
    "place-market-order", "place-limit-order", "place-stop-order", "place-stop-limit-order",
    "cancel-pending-order", "place-order", "cancel-order", "initiate-user-authorized-payment",
    "sign-user-authorized-transaction", "sign-and-broadcast-user-authorized-transaction",
]}
_EXEC_ACTION = _obj({
    "instrument": _str(128, 1, r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"),
    "side": {"type": "string", "enum": ["buy", "sell"]},
    "quantity": _str(41, 1, r"^(?:0|[1-9][0-9]{0,19})(?:\.[0-9]{1,18})?$"),
    "currency": _str(32, 1, r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,31}$"),
    "limit_price": _str(41, 1, r"^(?:0|[1-9][0-9]{0,19})(?:\.[0-9]{1,18})?$"),
    "stop_price": _str(41, 1, r"^(?:0|[1-9][0-9]{0,19})(?:\.[0-9]{1,18})?$"),
    "order_type": {"type": "string", "enum": ["limit", "market"]},
    "client_order_id": _str(128, 1, r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"),
    "provider_order_id": _str(128, 1, r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"),
    "amount": _str(41, 1, r"^(?:0|[1-9][0-9]{0,19})(?:\.[0-9]{1,18})?$"),
    "payment_reference": _str(128, 1, r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"),
    "transaction_digest": _str(64, 64, r"^[a-f0-9]{64}$"),
}, [])
_GENERIC_RESULT = {"type": "object"}

_WALLET_FIELDS: dict[str, Any] = {
    "network": _str(128, 1, r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"),
    "chain_id": {"type": "integer", "minimum": 1},
    "asset_id": _str(128, 1, r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"),
    "amount": _str(41, 1, r"^(?:0|[1-9][0-9]{0,19})(?:\.[0-9]{1,18})?$"),
    "max_fee": _str(41, 1, r"^(?:0|[1-9][0-9]{0,19})(?:\.[0-9]{1,18})?$"),
    "contract": _str(128, 1, r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"),
    "calldata_digest": _str(64, 64, r"^[a-f0-9]{64}$"),
    "test_asset": {"type": "boolean"}, "mainnet_bridge": {"type": "boolean"},
}
_WALLET_ACTION = _obj(_WALLET_FIELDS, [])

_ROWS = {
    ("financial-data-hub", "read"): _schema("financial-data-hub", "read",
        "plugin.financial-data-hub.read",
        _obj({"provider": _PROVIDER, "operation": _DATA_OPERATIONS, "filters": _FILTERS},
             ["provider", "operation", "filters"]), _DATA_RESULT),
    ("financial-execution-gateway", "execute"): _schema("financial-execution-gateway", "execute",
        "plugin.financial-execution-gateway.execute",
        _obj({"provider": _EXEC_PROVIDER, "operation": _EXEC_OPERATIONS, "action": _EXEC_ACTION},
             ["provider", "operation", "action"]), _GENERIC_RESULT,
        write=True, confirmation=True, expected_state="committed"),
    ("agent-live-wallet", "read"): _schema("agent-live-wallet", "read",
        "plugin.agent-live-wallet.read",
        _obj({"network": _str(128, 1), "operation": {"type": "string", "enum": ["construct", "simulate", "estimate-fee", "inspect"]},
              "action": _WALLET_ACTION}, ["network", "operation", "action"]), _GENERIC_RESULT),
    ("agent-live-wallet", "execute"): _schema("agent-live-wallet", "execute",
        "plugin.agent-live-wallet.execute",
        _obj({"network": _str(128, 1), "operation": {"type": "string", "enum": ["sign", "broadcast"]},
              "action": _WALLET_ACTION}, ["network", "operation", "action"]), _GENERIC_RESULT,
        write=True, confirmation=True, expected_state="committed"),
    ("agent-sandbox-wallet", "read"): _schema("agent-sandbox-wallet", "read",
        "plugin.agent-sandbox-wallet.read",
        _obj({"network": {"type": "string", "enum": ["ethereum-sepolia", "solana-devnet"]},
              "operation": {"type": "string", "enum": ["read-balance", "simulate", "inspect-receipt"]},
              "action": _WALLET_ACTION}, ["network", "operation", "action"]), _GENERIC_RESULT),
    ("agent-sandbox-wallet", "execute"): _schema("agent-sandbox-wallet", "execute",
        "plugin.agent-sandbox-wallet.execute",
        _obj({"network": {"type": "string", "enum": ["ethereum-sepolia", "solana-devnet"]},
              "operation": {"type": "string", "enum": ["create-account", "reset-account", "sign-test-transaction", "send-test-asset", "deploy-test-contract", "reviewed-testnet-dapp"]},
              "action": _WALLET_ACTION}, ["network", "operation", "action"]), _GENERIC_RESULT,
        write=True, confirmation=True, expected_state="committed"),
}

PLUGIN_ACTION_SCHEMAS = MappingProxyType(_ROWS)


def validate_financial_plugin_pins() -> None:
    """Validate exact vendored manifests and the current handler source digest."""
    source_path = Path(__file__).with_name("plugin_finance.py")
    if sha256(source_path.read_bytes()).hexdigest() != PLUGIN_FINANCE_ADAPTER_SHA256:
        raise RuntimeError("finance adapter changed; update PLUGIN_FINANCE_ADAPTER_SHA256")
    for plugin_id, expected in FINANCIAL_PLUGIN_MANIFEST_SHA256.items():
        path = _PLUGIN_DIR / f"{plugin_id}.yaml"
        if not path.is_file() or sha256(path.read_bytes()).hexdigest() != expected:
            raise RuntimeError(f"vendored {plugin_id} manifest changed; Sol review and repinning are required")
