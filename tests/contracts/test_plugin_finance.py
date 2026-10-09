from __future__ import annotations

from datetime import datetime, timezone
import unittest
import tempfile
from pathlib import Path
import hashlib
import json

from hermes_installer.components.plugin_finance import (
    AgentLiveWalletImplementation, AgentSandboxWalletImplementation, AgentWallet,
    DataOperation, DataProvider, FinancialDataHub, FinancialDataHubImplementation,
    FinancialExecutionGateway, FinancialExecutionGatewayImplementation,
    FinanceDenied, FinanceUnavailable,
    NetworkClass, NetworkEnrollment,
    SQLiteExecutionLedger, WalletAction,
    PLUGIN_ACTION_SCHEMAS,
)
from hermes_installer.components.plugin_effects import StaticPluginActionSchemas, _validate_schema
from hermes_installer.components.plugin_finance_schemas import (
    FINANCIAL_PLUGIN_MANIFEST_SHA256, PLUGIN_FINANCE_ADAPTER_SHA256,
    validate_financial_plugin_pins,
)


class ReadBroker:
    def __init__(self, reply=None):
        self.reply = reply if reply is not None else [{"balance": "12.5", "currency": "EUR",
            "timestamp": "2026-10-09T10:00:00Z", "account_id": "private-id",
            "access_token": "never-return"}]
        self.calls = []

    def read(self, **kwargs):
        self.calls.append(kwargs)
        return self.reply


class Confirmation:
    def __init__(self, *, reject=False):
        self.calls = []
        self.reject = reject

    def consume_financial_confirmation(self, **kwargs):
        self.calls.append(kwargs)
        if self.reject:
            raise FinanceDenied("stale or mismatched order")
        return {"grant": "root-only-fixture", "digest": kwargs["payload_digest"]}


class Ledger:
    def __init__(self):
        self.rows = {}

    def claim(self, execution_id, payload_digest):
        prior = self.rows.get(execution_id)
        if prior:
            if prior["digest"] != payload_digest:
                raise FinanceDenied("execution identity collision")
            return "already-attempted"
        self.rows[execution_id] = {"digest": payload_digest, "state": "claimed", "receipt": {}}
        return "new"

    def finish(self, execution_id, state, receipt):
        self.rows[execution_id]["state"] = state
        self.rows[execution_id]["receipt"] = dict(receipt)

    def get(self, execution_id):
        row = self.rows.get(execution_id)
        return None if row is None else {"state": row["state"], "receipt": row["receipt"], "payload_digest": row["digest"]}


class ExecutionBroker:
    def __init__(self, *, ambiguous=False, matched=True):
        self.calls = []
        self.ambiguous = ambiguous
        self.matched = matched

    def preflight(self, **kwargs):
        self.calls.append(("preflight", kwargs))
        return {"ready": True, "payload_digest": __import__("hashlib").sha256(
            __import__("json").dumps({"provider": kwargs["provider"], "account_ref": kwargs["account_ref"],
                "operation": kwargs["operation"], "payload": kwargs["payload"]},
                sort_keys=True, separators=(",", ":")).encode()).hexdigest()}

    def execute_once(self, **kwargs):
        self.calls.append(("execute", kwargs))
        if self.ambiguous:
            raise TimeoutError("fixture: provider may have committed")
        return {"provider_reference": "provider-order-1"}

    def reconcile(self, **kwargs):
        self.calls.append(("reconcile", kwargs))
        return {"matched": self.matched, "state": "filled", "access_token": "do-not-leak"}


class WalletBroker:
    def __init__(self):
        self.calls = []

    def preflight_wallet(self, **kwargs):
        self.calls.append({"preflight": kwargs})
        action = kwargs["action"]
        if "test_asset" in action:
            return {"ready": True, "payload_digest": hashlib.sha256(json.dumps(
                action, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")).hexdigest()}
        fields = {key: action.get(key) for key in WalletAction.__dataclass_fields__}
        return {"ready": True, "payload_digest": WalletAction(**fields).canonical_digest()}

    def wallet_action(self, **kwargs):
        self.calls.append(kwargs)
        return {"status": "ok", "seed_phrase": "must-not-escape", "transaction_id": "tx-1"}


class PluginContext:
    def __init__(self):
        self.tools = {}

    def register_tool(self, **kwargs):
        self.tools[kwargs["name"]] = kwargs


class PluginRuntime:
    def __init__(self, resource_id, effects=None):
        versions = {"financial-data-hub": "1.0.1", "agent-live-wallet": "1.0.0",
                    "agent-sandbox-wallet": "1.0.0", "financial-execution-gateway": "1.0.0"}
        self.identity = type("Identity", (), {"kind": "plugins", "resource_id": resource_id,
            "version": versions.get(resource_id, "1.0.0")})()
        self.plugin_effects = effects


class EffectSpy:
    def __init__(self, state="read-complete"):
        self.calls = []
        self.state = state

    def invoke(self, **kwargs):
        self.calls.append(kwargs)
        return {"schema": 1, "operation_id": "fixture-op", "state": self.state,
                "result": {"items": [{"balance": "10", "access_token": "secret"}]},
                "verification_status": "verified" if self.state == "committed" else "not-applicable",
                "resume_action_id": None}


class ExecutionSpy:
    def __init__(self):
        self.invocations = []

    def execute(self, **kwargs):
        self.invocations.append(kwargs["invocation"])
        return {"accepted": True}


class PluginFinanceTests(unittest.TestCase):
    def test_static_root_action_schemas_pin_all_finance_adapters_and_effect_states(self):
        expected = {
            ("financial-data-hub", "read"): ("plugin.financial-data-hub.read", "read-complete", False, False),
            ("financial-execution-gateway", "execute"): ("plugin.financial-execution-gateway.execute", "committed", True, True),
            ("agent-live-wallet", "read"): ("plugin.agent-live-wallet.read", "read-complete", False, False),
            ("agent-live-wallet", "execute"): ("plugin.agent-live-wallet.execute", "committed", True, True),
            ("agent-sandbox-wallet", "read"): ("plugin.agent-sandbox-wallet.read", "read-complete", False, False),
            ("agent-sandbox-wallet", "execute"): ("plugin.agent-sandbox-wallet.execute", "committed", True, True),
        }
        self.assertEqual(set(PLUGIN_ACTION_SCHEMAS), set(expected))
        catalog = StaticPluginActionSchemas(PLUGIN_ACTION_SCHEMAS)
        for key, (operation, state, idem, confirmation) in expected.items():
            row = catalog.resolve(*key)
            self.assertEqual(row.operation, operation)
            self.assertEqual(row.expected_state, state)
            self.assertEqual(row.requires_idempotency, idem)
            self.assertEqual(row.requires_confirmation, confirmation)
            self.assertTrue(row.argument_schema_id.endswith(".arguments.v1"))
            self.assertTrue(row.result_schema_id.endswith(".result.v1"))
            self.assertEqual(row.adapter_sha256, PLUGIN_FINANCE_ADAPTER_SHA256)
            self.assertEqual(row.request_bytes_limit, 262_144)
            self.assertEqual(row.response_bytes_limit, 2_097_152)
            self.assertEqual(row.deadline_seconds, 30.0)
        _validate_schema(catalog.resolve("financial-data-hub", "read").argument_schema,
                         {"provider": "bank-aisp", "operation": "balances", "filters": {"limit": 20}})
        _validate_schema(catalog.resolve("financial-execution-gateway", "execute").argument_schema,
                         {"provider": "trading212", "operation": "place-market-order",
                          "action": {"instrument": "ACME", "side": "buy", "quantity": "1", "currency": "EUR"}})
        _validate_schema(catalog.resolve("agent-sandbox-wallet", "execute").argument_schema,
                         {"network": "ethereum-sepolia", "operation": "create-account",
                          "action": {"mainnet_bridge": False}})
        with self.assertRaises(PermissionError):
            _validate_schema(catalog.resolve("financial-execution-gateway", "execute").argument_schema,
                {"provider": "trading212", "operation": "place-market-order", "account": "model-chosen",
                 "action": {"instrument": "ACME", "side": "buy", "quantity": "1", "currency": "EUR"}})
        self.assertIsNone(catalog.resolve("financial-execution-gateway", "withdraw"))
        self.assertEqual(set(FINANCIAL_PLUGIN_MANIFEST_SHA256), {
            "agent-live-wallet", "agent-sandbox-wallet", "financial-data-hub", "financial-execution-gateway"})
        validate_financial_plugin_pins()

    def test_data_hub_is_read_only_scoped_and_redacts_provider_identifiers(self):
        broker = ReadBroker()
        hub = FinancialDataHub(broker,
            credential_refs={DataProvider.BANK_AISP: "BANK_READ_CREDENTIAL"},
            account_refs={DataProvider.BANK_AISP: "BANK_READ_ACCOUNT"},
            account_aliases={DataProvider.BANK_AISP: "bank-main"},
            clock=lambda: datetime(2026, 10, 9, tzinfo=timezone.utc))
        result = hub.read(DataProvider.BANK_AISP, DataOperation.BALANCES)
        self.assertEqual(len(broker.calls), 1)
        self.assertEqual(broker.calls[0]["timeout_seconds"], 8.0)
        self.assertEqual(result[0].data, {"balance": "12.5", "currency": "EUR"})
        self.assertEqual(result[0].account_alias, "bank-main")
        self.assertEqual(result[0].freshness, "timestamped")
        with self.assertRaises(FinanceDenied):
            hub.read(DataProvider.BANK_AISP, DataOperation.BALANCES, filters={"url": "https://evil.invalid"})
        with self.assertRaises(FinanceDenied):
            hub.read(DataProvider.BANK_AISP, DataOperation.ACCOUNTS, filters={"limit": 1001})
        with self.assertRaises(TypeError):
            hub.read(DataProvider.BANK_AISP, DataOperation.BALANCES, account_alias="attacker-selected")
        with self.assertRaises(FinanceDenied):
            hub.read(DataProvider.LEDGER_READ, DataOperation.PUBLIC_ACCOUNT_METADATA)
        self.assertEqual(len(broker.calls), 1)

    def test_data_hub_rejects_execution_scope_and_cross_account_reference_mismatch(self):
        broker = ReadBroker()
        with self.assertRaises(FinanceUnavailable):
            FinancialDataHub(broker,
                credential_refs={DataProvider.BANK_AISP: "BANK_READ_CREDENTIAL"}, account_refs={}, account_aliases={})
        hub = FinancialDataHub(broker,
            credential_refs={DataProvider.TRADING212_READ: "T212_READ_CREDENTIAL"},
            account_refs={DataProvider.TRADING212_READ: "T212_READ_ACCOUNT"},
            account_aliases={DataProvider.TRADING212_READ: "broker-main"})
        with self.assertRaises(FinanceDenied):
            hub.read(DataProvider.TRADING212_READ, DataOperation.BALANCES)
        self.assertEqual(broker.calls, [])

    def _gateway(self, *, confirmation=None, broker=None, ledger=None):
        return FinancialExecutionGateway(broker=broker or ExecutionBroker(),
            confirmation_authority=confirmation or Confirmation(), ledger=ledger or Ledger(),
            enrolled_accounts={"my-account": "T212_EXECUTION_ACCOUNT"})

    def _order(self):
        return type("Invocation", (), {"order_id": "hermes-order-21"})()

    def _action(self):
        return {"instrument": "ACME", "side": "buy", "quantity": "2", "currency": "EUR",
                "limit_price": "10.5", "client_order_id": "client-order-21"}

    def test_execution_preflights_exact_payload_then_consumes_one_shot_authority(self):
        broker, confirmation = ExecutionBroker(), Confirmation()
        gateway = self._gateway(confirmation=confirmation, broker=broker)
        receipt = gateway.execute(provider="trading212", account="my-account",
            operation="place-limit-order", action=self._action(), invocation=self._order())
        self.assertEqual(receipt["state"], "reconciled")
        self.assertEqual([call[0] for call in broker.calls], ["preflight", "execute", "reconcile"])
        self.assertEqual(confirmation.calls[0]["ttl_seconds"], 300)
        self.assertEqual(broker.calls[1][1]["effect_grant"]["digest"], confirmation.calls[0]["payload_digest"])
        self.assertEqual(broker.calls[1][1]["timeout_seconds"], 8.0)
        self.assertNotIn("access_token", receipt["reconciliation"])

    def test_confirmation_rejection_stops_before_provider_write(self):
        broker = ExecutionBroker()
        gateway = self._gateway(confirmation=Confirmation(reject=True), broker=broker)
        with self.assertRaises(FinanceDenied):
            gateway.execute(provider="trading212", account="my-account", operation="place-limit-order",
                action=self._action(), invocation=self._order())
        self.assertEqual([call[0] for call in broker.calls], ["preflight"])

    def test_execution_account_operation_and_payload_are_independently_scoped(self):
        broker = ExecutionBroker()
        gateway = self._gateway(broker=broker)
        with self.assertRaises(FinanceDenied):
            gateway.execute(provider="trading212", account="other-account", operation="place-limit-order",
                action=self._action(), invocation=self._order())
        with self.assertRaises(FinanceDenied):
            gateway.execute(provider="trading212", account="my-account", operation="withdraw-funds",
                action=self._action(), invocation=self._order())
        invalid = self._action() | {"recipient": "attacker"}
        with self.assertRaises(FinanceDenied):
            gateway.execute(provider="trading212", account="my-account", operation="place-limit-order",
                action=invalid, invocation=self._order())
        self.assertEqual(broker.calls, [])

    def test_ambiguous_provider_result_is_durable_and_never_retried(self):
        broker, ledger = ExecutionBroker(ambiguous=True), Ledger()
        gateway = self._gateway(broker=broker, ledger=ledger)
        with self.assertRaisesRegex(FinanceUnavailable, "ambiguous"):
            gateway.execute(provider="trading212", account="my-account", operation="place-limit-order",
                action=self._action(), invocation=self._order())
        self.assertEqual(ledger.rows[next(iter(ledger.rows))]["state"], "ambiguous-provider-state")
        with self.assertRaisesRegex(FinanceDenied, "already attempted"):
            gateway.execute(provider="trading212", account="my-account", operation="place-limit-order",
                action=self._action(), invocation=self._order())
        self.assertEqual([call[0] for call in broker.calls], ["preflight", "execute"])

    def test_ambiguous_execution_can_only_be_reconciled_never_resubmitted(self):
        broker, ledger = ExecutionBroker(ambiguous=True), Ledger()
        gateway = self._gateway(broker=broker, ledger=ledger)
        with self.assertRaises(FinanceUnavailable):
            gateway.execute(provider="trading212", account="my-account", operation="place-limit-order",
                action=self._action(), invocation=self._order())
        execution_id = next(iter(ledger.rows))
        with self.assertRaises(FinanceDenied):
            gateway.reconcile_ambiguous(execution_id=execution_id, provider="pionex", account="my-account")
        self.assertEqual([call[0] for call in broker.calls], ["preflight", "execute"])
        result = gateway.reconcile_ambiguous(execution_id=execution_id, provider="trading212", account="my-account")
        self.assertEqual(result["state"], "reconciled")
        self.assertEqual([call[0] for call in broker.calls], ["preflight", "execute", "reconcile"])
        with self.assertRaises(FinanceDenied):
            gateway.reconcile_ambiguous(execution_id=execution_id, provider="trading212", account="my-account")

    def test_sqlite_ledger_claim_is_durable_atomic_and_private(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "executions.sqlite3"
            first = SQLiteExecutionLedger(path)
            execution_id, digest = "a" * 64, "b" * 64
            self.assertEqual(first.claim(execution_id, digest), "new")
            first.finish(execution_id, "executing", {"payload_digest": digest, "access_token": "omit"})
            first.finish(execution_id, "ambiguous-provider-state", {"payload_digest": digest})
            reopened = SQLiteExecutionLedger(path)
            self.assertEqual(reopened.claim(execution_id, digest), "ambiguous-provider-state")
            self.assertNotIn("access_token", reopened.get(execution_id)["receipt"])
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FinanceDenied):
                reopened.claim(execution_id, "c" * 64)

    def test_reconciliation_mismatch_blocks_success_receipt(self):
        broker, ledger = ExecutionBroker(matched=False), Ledger()
        gateway = self._gateway(broker=broker, ledger=ledger)
        with self.assertRaisesRegex(FinanceUnavailable, "reconciled"):
            gateway.execute(provider="pionex", account="my-account", operation="place-order",
                action={"instrument": "BTC-USDT", "side": "buy", "quantity": "0.1", "currency": "USDT", "order_type": "limit", "limit_price": "100"}, invocation=self._order())
        self.assertEqual(ledger.rows[next(iter(ledger.rows))]["state"], "reconciliation-failed")

    def test_wallet_network_rpc_asset_and_live_confirmation_boundaries(self):
        rpc = NetworkEnrollment("ethereum-mainnet", NetworkClass.MAINNET, 1,
            "RPC_ETH_MAINNET", frozenset({"ETH"}))
        broker, confirmation = WalletBroker(), Confirmation()
        with self.assertRaises(FinanceUnavailable):
            AgentWallet(broker=broker, wallet_ref="LIVE_WALLET_REF", networks={rpc.name: rpc}, sandbox=False)
        live = AgentWallet(broker=broker, wallet_ref="LIVE_WALLET_REF", networks={rpc.name: rpc},
            sandbox=False, confirmation_authority=confirmation)
        action = {"network": rpc.name, "chain_id": 1, "source_account": "live-account",
            "destination": "merchant", "asset_id": "ETH", "amount": "0.01", "max_fee": "0.002"}
        with self.assertRaises(FinanceDenied):
            live.act(network_name=rpc.name, operation="sign", action=action)
        result = live.act(network_name=rpc.name, operation="sign", action=action,
                          invocation=self._order())
        self.assertEqual(result, {"status": "ok", "transaction_id": "tx-1"})
        self.assertEqual(confirmation.calls[0]["ttl_seconds"], 300)
        self.assertEqual(len(broker.calls), 2)
        self.assertNotIn("secret", repr(live))
        wrong_chain = action | {"chain_id": True}
        with self.assertRaises(FinanceDenied):
            live.act(network_name=rpc.name, operation="broadcast", action=wrong_chain,
                     invocation=self._order())
        wrong_asset = action | {"asset_id": "UNKNOWN"}
        with self.assertRaises(FinanceDenied):
            live.act(network_name=rpc.name, operation="construct", action=wrong_asset)

    def test_live_wallet_rejected_fresh_confirmation_stops_before_signer_effect(self):
        rpc = NetworkEnrollment("ethereum-mainnet", NetworkClass.MAINNET, 1,
            "RPC_ETH_MAINNET", frozenset({"ETH"}))
        broker, confirmation = WalletBroker(), Confirmation(reject=True)
        live = AgentWallet(broker=broker, wallet_ref="LIVE_WALLET_REF", networks={rpc.name: rpc},
            sandbox=False, confirmation_authority=confirmation)
        action = {"network": rpc.name, "chain_id": 1, "source_account": "live-account",
            "destination": "merchant", "asset_id": "ETH", "amount": "0.01", "max_fee": "0.002"}
        with self.assertRaises(FinanceDenied):
            live.act(network_name=rpc.name, operation="sign", action=action, invocation=self._order())
        self.assertEqual(len(broker.calls), 1)
        self.assertIn("preflight", broker.calls[0])

    def test_sandbox_rejects_production_rpc_and_non_test_asset(self):
        broker = WalletBroker()
        mainnet = NetworkEnrollment("ethereum-mainnet", NetworkClass.MAINNET, 1,
            "RPC_ETH_MAINNET", frozenset({"ETH"}))
        with self.assertRaises(FinanceDenied):
            AgentWallet(broker=broker, wallet_ref="TEST_WALLET_REF",
                networks={mainnet.name: mainnet}, sandbox=True)
        sep = NetworkEnrollment("ethereum-sepolia", NetworkClass.TESTNET, 11155111,
            "RPC_SEPOLIA", frozenset({"TETH"}))
        sandbox = AgentWallet(broker=broker, wallet_ref="TEST_WALLET_REF",
            networks={sep.name: sep}, sandbox=True)
        action = {"network": sep.name, "chain_id": sep.chain_id, "asset_id": "TETH",
            "source_account": "test-account", "destination": "test-recipient", "amount": "1", "max_fee": "0.01",
            "test_asset": True, "mainnet_bridge": False}
        with self.assertRaises(FinanceDenied):
            sandbox.act(network_name=sep.name, operation="send-test-asset", action=action | {"mainnet_bridge": True})
        with self.assertRaises(FinanceDenied):
            sandbox.act(network_name=sep.name, operation="send-test-asset", action=action | {"asset_id": "USDC"})
        self.assertEqual(broker.calls, [])
        receipt = sandbox.act(network_name=sep.name, operation="send-test-asset", action=action)
        self.assertEqual(receipt["transaction_id"], "tx-1")
        self.assertEqual(len(broker.calls), 2)

    def test_rpc_configuration_is_a_service_id_not_an_arbitrary_url(self):
        with self.assertRaises(FinanceDenied):
            NetworkEnrollment("ethereum-sepolia", NetworkClass.TESTNET, 11155111,
                "https://rpc.evil.invalid", frozenset({"TETH"}))

    def test_native_finance_tools_call_only_root_selected_effect_boundary(self):
        effects = EffectSpy()
        runtime = PluginRuntime("financial-data-hub", effects)
        context = PluginContext()
        FinancialDataHubImplementation().register(context, runtime)
        tool = context.tools["financial_data_read"]
        result = tool["handler"]({"provider": "bank-aisp", "operation": "balances"})
        self.assertEqual(effects.calls[0]["adapter_id"], "financial-data-hub")
        self.assertEqual(effects.calls[0]["action_id"], "read")
        self.assertEqual(effects.calls[0]["arguments"]["operation"], "balances")
        self.assertNotIn("financial_data", vars(runtime))
        self.assertNotIn("access_token", str(result))

    def test_registered_tool_schemas_reuse_exact_catalog_without_account_or_recipient(self):
        for adapter, implementation, name in (
            ("financial-execution-gateway", FinancialExecutionGatewayImplementation(), "financial_execute_one_order"),
            ("agent-live-wallet", AgentLiveWalletImplementation(), "agent_live_wallet_action"),
            ("agent-sandbox-wallet", AgentSandboxWalletImplementation(), "agent_sandbox_wallet_action"),
        ):
            runtime = PluginRuntime(adapter, EffectSpy("committed"))
            context = PluginContext()
            implementation.register(context, runtime)
            schema = context.tools[name]["schema"]
            self.assertFalse(schema.get("additionalProperties", True))
            self.assertNotIn("account", schema["properties"])
            self.assertNotIn("recipient", schema["properties"])
            if adapter != "financial-execution-gateway":
                nested = schema["properties"]["action"]["properties"]
                self.assertNotIn("destination", nested)
                self.assertNotIn("source_account", nested)
                self.assertTrue(set(schema["properties"]["operation"]["enum"]) & {"sign", "send-test-asset"})
            else:
                self.assertIn("opaque_confirmation_attestation_id", schema["required"])

    def test_execution_requires_opaque_fresh_confirmation_and_root_dispatch(self):
        effects = EffectSpy("committed")
        runtime = PluginRuntime("financial-execution-gateway", effects)
        context = PluginContext()
        FinancialExecutionGatewayImplementation().register(context, runtime)
        tool = context.tools["financial_execute_one_order"]
        base = {"provider": "trading212", "operation": "place-market-order",
                "action": {"instrument": "ACME", "side": "buy", "quantity": "1", "currency": "EUR"}}
        with self.assertRaises(FinanceDenied):
            tool["handler"](base | {"opaque_confirmation_attestation_id": "x"})
        confirmation = "attestation_handle_123456"
        result = tool["handler"](base | {"opaque_confirmation_attestation_id": confirmation})
        call = effects.calls[0]
        self.assertEqual(call["action_id"], "execute")
        self.assertEqual(call["opaque_confirmation_attestation_id"], confirmation)
        self.assertNotIn("account", call["arguments"])
        self.assertNotIn("opaque_confirmation_attestation_id", call["arguments"])
        self.assertEqual(call["idempotency_key"], hashlib.sha256(json.dumps({
            "adapter": "financial-execution-gateway", "action": call["action_id"],
            "arguments": call["arguments"], "confirmation": confirmation}, sort_keys=True,
            separators=(",", ":"), ensure_ascii=True).encode("ascii")).hexdigest())
        self.assertEqual(result["items"][0]["balance"], "10")
        self.assertNotIn("access_token", str(result))

    def test_wallet_tools_use_fixed_root_actions_and_sandbox_constraints(self):
        live_effects = EffectSpy()
        live_runtime = PluginRuntime("agent-live-wallet", live_effects)
        live_context = PluginContext()
        AgentLiveWalletImplementation().register(live_context, live_runtime)
        live_tool = live_context.tools["agent_live_wallet_action"]
        with self.assertRaises(FinanceDenied):
            live_tool["handler"]({"network": "mainnet", "operation": "broadcast", "action": {}})
        live_tool["handler"]({"network": "ethereum-mainnet", "operation": "inspect", "action": {}})
        self.assertEqual(live_effects.calls[0]["action_id"], "read")

        sandbox_effects = EffectSpy("committed")
        sandbox_runtime = PluginRuntime("agent-sandbox-wallet", sandbox_effects)
        sandbox_context = PluginContext()
        AgentSandboxWalletImplementation().register(sandbox_context, sandbox_runtime)
        sandbox_tool = sandbox_context.tools["agent_sandbox_wallet_action"]
        with self.assertRaises(FinanceDenied):
            sandbox_tool["handler"]({"network": "ethereum-sepolia", "operation": "send-test-asset",
                "action": {"test_asset": True, "mainnet_bridge": True},
                "opaque_confirmation_attestation_id": "attestation_handle_123456"})
        with self.assertRaises(FinanceDenied):
            sandbox_tool["handler"]({"network": "ethereum-sepolia", "operation": "create-account",
                "action": {}, "opaque_confirmation_attestation_id": "attestation_handle_123456"})
        sandbox_tool["handler"]({"network": "ethereum-sepolia", "operation": "create-account",
            "action": {"mainnet_bridge": False}, "opaque_confirmation_attestation_id": "attestation_handle_123456"})
        sandbox_tool["handler"]({"network": "ethereum-sepolia", "operation": "send-test-asset",
            "action": {"test_asset": True, "mainnet_bridge": False},
            "opaque_confirmation_attestation_id": "attestation_handle_123456"})
        self.assertEqual(sandbox_effects.calls[0]["action_id"], "execute")

    def test_unavailable_runtime_and_ambiguous_envelope_never_claim_success(self):
        context = PluginContext()
        with self.assertRaises(FinanceUnavailable):
            FinancialDataHubImplementation().register(context, PluginRuntime("financial-data-hub"))
        effects = EffectSpy("ambiguous")
        runtime = PluginRuntime("financial-execution-gateway", effects)
        execution_context = PluginContext()
        FinancialExecutionGatewayImplementation().register(execution_context, runtime)
        result = execution_context.tools["financial_execute_one_order"]["handler"]({
            "provider": "trading212", "operation": "cancel-pending-order",
            "action": {"provider_order_id": "ord-1"},
            "opaque_confirmation_attestation_id": "attestation_handle_123456"})
        self.assertEqual(result["state"], "ambiguous")
        self.assertNotIn("accepted", result)

    def test_financial_data_hub_requires_exact_vendored_101_identity(self):
        runtime = PluginRuntime("financial-data-hub", EffectSpy())
        runtime.identity = type("Identity", (), {"kind": "plugins", "resource_id": "financial-data-hub",
            "version": "1.0.0"})()
        with self.assertRaises(FinanceUnavailable):
            FinancialDataHubImplementation().register(PluginContext(), runtime)


if __name__ == "__main__":
    unittest.main()
