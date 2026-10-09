from __future__ import annotations

from datetime import datetime, timezone
import unittest
import tempfile
from pathlib import Path
import hashlib
import json

from hermes_installer.components.plugin_finance import (
    AgentWallet, DataOperation, DataProvider, FinancialDataHub,
    FinancialExecutionGateway, FinancialExecutionGatewayImplementation,
    FinanceDenied, FinanceUnavailable,
    NetworkClass, NetworkEnrollment,
    SQLiteExecutionLedger, WalletAction,
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
    identity = type("Identity", (), {"kind": "plugins", "resource_id": "financial-execution-gateway"})()

    def __init__(self, service):
        self.financial_execution = service
        self.calls = 0

    def current_invocation(self):
        self.calls += 1
        return type("Invocation", (), {"order_id": "order-" + str(self.calls)})()


class ExecutionSpy:
    def __init__(self):
        self.invocations = []

    def execute(self, **kwargs):
        self.invocations.append(kwargs["invocation"])
        return {"accepted": True}


class PluginFinanceTests(unittest.TestCase):
    def test_data_hub_is_read_only_scoped_and_redacts_provider_identifiers(self):
        broker = ReadBroker()
        hub = FinancialDataHub(broker,
            credential_refs={DataProvider.BANK_AISP: "BANK_READ_CREDENTIAL"},
            account_refs={DataProvider.BANK_AISP: "BANK_READ_ACCOUNT"},
            clock=lambda: datetime(2026, 10, 9, tzinfo=timezone.utc))
        result = hub.read(DataProvider.BANK_AISP, DataOperation.BALANCES, account_alias="bank-main")
        self.assertEqual(len(broker.calls), 1)
        self.assertEqual(broker.calls[0]["timeout_seconds"], 8.0)
        self.assertEqual(result[0].data, {"balance": "12.5", "currency": "EUR"})
        self.assertEqual(result[0].account_alias, "bank-main")
        self.assertEqual(result[0].freshness, "timestamped")
        with self.assertRaises(FinanceDenied):
            hub.read(DataProvider.BANK_AISP, DataOperation.BALANCES, account_alias="bank-main",
                     filters={"url": "https://evil.invalid"})
        with self.assertRaises(FinanceDenied):
            hub.read(DataProvider.BANK_AISP, DataOperation.ACCOUNTS, account_alias="bank-main",
                     filters={"limit": 1001})
        with self.assertRaises(FinanceDenied):
            hub.read(DataProvider.LEDGER_READ, DataOperation.PUBLIC_ACCOUNT_METADATA, account_alias="bank-main")
        self.assertEqual(len(broker.calls), 1)

    def test_data_hub_rejects_execution_scope_and_cross_account_reference_mismatch(self):
        broker = ReadBroker()
        with self.assertRaises(FinanceUnavailable):
            FinancialDataHub(broker,
                credential_refs={DataProvider.BANK_AISP: "BANK_READ_CREDENTIAL"}, account_refs={})
        hub = FinancialDataHub(broker,
            credential_refs={DataProvider.TRADING212_READ: "T212_READ_CREDENTIAL"},
            account_refs={DataProvider.TRADING212_READ: "T212_READ_ACCOUNT"})
        with self.assertRaises(FinanceDenied):
            hub.read(DataProvider.TRADING212_READ, DataOperation.BALANCES, account_alias="broker")
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

    def test_native_tool_uses_fresh_runtime_invocation_and_has_no_confirmation_argument(self):
        runtime = PluginRuntime(ExecutionSpy())
        context = PluginContext()
        FinancialExecutionGatewayImplementation().register(context, runtime)
        tool = context.tools["financial_execute_one_order"]
        self.assertNotIn("confirmation", tool["schema"]["properties"])
        args = {"provider": "trading212", "account": "my-account", "operation": "x", "action": {}}
        tool["handler"](args)
        tool["handler"](args)
        self.assertEqual(runtime.calls, 2)
        self.assertEqual([item.order_id for item in runtime.financial_execution.invocations], ["order-1", "order-2"])


if __name__ == "__main__":
    unittest.main()
