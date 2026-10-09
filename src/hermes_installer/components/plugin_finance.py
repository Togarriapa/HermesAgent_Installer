"""Typed, fail-closed adapters for the four pinned financial Plugins.

The YAML declarations in the Resources bundle are policy inputs, never endpoint,
credential, or executable-code sources. All external effects cross injected
root-owned interfaces. Importing this module performs no I/O.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from contextlib import closing
from datetime import datetime, timezone
from enum import StrEnum
import hashlib
import json
import math
import os
from pathlib import Path
import sqlite3
import stat
import threading
import re
from typing import Any, Mapping, Protocol

from hermes_installer.components.plugin_finance_schemas import PLUGIN_ACTION_SCHEMAS
from urllib.parse import urlsplit


class FinanceDenied(PermissionError):
    """A financial operation exceeded its enrolled scope or host authority."""


class FinanceUnavailable(RuntimeError):
    """A required account, protected broker, or root verifier is not enrolled."""


_OPAQUE_REF = re.compile(r"^[A-Z][A-Z0-9_]{1,95}$")
_ID = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}$")
_HEX256 = re.compile(r"^[0-9a-f]{64}$")
_MAX_REPLY_BYTES = 2 * 1024 * 1024
_MAX_ROWS = 1000


class DataProvider(StrEnum):
    BANK_AISP = "bank-aisp"
    TRADING212_READ = "trading212-read"
    PIONEX_READ = "pionex-read"
    LEDGER_READ = "ledger-read"


class DataOperation(StrEnum):
    ACCOUNTS = "accounts"
    BALANCES = "balances"
    TRANSACTIONS = "transactions"
    POSITIONS = "positions"
    HISTORY = "history"
    DIVIDENDS = "dividends"
    OPEN_ORDERS = "open-orders"
    FILLS = "fills"
    PUBLIC_ACCOUNT_METADATA = "public-account-metadata"


_DATA_SCOPES: Mapping[DataProvider, frozenset[DataOperation]] = {
    DataProvider.BANK_AISP: frozenset({DataOperation.ACCOUNTS, DataOperation.BALANCES, DataOperation.TRANSACTIONS}),
    DataProvider.TRADING212_READ: frozenset({DataOperation.ACCOUNTS, DataOperation.POSITIONS, DataOperation.HISTORY, DataOperation.DIVIDENDS, DataOperation.TRANSACTIONS}),
    DataProvider.PIONEX_READ: frozenset({DataOperation.BALANCES, DataOperation.OPEN_ORDERS, DataOperation.HISTORY, DataOperation.FILLS}),
    DataProvider.LEDGER_READ: frozenset({DataOperation.ACCOUNTS, DataOperation.PUBLIC_ACCOUNT_METADATA}),
}


class FinancialReadBroker(Protocol):
    def read(self, *, provider: DataProvider, operation: DataOperation,
             credential_ref: str, account_ref: str, request: Mapping[str, object],
             timeout_seconds: float) -> object: ...


@dataclass(frozen=True, slots=True)
class FinancialObservation:
    provider: str
    account_alias: str
    kind: str
    observed_at: str
    source_timestamp: str | None
    freshness: str
    data: Mapping[str, object]


class FinancialDataHub:
    """Read-only multi-provider facade with a separate ref and scope per source."""

    def __init__(self, broker: FinancialReadBroker, *,
                 credential_refs: Mapping[DataProvider, str],
                 account_refs: Mapping[DataProvider, str],
                 account_aliases: Mapping[DataProvider, str],
                 clock=lambda: datetime.now(timezone.utc)) -> None:
        if not callable(getattr(broker, "read", None)):
            raise FinanceUnavailable("root financial read broker is unavailable")
        self._broker = broker
        self._credential_refs = self._validate_refs(credential_refs, "credential")
        self._account_refs = self._validate_refs(account_refs, "account")
        self._account_aliases = dict(account_aliases)
        if (set(self._credential_refs) != set(self._account_refs)
                or set(self._credential_refs) != set(self._account_aliases)
                or any(not isinstance(alias, str) or not _ID.fullmatch(alias) for alias in self._account_aliases.values())):
            raise FinanceUnavailable("financial sources require independently enrolled credentials, accounts, and fixed non-secret aliases")
        self._clock = clock

    @staticmethod
    def _validate_refs(values: Mapping[DataProvider, str], label: str) -> dict[DataProvider, str]:
        result: dict[DataProvider, str] = {}
        for provider, ref in values.items():
            if not isinstance(provider, DataProvider) or not isinstance(ref, str) or not _OPAQUE_REF.fullmatch(ref):
                raise FinanceDenied(f"{label} must be an opaque host reference")
            result[provider] = ref
        return result

    def read(self, provider: DataProvider, operation: DataOperation, *,
             filters: Mapping[str, object] | None = None) -> tuple[FinancialObservation, ...]:
        if provider not in self._credential_refs or provider not in _DATA_SCOPES:
            raise FinanceDenied("provider has no separately enrolled read-only source")
        if not isinstance(operation, DataOperation) or operation not in _DATA_SCOPES[provider]:
            raise FinanceDenied("operation is outside this provider's read-only scope")
        normalized_filters = _bounded_filter(filters or {})
        try:
            response = self._broker.read(
                provider=provider, operation=operation,
                credential_ref=self._credential_refs[provider],
                account_ref=self._account_refs[provider], request=normalized_filters,
                timeout_seconds=8.0,
            )
        except Exception:
            raise FinanceUnavailable("root financial read operation failed; credentials and provider response were withheld") from None
        rows = _bounded_rows(response)
        observed_at = _timestamp(self._clock())
        return tuple(_normalize_observation(provider, operation, self._account_aliases[provider], row, observed_at) for row in rows)


def _bounded_filter(filters: Mapping[str, object]) -> dict[str, object]:
    allowed = {"from", "to", "cursor", "limit", "asset", "instrument"}
    if not isinstance(filters, Mapping) or set(filters) - allowed:
        raise FinanceDenied("financial read filters contain an unreviewed field")
    result = dict(filters)
    if "limit" in result and (type(result["limit"]) is not int or not 1 <= result["limit"] <= _MAX_ROWS):
        raise FinanceDenied("financial read limit is outside its bound")
    for key in ("from", "to", "cursor", "asset", "instrument"):
        value = result.get(key)
        if value is not None and (not isinstance(value, str) or len(value.encode("utf-8")) > 256 or any(ord(c) < 32 for c in value)):
            raise FinanceDenied("financial read filter is malformed or too long")
    return result


def _bounded_rows(response: object) -> list[Mapping[str, object]]:
    if isinstance(response, bytes):
        if len(response) > _MAX_REPLY_BYTES:
            raise FinanceDenied("financial source reply exceeded its byte limit")
        try:
            response = json.loads(response)
        except (ValueError, UnicodeDecodeError):
            raise FinanceDenied("financial source reply was not valid JSON") from None
    if isinstance(response, Mapping):
        response = response.get("items", [response])
    if not isinstance(response, (list, tuple)) or len(response) > _MAX_ROWS:
        raise FinanceDenied("financial source returned an invalid or oversized result set")
    if any(not isinstance(row, Mapping) or len(row) > 64 for row in response):
        raise FinanceDenied("financial source returned an invalid record")
    return list(response)


def _timestamp(value: object) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise FinanceDenied("clock must return an aware timestamp")
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _normalize_observation(provider: DataProvider, operation: DataOperation,
                           alias: str, row: Mapping[str, object], observed: str) -> FinancialObservation:
    # Strip provider account IDs, credential-shaped fields, and arbitrary payload
    # blobs before output reaches profile-visible context.
    denied = {"authorization", "token", "access_token", "secret", "api_key", "private_key", "seed", "account_id", "iban"}
    clean: dict[str, object] = {}
    for key, value in row.items():
        if not isinstance(key, str) or key.casefold() in denied or "credential" in key.casefold():
            continue
        if not re.fullmatch(r"[a-zA-Z][a-zA-Z0-9_-]{0,63}", key):
            continue
        if isinstance(value, (str, int, float, bool)) or value is None:
            if isinstance(value, float) and not math.isfinite(value):
                continue
            if isinstance(value, str) and (len(value.encode("utf-8")) > 2048 or any(ord(c) < 32 for c in value)):
                continue
            clean[key] = value
    source_time = clean.pop("timestamp", None)
    if not isinstance(source_time, str) or len(source_time) > 64:
        source_time = None
    return FinancialObservation(provider.value, alias, operation.value, observed, source_time,
                                "timestamped" if source_time else "provider-timestamp-unavailable", clean)


class NetworkClass(StrEnum):
    MAINNET = "mainnet"
    TESTNET = "testnet"


@dataclass(frozen=True, slots=True)
class NetworkEnrollment:
    name: str
    network_class: NetworkClass
    chain_id: int
    rpc_service_id: str
    allowed_asset_ids: frozenset[str]

    def __post_init__(self) -> None:
        if not _ID.fullmatch(self.name) or type(self.chain_id) is not int or self.chain_id <= 0:
            raise FinanceDenied("network enrollment identity is malformed")
        if not _OPAQUE_REF.fullmatch(self.rpc_service_id):
            raise FinanceDenied("RPC must be an enrolled broker service ID, never a caller URL")
        if not self.allowed_asset_ids or any(not _ID.fullmatch(item) for item in self.allowed_asset_ids):
            raise FinanceDenied("network enrollment requires exact asset identifiers")


@dataclass(frozen=True, slots=True)
class WalletAction:
    network: str
    chain_id: int
    source_account: str
    destination: str
    asset_id: str
    amount: str
    max_fee: str
    contract: str | None = None
    calldata_digest: str | None = None

    def canonical_digest(self) -> str:
        payload = asdict(self)
        _validate_economic_decimal(self.amount, "amount")
        _validate_economic_decimal(self.max_fee, "maximum fee", allow_zero=True)
        for key in ("source_account", "destination", "asset_id"):
            if not isinstance(payload[key], str) or not _ID.fullmatch(payload[key]):
                raise FinanceDenied(f"{key} must be a bounded exact identifier")
        if self.contract is not None and (not _ID.fullmatch(self.contract) or not isinstance(self.calldata_digest, str) or not _HEX256.fullmatch(self.calldata_digest)):
            raise FinanceDenied("contract calls require a reviewed contract ID and exact calldata digest")
        if self.contract is None and self.calldata_digest is not None:
            raise FinanceDenied("calldata digest without a contract is not valid")
        return hashlib.sha256(_canonical_json(payload)).hexdigest()


def _validate_economic_decimal(value: object, label: str, *, allow_zero: bool = False) -> None:
    if not isinstance(value, str) or not re.fullmatch(r"(?:0|[1-9][0-9]{0,19})(?:\.[0-9]{1,18})?", value):
        raise FinanceDenied(f"{label} must be a canonical bounded decimal")
    if not allow_zero and float(value) <= 0:
        raise FinanceDenied(f"{label} must be positive")


def _canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


class ConfirmationAuthority(Protocol):
    def consume_financial_confirmation(self, *, invocation: object,
                                       payload_digest: str, action_id: str,
                                       ttl_seconds: int) -> object: ...


class FinancialEffectBroker(Protocol):
    def preflight(self, *, provider: str, account_ref: str, operation: str,
                  payload: Mapping[str, object], timeout_seconds: float) -> Mapping[str, object]: ...
    def execute_once(self, *, provider: str, account_ref: str, operation: str,
                     payload: Mapping[str, object], effect_grant: object,
                     idempotency_key: str, timeout_seconds: float) -> Mapping[str, object]: ...
    def reconcile(self, *, provider: str, account_ref: str, execution_id: str,
                  provider_reference: str | None, timeout_seconds: float) -> Mapping[str, object]: ...


class ExecutionLedger(Protocol):
    def claim(self, execution_id: str, payload_digest: str) -> str: ...
    def finish(self, execution_id: str, state: str, receipt: Mapping[str, object]) -> None: ...
    def get(self, execution_id: str) -> Mapping[str, object] | None: ...


class SQLiteExecutionLedger:
    """Private durable duplicate/replay ledger; stores hashes and redacted receipts only."""

    _STATES = {"claimed", "executing", "ambiguous-provider-state", "reconciliation-failed",
               "reconciled", "failed-before-provider-effect"}
    _TRANSITIONS = {
        "claimed": {"executing", "failed-before-provider-effect"},
        "executing": {"ambiguous-provider-state", "reconciliation-failed", "reconciled"},
        "ambiguous-provider-state": {"reconciliation-failed", "reconciled"},
        "reconciliation-failed": {"reconciled", "ambiguous-provider-state"},
        "reconciled": set(),
        "failed-before-provider-effect": set(),
    }

    def __init__(self, path: Path) -> None:
        if not isinstance(path, Path) or not path.is_absolute():
            raise FinanceDenied("execution ledger must use an absolute protected state path")
        parent = path.parent
        parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if parent.is_symlink() or not parent.is_dir() or stat.S_IMODE(parent.stat().st_mode) & 0o077:
            raise FinanceDenied("execution ledger directory must be a private non-symlink directory")
        if path.is_symlink():
            raise FinanceDenied("execution ledger path may not be a symlink")
        if path.exists() and (not path.is_file() or stat.S_IMODE(path.stat().st_mode) & 0o077):
            raise FinanceDenied("existing execution ledger must be a private regular file")
        self._path = path
        self._lock = threading.RLock()
        with closing(self._connect()) as db:
            db.execute("CREATE TABLE IF NOT EXISTS executions (execution_id TEXT PRIMARY KEY, payload_digest TEXT NOT NULL, state TEXT NOT NULL, receipt_json TEXT NOT NULL)")
        os.chmod(path, 0o600)

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self._path, timeout=3.0, isolation_level=None)
        db.execute("PRAGMA busy_timeout=3000")
        db.execute("PRAGMA journal_mode=WAL")
        return db

    def claim(self, execution_id: str, payload_digest: str) -> str:
        if not _HEX256.fullmatch(execution_id) or not _HEX256.fullmatch(payload_digest):
            raise FinanceDenied("execution ledger key or payload digest is invalid")
        with self._lock, closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                prior = db.execute("SELECT payload_digest, state FROM executions WHERE execution_id=?", (execution_id,)).fetchone()
                if prior is not None:
                    if prior[0] != payload_digest:
                        raise FinanceDenied("execution ID is already bound to another economic payload")
                    db.execute("COMMIT")
                    return str(prior[1])
                db.execute("INSERT INTO executions VALUES (?, ?, 'claimed', '{}')", (execution_id, payload_digest))
                db.execute("COMMIT")
                return "new"
            except BaseException:
                if db.in_transaction:
                    db.execute("ROLLBACK")
                raise

    def finish(self, execution_id: str, state: str, receipt: Mapping[str, object]) -> None:
        if not _HEX256.fullmatch(execution_id) or state not in self._STATES or not isinstance(receipt, Mapping):
            raise FinanceDenied("execution ledger transition is malformed")
        encoded = _canonical_json(_redact_mapping(receipt))
        if len(encoded) > 16_384:
            raise FinanceDenied("execution ledger receipt exceeds its bound")
        with self._lock, closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                row = db.execute("SELECT state FROM executions WHERE execution_id=?", (execution_id,)).fetchone()
                if row is None or state not in self._TRANSITIONS.get(row[0], set()):
                    raise FinanceDenied("execution ledger state transition is invalid")
                db.execute("UPDATE executions SET state=?, receipt_json=? WHERE execution_id=?",
                           (state, encoded.decode("ascii"), execution_id))
                db.execute("COMMIT")
            except BaseException:
                if db.in_transaction:
                    db.execute("ROLLBACK")
                raise

    def get(self, execution_id: str) -> Mapping[str, object] | None:
        if not _HEX256.fullmatch(execution_id):
            raise FinanceDenied("execution ID is invalid")
        with self._lock, closing(self._connect()) as db:
            row = db.execute("SELECT payload_digest, state, receipt_json FROM executions WHERE execution_id=?", (execution_id,)).fetchone()
        if row is None:
            return None
        try:
            receipt = json.loads(row[2])
        except (ValueError, TypeError):
            raise FinanceUnavailable("execution ledger receipt is corrupt; preserve it for operator review") from None
        if not isinstance(receipt, dict):
            raise FinanceUnavailable("execution ledger receipt is malformed; preserve it for operator review")
        return {"payload_digest": row[0], "state": row[1], "receipt": receipt}


class FinancialExecutionGateway:
    """One action, account, exact payload and consumed root confirmation per call."""

    def __init__(self, *, broker: FinancialEffectBroker, confirmation_authority: ConfirmationAuthority,
                 ledger: ExecutionLedger, enrolled_accounts: Mapping[str, str],
                 enrolled_recipients: Mapping[str, frozenset[str]] | None = None) -> None:
        self._broker, self._confirmation, self._ledger = broker, confirmation_authority, ledger
        if not enrolled_accounts or any(not _ID.fullmatch(k) or not _OPAQUE_REF.fullmatch(v) for k, v in enrolled_accounts.items()):
            raise FinanceUnavailable("independently scoped execution account references are not enrolled")
        self._accounts = dict(enrolled_accounts)
        self._recipients = dict(enrolled_recipients or {})

    def execute(self, *, provider: str, account: str, operation: str,
                action: Mapping[str, object], invocation: object) -> Mapping[str, object]:
        supported = {
            "trading212": {"place-market-order", "place-limit-order", "place-stop-order", "place-stop-limit-order", "cancel-pending-order"},
            "pionex": {"place-order", "cancel-order"},
            "regulated-pisp": {"initiate-user-authorized-payment"},
            "ledger-wallet-api": {"sign-user-authorized-transaction", "sign-and-broadcast-user-authorized-transaction"},
        }
        if provider not in supported or operation not in supported[provider]:
            raise FinanceDenied("provider operation is not in the fixed execution catalog")
        if account not in self._accounts:
            raise FinanceDenied("provider account has no independent execution enrollment")
        payload = _validate_execution_payload(provider, operation, action)
        if provider == "regulated-pisp" and payload.get("recipient") not in self._recipients.get(account, frozenset()):
            raise FinanceDenied("payment recipient is not independently enrolled for this account")
        account_ref = self._accounts[account]
        digest = hashlib.sha256(_canonical_json({"provider": provider, "account_ref": account_ref,
            "operation": operation, "payload": payload})).hexdigest()
        execution_id = hashlib.sha256((digest + ":" + str(getattr(invocation, "order_id", ""))).encode()).hexdigest()
        if not _HEX256.fullmatch(execution_id) or not isinstance(getattr(invocation, "order_id", None), str) or not _ID.fullmatch(invocation.order_id):
            raise FinanceDenied("fresh explicit user order is unavailable")
        state = self._ledger.claim(execution_id, digest)
        if state != "new":
            raise FinanceDenied("this order was already attempted; reconcile its existing execution instead of replaying it")
        ledger_scope = {"provider": provider, "account": account,
                        "account_ref": account_ref, "operation": operation,
                        "payload_digest": digest}
        try:
            prepared = self._broker.preflight(provider=provider, account_ref=account_ref,
                operation=operation, payload=payload, timeout_seconds=8.0)
            if not isinstance(prepared, Mapping) or prepared.get("payload_digest") != digest or prepared.get("ready") is not True:
                raise FinanceDenied("provider preflight did not approve the exact final action payload")
            grant = self._confirmation.consume_financial_confirmation(
                invocation=invocation, payload_digest=digest, action_id=execution_id, ttl_seconds=300)
            if grant is None:
                raise FinanceDenied("fresh one-shot confirmation was rejected by the root authority")
            idem = hashlib.sha256((execution_id + ":provider-call").encode()).hexdigest()
            self._ledger.finish(execution_id, "executing", ledger_scope)
            try:
                result = self._broker.execute_once(provider=provider, account_ref=account_ref,
                    operation=operation, payload=payload, effect_grant=grant,
                    idempotency_key=idem, timeout_seconds=8.0)
            except Exception:
                # The provider may have committed before a timeout. Never blindly retry.
                self._ledger.finish(execution_id, "ambiguous-provider-state", ledger_scope)
                raise FinanceUnavailable("provider outcome is ambiguous; reconcile through Hermes before any retry") from None
            if not isinstance(result, Mapping):
                self._ledger.finish(execution_id, "ambiguous-provider-state", ledger_scope)
                raise FinanceUnavailable("provider returned an invalid acknowledgement; reconcile before retry")
            provider_ref = result.get("provider_reference")
            if provider_ref is not None and (not isinstance(provider_ref, str) or not _ID.fullmatch(provider_ref)):
                self._ledger.finish(execution_id, "ambiguous-provider-state", ledger_scope)
                raise FinanceUnavailable("provider acknowledgement identity is invalid; reconcile before retry")
            reconciled = self._broker.reconcile(provider=provider, account_ref=account_ref,
                execution_id=execution_id, provider_reference=provider_ref, timeout_seconds=8.0)
            if not isinstance(reconciled, Mapping) or reconciled.get("matched") is not True:
                receipt = {**ledger_scope, "provider_reference": provider_ref}
                self._ledger.finish(execution_id, "reconciliation-failed", receipt)
                raise FinanceUnavailable("provider acknowledgement could not be reconciled; dependent actions are blocked")
            receipt = {"execution_id": execution_id, "provider": provider,
                "account": account, "operation": operation, "payload_digest": digest,
                "provider_reference": provider_ref, "state": "reconciled",
                "reconciliation": _redact_mapping(reconciled)}
            self._ledger.finish(execution_id, "reconciled", receipt)
            return receipt
        except (FinanceDenied, FinanceUnavailable):
            raise
        except Exception:
            self._ledger.finish(execution_id, "failed-before-provider-effect", {"payload_digest": digest})
            raise FinanceUnavailable("financial execution failed safely; no provider response or credential was exposed") from None

    def reconcile_ambiguous(self, *, execution_id: str, provider: str, account: str) -> Mapping[str, object]:
        """Refresh a prior uncertain call by its immutable execution ID; never resubmit it."""
        get = getattr(self._ledger, "get", None)
        if not callable(get) or not _HEX256.fullmatch(execution_id):
            raise FinanceUnavailable("durable execution lookup is unavailable")
        if provider not in {"trading212", "pionex", "regulated-pisp", "ledger-wallet-api"} or account not in self._accounts:
            raise FinanceDenied("reconciliation target has no matching independent enrollment")
        prior = get(execution_id)
        if prior is None or prior.get("state") not in {"ambiguous-provider-state", "reconciliation-failed"}:
            raise FinanceDenied("execution is not pending ambiguity reconciliation")
        saved = prior.get("receipt", {})
        if (not isinstance(saved, Mapping) or saved.get("provider") != provider
                or saved.get("account") != account or saved.get("account_ref") != self._accounts[account]):
            raise FinanceDenied("reconciliation must use the exact provider and account bound to the original action")
        provider_reference = saved.get("provider_reference")
        try:
            current = self._broker.reconcile(provider=provider, account_ref=self._accounts[account],
                execution_id=execution_id, provider_reference=provider_reference, timeout_seconds=8.0)
        except Exception:
            raise FinanceUnavailable("provider reconciliation failed; execution remains blocked from retry") from None
        if not isinstance(current, Mapping) or current.get("matched") is not True:
            self._ledger.finish(execution_id, "ambiguous-provider-state", {**saved, "provider_reference": provider_reference})
            return {"execution_id": execution_id, "state": "ambiguous-provider-state", "retry_allowed": False}
        receipt = {"execution_id": execution_id, "provider": provider, "account": account,
                   "state": "reconciled", "reconciliation": _redact_mapping(current)}
        self._ledger.finish(execution_id, "reconciled", receipt)
        return receipt


def _validate_execution_payload(provider: str, operation: str, action: Mapping[str, object]) -> dict[str, object]:
    if not isinstance(action, Mapping):
        raise FinanceDenied("execution payload must be an object")
    order_fields = {"instrument", "side", "quantity", "currency", "limit_price", "stop_price", "order_type", "client_order_id"}
    if operation in {"cancel-pending-order", "cancel-order"}:
        allowed = {"provider_order_id", "client_order_id"}
    elif provider in {"trading212", "pionex"}:
        allowed = order_fields
    elif provider == "regulated-pisp":
        # Payment recipient is resolved from the protected root enrollment and
        # the trusted human order. It is never a model-selected tool argument.
        allowed = {"amount", "currency", "payment_reference", "client_order_id"}
    else:
        allowed = {"transaction_digest", "client_order_id"}
    if set(action) - allowed:
        raise FinanceDenied("execution payload contains unreviewed fields")
    payload = dict(action)
    if operation in {"cancel-pending-order", "cancel-order"}:
        if not isinstance(payload.get("provider_order_id"), str) or not _ID.fullmatch(payload["provider_order_id"]):
            raise FinanceDenied("order cancellation requires the exact provider order ID")
    elif operation.startswith("place-") or operation == "place-order":
        for field in ("instrument", "side", "quantity"):
            if field not in payload:
                raise FinanceDenied("order requires exact instrument, side and quantity")
        if payload["side"] not in {"buy", "sell"}:
            raise FinanceDenied("order side is invalid")
        _validate_economic_decimal(payload["quantity"], "quantity")
        if not isinstance(payload["instrument"], str) or not _ID.fullmatch(payload["instrument"]):
            raise FinanceDenied("instrument must be an exact identifier")
        if not isinstance(payload.get("currency"), str) or not _ID.fullmatch(payload["currency"]):
            raise FinanceDenied("order requires the exact settlement currency")
        if operation == "place-market-order":
            price_fields: set[str] = set()
        elif operation == "place-limit-order":
            price_fields = {"limit_price"}
        elif operation == "place-order":
            if payload.get("order_type") not in {"limit", "market"}:
                raise FinanceDenied("Pionex order requires an explicit market or limit order type")
            price_fields = {"limit_price"} if payload["order_type"] == "limit" else set()
        elif operation == "place-stop-order":
            price_fields = {"stop_price"}
        elif operation == "place-stop-limit-order":
            price_fields = {"stop_price", "limit_price"}
        else:
            raise FinanceDenied("order type is not supported")
        if not price_fields.issubset(payload):
            raise FinanceDenied("order is missing its exact trigger or limit price")
        for key in price_fields:
            _validate_economic_decimal(payload[key], key.replace("_", " "))
        permitted = {"instrument", "side", "quantity", "currency", "client_order_id", "order_type"} | price_fields
        if set(payload) - permitted:
            raise FinanceDenied("order contains price or type fields outside its selected operation")
    elif operation == "initiate-user-authorized-payment":
        for field in ("amount", "currency"):
            if not isinstance(payload.get(field), str) or not _ID.fullmatch(payload[field]):
                raise FinanceDenied("payment requires exact amount and currency; recipient is root-selected")
        _validate_economic_decimal(payload["amount"], "payment amount")
    elif operation.startswith("sign-"):
        if not isinstance(payload.get("transaction_digest"), str) or not _HEX256.fullmatch(payload["transaction_digest"]):
            raise FinanceDenied("Ledger signing requires the exact transaction digest")
    if "client_order_id" in payload and (not isinstance(payload["client_order_id"], str) or not _ID.fullmatch(payload["client_order_id"])):
        raise FinanceDenied("client order ID is malformed")
    return payload


def _redact_mapping(value: Mapping[str, object]) -> dict[str, object]:
    excluded = {"token", "secret", "credential", "authorization", "private_key", "seed", "raw_response", "signature", "signed_transaction", "raw_transaction"}
    return {str(key): item for key, item in value.items()
            if isinstance(key, str) and not any(term in key.casefold() for term in excluded)
            and (isinstance(item, (str, int, float, bool)) or item is None)}


def _resolve_current_invocation(runtime_context: object) -> object | None:
    """Fetch invocation-bound authority at call time, never during setup."""
    direct = getattr(runtime_context, "current_invocation", None)
    if callable(direct):
        return direct()
    contexts = getattr(runtime_context, "invocation_contexts", None)
    for name in ("current", "for_current_call"):
        lookup = getattr(contexts, name, None)
        if callable(lookup):
            return lookup()
    return direct


class WalletEffectBroker(Protocol):
    def preflight_wallet(self, *, wallet_ref: str, network: NetworkEnrollment,
                         action: Mapping[str, object], timeout_seconds: float) -> Mapping[str, object]: ...
    def wallet_action(self, *, wallet_ref: str, network: NetworkEnrollment,
                      operation: str, action: Mapping[str, object],
                      effect_grant: object | None, timeout_seconds: float) -> Mapping[str, object]: ...


class AgentWallet:
    """Wallet facade whose signing keys exist only behind the root vault broker."""

    def __init__(self, *, broker: WalletEffectBroker, wallet_ref: str,
                 networks: Mapping[str, NetworkEnrollment], sandbox: bool,
                 confirmation_authority: ConfirmationAuthority | None = None) -> None:
        if not _OPAQUE_REF.fullmatch(wallet_ref) or not callable(getattr(broker, "wallet_action", None)):
            raise FinanceUnavailable("protected wallet reference or root wallet broker is not enrolled")
        if not networks or any(name != network.name for name, network in networks.items()):
            raise FinanceUnavailable("exact wallet network enrollment is missing")
        if sandbox and any(n.network_class is not NetworkClass.TESTNET for n in networks.values()):
            raise FinanceDenied("sandbox wallet network set contains a production network")
        if sandbox and set(networks) - {"ethereum-sepolia", "solana-devnet"}:
            raise FinanceDenied("sandbox supports only the enrolled Sepolia and Solana Devnet networks")
        if not sandbox and (confirmation_authority is None or any(n.network_class is not NetworkClass.MAINNET for n in networks.values())):
            raise FinanceUnavailable("live wallet requires exact mainnet allowlist and runtime confirmation authority")
        self._broker, self._wallet_ref, self._networks = broker, wallet_ref, dict(networks)
        self._sandbox, self._confirmation = sandbox, confirmation_authority

    def act(self, *, network_name: str, operation: str, action: Mapping[str, object],
            invocation: object | None = None) -> Mapping[str, object]:
        wallet_fields = {"network", "chain_id", "source_account", "destination", "asset_id", "amount", "max_fee", "contract", "calldata_digest", "test_asset", "mainnet_bridge"}
        if not isinstance(action, Mapping) or set(action) - wallet_fields:
            raise FinanceDenied("wallet action contains unreviewed fields")
        network = self._networks.get(network_name)
        if (network is None or type(action.get("chain_id")) is not int
                or action.get("chain_id") != network.chain_id):
            raise FinanceDenied("network and asserted chain ID do not match the exact enrollment")
        if action.get("network") != network.name or action.get("asset_id") not in network.allowed_asset_ids:
            raise FinanceDenied("wallet action is outside the enrolled network or exact asset allowlist")
        if not self._sandbox:
            if operation not in {"construct", "simulate", "estimate-fee", "inspect", "sign", "broadcast"}:
                raise FinanceDenied("live wallet operation is outside its fixed catalog")
            if operation in {"sign", "broadcast"} and (invocation is None or self._confirmation is None):
                raise FinanceDenied("live wallet signing requires a fresh user order and confirmation")
        else:
            if network.network_class is not NetworkClass.TESTNET or operation not in {
                "create-account", "reset-account", "read-balance", "simulate", "sign-test-transaction",
                "send-test-asset", "deploy-test-contract", "reviewed-testnet-dapp", "inspect-receipt",
            }:
                raise FinanceDenied("sandbox operation is outside the public testnet/test-asset catalog")
            if operation in {"sign-test-transaction", "send-test-asset", "deploy-test-contract", "reviewed-testnet-dapp"}:
                if action.get("test_asset") is not True or action.get("mainnet_bridge") is not False:
                    raise FinanceDenied("sandbox writes require test asset assertion and explicit mainnet-bridge denial")
        write_operation = operation in {"sign", "broadcast", "sign-test-transaction", "send-test-asset",
                                        "deploy-test-contract", "reviewed-testnet-dapp"}
        if self._sandbox:
            preflight_digest = hashlib.sha256(_canonical_json(dict(action))).hexdigest()
        else:
            fields = {key: action.get(key) for key in WalletAction.__dataclass_fields__}
            preflight_digest = WalletAction(**fields).canonical_digest()
        if write_operation:
            preflight = getattr(self._broker, "preflight_wallet", None)
            if not callable(preflight):
                raise FinanceUnavailable("root wallet simulation and balance preflight is unavailable")
            try:
                checked = preflight(wallet_ref=self._wallet_ref, network=network,
                    action=dict(action), timeout_seconds=8.0)
            except Exception:
                raise FinanceUnavailable("wallet preflight failed safely; no signing or broadcast was attempted") from None
            if not isinstance(checked, Mapping) or checked.get("ready") is not True or checked.get("payload_digest") != preflight_digest:
                raise FinanceDenied("wallet preflight did not approve the exact network/account/asset payload")
        if not self._sandbox:
            if operation in {"sign", "broadcast"}:
                grant = self._confirmation.consume_financial_confirmation(
                    invocation=invocation, payload_digest=preflight_digest,
                    action_id=hashlib.sha256((invocation.order_id + preflight_digest).encode()).hexdigest(), ttl_seconds=300)
            else:
                grant = None
        else:
            grant = None
        try:
            result = self._broker.wallet_action(wallet_ref=self._wallet_ref, network=network,
                operation=operation, action=dict(action), effect_grant=grant, timeout_seconds=8.0)
        except Exception:
            raise FinanceUnavailable("root wallet effect failed; secret material and provider details were withheld") from None
        if not isinstance(result, Mapping):
            raise FinanceUnavailable("root wallet effect returned an invalid bounded receipt")
        return _redact_mapping(result)


class _PluginImplementation:
    resource_id = ""
    service_attribute = ""
    tool_name = ""
    schema: Mapping[str, object] = {}
    description = ""

    def register(self, ctx: object, runtime_context: object) -> None:
        _require_effect_runtime(runtime_context, self.resource_id)
        register = getattr(ctx, "register_tool", None)
        if not callable(register):
            raise FinanceUnavailable("native Hermes PluginContext.register_tool is unavailable")
        register(name=self.tool_name, toolset=self.resource_id.replace("-", "_"), schema=self.schema,
                 handler=self.handler(runtime_context), requires_env=None, is_async=False,
                 description=self.description)

    @property
    def blocker(self) -> str:
        return "selected protected financial runtime is unavailable; enroll its exact scoped root adapter before activation"

    def handler(self, runtime_context: object):
        raise NotImplementedError


_CONFIRMATION_FIELD = "opaque_confirmation_attestation_id"
_ATTESTATION = re.compile(r"^[A-Za-z0-9_-]{16,256}$")
_DATA_ACTIONS: Mapping[tuple[DataProvider, DataOperation], str] = {
    (provider, operation): "read"
    for provider, operations in _DATA_SCOPES.items() for operation in operations
}
_EXECUTION_OPERATIONS: Mapping[str, frozenset[str]] = {
    "trading212": frozenset({"place-market-order", "place-limit-order", "place-stop-order", "place-stop-limit-order", "cancel-pending-order"}),
    "pionex": frozenset({"place-order", "cancel-order"}),
    "regulated-pisp": frozenset({"initiate-user-authorized-payment"}),
    "ledger-wallet-api": frozenset({"sign-user-authorized-transaction", "sign-and-broadcast-user-authorized-transaction"}),
}
_EXECUTION_WRITE_ACTIONS = frozenset({
    (provider, operation) for provider, operations in _EXECUTION_OPERATIONS.items() for operation in operations
})
_LIVE_OPERATIONS = frozenset({"construct", "simulate", "estimate-fee", "inspect", "sign", "broadcast"})
_LIVE_READS = frozenset({"construct", "simulate", "estimate-fee", "inspect"})
_SANDBOX_READS = frozenset({"read-balance", "simulate", "inspect-receipt"})
_SANDBOX_OPERATIONS = frozenset({"create-account", "reset-account", *_SANDBOX_READS,
    "sign-test-transaction", "send-test-asset", "deploy-test-contract", "reviewed-testnet-dapp"})


def _require_effect_runtime(runtime: object, adapter_id: str) -> object:
    identity = getattr(runtime, "identity", None)
    if (getattr(identity, "kind", None) != "plugins"
            or getattr(identity, "resource_id", None) != adapter_id
            or getattr(identity, "version", "1.0.0") != "1.0.0"):
        raise FinanceUnavailable("selected financial Plugin identity does not match the pinned adapter")
    effects = getattr(runtime, "plugin_effects", None)
    invoke = getattr(effects, "invoke", None)
    if not callable(invoke):
        raise FinanceUnavailable("root-selected financial effect broker is not enrolled")
    return runtime


def _idempotency_key(adapter_id: str, action_id: str, arguments: Mapping[str, object],
                     attestation: str | None) -> str:
    # Stable for the exact attempt, so a repeated invocation cannot become a
    # second effect merely by obtaining a new invocation trace.
    body = {"adapter": adapter_id, "action": action_id, "arguments": arguments,
            "confirmation": attestation}
    return hashlib.sha256(_canonical_json(body)).hexdigest()


def _effect(runtime: object, *, adapter_id: str, action_id: str,
            arguments: Mapping[str, object], write: bool,
            attestation: str | None = None) -> dict[str, object]:
    _require_effect_runtime(runtime, adapter_id)
    if write:
        if not isinstance(attestation, str) or not _ATTESTATION.fullmatch(attestation):
            raise FinanceDenied("a fresh exact-payload user confirmation handle is required")
    elif attestation is not None:
        raise FinanceDenied("read-only operation cannot carry a confirmation handle")
    key = _idempotency_key(adapter_id, action_id, arguments, attestation) if write else None
    try:
        response = runtime.plugin_effects.invoke(adapter_id=adapter_id, action_id=action_id,
            arguments=dict(arguments), idempotency_key=key,
            opaque_confirmation_attestation_id=attestation)
    except Exception:
        raise FinanceUnavailable("root financial effect failed; protected details were withheld") from None
    value = _effect_envelope(response)
    if value["state"] in {"ambiguous", "pending", "unavailable"}:
        return {"operation_id": value["operation_id"], "state": value["state"],
                "verification_status": value["verification_status"],
                "resume_action_id": value["resume_action_id"]}
    expected = "committed" if write else "read-complete"
    if value["state"] != expected or (write and value["verification_status"] != "verified"):
        raise FinanceUnavailable("root financial effect did not confirm the expected completion state")
    result = value["result"]
    if not isinstance(result, (dict, list, str, int, float, bool, type(None))):
        raise FinanceUnavailable("root financial effect result has an unsupported shape")
    clean = _sanitize_effect_result(result)
    return clean if isinstance(clean, dict) else {"result": clean}


_SENSITIVE_RESULT_KEYS = frozenset({"token", "secret", "credential", "authorization", "private_key",
    "seed", "seed_phrase", "mnemonic", "signature", "signed_transaction", "raw_transaction",
    "raw_response", "api_key", "access_token", "refresh_token", "account_id", "iban"})


def _sanitize_effect_result(value: object, depth: int = 0) -> object:
    if depth > 8:
        raise FinanceUnavailable("root financial effect result is nested beyond its bound")
    if isinstance(value, Mapping):
        result: dict[str, object] = {}
        for key, item in value.items():
            if not isinstance(key, str) or any(term in key.casefold() for term in _SENSITIVE_RESULT_KEYS):
                continue
            result[key] = _sanitize_effect_result(item, depth + 1)
        return result
    if isinstance(value, list):
        if len(value) > _MAX_ROWS:
            raise FinanceUnavailable("root financial effect result exceeds its record bound")
        return [_sanitize_effect_result(item, depth + 1) for item in value]
    if isinstance(value, str):
        if len(value.encode("utf-8")) > 16_384 or any(ord(char) < 32 for char in value):
            raise FinanceUnavailable("root financial effect contains an unbounded text value")
        return value
    if isinstance(value, float) and not math.isfinite(value):
        raise FinanceUnavailable("root financial effect contains a non-finite number")
    if value is None or isinstance(value, (int, float, bool)):
        return value
    raise FinanceUnavailable("root financial effect contains an unsupported value")


def _effect_envelope(response: object) -> dict[str, object]:
    if isinstance(response, Mapping):
        value = dict(response)
    else:
        status, body = getattr(response, "status", None), getattr(response, "body", None)
        if type(status) is not int or status != 200 or not isinstance(body, bytes) or len(body) > _MAX_REPLY_BYTES:
            raise FinanceUnavailable("root financial effect returned an invalid or oversized response")
        try:
            value = json.loads(body)
        except (ValueError, UnicodeDecodeError, RecursionError):
            raise FinanceUnavailable("root financial effect returned malformed JSON") from None
    required = {"schema", "operation_id", "state", "result", "verification_status", "resume_action_id"}
    if (not isinstance(value, dict) or set(value) != required or type(value.get("schema")) is not int
            or value["schema"] != 1 or value["state"] not in {"committed", "read-complete", "pending", "ambiguous", "unavailable"}
            or not isinstance(value["operation_id"], str) or len(value["operation_id"]) > 128
            or not isinstance(value["verification_status"], str)
            or value["resume_action_id"] is not None and not isinstance(value["resume_action_id"], str)):
        raise FinanceUnavailable("root financial effect returned an unexpected operation envelope")
    try:
        encoded = _canonical_json(value)
    except (TypeError, ValueError, OverflowError):
        raise FinanceUnavailable("root financial effect returned non-JSON data") from None
    if len(encoded) > _MAX_REPLY_BYTES:
        raise FinanceUnavailable("root financial effect exceeded the bounded response size")
    return value


def _bounded_action(value: object) -> dict[str, object]:
    if not isinstance(value, Mapping) or len(value) > 32:
        raise FinanceDenied("financial action must be a bounded object")
    try:
        encoded = _canonical_json(dict(value))
    except (TypeError, ValueError, OverflowError):
        raise FinanceDenied("financial action contains non-JSON values") from None
    if len(encoded) > 65_536:
        raise FinanceDenied("financial action exceeds its request bound")
    return dict(value)


def _attested_args(args: Mapping[str, object], ordinary: frozenset[str]) -> tuple[dict[str, object], str]:
    if set(args) != ordinary | {_CONFIRMATION_FIELD}:
        raise FinanceDenied("write requires exactly one opaque confirmation attestation field")
    attestation = args[_CONFIRMATION_FIELD]
    if not isinstance(attestation, str) or not _ATTESTATION.fullmatch(attestation):
        raise FinanceDenied("confirmation handle is malformed")
    return {key: value for key, value in args.items() if key != _CONFIRMATION_FIELD}, attestation


def _plain_schema(value: object) -> object:
    if isinstance(value, Mapping):
        return {key: _plain_schema(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_plain_schema(item) for item in value]
    return value


def _tool_schema(adapter_id: str, action_id: str, *, confirmation: bool = False,
                 merge_action_id: str | None = None) -> dict[str, object]:
    row = PLUGIN_ACTION_SCHEMAS[(adapter_id, action_id)]
    result = _plain_schema(row.argument_schema)
    if not isinstance(result, dict):
        raise FinanceUnavailable("source-reviewed Plugin action schema is malformed")
    result = dict(result)
    properties = dict(result["properties"])
    if merge_action_id is not None:
        other = _plain_schema(PLUGIN_ACTION_SCHEMAS[(adapter_id, merge_action_id)].argument_schema)
        other_properties = other["properties"]
        if set(other_properties) != set(properties):
            raise FinanceUnavailable("paired Plugin action schemas are incompatible")
        for key in properties:
            if key == "operation":
                properties[key] = {**properties[key], "enum": list(dict.fromkeys(
                    [*properties[key]["enum"], *other_properties[key]["enum"]]))}
            elif properties[key] != other_properties[key]:
                raise FinanceUnavailable("paired Plugin action schema field mismatch")
    required = list(result["required"])
    if confirmation:
        properties[_CONFIRMATION_FIELD] = {"type": "string", "minLength": 16, "maxLength": 256}
        required.append(_CONFIRMATION_FIELD)
    result["properties"] = properties
    result["required"] = required
    return result


class FinancialDataHubImplementation(_PluginImplementation):
    resource_id = "financial-data-hub"
    tool_name = "financial_data_read"
    schema = _tool_schema(resource_id, "read")
    description = "Read observations only from an independently consented financial source."

    def handler(self, runtime_context: object):
        def read(args: object):
            if not isinstance(args, Mapping) or set(args) - {"provider", "operation", "filters"}:
                raise FinanceDenied("financial read arguments contain unreviewed fields")
            try:
                provider, operation = DataProvider(args["provider"]), DataOperation(args["operation"])
            except (ValueError, TypeError):
                raise FinanceDenied("provider or operation is outside the fixed read catalog") from None
            action_id = _DATA_ACTIONS.get((provider, operation))
            if action_id is None:
                raise FinanceDenied("operation is outside this provider's pinned read-only scope")
            filters = _bounded_filter(args.get("filters", {}))
            result = _effect(runtime_context, adapter_id=self.resource_id, action_id=action_id,
                             arguments={"provider": provider.value, "operation": operation.value,
                                        "filters": filters}, write=False)
            rows = _bounded_rows(result)
            # Root enrollment fixes account identity. Only non-sensitive public
            # alias data is accepted back from the protected broker.
            alias = result.get("account_alias", "selected") if isinstance(result, Mapping) else "selected"
            if not isinstance(alias, str) or not _ID.fullmatch(alias):
                alias = "selected"
            observed = _timestamp(datetime.now(timezone.utc))
            return {"observations": [asdict(_normalize_observation(provider, operation, alias, row, observed))
                                     for row in rows]}
        return read


class FinancialExecutionGatewayImplementation(_PluginImplementation):
    resource_id = "financial-execution-gateway"
    tool_name = "financial_execute_one_order"
    schema = _tool_schema(resource_id, "execute", confirmation=True)
    description = "Execute only the exact provider action covered by a fresh one-shot Hermes user confirmation."

    def handler(self, runtime_context: object):
        def execute(args: object):
            if not isinstance(args, Mapping):
                raise FinanceDenied("execution arguments must match the reviewed exact schema")
            base, confirmation = _attested_args(args, frozenset({"provider", "operation", "action"}))
            provider, operation = base["provider"], base["operation"]
            if not isinstance(provider, str) or not isinstance(operation, str) or operation not in _EXECUTION_OPERATIONS.get(provider, frozenset()):
                raise FinanceDenied("provider operation is outside the fixed execution catalog")
            action = _validate_execution_payload(provider, operation, _bounded_action(base["action"]))
            # The root resolves the account and recipient from enrollment, then
            # binds and consumes this opaque confirmation against the final payload.
            return _effect(runtime_context, adapter_id=self.resource_id,
                action_id="execute",
                arguments={"provider": provider, "operation": operation, "action": action},
                write=True, attestation=confirmation)
        return execute


class AgentLiveWalletImplementation(_PluginImplementation):
    resource_id = "agent-live-wallet"
    tool_name = "agent_live_wallet_action"
    schema = _tool_schema(resource_id, "read", confirmation=True, merge_action_id="execute")
    description = "Prepare and inspect an allowlisted live-wallet action; signing and broadcast require fresh user confirmation."

    def handler(self, runtime_context: object):
        def act(args: object):
            if not isinstance(args, Mapping) or set(args) - {"network", "operation", "action", _CONFIRMATION_FIELD}:
                raise FinanceDenied("live wallet arguments do not match the reviewed schema")
            network, operation = args.get("network"), args.get("operation")
            if not isinstance(network, str) or not _ID.fullmatch(network) or operation not in _LIVE_OPERATIONS:
                raise FinanceDenied("live wallet network or operation is outside the fixed catalog")
            write = operation not in _LIVE_READS
            if write:
                payload, confirmation = _attested_args(args, frozenset({"network", "operation", "action"}))
            else:
                if set(args) != {"network", "operation", "action"}:
                    raise FinanceDenied("read-only wallet operation cannot carry a write confirmation")
                payload, confirmation = dict(args), None
            action = _bounded_action(payload["action"])
            return _effect(runtime_context, adapter_id=self.resource_id,
                action_id="execute" if write else "read",
                arguments={"network": network, "operation": operation, "action": action},
                write=write, attestation=confirmation)
        return act


class AgentSandboxWalletImplementation(_PluginImplementation):
    resource_id = "agent-sandbox-wallet"
    tool_name = "agent_sandbox_wallet_action"
    schema = _tool_schema(resource_id, "read", confirmation=True, merge_action_id="execute")
    description = "Experiment with enrolled test accounts on Sepolia or Solana Devnet using test assets only."

    def handler(self, runtime_context: object):
        def act(args: object):
            if not isinstance(args, Mapping) or set(args) - {"network", "operation", "action", _CONFIRMATION_FIELD}:
                raise FinanceDenied("sandbox wallet arguments do not match the reviewed schema")
            network, operation = args.get("network"), args.get("operation")
            if network not in {"ethereum-sepolia", "solana-devnet"} or operation not in _SANDBOX_OPERATIONS:
                raise FinanceDenied("sandbox operation is outside Sepolia/Solana Devnet test catalog")
            write = operation not in _SANDBOX_READS
            if write:
                payload, confirmation = _attested_args(args, frozenset({"network", "operation", "action"}))
            else:
                if set(args) != {"network", "operation", "action"}:
                    raise FinanceDenied("read-only sandbox operation cannot carry a write confirmation")
                payload, confirmation = dict(args), None
            action = _bounded_action(payload["action"])
            # Refuse mainnet bridges in the adapter as well as at the root.
            if write and action.get("mainnet_bridge") is not False:
                raise FinanceDenied("sandbox writes must explicitly deny mainnet bridge")
            if operation in {"sign-test-transaction", "send-test-asset", "deploy-test-contract", "reviewed-testnet-dapp"} and action.get("test_asset") is not True:
                raise FinanceDenied("sandbox transaction, asset and deployment writes must identify test assets")
            return _effect(runtime_context, adapter_id=self.resource_id,
                action_id="execute" if write else "read",
                arguments={"network": network, "operation": operation, "action": action},
                write=write, attestation=confirmation)
        return act


FINANCIAL_PLUGIN_IMPLEMENTATIONS = {
    "financial-data-hub": FinancialDataHubImplementation(),
    "financial-execution-gateway": FinancialExecutionGatewayImplementation(),
    "agent-live-wallet": AgentLiveWalletImplementation(),
    "agent-sandbox-wallet": AgentSandboxWalletImplementation(),
}
