# Financial Account Access Architecture

Hermes financial integrations are split into four deliberately separate layers:

1. **Read-only personal financial data** — `financial-data-hub`.
2. **Real-money execution** — `financial-execution-gateway`, technically write-capable but callable only from a one-shot explicit user order plus fresh confirmation.
3. **Agent live wallet** — `agent-live-wallet`, a dedicated real-value wallet with the same explicit-order confirmation gate.
4. **Agent experimentation wallet** — `agent-sandbox-wallet`, autonomous only on approved public test networks and faucet/test assets.

The separation is structural: analytical Profiles never receive raw credentials or implicit transaction authority, and a recommendation can never self-authorize its own execution.

`QUALITY_POLICY.yaml` also applies the finance/investment overlay: current material market/regulatory facts, explicit uncertainty/scenario risk, secret isolation, and strict separation of observation, analysis, recommendation, authorization, execution, and reconciliation.

## Authorization model for real money

Every bank payment, broker/exchange order, Ledger transaction, or dedicated agent-live-wallet mainnet transaction requires:

- an explicit user order routed through Hermes;
- a one-shot authorization envelope bound to the exact provider, account, operation and economic parameters;
- a fresh confirmation of the final normalized action payload;
- revalidation of current account/balance/position/market state before execution;
- simulation/fee/slippage estimation where supported;
- duplicate/replay protection;
- provider-result reconciliation and an immutable audit event after execution.

Authorization expires after five minutes and cannot be wildcarded, reused, inferred from a strategy, converted from a recommendation, or delegated as standing authority.

Host/runtime policy is the absolute authorization ceiling: even a valid user confirmation cannot invoke a provider operation that the configured execution gateway/account credential does not permit.

## One-shot execution state machine

A real-value action follows an explicit state machine:

`proposed -> normalized -> state-refreshed -> user-ordered -> payload-prepared -> user-confirmed -> executing -> provider-acknowledged -> reconciled -> reported`

Terminal/non-success states include:

`rejected`, `expired`, `cancelled`, `provider-failed`, `ambiguous-provider-state`, and `reconciliation-failed`.

Rules:

- changing any material economic/target parameter after confirmation invalidates the authorization and returns to a new confirmation cycle;
- an expired or cancelled authorization cannot be resumed;
- `provider-acknowledged` is not sufficient completion—resulting state must be reconciled;
- an ambiguous timeout must **not** be blindly retried if the first call may have succeeded;
- follow-on actions require new user authority unless they are a provider-internal atomic part of the exact confirmed operation.

## Idempotency and ambiguous failures

Each prepared action receives an internal immutable execution ID and, where the provider supports one, an idempotency/client-order key.

Before retrying a state-changing call after timeout/network failure, the execution operator should query provider state using the execution/client order ID or normalized action fingerprint. If success cannot be determined safely, mark the action `ambiguous-provider-state` and surface it through Hermes rather than risk a duplicate transfer/order.

Provider-specific non-idempotent endpoints require stronger local duplicate protection.

## Bank data and payments: Revolut, Banco BPI, moey

Read access uses a regulated PSD2 Account Information Service Provider (AISP) connection. Write/payment access uses a regulated Payment Initiation Service Provider (PISP) adapter when provider and institution coverage permit it. Hermes does not scrape banking credentials or impersonate an unlicensed TPP.

Target institutions are Revolut, Banco BPI, and moey. Actual institution/provider coverage, consent scope, SCA requirements, and available payment types are checked at connection/action time.

Read capabilities include accounts/metadata, balances, transaction history, and consent/freshness state.

Write capability is limited to initiating the exact payment explicitly ordered and confirmed through the regulated provider's consent/SCA flow.

Not granted:

- autonomous payments/transfers;
- beneficiary/account/card administration;
- agent-created standing/scheduled payment authority;
- passwords, PINs, reusable MFA material, or raw banking credentials.

Expired/revoked AIS/PIS consent is treated as an authorization failure and triggers a user-visible reconnection/consent requirement rather than credential fallback.

## Trading 212

Hermes uses separate observation and execution credentials:

- `TRADING212_READONLY_CREDENTIALS` — portfolio/account observation;
- `TRADING212_EXECUTION_CREDENTIALS` — minimum reviewed order permission and IP restriction.

Live order placement/cancellation is callable only by `financial-execution-operator` after explicit order + fresh confirmation. Funding/withdrawals/account administration remain denied.

Because some order flows may not be safely idempotent, the gateway records local order fingerprints/client IDs where supported and reconciles open orders/fills before retrying an uncertain request.

A market/price move between proposal and final confirmation should be reflected in the final normalized payload/risk display. If the requested order type does not guarantee the displayed estimate, Hermes must describe that uncertainty rather than present an estimated fill as certain.

## Pionex

Separate keys are used:

- `PIONEX_READONLY_API_CREDENTIALS` — `Read` only;
- `PIONEX_TRADE_API_CREDENTIALS` — minimum `Trade` scope required for placement/cancellation.

The Trade key is callable only through the execution gateway after explicit user order + confirmation. Withdrawals, transfers, credential/account administration, and unrelated trading authority remain denied.

Order acknowledgement is reconciled against order status/fills; ambiguous placement results are queried before any retry.

## Ledger

Observation uses Ledger Wallet API `account.list`. The execution gateway may use `transaction.sign` / `transaction.signAndBroadcast` only for the exact confirmed transaction and still depends on the user's Ledger hardware/on-device confirmation.

Denied:

- arbitrary message signing by default;
- seed/recovery phrase access;
- private-key access/export;
- background signing;
- substituting addresses/amounts after confirmation;
- treating device unlock/presence as approval of a different transaction.

The user's Ledger is never used as the agent-owned wallet.

## Normalized financial view

`financial-data-steward` consumes read sources through `financial-data-hub` and exposes a normalized, source-aware internal view to recruited finance specialists.

Each observation should retain:

- provider/source and non-secret account alias/reference;
- asset/currency/instrument identifier;
- units/balance/position;
- valuation currency and valuation source where relevant;
- observation timestamp and provider timestamp when available;
- freshness/consent status;
- reconciliation status and known data-quality limitations.

Raw provider credentials never enter Profile-visible context.

Cross-provider aggregation should not silently treat stale valuations, pending transactions, unsettled trades, locked/staked assets, or incompatible instrument identifiers as equivalent current cash/position state.

## Execution operator

`financial-execution-operator` is separate from advisors/managers/researchers. It executes **one exact confirmed action** and may not optimize, resize, substitute, split, change price/recipient, or create follow-on transactions without new authority.

Canonical path:

`Research/Manager -> recommendation -> Hermes -> explicit user order -> prepared exact payload -> fresh confirmation -> Financial Execution Operator -> provider -> reconciliation -> Hermes`

The operator should expose a structured receipt containing execution ID, provider reference, normalized requested action, provider result, resulting reconciled state, fees where known, timestamps, and any unresolved discrepancy—without leaking credentials/secrets.

## Dedicated agent live wallet

`agent-live-wallet` is a separate real-value wallet for Hermes use. It may receive real assets and technically construct/simulate/sign/broadcast transactions on an explicitly configured mainnet allowlist.

Private keys are generated/stored inside the host encrypted secret boundary and are never exported to Profiles, logs, Git, learned overlays, or the user's Ledger.

Every real-value transfer, swap, approval, contract call, bridge, staking action, or other economic transaction requires a specific user order and fresh confirmation. The agent may autonomously research, monitor, simulate, estimate gas/slippage, check allowances/nonces, and prepare the proposal but may not autonomously commit real value.

Before signing, the operator should refresh nonce/balance/allowance/network/chain ID, verify target contract/address and calldata interpretation where possible, simulate where supported, and reject unexpected network/account changes.

## Agent-owned cryptocurrency sandbox

`agent-sandbox-wallet` remains available for autonomous experimentation on approved public test networks. Initial networks are Ethereum Sepolia and Solana Devnet.

The sandbox may autonomously create/reset test accounts, receive faucet/test tokens, send/sign testnet transactions, deploy test contracts, interact with reviewed testnet dApps, simulate calls, and inspect receipts/events.

It must never connect to mainnet, accept intentional real-value deposits, use fiat on-ramps, receive production exchange withdrawals, bridge value to mainnet, import user/Ledger wallet secrets, or expose secret material.

Testnet contracts/tokens can still be malicious or misleading; sandbox autonomy does not waive cybersecurity/supply-chain review for arbitrary code/dApps.

## Credential and consent lifecycle

Financial credentials/connections should record non-secret metadata: provider, purpose (`read` vs `execute`), account scope, granted permissions, created/rotated date, expiry/consent expiry, allowed network/IP constraints, and owner/user binding.

The runtime should support rotation/revocation without changing Profile manifests. Revocation is fail-closed. A read credential must never be silently replaced by an execution credential merely to make an operation succeed.

## Reconciliation and audit

After every state-changing financial action:

1. capture provider acknowledgement/reference;
2. refresh affected account/order/wallet state;
3. compare requested vs provider-recorded result;
4. classify fees, partial fills/pending state, failures, or discrepancies;
5. record a redacted immutable audit event;
6. report the outcome through Hermes.

A reconciliation mismatch is not silently normalized away. Material discrepancies should recruit Financial Data Steward plus appropriate risk/accounting specialists and block dependent execution until understood when necessary.

## Separation remains structural

The financial architecture deliberately prevents analytical roles from self-executing their own recommendations. Quality policy, orchestration, Bundles, repeated prior approvals, or learned user preferences cannot collapse the data/recommendation/authorization/execution separation.
