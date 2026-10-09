# Investment and Wealth Governance

The investment domain is an internal decision-support system plus separately authorized execution under the normal Hermes topology:

`User <-> Hermes <-> Orchestrator <-> Wealth / Investment / Risk / Execution Profiles`

Research depth, team size, and internal debate can increase analytical quality; they never increase transaction authority.

## Role hierarchy

Management/advisory responsibilities are intentionally separated:

- **Financial Advisor** — goals, constraints, risk capacity, liquidity, liabilities, and investment-policy planning.
- **Wealth Manager** — coordinates the whole wealth picture and recruits accounting/legal/investment specialists.
- **Portfolio Manager** — portfolio construction, allocation, rebalancing design, performance and portfolio-level risk.
- **Asset Manager** — mandate, external-manager and asset oversight.
- **Stocks Manager** — public-equity portfolio domain.
- **Cryptocurrency Manager** — digital-asset portfolio domain.
- **Real Estate Manager** — real-estate investment domain.
- **Financial Data Steward** — account/portfolio aggregation, normalization, freshness, reconciliation and data-quality ownership.
- **Financial Execution Operator** — executes one exact real-money action only from explicit user order + fresh confirmation.
- **Crypto Live Wallet Operator** — operates the dedicated Hermes live wallet under the same one-shot gate.
- **Crypto Sandbox Operator** — autonomous approved-testnet experimentation only.

Analysts/researchers own independent evidence rather than inheriting execution authority: Investment Research, Equity, Fixed Income, Macroeconomic, Quantitative Investment, Investment Risk, Crypto Asset, Blockchain, and Real Estate Investment Analysts/Researchers.

## Investment decision record

A material recommendation should have enough structure to be challenged and revisited. The internal decision record should capture, where relevant:

- user objective and investment-policy constraint;
- time horizon and liquidity requirements;
- current holdings/exposures and data timestamp;
- proposed change or conclusion;
- thesis and key evidence with source dates;
- valuation/return assumptions;
- fees, taxes and implementation frictions where known;
- concentration/liquidity/leverage/counterparty/custody/currency/regulatory risks;
- base/upside/downside or other relevant scenarios;
- material counterarguments/disconfirming evidence;
- thesis-break/reconsideration conditions;
- confidence/uncertainty and known data limitations;
- independent risk challenge;
- whether the result is research, recommendation, prepared action, or executed action.

A decision record is not standing authority to trade.

## Independent research and challenge

Material decisions should recruit the smallest competent research set and preserve role independence. Parallel research is encouraged when assets/sectors/questions are independent.

Investment Risk Analyst should remain separate from the thesis owner for material portfolio decisions and actively challenge:

- concentration/correlation and hidden common factors;
- drawdown/tail risk;
- liquidity/market depth and exit assumptions;
- leverage/margin/liquidation paths;
- counterparty/custody/exchange/wallet risk;
- currency/rates/inflation/regime exposure;
- model/backtest/valuation assumptions;
- implementation/tax/fee drag;
- data freshness and unobserved liabilities/locked assets.

For contested recommendations, Orchestrator may recruit Debate Analyst and use the normal deliberation protocol. A majority of bullish analysts does not make the thesis correct.

## Evidence standards

Current market, issuer, regulatory, protocol, tax, and property facts should be refreshed before materially relying on them. Prefer primary sources such as official filings, regulators, central banks/statistical authorities, issuer/protocol documentation, audited reports, official exchange/broker data, and authoritative legal/tax sources.

Separate:

- observed facts;
- provider/source claims;
- analyst estimates;
- model outputs;
- forecasts;
- assumptions;
- opinion/judgment.

Publication date and the date the underlying event/data applies to should be distinguished where relevant.

Historical returns, backtests and forecasts must not be presented as guaranteed future performance. Quantitative work must explicitly guard against survivorship bias, look-ahead bias, leakage, overfitting, inappropriate regime selection, stale constituents, and unrealistic transaction costs/slippage.

## Portfolio governance

Portfolio proposals should be evaluated against an explicit mandate/policy rather than one asset in isolation. Consider:

- strategic allocation/risk budget;
- diversification and concentration limits;
- liquidity reserves and known cash needs;
- position sizing and maximum loss logic;
- rebalancing rationale/thresholds;
- tax/fee/turnover implications;
- currency and jurisdiction exposure;
- custody/operational constraints;
- scenario and stress behavior;
- monitoring and reconsideration triggers.

A recommendation that violates the current mandate should be described as a proposed **policy change**, not disguised as ordinary rebalancing.

## Read-only financial account access

`financial-data-hub` may ingest scoped observations from configured providers such as regulated PSD2 AISP connections, Trading 212 read credentials, Pionex `Read`, Ledger `account.list`, and other reviewed read sources.

`financial-data-steward` normalizes those observations for recruited finance specialists. Raw passwords, PINs, MFA secrets, API secrets, private keys, seed phrases, recovery codes and signing secrets remain outside Profile-visible context.

Data freshness, pending/unsettled activity, valuation provenance, locked assets, liabilities, and reconciliation status should be visible enough that analysts do not mistake an incomplete snapshot for current net wealth or immediately spendable liquidity.

## Explicit-order real-money execution

`financial-execution-gateway` is write-capable but non-autonomous. Every real-money action requires explicit user order through Hermes and fresh confirmation of the exact final normalized payload.

The authorization is one-shot, time-limited, payload-bound, and cannot be converted from a strategy/recommendation or reused after material parameter changes.

The Financial Execution Operator executes exactly the confirmed action. It cannot optimize size, substitute an asset, change recipient/price, split into additional actions, create follow-ons, or infer permission from past approvals.

Supported execution paths remain separately scoped in `FINANCIAL_ACCESS.md`; unsupported/account-admin/withdrawal/arbitrary-signing/property-contract capabilities remain denied unless a future explicitly reviewed resource adds them.

## Execution separation and conflicts

A Profile that originates a thesis/recommendation should not also silently act as its execution authority. The execution operator validates authorization/payload and performs the action; it does not re-underwrite the investment thesis or improve the trade.

Execution success is reconciled against provider/account state before dependent actions proceed. Ambiguous provider failures are not blindly retried.

See `FINANCIAL_ACCESS.md` for the one-shot execution state machine, idempotency, credential lifecycle, and reconciliation rules.

## Dedicated Hermes live wallet

The Hermes live wallet is a separate real-value wallet whose key material stays in the encrypted host secret boundary and is never mixed with the user's Ledger/other wallet secrets.

The agent may research, monitor, model, simulate and prepare mainnet transactions independently. Signing/broadcast of real economic value remains explicit-order + fresh-confirmation gated for every action.

Before a proposed blockchain action is confirmed, material review should consider network/chain ID, target address/contract, calldata intent, token approval scope, slippage/price impact, gas/fees, nonce/current wallet state, bridge/protocol/counterparty risk, and available simulation/security evidence.

## Agent crypto sandbox

`agent-sandbox-wallet` may autonomously transact only with test assets on approved public testnets such as Ethereum Sepolia and Solana Devnet. Testnet authority is isolated and cannot be reused for real accounts/wallets.

Testnets reduce economic risk but not all cybersecurity risk. Arbitrary testnet contracts/dApps may still be malicious, so security/source review remains relevant to code/wallet safety.

## Monitoring and thesis lifecycle

A recommendation is not permanent truth. Material theses/allocations should define monitoring signals and reconsideration triggers such as:

- thesis-break events;
- material valuation change;
- earnings/issuer/protocol/regulatory change;
- liquidity/custody/counterparty deterioration;
- user objective/liability/horizon change;
- concentration/risk-limit breach;
- model/data-quality deterioration.

Monitoring should surface a changed decision context to Hermes/Orchestrator; it does not create autonomous execution permission.

## Professional and jurisdiction boundaries

Financial planning, portfolio management, securities, tax, legal, estate, insurance, banking/payment, crypto, and property activities may be regulated differently by jurisdiction.

Profiles must distinguish research/planning from activities requiring regulated/licensed professionals, suitability/fiduciary obligations, filings, contracts, tax treatment, title, or other professional responsibility. Recruit the relevant Accounting, Portuguese/EU/International Law, Insurance, Privacy/Regulatory, or qualified human professional where necessary.

## Team bundles

Existing finance/investment Bundles are starting compositions for wealth/portfolio, public markets, digital assets, real assets, financial data, explicit execution, and crypto sandbox work. Orchestrator/Team Leader may recruit additional specialists or multiple analyst instances subject to the host/resource policy.

## Effective quality and audit

Finance/investment resources inherit `QUALITY_POLICY.yaml` defaults/domain overlays in addition to their explicit manifests. Internal records should preserve source provenance, assumptions, dissent/risk challenge, permissions, executed-vs-proposed status, verification/reconciliation, and redacted audit metadata needed to reproduce material decisions without exposing secrets.
