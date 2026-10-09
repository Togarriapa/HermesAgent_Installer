# Design

## Context

See proposal.md. Shared candidate ccddc8a0e3908fa72346f91de76eb8247540522a contains partial runtime code and fixture evidence, while every baseline runtime task remains open. R0054/R0058 already require real mediation; profile state and transient user services cannot establish kernel custody. RP01..06 remain independent Cloudflare verifier requirements.

## Goals / Non-Goals

Implement the existing host principal boundary without replacing official Hermes PM Python3.14, its native tools, Desktop, model identity or memory owner. This refinement grants no live infrastructure enrollment, spending, outbound test messaging, global Python changes or unowned service replacement.

## Decisions

Use a root-owned custodian and protected system service definitions as the trusted control plane. Root privilege is limited to fixed reviewed generation/identity/namespace setup and bounded enrolled operations; model-facing processes never execute arbitrary root shell commands. Distinct unprivileged UIDs run Hermes/profile workers, provider/credential brokers and the remote read verifier. Freeze executable modules/runtime paths and service definitions under host ownership; no model-writable import path, shell startup file, writable ancestor or shared profile can alter custodian code. Root-owned IPC endpoints authenticate Linux peer credentials and bind exact principal, operation, fixed resource, payload digest, config generation, nonce and deadline. Protected IPC is not a generic shell, URL proxy or credential resolver.

Use kernel mount/process/network namespaces and supported service sandbox controls, with explicit read-only source and per-principal writable state. Default network denial for workers; broker egress permits only selected fixed destinations with TLS verification and bounded calls. Deny access to sibling private files, host credential stores, other process environments/signals and namespace escape. Avoid shared writable profiles or reused OAuth material; provider brokers retain distinct eligible private/public routes and derived-content sensitivity through retries/background/extraction. Preserve Electron/browser sandbox. Where the required kernel mechanism is unavailable, mark that affected boundary unavailable; do not claim a user service or separate HERMES_HOME supplies equivalent protection.

Authentik is authoritative for System membership and recipients. Fresh authenticated subject must match request principal; direct and indirect membership traversal is complete, bounded and explicit about direction and hierarchy semantics, rejecting cycles, missing pages, inconsistent responses and unsupported semantics. Refresh each privileged write and independently resolve alarm recipient authority before delivery; deny outage/revocation/mismatch before side effects. Use only identified enrolled fixed targets/actions; no arbitrary SSH/systemctl or generic shell scope. Cloudflare RP verifier retains its separate read role, deadlines and observation-anchored leases.

Wire actual official Hermes entrypoints to mandatory broker/dispatch controls. Audit direct native tools, subprocesses, delegated callbacks, MCPs, schedules, webhooks, provider retries and memory extraction/embedding. If a native route cannot be mediated or confined, expose explicit unavailable state; an injected class exercised only by tests is partial evidence. Run denials through installed native workers, including direct bypass attempts and private canaries. No outbound installation-test alarm/message is required: recording synthetic recipient fixtures precede any separately authorized harmless account probe.

## Risks / Trade-offs

Kernel/ARM64 support varies -> probe actual target features and retain explicit affected-capability blockers. Compromised worker reaches writable trusted ancestors -> verify ownership/import paths and reject activation. Incomplete Authentik hierarchy -> deny without cached claims. Service update interrupts IPC -> generation-bound one-use grants, bounded cancellation/reap and ownership journal rollback. These controls cost operational complexity; simpler profiles/transient user units were rejected because they do not satisfy existing filesystem/process/network/credential boundaries.

## Migration Plan

Stage owned custody, identities and protected files without modifying unrelated services. Validate fixture policy and Linux hostile-worker denials, then native wiring, before enabling sensitive capabilities. Commit implementation, tests, docs and exact requirement/task IDs together. Separately run authorized native ARM64/account probes and preserve redacted UID/namespace/service/source/generation evidence. Restore prior working generation on failure or report disabled recoverable state; never export plaintext secrets in backups. HI-T06 target acceptance stays open until actual evidence. No runtime canonical spec sync/archive before genuine verification.
