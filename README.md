# HermesAgent Installer

This repository contains the validated specification and immutable implementation plan for a complete Raspberry Pi5 Hermes installer. The installer runtime is assigned to GPT-6 Luna; this baseline does not claim installed or target-tested integrations.

Read [the plan](planning/PLAN.md), [complete source-to-task/evidence map](planning/traceability.json), [component contracts](planning/component-contracts.json), [source evidence](SOURCES.md), [compatibility limits](COMPATIBILITY.md) and [engineering instructions](AGENTS.md).

## Planning checks

```bash
npm ci
npm run validate:specs
npm run validate:plan
npm run test:planning
```

Use Node24.6.0 (OpenSpec engine>=20.19.0). OpenSpec1.14.1 is pinned in the lock and generated Codex skills. The frozen baseline is plans/2026-10-09-v1 at annotated tag hermes-installer-plan-2026-10-09-v1. Live OpenSpec changes are proposals; only implemented planning governance is canonical. Refinements append Sol-reviewed amendments separately.

## Development handoff

GPT-6.1 Sol owns specification/task creation/refinement; GPT-6 Luna implements the unblocked DAG. Inspect change status and apply instructions, implement real component handlers with meaningful failure tests/docs, keep the evidence ledger truthful, and archive only genuinely verified scope. All 216 nonempty original lines,211 requirements,240 tasks,62 inventory records and 12 original plus 3 added acceptance criteria are mapped. Test paths identify semantic contracts and may be consolidated into real test functions in the mutable ledger without weakening assertions.

## Planned installer use

These commands are design contracts and are **not available yet**:

```bash
./install.sh --config installer.yaml --dry-run
hermes-installer install --config installer.yaml
hermes-installer resume --config installer.yaml
hermes-installer verify --target authorized-target.json --output evidence-dir
```

No privileged install may run on the development Mac. A physical target, credentials and selected external resources must be identified/authorized before live operations. Zero new metered spending is the default. Missing source identities/accounts/hardware do not block implementation of the independent code, fixtures and executable target workflow. Current source selection and live blockers are recorded explicitly.

The later direct Cloudflare requirement is captured separately in planning/user-additions/2026-10-09-remote-desktop.md and the remote-desktop-tunnel change. Blank hostname, secure scoped token, automatic owned tunnel/DNS/Access email-code setup, real native-app-only transport and bounded JWT/WebSocket expiry/revocation are required. No prefilled hostname, local-password substitute, repeated routine setup approvals or public host-desktop/shell/backend route. Live Cloudflare/Pi actions await secure target setup; full code/fixtures/docs/executable AC13..15 remain unblocked.
