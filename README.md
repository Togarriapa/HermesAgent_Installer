# HermesAgent Installer

This repository is implementing the validated plan for a complete Raspberry Pi 5 Hermes installer. The pinned bootstrap/runtime path has been exercised on an enrolled Pi; the complete installer is **not finished** and account-dependent/public services remain disabled.

Read [the plan](planning/PLAN.md), [complete source-to-task/evidence map](planning/traceability.json), [component contracts](planning/component-contracts.json), [source evidence](SOURCES.md), [compatibility limits](COMPATIBILITY.md) and [engineering instructions](AGENTS.md). Redacted Pi runtime evidence is in [the native provider probe report](docs/evidence/2026-10-09-pi-native-provider-probe.md).

## Planning and development checks

```bash
npm ci
npm run validate:specs
npm run validate:plan
npm run test:planning
```

Use Node24.6.0 (OpenSpec engine>=20.19.0). OpenSpec1.14.1 is pinned in the lock and generated Codex skills. The frozen baseline is plans/2026-10-09-v1 at annotated tag hermes-installer-plan-2026-10-09-v1. Live OpenSpec changes remain active; only verified implemented behavior belongs in canonical specs.

## Current runtime status

`./install.sh plan`, `doctor`, `status`, `install`, and `resume` are wired. Install/resume run the pinned official Hermes bootstrap and selected Desktop build; the CLI reports Agent artifact verification separately from provider configuration, user-session service readiness, and other pending steps. The local Hermes provider plugin and loopback dispatcher are implemented and fixture-tested, but are not yet wired into the installer lifecycle. OpenRouter inference defaults to denied until a fresh authoritative zero-charge account-policy proof exists; the provider metadata APIs inspected so far do not prove account-level paid processing is disabled.

The Pi test in the evidence report exercised the pinned PM environment and a synthetic recording upstream. It did not contact OpenRouter, create an external account, or activate a user/public service. The enrolled target is available, but no Cloudflare management token/account selection, provider credentials, external resource credentials, or GLM weights have been supplied.

`verify`, provider/MCP configuration and connection commands, memory/source selection, component operations, update/data lifecycle, registry activation, all per-item adapters, remote Desktop/Cloudflare automation, and GLM/Coral acceptance remain in implementation. Their presence in the CLI parser or plan is not evidence of a working adapter.

Zero additional metered spending is the default. No huge model download, paid inference, Pi reimage, or unrelated service replacement is authorized. Missing account inputs defer live account acceptance, not the corresponding code, fixtures, docs, or target verifier.

The later direct Cloudflare requirement is captured in planning/user-additions/2026-10-09-remote-desktop.md and the remote-desktop-tunnel change. The hostname prompt starts blank; setup securely collects a scoped token and allowed email addresses, automatically configures only owned resources, and exposes only the official native Desktop app through constrained transport. No prefilled hostname, local-password substitute, repeated routine approvals, public host desktop, shell, dashboard, or backend-management route is acceptable.
