# Design

## Context

See proposal.md for motivation. This empty authorized installer repository has a pinned planning toolchain; no runtime behavior is implemented. The canonical Hermes/registry observed revisions are recorded in SOURCES.md.

## Goals / Non-Goals

**Goals:** Implement all linked source obligations with observable contracts, per-item adapters and meaningful failure tests.

**Non-Goals:** This planning commit does not install software on the development Mac or enroll external hardware/accounts/infrastructure. Missing dependencies remain active scope and explicit blockers.

## Decisions

Native Hermes mcp_servers configuration uses pinned supported stdio/streamable HTTP interfaces and credential references, generated merge patches preserving user entries. Shared MCP lifecycle client validates initialize/protocol, tools/list schema, allowlist and harmless tool call, deadline/cancel/reconnect/revocation; bounded discovery and lazy initialization cannot hang core chat. Record endpoint and account eligibility separately from functional status. Adapter sandbox limits environment/files/network and scrubs tool outputs through privacy policy before any model.

Figma uses official https://mcp.figma.com/mcp and account plan/tool availability plus user-selected file. RevenueCat official https://mcp.revenuecat.ai/mcp uses scoped OAuth/API v2 and selected project; list/read only, no billing/product/customer mutation. Google official preview services require live eligibility verification; selectable Gmail/Drive/Docs/Sheets/Calendar/Contacts with minimal scopes/read-only checks and refresh/callback tests. If personal account lacks official eligibility, offer separately labeled reviewed taylorwilsdon/google_workspace_mcp option, never silently switch or call it official. Home Assistant uses stateless Streamable HTTP; base /api/mcp defaults admin-only and /api/mcp/assist can serve nonadmins. OAuth client identity/redirect scheme/domain and client-ID metadata must match official requirements (do not assume RFC7591 registration). It connects to the existing documented endpoint, exposed selected entity read; registry policy denies device writes during setup and no replacement HA instance.

Playwright pins @playwright/mcp and compatible native ARM64 browser. Isolated fresh profile tests only local fixture navigation/accessibility/screenshot with sandbox retained; no cookie import or --no-sandbox workaround counted as compliant. Protocol fixtures cover 401, revoked tokens, malformed schemas, long-running server, disconnect, repeated connect without duplicate config, cancellation and stderr secret redaction. Live external tests require user account interaction and selected resource; fixture success never represents authentication or external access.

Use typed modular orchestration and explicit adapters rather than a monolithic shell script, because checkpointed operations and injectable command/network/filesystem interfaces make preservation and failure contracts testable. Prefer native supported upstream mechanisms over replacement frameworks; wrap them only at actual policy/compatibility boundaries.

## Risks / Trade-offs

- Upstream drift or unsupported ARM64 transitive dependency -> revalidate pinned source at component configure/update; retain previous generation and truthful unsupported state.
- Account or hardware unavailable -> finish code and synthetic fixtures, deliver executable target workflow, keep live verification unchecked.
- Secret or authority propagation -> host-managed references, mandatory dispatch mediation, synthetic canary and negative side-effect tests.
- Resource contention or partial failure -> measured limits, bounded cancellation, per-step journal, atomic activation and ownership-aware rollback.

## Migration Plan

Implement foundation tasks before dependent obligations. Stage artifacts and review dry-run against pre-state; isolated fixtures precede any authorized target install. Activate only compatible verified generations; restore previous pointer/config snapshot on failure and retain user data. Commit code/test/evidence with requirement and change IDs. Archive only completed verified scope and merge deltas into canonical specs through the installed supported workflow.

## Open Questions

Live target/account values and pending source selections are tracked in planning/blockers.json. The architecture supports source overrides and configure-later without deleting these requirements. New technical scope choices require a separate Sol-reviewed append-only amendment, never edits to the frozen baseline.

### v24 native MCP handler binding

MC-F01/MC-F02 and HI-T04/08/09 use native-package-binding-contract.json native_mcp_dispatch exact source-backed in-process hook/catalog/RPC/result joins. All original native/account acceptance remains pending.

### v25 MCP lexical/config mapping

Use native_mcp_dispatch row_types/invocation_mapping/native_config exact records, same one-use lexical binding and root-backed native candidate registration. MC/HI acceptance remains pending.

Installed release/native assembly v33: `plans/amendments/2026-10-09-installed-release-native-assembly-v33.md`; exact root receipt and construction joins preserve existing task IDs and pending evidence.

Native candidate index delivery v38: `plans/amendments/2026-10-09-native-candidate-index-delivery-v38.md`; exact compiled member/receipt joins preserve open tasks.

Native schema artifact joins v39: `plans/amendments/2026-10-09-native-schema-artifact-joins-v39.md`; exact selected schema source mapping, original tasks remain pending.

Candidate toolset envelope v41: `plans/amendments/2026-10-09-native-candidate-toolset-envelope-v41.md`; exact source-backed owner/envelope metadata, tasks stay open.
