# Design

## Context

See proposal.md for motivation. This empty authorized installer repository has a pinned planning toolchain; no runtime behavior is implemented. The canonical Hermes/registry observed revisions are recorded in SOURCES.md.

## Goals / Non-Goals

**Goals:** Implement all linked source obligations with observable contracts, per-item adapters and meaningful failure tests.

**Non-Goals:** This planning commit does not install software on the development Mac or enroll external hardware/accounts/infrastructure. Missing dependencies remain active scope and explicit blockers.

## Decisions

Evidence records immutable candidate Git SHA, platform (x86 fixture/native ARM64/emulation/physical Pi), target identity, component/source/artifact versions, command/exit code, start/end UTC and displayed Europe/Lisbon, assertions/results, resource measures, redacted log/artifact hashes, status/blocker and exact resume command. Report authentication, reachability, functionality, enabled state and actual-target evidence as separate fields; never compute green from config presence. Expected tests are definitions until executed. One failed required dependency prevents full registry compliance while text-core may remain usable.

Implement fixtures: fake apt lock/package errors; interrupted HTTP Range/digest mismatch/DNS/TLS/disk ENOSPC; prepopulated owned/unowned/symlink roots; fake user-session/Desktop backend; registry malformed/catalog root/inheritance/selector/quality and overlay conflicts; broker/AuthenTik hierarchy/revocation/mismatch; provider recorder proving privacy/aggregate-budget/fallback/Retry-After/capability; mock MCP schemas/reconnect/revocation; memory namespace persistence/extraction; lifecycle crash checkpoint/atomic generation/DB restore; workload scheduler pressure. Test assertions compare effects and observed output, not implementation names. Per-item tests must exercise substantive adapter operations, not only registry enumeration.

Target verifier consumes authorized target record and explicit selected account/resource inputs. It rejects accidental development-host privileged install. Tests AC01..AC12 are separately selectable with honest skip/pending when dependencies absent; JSON evidence/report does not count skip as pass. Complete code/fixtures/docs despite unavailable hardware/accounts; target scripts must be executable without inventing results. Golden baseline plus fixture CI, native ARM64 runner/container evidence and physical Pi graphical/TPU/GLM evidence are distinct lanes.

Quickstart/account guides/recovery/update/backup/uninstall and troubleshooting commands must correspond to implemented CLI help. SOURCES and COMPATIBILITY record dated primary links and pinned revisions, unknown licenses/ARM64/feature gaps. Coverage checker maps all original prompt lines, unique components and aliases, each of 12 acceptance criteria to spec/tasks/manifest/evidence or blockers; it catches dropped items and claimed-complete placeholders. CI pins toolchain/action SHAs, strict OpenSpec validation, frozen-plan integrity, coverage, meaningful fixture suite and report artifacts. Review scenarios against actual code before archive; canonical specs represent verified implemented behavior only, not artifact completeness.

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

## Supplemental evidence profile decision

The verifier profile registry covers the exact current evidence IDs, including EV-RB06, EV-RB07, EV-RB08, EV-HI10, EV-HI11, EV-HI12, EV-HI13, EV-HW01, and EV-PR01. Each profile names the concrete requirement dimensions, rather than accepting a generic caller-supplied success flag. EV-RB06 asserts a public, fixed-service, bounded metadata read with hostile destinations and activation denied; EV-RB07 asserts authenticated, selected, bounded job admission and reduced child grants; EV-RB08 asserts immutable root-observed native package resolution and source closure, a finite action ledger, an actual selected-backend effect with a verified result, exact one-use operation grants, recipient/credential scope, confirmation/idempotency, durable reconciliation of ambiguous outcomes across restart, and negative effect proofs. EV-HI11 covers authenticated one-use producer-to-gateway handoff; EV-HI12 covers exact operation-bound grants and lease-preserving frame effects; EV-HI13 covers root verification of the actual Access JWT and selected policy before native bytes, binding the enrolled principal/session to route, generation and lease, denial of caller claims and forged/replayed identities before delivery, bounded active-stream closure, and secret separation. Profile presence proves coverage only; target and account observations remain pending unless every required assertion is observed true, the exact result is retained, and an enrolled verifier authenticates it. Unattempted dimensions use null and remain pending; an observed false or nonzero exit remains a failure.
### v28 installer-owned verifier constructors

VD-F02/VD-F04 use protected-runtime-assembly-contract.json installer_target_result_verifier exact current root target/candidate/admission/result constructors and receipts. All AC01..18 remain pending absent actual dimensions.
Application owned execution receipts v104: `plans/amendments/2026-10-10-application-owned-execution-receipts-v104.md`; actual distinct selected grant/controller/probe/manager terminal/artifact result producer required, no ResourceTask/RuntimeReview substitutes; existing implementation/acceptance tasks open.


Source-join producers v178: `plans/amendments/2026-10-10-source-join-producers-v178.md`. Exact retained setup/source/PM/native definition/member, finite fixture descriptor/service observation and local overlay invocation producers; all AC01..18 OPEN, baseline unchanged. Producer ownership/order and acceptance remain in HI-T178.1..5.


Reviewed source members and boundary joins v180: `plans/amendments/2026-10-10-reviewed-source-members-boundary-joins-v180.md`; finite exact merged module pins, corrected standalone builder role,21-field separate local-operation publication and per-worker kernel start barrier. Producer ownership/order/evidence tasks remain OPEN; baseline and all AC01..18 unchanged.


## Conditional Authentik and local-owner setup v181

Use the separate root-observed Linux-owner identity/principal/snapshot domain, finite selected owner-overlay ceiling, digest-covered native policy and genuine loaded worker joins; preserve Authentik TLS/credential/fresh System/recipient/broker checks. Contract and sequential producer/evidence details: `plans/amendments/2026-10-10-conditional-authentik-local-owner-setup-v181.md`. No runtime implementation or acceptance is claimed; all AC01..18 OPEN.


## Active network generation owner v182

Use the concrete RootActiveNetworkGenerationOwner/runtime signed-choice and active-publication composition in `plans/amendments/2026-10-10-active-network-generation-owner-v182.md`. Replace ambiguous active_enrollment with exact current generation projection; preserve original adoption deadline and fresh revocation, release/actor/key/journal/CAS checks independently of expired setup. Own-worker kernel gate and cleanup remain mandatory, all AC01..18 OPEN.


## Concrete signed worker and active overlay producers v183

Follow `plans/amendments/2026-10-10-signed-worker-recipes-active-overlay-producers-v183.md`: exact held recipe→signed choice→service-generation producer→active PM/native custody, and signed local-owner/source/view adoption→current NSS/loaded invocation/one-use four-method grant. No setup object or static metadata becomes active authority. Source pins pending committed review, all AC01..18 OPEN.


## Network wire/digest clarification v184

Exact field sets/FKs/source and lifecycle mapping: `plans/amendments/2026-10-10-network-row-wire-digest-boundaries-v184.md` / `planning/network-row-wire-v184.json`. Generated AF_UNIX rows stay separate from existing TCP private-loopback rows; enclosing digest exists only on runtime projection. Pre-READY mount permits loader binding; effects require later actual READY/source/invocation/grant proof. All AC01..18 OPEN.


## Owner observer/source/RPC clarification v185

Exact typed registration/READY/module/source-capture and worker proxy→native.owner-overlay.execute→observed invocation→one-use grant contract: `plans/amendments/2026-10-10-owner-overlay-observer-capture-rpc-v185.md` / `planning/owner-overlay-observer-wire-v185.json`. Backend61 action schemas unchanged, no synthetic observer/source authority, all AC01..18 OPEN.


## Preactive listener phase clarification v186

Actual fixed root-owned listener before recipe signing and exact authenticated active FD adoption/re-observation: `plans/amendments/2026-10-10-preactive-authority-listener-custody-v186.md`. No future path/socketpair or prepared receipt substitutes for active authority; no effects before adoption. Source pins pending, all AC01..18 OPEN.


## Cross-process listener activation v187

Exact supervised installed daemon/private pathname control/peer PIDFD/unit/release/source/current publication binding and one-use SCM_RIGHTS adoption: `plans/amendments/2026-10-10-supervised-listener-activation-channel-v187.md` / `planning/listener-activation-channel-v187.json`. Each actor verifies only itself locally; UID0/same-process/socketpair does not prove handoff. Source pins/acceptance OPEN.


Owner result source v188: `plans/amendments/2026-10-10-owner-result-source-selector-v188.md` adds exact separately signed tool-result enrollment/issuer/channel/root-handler member, paired to the invocation and consumed grant. Generic backend observer matching is insufficient; all acceptance/source pins remain pending.

Finite native worker mode v188 also resolves the fixed reviewed Hermes -m recipe versus generic child-script matcher contradiction through a private current active worker launch proof; generic interpreter rules remain unchanged.


Committed PM identity v189: `plans/amendments/2026-10-10-committed-pm-executable-identity-v189.md` supplies exact independently verified venv executable metadata to the selected native worker parser/runtime consumer, preserving generic static catalog checks and base/venv distinction. No source pin approval or acceptance.


Same-worker namespace handshake v190: `plans/amendments/2026-10-10-same-worker-namespace-handshake-v190.md` fixes schema2 helper-only initial launch, real owned MainPID namespace observation, authenticated namespace gate then actual probes and separate one-use app release. No future namespace/skip/source pin approval.


Two-actor health v191: `plans/amendments/2026-10-10-two-actor-health-commit-custody-v191.md` replaces unsafe setup-session aliasing with independently current daemon commit/source proof, actual fixed source run/events and one-use authenticated setup health intent. Only consumer-completed same-generation journal witness may enable; ACK is insufficient. All acceptance/source pins remain OPEN.


Selected view paths v192: `plans/amendments/2026-10-10-native-worker-selected-view-paths-v192.md` separates host source executable custody from fixed worker argv/path, retains byte-identical full PM venv/base closure and actual native output/package/helper views, and requires postmount inode/hash proof before release. No caller paths or broad host exposure; pins/acceptance remain OPEN.


Selected member custody v193: `plans/amendments/2026-10-10-native-worker-view-member-bind-custody-v193.md` permits only exact five native-output file binds into a separately owned readable target tree, preserving original protected root/member proof and empty hidden source parents; exact private selected/observed APIs distinguish source and target identity. All pins/acceptance OPEN.


Health causal ancestry v194: `plans/amendments/2026-10-10-health-event-causal-ancestry-v194.md` retains each native event digest meaning and real causal source relations, replaces impossible uniform run equality with observed authenticated DAG proof, and binds schema2 receipt/completion to final result closure plus health_run_proof_sha256. No fixture ancestry substitution; all acceptance/pins OPEN.


## Final coherent source review v195

Exact closed source/member/catalog/preload application under existing VD-T180.6/VD-T183.5: `plans/amendments/2026-10-10-final-coherent-source-pin-review-v195.md` and `planning/final-coherent-source-pin-review-v195.json`. Source0add8c33 follows reviewed nested leaf corrections; metadata self-pinning is excluded. All original implementation/acceptance tasks and AC01..AC18 remain OPEN.


## Safe bootstrap diagnostics v196

Exact finite output redaction, reviewed two-member source update and ownership/evidence: `plans/amendments/2026-10-10-safe-bootstrap-diagnostics-source-review-v196.md` / `planning/safe-bootstrap-diagnostics-source-review-v196.json`. Guards/phases and all acceptance remain unchanged; actual source-CAS failure diagnosis is independent of still-open display/task runtime custody.


## Installed startup and qualification custody v197

Actual daemon/setup process separation requires a closed source-issued startup intent and concrete tagged admission; installed qualification must construct its own real fixture source/publication/session/runtime graph. Exact finite contract/order/failures: `plans/amendments/2026-10-10-installed-startup-qualification-custody-v197.md` / `planning/installed-startup-qualification-custody-v197.json`. No private store copy, production relabel or BPF relaxation; all original AC and future source pins OPEN.


Durable Xpra startup adoption v198: `plans/amendments/2026-10-10-durable-xpra-startup-adoption-v198.md`. Existing HI-T197.1/.2 and VD-T197.4 require schema2 actual build/CAS/catalog reopening under a separate overlay signing domain, and admission-to-active lifecycle ownership. All acceptance remains OPEN.


Finite actual setup/fixture source producers v199: `plans/amendments/2026-10-10-setup-startup-and-fixture-source-producers-v199.md`. Existing HI197/173/178 tasks require genuine setup protected selection/role producer and distinct child-owned qualification acquisition; no copied stores, caller rows or publication cycle. All acceptance OPEN.


Fixed release-store publisher source review v200: `plans/amendments/2026-10-10-fixed-release-store-source-review-v200.md`. Existing HI-T149.1 admits only the exact corrected candidate-held publisher metadata and fixed root directory effect; no new pin table/catalog row or acceptance.


Actual publication core/acquisition compatibility v201: `plans/amendments/2026-10-10-publication-core-and-fixture-acquisition-v201.md`. Existing HI160/197 compiler emits authenticated core member; workload consumes exact published proof. New fixed acquisition original bound is separate from unchanged short effect leases. All acceptance OPEN.


Finite real remote choice/three-role source producer v202: `plans/amendments/2026-10-10-selected-remote-role-source-inputs-v202.md`. Workload owns actual TTY/source/runtime/NSS/build inputs; compiler consumes exact sealed inputs; original source/account/ARM64/sandbox/network acceptance remains OPEN.

Typed finite bootstrap diagnostics v203: `plans/amendments/2026-10-10-typed-bootstrap-runtime-diagnostics-v203.md`; exact source boundary RuntimeError only, no dynamic trust error text or behavior change.

Typed diagnostic source review v204: exact fd09b11d leaf replacements are in planning/typed-bootstrap-diagnostic-source-review-v204.json under BD-T203.1 / VD-T203.2. Pin application/unexcluded suite/target evidence remain open; all acceptance open.

Jarvis sole user-facing profile v205: direct user requirement and audited supported default/display_name mapping; all208 source profiles preserved,207 protected isolated delegate homes, actual native/UI/default routing and ownership-safe migration required. Contract planning/jarvis-sole-user-profile-contract-v205.json; all acceptance open.


Finite fixture-owned NSS subject v206: `plans/amendments/2026-10-10-fixture-subject-nss-custody-v206.md`. Existing HI173/178/197 source session issues genuine actual NSS receipt under its own fixture transaction/controller; no normal session scan/production marker authority. All acceptance OPEN.


Raspberry Pi vendor dependency refinement v207: plans/amendments/2026-10-10-raspberry-pi-nft-dependency-observation-v207.md defines only exact libc6/u3/arm64 signed evidence for reviewed Debian nft, per-archive retained trust anchors, bounded live/cache metadata and unchanged installed ELF/kernel proof. No package/key mutation; all acceptance OPEN.

Bootstrap handoff TTY reconfirmation v208: new explicit same-SHA observation after slow acquisition, same original controller/action/source/runtime joins, unchanged60s proof TTL and one-use transition. planning/bootstrap-handoff-tty-reconfirmation-v208.json; BD-T208.1/VD-T208.2 OPEN.

Handoff reconfirmation source review v211: exact26cf root_setup sole leaf replacement in planning/bootstrap-handoff-reconfirmation-source-review-v211.json; all other source rows unchanged, no wider runtime cohort. BD-T208.1/VD-T208.2 pin application/unexcluded checks/target evidence OPEN.

Jarvis selected task home custody v213: planning/jarvis-selected-task-home-custody-v213.json; current active held home→existing consumed task grant→fixed/hermes unprivileged mount. Root discovery not usability; all208/source/toolpolicy/namespace/private-public boundaries preserved. RB-T213.1/HI-T213.2/VD-T213.3 OPEN.

RB-T213.1/HI-T213.2 also require actual publication-owned core crosswalk/member readback and post-setup restart/current active home registry; setup-only maps cannot complete Jarvis delegate scope.
