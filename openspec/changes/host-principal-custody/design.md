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

## Fixed local service connector refinement

General model/profile workers remain AF_UNIX-only with external network denial. A separately reviewed `loopback_service` class is enrolled in protected host configuration with service ID, exact owner UID/cgroup/PIDFD, executable/module digests, generation, namespace identity and fixed target/finite protocol route map. It alone may create the required IPv4 loopback sockets inside its private network namespace. Root prepares the namespace and controlled lifecycle; a narrowly privileged connector owns only that namespace and selected loopback endpoint. No model-facing root shell, arbitrary setns target or general API proxy is exposed. Service-specific cgroup/firewall rules deny external destinations and sibling service namespaces. `IPAddressAllow=localhost`/namespace/seccomp enforcement must be measured on actual Linux, not inferred from unit text. Do not enable AF_INET globally for all worker classes.

Caller selects a protected logical target ID and approved action; caller never provides host, URL, port, namespace PID/path or service command. Authenticate Unix peer UID and host-issued principal/profile mapping. Validate fresh one-use grant bound to exact service generation, action/path or session, payload digest/nonce, observation and expiry before connecting or relaying payload bytes. Fixed supervisor catalog maps Xpra `hermes-desktop` generation to127.0.0.1:14500 in its own namespace, and Colibri `colibri-main` to127.0.0.1:8000 only in its namespace. These are installer target selections, not upstream authentication guarantees. Colibri pinned quickstart documents local OpenAI `/v1` and Anthropic HTTP interfaces; do not expose dashboard or claim built-in auth. Xpra pinned seamless/network docs support application mode and TCP/WebSocket; retain all actual raw-protocol forbidden-operation controls.

Preferred transport is a bounded typed stream handle/proxy over a caller-specific protected Unix socket, with fixed HTTP method/path and native WS binary protocol selection. An SCM_RIGHTS connected socket is allowed only if its recipient cannot reroute it and a trusted supervisor retains actual shutdown authority, byte/resource bounds and independent expiry/cancellation enforcement demonstrated across duplicate descriptors. Never hand over unbounded network authority or assume closing one duplicate revokes all descriptors. Maintain watchdog-owned lifetime, previous Access lease during renewal, bidirectional shutdown/reap on expiry/logout/cancel, bounded queued operations and no late grant use. Access JWT/issuer/audience/Origin/current verifier policy and lease are checked by gateway before connector admission and each protected relay/renewal; HI connector is additional host custody, never replacement for RP04 timing.

Other memory/MCP services are not implicitly added to this target catalog. Each reviewed service needs fixed protocol endpoints, authenticated principal/resource scopes, sanitized environment, no lazy installs, exact compatibility and lifecycle enrollment. Missing connector or unsupported native confinement leaves only that capability unavailable with exact secure resume. Preserve existing data/services and no external target enrollment.

## Native source-context and distinct ownership enrollment

Follow plans/amendments/2026-10-09-native-context-enrollment-v1.md and planning/native-host-service-contract.json. Caller journal root is distinct from host-resolved serviceUID home/work/data. Native per-request context is issued from actual authenticated source/effect bytes and full parent closure by protected broker; process-start envelope or plugin args is not source authority. Reviewed native boundary overlay must cover primary/aux/title/tools/memory/retry/background/children, with complete finalpayload receipt binding before fixed effects. Missing native wiring remains open, not default-deny completion.

## Fixed inspection and connector wire

HI10 operation process.inspect uses capability hermes-process-control, target <enrolled-profile-id>:inspect and exact payload schema1/process_id/generation. Root resolves only its current registered process handle, fixed unit and cgroup; enumerates actual cgroup descendants and attests stable PIDFD/starttime/executable device/inode/digest, parent lineage, UID and fixed sandbox evidence. No client physical PID/path/argv proof. Bound count/response/observation lease, reject incomplete inaccessible/changed processes, and preserve no environment/secrets output. MainPID-only inspection cannot prove renderer ancestry or relaunch protection. Actual graphical ARM64 evidence must test relaunch/window/sandbox conditions before native remote acceptance.

HI07 uses connector.open with capability hermes-service-connect and exact enrolled target xpra-native or colibri-main; approved route/action/generation/context/session/deadline are canonical grant payload. Response schema1 opaque connector_id/generation/expires_monotonic/max_frame_bytes/remaining_byte_budget, fixed read/write/close methods. Every method is peer/context/session bound, sequenced, protocol/byte/deadline bounded; root retains watchdog and bidirectional cancellation. Response is not arbitrary socket/URL authority. Protected handlers/rules/catalog must be installed explicitly; naming a wire does not establish implementation.

## Two-process native source bridge (HI11)

Use planning/native-cross-process-bridge-contract.json. Actual topology has separate enrolled Hermes producer and gateway; source.capture receipts bound to producer SO_PEERCRED cannot simply become gateway context inputs. Producer prepare_native_event/native.event.prepare accepts only schema1/source receipt handles/purpose/intent/trace/retry. Root authenticates actual producer, observes complete captured bytes/closure and derives normalized final body with protected canonicalizer; selected gateway enrollment comes solely from root profile policy. Caller cannot select role/destination/PID or public sensitivity.

Root retains opaque handle state bound to both current PIDFD/starttime/exe digest/enrollment/profile/generation identities, exact normalized digest/canonicalizer, complete receipts, fixed operation/target/recipient/retry and original minimum lease. Gateway dispatch_native_request/native.request.dispatch supplies only schema1/opaque handle/normalized payload/retry. Single root RPC authenticates gateway peer, atomically reserves one use, revalidates all bindings/current policy/account/budget, internally issues context+one-use grant and invokes the fixed provider.dispatch handler. Header conveys only opaque lookup reference; no portable effect grant, credential or worker classification. No worker-selected network destination.

Replay/concurrent use, PID/generation/executable change, digest/canonicalizer mismatch, dropped private parent and expired/revoked state deny before bytes. Failed effect never restores a consumed admission. Retry needs newly prepared bridge/fresh authorization with original complete provenance; retained ancestry is not repeat effect permission. Watchdog cancels active output/egress at original lease/revocation. Primary/aux/title/tools/memory/background/schedules/children remain mandatory coverage; two-process positive native flow and hostile negatives are separate from fixtures. Existing HI08 private/unknown defaults and all original provider/18AC scope stay unchanged/open.

## Full request capture clarification

HI11 prepare_native_event signature is prepare_native_event(payload:bytes, *, parent_receipt_handles=(), purpose,intent_id,trace_id,retry_index=0). Root directly observes exact complete SDK request envelope, not only messages. Existing source.capture receipt remains bounded immutable ancestry; its retention is not reusable effect permission. New prepare captures exact new attempt and joins full parents, then protected same canonicalizer derives expected final provider body. Gateway dispatch_native_request(handle,normalized_payload:bytes,retry_index=0) compares exact digest under authenticated fixed gateway peer and atomically performs effect. Missing model/tool/stream/request fields or normalization mismatch cannot be repaired by caller claims. Each retry needs a newly captured complete envelope and fresh bridge/root retry admission; no old bridge reuse or source ancestry deletion. Actual paired PID/exe/UID/generation values must be enrolled from observed host artifacts, not fabricated in planning.

## Exact operation rule index (HI12)

Protected rule lookup is (capability,operation,target), never only capability/target. Every context/effect admission intersects exact allowed operation and signed canonical payload/generation/recipient/retry/nonce/deadline. Same target may have distinct exact singleton-operation rules; duplicates/ambiguity/implicit wildcard or legacy pair fallback fail closed. Legacy rule migration may explicitly enroll its already-stated singleton operation and new policy revision; never infer extra verbs. Old grants invalidate on revision change.

HI07 exact operations connector.open/read/write/close all use hermes-service-connect plus same canonical enrolled target_id. Frames bind owned connectorID/generation/session/sequence/route plus requested read bound or exact write bytes/hash, remaining bytebudget and deadline; fresh one-use grant for every operation, no reusable open grant. Root original admission lease/resource limits remain hard ceiling, not renewed by later frame grants. Root watchdog expiry/revocation and authenticated owner cancellation close both directions independently of obtaining fresh authority; expired grant cannot keep a stream alive. Cross-owner/sibling close denied. Actual finite stream behavior and operation-switch/replay/duplicate/legacy/digest/deadline negatives are needed beyond rule-key fixtures.

## Protected native enrollment proof fields

HI10 protected Desktop enrollment requires actual immutable app manifest and renderer role/exe/tree digests, sandbox policy, relaunch monitor artifact/digest and window-denial patch artifact/digest. Missing installed value is incomplete; planning never invents a binary or patch SHA. Renderer flags/kernel namespace/seccomp/parent lineage and actual relaunch/window control observations must come from root inspector, not caller booleans. Role-specific browser/renderer/helper expectations are pinned; mainPID-only flags/seccomp do not prove renderer sandbox. sandbox_attestation schema1 fields and invalidation rules are in native-host-service-contract.json. New process/member/exe/generation/monitor/patch change invalidates exposure until fresh complete proof; preserve original actual native negative probes.

HI11 authority.json may contain strict native_bridges list with id,producer_profile_id,gateway_profile_id,canonicalizer_artifact_id,canonicalizer_sha256,approved_operation. Root joins principals/process_profiles for actual protected roles/UID/exe/profile and provider_enrollments for exact selected effect target/recipient/model/account; current peer PIDFD/starttime/cgroup/generation comes from trusted live process registry. Unique exact producer/operation mapping; duplicate/missing/ambiguous joins or absent immutable canonicalizer digest deny. Config lists no arbitrary process/URL/role supplied by worker. Complete request capture and same protected canonicalizer semantics from v2 stay required.

Protected native composition clarification: plans/amendments/2026-10-09-native-package-binding-v1.md, planning/native-package-binding-contract.json and native-cross-process-bridge-contract.json define root-selected immutable package/resolver, observed source channels and shared route normalization. Existing HI-T08/09/11, RB-T09 and PR-F03/PR-T01 remain open; no caller provenance or late payload mutation.

Native resolver reader v2: planning/native-package-binding-contract.json and plans/amendments/2026-10-09-native-resolver-reader-v2.md define peer-bound path-free immutable reader and presentation-only resolver; root re-resolves every effect. Existing HI-T08/09/RB-T09 remain open; document facade schemas retain actual tool/device/native evidence gates.

Fixed recipe/session clarification: plans/amendments/2026-10-09-fixed-operation-recipes-voice-sessions-v1.md defines selection-only operation_recipes and bounded root-observed voice sessions. Existing HI-T09/HW-T03/RB-T09 remain open; no caller shell/device/session authorization claims.

Native protected config v3: plans/amendments/2026-10-09-native-protected-config-v3.md specifies strict native-packages.json package/issuer joins and separate canonical normalization-policy/module hashes. Existing HI08/09/11/RB08/provider tasks remain open; config presence is not actual observer/native evidence.

Operation parameter grammar v2: plans/amendments/2026-10-09-operation-parameter-grammar-v2.md and native-package-binding-contract.json define exact root scalar schema catalog and argv token grammar; recipe ID distinct from process.start and full digest bound. Existing tasks remain open.

Selected binding/memory recipes v4: plans/amendments/2026-10-09-selected-native-binding-memory-recipes-v4.md defines root no-argument peer-selected package and fixed compound route steps with fresh child grants, no caller path/provenance or reused outer grant. Existing HI-T08/09/SK-T01 remain open.

Canonical native digest v4: plans/amendments/2026-10-09-native-canonical-digests-v4.md defines exact hash preimages/encoding and separates document/module/archive identities; existing HI08/09/11 tasks remain open.

Memory compound wire v5: plans/amendments/2026-10-09-memory-compound-wire-v5.md and memory-service-connector-contract.json specify canonical body envelope/root serializer/stateful finite steps; no worker HTTPframe/scope/step authority and fresh grants each step. Existing tasks remain open.

Root-observed remote session bridge HI13: plans/amendments/2026-10-09-remote-root-session-bridge-v1.md and planning/remote-root-session-bridge-contract.json specify actual JWT/current policy/root principal binding, no gateway selfsigned claim substitute, fixed allbytes connector lease and active revocation. Management/read/tunnel credential separation preserved; native/account evidence open.

Closed memory/model recipe identities v6: plans/amendments/2026-10-09-closed-memory-model-recipe-ids-v6.md and protected contract JSON define finite schema/recipe IDs, empty model launch parameters and root-owned forced scope. Actual serializer/result/ARM64 effect evidence remains pending, existing tasks open.

Device/profile generation join v2: plans/amendments/2026-10-09-device-profile-generation-join-v2.md defines independent exact epochs and protected expected_device_generation join. ExistingHI09/HW02 evidence remains open.

Root-observed source wire v5: plans/amendments/2026-10-09-root-observed-source-wire-v5.md and native-package-binding-contract.json define root-private observed capture/event joins and peer/cryptographic/replay bounds. ExistingHI-T08/09/11remainopen, no worker issuer labels.

HI13 remote root wire v2: plans/amendments/2026-10-09-remote-root-session-wire-v2.md defines typed opaque responses/challenge/rootselectedconnectorframes, distinct one-shotasset/leasedWS, internal freshHI12grant enforcement. ExistingHI-T13/RT-F03 and actualtarget evidence remainopen.

Protected runtime assembly v1: plans/amendments/2026-10-09-protected-runtime-assembly-v1.md and planning/protected-runtime-assembly-contract.json define rootactivegeneration catalog, exact native closure/import/mount, devicekernelpolicy, dynamicbuild outputreceipt and fullcanonical effectdigest/rootpeeridentity. ExistingHI07/08/09/11/13/HW02/03 tasks/evidence remainopen.

Active source/package/build consistency v2: plans/amendments/2026-10-09-active-source-package-build-consistency-v2.md reconciles source_issuers in active generation, selected build RPC, binder closuredigest and prebuildselection/postbuildactivated package manifest. ExistingHI08/09/HW01/03tasksremainopen.

Hermes/resource selection v3: plans/amendments/2026-10-09-hermes-bootstrap-resource-job-selection-v3.md defines fixed stage/health recipes and activegeneration resourcejob/DAG/source/backend joins; BD-F03/LC-F03/LC-F04/HI-T09/RB-T08 tasks and nativeevidence remainopen.

Remote dual-principal issuer/closure proof v3: plans/amendments/2026-10-09-remote-dual-principal-issuer-closure-proof-v3.md binds activeenrollment OTP/principal/gateway records, dedicatedroot perframeissuer withoutcontextrelabel, isolatedverifierclient, actualtoken/origin receipts and loadedclosure proofs. ExistingHI08/09/11/13/RP/RTtasksremainopen.

Native manifest digest domains v4: plans/amendments/2026-10-09-native-manifest-digest-domains-v4.md distinguishes binderentrypointSHA/fixedmanifest.json+closure layout from source ResourceIdentity/resolver hashes. Existingtasksremainopen.

Protected lifecycle control v1: plans/amendments/2026-10-09-protected-lifecycle-control-v1.md defines exactrootprovision/currentintent/firstsnapshot/CASrecovery, finiteprocess.control facade andactualloadedclosureprooflimits. ExistingBD/LC/HI tasksremainopen.

Resource backend/remote role v4: plans/amendments/2026-10-09-resource-backend-remote-role-v4.md defines activeRB07 selectedbackend/bodyrecipe joins/freshchildeffects andexplicitHI13profile-role plusactualrootlaunchproof. ExistingRB-T08/HI-T13remainopen.

Additive root-state/build-mount refinement (HI09 / HI-T09 / HI12 / HI-T12): see plans/amendments/2026-10-09-root-memory-state-build-mounts-v1.md; selected protected mount nodes and separate UID0 authority journal state are mandatory. Original scope and pending target acceptance unchanged.

Resource DAG/remote setup joins v5 (HI08/09/12/13 / HI-T08/09/12/13): see plans/amendments/2026-10-09-resource-dag-remote-setup-joins-v5.md and the live resource/native/assembly/remote contracts. Per-node protected joins and root-observed provenance are mandatory; existing implementation and target acceptance remain open.

Native observed invocation context v6: plans/amendments/2026-10-09-native-observed-invocation-context-v6.md and planning/native-package-binding-contract.json define exact root response/call handles and begin/ancestry DTOs; existing HI-T08/09/11/RB-T09/provider tasks remain open.

Resource profile execution v6: plans/amendments/2026-10-09-resource-profile-task-execution-v6.md and planning/protected-resource-job-contract.json bind each task backend to existing protected process recipe/native package with fresh child process.start. Existing RB-T08/HI-T09 remain open.

Full Hermes source archive v2: plans/amendments/2026-10-09-full-hermes-source-archive-pin-v2.md and planning/protected-artifact-source-catalog.json pin complete official source/archive/export identity. Source staging is separate from runtime/install/native acceptance; existing BD/HI tasks stay open.

Build service/bootstrap provenance v7: plans/amendments/2026-10-09-build-service-bootstrap-record-provenance-v7.md defines exact dedicated build profile join and root-selected identity versus actual runtime receipt provenance. Existing HI/HW/BD/LC tasks remain open.

Root setup/journal selection v8: plans/amendments/2026-10-09-root-setup-session-journal-catalog-v8.md specifies installed root-local initial session/intent/receipt transport and active root journal catalog. Existing HI/BD/LC/SK tasks and target evidence remain open.

Native observer/delivery/composite v9: plans/amendments/2026-10-09-native-observer-delivery-composite-v9.md defines exact adapter issuer joins, root-issued response lookup transport and strict outer→root finite child workflows. Existing HI/PR/RB tasks remain open.

Voice immutable workflow artifacts v10: plans/amendments/2026-10-09-voice-workflow-artifacts-v10.md and its JSON artifacts define exact selected recipes/action/schema/hash; actual root engine/primitive/native acceptance remains pending.

Private origin probe connector v11: plans/amendments/2026-10-09-private-origin-probe-connector-v11.md defines separate root-private typed issuer/consumer using exact existing HI12 payload/operation authority. Public RemoteSessionBinding/Access path unchanged; all HI13/remote target tasks remain open.

### v11 protocol refinement

HI-T08 / HI-T09: use planning/protected-runtime-assembly-contract.json native_custody_proof_protocol; immutable mount metadata alone cannot establish readiness, source provenance or action success. Existing task IDs and unchecked acceptance states are preserved.

### v12 loader progress framing

HI-T08/HI-T09 use native_custody_proof_protocol.progress_wire in planning/protected-runtime-assembly-contract.json; concrete root receiver and actual selected loader observations are required. Acceptance remains unchecked.

### v13 private probe joins

HI-T12/HI-T13 use private_origin_probe.connector_authority principal_join, sequence_domains and per_action_probe in planning/remote-root-session-bridge-contract.json; current protected native principal and immutable root child handles are mandatory. Acceptance remains pending.

### v16 installed input closure joins

Use the exact installed_selection_catalog.release_root, task_runner_protocol.source_resolver and native-package-binding-contract.json initial_native_input_observer joins. Existing BD/HI/RB tasks and acceptance remain pending.

### v17 supported loader and task controller

Use assembly native_custody_proof_protocol.systemd_transport/pending_pair_selector and resource task_runner_protocol.neutral_types/controller_source_split/root_event_context. Existing HI/RB tasks remain open; actual kernel effects required.

### v19 setup store and probe DTO

Use installed_selection_catalog artifact_catalog/artifact_store joins, root task canonical payload bytes and gateway_probe_response exact envelope. Existing BD/HI/RB tasks remain pending.

### v20 exact root peer/controller DTOs

Use pending_pair_DTO and task_runner_protocol.RootTaskController exact records/role mapping/PIDFD ownership. Existing HI/RB tasks remain pending.

### v23 root resource controller enrollment

Use active resource_controller_roles and root_controller_role_catalog exact actual daemon/module/source/backend/operation joins; current handler module SHA and stricter effective result bounds apply. HI/RB tasks remain pending.

### v24 native MCP handler binding

MC-F01/MC-F02 and HI-T04/08/09 use native-package-binding-contract.json native_mcp_dispatch exact source-backed in-process hook/catalog/RPC/result joins. All original native/account acceptance remains pending.

### v25 MCP lexical/config mapping

Use native_mcp_dispatch row_types/invocation_mapping/native_config exact records, same one-use lexical binding and root-backed native candidate registration. MC/HI acceptance remains pending.

### v29 native task and credential joins

Use separate result generation_api domains, task_runner_protocol.native_execution_receipt and backend_enrollments.credential_bindings exact active joins. Existing HI/RB tasks remain pending.

Root-selected lifecycle authority v80: `plans/amendments/2026-10-10-root-selected-service-lifecycle-authority-v80.md`; existing HI/RT/SK tasks open, separate actual controller and selected subject proof required.

Native registration projection v99: `plans/amendments/2026-10-10-native-registration-projection-v99.md`; exact source registration/selector/local-family coverage required; existing implementation and acceptance tasks remain open.

Private input recipient consent v100: `plans/amendments/2026-10-10-private-input-recipient-consent-v100.md`; actual root observed private-route choice/current input binding/epoch required, no capture-consent substitution; existing implementation/acceptance gates open.

Verified Xpra source pin v101: `plans/amendments/2026-10-10-xpra-verified-source-pin-v101.md`; exact source tree/finite links/actual transform and runtime proof required; no source-only acceptance or missing native-family waiver. Existing tasks open.

Selected runtime/profile currentness v102: `plans/amendments/2026-10-10-selected-runtime-profile-currentness-v102.md`; actual independent Resources choice/PM journal root/current consent and recipe-bound application limits; existing implementation/acceptance tasks open.

Private loopback host tool pins v103: `plans/amendments/2026-10-10-private-loopback-host-tool-pins-v103.md`; finite actual package/executable/dependency/namespace proof, no source-only or target acceptance; existing tasks remain open.

Application owned execution receipts v104: `plans/amendments/2026-10-10-application-owned-execution-receipts-v104.md`; actual distinct selected grant/controller/probe/manager terminal/artifact result producer required, no ResourceTask/RuntimeReview substitutes; existing implementation/acceptance tasks open.

Host tool observation v105: `plans/amendments/2026-10-10-host-tool-observation-v105.md`; finite network-owned host package producer, actual held installed dependency closure/currentness, no Coral receipt substitute. Existing implementation and acceptance tasks remain open.

Xpra managed transform v106: `plans/amendments/2026-10-10-xpra-managed-transform-v106.md`; finite managed target and actual PM/module/source/terminal/CAS receipts required. Existing HI-T09/HI-T13 implementation and acceptance remain open.

Xpra regular source build pin v109: `plans/amendments/2026-10-10-xpra-regular-source-build-pin-v109.md`; exact module/source topology, file builder root and data output role. Existing managed proof/acceptance tasks open.

Native local result bounds v110: `plans/amendments/2026-10-10-native-local-result-bounds-v110.md`; actual eight local schemas/recursive transport budget and unchanged protected result gates, no all18 omission. Implementation/acceptance tasks remain open.

Xpra link target source pin v111: `plans/amendments/2026-10-10-xpra-link-target-source-pin-v111.md`; final committed module and exact five link target byte hashes/sizes; managed proof/acceptance still required.

Native local schema artifacts v112: `plans/amendments/2026-10-10-native-local-schema-artifacts-v112.md`; eight literal source schema IDs/hashes and actual packaged receipt/validator/generation join. Existing all18 implementation/acceptance tasks remain open.

Protected native registration records v113: `plans/amendments/2026-10-10-protected-native-registration-records-v113.md`; separate42 registration/61action protected arrays from actual preactive source selections, typed workflows/observers/schemas, bounded backend-data wrappers. Existing HI-T08/HI-T11/HI-T12 and all18 acceptance remain open.

Native schema catalog identities v114: `plans/amendments/2026-10-10-native-schema-catalog-identities-v114.md`; exact eight literal catalog-compatible IDs, sourcebytes unchanged; actual receipt/assembly/acceptance still open.

Prepared build service selection v115: `plans/amendments/2026-10-10-prepared-build-service-selection-v115.md`; source-owned setup-only exact build subject/current NSS/root selection before activeprofile, no fabricated worker. Existing build/setup/acceptance tasks remain open.

Native financial/web bounded results v120: `plans/amendments/2026-10-10-native-financial-web-results-v120.md`; HI-T08/HI-T11 implementation and actual acceptance remain open.

Financial alias source bound v121: `plans/amendments/2026-10-10-financial-alias-source-bound-v121.md`; source128-character alias domain preserved, HI-T120 obligations open.

Native process role association v123: `plans/amendments/2026-10-10-native-process-role-association-v123.md`; actual role/source/loaded observer joins and acceptance remain open.

Web content root receipt v126: `plans/amendments/2026-10-10-web-content-root-receipt-v126.md`; actual bounded captured source/CAS/handler proof required; HI-T08/HI-T11 acceptance open.

Setup selectors/private profile v133: `plans/amendments/2026-10-10-setup-selector-private-profile-v133.md`; persistent root intent versus fresh actual identity/namespace snapshots, genuine v91 source-bound purpose profile choice. No authority lease extension or Resources alias; all AC remain open.

Native process-role delivery v134: `plans/amendments/2026-10-10-native-process-role-delivery-v134.md`; exact manifest role rows/digest and actual loader import observations with independently verified root custody, not adapter inference or catalog-only loaded proof. All AC open.

Initial native policy source v137: `plans/amendments/2026-10-10-native-policy-preparation-source-v137.md`; root TTY setup-owned actual target/effect/role/observer selection feeds first assembly, no active-before-selection, static-source authority or live proof inference. All eighteen obligations/AC remain open.

Public input/web permission v138: `plans/amendments/2026-10-10-public-input-web-permission-v138.md`; actual PUBLIC input plus purpose-specific finite scope permission, zero budget and per-retry currentness; no private consent widening or profile-based classification. All AC remain open.

Web registration source cohort v140: `plans/amendments/2026-10-10-web-registration-source-pin-v140.md`; actual current module pins/receipts and renewed register-call capture, historical source inventory unchanged, all AC open.

Finance registration source cohort v141: `plans/amendments/2026-10-10-finance-registration-source-pin-v141.md`; actual held current module and refreshed finite registration/schema source joins, bounded data distinct account/execution authority; all AC open.

Protected public web scope source v142: `plans/amendments/2026-10-10-protected-public-web-scopes-v142.md`; actual root configuration/source selection projects into nonrecursive active scopes independently of per-input PUBLIC egress permission. All AC open.

Durable setup choice signing v143: `plans/amendments/2026-10-10-durable-setup-choice-signing-v143.md`; actual same-key custody normal-session bridge and held release member source replace nonexistent pre-active AuthorityService. Publisher adoption distinct fresh runtime permissions. All AC open.

Source choice identity/order v146: `plans/amendments/2026-10-10-model-choice-observation-order-v146.md`; actual held root observation, completed TTY/source choice and later model verification, correctly named release digest and canonical public scope source. All AC open.

Concrete bootstrap/source/public disclosure v149: `plans/amendments/2026-10-10-runtime-member-role-public-disclosure-v149.md`; exact runtime member layout, prepared held source distinct live import, genuine per-input public disclosure. All AC open.

Runtime public choice currentness v153: `plans/amendments/2026-10-10-runtime-public-choice-currentness-v153.md`; durable adopted preference/current signed source epoch distinct fresh runtime effect/input proof, no setupTTL extension. All AC open.

Prepared source module layout v154: `plans/amendments/2026-10-10-prepared-source-module-layout-v154.md`; exact source-module members distinct root-imported module and later worker evidence. All AC open.

Runtime choice revocation source v156: `plans/amendments/2026-10-10-runtime-choice-revocation-source-v156.md`; genuine current installed actor/one-use displayed-choice TTY action, no expired setup authority.

Native capture profiles v158: `plans/amendments/2026-10-10-native-capture-profiles-v158.md`; genuine raw root input/result source and exact selected validator/action/role joins, separate presentation evidence.

Root native health start v159: `plans/amendments/2026-10-10-root-native-health-start-v159.md`; actual committed runnable authority then root health admission/control before fixture input, normal enablement withheld.

Installed local qualification v160: `plans/amendments/2026-10-10-installed-local-qualification-v160.md`; finite installed source-owned fixture dispatcher with genuine production actor/receipts and cleanup, distinct Pi acceptance.

Application build admission v161: `plans/amendments/2026-10-10-application-build-admission-v161.md`; finite actual setup managed app profile/input/output/grant and fixed source driver recipe, post-terminal output/probe evidence.

Qualification root adapter v162: `plans/amendments/2026-10-10-qualification-root-adapter-v162.md`; dedicated source-bound held root/publication/session/key namespace, actual core authority validation and untouched production constants.

Health input source delivery v163: `plans/amendments/2026-10-10-health-input-source-delivery-v163.md`; root-resolved PRIVATE fixture context, actual observer/source membership and distinct write/EOF/one-use take; no task-origin substitution.

Qualification envelope v164: `plans/amendments/2026-10-10-qualification-envelope-v164.md`; exact scoped envelope/generation/pointer/session bytes verified through held run-root FD and unchanged strict core validators.

Runtime role publication join v165: `plans/amendments/2026-10-10-runtime-role-publication-join-v165.md`; typed PM/native CAS closure and single strict atomic activation, fresh runtime committed observation independent expired setup.

Qualification key signer v166: `plans/amendments/2026-10-10-qualification-key-signer-v166.md`; genuine held key signs only exact fixture enrollment envelope before service adoption.

Qualification session storage v167: `plans/amendments/2026-10-10-qualification-session-storage-v167.md`; live session sealed/current only, retained file historical metadata without signature or authority.

Application Python entrypoint relocation v168: `plans/amendments/2026-10-10-application-python-entrypoint-relocation-v168.md`; exact held PM interpreter and finite source script normalization bound final observed tree, no ambient PATH.

Native precompile reservation v169: `plans/amendments/2026-10-10-native-precompile-reservation-v169.md`; source-backed preactive output authorization and same reservation through strict compilation/atomic publication.

Native output role correction v170: `plans/amendments/2026-10-10-native-output-role-correction-v170.md`; exact existing native-boundary-overlay/boundary-overlay, no alias or new role.

MCP discovery capture v171: `plans/amendments/2026-10-10-mcp-discovery-capture-v171.md`; genuine retained tools/list witness distinct selected tools/call result schema.
