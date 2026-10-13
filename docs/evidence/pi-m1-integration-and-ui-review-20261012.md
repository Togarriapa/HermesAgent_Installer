# M1 integration qualification and UI review

Change: `jarvis-core-platform`; R0090/R0200/R0201/R0203,
BD-T266.1/RT-T266.3/RB-T266.4/VD-T266.5. Reviewer: Root with Sol specification
and Luna implementation, 2026-10-12, Europe/Lisbon.

This record distinguishes source validation, controlled Pi fixtures, visual
review and production acceptance. All eight acceptance groups remain open.
The production source remains `0cbf9b819a6be41b3ff34d623374355cb64c3834`;
no new candidate was deployed during these checks. A fresh Root system-Python
check found aiohttp available and all four owned Core/Inspector/gateway/tunnel
units active. Process health does not prove usable chat.

## Executed checks and remaining qualification

| Candidate / archive | Actual Pi result |
| --- | --- |
| `6c7be1fd5ea285020528177c3dacbc475970df2a`, v36 | 10 failed, 115 passed, 7 skipped; strict specs/plan passed. |
| `c6b8675fda00a972ac42b767cec90e2b0be00798`, v37 | Source compilation stopped at a displaced child-authorization method body; tests did not run. |
| `d40390c2b2c90c86114c9754477aa64f6d7025bc`, v38 | Source compilation and strict specs/plan passed; test collection stopped at a malformed fixture `try` block. |
| `def9b1777b66b7fe42f1a3e9b3f668c1e6167a5b`, v39 | Source/tools/tests compilation and strict specs/plan passed; Root suite 24 failed, 234 passed, 5 errors. Root execution exercised cases previously skipped under admin. |
| `2dbdacc05538f9a48fbb693982db498558e2973d`, v40 | Source/tools/tests compilation and strict specs/plan passed. Specification validation only; runtime tests were not repeated. |
| `840343f7a4b762d61b5fad44af90fe1aa50babb3`, v41 | Compilation and strict specs/plan passed. Root effect subset 9 failed, 100 passed; generated guards actually ran as admin in isolated mount namespaces. |
| `07c8539628a10c7855101e2977f937c03b47f9a3`, v42 | Source/tools/tests compilation and strict specs/plan passed. Specification validation only. |
| `bf3fdfd98ae3ed3aebae2de9adaaff880b82dad7`, v44 | Compilation and strict specs/plan passed; Root suite 17 failed, 261 passed. Archive SHA-256 `e4ce6b9f6c8ad0afc2e5f9c0c80ed69e896449e47f9376bca5f406eacdfc56d6`. |
| `abf0296fb928e679843816b8ad0c936da1c8e6e1`, v45 | Compilation and strict specs/plan passed; Root private-mount suite 17 failed, 261 passed. Archive SHA-256 `72853ba5b0d9f43aab29c46b37769f18563e9d3dab30649c8ea36fc9b26bebc5`. |
| `12ab8ace214fe4b7eaca5e39d78b4e53122bd51c`, v46 | Strict specs/plan passed; focused retry 11 failed, 6 passed, 115 deselected. Archive SHA-256 `0f36184bcb73dab78e3822c0bfbde5bfe31a22c715f025297b105d9962ea55f2`. |
| `9c0ddfd9a90c7d1277e7fce58899a15b55cef3da`, v48 | Compilation stopped at a missing fixture brace; tests did not run. |
| `80171d46f1af9b8cd291742485eb9e367dc89fc6`, v49 | Compilation and strict specs/plan passed; Root suite 9 failed, 292 passed. Archive SHA-256 `cf1c64d052b529b499d89bb66ee17b1baba0e40bb5b2f02eedf2bd4e83de2413`. |
| `9bf2e67e0ebee5a340b5705a1802c1faa5d261a6`, v50 | Compilation and strict specs/plan passed; focused Root suite 3 failed, 53 passed. Actual Root-to-runuser importer effects and the Mission ownership/concurrency case passed. Staging only; live services remained unchanged. Archive SHA-256 `f0385330da41dffb9274a72a04f51e6cc0e5e34f43dc8d4d69184ec2576b248c`. |
| `1cb2bbb09ec0070e933a7664449f65801454ad3f`, v52 | Compilation, strict specs/plan and all 56 focused Root checks passed in 410.05s. Corrections retain actual importer effects and protected custody checks. Archive SHA-256 `3a6b6d319f3eabf7ebc93f2b59bce0b704f32966295a9975c98395219ce7dcc8`. |
| `6b4dd2b87412ae5efbce691fb18cf75a0836de37`, v53 | Compilation and strict specs/plan passed; gateway/JWT suite 3 failed, 36 passed. One new fixture used its accepted proof before assignment; two app-composition tests exposed an exact-versus-normalized shared-route comparison bug. |
| `6d4bd9be7d63bc73ce6ac6d7953279b4aa696f9e`, v55 | Compilation, strict specs/plan and all 43 gateway/JWT/Mission-route checks passed in 1.40s. Includes bounded household admission and the exact shared-route repair. Archive SHA-256 `ebf183238ab9e488acc03de7ee1abcc26621b1ee62d31e995ff4eed855b0dad0`. |
| `bf5bbf83c7969096b8167e5cf6fdcb2d2abf8030`, v56 | Compilation and strict specs/plan passed; adoption/gateway suite 6 failed, 86 passed. Existing effect fixtures needed the new source-switch keyword; static review separately found a missing final original-file CAS and pre-effect rollback classification. Staging only. |
| `9429c2b2ec152dc6edae1be35c30ab703feb3b18`, v59 | Compilation, strict specs/plan and all 99 adoption/gateway/JWT/Mission-route checks passed in 1.77s. Source review concurs on exact pre-backup/pre-stop CAS and no service effects for pre-stop byte, ownership or protected-read conflicts; post-effect rollback remains unchanged. Archive SHA-256 `683eb63424338d62f198a1dc3780ed07454769bda8780f19647e06bc160b501c`. Staging only. |
| `5bf3eda11fb66ea12f2b7567f0723465a88b000e`, v61 | Compilation and strict specs/plan passed. First effect group: 12 failed, 93 passed. Independent recovery retry: 1 failed, 11 passed. An earlier recovery selection matched no tests (exit5); it proves no recovery behavior. Failures identified obsolete reader/argv/partial-phase fixtures; source review separately found an absent prior-cohort and historical-vault-digest rollback edge. No live deployment. |
| `6e6e035d81e5b67525c4bc0fdc88ae2f36ebc7ea`, v62 | Compilation and strict specs/plan passed. Actual Pi effect group: 107 passed in12.44s; independent committed/interrupted recovery group: 12 passed in0.07s. The narrow fixes preserve actual argv/reader boundaries, all-null joins before Core return, no qualification replay during rollback, exact optional prior-cohort bytes and latest captured vault state. Archive SHA-256 `4ecaf5214ba3693328cc320f1e16dded71eb80bf993589ceec64ee70bac93833`. Production acceptance remains separate. |
| `d1322d74fdfc0f65e057c0488ce7f607228ea7f5`, v63 | Compilation and strict specs/plan passed for the Sol completed-snapshot handoff refinement. Runtime tests were not repeated for this specification-only candidate. Archive SHA-256 `c4522c82ccde75d8819c88ba986383d4037ba789a82198282e46b2ad1ef610af`. |
| `4737aa51904083fd2ed014febace8b5959e11bfe`, v64 | Compilation and strict specs/plan passed; first effect group2 failed/109 passed in13.05s, independent recovery12 passed. The closed-key reader rejected normalized records; review also found missing history-directory custody checks. No target deployment. Archive SHA-256 `b8d5718f8263daf453363d278b5bfffaea989e96b672c82eae218a2242da25ba`. |
| `1e45ba2eb4ab1c9d5c1e650fd3635562de3d9144`, v65 | Compilation and strict specs/plan passed; first effect group1 failed/112 passed in12.70s, independent recovery12 passed. Positive atomic succession exposed an incomplete prepared writer schema before its later runtime-hash setter. The correction initializes the nullable field before durable replacement; strict readers remain unchanged. No target deployment. Archive SHA-256 `b2c12632d25a599e3eb98196706a5b9855a0e49613ae30c06a9928885a03e493`. |
| `98c695b2360c818c758e2f6100b9167ca3ed251b`, v66 | Compilation and strict specs/plan passed. First effect group113 passed in12.56s; independent recovery12 passed in0.07s. Includes complete prepared-record round-trip, archived predecessor verification, filesystem succession/CAS/conflict checks and replaced history-directory refusal. Sol review concurs on the narrow schema/custody/writer fixes. Archive SHA-256 `e686add0f9fbf025a5bec3fdf0a65c4e88c7af160fd6fdcfb97dac60893e8fcd`. Live qualification remains separate. |
| `27b51cb11fc3af98438c8d7b46139d610b690455`, v67 | Compilation and strict specs/plan passed; diagnostic/adoption/gateway group141 passed in12.50s, independent recovery12 passed. Source review caught a real production snapshot-shape gap despite these fixture passes: optional missing digests use the exact `absent` sentinel. No live deployment. Archive SHA-256 `0949022ef48ce265182329be8f7958ba55011de27bc6f7b8e9e9b4e725f9734f`. |
| `61b9725c1c04da9b85ff029ce23a737a9b0cc71a`, v68 | Compilation and strict specs/plan passed; diagnostic/adoption/gateway group143 passed in13.13s, independent recovery12 passed in0.07s. Includes exact production absent-state round-trip and malformed/foreign/source-path refusal; trace metadata excludes exception messages, arguments and locals. Sol review concurs with the finite sentinel fix. Archive SHA-256 `c899d940dc7bbbbeffabd09ff88881f8bac3ecea86e439e5d2062b91abc3a501`. Live diagnosis and acceptance remain separate. |

Logs and status JSON are under
`/var/tmp/hermes-jarvis-core-checks-20261011/` on the identified Pi. OpenSpec
reported `spec-driven`, `ready`, eight total/zero complete/eight remaining;
no archive or canonical runtime acceptance was performed.

The v70 integrated candidate `14dffcaabec8f22f9e16c33714713a33bbaae508`
compiled on the Pi and passed strict specs/plan validation. The gateway,
adopter, qualifier, initial-primary and bootstrap group had3 failures and152
passes; the expanded Core update/recovery group had4 failures and14 passes.
Archive SHA-256
`724d8b66276832506da3864732cb946510a71d7d6d7722cfd891858b162c5bd8`.
The real Core-to-bootstrap prepare scope and0644/0664 source custody checks
passed. Source review separately found an adopter reference reader still
limited to9 members; transition backups contain exactly11. The candidate is
not admitted for staging/apply until the conditional consumer and all failed
checks are repaired and verified. Production remains on the old source.

The v71 candidate `b615af1a213500b1538bb56a5ddb8b04c1e6e757` compiled
on the Pi and passed strict specs/plan validation. First group1 failed/155
passed in12.74s; expanded Core group4 failed/14 passed in2.06s. Archive
SHA-256 `499b59357d231a9cb1082b0d933f0c6b3a9557c92e5eed06ede5ba7ec96f5ffa`.
The conditional11-member setter/backup checks and initial-primary repair
passed. The report tamper fixture shared a mutable dictionary with its
comparison field, so its mutation changed both sides; the corrected fixture
retains independent fields and the prior protected-report denial assertion.
Four old Core fixtures now reach the genuine Resources cohort snapshot but
do not supply its required discovery state/source joins. Those positive
cycle fixtures remain pending repair; no production proof is weakened.

The v72 candidate `766e360a81ef30759585993a722185ae0e3756bd` compiled
on the Pi and passed strict specs/plan validation. The first group passed
all156 checks in12.80s; expanded Core group4 failed/14 passed in84.32s.
Archive SHA-256
`3ebd243d8459b65677f22a2f0c1dd355e15ee0164776b40237543d2b645aef13`.
Each failed positive cycle stopped at its missing temporary HOME/SOUL.md.
Source inspection also identified fixed native readback/startup-provider calls
that require explicit fixture providers before those unit paths advance.
They were not reached in this run. Real provider/startup evidence remains
separate from controlled update-ordering and rollback tests.

The v73 candidate `1683aeb4c09b76bfb7225120b3e5499470faa0bf` compiled
on the Pi and passed strict specs/plan validation. First group156 passed
in12.89s; expanded Core group4 failed/14 passed in133.17s. Archive SHA-256
`8bd05cacad1f2dcdf37658f69d59083464a468912adb668260688d4be3c87c75`.
The four fixture failures were genuine recipe refusals: the fixture changed
its HOME/HERMES_HOME after creating the migrated unit, before the protected
active-reader comparison. Sol independently confirmed this ordering issue.
The fixture correction rebuilds its fixed unit/launcher and journal hashes
for the selected isolated home; production recipe validation is retained.

The v74 specification-only candidate
`8f644fffa96e57036c9c750933d98f2d6924fff1` compiled on the Pi and passed
strict specs/plan validation. Archive SHA-256
`078b76551e40b9299026a1b2af61143f59d2a4e7e6a3e8ecbd588ebe06f8a1f3`.
It records official Cloudflare client-session limits without enabling that
beta path, removing binding-cookie protection or enrolling any device.
Renewable device pairing remains unimplemented; browser720h was separately
verified live. Runtime tests were not repeated for this specification leaf.

The v75 candidate `c263d37c97cac6f3edecd79fc5dc8f0a01f69cd2` compiled
on the Pi and passed strict specs/plan validation. First group156 passed
in12.68s; expanded Core group4 failed/14 passed in91.57s. Archive SHA-256
`242a10ff10919be7223f0385b7380c62995eba66c15e3dc20d7c33ca128176d6`.
The fixture still validated the old journal after changing HOME but before
rewriting its recipe. The correction captures that validated record first.

The v76 candidate `4519f8e2ae7dbf1b239ac1e20f30a3c2cbf19ed7` compiled
on the Pi and passed strict specs/plan validation. Only the four changed
full-cycle fixtures were rerun:4 failures in143.94s. Source/tools were
byte-identical to v75, so its156 unchanged checks were not repeated.
Archive SHA-256
`3aaeb464a5ac4fa31c3edf92556783d11f750a1c448700fb174700f21737a4ed`.
The first positive exposed an actual updater bug at CoreRuntime5732:
`_read_transition_archive` returns manifest/files/helper but the caller
unpacked only two values. Other fixtures changed their guarded-unit journal
after rebinding discovery, leaving the recorded ownership hash stale.
The next correction consumes the real triple consistently across Core
initial/update/recovery paths and repairs only those fixture hash joins.
Sol reviewed the exact Core source and one-entry Inspector pin; runtime
qualification remains separate. No production apply followed these failures.

The v77 candidate `708c0ce2ce11f3815b2b79121bf26426aafb8b63` compiled
on the Pi and passed strict specs/plan validation. First group156 passed
in12.94s; expanded Core group4 failed/14 passed in176.79s. Archive SHA-256
`bd0282467491a029f771ff7277b177f1ffdfc059c2e2be014c3f33ac8f35a07e`.
The outer update/recovery wrapper hid the inner failure location. A bounded
test-only probe was added, keeping production failure handling unchanged.

The v78 diagnostic candidate `9fc4661f06d1f71f6aba194f29a421a1416e817a`
compiled and passed strict specs/plan checks; its one selected positive failed
in83.05s. Archive SHA-256
`603d6132d9687ac20a9c12facefc0001a6ca3e060ea18fb8d12cb05a0eaa1194`.
Routine generator exits obscured the probe's final bounded entries. The v79
probe filters those events and follows bounded exception-context metadata,
without messages, locals, arguments or file contents.

The v79 diagnostic candidate `9d6acb46f02f2fbfe8336456f1061ea17f9a1483`
compiled and passed strict specs/plan checks; one selected positive failed
in86.41s. Archive SHA-256
`879e159526ccc2bf137d905335219491f5427d60cf3ff5e18ba2e974d69db399`.
Its exact context found a second actual updater bug: the initial cohort
constructor expanded temporary primary-verification fields into a closed
journal that admits only the primary-record digest. The corrected producer
keeps temporary data in its existing private state and typed initial
transition, with the strict writer unchanged. Sol reviewed that finite
correction and the exact one-entry Core source pin.

The v80 candidate `9fd4e66faf53f328018fa1a853110d59af9a9849` compiled
and passed strict specs/plan validation. First group156 passed in12.89s;
expanded Core group4 failed/14 passed in218.27s. Archive SHA-256
`5b5a929e0986d5dba864185e45a3d0b3615ae0b1948c1e69b2d9fecc21ecdde3`.
The controlled fixture replaced sys.modules entries but left cached remote
package attributes pointing to real bootstrap/Inspector modules. The prepare
step refused before effects. The next fixture correction replaces both
bindings with the same explicit adapters. Real bootstrap filesystem checks
remain separate. No target apply or production acceptance followed these runs.

The v81 candidate `fa85ee40c77fdf5980e6cb0bd48b40fbe515ee34` compiled
on the Pi and passed strict specs/plan validation. The four changed full-cycle
fixtures failed in219.26s. Its source/tools matched v80, whose156 unchanged
checks were not repeated. Archive SHA-256
`d9711f2109d440c9a9cda4612dd28433c9e51651c02703d55b2b5945600943b0`.
The bounded context identified an actual prepared-transition constructor
error: omitted home role and an undeclared private prompt field. Its failed
recovery also left a pending primary transition outside the required rollback
phase. Both finite corrections were source-reviewed before v82.

The v82 candidate `90413cc75af19a09968f4dda0e22cba69c772aa0` compiled
and passed strict specs/plan validation; first group156 passed and expanded
Core group4 failed/14 passed in219.57s. Archive SHA-256
`e7f1002065ee5c0e0588a7e9aebf969685f6ef27ba69dd0637ef4087a02dee6c`.
The importer recheck found an obsolete fixture `_identity` keyword signature.
Recovery then exposed the strict reader's missing entirely-unwritten rollback
case: no progress or owner backup existed before profile writing. The proposed
correction accepts only all-null progress/backup with absent primary ownership,
and separately proves exact original SOUL bytes/signature under the stopped
cohort. Written/partly recorded states keep mandatory immutable backups.
Sol also found two actual later startup mismatches before another target run:
stale/out-of-scope journal read after initial adoption, and absent new-read
custody in startup context. Those were corrected without relaxing admission.
All subsequent checks and production acceptance remain pending.

The v69 specification-only candidate
`6b4621209a11895ce9f7894013ce034e1bdb3b05` compiled on the Pi and passed
strict specs/plan validation. Archive SHA-256
`909b867f3d89acffbc84e88d47a5f840f6448afadd8b1741435208404ed605ae`.
It defines the fixed two-file native plugin generation transition; no runtime
test or target deployment was repeated for that specification leaf.

The staged v68 actual target apply returned4 and restored the prior Core and
ingress. Its protected redacted diagnostic identified `CoreInspectionDenied`
at `verify_staged_native_resources_plugin`, before plugin replacement or Core
source transition. Actual installed `plugin.yaml` matched both source bundles;
installed `__init__.py` matched only the old0cb bundle. Both files were
root:root0444 under the fixed0555 directory. The updater was checking those
old installed bytes against the incoming bundle before replacing them.
The v69 refinement therefore retains old plugin bytes in the existing update
backup and permits replacement only while the captured old Core is stopped.
Fresh recovery readback retained all four old services, the single-address Pi
allowlist and the digest-addressed completed ingress history. This is failure
diagnosis and rollback evidence, not new-source startup or chat acceptance.

The staged v62 target `--apply` returned4 before effects because the fixed ingress
slot already contains the completed current0cb legacy-migration backup. Its
strict parser, current Gateway digest, effective runtime Inspector digest and
post-Core configuration digest all verified. Fresh actual old Core binding and
Inspector/socket custody also verified; the held PIDFD was closed after this
read-only check. The original snapshot remained in place. Sol's v63 handoff
contract and subsequent implementation retain exact completed raw bytes in
protected history and atomically replace the slot with a complete successor;
uncertain or changed prior records still refuse before effects. This source
work is separate from a successful live successor update.

The staged v66 actual target apply reached the fixed Root Core qualification
subprocess, returned4 and automatically restored the prior Core and ingress.
Fresh readback verified all four units active on0cb, local allowlist cardinality1,
and no remaining active ingress transaction. The original completed snapshot
is retained byte-for-byte at its digest-addressed history entry
`0297abdbc9d2dcceb25d4d68146d3a2fde79677309468ab957ca0e7f4bd2289c`,
root:root0600. A fresh actual qualification before-snapshot passed. The failed
subprocess report did not expose its exact caught CLI failure location, so
bounded source-location-only diagnostics are being added before further target
qualification. No new Core, primary adoption, provider completion or added-user
login acceptance follows from this recovered attempt.

On2026-10-13, fresh Cloudflare connector GETs verified the exact Jarvis hostname,
both application and allow-policy durations720h, three approved email entries,
and retained HttpOnly/binding-cookie protection. Existing issued tokens retain
their original expiry. This global browser convenience is distinct from native
individually revocable Android/tablet pairing and automatic refresh, which the
current Sol refinement explicitly retains as pending M5 work. A source audit
found no one-hour Access-JWT lifetime cap; the3600-second JWKS cache and bounded
request/turn leases do not define login duration. No physical-device restart,
month-long continuity or native pairing witness is claimed.

The v45 archive retained directory mode0775 and file mode0664. The genuine
immutable-source custody checks correctly refused that group-writable fixture.
v46 removes group/other write bits only from its extracted candidate source
before the private read-only bind. It does not change production validators or
the host's `/opt` view. It also retries corrected journal callback, closed-review
registry and actual activity-store fixtures. Four old updater tests still need
current real systemd/process/source-starting integration witnesses; no fake
PIDFD producer or negative-only replacement qualifies those obligations.

Remote inspection found only `main` and `codex/luna-installer-development`;
parallel work uses private local clones rather than additional remote branches.
Publication checkpoints skip automatically triggered off-Pi CI. The executed
checks in this record run through the authorized Pi browser terminal.

Concrete production corrections include plan/review response verification,
the closed review RPC, preservation of composed owner skill edits during
helper replacement, and restoration of displaced activity recording. Fixture
corrections retain production checks: native UID/GID1000, valid opaque handles,
complete registry state, actual socket context management and required CLI
backup identity. The initial-primary lane now has actual append/readback and
separate offline rollback contracts. The startup observer is Root-CLI-owned on
a fixed separate lifecycle-only socket rather than an inaccessible global in
another process. These source corrections still require actual Pi update,
provider completion, protected public chat and recovery evidence.

The actual v56 read-only live preflight returned a verified active adapter at
`/opt/hermes-installer-core-0cbf9b819/src`, an unmanaged primary prompt and zero
owner skill overlays. The separate legacy reader refused the same installation
with `legacy service unit differs from the fixed owned unit`; its normal native
observer socket already exists. Thus the legacy-only ingress adopter is not the
deployment path for this Pi. A bounded already-adapter cohort refresh must join
the real fixed Core update, exact owned old socket/process cleanup and protected
Inspector/Gateway/config switch. No Core update or ingress mutation was
attempted under the incompatible legacy recipe. The source review/fixtures above
do not close this live deployment gap. Logs: `read-only-core-preflight56.log`
and the browser's read-only migration-lane result. Four live units remained active.

## Full-shell visual review and disposition

Root inspected the actual Pi Chromium contact sheet for candidate
`5fad47196b3e7851e727f36f469beb25858e4219`: Overview, Chats, Projects,
Second Brain, Models, Profiles, Extensions, Calendar and Agent settings at
phone390x844, tablet768x1024 and desktop1440x900. It displays captured JPEGs
from the same controlled run without editing their pixels. Contact SHA-256:
`4fedd2f05cd00b49a74ad68e291afd5ed1edc951b7832d9b43a058b085ccaaad`.
Report SHA-256:
`28fec1aaea94bf738989b528c35a8dda0a3d1e1ae486fd8e45ba480802055661`.
Both are in `affected-flows-parallelcohort35-v19/` on the Pi.

| Review item | Observed result / follow-up |
| --- | --- |
| Placement, purpose and hierarchy | Overview uses the dedicated Jarvis circular presence view; five primary destinations are visible. Secondary resource/control destinations still need the roadmap's usability consolidation. |
| Desktop/tablet/phone reflow | All nine captured views were inspected. No general horizontal overflow was visible in the contact sheet. Small text and lower-fold content need focused full-resolution review. |
| Phone Chat primary journey | Prior blocking issue: history filled the first viewport. Source `78a3a98b18b2e5b093ea042909fb46e01db1f084` makes entry thread-first with a labeled history toggle. Pi v24 passed the entry/drawer/selection/returned-composer interaction. Root inspected the full-resolution drawer and returned-composer JPEGs; the textarea and per-message controls are visible. Real phone keyboard/provider behavior is separate acceptance. |
| Navigation interaction | Correct Work/Resources/System groups and bounded native details/ARIA timing pass in v24. Exact fake-chat messages/model-settings and ecosystem reads are finite fixture responses; unknown methods/routes remain denied. |
| Keyboard/touch, reduced motion and changing service states | Prior controlled probes cover bounded cases; complete focused visual and physical device verification remains pending. Still captures alone do not prove animation or audio. |
| Destructive actions and knowledge retention | Live save/delete/restore and Obsidian preservation were not exercised by this visual review. |
| Capability and authority claims | Synthetic fixture status, graphs and counts prove rendering only. Real native provider/resource/Expert/Team/Obsidian/account effects remain separate acceptance. |

Post-fix v24 uses source `2dbdacc05538f9a48fbb693982db498558e2973d`;
the reviewed static asset source is byte-identical through v55. Its actual
Pi report passes all checks at390x844,768x1024 and1440x900. Report SHA-256
`db3c03c887b904f518b69919bb39dde6fc8cdd56f9cd170634044a7fab6b5629`;
captures/report are in `affected-flows-parallelcohort40-v24/` on the Pi.
It covers synthetic rendering, keyboard/touch geometry, actual sampled motion
and reduced-motion/visibility rules; it does not establish real model, audio,
knowledge or task effects.

Root also inspected the actual v25 Mission contact sheet: unavailable, no-run,
Jarvis-approved, Jarvis-rejected and owner-approval-pending states at all three
sizes. Contact SHA-256 `2a862bb0283682cc339a6571adf5adeb1ddacc540358b44eacb99cacffcad474`.
Its synthetic fixture proves rendering only. The owner controls required a
focused capture. v26 and v27 correctly failed that additional check: v26
captured controls below the viewport; v27 brought both controls into view,
but its bounding-box corner hit tests sampled outside the buttons' rounded
hit areas. v28 preserves full viewport/occlusion checks while sampling each
actual rounded shape; all checks passed at phone/tablet/wide sizes. Report
SHA-256 `f18b666071a98eb6e7cc3aa7c359392ba197bfbaad327b47cafb16f0fc880be8`.
Root inspected the actual focused owner-control JPEGs at each size: both
separately named Approve/Reject controls are visible, the phone stacks them,
and their 44px touch targets remain unobscured. Phone/tablet/wide capture
digests respectively:
`a81b915b3796959c76d4db30d63cd84811a58200cf6ae2f5e7e03f157d6c31f1`,
`d1d5df522e1b56471860c12d2259c335fe8ea7a079e36d4d1caf1d35202e1154`,
`71f543823b8ca2a53b1518908bff0b1a9153ef0fdc672ff5e38c2a13a59fc38a`.
These captures are under `affected-flows-parallelcohort40-v28/`; their static
product assets are unchanged through v55. This satisfies the focused MVP
review for this journey, not actual review/approval effects or the roadmap's
finished design. Verbose status copy and overall navigation consolidation
remain M2 usability work. The v26 Second Brain failure
had no selected note/metadata, so it did not prove a clipping defect. The
same interaction passed in v27. Neither run changed product assets.

Cloudflare's owned Jarvis application and email-code allow policy were read
back with three approved emails and a 720-hour session duration. Cookie
binding, HttpOnly protection, OTP method, hostname/audience and other resources
were retained. Old tokens keep their original expiry. The Pi config still
contains its original single address: the bounded loader now passes signed
principal/ownership/CSRF/currentness tests, but its approved union must be
applied within the retained adoption transaction. No additional-account login
or chat acceptance is claimed. Global extension/vault owner gates remain
separate; a longer token never extends an existing turn or ingress lease.

Disposition: **scoped MVP visual gate satisfied; runtime acceptance pending**.
The phone layout blocker and focused Mission review capture are resolved in
the reviewed candidate. Full parity, real owner/family usage and final UI polish
remain unverified. No
provider, microphone, external messaging, account enrollment or production
mutation occurs in the UI fixture runs. Android/voice/communications research,
all14-image intake and every prior direct request remain in the one current
roadmap; neither this review nor the MVP repair closes that backlog.
