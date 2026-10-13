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

The v83 candidate `e0ffd6bb4782d69a80fbe0ecd47e5e46a9199c9f` compiled
on the Pi and passed strict specs/plan validation; the first group156 passed,
and the expanded Core group4 failed/16 passed in220.20s. Archive SHA-256
`0c5f3baed1d29d0c70c5fc8461827ebc1c2a50da9b19cca6e869291294eb9197`.
One later fixture identity hook still used the old keyword signature. The
real Root recovery path also called an admin-only generation verifier whose
effective-UID check rejected Root. The correction uses the existing bounded
Root descriptor/owner/tree verifier and preserves its exact generation,
marker, member, digest and backup-path checks. Sol reviewed the finite fix.

The v84 candidate `7b9cfd15c0c10ab2efb2e83003db923e672f8e2c` compiled
on the Pi and passed strict specs/plan validation; the unchanged first
group156 passed, and Core group4 failed/16 passed in221.87s. Archive SHA-256
`57638bacfc55dc16dc1a911dca54a236419e6054396ff26ef55893754c095313`.
The genuine root-to-admin importer closed its input before consuming the
framed archives: the fixture's temporary home did not satisfy the importer's
fixed `/home/admin/.hermes` contract. v85 changes only the fixture to bind a
disposable owner tree at that exact path in a recursively private mount
namespace, with checked namespace identity and unmount-before-delete cleanup.
The real Pi home stays outside that namespace. Importer admission is unchanged.
No production update or acceptance is claimed from these failed fixture runs.

The v85 fixture candidate `bd3f3ac46bc50852fe90ee940773f25281816e5e`
compiled and passed strict specs/plan validation on the Pi. Four affected
update cycles failed and two unwritten-primary rollback cases passed in133.63s;
the156 checks with unchanged source/tools were not repeated. Archive SHA-256
`87e5baf924eeaf4f56d82ff955314bee2f312b152b387373ff78907097105b4e`.
The fixed-home bind exposed another fixture leak before the importer: its
registration path override did not redirect the production directory-FD
lookup. It saw the actual Pi registration but no vault in the disposable
home. The explicitly unregistered fixture now isolates that lookup in both
the starting-cohort and actual updater helpers. Sol checked the helper call
sites and corrected the first incomplete test-only patch before another run.
Production registration, importer and vault custody rules remain unchanged;
registered-vault update qualification is separate and still pending.

The v86 test-only candidate `44c4e20943459ba3b99b01d307c8df3fa794e3e8`
compiled and passed strict specs/plan validation on the Pi. Four full cycles
failed and two unwritten-primary rollback cases passed in243.52s. Unchanged
source/tools checks were not repeated. Archive SHA-256
`58bda1b77438550cd4ef8662410bb2572f357c2fa3382f099e5a068eb1b1aaea`.
The genuine importer completed its input pipe, then failed the bounded result
gate. Recovery subsequently rejected the prior ownership marker. A test-only
probe now captures return code/output lengths and exact reviewed constant
refusal messages; raw child output, inputs, credentials and file contents are
not emitted. One affected case is selected before another full rerun.

Separately, read-only live registration/vault preflight using v86 source passed:
fixed owner path, valid root-owned registration, vault UID1000/mode0700.
Registration SHA-256
`0efd4e6bedf799eddd50a5cc41f3c50f716ccc6f8dcf15ba9c1a4b26dd3fef42`;
bounded vault tree SHA-256
`99a15ddd8f0eadcbc48b04958e17b81cc4a2c9301e5ffadd0a04456ded3a7ce5`.
This is before-update custody evidence only; it does not prove successful
update, rollback, restart or knowledge operation. Production stays unchanged.

The v87 diagnostic candidate `e188c853ad1cfaa6fea57e0f50b3815577ae9c0b`
compiled and passed strict specs/plan validation; one selected full-cycle case
failed in93.76s. Archive SHA-256
`c35d94ea8602180d4ddaeadb0eb5d0621fa771642b2309ddb8a6d3361e185c4f`.
The genuine importer returned0, stdout16807 bytes, stderr0 bytes. Core's
16384-byte result cap therefore rejected a successful complete bundle receipt.
Sol's finite four-artifact refinement admits a complete fixed receipt up to
32768 bytes, retains the16384-byte stderr cap and all closed schema, exact
inventory/path/backup and independent tree checks, and requires meaningful
positive/oversized refusal evidence. No output truncation or unbounded receipt
is admitted; actual runtime qualification remains open.

The v89 specification candidate `2615ac44a461ef34dbc41ccce16b992b84f76e80`
compiled and passed strict specs/plan validation on the Pi. Archive SHA-256
`73a84ef6781f3c2ac0fa086a2547691e57704a033e6accdcd9c343cfd5db6507`.
No runtime checks or deployment were repeated for this specification-only
leaf. Luna's bounded implementation follows the validated Sol handoff.

The v90 candidate `a3633c70fb5e4c09e55b4ed58af064ce9c2ad13b` compiled
and passed strict specs/plan validation on the Pi; affected contract group156
passed in12.83s. Archive SHA-256
`0a5794e7b0a8b1f7bcd832ef5a503c03bcf346a3011bb92165d5563ba4197174`.
The one full-cycle positive failed in319.47s after the genuine importer receipt
and independent new generation tree passed. The next guarded read refused
listener custody; the fixture still reached the real PIDFD listener reader
despite using a controlled service/process model. A bounded test-only correction
must join that model to the actual guarded-read predicates. Recovery also
refused the retained prior marker. No production deployment or full update,
oversized-receipt, recovery or new-read acceptance is claimed from this run.

The v91 fixture candidate `e9f86147dc32fbc42a7d8cccd75bedbb3cf85c21`
compiled and passed strict specs/plan checks. Archive SHA-256
`904bc60488eebf6c2920dd176ba5f19de93fde76d61a89b53ce59347b7be9712`.
Its process model supplies a fresh pipe-backed held handle per restart and a
real PIDFD for the test process's listener recheck. The first case remained
CPU-active; Root interrupted only the identified Root pytest process after
verifying exact command, source working directory and private mount namespace.
Pytest reports KeyboardInterrupt in its YAML emitter after534.77s; no selected
case completed, so this run establishes no pass/failure acceptance. The test
diagnostic tracer had traced library frames and handled every return event.
v92 filters call tracing to the three reviewed source modules and caches
filename classification. Runtime clocks, seals, admission and source pins are
unchanged. The interrupted fixture never changed the live Core service.

The v92 fixture candidate `5b97da0b5f00c51bbb32bd4449153c23210d8718`
compiled and passed strict specs/plan validation; one full-cycle positive failed
in139.59s. Archive SHA-256
`355f97fa56465aef8bcc28be66ce144438682312419cbba4b8821b59299f6580`.
The filtered diagnostic advanced through the genuine import, tree proof and
new-read issuance. Initial primary adoption then called its early root-context
journal reader outside the existing authorized initial-adoption scope; the
normal starting-journal recovery gate correctly refused. The minimal manager
correction enters that validated scope for this one read, with custody checks
before/after and normal Root/lock/journal admission unchanged. Sol reviewed
the manager delta and its exact one-entry source pin. Live deployment and
full update/recovery acceptance remain pending.

The v98 diagnostic candidate `d8fbb3ade7bceac14172c1efdf396f4ea34577ee`
compiled and passed strict specs/plan validation; one positive failed in138.44s.
Archive SHA-256
`0a8fe061c84315751519f7ca667d439df9468f76efb10b6b789959865f0542d9`.
Its false-return probe identified the initial validator's caught-exception
return. The existing exception pool stopped recording after80 events, obscuring
the later exception. The next test-only probe keeps the first30 plus latest50
sites, and separately at most12 internal initial-validator exception sites.
Source admission, leases and runtime code are unchanged; no acceptance follows
this diagnostic candidate.

The v99 diagnostic candidate `b4fdf7eab68771530483325d21f0207a033d8ba5`
compiled and passed strict specs/plan validation; one positive failed in139.05s.
Archive SHA-256
`1e3fb809d6e4f9ec9a0ae3be5d80e245b9ddfa3258fa19ad4585aceace7f22a9`.
Recent source locations identified an actual reader/producer mismatch: stage
recording writes the preparing manager digest into the cohort, but its reader
still required absence for both pending and preparing states. The finite
correction requires absence before recording, the exact preparing/writing/
adopted digest in its corresponding stage, and the immutable backup digest
equal to the retained prior SOUL. Existing closed progress, phase, after-Resources
and rolling-back proofs remain. Sol reviewed that repair and the exact Core
source pin. No live update or acceptance is claimed; the live Primary journal
remains restored to its original absent state.

The v93 candidate `bd9906eca2e44fbd89c7b565f31304db968b4279` compiled
and passed strict specs/plan validation; the affected contracts plus Primary
manager group168 passed in54.19s. Archive SHA-256
`7f78b9650d34d8eac1758be9b540f787ed25ac42fbe7401eaafb96875531d096`.
The full-cycle positive failed in139.05s with a PrimaryPromptAdoptionError
after entering the corrected early scope. The bounded probe omitted that
module's frames; v94 adds its filename to the same bounded call/site/context
filter. No runtime change or acceptance follows the diagnostic-only leaf.

The v94 diagnostic candidate `fc2af8ff7242642f961c150a18c15a397138e80a`
compiled and passed strict specs/plan validation; one positive failed in139.66s.
Archive SHA-256
`7911f3805f6779190bb88930d6641d40b89cb7515e09234a6849d30f7947d18c`.
The exact Primary manager frame was its source-receipt gate: the fixture
discovery projection omitted `resources_revision`, although its real CAS and
record contained it. v95 independently validates record revision/tree against
the parsed CAS manifest and includes the required revision in the projection.
This test-only correction does not relax production source admission or claim
successful profile/update/recovery effects. Unchanged168 checks were not
repeated for the diagnostic-only candidate.

The v95 fixture candidate `3b95ba26c5dc5fde2c838a1555c7bdd5599dcd91`
compiled and passed strict specs/plan validation; one positive failed in137.79s.
Archive SHA-256
`87a15f4a1c28c033966f6278215908f7ef9d0df125f571f9b75765f5176154f5`.
It passed the corrected source-receipt join, then exposed another actual
initial-adoption ordering bug: preparing manager record publication preceded
the immutable owner SOUL backup, so the immediate custody check and recovery
both refused the missing backup. The minimal initial-only manager correction
durably writes/readbacks the exact backup under validated scope before the
preparing record, with custody checks and owner lock retained. Record failure
keeps the immutable orphan; it does not grant ownership or remove owner data.
Ordinary adoption and existing resume paths are unchanged. Sol reviewed the
finite correction and exact Primary manager source pin; full Pi acceptance
and any target deployment remain pending.

The v96 candidate `929ca443193449754a28a8697224512f0ded5faf` compiled
and passed strict specs/plan validation; affected group170 passed in54.54s,
and one positive failed in59.05s before update effects because it found a
preparing primary record. Archive SHA-256
`11dbc75c62b5de14e830be0078c894f2900af116cb1e9a0024d638369bd491e5`.
**Fixture isolation incident:** its main journal/CAS were temporary, but
Primary journal/backups and Resources overlay/lock constants had not been
redirected. Pi95 had written the live preparing Primary record. Generic
directories/locks were also exposed. The private HOME bind protected the actual
SOUL path; the failed test was not free of host metadata effects. Earlier scoped
isolation descriptions must not be read as blanket host-effect guarantees.

Root's strict closed-record/custody read joined the record to the retained
Pi95 cohort: fixture source `/opt/hermes-installer-core-3b95ba26c/src`,
Core generation `c` repeated64, exact artifact/source-prompt/managed-block,
prior/desired SOUL digests and signature. Its exact known fixture prior bytes,
prefix length, empty result signature and null native proof matched; the actual
SOUL was not those fixture bytes. No hash-named immutable backup existed.
Record SHA-256
`cb3c4f819834a24734bdc0b3a424667935fc1bc05e12ba57ab54eda46280c8bb`;
retained cohort SHA-256
`12446d0a8d49efba6bbd7483b025e9f8c029e60516cc5e77a26aaa0fb70042df`.
Root preserved exact raw record, cohort and private provenance snapshots in
Root0700 `test-fixture-quarantine-20261013/` under the live Core runtime
directory, rechecked original inode/metadata/bytes, atomically moved only the
proven fixture record, and fsynced both directories. Original absent Primary
ownership is restored. Generic locks/directories and unrelated data remain.

The quarantine operation's before/after SOUL, present auth file, Core/Resources,
Obsidian registration and overlay-active digests matched. Separately all four
live units are active at old source0cbf9b819. Registration/vault digests still
match the earlier live preflight. This is bounded recovery evidence, not proof
of every historical test effect or successful Jarvis adoption. v97 redirects
and asserts all named Core metadata write paths under `tmp_path`; Sol reviewed
the finite fix before another test. Private HOME and `/opt` isolation remain
independently checked. No new Core has been deployed or accepted.

The v97 isolated fixture candidate `012c75e36cd0a57949d997385c2122e4bea3fb8e`
compiled and passed strict specs/plan validation. One positive failed in139.01s
after immutable backup, preparing manager record and stage recording. Archive
SHA-256 `68bace9923e64e29ab558b142078e495301063f299e990868828bf0a263de335`.
The next initial-custody predicate returned false; a test-only probe retains
at most12 filename/function/line tuples for selected false returns so the exact
gate can be identified without values or clock/admission changes. The live
Primary journal remained absent during and after v97. Source/tools match v96,
whose170 checks were not repeated; broader changed fixture qualification and
full update/recovery acceptance remain pending.

The v112 candidate `01f498f6f30cf6ba3e9779e590678d7c493d2d39`
compiled and passed strict specs/plan validation on the Pi. Archive SHA-256
`0bd2f955bca6e68fe79f27fbe0439dddeebb7a3fcdbe37d2d425d509bc75cc24`.
All ten quick actual guards passed in2.85s, including nine/eleven-member
empty-optional admission, tamper/missing refusal and empty-required refusal
with a matching empty-content manifest. The registered full update positive
passed, including the actual final generated guard and exact controlled
registration/vault preservation. The paired injected-restart rollback case
failed; combined result one pass/one failure in355.42s. This is isolated
orchestration evidence with explicit provider/native-readback fixtures, not
actual live registered-reader, provider or deployed-Jarvis acceptance.

The v113 test-only diagnostic candidate
`b41bf4d8b91d2b485077b25091f7bbd85e5fa98a`, archive
`4694a2bb9c8bc02f22a3553650c41b7a5d096c3a68ab665cae40cf50ed0569c0`,
passed compile/spec/plan and quick checks; only registered rollback was replayed.
It failed in94.69s. The injected restart failure did occur, but recovery then
failed validating the owner-generation restore receipt. The prior marker
diagnostic used a stale line number and therefore emitted no category. v114
uses a fixed function/error identity instead: source
`d16da73a5e8123f0ca667e75282651fc054a2f5d`, archive
`c4af23fb63bb8ba595981b162b9ff960eb8a14140b9e9cc0a1488831479adf6f`.
Its rollback-only case failed in95.25s; the A0/artifact mismatch is the expected
old-generation probe against current A1, and does not establish the recovery
cause. The exact failure is the closed restore-receipt check at Core line4991.
A bounded Boolean receipt-join diagnostic is required before any Source fix.
The passed v112 positive is not repeated for these test-only changes. Live
deployment, complete recovery and all eight broad task groups remain pending.

The v115 diagnostic candidate `265c6712e78d48d9a7dc2a5b75d028394a6b834b`,
archive `e4b7d6ca2cb9401c694ee54c6b2dc4386cac46b24d6f20dd60dc80580b3fbe59`,
passed compilation, strict specs/plan and ten quick checks. Registered rollback
failed in95.25s. Its bounded receipt diagnostic identified one false predicate:
the retained backup path. The genuine producer retains the generation under
`HERMES_HOME/name`; the Core consumer expected `HERMES_HOME/skills/name`.
The remaining closed receipt predicates were true. Luna corrected only that
consumer path join; Sol reviewed and updated the exact Core source pin.

The v116 specification-only candidate `6d1ea679abaf5bf7edfe2525c0cf75dc9eb2efdc`,
archive `0dab1271d977dfec91fdb191bc609876470ceb9de6f9f0ff1b8f232d57d4737f`,
passed compilation, OpenSpec status/instructions and strict specs/plan on the Pi.
It records the four independent feature leaves in Issues17–20. It proves no UI
rendering, audio, native effects or completed feature acceptance.

The v117 candidate `13cf877ee64306065052dccea4040a3c65089686`, archive
`ba65232b37ae51ca8e831ac71d5883f5d341fb3a1825561b45df56457d039dc6`,
passed compilation, strict specs/plan and all ten quick checks in2.93s.
The registered injected-restart rollback passed in94.92s. The genuine owner
importer restores the exact prior controlled generation while the closed receipt
and preservation assertions remain enforced. The full Core and adopter suites
are running separately against this identical archive; their outcome is pending.
This is controlled Pi recovery evidence, with explicit native/provider fixtures;
production adoption, real registered-reader/provider effects and broad acceptance
remain separate.

The v111 candidate `6437a6407fb938cdb4e1f1ffef678e55a319464a`
compiled and passed strict specs/plan validation on the Pi. Archive SHA-256
`9c4947bea285e60b70a9e0cb64bac9cf0d1140de2d59b424b1b40595cf033f9c`.
Seven quick actual guard/diagnostic checks passed in2.32s. The registered
full update stopped at the original committed guard denial in295.51s.
The bounded diagnostic is now usable: only backup verification is false;
current source/recipe, service files, Resources, initial Primary, native plugin,
cohort phase and reconstruction checks are true. Read-only checks of the
retained fixture backup prove its manifest is canonical and equals the current
journal reference; all11 files have exact recorded hashes and Root600
single-link custody. The overlay, prior Primary and prior cohort files are
empty, reflecting absence before update. The snapshot and backup writer
intentionally retain those empty bytes, while the generated guard erroneously
requires every backup member to be nonempty. Sol reviewed the bounded repair:
only four defined optional member names may have zero bytes with the exact
empty-content digest; all required members and other checks remain strict.
Fast actual nine/eleven-member positive and denial tests must precede the
next full replay. No full update/recovery or live acceptance is claimed.

The v110 candidate `e83cb5299e739dc3df5b01a2694fddecad9962a7`
compiled and passed strict specs/plan validation on the Pi. Archive SHA-256
`ed96754f5513ea4a449bce490cfa562c607957a96648e2c492861fe81f653d8a`.
Six quick actual guard tests passed in2.19s. The new registered-vault full
positive stopped at the final original guard denial in295.00s; no preservation
or complete positive acceptance is claimed. The failure-only traced diagnostic
produced `guard_flags=None`: its closed parser rejected an uncaptured
`base_ok=None`. The next test-only correction omits uncaptured flags and adds
a fast actual wrong-token diagnostic contract plus bounded exception metadata.
That quick contract must pass before another expensive full replay. The
original unwrapped guard remains authoritative, with the rerun occurring in
the retained private HOME/credential view; no live deployment occurred.

The v109 candidate `9f5ce0b49372647ee520b089e553701f308223ea`
compiled and passed strict specs/plan validation on the Pi. Archive SHA-256
`2656be1e3969b1c7e5d8c76d0aebb3586d7770a1cb2cdc9533976ddda8b2262e`.
All six quick actual guard tests passed in2.16s, including the committed
initial-adoption starting/final Resources distinction and tamper denials.
The full update group stopped with one failure and three passes,37 deselected
in294.69s. The controlled updater returns successfully but its final generated
guard still exits1 with an empty stderr. The failure is the final guard call
at test line1462; no remaining recovery assertions or live acceptance follow.
A bounded Boolean-only diagnostic of the unchanged guard is the next step;
no speculative admission weakening is authorized. All four live services were
active and the real Primary ownership journal remained absent during this run.

The v108 candidate `478199d5e3a61b22d24352fffbf3bff999fe6612`
compiled and passed strict specs/plan validation on the Pi. Archive SHA-256
`1c3f677f5c06caed5d91f25d2610f9e54d26eb7bb17e5c2ad9c3aa782d73e533`.
The first quick actual guard test stopped with a generated-script SyntaxError
in0.59s;53 cases were deselected. The expensive update group did not start.
The retained R_s predicate correction omitted one closing parenthesis. Luna
supplied the minimal syntax repair and Sol reviewed/pinned the changed Core;
actual quick guard validation remains required. No live deployment occurred.

The v107 candidate `19bce42d32c8c14e63e84a4903398265c9b6b1a4`
compiled on the Pi and passed strict specs/plan validation. Archive SHA-256
`e7d3fee77a791b0ffce5c1d11830e5cd4c5a3fafb7bd44f865b01ed974fbf9ee`.
The five quick guard cases passed in1.99s. A net fixture correction selects
only unit/launcher in a disposable Root-owned readable service tree before
recipe creation; no generic pytest-root mirror remains. The full group
stopped at one failure and three passes,36 deselected in297.09s. Complete
update returned successfully; public fixture paths removed the prior access
error, but the committed guard still denied. Sol identified the exact source
join: initial adoption retains the starting Resources receipt digest R_s,
whereas the committed current receipt is R_f with final journal ownership.
The guard incorrectly compares that retained starting digest to current R_f.
The pending correction must retain the immutable R_s/C starting join and the
separate current phase-selected R_f check; no receipt restamping or admission
weakening is permitted. A quick committed-adoption regression precedes further
expensive replay. Complete case, recovery and live acceptance remain open.

The v106 candidate `fb875d7df8323eb34632498fd014c88e66945db2`
compiled on the Pi and passed strict specs/plan validation. Archive SHA-256
`67f79d0acace81b11eb0f98bcd504f5f037ff81c9d3b757060a6d575be42c197`.
Its quick actual admin/private-mount startup guard group passed five tests,
53 deselected in1.98s: exact legacy9 and typed native11 backup modes,
missing-credential/plugin-tamper refusal, preserved Core subprocess denial,
and exact generated unit bytes across fresh Python hash seeds. The reviewed
source now emits sorted field tuples instead of process-dependent set repr;
only the existing Core source pin was refreshed. Installed plugin fixture
effects use actual root:root0555/0444 files inside the private HOME mount.
The broader group stopped at one failure and three passes,36 deselected
in295.38s. Complete controlled update again returned successfully; its real
admin guard then could not read the embedded fixture-unit recipe path beneath
Root-only `/tmp/pytest-of-root`. The helper exposes unit/launcher bytes at the
fixed production paths, but the full-unit check reads its recipe path. A
bounded isolated path-visibility correction is pending; host pytest directory
permissions and exact unit-byte checks must remain protected. These quick
results do not establish complete update, rollback or live chat acceptance.

The v105 candidate `f989ba66e50a4eee7bc707f57d156fb4f5f9be08`
compiled on the Pi and passed strict specs/plan validation. Archive SHA-256
`030a0ad6e818ef521d7a12c545024e4232f8998cf612636f84106aa5a071f7b5`.
The new quick runner case executed the real private namespace/admin guard,
emitted namespace-ready, and then the unchanged generated guard returned1.
Result: one failure,55 deselected in0.54s; the recipe stopped before expensive
update/recovery replay. Sol and Luna independently found production guard
drift: the closed cohort-key set omits `native_plugin_transition` and backup
membership still assumes9 instead of the exact conditional9/11 set. These
require a reviewed source correction; fixture rows and expected success are
retained. An initially suspected canonical-newline defect was disproved by
Sol's raw-source review: nested tool-output escaping caused the mistaken
observation, so no extra newline change is needed. A bounded Sol review also
found three stale test assumptions in
interruption injection, rollback start ordering and the two-phase reload
witness; their test-only correction is separate. Actual deployment, positive
startup guard and recovery qualification remain pending.

The v104 candidate `70c87e740d6d6cceeb146b32629fdc3afa00846e`
compiled on the Pi and passed strict specs/plan validation. Archive SHA-256
`8062e5f8d3934086c39555d0aae7ce5cdc405d729292560fed97479083619791`.
The unchanged107 adopter/lifecycle checks were not repeated. Broader Core
qualification again stopped at one failure and three passes,33 deselected
in295.62s. Complete update returned successfully and the exact new unit and
journaled unit digest matched. Its newly added real startup-guard execution
was blocked before invocation by the fixture's blanket host-subprocess deny.
The pending test-only runner correction captures the original subprocess
runner before that deny and passes it only to the existing isolated
unshare/admin guard helper; updater subprocesses remain denied and fixed live
unit/launcher before-after identity checks remain mandatory. Positive guard,
remaining success assertions and recovery qualification are still pending.
The Pi Connect browser session reconnected as admin and authorized sudo
restored the Root shell; no test result was discarded or rerun for reconnect.

The v103 candidate `448aab6b4b6b0b398f3a7644c220071de53ebe70`
compiled on the Pi and passed strict specs/plan validation. Archive SHA-256
`3c26cf6ab9ba00b68f7f8185ef27eccac1910cbfbf90d9d23d492d89946da799`.
The affected native adopter/lifecycle group passed107 tests in0.44s. The
broader Core update/recovery group stopped at its first failure: three passes,
one failure,33 deselected in297.28s. Complete controlled update returned its
success result and passed the new journal/source/selection/launcher checks;
the fixture then incorrectly required the new source-specific unit bytes to
equal the prior unit. The pending test-only correction must require exact new
unit and digest, positive new-unit startup guard, negative old-unit guard,
and preserved old unit in the immutable backup. The rest of that positive
case and the selected recovery cases remain unqualified. No new live source
deployment follows this intermediate updater result.

The v102 candidate `1de46f19219790842b02cd4dfd0be947ef08cf0b`
compiled on the Pi and passed strict specs/plan validation, including the
Managed OAuth research-only refinement. Archive SHA-256
`ee6b7b5f062bc466f57d041c6600269f9090c1373853020ccc7e97bf1b39df7d`.
Only the changed controlled readback and complete update were rerun; the
unchanged170 group was not repeated. Results: one pass and one failure,
51 deselected in293.19s. The independent native-readback verifier case passed;
complete update advanced through initial Primary adoption, Resources refresh
and the controlled new-source lifecycle proof, then failed at the final
journal/Resources join. The updater sets the final journal to `active` but
passes it to a binder that accepts only `starting`. Sol's narrow correction
requires a separate private final binder, exact starting-to-active derivative,
current Root-locked bindings-verified cohort and fresh held-peer custody;
the starting binder remains strict. Failure recovery also refused both old
and new generation owner markers, retaining the protected backup. That
separate recovery path is being audited; no safe full recovery or live new
candidate acceptance is claimed.

The v101 candidate `456a9314e851abc16b367f9b4dd928f326a8027a`
compiled on the Pi and passed strict specs/plan validation. Archive SHA-256
`50cb77fd218101b86d790c709d1f70950a75996d4c22fa4a7d3c1ce9017eab10`.
The affected gateway/lifecycle/plugin/Primary group passed170 tests. The
selected Core group returned one failure and six passes in193.62s. Fresh
writing metadata, prewrite/read-failure and drift-during-native-readback
refusals passed. Complete update now reaches `_verified_resources_payload`
and its controlled native readback: the fixture incorrectly asserts that an
unspecified managed-block expectation means the SOUL cannot contain a managed
block, even after genuine initial adoption has written it. Native/provider
readbacks remain explicit fixture substitutes. A test-only correction is
pending; complete update/recovery and actual target acceptance remain open.

The v100 candidate `0540742ca98920cf20a76156278519a7806cc6c2`
compiled on the Pi and passed strict specs/plan validation. Archive SHA-256
`fbc50b7a1a674df45973429f5644f78232c29545b08ba95a56255a3c319307d7`.
The affected gateway, lifecycle, plugin transition and Primary group passed
170 tests in54.73s. The selected Core group returned one failure and one pass
in145.05s: the preparing/writing/adopted manager-digest admission/refusal case
passed, while complete update advanced through actual immutable backup and
private SOUL replacement to `refresh_initial_primary_starting_tuple`. That
reader demanded the adopted signature from a writing record whose signature
is still empty; the manager persists it only after refresh. Sol reviewed the
narrow correction: exact writing-record digest and custody joins, fresh desired
SOUL bytes with original owner/mode/link metadata, then exact signature/bytes
and record recheck after A1 readback. The correction remains subject to Pi101
qualification. No live candidate deployment or native chat acceptance follows.

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

## Later Pi qualification runs 118–124

These are historical candidate results supplied from the Pi qualification
ledger. They are not a statement of current production state. Unless noted,
compilation and strict spec/plan validation passed with zero findings.

| Run / candidate | Archive SHA-256 | Pi result and disposition |
| --- | --- | --- |
| 118 `af3ea5c5ec1a1195bb3c8cbebe3225ff04e46f95` | `0b3b7a385ca835c053d7b7e6eb037c6a670a3f8f337f0dd87842ffd013072bbe` | Compile/spec/plan passed. |
| 119 `68aa99ab7c754c35ebfc6f596062ba6fd3cd96aa` | `da239656ac66f9f8dc57a5a00b4da314e9dace9c634f006b7df4fcebb10da6b9` | UI checks: 8 failed, 88 passed in 1.94s. Harness failures were corrected in `3d`. |
| 120 `c371ec0f3104fea5f28e03bfb93da70b85286fdf` | `450ed7db0d24d245ed53f4997399dacb56fee142e98c82f8737d130b22acc12a` | Focused checks: 4 failed, 8 passed in 11.79s. A private-option omission retry passed 1/1 in 10.58s. Overview CSS, exact class and fake-form issues were corrected in `544`. |
| 121 `66b08623d3afd6ae67f72a3acbc551f0e51be30e` | `0286f5d5672211bc2c316392f3536c051f54b2a0b6831a399890ec317c33aab5` | Compile/plan passed; strict spec validation reported one requirement over 500 words and two requirements. No waiver. UI collection had one error at the mount cap; Core was interrupted after one failure at 59.99s. |
| 122 `77111ac9357520bbc79953022754115ce4bfe39b` | `8de38bd2ff8c6dfa46266bba380a742b48385e7b03d13a76e95ac3f4c66aca17` | Compile/spec/plan passed. Editors: 3 failed, 72 passed in 1.34s. Extensions harness fix `980` and `54` followed. |
| 123 `d2819b7ced4d835d80f8f164f6b5a82494620a6d` | `fd47bc8b011185eed51c4ab42ad32ebab6d625938556514af57b89677e865116` | Compile/spec/plan passed. UI collection had one error: actual Obsidian UTF-8 mount measured 30,035 bytes. Core was interrupted after one failure at 58.88s: `_native_plugin_transition_scope` falsely reported the adapter lock unavailable, and `root_setup_install_resume` also lacked the lock before recovery effects. Fix `b0` acquires the existing protected lock before journal/effects and reuses the held path. Exact new Core `0dac9c434b5c9af0a7dc07dbecd1a8e9546951e1fa08a6786a04d49761394af5` was pinned in `6fe`; source review passed, Pi validation remains pending. |
| 124 `7c2ce140540887b5c5fab269cb285c676d800f83` | `cb1d89a445393c41d5a483b340ebbec615849b07d8b5818d89e79dc8743bf634` | Compile/spec/plan passed. Editors: 1 failed, 74 passed in 1.32s. A typed-required fixture accepted whitespace; `3aa` corrected it to require an exact empty value. |

The source-reviewed UI originals `4` and Sources `33/35` were not deployed.
At this ledger point, production remained on `0cbf9b819a6be41b3ff34d623374355cb64c3834`, and the Pi configuration still had its original single approved address. No result for run 126 was available. Accordingly, these entries record qualification evidence only; they do not establish deployment, additional-account access, or current acceptance.

## Later Pi qualification runs 126–130

Historical candidate results from the subsequent Pi ledger. These outcomes do
not establish current production state. Runs 126–130 passed source compilation
and strict spec/plan validation with zero findings unless explicitly stated.

| Run / candidate | Archive SHA-256 | Pi result and disposition |
| --- | --- | --- |
| 126 `b24d376d05889110b3c035275a082bbd94d1d90c` | `625fc4ebadc60eebd8b2d72da12a5fa8100fbd872e1654df8bfba244abb312fb` | UI: 10 failed, 172 passed in 3.77s. A new held-lock fixture initially failed because its private parent was absent; corrected in `c4`. Actual secondary Core effect run was interrupted: recovery passed, its partial test had 1 pass/1 failure in 124.17s; tail group passed 48 checks in 54.44s. |
| 127 `666ddbe4f2b2b19174ce60ccb743901c75d015d0` | `b6888ad2d61e597804e566095e277c8b77d531ba522f69995de5f00793982c87` | UI: 2 failed, 180 passed in 3.69s. Four Core lock/startup checks passed; partial group had 1 failure in 124.90s. |
| 128 `d09d1d72c4317ae960633672c246060bcd5e449b` | `349a641b45499d70599e7157f4b2dcb71195fe5964f206d4860190522eb32f9f` | Compile/spec/plan passed, including the first #21 spec validation. UI: 1 failed, 181 passed in 3.68s; stale captured approval-nonce assertion corrected in `e8`. Partial-group failure duration was not supplied. |
| 129 `3f2c7904da076c250ce9fc3d07f4254d9d15d2a1` | `f5cd03876350b4d67f480baebbcd1a16d550da1cc9501aff3acfeb62690441a9` | UI: 182 passed in 3.67s with 28 warnings. Partial group: 1 failure in 103.76s; `guard_ok=True`, then `PermissionError` at the original script's unit `stat`. Sandboxed Chromium helper `87c3f` against exact repo source 129 passed phone390x844, tablet768x1024 and wide1440x900 44px controls plus motion pause/resume, but had 7 render failures: phone composer/nav overlap; three Mission auto-close fixture flags; and three tablet Notes reads racing load/stale-button state. No qualification was weakened. Root visually reviewed a Pi127-derived wide Overview capture with synthetic quiet fixture. CSS `2f` raised controls from 42px to 44px and added nested mobile scrolling; actual navigation clearance remained pending. |
| 130 `ab509e65b63ce4df92e06f25263eb11506e5aa73` | `4472450c4c5bd628d7983f89bdd419b1f5945c3d4e70c43d329431d2dc384bc6` | Compile/spec/plan passed, including #21 one-use refinements; `f15` branch was not accepted. Partial group failed at `PermissionError` on `stat` of the allowlisted unit basename. Exact Root fixture public service-file mode `0644` source correction was reviewed; Pi validation remained pending 131. Renderer exited 2 because an Obsidian button was stale; `ca6` re-queries the live DOM and requires selected ID/body/digest, which does not prove production effects. |

At the supplied ledger point, run 131 jobs were still running with no results.
Root read back the four live units as active (Core, Inspector, Gateway and
tunnel), but no actual source deployment, configuration union, additional
admin enrollment, new provider, voice qualification or device proof occurred
in this turn. Core `0dac9c...` had genuine interrupted-recovery and 48-tail
passes plus four new-lock checks, but full new-source positive, restart,
partial-recovery and overall M1 acceptance remained open. Broad #21, #62 and
#18 items and eight other requirements remained open. These are historical
qualification facts, not a current production-status assertion.

## Pi qualification runs 131 and 133

These later results add recovery and UI evidence while keeping adoption and
final acceptance distinct. They are historical and do not state the current
production result.

| Run / candidate | Archive SHA-256 | Pi result and disposition |
| --- | --- | --- |
| 131 `dd13aefac6860621ca0a0b0c45c8e864550e9e01` | `02ba6e8dacbc7c798817dc5bb51f60d43fc188f3805df1dcbd1ae54b5fe75304` | Compile/spec/plan passed. Corrected partial/interrupted rollback: 1 pass in 96.24s. Positive updates: 2 passed in 611.25s. Restart-failure recovery: 2 passed in 199.54s. Core source `0dac9c...` was unchanged. |
| 133 `0972fe1dc3f20ad432c93ac42b54db56c470465a` | `2de26e4d5db5e52d4f4343f8026c4245abfe651f6e489c18a16e1fde2a99d49f` | Compile/spec/plan passed; chat checks 23 passed in 0.58s. Sandboxed responsive fixture passed with `failed_checks=[]` at390x844,768x1024 and1440x900 using helper `f26bd16e4e1b357c0e5f794e287a27dec823171db5b7046cd275c1e6a9b11e5d`. The measured control was73.5x44px at y453.765625–497.765625; a center hit succeeded with342x44px input. Stage verification found `/opt/hermes-installer-core-0972fe1dc`; it made no live change. Screenshots included a controls-modal overlay, so the targeted clean capture remains pending. |

At the time of the initial entry, Root had dispatched actual adoption and the
outcome was unknown. Its later readback is recorded below. The responsive
fixture and stage verification alone did not establish a completed live
adoption, final full-MVP acceptance, or actual Android/voice qualification.

## Pi 133 adoption attempt and recovery

The adoption attempt for source candidate `0972fe1dc3f20ad432c93ac42b54db56c470465a`
exited 4 during the fixed Root/Core qualification phase. Core reported
`current Resources generation is not fully discovered` at `root_setup` line 1050 and update
lines 5922/5980. The pre-transition check expected incoming helper bytes while
qualifying the old bundle; Luna/Sol's source correction is pending review.

An independent read-only projection of old source `0cbf9b819a6be41b3ff34d623374355cb64c3834`
confirmed Resources discovery, schema 3, with a receipt bound to both the Core
journal and generation (`f496ed0a8d5e667a40341578b916ffd36077f41968decde0c4d52b2ffd8c6ca0`).
The incoming `0972` read-current evidence was stale and referenced a different
artifact (`850b70f2e9e4e4d5a2d61f7eda41de18ab144aa408722cc6f2956428efdcca74`).
Automatic recovery verified the prior Core and ingress. Core generation,
Obsidian registration and vault, token, native plugin and overlays were all
reported preserved. Source `0972` was not deployed. The separately managed
Jarvis primary prompt was not adopted by this attempt and is not claimed as adopted.

The deployment remains unqualified pending the source correction and a new
verified adoption outcome. This attempt does not change the separate responsive
fixture result and is not final M1/full-MVP, Android or voice acceptance.
