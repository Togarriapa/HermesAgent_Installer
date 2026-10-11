# Safe bootstrap diagnostics and exact source review v196

This finite refinement of BD-F02, HI-T149.1 and existing VD-T180.6/VD-T183.5 preserves original R0033/R0035/R0040/R0054/R0155 and every frozen baseline obligation. It changes only safe local failure reporting and two current source leaf tuples; all 160 baseline hashes and the annotated tag remain unchanged. AC01..AC18 remain OPEN.

The actual published candidate 39f60361549e9c3e4c6baa8dc117fdb05a4f791f reached protected source CAS construction on the identified ARM64 target but returned a generic OSError reason before a final candidate existed. This is failure evidence, not source/runtime acceptance. Its errno/step was unknown before instrumentation; do not infer a successful fetch, materialization, handoff or installed execution from created CAS directories. Preserve exact source/actor/runtime verification and cleanup guards.

## Closed diagnostic contract

Root bootstrap may replace an OSError at the finite stage boundaries enumerated in `planning/safe-bootstrap-diagnostics-source-review-v196.json` with `BootstrapSystemCallFailure`. Expose only an exact allowlisted stage string and an allowlisted errno symbol; unknown errno emits no symbol. `_safe_reason` must revalidate exact error type and exact-string allowlist membership at output, because exception attributes are mutable. Tampered/subclass/invalid-stage values receive the fixed OSError category; invalid errno values are suppressed. Never format raw exception text, filename, path, arguments, causes, locals, stack or untrusted object string/repr. The existing generic pending reason and trust RuntimeError type-only rejection remain unchanged. No new caller field, authority, transport operation, blocker phase or successful-state claim is added.

Wrappers annotate source CAS construct/prepare/lock/inspect/materialize/resolve/lock-release, runtime provision, TTY choice and fixed handoff/reexec OS failures. Existing ownership, symlink, lock, hash, source origin, TTY, PIDFD, runtime, selected-candidate and lease checks remain mandatory. Catching an OSError provides diagnostic context only and cannot repair a conflict, release custody, retry with looser guards or authorize a missing runtime. Runtime source/trust errors retain their prior classification.

## Exact reviewed source and application

Reviewed committed implementation d1ce9fd80cf685f2499f7db87474f7164b473af2 plus final output-boundary correction fff388978141a027ddb036e94b4d08b2f5346116; final tree 78d20d172b9708f24580de6f74300421eedca88b. Sol recomputed committed leaf bytes. The exact authoritative replacement rows are `planning/safe-bootstrap-diagnostics-source-review-v196.json`:

- bootstrap_enrollment.py: source SHA256 6a5985a80064b661c93e1be0c62ae27a454eea1d90658be2c09fe0141e7ecedd,142594 bytes; installed installer-module:hermes_installer.authority.bootstrap_enrollment at lib/python/hermes_installer/authority/bootstrap_enrollment.py, module/root-owned0444.
- root_setup.py: source SHA256 a938ca78933cde596f627986a60b7c270c0093dc6d9edacf2acb467abbd27f9c,57764 bytes; installed installer-module:hermes_installer.root_setup at lib/python/hermes_installer/root_setup.py, module/root-owned0444.

Only these two rows supersede v195 member tuples. Apply them to corresponding builder/verifier REVIEWED_SOURCE_MODULES expected bytes and focused fixtures after root publishes the specification. All other v195 leaf tuples, helper/runtime roles, aliases and raw catalog rows remain unchanged. Neither changed member has a separate raw downloader artifact in the reviewed v195 list: actual verified candidate source snapshot and held installed/import member custody remain its authority; no new catalog URL/identity or expected source self-pin is needed. installer_release_build.py is metadata/application source and its actual current committed SHA 539708a4f4615857aed78e79267ff19a31e8ed3f714162a8dedd3187d47d4c52/254684-byte snapshot is recorded for independent structural review, not an expected self-pin that would cycle after metadata application.

Source review does not repair or close the separate display/task production composition gaps. Existing HI-T09/HI-T13/HI-T160.1/.2 and HI-T173.1 remain OPEN; no fake session store, fixture actor, runtime callback or copied setup authorization follows from this diagnostic appendix. Any necessary finite two-actor authority contract is reviewed separately.

## Tasks, evidence and ownership

- BD-T196.1 bootstrap diagnostic owner: implement the closed step/errno wrapper and final output revalidation with normal errno, unknown errno, private filename/text, mutated fields, hostile subclass and unchanged trust-rejection regressions. Exact source implementation is reviewed; pin application and actual target outcome remain OPEN.
- VD-T196.2 integration/evidence owner: apply the two exact source tuples, preserve full candidate/import custody and run the focused diagnostic/builder/verifier checks. On the already identified authorized ARM64 target, retain only the resulting finite step/errno/status/resume evidence; do not claim success until actual verified candidate publication and installed execution occur. Keep all original AC and runtime readiness open.

Reported source validation: focused redaction test 1 passed; combined root-setup/release-build suite 75 passed, 7 skipped, 1 expected old source-pin failure before this amendment is applied. The expected mismatch is explicitly unpassed evidence, not a waiver. Root publishes this spec-only commit, Luna applies reviewed pins and verifies, then root controls any subsequent target action. No new remote branch/push, canonical runtime sync/archive or live account/resource mutation occurs in this review.
