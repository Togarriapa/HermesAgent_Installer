# Acceptance evidence and readiness

The installer records each result against one immutable candidate Git SHA. The report aggregator trusts no JSON row by itself: its caller must authenticate the artifact through an enrolled verifier callback. Without that callback, even a syntactically valid prepopulated `pass` remains untrusted and the acceptance state stays pending. `fixture`, `native-arm64`, `physical-pi`, and `account` evidence are separate lanes. Source selection, download, configuration, discovery, and inventory can describe progress, but they never establish functional acceptance. A skipped or unimplemented workflow remains pending. A failure remains visible and prevents a green report.

`hermes-installer verify --acceptance AC01 --target <authorized-target.json> --output <evidence-dir>` is the target workflow shape. The runner requires an enrolled target whose owner authorization, expiry, and selected acceptance scope have been checked by the target-enrollment adapter. It dispatches only a registered adapter; no arbitrary shell command comes from a manifest. Without an adapter, the workflow records pending and performs no target effect. The current CLI verify command still returns pending until target enrollment and functional probes are integrated.

Each evidence record binds an evidence ID to the full candidate SHA, platform, target identity where applicable, UTC start/end, command, exit code, assertions actually observed, and digest of the retained artifact. The generated report lists every traceable requirement separately from its implementation state and evidence state, and reports fixture, native ARM64, physical Pi, and account lanes independently. A pass requires exit code zero, nonempty all-true observations, and a retained artifact digest. Reports serialize only an allow-listed record shape and redact token-like fields and values. Do not place credentials, access tokens, or private prompt content in evidence.

`load_acceptance_catalog(planning_dir)` combines AC01–AC15 from `planning/traceability.json` with AC16–AC18 from the append-only Resources, Access-read, and host-custody amendment manifests. It carries each amendment's requirement, task, and evidence IDs into the report and rejects missing or duplicate acceptance IDs. AC16 covers the self-contained Resources bundle and real native materialization; AC17 covers fresh Access policy membership and bounded revocation evidence; AC18 covers root-owned host custody, kernel-enforced worker isolation, and mandatory native dispatch mediation. AC13–AC15 and AC17 require both target and account evidence; the other workflows require physical Pi evidence. AC18 additionally needs the separate native isolation observations in its EV-HI evidence set.

## Current evidence

The development checkout and CI provide contract-fixture evidence only. Repository planning records 739 preserved Resources files and 692 declarations; this is source preservation, not native discoverability or successful workflow invocation. The prior isolated Pi attempt for candidate `51d3883442086bd473e518fd1917d0d031f03e23` failed in the products stage and its resume attempt failed; see [the dated Pi record](evidence/2026-10-09-pi-isolated-install-51d3883.md). It is not evidence for a later candidate.

No claim of full installer, account, physical Pi, native ARM64, GLM-5.2, Coral TPU, or full Resources acceptance is made here. Keep the OpenSpec tasks unchecked until the matching candidate has the required fixture and live evidence. Exact target blockers and resume commands belong in the generated JSON report. The isolated Pi owner runs hardware workflows in the Pi Connect browser and supplies the corresponding redacted result; do not substitute a local development Mac run.

## Review checklist

1. Confirm candidate SHA matches the tested tree and all evidence rows.
2. Check source/configuration/inventory states separately from functional execution.
3. Confirm every acceptance ID and original requirement has a linked task and evidence ID.
4. Preserve failures, skips, and pending account/hardware items with an exact blocker and resume command.
5. Check redaction and artifact digests before sharing a report.
