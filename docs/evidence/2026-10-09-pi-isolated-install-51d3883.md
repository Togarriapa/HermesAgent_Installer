# Isolated Raspberry Pi installer deployment evidence

Captured 2026-10-09T15:55:22Z from the authorized Raspberry Pi Connect remote shell.

## Candidate and isolation

- Repository candidate before this test: `51d3883442086bd473e518fd1917d0d031f03e23` on `codex/luna-installer-development`.
- Bundled HermesAgent Resources source pin: version `2.3.1`, source commit `113f42d33be9e0c8f0f47f5ca998e687323dec83`, archive SHA-256 `b09459b609676cff30f151ac7db1fc405039b8871486b483af563ba7f63e7cd1`.
- Target: Raspberry Pi 5, Debian GNU/Linux 13.6 (Trixie), aarch64, account UID 1000.
- Dedicated test config: `/tmp/hermes-luna-resource-wire.json`, created via `write_example`, validated with `load_config`, and mode 0600. Its only roots are `/home/admin/HermesInstaller/data/devtest-luna-resource-wire-51d3883/data` and `.../state`; both were observed installer-owned with mode 0700. Existing Hermes generations and system services were outside those roots.

## CLI results

- Read-only `status --config ... --json`: state `pending`, 10 pending findings and 5 ready findings. Pending reasons include existing `cloudflared-hermes.service` and `hermes-pi-testd.service` adoption conflicts, bound-port conflicts requiring review, active installer operation, absent recorded Hermes runtime verification, and absent recorded official Desktop build.
- `doctor --json`: reported pending review findings and stated no files, services, packages, or accounts were changed.
- `install --config /tmp/hermes-luna-resource-wire.json --dry-run --json`: `ready`; “Dry-run complete; no installer files, packages, services, or accounts were changed.”
- A bounded real `install --config /tmp/hermes-luna-resource-wire.json --json` was attempted with a 180-second timeout. No JSON completion result was captured. Subsequent status recorded `installer.operation` as active; do not treat this attempt as successful.
- `resume --config /tmp/hermes-luna-resource-wire.json --json`: exit code 1, state `failed`, message “Hermes stage products did not complete (exit 1); use hermes-installer resume”.
- `verify`, given a temporary target manifest limited to the isolated Pi data/state roots and a dedicated evidence output directory: exit code 0, state `pending`, message “Target verification adapter is not implemented yet; no target was contacted.”

## Native resource contract test

On the exact published candidate, `PYTHONPATH=src timeout 120s python3 -m unittest tests.contracts.test_registry_native tests.contracts.test_registry_runtime -v` ran 11 tests; one failed because materialization returns 694 files (692 resources plus Catalog and QUALITY_POLICY), while the test asserted 692. After correcting that stale expectation, the same command passed: 11 tests in 6.354 seconds. The accompanying test change is limited to that expected count. This records a Pi contract-test result, not native Hermes runtime acceptance. Actual Hermes-native discovery/use, runtime verification, and the installer finish gate remain pending.
