# Host principal custody implementation status

This document records implementation evidence separately from Linux runner, native ARM64, and Pi acceptance. The current branch contains a Linux transient-service supervisor prototype and an authority-gated admission contract. It is not evidence that an installed root-owned custodian or native Hermes worker has passed target qualification.

## Process admission contract

`hermes_installer.managed_process.ManagedProcessSpec` binds a resolved single-link executable and SHA-256 pin to an owned artifact root, one profile data root, a minimal environment allowlist, a dedicated service UID, a finite monotonic startup deadline, and a manager-enforced maximum lifetime. A host-issued `HostContext` and one-use `EffectAuthorization` are required. The effect target binds profile ID, resolved executable, executable digest, and resolved data root; its request digest binds the normalized full argv. Secrets in argv or environment are rejected. The service UID is `hermes-` plus the first 16 hex characters of SHA-256(profile ID), with no login shell, home directory, or supplemental groups. The profile root is mounted at `/hermes/profiles/<profile_id>` while `HERMES_HOME=/hermes`, preserving Hermes' native `profiles/<name>` lookup without exposing sibling profile data.

`ManagedProcessSupervisor.start(spec)` returns a handle only after checking the actual process start time, pidfd, cgroup membership, executable device/inode/hash, sanitized environment, service UID/groups, mount and network namespace identities, manager sandbox properties, and available kernel cgroup resource controls. The handle uses manager-owned cgroup cleanup, bounded nonblocking partial I/O, and escalation against the named unit. It does not use stale process-group signals. `run_managed_process` captures bounded stdout and stderr separately and returns cleanup evidence.

## Current limits

The implementation still launches `systemd-run` through `sudo` from the calling process. This is not the final trusted boundary: an enrolled root-owned fixed `process.start` handler must own service creation, and fixed process status/read/write/stop operations must own subsequent lifecycle control. Until that handler is wired, process execution remains unavailable for production use. Network namespaces deny worker egress; a reviewed broker-only download/egress route is still required before network-backed installer stages can run.

The host authority and process supervisor fixtures are synthetic contract fixtures. They do not prove the root service, protected IPC installation, actual authority key custody, or target policy enrollment. The Linux integration tests in `tests/contracts/test_managed_process.py` are intended to probe real kernel/systemd behavior when run on an eligible Linux CI host; they have not been run on the development Mac or Pi. Native ARM64 and Pi start/stop/parent-death, sibling filesystem/process/network/credential denials remain pending. No task is marked as native acceptance.

## Verification distinction

Static syntax and whitespace checks have passed for the current supervisor changes. The meaningful Linux negative-effect suite, CI result, root custodian integration, protected profile enrollment, and Pi evidence must be recorded separately before enabling any affected capability. A failed probe leaves that capability disabled with its exact retry/resume action.
