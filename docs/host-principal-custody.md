# Host principal custody implementation status

This document records implementation evidence separately from Linux runner, native ARM64, and Pi acceptance. The current branch contains an authority-broker client and a root-side fixed process handler. Neither local source nor fixture results establish that a protected daemon is installed or that a native Hermes worker has passed target qualification.

## Process admission contract

`hermes_installer.managed_process.ManagedProcessSpec` binds a resolved executable and SHA-256 pin, exact child artifact digests from a protected root-owned catalog, one profile data root, a minimal environment allowlist, a dedicated service UID, a finite startup deadline, manager-enforced lifetime/output bounds, and optional cgroup limits. A host-issued `HostContext` and one-use `EffectAuthorization` are required. Its target binds profile ID, executable path and digest, and data root; its request digest binds the complete canonical launch envelope. Secrets in argv or environment are rejected. The service UID is `hermes-` plus the first 16 hex characters of SHA-256(profile ID), with no login shell, home directory, or supplemental groups. The profile root is mounted at `/hermes/profiles/<profile_id>` while `HERMES_HOME=/hermes`, preserving Hermes' native `profiles/<name>` lookup without exposing sibling profile data.

`ManagedProcessEffectHandler` is the root-only adapter for fixed `process.start/status/read/write/stop` verbs. It accepts only the already-verified consumed grant, checks protected profile/catalog bindings, opens pidfds for the peer and worker, starts an exact systemd transient unit, reads kernel UID/cgroup/namespace/executable and cgroup limit evidence, and owns cgroup stop/escalation. `ManagedProcessSupervisor.start(spec)` talks only through `AuthorityClient.process_start`; its handle uses fixed broker controls and bounded separate stream cursors. It never signals a caller-supplied PID or process group. `run_managed_process` captures bounded stdout and stderr separately and records cleanup proof.

## Current limits

The daemon constructor and handler factory exist in source, but the root-owned daemon, protected profile/catalog registry, socket directory, and per-UID sockets have not been installed or exercised on Linux. Child scripts must be staged in an immutable root-owned catalog and explicitly enrolled by exact path and digest; caller-owned bootstrap staging is rejected. Admission currently checks actual manager properties, cgroup limits, namespaces, UID, environment, and executable identity, but actual negative-effect probes for host files, sibling processes, credentials, and network have not yet passed. Network namespaces deny worker egress; a reviewed broker-only download/egress route is still required before network-backed installer stages can run.

The host authority fixtures are synthetic contract fixtures. They do not prove the root service, protected IPC installation, actual authority key custody, or target policy enrollment. Linux integration tests in `tests/contracts/test_managed_process.py` have not yet been adapted to the broker-owned root handler or run on an eligible Linux CI host. Native ARM64 and Pi start/stop/parent-death, sibling filesystem/process/network/credential denials remain pending. No task is marked as native acceptance.

## Verification distinction

Static syntax and whitespace checks have passed for the current supervisor changes. The meaningful Linux negative-effect suite, CI result, root custodian integration, protected profile enrollment, and Pi evidence must be recorded separately before enabling any affected capability. A failed probe leaves that capability disabled with its exact retry/resume action.
