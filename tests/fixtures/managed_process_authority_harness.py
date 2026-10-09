#!/usr/bin/env python3
"""Unprivileged client for the disposable root AuthorityService CI harness.

This fixture carries no credentials. The enclosing test owns a short-lived
root broker, one dedicated non-login UID, and the exact temporary profile tree.
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from hermes_installer.authority.client import (
    AuthorityClient, canonical_digest, canonical_profile_target, profile_launch_envelope,
)
from hermes_installer.managed_process import ManagedProcessSpec, ManagedProcessSupervisor
from hermes_installer.state import Journal, OwnedRoot


async def main() -> None:
    request = json.load(sys.stdin)
    profile_id = request["profile_id"]
    data_root = Path(request["data_root"])
    executable = Path(request["executable"])
    artifact_root = Path(request["artifact_root"])
    owned = OwnedRoot(data_root)
    owned.ensure()
    cwd = owned.path("work")
    cwd.mkdir(mode=0o700, exist_ok=True)
    journal = Journal(owned.path("journal.sqlite"))
    client = AuthorityClient.for_current_process(timeout=10)
    argv = tuple(request.get("argv_override", (str(executable), request["artifact_ref"])))
    target = canonical_profile_target(profile_id, executable, data_root)
    launch = profile_launch_envelope(
        target=target, profile_id=profile_id, executable=executable,
        artifact_sha256=request["artifact_sha256"], artifact_root=artifact_root,
        cwd=cwd, data_root=data_root, argv=argv,
        env_allowlist=request["environment"], child_artifact_refs=request["child_artifact_refs"],
        max_lifetime_seconds=60, max_output_bytes=65536, stdin_mode="closed",
    )
    payload_digest = canonical_digest(launch)
    context = client.context(
        purpose="custody-kernel-ci", intent="launch-controlled-kernel-probe",
        trace_id=request["trace_id"], lease_seconds=60,
        final_payload_digest=payload_digest,
    )
    grant = client.authorize_effect(
        context, capability="hermes-profile-invoke", target=target,
        request_digest=payload_digest, retry_index=0,
    )
    spec = ManagedProcessSpec(
        executable=executable, argv=argv, artifact_sha256=request["artifact_sha256"],
        artifact_root=artifact_root, owned_root=owned, cwd=cwd, data_root=data_root,
        env_allowlist=request["environment"], journal_operation=request["operation_id"],
        journal=journal, service_identity="ci-kernel-custody", service_user=request["service_user"],
        startup_deadline_monotonic=time.monotonic() + float(request.get("startup_timeout", 12)),
        max_lifetime_seconds=60, profile_id=profile_id,
        child_artifact_refs=request["child_artifact_refs"],
        authority_context=context, effect_authorization=grant,
    )
    try:
        handle = await ManagedProcessSupervisor(client).start(spec)
    except Exception as exc:
        if request.get("expect_denial") is True:
            print(json.dumps({"event": "denied", "error_type": type(exc).__name__}), flush=True)
            return
        raise
    print(json.dumps({"event": "started", "process_id": handle.identity.process_id,
                      "pid": handle.identity.pid, "cgroup": handle.identity.cgroup,
                      "generation": handle.generation}), flush=True)
    if request["mode"] == "parent-death":
        await asyncio.Event().wait()
    stdout = await handle.read(65536, 5.0, stream="stdout")
    stderr = await handle.read(65536, 1.0, stream="stderr")
    await handle.stop("Linux custody integration probe", timeout=8)
    print(json.dumps({"event": "stopped", "stdout": stdout.decode("utf-8", "strict"),
                      "stderr": stderr.decode("utf-8", "strict"),
                      "process_id": handle.identity.process_id,
                      "cgroup": handle.identity.cgroup,
                      "uid": handle.identity.uid,
                      "generation": handle.generation,
                      "executable_device": handle.identity.executable_device,
                      "executable_inode": handle.identity.executable_inode,
                      "mount_namespace_inode": handle.identity.mount_namespace_inode,
                      "network_namespace_inode": handle.identity.network_namespace_inode,
                      "kernel_limits": dict(handle.identity.kernel_limits or {}),
                      "cleanup_verified": handle._closed}), flush=True)


if __name__ == "__main__":
    asyncio.run(main())
