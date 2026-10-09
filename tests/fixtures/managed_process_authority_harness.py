#!/usr/bin/env python3
"""Unprivileged selection-only client for the disposable root custody CI.

The profile executable, argv, script refs, cwd, environment and limits are all
root-enrolled in the AuthorityService fixture. This process sends only the
opaque enrollment/generation/operation selection and bounded typed params.
"""
from __future__ import annotations

import asyncio
import base64
import json
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from hermes_installer.authority.client import AuthorityClient, canonical_bytes, canonical_digest


async def main() -> None:
    request = json.load(sys.stdin)
    client = AuthorityClient.for_current_process(timeout=10)
    enrollment_id = request["enrollment_id"]
    generation = request["generation"]
    operation_id = request["operation_id"]
    parameters = request["parameters"]
    start_payload = canonical_bytes({"schema": 1, "enrollment_id": enrollment_id,
                                     "generation": generation, "operation_id": operation_id,
                                     "parameters": parameters})
    start_digest = canonical_digest(start_payload)
    start_context = client.context(
        purpose="custody-kernel-ci", intent="launch-enrolled-kernel-probe",
        operation="process.start", final_payload_digest=start_digest,
        trace_id="ci-trace-" + generation[-12:],
        lease_seconds=float(request.get("startup_timeout", 12)),
    )
    start_target = "hermes-profile-invoke:" + start_context.profile_id + ":operation"
    start_grant = client.authorize_effect(
        start_context, capability="hermes-profile-invoke", target=start_target,
        request_digest=start_digest, retry_index=0,
    )
    try:
        response = client.process_start_operation(
            start_grant, enrollment_id=enrollment_id, generation=generation,
            operation_id=operation_id, parameters=parameters,
            timeout=max(5.0, float(request.get("startup_timeout", 12))),
        )
        if response.status != 200:
            raise RuntimeError("root process.start denied")
        started = json.loads(response.body.decode("utf-8", "strict"))
    except Exception as exc:
        if request.get("expect_denial") is True:
            print(json.dumps({"event": "denied", "error_type": type(exc).__name__}), flush=True)
            return
        raise

    process_id = started["process_id"]
    if operation_id == "parent-death":
        print(json.dumps({"event": "started", **started}, sort_keys=True), flush=True)
        await asyncio.Event().wait()

    async def control(operation: str, fields: dict) -> dict:
        response = client.process_control_operation(
            operation, process_id=process_id, generation=generation,
            fields=fields, timeout=5.0,
        )
        return {"schema": response.schema, "process_id": response.process_id,
                "generation": response.generation, "operation": response.operation,
                "state": response.state, "result": dict(response.result),
                "expires_monotonic": response.expires_monotonic}

    inspection = await control("process.inspect", {})
    inspection.update(inspection["result"])
    members = inspection.get("processes", [])
    main_members = [member for member in members if member.get("role") == "main"]
    main_attestation = main_members[0].get("sandbox_attestation", {}) if main_members else {}
    if (inspection.get("process_id") != process_id
            or inspection.get("generation") != generation
            or not inspection.get("complete")
            or not main_members
            or main_attestation.get("kernel_uid") != os.getuid()
            or main_attestation.get("cgroup_identity") != started.get("cgroup")
            or main_attestation.get("namespace_identity") != (
                f"mnt:{started.get('mount_namespace_inode')};net:{started.get('network_namespace_inode')}"
            )
            or main_attestation.get("seccomp_mode") != 2
            or main_attestation.get("no_new_privs") is not True
            or main_attestation.get("forbidden_flags_present") is not False
            or any(member.get("role") == "main" for member in members if member not in main_members)
            or any("pid" in member or "argv" in member or "path" in member
                   for member in members)):
        raise RuntimeError("root process inspection returned incomplete or over-disclosed evidence")
    print(json.dumps({"event": "started", **started, "inspection": inspection}, sort_keys=True), flush=True)

    async def read_line(stream: str, deadline_seconds: float) -> bytes:
        deadline = time.monotonic() + deadline_seconds
        cursor = int(started["stdout_cursor"] if stream == "stdout" else started["stderr_cursor"])
        chunks = bytearray()
        while time.monotonic() < deadline and len(chunks) < 65536:
            value = {"stream": stream,
                     "maximum_bytes": min(65536 - len(chunks), 65536)}
            read = await control("process.read", value)
            data = base64.b64decode(read["result"]["data_bytes"], validate=True)
            if len(data) > 65536 - len(chunks):
                raise RuntimeError("root stream byte bound regressed")
            chunks.extend(data)
            if b"\n" in chunks or read["result"]["eof"]:
                break
            await asyncio.sleep(.05)
        return bytes(chunks)

    stdout = await read_line("stdout", 8.0)
    stderr = await read_line("stderr", 1.5)
    stopped = await control("process.stop", {"reason": "shutdown", "grace_seconds": 5})
    print(json.dumps({"event": "stopped", "stdout": stdout.decode("utf-8", "strict"),
                      "stderr": stderr.decode("utf-8", "strict"),
                      "stdout_complete": b"\n" in stdout,
                      "process_id": process_id, "generation": generation,
                      "pid": started["pid"], "cgroup": started["cgroup"],
                      "uid": started["uid"],
                      "executable_device": started["executable_device"],
                      "executable_inode": started["executable_inode"],
                      "mount_namespace_inode": started["mount_namespace_inode"],
                      "network_namespace_inode": started["network_namespace_inode"],
                      "kernel_limits": started.get("kernel_limits", {}),
                      "cleanup_verified": stopped.get("result", {}).get("closed") is True}, sort_keys=True), flush=True)


if __name__ == "__main__":
    asyncio.run(main())
