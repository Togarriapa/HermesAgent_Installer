"""Typed consumers for root-issued managed native-process evidence.

This module contains no local process discovery. Process identities and child
membership are accepted only from the fixed host AuthorityClient effect.
"""
from __future__ import annotations

import json
import math
import os
import re
from dataclasses import dataclass
from typing import Any, Callable, Mapping

from ..authority.client import AuthorityClient, canonical_bytes, canonical_digest
from ..authority.types import AuthorityDenied, BrokeredEffectResponse


@dataclass(frozen=True, slots=True)
class InspectedProcess:
    member_id: str
    parent_member_id: str | None
    kernel_uid: int
    pidfd_identity: str
    starttime: int
    exe_device: int
    exe_inode: int
    exe_sha256: str
    cgroup_identity: str
    role: str
    sandbox_attestation: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class ProcessInspectionReceipt:
    process_id: str
    generation: str
    profile_id: str
    cgroup_identity: str
    observation_monotonic: float
    expires_monotonic: float
    processes: tuple[InspectedProcess, ...]
    receipt_id: str


def _text(value: Any, name: str, *, maximum: int = 256) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum or "\x00" in value:
        raise AuthorityDenied("process.inspect", f"root inspection {name} is malformed")
    return value


def _integer(value: Any, name: str, *, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise AuthorityDenied("process.inspect", f"root inspection {name} is malformed")
    return value


def parse_process_inspection(value: Any, *, receipt_id: str,
                             process_id: str, generation: str,
                             profile_id: str, now_monotonic: float) -> ProcessInspectionReceipt:
    """Validate the exact HI10 receipt; never accept client-supplied PID/path data."""
    required = {
        "schema", "process_id", "generation", "profile_id", "cgroup_identity",
        "observation_monotonic", "expires_monotonic", "complete", "processes",
    }
    if not isinstance(value, dict) or set(value) != required or value.get("schema") != 1:
        raise AuthorityDenied("process.inspect", "root inspection receipt schema is invalid")
    if (value["process_id"] != process_id or value["generation"] != generation
            or value["profile_id"] != profile_id or value["complete"] is not True):
        raise AuthorityDenied("process.inspect", "root inspection does not bind the live enrolled process")
    observed, expires = value["observation_monotonic"], value["expires_monotonic"]
    if (isinstance(observed, bool) or not isinstance(observed, (float, int))
            or isinstance(expires, bool) or not isinstance(expires, (float, int))
            or not math.isfinite(observed) or not math.isfinite(expires)
            or observed > now_monotonic or expires <= now_monotonic or expires <= observed
            or expires - observed > 30):
        raise AuthorityDenied("process.inspect", "root inspection receipt is expired or outside its bound")
    raw_processes = value["processes"]
    if not isinstance(raw_processes, list) or not 1 <= len(raw_processes) <= 128:
        raise AuthorityDenied("process.inspect", "root inspection process set is incomplete or oversized")
    member_fields = {
        "opaque_member_id", "parent_member_id", "kernel_uid", "pidfd_identity",
        "starttime", "exe_device", "exe_inode", "exe_sha256", "cgroup_identity",
        "role", "sandbox_attestation",
    }
    members: list[InspectedProcess] = []
    seen: set[str] = set()
    for row in raw_processes:
        if not isinstance(row, dict) or set(row) != member_fields:
            raise AuthorityDenied("process.inspect", "root inspection member fields are invalid")
        member_id = _text(row["opaque_member_id"], "member identity")
        parent_id = row["parent_member_id"]
        if parent_id is not None:
            parent_id = _text(parent_id, "parent identity")
        digest = row["exe_sha256"]
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise AuthorityDenied("process.inspect", "root inspection executable pin is malformed")
        sandbox = row["sandbox_attestation"]
        attestation_fields = {
            "schema", "verified", "role", "artifact_verified", "parent_chain_verified",
            "kernel_uid", "cgroup_identity", "namespace_identity", "seccomp_mode",
            "no_new_privs", "forbidden_flags_present", "relaunch_monitor_verified",
            "window_denial_verified", "policy_manifest_sha256", "native_generation",
            "observation_monotonic", "expires_monotonic", "evidence_refs",
        }
        if not isinstance(sandbox, dict) or set(sandbox) != attestation_fields:
            raise AuthorityDenied("process.inspect", "root inspection sandbox evidence is malformed")
        for flag in ("verified", "artifact_verified", "parent_chain_verified", "no_new_privs",
                     "forbidden_flags_present", "relaunch_monitor_verified", "window_denial_verified"):
            if type(sandbox[flag]) is not bool:
                raise AuthorityDenied("process.inspect", "root inspection sandbox flags are malformed")
        if (sandbox["schema"] != 1 or type(sandbox["kernel_uid"]) is not int
                or type(sandbox["seccomp_mode"]) is not int
                or not isinstance(sandbox["evidence_refs"], list)
                or len(sandbox["evidence_refs"]) > 16
                or any(not isinstance(ref, str) or not ref or len(ref) > 128 for ref in sandbox["evidence_refs"])):
            raise AuthorityDenied("process.inspect", "root inspection sandbox attestation values are malformed")
        for key in ("role", "cgroup_identity", "namespace_identity", "native_generation"):
            _text(sandbox[key], "sandbox " + key)
        if (sandbox["role"] != row["role"] or sandbox["kernel_uid"] != row["kernel_uid"]
                or sandbox["cgroup_identity"] != row["cgroup_identity"]
                or sandbox["native_generation"] != generation
                or sandbox["verified"] is not True or sandbox["artifact_verified"] is not True
                or sandbox["parent_chain_verified"] is not True
                or sandbox["forbidden_flags_present"] is not False):
            raise AuthorityDenied("process.inspect", "root inspection role attestation is incomplete or mismatched")
        policy_digest = sandbox["policy_manifest_sha256"]
        if not isinstance(policy_digest, str) or not re.fullmatch(r"[0-9a-f]{64}", policy_digest):
            raise AuthorityDenied("process.inspect", "root inspection policy manifest pin is malformed")
        observed, expires = sandbox["observation_monotonic"], sandbox["expires_monotonic"]
        if (isinstance(observed, bool) or not isinstance(observed, (int, float))
                or isinstance(expires, bool) or not isinstance(expires, (int, float))
                or not math.isfinite(observed) or not math.isfinite(expires)
                or observed > now_monotonic or expires <= now_monotonic
                or expires <= observed or expires - observed > 30
                or expires > float(value["expires_monotonic"])):
            raise AuthorityDenied("process.inspect", "root inspection sandbox attestation lifetime is malformed")
        if any(not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", ref) for ref in sandbox["evidence_refs"]):
            raise AuthorityDenied("process.inspect", "root inspection evidence references are not opaque identifiers")
        if member_id in seen:
            raise AuthorityDenied("process.inspect", "root inspection has duplicate process identities")
        seen.add(member_id)
        members.append(InspectedProcess(
            member_id, parent_id, _integer(row["kernel_uid"], "UID", minimum=1),
            _text(row["pidfd_identity"], "pidfd identity"),
            _integer(row["starttime"], "start time", minimum=1),
            _integer(row["exe_device"], "executable device"),
            _integer(row["exe_inode"], "executable inode", minimum=1), digest,
            _text(row["cgroup_identity"], "cgroup identity"),
            _text(row["role"], "process role", maximum=64), dict(sandbox),
        ))
    for member in members:
        if member.parent_member_id is not None and member.parent_member_id not in seen:
            raise AuthorityDenied("process.inspect", "root inspection parent chain is incomplete")
    # The graph must be acyclic. A forged/corrupt cycle cannot prove lineage.
    parents = {member.member_id: member.parent_member_id for member in members}
    for member_id in parents:
        chain: set[str] = set()
        current: str | None = member_id
        while current is not None:
            if current in chain:
                raise AuthorityDenied("process.inspect", "root inspection parent chain is cyclic")
            chain.add(current)
            current = parents.get(current)
    return ProcessInspectionReceipt(
        process_id, generation, profile_id,
        _text(value["cgroup_identity"], "cgroup identity"), float(observed),
        float(expires), tuple(members), _text(receipt_id, "receipt ID"),
    )


def inspect_managed_process(authority: AuthorityClient, *, process_id: str,
                            generation: str, profile_id: str,
                            timeout: float = 5.0,
                            cancelled: Callable[[], bool] | None = None) -> ProcessInspectionReceipt:
    """Request HI10 through a one-use, exact-digest root effect.

    If this version of the installed authority has not enrolled the fixed
    operation/handler, the request is denied before any local process probe.
    """
    if type(authority) is not AuthorityClient:
        raise AuthorityDenied("process.inspect", "the installed root AuthorityClient is required")
    _text(process_id, "process ID")
    _text(generation, "generation")
    _text(profile_id, "profile ID")
    payload = {"schema": 1, "process_id": process_id, "generation": generation}
    encoded = canonical_bytes(payload)
    digest = canonical_digest(encoded)
    target = f"{profile_id}:inspect"
    context = authority.context(
        purpose="hermes-process-control", intent="inspect-managed-desktop-process",
        operation="process.inspect", final_payload_digest=digest, lease_seconds=timeout,
    )
    if (context.operation != "process.inspect" or context.profile_id != profile_id
            or context.uid != os.geteuid()
            or "hermes-process-control" not in context.capabilities
            or context.final_payload_digest != digest):
        raise AuthorityDenied("process.inspect", "host context does not bind the exact inspection request")
    grant = authority.authorize_effect(
        context, capability="hermes-process-control", target=target,
        request_digest=digest, retry_index=0,
    )
    if (grant.operation != "process.inspect" or grant.capability != "hermes-process-control"
            or grant.target != target
            or grant.request_digest != digest or grant.retry_index != 0):
        raise AuthorityDenied("process.inspect", "host grant does not bind the exact inspection request")
    inspect_effect = getattr(authority, "inspect_process", None)
    if not callable(inspect_effect):
        raise AuthorityDenied("process.inspect", "the root process inspector is not installed")
    response = inspect_effect(
        grant, target=target, process_id=process_id, generation=generation,
        timeout=timeout, cancelled=cancelled,
    )
    if (type(response) is not BrokeredEffectResponse or response.status != 200
            or not isinstance(response.body, bytes) or len(response.body) > 256 * 1024
            or not isinstance(response.receipt_id, str) or not response.receipt_id):
        raise AuthorityDenied("process.inspect", "root process inspection was denied or exceeded its bound")
    try:
        document = json.loads(response.body)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise AuthorityDenied("process.inspect", "root process inspection receipt is malformed") from None
    return parse_process_inspection(
        document, receipt_id=response.receipt_id, process_id=process_id,
        generation=generation, profile_id=profile_id,
        now_monotonic=authority.monotonic(),
    )
