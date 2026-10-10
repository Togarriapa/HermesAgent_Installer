"""Supervised, one-use authority listener activation (HI-T187).

The setup actor and the long-running authority daemon are different processes.
This module joins them through a root-owned pathname SOCK_SEQPACKET channel,
the kernel's peer credentials, a systemd MainPID observation, and a single
SCM_RIGHTS transfer of the already-bound listener.  It never treats UID 0 or
an in-process socketpair as a process identity.
"""
from __future__ import annotations

import array
import base64
import fcntl
import hashlib
import json
import math
import os
import re
import secrets
import socket
import stat
import struct
import subprocess
import time
from dataclasses import dataclass, field, replace
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping

from .types import AuthorityDenied

_UNIT = "hermes-installer-authority.service"
_UNIT_FILE = Path("/etc/systemd/system/hermes-installer-authority.service")
_CONTROL_ROOT = Path("/run/hermes-installer/listener-activation")
_AUTHORITY_SOCKET_ROOT = Path("/run/hermes-installer/authority")
_RECORD_FIELDS = frozenset({
    "schema", "activation_id", "setup_session_id", "transaction_handle",
    "prepared_endpoint_receipt_handle", "prepared_endpoint_receipt_sha256",
    "publication_receipt_handle", "publication_sha256", "service_generation_digest",
    "profile_id", "service_enrollment_id", "service_uid", "service_gid",
    "socket_device", "socket_inode", "setup_pid", "setup_start_ticks",
    "setup_interpreter_sha256", "setup_launcher_sha256", "setup_actor_binding_sha256",
    "daemon_unit_id", "daemon_unit_fragment_sha256", "daemon_invocation_id",
    "daemon_pid", "daemon_start_ticks", "daemon_cgroup", "daemon_interpreter_sha256",
    "daemon_launcher_sha256", "release_deployment_receipt_sha256",
    "release_closure_manifest_sha256", "activation_root_device", "activation_root_inode",
    "activation_socket_device", "activation_socket_inode", "nonce_sha256",
    "issued_monotonic", "expires_monotonic", "state",
})
_MESSAGE_FIELDS = frozenset({
    "schema", "operation", "activation_id", "nonce", "activation_record_sha256",
    "publication_receipt_handle", "publication_sha256", "service_generation_digest",
    "endpoint_receipt_sha256", "socket_device", "socket_inode",
})
_HEALTH_REQUEST_FIELDS = frozenset({
    "schema", "operation", "intent_handle", "intent_sha256", "nonce",
})
_HEALTH_ACCEPTED_FIELDS = frozenset({
    "schema", "operation", "intent_handle", "intent_sha256",
})
_HEALTH_COMPLETED_FIELDS = frozenset({
    "schema", "operation", "intent_handle", "completion_handle", "completion_sha256",
})
_HEALTH_INTENT_FIELDS = frozenset({
    "schema", "purpose", "intent_handle", "nonce_sha256",
    "setup_actor_witness_handle", "setup_actor_witness_sha256", "activation_id",
    "daemon_unit_id", "daemon_invocation_id", "committed_transaction_id",
    "bootstrap_transaction_handle", "generation_id", "service_generation_digest",
    "publication_receipt_handle", "publication_sha256", "profile_id", "enrollment_id",
    "source_choice_selection_handle", "source_choice_signed_record_sha256",
    "source_choice_epoch", "source_choice_revocation_epoch", "health_definition_sha256",
    "issued_monotonic", "expires_monotonic",
})
_HEALTH_JOURNAL_FIELDS = frozenset({
    "schema", "activation_id", "intent_body", "intent_sha256", "state",
    "accepted_monotonic", "completion_handle", "completion_sha256",
})
_HEALTH_JOURNAL_EVIDENCE_FIELDS = frozenset({
    "health_receipt_body", "health_receipt_sha256", "health_event_proof",
})
_HEALTH_COMPLETION_FIELDS = frozenset({
    "schema", "completion_handle", "intent_handle", "intent_sha256",
    "committed_transaction_id", "bootstrap_transaction_handle", "generation_id",
    "service_generation_digest", "publication_receipt_handle", "publication_sha256",
    "source_choice_signed_record_sha256", "health_definition_sha256",
    "health_receipt_handle", "health_receipt_sha256", "result_schema_id", "result_sha256",
    "parent_closure_digest", "terminal_receipt_handle", "daemon_unit_id",
    "daemon_invocation_id", "daemon_pid", "daemon_start_ticks",
    "daemon_actor_witness_sha256", "health_run_proof_sha256", "completed_monotonic",
})
_MAX_MESSAGE = 8192
_MAX_TTL = 30.0
_HEX32 = re.compile(r"[0-9a-f]{32}\Z")
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_SETUP_LAUNCHER_SOURCE = (
    "import pathlib\n"
    "import sys\n"
    "launcher = pathlib.Path(sys.argv.pop(1)).resolve(strict=True)\n"
    "sys.argv[0] = str(launcher)\n"
    "sys.path.insert(0, str(launcher.parent.parent / (\"lib/python\" if (launcher.parent.parent / \"lib/python\").is_dir() else \"src\")))\n"
    "from hermes_installer.root_setup import main\n"
    "raise SystemExit(main())\n"
)
_OPEN_DIR = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
_HEALTH_LEDGER = "native-health-intents"
_HEALTH_LEDGER_LOCK = ".ledger.lock"
_HEALTH_LEDGER_FILE = "intent.json"
_HEALTH_LEDGER_SEAL = object()


class ListenerActivationUnavailable(AuthorityDenied):
    """The installed root daemon or exact listener handoff is not current."""

    def __init__(self, message: str):
        super().__init__("authority.activation", message)


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _activation_generation_rows(generation: Any, publication: Any, endpoint: Any
                               ) -> tuple[Mapping[str, Any], Mapping[str, Any],
                                          Mapping[str, Any], Mapping[str, Any]]:
    """Check the producer's actual five-catalog field names and singleton joins."""
    from .native_worker_service_generation import RootPreparedNativeServiceGeneration
    if (type(generation) is not RootPreparedNativeServiceGeneration
            or generation.generation_id != publication.generation_id
            or len(generation.native_worker_runtime_records) != 1
            or len(generation.active_network_generation_records) != 1
            or len(generation.process_profile_records) != 1
            or len(generation.service_records) != 1):
        raise ValueError("selected native generation is not a current closed singleton")
    runtime_row = generation.native_worker_runtime_records[0]
    active_row = generation.active_network_generation_records[0]
    profile_row = generation.process_profile_records[0]
    service_row = generation.service_records[0]
    if not all(isinstance(row, Mapping) for row in (
            runtime_row, active_row, profile_row, service_row)):
        raise ValueError("selected native generation rows are malformed")
    if (active_row.get("worker_runtime_record_id") != runtime_row.get("id")
            or active_row.get("worker_runtime_record_sha256") != _digest(dict(runtime_row))
            or active_row.get("process_profile_id") != endpoint.profile_id
            or profile_row.get("profile_id", profile_row.get("id")) != endpoint.profile_id
            or service_row.get("profile_id") != endpoint.profile_id
            or service_row.get("service_uid", service_row.get("owner_uid")) != endpoint.service_uid
            or service_row.get("service_gid", service_row.get("owner_gid")) != endpoint.service_gid
            or runtime_row.get("profile_id") != endpoint.profile_id
            or runtime_row.get("generation_id") != generation.generation_id):
        raise ValueError("committed worker runtime, service, profile, and endpoint rows differ")
    return runtime_row, active_row, profile_row, service_row


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _health_identifier(value: Any) -> bool:
    return type(value) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", value) is not None


def _validate_health_receipt_evidence(value: Mapping[str, Any],
                                      completion: Mapping[str, Any]) -> None:
    """Validate the persisted original observer receipt and exact event closure."""
    from .native_health_observer import (
        RootNativeHealthEvent, RootNativeHealthReceipt, _validate_event_ancestry,
    )

    receipt_body = value.get("health_receipt_body")
    receipt_sha = value.get("health_receipt_sha256")
    proof_rows = value.get("health_event_proof")
    receipt_fields = set(RootNativeHealthReceipt.__dataclass_fields__)
    event_fields = set(RootNativeHealthEvent.__dataclass_fields__)
    if (not isinstance(receipt_body, dict) or set(receipt_body) != receipt_fields
            or type(receipt_body.get("schema")) is not int
            or not isinstance(receipt_sha, str) or not _HEX64.fullmatch(receipt_sha)
            or receipt_sha != _digest(receipt_body)
            or receipt_body.get("schema") != 2
            or not isinstance(proof_rows, list) or not 5 <= len(proof_rows) <= 6):
        raise ValueError("durable health receipt evidence has an invalid closed schema")
    receipt = RootNativeHealthReceipt(**receipt_body)
    completion_handles = ("completion_handle", "intent_handle", "publication_receipt_handle",
                         "health_receipt_handle", "terminal_receipt_handle")
    completion_identifiers = ("committed_transaction_id", "bootstrap_transaction_handle",
                              "generation_id", "result_schema_id", "daemon_invocation_id")
    completion_digests = ("intent_sha256", "service_generation_digest", "publication_sha256",
                          "source_choice_signed_record_sha256", "health_definition_sha256",
                          "health_receipt_sha256", "result_sha256", "parent_closure_digest",
                          "daemon_actor_witness_sha256", "health_run_proof_sha256")
    completed_at = completion.get("completed_monotonic")
    if (type(completion.get("schema")) is not int or completion.get("schema") != 2
            or any(type(completion.get(name)) is not str
                   or re.fullmatch(r"[A-Za-z0-9_-]{32,128}", completion[name]) is None
                   for name in completion_handles)
            or any(not _health_identifier(completion.get(name))
                   for name in completion_identifiers)
            or type(completion.get("daemon_unit_id")) is not str
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:@-]{0,255}", completion["daemon_unit_id"]) is None
            or any(type(completion.get(name)) is not str
                   or _HEX64.fullmatch(completion[name]) is None
                   for name in completion_digests)
            or type(completion.get("daemon_pid")) is not int or completion["daemon_pid"] <= 1
            or type(completion.get("daemon_start_ticks")) is not int
            or completion["daemon_start_ticks"] <= 0
            or isinstance(completed_at, bool) or type(completed_at) not in (int, float)
            or not math.isfinite(completed_at)):
        raise ValueError("completed health witness has invalid typed fields")
    if (receipt.status != "passed"
            or completion.get("health_receipt_handle") != receipt.health_receipt_handle
            or completion.get("health_receipt_sha256") != receipt_sha
            or completion.get("committed_transaction_id") != receipt.committed_enrollment_receipt_id
            or completion.get("bootstrap_transaction_handle") != receipt.bootstrap_transaction_handle
            or completion.get("service_generation_digest") != receipt.service_generation_digest
            or completion.get("result_schema_id") != receipt.result_schema_id
            or completion.get("result_sha256") != receipt.result_sha256
            or completion.get("parent_closure_digest") != receipt.parent_closure_digest
            or completion.get("health_run_proof_sha256") != receipt.health_run_proof_sha256
            or completion.get("terminal_receipt_handle") != receipt.terminal_receipt_handle):
        raise ValueError("completion row differs from the retained original health receipt")

    events: list[RootNativeHealthEvent] = []
    for raw in proof_rows:
        if not isinstance(raw, dict) or set(raw) != event_fields:
            raise ValueError("health event proof row differs from the exact event schema")
        row = dict(raw)
        for name in ("causal_parent_event_ids", "source_receipt_handles", "source_receipt_ids"):
            if not isinstance(row.get(name), list):
                raise ValueError("health event ancestry arrays are malformed")
            row[name] = tuple(row[name])
        encoded = row.get("result_bytes")
        if encoded is not None:
            if not isinstance(encoded, str):
                raise ValueError("health event result bytes are not canonical base64 text")
            try:
                decoded = base64.b64decode(encoded, validate=True)
            except Exception:
                raise ValueError("health event result bytes are malformed base64") from None
            if base64.b64encode(decoded).decode("ascii") != encoded:
                raise ValueError("health event result bytes are not canonical base64")
            row["result_bytes"] = decoded
        event = RootNativeHealthEvent(**row)
        if (not _health_identifier(event.event_id)
                or event.event_kind not in {"loader-ready", "native-request", "provider-result",
                                             "tool-invocation", "tool-result", "terminal"}
                or any(not _health_identifier(getattr(event, name)) for name in (
                    "operation_id", "enrollment_id", "profile_id", "process_generation",
                    "process_id", "package_id"))
                or any(not _HEX64.fullmatch(getattr(event, name)) for name in (
                    "service_generation_digest", "compiled_closure_sha256"))
                or (event.parent_closure_digest is not None
                    and not _HEX64.fullmatch(event.parent_closure_digest))
                or type(event.process_pid) is not int or event.process_pid <= 1
                or type(event.process_uid) is not int or event.process_uid <= 0
                or any(isinstance(number, bool) or type(number) not in (int, float)
                       or not math.isfinite(number) for number in (
                           event.observed_monotonic, event.expires_monotonic))
                or event.expires_monotonic <= event.observed_monotonic
                or type(event.cleanup_verified) is not bool
                or any(value is not None and not isinstance(value, str) for value in (
                    event.loader_ready_event_id, event.native_request_event_id,
                    event.provider_result_event_id, event.tool_invocation_event_id,
                    event.tool_result_event_id, event.terminal_receipt_handle,
                    event.result_schema_id, event.loaded_proof_id, event.action_id,
                    event.provider_result_reference, event.invocation_handle,
                    event.terminal_status))):
            raise ValueError("health event proof row has invalid typed values")
        if event.event_kind != "tool-result" and event.result_bytes is not None:
            raise ValueError("only the exact tool-result event may carry result bytes")
        if not _validate_event_ancestry(event):
            raise ValueError("health event does not preserve its actual native source ancestry")
        events.append(event)
    if len({row.event_id for row in events}) != len(events):
        raise ValueError("health event proof rows are duplicated")
    by_kind = {row.event_kind: row for row in events}
    required = {"loader-ready", "native-request", "tool-invocation", "tool-result", "terminal"}
    if receipt.provider_result_event_id is not None:
        required.add("provider-result")
    ordered_kinds = ["loader-ready", "native-request"]
    if receipt.provider_result_event_id is not None:
        ordered_kinds.append("provider-result")
    ordered_kinds.extend(("tool-invocation", "tool-result", "terminal"))
    if set(by_kind) != required or [event.event_kind for event in events] != ordered_kinds:
        raise ValueError("health event proof does not contain the receipt's exact role closure")
    loader, request = by_kind["loader-ready"], by_kind["native-request"]
    invocation, result, terminal = (by_kind["tool-invocation"], by_kind["tool-result"],
                                    by_kind["terminal"])
    provider = by_kind.get("provider-result")
    if (loader.event_id != receipt.loader_ready_event_id
            or request.event_id != receipt.native_request_event_id
            or (provider.event_id if provider else None) != receipt.provider_result_event_id
            or invocation.event_id != receipt.tool_invocation_event_id
            or result.event_id != receipt.tool_result_event_id
            or terminal.terminal_receipt_handle != receipt.terminal_receipt_handle
            or loader.loader_ready_event_id != loader.event_id
            or request.native_request_event_id != request.event_id
            or request.provider_result_event_id != (provider.event_id if provider else None)
            or (provider is not None and (provider.provider_result_event_id != provider.event_id
                                          or provider.native_request_event_id != request.event_id))
            or invocation.tool_invocation_event_id != invocation.event_id
            or invocation.native_request_event_id != request.event_id
            or invocation.provider_result_reference != (provider.event_id if provider else None)
            or result.tool_result_event_id != result.event_id
            or result.tool_invocation_event_id != invocation.event_id
            or result.result_schema_id != receipt.result_schema_id
            or not isinstance(result.result_bytes, bytes)
            or hashlib.sha256(result.result_bytes).hexdigest() != receipt.result_sha256
            or result.invocation_handle != invocation.invocation_handle
            or terminal.event_kind != "terminal" or terminal.terminal_status != "succeeded"
            or terminal.cleanup_verified is not True
            or receipt.parent_closure_digest != result.parent_closure_digest
            or loader.causal_parent_event_ids != ()
            or request.causal_parent_event_ids != (loader.event_id,)
            or (provider is not None and provider.causal_parent_event_ids != (request.event_id,))
            or invocation.causal_parent_event_ids != ((provider.event_id,)
                                                       if provider is not None else (request.event_id,))
            or result.causal_parent_event_ids != (invocation.event_id,)
            or terminal.causal_parent_event_ids != (result.event_id,)):
        raise ValueError("health event proof does not join the original receipt or terminal")
    first = events[0]
    for event in events:
        if ((event.operation_id, event.enrollment_id, event.profile_id,
             event.process_generation, event.service_generation_digest, event.process_id,
             event.process_pid, event.process_uid, event.package_id,
             event.compiled_closure_sha256)
                != (receipt.operation_id, receipt.enrollment_id, receipt.profile_id,
                    receipt.process_generation, receipt.service_generation_digest,
                    receipt.process_id, first.process_pid, first.process_uid,
                    first.package_id, first.compiled_closure_sha256)):
            raise ValueError("health events do not share the retained receipt's process closure")


def _read_proc_start_ticks(proc_root: Path, pid: int) -> int:
    raw = (proc_root / str(pid) / "stat").read_text()
    fields = raw[raw.rfind(")") + 2:].split()
    if len(fields) < 20:
        raise ListenerActivationUnavailable("process start observation is malformed")
    return int(fields[19])


def _read_proc_effective_ids(proc_root: Path, pid: int) -> tuple[int, int]:
    status = (proc_root / str(pid) / "status").read_text()
    uid_line = next(line for line in status.splitlines() if line.startswith("Uid:"))
    gid_line = next(line for line in status.splitlines() if line.startswith("Gid:"))
    return int(uid_line.split()[2]), int(gid_line.split()[2])


def _read_peer_cred(connection: socket.socket) -> tuple[int, int, int]:
    if not hasattr(socket, "SO_PEERCRED"):
        raise ListenerActivationUnavailable("Linux Unix peer credentials are unavailable")
    raw = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    if len(raw) != struct.calcsize("3i"):
        raise ListenerActivationUnavailable("Unix peer credential response is malformed")
    return struct.unpack("3i", raw)


@dataclass(frozen=True, slots=True, repr=False)
class RootAuthorityDaemonUnitSelection:
    """Finite installer-owned systemd launch selection, bound to one release."""
    unit_id: str
    activation_id: str
    unit_file: Path
    unit_file_sha256: str
    launcher_path: Path
    launcher_sha256: str
    interpreter_path: Path
    interpreter_sha256: str
    deployment_receipt_sha256: str
    closure_manifest_sha256: str
    _release: Any = field(repr=False, compare=False)
    _issuer: object = field(repr=False, compare=False)

    def __repr__(self) -> str:
        return "RootAuthorityDaemonUnitSelection(<fixed installer unit>)"


@dataclass(frozen=True, slots=True, repr=False)
class RootAuthorityDaemonPeerObservation:
    """Held PIDFD and concrete systemd/procfs facts for the daemon MainPID."""
    unit_id: str
    invocation_id: str
    pid: int
    uid: int
    gid: int
    start_ticks: int
    cgroup: str
    fragment_path: str
    fragment_sha256: str
    exec_start: str
    environment: tuple[str, ...]
    executable_path: str
    executable_sha256: str
    pidfd: int = field(repr=False, compare=False)
    _issuer: object = field(repr=False, compare=False)

    def __repr__(self) -> str:
        return "RootAuthorityDaemonPeerObservation(<systemd MainPID>)"

    def close(self) -> None:
        try:
            os.close(self.pidfd)
        except OSError:
            pass


class SystemdAuthorityDaemonInspector:
    """Observe only the fixed authority unit and its live root MainPID."""
    _PROPERTIES = ("LoadState", "ActiveState", "MainPID", "InvocationID", "ControlGroup",
                   "FragmentPath", "ExecStart", "Environment", "EnvironmentFiles",
                   "DropInPaths", "User", "Group")

    def __init__(self, *, systemctl: Path = Path("/usr/bin/systemctl"),
                 proc_root: Path = Path("/proc"), run: Any = subprocess.run,
                 euid: Any = os.geteuid, monotonic: Any = time.monotonic):
        self.systemctl, self.proc_root = systemctl, proc_root
        self.run, self.euid, self.monotonic = run, euid, monotonic

    def inspect_authority_daemon(self, selection: RootAuthorityDaemonUnitSelection
                                 ) -> RootAuthorityDaemonPeerObservation:
        if (type(selection) is not RootAuthorityDaemonUnitSelection
                or selection._issuer is not _SELECTION_ISSUER
                or selection.unit_id != _UNIT or not _HEX32.fullmatch(selection.activation_id)
                or self.euid() != 0):
            raise ListenerActivationUnavailable("fixed root authority unit selection is unavailable")
        try:
            result = self.run([str(self.systemctl), "--system", "show", "--no-pager",
                               "--property=" + ",".join(self._PROPERTIES), _UNIT],
                              stdin=subprocess.DEVNULL, capture_output=True, text=True,
                              env={"PATH": "/usr/bin:/bin", "LANG": "C"}, close_fds=True,
                              timeout=3.0, check=False)
        except (OSError, subprocess.TimeoutExpired):
            raise ListenerActivationUnavailable("fixed authority unit could not be observed") from None
        if result.returncode != 0 or len(result.stdout) > 32768:
            raise ListenerActivationUnavailable("fixed authority unit observation failed")
        props: dict[str, str] = {}
        for line in result.stdout.splitlines():
            key, sep, value = line.partition("=")
            if not sep or key not in self._PROPERTIES or key in props:
                raise ListenerActivationUnavailable("fixed authority unit properties are malformed")
            props[key] = value
        if (set(props) != set(self._PROPERTIES) or props["LoadState"] != "loaded"
                or props["ActiveState"] != "active" or props["User"] not in {"root", "0"}
                or props["Group"] not in {"root", "0"} or not props["ControlGroup"].startswith("/")
                or not _HEX32.fullmatch(props["InvocationID"])
                or props["EnvironmentFiles"] not in {"", "{}"}
                or props["DropInPaths"] not in {"", "{}"}
                or set(props["Environment"].split()) != {
                    "HOME=/root", "PATH=/usr/bin:/bin", "LANG=C", "PYTHONNOUSERSITE=1"}
                or not _HEX32.fullmatch(selection.activation_id)
                or props["ExecStart"].count(selection.launcher_path.as_posix()) != 1
                or f"authority-daemon-adopt --activation-id {selection.activation_id}" not in props["ExecStart"]):
            raise ListenerActivationUnavailable("active authority unit differs from its fixed launch recipe")
        pid = int(props["MainPID"] or "0")
        if pid <= 1:
            raise ListenerActivationUnavailable("authority unit has no MainPID")
        pidfd = -1
        try:
            pidfd = os.pidfd_open(pid, 0)
            if self._pidfd_exited(pidfd):
                raise ListenerActivationUnavailable("authority unit MainPID has exited")
            proc = self.proc_root / str(pid)
            start = _read_proc_start_ticks(self.proc_root, pid)
            status = (proc / "status").read_text()
            uid_line = next(x for x in status.splitlines() if x.startswith("Uid:"))
            gid_line = next(x for x in status.splitlines() if x.startswith("Gid:"))
            uid, euid = [int(v) for v in uid_line.split()[1:3]]
            gid, egid = [int(v) for v in gid_line.split()[1:3]]
            cgroups = [x.split("::", 1)[1] for x in (proc / "cgroup").read_text().splitlines() if "::" in x]
            if uid != 0 or euid != 0 or gid != 0 or egid != 0 or cgroups != [props["ControlGroup"]]:
                raise ListenerActivationUnavailable("authority MainPID identity/cgroup differs from manager")
            executable = proc / "exe"
            exe_info = os.stat(executable)
            pinned = selection.interpreter_path.stat(follow_symlinks=False)
            exe_hash = hashlib.sha256(executable.read_bytes()).hexdigest()
            if (os.path.realpath(executable) != str(selection.interpreter_path)
                    or (exe_info.st_dev, exe_info.st_ino) != (pinned.st_dev, pinned.st_ino)
                    or exe_hash != selection.interpreter_sha256
                    or hashlib.sha256(selection.launcher_path.read_bytes()).hexdigest() != selection.launcher_sha256):
                raise ListenerActivationUnavailable("authority MainPID executable or launcher pin changed")
            fragment = Path(props["FragmentPath"])
            if fragment != selection.unit_file or not fragment.is_absolute():
                raise ListenerActivationUnavailable("authority unit fragment is not the installer-owned fixed path")
            fragment_bytes = fragment.read_bytes()
            fragment_stat = fragment.stat(follow_symlinks=False)
            if (not stat.S_ISREG(fragment_stat.st_mode) or fragment_stat.st_uid != 0
                    or fragment_stat.st_mode & 0o022
                    or hashlib.sha256(fragment_bytes).hexdigest() != selection.unit_file_sha256):
                raise ListenerActivationUnavailable("authority unit fragment custody or digest changed")
            if _read_proc_start_ticks(self.proc_root, pid) != start or self._pidfd_exited(pidfd):
                raise ListenerActivationUnavailable("authority MainPID changed during inspection")
            observation = RootAuthorityDaemonPeerObservation(
                _UNIT, props["InvocationID"], pid, uid, gid, start, props["ControlGroup"],
                str(fragment), selection.unit_file_sha256, props["ExecStart"],
                tuple(sorted(x for x in props["Environment"].split() if x)),
                str(selection.interpreter_path), exe_hash, pidfd, selection._issuer)
            pidfd = -1
            return observation
        except ListenerActivationUnavailable:
            raise
        except (OSError, ValueError, StopIteration, IndexError):
            raise ListenerActivationUnavailable("authority MainPID could not be bound to the fixed unit") from None
        finally:
            if pidfd >= 0:
                os.close(pidfd)

    def verify_current(self, observation: RootAuthorityDaemonPeerObservation,
                       selection: RootAuthorityDaemonUnitSelection) -> RootAuthorityDaemonPeerObservation:
        if (type(observation) is not RootAuthorityDaemonPeerObservation
                or observation._issuer is not selection._issuer
                or self._pidfd_exited(observation.pidfd)
                or _read_proc_start_ticks(self.proc_root, observation.pid) != observation.start_ticks):
            raise ListenerActivationUnavailable("authority daemon PIDFD/start-time observation is stale")
        current = self.inspect_authority_daemon(selection)
        try:
            fields = ("unit_id", "invocation_id", "pid", "uid", "gid", "start_ticks", "cgroup",
                      "fragment_path", "fragment_sha256", "exec_start", "environment",
                      "executable_path", "executable_sha256")
            if any(getattr(current, name) != getattr(observation, name) for name in fields):
                raise ListenerActivationUnavailable("authority daemon unit invocation or peer changed")
        finally:
            current.close()
        return observation

    def _pidfd_exited(self, pidfd: int) -> bool:
        import select
        poller = select.poll()
        try:
            poller.register(pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
            return bool(poller.poll(0))
        except (OSError, ValueError):
            return True


_SELECTION_ISSUER = object()
_ACK_SEAL = object()


def _selection_from_release(release: Any, activation_id: str) -> RootAuthorityDaemonUnitSelection:
    from .installer_release import VerifiedInstallerReleaseReceipt
    if (type(release) is not VerifiedInstallerReleaseReceipt or not _HEX32.fullmatch(activation_id)):
        raise ListenerActivationUnavailable("verified release and generated activation ID are required")
    release.verify_current()
    launcher = [row for row in release.files if row.roles == ("launcher",)]
    interpreters = [row for row in release.files if row.roles == ("interpreter",)]
    if len(launcher) != 1 or len(interpreters) != 1:
        raise ListenerActivationUnavailable("installed launcher/interpreter closure is ambiguous")
    launch_path = release.release_root / launcher[0].relative_path
    interpreter_path = release.release_root / interpreters[0].relative_path
    for row in (launcher[0], interpreters[0]):
        fd = release.open_file(row.artifact_id)
        try:
            digest = hashlib.sha256()
            size = 0
            while True:
                chunk = os.read(fd, 128 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                digest.update(chunk)
            if size != row.size_bytes or digest.hexdigest() != row.sha256:
                raise ListenerActivationUnavailable("installed launcher/interpreter held bytes changed")
        finally:
            os.close(fd)
    contents = _unit_contents(launch_path, activation_id)
    return RootAuthorityDaemonUnitSelection(
        _UNIT, activation_id, _UNIT_FILE, hashlib.sha256(contents).hexdigest(), launch_path, launcher[0].sha256,
        interpreter_path, interpreters[0].sha256, release.deployment_receipt_sha256,
        release.closure_manifest_sha256, release, _SELECTION_ISSUER)


def _unit_contents(launcher_path: Path, activation_id: str) -> bytes:
    if (not launcher_path.is_absolute() or "\n" in str(launcher_path) or " " in str(launcher_path)
            or not _HEX32.fullmatch(activation_id)):
        raise ListenerActivationUnavailable("fixed authority unit launch fields are invalid")
    return ("[Unit]\nDescription=Hermes Installer Authority Daemon\nAfter=local-fs.target\n\n"
            "[Service]\nType=exec\nUser=root\nGroup=root\nUMask=0077\n"
            "WorkingDirectory=/\nEnvironment=HOME=/root\nEnvironment=PATH=/usr/bin:/bin\n"
            "Environment=LANG=C\nEnvironment=PYTHONNOUSERSITE=1\n"
            f"ExecStart={launcher_path} authority-daemon-adopt --activation-id {activation_id}\n"
            "KillMode=control-group\nRestart=no\nRuntimeMaxSec=infinity\n"
            "NoNewPrivileges=yes\nPrivateTmp=yes\nProtectSystem=strict\nProtectHome=read-only\n\n"
            "[Install]\nWantedBy=multi-user.target\n").encode("utf-8")


def _install_fixed_unit(selection: RootAuthorityDaemonUnitSelection) -> None:
    if os.geteuid() != 0 or selection._issuer is not _SELECTION_ISSUER:
        raise ListenerActivationUnavailable("only the held installed root setup actor may prepare the daemon unit")
    parent = _UNIT_FILE.parent
    try:
        pinfo = parent.lstat()
        if (not stat.S_ISDIR(pinfo.st_mode) or stat.S_ISLNK(pinfo.st_mode)
                or pinfo.st_uid != 0 or pinfo.st_mode & 0o022):
            raise ListenerActivationUnavailable("system unit directory custody is invalid")
        expected = _unit_contents(selection.launcher_path, selection.activation_id)
        if hashlib.sha256(expected).hexdigest() != selection.unit_file_sha256:
            raise ListenerActivationUnavailable("held unit recipe digest changed")
        try:
            existing = _UNIT_FILE.lstat()
        except FileNotFoundError:
            existing = None
        if existing is not None:
            if (not stat.S_ISREG(existing.st_mode) or stat.S_ISLNK(existing.st_mode)
                    or existing.st_uid != 0 or existing.st_mode & 0o022
                    or hashlib.sha256(_UNIT_FILE.read_bytes()).hexdigest() != selection.unit_file_sha256):
                raise ListenerActivationUnavailable("fixed daemon unit conflicts with an unowned or different file")
            return
        dir_fd = os.open(parent, _OPEN_DIR)
        temporary = ".hermes-installer-authority-" + secrets.token_hex(12)
        fd = -1
        try:
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
                         | getattr(os, "O_CLOEXEC", 0), 0o600, dir_fd=dir_fd)
            os.fchown(fd, 0, 0)
            os.fchmod(fd, 0o644)
            if os.write(fd, expected) != len(expected):
                raise ListenerActivationUnavailable("daemon unit write was short")
            os.fsync(fd)
            os.close(fd)
            fd = -1
            # linkat provides no-replace publication; a raced foreign file is preserved.
            os.link(temporary, _UNIT_FILE.name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd,
                    follow_symlinks=False)
            os.unlink(temporary, dir_fd=dir_fd)
            os.fsync(dir_fd)
        except FileExistsError:
            raise ListenerActivationUnavailable("fixed daemon unit appeared during owned publication") from None
        finally:
            if fd >= 0:
                os.close(fd)
            try:
                os.unlink(temporary, dir_fd=dir_fd)
            except OSError:
                pass
            os.close(dir_fd)
        info = _UNIT_FILE.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
                or stat.S_IMODE(info.st_mode) != 0o644
                or hashlib.sha256(_UNIT_FILE.read_bytes()).hexdigest() != selection.unit_file_sha256):
            raise ListenerActivationUnavailable("published daemon unit failed its inode/content readback")
    except ListenerActivationUnavailable:
        raise
    except OSError:
        raise ListenerActivationUnavailable("fixed daemon unit could not be safely installed") from None


def _systemd_mutation(action: str, *, systemctl: Path = Path("/usr/bin/systemctl")) -> None:
    if action not in {"daemon-reload", "start", "stop"}:
        raise ListenerActivationUnavailable("system manager operation is outside the fixed adapter")
    argv = [str(systemctl), "--system", action]
    if action in {"start", "stop"}:
        argv.append(_UNIT)
    try:
        result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, env={"PATH": "/usr/bin:/bin", "LANG": "C"},
                                close_fds=True, timeout=15.0, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise ListenerActivationUnavailable("fixed authority unit manager operation failed") from None
    if result.returncode != 0:
        raise ListenerActivationUnavailable("fixed authority unit manager operation was rejected")


@dataclass(frozen=True, slots=True, repr=False)
class RootAuthorityDaemonSupervisorAcknowledgment:
    activation_id: str
    activation_record_sha256: str
    endpoint_receipt_handle: str
    socket_device: int
    socket_inode: int
    publication_receipt_handle: str
    publication_sha256: str
    service_generation_digest: str
    nonce_sha256: str
    daemon_invocation_id: str
    peer_pid: int
    peer_start_ticks: int
    _issuer: object = field(repr=False, compare=False)
    _seal: object = field(repr=False, compare=False)

    def __repr__(self) -> str:
        return "RootAuthorityDaemonSupervisorAcknowledgment(<authenticated listener adoption>)"


@dataclass(frozen=True, slots=True, repr=False)
class RootListenerActivationTransaction:
    """Current setup-owned transaction; construction is restricted to supervisor."""
    activation_id: str
    activation_record_sha256: str
    endpoint_receipt_handle: str
    publication_receipt_handle: str
    publication_sha256: str
    service_generation_digest: str
    endpoint_device: int
    endpoint_inode: int
    activation_root_device: int
    activation_root_inode: int
    activation_socket_device: int
    activation_socket_inode: int
    nonce: bytes = field(repr=False, compare=False)
    expires_monotonic: float
    peer: RootAuthorityDaemonPeerObservation = field(repr=False, compare=False)
    _issuer: object = field(repr=False, compare=False)

    def __repr__(self) -> str:
        return "RootListenerActivationTransaction(<root-held one-use transaction>)"


@dataclass(frozen=True, slots=True, repr=False)
class RootActiveAuthorityListenerReceipt:
    """Supervisor-acknowledged transfer of the exact active authority listener."""
    activation_id: str
    activation_record_sha256: str
    endpoint_receipt_handle: str
    publication_receipt_handle: str
    publication_sha256: str
    service_generation_digest: str
    socket_device: int
    socket_inode: int
    daemon_unit_id: str
    daemon_invocation_id: str
    daemon_pid: int
    daemon_start_ticks: int
    adopted_monotonic: float
    expires_monotonic: float
    _issuer: object = field(repr=False, compare=False)

    def __repr__(self) -> str:
        return "RootActiveAuthorityListenerReceipt(<supervised active listener>)"


@dataclass(frozen=True, slots=True, repr=False)
class RootCurrentAuthorityListenerObservation:
    """Fresh observation of an already-adopted listener; not a new adoption."""
    activation_id: str
    activation_record_sha256: str
    endpoint_receipt_handle: str
    publication_receipt_handle: str
    publication_sha256: str
    service_generation_digest: str
    socket_device: int
    socket_inode: int
    daemon_unit_id: str
    daemon_invocation_id: str
    daemon_pid: int
    daemon_start_ticks: int
    observed_monotonic: float
    expires_monotonic: float
    _receipt: RootActiveAuthorityListenerReceipt = field(repr=False, compare=False)
    _issuer: object = field(repr=False, compare=False)

    def __repr__(self) -> str:
        return "RootCurrentAuthorityListenerObservation(<fresh active listener>)"


@dataclass(frozen=True, slots=True, repr=False)
class RootSetupHealthIntent:
    """Opaque setup-issued health request; body remains in the protected journal."""
    intent_handle: str
    intent_sha256: str
    nonce: bytes = field(repr=False, compare=False)
    activation_id: str
    expires_monotonic: float
    _issuer: object = field(repr=False, compare=False)

    def __repr__(self) -> str:
        return "RootSetupHealthIntent(<one-use fixed health request>)"


@dataclass(frozen=True, slots=True, repr=False)
class RootAcceptedHealthIntent:
    """Daemon-side journal receipt for an accepted, peer-bound health request."""
    intent_handle: str
    intent_sha256: str
    body: Mapping[str, Any] = field(repr=False, compare=False)
    accepted_monotonic: float
    activation_id: str
    _journal: Any = field(repr=False, compare=False)
    _seal: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._seal is not _HEALTH_LEDGER_SEAL or type(self._journal) is not RootSetupHealthIntentJournal:
            raise TypeError("accepted health intent is issued by its protected root journal")
        object.__setattr__(self, "body", MappingProxyType(dict(self.body)))

    def __repr__(self) -> str:
        return "RootAcceptedHealthIntent(<protected one-use request>)"


_SETUP_HEALTH_WITNESS_SEAL = object()


@dataclass(frozen=True, slots=True, repr=False)
class RootSetupFunctionalHealthWitness:
    """Setup-side handle to a daemon-completed, current durable health row."""
    intent_handle: str
    completion_handle: str
    completion_sha256: str
    body: Mapping[str, Any] = field(repr=False, compare=False)
    _seal: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._seal is not _SETUP_HEALTH_WITNESS_SEAL:
            raise TypeError("functional health witness is issued by the current setup resolver")
        object.__setattr__(self, "body", MappingProxyType(dict(self.body)))

    def __repr__(self) -> str:
        return "RootSetupFunctionalHealthWitness(<durable daemon completion>)"


class RootSetupHealthIntentJournal:
    """FD-anchored CAS ledger shared by the setup actor and installed daemon."""

    def __init__(self, root_journal: Any, activation_id: str, *, create: bool,
                 receiver: "RootAuthorityListenerActivationReceiver | None" = None,
                 active_receipt: RootActiveAuthorityListenerReceipt | None = None):
        from hermes_installer.protected_enrollment import RootJournalSelection
        if (type(root_journal) is not RootJournalSelection
                or root_journal.root_id != "installer-authority-journal-v1"
                or root_journal.service_generation_digest is None
                or not isinstance(root_journal.path, Path) or not root_journal.path.is_absolute()
                or type(activation_id) is not str or not _HEX32.fullmatch(activation_id)
                or os.geteuid() != 0):
            raise ListenerActivationUnavailable("current protected root journal and activation ID are required")
        self.root_journal = root_journal
        self.activation_id = activation_id
        if ((receiver is None) != (active_receipt is None)
                or (receiver is not None and type(receiver) is not RootAuthorityListenerActivationReceiver)
                or (active_receipt is not None and type(active_receipt) is not RootActiveAuthorityListenerReceipt)):
            raise ListenerActivationUnavailable("daemon health journal requires a complete listener receiver pair")
        self.receiver, self.active_receipt = receiver, active_receipt
        self._root_fd = self._ledger_fd = -1
        self._closed = False
        try:
            root_fd = os.open(root_journal.path, _OPEN_DIR)
            root = os.fstat(root_fd)
            named = root_journal.path.lstat()
            if (not stat.S_ISDIR(root.st_mode) or root.st_uid != 0 or root.st_gid != 0
                    or stat.S_IMODE(root.st_mode) != 0o700
                    or (root.st_dev, root.st_ino) != (root_journal.device, root_journal.inode)
                    or (named.st_dev, named.st_ino) != (root.st_dev, root.st_ino)):
                os.close(root_fd)
                raise ValueError("root journal directory identity changed")
            if create:
                try:
                    os.mkdir(_HEALTH_LEDGER, 0o700, dir_fd=root_fd)
                    os.chown(_HEALTH_LEDGER, 0, 0, dir_fd=root_fd, follow_symlinks=False)
                    os.chmod(_HEALTH_LEDGER, 0o700, dir_fd=root_fd, follow_symlinks=False)
                    os.fsync(root_fd)
                except FileExistsError:
                    pass
            ledger_fd = os.open(_HEALTH_LEDGER, _OPEN_DIR, dir_fd=root_fd)
            ledger = os.fstat(ledger_fd)
            if (not stat.S_ISDIR(ledger.st_mode) or ledger.st_uid != 0 or ledger.st_gid != 0
                    or stat.S_IMODE(ledger.st_mode) != 0o700):
                os.close(ledger_fd)
                os.close(root_fd)
                raise ValueError("health intent ledger directory is not root-private")
            self._root_fd, self._ledger_fd = root_fd, ledger_fd
            self._root_identity = (root.st_dev, root.st_ino)
            self._ledger_identity = (ledger.st_dev, ledger.st_ino)
        except ListenerActivationUnavailable:
            raise
        except Exception:
            self.close()
            raise ListenerActivationUnavailable("protected health intent ledger is unavailable") from None

    @classmethod
    def from_root_journal(cls, root_journal: Any, activation_id: str, *,
                          create: bool = False,
                          receiver: "RootAuthorityListenerActivationReceiver | None" = None,
                          active_receipt: RootActiveAuthorityListenerReceipt | None = None
                          ) -> "RootSetupHealthIntentJournal":
        return cls(root_journal, activation_id, create=create,
                   receiver=receiver, active_receipt=active_receipt)

    def _verify_directories(self) -> None:
        if self._closed or self._root_fd < 0 or self._ledger_fd < 0:
            raise ListenerActivationUnavailable("health intent ledger is closed")
        root = os.fstat(self._root_fd)
        ledger = os.fstat(self._ledger_fd)
        root_name = self.root_journal.path.lstat()
        ledger_name = os.stat(_HEALTH_LEDGER, dir_fd=self._root_fd, follow_symlinks=False)
        if ((root.st_dev, root.st_ino) != self._root_identity
                or (root_name.st_dev, root_name.st_ino) != self._root_identity
                or root.st_uid != 0 or root.st_gid != 0 or stat.S_IMODE(root.st_mode) != 0o700
                or (ledger.st_dev, ledger.st_ino) != self._ledger_identity
                or (ledger_name.st_dev, ledger_name.st_ino) != self._ledger_identity
                or ledger.st_uid != 0 or ledger.st_gid != 0 or stat.S_IMODE(ledger.st_mode) != 0o700):
            raise ListenerActivationUnavailable("health intent ledger directory custody changed")

    def _lock(self) -> int:
        self._verify_directories()
        try:
            fd = os.open(_HEALTH_LEDGER_LOCK,
                         os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
                         | getattr(os, "O_CLOEXEC", 0), 0o600, dir_fd=self._ledger_fd)
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
                    or stat.S_IMODE(info.st_mode) != 0o600):
                os.close(fd)
                raise ValueError("health intent lock is not root-owned mode 0600")
            fcntl.flock(fd, fcntl.LOCK_EX)
            self._verify_directories()
            return fd
        except Exception:
            raise ListenerActivationUnavailable("health intent ledger lock is unavailable") from None

    def _read(self) -> tuple[dict[str, Any], str, tuple[int, int]]:
        self._verify_directories()
        try:
            fd = os.open(_HEALTH_LEDGER_FILE,
                         os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                         | getattr(os, "O_CLOEXEC", 0), dir_fd=self._ledger_fd)
        except OSError:
            raise ListenerActivationUnavailable("health intent record is unavailable") from None
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > _MAX_MESSAGE * 4):
                raise ValueError("health intent record is not a bounded root-owned file")
            raw = bytearray()
            while len(raw) <= _MAX_MESSAGE * 4:
                block = os.read(fd, min(8192, _MAX_MESSAGE * 4 + 1 - len(raw)))
                if not block:
                    break
                raw.extend(block)
            if len(raw) != info.st_size or len(raw) > _MAX_MESSAGE * 4:
                raise ValueError("health intent record changed while reading")
            value = json.loads(bytes(raw).decode("utf-8"), object_pairs_hook=_unique_pairs)
            allowed_fields = {
                _HEALTH_JOURNAL_FIELDS,
                _HEALTH_JOURNAL_FIELDS | {"completion_body"},
                _HEALTH_JOURNAL_FIELDS | {"completion_body"} | _HEALTH_JOURNAL_EVIDENCE_FIELDS,
            }
            if (not isinstance(value, dict)
                    or set(value) not in allowed_fields):
                raise ValueError("health intent journal fields differ from its closed schema")
            body = value.get("intent_body")
            if (value.get("schema") != 1 or value.get("activation_id") != self.activation_id
                    or not isinstance(body, dict) or set(body) != _HEALTH_INTENT_FIELDS
                    or value.get("intent_sha256") != _digest(body)
                    or body.get("purpose") != "root-native-health-intent-v1"
                    or not isinstance(body.get("intent_handle"), str)
                    or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", body["intent_handle"])
                    or body.get("activation_id") != self.activation_id
                    or type(body.get("issued_monotonic")) not in (int, float)
                    or type(body.get("expires_monotonic")) not in (int, float)
                    or not body["issued_monotonic"] < body["expires_monotonic"]
                    or body["expires_monotonic"] - body["issued_monotonic"] > _MAX_TTL
                    or not _HEX64.fullmatch(body.get("nonce_sha256", ""))
                    or value.get("state") not in {"issued", "accepted", "started", "completed", "denied", "cancelled"}):
                raise ValueError("health intent journal digest or state is invalid")
            if value.get("state") == "completed":
                completion = value.get("completion_body")
                if (not isinstance(completion, dict) or set(completion) != _HEALTH_COMPLETION_FIELDS
                        or value.get("completion_handle") != completion.get("completion_handle")
                        or value.get("completion_sha256") != _digest(completion)):
                    raise ValueError("completed health witness differs from its durable CAS row")
                _validate_health_receipt_evidence(value, completion)
            elif _HEALTH_JOURNAL_EVIDENCE_FIELDS.intersection(value):
                raise ValueError("health receipt evidence exists before completion")
            return value, _digest(value), (info.st_dev, info.st_ino)
        except Exception:
            raise ListenerActivationUnavailable("health intent record failed closed validation") from None
        finally:
            os.close(fd)

    def _replace(self, value: Mapping[str, Any], old_identity: tuple[int, int] | None) -> tuple[dict[str, Any], str]:
        self._verify_directories()
        name = ".intent." + secrets.token_hex(16) + ".tmp"
        raw = _canonical(dict(value))
        if len(raw) > _MAX_MESSAGE * 4:
            raise ListenerActivationUnavailable("health intent state exceeds its storage bound")
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                     | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
                     0o600, dir_fd=self._ledger_fd)
        try:
            os.fchown(fd, 0, 0)
            os.fchmod(fd, 0o600)
            offset = 0
            while offset < len(raw):
                count = os.write(fd, raw[offset:])
                if count <= 0:
                    raise OSError("zero-length health intent journal write")
                offset += count
            os.fsync(fd)
        finally:
            os.close(fd)
        try:
            if old_identity is None:
                try:
                    os.stat(_HEALTH_LEDGER_FILE, dir_fd=self._ledger_fd, follow_symlinks=False)
                except FileNotFoundError:
                    pass
                else:
                    raise ListenerActivationUnavailable("health intent already exists for this activation")
            else:
                current, _digest_value, identity = self._read()
                if identity != old_identity:
                    raise ListenerActivationUnavailable("health intent changed during compare-and-swap")
            os.replace(name, _HEALTH_LEDGER_FILE, src_dir_fd=self._ledger_fd,
                       dst_dir_fd=self._ledger_fd)
            os.fsync(self._ledger_fd)
            result, digest, _identity = self._read()
            return result, digest
        finally:
            try:
                os.unlink(name, dir_fd=self._ledger_fd)
            except OSError:
                pass

    def issue(self, body: Mapping[str, Any]) -> tuple[str, str]:
        if (not isinstance(body, Mapping) or set(body) != _HEALTH_INTENT_FIELDS
                or body.get("activation_id") != self.activation_id
                or not isinstance(body.get("intent_handle"), str)
                or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", body["intent_handle"])):
            raise ListenerActivationUnavailable("health intent body differs from the fixed v191 schema")
        lockfd = self._lock()
        try:
            value = {"schema": 1, "activation_id": self.activation_id,
                     "intent_body": dict(body), "intent_sha256": _digest(dict(body)),
                     "state": "issued", "accepted_monotonic": None,
                     "completion_handle": None, "completion_sha256": None}
            _, digest = self._replace(value, None)
            return body["intent_handle"], value["intent_sha256"]
        finally:
            fcntl.flock(lockfd, fcntl.LOCK_UN)
            os.close(lockfd)

    def accept(self, intent_handle: str, intent_sha256: str, nonce: str,
               receiver: "RootAuthorityListenerActivationReceiver",
               active_receipt: RootActiveAuthorityListenerReceipt) -> RootAcceptedHealthIntent:
        if (not isinstance(intent_handle, str) or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", intent_handle)
                or not _HEX64.fullmatch(intent_sha256)
                or not _HEX64.fullmatch(nonce)
                or type(receiver) is not RootAuthorityListenerActivationReceiver):
            raise ListenerActivationUnavailable("health request is not a fixed one-use request")
        observation = receiver.observe_active_current(active_receipt)
        record = receiver._read_current_adopted_record()
        now = time.monotonic()
        if (observation.activation_id != self.activation_id
                or record.get("activation_id") != self.activation_id
                or receiver._setup_peer_pidfd is None
                or receiver._verify_setup_peer(record) != (record["setup_pid"], 0, 0)):
            raise ListenerActivationUnavailable("health setup peer is not the adopted current root actor")
        lockfd = self._lock()
        try:
            value, _old_digest, identity = self._read()
            body = value["intent_body"]
            if (body["intent_handle"] != intent_handle
                    or value["intent_sha256"] != intent_sha256
                    or body["nonce_sha256"] != nonce
                    or body["activation_id"] != self.activation_id
                    or body["daemon_unit_id"] != observation.daemon_unit_id
                    or body["daemon_invocation_id"] != observation.daemon_invocation_id
                    or body["publication_receipt_handle"] != observation.publication_receipt_handle
                    or body["publication_sha256"] != observation.publication_sha256
                    or body["service_generation_digest"] != observation.service_generation_digest
                    or body["setup_actor_witness_sha256"] != record["setup_actor_binding_sha256"]
                    or now < body["issued_monotonic"] or now >= body["expires_monotonic"]
                    or body["expires_monotonic"] - now > _MAX_TTL
                    # The journal transaction id is the durable CAS id; the
                    # activation record carries the setup transaction handle.
                    # They are distinct identifiers and are independently
                    # joined by the daemon health commit resolver.
                    or body["bootstrap_transaction_handle"] != record["transaction_handle"]
                    or body["profile_id"] != record["profile_id"]
                    or body["enrollment_id"] != record["service_enrollment_id"]):
                raise ListenerActivationUnavailable("health intent does not match current adopted source")
            if value["state"] == "issued":
                value["state"] = "accepted"
                value["accepted_monotonic"] = time.monotonic()
                value, _digest_value = self._replace(value, identity)
            elif value["state"] != "accepted":
                raise ListenerActivationUnavailable("health intent was already consumed or cancelled")
            return RootAcceptedHealthIntent(
                intent_handle, intent_sha256, dict(body), value["accepted_monotonic"],
                self.activation_id, self, _HEALTH_LEDGER_SEAL)
        finally:
            fcntl.flock(lockfd, fcntl.LOCK_UN)
            os.close(lockfd)

    def resolve_current_accepted_intent_for_handle(
            self, intent_handle: str, receiver: "RootAuthorityListenerActivationReceiver",
            active_receipt: RootActiveAuthorityListenerReceipt) -> RootAcceptedHealthIntent:
        observation = receiver.observe_active_current(active_receipt)
        value, _digest_value, _identity = self._read()
        body = value["intent_body"]
        if (type(intent_handle) is not str
                or value["state"] not in {"accepted", "started"}
                or body["intent_handle"] != intent_handle
                or body["daemon_unit_id"] != observation.daemon_unit_id
                or body["daemon_invocation_id"] != observation.daemon_invocation_id
                or body["service_generation_digest"] != observation.service_generation_digest
                or body["publication_sha256"] != observation.publication_sha256):
            raise ListenerActivationUnavailable("accepted health intent is no longer current")
        return RootAcceptedHealthIntent(intent_handle, value["intent_sha256"], dict(body),
                                        value["accepted_monotonic"], self.activation_id,
                                        self, _HEALTH_LEDGER_SEAL)

    def mark_started(self, accepted: RootAcceptedHealthIntent) -> RootAcceptedHealthIntent:
        if (type(accepted) is not RootAcceptedHealthIntent or accepted._journal is not self
                or self.receiver is None or self.active_receipt is None):
            raise ListenerActivationUnavailable("health start lacks the daemon's exact accepted intent")
        current = self.resolve_current_accepted_intent_for_handle(
            accepted.intent_handle, self.receiver, self.active_receipt)
        if current.intent_sha256 != accepted.intent_sha256:
            raise ListenerActivationUnavailable("accepted health intent changed before run start")
        lockfd = self._lock()
        try:
            value, _old_digest, identity = self._read()
            if value["state"] == "accepted":
                value["state"] = "started"
                self._replace(value, identity)
            elif value["state"] != "started":
                raise ListenerActivationUnavailable("health intent cannot start from its current state")
            return self.resolve_current_accepted_intent_for_handle(
                accepted.intent_handle, self.receiver, self.active_receipt)
        finally:
            fcntl.flock(lockfd, fcntl.LOCK_UN)
            os.close(lockfd)

    def mark_cancelled(self, accepted: RootAcceptedHealthIntent) -> None:
        """Persist a terminal non-success state after a failed one-use run."""
        if (type(accepted) is not RootAcceptedHealthIntent or accepted._journal is not self
                or self.receiver is None or self.active_receipt is None):
            raise ListenerActivationUnavailable("health cancellation lacks the daemon's exact accepted intent")
        current = self.resolve_current_accepted_intent_for_handle(
            accepted.intent_handle, self.receiver, self.active_receipt,
        )
        if current.intent_sha256 != accepted.intent_sha256:
            raise ListenerActivationUnavailable("health intent changed before cancellation")
        lockfd = self._lock()
        try:
            value, _old_digest, identity = self._read()
            if (value.get("state") not in {"accepted", "started"}
                    or value.get("intent_sha256") != accepted.intent_sha256):
                raise ListenerActivationUnavailable("health intent cannot be cancelled from its current state")
            value["state"] = "cancelled"
            self._replace(value, identity)
        finally:
            fcntl.flock(lockfd, fcntl.LOCK_UN)
            os.close(lockfd)
        self.resolve_current_intent_state(accepted.intent_handle)

    def commit_completion(self, intent_handle: str, intent_sha256: str,
                          completion_body: Mapping[str, Any], *,
                          health_receipt_body: Mapping[str, Any],
                          health_event_proof: tuple[Mapping[str, Any], ...] | list[Mapping[str, Any]]
                          ) -> tuple[str, str]:
        """Commit only an actual consumer-issued closed witness after its own revalidation."""
        if (self.receiver is None or self.active_receipt is None
                or not isinstance(completion_body, Mapping)
                or set(completion_body) != _HEALTH_COMPLETION_FIELDS
                or completion_body.get("schema") != 2
                or completion_body.get("intent_handle") != intent_handle
                or completion_body.get("intent_sha256") != intent_sha256
                or not isinstance(health_receipt_body, Mapping)
                or not isinstance(health_event_proof, (tuple, list))):
            raise ListenerActivationUnavailable("health completion is not the exact daemon-owned witness")
        receipt_body = dict(health_receipt_body)
        event_proof = [dict(row) if isinstance(row, Mapping) else row for row in health_event_proof]
        receipt_sha256 = _digest(receipt_body)
        evidence = {
            "health_receipt_body": receipt_body,
            "health_receipt_sha256": receipt_sha256,
            "health_event_proof": event_proof,
        }
        _validate_health_receipt_evidence(evidence, completion_body)
        accepted = self.resolve_current_accepted_intent_for_handle(
            intent_handle, self.receiver, self.active_receipt)
        lockfd = self._lock()
        try:
            value, _old_digest, identity = self._read()
            intent = value["intent_body"]
            if value["state"] == "completed":
                existing = value["completion_body"]
                if (existing != dict(completion_body)
                        or any(value.get(key) != item for key, item in evidence.items())
                        or value["completion_sha256"] != _digest(existing)):
                    raise ListenerActivationUnavailable("completed health witness conflicts with prior CAS")
                return existing["completion_handle"], value["completion_sha256"]
            if (value["state"] != "started" or value["intent_sha256"] != intent_sha256
                    or accepted.intent_sha256 != intent_sha256
                    or completion_body.get("committed_transaction_id") != intent.get("committed_transaction_id")
                    or completion_body.get("bootstrap_transaction_handle") != intent.get("bootstrap_transaction_handle")
                    or completion_body.get("generation_id") != intent.get("generation_id")
                    or completion_body.get("service_generation_digest") != intent.get("service_generation_digest")
                    or completion_body.get("publication_receipt_handle") != intent.get("publication_receipt_handle")
                    or completion_body.get("publication_sha256") != intent.get("publication_sha256")
                    or completion_body.get("source_choice_signed_record_sha256")
                       != intent.get("source_choice_signed_record_sha256")
                    or completion_body.get("health_definition_sha256") != intent.get("health_definition_sha256")
                    or completion_body.get("daemon_unit_id") != self.active_receipt.daemon_unit_id
                    or completion_body.get("daemon_invocation_id") != self.active_receipt.daemon_invocation_id
                    or completion_body.get("daemon_pid") != self.active_receipt.daemon_pid
                    or completion_body.get("daemon_start_ticks") != self.active_receipt.daemon_start_ticks):
                raise ListenerActivationUnavailable("health witness does not join the current intent and daemon")
            self.receiver.observe_active_current(self.active_receipt)
            value["state"] = "completed"
            value["completion_handle"] = completion_body["completion_handle"]
            value["completion_sha256"] = _digest(dict(completion_body))
            value["completion_body"] = dict(completion_body)
            value.update(evidence)
            self._replace(value, identity)
            return value["completion_handle"], value["completion_sha256"]
        finally:
            fcntl.flock(lockfd, fcntl.LOCK_UN)
            os.close(lockfd)

    def resolve_current_completed_intent(self, intent_handle: str,
                                         completion_handle: str) -> Mapping[str, Any]:
        if self.receiver is not None and self.active_receipt is not None:
            self.receiver.observe_active_current(self.active_receipt)
        lockfd = self._lock()
        try:
            value, _digest_value, _identity = self._read()
            body = value.get("completion_body")
            if (value["state"] != "completed" or not isinstance(body, dict)
                    or body.get("completion_handle") != completion_handle
                    or body.get("intent_handle") != intent_handle
                    or value.get("completion_handle") != completion_handle
                    or value.get("completion_sha256") != _digest(body)):
                raise ListenerActivationUnavailable("daemon-owned functional health witness is not completed")
            return MappingProxyType(dict(body))
        finally:
            fcntl.flock(lockfd, fcntl.LOCK_UN)
            os.close(lockfd)

    def resolve_current_completed_pair(self, intent_handle: str,
                                        completion_handle: str
                                        ) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
        if self.receiver is not None and self.active_receipt is not None:
            self.receiver.observe_active_current(self.active_receipt)
        lockfd = self._lock()
        try:
            value, _digest_value, _identity = self._read()
            intent = value.get("intent_body")
            completion = value.get("completion_body")
            if (value.get("state") != "completed" or not isinstance(intent, dict)
                    or not isinstance(completion, dict)
                    or intent.get("intent_handle") != intent_handle
                    or completion.get("intent_handle") != intent_handle
                    or completion.get("completion_handle") != completion_handle
                    or value.get("completion_handle") != completion_handle
                    or value.get("completion_sha256") != _digest(completion)):
                raise ListenerActivationUnavailable("completed health intent and witness are not a current durable pair")
            return MappingProxyType(dict(intent)), MappingProxyType(dict(completion))
        finally:
            fcntl.flock(lockfd, fcntl.LOCK_UN)
            os.close(lockfd)

    def resolve_current_completed_for_intent(
            self, intent_handle: str
    ) -> tuple[str, str, Mapping[str, Any]]:
        """Reopen the unique completion after a lost reply without rerunning health."""
        if self.receiver is not None and self.active_receipt is not None:
            self.receiver.observe_active_current(self.active_receipt)
        lockfd = self._lock()
        try:
            value, _digest_value, _identity = self._read()
            body = value.get("completion_body")
            if (value.get("state") != "completed" or not isinstance(body, dict)
                    or value.get("intent_body", {}).get("intent_handle") != intent_handle
                    or body.get("intent_handle") != intent_handle
                    or value.get("completion_handle") != body.get("completion_handle")
                    or value.get("completion_sha256") != _digest(body)):
                raise ListenerActivationUnavailable("intent has no unique current completed witness")
            if self.receiver is not None and self.active_receipt is not None:
                self.receiver.observe_active_current(self.active_receipt)
            return (body["completion_handle"], value["completion_sha256"],
                    MappingProxyType(dict(body)))
        finally:
            fcntl.flock(lockfd, fcntl.LOCK_UN)
            os.close(lockfd)

    def resolve_current_intent_state(self, intent_handle: str) -> str:
        """Read only the current durable state; this never authorizes a rerun."""
        if (self.receiver is None or self.active_receipt is None
                or not isinstance(intent_handle, str)
                or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", intent_handle)):
            raise ListenerActivationUnavailable("current daemon intent state is unavailable")
        self.receiver.observe_active_current(self.active_receipt)
        lockfd = self._lock()
        try:
            value, _digest_value, _identity = self._read()
            if value.get("intent_body", {}).get("intent_handle") != intent_handle:
                raise ListenerActivationUnavailable("health intent handle is not the unique current intent")
            state = value.get("state")
            if state not in {"accepted", "started", "completed", "denied", "cancelled"}:
                raise ListenerActivationUnavailable("health intent is not durably accepted")
            self.receiver.observe_active_current(self.active_receipt)
            return state
        finally:
            fcntl.flock(lockfd, fcntl.LOCK_UN)
            os.close(lockfd)

    def resolve_current_completed_health_proof(
            self, intent_handle: str, completion_handle: str
    ) -> tuple[Mapping[str, Any], Mapping[str, Any], tuple[Mapping[str, Any], ...]]:
        """Return the validated completion plus its retained original receipt/events."""
        if self.receiver is not None and self.active_receipt is not None:
            self.receiver.observe_active_current(self.active_receipt)
        lockfd = self._lock()
        try:
            value, _digest_value, _identity = self._read()
            if (value.get("state") != "completed"
                    or value.get("intent_body", {}).get("intent_handle") != intent_handle
                    or value.get("completion_handle") != completion_handle):
                raise ListenerActivationUnavailable("health proof is not the current completed intent")
            completion = value["completion_body"]
            _validate_health_receipt_evidence(value, completion)
            if (completion.get("completion_handle") != completion_handle
                    or value.get("completion_sha256") != _digest(completion)):
                raise ListenerActivationUnavailable("health proof completion digest is stale")
            if self.receiver is not None and self.active_receipt is not None:
                self.receiver.observe_active_current(self.active_receipt)
            return (
                MappingProxyType(dict(completion)),
                MappingProxyType(dict(value["health_receipt_body"])),
                tuple(MappingProxyType(dict(row)) for row in value["health_event_proof"]),
            )
        finally:
            fcntl.flock(lockfd, fcntl.LOCK_UN)
            os.close(lockfd)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        for fd in (self._ledger_fd, self._root_fd):
            if fd >= 0:
                try:
                    os.close(fd)
                except OSError:
                    pass
        self._ledger_fd = self._root_fd = -1

    def __repr__(self) -> str:
        return "RootSetupHealthIntentJournal(<protected root journal>)"


class RootSetupHealthIntentIssuer:
    """Issue one selected, source-bound native-health request from live setup."""

    def __init__(self, binding: Any, held_release: Any, own_actor: Any,
                 activation_supervisor: "RootAuthorityListenerActivationSupervisor"):
        from .bootstrap_runtime_factory import RootSelectedInstallationBinding
        from .installer_release import RootActorObservation, VerifiedInstallerReleaseReceipt
        if (type(binding) is not RootSelectedInstallationBinding
                or type(held_release) is not VerifiedInstallerReleaseReceipt
                or type(own_actor) is not RootActorObservation
                or type(activation_supervisor) is not RootAuthorityListenerActivationSupervisor
                or activation_supervisor.binding is not binding
                or activation_supervisor.held_release is not held_release
                or activation_supervisor.current_actor is not own_actor):
            raise ListenerActivationUnavailable("exact current root setup and activation supervisor are required")
        own_actor.verify_current(held_release)
        binding._session._check_live()
        self.binding, self.held_release, self.own_actor = binding, held_release, own_actor
        self.supervisor = activation_supervisor
        self._issuer = object()
        if (activation_supervisor._health_intent_issuer is not None
                and activation_supervisor._health_intent_issuer is not self):
            raise ListenerActivationUnavailable("activation supervisor already has a health issuer")
        activation_supervisor._health_intent_issuer = self

    @classmethod
    def from_current_root_setup(cls, binding: Any, held_release: Any, own_actor: Any,
                                activation_supervisor: "RootAuthorityListenerActivationSupervisor"
                                ) -> "RootSetupHealthIntentIssuer":
        return cls(binding, held_release, own_actor, activation_supervisor)

    def issue_after_activation(self, endpoint_receipt_handle: str, publication: Any,
                               active_listener_receipt: RootActiveAuthorityListenerReceipt
                               ) -> RootSetupHealthIntent:
        session = self.binding._session
        try:
            session._check_live()
            session._refresh_authorization()
            self.held_release.verify_current()
            self.own_actor.verify_current(self.held_release)
            selection = self.supervisor._selections.get(endpoint_receipt_handle)
            if (selection is None or type(active_listener_receipt) is not RootActiveAuthorityListenerReceipt
                    or active_listener_receipt._issuer is not self.supervisor._issuer
                    or active_listener_receipt.endpoint_receipt_handle != endpoint_receipt_handle):
                raise ValueError("listener activation was not issued from this exact setup selection")
            self.supervisor.verify_current_selection(selection)
            self.supervisor.verify_active_current(active_listener_receipt)
            current_publication = session._resolve_current_active_policy_publication()
            if (current_publication is not publication
                    or current_publication.publication_handle != selection.publication_receipt_handle
                    or current_publication.publication_sha256 != selection.publication_sha256
                    or current_publication.service_generation_digest != selection.service_generation_digest):
                raise ValueError("health intent publication is not the current selected publication")
            active = session._resolve_current_active_enrollment()
            committed = session._transaction.verify_committed_receipt(active, session._authorization)
            producer = session.resolve_current_native_worker_service_generation_producer()
            generation = producer.resolve_current_selected_generation(selection.selection_handle)
            if producer.verify_active_current(generation, committed,
                    generation.native_worker_runtime_records[0]["id"]) is not generation:
                raise ValueError("native worker source generation is no longer current")
            recipe = generation._recipe
            definition = getattr(recipe, "health_definition", None)
            definition_digest = getattr(recipe, "health_definition_sha256", None)
            projection = definition.public_projection() if callable(
                getattr(definition, "public_projection", None)) else None
            if (not isinstance(projection, Mapping)
                    or set(projection) != {"schema", "operation_id", "parameter_schema_id",
                        "parameter_schema_sha256", "health_recipe_artifact_id", "health_recipe_sha256",
                        "health_recipe_receipt_handle", "health_request_artifact_id", "health_request_sha256",
                        "health_request_receipt_handle", "health_seed_artifact_id", "health_seed_sha256",
                        "health_seed_receipt_handle", "health_expected_result_artifact_id",
                        "health_expected_result_sha256", "health_expected_result_receipt_handle",
                        "health_result_schema_id", "health_result_schema_sha256",
                        "health_result_schema_receipt_handle", "health_action_id", "provider_required"}
                    or definition_digest != _digest(dict(projection))):
                raise ValueError("selected signed worker recipe has no exact health source definition")
            native_selection = self.binding.resolve_current_native_policy_selection(
                selection.selection_handle)
            if (not native_selection.selected_worker_recipe_handles
                    or native_selection.selected_worker_recipe_handles != (recipe.receipt_handle,)
                    or native_selection.selected_worker_recipe_digests != (recipe.complete_recipe_sha256,)):
                raise ValueError("health source recipe is not the exact current signed setup choice")
            deadline = session._factory.session_store.current_deadline(session._handle)
            now = time.monotonic()
            expires = min(now + _MAX_TTL, deadline,
                          selection.original_setup_deadline_monotonic,
                          active_listener_receipt.expires_monotonic)
            if expires <= now:
                raise ValueError("original setup authorization deadline has expired")
            intent_handle = secrets.token_urlsafe(36)
            nonce = secrets.token_bytes(32)
            body = {
                "schema": 1, "purpose": "root-native-health-intent-v1",
                "intent_handle": intent_handle,
                "nonce_sha256": hashlib.sha256(nonce).hexdigest(),
                "setup_actor_witness_handle": session._handle.session_id,
                "setup_actor_witness_sha256": _digest({
                    "pid": self.own_actor.pid, "uid": self.own_actor.uid, "gid": self.own_actor.gid,
                    "start_ticks": self.own_actor.start_time,
                    "launcher": list(self.own_actor.launcher),
                    "interpreter": list(self.own_actor.interpreter),
                    "modules": [list(row) for row in self.own_actor.module_origins],
                }),
                "activation_id": active_listener_receipt.activation_id,
                "daemon_unit_id": active_listener_receipt.daemon_unit_id,
                "daemon_invocation_id": active_listener_receipt.daemon_invocation_id,
                "committed_transaction_id": committed.journal_transaction_id,
                "bootstrap_transaction_handle": session._authorization.transaction_handle,
                "generation_id": active.generation_id,
                "service_generation_digest": active.generation_digest,
                "publication_receipt_handle": publication.receipt_handle,
                "publication_sha256": publication.publication_sha256,
                "profile_id": selection.profile_id,
                "enrollment_id": generation.service_records[0]["id"],
                "source_choice_selection_handle": generation.source_choice_selection_handle,
                "source_choice_signed_record_sha256": generation.source_choice_signed_record_sha256,
                "source_choice_epoch": native_selection.choice_epoch,
                "source_choice_revocation_epoch": native_selection.revocation_epoch,
                "health_definition_sha256": definition_digest,
                "issued_monotonic": now, "expires_monotonic": expires,
            }
            journal_selection = session._current_root_journal_selection()
            journal = RootSetupHealthIntentJournal.from_root_journal(
                journal_selection, active_listener_receipt.activation_id, create=True)
            try:
                journal.issue(body)
            finally:
                journal.close()
            return RootSetupHealthIntent(intent_handle, _digest(body), nonce,
                                         active_listener_receipt.activation_id, expires, self._issuer)
        except ListenerActivationUnavailable:
            raise
        except Exception:
            raise ListenerActivationUnavailable(
                "current committed source does not authorize the fixed health intent") from None


class RootSetupFunctionalHealthWitnessResolver:
    """Resolve daemon completion only against the original live setup custody."""

    def __init__(self, binding: Any, held_release: Any, own_actor: Any,
                 supervisor: "RootAuthorityListenerActivationSupervisor"):
        from .bootstrap_runtime_factory import RootSelectedInstallationBinding
        from .installer_release import RootActorObservation, VerifiedInstallerReleaseReceipt
        if (type(binding) is not RootSelectedInstallationBinding
                or type(held_release) is not VerifiedInstallerReleaseReceipt
                or type(own_actor) is not RootActorObservation
                or type(supervisor) is not RootAuthorityListenerActivationSupervisor
                or supervisor.binding is not binding or supervisor.held_release is not held_release
                or supervisor.current_actor is not own_actor):
            raise ListenerActivationUnavailable("exact current setup witness sources are required")
        self.binding, self.held_release = binding, held_release
        self.own_actor, self.supervisor = own_actor, supervisor

    @classmethod
    def from_current_root_setup(cls, binding: Any, held_release: Any,
                                own_actor: Any) -> "RootSetupFunctionalHealthWitnessResolver":
        session = getattr(binding, "_session", None)
        supervisor = getattr(session, "_health_activation_supervisor", None)
        return cls(binding, held_release, own_actor, supervisor)

    def resolve_current_completed_intent(self, intent_handle: str,
                                         completion_handle: str) -> RootSetupFunctionalHealthWitness:
        session = self.binding._session
        try:
            session._check_live()
            self.held_release.verify_current()
            self.own_actor.verify_current(self.held_release)
            if len(self.supervisor._transactions) != 1:
                raise ValueError("setup has no unique retained daemon adoption")
            active_listener = next(iter(self.supervisor._transactions.values()))
            self.supervisor.verify_active_current(active_listener)
            current_publication = session._resolve_current_active_policy_publication()
            active = session._resolve_current_active_enrollment()
            committed = session._transaction.verify_committed_receipt(active, session._authorization)
            producer = session.resolve_current_native_worker_service_generation_producer()
            generation = producer.resolve_current_selected_generation(
                active_listener.publication_receipt_handle)
            if producer.verify_active_current(
                    generation, committed,
                    generation.native_worker_runtime_records[0]["id"]) is not generation:
                raise ValueError("selected health source generation is stale")
            journal = RootSetupHealthIntentJournal.from_root_journal(
                session._current_root_journal_selection(), active_listener.activation_id)
            try:
                intent, witness = journal.resolve_current_completed_pair(intent_handle, completion_handle)
                durable_witness, receipt_body, event_rows = journal.resolve_current_completed_health_proof(
                    intent_handle, completion_handle)
            finally:
                journal.close()
            recipe = generation._recipe
            if (dict(durable_witness) != dict(witness)
                    or receipt_body.get("schema") != 2
                    or receipt_body.get("health_run_proof_sha256")
                       != witness.get("health_run_proof_sha256")
                    or receipt_body.get("parent_closure_digest")
                       != witness.get("parent_closure_digest")
                    or not event_rows
                    or event_rows[-1].get("event_kind") != "terminal"
                    or intent.get("purpose") != "root-native-health-intent-v1"
                    or intent.get("committed_transaction_id") != committed.journal_transaction_id
                    or intent.get("bootstrap_transaction_handle") != active.transaction_handle
                    or intent.get("generation_id") != active.generation_id
                    or intent.get("service_generation_digest") != active.generation_digest
                    or intent.get("publication_receipt_handle") != current_publication.receipt_handle
                    or intent.get("publication_sha256") != current_publication.publication_sha256
                    or intent.get("source_choice_signed_record_sha256")
                       != generation.source_choice_signed_record_sha256
                    or intent.get("health_definition_sha256") != recipe.health_definition_sha256
                    or witness.get("intent_sha256") != _digest(dict(intent))
                    or witness.get("completion_handle") != completion_handle
                    or witness.get("committed_transaction_id") != committed.journal_transaction_id
                    or witness.get("bootstrap_transaction_handle") != active.transaction_handle
                    or witness.get("generation_id") != active.generation_id
                    or witness.get("service_generation_digest") != active.generation_digest
                    or witness.get("publication_receipt_handle") != current_publication.receipt_handle
                    or witness.get("publication_sha256") != current_publication.publication_sha256
                    or witness.get("source_choice_signed_record_sha256")
                       != generation.source_choice_signed_record_sha256
                    or witness.get("health_definition_sha256") != recipe.health_definition_sha256
                    or witness.get("schema") != 2
                    or witness.get("health_run_proof_sha256") != receipt_body.get("health_run_proof_sha256")
                    or witness.get("daemon_unit_id") != active_listener.daemon_unit_id
                    or witness.get("daemon_invocation_id") != active_listener.daemon_invocation_id
                    or witness.get("daemon_pid") != active_listener.daemon_pid
                    or witness.get("daemon_start_ticks") != active_listener.daemon_start_ticks):
                raise ValueError("completed health witness differs from current setup and selected source")
            return RootSetupFunctionalHealthWitness(
                intent_handle, completion_handle, _digest(dict(witness)), dict(witness),
                _SETUP_HEALTH_WITNESS_SEAL)
        except ListenerActivationUnavailable:
            raise
        except Exception:
            raise ListenerActivationUnavailable(
                "completed health witness is not joined to current committed setup") from None


@dataclass(frozen=True, slots=True, repr=False)
class RootVerifiedListenerActivationSelection:
    """Setup-side source selection minted from the committed publication.

    This private object is the seam between setup-owned source/member custody
    and the endpoint custodian.  It deliberately contains no caller-provided
    peer identity and no daemon-local network projection.
    """
    endpoint_receipt_handle: str
    publication_receipt_handle: str
    publication_sha256: str
    service_generation_digest: str
    generation_id: str
    selection_handle: str
    worker_runtime_record_id: str
    profile_id: str
    service_uid: int
    service_gid: int
    original_setup_deadline_monotonic: float
    _endpoint: Any = field(repr=False, compare=False)
    _publication: Any = field(repr=False, compare=False)
    _generation: Any = field(repr=False, compare=False)
    _materialization: Any = field(repr=False, compare=False)
    _root_receipt: Any = field(repr=False, compare=False)
    _supervisor: Any = field(repr=False, compare=False)
    _issuer: object = field(repr=False, compare=False)

    def __repr__(self) -> str:
        return "RootVerifiedListenerActivationSelection(<committed setup source>)"


def _activation_message(*, operation: str, activation_id: str, nonce: bytes,
                        record_sha256: str, publication_handle: str,
                        publication_sha256: str, generation_sha256: str,
                        endpoint_sha256: str, socket_device: int,
                        socket_inode: int) -> dict[str, Any]:
    if (operation not in {"daemon-ready-for-listener", "transfer-listener", "listener-adopted"}
            or not _HEX32.fullmatch(activation_id) or len(nonce) != 32):
        raise ListenerActivationUnavailable("activation wire operation or nonce is invalid")
    return {
        "schema": 1, "operation": operation, "activation_id": activation_id,
        "nonce": nonce.hex(), "activation_record_sha256": record_sha256,
        "publication_receipt_handle": publication_handle,
        "publication_sha256": publication_sha256,
        "service_generation_digest": generation_sha256,
        "endpoint_receipt_sha256": endpoint_sha256,
        "socket_device": socket_device, "socket_inode": socket_inode,
    }


def _send_packet(connection: socket.socket, message: Mapping[str, Any], *, fd: int | None = None) -> None:
    payload = _canonical(dict(message))
    if len(payload) > _MAX_MESSAGE:
        raise ListenerActivationUnavailable("activation message exceeds its fixed bound")
    ancillary: list[tuple[int, int, bytes]] = []
    if fd is not None:
        if type(fd) is not int or fd < 0:
            raise ListenerActivationUnavailable("listener descriptor is invalid")
        rights = array.array("i", [fd])
        ancillary.append((socket.SOL_SOCKET, socket.SCM_RIGHTS, rights.tobytes()))
    sent = connection.sendmsg([payload], ancillary)
    if sent != len(payload):
        raise ListenerActivationUnavailable("activation packet was not sent atomically")


def _recv_packet(connection: socket.socket, *, expected_peer: tuple[int, int, int],
                 expected_fd_count: int, timeout: float = 3.0
                 ) -> tuple[dict[str, Any], tuple[int, ...]]:
    if expected_fd_count not in {0, 1}:
        raise ListenerActivationUnavailable("activation descriptor count is outside the finite schema")
    if type(timeout) not in (int, float) or not 0 < timeout <= 300:
        raise ListenerActivationUnavailable("channel wait is outside its fixed health/activation bound")
    connection.settimeout(timeout)
    if not hasattr(socket, "SO_PASSCRED"):
        raise ListenerActivationUnavailable("Linux per-message credential delivery is unavailable")
    connection.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
    cred_size = socket.CMSG_SPACE(struct.calcsize("3i"))
    rights_size = socket.CMSG_SPACE(array.array("i").itemsize * 2)
    raw, ancillary, flags, _address = connection.recvmsg(
        _MAX_MESSAGE + 1, cred_size + rights_size, getattr(socket, "MSG_CMSG_CLOEXEC", 0))
    received_fds: list[int] = []
    credentials: tuple[int, int, int] | None = None
    try:
        if (not raw or len(raw) > _MAX_MESSAGE
                or flags & (getattr(socket, "MSG_TRUNC", 0) | getattr(socket, "MSG_CTRUNC", 0))):
            raise ListenerActivationUnavailable("activation packet is empty, oversized, or truncated")
        if _read_peer_cred(connection) != expected_peer:
            raise ListenerActivationUnavailable("activation peer credentials changed")
        for level, kind, data in ancillary:
            if level != socket.SOL_SOCKET:
                raise ListenerActivationUnavailable("activation ancillary level is invalid")
            if kind == socket.SCM_CREDENTIALS:
                if credentials is not None or len(data) != struct.calcsize("3i"):
                    raise ListenerActivationUnavailable("activation credentials are duplicated or malformed")
                credentials = struct.unpack("3i", data)
            elif kind == socket.SCM_RIGHTS:
                values = array.array("i")
                if len(data) % values.itemsize:
                    raise ListenerActivationUnavailable("activation descriptor ancillary data is malformed")
                values.frombytes(data)
                received_fds.extend(values.tolist())
            else:
                raise ListenerActivationUnavailable("activation ancillary type is not permitted")
        if credentials != expected_peer or len(received_fds) != expected_fd_count:
            raise ListenerActivationUnavailable("activation packet peer or descriptor count differs")
        try:
            message = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_pairs)
        except (ValueError, UnicodeError):
            raise ListenerActivationUnavailable("activation message is not valid closed JSON") from None
        message = _validate_channel_message(message)
        if received_fds:
            for descriptor in received_fds:
                os.set_inheritable(descriptor, False)
        return message, tuple(received_fds)
    except BaseException:
        for descriptor in received_fds:
            try:
                os.close(descriptor)
            except OSError:
                pass
        raise


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate activation JSON field")
        result[key] = value
    return result


def _validate_channel_message(message: Any) -> dict[str, Any]:
    """Validate a closed activation or v191 health frame."""
    if not isinstance(message, dict) or type(message.get("schema")) is not int or message["schema"] != 1:
        raise ListenerActivationUnavailable("channel message does not use the fixed schema")
    operation = message.get("operation")
    expected_fields = {
        "daemon-ready-for-listener": _MESSAGE_FIELDS,
        "transfer-listener": _MESSAGE_FIELDS,
        "listener-adopted": _MESSAGE_FIELDS,
        "health-request": _HEALTH_REQUEST_FIELDS,
        "health-accepted": _HEALTH_ACCEPTED_FIELDS,
        "health-completed": _HEALTH_COMPLETED_FIELDS,
    }.get(operation)
    if expected_fields is None or set(message) != expected_fields:
        raise ListenerActivationUnavailable("channel message fields differ from its fixed operation schema")
    if operation in {"health-request", "health-accepted", "health-completed"}:
        intent_keys = (("intent_handle", "intent_sha256")
                       if operation != "health-completed" else ("intent_handle",))
        for key in intent_keys:
            value = message.get(key)
            if not isinstance(value, str) or not _HEX64.fullmatch(value):
                raise ListenerActivationUnavailable("health intent reference is malformed")
        if operation == "health-request":
            nonce = message.get("nonce")
            if not isinstance(nonce, str) or not _HEX64.fullmatch(nonce):
                raise ListenerActivationUnavailable("health intent nonce is malformed")
        elif operation == "health-completed":
            handle, digest = message.get("completion_handle"), message.get("completion_sha256")
            if (not isinstance(handle, str) or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", handle)
                    or not isinstance(digest, str) or not _HEX64.fullmatch(digest)):
                raise ListenerActivationUnavailable("health completion reference is malformed")
    return message


def _verify_packet(message: Mapping[str, Any], expected: Mapping[str, Any]) -> None:
    if set(message) != _MESSAGE_FIELDS or any(message.get(key) != value for key, value in expected.items()):
        raise ListenerActivationUnavailable("activation packet differs from the current one-use transaction")


def _verify_transferred_listener(fd: int, *, socket_device: int, socket_inode: int,
                                 owner_uid: int, owner_gid: int,
                                 socket_root: Path = _AUTHORITY_SOCKET_ROOT) -> socket.socket:
    if type(fd) is not int or fd < 0:
        raise ListenerActivationUnavailable("transferred listener descriptor is unavailable")
    try:
        listener = socket.socket(fileno=fd)
        address = listener.getsockname()
        accepting = listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN)
        sock_type = listener.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE)
        if (listener.family != socket.AF_UNIX or sock_type != socket.SOCK_STREAM or accepting != 1
                or not isinstance(address, str) or not address.startswith(str(socket_root) + "/")
                or address.rsplit("/", 1)[-1] != f"{owner_uid}.sock"):
            listener.detach()
            raise ListenerActivationUnavailable("transferred descriptor is not the selected listening endpoint")
        path_info = Path(address).lstat()
        if (not stat.S_ISSOCK(path_info.st_mode) or path_info.st_uid != 0
                or path_info.st_gid != owner_gid or stat.S_IMODE(path_info.st_mode) != 0o660
                or (path_info.st_dev, path_info.st_ino) != (socket_device, socket_inode)):
            listener.detach()
            raise ListenerActivationUnavailable("transferred endpoint leaf custody changed")
        listener.set_inheritable(False)
        return listener
    except ListenerActivationUnavailable:
        raise
    except OSError:
        raise ListenerActivationUnavailable("transferred listener could not be inspected") from None


def _select_active_worker_row(rows: Any, profile_id: str) -> Mapping[str, Any]:
    """Select by the actual closed active-row key, process_profile_id."""
    if not isinstance(rows, (tuple, list)):
        raise ListenerActivationUnavailable("active worker catalog is unavailable")
    selected = [row for row in rows if isinstance(row, Mapping)
                and row.get("process_profile_id") == profile_id]
    if len(selected) != 1:
        raise ListenerActivationUnavailable("active worker row is absent or ambiguous")
    return selected[0]


def _ensure_control_root(prefix_fd: int, prefix_identity: tuple[int, int]) -> int:
    """Create only the fixed child beneath the held, journal-owned /run prefix."""
    prefix = _CONTROL_ROOT.parent
    pfd = -1
    try:
        pfd = os.dup(prefix_fd)
        pinfo = os.fstat(pfd)
        ppath = prefix.lstat()
        if (not stat.S_ISDIR(pinfo.st_mode) or pinfo.st_uid != 0 or pinfo.st_gid != 0
                or pinfo.st_mode & 0o022
                or (pinfo.st_dev, pinfo.st_ino) != prefix_identity
                or (pinfo.st_dev, pinfo.st_ino) != (ppath.st_dev, ppath.st_ino)):
            raise ListenerActivationUnavailable("fixed /run/hermes-installer custody is invalid")
        try:
            os.mkdir(_CONTROL_ROOT.name, 0o711, dir_fd=pfd)
        except FileExistsError:
            pass
        root_fd = os.open(_CONTROL_ROOT.name, _OPEN_DIR, dir_fd=pfd)
        info = os.fstat(root_fd)
        entry = os.stat(_CONTROL_ROOT.name, dir_fd=pfd, follow_symlinks=False)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
                or stat.S_IMODE(info.st_mode) != 0o711 or (info.st_dev, info.st_ino) != (entry.st_dev, entry.st_ino)):
            os.close(root_fd)
            raise ListenerActivationUnavailable("fixed listener activation root is foreign or unsafe")
        return root_fd
    except ListenerActivationUnavailable:
        raise
    except OSError:
        raise ListenerActivationUnavailable("fixed listener activation root is unavailable") from None
    finally:
        if "pfd" in locals():
            os.close(pfd)


def _create_control_listener(activation_id: str, prefix_fd: int,
                             prefix_identity: tuple[int, int]
                             ) -> tuple[int, int, socket.socket, tuple[int, int]]:
    if not _HEX32.fullmatch(activation_id) or os.geteuid() != 0:
        raise ListenerActivationUnavailable("activation directory ID or root actor is invalid")
    root_fd = _ensure_control_root(prefix_fd, prefix_identity)
    activation_fd = -1
    listener: socket.socket | None = None
    created_directory = False
    created_socket = False
    try:
        os.mkdir(activation_id, 0o700, dir_fd=root_fd)
        created_directory = True
        activation_fd = os.open(activation_id, _OPEN_DIR, dir_fd=root_fd)
        info = os.fstat(activation_fd)
        entry = os.stat(activation_id, dir_fd=root_fd, follow_symlinks=False)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
                or stat.S_IMODE(info.st_mode) != 0o700
                or (info.st_dev, info.st_ino) != (entry.st_dev, entry.st_ino)):
            raise ListenerActivationUnavailable("new activation directory identity or custody is invalid")
        canonical_directory = _CONTROL_ROOT / activation_id
        named_directory = canonical_directory.lstat()
        if (stat.S_ISLNK(named_directory.st_mode)
                or (named_directory.st_dev, named_directory.st_ino) != (info.st_dev, info.st_ino)):
            raise ListenerActivationUnavailable("activation directory pathname differs from held custody")
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
        listener.set_inheritable(False)
        canonical_socket = canonical_directory / "control.sock"
        listener.bind(str(canonical_socket))
        created_socket = True
        os.chown("control.sock", 0, 0, dir_fd=activation_fd, follow_symlinks=False)
        os.chmod("control.sock", 0o600, dir_fd=activation_fd, follow_symlinks=False)
        listener.listen(1)
        listener.settimeout(3.0)
        leaf = os.stat("control.sock", dir_fd=activation_fd, follow_symlinks=False)
        after_directory = canonical_directory.lstat()
        after_socket = canonical_socket.lstat()
        if (listener.getsockname() != str(canonical_socket)
                or (after_directory.st_dev, after_directory.st_ino) != (info.st_dev, info.st_ino)
                or (after_socket.st_dev, after_socket.st_ino) != (leaf.st_dev, leaf.st_ino)
                or not stat.S_ISSOCK(leaf.st_mode) or leaf.st_uid != 0 or leaf.st_gid != 0
                or stat.S_IMODE(leaf.st_mode) != 0o600):
            raise ListenerActivationUnavailable("new activation control socket is not root-private")
        return root_fd, activation_fd, listener, (info.st_dev, info.st_ino)
    except BaseException:
        if listener is not None:
            listener.close()
        if activation_fd >= 0:
            if created_socket:
                try:
                    os.unlink("control.sock", dir_fd=activation_fd)
                except OSError:
                    pass
            os.close(activation_fd)
        if created_directory:
            try:
                os.rmdir(activation_id, dir_fd=root_fd)
            except OSError:
                pass
        os.close(root_fd)
        raise


def _read_record_at(activation_fd: int) -> tuple[dict[str, Any], str, tuple[int, int]]:
    try:
        fd = os.open("state.json", os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                     | getattr(os, "O_CLOEXEC", 0), dir_fd=activation_fd)
    except OSError:
        raise ListenerActivationUnavailable("activation journal record is unavailable") from None
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1 or info.st_size > _MAX_MESSAGE * 2):
            raise ListenerActivationUnavailable("activation journal custody is invalid")
        raw = bytearray()
        while len(raw) <= _MAX_MESSAGE * 2:
            chunk = os.read(fd, min(4096, _MAX_MESSAGE * 2 + 1 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
        if len(raw) != info.st_size:
            raise ListenerActivationUnavailable("activation journal changed during read")
    finally:
        os.close(fd)
    try:
        value = json.loads(bytes(raw).decode("utf-8"), object_pairs_hook=_unique_pairs)
    except (ValueError, UnicodeError):
        raise ListenerActivationUnavailable("activation journal is malformed") from None
    if (not isinstance(value, dict) or set(value) != _RECORD_FIELDS or value.get("schema") != 1
            or value.get("state") not in {"prepared", "receiver-verified", "fd-sent", "adopted", "cancelled"}):
        raise ListenerActivationUnavailable("activation journal schema or state is unknown")
    integer_fields = {
        "schema", "service_uid", "service_gid", "socket_device", "socket_inode",
        "setup_pid", "setup_start_ticks", "daemon_pid", "daemon_start_ticks",
        "activation_root_device", "activation_root_inode", "activation_socket_device",
        "activation_socket_inode",
    }
    text_fields = _RECORD_FIELDS - integer_fields - {"issued_monotonic", "expires_monotonic", "state"}
    digest_fields = {
        "prepared_endpoint_receipt_sha256", "publication_sha256", "service_generation_digest",
        "setup_interpreter_sha256", "setup_launcher_sha256", "setup_actor_binding_sha256",
        "daemon_unit_fragment_sha256", "daemon_interpreter_sha256", "daemon_launcher_sha256",
        "release_deployment_receipt_sha256", "release_closure_manifest_sha256", "nonce_sha256",
    }
    if (any(type(value.get(key)) is not int or value[key] < 0 for key in integer_fields)
            or any(not isinstance(value.get(key), str) or not value[key] or len(value[key]) > 1024
                   for key in text_fields)
            or any(not _HEX64.fullmatch(value[key]) for key in digest_fields)
            or any(type(value.get(key)) not in {int, float} for key in ("issued_monotonic", "expires_monotonic"))
            or not value["issued_monotonic"] < value["expires_monotonic"]
            or value["expires_monotonic"] - value["issued_monotonic"] > _MAX_TTL):
        raise ListenerActivationUnavailable("activation journal field types, hashes, or deadline are invalid")
    leaf = os.stat("state.json", dir_fd=activation_fd, follow_symlinks=False)
    if (leaf.st_dev, leaf.st_ino) != (info.st_dev, info.st_ino):
        raise ListenerActivationUnavailable("activation journal leaf changed while being read")
    return value, hashlib.sha256(raw).hexdigest(), (info.st_dev, info.st_ino)


def _write_initial_record(activation_fd: int, record: Mapping[str, Any]) -> str:
    if set(record) != _RECORD_FIELDS or record.get("schema") != 1:
        raise ListenerActivationUnavailable("initial activation record differs from closed schema 1")
    raw = _canonical(dict(record))
    if len(raw) > _MAX_MESSAGE * 2:
        raise ListenerActivationUnavailable("activation record exceeds its fixed bound")
    fd = os.open("state.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
                 | getattr(os, "O_CLOEXEC", 0), 0o600, dir_fd=activation_fd)
    try:
        os.fchown(fd, 0, 0)
        os.fchmod(fd, 0o600)
        offset = 0
        while offset < len(raw):
            offset += os.write(fd, raw[offset:])
        os.fsync(fd)
    except BaseException:
        try:
            os.unlink("state.json", dir_fd=activation_fd)
        except OSError:
            pass
        raise
    finally:
        os.close(fd)
    os.fsync(activation_fd)
    return hashlib.sha256(raw).hexdigest()


def _cas_activation_record(activation_fd: int, expected_sha256: str,
                           new_state: str) -> tuple[dict[str, Any], str]:
    import fcntl
    if new_state not in {"receiver-verified", "fd-sent", "adopted", "cancelled"}:
        raise ListenerActivationUnavailable("activation state transition is outside schema 1")
    fcntl.flock(activation_fd, fcntl.LOCK_EX)
    try:
        original, digest, old_identity = _read_record_at(activation_fd)
        if not secrets.compare_digest(digest, expected_sha256):
            raise ListenerActivationUnavailable("activation journal compare-and-swap lost its current version")
        transitions = {"prepared": {"receiver-verified", "cancelled"},
                       "receiver-verified": {"fd-sent", "cancelled"},
                       "fd-sent": {"adopted", "cancelled"},
                       "adopted": set(), "cancelled": set()}
        if new_state not in transitions[original["state"]]:
            raise ListenerActivationUnavailable("activation state transition is duplicate or out of order")
        updated = dict(original)
        updated["state"] = new_state
        raw = _canonical(updated)
        temp = ".state-" + secrets.token_hex(16)
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
                     | getattr(os, "O_CLOEXEC", 0), 0o600, dir_fd=activation_fd)
        try:
            os.fchown(fd, 0, 0)
            os.fchmod(fd, 0o600)
            offset = 0
            while offset < len(raw):
                offset += os.write(fd, raw[offset:])
            os.fsync(fd)
        finally:
            os.close(fd)
        try:
            again, again_digest, identity = _read_record_at(activation_fd)
            if again_digest != expected_sha256 or identity != old_identity or again != original:
                raise ListenerActivationUnavailable("activation journal changed during compare-and-swap")
            os.replace(temp, "state.json", src_dir_fd=activation_fd, dst_dir_fd=activation_fd)
            os.fsync(activation_fd)
        except BaseException:
            try:
                os.unlink(temp, dir_fd=activation_fd)
            except OSError:
                pass
            raise
        result, result_digest, _identity = _read_record_at(activation_fd)
        return result, result_digest
    finally:
        fcntl.flock(activation_fd, fcntl.LOCK_UN)


class RootAuthorityListenerActivationSupervisor:
    """Setup-side coordinator for one real, supervised listener adoption."""

    def __init__(self, binding: Any, custodian: Any, held_release: Any,
                 current_actor: Any, authority_root_receipt: Any, *,
                 inspector: SystemdAuthorityDaemonInspector | None = None):
        from .bootstrap_runtime_factory import RootSelectedInstallationBinding
        from .installer_release import RootActorObservation, VerifiedInstallerReleaseReceipt
        from .native_worker_endpoint_custody import RootPreparedAuthorityEndpointCustodian
        from .runtime_root_custody import RootPreparedAuthorityRootReceipt
        if (type(binding) is not RootSelectedInstallationBinding
                or type(custodian) is not RootPreparedAuthorityEndpointCustodian
                or custodian.binding is not binding
                or type(held_release) is not VerifiedInstallerReleaseReceipt
                or type(current_actor) is not RootActorObservation
                or type(authority_root_receipt) is not RootPreparedAuthorityRootReceipt
                or custodian.prepared_authority_root_receipt is not authority_root_receipt
                or os.geteuid() != 0):
            raise ListenerActivationUnavailable("exact live root setup, endpoint, release, and root receipts are required")
        current_actor.verify_current(held_release)
        authority_root_receipt.verify_current()
        self.binding, self.custodian = binding, custodian
        self.held_release, self.current_actor = held_release, current_actor
        self.authority_root_receipt = authority_root_receipt
        self.inspector = inspector or SystemdAuthorityDaemonInspector()
        self._issuer = object()
        self._selections: dict[str, RootVerifiedListenerActivationSelection] = {}
        self._transactions: dict[str, RootActiveAuthorityListenerReceipt] = {}
        self._health_connection: socket.socket | None = None
        self._health_intent_issuer: RootSetupHealthIntentIssuer | None = None
        self._closed = False

    @classmethod
    def from_root_setup(cls, current_binding: Any, custodian: Any,
                        held_release: Any, current_actor: Any,
                        authority_root_receipt: Any, *,
                        inspector: SystemdAuthorityDaemonInspector | None = None
                        ) -> "RootAuthorityListenerActivationSupervisor":
        return cls(current_binding, custodian, held_release, current_actor,
                   authority_root_receipt, inspector=inspector)

    def verify_setup_selection(self, endpoint_receipt_handle: str,
                               publication: Any) -> RootVerifiedListenerActivationSelection:
        """Resolve the selected source/member graph from the live post-CAS root."""
        self._check_setup_actor()
        from .setup_policy_publication import RootSetupPublicationReceipt
        from .native_worker_endpoint_custody import RootPreparedAuthorityListenerReceipt
        session = self.binding._session
        if (type(publication) is not RootSetupPublicationReceipt
                or publication.state != "active-committed"
                or not isinstance(endpoint_receipt_handle, str)):
            raise ListenerActivationUnavailable("a current active publication and selected endpoint are required")
        try:
            # The root receipt is explicitly adopted by the committed CAS;
            # ordinary prepared-session endpoint resolution is no longer valid.
            self.authority_root_receipt.adopt_current_active_publication()
            current_publication = session._resolve_current_active_policy_publication()
            active = session._resolve_current_active_enrollment()
            endpoint = self.custodian._receipts.get(endpoint_receipt_handle)
            selection_handle = session._current_native_policy_selection_handle
            if (type(endpoint) is not RootPreparedAuthorityListenerReceipt
                    or endpoint._issuer is not self.custodian._issuer
                    or current_publication.publication_handle != publication.publication_handle
                    or current_publication.publication_sha256 != publication.publication_sha256
                    or current_publication.generation_id != publication.generation_id
                    or current_publication.service_generation_digest != publication.service_generation_digest
                    or publication.transaction_handle != endpoint.transaction_handle
                    or publication.service_generation_digest != active.generation_digest
                    or publication.generation_id != active.generation_id
                    or active.state != "committed" or not active.enrollment_ids
                    or active.transaction_handle != endpoint.transaction_handle
                    or endpoint.setup_session_id != session._handle.session_id
                    or endpoint.plan_sha256 != session._authorization.plan_digest
                    or not isinstance(selection_handle, str) or not selection_handle):
                raise ValueError("publication, active CAS, setup session, and endpoint do not join")
            endpoint = self.custodian._resolve_current_activation_endpoint(endpoint_receipt_handle)
            producer = session.resolve_current_native_worker_service_generation_producer()
            generation = producer.resolve_current_selected_generation(selection_handle)
            if (generation.setup_session_id != session._handle.session_id
                    or generation.transaction_handle != endpoint.transaction_handle
                    or generation.source_choice_selection_handle != selection_handle):
                raise ValueError("selected native generation differs from the live setup transaction")
            runtime_row, active_row, profile_row, service_row = _activation_generation_rows(
                generation, publication, endpoint)
            committed = session._transaction.verify_committed_receipt(active, session._authorization)
            if producer.verify_active_current(generation, committed, runtime_row["id"]) is not generation:
                raise ValueError("current active native source/member receipt changed")
            materialization = generation._runtime_materialization
            materializer = session.resolve_current_native_worker_runtime_materialization_registry()
            if (materializer._active_bindings.get(materialization.receipt_handle) != active.generation_id
                    or materializer._issued.get(materialization.receipt_handle) is not materialization):
                raise ValueError("actual retained PM/output members were not adopted by the committed CAS")
            adopted = [row for row in publication.choice_adoptions
                       if row.selection_handle == selection_handle
                       and row.service_generation_digest == publication.service_generation_digest
                       and row.setup_deadline_unix > time.time()]
            if len(adopted) != 1:
                raise ValueError("signed selected worker source has no unique current publisher adoption")
            remaining = adopted[0].setup_deadline_unix - time.time()
            deadline = min(self.authority_root_receipt.expires_monotonic,
                           endpoint.expires_monotonic, time.monotonic() + remaining)
            if deadline <= time.monotonic():
                raise ValueError("original setup deadline has expired")
            self.authority_root_receipt.adopt_current_active_publication()
            self.authority_root_receipt.verify_current()
            receipt = RootVerifiedListenerActivationSelection(
                endpoint.receipt_handle, publication.receipt_handle,
                publication.publication_sha256, publication.service_generation_digest,
                publication.generation_id, selection_handle, runtime_row["id"],
                endpoint.profile_id, endpoint.service_uid, endpoint.service_gid,
                deadline, endpoint, publication, generation, materialization,
                self.authority_root_receipt, self, self._issuer)
            previous = self._selections.get(endpoint.receipt_handle)
            if previous is not None:
                if (previous._endpoint is not endpoint or previous._generation is not generation
                        or previous._materialization is not materialization
                        or previous.publication_sha256 != receipt.publication_sha256
                        or previous.service_generation_digest != receipt.service_generation_digest
                        or previous.selection_handle != receipt.selection_handle
                        or previous.profile_id != receipt.profile_id
                        or previous.service_uid != receipt.service_uid
                        or previous.service_gid != receipt.service_gid):
                    raise ValueError("previously issued activation selection changed its joined source")
                return previous
            self._selections[endpoint.receipt_handle] = receipt
            return receipt
        except ListenerActivationUnavailable:
            raise
        except Exception as exc:
            raise ListenerActivationUnavailable(
                "current committed setup source, runtime members, and endpoint do not join") from exc

    def verify_current_selection(self, selection: RootVerifiedListenerActivationSelection
                                  ) -> RootVerifiedListenerActivationSelection:
        self._check_setup_actor()
        if (type(selection) is not RootVerifiedListenerActivationSelection
                or selection._issuer is not self._issuer
                or self._selections.get(selection.endpoint_receipt_handle) is not selection):
            raise ListenerActivationUnavailable("activation selection is not a current supervisor-issued receipt")
        current_publication = self.binding._session._resolve_current_active_policy_publication()
        current = self.verify_setup_selection(selection.endpoint_receipt_handle, current_publication)
        if current is not selection:
            raise ListenerActivationUnavailable("active source selection changed after issuance")
        return selection

    def request_functional_health(self, intent: RootSetupHealthIntent) -> tuple[str, str]:
        """Send one fixed request and return only the daemon's journal witness reference."""
        if (type(intent) is not RootSetupHealthIntent
                or self._health_intent_issuer is None
                or intent._issuer is not self._health_intent_issuer._issuer
                or intent.expires_monotonic <= time.monotonic()
                or self._health_connection is None):
            raise ListenerActivationUnavailable("current one-use health intent or retained channel is unavailable")
        self._check_setup_actor()
        receipt = next((item for item in self._transactions.values()
                        if item.activation_id == intent.activation_id), None)
        if (receipt is None or receipt.activation_id != intent.activation_id
                or receipt.expires_monotonic <= time.monotonic()):
            raise ListenerActivationUnavailable("health request has no current adopted listener")
        selection = self.verify_current_selection(
            self._selections[receipt.endpoint_receipt_handle])
        health = RootSetupHealthIntentJournal.from_root_journal(
            self.binding._session._current_root_journal_selection(), intent.activation_id)
        daemon_selection = _selection_from_release(self.held_release, intent.activation_id)
        peer = self.inspector.inspect_authority_daemon(daemon_selection)
        try:
            if (peer.pid != receipt.daemon_pid or peer.invocation_id != receipt.daemon_invocation_id
                    or peer.start_ticks != receipt.daemon_start_ticks):
                raise ListenerActivationUnavailable("health channel daemon peer changed")
            expected = (peer.pid, 0, 0)
            if _read_peer_cred(self._health_connection) != expected:
                raise ListenerActivationUnavailable("retained health channel peer credentials changed")
            self.verify_current_selection(selection)
            message = {"schema": 1, "operation": "health-request",
                       "intent_handle": intent.intent_handle,
                       "intent_sha256": intent.intent_sha256,
                       "nonce": intent.nonce.hex()}
            _send_packet(self._health_connection, message)
            accepted, fds = _recv_packet(self._health_connection,
                                         expected_peer=expected, expected_fd_count=0)
            if fds or (accepted.get("operation") != "health-accepted"
                       or accepted.get("intent_handle") != intent.intent_handle
                       or accepted.get("intent_sha256") != intent.intent_sha256):
                raise ListenerActivationUnavailable("daemon did not accept the exact health intent")
            # A health run may take up to the fixed 300-second recipe limit.
            # The 30-second intent is consumed at acceptance, never extended.
            try:
                completed, fds = _recv_packet(self._health_connection,
                                              expected_peer=expected, expected_fd_count=0,
                                              timeout=300.0)
            except (TimeoutError, ConnectionError):
                # The daemon may have durably committed the completion before
                # its reply was lost. Reopen that exact CAS only while the
                # same supervised daemon/source selection remains current.
                self.verify_active_current(receipt)
                self.verify_current_selection(selection)
                completion_handle, digest, witness = health.resolve_current_completed_for_intent(
                    intent.intent_handle)
                if (witness.get("intent_sha256") != intent.intent_sha256
                        or _digest(dict(witness)) != digest):
                    raise ListenerActivationUnavailable(
                        "recovered health completion differs from the durable intent") from None
                health.resolve_current_completed_health_proof(intent.intent_handle, completion_handle)
                return completion_handle, digest
            if (fds or completed.get("operation") != "health-completed"
                    or completed.get("intent_handle") != intent.intent_handle):
                raise ListenerActivationUnavailable("daemon returned no closed completion reference")
            witness = health.resolve_current_completed_intent(
                intent.intent_handle, completed["completion_handle"])
            digest = _digest(dict(witness))
            if (digest != completed["completion_sha256"]
                    or witness.get("intent_sha256") != intent.intent_sha256):
                raise ListenerActivationUnavailable("daemon completion frame differs from the durable witness")
            return completed["completion_handle"], digest
        finally:
            health.close()
            peer.close()

    def _verify_ack_for_export(self, export: Any, acknowledgment: Any) -> None:
        if (type(export) is not __import__(
                "hermes_installer.authority.native_worker_endpoint_custody",
                fromlist=["RootActiveAuthorityListenerExport"]).RootActiveAuthorityListenerExport
                or type(acknowledgment) is not RootAuthorityDaemonSupervisorAcknowledgment
                or acknowledgment._seal is not _ACK_SEAL
                or acknowledgment._issuer is not self._issuer
                or export._selection._supervisor is not self
                or export._selection._issuer is not self._issuer
                or acknowledgment.endpoint_receipt_handle != export.endpoint_receipt_handle
                or acknowledgment.publication_receipt_handle != export.publication_receipt_handle
                or acknowledgment.publication_sha256 != export.publication_sha256
                or acknowledgment.service_generation_digest != export.service_generation_digest
                or acknowledgment.socket_device != export.socket_device
                or acknowledgment.socket_inode != export.socket_inode
                or not _HEX32.fullmatch(acknowledgment.activation_id)
                or not _HEX64.fullmatch(acknowledgment.activation_record_sha256)
                or not _HEX64.fullmatch(acknowledgment.nonce_sha256)):
            raise ListenerActivationUnavailable("daemon acknowledgement is not sealed to the active listener export")
        unit_selection = _selection_from_release(self.held_release, acknowledgment.activation_id)
        peer = self.inspector.inspect_authority_daemon(unit_selection)
        try:
            if (peer.pid != acknowledgment.peer_pid
                    or peer.start_ticks != acknowledgment.peer_start_ticks
                    or peer.invocation_id != acknowledgment.daemon_invocation_id):
                raise ListenerActivationUnavailable("ACK peer is not the current fixed unit MainPID")
            self.verify_current_selection(export._selection)
        finally:
            peer.close()

    def begin_active_listener_activation(self, endpoint_receipt_handle: str,
                                         publication: Any) -> RootActiveAuthorityListenerReceipt:
        """Launch the exact fixed root daemon and consume one transferred listener FD."""
        self._check_setup_actor()
        selection = self.verify_setup_selection(endpoint_receipt_handle, publication)
        if endpoint_receipt_handle in self._transactions:
            return self.verify_active_current(self._transactions[endpoint_receipt_handle])
        activation_id = secrets.token_hex(16)
        daemon_selection = _selection_from_release(self.held_release, activation_id)
        root_fd = activation_fd = -1
        control: socket.socket | None = None
        connection: socket.socket | None = None
        exported: Any = None
        daemon_peer: RootAuthorityDaemonPeerObservation | None = None
        record_created = False
        try:
            self.authority_root_receipt.verify_current()
            root_fd, activation_fd, control, root_identity = _create_control_listener(
                activation_id, self.authority_root_receipt._prefix_fd,
                self.authority_root_receipt._prefix_identity)
            control_leaf = os.stat("control.sock", dir_fd=activation_fd, follow_symlinks=False)
            _install_fixed_unit(daemon_selection)
            _systemd_mutation("daemon-reload")
            _systemd_mutation("start")
            daemon_peer = self.inspector.inspect_authority_daemon(daemon_selection)
            self.inspector.verify_current(daemon_peer, daemon_selection)
            endpoint_digest = _digest({
                "receipt_handle": selection._endpoint.receipt_handle,
                "profile_id": selection.profile_id,
                "service_uid": selection.service_uid,
                "service_gid": selection.service_gid,
                "socket_device": selection._endpoint.socket_device,
                "socket_inode": selection._endpoint.socket_inode,
                "challenge_sha256": selection._endpoint.challenge_sha256,
            })
            now = time.monotonic()
            expires = min(now + _MAX_TTL, selection.original_setup_deadline_monotonic,
                          selection._endpoint.expires_monotonic)
            nonce = secrets.token_bytes(32)
            record = {
                "schema": 1, "activation_id": activation_id,
                "setup_session_id": selection._endpoint.setup_session_id,
                "transaction_handle": selection._endpoint.transaction_handle,
                "prepared_endpoint_receipt_handle": selection.endpoint_receipt_handle,
                "prepared_endpoint_receipt_sha256": endpoint_digest,
                "publication_receipt_handle": selection.publication_receipt_handle,
                "publication_sha256": selection.publication_sha256,
                "service_generation_digest": selection.service_generation_digest,
                "profile_id": selection.profile_id,
                "service_enrollment_id": selection._generation.service_records[0].get("id"),
                "service_uid": selection.service_uid, "service_gid": selection.service_gid,
                "socket_device": selection._endpoint.socket_device,
                "socket_inode": selection._endpoint.socket_inode,
                "setup_pid": self.current_actor.pid,
                "setup_start_ticks": self.current_actor.start_time,
                "setup_interpreter_sha256": self.current_actor.interpreter[3],
                "setup_launcher_sha256": self.current_actor.launcher[3],
                "setup_actor_binding_sha256": _digest({
                    "pid": self.current_actor.pid, "uid": self.current_actor.uid,
                    "gid": self.current_actor.gid, "start_ticks": self.current_actor.start_time,
                    "launcher": list(self.current_actor.launcher),
                    "interpreter": list(self.current_actor.interpreter),
                    "modules": [list(row) for row in self.current_actor.module_origins],
                }),
                "daemon_unit_id": daemon_selection.unit_id,
                "daemon_unit_fragment_sha256": daemon_selection.unit_file_sha256,
                "daemon_invocation_id": daemon_peer.invocation_id,
                "daemon_pid": daemon_peer.pid,
                "daemon_start_ticks": daemon_peer.start_ticks,
                "daemon_cgroup": daemon_peer.cgroup,
                "daemon_interpreter_sha256": daemon_peer.executable_sha256,
                "daemon_launcher_sha256": daemon_selection.launcher_sha256,
                "release_deployment_receipt_sha256": daemon_selection.deployment_receipt_sha256,
                "release_closure_manifest_sha256": daemon_selection.closure_manifest_sha256,
                "activation_root_device": root_identity[0], "activation_root_inode": root_identity[1],
                "activation_socket_device": control_leaf.st_dev,
                "activation_socket_inode": control_leaf.st_ino,
                "nonce_sha256": hashlib.sha256(nonce).hexdigest(),
                "issued_monotonic": now, "expires_monotonic": expires, "state": "prepared",
            }
            record_digest = _write_initial_record(activation_fd, record)
            record_created = True
            remaining = expires - time.monotonic()
            if remaining <= 0:
                raise ListenerActivationUnavailable("activation reached its original setup deadline")
            control.settimeout(min(3.0, remaining))
            connection, _ = control.accept()
            expected_daemon = (daemon_peer.pid, 0, 0)
            if _read_peer_cred(connection) != expected_daemon:
                raise ListenerActivationUnavailable("activation socket peer differs from fixed daemon MainPID")
            self._check_setup_actor()
            self.authority_root_receipt.verify_current()
            self.inspector.verify_current(daemon_peer, daemon_selection)
            challenge = _activation_message(
                operation="daemon-ready-for-listener", activation_id=activation_id,
                nonce=nonce, record_sha256=record_digest,
                publication_handle=selection.publication_receipt_handle,
                publication_sha256=selection.publication_sha256,
                generation_sha256=selection.service_generation_digest,
                endpoint_sha256=endpoint_digest,
                socket_device=selection._endpoint.socket_device,
                socket_inode=selection._endpoint.socket_inode)
            _send_packet(connection, challenge)
            ready, fds = _recv_packet(connection, expected_peer=expected_daemon, expected_fd_count=0)
            if fds:
                raise ListenerActivationUnavailable("daemon-ready unexpectedly carried a descriptor")
            _verify_packet(ready, challenge)
            if not secrets.compare_digest(hashlib.sha256(nonce).hexdigest(), record["nonce_sha256"]):
                raise ListenerActivationUnavailable("one-use listener nonce does not match its protected record")
            record, record_digest = _cas_activation_record(activation_fd, record_digest, "receiver-verified")
            self._check_setup_actor()
            self.authority_root_receipt.verify_current()
            self.inspector.verify_current(daemon_peer, daemon_selection)
            exported = self.custodian._export_current_active_listener(
                selection.endpoint_receipt_handle, selection)
            if (getattr(exported, "socket_device", None) != selection._endpoint.socket_device
                    or getattr(exported, "socket_inode", None) != selection._endpoint.socket_inode):
                raise ListenerActivationUnavailable("endpoint export differs from selected live socket inode")
            record, record_digest = _cas_activation_record(activation_fd, record_digest, "fd-sent")
            transfer = _activation_message(
                operation="transfer-listener", activation_id=activation_id,
                nonce=nonce, record_sha256=record_digest,
                publication_handle=selection.publication_receipt_handle,
                publication_sha256=selection.publication_sha256,
                generation_sha256=selection.service_generation_digest,
                endpoint_sha256=endpoint_digest,
                socket_device=selection._endpoint.socket_device,
                socket_inode=selection._endpoint.socket_inode)
            _send_packet(connection, transfer, fd=exported.listener_fd)
            ack, fds = _recv_packet(connection, expected_peer=expected_daemon, expected_fd_count=0)
            if fds:
                raise ListenerActivationUnavailable("listener adoption acknowledgement carried an FD")
            _verify_packet(ack, {**transfer, "operation": "listener-adopted"})
            self._check_setup_actor()
            self.authority_root_receipt.verify_current()
            self.inspector.verify_current(daemon_peer, daemon_selection)
            record, record_digest = _cas_activation_record(activation_fd, record_digest, "adopted")
            ack_type = RootAuthorityDaemonSupervisorAcknowledgment
            ack_receipt = ack_type(
                activation_id, record_digest, selection.endpoint_receipt_handle,
                selection._endpoint.socket_device, selection._endpoint.socket_inode,
                selection.publication_receipt_handle, selection.publication_sha256,
                selection.service_generation_digest, hashlib.sha256(nonce).hexdigest(),
                daemon_peer.invocation_id, daemon_peer.pid, daemon_peer.start_ticks,
                self._issuer, _ACK_SEAL)
            self.custodian._adopt_after_supervisor_ack(exported, ack_receipt, self._issuer)
            final_peer = self.inspector.inspect_authority_daemon(daemon_selection)
            try:
                if (final_peer.pid != daemon_peer.pid
                        or final_peer.invocation_id != daemon_peer.invocation_id
                        or final_peer.start_ticks != daemon_peer.start_ticks):
                    raise ListenerActivationUnavailable("daemon changed after listener adoption acknowledgement")
                active = RootActiveAuthorityListenerReceipt(
                    activation_id, record_digest, selection.endpoint_receipt_handle,
                    selection.publication_receipt_handle, selection.publication_sha256,
                    selection.service_generation_digest, selection._endpoint.socket_device,
                    selection._endpoint.socket_inode, daemon_selection.unit_id,
                    final_peer.invocation_id, final_peer.pid, final_peer.start_ticks,
                    time.monotonic(), expires, self._issuer)
            finally:
                final_peer.close()
            self._transactions[endpoint_receipt_handle] = active
            self._health_connection = connection
            connection = None
            return active
        except BaseException:
            if activation_fd >= 0 and record_created:
                try:
                    current, digest, _identity = _read_record_at(activation_fd)
                    if current["state"] not in {"adopted", "cancelled"}:
                        _cas_activation_record(activation_fd, digest, "cancelled")
                except Exception:
                    pass
            # Unit/socket cleanup is identity-safe and only attempted before
            # a successful adoption; a live adopted daemon owns its listener.
            if daemon_peer is not None:
                try:
                    self.inspector.verify_current(daemon_peer, daemon_selection)
                except Exception:
                    pass
            raise
        finally:
            if exported is not None:
                try:
                    exported.close()
                except Exception:
                    pass
            if connection is not None:
                connection.close()
            if control is not None:
                control.close()
            if activation_fd >= 0:
                os.close(activation_fd)
            if root_fd >= 0:
                os.close(root_fd)
            if daemon_peer is not None:
                daemon_peer.close()

    def verify_active_current(self, receipt: RootActiveAuthorityListenerReceipt
                              ) -> RootActiveAuthorityListenerReceipt:
        self._check_setup_actor()
        if (type(receipt) is not RootActiveAuthorityListenerReceipt
                or receipt._issuer is not self._issuer
                or receipt.expires_monotonic <= time.monotonic()
                or self._transactions.get(receipt.endpoint_receipt_handle) is not receipt):
            raise ListenerActivationUnavailable("active listener receipt is foreign, stale, or expired")
        self.authority_root_receipt.verify_current()
        self.verify_setup_selection(receipt.endpoint_receipt_handle,
                                    self.binding._session._resolve_current_active_policy_publication())
        return receipt

    def resolve_current_functional_health_witness(self, intent_handle: str,
                                                   completion_handle: str) -> Mapping[str, Any]:
        self._check_setup_actor()
        session = self.binding._session
        if len(self._transactions) != 1:
            raise ListenerActivationUnavailable("current setup has no unique active listener witness")
        active_listener = next(iter(self._transactions.values()))
        if type(intent_handle) is not str or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", intent_handle):
            raise ListenerActivationUnavailable("health completion handle is malformed")
        self.verify_active_current(active_listener)
        current_publication = session._resolve_current_active_policy_publication()
        active = session._resolve_current_active_enrollment()
        committed = session._transaction.verify_committed_receipt(active, session._authorization)
        generation = session.resolve_current_native_worker_service_generation_producer().resolve_current_selected_generation(
            session._current_native_policy_selection_handle)
        journal = RootSetupHealthIntentJournal.from_root_journal(
            session._current_root_journal_selection(), active_listener.activation_id)
        try:
            witness = journal.resolve_current_completed_intent(intent_handle, completion_handle)
            if (witness.get("committed_transaction_id") != committed.journal_transaction_id
                    or witness.get("bootstrap_transaction_handle") != active.transaction_handle
                    or witness.get("generation_id") != active.generation_id
                    or witness.get("service_generation_digest") != active.generation_digest
                    or witness.get("publication_receipt_handle") != current_publication.receipt_handle
                    or witness.get("publication_sha256") != current_publication.publication_sha256
                    or witness.get("source_choice_signed_record_sha256")
                       != generation.source_choice_signed_record_sha256
                    or witness.get("daemon_unit_id") != active_listener.daemon_unit_id
                    or witness.get("daemon_invocation_id") != active_listener.daemon_invocation_id
                    or witness.get("daemon_pid") != active_listener.daemon_pid
                    or witness.get("daemon_start_ticks") != active_listener.daemon_start_ticks):
                raise ListenerActivationUnavailable("completed health witness differs from current committed setup")
            return witness
        finally:
            journal.close()

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._selections.clear()
        self._transactions.clear()
        if self._health_connection is not None:
            self._health_connection.close()
            self._health_connection = None

    def _check_setup_actor(self) -> None:
        if self._closed:
            raise ListenerActivationUnavailable("setup supervisor is closed")
        try:
            self.binding._session._check_live()
            self.held_release.verify_current()
            self.current_actor.verify_current(self.held_release)
            self.authority_root_receipt.verify_current()
        except Exception:
            raise ListenerActivationUnavailable("local root setup actor or held source custody is no longer current") from None


class RootAuthorityListenerActivationReceiver:
    """Installed-daemon receiver for one systemd-supervised listener handoff."""

    def __init__(self, service: Any, enrollment: Any, activation_id: str,
                 held_release: Any, current_actor: Any, *,
                 inspector: SystemdAuthorityDaemonInspector | None = None):
        from .installer_release import RootActorObservation, VerifiedInstallerReleaseReceipt
        from .runtime_composition import RootAuthorityRuntime
        runtime = getattr(service, "root_authority_runtime", None)
        if (type(held_release) is not VerifiedInstallerReleaseReceipt
                or type(current_actor) is not RootActorObservation
                or type(runtime) is not RootAuthorityRuntime or runtime.service is not service
                or os.geteuid() != 0 or not _HEX32.fullmatch(activation_id)):
            raise ListenerActivationUnavailable("current installed daemon runtime and action ID are required")
        current_actor.verify_current(held_release)
        self.service, self.enrollment = service, enrollment
        self.activation_id, self.held_release = activation_id, held_release
        self.current_actor, self.runtime = current_actor, runtime
        self.inspector = inspector or SystemdAuthorityDaemonInspector()
        self.selection = _selection_from_release(held_release, activation_id)
        self._owner = None
        self._projection = None
        self._nonce: str | None = None
        self._setup_peer_pidfd: int | None = None
        self._active_receipt: RootActiveAuthorityListenerReceipt | None = None
        self._active_listener: socket.socket | None = None
        self._adopted_monotonic: float | None = None
        self._health_connection: socket.socket | None = None
        self._health_intent_journal: RootSetupHealthIntentJournal | None = None

    @classmethod
    def from_current_installed_daemon(cls, runtime: Any, activation_id: str,
                                      held_release: Any, current_actor: Any, *,
                                      service: Any | None = None,
                                      enrollment: Any | None = None,
                                      inspector: SystemdAuthorityDaemonInspector | None = None
                                      ) -> "RootAuthorityListenerActivationReceiver":
        service = service or getattr(runtime, "service", None)
        if service is None or runtime is not getattr(service, "root_authority_runtime", None):
            raise ListenerActivationUnavailable("receiver runtime is detached from the local authority service")
        return cls(service, enrollment, activation_id, held_release, current_actor,
                   inspector=inspector)

    def receive_listener(self) -> tuple[socket.socket, RootActiveAuthorityListenerReceipt]:
        """Adopt, acknowledge, and wait for the setup journal's final CAS."""
        self._verify_local_runtime()
        peer = self.inspector.inspect_authority_daemon(self.selection)
        connection: socket.socket | None = None
        activation_fd = -1
        setup_peer_pidfd = -1
        listener: socket.socket | None = None
        try:
            if (peer.pid != os.getpid() or peer.uid != 0 or peer.gid != 0
                    or peer.start_ticks != _read_proc_start_ticks(Path("/proc"), os.getpid())):
                raise ListenerActivationUnavailable("receiver is not this fixed systemd MainPID")
            activation_fd, root_identity, channel_identity, record, digest = self._wait_prepared_record()
            try:
                setup_peer_pidfd = os.pidfd_open(record["setup_pid"], 0)
            except OSError:
                raise ListenerActivationUnavailable("setup supervisor PIDFD could not be opened") from None
            self._setup_peer_pidfd = setup_peer_pidfd
            if (record["activation_id"] != self.activation_id
                    or record["daemon_unit_id"] != self.selection.unit_id
                    or record["daemon_unit_fragment_sha256"] != self.selection.unit_file_sha256
                    or record["daemon_invocation_id"] != peer.invocation_id
                    or record["daemon_pid"] != peer.pid
                    or record["daemon_start_ticks"] != peer.start_ticks
                    or record["daemon_cgroup"] != peer.cgroup
                    or record["daemon_interpreter_sha256"] != peer.executable_sha256
                    or record["daemon_launcher_sha256"] != self.selection.launcher_sha256
                    or record["release_deployment_receipt_sha256"] != self.held_release.deployment_receipt_sha256
                    or record["release_closure_manifest_sha256"] != self.held_release.closure_manifest_sha256
                    or (record["activation_root_device"], record["activation_root_inode"]) != root_identity
                    or (record["activation_socket_device"], record["activation_socket_inode"]) != channel_identity
                    or record["state"] != "prepared"
                    or record["expires_monotonic"] <= time.monotonic()
                    or record["expires_monotonic"] - record["issued_monotonic"] > _MAX_TTL):
                raise ListenerActivationUnavailable("protected activation record differs from this daemon incarnation")
            self._resolve_current_projection(record)
            expected_setup_peer = self._verify_setup_peer(record)
            channel_path = _CONTROL_ROOT / self.activation_id / "control.sock"
            leaf = channel_path.lstat()
            if (not stat.S_ISSOCK(leaf.st_mode) or leaf.st_uid != 0 or leaf.st_gid != 0
                    or stat.S_IMODE(leaf.st_mode) != 0o600
                    or (leaf.st_dev, leaf.st_ino) != channel_identity):
                raise ListenerActivationUnavailable("activation control pathname custody changed")
            connection = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
            connection.settimeout(min(3.0, record["expires_monotonic"] - time.monotonic()))
            connection.connect(str(channel_path))
            leaf = channel_path.lstat()
            if (leaf.st_dev, leaf.st_ino) != channel_identity:
                raise ListenerActivationUnavailable("activation control pathname changed during connect")
            challenge, fds = _recv_packet(connection, expected_peer=expected_setup_peer, expected_fd_count=0)
            if fds:
                raise ListenerActivationUnavailable("readiness challenge unexpectedly carried an FD")
            self._verify_message(challenge, record, digest, "daemon-ready-for-listener")
            self._verify_local_runtime()
            self._resolve_current_projection(record)
            if self._verify_setup_peer(record) != expected_setup_peer:
                raise ListenerActivationUnavailable("setup supervisor credentials changed during activation")
            self.inspector.verify_current(peer, self.selection)
            self._nonce = challenge["nonce"]
            _send_packet(connection, challenge)
            transfer, descriptors = _recv_packet(connection, expected_peer=expected_setup_peer,
                                                 expected_fd_count=1)
            current, digest, _identity = _read_record_at(activation_fd)
            if current["state"] != "fd-sent":
                raise ListenerActivationUnavailable("listener FD arrived outside the one-use sent state")
            self._verify_message(transfer, current, digest, "transfer-listener")
            self._verify_local_runtime()
            self._resolve_current_projection(current)
            if self._verify_setup_peer(current) != expected_setup_peer:
                raise ListenerActivationUnavailable("setup supervisor credentials changed before FD transfer")
            self.inspector.verify_current(peer, self.selection)
            if any(current[key] != record[key] for key in (
                    "socket_device", "socket_inode", "prepared_endpoint_receipt_handle",
                    "prepared_endpoint_receipt_sha256", "publication_receipt_handle",
                    "publication_sha256", "service_generation_digest", "nonce_sha256")):
                raise ListenerActivationUnavailable("current FD transfer changed its selected endpoint or source")
            try:
                listener = _verify_transferred_listener(
                    descriptors[0], socket_device=current["socket_device"],
                    socket_inode=current["socket_inode"], owner_uid=current["service_uid"],
                    owner_gid=current["service_gid"])
            except BaseException:
                for descriptor in descriptors:
                    try:
                        os.close(descriptor)
                    except OSError:
                        pass
                raise
            active = RootActiveAuthorityListenerReceipt(
                self.activation_id, digest, current["prepared_endpoint_receipt_handle"],
                current["publication_receipt_handle"], current["publication_sha256"],
                current["service_generation_digest"], current["socket_device"],
                current["socket_inode"], current["daemon_unit_id"],
                current["daemon_invocation_id"], current["daemon_pid"],
                current["daemon_start_ticks"], time.monotonic(),
                current["expires_monotonic"], _RECEIVER_ISSUER)
            self._verify_local_runtime()
            self._resolve_current_projection(current)
            self.inspector.verify_current(peer, self.selection)
            ack = dict(transfer)
            ack["operation"] = "listener-adopted"
            _send_packet(connection, ack)
            adopted_at = self._await_adoption(activation_fd, record)
            active = replace(active, adopted_monotonic=adopted_at)
            self._verify_local_runtime()
            self._resolve_current_projection(current)
            self.inspector.verify_current(peer, self.selection)
            self._active_receipt = active
            self._active_listener = listener
            self._adopted_monotonic = adopted_at
            self._health_connection = connection
            connection = None
            self._setup_peer_pidfd = setup_peer_pidfd
            setup_peer_pidfd = -1
            return listener, active
        except BaseException:
            if listener is not None:
                listener.close()
            raise
        finally:
            if connection is not None:
                connection.close()
            if activation_fd >= 0:
                os.close(activation_fd)
            if setup_peer_pidfd >= 0:
                self._setup_peer_pidfd = None
                os.close(setup_peer_pidfd)
            peer.close()

    def verify_active_current(self, receipt: RootActiveAuthorityListenerReceipt
                              ) -> RootActiveAuthorityListenerReceipt:
        """Verify the original one-use adoption receipt while its handshake lease is live."""
        if (type(receipt) is not RootActiveAuthorityListenerReceipt
                or receipt._issuer is not _RECEIVER_ISSUER
                or self._active_receipt is not receipt
                or self._active_listener is None
                or receipt.expires_monotonic <= time.monotonic()):
            raise ListenerActivationUnavailable("active listener receipt is foreign, stale, or unavailable")
        self.observe_active_current(receipt)
        return receipt

    def observe_active_current(self, receipt: RootActiveAuthorityListenerReceipt
                               ) -> RootCurrentAuthorityListenerObservation:
        """Issue a fresh bounded currentness observation for the adopted FD.

        The original transaction deadline gates adoption only.  A successful
        timely adopted CAS is retained as provenance; this method then checks
        the current protected adopted record, daemon incarnation, listener
        inode and active publication and issues a new short observation.
        """
        if (type(receipt) is not RootActiveAuthorityListenerReceipt
                or receipt._issuer is not _RECEIVER_ISSUER
                or self._active_receipt is not receipt
                or self._active_listener is None
                or self._adopted_monotonic is None):
            raise ListenerActivationUnavailable("active listener provenance is foreign or unavailable")
        self._verify_local_runtime()
        peer = self.inspector.inspect_authority_daemon(self.selection)
        try:
            self.inspector.verify_current(peer, self.selection)
            current = self._read_current_adopted_record()
            if (current.get("state") != "adopted"
                    or self._adopted_monotonic > current["expires_monotonic"]
                    or current.get("activation_id") != receipt.activation_id
                    or current.get("setup_pid") <= 1
                    or current.get("publication_receipt_handle") != receipt.publication_receipt_handle
                    or current.get("publication_sha256") != receipt.publication_sha256
                    or current.get("service_generation_digest") != receipt.service_generation_digest
                    or current.get("socket_device") != receipt.socket_device
                    or current.get("socket_inode") != receipt.socket_inode
                    or current.get("daemon_invocation_id") != receipt.daemon_invocation_id
                    or current.get("daemon_pid") != receipt.daemon_pid
                    or current.get("daemon_start_ticks") != receipt.daemon_start_ticks):
                raise ValueError("protected adopted record no longer proves timely listener handoff")
            listener = self._active_listener
            address = listener.getsockname()
            named = Path(address).lstat() if isinstance(address, str) else None
            profile = self.runtime.bindings.process_profiles.get(self._projection.process_profile_id)
            if (peer.pid != receipt.daemon_pid
                    or peer.start_ticks != receipt.daemon_start_ticks
                    or peer.invocation_id != receipt.daemon_invocation_id
                    or peer.unit_id != receipt.daemon_unit_id
                    or profile is None
                    or address != str(_AUTHORITY_SOCKET_ROOT / f"{profile.owner_uid}.sock")
                    or listener.family != socket.AF_UNIX
                    or listener.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_STREAM
                    or listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) != 1
                    or named is None or not stat.S_ISSOCK(named.st_mode)
                    or (named.st_dev, named.st_ino) != (receipt.socket_device, receipt.socket_inode)
                    or receipt.activation_id != self.activation_id):
                raise ValueError("daemon or adopted listener identity changed")
            current = self._resolve_current_projection({
                "profile_id": self._projection.process_profile_id,
                "publication_receipt_handle": receipt.publication_receipt_handle,
                "publication_sha256": receipt.publication_sha256,
                "service_generation_digest": receipt.service_generation_digest,
                "service_enrollment_id": self._projection.enrollment_id,
            })
            if (current.publication_receipt_handle != receipt.publication_receipt_handle
                    or current.publication_sha256 != receipt.publication_sha256
                    or current.service_generation_digest != receipt.service_generation_digest
                    or current.network_id != self._projection.network_id
                    or current.process_profile_id != self._projection.process_profile_id):
                raise ValueError("active publication or selected worker changed")
            observed = time.monotonic()
            return RootCurrentAuthorityListenerObservation(
                receipt.activation_id, receipt.activation_record_sha256,
                receipt.endpoint_receipt_handle, receipt.publication_receipt_handle,
                receipt.publication_sha256, receipt.service_generation_digest,
                receipt.socket_device, receipt.socket_inode, receipt.daemon_unit_id,
                receipt.daemon_invocation_id, receipt.daemon_pid, receipt.daemon_start_ticks,
                observed, observed + 30.0, receipt, _RECEIVER_ISSUER)
        except Exception:
            raise ListenerActivationUnavailable(
                "same daemon unit and adopted listener are no longer current") from None
        finally:
            peer.close()

    def close(self) -> None:
        if self._health_intent_journal is not None:
            self._health_intent_journal.close()
            self._health_intent_journal = None
        if self._health_connection is not None:
            self._health_connection.close()
            self._health_connection = None
        if self._active_listener is not None:
            self._active_listener.close()
            self._active_listener = None
        if self._setup_peer_pidfd is not None:
            try:
                os.close(self._setup_peer_pidfd)
            except OSError:
                pass
            self._setup_peer_pidfd = None

    def current_active_receipt(self) -> RootActiveAuthorityListenerReceipt:
        """Return the exact daemon-retained adopted receipt after fresh observation."""
        receipt = self._active_receipt
        if type(receipt) is not RootActiveAuthorityListenerReceipt:
            raise ListenerActivationUnavailable("daemon has no retained active listener receipt")
        self.observe_active_current(receipt)
        return receipt

    def attach_health_intent_journal(self, journal: RootSetupHealthIntentJournal) -> None:
        receipt = self.current_active_receipt()
        if (type(journal) is not RootSetupHealthIntentJournal
                or journal.receiver not in (None, self)
                or journal.active_receipt not in (None, receipt)
                or journal.activation_id != self.activation_id):
            raise ListenerActivationUnavailable("health journal does not match the adopted daemon receiver")
        if (self._health_intent_journal is not None
                and self._health_intent_journal is not journal):
            raise ListenerActivationUnavailable("daemon receiver already owns another health journal")
        journal.receiver, journal.active_receipt = self, receipt
        self._health_intent_journal = journal

    def receive_health_intent(self, journal: RootSetupHealthIntentJournal, *, timeout: float = 3.0
                              ) -> RootAcceptedHealthIntent:
        """Accept one current setup intent over the retained authenticated channel."""
        receipt = self.current_active_receipt()
        connection = self._health_connection
        if (type(journal) is not RootSetupHealthIntentJournal
                or journal is not self._health_intent_journal
                or journal.receiver is not self or journal.active_receipt is not receipt
                or connection is None or journal.activation_id != self.activation_id):
            raise ListenerActivationUnavailable("daemon health channel lacks its exact receiver journal")
        record = self._read_current_adopted_record()
        expected_peer = self._verify_setup_peer(record)
        if _read_peer_cred(connection) != expected_peer:
            raise ListenerActivationUnavailable("health request came from a different setup actor")
        self.observe_active_current(receipt)
        request, descriptors = _recv_packet(connection, expected_peer=expected_peer,
                                            expected_fd_count=0, timeout=timeout)
        if descriptors or request.get("operation") != "health-request":
            raise ListenerActivationUnavailable("health channel did not carry a fixed request")
        accepted = journal.accept(request["intent_handle"], request["intent_sha256"],
                                  request["nonce"], self, receipt)
        self.observe_active_current(receipt)
        _send_packet(connection, {"schema": 1, "operation": "health-accepted",
                                  "intent_handle": accepted.intent_handle,
                                  "intent_sha256": accepted.intent_sha256})
        return accepted

    def send_health_completion(self, intent: RootAcceptedHealthIntent,
                               completion_handle: str) -> tuple[str, str]:
        """Send only a durable completion row already committed by the health consumer."""
        receipt = self.current_active_receipt()
        journal = self._health_intent_journal
        connection = self._health_connection
        if (type(intent) is not RootAcceptedHealthIntent or intent._journal is not journal
                or intent.activation_id != self.activation_id or connection is None
                or journal is None or journal.receiver is not self
                or journal.active_receipt is not receipt):
            raise ListenerActivationUnavailable("completion is not tied to this accepted daemon intent")
        witness = journal.resolve_current_completed_intent(intent.intent_handle, completion_handle)
        digest = _digest(dict(witness))
        record = self._read_current_adopted_record()
        expected_peer = self._verify_setup_peer(record)
        if _read_peer_cred(connection) != expected_peer:
            raise ListenerActivationUnavailable("setup actor changed before completion response")
        self.observe_active_current(receipt)
        _send_packet(connection, {"schema": 1, "operation": "health-completed",
                                  "intent_handle": intent.intent_handle,
                                  "completion_handle": completion_handle,
                                  "completion_sha256": digest})
        return completion_handle, digest

    def abort_health_exchange(self) -> None:
        """Close only the setup control channel after a fail-closed health stop.

        This is transport cleanup, not a health result or journal transition.
        The protected intent remains accepted/started as written, so callers
        cannot turn a failed or interrupted run into a second execution.
        """
        receipt = self.current_active_receipt()
        journal = self._health_intent_journal
        connection = self._health_connection
        if (journal is None or journal.receiver is not self
                or journal.active_receipt is not receipt or connection is None):
            raise ListenerActivationUnavailable("current health exchange is unavailable")
        record = self._read_current_adopted_record()
        expected_peer = self._verify_setup_peer(record)
        self.observe_active_current(receipt)
        if _read_peer_cred(connection) != expected_peer:
            raise ListenerActivationUnavailable("health setup peer changed before transport abort")
        self._health_connection = None
        try:
            connection.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        finally:
            connection.close()

    def _read_current_adopted_record(self) -> Mapping[str, Any]:
        root_fd = activation_fd = -1
        try:
            root_fd = os.open(_CONTROL_ROOT, _OPEN_DIR)
            root_info = os.fstat(root_fd)
            named_root = _CONTROL_ROOT.lstat()
            if (not stat.S_ISDIR(root_info.st_mode) or root_info.st_uid != 0
                    or root_info.st_gid != 0 or stat.S_IMODE(root_info.st_mode) != 0o711
                    or (root_info.st_dev, root_info.st_ino) != (named_root.st_dev, named_root.st_ino)):
                raise ValueError("activation root custody changed")
            activation_fd = os.open(self.activation_id, _OPEN_DIR, dir_fd=root_fd)
            current, _digest, _identity = _read_record_at(activation_fd)
            return current
        except Exception:
            raise ListenerActivationUnavailable(
                "protected adopted listener journal is unavailable") from None
        finally:
            for fd in (activation_fd, root_fd):
                if fd >= 0:
                    os.close(fd)

    def _wait_prepared_record(self) -> tuple[int, tuple[int, int], tuple[int, int],
                                               dict[str, Any], str]:
        deadline = time.monotonic() + _MAX_TTL
        while time.monotonic() < deadline:
            root_fd = activation_fd = -1
            try:
                root_fd = os.open(_CONTROL_ROOT, _OPEN_DIR)
                root = os.fstat(root_fd)
                named_root = _CONTROL_ROOT.lstat()
                if ((root.st_dev, root.st_ino) != (named_root.st_dev, named_root.st_ino)
                        or root.st_uid != 0 or root.st_gid != 0
                        or stat.S_IMODE(root.st_mode) != 0o711):
                    raise ListenerActivationUnavailable("fixed activation root is not protected")
                activation_fd = os.open(self.activation_id, _OPEN_DIR, dir_fd=root_fd)
                directory = os.fstat(activation_fd)
                named_directory = os.stat(self.activation_id, dir_fd=root_fd, follow_symlinks=False)
                if ((directory.st_dev, directory.st_ino) != (named_directory.st_dev, named_directory.st_ino)
                        or directory.st_uid != 0 or directory.st_gid != 0
                        or stat.S_IMODE(directory.st_mode) != 0o700):
                    raise ListenerActivationUnavailable("activation transaction directory is not protected")
                record, digest, _identity = _read_record_at(activation_fd)
                channel = os.stat("control.sock", dir_fd=activation_fd, follow_symlinks=False)
                if (not stat.S_ISSOCK(channel.st_mode) or channel.st_uid != 0 or channel.st_gid != 0
                        or stat.S_IMODE(channel.st_mode) != 0o600
                        or (root.st_dev, root.st_ino) != (
                            record["activation_root_device"], record["activation_root_inode"])):
                    raise ListenerActivationUnavailable("activation channel or protected root inode changed")
                identity, channel_identity = (directory.st_dev, directory.st_ino), (channel.st_dev, channel.st_ino)
                os.close(root_fd)
                return activation_fd, identity, channel_identity, record, digest
            except FileNotFoundError:
                if activation_fd >= 0:
                    os.close(activation_fd)
                if root_fd >= 0:
                    os.close(root_fd)
                time.sleep(0.025)
            except BaseException:
                if activation_fd >= 0:
                    os.close(activation_fd)
                raise
        raise ListenerActivationUnavailable("protected activation record did not appear within the bounded start interval")

    def _verify_local_runtime(self) -> None:
        try:
            self.held_release.verify_current()
            self.current_actor.verify_current(self.held_release)
            if (os.getpid() != self.current_actor.pid
                    or _read_proc_start_ticks(Path("/proc"), os.getpid()) != self.current_actor.start_time):
                raise ValueError("receiver process identity changed")
        except Exception:
            raise ListenerActivationUnavailable("daemon's own installed root actor is no longer current") from None

    def _verify_setup_peer(self, record: Mapping[str, Any]) -> tuple[int, int, int]:
        if (record["setup_pid"] <= 1 or self._setup_peer_pidfd is None
                or self.inspector._pidfd_exited(self._setup_peer_pidfd)):
            raise ListenerActivationUnavailable("setup supervisor PID/start-time witness is stale")
        try:
            start = _read_proc_start_ticks(Path("/proc"), record["setup_pid"])
            uid, gid = _read_proc_effective_ids(Path("/proc"), record["setup_pid"])
            proc = Path("/proc") / str(record["setup_pid"])
            executable = proc / "exe"
            executable_info = os.stat(executable)
            expected_interpreter = self.selection.interpreter_path.stat(follow_symlinks=False)
            executable_hash = hashlib.sha256(executable.read_bytes()).hexdigest()
            argv = (proc / "cmdline").read_bytes().split(b"\0")
            if argv and argv[-1] == b"":
                argv.pop()
            decoded_argv = [item.decode("utf-8", errors="strict") for item in argv]
            if (start != record["setup_start_ticks"] or uid != 0
                    or record["setup_launcher_sha256"] != self.selection.launcher_sha256
                    or record["setup_interpreter_sha256"] != self.selection.interpreter_sha256
                    or os.path.realpath(executable) != str(self.selection.interpreter_path)
                    or (executable_info.st_dev, executable_info.st_ino) != (
                        expected_interpreter.st_dev, expected_interpreter.st_ino)
                    or executable_hash != self.selection.interpreter_sha256
                    or len(decoded_argv) != 8
                    or decoded_argv[0] != str(self.selection.interpreter_path)
                    or decoded_argv[1:5] != ["-B", "-I", "-S", "-c"]
                    or decoded_argv[5] != _SETUP_LAUNCHER_SOURCE
                    or decoded_argv[6] != str(self.selection.launcher_path)
                    or decoded_argv[7] not in {"install", "resume", "update"}
                    or self.inspector._pidfd_exited(self._setup_peer_pidfd)
                    or _read_proc_start_ticks(Path("/proc"), record["setup_pid"]) != start
                    or _read_proc_effective_ids(Path("/proc"), record["setup_pid"]) != (uid, gid)):
                raise ValueError("setup process changed while reading credentials")
            return record["setup_pid"], uid, gid
        except (OSError, StopIteration, ValueError, IndexError, UnicodeError):
            raise ListenerActivationUnavailable("setup supervisor PID/start-time/root credentials are stale") from None

    def _resolve_current_projection(self, record: Mapping[str, Any]) -> Any:
        from .active_network_generation import RootActiveNetworkGenerationOwner
        try:
            rows = tuple(self.runtime.bindings.enrollment_catalog.active_network_generation_records)
            selected = _select_active_worker_row(rows, record["profile_id"])
            if self._owner is None:
                self._owner = RootActiveNetworkGenerationOwner.from_root_runtime(self.runtime)
            projection = self._owner.resolve_selected_worker(selected["network_id"], record["profile_id"])
            self._owner.verify_current(projection)
            if (projection.publication_receipt_handle != record["publication_receipt_handle"]
                    or projection.publication_sha256 != record["publication_sha256"]
                    or projection.service_generation_digest != record["service_generation_digest"]
                    or projection.enrollment_id != record["service_enrollment_id"]
                    or projection.profile_generation != self.service.profile_generations.get(record["profile_id"])
                    or projection.source_choice_selection_handle != selected.get("source_choice_selection_handle")):
                raise ValueError("daemon publication/source projection differs from setup selection")
            if self._projection is not None and (
                    self._projection.publication_sha256 != projection.publication_sha256
                    or self._projection.service_generation_digest != projection.service_generation_digest
                    or self._projection.source_choice_selection_handle != projection.source_choice_selection_handle):
                raise ValueError("active source projection changed during FD adoption")
            self._projection = projection
            return projection
        except Exception:
            raise ListenerActivationUnavailable("daemon could not independently reopen active source and publication") from None

    def _verify_message(self, message: Mapping[str, Any], record: Mapping[str, Any],
                        digest: str, operation: str) -> None:
        nonce = message.get("nonce") if operation == "daemon-ready-for-listener" else self._nonce
        if (not isinstance(nonce, str) or not re.fullmatch(r"[0-9a-f]{64}", nonce)
                or not secrets.compare_digest(hashlib.sha256(bytes.fromhex(nonce)).hexdigest(),
                                              record["nonce_sha256"])):
            raise ListenerActivationUnavailable("activation nonce differs from protected one-use journal")
        expected = _activation_message(
            operation=operation, activation_id=record["activation_id"], nonce=bytes.fromhex(nonce),
            record_sha256=digest, publication_handle=record["publication_receipt_handle"],
            publication_sha256=record["publication_sha256"],
            generation_sha256=record["service_generation_digest"],
            endpoint_sha256=record["prepared_endpoint_receipt_sha256"],
            socket_device=record["socket_device"], socket_inode=record["socket_inode"])
        _verify_packet(message, expected)

    def _await_adoption(self, activation_fd: int, prepared: Mapping[str, Any]) -> float:
        deadline = min(prepared["expires_monotonic"], time.monotonic() + 3.0)
        while time.monotonic() < deadline:
            current, _digest_value, _identity = _read_record_at(activation_fd)
            if current["state"] == "adopted":
                adopted_at = time.monotonic()
                if any(current[key] != prepared[key] for key in (
                        "activation_id", "setup_pid", "setup_start_ticks", "nonce_sha256",
                        "publication_receipt_handle", "publication_sha256", "service_generation_digest",
                        "prepared_endpoint_receipt_handle", "prepared_endpoint_receipt_sha256")):
                    raise ListenerActivationUnavailable("adopted record does not join this receiver transaction")
                if adopted_at > prepared["expires_monotonic"]:
                    raise ListenerActivationUnavailable("supervisor committed listener adoption after its deadline")
                return adopted_at
            if current["state"] == "cancelled":
                raise ListenerActivationUnavailable("setup cancelled ambiguous listener adoption")
            time.sleep(0.025)
        raise ListenerActivationUnavailable("supervisor did not commit listener adoption before its bounded deadline")


_RECEIVER_ISSUER = object()
