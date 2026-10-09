"""Host-authorized bootstrap downloads and process custody.

This adapter only speaks the fixed host authority verbs. It has no subprocess,
shell, URL-fetch, or privilege-escalation fallback. A host must issue a fresh
one-use grant for each download, launch, read, status, and stop effect.
"""
from __future__ import annotations

import base64
import hashlib
import inspect
import json
import math
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence


class BootstrapCustodyError(RuntimeError):
    """The installed host authority or custodian denied/failed an effect."""


class BootstrapCancelled(KeyboardInterrupt):
    """Bootstrap cancellation after custody cleanup was attempted."""

    def __init__(self, *, cleanup_verified: bool):
        super().__init__("managed Hermes bootstrap process cancelled")
        self.cleanup_verified = cleanup_verified


@dataclass(frozen=True)
class ManagedCommandResult:
    exit_code: int
    stdout: bytes
    diagnostic: bytes
    timed_out: bool
    cleanup_verified: bool
    receipt_id: str
    process_id: str
    uid: int


def _canonical_bytes(value: Mapping[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _json_response(response: Any, *, label: str) -> dict[str, Any]:
    if getattr(response, "status", None) != 200:
        raise BootstrapCustodyError(f"Host {label} effect was denied")
    try:
        body = json.loads(response.body.decode("utf-8"))
    except (AttributeError, UnicodeError, ValueError):
        raise BootstrapCustodyError(f"Host {label} response was malformed") from None
    if not isinstance(body, dict):
        raise BootstrapCustodyError(f"Host {label} response was malformed")
    return body


class BootstrapCustody:
    """Adapter over the fixed root-owned AuthorityClient API."""

    def __init__(self, client: Any | None = None, *, journal=None,
                 journal_operation: str = "hermes-agent"):
        if client is None:
            try:
                from .authority import AuthorityClient
                client = AuthorityClient.for_current_process()
            except (ImportError, OSError, ValueError):
                client = None
        self.client = client
        self.journal = journal
        self.journal_operation = journal_operation

    def _record_receipt(self, step: str, target: str, response: Any) -> None:
        if self.journal is not None:
            self.journal.event(self.journal_operation, step, "host_effect_receipt", {
                "target": target, "receipt_id": str(getattr(response, "receipt_id", "")),
                "status": getattr(response, "status", None),
            })

    def _required_client(self):
        if self.client is None:
            raise BootstrapCustodyError("Host authority is not installed or enrolled")
        return self.client

    def fetch_artifact(self, *, artifact_id: str, sha256: str,
                       max_bytes: int, timeout: float = 30.0) -> tuple[str, str]:
        client = self._required_client()
        target = f"artifact:{artifact_id}:{sha256}"
        payload = {"schema": 1, "artifact_id": artifact_id, "sha256": sha256,
                   "max_bytes": max_bytes}
        digest = hashlib.sha256(_canonical_bytes(payload)).hexdigest()
        context = client.context(purpose="hermes-bootstrap",
            intent=f"Fetch pinned artifact {artifact_id}", operation="artifact.fetch",
            final_payload_digest=digest)
        grant = client.authorize_effect(context, capability="hermes-bootstrap",
            target=target, recipient=None, request_digest=digest)
        response = client.fetch_artifact(grant, target=target, artifact_id=artifact_id,
            sha256=sha256, max_bytes=max_bytes, timeout=timeout)
        self._record_receipt("artifact.fetch", target, response)
        if response.status != 200:
            raise BootstrapCustodyError("Pinned host artifact fetch was denied")
        try:
            receipt = json.loads(response.body.decode("utf-8"))
        except (AttributeError, UnicodeError, ValueError):
            raise BootstrapCustodyError("Host artifact fetch receipt was malformed") from None
        if (not isinstance(receipt, dict) or receipt.get("artifact_id") != artifact_id
                or receipt.get("sha256") != sha256
                or type(receipt.get("size_bytes")) is not int
                or not 0 <= receipt["size_bytes"] <= max_bytes
                or not isinstance(receipt.get("version"), str)
                or receipt.get("store_id") != f"artifact:{artifact_id}:{sha256}"):
            raise BootstrapCustodyError("Host artifact receipt does not match the requested immutable artifact")
        return receipt["store_id"], str(getattr(response, "receipt_id", ""))

    def _control(self, *, profile_id: str, data_root: Path, operation: str,
                 payload: Mapping[str, Any], source_receipt: str | None = None,
                 timeout: float = 5.0) -> dict[str, Any]:
        client = self._required_client()
        body = _canonical_bytes(payload)
        verb = operation.removeprefix("process.")
        if verb not in {"status", "read", "write", "stop"}:
            raise BootstrapCustodyError("Host process control verb is not fixed")
        target = f"hermes-profile-control:{profile_id}:{data_root.resolve(strict=True)}:{verb}"
        context = client.context(purpose="hermes-bootstrap",
            intent=f"Control owned Hermes bootstrap process: {operation}",
            operation=operation,
            final_payload_digest=hashlib.sha256(body).hexdigest(),
            source_receipt_handles=(source_receipt,) if source_receipt else ())
        if context.profile_id != profile_id:
            raise BootstrapCustodyError("Host authority profile does not match the requested process")
        grant = client.authorize_effect(context, capability="hermes-process-control", target=target,
            recipient=None, request_digest=hashlib.sha256(body).hexdigest())
        response = client.process_control(grant, operation=operation, target=target,
                                          payload=body, timeout=timeout)
        self._record_receipt(operation, target, response)
        return _json_response(response, label=operation)

    def run_process(self, *, profile_id: str | None = None, executable: Path,
                    artifact_root: Path, cwd: Path, data_root: Path,
                    argv: Sequence[str], env_allowlist: Mapping[str, str],
                    timeout: float, output_limit: int = 4 * 1024 * 1024,
                    stdout_return_limit: int = 64 * 1024,
                    diagnostic_limit: int = 96 * 1024,
                    child_artifact_refs: Mapping[str, str] | None = None) -> ManagedCommandResult:
        if (isinstance(timeout, bool) or not isinstance(timeout, (int, float))
                or not math.isfinite(timeout) or not 0 < timeout <= 600
                or type(output_limit) is not int or not 1 <= output_limit <= 4 * 1024 * 1024
                or type(stdout_return_limit) is not int or not 0 <= stdout_return_limit <= output_limit
                or type(diagnostic_limit) is not int or not 1 <= diagnostic_limit <= 1024 * 1024):
            raise ValueError("managed bootstrap process bounds are invalid")
        client = self._required_client()
        try:
            from .authority import canonical_digest, canonical_profile_target, profile_launch_envelope
        except ImportError:
            raise BootstrapCustodyError("Host process launch contract is not installed") from None
        # The first context is used only to obtain the host-selected profile
        # identity. The effect context below is issued after the exact launch
        # envelope and digest have been computed.
        discovery = client.context(purpose="hermes-bootstrap",
            intent="Resolve the host-enrolled profile for a pinned bootstrap stage",
            operation="process.start")
        bound_profile = discovery.profile_id
        if profile_id is not None and profile_id != bound_profile:
            raise BootstrapCustodyError("Host authority profile does not match the requested launch")
        profile_id = bound_profile
        executable = executable.resolve(strict=True)
        data_root = data_root.resolve(strict=True)
        artifact_root = artifact_root.resolve(strict=True)
        launch_target = canonical_profile_target(profile_id, executable, data_root)
        executable_digest = hashlib.sha256(executable.read_bytes()).hexdigest()
        launch_args = dict(target=launch_target, profile_id=profile_id,
            executable=executable, artifact_sha256=executable_digest,
            artifact_root=artifact_root, cwd=cwd, data_root=data_root,
            argv=argv, env_allowlist=env_allowlist,
            max_lifetime_seconds=max(1, min(int(timeout), 600)),
            max_output_bytes=output_limit, stdin_mode="closed")
        if child_artifact_refs:
            if "child_artifact_refs" not in inspect.signature(profile_launch_envelope).parameters:
                raise BootstrapCustodyError("Host launch contract cannot pin opaque installer artifact references")
            launch_args["child_artifact_refs"] = dict(child_artifact_refs)
        launch = profile_launch_envelope(**launch_args)
        launch_digest = canonical_digest(launch)
        context = client.context(purpose="hermes-bootstrap",
            intent="Run one pinned Hermes bootstrap stage under host custody",
            operation="process.start", final_payload_digest=launch_digest,
            source_contexts=(discovery,))
        if context.profile_id != profile_id:
            raise BootstrapCustodyError("Host authority profile changed while binding the launch")
        grant = client.authorize_effect(context, capability="hermes-profile-invoke",
            target=launch_target, recipient=None, request_digest=launch_digest)
        start_response = client.process_start(grant, target=launch_target,
            launch=launch, timeout=min(5.0, timeout))
        self._record_receipt("process.start", launch_target, start_response)
        started = _json_response(start_response, label="process.start")
        start_receipt = str(getattr(start_response, "receipt_id", ""))
        possible_process_id = started.get("process_id")
        possible_generation = started.get("generation")
        required = {"process_id", "generation", "pid", "uid", "namespace_id",
                    "started_at_monotonic", "stdout_cursor", "stderr_cursor",
                    "expires_at_monotonic"}
        if (not required.issubset(started) or not isinstance(started["process_id"], str)
                or not started["process_id"] or type(started.get("uid")) is not int
                or started["uid"] <= 0):
            if isinstance(possible_process_id, str) and possible_process_id and isinstance(possible_generation, str) and possible_generation:
                try:
                    self._stop(profile_id, data_root, possible_process_id, possible_generation,
                               source_receipt=start_receipt or None)
                except BaseException:
                    pass
            raise BootstrapCustodyError("Host process.start receipt lacks a valid owned process handle")
        process_id = started["process_id"]
        generation = started["generation"]
        if not start_receipt:
            self._stop(profile_id, data_root, process_id, generation)
            raise BootstrapCustodyError("Host process.start omitted its source receipt handle")
        stdout_cursor = started["stdout_cursor"]
        stderr_cursor = started["stderr_cursor"]
        if not isinstance(generation, str) or not generation:
            raise BootstrapCustodyError("Host process.start receipt omitted its custody generation")
        if (type(stdout_cursor) is not int or stdout_cursor < 0
                or type(stderr_cursor) is not int or stderr_cursor < 0):
            try:
                self._stop(profile_id, data_root, process_id, generation,
                           source_receipt=start_receipt)
            except BaseException:
                pass
            raise BootstrapCustodyError("Host process.start receipt is malformed")
        stdout = bytearray()
        diagnostic = bytearray()
        total = 0
        effective_timeout = min(timeout, 600.0)
        deadline = time.monotonic() + effective_timeout
        cleanup_verified = False

        def read_stream(stream: str, cursor: int, available: int) -> tuple[int, bool]:
            nonlocal total
            while cursor < available:
                request = {"schema": 1, "process_id": process_id, "generation": generation,
                           "stream": stream, "after_cursor": cursor,
                           "max_bytes": min(65536, available - cursor)}
                reply = self._control(profile_id=profile_id, data_root=data_root,
                    operation="process.read", payload=request, source_receipt=start_receipt,
                    timeout=min(5.0, max(0.1, deadline-time.monotonic())))
                try:
                    chunk = base64.b64decode(reply["data"], validate=True)
                    next_cursor = reply["cursor"]
                    eof = reply["eof"]
                except (KeyError, ValueError, TypeError):
                    raise BootstrapCustodyError("Host process.read response was malformed") from None
                if (type(next_cursor) is not int or next_cursor != cursor + len(chunk)
                        or type(eof) is not bool or len(chunk) > 65536):
                    raise BootstrapCustodyError("Host process.read cursor or data bound was invalid")
                cursor = next_cursor
                total += len(chunk)
                if total > output_limit:
                    raise BootstrapCustodyError("Host process output exceeded its enrolled byte limit")
                if stream == "stdout":
                    stdout.extend(chunk[:max(0, stdout_return_limit - len(stdout))])
                diagnostic.extend((b"[" + stream.encode("ascii") + b"] " + chunk))
                if len(diagnostic) > diagnostic_limit:
                    del diagnostic[:-diagnostic_limit]
                if eof and cursor >= available:
                    return cursor, True
                if not chunk:
                    break
            return cursor, False

        try:
            while time.monotonic() < deadline:
                status = self._control(profile_id=profile_id, data_root=data_root,
                    operation="process.status", payload={"schema": 1, "process_id": process_id,
                        "generation": generation}, source_receipt=start_receipt,
                    timeout=min(5.0, max(0.1, deadline-time.monotonic())))
                state = status.get("state")
                if state not in {"starting", "running", "exited", "stopped", "failed"}:
                    raise BootstrapCustodyError("Host process.status returned an unknown state")
                for name, cursor_key in (("stdout", "stdout_cursor"), ("stderr", "stderr_cursor")):
                    available = status.get(cursor_key)
                    cursor = stdout_cursor if name == "stdout" else stderr_cursor
                    if type(available) is not int or available < cursor:
                        raise BootstrapCustodyError("Host process.status returned an invalid output cursor")
                    cursor, _ = read_stream(name, cursor, available)
                    if name == "stdout":
                        stdout_cursor = cursor
                    else:
                        stderr_cursor = cursor
                if state in {"exited", "failed", "stopped"}:
                    code = status.get("exit_code")
                    if type(code) is not int:
                        raise BootstrapCustodyError("Host process.status omitted the process exit code")
                    return ManagedCommandResult(code, bytes(stdout), bytes(diagnostic),
                        False, True, str(getattr(start_response, "receipt_id", "")), process_id,
                        started["uid"])
                time.sleep(min(0.05, max(0.0, deadline-time.monotonic())))
            self._stop(profile_id, data_root, process_id, generation, source_receipt=start_receipt)
            cleanup_verified = True
            return ManagedCommandResult(124, bytes(stdout), bytes(diagnostic), True,
                cleanup_verified, str(getattr(start_response, "receipt_id", "")), process_id,
                started["uid"])
        except KeyboardInterrupt:
            try:
                self._stop(profile_id, data_root, process_id, generation, source_receipt=start_receipt)
                cleanup_verified = True
            except BaseException:
                cleanup_verified = False
            raise BootstrapCancelled(cleanup_verified=cleanup_verified) from None
        except BaseException:
            try:
                self._stop(profile_id, data_root, process_id, generation, source_receipt=start_receipt)
                cleanup_verified = True
            except BaseException:
                cleanup_verified = False
            if not cleanup_verified:
                raise BootstrapCustodyError("Host process failed and complete cleanup could not be verified") from None
            raise

    def _stop(self, profile_id: str, data_root: Path, process_id: str,
              generation: str, *, source_receipt: str | None = None) -> None:
        stopped = self._control(profile_id=profile_id, data_root=data_root,
            operation="process.stop", payload={"schema": 1, "process_id": process_id,
                "generation": generation}, source_receipt=source_receipt, timeout=5.0)
        if stopped.get("stopped") is not True:
            raise BootstrapCustodyError("Host process.stop did not verify complete cleanup")
