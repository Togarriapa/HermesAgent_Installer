"""Host-authorized bootstrap downloads and process custody.

This adapter only speaks the fixed host authority verbs. It has no subprocess,
shell, URL-fetch, or privilege-escalation fallback. A host must issue a fresh
one-use grant for each download, launch, read, status, and stop effect.
"""
from __future__ import annotations

import base64
import asyncio
import hashlib
import json
import math
import re
import time
from dataclasses import dataclass
from typing import Any, Callable, Mapping


class BootstrapCustodyError(RuntimeError):
    """The installed host authority or custodian denied/failed an effect."""

    def __init__(self, message: str, *, process_id: str | None = None,
                 generation: str | None = None, cleanup_verified: bool | None = None,
                 receipt_id: str | None = None):
        super().__init__(message)
        self.process_id = process_id
        self.generation = generation
        self.cleanup_verified = cleanup_verified
        self.receipt_id = receipt_id


class BootstrapCancelled(KeyboardInterrupt):
    """Bootstrap cancellation after custody cleanup was attempted."""

    def __init__(self, *, cleanup_verified: bool, process_id: str | None = None,
                 generation: str | None = None, receipt_id: str | None = None):
        super().__init__("managed Hermes bootstrap process cancelled")
        self.cleanup_verified = cleanup_verified
        self.process_id = process_id
        self.generation = generation
        self.receipt_id = receipt_id


@dataclass(frozen=True)
class ManagedCommandResult:
    exit_code: int
    stdout: bytes
    diagnostic: bytes
    timed_out: bool
    cleanup_verified: bool
    receipt_id: str
    process_id: str
    generation: str
    uid: int


@dataclass(frozen=True, slots=True)
class SelectedHermesRun:
    """Custody-validated run bound to one committed service generation.

    This records completion of an enrolled operation recipe only. In
    particular, a successful ``hermes-agent-health-v1`` process is not itself
    native Agent functional-health evidence; that requires the separate
    HI08/HI11 observed registration/request/result receipt.
    """

    operation_id: str
    enrollment_id: str
    generation_id: str
    generation_digest: str
    result: ManagedCommandResult

    @property
    def operation_completed(self) -> bool:
        return (self.result.exit_code == 0 and not self.result.timed_out
                and self.result.cleanup_verified is True)


class RootSelectedHermesOperations:
    """Run only the two protected parameter-free Hermes recipes.

    The enrollment receipt is supplied by the root-local bootstrap setup
    transport. The custody adapter performs authenticated process.start and
    control calls; this wrapper accepts no executable, argv, path or
    environment. A prepared receipt without a selected service enrollment is
    intentionally insufficient.
    """

    def __init__(self, custody: "BootstrapCustody", enrollment_receipt: Any):
        from .authority.bootstrap_enrollment import EnrollmentReceipt

        if type(custody) is not BootstrapCustody or type(enrollment_receipt) is not EnrollmentReceipt:
            raise TypeError("root-selected custody and typed enrollment receipt are required")
        if (enrollment_receipt.schema != 1 or enrollment_receipt.state != "committed"
                or len(enrollment_receipt.enrollment_ids) != 1
                or not enrollment_receipt.generation_id
                or not re.fullmatch(r"[0-9a-f]{64}", enrollment_receipt.generation_digest)
                or enrollment_receipt.expires_monotonic <= time.monotonic()):
            raise BootstrapCustodyError("Root enrollment is not a current committed service generation")
        self._custody = custody
        self._enrollment_id = enrollment_receipt.enrollment_ids[0]
        self._generation_id = enrollment_receipt.generation_id
        self._generation_digest = enrollment_receipt.generation_digest
        self._stage: SelectedHermesRun | None = None

    @property
    def generation_id(self) -> str:
        return self._generation_id

    @property
    def generation_digest(self) -> str:
        return self._generation_digest

    def _run(self, operation_id: str, *, timeout: float,
             cancelled: Callable[[], bool] | None = None) -> SelectedHermesRun:
        result = self._custody.run_selected_operation(
            enrollment_id=self._enrollment_id,
            generation=self._generation_id,
            operation_id=operation_id,
            timeout=timeout,
            cancelled=cancelled,
        )
        if (type(result) is not ManagedCommandResult or not result.receipt_id
                or not result.process_id or not result.generation
                or result.uid <= 0 or not result.cleanup_verified):
            raise BootstrapCustodyError("Root-selected Hermes operation lacks a clean custody receipt",
                cleanup_verified=False)
        return SelectedHermesRun(operation_id, self._enrollment_id,
            self._generation_id, self._generation_digest, result)

    def stage(self, *, timeout: float = 600.0,
              cancelled: Callable[[], bool] | None = None) -> SelectedHermesRun:
        if self._stage is not None:
            raise BootstrapCustodyError("This setup session already consumed its Hermes stage attempt")
        self._stage = self._run("hermes-agent-stage-v1", timeout=timeout, cancelled=cancelled)
        return self._stage


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
                       max_bytes: int, timeout: float = 30.0,
                       cancelled=None) -> tuple[str, str]:
        client = self._required_client()
        target = f"artifact:{artifact_id}:{sha256}"
        payload = {"schema": 1, "artifact_id": artifact_id, "sha256": sha256,
                   "max_bytes": max_bytes}
        digest = hashlib.sha256(_canonical_bytes(payload)).hexdigest()
        context = client.context(purpose="hermes-bootstrap",
            intent=f"Fetch pinned artifact {artifact_id}", operation="artifact.fetch",
            final_payload_digest=digest)
        grant = client.authorize_effect(context, capability="installer-bootstrap",
            target=target, recipient=None, request_digest=digest)
        response = client.fetch_artifact(grant, target=target, artifact_id=artifact_id,
            sha256=sha256, max_bytes=max_bytes, timeout=timeout, cancelled=cancelled)
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

    def _control(self, operation: str, process_id: str, generation: str,
                 fields: Mapping[str, Any] | None = None, *, timeout: float = 5.0,
                 cancelled: Callable[[], bool] | None = None):
        """Use the root's active-handle resolver; never derive a target locally."""
        if operation not in {"process.status", "process.read", "process.stop"}:
            raise BootstrapCustodyError("Host process control verb is not fixed")
        client = self._required_client()
        method = getattr(client, "process_control_operation", None)
        if not callable(method):
            raise BootstrapCustodyError("Root-selected process control is not installed")
        try:
            response = method(operation, process_id=process_id, generation=generation,
                              fields=fields or {}, timeout=timeout, cancelled=cancelled)
        except Exception:
            raise BootstrapCustodyError("Root-selected process control was denied") from None
        self._record_receipt(operation, process_id, response)
        return response

    def run_selected_operation(self, *, enrollment_id: str, generation: str,
                               operation_id: str, timeout: float,
                               output_limit: int = 4 * 1024 * 1024,
                               stdout_return_limit: int = 64 * 1024,
                               diagnostic_limit: int = 96 * 1024,
                               cancelled: Callable[[], bool] | None = None) -> ManagedCommandResult:
        """Run a protected stage/health recipe selected entirely by root.

        No executable, path, argv, environment, uid, or host target is accepted
        from the installer. The enrollment's immutable recipe supplies those.
        """
        if (operation_id not in {"hermes-agent-stage-v1", "hermes-agent-health-v1"}
                or not isinstance(enrollment_id, str) or not enrollment_id
                or not isinstance(generation, str) or not generation
                or isinstance(timeout, bool) or not isinstance(timeout, (int, float))
                or not math.isfinite(timeout) or not 0 < timeout <= 600
                or type(output_limit) is not int or not 1 <= output_limit <= 4 * 1024 * 1024
                or type(stdout_return_limit) is not int or not 0 <= stdout_return_limit <= output_limit
                or type(diagnostic_limit) is not int or not 1 <= diagnostic_limit <= 1024 * 1024):
            raise ValueError("selected Hermes operation or bounds are invalid")
        client = self._required_client()
        starter = getattr(client, "start_enrolled_process_operation", None)
        if not callable(starter):
            raise BootstrapCustodyError("Root-selected Hermes operation start is not installed")
        try:
            start = starter(enrollment_id=enrollment_id, generation=generation,
                operation_id=operation_id, parameters={}, purpose="hermes-bootstrap",
                intent=f"Run enrolled Hermes operation {operation_id}", timeout=min(timeout, 30.0),
                cancelled=cancelled)
            started = _json_response(start, label="process.start")
        except Exception:
            receipt_id = str(getattr(locals().get("start"), "receipt_id", "")) or None
            raise BootstrapCustodyError("Root-selected Hermes operation receipt is unavailable; "
                "process cleanup is unverified", cleanup_verified=False,
                receipt_id=receipt_id) from None
        receipt_id = str(getattr(start, "receipt_id", ""))
        process_id, process_generation = started.get("process_id"), started.get("generation")
        uid = started.get("uid")
        valid_handle = (isinstance(process_id, str) and re.fullmatch(r"[0-9a-f]{32}", process_id)
                        and isinstance(process_generation, str) and bool(process_generation))
        if (not valid_handle or type(uid) is not int or uid <= 0 or not receipt_id):
            verified = False
            if valid_handle:
                try:
                    stop_result = self._control("process.stop", process_id,
                        process_generation, {"reason": "rollback", "grace_seconds": 5}, timeout=5.0)
                    stop_body = dict(stop_result.result)
                    verified = (stop_body.get("closed") is True
                        and stop_body.get("reap_state") in {"complete", "already-exited"})
                except Exception:
                    verified = False
            raise BootstrapCustodyError("Root-selected operation returned an invalid process receipt",
                process_id=process_id if isinstance(process_id, str) else None,
                generation=process_generation if isinstance(process_generation, str) else None,
                cleanup_verified=verified, receipt_id=receipt_id or None)

        stdout, diagnostic = bytearray(), bytearray()
        total = 0
        deadline = time.monotonic() + float(timeout)
        cleanup_verified = False

        def stop(reason: str) -> bool:
            response = self._control("process.stop", process_id, process_generation,
                {"reason": reason, "grace_seconds": 5}, timeout=5.0)
            result = dict(response.result)
            good = (result.get("closed") is True
                    and result.get("reap_state") in {"complete", "already-exited"})
            return good

        try:
            eof = {"stdout": False, "stderr": False}
            while time.monotonic() < deadline:
                status = self._control("process.status", process_id, process_generation,
                    timeout=min(5.0, max(.1, deadline-time.monotonic())), cancelled=cancelled)
                state = status.state
                result = dict(status.result)
                for stream in ("stdout", "stderr"):
                    if eof[stream]:
                        continue
                    maximum = min(65536, max(1, output_limit-total))
                    reply = self._control("process.read", process_id, process_generation,
                        {"stream": stream, "maximum_bytes": maximum},
                        timeout=min(1.0, max(.1, deadline-time.monotonic())), cancelled=cancelled)
                    read_result = dict(reply.result)
                    try:
                        chunk = base64.b64decode(read_result["data_bytes"], validate=True)
                        eof[stream] = read_result["eof"]
                    except (KeyError, ValueError, TypeError):
                        raise BootstrapCustodyError("Root process read receipt was malformed") from None
                    if type(eof[stream]) is not bool or len(chunk) > maximum:
                        raise BootstrapCustodyError("Root process read receipt exceeded its selected bound")
                    total += len(chunk)
                    if total > output_limit:
                        raise BootstrapCustodyError("Root process output exceeded its bounded capture")
                    if stream == "stdout":
                        stdout.extend(chunk[:max(0, stdout_return_limit-len(stdout))])
                    diagnostic.extend(b"[" + stream.encode("ascii") + b"] " + chunk)
                    if len(diagnostic) > diagnostic_limit:
                        del diagnostic[:-diagnostic_limit]
                if state in {"exited", "failed", "stopped"}:
                    # After exit, keep reading until the root reports EOF for
                    # both streams so trailing stderr is not lost.
                    if not all(eof.values()):
                        continue
                    code = result.get("exit_code")
                    if type(code) is not int:
                        raise BootstrapCustodyError("Root process status omitted its exit code")
                    cleanup_verified = stop("shutdown")
                    if not cleanup_verified:
                        raise BootstrapCustodyError("Root custodian did not verify operation cleanup",
                            process_id=process_id, generation=process_generation,
                            cleanup_verified=False, receipt_id=receipt_id)
                    return ManagedCommandResult(code, bytes(stdout), bytes(diagnostic), False,
                        True, receipt_id, process_id, process_generation, uid)
                time.sleep(min(.05, max(0.0, deadline-time.monotonic())))
            cleanup_verified = stop("cancel")
            if not cleanup_verified:
                raise BootstrapCustodyError("Timed out operation cleanup could not be verified",
                    process_id=process_id, generation=process_generation,
                    cleanup_verified=False, receipt_id=receipt_id)
            return ManagedCommandResult(124, bytes(stdout), bytes(diagnostic), True,
                True, receipt_id, process_id, process_generation, uid)
        except (KeyboardInterrupt, asyncio.CancelledError):
            try:
                cleanup_verified = stop("cancel")
            except Exception:
                cleanup_verified = False
            raise BootstrapCancelled(cleanup_verified=cleanup_verified, process_id=process_id,
                generation=process_generation, receipt_id=receipt_id) from None
        except Exception as exc:
            if not cleanup_verified:
                try:
                    cleanup_verified = stop("rollback")
                except Exception:
                    cleanup_verified = False
            raise BootstrapCustodyError("Root-selected operation failed; cleanup "
                + ("was verified" if cleanup_verified else "is unverified"),
                process_id=process_id, generation=process_generation,
                cleanup_verified=cleanup_verified, receipt_id=receipt_id) from None

    def run_process(self, **_physical_launch) -> ManagedCommandResult:
        """Reject legacy caller-selected physical process launches."""
        raise BootstrapCustodyError(
            "Physical-path process launch is disabled; use an enrolled root-selected operation",
            cleanup_verified=True)
