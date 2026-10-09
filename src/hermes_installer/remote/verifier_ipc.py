"""Authenticated, narrow Unix IPC between browser gateway and policy verifier.

No Cloudflare API credential or resolver exists in the gateway process. The verifier
accepts only a signed Access JWT and fixed action/session bindings; it has no generic
URL, account, method, or secret-export operation.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import math
import os
import secrets
import socket
import stat
import struct
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping

from .gateway import GatewayDenied, Principal, RemotePolicy, validate_access_jwt
from .policy import FreshAccessPolicyAuthority


MAX_REQUEST_BYTES = 20_480
MAX_RESPONSE_BYTES = 4_096
MAX_PENDING_READS = 4
MAX_IPC_SECONDS = 9.0
PROFILE_ID = "hermes-desktop"
_ACTIONS = frozenset({"issue", "socket", "renew"})
_ID = __import__("re").compile(r"[A-Za-z0-9_-]{20,128}")
_DIGEST = __import__("re").compile(r"[0-9a-f]{64}")


class VerifierIPCError(GatewayDenied):
    """Verifier channel or decision did not satisfy the fixed protocol."""


@dataclass(frozen=True, slots=True)
class PolicyGrant:
    action: str
    session_id: str
    principal: Principal
    observed_start_monotonic: float
    observed_end_monotonic: float
    jwt_deadline_monotonic: float
    valid_until_monotonic: float
    config_digest: str
    nonce: str


class PolicyVerifierClient:
    """Gateway-side client. It knows a socket path and verifier UID, never a secret ref."""

    def __init__(self, socket_path: Path, *, verifier_uid: int, config_digest: str,
                 profile_id: str = PROFILE_ID, monotonic: Callable[[], float] = time.monotonic):
        if not socket_path.is_absolute() or verifier_uid <= 0 or not isinstance(config_digest,str) or not _DIGEST.fullmatch(config_digest):
            raise ValueError("fixed verifier socket identity and config digest are required")
        if profile_id != PROFILE_ID:
            raise ValueError("only the Hermes Desktop profile is supported")
        self.socket_path = socket_path
        self.verifier_uid = verifier_uid
        self.config_digest = config_digest
        self.profile_id = profile_id
        self.monotonic = monotonic
        self._used_nonces: dict[str, float] = {}
        self._nonce_lock = asyncio.Lock()

    async def authorize(self, *, action: str, session_id: str, access_jwt: str,
                        expected: Principal) -> PolicyGrant:
        if action not in _ACTIONS or not isinstance(session_id,str) or not _ID.fullmatch(session_id):
            raise VerifierIPCError("invalid verifier action/session")
        if not isinstance(access_jwt, str) or not 1 <= len(access_jwt) <= 16_384:
            raise VerifierIPCError("invalid verifier identity token")
        nonce = secrets.token_urlsafe(32)
        request = {
            "version": 1, "action": action, "nonce": nonce,
            "profile_id": self.profile_id, "session_id": session_id,
            "config_digest": self.config_digest, "access_jwt": access_jwt,
        }
        wire = json.dumps(request, separators=(",", ":"), ensure_ascii=True).encode("ascii") + b"\n"
        if len(wire) > MAX_REQUEST_BYTES:
            raise VerifierIPCError("verifier request exceeds bound")
        started = self.monotonic()
        deadline = started + MAX_IPC_SECONDS
        def remaining():
            value = deadline - self.monotonic()
            if value <= 0:
                raise VerifierIPCError("verifier request exceeded its hard deadline")
            return value
        writer = None
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_unix_connection(str(self.socket_path), limit=MAX_RESPONSE_BYTES + 1),
                timeout=min(2, remaining()),
            )
            self._check_server_peer(writer.get_extra_info("socket"))
            writer.write(wire)
            await asyncio.wait_for(writer.drain(), timeout=min(2, remaining()))
            line = await asyncio.wait_for(reader.readline(), timeout=remaining())
            if not line or len(line) > MAX_RESPONSE_BYTES or not line.endswith(b"\n"):
                raise VerifierIPCError("verifier response is missing or oversized")
            reply = _decode_strict_json(line[:-1])
            return await self._consume_reply(reply, request, expected, started)
        except VerifierIPCError:
            raise
        except Exception:
            raise VerifierIPCError("current Access verifier is unavailable") from None
        finally:
            if writer is not None:
                writer.close()
                try:
                    await asyncio.wait_for(writer.wait_closed(), timeout=1)
                except Exception:
                    pass

    async def _consume_reply(self, reply: Any, request: Mapping[str, Any], expected: Principal,
                             request_started: float) -> PolicyGrant:
        common = {"version", "action", "nonce", "profile_id", "session_id", "config_digest", "decision", "code"}
        if not isinstance(reply, dict) or not common.issubset(reply):
            raise VerifierIPCError("malformed verifier decision")
        if any(reply.get(k) != request[k] for k in ("action", "nonce", "profile_id", "session_id", "config_digest")):
            raise VerifierIPCError("verifier decision binding mismatch")
        if type(reply.get("version")) is not int or reply.get("version") != 1 or reply.get("decision") is not True or reply.get("code") != "ALLOW":
            raise VerifierIPCError("fresh current Access policy denied")
        required = common | {"email", "subject", "token_fingerprint", "observed_start_monotonic",
                             "observed_end_monotonic", "jwt_deadline_monotonic", "valid_until_monotonic"}
        if set(reply) != required:
            raise VerifierIPCError("verifier decision fields are invalid")
        email, subject = reply["email"], reply["subject"]
        fingerprint = reply["token_fingerprint"]
        if not isinstance(email, str) or not isinstance(subject, str) or not isinstance(fingerprint, str):
            raise VerifierIPCError("verifier principal binding is invalid")
        if email.casefold() != expected.email.casefold() or subject != expected.subject:
            raise VerifierIPCError("verifier principal binding mismatch")
        if not secrets.compare_digest(fingerprint, expected.token_fingerprint):
            raise VerifierIPCError("verifier token binding mismatch")
        now = self.monotonic()
        observed = _finite_number(reply["observed_start_monotonic"])
        finished = _finite_number(reply["observed_end_monotonic"])
        jwt_deadline = _finite_number(reply["jwt_deadline_monotonic"])
        valid_until = _finite_number(reply["valid_until_monotonic"])
        if (observed < request_started - 0.01 or observed > finished or finished > now + 0.01
                or now - observed > MAX_IPC_SECONDS or valid_until > observed + 60
                or valid_until > jwt_deadline or valid_until <= now):
            raise VerifierIPCError("verifier decision is stale or exceeds its lease bound")
        async with self._nonce_lock:
            self._purge_nonces(now)
            if len(self._used_nonces) >= 4096 or reply["nonce"] in self._used_nonces:
                raise VerifierIPCError("verifier decision was replayed or capacity is exhausted")
            self._used_nonces[reply["nonce"]] = valid_until
        return PolicyGrant(request["action"], request["session_id"], expected, observed, finished,
                           jwt_deadline, valid_until, request["config_digest"], request["nonce"])

    def _purge_nonces(self, now: float) -> None:
        self._used_nonces = {key: expiry for key, expiry in self._used_nonces.items() if expiry > now}

    def _check_server_peer(self, conn: socket.socket | None) -> None:
        _assert_client_socket_path(self.socket_path, self.verifier_uid)
        if conn is None or not hasattr(socket, "SO_PEERCRED"):
            raise VerifierIPCError("authenticated Unix peer credentials are unavailable")
        raw = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
        _pid, uid, _gid = struct.unpack("3i", raw)
        if uid != self.verifier_uid:
            raise VerifierIPCError("verifier socket peer UID mismatch")


def verifier_config_digest(identity, *, issuer: str, audience: str,
                           profile_id: str = PROFILE_ID) -> str:
    """Canonical nonsecret digest binding journal IDs and all policy inputs."""
    if audience != identity.audience:
        raise ValueError("Access audience must match the journaled application audience tag")
    fields = {
        "account_id": identity.account_id,
        "application_id": identity.application_id,
        "policy_id": identity.policy_id,
        "identity_provider_id": identity.identity_provider_id,
        "hostname": identity.hostname.casefold(),
        "application_name": identity.application_name,
        "policy_name": identity.policy_name,
        "identity_provider_name": identity.identity_provider_name,
        "allowed_emails": sorted(x.casefold() for x in identity.allowed_emails),
        "application_audience": identity.audience,
        "issuer": issuer,
        "audience": audience,
        "profile_id": profile_id,
    }
    return hashlib.sha256(json.dumps(fields, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


@dataclass(frozen=True, slots=True)
class VerifierRuntime:
    """Custodian-only immutable config; never construct this in the gateway."""

    policy: RemotePolicy
    authority: FreshAccessPolicyAuthority
    profile_id: str
    config_digest: str

    def __post_init__(self) -> None:
        if self.profile_id != PROFILE_ID or not isinstance(self.config_digest, str) or not _DIGEST.fullmatch(self.config_digest):
            raise ValueError("fixed policy verifier profile/config digest required")
        identity = self.authority.identity
        if (self.policy.hostname.casefold() != identity.hostname
                or self.policy.audience != identity.audience
                or frozenset(x.casefold() for x in self.policy.allowed_emails) != identity.allowed_emails
                or verifier_config_digest(identity,issuer=self.policy.issuer,audience=self.policy.audience,profile_id=self.profile_id)!=self.config_digest):
            raise ValueError("verifier JWT and exact Cloudflare resource identities differ")


class PolicyVerifierService:
    """Cancellable bounded verifier service over one protected AF_UNIX socket."""

    def __init__(self, runtime: VerifierRuntime, *, gateway_uid: int,
                 service_uid: int, service_gid: int | None = None):
        if (type(gateway_uid) is not int or gateway_uid <= 0
                or type(service_uid) is not int or service_uid <= 0
                or service_uid == gateway_uid):
            raise ValueError("distinct dedicated non-root gateway and verifier UIDs are required")
        self.runtime = runtime
        self.gateway_uid = gateway_uid
        self.service_uid = service_uid
        self.service_gid = service_gid
        self._pool = ThreadPoolExecutor(max_workers=MAX_PENDING_READS, thread_name_prefix="access-policy-read")
        self._slots = threading.BoundedSemaphore(MAX_PENDING_READS)
        self._connections = threading.BoundedSemaphore(MAX_PENDING_READS * 2)
        self._seen: dict[str, float] = {}
        self._seen_lock = threading.Lock()
        self._active_cancellations: set[threading.Event] = set()
        self._active_futures: set[asyncio.Future] = set()
        self._active_lock = threading.Lock()
        self._server = None
        self._socket_path: Path | None = None
        self._socket_identity: tuple[int, int] | None = None

    async def start(self, socket_path: Path) -> None:
        if os.geteuid() != self.service_uid:
            raise RuntimeError("verifier must run under its own dedicated service UID")
        if not socket_path.is_absolute() or socket_path.exists() or socket_path.is_symlink():
            raise RuntimeError("verifier socket path must be absolute and unoccupied")
        parent = socket_path.parent
        _assert_safe_socket_directories(parent, allowed_owners={0, self.service_uid})
        info = parent.stat(follow_symlinks=False)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid not in {0, self.service_uid}:
            raise RuntimeError("verifier socket parent must be root/service-owned and not group/world writable")
        self._server = await asyncio.start_unix_server(self._handle, path=str(socket_path), limit=MAX_REQUEST_BYTES + 1)
        try:
            os.chmod(socket_path, 0o660 if self.service_gid is not None else 0o600)
            if self.service_gid is not None:
                os.chown(socket_path, self.service_uid, self.service_gid)
            info = os.stat(socket_path, follow_symlinks=False)
            if not stat.S_ISSOCK(info.st_mode) or info.st_uid != self.service_uid:
                raise RuntimeError("verifier socket ownership could not be established")
            self._socket_identity = (info.st_dev, info.st_ino)
            self._socket_path = socket_path
        except Exception:
            self._server.close()
            await self._server.wait_closed()
            try:
                socket_path.unlink()
            except OSError:
                pass
            raise

    async def close(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
        with self._active_lock:
            for event in tuple(self._active_cancellations):
                event.set()
        pending = tuple(self._active_futures)
        if pending:
            _done, still_running = await asyncio.wait(pending, timeout=MAX_IPC_SECONDS + 1)
            if still_running:
                # Do not block the event loop or pretend that cancellation killed
                # an arbitrary callback. The owning systemd scope must stop its
                # cgroup and supply custody evidence before this service is gone.
                raise RuntimeError("verifier worker exceeded bounded shutdown; stop the owned service scope")
        self._pool.shutdown(wait=True, cancel_futures=True)
        if self._socket_path is not None:
            try:
                info = os.stat(self._socket_path, follow_symlinks=False)
                if self._socket_identity == (info.st_dev, info.st_ino) and stat.S_ISSOCK(info.st_mode):
                    self._socket_path.unlink()
            except OSError:
                pass
            self._socket_path = None

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        if not self._connections.acquire(blocking=False):
            writer.close()
            return
        cancel = threading.Event()
        operation = None
        try:
            self._check_client_peer(writer.get_extra_info("socket"))
            line = await asyncio.wait_for(reader.readline(), timeout=2)
            if not line or len(line) > MAX_REQUEST_BYTES or not line.endswith(b"\n"):
                await self._deny(writer, None)
                return
            request = _decode_strict_json(line[:-1])
            if not self._valid_request(request):
                await self._deny(writer, request if isinstance(request, dict) else None)
                return
            now = time.monotonic()
            with self._seen_lock:
                self._seen = {key: expires for key, expires in self._seen.items() if expires > now}
                replayed = len(self._seen) >= 4096 or request["nonce"] in self._seen
                if not replayed:
                    self._seen[request["nonce"]] = now + 60
            if replayed:
                await self._deny(writer, request)
                return
            if not self._slots.acquire(blocking=False):
                await self._deny(writer, request)
                return
            operation = {"cancel": cancel, "released": False}
            with self._active_lock:
                self._active_cancellations.add(cancel)
            loop = asyncio.get_running_loop()
            future = loop.run_in_executor(self._pool, self._evaluate, request, cancel)
            operation["future"] = future
            self._active_futures.add(future)
            def finished(_):
                self._active_futures.discard(future)
                if operation and not operation["released"]:
                    operation["future_done"] = True
                    operation["released"] = True
                    self._slots.release()
                    with self._active_lock:
                        self._active_cancellations.discard(cancel)
            future.add_done_callback(finished)
            disconnect = asyncio.create_task(reader.read(1))
            try:
                done, _pending = await asyncio.wait(
                    {future, disconnect}, timeout=MAX_IPC_SECONDS, return_when=asyncio.FIRST_COMPLETED,
                )
                if future not in done:
                    cancel.set()
                    disconnect.cancel()
                    await self._deny(writer, request)
                    return
                if disconnect in done:
                    cancel.set()
                    await self._deny(writer, request)
                    return
            except asyncio.CancelledError:
                cancel.set()
                disconnect.cancel()
                raise
            if future not in done:
                cancel.set()
                disconnect.cancel()
                await self._deny(writer, request)
                return
            disconnect.cancel()
            try:
                decision = future.result()
            except Exception:
                decision = None
            if decision is None or cancel.is_set():
                await self._deny(writer, request)
                return
            line = json.dumps(decision, separators=(",", ":"), ensure_ascii=True).encode("ascii") + b"\n"
            if len(line) > MAX_RESPONSE_BYTES:
                await self._deny(writer, request)
                return
            writer.write(line)
            await asyncio.wait_for(writer.drain(), timeout=1)
        except asyncio.CancelledError:
            cancel.set()
            raise
        except Exception:
            cancel.set()
            await self._deny(writer, None)
        finally:
            self._connections.release()
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), timeout=1)
            except Exception:
                pass

    def _valid_request(self, request: Any) -> bool:
        required = {"version", "action", "nonce", "profile_id", "session_id", "config_digest", "access_jwt"}
        return (
            isinstance(request, dict) and set(request) == required
            and type(request.get("version")) is int and request.get("version") == 1
            and request.get("action") in _ACTIONS
            and isinstance(request.get("nonce"), str) and _ID.fullmatch(request["nonce"]) is not None
            and request.get("profile_id") == self.runtime.profile_id
            and isinstance(request.get("session_id"), str) and _ID.fullmatch(request["session_id"]) is not None
            and request.get("config_digest") == self.runtime.config_digest
            and isinstance(request.get("access_jwt"), str) and 1 <= len(request["access_jwt"]) <= 16_384
        )

    def _evaluate(self, request: Mapping[str, Any], cancel: threading.Event) -> dict[str, Any] | None:
        start_mono = time.monotonic()
        start_wall = time.time()
        deadline = start_mono + MAX_IPC_SECONDS
        try:
            if cancel.is_set():
                return None
            principal = validate_access_jwt(
                request["access_jwt"], policy=self.runtime.policy,
                now=lambda: start_wall, cancel_event=cancel, deadline_monotonic=deadline,
            )
            observation = self.runtime.authority.inspect(
                principal.email, cancel_event=cancel, deadline_monotonic=deadline,
            )
            end_mono = time.monotonic()
            if not observation.allowed or cancel.is_set() or end_mono > deadline:
                return None
            jwt_deadline = start_mono + max(0.0, principal.expires_at - start_wall)
            valid_until = min(observation.started_monotonic + 60.0, jwt_deadline)
            if valid_until <= end_mono:
                return None
            return {
                "version": 1, "action": request["action"], "nonce": request["nonce"],
                "profile_id": self.runtime.profile_id, "session_id": request["session_id"],
                "config_digest": self.runtime.config_digest, "decision": True, "code": "ALLOW",
                "email": principal.email, "subject": principal.subject,
                "token_fingerprint": principal.token_fingerprint,
                "observed_start_monotonic": observation.started_monotonic,
                "observed_end_monotonic": observation.ended_monotonic,
                "jwt_deadline_monotonic": jwt_deadline, "valid_until_monotonic": valid_until,
            }
        except Exception:
            return None
        finally:
            # Clear the request's bearer-JWT reference when the bounded worker ends.
            if isinstance(request, dict):
                request["access_jwt"] = ""

    async def _deny(self, writer: asyncio.StreamWriter, request: Mapping[str, Any] | None) -> None:
        if request is None:
            return
        denial = {
            "version": 1, "action": request.get("action"), "nonce": request.get("nonce"),
            "profile_id": request.get("profile_id"), "session_id": request.get("session_id"),
            "config_digest": request.get("config_digest"), "decision": False, "code": "DENY",
        }
        try:
            writer.write(json.dumps(denial, separators=(",", ":")).encode("ascii") + b"\n")
            await asyncio.wait_for(writer.drain(), timeout=0.5)
        except Exception:
            pass

    def _check_client_peer(self, conn: socket.socket | None) -> None:
        if conn is None or not hasattr(socket, "SO_PEERCRED"):
            raise VerifierIPCError("authenticated Unix peer credentials are unavailable")
        raw = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
        _pid, uid, _gid = struct.unpack("3i", raw)
        if uid != self.gateway_uid:
            raise VerifierIPCError("gateway peer UID mismatch")


def _decode_strict_json(data: bytes) -> Any:
    if len(data) > max(MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES):
        raise VerifierIPCError("IPC JSON exceeds hard bound")
    try:
        return json.loads(data.decode("ascii"), object_pairs_hook=_no_duplicate_keys,
                          parse_constant=lambda _x: (_ for _ in ()).throw(ValueError("non-finite number")))
    except Exception:
        raise VerifierIPCError("malformed verifier message") from None


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _finite_number(value: Any) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise VerifierIPCError("non-numeric verifier deadline")
    number = float(value)
    if not math.isfinite(number):
        raise VerifierIPCError("non-finite verifier deadline")
    return number


def _assert_safe_socket_directories(path: Path, *, allowed_owners: set[int]) -> None:
    """Reject symlinked, foreign-owned, or group/world-writable socket ancestors."""
    if not path.is_absolute():
        raise RuntimeError("verifier socket directory must be absolute")
    current = Path("/")
    for part in path.parts[1:]:
        current = current / part
        info = os.stat(current, follow_symlinks=False)
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise RuntimeError("verifier socket ancestry contains a symlink or non-directory")
        if info.st_uid not in allowed_owners or info.st_mode & 0o022:
            raise RuntimeError("verifier socket ancestry is not privately owned")


def _assert_client_socket_path(path: Path, verifier_uid: int) -> None:
    _assert_safe_socket_directories(path.parent, allowed_owners={0, os.geteuid(), verifier_uid})
    try:
        info = os.stat(path, follow_symlinks=False)
    except OSError:
        raise VerifierIPCError("verifier socket is unavailable") from None
    if (not stat.S_ISSOCK(info.st_mode) or info.st_uid != verifier_uid
            or info.st_mode & 0o007):
        raise VerifierIPCError("verifier socket identity or permissions mismatch")
