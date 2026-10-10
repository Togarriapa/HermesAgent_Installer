"""Root-derived Composio trigger schema artifacts from authenticated discovery.

This is deliberately a source-specific producer. It accepts only the root
exchange receipt created by the fixed Composio catalog reader and emits an
immutable derived artifact receipt; it never treats discovery as connected
account readiness or changes the static artifact catalog.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
import secrets
import stat
import threading
import time
from types import MappingProxyType
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Protocol

from hermes_installer.protected_enrollment import RootJournalSelection
from hermes_installer.authority.enrollment import ARTIFACT_STAGING_DIRECTORY


_SLUG = re.compile(r"[A-Z][A-Z0-9_]{0,127}\Z", re.ASCII)
_HANDLE = re.compile(r"[A-Za-z0-9_-]{8,128}\Z", re.ASCII)
_SHA = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_ARTIFACT_ID = re.compile(r"composio-whatsapp-trigger-type:[0-9a-f]{64}\Z", re.ASCII)
_MAX = 256 * 1024
_POLICY_ID = "installer-composio-whatsapp-catalog-read-policy-v1"
_POLICY_SHA256 = "319076116a060e371c10886e5c2cfea274ed4d985aa03f5e66a4f611f949cfc5"
_SEAL = object()


class ComposioTriggerArtifactUnavailable(PermissionError):
    """The selected authenticated detail cannot produce a current artifact."""


class ComposioCatalogExchangeRegistry(Protocol):
    def resolve_catalog_exchange_receipt(self, exchange_receipt_handle: str) -> Any: ...
    def resolve_catalog_request_bytes(self, exchange_receipt_handle: str) -> bytes: ...
    def resolve_catalog_response_bytes(self, exchange_receipt_handle: str) -> bytes: ...
    def read_verified_trigger_detail(self, exchange_receipt_handle: str,
                                     selected_returned_slug: str) -> tuple[Any, bytes]: ...


class RootSigner(Protocol):
    def sign(self, payload: bytes) -> bytes: ...
    def verify(self, payload: bytes, signature: bytes) -> bool: ...


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _safe_json(raw: bytes) -> Mapping[str, Any]:
    if not isinstance(raw, bytes) or not 1 <= len(raw) <= 2 * 1024 * 1024:
        raise ComposioTriggerArtifactUnavailable("authenticated trigger detail is outside its response bound")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_pairs,
                           parse_constant=lambda _v: (_ for _ in ()).throw(ValueError()))
    except Exception:
        raise ComposioTriggerArtifactUnavailable("authenticated trigger detail is not strict finite JSON") from None
    if not isinstance(value, dict):
        raise ComposioTriggerArtifactUnavailable("authenticated trigger detail is not an object")
    return value


def _detail_projection(row: Mapping[str, Any], *, slug: str, toolkit_version: str) -> dict[str, Any]:
    toolkit = row.get("toolkit")
    required = {"slug", "name", "description", "type", "config", "payload", "version", "toolkit"}
    optional = {"instructions", "requires_webhook_endpoint_setup"}
    if (not required <= set(row) or set(row) - required - optional
            or row.get("slug") != slug or row.get("version") != toolkit_version
            or not isinstance(toolkit, Mapping) or toolkit.get("slug") != "whatsapp"
            or row.get("type") not in {"webhook", "poll"}
            or not isinstance(row.get("name"), str) or len(row["name"]) > 1024
            or not isinstance(row.get("description"), str) or len(row["description"]) > 8192
            or "instructions" in row and (not isinstance(row["instructions"], str)
                                            or len(row["instructions"]) > 16384)
            or not isinstance(row.get("config"), Mapping)
            or not isinstance(row.get("payload"), Mapping)):
        raise ComposioTriggerArtifactUnavailable("detail does not match the selected WhatsApp schema contract")
    config = dict(row["config"])
    payload = dict(row["payload"])
    try:
        if len(_canonical({"config": config, "payload": payload})) > _MAX:
            raise ValueError
    except (TypeError, ValueError, RecursionError):
        raise ComposioTriggerArtifactUnavailable("trigger schema is not bounded finite JSON") from None
    requires = row.get("requires_webhook_endpoint_setup")
    if requires is not None and type(requires) is not bool:
        raise ComposioTriggerArtifactUnavailable("trigger webhook setup field is malformed")
    return {
        "schema": 1,
        "artifact_id": "",  # assigned from the actual response digest below
        "toolkit_slug": "whatsapp",
        "toolkit_version": toolkit_version,
        "trigger_slug": slug,
        "trigger_type": row["type"],
        "config_schema": config,
        "payload_schema": payload,
        "requires_webhook_endpoint_setup": requires,
    }


@dataclass(frozen=True, slots=True, repr=False)
class RootComposioTriggerArtifactReceipt:
    schema: int
    receipt_handle: str
    artifact_id: str
    artifact_sha256: str
    size_bytes: int
    document_sha256: str
    toolkit_version: str
    trigger_slug: str
    exchange_receipt_handle: str
    request_sha256: str
    response_sha256: str
    request_policy_artifact_id: str
    request_policy_sha256: str
    setup_session_handle: str
    transaction_handle: str
    principal_id: str
    project_id: str
    issued_monotonic: float
    expires_monotonic: float
    signature: bytes = field(repr=False)
    _seal: object = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._seal is not _SEAL:
            raise TypeError("Composio trigger artifact receipts are root-issued")

    def claims(self) -> bytes:
        return _canonical({
            "schema": self.schema, "receipt_handle": self.receipt_handle,
            "artifact_id": self.artifact_id, "artifact_sha256": self.artifact_sha256,
            "size_bytes": self.size_bytes, "document_sha256": self.document_sha256,
            "toolkit_version": self.toolkit_version, "trigger_slug": self.trigger_slug,
            "exchange_receipt_handle": self.exchange_receipt_handle,
            "request_sha256": self.request_sha256, "response_sha256": self.response_sha256,
            "request_policy_artifact_id": self.request_policy_artifact_id,
            "request_policy_sha256": self.request_policy_sha256,
            "setup_session_handle": self.setup_session_handle,
            "transaction_handle": self.transaction_handle, "principal_id": self.principal_id,
            "project_id": self.project_id, "issued_monotonic": self.issued_monotonic,
            "expires_monotonic": self.expires_monotonic,
        })


@dataclass(frozen=True, slots=True, repr=False)
class VerifiedComposioTriggerArtifact:
    receipt: RootComposioTriggerArtifactReceipt
    document_bytes: bytes = field(repr=False)
    _registry_id: str = field(repr=False)
    _seal: object = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._seal is not _SEAL:
            raise TypeError("verified Composio artifact values are root-issued")

    @property
    def artifact_id(self) -> str:
        return self.receipt.artifact_id

    @property
    def artifact_sha256(self) -> str:
        return self.receipt.artifact_sha256

    @property
    def schema_sha256(self) -> str:
        """The ingress verifier's schema digest is the exact published CAS SHA."""
        return self.receipt.artifact_sha256

    @property
    def size_bytes(self) -> int:
        return self.receipt.size_bytes

    @property
    def active_catalog_binding(self) -> Mapping[str, str]:
        """Exact fields a root compiler may bind into the selected channel row."""
        return MappingProxyType({
            "trigger_artifact_id": self.receipt.artifact_id,
            "trigger_artifact_sha256": self.receipt.artifact_sha256,
            "trigger_slug": self.receipt.trigger_slug,
            "toolkit_version": self.receipt.toolkit_version,
        })


@dataclass(frozen=True, slots=True, repr=False)
class ComposioTriggerArtifactCASObservation:
    """Held root-CAS output proof, produced only by this registry instance."""
    artifact_id: str
    artifact_sha256: str
    size_bytes: int
    device: int
    inode: int
    _fd: int = field(repr=False, compare=False)
    _registry_id: str = field(repr=False)
    _seal: object = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._seal is not _SEAL:
            raise TypeError("Composio CAS observations are root-issued")


class RootComposioTriggerArtifactRegistry:
    """Derive a root CAS artifact only from a live selected Composio detail."""

    def __init__(self, selected_session_registry: Any,
                 catalog_exchange_registry: ComposioCatalogExchangeRegistry,
                 owned_artifact_store: Path, artifact_catalog: Any,
                 journal: RootJournalSelection, signer: RootSigner, *,
                 expected_uid: int = 0, monotonic=time.monotonic):
        if (os.geteuid() != expected_uid or expected_uid != 0
                or not (callable(getattr(selected_session_registry, "resolve_live_session_id", None))
                        or callable(getattr(selected_session_registry, "resolve_live_session", None)))
                or not callable(getattr(catalog_exchange_registry, "read_verified_trigger_detail", None))
                or not callable(getattr(catalog_exchange_registry, "resolve_catalog_exchange_receipt", None))
                or not callable(getattr(catalog_exchange_registry, "resolve_catalog_request_bytes", None))
                or not callable(getattr(catalog_exchange_registry, "resolve_catalog_response_bytes", None))
                or not isinstance(owned_artifact_store, Path)
                or owned_artifact_store != ARTIFACT_STAGING_DIRECTORY
                or not isinstance(journal, RootJournalSelection)
                or not callable(getattr(signer, "sign", None)) or not callable(getattr(signer, "verify", None))
                or not callable(monotonic)):
            raise ComposioTriggerArtifactUnavailable("root artifact derivation dependencies are unavailable")
        self.sessions = selected_session_registry
        self.exchanges = catalog_exchange_registry
        self.store = owned_artifact_store
        self.artifact_catalog = artifact_catalog
        self.journal = journal
        self.signer = signer
        self.expected_uid = expected_uid
        self.monotonic = monotonic
        self._instance = secrets.token_urlsafe(24)
        self._records: dict[str, tuple[RootComposioTriggerArtifactReceipt, bytes]] = {}
        self._used_exchanges: set[str] = set()
        self._lock = threading.RLock()

    @classmethod
    def from_root_setup(cls, selected_session_registry: Any,
                        catalog_exchange_registry: ComposioCatalogExchangeRegistry,
                        owned_artifact_store: Path, artifact_catalog: Any,
                        journal: RootJournalSelection, signer: RootSigner,
                        *, expected_uid: int = 0, monotonic=time.monotonic):
        return cls(selected_session_registry, catalog_exchange_registry,
                   owned_artifact_store, artifact_catalog, journal, signer,
                   expected_uid=expected_uid, monotonic=monotonic)

    def persist_selected_trigger_type(self, exchange_receipt_handle: str,
                                      selected_returned_slug: str) -> RootComposioTriggerArtifactReceipt:
        with self._lock:
            return self._persist_selected_trigger_type(exchange_receipt_handle, selected_returned_slug)

    def _persist_selected_trigger_type(self, exchange_receipt_handle: str,
                                       selected_returned_slug: str) -> RootComposioTriggerArtifactReceipt:
        self._require_root()
        if (not isinstance(exchange_receipt_handle, str) or not _HANDLE.fullmatch(exchange_receipt_handle)
                or not isinstance(selected_returned_slug, str) or not _SLUG.fullmatch(selected_returned_slug)):
            raise ComposioTriggerArtifactUnavailable("selected exchange or returned trigger slug is malformed")
        if exchange_receipt_handle in self._used_exchanges:
            raise ComposioTriggerArtifactUnavailable("Composio detail exchange was already consumed for derivation")
        try:
            exchange, raw = self.exchanges.read_verified_trigger_detail(
                exchange_receipt_handle, selected_returned_slug)
        except Exception:
            raise ComposioTriggerArtifactUnavailable("selected authenticated Composio detail receipt is unavailable") from None
        self._validate_exchange(exchange, exchange_receipt_handle, selected_returned_slug)
        try:
            request_bytes = self.exchanges.resolve_catalog_request_bytes(exchange_receipt_handle)
        except Exception:
            raise ComposioTriggerArtifactUnavailable("authenticated catalog request evidence is unavailable") from None
        if (not isinstance(request_bytes, bytes)
                or not secrets.compare_digest(hashlib.sha256(request_bytes).hexdigest(), exchange.request_sha256)
                or not secrets.compare_digest(hashlib.sha256(raw).hexdigest(), exchange.response_sha256)):
            raise ComposioTriggerArtifactUnavailable("catalog source bytes differ from their exchange receipt")
        if (len(raw) != exchange.response_size_bytes
                or not secrets.compare_digest(hashlib.sha256(raw).hexdigest(), exchange.response_sha256)):
            raise ComposioTriggerArtifactUnavailable("detail bytes differ from their retained exchange receipt")
        row = _safe_json(raw)
        projected = _detail_projection(row, slug=selected_returned_slug,
                                       toolkit_version=exchange.toolkit_version)
        response_sha = hashlib.sha256(raw).hexdigest()
        identity = _canonical({"toolkit_version": exchange.toolkit_version,
                               "trigger_slug": selected_returned_slug,
                               "response_sha256": response_sha})
        artifact_id = "composio-whatsapp-trigger-type:" + hashlib.sha256(identity).hexdigest()
        known_artifacts = getattr(self.artifact_catalog, "artifacts", {})
        if artifact_id in known_artifacts:
            raise ComposioTriggerArtifactUnavailable(
                "derived Composio identity collides with the static artifact catalog")
        projected["artifact_id"] = artifact_id
        projected["source_request_receipt_handle"] = exchange_receipt_handle
        projected["source_response_receipt_handle"] = exchange_receipt_handle
        semantic_sha = hashlib.sha256(_canonical(projected)).hexdigest()
        document = dict(projected, sha256=semantic_sha)
        document_bytes = _canonical(document) + b"\n"
        if len(document_bytes) > _MAX:
            raise ComposioTriggerArtifactUnavailable("derived Composio trigger artifact exceeds its bound")
        artifact_sha = hashlib.sha256(document_bytes).hexdigest()
        expires = min(float(exchange.expires_monotonic), float(exchange.issued_monotonic) + 30.0)
        now = self.monotonic()
        if not now < expires:
            raise ComposioTriggerArtifactUnavailable("selected Composio catalog exchange lease expired")
        session = self._resolve_session(exchange.session_handle)
        self._validate_session(session, exchange)
        self._store_bytes(artifact_id, artifact_sha, document_bytes)
        observation = self._hold_cas_output(artifact_id, artifact_sha, document_bytes)
        try:
            self._verify_held_output(observation, document_bytes)
            handle = secrets.token_urlsafe(32)
            claims = {
                "schema": 1, "receipt_handle": handle, "artifact_id": artifact_id,
                "artifact_sha256": artifact_sha, "size_bytes": len(document_bytes),
                "document_sha256": semantic_sha, "toolkit_version": exchange.toolkit_version,
                "trigger_slug": selected_returned_slug,
                "exchange_receipt_handle": exchange_receipt_handle,
                "request_sha256": exchange.request_sha256,
                "response_sha256": exchange.response_sha256,
                "request_policy_artifact_id": _POLICY_ID,
                "request_policy_sha256": _POLICY_SHA256,
                "setup_session_handle": exchange.session_handle,
                "transaction_handle": exchange.transaction_handle,
                "principal_id": exchange.principal_id, "project_id": exchange.project_id,
                "issued_monotonic": now, "expires_monotonic": expires,
            }
            signature = self.signer.sign(_canonical(claims))
            if not isinstance(signature, bytes) or not signature:
                raise ComposioTriggerArtifactUnavailable("root receipt signer failed")
            receipt = RootComposioTriggerArtifactReceipt(**claims, signature=signature, _seal=_SEAL)
            self._write_receipt(receipt)
            self._records[handle] = (receipt, document_bytes)
            self._used_exchanges.add(exchange_receipt_handle)
            return receipt
        finally:
            os.close(observation._fd)

    def resolve_selected_trigger_artifact(self, receipt_handle: str,
                                          current_setup_session: Any) -> VerifiedComposioTriggerArtifact:
        self._require_root()
        if not isinstance(receipt_handle, str) or not _HANDLE.fullmatch(receipt_handle):
            raise ComposioTriggerArtifactUnavailable("Composio trigger artifact receipt handle is malformed")
        item = self._records.get(receipt_handle)
        if item is None:
            raise ComposioTriggerArtifactUnavailable("Composio derived receipt is not retained by this root registry")
        receipt, body = item
        if (receipt is not item[0] or not self.signer.verify(receipt.claims(), receipt.signature)
                or receipt.setup_session_handle != self._session_id(current_setup_session)
                or not receipt.issued_monotonic < self.monotonic() < receipt.expires_monotonic
                or hashlib.sha256(body).hexdigest() != receipt.artifact_sha256
                or len(body) != receipt.size_bytes):
            raise ComposioTriggerArtifactUnavailable("Composio trigger artifact receipt is stale or changed")
        self._verify_receipt_file(receipt)
        session = self._resolve_session(receipt.setup_session_handle)
        exchange, verified_body = self.exchanges.read_verified_trigger_detail(
            receipt.exchange_receipt_handle, receipt.trigger_slug)
        self._validate_exchange(exchange, receipt.exchange_receipt_handle, receipt.trigger_slug)
        self._validate_session(session, exchange)
        try:
            request_bytes = self.exchanges.resolve_catalog_request_bytes(receipt.exchange_receipt_handle)
            response_bytes = self.exchanges.resolve_catalog_response_bytes(receipt.exchange_receipt_handle)
        except Exception:
            raise ComposioTriggerArtifactUnavailable("catalog exchange byte domains could not be re-opened") from None
        if (not isinstance(request_bytes, bytes)
                or hashlib.sha256(request_bytes).hexdigest() != receipt.request_sha256
                or not isinstance(response_bytes, bytes) or response_bytes != verified_body
                or verified_body is None or hashlib.sha256(verified_body).hexdigest() != receipt.response_sha256
                or exchange.request_sha256 != receipt.request_sha256
                or len(verified_body) != exchange.response_size_bytes
                or verified_body != self._detail_source_body(exchange, receipt)):
            raise ComposioTriggerArtifactUnavailable("selected source exchange no longer matches the derived artifact")
        self._verify_stored_bytes(receipt, body)
        return VerifiedComposioTriggerArtifact(receipt, body, self._instance, _SEAL)

    def _detail_source_body(self, exchange: Any, receipt: RootComposioTriggerArtifactReceipt) -> bytes:
        _, body = self.exchanges.read_verified_trigger_detail(
            receipt.exchange_receipt_handle, receipt.trigger_slug)
        return body

    def _resolve_session(self, handle: str) -> Any:
        try:
            resolver = getattr(self.sessions, "resolve_live_session_id", None)
            if callable(resolver):
                return resolver(handle)
            if isinstance(handle, str):
                raise TypeError("selected session registry has no string-ID resolver")
            return self.sessions.resolve_live_session(handle)
        except Exception:
            raise ComposioTriggerArtifactUnavailable("selected root Composio setup session is no longer live") from None

    @staticmethod
    def _session_id(session: Any) -> str:
        handle = getattr(session, "_handle", None)
        session_id = getattr(handle, "session_id", None)
        if not isinstance(session_id, str):
            raise ComposioTriggerArtifactUnavailable("current setup session identity is unavailable")
        return session_id

    def _validate_session(self, session: Any, exchange: Any) -> None:
        if (self._session_id(session) != exchange.session_handle
                or getattr(getattr(session, "_authorization", None), "transaction_handle", None)
                    != exchange.transaction_handle):
            raise ComposioTriggerArtifactUnavailable("Composio exchange does not belong to the selected live session")

    def _validate_exchange(self, exchange: Any, handle: str, slug: str) -> None:
        if (getattr(exchange, "receipt_handle", None) != handle
                or getattr(exchange, "selected_slug", None) != slug
                or getattr(exchange, "operation", None) != "composio.whatsapp.catalog.read"
                or getattr(exchange, "request_policy_artifact_id", None) != _POLICY_ID
                or getattr(exchange, "request_policy_sha256", None) != _POLICY_SHA256
                or getattr(exchange, "toolkit_version", None) != "20260721_00"
                or not _SHA.fullmatch(str(getattr(exchange, "request_sha256", "")))
                or not _SHA.fullmatch(str(getattr(exchange, "response_sha256", "")))
                or not _HANDLE.fullmatch(str(getattr(exchange, "session_handle", "")))
                or not _HANDLE.fullmatch(str(getattr(exchange, "transaction_handle", "")))
                or not isinstance(getattr(exchange, "principal_id", None), str)
                or not isinstance(getattr(exchange, "project_id", None), str)
                or type(getattr(exchange, "response_size_bytes", None)) is not int
                or not 1 <= exchange.response_size_bytes <= 2 * 1024 * 1024
                or not isinstance(getattr(exchange, "issued_monotonic", None), (int, float))
                or isinstance(exchange.issued_monotonic, bool)
                or not math.isfinite(exchange.issued_monotonic)
                or not isinstance(getattr(exchange, "expires_monotonic", None), (int, float))
                or isinstance(exchange.expires_monotonic, bool)
                or not math.isfinite(exchange.expires_monotonic)
                or not exchange.issued_monotonic < self.monotonic() < exchange.expires_monotonic):
            raise ComposioTriggerArtifactUnavailable("Composio source exchange receipt differs from the pinned policy")

    def _store_bytes(self, artifact_id: str, digest: str, body: bytes) -> None:
        if not _ARTIFACT_ID.fullmatch(artifact_id) or not _SHA.fullmatch(digest):
            raise ComposioTriggerArtifactUnavailable("derived Composio artifact identity is malformed")
        root = self._cas_root(create=True)
        object_dir = root / artifact_id
        if not object_dir.exists():
            object_dir.mkdir(mode=0o700)
            self._fsync_dir(root)
        self._ensure_dir(object_dir)
        object_path = object_dir / digest
        try:
            fd = os.open(object_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        except FileExistsError:
            if self._read_object(object_path) != body:
                raise ComposioTriggerArtifactUnavailable("Composio trigger CAS digest collision") from None
            return
        try:
            os.fchmod(fd, 0o400)
            view = memoryview(body)
            while view:
                count = os.write(fd, view)
                if count <= 0:
                    raise OSError("short Composio CAS write")
                view = view[count:]
            os.fsync(fd)
        except Exception:
            try:
                os.unlink(object_path)
            except OSError:
                pass
            raise ComposioTriggerArtifactUnavailable("Composio trigger CAS write failed") from None
        finally:
            os.close(fd)
        self._fsync_dir(object_dir)

    def _verify_stored_bytes(self, receipt: RootComposioTriggerArtifactReceipt, expected: bytes) -> None:
        root = self._cas_root(create=False) / receipt.artifact_id
        actual = self._read_object(root / receipt.artifact_sha256)
        if actual != expected or hashlib.sha256(actual).hexdigest() != receipt.artifact_sha256:
            raise ComposioTriggerArtifactUnavailable("immutable Composio CAS object changed")

    def _hold_cas_output(self, artifact_id: str, digest: str,
                         expected: bytes) -> ComposioTriggerArtifactCASObservation:
        if not _ARTIFACT_ID.fullmatch(artifact_id):
            raise ComposioTriggerArtifactUnavailable("derived Composio artifact identity is malformed")
        root = self._cas_root(create=False) / artifact_id
        self._ensure_dir(root)
        path = root / digest
        fd: int | None = None
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            info = os.fstat(fd)
            named = path.lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != self.expected_uid
                    or stat.S_IMODE(info.st_mode) != 0o400 or info.st_size != len(expected)
                    or (info.st_dev, info.st_ino) != (named.st_dev, named.st_ino)):
                raise OSError("CAS output custody mismatch")
            observation = ComposioTriggerArtifactCASObservation(
                artifact_id, digest, info.st_size, info.st_dev, info.st_ino,
                fd, self._instance, _SEAL)
            self._verify_held_output(observation, expected)
            return observation
        except Exception:
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass
            raise ComposioTriggerArtifactUnavailable("root could not hold the derived CAS output") from None

    def _verify_held_output(self, observation: ComposioTriggerArtifactCASObservation,
                            expected: bytes) -> None:
        if (type(observation) is not ComposioTriggerArtifactCASObservation
                or observation._seal is not _SEAL or observation._registry_id != self._instance
                or observation.size_bytes != len(expected)
                or observation.artifact_sha256 != hashlib.sha256(expected).hexdigest()):
            raise ComposioTriggerArtifactUnavailable("held Composio CAS output observation is invalid")
        try:
            parsed = json.loads(expected[:-1].decode("utf-8"), object_pairs_hook=_unique_pairs)
            semantic = {key: value for key, value in parsed.items() if key != "sha256"}
            if (expected[-1:] != b"\n" or _canonical(parsed) + b"\n" != expected
                    or parsed.get("artifact_id") != observation.artifact_id
                    or hashlib.sha256(_canonical(semantic)).hexdigest() != parsed.get("sha256")):
                raise ValueError("output document does not bind the held artifact identity")
        except Exception:
            raise ComposioTriggerArtifactUnavailable("held Composio output document is not canonical") from None
        try:
            fd_info = os.fstat(observation._fd)
            path = self._cas_root(create=False) / observation.artifact_id / observation.artifact_sha256
            path_info = path.lstat()
            if ((fd_info.st_dev, fd_info.st_ino) != (observation.device, observation.inode)
                    or (path_info.st_dev, path_info.st_ino) != (observation.device, observation.inode)
                    or fd_info.st_uid != self.expected_uid or path_info.st_uid != self.expected_uid
                    or not stat.S_ISREG(path_info.st_mode)
                    or stat.S_IMODE(path_info.st_mode) != 0o400):
                raise OSError("held CAS identity changed")
            chunks = bytearray()
            offset = 0
            while len(chunks) <= _MAX:
                part = os.pread(observation._fd, min(65536, _MAX + 1 - len(chunks)), offset)
                if not part:
                    break
                chunks.extend(part)
                offset += len(part)
            if bytes(chunks) != expected:
                raise OSError("held CAS bytes changed")
        except Exception:
            raise ComposioTriggerArtifactUnavailable("held Composio CAS output changed before receipt signing") from None

    def _read_object(self, path: Path) -> bytes:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != self.expected_uid
                    or stat.S_IMODE(info.st_mode) != 0o400 or info.st_size > _MAX):
                raise OSError("invalid CAS object custody")
            data = bytearray()
            while len(data) <= _MAX:
                chunk = os.read(fd, min(65536, _MAX + 1 - len(data)))
                if not chunk:
                    return bytes(data)
                data.extend(chunk)
            raise OSError("CAS object exceeded bound")
        except OSError:
            raise ComposioTriggerArtifactUnavailable("Composio CAS object is absent or invalid") from None
        finally:
            os.close(fd)

    def _write_receipt(self, receipt: RootComposioTriggerArtifactReceipt) -> None:
        receipts = self._receipt_root(create=True)
        value = json.loads(receipt.claims().decode("utf-8"))
        value["signature"] = receipt.signature.hex()
        raw = _canonical(value)
        path = receipts / f"{receipt.receipt_handle}.json"
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            os.fchmod(fd, 0o600)
            view = memoryview(raw)
            while view:
                count = os.write(fd, view)
                if count <= 0:
                    raise OSError("short Composio receipt write")
                view = view[count:]
            os.fsync(fd)
        finally:
            os.close(fd)
        self._fsync_dir(receipts)

    def _verify_receipt_file(self, receipt: RootComposioTriggerArtifactReceipt) -> None:
        path = self._receipt_root(create=False) / f"{receipt.receipt_handle}.json"
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                info = os.fstat(fd)
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != self.expected_uid
                        or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 16 * 1024):
                    raise OSError("invalid receipt custody")
                raw = bytearray()
                while len(raw) <= 16 * 1024:
                    part = os.read(fd, min(4096, 16 * 1024 + 1 - len(raw)))
                    if not part:
                        break
                    raw.extend(part)
            finally:
                os.close(fd)
            value = json.loads(bytes(raw).decode("utf-8"), object_pairs_hook=_unique_pairs)
            expected = json.loads(receipt.claims().decode("utf-8"))
            expected["signature"] = receipt.signature.hex()
            if value != expected:
                raise ValueError("receipt contents changed")
        except Exception:
            raise ComposioTriggerArtifactUnavailable("persisted Composio artifact receipt is absent or changed") from None

    def _receipt_root(self, *, create: bool) -> Path:
        self._validate_journal()
        root = self.journal.path / "composio-trigger-artifacts"
        if not root.exists() and create:
            root.mkdir(mode=0o700)
            self._fsync_dir(root.parent)
        self._ensure_dir(root)
        receipts = root / "receipts"
        if not receipts.exists() and create:
            receipts.mkdir(mode=0o700)
            self._fsync_dir(root)
        self._ensure_dir(receipts)
        return receipts

    def _validate_journal(self) -> None:
        if (self.journal.service_generation_digest == ""
                or self.journal.path != self.journal.path.resolve(strict=True)):
            raise ComposioTriggerArtifactUnavailable("selected root journal changed")
        info = self.journal.path.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != self.expected_uid
                or info.st_dev != self.journal.device or info.st_ino != self.journal.inode
                or info.st_mode & 0o022):
            raise ComposioTriggerArtifactUnavailable("selected root journal custody changed")
    def _cas_root(self, *, create: bool) -> Path:
        root = self.store / "composio-derived" / "objects"
        parent = self.store
        parent_info = parent.lstat()
        if (not stat.S_ISDIR(parent_info.st_mode) or stat.S_ISLNK(parent_info.st_mode)
                or parent_info.st_uid != self.expected_uid or parent_info.st_mode & 0o022):
            raise ComposioTriggerArtifactUnavailable("protected artifact store custody is invalid")
        derived = parent / "composio-derived"
        if not derived.exists() and create:
            derived.mkdir(mode=0o700)
            self._fsync_dir(parent)
        self._ensure_dir(derived)
        if not root.exists() and create:
            root.mkdir(mode=0o700)
            self._fsync_dir(derived)
        self._ensure_dir(root)
        return root

    def _ensure_dir(self, path: Path) -> None:
        info = path.lstat()
        if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
                or info.st_uid != self.expected_uid or stat.S_IMODE(info.st_mode) != 0o700):
            raise ComposioTriggerArtifactUnavailable("derived artifact directory custody is invalid")

    @staticmethod
    def _fsync_dir(path: Path) -> None:
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def _require_root(self) -> None:
        if os.geteuid() != self.expected_uid or self.expected_uid != 0:
            raise ComposioTriggerArtifactUnavailable("Composio trigger artifact derivation requires root")
