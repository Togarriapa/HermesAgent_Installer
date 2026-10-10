"""Root-owned authority enrollment and credential custody.

This is the only parser for `/etc/hermes-installer/authority.json`. Worker
configuration never flows into these records, and secret values are read from
individual root-only files only when Authentik authority is queried.
"""
from __future__ import annotations

import json
import hashlib
import hmac
import math
import os
import re
import secrets
import stat
import sys
import time
from urllib.parse import urlsplit
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping

from .authentik import (
    AuthentikEnrollment, AuthentikSystemPolicy, PrincipalIdentity,
    TLSAuthentikTransport,
)
from .service import AuthorityPolicy, ChildDelegationRule, EffectRule, PrincipalBinding
from .types import AuthorityDenied, Sensitivity

AUTHORITY_CONFIG_PATH = Path("/etc/hermes-installer/authority.json")
AUTHORITY_KEY_PATH = Path("/etc/hermes-installer/authority.key")
CREDENTIAL_DIRECTORY = Path("/etc/hermes-installer/credentials")
ARTIFACT_CATALOG_PATH = Path("/etc/hermes-installer/artifact-catalog.json")
ARTIFACT_STAGING_DIRECTORY = Path("/var/lib/hermes-installer/artifacts")
MAX_CONFIG_BYTES = 8 * 1_048_576
MAX_CREDENTIAL_BYTES = 16_384


@dataclass(frozen=True, slots=True, repr=False)
class RootAuthorityKeyReceipt:
    schema: int
    receipt_handle: str
    key_id: str
    algorithm: str
    key_device: int
    key_inode: int
    key_uid: int
    key_mode: int
    release_receipt_handle: str
    initial_compilation_session_handle: str
    issued_monotonic: float
    expires_monotonic: float
    _issuer_seal: str


_SETUP_CHOICE_PURPOSES = frozenset({
    "memory-service-enablement", "memory-capture-configuration", "private-input-routes",
    "public-free-web-read", "existing-model-selection", "native-policy-preparation",
    "application-qualification",
})
_SETUP_CHOICE_DOMAIN = b"hermes-installer.setup-choice.v1\0"


class RootSetupChoiceSigner:
    """Purpose-bounded signer over the already selected authority key."""
    def __init__(self, issuer: "RootAuthorityKeySelectionRegistry", *, key_fd: int,
                 session_handle: Any, key_id: str, key_device: int, key_inode: int,
                 key_digest: str, adoption_record: Mapping[str, Any]):
        self._issuer, self._key_fd = issuer, key_fd
        self._session_handle, self.key_id = session_handle, key_id
        self._key_device, self._key_inode = key_device, key_inode
        self._key_digest, self._adoption_record = key_digest, dict(adoption_record)

    def sign_choice(self, purpose: str, canonical_record_bytes: bytes) -> str:
        key = self._current_key(purpose, canonical_record_bytes)
        try:
            message = _setup_choice_message(purpose, canonical_record_bytes)
            return hmac.new(key, message, hashlib.sha256).hexdigest()
        finally:
            key = b""

    def verify_choice(self, purpose: str, canonical_record_bytes: bytes,
                      signature: str) -> bool:
        if not isinstance(signature, str) or not re.fullmatch(r"[0-9a-f]{64}", signature):
            return False
        expected = self.sign_choice(purpose, canonical_record_bytes)
        return hmac.compare_digest(expected, signature)

    def _current_key(self, purpose: str, record: bytes) -> bytes:
        if purpose not in _SETUP_CHOICE_PURPOSES or not isinstance(record, bytes) or len(record) > 1_048_576:
            raise AuthorityDenied("setup.choice", "setup choice purpose or canonical record is invalid")
        self._issuer._verify_normal_choice_signer(self)
        info = os.fstat(self._key_fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
                or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_dev != self._key_device or info.st_ino != self._key_inode):
            raise AuthorityDenied("setup.choice", "selected setup key descriptor custody changed")
        raw = os.pread(self._key_fd, 33, 0)
        if len(raw) != 32 or not secrets.compare_digest(hashlib.sha256(raw).hexdigest(), self._key_digest):
            raise AuthorityDenied("setup.choice", "selected setup key continuity changed")
        return raw


def _setup_choice_message(purpose: str, record: bytes) -> bytes:
    if purpose not in _SETUP_CHOICE_PURPOSES or not isinstance(record, bytes) or len(record) > 1_048_576:
        raise AuthorityDenied("setup.choice", "setup choice purpose or canonical record is invalid")
    return _SETUP_CHOICE_DOMAIN + purpose.encode("ascii") + b"\0" + record


def _normal_choice_binding(record: Mapping[str, Any]) -> bytes:
    return b"hermes-installer.normal-setup-choice-signer.v1\0" + json.dumps(
        dict(record), sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("ascii")


class RootAuthorityKeySelectionRegistry:
    """Bind a root-selected nonsecret key ID to the existing root HMAC key."""

    selection_path = Path("/etc/hermes-installer/authority-key-selection.json")
    private_root_name = "authority-key-receipts"

    def __init__(self, release: Any, actor_verifier: Any, root_journal: Path,
                 *, initial_compilation_registry: Any):
        from .installer_release import VerifiedInstallerReleaseReceipt
        from .bootstrap_runtime_factory import RootInitialCompilationRegistry
        if (not isinstance(release, VerifiedInstallerReleaseReceipt)
                or not callable(getattr(actor_verifier, "verify_current", None))
                or not isinstance(root_journal, Path)
                or root_journal != Path("/var/lib/hermes-installer/authority-journal")):
            raise ValueError("root authority key selection dependencies are incomplete")
        if (not isinstance(initial_compilation_registry, RootInitialCompilationRegistry)
                or initial_compilation_registry.release is not release
                or initial_compilation_registry.root_journal != root_journal
                or initial_compilation_registry.actor_verifier is not actor_verifier):
            raise ValueError("authority key selection stage-zero registry does not match its installed release")
        self.release, self.actor_verifier, self.root_journal = release, actor_verifier, root_journal
        self.initial_compilation_registry = initial_compilation_registry
        self._seal = secrets.token_hex(32)
        self._receipts: dict[str, RootAuthorityKeyReceipt] = {}
        self._key_fds: dict[str, int] = {}
        self._key_digests: dict[str, str] = {}
        self._receipt_handles_by_session: dict[str, str] = {}
        self._normal_signers: dict[str, RootSetupChoiceSigner] = {}

    @classmethod
    def from_installed_release(cls, verified_release: Any, installed_actor_verifier: Any,
                               root_journal: Path, *,
                               initial_compilation_registry: Any
                               ) -> "RootAuthorityKeySelectionRegistry":
        return cls(verified_release, installed_actor_verifier, root_journal,
                   initial_compilation_registry=initial_compilation_registry)

    def ensure_selected_key(self, initial_compilation_session_handle: str) -> RootAuthorityKeyReceipt:
        session = self._resolve_stage0(initial_compilation_session_handle)
        if os.geteuid() != 0 or not sys.platform.startswith("linux"):
            raise AuthorityDenied("key.enrollment", "authority key selection requires installed Linux root")
        self._verify_key_parent()
        active_key_id = self._active_key_id()
        key_present = _path_exists_nofollow(AUTHORITY_KEY_PATH)
        if not key_present and active_key_id is not None:
            raise AuthorityDenied("key.selection", "active authority key ID exists without its signing key")
        if not key_present:
            # Creation is exclusive, journaled as the first-install case, and
            # never repairs or overwrites an existing key.
            marker_path = self.root_journal / self.private_root_name / "first-install.json"
            if (_path_exists_nofollow(marker_path)
                    and self._first_install_marker(session) is None):
                raise AuthorityDenied("key.selection", "another initial key-creation transaction needs root reconciliation")
            self._write_first_install_marker(session, None, None, None, state="creating")
            create_authority_signing_key(expected_uid=0)
            created = True
        else:
            created = False
        fd, info, raw = self._open_key()
        try:
            prior = self._read_selection()
            if prior is not None:
                if (prior["key_device"] != info.st_dev or prior["key_inode"] != info.st_ino
                        or prior["key_id"] != active_key_id and active_key_id is not None):
                    raise AuthorityDenied("key.selection", "existing authority key selection conflicts with the installed key")
                key_id = prior["key_id"]
                receipt_handle = (prior["receipt_handle"] if prior["initial_compilation_session_handle"]
                                  == session.compilation_session_handle else secrets.token_hex(32))
                issued = (prior["issued_monotonic"] if receipt_handle == prior["receipt_handle"]
                          else time.monotonic())
            elif active_key_id is not None:
                key_id = active_key_id
                receipt_handle = secrets.token_hex(32)
                issued = time.monotonic()
            else:
                first_install = self._first_install_marker(session)
                if not (created or first_install is not None):
                    raise AuthorityDenied("key.selection", "existing signing key has no verified active key ID or first-install journal")
                key_id = (first_install.get("key_id") if first_install is not None
                          and first_install.get("state") == "created" else None)
                if not isinstance(key_id, str) or not re.fullmatch(r"authority-key-[0-9a-f]{32}", key_id):
                    key_id = "authority-key-" + secrets.token_hex(16)
                receipt_handle = secrets.token_hex(32)
                issued = time.monotonic()
                self._write_first_install_marker(session, info, receipt_handle, key_id, state="created")
            expires = min(float(session.expires_monotonic), issued + 300.0)
            if expires <= time.monotonic():
                raise AuthorityDenied("key.selection", "initial compilation session expired")
            receipt = RootAuthorityKeyReceipt(
                1, receipt_handle, key_id, "HMAC-SHA256", info.st_dev, info.st_ino,
                0, 0o600, session.verified_release_receipt_handle,
                session.compilation_session_handle, issued, expires, self._seal,
            )
            self._persist_selection(receipt)
            self._persist_private_binding(receipt, hashlib.sha256(raw).hexdigest())
            old_fd = self._key_fds.pop(receipt_handle, None)
            if old_fd is not None:
                os.close(old_fd)
            self._receipts[receipt_handle] = receipt
            self._key_fds[receipt_handle] = fd
            self._key_digests[receipt_handle] = hashlib.sha256(raw).hexdigest()
            self._receipt_handles_by_session[session.compilation_session_handle] = receipt_handle
            fd = -1
            return receipt
        finally:
            if fd >= 0:
                os.close(fd)
            raw = b""

    def resolve_selected_key_for_compilation_session(
        self, compilation_session_handle: str,
    ) -> RootAuthorityKeyReceipt:
        """Return the live typed key receipt issued for this exact stage-zero session."""
        session = self._resolve_stage0(compilation_session_handle)
        handle = self._receipt_handles_by_session.get(session.compilation_session_handle)
        if not isinstance(handle, str):
            raise AuthorityDenied("key.selection", "no root authority key receipt was issued for this setup")
        return self.resolve_selected_key(handle, session.compilation_session_handle)

    def adopt_for_normal_setup(
        self, key_receipt_handle: str, initial_compilation_session_handle: str,
        normal_setup_session_handle: Any, prepared_publication_handoff_handle: str,
    ) -> RootSetupChoiceSigner:
        from .bootstrap_enrollment import RootSetupSessionHandle, RootSetupSessionStore
        if not isinstance(normal_setup_session_handle, RootSetupSessionHandle):
            raise AuthorityDenied("setup.choice", "normal setup adoption requires its root session handle")
        stage0 = self._resolve_stage0(initial_compilation_session_handle)
        receipt = self.resolve_selected_key(key_receipt_handle, initial_compilation_session_handle)
        store = getattr(self.initial_compilation_registry, "_session_store", None)
        if not isinstance(store, RootSetupSessionStore):
            raise AuthorityDenied("setup.choice", "normal root setup store is not adopted")
        live = store._live(normal_setup_session_handle)
        proof = store._proof(live)
        try:
            handoff = self.initial_compilation_registry.resolve_adopted_handoff(normal_setup_session_handle)
        except Exception:
            raise AuthorityDenied("setup.choice", "normal session has no current publication handoff") from None
        if (handoff.handoff_handle != prepared_publication_handoff_handle
                or handoff.compilation_session_handle != stage0.compilation_session_handle
                or handoff.compilation_transaction_handle != stage0.compilation_transaction_handle
                or handoff.plan_sha256 != stage0.plan_sha256
                or handoff.publication_receipt_handle == ""
                or handoff.normal_transaction_handle != proof.transaction_handle
                or receipt.initial_compilation_session_handle != stage0.compilation_session_handle
                or receipt.release_receipt_handle != stage0.verified_release_receipt_handle):
            raise AuthorityDenied("setup.choice", "selected key receipt and publication handoff do not join")
        self.initial_compilation_registry.actor.verify_current(self.release)
        plan = store.plan_resolver.resolve(proof.plan_artifact_id)
        store.actor_verifier.verify_current(plan)
        signer = self._mint_normal_signer(receipt, normal_setup_session_handle, proof, handoff)
        return signer

    def resolve_normal_setup_choice_signer(self, normal_setup_session_handle: Any) -> RootSetupChoiceSigner:
        from .bootstrap_enrollment import RootSetupSessionHandle, RootSetupSessionStore
        if not isinstance(normal_setup_session_handle, RootSetupSessionHandle):
            raise AuthorityDenied("setup.choice", "normal setup choice signer requires its root session handle")
        store = getattr(self.initial_compilation_registry, "_session_store", None)
        if not isinstance(store, RootSetupSessionStore):
            raise AuthorityDenied("setup.choice", "normal root setup store is unavailable")
        live = store._live(normal_setup_session_handle)
        proof = store._proof(live)
        try:
            handoff = self.initial_compilation_registry.resolve_adopted_handoff(normal_setup_session_handle)
        except Exception:
            raise AuthorityDenied("setup.choice", "normal session publication adoption is stale") from None
        path = self._normal_signer_path(normal_setup_session_handle.session_id)
        try:
            row = json.loads(_read_root_selection_bytes(path, 16_384).decode("ascii"),
                             object_pairs_hook=_unique_pairs)
        except Exception:
            raise AuthorityDenied("setup.choice", "normal setup key signer receipt is unavailable") from None
        record = self._validate_normal_signer_record(row, proof, handoff)
        fd, info, raw = self._open_key()
        try:
            digest = hashlib.sha256(raw).hexdigest()
            binding_hmac = record.pop("binding_hmac")
            selection = self._read_selection()
            private_binding = json.loads(_read_root_selection_bytes(
                self.root_journal / self.private_root_name / f"{record['key_receipt_handle']}.json",
                4096).decode("ascii"), object_pairs_hook=_unique_pairs)
            if (info.st_dev != record["key_device"] or info.st_ino != record["key_inode"]
                    or digest != record["key_sha256"] or selection is None
                    or selection["key_id"] != record["key_id"]
                    or selection["receipt_handle"] != record["key_receipt_handle"]
                    or selection["initial_compilation_session_handle"] != record["compilation_session_handle"]
                    or selection["key_device"] != info.st_dev or selection["key_inode"] != info.st_ino
                    or selection["release_receipt_handle"] != record["release_receipt_handle"]
                    or private_binding != {"schema": 1, "receipt_handle": record["key_receipt_handle"],
                                           "key_device": info.st_dev, "key_inode": info.st_ino,
                                           "key_sha256": digest}):
                raise AuthorityDenied("setup.choice", "selected authority key changed after setup adoption")
            expected = hmac.new(raw, _normal_choice_binding(record), hashlib.sha256).hexdigest()
            if not secrets.compare_digest(expected, binding_hmac):
                raise AuthorityDenied("setup.choice", "normal setup choice signer binding is invalid")
            plan = store.plan_resolver.resolve(proof.plan_artifact_id)
            store.actor_verifier.verify_current(plan)
            self.initial_compilation_registry.actor.verify_current(self.release)
            signer = RootSetupChoiceSigner(self, key_fd=fd, session_handle=normal_setup_session_handle,
                                           key_id=record["key_id"], key_device=info.st_dev,
                                           key_inode=info.st_ino, key_digest=digest, adoption_record=record)
            self._normal_signers[normal_setup_session_handle.session_id] = signer
            fd = -1
            return signer
        finally:
            if fd >= 0:
                os.close(fd)
            raw = b""

    def _mint_normal_signer(self, receipt: RootAuthorityKeyReceipt, handle: Any,
                            proof: Any, handoff: Any) -> RootSetupChoiceSigner:
        key_fd = self._key_fds.get(receipt.receipt_handle)
        digest = self._key_digests.get(receipt.receipt_handle)
        if key_fd is None or digest is None:
            raise AuthorityDenied("setup.choice", "stage-zero selected key descriptor is unavailable")
        # Adoption can be retried after the durable rename succeeded but before
        # the caller observed success. Re-resolve the exact record rather than
        # replacing it with a fresh timestamp/HMAC or treating it as a conflict.
        path = self._normal_signer_path(handle.session_id)
        if _path_exists_nofollow(path):
            cached = self._normal_signers.get(handle.session_id)
            if cached is not None:
                self._verify_normal_choice_signer(cached)
                if (cached._adoption_record.get("key_receipt_handle") != receipt.receipt_handle
                        or cached.key_id != receipt.key_id or cached._key_device != receipt.key_device
                        or cached._key_inode != receipt.key_inode or cached._key_digest != digest):
                    raise AuthorityDenied("setup.choice", "durable normal setup signer belongs to another key adoption")
                return cached
            signer = self.resolve_normal_setup_choice_signer(handle)
            if (signer._adoption_record.get("key_receipt_handle") != receipt.receipt_handle
                    or signer.key_id != receipt.key_id
                    or signer._key_device != receipt.key_device
                    or signer._key_inode != receipt.key_inode
                    or signer._key_digest != digest):
                os.close(signer._key_fd)
                self._normal_signers.pop(handle.session_id, None)
                raise AuthorityDenied("setup.choice", "durable normal setup signer belongs to another key adoption")
            return signer
        record = {"schema": 1, "normal_setup_session_id": handle.session_id,
                  "normal_transaction_handle": proof.transaction_handle,
                  "normal_plan_digest": proof.plan_digest,
                  "compilation_session_handle": handoff.compilation_session_handle,
                  "compilation_transaction_handle": handoff.compilation_transaction_handle,
                  "publication_handoff_handle": handoff.handoff_handle,
                  "publication_receipt_handle": handoff.publication_receipt_handle,
                  "publication_sha256": handoff.publication_sha256,
                  "release_receipt_handle": receipt.release_receipt_handle,
                  "key_id": receipt.key_id, "key_device": receipt.key_device,
                  "key_inode": receipt.key_inode, "key_sha256": digest,
                  "key_receipt_handle": receipt.receipt_handle,
                  "issued_unix": time.time(), "setup_deadline_unix": time.time() +
                  max(0.0, proof.expires_monotonic - time.monotonic())}
        _write_root_selection(path, {**record, "binding_hmac": hmac.new(
            os.pread(key_fd, 32, 0), _normal_choice_binding(record), hashlib.sha256).hexdigest()},
            exclusive=True)
        signer = RootSetupChoiceSigner(self, key_fd=os.dup(key_fd), session_handle=handle,
                                       key_id=receipt.key_id, key_device=receipt.key_device,
                                       key_inode=receipt.key_inode, key_digest=digest,
                                       adoption_record=record)
        self._normal_signers[handle.session_id] = signer
        return signer

    def _verify_normal_choice_signer(self, signer: RootSetupChoiceSigner) -> None:
        from .bootstrap_enrollment import RootSetupSessionStore
        store = getattr(self.initial_compilation_registry, "_session_store", None)
        if not isinstance(store, RootSetupSessionStore):
            raise AuthorityDenied("setup.choice", "normal root setup store is unavailable")
        live = store._live(signer._session_handle)
        proof = store._proof(live)
        handoff = self.initial_compilation_registry.resolve_adopted_handoff(signer._session_handle)
        current = self._normal_signers.get(signer._session_handle.session_id)
        if (current is not signer
                or signer._adoption_record.get("normal_transaction_handle") != proof.transaction_handle
                or signer._adoption_record.get("publication_handoff_handle") != handoff.handoff_handle):
            raise AuthorityDenied("setup.choice", "normal setup choice signer is revoked or stale")
        try:
            durable = json.loads(_read_root_selection_bytes(
                self._normal_signer_path(signer._session_handle.session_id), 16_384).decode("ascii"),
                object_pairs_hook=_unique_pairs)
        except Exception:
            raise AuthorityDenied("setup.choice", "durable normal setup signer record is unavailable") from None
        record = self._validate_normal_signer_record(durable, proof, handoff)
        binding = record.pop("binding_hmac")
        fd, info, raw = self._open_key()
        try:
            expected = hmac.new(raw, _normal_choice_binding(record), hashlib.sha256).hexdigest()
            if (not secrets.compare_digest(binding, expected)
                    or record != signer._adoption_record
                    or record["key_id"] != signer.key_id):
                raise AuthorityDenied("setup.choice", "durable normal setup signer binding changed")
            selection = self._read_selection()
            private_binding = json.loads(_read_root_selection_bytes(
                self.root_journal / self.private_root_name / f"{record['key_receipt_handle']}.json",
                4096).decode("ascii"), object_pairs_hook=_unique_pairs)
            if (selection is None or selection["key_id"] != record["key_id"]
                    or selection["receipt_handle"] != record["key_receipt_handle"]
                    or selection["initial_compilation_session_handle"] != record["compilation_session_handle"]
                    or selection["key_device"] != record["key_device"]
                    or selection["key_inode"] != record["key_inode"]
                    or selection["release_receipt_handle"] != record["release_receipt_handle"]
                    or private_binding != {"schema": 1, "receipt_handle": record["key_receipt_handle"],
                                           "key_device": record["key_device"],
                                           "key_inode": record["key_inode"],
                                           "key_sha256": record["key_sha256"]}):
                raise AuthorityDenied("setup.choice", "selected setup key receipt continuity changed")
        finally:
            os.close(fd)
            raw = b""
        plan = store.plan_resolver.resolve(proof.plan_artifact_id)
        store.actor_verifier.verify_current(plan)
        self.initial_compilation_registry.actor.verify_current(self.release)
        fresh_fd, info, raw = self._open_key()
        try:
            if (info.st_dev != signer._key_device or info.st_ino != signer._key_inode
                    or not secrets.compare_digest(hashlib.sha256(raw).hexdigest(), signer._key_digest)):
                raise AuthorityDenied("setup.choice", "selected setup key has changed")
        finally:
            os.close(fresh_fd)
            raw = b""

    def _normal_signer_path(self, session_id: str) -> Path:
        if not isinstance(session_id, str) or not re.fullmatch(r"setup-[0-9a-f]{32}", session_id):
            raise AuthorityDenied("setup.choice", "normal setup session ID is malformed")
        return self.root_journal / self.private_root_name / (
            "normal-" + hashlib.sha256(session_id.encode("ascii")).hexdigest() + ".json")

    def _validate_normal_signer_record(self, row: Any, proof: Any, handoff: Any) -> dict[str, Any]:
        release_receipt_handle = self._release_receipt_handle_for_handoff(handoff)
        fields = {"schema", "normal_setup_session_id", "normal_transaction_handle", "normal_plan_digest",
                  "compilation_session_handle", "compilation_transaction_handle", "publication_handoff_handle",
                  "publication_receipt_handle", "publication_sha256", "release_receipt_handle", "key_id",
                  "key_device", "key_inode", "key_sha256", "key_receipt_handle",
                  "issued_unix", "setup_deadline_unix", "binding_hmac"}
        if (not isinstance(row, dict) or set(row) != fields or row.get("schema") != 1
                or row.get("normal_setup_session_id") != proof.setup_session_id
                or row.get("normal_transaction_handle") != proof.transaction_handle
                or row.get("normal_plan_digest") != proof.plan_digest
                or row.get("publication_handoff_handle") != handoff.handoff_handle
                or row.get("compilation_session_handle") != handoff.compilation_session_handle
                or row.get("publication_sha256") != handoff.publication_sha256
                or row.get("publication_receipt_handle") != handoff.publication_receipt_handle
                or row.get("release_receipt_handle") != release_receipt_handle
                or not re.fullmatch(r"authority-key-[0-9a-f]{32}", str(row.get("key_id")))
                or type(row.get("key_device")) is not int or type(row.get("key_inode")) is not int
                or not re.fullmatch(r"[0-9a-f]{64}", str(row.get("key_sha256")))
                or not re.fullmatch(r"[0-9a-f]{64}", str(row.get("key_receipt_handle")))
                or not re.fullmatch(r"[0-9a-f]{64}", str(row.get("binding_hmac")))
                or type(row.get("issued_unix")) not in (int, float)
                or type(row.get("setup_deadline_unix")) not in (int, float)
                or not math.isfinite(row["issued_unix"])
                or not math.isfinite(row["setup_deadline_unix"])
                or row["setup_deadline_unix"] <= time.time()
                or row["issued_unix"] > time.time()):
            raise AuthorityDenied("setup.choice", "normal setup signer record does not match current handoff")
        return row

    def _release_receipt_handle_for_handoff(self, handoff: Any) -> str:
        """Resolve the exact registry-issued release handle carried by the adopted session."""
        from .bootstrap_runtime_factory import RootInitialCompilationSession, RootInitialPublicationHandoff
        initial = getattr(handoff, "_initial_session", None)
        if (not isinstance(handoff, RootInitialPublicationHandoff)
                or not isinstance(initial, RootInitialCompilationSession)
                or initial._release is not self.release
                or initial._actor is not self.initial_compilation_registry.actor
                or handoff._registry_seal != getattr(self.initial_compilation_registry, "_seal", None)
                or initial.compilation_session_handle != handoff.compilation_session_handle
                or initial.compilation_transaction_handle != handoff.compilation_transaction_handle
                or not isinstance(initial.verified_release_receipt_handle, str)
                or not re.fullmatch(r"[0-9a-f]{64}", initial.verified_release_receipt_handle)):
            raise AuthorityDenied("setup.choice", "publication handoff lacks its current verified release receipt")
        try:
            self.release.verify_current()
        except Exception:
            raise AuthorityDenied("setup.choice", "selected installer release is no longer current") from None
        return initial.verified_release_receipt_handle

    def resolve_selected_key(self, receipt_handle: str,
                             initial_compilation_session_handle: str) -> RootAuthorityKeyReceipt:
        session = self._resolve_stage0(initial_compilation_session_handle)
        receipt = self._receipts.get(receipt_handle)
        if (receipt is None or not secrets.compare_digest(receipt._issuer_seal, self._seal)
                or receipt.expires_monotonic <= time.monotonic()
                or receipt.initial_compilation_session_handle != session.compilation_session_handle
                or receipt.release_receipt_handle != session.verified_release_receipt_handle):
            raise AuthorityDenied("key.selection", "root authority key receipt is absent or stale")
        fd = self._key_fds.get(receipt_handle)
        if fd is None:
            raise AuthorityDenied("key.selection", "root authority key continuity handle is absent")
        info = os.fstat(fd)
        current_fd, path_info, raw = self._open_key()
        try:
            if (info.st_dev != receipt.key_device or info.st_ino != receipt.key_inode
                    or info.st_uid != 0 or info.st_gid != 0 or stat.S_IMODE(info.st_mode) != 0o600
                    or path_info.st_dev != receipt.key_device or path_info.st_ino != receipt.key_inode
                    or not secrets.compare_digest(hashlib.sha256(raw).hexdigest(),
                                                  self._key_digests[receipt_handle])):
                raise AuthorityDenied("key.selection", "root authority signing key custody changed")
            self._verify_private_binding(receipt, self._key_digests[receipt_handle])
            self._verify_selection(receipt)
            return receipt
        finally:
            os.close(current_fd)
            raw = b""

    def _resolve_stage0(self, handle: str) -> Any:
        from .bootstrap_runtime_factory import RootInitialCompilationRegistry, RootInitialCompilationSession
        if os.geteuid() != 0 or not isinstance(handle, str) or not re.fullmatch(r"[0-9a-f]{64}", handle):
            raise AuthorityDenied("key.selection", "authority key selection requires a live root stage-zero handle")
        # The installed actor verifier is also the stage-zero registry's actor.
        # Resolve through a root registry supplied by the caller's release object.
        registry = self.initial_compilation_registry
        if not isinstance(registry, RootInitialCompilationRegistry):
            raise AuthorityDenied("key.selection", "verified release is not bound to the root stage-zero registry")
        session = registry.resolve_initial_session(handle)
        if not isinstance(session, RootInitialCompilationSession):
            raise AuthorityDenied("key.selection", "root stage-zero session is malformed")
        registry.verify_initial_session(session)
        if session._release is not self.release or session._actor is not registry.actor:
            raise AuthorityDenied("key.selection", "stage-zero session belongs to a different verified release")
        plan = registry.resolve_setup_plan(session)
        self.actor_verifier.verify_current(plan)
        return session

    def _verify_key_parent(self) -> None:
        _secure_path(AUTHORITY_KEY_PATH.parent / "placeholder", expected_uid=0, allow_missing_leaf=True)
        _ensure_root_private_dir(self.root_journal / self.private_root_name)

    def _open_key(self):
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        try:
            fd = os.open(AUTHORITY_KEY_PATH, flags)
            info = os.fstat(fd)
            path_info = AUTHORITY_KEY_PATH.lstat()
            raw = os.read(fd, 33)
        except OSError:
            raise AuthorityDenied("key.selection", "authority signing key is unavailable") from None
        if (stat.S_ISLNK(path_info.st_mode) or not stat.S_ISREG(info.st_mode)
                or info.st_uid != 0 or info.st_gid != 0 or stat.S_IMODE(info.st_mode) != 0o600
                or path_info.st_dev != info.st_dev or path_info.st_ino != info.st_ino
                or len(raw) != 32 or os.read(fd, 1)):
            os.close(fd)
            raise AuthorityDenied("key.selection", "authority signing key custody is invalid")
        os.lseek(fd, 0, os.SEEK_SET)
        return fd, info, raw

    def _active_key_id(self) -> str | None:
        if not _path_exists_nofollow(AUTHORITY_CONFIG_PATH):
            return None
        protected = load_protected_enrollment()
        return protected.key_id

    def _read_selection(self) -> dict[str, Any] | None:
        if not _path_exists_nofollow(self.selection_path):
            return None
        raw = _read_root_selection_bytes(self.selection_path, 16_384)
        try:
            row = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_pairs)
        except (ValueError, UnicodeError):
            raise AuthorityDenied("key.selection", "authority key selection file is malformed") from None
        return _validate_root_key_selection(row)

    def _persist_selection(self, receipt: RootAuthorityKeyReceipt) -> None:
        document = {"schema": 1, "receipt_handle": receipt.receipt_handle,
                    "key_id": receipt.key_id, "algorithm": receipt.algorithm,
                    "key_device": receipt.key_device, "key_inode": receipt.key_inode,
                    "key_uid": 0, "key_mode": 0o600,
                    "release_receipt_handle": receipt.release_receipt_handle,
                    "initial_compilation_session_handle": receipt.initial_compilation_session_handle,
                    "issued_monotonic": receipt.issued_monotonic,
                    "expires_monotonic": receipt.expires_monotonic}
        _write_root_selection(self.selection_path, document)

    def _persist_private_binding(self, receipt: RootAuthorityKeyReceipt, digest: str) -> None:
        root = self.root_journal / self.private_root_name
        _ensure_root_private_dir(root)
        _write_root_selection(root / f"{receipt.receipt_handle}.json", {
            "schema": 1, "receipt_handle": receipt.receipt_handle,
            "key_device": receipt.key_device, "key_inode": receipt.key_inode,
            "key_sha256": digest,
        }, exclusive=True)

    def _verify_private_binding(self, receipt: RootAuthorityKeyReceipt, digest: str) -> None:
        root = self.root_journal / self.private_root_name
        try:
            row = json.loads(_read_root_selection_bytes(root / f"{receipt.receipt_handle}.json",
                                                        4096).decode(),
                             object_pairs_hook=_unique_pairs)
        except Exception:
            raise AuthorityDenied("key.selection", "private root key continuity record is absent") from None
        if row != {"schema": 1, "receipt_handle": receipt.receipt_handle,
                   "key_device": receipt.key_device, "key_inode": receipt.key_inode,
                   "key_sha256": digest}:
            raise AuthorityDenied("key.selection", "private root key continuity record changed")

    def _verify_selection(self, receipt: RootAuthorityKeyReceipt) -> None:
        row = self._read_selection()
        if row is None or row != {
            "schema": 1, "receipt_handle": receipt.receipt_handle,
            "key_id": receipt.key_id, "algorithm": receipt.algorithm,
            "key_device": receipt.key_device, "key_inode": receipt.key_inode,
            "key_uid": 0, "key_mode": 0o600,
            "release_receipt_handle": receipt.release_receipt_handle,
            "initial_compilation_session_handle": receipt.initial_compilation_session_handle,
            "issued_monotonic": receipt.issued_monotonic,
            "expires_monotonic": receipt.expires_monotonic,
        }:
            raise AuthorityDenied("key.selection", "authority key selection changed")

    def _write_first_install_marker(self, session: Any, info: os.stat_result | None,
                                    receipt_handle: str | None, key_id: str | None,
                                    *, state: str) -> None:
        root = self.root_journal / self.private_root_name
        _ensure_root_private_dir(root)
        _write_root_selection(root / "first-install.json", {
            "schema": 1, "receipt_handle": receipt_handle,
            "initial_compilation_session_handle": session.compilation_session_handle,
            "key_id": key_id,
            "key_device": None if info is None else info.st_dev,
            "key_inode": None if info is None else info.st_ino,
            "state": state,
        })

    def _first_install_marker(self, session: Any) -> dict[str, Any] | None:
        path = self.root_journal / self.private_root_name / "first-install.json"
        if not _path_exists_nofollow(path):
            return None
        row = json.loads(_read_root_selection_bytes(path, 4096).decode(),
                         object_pairs_hook=_unique_pairs)
        expected = {"schema", "receipt_handle", "initial_compilation_session_handle",
                    "key_id", "key_device", "key_inode", "state"}
        if (not isinstance(row, dict) or set(row) != expected
                or type(row.get("schema")) is not int or row.get("schema") != 1
                or row.get("initial_compilation_session_handle") != session.compilation_session_handle
                or row.get("state") not in {"creating", "created"}):
            return None
        if row["state"] == "creating":
            if any(row.get(key) is not None for key in ("receipt_handle", "key_id", "key_device", "key_inode")):
                raise AuthorityDenied("key.selection", "initial key creation journal is malformed")
        elif (not isinstance(row.get("receipt_handle"), str)
              or not re.fullmatch(r"[0-9a-f]{64}", row["receipt_handle"])
              or not isinstance(row.get("key_id"), str)
              or not re.fullmatch(r"authority-key-[0-9a-f]{32}", row["key_id"])
              or type(row.get("key_device")) is not int or row["key_device"] < 0
              or type(row.get("key_inode")) is not int or row["key_inode"] <= 0):
            raise AuthorityDenied("key.selection", "completed initial key creation journal is malformed")
        return row


def _path_exists_nofollow(path: Path) -> bool:
    try:
        path.lstat()
        return True
    except FileNotFoundError:
        return False


def _validate_root_key_selection(row: Any) -> dict[str, Any]:
    fields = {"schema", "receipt_handle", "key_id", "algorithm", "key_device", "key_inode",
              "key_uid", "key_mode", "release_receipt_handle", "initial_compilation_session_handle",
              "issued_monotonic", "expires_monotonic"}
    if (not isinstance(row, dict) or set(row) != fields or type(row.get("schema")) is not int
            or row.get("schema") != 1 or not isinstance(row.get("receipt_handle"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", row["receipt_handle"])
            or not isinstance(row.get("key_id"), str)
            or not re.fullmatch(r"authority-key-[0-9a-f]{32}", row["key_id"])
            or row.get("algorithm") != "HMAC-SHA256"
            or type(row.get("key_device")) is not int or row["key_device"] < 0
            or type(row.get("key_inode")) is not int or row["key_inode"] <= 0
            or type(row.get("key_uid")) is not int or row["key_uid"] != 0
            or type(row.get("key_mode")) is not int or row["key_mode"] != 0o600
            or not isinstance(row.get("release_receipt_handle"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", row["release_receipt_handle"])
            or not isinstance(row.get("initial_compilation_session_handle"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", row["initial_compilation_session_handle"])
            or type(row.get("issued_monotonic")) not in (int, float)
            or type(row.get("expires_monotonic")) not in (int, float)
            or not math.isfinite(row["issued_monotonic"])
            or not math.isfinite(row["expires_monotonic"])
            or row["expires_monotonic"] <= row["issued_monotonic"]):
        raise AuthorityDenied("key.selection", "authority key selection fields are malformed")
    return row


def _read_root_selection_bytes(path: Path, maximum: int) -> bytes:
    data = read_protected_file(path, expected_uid=0, maximum=maximum)
    info = path.lstat()
    if (stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode)
            or info.st_uid != 0 or info.st_gid != 0 or stat.S_IMODE(info.st_mode) != 0o600):
        raise AuthorityDenied("key.selection", "root authority key receipt custody is invalid")
    return data


def _ensure_root_private_dir(path: Path) -> None:
    if (path != Path("/var/lib/hermes-installer/authority-journal/authority-key-receipts")
            or os.geteuid() != 0):
        raise AuthorityDenied("key.selection", "private authority key journal path is not selected")
    try:
        path.mkdir(mode=0o700)
        os.chown(path, 0, 0)
        fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except FileExistsError:
        pass
    except OSError:
        raise AuthorityDenied("key.selection", "private authority key journal could not be created") from None
    info = path.lstat()
    if (stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode)
            or info.st_uid != 0 or info.st_gid != 0 or stat.S_IMODE(info.st_mode) != 0o700):
        raise AuthorityDenied("key.selection", "private authority key journal custody is invalid")


def _write_root_selection(path: Path, document: Mapping[str, Any], *, exclusive: bool = False) -> None:
    selection = Path("/etc/hermes-installer/authority-key-selection.json")
    private = Path("/var/lib/hermes-installer/authority-journal/authority-key-receipts")
    private_child = (path.parent == private
                     and (path.name == "first-install.json"
                          or bool(re.fullmatch(r"[0-9a-f]{64}\.json", path.name))
                          or bool(re.fullmatch(r"normal-[0-9a-f]{64}\.json", path.name))))
    if os.geteuid() != 0 or (path != selection and not private_child):
        raise AuthorityDenied("key.selection", "authority key receipt destination is not selected")
    _secure_path(path.parent / "placeholder", expected_uid=0, allow_missing_leaf=True)
    _secure_path(path, expected_uid=0, allow_missing_leaf=True)
    payload = json.dumps(dict(document), sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    if len(payload) > 16_384:
        raise AuthorityDenied("key.selection", "authority key selection exceeds its size bound")
    if _path_exists_nofollow(path):
        existing = path.lstat()
        if (stat.S_ISLNK(existing.st_mode) or not stat.S_ISREG(existing.st_mode)
                or existing.st_uid != 0 or existing.st_gid != 0
                or stat.S_IMODE(existing.st_mode) != 0o600):
            raise AuthorityDenied("key.selection", "existing authority key selection custody is invalid")
        current = read_protected_file(path, expected_uid=0, maximum=16_384)
        if current == payload:
            return
        if exclusive:
            raise AuthorityDenied("key.selection", "private authority key receipt already exists")
    temporary = path.with_name("." + path.name + "." + secrets.token_hex(8) + ".tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(temporary, flags, 0o600)
        try:
            os.fchown(fd, 0, 0)
            os.fchmod(fd, 0o600)
            offset = 0
            while offset < len(payload):
                offset += os.write(fd, payload[offset:])
            os.fsync(fd)
        finally:
            os.close(fd)
        if _path_exists_nofollow(path):
            os.replace(temporary, path)
        else:
            os.rename(temporary, path)
        parent_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) |
                            getattr(os, "O_NOFOLLOW", 0))
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
    except OSError:
        raise AuthorityDenied("key.selection", "authority key selection update failed") from None
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _secure_path(path: Path, *, expected_uid: int, allow_missing_leaf: bool = False) -> None:
    if not path.is_absolute():
        raise AuthorityDenied("custody.path", "protected path must be absolute")
    current = Path(path.anchor)
    for index, part in enumerate(path.parts[1:]):
        current /= part
        is_leaf = index == len(path.parts[1:]) - 1
        try:
            info = current.lstat()
        except FileNotFoundError:
            if is_leaf and allow_missing_leaf:
                return
            raise AuthorityDenied("custody.path", "protected path is unavailable") from None
        if stat.S_ISLNK(info.st_mode):
            raise AuthorityDenied("custody.path", "protected path contains a symlink")
        if not is_leaf:
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != expected_uid
                    or stat.S_IMODE(info.st_mode) & 0o022):
                raise AuthorityDenied("custody.path", "protected directory ownership or mode is invalid")


def read_protected_file(path: Path, *, expected_uid: int = 0,
                        maximum: int = MAX_CONFIG_BYTES) -> bytes:
    _secure_path(path, expected_uid=expected_uid)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != expected_uid
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > maximum):
                raise AuthorityDenied("custody.file", "protected file ownership, mode, or size is invalid")
            data = bytearray()
            while len(data) <= maximum:
                block = os.read(fd, min(65536, maximum + 1 - len(data)))
                if not block:
                    break
                data.extend(block)
            if len(data) > maximum:
                raise AuthorityDenied("custody.file", "protected file exceeds its size bound")
            return bytes(data)
        finally:
            os.close(fd)
    except AuthorityDenied:
        raise
    except OSError:
        raise AuthorityDenied("custody.file", "protected file could not be read") from None


def write_protected_file(path: Path, data: bytes, *, expected_uid: int = 0,
                         maximum: int = MAX_CONFIG_BYTES) -> None:
    """Atomically create/replace a root-only config or secret without following links."""
    if os.geteuid() != expected_uid:
        raise AuthorityDenied("custody.write", "protected enrollment writer has the wrong UID")
    if not (path in {AUTHORITY_CONFIG_PATH, AUTHORITY_KEY_PATH, ARTIFACT_CATALOG_PATH}
            or path.parent == CREDENTIAL_DIRECTORY and _is_credential_reference(path.name)):
        raise AuthorityDenied("custody.write", "protected file destination is not enrolled")
    if not isinstance(data, bytes) or len(data) > maximum or not path.is_absolute():
        raise AuthorityDenied("custody.write", "protected file contents or path exceed bounds")
    _secure_path(path.parent / "placeholder", expected_uid=expected_uid,
                 allow_missing_leaf=True)
    _secure_path(path, expected_uid=expected_uid, allow_missing_leaf=True)
    try:
        existing = path.lstat()
    except FileNotFoundError:
        existing = None
    if existing is not None and (not stat.S_ISREG(existing.st_mode)
                                 or existing.st_uid != expected_uid
                                 or stat.S_IMODE(existing.st_mode) != 0o600):
        raise AuthorityDenied("custody.write", "existing protected file has invalid custody")
    parent = path.parent
    temp_path = parent / f".{path.name}.{secrets.token_hex(12)}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    fd = -1
    try:
        fd = os.open(temp_path, flags, 0o600)
        os.fchmod(fd, 0o600)
        offset = 0
        while offset < len(data):
            offset += os.write(fd, data[offset:])
        os.fsync(fd)
        os.close(fd)
        fd = -1
        os.replace(temp_path, path)
        dirfd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(dirfd)
        finally:
            os.close(dirfd)
    except AuthorityDenied:
        raise
    except OSError:
        raise AuthorityDenied("custody.write", "protected file update failed") from None
    finally:
        if fd >= 0:
            os.close(fd)
        try:
            temp_path.unlink()
        except OSError:
            pass


def _reject_secret_material(value: Any) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = str(key).casefold().replace("-", "_")
            if normalized in {"token", "secret", "password", "access_token", "refresh_token", "bearer_token", "credential"}:
                raise AuthorityDenied("enrollment.secret", "authority configuration must contain credential references only")
            _reject_secret_material(child)
    elif isinstance(value, list):
        for child in value:
            _reject_secret_material(child)


def write_authority_config(document: Mapping[str, Any], *, expected_uid: int = 0) -> None:
    """Atomically install a strict reference-only authority configuration."""
    if expected_uid != 0 or not isinstance(document, Mapping):
        raise AuthorityDenied("enrollment.schema", "authority configuration must be a mapping")
    root = dict(document)
    _reject_secret_material(root)
    required = {"schema", "key_id", "principals", "rules", "authentik", "process_profiles",
                "provider_enrollments", "mcp_services", "mcp_http_bindings", "memory_providers",
                "native_bridges", "normalization_policies", "delegations", "service_generations"}
    root = _exact(root, required, "authority")
    if root["schema"] != 1:
        raise AuthorityDenied("enrollment.schema", "authority configuration schema version is unsupported")
    _validate_service_generations(root["service_generations"])
    encoded = json.dumps(root, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    write_protected_file(AUTHORITY_CONFIG_PATH, encoded, expected_uid=expected_uid)


def write_artifact_catalog(document: Mapping[str, Any], *, expected_uid: int = 0) -> None:
    if expected_uid != 0 or not isinstance(document, Mapping) or set(document) != {"schema", "artifacts", "packages"} or document.get("schema") != 1:
        raise AuthorityDenied("enrollment.catalog", "artifact catalog schema is invalid")
    encoded = json.dumps(dict(document), sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    write_protected_file(ARTIFACT_CATALOG_PATH, encoded, expected_uid=expected_uid)


def create_authority_signing_key(*, expected_uid: int = 0) -> None:
    """Create the authority HMAC key once; rotation is a separate reviewed operation."""
    if os.geteuid() != expected_uid or expected_uid != 0:
        raise AuthorityDenied("key.enrollment", "signing-key enrollment requires the root authority identity")
    path = AUTHORITY_KEY_PATH
    _secure_path(path.parent / "placeholder", expected_uid=expected_uid, allow_missing_leaf=True)
    data = secrets.token_bytes(32)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags, 0o600)
        try:
            os.fchmod(fd, 0o600)
            offset = 0
            while offset < len(data):
                offset += os.write(fd, data[offset:])
            os.fsync(fd)
        finally:
            os.close(fd)
        dirfd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(dirfd)
        finally:
            os.close(dirfd)
    except FileExistsError:
        raise AuthorityDenied("key.exists", "authority signing key already exists") from None
    except OSError:
        raise AuthorityDenied("key.enrollment", "authority signing key could not be created") from None
    finally:
        del data


class RootCredentialVault:
    """Resolve opaque IDs only from the fixed root-owned credential directory."""

    def __init__(self, directory: Path = CREDENTIAL_DIRECTORY, *, expected_uid: int = 0):
        if directory != CREDENTIAL_DIRECTORY or type(expected_uid) is not int or expected_uid != 0:
            raise ValueError("credential vault path and owner are fixed")
        _secure_path(directory / "entry", expected_uid=expected_uid, allow_missing_leaf=True)
        self.directory = directory
        self.expected_uid = expected_uid

    def resolve_reference(self, reference: str, *, peer_uid: int | None = None,
                          required_scope: str | None = None,
                          principal_id: str | None = None) -> str:
        if (not isinstance(reference, str) or not 1 <= len(reference) <= 96
                or any(char not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-" for char in reference)):
            raise AuthorityDenied("credential.reference", "credential reference is invalid")
        secret = read_protected_file(self.directory / reference,
                                     expected_uid=self.expected_uid,
                                     maximum=MAX_CREDENTIAL_BYTES)
        try:
            record = json.loads(secret.decode("utf-8"), object_pairs_hook=_unique_pairs)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
            raise AuthorityDenied("credential.value", "protected credential is malformed")
        item = _exact(record, {"schema", "credential", "principal_id", "allowed_uids", "scopes"}, "credential")
        if (type(item["schema"]) is not int or item["schema"] != 1
                or not isinstance(item["principal_id"], str)
                or not isinstance(item["credential"], str)
                or not item["credential"] or any(char in item["credential"] for char in "\x00\r\n")
                or not isinstance(item["allowed_uids"], list) or not isinstance(item["scopes"], list)
                or not item["allowed_uids"]
                or any(type(uid) is not int or uid < 0 for uid in item["allowed_uids"])
                or any(not isinstance(scope, str) or not scope for scope in item["scopes"])):
            raise AuthorityDenied("credential.value", "protected credential metadata is malformed")
        if principal_id is not None and item["principal_id"] != principal_id:
            raise AuthorityDenied("credential.principal", "credential belongs to a different principal")
        if peer_uid is not None and (type(peer_uid) is not int or peer_uid not in item["allowed_uids"]):
            raise AuthorityDenied("credential.uid", "credential is not enrolled for this peer UID")
        if required_scope is not None and required_scope not in item["scopes"]:
            raise AuthorityDenied("credential.scope", "credential does not carry the required enrolled scope")
        return item["credential"]

    def write_credential(self, reference: str, credential: str, *,
                         principal_id: str, allowed_uids: list[int], scopes: list[str]) -> None:
        if (not isinstance(reference, str) or not 1 <= len(reference) <= 96
                or any(char not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-" for char in reference)
                or not isinstance(credential, str) or not credential
                or any(char in credential for char in "\x00\r\n")
                or not isinstance(allowed_uids, list) or not allowed_uids
                or any(type(uid) is not int or uid < 0 for uid in allowed_uids)
                or len(set(allowed_uids)) != len(allowed_uids)
                or not isinstance(scopes, list) or not scopes
                or any(not isinstance(scope, str) or not 1 <= len(scope) <= 128 for scope in scopes)
                or len(set(scopes)) != len(scopes)):
            raise AuthorityDenied("credential.enrollment", "credential enrollment metadata is invalid")
        payload = json.dumps({"schema": 1, "credential": credential,
                              "principal_id": _read_id(principal_id, "principal ID"),
                              "allowed_uids": sorted(allowed_uids), "scopes": sorted(scopes)},
                             sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
        write_protected_file(self.directory / reference, payload,
                             expected_uid=self.expected_uid, maximum=MAX_CREDENTIAL_BYTES)


class RootMCPCredentialHandle:
    """Opaque root-only MCP bearer resolver; it never crosses the IPC boundary."""

    __slots__ = ("_service_id", "_reference", "_vault")

    def __init__(self, service_id: str, reference: str, vault: RootCredentialVault):
        self._service_id = service_id
        self._reference = reference
        self._vault = vault

    def headers_for(self, service_id: str, context: Any, authorization: Any) -> Mapping[str, str]:
        if (service_id != self._service_id or context.principal_id != authorization.principal_id
                or context.uid != authorization.uid
                or authorization.capability not in {f"mcp:{service_id}:read", f"mcp:{service_id}:connect"}):
            raise AuthorityDenied("mcp.credential", "MCP credential handle is outside its protected binding")
        scope = (f"mcp:{service_id}:connect" if authorization.capability == f"mcp:{service_id}:connect"
                 else f"mcp:{service_id}:read")
        token = self._vault.resolve_reference(
            self._reference, peer_uid=context.uid,
            required_scope=scope, principal_id=context.principal_id)
        return {"Authorization": f"Bearer {token}"}

    def __repr__(self) -> str:
        return "<RootMCPCredentialHandle protected>"


def _is_credential_reference(value: str) -> bool:
    return (isinstance(value, str) and 1 <= len(value) <= 96
            and all(char in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-" for char in value))


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _exact(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise AuthorityDenied("enrollment.schema", f"protected {label} schema is invalid")
    return value


def _read_id(value: Any, label: str) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 256 or any(ord(char) < 0x21 or char in "\\\x7f" for char in value):
        raise AuthorityDenied("enrollment.schema", f"protected {label} is invalid")
    return value


@dataclass(frozen=True, slots=True)
class NativeBridgeEnrollment:
    """Root-selected producer/gateway pair and exact canonical provider route."""

    bridge_id: str
    producer_profile_id: str
    producer_uid: int
    producer_generation: str
    producer_executable: Path
    producer_executable_sha256: str
    producer_principal_id: str
    gateway_profile_id: str
    gateway_uid: int
    gateway_generation: str
    gateway_executable: Path
    gateway_executable_sha256: str
    gateway_principal_id: str
    canonicalizer_artifact_id: str
    canonicalizer_sha256: str
    normalization_policy_id: str
    normalization_policy_sha256: str
    normalization_policy_revision: int
    route_schema_id: str
    output_limit_mode: str
    output_limit_ceiling: int | None
    approved_operation: str
    provider_enrollment_id: str
    target: str
    recipient: str
    observer_delivery_bindings: tuple[Any, ...] = ()


@dataclass(frozen=True, slots=True)
class SourceIssuerRecord:
    issuer_channel_id: str
    producer_profile_id: str
    producer_role_artifact_id: str
    producer_role_sha256: str
    capture_schema_id: str
    allowed_parent_channels: tuple[str, ...]
    generation: str
    observer_enrollment_id: str
    source_action_ids: tuple[str, ...]
    private_provider_route_ids: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class RootObserverDeliveryBinding:
    observer_enrollment_id: str
    delivery_role: str


# Compatibility name used by the strict authority configuration parser.
ProtectedObserverDeliveryBinding = RootObserverDeliveryBinding


@dataclass(frozen=True, slots=True)
class ProtectedEnrollment:
    key_id: str
    bindings_by_uid: Mapping[int, PrincipalBinding]
    rules: Mapping[tuple[str, str, str], EffectRule]
    policy: AuthorityPolicy
    process_profiles: Mapping[str, Any]
    provider_enrollments: Mapping[str, Any]
    mcp_services: Mapping[str, Any]
    mcp_http_bindings: Mapping[str, Any]
    delegations: Mapping[str, ChildDelegationRule]
    memory_providers: Mapping[str, Any]
    native_bridges: Mapping[str, NativeBridgeEnrollment]
    artifact_catalog: Mapping[str, Any]
    package_catalog: Mapping[str, Any]
    artifact_catalog_path: Path
    artifact_staging_directory: Path
    service_records: list[Mapping[str, Any]]
    protected_devices: list[Mapping[str, Any]]
    protected_build_records: list[Mapping[str, Any]]
    protected_enrollment_digest: str
    native_package_records: list[Mapping[str, Any]]
    memory_enrollments: Mapping[tuple[str, str], Any]
    operation_parameter_schemas: list[Mapping[str, Any]]
    source_issuers: tuple[SourceIssuerRecord, ...]
    resource_job_records: tuple[Mapping[str, Any], ...]
    remote_session_records: tuple[Mapping[str, Any], ...]
    resource_backend_enrollment_records: tuple[Mapping[str, Any], ...]
    resource_body_recipe_records: tuple[Mapping[str, Any], ...]
    resource_scope_binding_records: tuple[Mapping[str, Any], ...] = ()
    resource_validator_records: tuple[Mapping[str, Any], ...] = ()
    root_journal_root_records: tuple[Mapping[str, Any], ...] = ()
    native_mcp_tool_binding_records: tuple[Mapping[str, Any], ...] = ()
    resource_controller_role_records: tuple[Mapping[str, Any], ...] = ()
    remote_observation_records: tuple[Mapping[str, Any], ...] = ()
    native_schema_artifact_records: tuple[Mapping[str, Any], ...] = ()
    composio_channel_enrollment_records: tuple[Mapping[str, Any], ...] = ()
    channel_delivery_binding_records: tuple[Mapping[str, Any], ...] = ()
    remote_startup_records: tuple[Mapping[str, Any], ...] = ()
    private_loopback_network_records: tuple[Mapping[str, Any], ...] = ()
    selected_resource_execution_records: tuple[Mapping[str, Any], ...] = ()
    selected_application_runtime_records: tuple[Mapping[str, Any], ...] = ()


_SOURCE_ACTIONS_BY_CHANNEL = {
    "native-input": frozenset({"authenticated-input"}),
    "tool-result": frozenset({"registered-tool-result"}),
    "memory-result": frozenset({"registered-memory-result"}),
    "effect-result": frozenset({"registered-effect-result"}),
    "delegated-child": frozenset({"registered-child-result"}),
    "schedule-event": frozenset({"root-timer-event"}),
    "webhook-event": frozenset({"authenticated-webhook-event"}),
}


def _parse_source_issuers(value: Any) -> tuple[SourceIssuerRecord, ...]:
    if not isinstance(value, list) or len(value) > 1024:
        raise AuthorityDenied("enrollment.source", "protected source issuer catalog is invalid")
    result = []
    seen_ids: set[str] = set()
    required = {"issuer_channel_id", "producer_profile_id", "producer_role_artifact_id",
                "producer_role_sha256", "capture_schema_id", "allowed_parent_channels",
                "generation", "observer_enrollment_id", "source_action_ids"}
    channels = set(_SOURCE_ACTIONS_BY_CHANNEL)
    for row in value:
        if not isinstance(row, dict) or set(row) not in (required, required | {"private_provider_route_ids"}):
            raise AuthorityDenied("enrollment.source", "protected source issuer fields are invalid")
        item = row
        channel = _read_id(item["issuer_channel_id"], "issuer channel")
        profile = _read_id(item["producer_profile_id"], "source producer profile")
        role_artifact = _read_id(item["producer_role_artifact_id"], "source producer role artifact")
        capture_schema = _read_id(item["capture_schema_id"], "source capture schema")
        generation = _read_id(item["generation"], "source producer generation")
        observer_id = _read_id(item["observer_enrollment_id"], "source observer enrollment")
        role_sha = item["producer_role_sha256"]
        actions = item["source_action_ids"]
        parents = item["allowed_parent_channels"]
        private_routes = item.get("private_provider_route_ids", [])
        if (channel not in channels or not isinstance(role_sha, str)
                or not re.fullmatch(r"[0-9a-f]{64}", role_sha)
                or not isinstance(actions, list) or not actions or len(actions) > 16
                or any(not isinstance(action, str) for action in actions)
                or len(actions) != len(set(actions))
                or not set(actions).issubset(_SOURCE_ACTIONS_BY_CHANNEL[channel])
                or not isinstance(parents, list) or len(parents) > len(channels)
                or any(not isinstance(parent, str) or parent not in channels for parent in parents)
                or len(parents) != len(set(parents))
                or not isinstance(private_routes, list) or len(private_routes) > 64
                or any(not isinstance(route, str) for route in private_routes)
                or len(private_routes) != len(set(private_routes))):
            raise AuthorityDenied("enrollment.source", "protected source issuer row is malformed")
        for route in private_routes:
            _read_id(route, "source private provider route")
        if observer_id in seen_ids:
            raise AuthorityDenied("enrollment.source", "protected source issuer is duplicated")
        seen_ids.add(observer_id)
        result.append(SourceIssuerRecord(
            channel, profile, role_artifact, role_sha, capture_schema,
            tuple(parents), generation, observer_id, tuple(actions), tuple(private_routes),
        ))
    return tuple(result)


def _parse_observer_delivery_bindings(
    value: Any, *, source_issuers: tuple[SourceIssuerRecord, ...],
    peer_generations: Mapping[str, str],
) -> tuple[RootObserverDeliveryBinding, ...]:
    """Parse bridge target-role selectors and join each observer to a bridge peer."""
    if not isinstance(value, list) or len(value) > 128:
        raise AuthorityDenied("enrollment.native_bridge", "native observer delivery bindings are malformed")
    issuers = {row.observer_enrollment_id: row for row in source_issuers}
    selected: list[RootObserverDeliveryBinding] = []
    seen: set[str] = set()
    for raw in value:
        try:
            item = _exact(raw, {"observer_enrollment_id", "delivery_role"},
                          "native observer delivery binding")
            observer_id = _read_id(item["observer_enrollment_id"], "observer enrollment ID")
            role = item["delivery_role"]
            issuer = issuers.get(observer_id)
            if (role not in {"producer", "gateway"} or issuer is None
                    or observer_id in seen
                    or peer_generations.get(issuer.producer_profile_id) != issuer.generation):
                raise ValueError("observer delivery target or peer join is invalid")
            seen.add(observer_id)
            selected.append(RootObserverDeliveryBinding(observer_id, role))
        except (TypeError, ValueError, AuthorityDenied):
            raise AuthorityDenied(
                "enrollment.native_bridge",
                "native observer delivery binding is not joined to a current bridge peer",
            ) from None
    return tuple(selected)


def _parse_native_schema_artifact_records(value: Any) -> tuple[Mapping[str, Any], ...]:
    """Validate active native schema artifact references without trusting receipt labels."""
    if not isinstance(value, list) or len(value) > 4096:
        raise AuthorityDenied("enrollment.generation", "native schema artifact catalog is invalid")
    fields = {"id", "artifact_id", "sha256", "schema_kind", "native_package_id",
              "native_package_generation", "adapter_id", "action_id", "source_receipt_handle",
              "size_bytes", "derivation_receipt_handle"}
    records: list[Mapping[str, Any]] = []
    seen: set[tuple[str, str, str, str, str, str]] = set()
    for raw in value:
        item = _exact(raw, fields, "native schema artifact")
        schema_id = _read_id(item["id"], "native schema ID")
        artifact_id = _read_id(item["artifact_id"], "native schema artifact ID")
        package_id = _read_id(item["native_package_id"], "native schema package ID")
        generation = _read_id(item["native_package_generation"], "native schema package generation")
        adapter_id = _read_id(item["adapter_id"], "native schema adapter ID")
        action_id = _read_id(item["action_id"], "native schema action ID")
        source_receipt = _read_id(item["source_receipt_handle"], "native schema source receipt")
        derivation_receipt = item["derivation_receipt_handle"]
        if derivation_receipt is not None:
            _read_id(derivation_receipt, "native schema derivation receipt")
        digest = item["sha256"]
        kind = item["schema_kind"]
        size_bytes = item["size_bytes"]
        if (not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest)
                or kind not in {"arguments", "result"}
                or type(size_bytes) is not int or not 1 <= size_bytes <= 262144
                or ((artifact_id == f"native-mcp-schema:{digest}") != (derivation_receipt is not None))):
            raise AuthorityDenied("enrollment.generation", "native schema artifact digest or kind is invalid")
        identity = (schema_id, package_id, generation, adapter_id, action_id, kind)
        if identity in seen:
            raise AuthorityDenied("enrollment.generation", "native schema artifact binding is duplicated")
        seen.add(identity)
        records.append(MappingProxyType({
            "id": schema_id, "artifact_id": artifact_id, "sha256": digest,
            "schema_kind": kind, "native_package_id": package_id,
            "native_package_generation": generation, "adapter_id": adapter_id,
            "action_id": action_id, "source_receipt_handle": source_receipt,
            "size_bytes": size_bytes, "derivation_receipt_handle": derivation_receipt,
        }))
    return tuple(records)


def _parse_composio_channel_enrollment_records(value: Any) -> tuple[Mapping[str, Any], ...]:
    """Strictly retain digest-covered WhatsApp Composio selections."""
    if not isinstance(value, list) or len(value) > 1024:
        raise AuthorityDenied("enrollment.generation", "Composio channel enrollment catalog is invalid")
    fields = {
        "id", "channel_resource_id", "resource_generation", "profile_id", "controller_role_id",
        "source_issuer_id", "composio_enrollment_id", "composio_user_id", "connected_account_id",
        "auth_config_id", "toolkit_version", "trigger_artifact_id", "trigger_artifact_sha256",
        "trigger_slug", "trigger_instance_id", "webhook_subscription_id",
        "webhook_route_enrollment_id", "webhook_secret_reference_id", "allowed_user_numbers",
        "payload_field_bindings", "max_event_age_seconds", "account_receipt_handle",
        "setup_receipt_handle",
    }
    rows: list[Mapping[str, Any]] = []
    seen: set[str] = set()
    binding_fields = {"sender_number", "message_id", "message_text", "event_timestamp"}
    for raw in value:
        item = _exact(raw, fields, "Composio channel enrollment")
        row_id = _read_id(item["id"], "Composio channel enrollment ID")
        if row_id in seen:
            raise AuthorityDenied("enrollment.generation", "Composio channel enrollment is duplicated")
        seen.add(row_id)
        id_fields = fields - {"trigger_artifact_sha256", "toolkit_version", "trigger_slug",
                              "allowed_user_numbers", "payload_field_bindings", "max_event_age_seconds"}
        clean = {name: _read_id(item[name], f"Composio {name}") for name in id_fields}
        if item["toolkit_version"] != "20260721_00":
            raise AuthorityDenied("enrollment.generation", "Composio toolkit version is not the pinned selection")
        slug = item["trigger_slug"]
        if (not isinstance(slug, str) or not 1 <= len(slug) <= 256
                or any(ord(ch) < 0x21 or ord(ch) > 0x7e for ch in slug)):
            raise AuthorityDenied("enrollment.generation", "Composio trigger slug is invalid")
        digest = item["trigger_artifact_sha256"]
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise AuthorityDenied("enrollment.generation", "Composio trigger artifact digest is invalid")
        numbers = item["allowed_user_numbers"]
        if (not isinstance(numbers, list) or not 1 <= len(numbers) <= 256
                or any(not isinstance(number, str) or not re.fullmatch(r"\+[1-9][0-9]{1,14}", number)
                       for number in numbers) or len(set(numbers)) != len(numbers)):
            raise AuthorityDenied("enrollment.generation", "Composio sender allowlist is invalid")
        raw_bindings = item["payload_field_bindings"]
        if not isinstance(raw_bindings, dict) or set(raw_bindings) != binding_fields:
            raise AuthorityDenied("enrollment.generation", "Composio payload field bindings are invalid")
        bindings: dict[str, tuple[str, ...]] = {}
        for name in sorted(binding_fields):
            selected = raw_bindings[name]
            if (not isinstance(selected, list) or not 1 <= len(selected) <= 8
                    or any(not isinstance(field, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,127}", field)
                           for field in selected) or len(set(selected)) != len(selected)):
                raise AuthorityDenied("enrollment.generation", "Composio payload field binding is invalid")
            bindings[name] = tuple(selected)
        max_age = item["max_event_age_seconds"]
        if type(max_age) is not int or not 1 <= max_age <= 300:
            raise AuthorityDenied("enrollment.generation", "Composio event freshness bound is invalid")
        rows.append(MappingProxyType({
            **clean, "toolkit_version": item["toolkit_version"], "trigger_slug": slug,
            "trigger_artifact_sha256": digest, "allowed_user_numbers": tuple(numbers),
            "payload_field_bindings": MappingProxyType(bindings), "max_event_age_seconds": max_age,
        }))
    return tuple(rows)


def _parse_channel_delivery_binding_records(value: Any) -> tuple[Mapping[str, Any], ...]:
    if not isinstance(value, list) or len(value) > 1024:
        raise AuthorityDenied("enrollment.generation", "channel delivery binding catalog is invalid")
    fields = {"id", "profile_id", "process_generation", "native_package_id",
              "native_package_generation", "authority_endpoint_id", "allowed_channel_ingress_ids",
              "source_observer_enrollment_ids", "generation"}
    result: list[Mapping[str, Any]] = []
    seen: set[str] = set()
    for raw in value:
        row = _exact(raw, fields, "channel delivery binding")
        clean = {name: _read_id(row[name], f"channel delivery {name}")
                 for name in fields - {"allowed_channel_ingress_ids", "source_observer_enrollment_ids"}}
        if clean["id"] in seen:
            raise AuthorityDenied("enrollment.generation", "channel delivery binding is duplicated")
        seen.add(clean["id"])
        lists: dict[str, tuple[str, ...]] = {}
        for name in ("allowed_channel_ingress_ids", "source_observer_enrollment_ids"):
            selected = row[name]
            if (not isinstance(selected, list) or not 1 <= len(selected) <= 16
                    or any(not isinstance(item, str) for item in selected)
                    or len(set(selected)) != len(selected)):
                raise AuthorityDenied("enrollment.generation", "channel delivery selection list is invalid")
            lists[name] = tuple(_read_id(item, f"channel delivery {name} item") for item in selected)
        result.append(MappingProxyType({**clean, **lists}))
    return tuple(result)


def _validate_service_generations(value: Any) -> dict[str, Any]:
    """Validate the one active, root-owned HI09 catalog snapshot and its digest."""
    keys = {"schema", "generation_id", "service_records", "protected_devices",
            "protected_build_records", "native_packages", "memory_enrollments",
            "operation_parameter_schemas", "source_issuers", "resource_jobs",
            "remote_session_enrollments", "resource_backend_enrollments",
            "resource_body_recipes", "resource_scope_bindings", "resource_validators",
            "root_journal_roots", "resource_controller_roles",
            "native_mcp_tool_bindings", "remote_observation_enrollments",
            "native_schema_artifacts", "composio_channel_enrollments", "channel_delivery_bindings",
            "remote_startup_enrollments", "private_loopback_networks",
            "selected_resource_executions",
            "selected_application_runtimes",
            "generation_digest"}
    item = _exact(value, keys, "service generation snapshot")
    if type(item["schema"]) is not int or item["schema"] != 1:
        raise AuthorityDenied("enrollment.generation", "service generation snapshot schema is unsupported")
    _read_id(item["generation_id"], "service generation snapshot ID")
    digest = item["generation_digest"]
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise AuthorityDenied("enrollment.generation", "service generation snapshot digest is invalid")
    unsigned = {key: child for key, child in item.items() if key != "generation_digest"}
    actual = hashlib.sha256(json.dumps(
        unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")).hexdigest()
    if actual != digest:
        raise AuthorityDenied("enrollment.generation", "service generation snapshot digest does not match")
    list_fields = ("service_records", "protected_devices", "protected_build_records",
                   "native_packages", "memory_enrollments", "operation_parameter_schemas",
                   "source_issuers", "native_mcp_tool_bindings",
                   "resource_controller_roles", "remote_observation_enrollments",
                   "remote_startup_enrollments", "private_loopback_networks",
                   "selected_resource_executions", "selected_application_runtimes")
    for name in list_fields:
        rows = item[name]
        if (not isinstance(rows, list) or len(rows) > 1024
                or any(not isinstance(row, dict) for row in rows)):
            raise AuthorityDenied("enrollment.generation", f"protected {name} catalog is invalid")
    native_schema_records = _parse_native_schema_artifact_records(item["native_schema_artifacts"])
    composio_channel_records = _parse_composio_channel_enrollment_records(
        item["composio_channel_enrollments"],
    )
    channel_delivery_records = _parse_channel_delivery_binding_records(item["channel_delivery_bindings"])
    native_mcp_fields = {
        "id", "profile_id", "process_generation", "native_package_id",
        "native_package_generation", "native_server_name", "native_tool_name",
        "native_schema_sha256", "mcp_enrollment_id", "mcp_generation",
        "mcp_tool_name", "request_schema_id", "result_schema_id", "effect_operation",
        "effect_target", "capability", "recipient", "scope_bindings",
        "handler_artifact_id", "handler_artifact_sha256",
    }
    native_mcp_ids: set[str] = set()
    native_mcp_action_keys: set[tuple[str, str, str]] = set()
    for row in item["native_mcp_tool_bindings"]:
        binding = _exact(row, native_mcp_fields, "native MCP tool binding")
        binding_id = _read_id(binding["id"], "native MCP binding ID")
        if binding_id in native_mcp_ids:
            raise AuthorityDenied("enrollment.generation", "native MCP binding ID is duplicated")
        native_mcp_ids.add(binding_id)
        for field in (native_mcp_fields - {"native_schema_sha256", "handler_artifact_sha256",
                                           "native_server_name", "native_tool_name", "mcp_tool_name",
                                           "effect_operation", "recipient", "scope_bindings"}):
            _read_id(binding[field], f"native MCP {field}")
        for field in ("native_schema_sha256", "handler_artifact_sha256"):
            if not isinstance(binding[field], str) or not re.fullmatch(r"[0-9a-f]{64}", binding[field]):
                raise AuthorityDenied("enrollment.generation", "native MCP digest is malformed")
        if (not isinstance(binding["native_server_name"], str)
                or not re.fullmatch(r"[a-z][a-z0-9_-]{0,62}", binding["native_server_name"])
                or any(not isinstance(binding[field], str) or not re.fullmatch(
                    r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}", binding[field])
                       for field in ("native_tool_name", "mcp_tool_name"))
                or binding["effect_operation"] not in {"mcp.request", "mcp.stdio"}
                or binding["recipient"] is not None):
            raise AuthorityDenied("enrollment.generation", "native MCP tool identity is malformed")
        key = (binding["profile_id"], binding["process_generation"], binding["native_tool_name"])
        if key in native_mcp_action_keys:
            raise AuthorityDenied("enrollment.generation", "native MCP tool selection is duplicated")
        native_mcp_action_keys.add(key)
        scopes = binding["scope_bindings"]
        if not isinstance(scopes, list) or not 1 <= len(scopes) <= 64:
            raise AuthorityDenied("enrollment.generation", "native MCP scope bindings are malformed")
        names: set[str] = set()
        selected_resources: set[str] = set()
        for raw_scope in scopes:
            scope = _exact(raw_scope, {"argument_field", "selected_resource_id"}, "native MCP scope binding")
            name = _read_id(scope["argument_field"], "native MCP argument field")
            selected = _read_id(scope["selected_resource_id"], "native MCP selected resource")
            if name in names or selected in selected_resources:
                raise AuthorityDenied("enrollment.generation", "native MCP scope binding is duplicated")
            names.add(name)
            selected_resources.add(selected)
    controller_fields = {"id", "controller_kind", "daemon_unit_id", "daemon_executable_artifact_id",
                         "daemon_executable_sha256", "role_module_artifact_id", "role_module_sha256",
                         "controller_generation", "source_observer_enrollment_ids",
                         "allowed_backend_enrollment_ids", "allowed_operations", "max_lease_seconds"}
    controller_ids: set[str] = set()
    for row in item["resource_controller_roles"]:
        controller = _exact(row, controller_fields, "resource controller role")
        controller_id = _read_id(controller["id"], "resource controller ID")
        if controller_id in controller_ids:
            raise AuthorityDenied("enrollment.generation", "resource controller role is duplicated")
        controller_ids.add(controller_id)
        for field in ("daemon_unit_id", "daemon_executable_artifact_id", "role_module_artifact_id",
                      "controller_generation"):
            _read_id(controller[field], f"resource controller {field}")
        if (controller["controller_kind"] not in {"worker", "root-scheduler", "root-webhook", "root-channel"}
                or any(not isinstance(controller[field], str) or not re.fullmatch(r"[0-9a-f]{64}", controller[field])
                       for field in ("daemon_executable_sha256", "role_module_sha256"))
                or type(controller["max_lease_seconds"]) is not int
                or not 1 <= controller["max_lease_seconds"] <= 600):
            raise AuthorityDenied("enrollment.generation", "resource controller role is malformed")
        for field in ("source_observer_enrollment_ids", "allowed_backend_enrollment_ids", "allowed_operations"):
            values = controller[field]
            if (not isinstance(values, list) or len(values) > 128
                    or any(not isinstance(value, str) for value in values)
                    or len(values) != len(set(values))):
                raise AuthorityDenied("enrollment.generation", "resource controller role lists are malformed")
            for value in values:
                _read_id(value, f"resource controller {field}")
    jobs = item["resource_jobs"]
    if (not isinstance(jobs, list) or len(jobs) > 692
            or any(not isinstance(row, dict) for row in jobs)):
        raise AuthorityDenied("enrollment.generation", "protected resource_jobs catalog is invalid")
    resource_fields = {
        "resource_id", "kind", "selected_enabled", "profile_id", "principal_id",
        "generation", "consent_revision", "approved_action_ids", "fixed_target_ids",
        "credential_reference_ids", "recipient_scope", "source_policy", "schedule_or_route_id",
        "max_children", "max_concurrency", "max_runtime_seconds", "max_payload_bytes",
        "max_replay_entries", "enrollment_id", "source_issuer_channel_id",
        "observer_enrollment_id", "approved_dag",
    }
    seen_resource_ids: set[str] = set()
    for row in jobs:
        resource = _exact(row, resource_fields, "resource job enrollment")
        resource_id = _read_id(resource["resource_id"], "resource job ID")
        if resource_id in seen_resource_ids:
            raise AuthorityDenied("enrollment.generation", "resource job enrollment is duplicated")
        seen_resource_ids.add(resource_id)
        for field in ("kind", "profile_id", "principal_id", "generation",
                      "consent_revision", "enrollment_id", "source_issuer_channel_id",
                      "observer_enrollment_id"):
            _read_id(resource[field], f"resource job {field}")
        if type(resource["selected_enabled"]) is not bool:
            raise AuthorityDenied("enrollment.generation", "resource selection flag is not boolean")
        for field in ("approved_action_ids", "fixed_target_ids", "credential_reference_ids"):
            values = resource[field]
            if (not isinstance(values, list) or len(values) > 128
                    or any(not isinstance(selected, str) for selected in values)
                    or len(set(values)) != len(values)):
                raise AuthorityDenied("enrollment.generation", f"resource job {field} is malformed")
            for selected in values:
                (_read_id(selected, f"resource job {field[:-4]}") if field != "credential_reference_ids"
                 else None)
            if field == "credential_reference_ids" and any(
                    not _is_credential_reference(selected) for selected in values):
                raise AuthorityDenied("enrollment.generation", "resource job credential refs are malformed")
        for field in ("max_children", "max_concurrency", "max_runtime_seconds",
                      "max_payload_bytes", "max_replay_entries"):
            limit = resource[field]
            lower = 0 if field == "max_replay_entries" else 1
            upper = 262144 if field == "max_payload_bytes" else 4096
            if type(limit) is not int or not lower <= limit <= upper:
                raise AuthorityDenied("enrollment.generation", f"resource job {field} is invalid")
        if resource["schedule_or_route_id"] is not None:
            _read_id(resource["schedule_or_route_id"], "resource schedule or route")
        dag = _exact(resource["approved_dag"], {"dag_sha256", "nodes"}, "resource job DAG")
        if (not isinstance(dag["dag_sha256"], str)
                or not re.fullmatch(r"[0-9a-f]{64}", dag["dag_sha256"])
                or not isinstance(dag["nodes"], list) or not 1 <= len(dag["nodes"]) <= 128):
            raise AuthorityDenied("enrollment.generation", "protected resource job DAG is malformed")
        node_fields = {"node_id", "resource_id", "action_id", "operation", "target_id",
                       "recipient", "request_schema_id", "body_recipe_id", "depends_on",
                       "maximum_attempts", "backend_enrollment_id", "result_schema_id",
                       "scope_binding_id"}
        node_ids: set[str] = set()
        normalized_nodes = []
        for raw_node in dag["nodes"]:
            node = _exact(raw_node, node_fields, "resource job DAG node")
            node_id = _read_id(node["node_id"], "resource DAG node ID")
            if node_id in node_ids:
                raise AuthorityDenied("enrollment.generation", "resource job DAG node is duplicated")
            node_ids.add(node_id)
            for field in ("resource_id", "action_id", "operation", "target_id",
                          "request_schema_id", "body_recipe_id", "backend_enrollment_id",
                          "result_schema_id", "scope_binding_id"):
                _read_id(node[field], f"resource DAG {field}")
            if node["recipient"] is not None:
                _read_id(node["recipient"], "resource DAG recipient")
            dependencies = node["depends_on"]
            if (not isinstance(dependencies, list) or len(dependencies) > 128
                    or any(not isinstance(dependency, str) for dependency in dependencies)
                    or len(dependencies) != len(set(dependencies))):
                raise AuthorityDenied("enrollment.generation", "resource DAG dependencies are malformed")
            for dependency in dependencies:
                _read_id(dependency, "resource DAG dependency")
            attempts = node["maximum_attempts"]
            if type(attempts) is not int or not 1 <= attempts <= 10:
                raise AuthorityDenied("enrollment.generation", "resource DAG retry bound is invalid")
            normalized_nodes.append(node)
        actual_dag_digest = hashlib.sha256(json.dumps(
            sorted(normalized_nodes, key=lambda node: node["node_id"]),
            sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        ).encode("utf-8")).hexdigest()
        if actual_dag_digest != dag["dag_sha256"]:
            raise AuthorityDenied("enrollment.generation", "resource DAG digest does not match its nodes")
    remote_rows = item["remote_session_enrollments"]
    if not isinstance(remote_rows, list) or len(remote_rows) > 128:
        raise AuthorityDenied("enrollment.generation", "protected remote session catalog is invalid")
    remote_fields = {
        "id", "gateway_profile_id", "gateway_role_artifact_id", "gateway_role_sha256",
        "native_desktop_profile_id", "native_generation", "connector_target_id",
        "approved_asset_routes", "approved_websocket_route", "expected_hostname",
        "expected_origin", "jwt_issuer", "jwt_audience", "jwks_origin",
        "jwt_algorithm_allowlist", "allowed_email_reference_id", "policy_verifier_enrollment_id",
        "policy_config_digest", "maximum_lease_seconds", "watchdog_interval_seconds",
        "policy_revision", "principal_bindings_by_subject", "access_policy_binding",
        "tunnel_runtime_binding", "setup_writer_binding",
    }
    access_fields = {
        "verifier_enrollment_id", "account_id", "application_id", "policy_id",
        "otp_identity_provider_id", "otp_provider_type", "verifier_config_digest",
        "read_credential_reference_id",
    }
    tunnel_fields = {
        "tunnel_enrollment_id", "tunnel_id", "cloudflared_profile_id",
        "tunnel_token_reference_id", "token_sink_id", "origin_readiness_policy_id",
    }
    setup_writer_fields = {
        "setup_profile_id", "setup_generation", "setup_role_artifact_id", "setup_role_sha256",
        "setup_enrollment_id", "setup_transaction_policy_id", "allowed_tunnel_enrollment_ids",
        "token_writer_enrollment_id", "origin_probe_enrollment_id",
    }
    seen_remote_ids: set[str] = set()
    for row in remote_rows:
        remote = _exact(row, remote_fields, "remote session enrollment")
        remote_id = _read_id(remote["id"], "remote session enrollment ID")
        if remote_id in seen_remote_ids:
            raise AuthorityDenied("enrollment.generation", "remote session enrollment is duplicated")
        try:
            for name in (
                "gateway_profile_id", "gateway_role_artifact_id", "native_desktop_profile_id",
                "native_generation", "connector_target_id", "approved_websocket_route",
                "expected_hostname", "expected_origin", "jwt_issuer", "jwt_audience",
                "jwks_origin", "allowed_email_reference_id", "policy_verifier_enrollment_id",
                "policy_revision",
            ):
                _read_id(remote[name], f"remote session {name}")
            if (not isinstance(remote["gateway_role_sha256"], str)
                    or not re.fullmatch(r"[0-9a-f]{64}", remote["gateway_role_sha256"])
                    or not isinstance(remote["policy_config_digest"], str)
                    or not re.fullmatch(r"[0-9a-f]{64}", remote["policy_config_digest"])):
                raise ValueError("remote session digest is invalid")
            assets = remote["approved_asset_routes"]
            algorithms = remote["jwt_algorithm_allowlist"]
            if (not isinstance(assets, list) or not assets or len(assets) > 32
                    or any(not isinstance(route, str) for route in assets)
                    or len(assets) != len(set(assets))
                    or not isinstance(algorithms, list) or algorithms != ["RS256"]
                    or type(remote["maximum_lease_seconds"]) is not int
                    or not 1 <= remote["maximum_lease_seconds"] <= 60
                    or type(remote["watchdog_interval_seconds"]) is not int
                    or not 1 <= remote["watchdog_interval_seconds"] <= 5):
                raise ValueError("remote session routes, JWT, or lease bounds are invalid")
            for route in assets:
                _read_id(route, "remote approved asset route")
            principals = remote["principal_bindings_by_subject"]
            if not isinstance(principals, dict) or not principals or len(principals) > 256:
                raise ValueError("remote principal subject map is invalid")
            for subject, binding in principals.items():
                _read_id(subject, "remote verified subject")
                item_binding = _exact(binding, {"principal_id", "profile_id", "email"},
                                      "remote verified principal binding")
                _read_id(item_binding["principal_id"], "remote principal ID")
                _read_id(item_binding["profile_id"], "remote profile ID")
                email = item_binding["email"]
                if (not isinstance(email, str) or len(email) > 320 or "@" not in email
                        or email != email.casefold() or any(c.isspace() for c in email)):
                    raise ValueError("remote verified email binding is invalid")
            access = _exact(remote["access_policy_binding"], access_fields,
                            "remote Access policy binding")
            for name in access_fields - {"otp_provider_type", "verifier_config_digest"}:
                _read_id(access[name], f"remote access {name}")
            if (access["otp_provider_type"] != "onetimepin"
                    or not isinstance(access["verifier_config_digest"], str)
                    or not re.fullmatch(r"[0-9a-f]{64}", access["verifier_config_digest"])):
                raise ValueError("remote Access verifier binding is invalid")
            tunnel = _exact(remote["tunnel_runtime_binding"], tunnel_fields,
                            "remote tunnel runtime binding")
            for name in tunnel_fields:
                _read_id(tunnel[name], f"remote tunnel {name}")
            writer = _exact(remote["setup_writer_binding"], setup_writer_fields,
                            "remote setup writer binding")
            for name in ("setup_profile_id", "setup_generation", "setup_role_artifact_id",
                         "setup_enrollment_id", "setup_transaction_policy_id",
                         "token_writer_enrollment_id", "origin_probe_enrollment_id"):
                _read_id(writer[name], f"remote setup writer {name}")
            if (not isinstance(writer["setup_role_sha256"], str)
                    or not re.fullmatch(r"[0-9a-f]{64}", writer["setup_role_sha256"])
                    or not isinstance(writer["allowed_tunnel_enrollment_ids"], list)
                    or not writer["allowed_tunnel_enrollment_ids"]
                    or len(writer["allowed_tunnel_enrollment_ids"]) > 64
                    or any(not isinstance(value, str) for value in writer["allowed_tunnel_enrollment_ids"])
                    or len(set(writer["allowed_tunnel_enrollment_ids"]))
                    != len(writer["allowed_tunnel_enrollment_ids"])):
                raise ValueError("remote setup writer binding is malformed")
            for value in writer["allowed_tunnel_enrollment_ids"]:
                _read_id(value, "remote allowed tunnel enrollment")
        except (TypeError, ValueError, AuthorityDenied):
            raise AuthorityDenied("enrollment.generation", "protected remote session record is malformed") from None
        seen_remote_ids.add(remote_id)
    observation_rows = item["remote_observation_enrollments"]
    if (not isinstance(observation_rows, list) or len(observation_rows) > 128
            or any(not isinstance(row, dict) for row in observation_rows)):
        raise AuthorityDenied("enrollment.generation", "protected remote observation catalog is invalid")
    remote_by_id = {row["id"]: row for row in remote_rows}
    observation_fields = {"id", "remote_enrollment_id", "gateway_listener_port",
                          "native_window_enrollment_id", "display_server_profile_id",
                          "display_server_generation", "display_name", "xauthority_receipt_handle"}
    observation_ids: set[str] = set()
    selected_remote_ids: set[str] = set()
    for row in observation_rows:
        observation = _exact(row, observation_fields, "remote observation selection")
        observation_id = _read_id(observation["id"], "remote observation ID")
        remote_id = _read_id(observation["remote_enrollment_id"], "remote observation enrollment")
        native_window_id = _read_id(observation["native_window_enrollment_id"], "native window enrollment")
        _read_id(observation["display_server_profile_id"], "display server profile")
        _read_id(observation["display_server_generation"], "display server generation")
        _read_id(observation["display_name"], "selected display name")
        _read_id(observation["xauthority_receipt_handle"], "Xauthority receipt handle")
        port = observation["gateway_listener_port"]
        remote = remote_by_id.get(remote_id)
        native_service_rows = [service for service in item["service_records"]
                               if service.get("profile_id") == (remote or {}).get("native_desktop_profile_id")
                               and service.get("generation") == (remote or {}).get("native_generation")]
        display_service_rows = [service for service in item["service_records"]
                                if service.get("profile_id") == observation["display_server_profile_id"]
                                and service.get("generation") == observation["display_server_generation"]]
        if (observation_id in observation_ids or remote_id in selected_remote_ids or remote is None
                or type(port) is not int or not 1 <= port <= 65535
                or len(native_service_rows) != 1 or len(display_service_rows) != 1
                or native_window_id != native_service_rows[0].get("enrollment_id")
                or observation["display_server_profile_id"] == remote["native_desktop_profile_id"]
                or not observation["display_name"].strip()
                or len(observation["display_name"]) > 128
                or any(ord(char) < 0x20 for char in observation["display_name"])):
            raise AuthorityDenied("enrollment.generation", "remote observation selection is malformed or stale")
        observation_ids.add(observation_id)
        selected_remote_ids.add(remote_id)
    startup_rows = item["remote_startup_enrollments"]
    if not isinstance(startup_rows, list) or len(startup_rows) > 128:
        raise AuthorityDenied("enrollment.generation", "protected remote startup catalog is invalid")
    startup_fields = {
        "id", "remote_enrollment_id", "display_enrollment_id", "display_generation",
        "display_operation_id", "gateway_enrollment_id", "gateway_generation",
        "gateway_operation_id", "desktop_enrollment_id", "desktop_generation",
        "desktop_operation_id", "network_enrollment_id", "xauthority_mount_id",
        "xpra_xauthority_overlay_artifact_id", "xpra_xauthority_overlay_sha256",
        "xpra_xauthority_patch_receipt_handle",
    }
    service_by_identity = {}
    for service in item["service_records"]:
        identity = (service.get("enrollment_id"), service.get("generation"))
        if identity in service_by_identity:
            raise AuthorityDenied("enrollment.generation", "service enrollment generation is duplicated")
        service_by_identity[identity] = service
    network_ids = {row.get("id") for row in item["private_loopback_networks"]
                   if isinstance(row, dict)}
    startup_ids: set[str] = set()
    startup_remote_ids: set[str] = set()
    expected_operations = {
        "display_operation_id": "native-display-start-v1",
        "gateway_operation_id": "native-remote-gateway-start-v1",
        "desktop_operation_id": "native-desktop-app-start-v1",
    }
    for raw in startup_rows:
        startup = _exact(raw, startup_fields, "remote startup enrollment")
        startup_id = _read_id(startup["id"], "remote startup ID")
        remote_id = _read_id(startup["remote_enrollment_id"], "remote startup session")
        if startup_id in startup_ids or remote_id in startup_remote_ids or remote_id not in remote_by_id:
            raise AuthorityDenied("enrollment.generation", "remote startup is duplicate or has no session")
        startup_ids.add(startup_id)
        startup_remote_ids.add(remote_id)
        for field in ("display_enrollment_id", "display_generation", "gateway_enrollment_id",
                      "gateway_generation", "desktop_enrollment_id", "desktop_generation",
                      "network_enrollment_id", "xauthority_mount_id",
                      "xpra_xauthority_overlay_artifact_id", "xpra_xauthority_patch_receipt_handle"):
            _read_id(startup[field], f"remote startup {field}")
        if any(startup[field] != fixed for field, fixed in expected_operations.items()):
            raise AuthorityDenied("enrollment.generation", "remote startup operation selector is not fixed")
        if (not isinstance(startup["xpra_xauthority_overlay_sha256"], str)
                or not re.fullmatch(r"[0-9a-f]{64}", startup["xpra_xauthority_overlay_sha256"])):
            raise AuthorityDenied("enrollment.generation", "remote startup overlay digest is invalid")
        session = remote_by_id[remote_id]
        if (startup["gateway_enrollment_id"], startup["gateway_generation"]) not in service_by_identity:
            raise AuthorityDenied("enrollment.generation", "remote startup gateway service is absent")
        if (startup["desktop_enrollment_id"], startup["desktop_generation"]) not in service_by_identity:
            raise AuthorityDenied("enrollment.generation", "remote startup desktop service is absent")
        if (startup["display_enrollment_id"], startup["display_generation"]) not in service_by_identity:
            raise AuthorityDenied("enrollment.generation", "remote startup display service is absent")
        gateway = service_by_identity[(startup["gateway_enrollment_id"], startup["gateway_generation"])]
        desktop = service_by_identity[(startup["desktop_enrollment_id"], startup["desktop_generation"])]
        if (gateway.get("profile_id") != session.get("gateway_profile_id")
                or desktop.get("profile_id") != session.get("native_desktop_profile_id")
                or startup["desktop_generation"] != session.get("native_generation")
                or startup["network_enrollment_id"] not in network_ids):
            raise AuthorityDenied("enrollment.generation", "remote startup selection does not join its session")
        startup_display = service_by_identity[(startup["display_enrollment_id"], startup["display_generation"])]
        observations = [row for row in observation_rows
                        if row.get("remote_enrollment_id") == remote_id]
        if (len(observations) != 1
                or startup_display.get("profile_id") != observations[0].get("display_server_profile_id")
                or startup["display_generation"] != observations[0].get("display_server_generation")):
            raise AuthorityDenied("enrollment.generation", "remote startup display does not join selected observation")
        selected_members = {startup["display_enrollment_id"], startup["gateway_enrollment_id"],
                            startup["desktop_enrollment_id"]}
        selected_networks = [row for row in item["private_loopback_networks"]
                             if row.get("id") == startup["network_enrollment_id"]]
        if (len(selected_networks) != 1
                or not selected_members.issubset(set(selected_networks[0].get("member_enrollment_ids", ())))):
            raise AuthorityDenied("enrollment.generation", "remote startup roles do not join its selected network")
    network_rows = item["private_loopback_networks"]
    if not isinstance(network_rows, list) or len(network_rows) > 128:
        raise AuthorityDenied("enrollment.generation", "protected private loopback catalog is invalid")
    network_fields = {"id", "generation", "namespace_identity", "member_enrollment_ids",
                      "listener_bindings", "client_bindings", "policy_artifact_id", "policy_sha256"}
    seen_network_ids: set[str] = set()
    for raw in network_rows:
        network = _exact(raw, network_fields, "private loopback network")
        network_id = _read_id(network["id"], "private loopback network ID")
        _read_id(network["generation"], "private loopback generation")
        _read_id(network["namespace_identity"], "private loopback namespace identity")
        _read_id(network["policy_artifact_id"], "private loopback policy artifact")
        if network_id in seen_network_ids:
            raise AuthorityDenied("enrollment.generation", "private loopback network is duplicated")
        seen_network_ids.add(network_id)
        if (not isinstance(network["policy_sha256"], str)
                or not re.fullmatch(r"[0-9a-f]{64}", network["policy_sha256"])):
            raise AuthorityDenied("enrollment.generation", "private loopback policy digest is invalid")
        members = network["member_enrollment_ids"]
        if (not isinstance(members, list) or not 2 <= len(members) <= 32
                or any(not isinstance(value, str) for value in members) or len(set(members)) != len(members)):
            raise AuthorityDenied("enrollment.generation", "private loopback member list is malformed")
        for member in members:
            _read_id(member, "private loopback member enrollment")
        listeners, clients = network["listener_bindings"], network["client_bindings"]
        if (not isinstance(listeners, list) or not isinstance(clients, list)
                or len(listeners) > 32 or len(clients) > 32):
            raise AuthorityDenied("enrollment.generation", "private loopback bindings are malformed")
        listener_keys: set[tuple[str, int]] = set()
        for raw_binding in listeners:
            binding = _exact(raw_binding, {"enrollment_id", "role", "ipv4", "port"},
                             "private loopback listener")
            member = _read_id(binding["enrollment_id"], "loopback listener enrollment")
            _read_id(binding["role"], "loopback listener role")
            port = binding["port"]
            if (member not in members or binding["ipv4"] != "127.0.0.1"
                    or type(port) is not int or not 1 <= port <= 65535
                    or (member, port) in listener_keys):
                raise AuthorityDenied("enrollment.generation", "private loopback listener is invalid")
            listener_keys.add((member, port))
        client_keys: set[tuple[str, str, int]] = set()
        for raw_binding in clients:
            binding = _exact(raw_binding, {"enrollment_id", "listener_enrollment_id", "port"},
                             "private loopback client")
            member = _read_id(binding["enrollment_id"], "loopback client enrollment")
            listener = _read_id(binding["listener_enrollment_id"], "loopback client listener")
            port = binding["port"]
            if (member not in members or listener not in members or member == listener
                    or type(port) is not int or not 1 <= port <= 65535
                    or (listener, port) not in listener_keys
                    or (member, listener, port) in client_keys):
                raise AuthorityDenied("enrollment.generation", "private loopback client is invalid")
            client_keys.add((member, listener, port))
    backend_rows = item["resource_backend_enrollments"]
    if (not isinstance(backend_rows, list) or len(backend_rows) > 692
            or any(not isinstance(row, dict) for row in backend_rows)):
        raise AuthorityDenied("enrollment.generation", "protected resource backend catalog is invalid")
    backend_fields = {
        "id", "resource_id", "profile_id", "principal_id", "generation", "consent_revision",
        "source_issuer_channel_id", "observer_enrollment_id", "native_package_id",
        "native_package_generation", "handler_artifact_id", "handler_sha256",
        "approved_action_ids", "operation", "target_id", "recipient",
        "credential_reference_ids", "request_schema_id", "result_schema_id", "body_recipe_id",
        "scope_binding_id", "maximum_request_bytes", "maximum_response_bytes", "maximum_seconds",
        "profile_generation", "execution_binding", "credential_bindings",
    }
    seen_backend_ids: set[str] = set()
    for row in backend_rows:
        backend = _exact(row, backend_fields, "resource backend enrollment")
        backend_id = _read_id(backend["id"], "resource backend enrollment ID")
        if backend_id in seen_backend_ids:
            raise AuthorityDenied("enrollment.generation", "resource backend enrollment is duplicated")
        seen_backend_ids.add(backend_id)
        for name in (backend_fields - {"handler_sha256", "approved_action_ids",
                                       "credential_reference_ids", "maximum_request_bytes",
                                       "maximum_response_bytes", "maximum_seconds", "recipient",
                                       "execution_binding", "credential_bindings"}):
            _read_id(backend[name], f"resource backend {name}")
        if (not isinstance(backend["handler_sha256"], str)
                or not re.fullmatch(r"[0-9a-f]{64}", backend["handler_sha256"])
                or not isinstance(backend["approved_action_ids"], list)
                or not backend["approved_action_ids"]
                or len(backend["approved_action_ids"]) > 64
                or any(not isinstance(value, str) for value in backend["approved_action_ids"])
                or len(set(backend["approved_action_ids"])) != len(backend["approved_action_ids"])
                or not isinstance(backend["credential_reference_ids"], list)
                or len(backend["credential_reference_ids"]) > 64
                or any(not _is_credential_reference(value) for value in backend["credential_reference_ids"])
                or len(set(backend["credential_reference_ids"])) != len(backend["credential_reference_ids"])
                or type(backend["maximum_request_bytes"]) is not int
                or not 1 <= backend["maximum_request_bytes"] <= 256 * 1024
                or type(backend["maximum_response_bytes"]) is not int
                or not 1 <= backend["maximum_response_bytes"] <= 2 * 1024 * 1024
                or type(backend["maximum_seconds"]) is not int
                or not 1 <= backend["maximum_seconds"] <= 600):
            raise AuthorityDenied("enrollment.generation", "protected resource backend bounds are invalid")
        for action in backend["approved_action_ids"]:
            _read_id(action, "resource backend action ID")
        credential_bindings = backend["credential_bindings"]
        if (not isinstance(credential_bindings, list) or len(credential_bindings) > 16
                or any(not isinstance(binding, dict) for binding in credential_bindings)):
            raise AuthorityDenied("enrollment.generation", "resource backend credential bindings are malformed")
        placeholders: set[str] = set()
        allowed_usage = {"webhook-hmac-verify", "channel-account", "backend-account"}
        allowed_refs = set(backend["credential_reference_ids"])
        for raw_binding in credential_bindings:
            binding = _exact(raw_binding, {"source_placeholder", "credential_reference_id", "usage"},
                             "resource credential binding")
            placeholder = _read_id(binding["source_placeholder"], "resource credential placeholder")
            reference, usage = binding["credential_reference_id"], binding["usage"]
            if (placeholder in placeholders or not _is_credential_reference(reference)
                    or reference not in allowed_refs or usage not in allowed_usage):
                raise AuthorityDenied("enrollment.generation", "resource credential binding is invalid")
            placeholders.add(placeholder)
        if backend["recipient"] is not None:
            _read_id(backend["recipient"], "resource backend recipient")
        execution = backend["execution_binding"]
        if execution is not None:
            execution_fields = {
                "process_enrollment_id", "process_generation", "operation_id",
                "native_package_id", "native_package_generation", "child_operation",
                "child_target_id", "child_capability", "task_body_recipe_id",
                "task_request_schema_id",
            }
            selected = _exact(execution, execution_fields, "resource profile execution binding")
            for field in execution_fields:
                _read_id(selected[field], f"resource execution {field}")
    body_rows = item["resource_body_recipes"]
    if (not isinstance(body_rows, list) or len(body_rows) > 4096
            or any(not isinstance(row, dict) for row in body_rows)):
        raise AuthorityDenied("enrollment.generation", "protected resource body recipe catalog is invalid")
    body_fields = {"id", "schema_id", "source_artifact_id", "source_sha256",
                   "output_fields", "scope_bindings", "maximum_bytes"}
    seen_body_ids: set[str] = set()
    for row in body_rows:
        body = _exact(row, body_fields, "resource body recipe")
        body_id = _read_id(body["id"], "resource body recipe ID")
        if body_id in seen_body_ids:
            raise AuthorityDenied("enrollment.generation", "resource body recipe is duplicated")
        seen_body_ids.add(body_id)
        for name in ("schema_id", "source_artifact_id"):
            _read_id(body[name], f"resource body recipe {name}")
        if (not isinstance(body["source_sha256"], str)
                or not re.fullmatch(r"[0-9a-f]{64}", body["source_sha256"])
                or type(body["maximum_bytes"]) is not int
                or not 1 <= body["maximum_bytes"] <= 256 * 1024
                or not isinstance(body["output_fields"], list)
                or not 1 <= len(body["output_fields"]) <= 64
                or not isinstance(body["scope_bindings"], list)
                or len(body["scope_bindings"]) > 64):
            raise AuthorityDenied("enrollment.generation", "protected resource body recipe is malformed")
        output_names: set[str] = set()
        for output in body["output_fields"]:
            item_output = _exact(output, {"name", "source", "value", "validator_id"},
                                 "resource body recipe output")
            name = _read_id(item_output["name"], "resource body field name")
            if (name in output_names or item_output["source"] not in {
                    "literal", "observed-event-field", "owned-parent-result-field"}):
                raise AuthorityDenied("enrollment.generation", "resource body recipe output is invalid")
            _read_id(item_output["validator_id"], "resource body validator ID")
            output_names.add(name)
        body_scope_names: set[str] = set()
        for raw_scope in body["scope_bindings"]:
            body_scope = _exact(raw_scope, {"name", "scope_binding_id", "field", "validator_id"},
                                "resource body scope output")
            scope_name = _read_id(body_scope["name"], "resource body scope name")
            if scope_name in body_scope_names:
                raise AuthorityDenied("enrollment.generation", "resource body scope output is duplicated")
            body_scope_names.add(scope_name)
            for name in ("scope_binding_id", "field", "validator_id"):
                _read_id(body_scope[name], f"resource body scope {name}")
    scope_rows = item["resource_scope_bindings"]
    if (not isinstance(scope_rows, list) or len(scope_rows) > 4096
            or any(not isinstance(row, dict) for row in scope_rows)):
        raise AuthorityDenied("enrollment.generation", "protected resource scope catalog is invalid")
    scope_fields = {"id", "resource_id", "profile_id", "principal_id", "resource_generation",
                    "profile_generation", "backend_enrollment_id", "fixed_fields",
                    "credential_reference_ids", "recipient"}
    seen_scope_ids: set[str] = set()
    for row in scope_rows:
        scope = _exact(row, scope_fields, "resource scope binding")
        scope_id = _read_id(scope["id"], "resource scope binding ID")
        if scope_id in seen_scope_ids:
            raise AuthorityDenied("enrollment.generation", "resource scope binding is duplicated")
        seen_scope_ids.add(scope_id)
        for field in ("resource_id", "profile_id", "principal_id", "resource_generation",
                      "profile_generation", "backend_enrollment_id"):
            _read_id(scope[field], f"resource scope {field}")
        fixed_fields = scope["fixed_fields"]
        if not isinstance(fixed_fields, dict) or len(fixed_fields) > 64:
            raise AuthorityDenied("enrollment.generation", "resource fixed scope fields are invalid")
        for field_name, value in fixed_fields.items():
            _read_id(field_name, "resource fixed scope field")
            if not (value is None or type(value) in {str, int, bool}):
                raise AuthorityDenied("enrollment.generation", "resource fixed scope value is not scalar")
        refs = scope["credential_reference_ids"]
        if (not isinstance(refs, list) or len(refs) > 64
                or any(not _is_credential_reference(ref) for ref in refs)
                or len(refs) != len(set(refs))):
            raise AuthorityDenied("enrollment.generation", "resource scope credentials are malformed")
        if scope["recipient"] is not None:
            _read_id(scope["recipient"], "resource scope recipient")
    validator_rows = item["resource_validators"]
    if (not isinstance(validator_rows, list) or len(validator_rows) > 4096
            or any(not isinstance(row, dict) for row in validator_rows)):
        raise AuthorityDenied("enrollment.generation", "protected resource validator catalog is invalid")
    validator_fields = {"id", "kind", "maximum_bytes", "minimum", "maximum",
                        "allowed_values", "schema_artifact_id", "schema_sha256"}
    validator_kinds = {"utf8-string", "opaque-id", "integer", "boolean", "enum", "bounded-json"}
    seen_validator_ids: set[str] = set()
    for row in validator_rows:
        validator = _exact(row, validator_fields, "resource validator")
        validator_id = _read_id(validator["id"], "resource validator ID")
        if validator_id in seen_validator_ids:
            raise AuthorityDenied("enrollment.generation", "resource validator is duplicated")
        seen_validator_ids.add(validator_id)
        kind, maximum_bytes = validator["kind"], validator["maximum_bytes"]
        minimum, maximum = validator["minimum"], validator["maximum"]
        if (not isinstance(kind, str) or kind not in validator_kinds
                or type(maximum_bytes) is not int
                or not 1 <= maximum_bytes <= 262144
                or (minimum is not None and type(minimum) is not int)
                or (maximum is not None and type(maximum) is not int)
                or (minimum is not None and maximum is not None and minimum > maximum)):
            raise AuthorityDenied("enrollment.generation", "resource validator bounds are malformed")
        allowed = validator["allowed_values"]
        if (allowed is not None and (not isinstance(allowed, list) or len(allowed) > 128
                                     or any(value is not None and type(value) not in {str, int, bool}
                                            for value in allowed)
                                     or len({json.dumps(value, sort_keys=True) for value in allowed})
                                     != len(allowed))):
            raise AuthorityDenied("enrollment.generation", "resource validator enum values are malformed")
        if (kind == "enum" and (not isinstance(allowed, list) or not allowed)
                or kind != "enum" and allowed is not None):
            raise AuthorityDenied("enrollment.generation", "resource validator enum binding is malformed")
        schema_id, schema_sha = validator["schema_artifact_id"], validator["schema_sha256"]
        if kind == "bounded-json":
            _read_id(schema_id, "resource validator schema artifact")
            if not isinstance(schema_sha, str) or not re.fullmatch(r"[0-9a-f]{64}", schema_sha):
                raise AuthorityDenied("enrollment.generation", "resource validator schema pin is malformed")
        elif schema_id is not None or schema_sha is not None:
            raise AuthorityDenied("enrollment.generation", "non-JSON resource validator has a schema pin")
    journal_rows = item["root_journal_roots"]
    if (not isinstance(journal_rows, list) or len(journal_rows) > 1024
            or any(not isinstance(row, dict) for row in journal_rows)):
        raise AuthorityDenied("enrollment.generation", "protected root journal catalog is invalid")
    journal_fields = {"root_id", "absolute_path", "owner_uid", "owner_gid", "mode",
                      "device", "inode", "generation", "purpose"}
    seen_journal_ids: set[str] = set()
    for row in journal_rows:
        journal = _exact(row, journal_fields, "root journal root")
        root_id = _read_id(journal["root_id"], "root journal ID")
        if root_id in seen_journal_ids:
            raise AuthorityDenied("enrollment.generation", "root journal ID is duplicated")
        seen_journal_ids.add(root_id)
        path = journal["absolute_path"]
        numbers = (journal["owner_uid"], journal["owner_gid"], journal["mode"],
                   journal["device"], journal["inode"])
        if (not isinstance(path, str) or not Path(path).is_absolute() or "\x00" in path
                or any(type(value) is not int for value in numbers)
                or journal["owner_uid"] != 0 or journal["owner_gid"] != 0
                or journal["mode"] != 0o700 or journal["device"] < 0 or journal["inode"] <= 0
                or journal["purpose"] != "authority-journal"):
            raise AuthorityDenied("enrollment.generation", "root journal identity or purpose is malformed")
        _read_id(journal["generation"], "root journal generation")
    selected_rows = item["selected_resource_executions"]
    if (not isinstance(selected_rows, list) or len(selected_rows) > 692
            or any(not isinstance(row, dict) for row in selected_rows)):
        raise AuthorityDenied("enrollment.generation", "protected selected resource execution catalog is invalid")
    selected_fields = {
        "resource_id", "resource_kind", "source_revision", "source_manifest_sha256",
        "resource_generation", "profile_id", "profile_generation",
        "materialization_receipt_handle", "materialized_member_path", "materialized_member_sha256",
        "materialized_member_size_bytes", "effective_spec_sha256", "backend_enrollment_id",
        "operation", "capability", "target_id", "recipient", "delegation_id", "enabled",
    }
    backend_by_id = {row["id"]: row for row in backend_rows}
    services_by_profile_generation = {
        (row.get("profile_id"), row.get("generation")): row for row in item["service_records"]
    }
    selected_keys: set[tuple[str, str, str]] = set()
    materialization_handles: set[str] = set()
    resource_kinds = {"profiles", "skills", "plugins", "mcps", "bundles", "channels", "crons", "webhooks"}
    operations_by_kind = {
        "bundles": "resource.orchestrator.recruit", "channels": "resource.channel.route",
        "crons": "resource.cron.run", "webhooks": "resource.webhook.deliver",
    }
    for raw in selected_rows:
        selected = _exact(raw, selected_fields, "selected resource execution")
        resource_id = _read_id(selected["resource_id"], "selected resource ID")
        kind = selected["resource_kind"]
        if kind not in resource_kinds:
            raise AuthorityDenied("enrollment.generation", "selected resource kind is unsupported")
        revision, manifest_sha = selected["source_revision"], selected["source_manifest_sha256"]
        if (not isinstance(revision, str) or not re.fullmatch(r"[0-9a-f]{40,64}", revision)
                or not isinstance(manifest_sha, str) or not re.fullmatch(r"[0-9a-f]{64}", manifest_sha)):
            raise AuthorityDenied("enrollment.generation", "selected resource source pin is malformed")
        resource_generation = selected["resource_generation"]
        profile_id = _read_id(selected["profile_id"], "selected resource profile")
        profile_generation = _read_id(selected["profile_generation"], "selected resource profile generation")
        if not isinstance(resource_generation, str) or not re.fullmatch(r"[0-9a-f]{64}", resource_generation):
            raise AuthorityDenied("enrollment.generation", "selected resource generation digest is malformed")
        key = (resource_id, resource_generation, profile_id)
        if key in selected_keys:
            raise AuthorityDenied("enrollment.generation", "selected resource execution is duplicated")
        selected_keys.add(key)
        receipt = _read_id(selected["materialization_receipt_handle"], "native materialization receipt handle")
        if receipt in materialization_handles:
            raise AuthorityDenied("enrollment.generation", "native materialization receipt is reused")
        materialization_handles.add(receipt)
        member_path = selected["materialized_member_path"]
        if (not isinstance(member_path, str) or not member_path or len(member_path) > 512
                or "\\" in member_path or member_path.startswith("/") or "\x00" in member_path
                or any(part in {"", ".", ".."} for part in member_path.split("/"))
                or not member_path.endswith((".yaml", ".yml"))):
            raise AuthorityDenied("enrollment.generation", "selected resource materialized member path is invalid")
        for field in ("materialized_member_sha256", "effective_spec_sha256"):
            if not isinstance(selected[field], str) or not re.fullmatch(r"[0-9a-f]{64}", selected[field]):
                raise AuthorityDenied("enrollment.generation", "selected resource materialization digest is malformed")
        size = selected["materialized_member_size_bytes"]
        if type(size) is not int or not 1 <= size <= 1024 * 1024:
            raise AuthorityDenied("enrollment.generation", "selected resource materialized member size is invalid")
        backend_id = _read_id(selected["backend_enrollment_id"], "selected resource backend")
        operation = _read_id(selected["operation"], "selected resource operation")
        capability = _read_id(selected["capability"], "selected resource capability")
        target_id = _read_id(selected["target_id"], "selected resource target")
        recipient = selected["recipient"]
        delegation = selected["delegation_id"]
        if recipient is not None:
            _read_id(recipient, "selected resource recipient")
        if delegation is not None:
            _read_id(delegation, "selected resource delegation")
        if type(selected["enabled"]) is not bool:
            raise AuthorityDenied("enrollment.generation", "selected resource enabled state is not boolean")
        if kind in operations_by_kind and operation != operations_by_kind[kind]:
            raise AuthorityDenied("enrollment.generation", "selected resource operation does not match its kind")
        service = services_by_profile_generation.get((profile_id, profile_generation))
        backend = backend_by_id.get(backend_id)
        if (service is None or backend is None
                or backend.get("profile_id") != profile_id
                or backend.get("profile_generation") != profile_generation
                or backend.get("resource_id") != resource_id
                or backend.get("generation") != resource_generation
                or backend.get("operation") != operation or backend.get("target_id") != target_id
                or backend.get("recipient") != recipient
                or backend.get("principal_id") != service.get("principal_id")):
            raise AuthorityDenied("enrollment.generation", "selected resource execution does not join its service/backend")
    application_rows = item["selected_application_runtimes"]
    if (not isinstance(application_rows, list) or len(application_rows) > 256
            or any(not isinstance(row, dict) for row in application_rows)):
        raise AuthorityDenied("enrollment.generation", "selected application runtime catalog is invalid")
    application_fields = {
        "application_id", "profile_id", "profile_generation", "principal_id", "adapter_id",
        "source_identity", "source_revision", "source_tree_sha256", "source_generation_receipt_handle",
        "source_generation_manifest_sha256", "runtime_id", "runtime_receipt_handle",
        "runtime_manifest_sha256", "lock_sha256", "work_root_id", "data_root_id", "operation_id",
        "process_start_target", "request_schema_id", "request_schema_sha256", "result_schema_id",
        "result_validator_artifact_id", "result_validator_sha256", "capability_ids", "provider_route_ids",
        "credential_reference_ids", "account_eligibility_receipt_handle", "memory_owner_generation",
        "max_lifetime_seconds", "max_memory_bytes", "max_workers", "metered_budget_usd", "enabled",
    }
    selected_application_ids: set[tuple[str, str]] = set()
    for raw in application_rows:
        selected = _exact(raw, application_fields, "selected application runtime")
        application_id = _read_id(selected["application_id"], "selected application ID")
        profile_id = _read_id(selected["profile_id"], "selected application profile")
        profile_generation = _read_id(selected["profile_generation"], "selected application generation")
        key = (application_id, profile_id)
        if key in selected_application_ids:
            raise AuthorityDenied("enrollment.generation", "selected application runtime is duplicated")
        selected_application_ids.add(key)
        for name in ("principal_id", "adapter_id", "source_generation_receipt_handle",
                     "runtime_id", "runtime_receipt_handle", "work_root_id", "data_root_id",
                     "operation_id", "process_start_target", "request_schema_id", "result_schema_id",
                     "result_validator_artifact_id"):
            _read_id(selected[name], f"selected application {name}")
        source_identity = selected["source_identity"]
        if (not isinstance(source_identity, str) or not source_identity or len(source_identity) > 1024
                or any(ord(char) < 0x20 for char in source_identity)):
            raise AuthorityDenied("enrollment.generation", "selected application source identity is malformed")
        if (not isinstance(selected["source_revision"], str)
                or not re.fullmatch(r"[0-9a-f]{40,64}", selected["source_revision"])):
            raise AuthorityDenied("enrollment.generation", "selected application source revision is malformed")
        for name in ("source_tree_sha256", "source_generation_manifest_sha256", "runtime_manifest_sha256",
                     "lock_sha256", "request_schema_sha256", "result_validator_sha256"):
            if not isinstance(selected[name], str) or not re.fullmatch(r"[0-9a-f]{64}", selected[name]):
                raise AuthorityDenied("enrollment.generation", f"selected application {name} is malformed")
        for name in ("capability_ids", "provider_route_ids", "credential_reference_ids"):
            values = selected[name]
            if (not isinstance(values, list) or len(values) > 64
                    or any(not isinstance(value, str) for value in values)
                    or len(set(values)) != len(values)):
                raise AuthorityDenied("enrollment.generation", f"selected application {name} is malformed")
            for value in values:
                if name == "credential_reference_ids":
                    if not _is_credential_reference(value):
                        raise AuthorityDenied("enrollment.generation", "selected application credential reference is invalid")
                else:
                    _read_id(value, f"selected application {name} item")
        account_receipt = selected["account_eligibility_receipt_handle"]
        if account_receipt is not None:
            _read_id(account_receipt, "selected application account eligibility receipt")
        owner_generation = selected["memory_owner_generation"]
        if owner_generation is not None and (type(owner_generation) is not int or owner_generation <= 0):
            raise AuthorityDenied("enrollment.generation", "selected application memory owner generation is invalid")
        lifetime, memory_bytes, workers = (selected["max_lifetime_seconds"], selected["max_memory_bytes"],
                                           selected["max_workers"])
        # Serialization bounds are not authorization. The effective limit is
        # intersected with the selected service profile at resolution time.
        if (type(lifetime) is not int or not 1 <= lifetime <= (1 << 63) - 1
                or type(memory_bytes) is not int or not 1 <= memory_bytes <= (1 << 63) - 1
                or type(workers) is not int or workers != 1):
            raise AuthorityDenied("enrollment.generation", "selected application runtime bounds are invalid")
        budget = selected["metered_budget_usd"]
        if type(budget) not in {int, float} or budget != 0:
            raise AuthorityDenied("enrollment.generation", "selected application metered budget is invalid")
        if type(selected["enabled"]) is not bool:
            raise AuthorityDenied("enrollment.generation", "selected application enabled state is not boolean")
        service = services_by_profile_generation.get((profile_id, profile_generation))
        if (service is None or service.get("principal_id") != selected["principal_id"]
                or service.get("roots", {}).get("work_id") != selected["work_root_id"]
                or service.get("roots", {}).get("data_id") != selected["data_root_id"]
                or selected["process_start_target"] != service.get("operation_targets", {}).get("process.start")
                or selected["operation_id"] not in service.get("operation_recipes", {})):
            raise AuthorityDenied("enrollment.generation", "selected application runtime does not join its service profile")
    # Parse the exact active source-issuer schema here, after verifying the
    # digest, so callers cannot fall back to an unsigned sidecar catalog.
    _parse_source_issuers(item["source_issuers"])
    return item


def _verify_active_process_rules(service_profiles: Mapping[str, Any],
                                authority_profiles: Mapping[str, Any],
                                bindings: Mapping[int, Any],
                                rules: Mapping[tuple[str, str, str], Any]) -> None:
    """Require one exact authority rule for every root-registered process verb."""
    if set(service_profiles) != set(authority_profiles):
        raise ValueError("active service generations and authority process profiles differ")
    binding_by_profile: dict[str, Any] = {}
    for binding in bindings.values():
        if binding.profile_id in binding_by_profile:
            raise ValueError("authority process profile principal is duplicated")
        binding_by_profile[binding.profile_id] = binding
    process_operations = (
        ("hermes-profile-invoke", "process.start"),
        ("hermes-process-control", "process.status"),
        ("hermes-process-control", "process.read"),
        ("hermes-process-control", "process.write"),
        ("hermes-process-control", "process.stop"),
        ("hermes-process-control", "process.inspect"),
    )
    seen_targets: set[tuple[str, str]] = set()
    for profile_id, service in service_profiles.items():
        authority_profile = authority_profiles[profile_id]
        binding = binding_by_profile.get(profile_id)
        if (authority_profile.owner_uid != service.service_uid
                or authority_profile.owner_gid != service.service_gid
                or authority_profile.generation != service.generation
                or binding is None or binding.principal_id != service.principal_id
                or binding.profile_id != service.profile_id
                or binding.namespace_id != service.namespace_identity
                or binding.uid != service.service_uid):
            raise ValueError("service generation does not join its authority process identity")
        for capability, operation in process_operations:
            target = service.operation_targets.get(operation)
            if not isinstance(target, str) or not target:
                raise ValueError("active service generation omits a registered process target")
            handler_key = (operation, target)
            if handler_key in seen_targets:
                raise ValueError("managed process target is duplicated")
            seen_targets.add(handler_key)
            rule = rules.get((capability, operation, target))
            if (rule is None or rule.operation != operation or rule.recipient is not None
                    or capability not in binding.capabilities):
                raise ValueError("managed process handler has no exact authority rule")


def load_protected_enrollment(path: Path = AUTHORITY_CONFIG_PATH, *,
                              vault: RootCredentialVault | None = None,
                              expected_uid: int = 0) -> ProtectedEnrollment:
    if path != AUTHORITY_CONFIG_PATH or expected_uid != 0:
        raise ValueError("authority configuration path and owner are fixed")
    vault = vault or RootCredentialVault(expected_uid=expected_uid)
    try:
        value = json.loads(read_protected_file(path, expected_uid=expected_uid).decode("utf-8"),
                           object_pairs_hook=_unique_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise AuthorityDenied("enrollment.schema", "protected authority configuration is malformed") from None
    root = _exact(value, {"schema", "key_id", "principals", "rules", "authentik", "process_profiles", "provider_enrollments", "mcp_services", "mcp_http_bindings", "memory_providers", "native_bridges", "normalization_policies", "delegations", "service_generations"}, "authority")
    _reject_secret_material(root)
    if type(root["schema"]) is not int or root["schema"] != 1:
        raise AuthorityDenied("enrollment.schema", "protected authority schema version is unsupported")
    service_generations = _validate_service_generations(root["service_generations"])
    key_id = _read_id(root["key_id"], "key_id")
    if not isinstance(root["principals"], list) or not root["principals"] or len(root["principals"]) > 256:
        raise AuthorityDenied("enrollment.schema", "protected principal catalog is invalid")
    bindings: dict[int, PrincipalBinding] = {}
    profiles_seen: set[str] = set()
    identities: dict[str, PrincipalIdentity] = {}
    actor_refs: dict[str, str] = {}
    uid_by_principal: dict[str, int] = {}
    for raw in root["principals"]:
        item = _exact(raw, {"uid", "principal_id", "profile_id", "namespace_id", "capabilities", "username", "email", "authentik_subject_id", "actor_credential_ref"}, "principal")
        uid = item["uid"]
        if type(uid) is not int or uid <= 0 or uid in bindings:
            raise AuthorityDenied("enrollment.principal", "protected principal UID is invalid or duplicated")
        principal_id = _read_id(item["principal_id"], "principal ID")
        if principal_id in identities:
            raise AuthorityDenied("enrollment.principal", "protected principal identity is duplicated")
        caps = item["capabilities"]
        if not isinstance(caps, list) or not caps or len(caps) > 256 or any(not isinstance(cap, str) for cap in caps) or len(set(caps)) != len(caps):
            raise AuthorityDenied("enrollment.principal", "protected capability set is invalid")
        binding = PrincipalBinding(uid, principal_id,
                                   _read_id(item["profile_id"], "profile ID"),
                                   _read_id(item["namespace_id"], "namespace ID"),
                                   frozenset(caps))
        if binding.profile_id in profiles_seen:
            raise AuthorityDenied("enrollment.principal", "each managed profile has one protected principal UID")
        profiles_seen.add(binding.profile_id)
        bindings[uid] = binding
        try:
            identities[principal_id] = PrincipalIdentity(
                _read_id(item["username"], "Authentik username"),
                _read_id(item["email"], "Authentik email"),
                _read_id(item["authentik_subject_id"], "Authentik subject ID"),
            )
        except (TypeError, ValueError):
            raise AuthorityDenied("enrollment.principal", "protected Authentik identity is malformed") from None
        actor_refs[principal_id] = _read_id(item["actor_credential_ref"], "actor credential reference")
        uid_by_principal[principal_id] = uid
    if not isinstance(root["rules"], list) or not root["rules"] or len(root["rules"]) > 4096:
        raise AuthorityDenied("enrollment.schema", "protected effect rule catalog is invalid")
    rules: dict[tuple[str, str, str], EffectRule] = {}
    for raw in root["rules"]:
        item = _exact(raw, {"capability", "operation", "target", "recipient"}, "effect rule")
        capability = _read_id(item["capability"], "capability")
        target = _read_id(item["target"], "effect target")
        rule = EffectRule(capability, _read_id(item["operation"], "operation"), target,
                          None if item["recipient"] is None else _read_id(item["recipient"], "recipient"))
        key = (capability, rule.operation, target)
        if key in rules:
            raise AuthorityDenied("enrollment.rule", "protected effect rule is duplicated")
        rules[key] = rule
    auth = _exact(root["authentik"], {"base_url", "system_group_id", "write_group_by_target", "recipient_group_id", "recipient_email_by_id", "allowed_effects", "public_profile_purposes", "max_sensitivity_by_capability", "directory_credential_ref", "policy_revision"}, "Authentik policy")
    write_groups = auth["write_group_by_target"]
    emails = auth["recipient_email_by_id"]
    maxima = auth["max_sensitivity_by_capability"]
    if (not isinstance(write_groups, dict) or not isinstance(emails, dict)
            or not isinstance(maxima, dict) or not isinstance(auth["allowed_effects"], list)
            or not isinstance(auth["public_profile_purposes"], list)):
        raise AuthorityDenied("enrollment.authentik", "protected Authentik policy fields are malformed")
    allowed: set[tuple[str, str]] = set()
    for pair in auth["allowed_effects"]:
        if not isinstance(pair, list) or len(pair) != 2:
            raise AuthorityDenied("enrollment.authentik", "protected Authentik effect allowlist is malformed")
        parsed_pair = (_read_id(pair[0], "capability"), _read_id(pair[1], "effect target"))
        if parsed_pair in allowed:
            raise AuthorityDenied("enrollment.authentik", "protected Authentik effect is duplicated")
        allowed.add(parsed_pair)
    public: set[tuple[str, str]] = set()
    for pair in auth["public_profile_purposes"]:
        if not isinstance(pair, list) or len(pair) != 2:
            raise AuthorityDenied("enrollment.authentik", "protected public purpose rule is malformed")
        parsed_pair = (_read_id(pair[0], "profile ID"), _read_id(pair[1], "purpose"))
        if parsed_pair in public:
            raise AuthorityDenied("enrollment.authentik", "protected public purpose rule is duplicated")
        public.add(parsed_pair)
    if public:
        raise AuthorityDenied("enrollment.public-policy", "purpose labels cannot enroll public-data declassification")
    try:
        max_sensitivity = { _read_id(cap, "capability"): Sensitivity(value)
                           for cap, value in maxima.items() }
    except (ValueError, TypeError):
        raise AuthorityDenied("enrollment.authentik", "sensitivity ceiling is invalid") from None
    try:
        enrollment = AuthentikEnrollment(
            principal_identities=identities,
            system_group_id=_read_id(auth["system_group_id"], "System group ID"),
            write_group_by_target={_read_id(k, "target"): _read_id(v, "group ID") for k, v in write_groups.items()},
            recipient_group_id=_read_id(auth["recipient_group_id"], "recipient group ID"),
            recipient_email_by_id={_read_id(k, "recipient ID"): _read_id(v, "recipient email") for k, v in emails.items()},
            allowed_effects=frozenset(allowed), public_profile_purposes=frozenset(public),
            max_sensitivity_by_capability=max_sensitivity,
            policy_revision=_read_id(auth["policy_revision"], "policy revision"),
        )
        policy = AuthentikSystemPolicy(
            enrollment=enrollment,
            actor_token=lambda principal: vault.resolve_reference(
                actor_refs[principal], peer_uid=uid_by_principal[principal], required_scope="authentik-system-read",
                principal_id=principal) if principal in actor_refs else None,
            directory_token=lambda: vault.resolve_reference(
                _read_id(auth["directory_credential_ref"], "directory credential reference"),
                peer_uid=0, required_scope="authentik-directory-read",
                principal_id="authority:directory"),
            transport=TLSAuthentikTransport(auth["base_url"]),
        )
    except (TypeError, ValueError):
        raise AuthorityDenied("enrollment.authentik", "protected Authentik transport enrollment is invalid") from None
    for (cap, _operation, _target), rule in rules.items():
        if (cap, rule.target) not in enrollment.allowed_effects:
            raise AuthorityDenied("enrollment.rule", "effect rule is outside Authentik protected allowlist")
    if not isinstance(root["delegations"], list) or len(root["delegations"]) > 512:
        raise AuthorityDenied("enrollment.delegation", "protected delegation catalog is invalid")
    delegations: dict[str, ChildDelegationRule] = {}
    profiles_by_id = {binding.profile_id: binding for binding in bindings.values()}
    for raw in root["delegations"]:
        item = _exact(raw, {"id", "parent_profile_id", "parent_capability", "parent_operation",
                            "parent_target", "child_profile_id", "child_capability", "child_operation",
                            "child_target", "child_recipient", "child_purpose"}, "child delegation")
        rule = ChildDelegationRule(
            delegation_id=_read_id(item["id"], "delegation ID"),
            parent_profile_id=_read_id(item["parent_profile_id"], "parent profile ID"),
            parent_capability=_read_id(item["parent_capability"], "parent capability"),
            parent_operation=_read_id(item["parent_operation"], "parent operation"),
            parent_target=_read_id(item["parent_target"], "parent target"),
            child_profile_id=_read_id(item["child_profile_id"], "child profile ID"),
            child_capability=_read_id(item["child_capability"], "child capability"),
            child_operation=_read_id(item["child_operation"], "child operation"),
            child_target=_read_id(item["child_target"], "child target"),
            child_recipient=None if item["child_recipient"] is None else _read_id(item["child_recipient"], "child recipient"),
            child_purpose=_read_id(item["child_purpose"], "child purpose"),
        )
        parent_binding = profiles_by_id.get(rule.parent_profile_id)
        child_binding = profiles_by_id.get(rule.child_profile_id)
        parent_rule = rules.get((rule.parent_capability, rule.parent_operation, rule.parent_target))
        child_rule = rules.get((rule.child_capability, rule.child_operation, rule.child_target))
        if (rule.delegation_id in delegations or parent_binding is None or child_binding is None
                or rule.parent_capability not in parent_binding.capabilities
                or rule.child_capability not in child_binding.capabilities
                or parent_rule is None or parent_rule.operation != rule.parent_operation
                or child_rule is None or child_rule.operation != rule.child_operation
                or child_rule.recipient != rule.child_recipient):
            raise AuthorityDenied("enrollment.delegation", "child delegation is outside protected principal/effect rules")
        delegations[rule.delegation_id] = rule
    profiles = root["process_profiles"]
    if not isinstance(profiles, list) or len(profiles) > 256:
        raise AuthorityDenied("enrollment.process", "protected process profile catalog is invalid")
    process_profiles: dict[str, Any] = {}
    for raw in profiles:
        from hermes_installer.managed_process_custodian import ManagedProfileCustody
        item = _exact(raw, {"profile_id", "owner_uid", "owner_gid", "service_user", "executable", "artifact_sha256", "artifact_root", "data_root", "generation", "memory_max_bytes", "cpu_quota_percent", "io_weight", "max_lifetime_seconds", "child_artifact_refs", "argv_recipe"}, "process profile")
        profile_id = _read_id(item["profile_id"], "process profile ID")
        if profile_id in process_profiles:
            raise AuthorityDenied("enrollment.process", "process profile is duplicated")
        recipe = item["argv_recipe"]
        if (not isinstance(recipe, list) or not recipe or len(recipe) > 64
                or any(not isinstance(arg, str) or len(arg) > 4096 or "\x00" in arg for arg in recipe)):
            raise AuthorityDenied("enrollment.process", "protected argv recipe is malformed")
        process_profiles[profile_id] = ManagedProfileCustody(
            profile_id=profile_id, owner_uid=item["owner_uid"], owner_gid=item["owner_gid"],
            service_user=_read_id(item["service_user"], "service user"),
            executable=Path(_read_id(item["executable"], "executable path")),
            artifact_sha256=item["artifact_sha256"],
            artifact_root=Path(_read_id(item["artifact_root"], "artifact root")),
            data_root=Path(_read_id(item["data_root"], "data root")),
            generation=_read_id(item["generation"], "generation"),
            memory_max_bytes=item["memory_max_bytes"], cpu_quota_percent=item["cpu_quota_percent"],
            io_weight=item["io_weight"], max_lifetime_seconds=item["max_lifetime_seconds"],
            child_artifact_refs=item["child_artifact_refs"],
            argv_recipe=tuple(recipe),
            authority_socket=Path(f"/run/hermes-installer/authority/{item['owner_uid']}.sock"),
        )
    if (not process_profiles or any(binding.profile_id not in process_profiles
                                    or process_profiles[binding.profile_id].owner_uid != uid
                                    for uid, binding in bindings.items())):
        raise AuthorityDenied("enrollment.principal", "each socket principal must map to its exact managed profile UID")
    primary_gids = [process_profiles[binding.profile_id].owner_gid for binding in bindings.values()]
    if len(primary_gids) != len(set(primary_gids)) or any(type(gid) is not int or gid <= 0 for gid in primary_gids):
        raise AuthorityDenied("enrollment.principal", "socket principals require unique protected primary groups")
    catalogs = {}
    for field in ("provider_enrollments", "mcp_services", "memory_providers"):
        entries = root[field]
        if not isinstance(entries, list) or len(entries) > 4096:
            raise AuthorityDenied("enrollment.catalog", f"protected {field} catalog is invalid")
        index: dict[str, Any] = {}
        for entry in entries:
            if not isinstance(entry, dict) or "id" not in entry:
                raise AuthorityDenied("enrollment.catalog", f"protected {field} entry is invalid")
            entry_id = _read_id(entry["id"], f"{field} entry ID")
            if entry_id in index:
                raise AuthorityDenied("enrollment.catalog", f"protected {field} entry is duplicated")
            index[entry_id] = dict(entry)
        catalogs[field] = index
    for raw in catalogs["provider_enrollments"].values():
        item = _exact(raw, {"id", "provider", "account_id", "principal_id", "target", "recipient",
                            "credential_ref", "credential_scope", "models", "allowed_sensitivities",
                            "additional_metered_fee_usd"}, "provider enrollment")
        if (not _is_credential_reference(item["credential_ref"])
                or not isinstance(item["models"], list) or not item["models"]
                or len(item["models"]) != len(set(item["models"]))
                or any(not isinstance(model, str) or not model for model in item["models"])
                or not isinstance(item["allowed_sensitivities"], list)
                or not item["allowed_sensitivities"]
                or len(item["allowed_sensitivities"]) != len(set(item["allowed_sensitivities"]))
                or any(value not in {s.value for s in Sensitivity} for value in item["allowed_sensitivities"])
                or not isinstance(item["additional_metered_fee_usd"], (int, float))
                or isinstance(item["additional_metered_fee_usd"], bool)
                or item["additional_metered_fee_usd"] < 0):
            raise AuthorityDenied("enrollment.provider", "provider enrollment lacks a precise protected route binding")
    # HI11 root role pairing. The producer and gateway are selected only from
    # protected process/principal records; worker payloads never name either.
    raw_bridges = root["native_bridges"]
    if not isinstance(raw_bridges, list) or len(raw_bridges) > 128:
        raise AuthorityDenied("enrollment.native_bridge", "protected native bridge catalog is invalid")
    native_bridges: dict[str, Any] = {}
    bridge_pairs: set[tuple[str, str]] = set()
    binding_by_profile = {binding.profile_id: binding for binding in bindings.values()}
    for raw in raw_bridges:
        item = _exact(raw, {"id", "producer_profile_id", "gateway_profile_id",
                            "canonicalizer_artifact_id", "canonicalizer_sha256",
                            "normalization_policy_id", "normalization_policy_sha256",
                            "normalization_policy_revision", "route_schema_id",
                            "output_limit_mode", "output_limit_ceiling",
                            "approved_operation", "observer_delivery_bindings"}, "native bridge")
        bridge_id = _read_id(item["id"], "native bridge ID")
        producer_id = _read_id(item["producer_profile_id"], "native producer profile")
        gateway_id = _read_id(item["gateway_profile_id"], "native gateway profile")
        canonicalizer_id = _read_id(item["canonicalizer_artifact_id"], "native canonicalizer artifact")
        canonicalizer_sha = item["canonicalizer_sha256"]
        policy_id = _read_id(item["normalization_policy_id"], "normalization policy ID")
        policy_sha = item["normalization_policy_sha256"]
        policy_revision = item["normalization_policy_revision"]
        route_schema_id = _read_id(item["route_schema_id"], "provider route schema")
        limit_mode = item["output_limit_mode"]
        output_ceiling = item["output_limit_ceiling"]
        pair = (producer_id, gateway_id)
        producer = process_profiles.get(producer_id)
        gateway = process_profiles.get(gateway_id)
        producer_binding = binding_by_profile.get(producer_id)
        gateway_binding = binding_by_profile.get(gateway_id)
        if (bridge_id in native_bridges or pair in bridge_pairs or producer_id == gateway_id
                or item["approved_operation"] != "provider.dispatch"
                or canonicalizer_id != "provider-canonicalizer-v1"
                or canonicalizer_sha != "8539e50998ca68e1075030c021a5cb9d698fb2b01b50806f7218d8d1d1a50a52"
                or not isinstance(canonicalizer_sha, str)
                or not re.fullmatch(r"[0-9a-f]{64}", canonicalizer_sha)
                or producer is None or gateway is None
                or producer_binding is None or gateway_binding is None
                or producer.owner_uid == gateway.owner_uid
                or producer_binding.uid != producer.owner_uid
                or gateway_binding.uid != gateway.owner_uid):
            raise AuthorityDenied("enrollment.native_bridge", "native bridge identity or canonicalizer binding is invalid")
        delivery_bindings = _parse_observer_delivery_bindings(
            item["observer_delivery_bindings"],
            source_issuers=_parse_source_issuers(service_generations["source_issuers"]),
            peer_generations={producer_id: producer.generation, gateway_id: gateway.generation},
        )
        provider_routes = [route for route in catalogs["provider_enrollments"].values()
                           if route["principal_id"] == producer_binding.principal_id]
        if len(provider_routes) != 1 or "provider-dispatch" not in producer_binding.capabilities:
            raise AuthorityDenied("enrollment.native_bridge", "producer must have one exact enrolled provider route")
        route = provider_routes[0]
        raw_policies = root["normalization_policies"]
        if not isinstance(raw_policies, list) or len(raw_policies) > 64:
            raise AuthorityDenied("enrollment.native_bridge", "normalization policy catalog is invalid")
        policy_catalog: dict[str, dict[str, Any]] = {}
        for raw_policy in raw_policies:
            policy = _exact(raw_policy, {"id", "revision", "route_schema_id", "output_limit_mode",
                                         "output_limit_ceiling", "canonicalizer_artifact_id",
                                         "canonicalizer_sha256", "normalization_policy_sha256"},
                            "normalization policy")
            item_id = _read_id(policy["id"], "normalization policy ID")
            if item_id in policy_catalog:
                raise AuthorityDenied("enrollment.native_bridge", "normalization policy is duplicated")
            revision = policy["revision"]
            module_hash = policy["canonicalizer_sha256"]
            policy_hash = policy["normalization_policy_sha256"]
            body = {key: value for key, value in policy.items() if key != "normalization_policy_sha256"}
            expected_policy_hash = hashlib.sha256(json.dumps(
                body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")).hexdigest()
            if (type(revision) is not int or revision < 1
                    or not isinstance(module_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", module_hash)
                    or not isinstance(policy_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", policy_hash)
                    or policy_hash != expected_policy_hash):
                raise AuthorityDenied("enrollment.native_bridge", "normalization policy hash or revision is invalid")
            policy_catalog[item_id] = policy
        if route["provider"] == "openrouter":
            expected_policy = ("provider-output-reject-4096-v1", 1, "provider-chat-compatible-v1",
                              "reject-over-ceiling", 4096)
        elif route["provider"] == "codex":
            expected_policy = ("siwc-output-unsupported-v1", 1, "siwc-responses-preview-v1",
                              "unsupported-field-reject", None)
        else:
            raise AuthorityDenied("enrollment.native_bridge", "provider route has no reviewed native normalization policy")
        policy_record = policy_catalog.get(policy_id)
        if (policy_record is None or type(policy_revision) is not int or policy_revision < 1
                or policy_record["id"] != expected_policy[0]
                or policy_revision != expected_policy[1]
                or policy_record["revision"] != policy_revision
                or policy_record["normalization_policy_sha256"] != policy_sha
                or (policy_record["route_schema_id"], policy_record["output_limit_mode"],
                    policy_record["output_limit_ceiling"]) != expected_policy[2:]
                or (policy_id, policy_revision, route_schema_id, limit_mode, output_ceiling) != expected_policy
                or policy_record["canonicalizer_artifact_id"] != canonicalizer_id
                or policy_record["canonicalizer_sha256"] != canonicalizer_sha):
            raise AuthorityDenied("enrollment.native_bridge", "native request normalization policy is not the selected route policy")
        provider_target = _read_id(route["target"], "native provider target")
        provider_recipient = _read_id(route["recipient"], "native provider recipient")
        native_bridges[bridge_id] = NativeBridgeEnrollment(
            bridge_id=bridge_id, producer_profile_id=producer_id,
            producer_uid=producer.owner_uid, producer_generation=producer.generation,
            producer_executable=producer.executable, producer_executable_sha256=producer.artifact_sha256,
            producer_principal_id=producer_binding.principal_id,
            gateway_profile_id=gateway_id, gateway_uid=gateway.owner_uid,
            gateway_generation=gateway.generation, gateway_executable=gateway.executable,
            gateway_executable_sha256=gateway.artifact_sha256,
            gateway_principal_id=gateway_binding.principal_id,
            canonicalizer_artifact_id=canonicalizer_id, canonicalizer_sha256=canonicalizer_sha,
            normalization_policy_id=policy_id, normalization_policy_sha256=policy_sha,
            normalization_policy_revision=policy_revision, route_schema_id=route_schema_id,
            output_limit_mode=limit_mode, output_limit_ceiling=output_ceiling,
            approved_operation="provider.dispatch", provider_enrollment_id=route["id"],
            target=provider_target, recipient=provider_recipient,
            observer_delivery_bindings=tuple(delivery_bindings),
        )
        bridge_pairs.add(pair)
    mcp_bindings: dict[str, Any] = {}
    raw_bindings = root["mcp_http_bindings"]
    if not isinstance(raw_bindings, list) or len(raw_bindings) > 256:
        raise AuthorityDenied("enrollment.mcp", "protected MCP HTTP binding catalog is invalid")
    try:
        from hermes_installer.mcp.broker import ProtectedMCPService
        from hermes_installer.mcp.enrolled_transport import ProtectedMCPHTTPBinding
        protected_services: dict[str, Any] = {}
        for raw in catalogs["mcp_services"].values():
            item = _exact(raw, {"id", "channel", "allowed_tools", "transport_binding_id",
                                "reviewed_revision", "selection_arguments"}, "MCP service")
            service_id = _read_id(item["id"], "MCP service ID")
            if (not isinstance(item["allowed_tools"], list)
                    or not isinstance(item["selection_arguments"], dict)
                    or set(item["selection_arguments"]) != set(item["allowed_tools"])):
                raise ValueError("MCP service tool selection schema is invalid")
            selections = {}
            for tool, arguments in item["selection_arguments"].items():
                if (not isinstance(tool, str) or not isinstance(arguments, list) or not arguments
                        or any(not isinstance(arg, str) or not arg for arg in arguments)
                        or len(arguments) != len(set(arguments))):
                    raise ValueError("MCP selected-resource arguments are invalid")
                selections[tool] = tuple(arguments)
            protected_services[service_id] = ProtectedMCPService(
                service_id=service_id, channel=item["channel"],
                allowed_tools=frozenset(item["allowed_tools"]),
                transport_binding_id=_read_id(item["transport_binding_id"], "MCP transport binding"),
                reviewed_revision=item["reviewed_revision"], selection_arguments=selections)
        for raw in raw_bindings:
            item = _exact(raw, {"binding_id", "service_id", "endpoint", "endpoint_source_id",
                                "reviewed_revision", "credential_ref"}, "MCP HTTP binding")
            binding_id = _read_id(item["binding_id"], "MCP HTTP binding ID")
            service_id = _read_id(item["service_id"], "MCP service ID")
            service = protected_services.get(service_id)
            endpoint = item["endpoint"]
            parsed = urlsplit(endpoint) if isinstance(endpoint, str) else None
            if (binding_id in mcp_bindings or service is None or service.channel != "http"
                    or service.transport_binding_id != binding_id
                    or service.reviewed_revision != item["reviewed_revision"]
                    or parsed is None or parsed.scheme != "https" or not parsed.hostname
                    or parsed.username or parsed.password or parsed.query or parsed.fragment):
                raise ValueError("MCP endpoint does not match its reviewed HTTP service")
            reference = _read_id(item["credential_ref"], "MCP credential reference")
            if not _is_credential_reference(reference):
                raise ValueError("MCP credential reference is invalid")
            handle = RootMCPCredentialHandle(service_id, reference, vault)
            mcp_bindings[binding_id] = ProtectedMCPHTTPBinding(
                binding_id=binding_id, service_id=service_id, endpoint=endpoint,
                endpoint_source_id=_read_id(item["endpoint_source_id"], "MCP endpoint source"),
                reviewed_revision=item["reviewed_revision"], credential_handle=handle)
        if len(mcp_bindings) != sum(1 for service in protected_services.values() if service.channel == "http"):
            raise ValueError("every protected HTTP service needs exactly one binding")
    except (TypeError, ValueError, ImportError):
        raise AuthorityDenied("enrollment.mcp", "protected MCP service/endpoint enrollment is invalid") from None
    if catalogs["memory_providers"]:
        raise AuthorityDenied("enrollment.memory", "legacy memory provider rows cannot authorize active services")
    memory_enrollments: dict[tuple[str, str], Any] = {}
    if service_generations["memory_enrollments"]:
        try:
            from hermes_installer.memory.enrollment import MemoryServiceEnrollment
            journal_root_ids = {
                row["root_id"] for row in service_generations["root_journal_roots"]
            }
            generation_records: dict[tuple[str, str], Mapping[str, Any]] = {}
            for service_record in service_generations["service_records"]:
                identity = (service_record.get("enrollment_id"), service_record.get("generation"))
                if not all(isinstance(value, str) and value for value in identity) or identity in generation_records:
                    raise ValueError("service generation identity is malformed or duplicated")
                generation_records[identity] = service_record
            for raw_memory in service_generations["memory_enrollments"]:
                memory = MemoryServiceEnrollment.from_protected_record(raw_memory)
                state_root_id = getattr(memory, "authority_state_root_id", None)
                if (not isinstance(state_root_id, str)
                        or state_root_id not in journal_root_ids):
                    raise ValueError("memory authority state root is not in active root journal catalog")
                key = (memory.service_enrollment_id, memory.service_generation)
                if key in memory_enrollments:
                    raise ValueError("memory service enrollment generation is duplicated")
                service_record = generation_records.get(key)
                profile = process_profiles.get(memory.profile_id)
                principal = next((binding for binding in bindings.values()
                                  if binding.profile_id == memory.profile_id), None)
                if (service_record is None or service_record.get("profile_id") != memory.profile_id
                        or service_record.get("principal_id") != memory.principal_id
                        or service_record.get("namespace_identity") != memory.namespace_identity
                        or profile is None or profile.generation != memory.service_generation
                        or principal is None
                        or memory.principal_id != principal.principal_id
                        or memory.namespace_identity != principal.namespace_id
                        or memory.data_root_id != profile.data_id):
                    raise ValueError("memory row does not join its protected service identity and data root")
                memory_enrollments[key] = memory
        except (ImportError, TypeError, ValueError, KeyError):
            raise AuthorityDenied("enrollment.memory", "protected memory service generation is invalid") from None
    # Process effect rules are joined to the active digest-bound service
    # snapshot, not targets reconstructed from caller journal/profile paths.
    # The root manager registers precisely these six handlers per profile.
    try:
        from hermes_installer.protected_enrollment import ProtectedEnrollmentCatalog
        generation_catalog = ProtectedEnrollmentCatalog.from_verified_records(
            service_generations["service_records"],
            protected_digest=service_generations["generation_digest"],
            expected_uid=0,
            native_packages=service_generations["native_packages"],
            source_issuers=_parse_source_issuers(service_generations["source_issuers"]),
            memory_enrollments=memory_enrollments,
            parameter_schemas=service_generations["operation_parameter_schemas"],
            selected_application_runtimes=service_generations["selected_application_runtimes"],
            native_schema_artifacts=service_generations["native_schema_artifacts"],
            native_mcp_tool_bindings=service_generations["native_mcp_tool_bindings"],
        )
        generation_profiles = {}
        for service_record in service_generations["service_records"]:
            service = generation_catalog.resolve(
                service_record["enrollment_id"], service_record["generation"],
            )
            if service.profile_id in generation_profiles:
                raise ValueError("service profile is duplicated")
            authority_profile = process_profiles.get(service.profile_id)
            if (authority_profile is None
                    or authority_profile.owner_uid != service.service_uid
                    or authority_profile.owner_gid != service.service_gid
                    or authority_profile.generation != service.generation):
                raise ValueError("service generation does not join its authority process identity")
            generation_profiles[service.profile_id] = service
        _verify_active_process_rules(generation_profiles, process_profiles, bindings, rules)
    except (ImportError, AttributeError, KeyError, PermissionError, TypeError, ValueError):
        raise AuthorityDenied("enrollment.process", "managed process targets do not join the active service generation") from None
    return ProtectedEnrollment(
        key_id, bindings, rules, policy, process_profiles,
        catalogs["provider_enrollments"], catalogs["mcp_services"],
        mcp_bindings, delegations, catalogs["memory_providers"],
        native_bridges, {}, {}, ARTIFACT_CATALOG_PATH,
        ARTIFACT_STAGING_DIRECTORY,
        service_generations["service_records"],
        service_generations["protected_devices"],
        service_generations["protected_build_records"],
        service_generations["generation_digest"],
        service_generations["native_packages"],
        MappingProxyType(memory_enrollments),
        service_generations["operation_parameter_schemas"],
        _parse_source_issuers(service_generations["source_issuers"]),
        tuple(MappingProxyType(dict(row)) for row in service_generations["resource_jobs"]),
        tuple(dict(row) for row in service_generations["remote_session_enrollments"]),
        tuple(MappingProxyType(dict(row)) for row in service_generations["resource_backend_enrollments"]),
        tuple(MappingProxyType(dict(row)) for row in service_generations["resource_body_recipes"]),
        tuple(MappingProxyType(dict(row)) for row in service_generations["resource_scope_bindings"]),
        tuple(MappingProxyType(dict(row)) for row in service_generations["resource_validators"]),
        tuple(MappingProxyType(dict(row)) for row in service_generations["root_journal_roots"]),
        tuple(MappingProxyType(dict(row)) for row in service_generations["native_mcp_tool_bindings"]),
        tuple(MappingProxyType(dict(row)) for row in service_generations["resource_controller_roles"]),
        tuple(MappingProxyType(dict(row)) for row in service_generations["remote_observation_enrollments"]),
        tuple(native_schema_records),
        tuple(composio_channel_records),
        tuple(channel_delivery_records),
        tuple(MappingProxyType(dict(row)) for row in service_generations["remote_startup_enrollments"]),
        tuple(MappingProxyType(dict(row)) for row in service_generations["private_loopback_networks"]),
        tuple(MappingProxyType(dict(row)) for row in service_generations["selected_resource_executions"]),
        tuple(MappingProxyType(dict(row)) for row in service_generations["selected_application_runtimes"]),
    )


def load_artifact_catalog(enrollment: ProtectedEnrollment) -> Any:
    """Read the separately protected immutable artifact/package catalog."""
    from hermes_installer.artifacts import load_protected_catalog
    return load_protected_catalog(enrollment.artifact_catalog_path, expected_uid=0)
