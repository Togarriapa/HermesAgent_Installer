"""Root TTY intent and exact-input disclosure for free public web reads.

These records preserve operator intent; they do not grant runtime egress.  The
active publisher and per-input permission registry still have to join them to
current target, source, identity, and execution evidence.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import time
from dataclasses import dataclass, field
from typing import Any

_CHOICE_SEAL = object()
_CONFIGURATION_SEAL = object()
_DISCLOSURE_SEAL = object()
_TTL_SECONDS = 300.0
_DISCLOSURE_TTL_SECONDS = 30.0
_MAX_SCOPE_BYTES = 256 * 1024
_MAX_DISCLOSURE_BYTES = 16 * 1024


class PublicWebSelectionDenied(PermissionError):
    """Public TTY intent is absent, stale, malformed, or not current."""


@dataclass(frozen=True, slots=True, repr=False)
class RootSelectedPublicWebPermissionChoice:
    """Sealed explicit public-web configuration selected at the root TTY."""

    choice_handle: str
    choice_observation_id: str
    setup_session_id: str
    transaction_handle: str
    plan_sha256: str
    prepared_generation_id: str
    prepared_generation_digest: str
    principal_selection_handle: str
    principal_binding_sha256: str
    namespace_selection_handle: str
    namespace_binding_sha256: str
    principal_id: str
    profile_id: str
    namespace_id: str
    profile_generation: str
    target_selection_handles: tuple[str, ...]
    web_scope_ids: tuple[str, ...]
    scope_payloads: tuple[bytes, ...]
    scope_payload_sha256s: tuple[str, ...]
    configuration_observation_handles: tuple[str, ...]
    configuration_sha256s: tuple[str, ...]
    target_contract_artifact_ids: tuple[str, ...]
    target_contract_sha256s: tuple[str, ...]
    target_contract_source_receipt_handles: tuple[str, ...]
    controller_binding_handle: str
    issued_monotonic: float
    expires_monotonic: float
    revocation_epoch: int
    _issuer_token: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._issuer_token is not _CHOICE_SEAL:
            raise TypeError("public web choices are issued by the root TTY registry")
        _validate_choice(self, time.monotonic())

    def __repr__(self) -> str:
        return "RootSelectedPublicWebPermissionChoice(<root-private>)"


@dataclass(frozen=True, slots=True, repr=False)
class RootPublicWebScopeConfiguration:
    """Sealed finite v142 config entered at the live root TTY for one target."""

    native_policy_selection_handle: str
    target_candidate_handle: str
    component_id: str
    target_id: str
    profile_id: str
    profile_generation: str
    recipient: str
    scope_payload: bytes
    scope_payload_sha256: str
    tty_configuration_sha256: str
    tty_controller_observation_handle: str
    issued_monotonic: float
    expires_monotonic: float
    _issuer_token: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._issuer_token is not _CONFIGURATION_SEAL:
            raise TypeError("public web configuration is issued by the root TTY")
        _validate_scope_configuration(self, time.monotonic())

    def __repr__(self) -> str:
        return "RootPublicWebScopeConfiguration(<root-private>)"


def collect_root_tty_public_web_scope_configuration(
        root_session: Any, target: Any, native_policy_selection_handle: str,
) -> RootPublicWebScopeConfiguration:
    """Collect a closed v142 row with no public default and bind it to target."""
    from .bootstrap_runtime_factory import RootBootstrapSession

    if type(root_session) is not RootBootstrapSession:
        raise PublicWebSelectionDenied("public scope requires the exact root setup session")
    root_session._check_live()
    required_target = (
        "candidate_handle", "native_policy_selection_handle", "component_id",
        "target_id", "profile_id", "profile_generation", "recipient",
        "principal_selection_handle", "namespace_selection_handle",
    )
    if (any(not isinstance(getattr(target, name, None), str)
            or not getattr(target, name) for name in required_target)
            or target.native_policy_selection_handle != native_policy_selection_handle
            or getattr(target, "backend_generation", None) != target.profile_generation
            or not isinstance(target.recipient, str) or not target.recipient):
        raise PublicWebSelectionDenied("public scope requires an exact current typed target")
    from ..root_setup import _capture_root_tty_proof, _verify_root_tty_proof
    proof = _capture_root_tty_proof()
    try:
        _verify_root_tty_proof(proof)
        if proof.controller_uid != 0 or proof.controller_pid != __import__("os").getpid():
            raise PublicWebSelectionDenied("public scope requires the live root controlling TTY")
        prompt = ("\nConfigure public HTTPS scope for this selected target. No default is set.\n"
                  f"Target: {target.target_id}\nRecipient: {target.recipient}\n"
                  "Enter one JSON object with exactly targets, request_bytes_limit, "
                  "response_bytes_limit, deadline_seconds. targets is a list of exact "
                  "hostname/path_prefixes/query_keys rows. Empty input denies: ")
        __import__("os").write(2, prompt.encode("utf-8"))
        raw_tty = _read_tty_line(proof.stdin_fd, max_bytes=_MAX_SCOPE_BYTES + 1)
        if not raw_tty.strip():
            raise PublicWebSelectionDenied("blank public scope selection means no public-web configuration")
        _verify_root_tty_proof(proof)
        try:
            fields = json.loads(raw_tty.decode("utf-8"))
        except Exception:
            raise PublicWebSelectionDenied("public scope input is not valid UTF-8 JSON") from None
        if type(fields) is not dict or set(fields) != {
                "targets", "request_bytes_limit", "response_bytes_limit", "deadline_seconds"}:
            raise PublicWebSelectionDenied("public scope input does not match the closed v142 TTY schema")
        identity = root_session.resolve_current_setup_identity()
        if (identity.principal.selection_handle != target.principal_selection_handle
                or identity.namespace.selection_handle != target.namespace_selection_handle):
            raise PublicWebSelectionDenied("target no longer belongs to the current principal and namespace")
        value = {
            "enrollment_id": "scope-" + secrets.token_hex(16),
            "target_id": target.target_id,
            "generation": target.profile_generation,
            "principal_id": identity.principal.principal_id,
            "profile_id": target.profile_id,
            "recipient": target.recipient,
            "targets": fields["targets"],
            "request_bytes_limit": fields["request_bytes_limit"],
            "response_bytes_limit": fields["response_bytes_limit"],
            "deadline_seconds": fields["deadline_seconds"],
        }
        payload, payload_sha = canonical_scope_payload(value)
        __import__("os").write(
            2, ("\nSelected finite public web scope:\n"
                + json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False)
                + "\nThis is a PUBLIC web-read choice with $0 additional metered budget. "
                  "Type PUBLIC to retain it, or anything else to deny: ").encode("utf-8"))
        if _read_tty_line(proof.stdin_fd, max_bytes=64) != b"PUBLIC":
            raise PublicWebSelectionDenied("public web scope was not explicitly confirmed")
        now = time.monotonic()
        result = RootPublicWebScopeConfiguration(
            native_policy_selection_handle=native_policy_selection_handle,
            target_candidate_handle=target.candidate_handle,
            component_id=target.component_id,
            target_id=target.target_id,
            profile_id=target.profile_id,
            profile_generation=target.profile_generation,
            recipient=target.recipient,
            scope_payload=payload,
            scope_payload_sha256=payload_sha,
            tty_configuration_sha256=hashlib.sha256(raw_tty).hexdigest(),
            tty_controller_observation_handle=_tty_controller_digest(proof),
            issued_monotonic=now,
            expires_monotonic=now + _TTL_SECONDS,
            _issuer_token=_CONFIGURATION_SEAL,
        )
        _verify_root_tty_proof(proof)
        return result
    finally:
        proof.close()


def _validate_scope_configuration(value: RootPublicWebScopeConfiguration, now: float) -> None:
    strings = (value.native_policy_selection_handle, value.target_candidate_handle,
               value.component_id, value.target_id, value.profile_id,
               value.profile_generation, value.recipient, value.tty_controller_observation_handle)
    if (any(type(item) is not str or not item for item in strings)
            or type(value.scope_payload) is not bytes
            or len(value.scope_payload) > _MAX_SCOPE_BYTES
            or hashlib.sha256(value.scope_payload).hexdigest() != value.scope_payload_sha256
            or len(value.scope_payload_sha256) != 64
            or len(value.tty_configuration_sha256) != 64
            or any(c not in "0123456789abcdef" for c in
                   value.scope_payload_sha256 + value.tty_configuration_sha256)
            or type(value.issued_monotonic) not in (int, float)
            or type(value.expires_monotonic) not in (int, float)
            or value.issued_monotonic > now or value.expires_monotonic <= now
            or value.expires_monotonic - value.issued_monotonic > _TTL_SECONDS):
        raise PublicWebSelectionDenied("root public scope configuration is malformed or stale")
    try:
        row = json.loads(value.scope_payload.decode("utf-8"))
        if (_canonical_json(row) != value.scope_payload or row["target_id"] != value.target_id
                or row["profile_id"] != value.profile_id
                or row["generation"] != value.profile_generation
                or row["recipient"] != value.recipient):
            raise ValueError
    except Exception:
        raise PublicWebSelectionDenied("scope payload changed from the exact target configuration") from None


@dataclass(frozen=True, slots=True, repr=False)
class RootTTYPublicInputDisclosure:
    """One-use disclosure proving that exact root-retained input was reviewed."""

    disclosure_observation_handle: str
    disclosure_sha256: str
    retained_observed_input_handle: str
    input_sha256: str
    input_size_bytes: int
    public_permission_selection_handle: str
    selected_execution_handle: str
    tty_controller_observation_handle: str
    issued_monotonic: float
    expires_monotonic: float
    one_use_nonce: str
    _issuer_token: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._issuer_token is not _DISCLOSURE_SEAL:
            raise TypeError("input disclosure is issued by the root TTY registry")
        _validate_disclosure(self, time.monotonic())

    def __repr__(self) -> str:
        return "RootTTYPublicInputDisclosure(<root-private>)"


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def canonical_scope_payload(value: Any) -> tuple[bytes, str]:
    """Validate finite v142 scope fields and return their exact canonical bytes."""
    fields = {
        "enrollment_id", "target_id", "generation", "principal_id", "profile_id",
        "recipient", "targets", "request_bytes_limit", "response_bytes_limit",
        "deadline_seconds",
    }
    if type(value) is not dict or set(value) != fields:
        raise PublicWebSelectionDenied("public scope must use the closed v142 payload schema")
    try:
        raw = _canonical_json(value)
        if len(raw) > _MAX_SCOPE_BYTES:
            raise ValueError
        from ..protected_enrollment import RootSelectedPublicWebScope
        # Reuse the existing strict production parser for DNS/path/query rules.
        record = dict(value)
        record.update({
            "target_selection_handle": "fixture-target-selection",
            "configuration_observation_handle": "fixture-configuration-observation",
            "configuration_sha256": "0" * 64,
            "target_contract_artifact_id": "fixture-contract-artifact",
            "target_contract_sha256": "0" * 64,
            "target_contract_source_receipt_handle": "fixture-contract-receipt",
        })
        scope = RootSelectedPublicWebScope.from_protected_record(
            record, service_generation_digest="0" * 64)
        digest = hashlib.sha256(raw).hexdigest()
        if scope.scope_payload_sha256 != digest:
            raise ValueError
    except Exception:
        raise PublicWebSelectionDenied("public scope is malformed or outside the finite v142 schema") from None
    return raw, digest


def _validate_choice(choice: RootSelectedPublicWebPermissionChoice, now: float) -> None:
    strings = (
        choice.choice_handle, choice.choice_observation_id, choice.setup_session_id,
        choice.transaction_handle, choice.prepared_generation_id,
        choice.principal_selection_handle, choice.namespace_selection_handle,
        choice.principal_id, choice.profile_id, choice.namespace_id,
        choice.profile_generation, choice.controller_binding_handle,
    )
    hashes = (
        choice.plan_sha256, choice.prepared_generation_digest,
        choice.principal_binding_sha256, choice.namespace_binding_sha256,
        *choice.scope_payload_sha256s, *choice.configuration_sha256s,
        *choice.target_contract_sha256s,
    )
    aligned = (
        choice.target_selection_handles, choice.web_scope_ids, choice.scope_payloads,
        choice.scope_payload_sha256s, choice.configuration_observation_handles,
        choice.configuration_sha256s, choice.target_contract_artifact_ids,
        choice.target_contract_sha256s, choice.target_contract_source_receipt_handles,
    )
    if (any(type(value) is not str or not value for value in strings)
            or any(type(value) is not str or len(value) != 64
                   or any(c not in "0123456789abcdef" for c in value) for value in hashes)
            or not choice.web_scope_ids or len(set(choice.web_scope_ids)) != len(choice.web_scope_ids)
            or tuple(sorted(choice.web_scope_ids)) != choice.web_scope_ids
            or any(type(values) is not tuple for values in aligned)
            or any(len(values) != len(choice.web_scope_ids) for values in aligned)
            or len(set(choice.target_selection_handles)) != len(choice.target_selection_handles)
            or tuple(sorted(choice.target_selection_handles)) != choice.target_selection_handles
            or any(not isinstance(item, str) or not item for values in
                   (choice.target_selection_handles, choice.web_scope_ids,
                    choice.configuration_observation_handles, choice.target_contract_artifact_ids,
                    choice.target_contract_source_receipt_handles) for item in values)
            or any(type(raw) is not bytes or len(raw) > _MAX_SCOPE_BYTES
                   for raw in choice.scope_payloads)
            or any(hashlib.sha256(raw).hexdigest() != digest for raw, digest in
                   zip(choice.scope_payloads, choice.scope_payload_sha256s))
            or type(choice.issued_monotonic) not in (int, float)
            or type(choice.expires_monotonic) not in (int, float)
            or choice.issued_monotonic > now or choice.expires_monotonic <= now
            or choice.expires_monotonic - choice.issued_monotonic > _TTL_SECONDS
            or type(choice.revocation_epoch) is not int or choice.revocation_epoch < 0):
        raise PublicWebSelectionDenied("root public web choice is malformed, stale, or unaligned")
    for raw, scope_id in zip(choice.scope_payloads, choice.web_scope_ids):
        try:
            value = json.loads(raw.decode("utf-8"))
            if (_canonical_json(value) != raw or value["enrollment_id"] != scope_id
                    or value["principal_id"] != choice.principal_id
                    or value["profile_id"] != choice.profile_id
                    or value["generation"] != choice.profile_generation):
                raise ValueError
        except Exception:
            raise PublicWebSelectionDenied("choice scope payload does not match selected identity") from None


def _validate_disclosure(disclosure: RootTTYPublicInputDisclosure, now: float) -> None:
    strings = (disclosure.disclosure_observation_handle, disclosure.retained_observed_input_handle,
               disclosure.public_permission_selection_handle, disclosure.selected_execution_handle,
               disclosure.tty_controller_observation_handle, disclosure.one_use_nonce)
    hashes = (disclosure.disclosure_sha256, disclosure.input_sha256)
    if (any(type(value) is not str or not value for value in strings)
            or any(type(value) is not str or len(value) != 64
                   or any(c not in "0123456789abcdef" for c in value) for value in hashes)
            or type(disclosure.input_size_bytes) is not int
            or not 1 <= disclosure.input_size_bytes <= _MAX_DISCLOSURE_BYTES
            or type(disclosure.issued_monotonic) not in (int, float)
            or type(disclosure.expires_monotonic) not in (int, float)
            or disclosure.issued_monotonic > now or disclosure.expires_monotonic <= now
            or disclosure.expires_monotonic - disclosure.issued_monotonic > _DISCLOSURE_TTL_SECONDS):
        raise PublicWebSelectionDenied("root TTY disclosure is malformed or stale")
    expected = hashlib.sha256(_canonical_json({
        "input_sha256": disclosure.input_sha256,
        "input_size_bytes": disclosure.input_size_bytes,
        "public_permission_selection_handle": disclosure.public_permission_selection_handle,
        "retained_observed_input_handle": disclosure.retained_observed_input_handle,
        "selected_execution_handle": disclosure.selected_execution_handle,
        "tty_controller_observation_handle": disclosure.tty_controller_observation_handle,
        "one_use_nonce": disclosure.one_use_nonce,
    })).hexdigest()
    if not secrets.compare_digest(expected, disclosure.disclosure_sha256):
        raise PublicWebSelectionDenied("root TTY disclosure digest does not bind its exact proof fields")


class RootPublicInputDisclosureRegistry:
    """Session-owned TTY proof registry for exact retained native input bytes."""

    def __init__(self, root_session: Any, source_observer_registry: Any) -> None:
        from .bootstrap_runtime_factory import RootBootstrapSession

        if (type(root_session) is not RootBootstrapSession
                or not callable(getattr(source_observer_registry,
                                        "resolve_current_retained_selected_input", None))
                or not callable(getattr(source_observer_registry,
                                        "verify_current_retained_selected_input", None))):
            raise ValueError("public input disclosure requires exact root session and source observer")
        self._session = root_session
        self._source = source_observer_registry
        self._seal = secrets.token_bytes(32)
        self._by_handle: dict[str, RootTTYPublicInputDisclosure] = {}
        self._consumed: set[str] = set()
        self._input_proofs: dict[str, tuple[Any, Any, bytes]] = {}
        self._permission_selections: dict[str, Any] = {}

    def observe_public_input_disclosure(
            self, public_permission_selection_handle: str,
            retained_observed_input_handle: str, selected_execution_handle: str,
    ) -> RootTTYPublicInputDisclosure:
        """Prompt over exact retained bytes; blank, EOF, or any other answer denies."""
        session = self._session
        session._check_live()
        if (not isinstance(public_permission_selection_handle, str)
                or not public_permission_selection_handle
                or not isinstance(retained_observed_input_handle, str)
                or not retained_observed_input_handle
                or not isinstance(selected_execution_handle, str)
                or not selected_execution_handle):
            raise PublicWebSelectionDenied("public input disclosure handles are malformed")
        try:
            permission_registry = getattr(self._source.service,
                                          "public_input_permission_registry", None)
            resolve_selection = getattr(permission_registry, "resolve_current_selection", None)
            if not callable(resolve_selection):
                raise ValueError
            selection = resolve_selection(public_permission_selection_handle)
            proof = self._source.resolve_current_retained_selected_input(
                retained_observed_input_handle, selected_execution_handle)
            if not self._source.verify_current_retained_selected_input(
                    retained_observed_input_handle, selected_execution_handle):
                raise ValueError
            execution = self._source.resolve_current_selected_execution(selected_execution_handle)
            if (getattr(selection, "selection_handle", None) != public_permission_selection_handle
                    or getattr(execution, "selection_handle", None) != selected_execution_handle
                    or getattr(execution, "public_input_permission_selection_handle", None)
                        != public_permission_selection_handle
                    or getattr(execution, "profile_id", None) != getattr(selection, "profile_id", None)):
                raise ValueError
            raw = getattr(proof, "payload_bytes", None)
            if type(raw) is not bytes or len(raw) > _MAX_DISCLOSURE_BYTES:
                raise ValueError
            digest = hashlib.sha256(raw).hexdigest()
            observation_handle = secrets.token_hex(32)
            from ..root_setup import _capture_root_tty_proof, _verify_root_tty_proof
            tty_proof = _capture_root_tty_proof()
            try:
                _verify_root_tty_proof(tty_proof)
                if (tty_proof.controller_uid != 0 or tty_proof.controller_pid != os.getpid()
                        or not getattr(selection, "controller_binding_handle", None)):
                    raise ValueError
                tty_handle = _tty_controller_digest(tty_proof)
                _render_exact_input_for_public_review(raw, digest)
                answer = _read_tty_line(tty_proof.stdin_fd, max_bytes=64)
                _verify_root_tty_proof(tty_proof)
                if answer != b"PUBLIC":
                    raise PublicWebSelectionDenied("public input disclosure was not explicitly confirmed")
                now = time.monotonic()
                one_use_nonce = secrets.token_hex(32)
                disclosure_sha256 = hashlib.sha256(_canonical_json({
                    "input_sha256": digest,
                    "input_size_bytes": len(raw),
                    "public_permission_selection_handle": public_permission_selection_handle,
                    "retained_observed_input_handle": retained_observed_input_handle,
                    "selected_execution_handle": selected_execution_handle,
                    "tty_controller_observation_handle": tty_handle,
                    "one_use_nonce": one_use_nonce,
                })).hexdigest()
                disclosure = RootTTYPublicInputDisclosure(
                    disclosure_observation_handle=observation_handle,
                    disclosure_sha256=disclosure_sha256,
                    retained_observed_input_handle=retained_observed_input_handle,
                    input_sha256=digest,
                    input_size_bytes=len(raw),
                    public_permission_selection_handle=public_permission_selection_handle,
                    selected_execution_handle=selected_execution_handle,
                    tty_controller_observation_handle=tty_handle,
                    issued_monotonic=now,
                    expires_monotonic=now + _DISCLOSURE_TTL_SECONDS,
                    one_use_nonce=one_use_nonce,
                    _issuer_token=_DISCLOSURE_SEAL,
                )
                if (not self._source.verify_current_retained_selected_input(
                        retained_observed_input_handle, selected_execution_handle)
                        or resolve_selection(public_permission_selection_handle) is not selection
                        or self._source.resolve_current_selected_execution(
                            selected_execution_handle) is not execution):
                    raise PublicWebSelectionDenied("selection or source input changed during root TTY review")
                self._by_handle[observation_handle] = disclosure
                self._input_proofs[observation_handle] = (proof, execution, raw)
                self._permission_selections[observation_handle] = selection
                return disclosure
            finally:
                tty_proof.close()
        except PublicWebSelectionDenied:
            raise
        except Exception:
            raise PublicWebSelectionDenied("current root TTY, input, execution, or permission is unavailable") from None

    def resolve_current_input_disclosure(self, disclosure_handle: str) -> RootTTYPublicInputDisclosure:
        disclosure = self._by_handle.get(disclosure_handle)
        if (type(disclosure) is not RootTTYPublicInputDisclosure
                or disclosure._issuer_token is not _DISCLOSURE_SEAL
                or disclosure_handle in self._consumed):
            raise PublicWebSelectionDenied("public input disclosure is absent or already consumed")
        _validate_disclosure(disclosure, time.monotonic())
        proof, execution, raw = self._input_proofs[disclosure_handle]
        if (hashlib.sha256(raw).hexdigest() != disclosure.input_sha256
                or len(raw) != disclosure.input_size_bytes
                or not self._source.verify_current_retained_selected_input(
                    disclosure.retained_observed_input_handle, disclosure.selected_execution_handle)
                or self._source.resolve_current_retained_selected_input(
                    disclosure.retained_observed_input_handle,
                    disclosure.selected_execution_handle) is not proof
                or self._source.resolve_current_selected_execution(
                    disclosure.selected_execution_handle) is not execution
                or not self._same_current_permission_selection(disclosure, disclosure_handle)):
            raise PublicWebSelectionDenied("public input disclosure no longer resolves to current held state")
        return disclosure

    def _same_current_permission_selection(self, disclosure: RootTTYPublicInputDisclosure,
                                           disclosure_handle: str) -> bool:
        registry = getattr(self._source.service, "public_input_permission_registry", None)
        resolver = getattr(registry, "resolve_current_selection", None)
        return (callable(resolver)
                and resolver(disclosure.public_permission_selection_handle)
                    is self._permission_selections[disclosure_handle])

    def verify_current_input_disclosure(self, disclosure: Any, proof: Any,
                                        execution: Any) -> bool:
        if type(disclosure) is not RootTTYPublicInputDisclosure:
            return False
        retained = self._by_handle.get(disclosure.disclosure_observation_handle)
        if (retained is not disclosure or disclosure.disclosure_observation_handle in self._consumed
                or disclosure._issuer_token is not _DISCLOSURE_SEAL):
            return False
        try:
            self.resolve_current_input_disclosure(disclosure.disclosure_observation_handle)
            retained_proof, retained_execution, raw = self._input_proofs[
                disclosure.disclosure_observation_handle]
            return (retained_proof is proof
                    and retained_execution is execution
                    and hashlib.sha256(raw).hexdigest() == disclosure.input_sha256
                    and getattr(proof, "proof_nonce", None)
                    == disclosure.retained_observed_input_handle
                    and getattr(execution, "selection_handle", None)
                    == disclosure.selected_execution_handle)
        except Exception:
            return False

    def consume_current_input_disclosure(self, disclosure: RootTTYPublicInputDisclosure,
                                         proof: Any, execution: Any) -> bool:
        if not self.verify_current_input_disclosure(disclosure, proof, execution):
            return False
        self._consumed.add(disclosure.disclosure_observation_handle)
        return True

    def verify_consumed_input_disclosure(self, disclosure: Any, proof: Any,
                                         execution: Any) -> bool:
        """Revalidate an already-consumed TTY proof without making it reusable.

        Source material can be checked after the source consumer has atomically
        consumed its one-use nonce. This path never resolves or renews the
        pending source observation and never removes the consumed marker.
        """
        if type(disclosure) is not RootTTYPublicInputDisclosure:
            return False
        handle = disclosure.disclosure_observation_handle
        if (self._by_handle.get(handle) is not disclosure
                or handle not in self._consumed
                or disclosure._issuer_token is not _DISCLOSURE_SEAL):
            return False
        try:
            _validate_disclosure(disclosure, time.monotonic())
            retained_proof, retained_execution, raw = self._input_proofs[handle]
            if (retained_proof is not proof or retained_execution is not execution
                    or type(raw) is not bytes
                    or hashlib.sha256(raw).hexdigest() != disclosure.input_sha256
                    or len(raw) != disclosure.input_size_bytes
                    or getattr(proof, "proof_nonce", None)
                        != disclosure.retained_observed_input_handle
                    or getattr(execution, "selection_handle", None)
                        != disclosure.selected_execution_handle
                    or getattr(execution, "public_input_permission_selection_handle", None)
                        != disclosure.public_permission_selection_handle
                    or getattr(proof, "selected_execution", None) is not execution):
                return False
            if not self._same_current_permission_selection(disclosure, handle):
                return False
            # The original root controller must still be the current root TTY
            # controller; merely presenting a copied DTO cannot pass this join.
            session = self._session
            session._check_live()
            from ..root_setup import _capture_root_tty_proof, _verify_root_tty_proof
            tty = _capture_root_tty_proof()
            try:
                _verify_root_tty_proof(tty)
                return (tty.controller_uid == 0
                        and tty.controller_pid == os.getpid()
                        and _tty_controller_digest(tty)
                            == disclosure.tty_controller_observation_handle)
            finally:
                tty.close()
        except Exception:
            return False


class RootPublicWebSelectionRegistry:
    """Compose exact preactive targets into one signed durable root TTY choice."""

    def __init__(self, root_session: Any, target_registry: Any) -> None:
        from .bootstrap_runtime_factory import RootBootstrapSession

        if (type(root_session) is not RootBootstrapSession
                or not callable(getattr(target_registry, "resolve_current_target", None))
                or not callable(getattr(target_registry, "observe_configured_public_web_scope", None))
                or not callable(getattr(target_registry, "resolve_current_public_web_target_candidates", None))):
            raise ValueError("public web selection requires the current root target registry")
        self._session = root_session
        self._targets = target_registry
        self._choices: dict[str, RootSelectedPublicWebPermissionChoice] = {}

    def observe_public_web_permission_selection(
            self, native_policy_selection_handle: str,
    ) -> str | None:
        """Select configured public scopes from actual preactive target candidates."""
        session = self._session
        session._check_live()
        binding = session.selected_installation
        try:
            policy_registry = binding.resolve_current_native_policy_registry()
            policy = binding.resolve_current_native_policy_selection(native_policy_selection_handle)
            if (policy_registry is None
                    or policy.selection_handle != native_policy_selection_handle):
                raise ValueError
            candidates = self._targets.resolve_current_public_web_target_candidates(
                native_policy_selection_handle)
        except Exception:
            raise PublicWebSelectionDenied(
                "current preactive public web target candidates are unavailable") from None
        if type(candidates) is not tuple or not candidates:
            return None
        if any(getattr(candidate, "native_policy_selection_handle", None)
               != native_policy_selection_handle for candidate in candidates):
            raise PublicWebSelectionDenied("public web candidate belongs to another policy selection")

        _write_candidate_menu(candidates)
        from ..root_setup import _capture_root_tty_proof, _verify_root_tty_proof
        proof = _capture_root_tty_proof()
        try:
            _verify_root_tty_proof(proof)
            _write_tty_prompt("Choose exact public target candidate IDs (comma-separated); blank disables public web: ")
            raw = _read_tty_line(proof.stdin_fd, max_bytes=4096)
            _verify_root_tty_proof(proof)
            if not raw.strip():
                profile_ids = {getattr(row, "profile_id", None) for row in candidates}
                if len(profile_ids) != 1 or not next(iter(profile_ids)):
                    raise PublicWebSelectionDenied(
                        "blank public choice cannot revoke without one exact candidate profile")
                revoke = getattr(binding, "revoke_durable_setup_choice_purpose", None)
                if not callable(revoke):
                    raise PublicWebSelectionDenied("durable public-choice revocation is unavailable")
                revoke("public-free-web-read", next(iter(profile_ids)))
                return None
            try:
                selected_ids = tuple(item.strip() for item in raw.decode("utf-8").split(","))
            except UnicodeDecodeError:
                raise PublicWebSelectionDenied("target selection is not valid UTF-8") from None
            available = {getattr(row, "candidate_handle", None): row for row in candidates}
            if (not selected_ids or any(not item for item in selected_ids)
                    or len(set(selected_ids)) != len(selected_ids)
                    or any(item not in available for item in selected_ids)):
                raise PublicWebSelectionDenied("target selection exceeds the current finite candidate set")
        finally:
            proof.close()

        current_identity = session.resolve_current_setup_identity()
        configurations = []
        targets = []
        for candidate_handle in selected_ids:
            candidate = available[candidate_handle]
            config = collect_root_tty_public_web_scope_configuration(
                session, candidate, native_policy_selection_handle)
            try:
                target = self._targets.observe_configured_public_web_scope(
                    native_policy_selection_handle, candidate_handle, config)
                current = self._targets.resolve_current_target(
                    target.selection_handle, native_policy_selection_handle)
                if type(current) is not type(target) or current is not target:
                    raise ValueError
            except Exception:
                raise PublicWebSelectionDenied(
                    "configured public scope did not resolve to the same current source-owned target") from None
            targets.append(current)
            configurations.append(config)
        if not targets:
            return None
        return self._record_choice(policy, current_identity, targets, configurations)

    def resolve_current_public_web_permission_choice(
            self, choice_handle: str,
    ) -> RootSelectedPublicWebPermissionChoice:
        choice = self._choices.get(choice_handle)
        if type(choice) is not RootSelectedPublicWebPermissionChoice:
            raise PublicWebSelectionDenied("public web choice is absent or not retained")
        _validate_choice(choice, time.monotonic())
        session = self._session
        session._check_live()
        binding = session.selected_installation
        first_target = self._targets.resolve_current_target_handle(
            choice.target_selection_handles[0])
        policy_handle = first_target.native_policy_selection_handle
        policy_registry = binding.resolve_current_native_policy_registry()
        policy = binding.resolve_current_native_policy_selection(policy_handle)
        identity = session.resolve_current_setup_identity()
        if (identity.principal.principal_id != choice.principal_id
                or identity.namespace.namespace_id != choice.namespace_id
                or identity.principal.selection_handle != choice.principal_selection_handle
                or identity.namespace.selection_handle != choice.namespace_selection_handle
                or policy.selection_handle != policy_handle
                or policy.prepared_generation_id != choice.prepared_generation_id
                or policy.prepared_generation_digest != choice.prepared_generation_digest):
            raise PublicWebSelectionDenied("current identity or prepared policy differs from public TTY choice")
        payload_indexes = {digest: index for index, digest in enumerate(choice.scope_payload_sha256s)}
        for target_handle in choice.target_selection_handles:
            target = self._targets.resolve_current_target(target_handle, policy.selection_handle)
            index = payload_indexes.get(target.scope_payload_sha256)
            if index is None:
                raise PublicWebSelectionDenied("current target is absent from the retained public scopes")
            if (target.scope_payload != choice.scope_payloads[index]
                    or target.scope_payload_sha256 != choice.scope_payload_sha256s[index]
                    or target.configuration_observation_handle
                        != choice.configuration_observation_handles[index]
                    or target.configuration_sha256 != choice.configuration_sha256s[index]
                    or target.target_contract_artifact_id != choice.target_contract_artifact_ids[index]
                    or target.target_contract_sha256 != choice.target_contract_sha256s[index]
                    or target.target_contract_source_receipt_handle
                        != choice.target_contract_source_receipt_handles[index]):
                raise PublicWebSelectionDenied("current target, configuration, or source receipt changed")
        return choice

    def _record_choice(self, policy: Any, identity: Any, targets: list[Any],
                       configs: list[RootPublicWebScopeConfiguration]) -> str:
        rows = []
        for target, config in zip(targets, configs):
            if (target.scope_payload is None
                    or target.scope_payload_sha256 != config.scope_payload_sha256
                    or target.scope_payload != config.scope_payload):
                raise PublicWebSelectionDenied("target registry did not retain exact TTY scope bytes")
            try:
                payload = json.loads(target.scope_payload.decode("utf-8"))
            except Exception:
                raise PublicWebSelectionDenied("current target scope payload is malformed") from None
            rows.append((payload["enrollment_id"], target, config))
        rows.sort(key=lambda item: item[0])
        scope_ids = tuple(row[0] for row in rows)
        if len(set(scope_ids)) != len(scope_ids):
            raise PublicWebSelectionDenied("configured public scope enrollment IDs collide")
        policy_registry = self._session.selected_installation.resolve_current_native_policy_registry()
        policy_current = policy_registry.resolve_selection_current(policy.selection_handle)
        now = time.monotonic()
        handle = secrets.token_urlsafe(32)
        choice = RootSelectedPublicWebPermissionChoice(
            choice_handle=handle,
            choice_observation_id=secrets.token_hex(32),
            setup_session_id=policy.setup_session_id,
            transaction_handle=policy.transaction_handle,
            plan_sha256=policy.plan_sha256,
            prepared_generation_id=policy.prepared_generation_id,
            prepared_generation_digest=policy.prepared_generation_digest,
            principal_selection_handle=policy.principal_selection_handle,
            principal_binding_sha256=policy.principal_binding_sha256,
            namespace_selection_handle=policy.namespace_selection_handle,
            namespace_binding_sha256=policy.namespace_binding_sha256,
            principal_id=identity.principal.principal_id,
            profile_id=targets[0].profile_id,
            namespace_id=identity.namespace.namespace_id,
            profile_generation=targets[0].profile_generation,
            target_selection_handles=tuple(sorted(row[1].selection_handle for row in rows)),
            web_scope_ids=scope_ids,
            scope_payloads=tuple(row[1].scope_payload for row in rows),
            scope_payload_sha256s=tuple(row[1].scope_payload_sha256 for row in rows),
            configuration_observation_handles=tuple(
                row[1].configuration_observation_handle for row in rows),
            configuration_sha256s=tuple(row[1].configuration_sha256 for row in rows),
            target_contract_artifact_ids=tuple(row[1].target_contract_artifact_id for row in rows),
            target_contract_sha256s=tuple(row[1].target_contract_sha256 for row in rows),
            target_contract_source_receipt_handles=tuple(
                row[1].target_contract_source_receipt_handle for row in rows),
            controller_binding_handle=rows[0][2].tty_controller_observation_handle,
            issued_monotonic=now,
            expires_monotonic=min(now + _TTL_SECONDS,
                                  *(target.expires_monotonic for target in targets),
                                  *(config.expires_monotonic for config in configs)),
            revocation_epoch=policy_current.revocation_epoch,
            _issuer_token=_CHOICE_SEAL,
        )
        self._choices[handle] = choice
        try:
            durable = self._session.record_durable_setup_choice(choice)
        except Exception:
            self._choices.pop(handle, None)
            raise PublicWebSelectionDenied("signed durable public web TTY choice could not be retained") from None
        if not isinstance(durable, str) or not durable:
            self._choices.pop(handle, None)
            raise PublicWebSelectionDenied("signed durable public web TTY choice has no selection handle")
        return durable


def _write_tty_prompt(value: str) -> None:
    import os
    os.write(2, value.encode("utf-8"))


def _write_candidate_menu(candidates: tuple[Any, ...]) -> None:
    import os
    rows = []
    for candidate in candidates:
        handle = getattr(candidate, "candidate_handle", None)
        component = getattr(candidate, "component_id", None)
        target = getattr(candidate, "target_id", None)
        if (not isinstance(handle, str) or not handle or not isinstance(component, str)
                or not component or not isinstance(target, str) or not target):
            raise PublicWebSelectionDenied("source-derived candidate lacks finite display identities")
        rows.append(f"  {handle}  {component}  {target}")
    os.write(2, ("\nCurrent source-derived public web targets (no permission yet):\n"
                 + "\n".join(rows) + "\n").encode("utf-8"))


def _tty_controller_digest(proof: Any) -> str:
    return "tty-" + hashlib.sha256(_canonical_json({
        "pid": proof.controller_pid, "start_ticks": proof.controller_start_ticks,
        "uid": proof.controller_uid, "gid": proof.controller_gid,
        "session": proof.session_id, "process_group": proof.process_group_id,
        "device": proof.tty_device, "inode": proof.tty_inode,
        "rdevice": proof.tty_rdevice,
    })).hexdigest()


def _render_exact_input_for_public_review(raw: bytes, digest: str) -> None:
    import os
    # repr(bytes) is bounded, unambiguous, and does not render terminal control
    # sequences from the disclosed input as active terminal commands.
    display = repr(raw)
    os.write(2, ("\nPublic web input review\n"
                 f"SHA-256: {digest}\nBytes: {len(raw)}\n"
                 f"Escaped input: {display}\n"
                 "Type PUBLIC to disclose this exact input to the selected public web scopes; "
                 "blank or any other response denies: ").encode("utf-8"))


def _read_tty_line(fd: int, *, max_bytes: int) -> bytes:
    import os
    result = bytearray()
    while len(result) < max_bytes:
        chunk = os.read(fd, 1)
        if not chunk or chunk in (b"\n", b"\r"):
            break
        result.extend(chunk)
    if len(result) >= max_bytes:
        raise PublicWebSelectionDenied("root TTY response exceeded its bound")
    return bytes(result)
