"""Source-bound loader for the isolated installed qualification authority.

This adapter shares the ordinary enrollment validators, but obtains every byte
through the retained fixture publication and lease.  It has no path override
and never falls back to the production authority/catalog locations.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
import stat
import time
from dataclasses import InitVar, dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any

from hermes_installer.authority import enrollment as _enrollment
from hermes_installer.authority import installed_qualification as _fixture
from hermes_installer.authority import qualification_publication as _publication
from hermes_installer.artifacts import (
    ArtifactCatalog, _artifact_from_record, _package_from_record, _unique_object,
)


_ENROLLMENT_SEAL = object()
_SHA256 = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_ENVELOPE_FIELDS = frozenset({
    "schema", "publication", "authority_sha256", "catalog_sha256",
    "generation_sha256", "signature",
})
_PUBLICATION_FIELDS = frozenset({
    "schema", "publication_receipt_handle", "fixture_selection_handle",
    "fixture_run_id", "authority_root_id", "fixture_generation_id",
    "policy_sha256", "catalog_sha256", "source_recipe_sha256", "key_id",
    "controller_lease_handle", "issued_monotonic", "expires_monotonic",
})
_SESSION_FIELDS = frozenset({
    "schema", "session_handle", "fixture_selection_handle",
    "publication_receipt_handle", "fixture_run_id", "authority_root_id",
    "fixture_generation_id", "source_recipe_sha256", "controller_lease_handle",
    "issued_monotonic", "expires_monotonic",
})
_MEMBERS = {
    "fixture-authority.json": 16 * 1024 * 1024,
    "fixture-policy/generation.json": 16 * 1024 * 1024,
    "fixture-policy/selection.json": 64 * 1024,
    "fixture-session.json": 64 * 1024,
}


class QualificationEnrollmentUnavailable(PermissionError):
    """A fixture publication is absent, stale, or outside its fixed scope."""


@dataclass(frozen=True, slots=True, repr=False)
class RootQualificationEnrollment:
    """Sealed core enrollment plus the exact fixture-local catalog and lease."""

    schema: int
    publication_receipt_handle: str
    fixture_selection_handle: str
    authority_root_id: str
    fixture_run_id: str
    fixture_generation_id: str
    policy_sha256: str
    catalog_sha256: str
    key_id: str
    source_recipe_sha256: str
    controller_lease_handle: str
    issued_monotonic: float
    expires_monotonic: float
    service_generation_digest: str
    _protected_enrollment: _enrollment.ProtectedEnrollment
    _artifact_catalog: ArtifactCatalog
    _lease: _fixture.RootOwnedQualificationFixtureLease
    _publication_receipt: _publication.RootQualificationPublicationReceipt
    _key_observation: _publication.RootQualificationAuthorityKeyObservation
    _publisher: Any
    _historical_session: Any
    _seal: InitVar[object] = None

    def __post_init__(self, _seal: object) -> None:
        if _seal is not _ENROLLMENT_SEAL:
            raise TypeError("qualification enrollment can only be minted by its held loader")
        if (self.schema != 1
                or type(self._protected_enrollment) is not _enrollment.ProtectedEnrollment
                or type(self._artifact_catalog) is not ArtifactCatalog
                or type(self._lease) is not _fixture.RootOwnedQualificationFixtureLease
                or type(self._publication_receipt) is not _publication.RootQualificationPublicationReceipt
                or type(self._key_observation) is not _publication.RootQualificationAuthorityKeyObservation
                or not _SHA256.fullmatch(self.policy_sha256)
                or not _SHA256.fullmatch(self.catalog_sha256)
                or not _SHA256.fullmatch(self.source_recipe_sha256)
                or not _SHA256.fullmatch(self.service_generation_digest)
                or type(self.issued_monotonic) not in (int, float)
                or type(self.expires_monotonic) not in (int, float)
                or not math.isfinite(self.issued_monotonic)
                or not math.isfinite(self.expires_monotonic)
                or self.expires_monotonic <= self.issued_monotonic):
            raise ValueError("qualification enrollment is malformed")

    @property
    def protected_enrollment(self) -> _enrollment.ProtectedEnrollment:
        """The strict, digest-verified core document for fixture composition."""
        self.verify_current()
        return self._protected_enrollment

    @property
    def artifact_catalog(self) -> ArtifactCatalog:
        self.verify_current()
        return self._artifact_catalog

    def verify_current(self) -> bool:
        self._lease.verify_current()
        self._publication_receipt.verify_current()
        self._key_observation.verify_current()
        verify_session = getattr(self._publisher, "verify_historical_session", None)
        if (not callable(verify_session)
                or verify_session(self._lease, self._publication_receipt,
                                  self._historical_session) is not True):
            raise QualificationEnrollmentUnavailable("qualification session is no longer current")
        if time.monotonic() >= self.expires_monotonic:
            raise QualificationEnrollmentUnavailable("qualification enrollment expired")
        if (self._lease.selection.selection_handle != self.fixture_selection_handle
                or self._lease.run_name != self.fixture_run_id
                or self._lease.selection.fixture_generation_id != self.fixture_generation_id
                or self._lease.selection.fixture_profile_id not in self._protected_enrollment.process_profiles
                or self._protected_enrollment.protected_enrollment_digest
                != self.service_generation_digest):
            raise QualificationEnrollmentUnavailable("qualification enrollment no longer joins its held fixture")
        return True

    def __repr__(self) -> str:
        return "RootQualificationEnrollment(<root-private>)"


class _NoFixtureCredentials:
    """Fixture authority has no credential directory or secret resolver."""

    def resolve_reference(self, *_args: Any, **_kwargs: Any) -> str:
        raise QualificationEnrollmentUnavailable("fixture enrollment has no credential resolver")


def load_qualification_enrollment(
    lease: _fixture.RootOwnedQualificationFixtureLease,
    publication_receipt: _publication.RootQualificationPublicationReceipt,
    key_observation: _publication.RootQualificationAuthorityKeyObservation,
    publisher: Any,
) -> RootQualificationEnrollment:
    """Load only the current signed envelope published beneath ``lease``.

    All paths are fixed member names opened by the retained publisher.  A
    caller-provided path, document, catalog, verifier, or signature callback is
    deliberately absent from this API.
    """
    if (type(lease) is not _fixture.RootOwnedQualificationFixtureLease
            or type(publication_receipt) is not _publication.RootQualificationPublicationReceipt
            or type(key_observation) is not _publication.RootQualificationAuthorityKeyObservation):
        raise QualificationEnrollmentUnavailable("qualification enrollment requires sealed root capabilities")
    publisher_type = getattr(_publication, "RootQualificationPolicyPublisher", None)
    if publisher_type is None or type(publisher) is not publisher_type:
        raise QualificationEnrollmentUnavailable("qualification enrollment publisher is not the reviewed root publisher")

    try:
        lease.verify_current()
        publication_receipt.verify_current()
        if publication_receipt._runtime is not publisher:
            raise ValueError("publication belongs to another publisher")
        key_observation.verify_current()
        selection = lease.selection
        if (selection.suite_id != "resource-cron-task-v1"
                or key_observation.fixture_selection_handle != selection.selection_handle
                or key_observation.fixture_run_id != lease.run_name
                or key_observation.authority_root_id != publication_receipt.authority_root_id
                or key_observation.source_recipe_sha256 != selection.fixture_recipe_sha256
                or publication_receipt.fixture_selection_handle != selection.selection_handle
                or publication_receipt.fixture_run_id != lease.run_name
                or publication_receipt.authority_root_id != key_observation.authority_root_id
                or publication_receipt.fixture_generation_id != selection.fixture_generation_id
                or publication_receipt.source_recipe_sha256 != selection.fixture_recipe_sha256
                or publication_receipt.key_id != key_observation.key_id
                or publication_receipt.controller_lease_handle != selection.controller_unit_observation_handle):
            raise ValueError("publication, key and fixture lease identities differ")

        signer = key_observation._registry.resolve_enrollment_signer(key_observation)
        envelope_bytes = _read_member(lease, publication_receipt, "fixture-authority.json")
        generation_bytes = _read_member(lease, publication_receipt, "fixture-policy/generation.json")
        selection_bytes = _read_member(lease, publication_receipt, "fixture-policy/selection.json")
        session_bytes = _read_member(lease, publication_receipt, "fixture-session.json")

        envelope = _decode_canonical(envelope_bytes, "fixture envelope")
        if set(envelope) != _ENVELOPE_FIELDS or type(envelope["schema"]) is not int or envelope["schema"] != 1:
            raise ValueError("qualification envelope fields are invalid")
        publication = envelope["publication"]
        if type(publication) is not dict or set(publication) != _PUBLICATION_FIELDS:
            raise ValueError("qualification publication fields are invalid")
        expected_publication = _receipt_fields(publication_receipt)
        if publication != expected_publication:
            raise ValueError("signed publication differs from the retained publication receipt")
        if (not _SHA256.fullmatch(envelope["authority_sha256"])
                or not _SHA256.fullmatch(envelope["catalog_sha256"])
                or not _SHA256.fullmatch(envelope["generation_sha256"])):
            raise ValueError("qualification envelope digest is malformed")
        if signer.verify_qualification_enrollment(envelope) is not True:
            raise ValueError("qualification envelope signature is invalid")

        generation = _decode_canonical(generation_bytes, "fixture generation")
        if type(generation) is not dict or set(generation) != {"schema", "authority", "catalog"}:
            raise ValueError("fixture generation fields are invalid")
        if type(generation["schema"]) is not int or generation["schema"] != 1:
            raise ValueError("fixture generation schema is unsupported")
        authority, catalog_document = generation["authority"], generation["catalog"]
        authority_bytes, catalog_bytes = _canonical(authority), _canonical(catalog_document)
        authority_sha = hashlib.sha256(authority_bytes).hexdigest()
        catalog_sha = hashlib.sha256(catalog_bytes).hexdigest()
        generation_sha = hashlib.sha256(generation_bytes).hexdigest()
        if (authority_sha != publication_receipt.policy_sha256
                or catalog_sha != publication_receipt.catalog_sha256
                or authority_sha != envelope["authority_sha256"]
                or catalog_sha != envelope["catalog_sha256"]
                or generation_sha != envelope["generation_sha256"]):
            raise ValueError("qualification generation does not match its signed digests")

        selection_pointer = _decode_canonical(selection_bytes, "fixture publication selection")
        expected_pointer = {
            "schema": 1,
            "publication_receipt_handle": publication_receipt.publication_receipt_handle,
            "fixture_generation_id": publication_receipt.fixture_generation_id,
            "policy_sha256": publication_receipt.policy_sha256,
            "catalog_sha256": publication_receipt.catalog_sha256,
        }
        if selection_pointer != expected_pointer:
            raise ValueError("fixture publication selection does not point to this signed generation")
        session = _decode_canonical(session_bytes, "fixture historical session")
        if type(session) is not dict or set(session) != _SESSION_FIELDS:
            raise ValueError("fixture historical session fields are invalid")
        expected_session = _session_from_publication(publication_receipt)
        if any(session.get(key) != value for key, value in expected_session.items()):
            raise ValueError("fixture historical session differs from selected publication")
        verify_session = getattr(publisher, "verify_historical_session", None)
        if not callable(verify_session) or verify_session(lease, publication_receipt, session) is not True:
            raise ValueError("fixture historical session has no matching retained live session")

        artifact_catalog = _parse_artifact_catalog(catalog_document)
        core = _enrollment._parse_protected_enrollment_document(
            authority, vault=_NoFixtureCredentials(),
            artifact_catalog_path=Path("/dev/null"),
            artifact_staging_directory=Path("/dev/null"),
        )
        _verify_fixed_fixture_scope(core, lease, publication_receipt)
        lease.verify_current()
        publication_receipt.verify_current()
        key_observation.verify_current()
        return RootQualificationEnrollment(
            schema=1,
            publication_receipt_handle=publication_receipt.publication_receipt_handle,
            fixture_selection_handle=publication_receipt.fixture_selection_handle,
            authority_root_id=publication_receipt.authority_root_id,
            fixture_run_id=publication_receipt.fixture_run_id,
            fixture_generation_id=publication_receipt.fixture_generation_id,
            policy_sha256=publication_receipt.policy_sha256,
            catalog_sha256=publication_receipt.catalog_sha256,
            key_id=publication_receipt.key_id,
            source_recipe_sha256=publication_receipt.source_recipe_sha256,
            controller_lease_handle=publication_receipt.controller_lease_handle,
            issued_monotonic=publication_receipt.issued_monotonic,
            expires_monotonic=publication_receipt.expires_monotonic,
            service_generation_digest=core.protected_enrollment_digest,
            _protected_enrollment=core,
            _artifact_catalog=artifact_catalog,
            _lease=lease,
            _publication_receipt=publication_receipt,
            _key_observation=key_observation,
            _publisher=publisher,
            _historical_session=MappingProxyType(dict(session)),
            _seal=_ENROLLMENT_SEAL,
        )
    except QualificationEnrollmentUnavailable:
        raise
    except Exception:
        raise QualificationEnrollmentUnavailable("qualification enrollment is malformed, stale, or unowned") from None


def _read_member(lease: _fixture.RootOwnedQualificationFixtureLease,
                 receipt: _publication.RootQualificationPublicationReceipt,
                 name: str) -> bytes:
    maximum = _MEMBERS[name]
    fd = receipt.open_member(name)
    try:
        info = os.fstat(fd)
        root_info = os.fstat(lease.fixture_root_fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
                or info.st_size < 2 or info.st_size > maximum
                or not stat.S_ISDIR(root_info.st_mode) or root_info.st_uid != 0
                or stat.S_IMODE(root_info.st_mode) != 0o700
                or (root_info.st_dev, root_info.st_ino)
                != (lease.fixture_device, lease.fixture_inode)):
            raise ValueError("fixture publication member has unsafe file identity")
        if name.startswith("fixture-policy/"):
            parent = os.open("fixture-policy", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                             dir_fd=lease.fixture_root_fd)
            parent_info = os.fstat(parent)
            if (parent_info.st_uid != 0 or stat.S_IMODE(parent_info.st_mode) != 0o700):
                os.close(parent)
                raise ValueError("fixture policy directory ownership or mode is unsafe")
            relative = name.partition("/")[2]
        else:
            parent, relative = lease.fixture_root_fd, name
        try:
            path_info = os.stat(relative, dir_fd=parent, follow_symlinks=False)
            if (not stat.S_ISREG(path_info.st_mode)
                    or (path_info.st_dev, path_info.st_ino) != (info.st_dev, info.st_ino)):
                raise ValueError("fixture publication member is not its held fixed name")
        finally:
            if parent != lease.fixture_root_fd:
                os.close(parent)
        content = bytearray()
        os.lseek(fd, 0, os.SEEK_SET)
        while len(content) <= maximum:
            chunk = os.read(fd, min(65536, maximum + 1 - len(content)))
            if not chunk:
                break
            content.extend(chunk)
        if len(content) != info.st_size or len(content) > maximum:
            raise ValueError("fixture publication member length changed")
        return bytes(content)
    finally:
        os.close(fd)


def _decode_canonical(raw: bytes, label: str) -> dict[str, Any]:
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object,
                       parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("invalid number")))
    if type(value) is not dict or _canonical(value) != raw:
        raise ValueError(f"{label} is not canonical JSON")
    return value


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _receipt_fields(receipt: _publication.RootQualificationPublicationReceipt) -> dict[str, Any]:
    return {name: getattr(receipt, name) for name in _PUBLICATION_FIELDS}


def _session_from_publication(receipt: _publication.RootQualificationPublicationReceipt) -> dict[str, Any]:
    values = {
        "schema": 1,
        "fixture_selection_handle": receipt.fixture_selection_handle,
        "publication_receipt_handle": receipt.publication_receipt_handle,
        "fixture_run_id": receipt.fixture_run_id,
        "authority_root_id": receipt.authority_root_id,
        "fixture_generation_id": receipt.fixture_generation_id,
        "source_recipe_sha256": receipt.source_recipe_sha256,
        "controller_lease_handle": receipt.controller_lease_handle,
        "issued_monotonic": receipt.issued_monotonic,
        "expires_monotonic": receipt.expires_monotonic,
    }
    return {key: value for key, value in values.items() if key in _SESSION_FIELDS}


def _parse_artifact_catalog(value: Any) -> ArtifactCatalog:
    if type(value) is not dict or set(value) != {"schema", "artifacts", "packages"}:
        raise ValueError("fixture artifact catalog fields are invalid")
    if type(value["schema"]) is not int or value["schema"] != 1:
        raise ValueError("fixture artifact catalog schema is unsupported")
    if not isinstance(value["artifacts"], list) or not isinstance(value["packages"], list):
        raise ValueError("fixture artifact catalog collections are invalid")
    artifacts = tuple(_artifact_from_record(item) for item in value["artifacts"])
    packages = tuple(_package_from_record(item) for item in value["packages"])
    return ArtifactCatalog.from_records(artifacts, packages)


def _verify_fixed_fixture_scope(core: _enrollment.ProtectedEnrollment,
                                lease: _fixture.RootOwnedQualificationFixtureLease,
                                receipt: _publication.RootQualificationPublicationReceipt) -> None:
    selection = lease.selection
    if selection.suite_id != "resource-cron-task-v1":
        raise ValueError("only the fixed resource-cron task fixture is implemented")
    principals = [binding for binding in core.bindings_by_uid.values()
                  if binding.profile_id == selection.fixture_profile_id]
    if (len(core.bindings_by_uid) != 1 or len(core.process_profiles) != 1
            or len(principals) != 1 or principals[0].principal_id != selection.fixture_principal_id
            or principals[0].namespace_id != selection.fixture_namespace_id):
        raise ValueError("fixture authority principal does not match its observed private identity")
    profile = core.process_profiles.get(selection.fixture_profile_id)
    if profile is None or profile.generation != receipt.fixture_generation_id:
        raise ValueError("fixture authority process profile does not match its observed generation")
    if (core.provider_enrollments or core.mcp_services or core.mcp_http_bindings
            or core.memory_enrollments or core.native_bridges or core.delegations
            or core.memory_providers):
        raise ValueError("qualification fixture authority contains an unrelated account or service route")
    if len(core.service_records) != 1:
        raise ValueError("qualification fixture does not have exactly one active service record")
    row = core.service_records[0]
    if (row.get("principal_id") != selection.fixture_principal_id
            or row.get("profile_id") != selection.fixture_profile_id
            or row.get("namespace_identity") != selection.fixture_namespace_id
            or row.get("generation") != receipt.fixture_generation_id
            or set(profile.operation_recipes) != {"hermes-resource-profile-task-v1"}):
        raise ValueError("qualification fixture service row differs from selected identity")
    process_verbs = (
        ("process.start", "hermes-profile-invoke"),
        ("process.status", "hermes-process-control"),
        ("process.read", "hermes-process-control"),
        ("process.write", "hermes-process-control"),
        ("process.stop", "hermes-process-control"),
        ("process.inspect", "hermes-process-control"),
    )
    expected_rules = {
        (capability, operation, profile.operation_targets[operation])
        for operation, capability in process_verbs
    }
    actual_rules = set(core.rules)
    if actual_rules != expected_rules or any(rule.recipient is not None for rule in core.rules.values()):
        raise ValueError("qualification fixture effect rules exceed fixed process operations")
    if (len(core.source_issuers) != 1
            or core.source_issuers[0].issuer_channel_id != "schedule-event"
            or core.source_issuers[0].source_action_ids != ("root-timer-event",)
            or core.source_issuers[0].allowed_parent_channels
            or core.source_issuers[0].private_provider_route_ids
            or core.source_issuers[0].public_web_scope_ids
            or core.source_issuers[0].producer_profile_id != selection.fixture_profile_id
            or core.source_issuers[0].generation != receipt.fixture_generation_id):
        raise ValueError("qualification fixture source issuer exceeds the fixed local timer input")
