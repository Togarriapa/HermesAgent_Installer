"""Current owner for the finite active AF_UNIX native worker generation (HI-T182)."""
from __future__ import annotations

import hashlib
import secrets
import time
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Mapping

from .types import AuthorityDenied


@dataclass(frozen=True, slots=True, repr=False)
class RootActiveNetworkGenerationProjection:
    """Short owner-issued current projection; never durable authorization."""

    schema: int
    projection_handle: str
    owner_instance_epoch: str
    boot_epoch: str
    publication_receipt_handle: str
    publication_sha256: str
    selection_sha256: str
    claim_digest: str
    service_generation_digest: str
    installed_deployment_receipt_sha256: str
    installed_closure_manifest_sha256: str
    authority_policy_revision: str
    source_choice_selection_handle: str
    source_choice_signed_record_sha256: str
    source_choice_payload_sha256: str
    source_choice_epoch: int
    source_choice_revocation_epoch: int
    source_adopted_at_unix: float
    source_original_setup_deadline_unix: float
    source_member_receipt_handles: tuple[str, ...]
    network_id: str
    network_row_sha256: str
    process_profile_id: str
    process_profile_row_sha256: str
    profile_generation: str
    enrollment_id: str
    enrollment_row_sha256: str
    principal_binding_sha256: str
    namespace_binding_sha256: str
    root_journal_id: str
    root_journal_device: int
    root_journal_inode: int
    root_journal_generation: str
    issued_monotonic: float
    expires_monotonic: float
    network_record: Mapping[str, Any] = field(repr=False)
    active_record: Mapping[str, Any] = field(repr=False)
    runtime_record: Mapping[str, Any] = field(repr=False)
    _issuer: object = field(repr=False, compare=False)
    _adoption: Any = field(repr=False, compare=False)

    def __repr__(self) -> str:
        return "RootActiveNetworkGenerationProjection(<root-private>)"


class RootActiveNetworkGenerationOwner:
    """Re-resolve publication, source adoption, actor and all row joins per use."""

    def __init__(self, runtime: Any, *, _seal: object):
        from .runtime_composition import RootAuthorityRuntime
        from .installer_release import RootActorObservation, VerifiedInstallerReleaseReceipt
        from .root_setup_choices import RootSetupChoiceRegistry

        service, bindings = getattr(runtime, "service", None), getattr(runtime, "bindings", None)
        release = getattr(runtime, "controller_release_receipt", None)
        actor = getattr(runtime, "controller_actor_observation", None)
        if (_seal is not _OWNER_SEAL or type(runtime) is not RootAuthorityRuntime
                or runtime.service is not service or runtime.bindings is not bindings
                or getattr(service, "root_authority_runtime", None) is not runtime
                or getattr(service, "root_runtime_bindings", None) is not bindings
                or type(release) is not VerifiedInstallerReleaseReceipt
                or type(actor) is not RootActorObservation
                or runtime.enrollment.protected_enrollment_digest != bindings.enrollment_catalog.digest
                or service.service_generation_digest != bindings.enrollment_catalog.digest):
            raise AuthorityDenied("network_generation.runtime", "exact active root runtime custody is unavailable")
        choice_registry = (getattr(runtime, "root_setup_choice_registry", None)
                           or getattr(bindings, "root_setup_choice_registry", None))
        if (type(choice_registry) is not RootSetupChoiceRegistry
                or not getattr(choice_registry, "_runtime_only", False)
                or choice_registry.service is not service
                or choice_registry.release is not release):
            raise AuthorityDenied("network_generation.choice", "current signed-choice/revocation registry is unavailable")
        self._runtime = runtime
        self._release = release
        self._actor = actor
        self._choices = choice_registry
        self._issuer_token = object()
        self._projections: dict[str, RootActiveNetworkGenerationProjection] = {}
        self._closed = False
        self._instance_epoch = secrets.token_hex(24)

    @classmethod
    def from_root_runtime(cls, runtime: Any) -> "RootActiveNetworkGenerationOwner":
        return cls(runtime, _seal=_OWNER_SEAL)

    def resolve_selected_worker(self, network_id: str, profile_id: str
                                ) -> RootActiveNetworkGenerationProjection:
        self._require_live()
        try:
            projection = self._resolve(network_id, profile_id)
        except AuthorityDenied:
            raise
        except Exception:
            raise AuthorityDenied("network_generation.current", "selected worker generation is unavailable") from None
        self._projections[projection.projection_handle] = projection
        return projection

    def verify_current(self, projection: RootActiveNetworkGenerationProjection
                       ) -> RootActiveNetworkGenerationProjection:
        self._require_live()
        if (type(projection) is not RootActiveNetworkGenerationProjection
                or projection._issuer is not self._issuer_token
                or self._projections.get(projection.projection_handle) is not projection):
            raise AuthorityDenied("network_generation.handle", "projection is not a current owner-issued member")
        current = self._resolve(projection.network_id, projection.process_profile_id)
        if not _same_projection_inputs(current, projection):
            self._projections.pop(projection.projection_handle, None)
            raise AuthorityDenied("network_generation.stale", "selected worker generation changed")
        return projection

    def close(self) -> None:
        self._closed = True
        self._projections.clear()

    def _require_live(self) -> None:
        if self._closed:
            raise AuthorityDenied("network_generation.closed", "active network generation owner is closed")
        try:
            self._release.verify_current()
            self._actor.verify_current(self._release)
        except Exception:
            self.close()
            raise AuthorityDenied("network_generation.controller", "current root controller custody is unavailable") from None
        runtime = self._runtime
        if (getattr(runtime.service, "root_authority_runtime", None) is not runtime
                or getattr(runtime.service, "root_runtime_bindings", None) is not runtime.bindings
                or runtime.boot_epoch != runtime.service.authority_epoch
                or runtime.enrollment.protected_enrollment_digest
                != runtime.bindings.enrollment_catalog.digest
                or runtime.service.service_generation_digest != runtime.bindings.enrollment_catalog.digest):
            self.close()
            raise AuthorityDenied("network_generation.runtime", "active root runtime generation changed")

    def _resolve(self, network_id: str, profile_id: str) -> RootActiveNetworkGenerationProjection:
        from .setup_policy_publication import PolicyPublicationReceiptResolver

        self._require_live()
        runtime, bindings = self._runtime, self._runtime.bindings
        try:
            publication = PolicyPublicationReceiptResolver.resolve_current()
            if (publication.state != "active-committed"
                    or publication.service_generation_digest != bindings.enrollment_catalog.digest):
                raise ValueError("current publication differs from loaded service generation")
            network, active, worker_runtime = bindings.enrollment_catalog.resolve_native_worker_generation(
                network_id, profile_id,
                service_generation_digest=bindings.enrollment_catalog.digest,
            )
            adopted = self._choices.resolve_current_adopted_choice(
                active["source_choice_selection_handle"],
                "native-policy-preparation", publication,
            )
            publisher_adoptions = [row for row in publication.choice_adoptions
                                   if row.selection_handle == active["source_choice_selection_handle"]
                                   and row.purpose == "native-policy-preparation"]
            if len(publisher_adoptions) != 1:
                raise ValueError("signed choice has no unique current publisher adoption")
            publisher_adoption = publisher_adoptions[0]
            payload = adopted.choice_payload
            records = payload.get("selected_worker_recipe_records")
            recipe_rows = [row for row in records if isinstance(row, Mapping)
                           and row.get("receipt_handle") == active["recipe_definition_receipt_handle"]
                           and row.get("recipe_sha256") == active["recipe_sha256"]]
            if (len(recipe_rows) != 1
                    or adopted.selection_handle != active["source_choice_selection_handle"]
                    or adopted.signed_record_sha256 != active["source_choice_signed_record_sha256"]
                    or adopted.choice_payload_sha256 != active["source_choice_payload_sha256"]
                    or adopted.choice_epoch != active["source_choice_epoch"]
                    or adopted.revocation_epoch != active["source_choice_revocation_epoch"]
                    or adopted.setup_deadline_unix != active["source_original_setup_deadline_unix"]
                    or publisher_adoption.signed_record_sha256 != adopted.signed_record_sha256
                    or publisher_adoption.choice_payload_sha256 != adopted.choice_payload_sha256
                    or publisher_adoption.choice_epoch != adopted.choice_epoch
                    or publisher_adoption.revocation_epoch != adopted.revocation_epoch
                    or publisher_adoption.setup_deadline_unix != adopted.setup_deadline_unix
                    or publisher_adoption.service_generation_digest != bindings.enrollment_catalog.digest
                    or publisher_adoption.publication_receipt_handle != publication.receipt_handle
                    or publisher_adoption.publication_sha256 != publication.publication_sha256
                    or publisher_adoption.generation_id != publication.generation_id
                    or publisher_adoption.profile_id != active["process_profile_id"]
                    or publisher_adoption.principal_id != active["principal_id"]
                    or publisher_adoption.namespace_id != active["namespace_id"]
                    or publisher_adoption.source_member_receipt_handles
                       != tuple(active["source_member_receipt_handles"])
                    or not publisher_adoption.issued_at_unix
                       <= publisher_adoption.adopted_at_unix
                       <= publisher_adoption.setup_deadline_unix
                    or publisher_adoption.principal_binding_sha256 != active["principal_binding_sha256"]
                    or publisher_adoption.namespace_binding_sha256 != active["namespace_binding_sha256"]
                    or adopted.principal_selection_handle != payload.get("principal_selection_handle")
                    or adopted.namespace_selection_handle != payload.get("namespace_selection_handle")
                    or payload.get("principal_binding_sha256") != active["principal_binding_sha256"]
                    or payload.get("namespace_binding_sha256") != active["namespace_binding_sha256"]
                    or payload.get("service_profile_id") != active["process_profile_id"]
                    or payload.get("service_generation") != active["process_profile_generation"]):
                raise ValueError("signed adopted choice does not bind the selected worker recipe")
            principal = runtime.service.resolve_current_active_principal_binding(profile_id)
            profile = bindings.process_profiles.get(profile_id)
            service = bindings.enrollment_catalog.resolve(
                active["service_enrollment_id"], active["service_generation"])
            if (profile is None or principal.profile_id != profile_id
                    or principal.principal_id != active["principal_id"]
                    or principal.namespace_id != active["namespace_id"]
                    or service.profile_id != profile_id
                    or service.principal_id != principal.principal_id
                    or service.namespace_identity != principal.namespace_id
                    or service.generation != profile.generation
                    or profile.generation != active["process_profile_generation"]):
                raise ValueError("current principal/process/enrollment rows no longer join")
            journal = bindings.resolve_root_journal(
                active["root_journal_id"],
                expected_active_generation_digest=bindings.enrollment_catalog.digest,
            )
            if journal.generation != active["root_journal_generation"]:
                raise ValueError("selected root journal generation changed")
            # Re-read current publication and choice after all catalog/profile joins.
            current = PolicyPublicationReceiptResolver.resolve_current()
            self._choices.resolve_current_adopted_choice(
                active["source_choice_selection_handle"], "native-policy-preparation", current,
            )
            if (current.receipt_handle != publication.receipt_handle
                    or current.publication_sha256 != publication.publication_sha256
                    or current.service_generation_digest != publication.service_generation_digest):
                raise ValueError("active publication changed during projection")
            now = time.monotonic()
            expires = min(now + 30.0, adopted.expires_monotonic)
            if expires <= now:
                raise ValueError("active signed choice lease expired")
            return RootActiveNetworkGenerationProjection(
                schema=1,
                projection_handle=secrets.token_urlsafe(32),
                owner_instance_epoch=self._instance_epoch, boot_epoch=runtime.boot_epoch,
                publication_receipt_handle=publication.receipt_handle,
                publication_sha256=publication.publication_sha256,
                selection_sha256=publication.selection_sha256,
                claim_digest=publication.claim_digest,
                service_generation_digest=bindings.enrollment_catalog.digest,
                installed_deployment_receipt_sha256=self._release.deployment_receipt_sha256,
                installed_closure_manifest_sha256=self._release.closure_manifest_sha256,
                authority_policy_revision=runtime.service.current_authority_policy_revision(),
                source_choice_selection_handle=adopted.selection_handle,
                source_choice_signed_record_sha256=adopted.signed_record_sha256,
                source_choice_payload_sha256=adopted.choice_payload_sha256,
                source_choice_epoch=adopted.choice_epoch,
                source_choice_revocation_epoch=adopted.revocation_epoch,
                source_adopted_at_unix=publisher_adoption.adopted_at_unix,
                source_original_setup_deadline_unix=adopted.setup_deadline_unix,
                source_member_receipt_handles=publisher_adoption.source_member_receipt_handles,
                network_id=network["id"], network_row_sha256=active["network_row_sha256"],
                process_profile_id=profile_id, process_profile_row_sha256=active["process_row_sha256"],
                profile_generation=profile.generation, enrollment_id=service.enrollment_id,
                enrollment_row_sha256=active["service_row_sha256"],
                principal_binding_sha256=active["principal_binding_sha256"],
                namespace_binding_sha256=active["namespace_binding_sha256"],
                root_journal_id=journal.root_id, root_journal_device=journal.device,
                root_journal_inode=journal.inode, root_journal_generation=journal.generation,
                issued_monotonic=now, expires_monotonic=expires,
                network_record=network, active_record=active, runtime_record=worker_runtime,
                _issuer=self._issuer_token, _adoption=adopted,
            )
        except AuthorityDenied:
            raise
        except Exception:
            raise AuthorityDenied("network_generation.current", "selected active network generation is unavailable") from None


def _same_projection_inputs(left: RootActiveNetworkGenerationProjection,
                            right: RootActiveNetworkGenerationProjection) -> bool:
    return (left.owner_instance_epoch == right.owner_instance_epoch
            and left.boot_epoch == right.boot_epoch
            and left.publication_receipt_handle == right.publication_receipt_handle
            and left.publication_sha256 == right.publication_sha256
            and left.selection_sha256 == right.selection_sha256
            and left.claim_digest == right.claim_digest
            and left.installed_deployment_receipt_sha256 == right.installed_deployment_receipt_sha256
            and left.installed_closure_manifest_sha256 == right.installed_closure_manifest_sha256
            and left.authority_policy_revision == right.authority_policy_revision
            and left.source_choice_selection_handle == right.source_choice_selection_handle
            and left.network_id == right.network_id
            and left.process_profile_id == right.process_profile_id
            and left.network_row_sha256 == right.network_row_sha256
            and left.process_profile_row_sha256 == right.process_profile_row_sha256
            and left.enrollment_row_sha256 == right.enrollment_row_sha256
            and left.service_generation_digest == right.service_generation_digest
            and left.source_choice_signed_record_sha256 == right.source_choice_signed_record_sha256
            and left.source_choice_payload_sha256 == right.source_choice_payload_sha256
            and left.source_choice_epoch == right.source_choice_epoch
            and left.source_choice_revocation_epoch == right.source_choice_revocation_epoch
            and left.source_adopted_at_unix == right.source_adopted_at_unix
            and left.source_original_setup_deadline_unix == right.source_original_setup_deadline_unix
            and left.source_member_receipt_handles == right.source_member_receipt_handles
            and left.profile_generation == right.profile_generation
            and left.enrollment_id == right.enrollment_id
            and left.principal_binding_sha256 == right.principal_binding_sha256
            and left.namespace_binding_sha256 == right.namespace_binding_sha256
            and left.root_journal_id == right.root_journal_id
            and left.root_journal_device == right.root_journal_device
            and left.root_journal_inode == right.root_journal_inode
            and left.root_journal_generation == right.root_journal_generation
            and left.network_record == right.network_record
            and left.active_record == right.active_record
            and left.runtime_record == right.runtime_record
            and left.expires_monotonic > time.monotonic())


_OWNER_SEAL = object()
