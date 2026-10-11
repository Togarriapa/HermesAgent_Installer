"""Current published Jarvis profile homes and one-use task bindings.

The publication row describes durable source/home facts. A live task binding
adds the exact selected task, current service identity and a short held-FD
lease. Neither DTO exposes a host path or directory descriptor to workers.
"""
from __future__ import annotations

import hashlib
import json
import os
import pwd
import re
import secrets
import stat
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Mapping

from .setup_policy_publication import (
    RootPublishedAuthorityCore,
    RootPublishedNativeProfileHomeCrosswalk,
    RootPublishedNativeProfileHomeRow,
)
from .types import AuthorityDenied


_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,255}\Z")
_PROFILE = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}\Z")
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_ROW_FIELDS = (
    "home_binding_id", "source_profile_id", "source_revision", "source_manifest_sha256",
    "role", "native_profile_key", "display_name", "home_selection_handle",
    "materialization_receipt_handle", "mapping_sha256", "home_generation", "principal_id",
    "namespace_id", "runtime_receipt_handle", "runtime_identity_sha256",
    "behavioral_manifest_sha256",
)
_LIVE_FIELDS = (
    "binding_handle", "binding_sha256", "profile_id", "profile_generation", "resource_id",
    "resource_generation", "process_enrollment_id", "process_generation", "authority_epoch",
    "policy_revision", "service_generation_digest", "publication_handle",
    "crosswalk_member_sha256", "source_output_claim_sha256", "home_device", "home_inode",
    "home_owner_uid", "home_owner_gid", "home_mode", "issued_monotonic",
    "expires_monotonic", "principal_uid", "principal_gid",
)
_PUBLIC_FIELDS = _ROW_FIELDS + _LIVE_FIELDS


def _canonical(value: Mapping[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def _text(value: Any, name: str, *, maximum: int = 256) -> None:
    if not isinstance(value, str) or not 1 <= len(value) <= maximum or not _ID.fullmatch(value):
        raise ValueError(f"published native home {name} is malformed")


@dataclass(frozen=True, slots=True, repr=False)
class RootSelectedResourceTaskHomeBinding:
    """One short-lived selected task binding with a retained directory FD."""

    home_binding_id: str
    source_profile_id: str
    source_revision: str
    source_manifest_sha256: str
    role: str
    native_profile_key: str
    display_name: str
    home_selection_handle: str
    materialization_receipt_handle: str
    mapping_sha256: str
    home_generation: str
    principal_id: str
    namespace_id: str
    runtime_receipt_handle: str
    runtime_identity_sha256: str
    behavioral_manifest_sha256: str
    binding_handle: str
    binding_sha256: str
    profile_id: str
    profile_generation: str
    resource_id: str
    resource_generation: str
    process_enrollment_id: str
    process_generation: str
    authority_epoch: str
    policy_revision: str
    service_generation_digest: str
    publication_handle: str
    crosswalk_member_sha256: str
    source_output_claim_sha256: str
    home_device: int
    home_inode: int
    home_owner_uid: int
    home_owner_gid: int
    home_mode: int
    issued_monotonic: float
    expires_monotonic: float
    principal_uid: int
    principal_gid: int
    _home: Any = field(repr=False, compare=False)
    _home_fd: int = field(repr=False, compare=False)
    _runtime: Any = field(repr=False, compare=False)
    _admission_handle: Any = field(repr=False, compare=False)
    _child_admission: Any = field(repr=False, compare=False)
    _task_admission: Any = field(repr=False, compare=False)
    _admitted_source: Any = field(repr=False, compare=False)
    _root_event: Any = field(repr=False, compare=False)
    _controller_evidence: tuple[Any, ...] = field(repr=False, compare=False)
    _node_id: str = field(repr=False, compare=False)
    _selection: Any = field(repr=False, compare=False)
    _issuer: Any = field(repr=False, compare=False)
    _seal: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._seal is not getattr(self._issuer, "_binding_seal", None):
            raise TypeError("selected task home bindings are issued by the current root registry")
        for name in ("home_binding_id", "source_profile_id", "source_revision", "native_profile_key",
                     "display_name", "home_selection_handle", "materialization_receipt_handle",
                     "home_generation", "principal_id", "namespace_id", "runtime_receipt_handle",
                     "binding_handle", "profile_id", "profile_generation", "resource_id",
                     "resource_generation", "process_enrollment_id", "process_generation",
                     "authority_epoch", "policy_revision", "publication_handle"):
            _text(getattr(self, name), name)
        for name in ("source_manifest_sha256", "mapping_sha256", "runtime_identity_sha256",
                     "behavioral_manifest_sha256", "binding_sha256", "service_generation_digest",
                     "crosswalk_member_sha256", "source_output_claim_sha256"):
            if not isinstance(getattr(self, name), str) or not _SHA.fullmatch(getattr(self, name)):
                raise ValueError(f"selected task home {name} is not a SHA-256 digest")
        for name in ("home_device", "home_inode", "home_owner_uid", "home_owner_gid", "home_mode",
                     "principal_uid", "principal_gid"):
            if type(getattr(self, name)) is not int or getattr(self, name) < 0:
                raise ValueError(f"selected task home {name} is malformed")
        if (type(self.issued_monotonic) not in (int, float)
                or type(self.expires_monotonic) not in (int, float)
                or self.expires_monotonic <= self.issued_monotonic
                or self.expires_monotonic - self.issued_monotonic > 30.0):
            raise ValueError("selected task home lease is invalid")
        if type(self._home_fd) is not int or self._home_fd < 0:
            raise ValueError("selected task home must retain its own directory descriptor")

    def public_fields(self) -> dict[str, Any]:
        return {name: getattr(self, name) for name in _PUBLIC_FIELDS}

    def verify_current(self, selection: Any) -> bool:
        return self._issuer.verify_current(self, selection)

    def duplicate_home_fd(self, selection: Any) -> int:
        return self._issuer.duplicate_home_fd(self, selection)

    def __repr__(self) -> str:
        return "RootSelectedResourceTaskHomeBinding(<root-private>)"


class RootNativeProfileTaskHomeRegistry:
    """Resolve current published home rows and mint a binding for one task."""

    def __init__(self, *, core: Any, crosswalk: RootPublishedNativeProfileHomeCrosswalk,
                 owned_profile_home_registry: Any, pm_runtime_registry: Any,
                 principal_namespace_registry: Any, root_journal: Any,
                 resource_job_authority: Any, controller_registry: Any, service: Any,
                 monotonic=time.monotonic):
        from hermes_installer.protected_enrollment import RootJournalSelection

        if (type(core) is not RootPublishedAuthorityCore
                or type(crosswalk) is not RootPublishedNativeProfileHomeCrosswalk
                or crosswalk._core is not core
                or type(root_journal) is not RootJournalSelection
                or root_journal.root_id != "installer-authority-journal-v1"
                or root_journal.service_generation_digest != core.service_generation_digest
                or not callable(getattr(owned_profile_home_registry, "open_current_profile_home", None))
                or not callable(getattr(pm_runtime_registry, "resolve_current_profile_home_runtime", None))
                or not callable(getattr(pm_runtime_registry, "verify_current", None))
                or not callable(getattr(principal_namespace_registry, "resolve_selected_native_principal", None))
                or not callable(getattr(resource_job_authority, "resolve_admitted_task", None))
                or not callable(getattr(resource_job_authority, "resolve_admitted_task_source", None))
                or not callable(getattr(resource_job_authority, "resolve_admitted_task_controller", None))
                or not callable(getattr(principal_namespace_registry, "resolve_root_journal", None))
                or not callable(getattr(service, "_policy_revision", None))
                or not callable(monotonic)):
            raise AuthorityDenied("resource.home_registry", "published task home runtime bindings are incomplete")
        self.core = core
        self.crosswalk = crosswalk
        self.homes = owned_profile_home_registry
        self.pm = pm_runtime_registry
        self.principals = principal_namespace_registry
        self.root_journal = root_journal
        self.jobs = resource_job_authority
        self.controllers = controller_registry
        self.service = service
        self.monotonic = monotonic
        self._binding_seal = object()
        self._lock = threading.RLock()
        self._bindings: dict[str, RootSelectedResourceTaskHomeBinding] = {}

    @classmethod
    def from_published_authority_core(cls, core: Any, owned_profile_home_registry: Any,
                                      pm_runtime_registry: Any,
                                      principal_namespace_registry: Any, root_journal: Any,
                                      resource_job_authority: Any, controller_registry: Any,
                                      service: Any,
                                      *, monotonic=time.monotonic) -> "RootNativeProfileTaskHomeRegistry":
        if type(core) is not RootPublishedAuthorityCore:
            raise AuthorityDenied("resource.home_registry", "current published authority core is required")
        crosswalk = None
        registry = None
        try:
            core.verify_current()
            crosswalk = core.resolve_current_native_profile_home_crosswalk()
            crosswalk.verify_current()
            registry = cls(core=core, crosswalk=crosswalk,
                           owned_profile_home_registry=owned_profile_home_registry,
                           pm_runtime_registry=pm_runtime_registry,
                           principal_namespace_registry=principal_namespace_registry,
                           root_journal=root_journal,
                           resource_job_authority=resource_job_authority,
                           controller_registry=controller_registry, service=service,
                           monotonic=monotonic)
            registry._validate_crosswalk()
            return registry
        except AuthorityDenied:
            if registry is not None:
                registry.close()
            else:
                for component in (crosswalk, core):
                    close = getattr(component, "close", None)
                    if callable(close):
                        try:
                            close()
                        except Exception:
                            pass
            raise
        except Exception:
            if registry is not None:
                registry.close()
            else:
                for component in (crosswalk, core):
                    close = getattr(component, "close", None)
                    if callable(close):
                        try:
                            close()
                        except Exception:
                            pass
            raise AuthorityDenied("resource.home_registry", "current published home crosswalk is unavailable") from None

    def resolve_selected_resource_task_home(
        self, selection: Any, *, admission_handle: Any, node_id: str,
        task_admission: Any, admitted_source: Any,
    ) -> RootSelectedResourceTaskHomeBinding:
        from hermes_installer.registry.resource_jobs import (
            RootAdmittedTask, RootAdmittedTaskSource, RootResourceJobAdmissionHandle,
        )
        from hermes_installer.registry.resource_backends import SelectedResourceProfileTask

        if (type(selection) is not SelectedResourceProfileTask
                or type(admission_handle) is not RootResourceJobAdmissionHandle
                or type(task_admission) is not RootAdmittedTask
                or type(admitted_source) is not RootAdmittedTaskSource
                or not isinstance(node_id, str) or node_id != admission_handle.node_id):
            raise AuthorityDenied("resource.home_binding", "root-selected resource task is required")
        current_controller = None
        try:
            current_task = self.jobs.resolve_admitted_task(admission_handle, node_id)
            current_child = self.jobs.resolve_task_child_admission(admission_handle, node_id)
            root_event = self.jobs._root_event_by_job.get(admission_handle.job_id)
            if root_event is None:
                raise AuthorityDenied("resource.home_binding", "current root task controller event is unavailable")
            with self.jobs._task_handle_lock:
                controller_evidence = self.jobs._resolved_controller_evidence.get(admission_handle.handle_id)
            if (not isinstance(controller_evidence, tuple) or len(controller_evidence) != 12
                    or controller_evidence[1] != root_event.handle
                    or admission_handle.handle_id not in self.jobs._controller_resolved_handles):
                raise AuthorityDenied("resource.home_binding", "the task's consumed controller proof is unavailable")
            current_controller = self.controllers.resolve_for_event(root_event, node_id)
            current = (current_task is task_admission
                       and current_child.admission_id == admission_handle.child_admission_id
                       and self._source_is_current(admission_handle, task_admission, admitted_source)
                       and self.jobs.is_admitted_task_current(task_admission)
                       and current_controller.controller_kind in {
                           "root-scheduler", "root-webhook", "root-channel"}
                       and current_controller.uid == 0
                       and current_controller.controller_profile_id is None
                       and current_controller.source_receipt_id is None
                       and current_controller.service_generation_digest == self.service.service_generation_digest
                       and current_controller.subject_profile_id == admitted_source.profile_id
                       and current_controller.subject_principal_id == admitted_source.principal_id
                       and current_controller.subject_namespace_id == admitted_source.namespace_id
                       and controller_evidence[11] == self.service.authority_epoch
                       and self._controller_matches_evidence(current_controller, controller_evidence))
        except Exception:
            current = False
            if current_controller is not None:
                try:
                    os.close(current_controller.pidfd)
                except OSError:
                    pass
            current_controller = None
        if not current:
            raise AuthorityDenied("resource.home_binding", "selected task admission, source or controller is stale")
        controller_expiry = float(current_controller.expires_monotonic)
        try:
            os.close(current_controller.pidfd)
        except OSError:
            pass
        current_controller = None
        now = self.monotonic()
        limits = [now + 30.0, float(admission_handle.expires_monotonic),
                  float(task_admission.deadline_monotonic), float(admitted_source.expires_monotonic),
                  controller_expiry, float(controller_evidence[9])]
        expiry = min(limits)
        source_profile_id = getattr(selection, "source_profile_id", None)
        if not isinstance(source_profile_id, str) or not _PROFILE.fullmatch(source_profile_id):
            raise AuthorityDenied("resource.home_binding", "selected task has no exact source profile identity")
        crosswalk = self._current_crosswalk()
        try:
            rows = [row for row in crosswalk.rows if row.source_profile_id == source_profile_id]
            if len(rows) != 1:
                raise AuthorityDenied("resource.home_binding", "selected source has no unique active home row")
            row = rows[0]
            crosswalk_facts = (crosswalk.publication_handle, crosswalk.crosswalk_member_sha256,
                               crosswalk.source_output_claim_sha256)
        finally:
            crosswalk.close()
        if (getattr(selection, "home_binding_id", None) != row.home_binding_id
                or getattr(selection, "source_profile_id", None) != row.source_profile_id):
            raise AuthorityDenied("resource.home_binding", "protected selected source/home mapping changed")
        profile_id = getattr(selection, "profile_id", None)
        profile_generation = getattr(selection, "profile_generation", None)
        service_digest = getattr(self.principals, "service_generation_digest", None)
        principal = self.principals.resolve_selected_native_principal(
            profile_id, profile_generation, service_digest,
        )
        managed_profiles = getattr(self.principals, "process_profiles", None)
        if not isinstance(managed_profiles, Mapping):
            managed_profiles = getattr(getattr(self.principals, "process_manager", None),
                                       "profiles", None)
        if not isinstance(managed_profiles, Mapping):
            managed_profiles = getattr(getattr(self.service, "process_effect_handler", None),
                                       "profiles", None)
        managed_profile = (managed_profiles.get(profile_id)
                           if isinstance(managed_profiles, Mapping) else None)
        if (principal.principal_id != selection.principal_id
                or principal.profile_id != profile_id
                or principal.principal_id != row.principal_id
                or principal.namespace_id != row.namespace_id
                or principal.uid <= 0 or principal.gid < 0
                or managed_profile is None
                or managed_profile.profile_id != profile_id
                or managed_profile.generation != profile_generation
                or managed_profile.owner_uid != principal.uid
                or managed_profile.owner_gid != principal.gid
                or not isinstance(managed_profile.service_user, str)):
            raise AuthorityDenied("resource.home_binding", "task home principal or namespace differs from current identity")
        try:
            account = pwd.getpwuid(principal.uid)
        except (KeyError, OSError):
            raise AuthorityDenied("resource.home_binding", "selected task identity is absent from current NSS") from None
        if (account.pw_uid != principal.uid or account.pw_gid != principal.gid
                or account.pw_name != managed_profile.service_user):
            raise AuthorityDenied("resource.home_binding", "selected task NSS identity changed")
        runtime_proof = self._resolve_runtime(row)
        home = None
        home_fd = None
        try:
            home = self.homes.open_current_profile_home(row)
            self._verify_home(home, row, principal.uid, principal.gid)
            home_fd = home.duplicate_home_fd()
            held_info = os.fstat(home_fd)
            if (not stat.S_ISDIR(held_info.st_mode)
                    or (held_info.st_dev, held_info.st_ino, held_info.st_uid, held_info.st_gid,
                        stat.S_IMODE(held_info.st_mode))
                    != (home.device, home.inode, home.owner_uid, home.owner_gid, home.mode)):
                raise AuthorityDenied("resource.home_owner", "per-task home descriptor differs from the verified shared home")
            fields: dict[str, Any] = {**row.to_record()}
            fields.update({
                "binding_handle": secrets.token_urlsafe(32), "binding_sha256": "0" * 64,
                "profile_id": profile_id, "profile_generation": profile_generation,
                "resource_id": selection.resource_id,
                "resource_generation": selection.resource_generation,
                "process_enrollment_id": selection.process_enrollment_id,
                "process_generation": selection.process_generation,
                "authority_epoch": self.service.authority_epoch,
                "policy_revision": self.service._policy_revision(),
                "service_generation_digest": service_digest,
                "publication_handle": crosswalk_facts[0],
                "crosswalk_member_sha256": crosswalk_facts[1],
                "source_output_claim_sha256": crosswalk_facts[2],
                "home_device": home.device, "home_inode": home.inode,
                "home_owner_uid": home.owner_uid, "home_owner_gid": home.owner_gid,
                "home_mode": home.mode, "issued_monotonic": now,
                "expires_monotonic": min(expiry, float(runtime_proof.expires_monotonic)),
                "principal_uid": principal.uid,
                "principal_gid": principal.gid,
            })
            if fields["expires_monotonic"] <= now:
                raise AuthorityDenied("resource.home_runtime", "selected PM runtime proof expired before binding")
            digest_fields = {name: value for name, value in fields.items()
                             if name != "binding_sha256"}
            fields["binding_sha256"] = hashlib.sha256(_canonical(digest_fields)).hexdigest()
            binding = RootSelectedResourceTaskHomeBinding(**fields, _home=home, _home_fd=home_fd,
                                                          _runtime=runtime_proof, _issuer=self,
                                                          _seal=self._binding_seal,
                                                          _admission_handle=admission_handle,
                                                          _child_admission=current_child,
                                                          _task_admission=task_admission,
                                                          _admitted_source=admitted_source,
                                                          _root_event=root_event,
                                                          _controller_evidence=controller_evidence,
                                                          _node_id=node_id, _selection=selection)
            with self._lock:
                self._prune(now)
                if binding.binding_handle in self._bindings:
                    raise AuthorityDenied("resource.home_binding", "selected home binding handle collided")
                self._bindings[binding.binding_handle] = binding
            home = None
            home_fd = None
            runtime_proof = None
            return binding
        finally:
            if home_fd is not None:
                try:
                    os.close(home_fd)
                except OSError:
                    pass
            if "runtime_proof" in locals() and runtime_proof is not None:
                try:
                    runtime_proof.close()
                except Exception:
                    pass
            if current_controller is not None:
                try:
                    os.close(current_controller.pidfd)
                except OSError:
                    pass

    def verify_current(self, binding: RootSelectedResourceTaskHomeBinding, selection: Any) -> bool:
        # The selected-task grant is checked by its enclosing proof at each
        # effect boundary: RootResourceTaskAuthority._is_current validates
        # the consumed grant/nonce/context and then calls this binding verifier;
        # ManagedProcessEffectHandler._root_resource_start_current delegates
        # back to that exact proof from the pre-unit start guard.
        if (type(binding) is not RootSelectedResourceTaskHomeBinding
                or binding._issuer is not self or binding._seal is not self._binding_seal):
            return False
        now = self.monotonic()
        with self._lock:
            if self._bindings.get(binding.binding_handle) is not binding:
                return False
        try:
            if (selection is not binding._selection
                    or now >= binding.expires_monotonic
                    or binding.binding_sha256 != hashlib.sha256(_canonical(
                        {name: value for name, value in binding.public_fields().items()
                         if name != "binding_sha256"})).hexdigest()
                    or binding.profile_id != selection.profile_id
                    or binding.profile_generation != selection.profile_generation
                    or binding.resource_id != selection.resource_id
                    or binding.resource_generation != selection.resource_generation
                    or binding.process_enrollment_id != selection.process_enrollment_id
                    or binding.process_generation != selection.process_generation
                or binding.principal_id != selection.principal_id
                    or binding.service_generation_digest != self.principals.service_generation_digest
                    or binding.authority_epoch != self.service.authority_epoch
                    or binding.policy_revision != self.service._policy_revision()
                or binding.source_profile_id != selection.source_profile_id
                    or binding.home_binding_id != selection.home_binding_id):
                return False
            if not self._task_source_controller_current(binding):
                return False
            crosswalk = self._current_crosswalk()
            try:
                row = next((item for item in crosswalk.rows
                            if item.source_profile_id == binding.source_profile_id), None)
                if (row is None
                        or row.to_record() != {name: getattr(binding, name) for name in _ROW_FIELDS}
                        or crosswalk.publication_handle != binding.publication_handle
                        or crosswalk.crosswalk_member_sha256 != binding.crosswalk_member_sha256
                        or crosswalk.source_output_claim_sha256 != binding.source_output_claim_sha256):
                    return False
            finally:
                crosswalk.close()
            principal = self.principals.resolve_selected_native_principal(
                binding.profile_id, binding.profile_generation, binding.service_generation_digest,
            )
            if (principal.principal_id != binding.principal_id
                    or principal.namespace_id != binding.namespace_id
                    or principal.uid != binding.principal_uid or principal.gid != binding.principal_gid):
                return False
            if (self.pm.verify_current(binding._runtime, row) is not True
                    or binding._runtime.expires_monotonic <= now):
                return False
            self._verify_home(binding._home, row, binding.principal_uid, binding.principal_gid,
                              expected=(binding.home_device, binding.home_inode,
                                        binding.home_owner_uid, binding.home_owner_gid, binding.home_mode))
            held = os.fstat(binding._home_fd)
            if (not stat.S_ISDIR(held.st_mode)
                    or (held.st_dev, held.st_ino, held.st_uid, held.st_gid,
                        stat.S_IMODE(held.st_mode))
                       != (binding.home_device, binding.home_inode, binding.home_owner_uid,
                           binding.home_owner_gid, binding.home_mode)):
                return False
            return True
        except Exception:
            return False

    def _task_source_controller_current(self, binding: RootSelectedResourceTaskHomeBinding) -> bool:
        """Recheck the exact retained task, source closure and controller without consuming them."""
        controller = None
        try:
            handle, node_id = binding._admission_handle, binding._node_id
            if (self.jobs.resolve_admitted_task(handle, node_id) is not binding._task_admission
                    or self.jobs.resolve_task_child_admission(handle, node_id)
                       is not binding._child_admission
                    or not self.jobs.is_admitted_task_current(binding._task_admission)
                    or not self._source_is_current(handle, binding._task_admission,
                                                   binding._admitted_source)
                    or binding._controller_evidence[11] != self.service.authority_epoch
                    or self.jobs._root_event_by_job.get(handle.job_id) is not binding._root_event):
                return False
            with self.jobs._task_handle_lock:
                current_evidence = self.jobs._resolved_controller_evidence.get(handle.handle_id)
                resolved = handle.handle_id in self.jobs._controller_resolved_handles
            if not resolved or current_evidence != binding._controller_evidence:
                return False
            controller = self.controllers.resolve_for_event(binding._root_event, node_id)
            if (not self._controller_matches_evidence(controller, binding._controller_evidence)
                    or controller.subject_profile_id != binding._admitted_source.profile_id
                    or controller.subject_principal_id != binding._admitted_source.principal_id
                    or controller.subject_namespace_id != binding._admitted_source.namespace_id):
                return False
            from dataclasses import replace
            recorded = replace(controller, controller_handle=binding._controller_evidence[0])
            return (self.jobs.is_admitted_task_controller_current(handle, node_id, recorded)
                    and self.jobs.verify_admitted_root_task_controller(
                        handle, binding._task_admission, binding._admitted_source, recorded))
        except Exception:
            return False
        finally:
            if controller is not None:
                try:
                    os.close(controller.pidfd)
                except OSError:
                    pass

    def duplicate_home_fd(self, binding: RootSelectedResourceTaskHomeBinding, selection: Any) -> int:
        if not self.verify_current(binding, selection):
            raise AuthorityDenied("resource.home_binding", "selected task home is stale or foreign")
        try:
            duplicate = os.dup(binding._home_fd)
            info = os.fstat(duplicate)
            if (info.st_dev, info.st_ino) != (binding.home_device, binding.home_inode):
                os.close(duplicate)
                raise OSError("held home descriptor identity changed")
            return duplicate
        except Exception:
            raise AuthorityDenied("resource.home_binding", "held selected task home descriptor is unavailable") from None

    def revoke(self, binding: RootSelectedResourceTaskHomeBinding) -> None:
        with self._lock:
            if self._bindings.pop(binding.binding_handle, None) is binding:
                self._release_binding(binding)

    def close(self) -> None:
        with self._lock:
            bindings = tuple(self._bindings.values())
            self._bindings.clear()
        for binding in bindings:
            self._release_binding(binding)
        errors: list[BaseException] = []
        for component in (self.pm, self.homes, self.crosswalk, self.core):
            close = getattr(component, "close", None)
            if callable(close):
                try:
                    close()
                except BaseException as exc:
                    errors.append(exc)
        if errors:
            raise errors[0]

    def _current_crosswalk(self) -> RootPublishedNativeProfileHomeCrosswalk:
        current_journal = self.principals.resolve_root_journal(
            "installer-authority-journal-v1",
            expected_active_generation_digest=self.core.service_generation_digest,
        )
        if current_journal != self.root_journal:
            raise AuthorityDenied("resource.home_journal", "current root journal selection changed")
        self.core.verify_current()
        current = self.core.resolve_current_native_profile_home_crosswalk()
        try:
            current.verify_current()
            if (current.publication_handle != self.crosswalk.publication_handle
                    or current.crosswalk_member_sha256 != self.crosswalk.crosswalk_member_sha256
                    or current.source_output_claim_sha256 != self.crosswalk.source_output_claim_sha256):
                raise AuthorityDenied("resource.home_crosswalk", "published home crosswalk changed")
            return current
        except BaseException:
            current.close()
            raise

    @staticmethod
    def _controller_matches_evidence(controller: Any, evidence: tuple[Any, ...]) -> bool:
        return bool(
            isinstance(evidence, tuple) and len(evidence) == 12
            and controller.identity == evidence[2]
            and controller.pid == evidence[3]
            and controller.uid == evidence[4]
            and controller.controller_kind == evidence[5]
            and controller.controller_role_artifact_id == evidence[6]
            and controller.controller_role_sha256 == evidence[7]
            and controller.controller_generation == evidence[8]
            and controller.expires_monotonic >= evidence[9]
            and controller.service_generation_digest == evidence[10]
        )

    @staticmethod
    def _release_binding(binding: RootSelectedResourceTaskHomeBinding) -> None:
        try:
            os.close(binding._home_fd)
        except OSError:
            pass
        close = getattr(binding._runtime, "close", None)
        if callable(close):
            try:
                close()
            except Exception:
                pass

    def _source_is_current(self, admission: Any, task: Any, source: Any) -> bool:
        """Revalidate the already-consumed source closure without consuming it again."""
        try:
            with self.jobs._task_handle_lock:
                registered = self.jobs._running_task_handles.get(admission.handle_id)
                context_handle = self.jobs._source_context_handles.get(admission.handle_id)
            if (registered is None or registered[0] is not admission or len(registered) != 4
                    or self.jobs._resolved_task_dtos.get(admission.handle_id) is not task
                    or context_handle != task.source_context_handle
                    or source.source_context_handle != context_handle
                    or source.parent_closure_digest != task.parent_closure_digest
                    or source.expires_monotonic <= self.monotonic()):
                return False
            event = registered[3]
            parent = event.parent_context
            if (parent is None or parent.profile_id != source.profile_id
                    or parent.principal_id != source.principal_id
                    or parent.namespace_id != source.namespace_id
                    or not self.jobs.is_admitted_task_current(task)):
                return False
            self.service._verify_context_signature(parent)
            parent_binding = self.service._binding(parent.uid)
            self.service._assert_current_context(parent, parent_binding, parent.uid)
            from .types import SourceReceipt
            if (len(source.signed_receipt_wires) != len(event.source_receipts)
                    or tuple(sorted(source.signed_receipt_wires))
                    != tuple(sorted(_canonical(item.to_wire()) for item in event.source_receipts))):
                return False
            for raw in source.signed_receipt_wires:
                receipt = SourceReceipt.from_wire(json.loads(raw.decode("ascii")))
                self.service._verify_source_receipt(receipt, parent_binding)
            return True
        except Exception:
            return False

    def _validate_crosswalk(self) -> None:
        rows = self.crosswalk.rows
        ids = [row.source_profile_id for row in rows]
        handles = [row.home_binding_id for row in rows]
        if (len(rows) != 208 or len(set(ids)) != len(ids)
                or len(set(handles)) != len(handles) or "hermes" not in ids
                or ids != sorted(ids)
                or sum(row.role == "jarvis-primary-home" for row in rows) != 1
                or sum(row.role == "resource-delegate-home" for row in rows) != len(rows) - 1):
            raise AuthorityDenied("resource.home_crosswalk", "published home crosswalk rows are incomplete or ambiguous")

    def _resolve_runtime(self, row: RootPublishedNativeProfileHomeRow) -> Any:
        from .durable_pm_runtime import RootVerifiedPublishedProfileHomePMRuntime

        try:
            proof = self.pm.resolve_current_profile_home_runtime(row)
        except Exception:
            raise AuthorityDenied("resource.home_runtime", "selected Hermes PM runtime is stale") from None
        if (type(proof) is not RootVerifiedPublishedProfileHomePMRuntime
                or not isinstance(getattr(proof, "expires_monotonic", None), (int, float))
                or proof.expires_monotonic <= self.monotonic()
                or proof.source_profile_id != row.source_profile_id
                or proof.home_binding_id != row.home_binding_id
                or proof.runtime_identity_sha256 != row.runtime_identity_sha256):
            close = getattr(proof, "close", None)
            if callable(close):
                close()
            raise AuthorityDenied("resource.home_runtime", "selected Hermes PM runtime identity differs")
        return proof

    @staticmethod
    def _verify_home(home: Any, row: RootPublishedNativeProfileHomeRow,
                     uid: int, gid: int, expected: tuple[int, int, int, int, int] | None = None) -> None:
        verifier = getattr(home, "verify_current", None)
        info = getattr(home, "identity", None)
        if not callable(verifier) or verifier(row) is not True or not isinstance(info, Mapping):
            raise AuthorityDenied("resource.home_owner", "selected native home ownership or member readback failed")
        observed = (info.get("device"), info.get("inode"), info.get("owner_uid"),
                    info.get("owner_gid"), info.get("mode"))
        if (any(type(value) is not int or value < 0 for value in observed)
                or observed[2] != uid or observed[3] != gid
                or observed[4] & 0o077 != 0
                or expected is not None and observed != expected):
            raise AuthorityDenied("resource.home_owner", "selected home inode, owner, or mode changed")

    def _prune(self, now: float) -> None:
        for handle, binding in tuple(self._bindings.items()):
            if binding.expires_monotonic <= now:
                self._bindings.pop(handle, None)
                self._release_binding(binding)
