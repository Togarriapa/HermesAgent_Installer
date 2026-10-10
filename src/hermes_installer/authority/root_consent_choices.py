"""Durable root-terminal choices for private input and automatic memory.

These records are preferences only.  A separate consent registry still joins
each choice to a live input observation or a completed native turn.
"""
from __future__ import annotations

import hmac
import os
import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Mapping

from .root_private_input_consent import _ProtectedStore
from .service import AuthorityService, PrincipalBinding
from .types import AuthorityDenied, canonical_digest

_SEAL = object()
_DOMAIN = "root-tty-consent-choice-v1"


@dataclass(frozen=True, slots=True, repr=False)
class RootPrivateProviderRouteChoice:
    choice_receipt_handle: str
    profile_selection_handle: str
    principal_id: str
    profile_id: str
    namespace_id: str
    profile_generation: str
    provider_route_ids: tuple[str, ...]
    private_recipient_ids: tuple[str, ...]
    additional_metered_budget_usd: float
    policy_revision: str
    policy_selection_sha256: str
    actor_uid: int
    tty_session_id: int
    tty_device: int
    tty_inode: int
    _registry_seal: object = field(repr=False, compare=False)


@dataclass(frozen=True, slots=True, repr=False)
class RootMemoryCaptureRouteChoice:
    choice_receipt_handle: str
    profile_selection_handle: str
    principal_id: str
    profile_id: str
    namespace_id: str
    profile_generation: str
    memory_owner_generation: int
    service_enrollment_id: str
    service_generation: str
    provider: str
    route_ids: tuple[str, ...]
    private_recipient_ids: tuple[str, ...]
    policy_revision: str
    source_selection_digest: str
    actor_uid: int
    tty_session_id: int
    tty_device: int
    tty_inode: int
    _registry_seal: object = field(repr=False, compare=False)


class RootTTYConsentChoiceRegistry:
    """Root-only finite TTY chooser, bound to a committed active authority."""

    def __init__(self, service: AuthorityService, provider_catalog: Any,
                 memory_enrollment_catalog: Any, root_journal: Any, *,
                 monotonic: Any = time.monotonic):
        if (type(service) is not AuthorityService or provider_catalog is None
                or memory_enrollment_catalog is None or not callable(monotonic)):
            raise ValueError("active authority and protected finite catalogs are required")
        from hermes_installer.authority.enrollment import ProtectedEnrollment
        from hermes_installer.authority.provider_runtime_composition import ProviderRuntimeSelection
        if (type(provider_catalog) is not ProviderRuntimeSelection
                or type(memory_enrollment_catalog) is not ProtectedEnrollment
                or service.service_generation_digest != memory_enrollment_catalog.protected_enrollment_digest
                or service.bindings_by_uid != dict(memory_enrollment_catalog.bindings_by_uid)
                or any(service.bindings_by_uid.get(uid) is not binding
                       for uid, binding in memory_enrollment_catalog.bindings_by_uid.items())):
            raise ValueError("provider and memory catalogs must be the exact typed active protected generation")
        self.service = service
        self.provider_catalog = provider_catalog
        self.memory_catalog = memory_enrollment_catalog
        self.monotonic = monotonic
        self._registry_seal = _SEAL
        self._lock = threading.RLock()
        self._store = _ProtectedStore(root_journal, "root-tty-consent-choices", service)
        self._rows = self._store.load()

    def observe_current_profile_selection_from_tty(self) -> str | None:
        """Select a profile from current protected active bindings; blank cancels."""
        from hermes_installer.root_setup import _capture_root_tty_proof, _verify_root_tty_proof
        resolver = getattr(self.service, "resolve_current_active_principal_binding", None)
        if not callable(resolver):
            raise AuthorityDenied("consent.profile", "committed active-profile resolver is unavailable")
        profiles = []
        for profile_id in sorted({b.profile_id for b in self.service.bindings_by_uid.values()
                                  if type(b) is PrincipalBinding}):
            try:
                self._resolve_active(profile_id)
            except AuthorityDenied:
                continue
            profiles.append(profile_id)
        if not profiles:
            raise AuthorityDenied("consent.profile", "there is no active private profile to select")
        proof = _capture_root_tty_proof()
        try:
            _verify_root_tty_proof(proof)
            self._tty_write(proof, "Select the active private profile for consent:\n")
            for index, profile in enumerate(profiles, 1):
                self._tty_write(proof, f"{index}. {profile}\n")
            self._tty_write(proof, "Enter a number, or press Enter for no selection.\n")
            answer = self._tty_read_line(proof, "Profile: ").strip()
            _verify_root_tty_proof(proof)
            if not answer:
                with self._lock:
                    self._rows.clear()
                    self._save()
                return None
            if not answer.isdecimal() or not 1 <= int(answer) <= len(profiles):
                raise AuthorityDenied("consent.profile", "profile choice is outside the finite active list")
            profile_id = profiles[int(answer) - 1]
            binding = self._resolve_active(profile_id)
            handle = secrets.token_urlsafe(32)
            row = self._profile_row(handle, binding, proof)
            with self._lock:
                self._rows["profile"] = row
                self._save()
            return handle
        finally:
            proof.close()

    def current_profile_selection_handle(self, binding: PrincipalBinding) -> str:
        current = self._current_binding(binding)
        row = self._rows.get("profile")
        if not isinstance(row, dict):
            raise AuthorityDenied("consent.profile", "no persistent root TTY profile choice is active")
        self._verify_row(row)
        if (row.get("profile_id") != current.profile_id
                or row.get("principal_id") != current.principal_id
                or row.get("namespace_id") != current.namespace_id
                or row.get("uid") != current.uid
                or row.get("service_generation_digest") != self.service.service_generation_digest
                or row.get("profile_generation") != self.service.profile_generations.get(current.profile_id)):
            raise AuthorityDenied("consent.profile", "root TTY profile choice is stale")
        return str(row["handle"])

    def observe_selected_private_provider_routes(self, profile_selection_handle: str) -> str | None:
        binding, profile = self._selected_profile(profile_selection_handle)
        routes = self._private_routes(binding)
        if not routes:
            raise AuthorityDenied("consent.routes", "no finite private provider routes are available")
        from hermes_installer.root_setup import _capture_root_tty_proof, _verify_root_tty_proof
        proof = _capture_root_tty_proof()
        try:
            selected_ids = self._prompt_ids(proof, "private provider routes", routes)
            if not selected_ids:
                self._clear_choice("private")
                return None
            recipients = tuple(sorted({routes[r].recipient for r in selected_ids}))
            policy_revision = self._policy_revision()
            policy_hash = self._policy_hash(binding, profile, selected_ids)
            handle = secrets.token_urlsafe(32)
            row = self._signed({
                "kind": "private", "handle": handle, "profile_selection_handle": profile_selection_handle,
                "principal_id": binding.principal_id, "profile_id": binding.profile_id,
                "namespace_id": binding.namespace_id, "uid": binding.uid,
                "profile_generation": self.service.profile_generations[binding.profile_id],
                "service_generation_digest": self.service.service_generation_digest,
                "provider_route_ids": list(selected_ids), "private_recipient_ids": list(recipients),
                "additional_metered_budget_usd": 0.0, "policy_revision": policy_revision,
                "policy_selection_sha256": policy_hash, **self._tty_claims(proof),
            })
            with self._lock:
                self._rows["private"] = row
                self._save()
            return handle
        finally:
            proof.close()

    def resolve_private_provider_routes_choice(self, handle: str,
                                               profile_selection_handle: str) -> RootPrivateProviderRouteChoice:
        binding, profile = self._selected_profile(profile_selection_handle)
        row = self._current_choice("private", handle, profile_selection_handle, binding)
        claims = {k: v for k, v in row.items() if k != "signature"}
        return RootPrivateProviderRouteChoice(
            choice_receipt_handle=handle, profile_selection_handle=profile_selection_handle,
            principal_id=binding.principal_id, profile_id=binding.profile_id,
            namespace_id=binding.namespace_id, profile_generation=profile["profile_generation"],
            provider_route_ids=tuple(claims["provider_route_ids"]),
            private_recipient_ids=tuple(claims["private_recipient_ids"]),
            additional_metered_budget_usd=0.0, policy_revision=claims["policy_revision"],
            policy_selection_sha256=claims["policy_selection_sha256"], actor_uid=claims["actor_uid"],
            tty_session_id=claims["tty_session_id"], tty_device=claims["tty_device"],
            tty_inode=claims["tty_inode"], _registry_seal=_SEAL)

    def is_current_private_provider_choice(self, choice: Any) -> bool:
        if type(choice) is not RootPrivateProviderRouteChoice or choice._registry_seal is not _SEAL:
            return False
        try:
            current = self.resolve_private_provider_routes_choice(
                choice.choice_receipt_handle, choice.profile_selection_handle)
            return current == choice
        except (AuthorityDenied, KeyError, TypeError, ValueError):
            return False

    def observe_selected_memory_capture(self, profile_selection_handle: str) -> str | None:
        binding, _profile = self._selected_profile(profile_selection_handle)
        enrollments = self._memory_enrollments(binding)
        if not enrollments:
            raise AuthorityDenied("memory.choice", "no active memory engine is available for this profile")
        from hermes_installer.root_setup import _capture_root_tty_proof, _verify_root_tty_proof
        proof = _capture_root_tty_proof()
        try:
            selected = self._prompt_one(proof, "memory capture engine", enrollments,
                                        lambda e: f"{e.provider} / {e.service_enrollment_id}")
            if selected is None:
                self._clear_choice("memory")
                return None
            route_map = {route_id: route for route_id, route in selected.fixed_route_map.items()
                         if route_id.endswith("-capture")}
            if not route_map:
                self._clear_choice("memory")
                return None
            selected_routes = self._prompt_ids(proof, "capture routes", route_map)
            if not selected_routes:
                self._clear_choice("memory")
                return None
            profile = self._selected_profile(profile_selection_handle)[1]
            recipients = (selected.service_enrollment_id,)
            source_digest = canonical_digest({
                "profile": profile_selection_handle, "memory_owner_generation": selected.memory_owner_generation,
                "service_enrollment_id": selected.service_enrollment_id,
                "service_generation": selected.service_generation, "provider": selected.provider,
                "routes": selected_routes, "recipients": recipients,
            })
            handle = secrets.token_urlsafe(32)
            row = self._signed({
                "kind": "memory", "handle": handle, "profile_selection_handle": profile_selection_handle,
                "principal_id": binding.principal_id, "profile_id": binding.profile_id,
                "namespace_id": binding.namespace_id, "uid": binding.uid,
                "profile_generation": profile["profile_generation"],
                "service_generation_digest": self.service.service_generation_digest,
                "memory_owner_generation": selected.memory_owner_generation,
                "service_enrollment_id": selected.service_enrollment_id,
                "service_generation": selected.service_generation, "provider": selected.provider,
                "route_ids": list(selected_routes), "private_recipient_ids": list(recipients),
                "policy_revision": selected.background_consent_revision,
                "source_selection_digest": source_digest, **self._tty_claims(proof),
            })
            with self._lock:
                self._rows["memory"] = row
                self._save()
            return handle
        finally:
            proof.close()

    def resolve_memory_capture_choice(self, handle: str,
                                      profile_selection_handle: str) -> RootMemoryCaptureRouteChoice:
        binding, profile = self._selected_profile(profile_selection_handle)
        row = self._current_choice("memory", handle, profile_selection_handle, binding)
        selected = self.resolve_current_memory_enrollment(row["service_enrollment_id"])
        return RootMemoryCaptureRouteChoice(
            choice_receipt_handle=handle, profile_selection_handle=profile_selection_handle,
            principal_id=binding.principal_id, profile_id=binding.profile_id,
            namespace_id=binding.namespace_id, profile_generation=profile["profile_generation"],
            memory_owner_generation=selected.memory_owner_generation,
            service_enrollment_id=selected.service_enrollment_id,
            service_generation=selected.service_generation, provider=selected.provider,
            route_ids=tuple(row["route_ids"]), private_recipient_ids=tuple(row["private_recipient_ids"]),
            policy_revision=row["policy_revision"], source_selection_digest=row["source_selection_digest"],
            actor_uid=row["actor_uid"], tty_session_id=row["tty_session_id"],
            tty_device=row["tty_device"], tty_inode=row["tty_inode"], _registry_seal=_SEAL)

    def is_current_memory_capture_choice(self, choice: Any) -> bool:
        if type(choice) is not RootMemoryCaptureRouteChoice or choice._registry_seal is not _SEAL:
            return False
        try:
            return self.resolve_memory_capture_choice(choice.choice_receipt_handle,
                                                       choice.profile_selection_handle) == choice
        except (AuthorityDenied, KeyError, TypeError, ValueError):
            return False

    def resolve_current_memory_enrollment(self, enrollment_id: str) -> Any:
        from hermes_installer.memory.enrollment import MemoryServiceEnrollment
        matches = [item for item in self.memory_catalog.memory_enrollments.values()
                   if type(item) is MemoryServiceEnrollment and item.service_enrollment_id == enrollment_id]
        if len(matches) != 1:
            raise AuthorityDenied("memory.binding", "memory enrollment is absent or ambiguous")
        item = matches[0]
        if not any(candidate is item for candidate in self.memory_catalog.memory_enrollments.values()):
            raise AuthorityDenied("memory.binding", "memory enrollment is not retained by active protected catalog")
        self._resolve_active(item.profile_id, item.principal_id, item.namespace_identity)
        if self.service.profile_generations.get(item.profile_id) != item.service_generation:
            raise AuthorityDenied("memory.binding", "memory service generation is not current for the active profile")
        return item

    def _current_choice(self, kind: str, handle: str, profile_handle: str,
                        binding: PrincipalBinding) -> dict[str, Any]:
        row = self._rows.get(kind)
        if (not isinstance(row, dict) or row.get("handle") != handle
                or row.get("profile_selection_handle") != profile_handle):
            raise AuthorityDenied("consent.choice", "root TTY choice is absent, replaced, or for another profile")
        self._verify_row(row)
        if (row.get("kind") != kind or row.get("principal_id") != binding.principal_id
                or row.get("profile_id") != binding.profile_id or row.get("namespace_id") != binding.namespace_id
                or row.get("service_generation_digest") != self.service.service_generation_digest
                or row.get("profile_generation") != self.service.profile_generations.get(binding.profile_id)):
            raise AuthorityDenied("consent.choice", "root TTY choice is stale for the current authority generation")
        if kind == "private":
            routes = self._private_routes(binding)
            if (any(r not in routes for r in row.get("provider_route_ids", ()))
                    or tuple(sorted({routes[r].recipient for r in row["provider_route_ids"]}))
                    != tuple(row.get("private_recipient_ids", ()))
                    or row.get("policy_revision") != self._policy_revision()
                    or row.get("policy_selection_sha256") != self._policy_hash(
                        binding, self._rows["profile"], tuple(row["provider_route_ids"]))):
                raise AuthorityDenied("consent.choice", "private route selection or policy changed")
        else:
            enrollment = self.resolve_current_memory_enrollment(row["service_enrollment_id"])
            if (enrollment.profile_id != binding.profile_id or enrollment.principal_id != binding.principal_id
                    or enrollment.memory_owner_generation != row.get("memory_owner_generation")
                    or enrollment.service_generation != row.get("service_generation")
                    or enrollment.provider != row.get("provider")
                    or enrollment.background_consent_revision != row.get("policy_revision")
                    or not set(row.get("route_ids", ())).issubset(enrollment.fixed_route_map)):
                raise AuthorityDenied("consent.choice", "memory engine owner, generation, routes, or policy changed")
        return row

    def _selected_profile(self, handle: str) -> tuple[PrincipalBinding, dict[str, Any]]:
        row = self._rows.get("profile")
        if not isinstance(row, dict) or row.get("handle") != handle:
            raise AuthorityDenied("consent.profile", "root profile TTY choice is absent or replaced")
        self._verify_row(row)
        binding = self._resolve_active(row["profile_id"])
        if (binding.principal_id != row["principal_id"] or binding.namespace_id != row["namespace_id"]
                or binding.uid != row["uid"] or row["service_generation_digest"] != self.service.service_generation_digest
                or row["profile_generation"] != self.service.profile_generations.get(binding.profile_id)):
            raise AuthorityDenied("consent.profile", "selected profile is no longer current")
        return binding, row

    def _profile_row(self, handle: str, binding: PrincipalBinding, proof: Any) -> dict[str, Any]:
        if not isinstance(self.service.service_generation_digest, str):
            raise AuthorityDenied("consent.profile", "active protected generation is unavailable")
        return self._signed({"kind": "profile", "handle": handle, "profile_id": binding.profile_id,
                             "principal_id": binding.principal_id, "namespace_id": binding.namespace_id,
                             "uid": binding.uid, "profile_generation": self.service.profile_generations[binding.profile_id],
                             "service_generation_digest": self.service.service_generation_digest,
                             **self._tty_claims(proof)})

    def _resolve_active(self, profile_id: str, principal_id: str | None = None,
                        namespace_id: str | None = None) -> PrincipalBinding:
        resolver = getattr(self.service, "resolve_current_active_principal_binding", None)
        if not callable(resolver):
            raise AuthorityDenied("consent.profile", "committed active-profile resolver is unavailable")
        binding = resolver(profile_id)
        if (type(binding) is not PrincipalBinding or self.service.bindings_by_uid.get(binding.uid) is not binding
                or binding.profile_id != profile_id
                or principal_id is not None and binding.principal_id != principal_id
                or namespace_id is not None and binding.namespace_id != namespace_id):
            raise AuthorityDenied("consent.profile", "selected profile is not the exact active protected binding")
        return binding

    def _current_binding(self, binding: PrincipalBinding) -> PrincipalBinding:
        if type(binding) is not PrincipalBinding:
            raise AuthorityDenied("consent.profile", "typed current PrincipalBinding is required")
        current = self._resolve_active(binding.profile_id, binding.principal_id, binding.namespace_id)
        if current is not binding:
            raise AuthorityDenied("consent.profile", "binding differs from current active protected identity")
        return current

    def _private_routes(self, binding: PrincipalBinding) -> Mapping[str, Any]:
        routes = getattr(self.provider_catalog, "provider_enrollments_by_id", None)
        if not isinstance(routes, Mapping):
            raise AuthorityDenied("consent.routes", "active provider route catalog is unavailable")
        protected = self.memory_catalog.provider_enrollments
        return {key: item for key, item in routes.items()
                if key in protected and self._provider_route_matches_protected(item, protected[key])
                if getattr(item, "principal_id", None) == binding.principal_id
                and "private" in getattr(item, "allowed_sensitivities", ())
                and "public" not in getattr(item, "allowed_sensitivities", ())
                and getattr(item, "additional_metered_fee_usd", None) == 0}

    @staticmethod
    def _provider_route_matches_protected(route: Any, protected: Any) -> bool:
        return (getattr(route, "principal_id", None) == protected.get("principal_id")
                and getattr(route, "target", None) == protected.get("target")
                and getattr(route, "recipient", None) == protected.get("recipient")
                and getattr(route, "credential_ref", None) == protected.get("credential_ref")
                and getattr(route, "credential_scope", None) == protected.get("credential_scope")
                and getattr(route, "models", None) == frozenset(protected.get("models", ()))
                and getattr(route, "allowed_sensitivities", None)
                == frozenset(protected.get("allowed_sensitivities", ()))
                and getattr(route, "additional_metered_fee_usd", None)
                == protected.get("additional_metered_fee_usd", 0.0))

    def _memory_enrollments(self, binding: PrincipalBinding) -> tuple[Any, ...]:
        from hermes_installer.memory.enrollment import MemoryServiceEnrollment
        rows = tuple(item for item in self.memory_catalog.memory_enrollments.values()
                     if type(item) is MemoryServiceEnrollment and item.profile_id == binding.profile_id
                     and item.principal_id == binding.principal_id
                     and item.namespace_identity == binding.namespace_id
                     and item.service_generation == self.service.profile_generations.get(binding.profile_id))
        return tuple(sorted(rows, key=lambda row: row.service_enrollment_id))

    def _prompt_ids(self, proof: Any, label: str, choices: Mapping[str, Any]) -> tuple[str, ...]:
        from hermes_installer.root_setup import _verify_root_tty_proof
        ordered = sorted(choices)
        _verify_root_tty_proof(proof)
        self._tty_write(proof, f"Select {label}; separate multiple numbers with commas, or press Enter for none:\n")
        for index, route_id in enumerate(ordered, 1):
            self._tty_write(proof, f"{index}. {route_id}\n")
        answer = self._tty_read_line(proof, "Selection: ").strip()
        _verify_root_tty_proof(proof)
        if not answer:
            return ()
        try:
            indexes = [int(part.strip()) for part in answer.split(",")]
        except ValueError:
            raise AuthorityDenied("consent.choice", "route choice must use finite displayed numbers") from None
        if not indexes or len(set(indexes)) != len(indexes) or any(i < 1 or i > len(ordered) for i in indexes):
            raise AuthorityDenied("consent.choice", "route choice is outside the finite displayed list")
        return tuple(sorted(ordered[i - 1] for i in indexes))

    def _prompt_one(self, proof: Any, label: str, choices: tuple[Any, ...], display: Any) -> Any | None:
        from hermes_installer.root_setup import _verify_root_tty_proof
        _verify_root_tty_proof(proof)
        self._tty_write(proof, f"Select {label}, or press Enter for none:\n")
        for index, item in enumerate(choices, 1):
            self._tty_write(proof, f"{index}. {display(item)}\n")
        answer = self._tty_read_line(proof, "Selection: ").strip()
        _verify_root_tty_proof(proof)
        if not answer:
            return None
        if not answer.isdecimal() or not 1 <= int(answer) <= len(choices):
            raise AuthorityDenied("consent.choice", "choice is outside the finite displayed list")
        return choices[int(answer) - 1]

    def _policy_hash(self, binding: PrincipalBinding, profile: Mapping[str, Any], routes: tuple[str, ...]) -> str:
        return canonical_digest({"policy_revision": self._policy_revision(),
                                 "service_generation_digest": self.service.service_generation_digest,
                                 "profile_generation": self.service.profile_generations[binding.profile_id],
                                 "principal_id": binding.principal_id, "namespace_id": binding.namespace_id,
                                 "routes": routes, "rules": sorted(
                                     [list(k) + [v.capability, v.operation, v.target, v.recipient]
                                      for k, v in self.service.rules.items()])})

    def _policy_revision(self) -> str:
        resolver = getattr(self.service, "current_authority_policy_revision", None)
        if not callable(resolver):
            raise AuthorityDenied("consent.policy", "current protected policy revision resolver is unavailable")
        revision = resolver()
        if not isinstance(revision, str) or not revision:
            raise AuthorityDenied("consent.policy", "current protected policy revision is unavailable")
        return revision

    @staticmethod
    def _tty_write(proof: Any, text: str) -> None:
        from hermes_installer.root_setup import _verify_root_tty_proof
        _verify_root_tty_proof(proof)
        os.write(2, text.encode("utf-8", errors="strict"))

    @staticmethod
    def _tty_read_line(proof: Any, prompt: str, *, maximum: int = 1024) -> str:
        from hermes_installer.root_setup import _verify_root_tty_proof
        _verify_root_tty_proof(proof)
        os.write(2, prompt.encode("utf-8", errors="strict"))
        result = bytearray()
        while len(result) <= maximum:
            chunk = os.read(proof.stdin_fd, 1)
            if not chunk:
                raise AuthorityDenied("consent.tty", "root controlling terminal closed during consent selection")
            if chunk in {b"\n", b"\r"}:
                break
            result.extend(chunk)
        else:
            raise AuthorityDenied("consent.tty", "root TTY choice exceeds its fixed input bound")
        _verify_root_tty_proof(proof)
        try:
            return result.decode("utf-8", errors="strict")
        except UnicodeError:
            raise AuthorityDenied("consent.tty", "root TTY choice is not valid UTF-8") from None

    @staticmethod
    def _tty_claims(proof: Any) -> dict[str, Any]:
        return {"actor_uid": proof.controller_uid, "actor_gid": proof.controller_gid,
                "controller_pid": proof.controller_pid, "controller_start_ticks": proof.controller_start_ticks,
                "tty_session_id": proof.session_id, "tty_process_group_id": proof.process_group_id,
                "tty_device": proof.tty_device, "tty_inode": proof.tty_inode,
                "tty_rdevice": proof.tty_rdevice, "tty_issued_monotonic": proof.issued_monotonic}

    def _signed(self, row: dict[str, Any]) -> dict[str, Any]:
        row["signature"] = self.service._sign({"domain": _DOMAIN, **row})
        return row

    def _verify_row(self, row: Mapping[str, Any]) -> None:
        unsigned = {k: v for k, v in row.items() if k != "signature"}
        if not hmac.compare_digest(self.service._sign({"domain": _DOMAIN, **unsigned}),
                                   str(row.get("signature", ""))):
            raise AuthorityDenied("consent.choice", "persistent root TTY choice signature is invalid")

    def _clear_choice(self, key: str) -> None:
        with self._lock:
            self._rows.pop(key, None)
            self._save()

    def _save(self) -> None:
        self._store.save(self._rows)
