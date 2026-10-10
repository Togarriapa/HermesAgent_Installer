"""Root-owned current projection of the install-time memory service choice.

This selection authorizes only the selected service lifecycle. It is deliberately
separate from ``RootMemoryCaptureConsentRegistry`` and provider-route consent.
The setup TTY registry retains the actual yes/no choice; the active root runtime
catalog projects that same signed observation onto the installed service
generation. A handle alone never establishes currentness.
"""
from __future__ import annotations

import threading
import os
import stat
import time
from dataclasses import dataclass
from typing import Any, Mapping

from .runtime_bindings import RootRuntimeBindings
from ..memory.enrollment import MemoryServiceEnrollment
from ..protected_enrollment import RootJournalSelection
from .types import canonical_digest


class RootMemoryServiceEnablementDenied(PermissionError):
    """The explicit root service choice is absent, stale, or mismatched."""


@dataclass(frozen=True, slots=True, repr=False)
class RootMemoryServiceEnablementSelection:
    """Immutable active projection of one explicit root setup TTY choice."""

    selection_handle: str
    choice_observation_id: str
    principal_id: str
    profile_id: str
    namespace_id: str
    provider: str
    backend_variant: str
    service_enrollment_id: str
    service_generation: str
    memory_owner_generation: int
    start_operation_id: str
    policy_revision: str
    selection_digest: str
    state: str
    revocation_epoch: int
    _registry_seal: object

    def __repr__(self) -> str:
        return "RootMemoryServiceEnablementSelection(<root-private>)"


_SEAL = object()
_FIELDS = frozenset({
    "selection_handle", "choice_observation_id", "principal_id", "profile_id",
    "namespace_id", "provider", "backend_variant", "service_enrollment_id",
    "service_generation", "memory_owner_generation", "start_operation_id",
    "policy_revision", "selection_digest", "state", "revocation_epoch",
})


class RootMemoryServiceEnablementRegistry:
    """Resolve active lifecycle consent from a durable root TTY choice and catalog.

    The setup-choice registry must resolve the same signed choice observation
    retained by active publication. The runtime catalog independently verifies
    the choice-to-enrollment linkage and active generation on every lookup.
    """

    def __init__(self, active_bindings: RootRuntimeBindings,
                 root_setup_choice_registry: Any, root_journal: RootJournalSelection):
        active_digest = _active_digest(active_bindings)
        if (os.geteuid() != 0
                or type(active_bindings) is not RootRuntimeBindings
                or root_setup_choice_registry is None
                or type(root_journal) is not RootJournalSelection
                or active_digest is None
                or root_journal.service_generation_digest != active_digest):
            raise RootMemoryServiceEnablementDenied("active root runtime and matching root journal are required")
        self.bindings = active_bindings
        self.choices = root_setup_choice_registry
        self.journal = root_journal
        self._lock = threading.RLock()
        self._check_journal()

    @classmethod
    def from_root_runtime(cls, active_bindings: RootRuntimeBindings,
                          root_setup_choice_registry: Any,
                          root_journal: RootJournalSelection) -> "RootMemoryServiceEnablementRegistry":
        if type(active_bindings) is not RootRuntimeBindings:
            raise RootMemoryServiceEnablementDenied("verified active RootRuntimeBindings are required")
        return cls(active_bindings, root_setup_choice_registry, root_journal)

    def resolve_selected_enablement(self, memory_enrollment_id: str
                                    ) -> RootMemoryServiceEnablementSelection:
        """Return the current lifecycle-purpose projection for one exact enrollment."""
        if not isinstance(memory_enrollment_id, str) or not memory_enrollment_id:
            raise RootMemoryServiceEnablementDenied("memory enrollment selector is invalid")
        digest = _active_digest(self.bindings)
        if digest is None:
            raise RootMemoryServiceEnablementDenied("active service generation digest is unavailable")
        try:
            self._check_journal()
            enrollment = self.bindings.resolve_memory_enrollment(
                memory_enrollment_id, service_generation_digest=digest)
            if type(enrollment) is not MemoryServiceEnrollment:
                raise RootMemoryServiceEnablementDenied("selected memory enrollment is not typed")
            resolver = getattr(self.bindings,
                               "resolve_current_memory_service_enablement_selection", None)
            if not callable(resolver):
                raise RootMemoryServiceEnablementDenied("active lifecycle selection resolver is unavailable")
            row = resolver(enrollment, service_generation_digest=digest)
            return self._validate_projection(row, enrollment)
        except RootMemoryServiceEnablementDenied:
            raise
        except Exception:
            raise RootMemoryServiceEnablementDenied(
                "current root memory service enablement is unavailable") from None

    def is_current(self, selection: RootMemoryServiceEnablementSelection) -> bool:
        if type(selection) is not RootMemoryServiceEnablementSelection or selection._registry_seal is not _SEAL:
            return False
        try:
            current = self.resolve_selected_enablement(selection.service_enrollment_id)
            return current == selection
        except (RootMemoryServiceEnablementDenied, KeyError, TypeError, ValueError):
            return False

    def revoke_selected_enablement(self, choice_handle: str,
                                   current_authorized_owner_request: Any) -> Any:
        """Forward explicit revocation to the root setup choice owner.

        The lifecycle permission stays disabled if the choice owner, active
        publisher, or owner-request proof cannot resolve the same record.
        """
        revoke = getattr(self.choices, "revoke_memory_service_enablement", None)
        if not callable(revoke):
            raise RootMemoryServiceEnablementDenied("root setup choice revocation is unavailable")
        return revoke(choice_handle, current_authorized_owner_request)

    def _check_journal(self) -> None:
        digest = _active_digest(self.bindings)
        if os.geteuid() != 0 or digest != self.journal.service_generation_digest:
            raise RootMemoryServiceEnablementDenied("root journal belongs to a stale or non-root generation")
        resolver = getattr(self.bindings, "resolve_root_journal", None)
        if not callable(resolver):
            raise RootMemoryServiceEnablementDenied("protected root journal resolver is unavailable")
        try:
            current = resolver(self.journal.root_id,
                               expected_active_generation_digest=digest)
            info = self.journal.path.stat(follow_symlinks=False)
        except Exception:
            raise RootMemoryServiceEnablementDenied("protected root journal is unavailable") from None
        if (current != self.journal or not stat.S_ISDIR(info.st_mode) or info.st_uid != 0
                or stat.S_IMODE(info.st_mode) != 0o700
                or (info.st_dev, info.st_ino) != (self.journal.device, self.journal.inode)):
            raise RootMemoryServiceEnablementDenied("protected root journal identity changed")

    def _validate_projection(self, row: Any,
                             enrollment: MemoryServiceEnrollment
                             ) -> RootMemoryServiceEnablementSelection:
        if not isinstance(row, Mapping) or set(row) != _FIELDS:
            raise RootMemoryServiceEnablementDenied("active lifecycle selection fields differ from v124")
        text_fields = _FIELDS - {"memory_owner_generation", "revocation_epoch", "state"}
        if any(not isinstance(row.get(name), str) or not row[name] for name in text_fields):
            raise RootMemoryServiceEnablementDenied("active lifecycle selection identity is malformed")
        if (type(row["memory_owner_generation"]) is not int or row["memory_owner_generation"] < 1
                or type(row["revocation_epoch"]) is not int or row["revocation_epoch"] < 1
                or row["state"] != "enabled"):
            raise RootMemoryServiceEnablementDenied("memory service lifecycle choice is disabled or revoked")
        lifecycle = enrollment.lifecycle_binding
        if lifecycle is None:
            raise RootMemoryServiceEnablementDenied("selected memory service has no protected start recipe")
        expected = {
            "principal_id": enrollment.principal_id,
            "profile_id": enrollment.profile_id,
            "namespace_id": enrollment.namespace_identity,
            "provider": enrollment.provider,
            "backend_variant": enrollment.backend_variant,
            "service_enrollment_id": enrollment.service_enrollment_id,
            "service_generation": enrollment.service_generation,
            "memory_owner_generation": enrollment.memory_owner_generation,
            "start_operation_id": lifecycle.start_operation_id,
        }
        if any(row.get(key) != value for key, value in expected.items()):
            raise RootMemoryServiceEnablementDenied("lifecycle selection differs from active memory enrollment")
        if (not _valid_digest(row["selection_digest"])
                or not _valid_id(row["choice_observation_id"])
                or not _valid_id(row["selection_handle"])):
            raise RootMemoryServiceEnablementDenied("lifecycle selection digest or TTY observation is invalid")
        digest_claims = {key: value for key, value in row.items() if key != "selection_digest"}
        if canonical_digest(digest_claims) != row["selection_digest"]:
            raise RootMemoryServiceEnablementDenied("lifecycle selection digest does not cover its claims")
        # The active compiler is responsible for verifying the source choice's
        # signed receipt and current index before it exposes the projection.
        # Require that exact source resolver as a second currentness check.
        source_resolver = getattr(self.choices, "resolve_current_memory_service_enablement_choice", None)
        if not callable(source_resolver):
            raise RootMemoryServiceEnablementDenied("retained root TTY service choice resolver is unavailable")
        choice = source_resolver(row["selection_handle"])
        from .root_setup_choices import RootAdoptedMemoryServiceEnablementChoice
        now = time.monotonic()
        if (type(choice) is not RootAdoptedMemoryServiceEnablementChoice
                or choice.selection_handle != row["selection_handle"]
                or not _valid_digest(choice.source_choice_row_sha256)
                or not _valid_digest(choice.choice_payload_sha256)
                or choice.revocation_epoch != row["revocation_epoch"]
                or choice.principal_id != row["principal_id"]
                or choice.profile_id != row["profile_id"]
                or choice.namespace_id != row["namespace_id"]
                or choice.policy_revision != row["policy_revision"]
                or choice.service_generation_digest != _active_digest(self.bindings)
                or choice.issued_monotonic > now
                or choice.expires_monotonic <= now
                or choice.choice_observation_id != row["choice_observation_id"]
                or getattr(choice, "provider", None) != enrollment.provider
                or getattr(choice, "backend_variant", None) != enrollment.backend_variant
                or getattr(choice, "enabled", None) is not True):
            raise RootMemoryServiceEnablementDenied("root TTY service choice is stale or differs from selection")
        return RootMemoryServiceEnablementSelection(**dict(row), _registry_seal=_SEAL)


def _valid_digest(value: Any) -> bool:
    return (isinstance(value, str) and len(value) == 64
            and all(char in "0123456789abcdef" for char in value))


def _valid_id(value: Any) -> bool:
    return (isinstance(value, str) and 1 <= len(value) <= 256
            and value[0].isascii() and value[0].isalnum()
            and all(char.isascii() and (char.isalnum() or char in "_.:-") for char in value))


def _active_digest(bindings: Any) -> str | None:
    digest = getattr(bindings, "service_generation_digest", None)
    if digest is None:
        digest = getattr(getattr(bindings, "enrollment_catalog", None), "digest", None)
    return digest if _valid_digest(digest) else None
