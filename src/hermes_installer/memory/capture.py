"""Root-only bridge from completed native turns to durable memory ingestion.

The caller can select an enrolled memory provider and present a consent handle,
but cannot provide transcript bytes, source labels, or lineage. Those are
resolved from the native turn observer and re-authorized by AuthorityService.
"""
from __future__ import annotations

import hashlib
import re
from typing import Any, Mapping

from hermes_installer.memory.broker import (
    BrokerDenied, BrokerUnavailable, DurableMemoryQueue, MemoryTarget,
)
from hermes_installer.memory.enrollment import MemoryServiceEnrollment


_HANDLE = re.compile(r"[A-Za-z0-9_-]{20,128}\Z", re.ASCII)


class MemoryCaptureUnavailable(RuntimeError):
    """Root whole-turn capture is not composed or currently authorized."""


class RootMemoryCaptureCoordinator:
    """Exact attached coordinator for one-use root-observed turn persistence."""

    def __init__(self, *, service: Any, turn_registry: Any,
                 targets: Mapping[tuple[str, str, str], MemoryTarget],
                 queue: Any, owner_state: Any,
                 expected_active_generation_digest: str):
        try:
            from hermes_installer.authority.native_turn_observation import RootNativeTurnObservationRegistry
        except ImportError:
            raise MemoryCaptureUnavailable("root native turn observation registry is not installed") from None

        if type(turn_registry) is not RootNativeTurnObservationRegistry:
            raise TypeError("root native turn observation registry is required")
        if turn_registry.service is not service:
            raise TypeError("turn registry and capture coordinator must share AuthorityService identity")
        if not isinstance(expected_active_generation_digest, str) or not re.fullmatch(
                r"[0-9a-f]{64}", expected_active_generation_digest):
            raise ValueError("active protected generation digest is required")
        if not callable(owner_state) or not callable(getattr(queue, "enqueue_completed_turn", None)):
            raise TypeError("profiled durable queue and current owner resolver are required")
        selected: dict[str, MemoryTarget] = {}
        for key, target in targets.items():
            if (not isinstance(target, MemoryTarget) or target.enrollment is None
                    or key != (target.profile_id, target.namespace_id, target.provider)):
                raise ValueError("capture targets must be strict active memory enrollments")
            enrollment = target.enrollment
            if enrollment.service_enrollment_id in selected:
                raise ValueError("memory service enrollment ID is ambiguous")
            selected[enrollment.service_enrollment_id] = target
        self.service = service
        self.turn_registry = turn_registry
        self.targets = selected
        self.queue = queue
        self.owner_state = owner_state
        self.expected_active_generation_digest = expected_active_generation_digest

    def capture_completed_turn(self, completed_turn_handle: str, *,
                               selected_memory_enrollment_id: str,
                               background_consent_handle: str) -> str:
        """Persist a selected turn through the registry's reserve/commit path."""
        if (not isinstance(completed_turn_handle, str) or not _HANDLE.fullmatch(completed_turn_handle)
                or not isinstance(background_consent_handle, str)
                or not _HANDLE.fullmatch(background_consent_handle)):
            raise BrokerDenied("opaque completed-turn and consent handles are required")
        target = self.targets.get(selected_memory_enrollment_id)
        if target is None:
            raise BrokerDenied("selected memory enrollment is not active")
        persist = getattr(self.turn_registry, "persist_completed_turn", None)
        if not callable(persist):
            raise MemoryCaptureUnavailable("atomic root turn persistence API is unavailable")
        receipt = persist(
            completed_turn_handle,
            memory_capture_coordinator=self,
            selected_memory_enrollment_id=selected_memory_enrollment_id,
            background_consent_handle=background_consent_handle,
        )
        if not isinstance(receipt, str) or not _HANDLE.fullmatch(receipt):
            raise BrokerUnavailable("turn observer did not return a validated durable memory receipt")
        return receipt

    def persist_observed_turn(self, record: Any, transcript: bytes, *,
                              completed_turn_handle: str,
                              selected_memory_enrollment_id: str,
                              background_consent_handle: str) -> str:
        """Observer-only callback, invoked while its exact row is reserved."""
        from hermes_installer.authority.native_turn_observation import RootCompletedNativeTurn
        from hermes_installer.authority.types import HostContext
        from hermes_installer.authority.service import BackgroundConsent

        if (type(record) is not RootCompletedNativeTurn
                or record.receipt_handle != completed_turn_handle
                or not isinstance(transcript, bytes)
                or not isinstance(background_consent_handle, str)
                or not _HANDLE.fullmatch(background_consent_handle)):
            raise BrokerDenied("reserved root completed-turn observation is invalid")
        target = self.targets.get(selected_memory_enrollment_id)
        if target is None or target.enrollment is None:
            raise BrokerDenied("selected memory enrollment is not active")
        enrollment = target.enrollment
        if (record.profile_id != target.profile_id
                or record.service_generation_digest != self.expected_active_generation_digest
                or record.transcript_size_bytes != len(transcript)
                or record.transcript_sha256 != hashlib.sha256(transcript).hexdigest()):
            raise BrokerDenied("completed turn is stale or differs from the selected profile generation")
        owner, owner_generation = self.owner_state(record.profile_id)
        if owner != target.provider or owner_generation != enrollment.memory_owner_generation:
            raise BrokerDenied("selected memory provider is not the current owner")
        authorize = getattr(self.service, "authorize_completed_memory_turn", None)
        if not callable(authorize):
            raise MemoryCaptureUnavailable("root completed-turn memory authorization is unavailable")
        context, consent = authorize(
            record,
            enrollment=enrollment,
            transcript_sha256=record.transcript_sha256,
            background_consent_handle=background_consent_handle,
            owner_generation=owner_generation,
        )
        if not isinstance(context, HostContext) or type(consent) is not BackgroundConsent:
            raise BrokerDenied("authority did not return typed host context and signed consent")
        return self.queue.enqueue_completed_turn(
            target=target, context=context, completed_turn=record,
            transcript=transcript, consent=consent,
        )
