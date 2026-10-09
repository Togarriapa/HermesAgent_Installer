"""OpenViking component contract at the recorded upstream source revision."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from hermes_installer.memory.lifecycle import MemoryManager, MemoryRecord, MemoryUnavailable
from hermes_installer.memory.providers import OpenVikingProvider, ProviderStatus


@dataclass(frozen=True, slots=True)
class OpenVikingEvidence:
    doctor: ProviderStatus
    capture_owner: str | None
    profile: str
    namespace: str
    restart_callback_invoked: bool
    native_restart_receipt: None
    target_acceptance: str
    retrieved_record_id: str | None


class OpenVikingComponent:
    component_id = "open-viking"
    source_revision = "e7b2e974b1fb97cd8c6087ff013181ddfec94f77"

    def __init__(self, provider: OpenVikingProvider, manager: MemoryManager):
        self.provider, self.manager = provider, manager

    def doctor(self, context: Any) -> ProviderStatus:
        return self.provider.doctor(context)

    def start_capture(self, profile: str, context: Any) -> None:
        if getattr(context, "profile_id", None) != profile:
            raise PermissionError("profile context does not match selected profile")
        if not self.provider.doctor(context).available:
            raise MemoryUnavailable("supervised OpenViking service is not ready")
        self.manager.select_owner(profile, self.provider.name, context=context)

    def search(self, namespace: str, query: str, context: Any, limit: int = 10) -> list[MemoryRecord]:
        return self.manager.search(self.provider.name, namespace, query, limit, context=context)

    def exercise_restart_retrieval_fixture(self, record: MemoryRecord, *, initial_context: Any,
                                new_context: Callable[[], Any],
                                restart_service: Callable[[], None]) -> OpenVikingEvidence:
        if record.profile != getattr(initial_context, "profile_id", None):
            raise PermissionError("synthetic record profile does not match host context")
        self.manager.ingest(record, context=initial_context)
        restart_service()
        context = new_context()
        if context is initial_context or getattr(context, "trace_id", None) == getattr(initial_context, "trace_id", None):
            raise PermissionError("restart retrieval requires a fresh host context")
        found = self.search(record.namespace, record.text, context, 100)
        status = self.doctor(context)
        match = next((item.id for item in found if item.id == record.id), None)
        return OpenVikingEvidence(status, self.manager.owner_ledger.get_owner(record.profile),
                                  record.profile, record.namespace, True, None,
                                  "pending_supervised_restart_and_native_session_evidence", match)
