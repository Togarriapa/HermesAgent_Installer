"""Typed inputs for root-owned resource source producers.

These value objects describe observations only. Constructing one does not
authenticate a sender, issue a source receipt, select a profile, or authorize an
effect. Root controller adapters must resolve the active protected enrollment,
verify the live controller/connector identity, and mint the source context.
They are deliberately not worker RPC request types.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from types import MappingProxyType
from typing import Any, Mapping, Sequence


class ResourceObservationError(ValueError):
    """A producer observation is malformed or exceeds its finite input bound."""


_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_HEADER = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]{1,128}\Z")


def _identifier(value: object, field: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise ResourceObservationError(f"{field} is invalid")
    return value


def _instant(value: object, field: str) -> datetime:
    if not isinstance(value, str) or len(value) > 64:
        raise ResourceObservationError(f"{field} must be an explicit timezone-aware instant")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise ResourceObservationError(f"{field} must be an explicit timezone-aware instant") from None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ResourceObservationError(f"{field} must be an explicit timezone-aware instant")
    return parsed


@dataclass(frozen=True, slots=True)
class CronTickObservation:
    """A scheduler's due/fired observation, pending root role verification."""

    resource_id: str
    schedule_id: str
    sequence: int
    due_at: str
    fired_at: str

    def __post_init__(self) -> None:
        _identifier(self.resource_id, "cron resource ID")
        _identifier(self.schedule_id, "selected schedule ID")
        if type(self.sequence) is not int or self.sequence < 1:
            raise ResourceObservationError("cron tick sequence must be positive")
        due, fired = _instant(self.due_at, "cron due_at"), _instant(self.fired_at, "cron fired_at")
        if fired < due:
            raise ResourceObservationError("cron fire time cannot precede its due time")


@dataclass(frozen=True, slots=True)
class WebhookRequestObservation:
    """Raw HTTP request values for verification inside root ingress custody."""

    resource_id: str
    headers: tuple[tuple[str, str], ...]
    body: bytes

    def __post_init__(self) -> None:
        _identifier(self.resource_id, "webhook resource ID")
        if (not isinstance(self.headers, tuple) or len(self.headers) > 128
                or any(not isinstance(row, tuple) or len(row) != 2 for row in self.headers)):
            raise ResourceObservationError("webhook headers must be a bounded immutable sequence")
        seen: set[str] = set()
        for name, value in self.headers:
            if (not isinstance(name, str) or not _HEADER.fullmatch(name)
                    or not isinstance(value, str) or len(value) > 16_384
                    or any(ord(char) < 0x20 and char != "\t" for char in value)
                    or any(ord(char) == 0x7f for char in value)):
                raise ResourceObservationError("webhook header is malformed")
            normalized = name.casefold()
            if normalized in seen:
                raise ResourceObservationError("duplicate webhook header names are rejected")
            seen.add(normalized)
        if not isinstance(self.body, bytes) or len(self.body) > 4 * 1024 * 1024:
            raise ResourceObservationError("webhook body exceeds the root ingress bound")

    @classmethod
    def from_headers(cls, resource_id: str, headers: Sequence[tuple[str, str]], body: bytes) -> "WebhookRequestObservation":
        if not isinstance(headers, (tuple, list)):
            raise ResourceObservationError("webhook headers must be an ordered sequence")
        return cls(resource_id, tuple(headers), body)


@dataclass(frozen=True, slots=True)
class AuthenticatedChannelIngress:
    """Connector observation values; the type itself is not authentication proof.

    The root source controller must additionally verify that this call came
    from the current selected connector/account process and that the account
    binding matches the protected source issuer. No boolean authentication
    claim is accepted here.
    """

    resource_id: str
    connector_id: str
    account_binding_id: str
    event_id: str
    conversation_id: str
    content: bytes

    def __post_init__(self) -> None:
        for field, value in (
            ("channel resource ID", self.resource_id),
            ("channel connector ID", self.connector_id),
            ("channel account binding ID", self.account_binding_id),
            ("channel event ID", self.event_id),
            ("channel conversation ID", self.conversation_id),
        ):
            _identifier(value, field)
        if not isinstance(self.content, bytes) or not 1 <= len(self.content) <= 1_048_576:
            raise ResourceObservationError("channel content is empty or exceeds the one MiB bound")


class SelectedWebhookIngress:
    """Root-owned fixed-route HMAC verification and durable replay claim.

    The listener supplies only the actual HTTP method, path, ordered headers,
    and bounded body. Resource identity, effective spec, account principal,
    secret reference, and replay identity are all resolved from the immutable
    active root selection. This adapter returns an authenticated receipt only;
    a receipt is not a source receipt and cannot itself admit or dispatch a job.
    """

    def __init__(
        self,
        *,
        selected_resources: Any,
        job_enrollments: Mapping[tuple[str, str], Any],
        bindings: Any,
        credential_vault: Any,
        replay_store: Any,
        service_generation_digest: str,
        expected_uid: int = 0,
        now: Any = None,
    ) -> None:
        from .resources_runtime import SelectedResourceRegistry, WebhookVerifier

        if not isinstance(selected_resources, SelectedResourceRegistry):
            raise TypeError("protected selected-resource registry is required")
        if (not isinstance(service_generation_digest, str)
                or not re.fullmatch(r"[0-9a-f]{64}", service_generation_digest)
                or selected_resources.generation_digest != service_generation_digest):
            raise ResourceObservationError("webhook selection is not from the active service generation")
        if type(expected_uid) is not int or expected_uid != 0:
            raise ResourceObservationError("webhook credential resolution is root-only")
        if not isinstance(job_enrollments, Mapping):
            raise ResourceObservationError("protected resource job enrollments are required")
        if not callable(getattr(bindings, "resolve_resource_credential_binding", None)):
            raise ResourceObservationError("protected resource credential binding resolver is unavailable")
        if not callable(getattr(credential_vault, "resolve_reference", None)):
            raise ResourceObservationError("protected root credential vault is unavailable")
        if not callable(getattr(replay_store, "claim", None)):
            raise ResourceObservationError("durable root-owned webhook replay store is required")

        routes: dict[str, tuple[Any, Any]] = {}
        for selected in selected_resources.rows:
            if selected.identity.kind != "webhooks" or not selected.enabled:
                continue
            enrollment = job_enrollments.get((selected.identity.resource_id, selected.generation_digest))
            if (enrollment is None or enrollment.kind != "webhooks"
                    or enrollment.selected_enabled is not True
                    or enrollment.resource_id != selected.identity.resource_id
                    or enrollment.generation != selected.generation_digest
                    or enrollment.profile_id != selected.profile_id):
                raise ResourceObservationError("selected webhook lacks its exact active job enrollment")
            spec = selected.effective_spec
            authentication = spec.get("authentication")
            if (not isinstance(authentication, Mapping)
                    or authentication.get("type") != "hmac-sha256"):
                # In particular, bearer-only declarations never get routed
                # through this HMAC producer.
                continue
            path, method = spec.get("path"), spec.get("method")
            if (not isinstance(path, str) or not path.startswith("/") or len(path) > 512
                    or "?" in path or "#" in path or "\\" in path
                    or any(part in {"", ".", ".."} for part in path.split("/")[1:])
                    or method != "POST"):
                raise ResourceObservationError("selected webhook route is not a fixed safe POST path")
            if path in routes:
                raise ResourceObservationError("selected webhook path is ambiguous")
            routes[path] = (selected, enrollment)

        self._routes = MappingProxyType(routes)
        self._selected_resources = selected_resources
        self._job_enrollments = MappingProxyType(dict(job_enrollments))
        self._bindings = bindings
        self._vault = credential_vault
        self._service_generation_digest = service_generation_digest
        self._replay_store = replay_store
        self._verifier = WebhookVerifier(replay_store, max_body_bytes=4 * 1024 * 1024,
                                         now=now) if now is not None else WebhookVerifier(
                                             replay_store, max_body_bytes=4 * 1024 * 1024)

    @property
    def routes(self) -> tuple[str, ...]:
        """Fixed active paths for listener construction; never a caller route map."""
        return tuple(sorted(self._routes))

    def accept_request(
        self, method: str, path: str, headers: Sequence[tuple[str, str]], body: bytes,
    ) -> Any:
        """Authenticate one selected HMAC webhook and claim its replay ID."""
        from .resources_runtime import ResourceRuntimeError, WebhookReceipt

        if method != "POST" or not isinstance(path, str):
            raise ResourceObservationError("webhook method or route is not selected")
        selected_and_enrollment = self._routes.get(path)
        if selected_and_enrollment is None:
            raise ResourceObservationError("webhook route is not selected")
        observation = WebhookRequestObservation.from_headers(
            selected_and_enrollment[0].identity.resource_id, headers, body,
        )
        selected, enrollment = selected_and_enrollment
        if (selected.generation_digest != self._service_generation_digest
                or self._selected_resources.resolve(selected.identity) is not selected
                or self._job_enrollments.get((enrollment.resource_id, enrollment.generation)) is not enrollment
                or enrollment.selected_enabled is not True):
            raise ResourceObservationError("webhook selection changed; ingress denied")
        spec = selected.effective_spec
        if spec.get("method") != method or spec.get("path") != path:
            raise ResourceObservationError("webhook route differs from the protected selection")
        secret_template = spec.get("authentication", {}).get("secret")
        if (not isinstance(secret_template, str)
                or not re.fullmatch(r"\$\{[A-Z][A-Z0-9_]{0,95}\}", secret_template)):
            raise ResourceObservationError("selected webhook has no exact protected HMAC placeholder")
        placeholder = secret_template
        node_backend_ids = {node.backend_enrollment_id for node in enrollment.nodes}
        backends = [backend for backend in enrollment.backends.values()
                    if backend.resource_id == enrollment.resource_id
                    and backend.profile_id == enrollment.profile_id
                    and backend.generation == enrollment.generation
                    and backend.observer_enrollment_id == enrollment.observer_enrollment_id
                    and backend.backend_id in node_backend_ids]
        if len(backends) != 1:
            raise ResourceObservationError("webhook HMAC credential binding is absent or ambiguous")
        backend = backends[0]
        binding = self._bindings.resolve_resource_credential_binding(
            backend.backend_id, placeholder, "webhook-hmac-verify",
            profile_id=enrollment.profile_id,
            profile_generation=enrollment.profile_generation,
            resource_id=enrollment.resource_id,
            resource_generation=enrollment.generation,
            observer_enrollment_id=enrollment.observer_enrollment_id,
            service_generation_digest=self._service_generation_digest,
        )
        if getattr(binding, "credential_reference_id", None) not in backend.credential_reference_ids:
            raise ResourceObservationError("webhook HMAC reference is outside the selected backend allowlist")
        try:
            secret_value = self._vault.resolve_reference(
                binding.credential_reference_id, peer_uid=0,
                required_scope="webhook-hmac-verify", principal_id=enrollment.principal_id,
            )
            if not isinstance(secret_value, str):
                raise ValueError("credential vault returned a non-text value")
            receipt = self._verifier.verify(
                enrollment.resource_id, spec,
                {name: value for name, value in observation.headers},
                observation.body, secret_value.encode("utf-8"),
            )
        except ResourceRuntimeError:
            raise
        except Exception:
            # Never surface protected path, credential metadata, or secret.
            raise ResourceObservationError("selected webhook authentication failed closed") from None
        if not isinstance(receipt, WebhookReceipt):
            raise ResourceObservationError("webhook verifier returned an invalid receipt")
        return receipt


def build_selected_webhook_ingress(
    *,
    selected_resources: Any,
    job_enrollments: Mapping[tuple[str, str], Any],
    bindings: Any,
    credential_vault: Any,
    replay_store: Any,
    service_generation_digest: str,
    expected_uid: int = 0,
    now: Any = None,
) -> SelectedWebhookIngress:
    """Root-composition constructor for the selected HMAC ingress adapter."""
    return SelectedWebhookIngress(
        selected_resources=selected_resources,
        job_enrollments=job_enrollments,
        bindings=bindings,
        credential_vault=credential_vault,
        replay_store=replay_store,
        service_generation_digest=service_generation_digest,
        expected_uid=expected_uid,
        now=now,
    )
