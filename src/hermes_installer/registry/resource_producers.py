"""Typed inputs for root-owned resource source producers.

These value objects describe observations only. Constructing one does not
authenticate a sender, issue a source receipt, select a profile, or authorize an
effect. Root controller adapters must resolve the active protected enrollment,
verify the live controller/connector identity, and mint the source context.
They are deliberately not worker RPC request types.
"""
from __future__ import annotations

import re
import hashlib
import json
import secrets
import time
from dataclasses import dataclass
from datetime import datetime
from types import MappingProxyType
from typing import Any, Mapping, Sequence


class ResourceObservationError(ValueError):
    """A producer observation is malformed or exceeds its finite input bound."""


@dataclass(frozen=True, slots=True)
class _RetainedWebhookObservation:
    """One-use raw observation retained by the selected root listener.

    Only object identity in ``SelectedWebhookIngress``'s private pending map
    makes this consumable by the issuer.  The opaque handle is a locator, not
    authority; all selected identity is rechecked against the live controller
    proof when the issuer consumes it.
    """

    raw_observation_handle: str
    raw_payload: bytes
    event_id: str
    replay_key_sha256: str
    observed_monotonic: float
    event_data: Mapping[str, Any]
    resource_id: str
    resource_generation: str
    profile_id: str
    backend_id: str
    source_issuer_id: str
    service_generation_digest: str


class _SelectedWebhookSourceProducer:
    """Issuer-registered adapter for exactly one protected webhook route."""

    def __init__(self, ingress: "SelectedWebhookIngress", resource_id: str,
                 selected: Any, enrollment: Any, backend: Any, binding: Any):
        self.ingress = ingress
        self.resource_id = resource_id
        self.selected = selected
        self.enrollment = enrollment
        self.backend = backend
        self.binding = binding

    def consume_verified_raw_observation(self, raw_observation: object,
                                         controller_proof: object) -> _RetainedWebhookObservation:
        return self.ingress._consume_for_source(
            raw_observation, controller_proof, self.resource_id,
            self.selected, self.enrollment, self.backend, self.binding,
        )


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def _freeze_event(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType({key: _freeze_event(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze_event(item) for item in value)
    return value


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
    active root selection. The adapter returns a private one-use raw
    observation; it is not a source receipt and cannot itself admit or
    dispatch a job.
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
                or not re.fullmatch(r"[0-9a-f]{64}", service_generation_digest)):
            raise ResourceObservationError("webhook selection is not from the active service generation")
        if type(expected_uid) is not int or expected_uid != 0:
            raise ResourceObservationError("webhook credential resolution is root-only")
        if not isinstance(job_enrollments, Mapping):
            raise ResourceObservationError("protected resource job enrollments are required")
        if not callable(getattr(bindings, "resolve_resource_credential_binding", None)):
            raise ResourceObservationError("protected resource credential binding resolver is unavailable")
        catalog = getattr(bindings, "enrollment_catalog", None)
        if getattr(catalog, "digest", None) != service_generation_digest:
            raise ResourceObservationError("webhook credential bindings are not from the active service generation")
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
        self._pending_observations: dict[
            int, tuple[_RetainedWebhookObservation, Any, object | None]
        ] = {}
        self._pending_lock = __import__("threading").RLock()
        self._source_producers: dict[str, tuple[Any, object, Any]] = {}
        self._event_issuer: Any | None = None
        self._verifier = WebhookVerifier(replay_store, max_body_bytes=4 * 1024 * 1024,
                                         now=now) if now is not None else WebhookVerifier(
                                             replay_store, max_body_bytes=4 * 1024 * 1024)

    @property
    def routes(self) -> tuple[str, ...]:
        """Fixed active paths for listener construction; never a caller route map."""
        return tuple(sorted(self._routes))

    def accept_request(
        self, method: str, path: str, headers: Sequence[tuple[str, str]], body: bytes,
        *, controller_proof: object | None = None,
    ) -> Any:
        """Authenticate one selected HMAC webhook and retain raw provenance.

        The returned value is an opaque one-use producer observation.  It is
        not a ``SourceReceipt`` and cannot admit a job until passed through the
        attached root issuer and controller registry.
        """
        from .resources_runtime import ResourceRuntimeError, WebhookReceipt

        if method != "POST" or not isinstance(path, str):
            raise ResourceObservationError("webhook method or route is not selected")
        selected_and_enrollment = self._routes.get(path)
        if selected_and_enrollment is None:
            raise ResourceObservationError("webhook route is not selected")
        selected, enrollment = selected_and_enrollment
        backend_ids = {node.backend_enrollment_id for node in enrollment.nodes}
        source_backend_rows = [row for row in enrollment.backends.values()
                               if row.backend_id in backend_ids and row.resource_id == enrollment.resource_id
                               and row.generation == enrollment.generation]
        if len(source_backend_rows) != 1:
            raise ResourceObservationError("selected webhook source backend is ambiguous")
        source_backend = source_backend_rows[0]
        source_producer = self._source_producers.get(enrollment.resource_id)
        if source_producer is not None:
            from ..authority.root_controller_custody import RootIngressControllerProof
            _adapter, _capability, selected_binding = source_producer
            if (type(controller_proof) is not RootIngressControllerProof
                    or controller_proof.revalidate() is not True
                    or controller_proof.controller_role_id != selected_binding.role.id
                    or controller_proof.source_issuer_id != selected_binding.source_issuer.issuer_channel_id
                    or controller_proof.backend_enrollment_id != source_backend.backend_id
                    or controller_proof.resource_generation != enrollment.generation
                    or controller_proof.service_generation_digest != self._service_generation_digest
                    or controller_proof.authority_epoch != selected_binding.authority_epoch
                    or controller_proof.selected_ingress_binding_id != selected_binding.selected_ingress_binding_id):
                raise ResourceObservationError("selected root ingress custody is required before request capture")
        elif controller_proof is not None:
            raise ResourceObservationError("unregistered root ingress custody proof")
        observed_monotonic = time.monotonic()
        if (not isinstance(body, bytes)
                or len(body) > min(1_048_576, enrollment.max_payload_bytes)):
            raise ResourceObservationError("webhook body exceeds the selected root ingress byte bound")
        observation = WebhookRequestObservation.from_headers(
            selected.identity.resource_id, headers, body,
        )
        if (getattr(getattr(self._bindings, "enrollment_catalog", None), "digest", None)
                != self._service_generation_digest
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
            delivery_header = (spec.get("replayProtection") or {}).get("deliveryIdHeader")
            delivery_id = next((value for name, value in observation.headers
                                if isinstance(delivery_header, str)
                                and name.casefold() == delivery_header.casefold()), None)
            if not isinstance(delivery_id, str) or not 1 <= len(delivery_id) <= 256:
                raise ResourceObservationError("selected webhook delivery identity is malformed")
            replay_key = hashlib.sha256(_canonical_json({
                "resource_id": enrollment.resource_id,
                "resource_generation": enrollment.generation,
                "delivery_id": delivery_id,
            })).hexdigest()
            receipt = self._verifier.verify(
                enrollment.resource_id, spec,
                {name: value for name, value in observation.headers},
                observation.body, secret_value.encode("utf-8"), replay_identity=replay_key,
                claim_replay=False,
            )
        except ResourceRuntimeError:
            raise
        except Exception:
            # Never surface protected path, credential metadata, or secret.
            raise ResourceObservationError("selected webhook authentication failed closed") from None
        if not isinstance(receipt, WebhookReceipt):
            raise ResourceObservationError("webhook verifier returned an invalid receipt")
        try:
            event_data = json.loads(
                receipt.body.decode("utf-8"),
                object_pairs_hook=_unique_json_object,
                parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("non-finite number")),
            )
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError):
            raise ResourceObservationError("authenticated webhook payload failed its selected schema") from None
        event_data = self._validate_selected_event_data(selected, enrollment, backend, event_data)
        try:
            if not self._replay_store.claim(
                    enrollment.resource_id, replay_key,
                    receipt.received_at + self._verifier.replay_window_seconds):
                raise ResourceObservationError("duplicate webhook delivery was rejected")
        except ResourceObservationError:
            raise
        except Exception:
            raise ResourceObservationError("webhook replay admission failed closed") from None
        retained = _RetainedWebhookObservation(
            raw_observation_handle=secrets.token_urlsafe(32),
            raw_payload=receipt.body,
            event_id="e" + secrets.token_urlsafe(32),
            replay_key_sha256=replay_key,
            observed_monotonic=observed_monotonic,
            event_data=_freeze_event(event_data),
            resource_id=enrollment.resource_id,
            resource_generation=enrollment.generation,
            profile_id=enrollment.profile_id,
            backend_id=backend.backend_id,
            source_issuer_id=enrollment.source_issuer_channel_id,
            service_generation_digest=self._service_generation_digest,
        )
        with self._pending_lock:
            if len(self._pending_observations) >= 256:
                raise ResourceObservationError("root webhook has too many outstanding observations")
            self._pending_observations[id(retained)] = (retained, receipt, controller_proof)
        return retained

    def attach_event_issuer(self, issuer: Any, selected_ingress_bindings: Mapping[str, Any]) -> Mapping[str, object]:
        """Register one fixed producer per selected route with the root issuer.

        The provided bindings must be the already resolved root-selected
        ingress records. This method never creates role/custody identity.
        """
        from ..authority.root_controller_custody import RootSelectedIngressBinding
        from ..authority.resource_event_issuance import ResourceEventContextIssuer

        register = getattr(issuer, "register_selected_source_producer", None)
        if (type(issuer) is not ResourceEventContextIssuer or not callable(register)
                or not isinstance(selected_ingress_bindings, Mapping)
                or issuer.service.service_generation_digest != self._service_generation_digest):
            raise ResourceObservationError("selected root source issuer is unavailable")
        with self._pending_lock:
            if self._source_producers:
                raise ResourceObservationError("webhook producers are already attached")
            staged: dict[str, tuple[Any, object, Any]] = {}
            for route, (selected, enrollment) in self._routes.items():
                resource_id = enrollment.resource_id
                binding = selected_ingress_bindings.get(resource_id)
                if type(binding) is not RootSelectedIngressBinding:
                    raise ResourceObservationError("selected webhook ingress binding is unavailable")
                backend_ids = {node.backend_enrollment_id for node in enrollment.nodes}
                backends = [row for row in enrollment.backends.values()
                            if row.backend_id in backend_ids and row.resource_id == resource_id
                            and row.generation == enrollment.generation]
                if len(backends) != 1:
                    raise ResourceObservationError("selected webhook source backend is ambiguous")
                backend = backends[0]
                if (binding.backend.backend_id != backend.backend_id
                        or binding.backend.resource_id != backend.resource_id
                        or binding.backend.generation != backend.generation
                        or binding.backend.source_issuer_channel_id != enrollment.source_issuer_channel_id
                        or binding.resource_generation != enrollment.generation
                        or binding.service_generation_digest != self._service_generation_digest
                        or binding.source_issuer.issuer_channel_id != enrollment.source_issuer_channel_id
                        or binding.source_observer.observer_enrollment_id != enrollment.observer_enrollment_id
                        or binding.backend.profile_id != enrollment.profile_id
                        or binding.backend.principal_id != enrollment.principal_id):
                    raise ResourceObservationError("selected webhook ingress binding is stale or mismatched")
                producer = _SelectedWebhookSourceProducer(
                    self, resource_id, selected, enrollment, backend, binding,
                )
                capability = register(producer, selected_ingress_binding=binding)
                staged[resource_id] = (producer, capability, binding)
            self._source_producers = staged
            self._event_issuer = issuer
            return MappingProxyType({key: value[1] for key, value in staged.items()})

    def capture_verified_observation(self, raw_observation: object,
                                     controller_registry: Any) -> Any:
        """Convert a pending HMAC observation to a root-captured event handle."""
        with self._pending_lock:
            pending = self._pending_observations.get(id(raw_observation))
        if pending is None or pending[0] is not raw_observation:
            raise ResourceObservationError("webhook observation is stale or already consumed")
        resource_id = pending[0].resource_id
        attached = self._source_producers.get(resource_id)
        if attached is None:
            raise ResourceObservationError("selected webhook source producer is not attached")
        producer, capability, binding = attached
        issuer = self._event_issuer
        from ..authority.resource_source_controllers import RootResourceControllerRegistry
        if (issuer is None or type(controller_registry) is not RootResourceControllerRegistry
                or controller_registry is not issuer.controller_registry
                or getattr(controller_registry, "_event_issuer", None) is not issuer):
            raise ResourceObservationError("root event issuer is not attached to the registry")
        controller = pending[2]
        if controller is None:
            raise ResourceObservationError("request was not observed under root controller custody")
        proof = issuer.mint_selected_source_proof(
            capability, controller_proof=controller, raw_observation=raw_observation,
        )
        return controller_registry.capture_selected_ingress(controller.proof_handle, proof)

    def _consume_for_source(self, raw_observation: object, controller_proof: object,
                            resource_id: str, selected: Any, enrollment: Any,
                            backend: Any, binding: Any) -> _RetainedWebhookObservation:
        from ..authority.root_controller_custody import RootIngressControllerProof

        if type(controller_proof) is not RootIngressControllerProof:
            raise ResourceObservationError("root controller custody proof is required")
        with self._pending_lock:
            pending = self._pending_observations.pop(id(raw_observation), None)
        if pending is None or pending[0] is not raw_observation:
            raise ResourceObservationError("webhook observation is stale or already consumed")
        value = pending[0]
        if (value.resource_id != resource_id
                or value.resource_generation != enrollment.generation
                or value.profile_id != enrollment.profile_id
                or value.backend_id != backend.backend_id
                or pending[2] is not controller_proof
                or controller_proof.revalidate() is not True
                or controller_proof.controller_role_id != binding.role.id
                or controller_proof.source_issuer_id != binding.source_issuer.issuer_channel_id
                or controller_proof.backend_enrollment_id != backend.backend_id
                or controller_proof.resource_generation != enrollment.generation
                or controller_proof.service_generation_digest != self._service_generation_digest
                or controller_proof.authority_epoch != binding.authority_epoch
                or controller_proof.selected_ingress_binding_id != binding.selected_ingress_binding_id
                or controller_proof.issued_monotonic > value.observed_monotonic
                or controller_proof.expires_monotonic < value.observed_monotonic
                or self._selected_resources.resolve(selected.identity) is not selected
                or self._job_enrollments.get((resource_id, enrollment.generation)) is not enrollment):
            raise ResourceObservationError("webhook observation is outside current root custody")
        return value

    @staticmethod
    def _validate_selected_event_data(selected: Any, enrollment: Any,
                                      backend: Any, value: Any) -> Mapping[str, Any]:
        """Apply the two explicitly reviewed webhook payload schemas.

        Account/repository membership is checked against protected scope data;
        absent or ambiguous scope stays unavailable rather than accepting a
        syntactically valid but unbound event.
        """
        if not isinstance(value, dict):
            raise ResourceObservationError("selected webhook payload must be an object")
        resource_id = enrollment.resource_id
        if resource_id == "github-push":
            repository = value.get("repository")
            if (not isinstance(value.get("ref"), str) or not 1 <= len(value["ref"]) <= 1024
                    or not re.fullmatch(r"[0-9a-f]{40}", value.get("before", ""))
                    or not re.fullmatch(r"[0-9a-f]{40}", value.get("after", ""))
                    or not isinstance(repository, dict)
                    or type(repository.get("id")) is not int or repository["id"] < 1
                    or not isinstance(repository.get("full_name"), str)
                    or not 1 <= len(repository["full_name"]) <= 256):
                raise ResourceObservationError("GitHub push body failed its pinned schema")
            scope = getattr(enrollment, "scope_bindings", {}).get(backend.scope_binding_id)
            fields = getattr(scope, "fixed_fields", None)
            # Field names are part of the protected setup contract. Until the
            # exact account join is present, do not accept an arbitrary repo.
            if not isinstance(fields, Mapping):
                raise ResourceObservationError("selected GitHub repository scope is unavailable")
            expected_id = fields.get("github_repository_id")
            expected_name = fields.get("github_repository_full_name")
            if (type(expected_id) is not int or not isinstance(expected_name, str)
                    or not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}", expected_name)
                    or repository["id"] != expected_id
                    or repository["full_name"] != expected_name):
                raise ResourceObservationError("GitHub push is outside the selected repository")
        elif resource_id == "registry-update-notice":
            if (set(value) != {"repository", "branch", "commit"}
                    or value.get("branch") != "main"
                    or not isinstance(value.get("repository"), str)
                    or not 1 <= len(value["repository"]) <= 512
                    or not re.fullmatch(r"[0-9a-f]{40}", value.get("commit", ""))):
                raise ResourceObservationError("registry notice failed its pinned schema")
            scope = getattr(enrollment, "scope_bindings", {}).get(backend.scope_binding_id)
            fields = getattr(scope, "fixed_fields", None)
            source_repository = fields.get("resources_repository") if isinstance(fields, Mapping) else None
            source_revision = fields.get("resources_revision") if isinstance(fields, Mapping) else None
            if (source_repository != value["repository"]
                    or not isinstance(source_revision, str)
                    or not re.fullmatch(r"[0-9a-f]{40}", source_revision)):
                raise ResourceObservationError("registry notice does not match the selected source lock")
        else:
            raise ResourceObservationError("selected webhook protocol schema is unavailable")
        return value

    @staticmethod
    def selected_protocol_schema(resource_id: str, resource_generation: str,
                                 source_issuer_id: str, source_kind: str,
                                 selected_resources: Any,
                                 job_enrollments: Mapping[tuple[str, str], Any]) -> tuple[str, str]:
        """Resolve the closed protocol schema only from an active exact row."""
        rows = [row for row in selected_resources.rows
                if row.identity.resource_id == resource_id
                and row.generation_digest == resource_generation and row.enabled]
        if len(rows) != 1 or rows[0].identity.kind != "webhooks":
            raise ResourceObservationError("selected webhook protocol row is missing or ambiguous")
        selected = rows[0]
        enrollment = job_enrollments.get((resource_id, resource_generation))
        if (enrollment is None or enrollment.selected_enabled is not True
                or enrollment.source_issuer_channel_id != source_issuer_id
                or enrollment.kind != "webhooks"):
            raise ResourceObservationError("selected webhook source issuer is unavailable")
        if (resource_id, selected.identity.version) == ("github-push", "1.0.1"):
            if source_kind != "webhook-event":
                raise ResourceObservationError("GitHub webhook source kind is mismatched")
            return ("resource-github-push-v1", "3b27135572adf4392f85b0f37a8dcce0e18dbac2aba811462416807c5e4733c8")
        if (resource_id, selected.identity.version) == ("registry-update-notice", "1.0.0"):
            if source_kind != "webhook-event":
                raise ResourceObservationError("registry webhook source kind is mismatched")
            return ("resource-registry-update-notice-v1", "01bdc4055a7675038feb5d61bbf36e345315543e3008d22e0e1c4815edb2c278")
        raise ResourceObservationError("selected webhook protocol schema is not implemented")


def build_selected_webhook_protocol_schema_resolver(
        selected_resources: Any,
        job_enrollments: Mapping[tuple[str, str], Any],
):
    """Return the issuer's exact closed-schema resolver over protected rows.

    The callback accepts identity fields only so the issuer can request its
    fixed catalog join. It never takes a schema ID, digest, or validator from
    the event or producer.
    """
    from .resources_runtime import SelectedResourceRegistry

    if not isinstance(selected_resources, SelectedResourceRegistry):
        raise TypeError("protected selected-resource registry is required")
    rows = MappingProxyType(dict(job_enrollments))

    def resolve(resource_id: str, resource_generation: str,
                source_issuer_id: str, source_kind: str) -> tuple[str, str]:
        return SelectedWebhookIngress.selected_protocol_schema(
            resource_id, resource_generation, source_issuer_id, source_kind,
            selected_resources, rows,
        )

    return resolve

def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object member")
        result[key] = value
    return result


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
