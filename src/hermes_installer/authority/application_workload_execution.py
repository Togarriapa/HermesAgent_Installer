"""Root-owned selected application grants and bounded execution receipts (v104).

This authority is deliberately disjoint from resource tasks, builds and plugin
worker grants. It accepts only root-retained invocation/admission/step records;
workload IDs resolve through the reviewed four-recipe registry.
"""
from __future__ import annotations

import hashlib
import hmac
import http.server
import ipaddress
import json
import math
import os
import secrets
import sqlite3
import stat
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlsplit

from .types import AuthorityDenied, canonical_bytes
from .application_runtime import RootApplicationRunReceipt

_HEX = frozenset("0123456789abcdef")
_OPAQUE = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-")
_ROLES = frozenset({"application-runtime-probe", "application-workload"})
_QUALIFICATION_WORKFLOWS = {
    "qualify-browser-use-v1": ("browser-use", "browser-fixture", frozenset({"fixture_url"})),
    "qualify-graphify-v1": ("graphify", "graphify-code-fixture", frozenset()),
    "qualify-hyperframes-v1": ("hyperframes", "hyperframes-render-fixture", frozenset()),
    "qualify-scrapegraph-v1": ("scrapegraph-ai", "scrapegraph-local-fixture", frozenset()),
}


def _digest(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(c in _HEX for c in value)


def _handle(value: Any) -> bool:
    return isinstance(value, str) and 32 <= len(value) <= 128 and all(c in _OPAQUE for c in value)


def _runtime_preparation_selection_type() -> type:
    """Load the sealed pre-active selection DTO without a module cycle."""
    from .application_source_preparation import RootApplicationRuntimePreparationSelection
    return RootApplicationRuntimePreparationSelection


def _canonical(raw: bytes) -> Mapping[str, Any]:
    if not isinstance(raw, bytes) or not 1 <= len(raw) <= 65536:
        raise AuthorityDenied("application.selection", "selected application payload is outside its bound")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise AuthorityDenied("application.selection", "selected application payload is malformed") from None
    if not isinstance(value, dict) or canonical_bytes(value) != raw:
        raise AuthorityDenied("application.selection", "selected application payload is not canonical JSON")
    return value


def _owned_loopback_url(value: Any) -> bool:
    if not isinstance(value, str) or len(value) > 2048:
        return False
    try:
        parsed = urlsplit(value)
        host = parsed.hostname
        port = parsed.port
        return bool(parsed.scheme == "http" and host is not None and port is not None
            and 1 <= port <= 65535 and parsed.username is None and parsed.password is None
            and not parsed.query and not parsed.fragment
            and (host == "localhost" or ipaddress.ip_address(host).is_loopback))
    except ValueError:
        return False


@dataclass(frozen=True, slots=True)
class RootApplicationExecutionContext:
    schema: int
    context_handle: str
    admission_handle: str
    application_id: str
    workload_id: str
    step_id: str
    sequence: int
    profile_id: str
    profile_generation: str
    principal_id: str
    enrollment_id: str
    operation_id: str
    subject_uid: int
    subject_gid: int
    service_generation_digest: str
    role: str
    operation: str
    capability: str
    target: str
    request_sha256: str
    source_receipt_handle: str
    runtime_receipt_handle: str
    source_closure_sha256: str
    controller_binding_handle: str
    issued_monotonic: float
    expires_monotonic: float
    nonce: str
    signature: str

    def claims(self) -> dict[str, Any]:
        return {name: getattr(self, name) for name in self.__dataclass_fields__ if name != "signature"}

    @property
    def uid(self) -> int: return self.subject_uid
    @property
    def namespace_id(self) -> str: return self.profile_id
    @property
    def monotonic_expires_at(self) -> float: return self.expires_monotonic


@dataclass(frozen=True, slots=True)
class RootApplicationExecutionAuthorization:
    schema: int
    grant_id: str
    context_sha256: str
    admission_handle: str
    operation: str
    capability: str
    target: str
    request_sha256: str
    nonce: str
    issued_monotonic: float
    expires_monotonic: float
    signature: str

    def claims(self) -> dict[str, Any]:
        return {name: getattr(self, name) for name in self.__dataclass_fields__ if name != "signature"}

    @property
    def monotonic_expires_at(self) -> float: return self.expires_monotonic


@dataclass(frozen=True, slots=True)
class RootApplicationStartGrant:
    context: RootApplicationExecutionContext
    authorization: RootApplicationExecutionAuthorization


@dataclass(frozen=True, slots=True)
class VerifiedRootApplicationStart:
    """In-process proof retained by the service after atomic one-use consume."""
    context: RootApplicationExecutionContext
    authorization: RootApplicationExecutionAuthorization
    selected_profile: Any = field(repr=False, compare=False)
    selected_step: Any = field(repr=False, compare=False)
    _issuer: Any = field(repr=False, compare=False)
    _seal: object = field(repr=False, compare=False)
    _nonce: str = field(repr=False, compare=False)


@dataclass(frozen=True, slots=True)
class RootApplicationWorkloadAdmission:
    schema: int
    admission_handle: str
    application_id: str
    workload_id: str
    profile_id: str
    profile_generation: str
    principal_id: str
    service_generation_digest: str
    request_sha256: str
    source_receipt_handles: tuple[str, ...]
    source_closure_sha256: str
    controller_binding_handle: str
    source_receipt_handle: str
    runtime_receipt_handle: str
    operation_recipe_ids: tuple[str, ...]
    max_steps: int
    deadline_monotonic: float
    cancel_epoch: int
    issued_monotonic: float
    expires_monotonic: float
    observed_request_sha256: str = ""
    qualification_request_handle: str = ""


@dataclass(frozen=True, slots=True)
class RootApplicationQualificationRequest:
    schema: int
    request_handle: str
    request_id: str
    purpose: str
    workflow_id: str
    application_id: str
    adapter_id: str
    profile_id: str
    profile_generation: str
    principal_id: str
    namespace_id: str
    enclosing_service_generation_digest: str
    selected_runtime_row_sha256: str
    setup_session_id: str
    controller_binding_handle: str
    source_receipt_handles: tuple[str, ...]
    source_context_digest: str
    canonical_workload_sha256: str
    argument_schema_id: str
    fixture_receipt_handle: str
    issued_monotonic: float
    expires_monotonic: float
    revocation_epoch: int
    runtime_preparation_selection_handle: str = ""
    runtime_probe_receipt_handle: str = ""
    runtime_manifest_sha256: str = ""


@dataclass(frozen=True, slots=True)
class RootApplicationQualificationContext:
    """Root-only live setup/session and fixture evidence, never RPC input."""
    setup_session_id: str
    application_id: str
    adapter_id: str
    profile_id: str
    profile_generation: str
    principal_id: str
    namespace_id: str
    enclosing_service_generation_digest: str
    selected_runtime_row_sha256: str
    controller_binding_handle: str
    source_receipt_handles: tuple[str, ...]
    source_context_digest: str
    argument_schema_id: str
    fixture_receipt_handle: str
    fixture_url: str | None
    observed_request_sha256: str
    revocation_epoch: int
    qualification_choice_handle: str = ""
    source_preparation_selection_handle: str = ""
    prepared_source_receipt_handle: str = ""
    selected_lock_receipt_handle: str = ""
    runtime_preparation_selection_handle: str = ""
    runtime_probe_receipt_handle: str = ""
    namespace_selection_receipt_handle: str = ""
    principal_selection_receipt_handle: str | None = None
    qualification_consent_receipt_handle: str = ""
    source_generation_manifest_sha256: str = ""
    lock_sha256: str = ""
    runtime_manifest_sha256: str = ""


@dataclass(frozen=True, slots=True)
class RootApplicationFixtureReceipt:
    """Receipt for a live, root-owned loopback fixture listener."""
    schema: int
    handle: str
    fixture_id: str
    setup_session_id: str
    controller_binding_handle: str
    service_generation_digest: str
    url: str
    issued_monotonic: float
    expires_monotonic: float


class RootOwnedApplicationFixtureServer:
    """Serve one fixed bounded fixture on an owned IPv4 loopback socket.

    The listener owns its socket and thread and emits a receipt only after the
    socket is listening. It has no URL, content, or bind-address inputs.
    """
    _BODY = (b'<!doctype html><html><head><title>Hermes qualification fixture</title></head>'
             b'<body><p id="proof">ready</p><button id="action" type="button" '
             b'onclick="document.getElementById(\'proof\').textContent=\'interaction-ok\'">'
             b'Run fixture interaction</button></body></html>')

    def __init__(self, *, controllers: Any, monotonic: Any, service_generation_digest: str,
                 ttl_seconds: float = 120.0):
        if (not _digest(service_generation_digest) or not 0 < ttl_seconds <= 300
                or not callable(monotonic)):
            raise ValueError("application fixture server configuration is invalid")
        self._controllers = controllers
        self._clock = monotonic
        self._generation = service_generation_digest
        self._ttl = float(ttl_seconds)
        self._lock = threading.RLock()
        self._server: http.server.ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._receipt: RootApplicationFixtureReceipt | None = None

    def _resolve_controller(self, handle: str) -> Any:
        resolver = getattr(self._controllers, "resolve_binding", None)
        if callable(resolver):
            return resolver(handle)
        resolver = getattr(self._controllers, "resolve_application_controller_binding_by_handle", None)
        return resolver(handle) if callable(resolver) else None

    def _verify_controller(self, binding: Any) -> bool:
        verifier = getattr(self._controllers, "verify_binding", None)
        if callable(verifier):
            return verifier(binding) is True
        verifier = getattr(self._controllers, "verify_application_controller_binding", None)
        return callable(verifier) and verifier(binding) is True

    def start(self, *, setup_session_id: str, controller_binding_handle: str) -> RootApplicationFixtureReceipt:
        if (not isinstance(setup_session_id, str) or not setup_session_id
                or not _handle(controller_binding_handle)):
            raise AuthorityDenied("application.fixture", "fixture requires a live setup session and controller")
        with self._lock:
            if self._receipt is not None:
                raise AuthorityDenied("application.fixture", "fixture listener is one-use")
            binding = self._resolve_controller(controller_binding_handle)
            if binding is None or not self._verify_controller(binding):
                raise AuthorityDenied("application.fixture", "setup controller binding is not current")
            body = self._BODY

            class Handler(http.server.BaseHTTPRequestHandler):
                def do_GET(self) -> None:
                    if self.path != "/fixture" or self.headers.get("Host", "").split(":", 1)[0] not in {"127.0.0.1", "localhost"}:
                        self.send_error(404)
                        return
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.send_header("Content-Length", str(len(body)))
                    self.send_header("Cache-Control", "no-store")
                    self.end_headers()
                    self.wfile.write(body)

                def log_message(self, *_: Any) -> None:
                    return

            server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
            server.daemon_threads = True
            server.timeout = 0.25
            thread = threading.Thread(target=server.serve_forever, name="hermes-app-fixture", daemon=True)
            thread.start()
            now = self._clock()
            expiry = min(now + self._ttl, float(binding.expires_monotonic))
            if expiry <= now:
                server.shutdown()
                server.server_close()
                raise AuthorityDenied("application.fixture", "setup controller lease has expired")
            host, port = server.server_address
            receipt = RootApplicationFixtureReceipt(1, secrets.token_urlsafe(32), "browser-fixture",
                setup_session_id, controller_binding_handle, self._generation,
                f"http://{host}:{port}/fixture", now, expiry)
            self._server, self._thread, self._receipt = server, thread, receipt
            return receipt

    def resolve(self, handle: str, *, setup_session_id: str,
                 service_generation_digest: str) -> RootApplicationFixtureReceipt:
        with self._lock:
            receipt, server, thread = self._receipt, self._server, self._thread
        if (receipt is None or receipt.handle != handle or receipt.setup_session_id != setup_session_id
                or receipt.service_generation_digest != service_generation_digest
                or service_generation_digest != self._generation or receipt.expires_monotonic <= self._clock()
                or server is None or thread is None or not thread.is_alive()
                or server.socket.fileno() < 0 or server.server_address[0] != "127.0.0.1"
                or not _owned_loopback_url(receipt.url)):
            raise AuthorityDenied("application.fixture", "owned fixture listener receipt is stale")
        binding = self._resolve_controller(receipt.controller_binding_handle)
        if binding is None or not self._verify_controller(binding):
            raise AuthorityDenied("application.fixture", "fixture controller binding is stale")
        return receipt

    def close(self) -> None:
        with self._lock:
            server, self._server, self._thread = self._server, None, None
        if server is not None:
            server.shutdown()
            server.server_close()


class RootApplicationQualificationContextProducer:
    """Run the ordered, setup-owned pre-active application qualification phases.

    Every selector is resolved from the live setup session. The returned
    context binds the exact source, lock, runtime preparation, probe terminal,
    namespace, consent and (for Browser Use) owned fixture receipts. It never
    looks up or fabricates an active application row.
    """

    _PHASES = (
        "stage-pinned-source-locks", "prepare-locked-isolated-runtime",
        "observe-runtime-probe", "run-owned-local-fixture",
    )

    def __init__(self, setup_runtime_factory: Any, source_preparation_registry: Any,
                 component_source_receipt_registry: Any, runtime_preparation_resolver: Any,
                 runtime_probe_authority: Any, fixture_server: RootOwnedApplicationFixtureServer,
                 service: Any, controller_bindings: Any):
        required = (
            (setup_runtime_factory, "resolve_live_session_id"),
            (source_preparation_registry, "prepare_selected_source"),
            (source_preparation_registry, "resolve_application_lock_for_prepared_source"),
            (source_preparation_registry, "record_prepared_verified_generation"),
            (source_preparation_registry, "resolve_prepared_source"),
            (controller_bindings, "resolve_application_controller_binding"),
            (controller_bindings, "verify_application_controller_binding"),
        )
        if (fixture_server is None or service is None
                or any(not callable(getattr(owner, name, None)) for owner, name in required)
                or (runtime_preparation_resolver is not None and any(
                    not callable(getattr(runtime_preparation_resolver, name, None))
                    for name in ("resolve_application_runtime_preparation",
                                 "resolve_application_runtime_preparation_selection",
                                 "resolve_application_runtime_probe_step")))
                or (runtime_probe_authority is not None and any(
                    not callable(getattr(runtime_probe_authority, name, None))
                    for name in ("run_selected_runtime_probe", "resolve_application_runtime_probe")))):
            raise ValueError("pre-active application qualification producer dependencies are invalid")
        self.setup_factory = setup_runtime_factory
        self.source_preparations = source_preparation_registry
        self.source_receipts = component_source_receipt_registry
        self.runtime_preparations = runtime_preparation_resolver
        self.probes = runtime_probe_authority
        self.fixtures = fixture_server
        self.service = service
        self.controllers = controller_bindings
        self._contexts: dict[str, tuple[RootApplicationQualificationContext, Any, Any, Any, Any, Any, Any, Any]] = {}
        self._lock = threading.RLock()

    def _phase_consent(self, binding: Any, choice: Any, phase_id: str) -> Any:
        resolve = getattr(binding, "resolve_application_qualification_consent", None)
        if not callable(resolve):
            raise AuthorityDenied("application.qualification.consent", f"phase {phase_id}: setup consent resolver is unavailable")
        try:
            consent = resolve(choice.selection_handle, phase_id)
        except Exception:
            raise AuthorityDenied("application.qualification.consent", f"phase {phase_id}: current setup consent is unavailable") from None
        try:
            from .bootstrap_runtime_factory import RootApplicationQualificationConsent
            valid_type = type(consent) is RootApplicationQualificationConsent
        except ImportError:
            valid_type = False
        if (not valid_type or consent.qualification_choice_handle != choice.selection_handle
                or consent.setup_session_id != choice.setup_session_id
                or consent.transaction_handle != choice.transaction_handle
                or consent.prepared_generation_id != choice.prepared_generation_id
                or consent.application_id != choice.application_id
                or consent.workflow_id != choice.workflow_id
                or consent.target_profile_id != choice.target_profile_id
                or consent.namespace_selection_receipt_handle != choice.namespace_selection_receipt_handle
                or consent.controller_binding_handle != choice.controller_binding_handle
                or consent.purpose != "installer-application-local-qualification"
                or consent.allowed_phase_ids != (phase_id,)
                or consent.additional_metered_budget_usd != 0.0
                or consent.revocation_epoch < 0
                or consent.issued_monotonic > self.service.monotonic()
                or consent.expires_monotonic <= self.service.monotonic()
                or consent.expires_monotonic - consent.issued_monotonic > 30.0):
            raise AuthorityDenied("application.qualification.consent", f"phase {phase_id}: consent binding is invalid or expired")
        return consent

    def produce(self, root_setup_session_handle: str,
                workflow_id: str) -> RootApplicationQualificationContext:
        if (not isinstance(root_setup_session_handle, str) or not _handle(root_setup_session_handle)
                or workflow_id not in _QUALIFICATION_WORKFLOWS):
            raise AuthorityDenied("application.qualification", "setup session or finite workflow selector is malformed")
        try:
            session = self.setup_factory.resolve_live_session_id(root_setup_session_handle)
            binding = session.selected_installation
            choice_handle = binding.observe_application_qualification_workflow()
            choice = binding.resolve_application_setup_choice(choice_handle)
            from .bootstrap_runtime_factory import RootSelectedApplicationQualificationChoice
            from .application_source_preparation import RootApplicationSourcePreparationSelection
            from .application_source_preparation import RootPreparedApplicationSourceReceipt
            from .application_source_preparation import RootApplicationLockReceipt
            from .application_source_preparation import RootApplicationRuntimePreparationSelection
        except Exception:
            raise AuthorityDenied("application.qualification", "live root setup choice or source preparation types are unavailable") from None
        app_id, workload_id, argument_names = _QUALIFICATION_WORKFLOWS[workflow_id]
        if (type(choice) is not RootSelectedApplicationQualificationChoice
                or choice.workflow_id != workflow_id or choice.application_id != app_id
                or choice.workload_id != workload_id):
            raise AuthorityDenied("application.qualification", "root TTY choice differs from the requested fixed workflow")

        # The same retained TTY choice grants only these four bounded phases.
        consent = self._phase_consent(binding, choice, self._PHASES[0])
        try:
            source_selection = self.source_preparations.resolve_application_source_preparation(
                choice.selection_handle, choice.application_id)
            if (type(source_selection) is not RootApplicationSourcePreparationSelection
                    or source_selection.qualification_choice_handle != choice.selection_handle
                    or source_selection.workflow_id != workflow_id
                    or source_selection.application_id != app_id):
                raise AuthorityDenied("application.source", "typed source selection does not match root TTY choice")
            prepared = self.source_preparations.prepare_selected_source(source_selection.selection_handle)
            if type(prepared) is not RootPreparedApplicationSourceReceipt:
                raise AuthorityDenied("application.source", "source staging returned no root prepared-source receipt")
            source = self.source_preparations.record_prepared_verified_generation(
                prepared.receipt_handle, source_selection.selection_handle)
            if type(source) is not RootPreparedApplicationSourceReceipt or source is not prepared:
                raise AuthorityDenied("application.source", "prepared source receipt identity changed")
            lock = self.source_preparations.resolve_application_lock_for_prepared_source(
                source_selection.selection_handle, source.receipt_handle)
            if type(lock) is not RootApplicationLockReceipt:
                raise AuthorityDenied("application.lock", "selected lock receipt is unavailable")
        except AuthorityDenied:
            raise
        except Exception:
            raise AuthorityDenied("application.source", "pinned source or lock phase is unavailable") from None
        self._phase_consent(binding, choice, self._PHASES[1])
        if self.runtime_preparations is None or self.probes is None:
            raise AuthorityDenied("application.runtime", "locked isolated runtime builder or reviewed probe artifact is unavailable")
        try:
            preparation = self.runtime_preparations.resolve_application_runtime_preparation(
                app_id, source.receipt_handle, lock.receipt_handle)
            if (type(preparation) is not RootApplicationRuntimePreparationSelection
                    or preparation.application_id != app_id
                    or preparation.source_receipt_handle != source.receipt_handle
                    or preparation.selected_lock_receipt_handle != lock.receipt_handle
                    or preparation.lock_sha256 != lock.lock_sha256
                    or preparation.controller_binding_handle != choice.controller_binding_handle):
                raise AuthorityDenied("application.runtime", "runtime preparation differs from source, lock, or setup choice")
        except AuthorityDenied:
            raise
        except Exception:
            raise AuthorityDenied("application.runtime", "locked isolated runtime preparation is unavailable") from None

        self._phase_consent(binding, choice, self._PHASES[2])
        probe = self.probes.run_selected_runtime_probe(preparation.handle)
        try:
            from .application_workload_execution import RootApplicationRuntimeProbeReceipt
            if type(probe) is not RootApplicationRuntimeProbeReceipt:
                raise AuthorityDenied("application.probe", "runtime runner returned no typed managed probe receipt")
            retained_probe = self.probes.resolve_application_runtime_probe(probe.handle)
            current_preparation = self.runtime_preparations.resolve_application_runtime_preparation_selection(
                preparation.handle)
            step = self.runtime_preparations.resolve_application_runtime_probe_step(preparation.handle)
        except AuthorityDenied:
            raise
        except Exception:
            raise AuthorityDenied("application.probe", "managed runtime probe lineage is unavailable") from None
        from .application_workload_execution import RootApplicationSelectedStep
        if (retained_probe is not probe or current_preparation is not preparation
                or type(step) is not RootApplicationSelectedStep
                or not self.runtime_probe_authority_is_current(preparation, step, probe)):
            raise AuthorityDenied("application.probe", "runtime probe or selected step is stale")

        self._phase_consent(binding, choice, self._PHASES[3])
        controller = self.controllers.resolve_application_controller_binding(choice.selection_handle)
        if (not self.controllers.verify_application_controller_binding(controller)
                or controller.handle != choice.controller_binding_handle
                or controller.setup_session_id != choice.setup_session_id):
            raise AuthorityDenied("application.controller", "root TTY controller binding is stale")
        fixture = None
        fixture_url: str | None = None
        if workload_id == "browser-fixture":
            fixture = self.fixtures.start(setup_session_id=choice.setup_session_id,
                controller_binding_handle=choice.controller_binding_handle)
            if (fixture.setup_session_id != choice.setup_session_id
                    or fixture.controller_binding_handle != choice.controller_binding_handle
                    or fixture.service_generation_digest != self.service.service_generation_digest
                    or not _owned_loopback_url(fixture.url)):
                raise AuthorityDenied("application.fixture", "owned loopback fixture receipt does not match setup choice")
            fixture_url = fixture.url

        principal = session.resolve_adopted_principal_selection()
        namespace = session.resolve_adopted_namespace_selection()
        if (principal.receipt_id != choice.principal_selection_receipt_handle
                or namespace.receipt_handle != choice.namespace_selection_receipt_handle
                or namespace.principal_selection_receipt_id != principal.receipt_id):
            raise AuthorityDenied("application.identity", "prepared principal or namespace selection changed")
        source_digest = hashlib.sha256(canonical_bytes({
            "source": {name: getattr(source, name) for name in source.__dataclass_fields__
                       if not name.startswith("_")},
            "lock": {name: getattr(lock, name) for name in lock.__dataclass_fields__
                     if not name.startswith("_")},
        })).hexdigest()
        request_shape = {"fixture_url": fixture_url} if argument_names else {}
        observed = hashlib.sha256(canonical_bytes(request_shape)).hexdigest()
        context = RootApplicationQualificationContext(
            choice.setup_session_id, app_id, app_id, preparation.profile_id,
            preparation.profile_generation, principal.principal_id, namespace.namespace_id,
            preparation.service_selection_digest, "", choice.controller_binding_handle,
            (source.receipt_handle,), source_digest, f"workload:{workload_id}:v1",
            "" if fixture is None else fixture.handle, fixture_url, observed,
            consent.revocation_epoch, choice.selection_handle, source_selection.selection_handle,
            source.receipt_handle, lock.receipt_handle, preparation.handle, probe.handle,
            namespace.receipt_handle, principal.receipt_id, consent.receipt_handle,
            source.source_generation_manifest_sha256, lock.lock_sha256,
            preparation.runtime_manifest_sha256,
        )
        key = context.source_preparation_selection_handle
        with self._lock:
            self._contexts[key] = (context, choice, source_selection, source, lock, preparation, probe, fixture)
        return context

    def runtime_probe_authority_is_current(self, preparation: Any, step: Any, probe: Any) -> bool:
        try:
            resolver = getattr(self.runtime_preparations, "resolve_application_runtime_preparation_current", None)
            return bool(callable(resolver) and resolver(preparation.handle) is True
                and self.runtime_probe_authority.resolve_application_runtime_probe(probe.handle) is probe
                and step.preparation_selection_handle == preparation.handle
                and step.role == "application-runtime-probe"
                and step.source_receipt_handle == preparation.source_receipt_handle
                and step.selected_lock_receipt_handle == preparation.selected_lock_receipt_handle
                and step.lock_sha256 == preparation.lock_sha256
                and step.runtime_manifest_sha256 == preparation.runtime_manifest_sha256)
        except Exception:
            return False

    def is_current(self, context: RootApplicationQualificationContext,
                   workflow_id: str) -> bool:
        with self._lock:
            row = self._contexts.get(context.source_preparation_selection_handle)
        if row is None or row[0] is not context:
            return False
        _context, choice, source_selection, source, lock, preparation, probe, fixture = row
        try:
            session = self.setup_factory.resolve_live_session_id(context.setup_session_id)
            binding = session.selected_installation
            current_choice = binding.resolve_application_setup_choice(choice.selection_handle)
            current_selection = binding.resolve_application_source_preparation(
                choice.selection_handle, choice.application_id)
            current_source = self.source_preparations.resolve_prepared_source(source.receipt_handle)
            current_lock = self.source_preparations.resolve_application_lock_for_prepared_source(
                source_selection.selection_handle, source.receipt_handle)
            current_preparation = self.runtime_preparations.resolve_application_runtime_preparation_selection(
                preparation.handle)
            current_probe = self.probes.resolve_application_runtime_probe(probe.handle)
            for phase_id in self._PHASES:
                self._phase_consent(binding, choice, phase_id)
            if (current_choice is not choice or current_selection is not source_selection
                    or current_source is not source or current_lock is not lock
                    or current_preparation is not preparation or current_probe is not probe
                    or choice.workflow_id != workflow_id
                    or self.controllers.is_application_controller_binding_current(
                        choice.controller_binding_handle) is not True):
                return False
            if fixture is not None:
                live_fixture = self.fixtures.resolve(fixture.handle,
                    setup_session_id=choice.setup_session_id,
                    service_generation_digest=self.service.service_generation_digest)
                if live_fixture is not fixture:
                    return False
            return True
        except Exception:
            return False

    def resolve_controller_binding(self, controller_binding_handle: str) -> Any:
        with self._lock:
            row = next((item for item in self._contexts.values()
                        if item[1].controller_binding_handle == controller_binding_handle), None)
        if row is None:
            raise AuthorityDenied("application.controller", "setup controller binding is not retained")
        choice = row[1]
        session = self.setup_factory.resolve_live_session_id(choice.setup_session_id)
        binding = session.selected_installation.resolve_application_controller_binding(choice.selection_handle)
        if (binding.handle != controller_binding_handle
                or not session.selected_installation.verify_application_controller_binding(binding)):
            raise AuthorityDenied("application.controller", "setup controller binding is stale")
        return binding

    def is_controller_current(self, controller_binding_handle: str) -> bool:
        try:
            return self.resolve_controller_binding(controller_binding_handle) is not None
        except Exception:
            return False


class RootApplicationExecutionJournal:
    """Durable replay ledger for root-selected application execution.

    The database is bound to one protected journal directory and one active
    service generation. DTO objects remain process-local capabilities: after a
    daemon restart, the durable rows prevent replay but never recreate handles.
    """

    def __init__(self, selection: Any, *, selection_resolver: Any,
                 expected_uid: int = 0,
                 monotonic: Any = time.monotonic):
        from hermes_installer.protected_enrollment import RootJournalSelection
        if (type(selection) is not RootJournalSelection or not selection.path.is_absolute()
                or not _digest(selection.service_generation_digest)
                or not isinstance(selection.generation, str) or not 1 <= len(selection.generation) <= 256
                or type(expected_uid) is not int or expected_uid < 0 or not callable(monotonic)
                or not callable(selection_resolver)):
            raise AuthorityDenied("application.journal", "protected application journal selection is malformed")
        try:
            root_info = selection.path.lstat()
            if (not stat.S_ISDIR(root_info.st_mode) or root_info.st_uid != expected_uid
                    or stat.S_IMODE(root_info.st_mode) != 0o700
                    or (root_info.st_dev, root_info.st_ino) != (selection.device, selection.inode)):
                raise ValueError
            path = selection.path / "application-execution-v1.sqlite3"
            fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
            try:
                info = os.fstat(fd)
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != expected_uid or info.st_nlink != 1
                        or stat.S_IMODE(info.st_mode) != 0o600):
                    raise ValueError
            finally:
                os.close(fd)
            self._db = sqlite3.connect(path, timeout=5.0, isolation_level=None,
                                       check_same_thread=False)
            os.chmod(path, 0o600)
            self._db.execute("PRAGMA journal_mode=DELETE")
            self._db.execute("PRAGMA synchronous=FULL")
            self._db.executescript("""
                CREATE TABLE IF NOT EXISTS qualification (
                    handle TEXT PRIMARY KEY, request_sha256 TEXT NOT NULL,
                    request BLOB NOT NULL, projected BLOB NOT NULL,
                    consumed INTEGER NOT NULL DEFAULT 0 CHECK(consumed IN (0,1)));
                CREATE TABLE IF NOT EXISTS admission (
                    handle TEXT PRIMARY KEY, service_generation_digest TEXT NOT NULL,
                    expires REAL NOT NULL, request_sha256 TEXT NOT NULL, current INTEGER NOT NULL DEFAULT 1);
                CREATE TABLE IF NOT EXISTS step (
                    handle TEXT PRIMARY KEY, admission_handle TEXT NOT NULL,
                    step_id TEXT NOT NULL, payload BLOB NOT NULL, current INTEGER NOT NULL DEFAULT 1,
                    UNIQUE(admission_handle, step_id));
                CREATE TABLE IF NOT EXISTS capsule (
                    handle TEXT PRIMARY KEY, admission_handle TEXT NOT NULL,
                    capsule BLOB NOT NULL, payload BLOB NOT NULL, terminal BLOB NOT NULL);
            """)
            info = path.lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != expected_uid
                    or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600):
                raise ValueError
        except Exception:
            raise AuthorityDenied("application.journal", "protected application journal storage is unsafe") from None
        self.selection = selection
        self._selection_resolver = selection_resolver
        self.expected_uid = expected_uid
        self.monotonic = monotonic
        self._lock = threading.RLock()
        self._requests: dict[str, tuple[Any, Any, bytes]] = {}
        self._admissions: dict[str, Any] = {}
        self._steps: dict[str, Any] = {}
        self._capsules: dict[str, tuple[Any, bytes, Any]] = {}

    def _verify_selection(self) -> None:
        try:
            current = self._selection_resolver()
        except Exception:
            raise AuthorityDenied("application.journal", "protected application journal selection is stale") from None
        if (type(current) is not type(self.selection)
                or current.root_id != self.selection.root_id or current.path != self.selection.path
                or current.device != self.selection.device or current.inode != self.selection.inode
                or current.generation != self.selection.generation
                or current.service_generation_digest != self.selection.service_generation_digest):
            raise AuthorityDenied("application.journal", "protected application journal selection changed")

    def _transaction(self, operation: Any) -> Any:
        with self._lock:
            self._verify_selection()
            try:
                self._db.execute("BEGIN IMMEDIATE")
                result = operation()
                self._db.execute("COMMIT")
                return result
            except Exception:
                self._db.execute("ROLLBACK")
                raise

    def retain_application_qualification_request(self, request: Any, context: Any,
                                                   projected: bytes) -> None:
        if (type(request) is not RootApplicationQualificationRequest
                or type(context) is not RootApplicationQualificationContext
                or not isinstance(projected, bytes) or hashlib.sha256(projected).hexdigest()
                != request.canonical_workload_sha256):
            raise AuthorityDenied("application.journal", "qualification journal input is malformed")
        encoded = canonical_bytes({name: getattr(request, name) for name in request.__dataclass_fields__})
        def write() -> None:
            self._db.execute("INSERT INTO qualification(handle,request_sha256,request,projected) VALUES(?,?,?,?)",
                (request.request_handle, request.canonical_workload_sha256, encoded, projected))
        self._transaction(write)
        with self._lock:
            self._requests[request.request_handle] = (request, context, projected)

    def resolve_application_qualification_request(self, handle: str) -> Any:
        self._verify_selection()
        with self._lock:
            item = self._requests.get(handle)
            row = self._db.execute("SELECT consumed FROM qualification WHERE handle=?", (handle,)).fetchone()
        if item is None or row is None or row[0] != 0:
            raise AuthorityDenied("application.journal", "qualification request is consumed or unavailable")
        return item[0]

    def is_application_qualification_request_current(self, handle: str) -> bool:
        try:
            self._verify_selection()
        except AuthorityDenied:
            return False
        with self._lock:
            return bool(handle in self._requests and self._db.execute(
                "SELECT 1 FROM qualification WHERE handle=? AND consumed=0", (handle,)).fetchone())

    def consume_application_qualification_request(self, handle: str) -> bool:
        def consume() -> bool:
            cursor = self._db.execute("UPDATE qualification SET consumed=1 WHERE handle=? AND consumed=0", (handle,))
            return cursor.rowcount == 1
        return self._transaction(consume)

    def _admit(self, *, application_id: str, profile_id: str, profile_generation: str,
               principal_id: str, service_generation_digest: str,
               source_receipt_handles: tuple[str, ...], source_context_digest: str,
               expires_monotonic: float, workload_id: str, payload: bytes,
               selection: Any, request_sha256: str, observed_sha256: str,
               source_receipt_handle: str, controller_binding_handle: str,
               qualification_handle: str = "") -> RootApplicationWorkloadAdmission:
        from hermes_installer.components.workloads import _REGISTERED
        definition = _REGISTERED.get(workload_id)
        if definition is None or not isinstance(payload, bytes) or not _digest(request_sha256):
            raise AuthorityDenied("application.journal", "selected workload recipe is unavailable")
        now = self.monotonic()
        expiry = min(now + float(definition.timeout_seconds), expires_monotonic)
        admission_handle = secrets.token_urlsafe(32)
        operation_id = getattr(selection, "operation_id", None)
        if not isinstance(operation_id, str) or not operation_id:
            raise AuthorityDenied("application.journal", "selected operation recipe is unavailable")
        admission = RootApplicationWorkloadAdmission(
            1, admission_handle, application_id, workload_id, profile_id,
            profile_generation, principal_id, service_generation_digest,
            request_sha256, tuple(source_receipt_handles), source_context_digest,
            controller_binding_handle, source_receipt_handle,
            getattr(selection, "runtime_receipt_handle", getattr(selection, "handle", "")),
            (operation_id,), 1, expiry, 0, now, expiry, observed_sha256, qualification_handle)
        step_handle = secrets.token_urlsafe(32)
        step = RootApplicationSelectedStep(1, step_handle, admission_handle, application_id,
            workload_id, f"{workload_id}:0", 1, profile_id, profile_generation,
            service_generation_digest, operation_id, request_sha256,
            source_receipt_handle, selection.runtime_receipt_handle, source_context_digest,
            controller_binding_handle, payload, expiry)
        def write() -> None:
            self._db.execute("INSERT INTO admission(handle,service_generation_digest,expires,request_sha256) VALUES(?,?,?,?)",
                (admission_handle, service_generation_digest, expiry, request_sha256))
            self._db.execute("INSERT INTO step(handle,admission_handle,step_id,payload) VALUES(?,?,?,?)",
                (step_handle, admission_handle, step.step_id, payload))
        self._transaction(write)
        with self._lock:
            self._admissions[admission_handle] = admission
            self._steps[step_handle] = step
        return admission

    def admit_selected_application_qualification_workload(self, *, request: Any, context: Any,
            workload_bytes: bytes, selection: Any) -> RootApplicationWorkloadAdmission:
        if (type(request) is not RootApplicationQualificationRequest
                or not isinstance(workload_bytes, bytes)
                or hashlib.sha256(workload_bytes).hexdigest() != request.canonical_workload_sha256):
            raise AuthorityDenied("application.journal", "qualification workload bytes differ from retained request")
        workload = json.loads(workload_bytes.decode("utf-8"))
        return self._admit(application_id=request.application_id, profile_id=request.profile_id,
            profile_generation=request.profile_generation, principal_id=request.principal_id,
            service_generation_digest=request.enclosing_service_generation_digest,
            source_receipt_handles=request.source_receipt_handles,
            source_context_digest=request.source_context_digest,
            expires_monotonic=request.expires_monotonic,
            workload_id=workload["id"], payload=workload_bytes, selection=selection,
            request_sha256=request.canonical_workload_sha256,
            observed_sha256=context.observed_request_sha256,
            source_receipt_handle=getattr(selection, "source_receipt_handle",
                                          getattr(selection, "source_generation_receipt_handle", "")),
            controller_binding_handle=context.controller_binding_handle,
            qualification_handle=request.request_handle)

    def admit_selected_application_workload(self, *, invocation: Any, action: Any, workload: Any,
            selection: Any, request_sha256: str, source_closure_sha256: str) -> RootApplicationWorkloadAdmission:
        payload = canonical_bytes({"id": workload.id, "arguments": dict(workload.arguments)})
        return self._admit(application_id=action.application_id, profile_id=action.profile_id,
            profile_generation=action.profile_generation, principal_id=invocation.principal_id,
            service_generation_digest=action.service_generation_digest,
            source_receipt_handles=(action.source_receipt_handle,),
            source_context_digest=source_closure_sha256,
            expires_monotonic=invocation.expires_monotonic,
            workload_id=workload.id, payload=payload, selection=selection, request_sha256=request_sha256,
            observed_sha256=request_sha256, source_receipt_handle=action.source_receipt_handle,
            controller_binding_handle=action.controller_binding_handle)

    def resolve_application_admission(self, handle: str) -> Any:
        with self._lock:
            admission = self._admissions.get(handle)
        if admission is None or not self.is_application_admission_current(handle):
            raise AuthorityDenied("application.journal", "application admission is stale")
        return admission

    def is_application_admission_current(self, handle: str) -> bool:
        try:
            self._verify_selection()
        except AuthorityDenied:
            return False
        with self._lock:
            admission = self._admissions.get(handle)
            row = self._db.execute("SELECT service_generation_digest,expires,current FROM admission WHERE handle=?", (handle,)).fetchone()
        return bool(admission is not None and row is not None and row[2] == 1
                    and row[0] == self.selection.service_generation_digest
                    and row[1] > self.monotonic()
                    and admission.service_generation_digest == row[0])

    def application_step_handle(self, step: RootApplicationSelectedStep) -> str:
        return step.handle if self._steps.get(step.handle) is step else ""

    def resolve_application_step(self, admission_handle: str, step_id: str) -> Any:
        with self._lock:
            matches = [item for item in self._steps.values()
                       if item.admission_handle == admission_handle and item.step_id == step_id]
        if len(matches) != 1 or not self.is_application_step_current(matches[0].handle):
            raise AuthorityDenied("application.journal", "application step is stale")
        return matches[0]

    def is_application_step_current(self, handle: str) -> bool:
        try:
            self._verify_selection()
        except AuthorityDenied:
            return False
        with self._lock:
            step = self._steps.get(handle)
            row = self._db.execute("SELECT admission_handle,current FROM step WHERE handle=?", (handle,)).fetchone()
        return bool(step is not None and row is not None and row[1] == 1
                    and row[0] == step.admission_handle and self.is_application_admission_current(row[0]))

    def retain_application_result_capsule(self, capsule: Any, payload: bytes, terminal: Any) -> None:
        if (type(capsule) is not RootApplicationResultCapsule or not isinstance(payload, bytes)
                or not 1 <= len(payload) <= 4 * 1024 * 1024):
            raise AuthorityDenied("application.journal", "result capsule exceeds its journal bound")
        capsule_bytes = canonical_bytes(capsule.claims() | {"signature": capsule.signature})
        terminal_bytes = canonical_bytes(terminal.claims() | {"signature": terminal.signature})
        def write() -> None:
            self._db.execute("INSERT INTO capsule(handle,admission_handle,capsule,payload,terminal) VALUES(?,?,?,?,?)",
                (capsule.handle, capsule.admission_handle, capsule_bytes, payload, terminal_bytes))
        self._transaction(write)
        with self._lock:
            self._capsules[capsule.handle] = (capsule, payload, terminal)

    def resolve_application_result_capsule(self, handle: str) -> Any:
        with self._lock:
            item = self._capsules.get(handle)
        if item is None or not self.is_application_admission_current(item[0].admission_handle):
            raise AuthorityDenied("application.journal", "application capsule is stale")
        return item


@dataclass(frozen=True, slots=True)
class RootSelectedApplicationWorkloadAction:
    """Root catalog's exact action-to-finite-workload join."""
    application_id: str
    profile_id: str
    profile_generation: str
    adapter_id: str
    workload_id: str
    controller_binding_handle: str
    request_schema_sha256: str
    request_sha256: str
    source_receipt_handle: str
    runtime_receipt_handle: str
    operation_id: str
    request_schema_id: str
    result_schema_id: str
    result_validator_artifact_id: str
    result_validator_sha256: str
    capability_ids: tuple[str, ...]
    provider_route_ids: tuple[str, ...]
    credential_reference_ids: tuple[str, ...]
    account_eligibility_receipt_handle: str | None
    metered_budget_usd: str
    service_generation_digest: str


@dataclass(frozen=True, slots=True)
class RootApplicationSelectedStep:
    schema: int
    handle: str
    admission_handle: str
    application_id: str
    workload_id: str
    step_id: str
    sequence: int
    profile_id: str
    profile_generation: str
    service_generation_digest: str
    operation_id: str
    request_sha256: str
    source_receipt_handle: str
    runtime_receipt_handle: str
    source_closure_sha256: str
    controller_binding_handle: str
    selection_payload: bytes = field(repr=False)
    deadline_monotonic: float
    role: str = "application-workload"
    preparation_selection_handle: str = ""
    selected_lock_receipt_handle: str = ""
    lock_sha256: str = ""
    runtime_id: str = ""
    runtime_manifest_sha256: str = ""


from hermes_installer.managed_process_custodian import RootApplicationTerminalReceipt


@dataclass(frozen=True, slots=True)
class RootApplicationResultCapsule:
    schema: int
    handle: str
    admission_handle: str
    terminal_receipt_handle: str
    application_id: str
    workload_id: str
    step_id: str
    result_schema_id: str
    validator_artifact_id: str
    validator_sha256: str
    payload_sha256: str
    payload_size_bytes: int
    source_closure_sha256: str
    service_generation_digest: str
    issued_monotonic: float
    expires_monotonic: float
    signature: str

    def claims(self) -> dict[str, Any]:
        return {name: getattr(self, name) for name in self.__dataclass_fields__ if name != "signature"}


@dataclass(slots=True)
class _GrantEntry:
    grant: RootApplicationStartGrant
    step: RootApplicationSelectedStep
    profile: Any
    controller: Any
    state: str = "pending"
    proof: VerifiedRootApplicationStart | None = None


class RootApplicationWorkloadAuthority:
    """Service-bound issuer/consumer for fresh selected-app process starts."""

    def __init__(self, service: Any, selected_application_catalog: Any,
                 component_source_receipt_registry: Any, application_runtime_receipt_registry: Any,
                 root_invocation_registry: Any, root_controller_custody: Any, root_journal: Any):
        self.service = service
        self.catalog = selected_application_catalog
        self.sources = component_source_receipt_registry
        self.runtimes = application_runtime_receipt_registry
        self.invocations = root_invocation_registry
        self.controllers = root_controller_custody
        self.journal = root_journal
        self._lock = threading.RLock()
        self._seal = object()
        self._grants: dict[str, _GrantEntry] = {}
        self._nonces: dict[str, tuple[str, float]] = {}
        self._admission_invocations: dict[str, Any] = {}
        self._admission_actions: dict[str, Any] = {}
        self._qualification_admissions: dict[str, str] = {}
        self._qualification_context_producer: RootApplicationQualificationContextProducer | None = None
        self._application_preparations: Any | None = None
        self._probe_steps: dict[str, tuple[Any, RootApplicationSelectedStep]] = {}
        self._qualification_requests: dict[str, tuple[RootApplicationQualificationRequest,
            RootApplicationQualificationContext, bytes, Any, str]] = {}

    def attach_qualification_context_producer(
            self, producer: RootApplicationQualificationContextProducer) -> None:
        if type(producer) is not RootApplicationQualificationContextProducer:
            raise AuthorityDenied("application.qualification", "root qualification context producer has invalid type")
        with self._lock:
            if (self._qualification_context_producer is not None
                    and self._qualification_context_producer is not producer):
                raise AuthorityDenied("application.qualification", "qualification producer is already attached")
            self._qualification_context_producer = producer
            if self._application_preparations is None:
                self._application_preparations = producer.runtime_preparations

    def attach_application_preparation_resolver(self, resolver: Any) -> None:
        """Attach one root-owned pre-active probe resolver to this authority."""
        required = ("resolve_application_runtime_preparation_selection",
                    "resolve_application_runtime_probe_step")
        if resolver is None or any(not callable(getattr(resolver, name, None)) for name in required):
            raise AuthorityDenied("application.probe", "pre-active preparation resolver is incomplete")
        with self._lock:
            if self._application_preparations is not None and self._application_preparations is not resolver:
                raise AuthorityDenied("application.probe", "pre-active preparation resolver is already attached")
            self._application_preparations = resolver

    @classmethod
    def from_authority_service(cls, service: Any, selected_application_catalog: Any,
                               component_source_receipt_registry: Any,
                               application_runtime_receipt_registry: Any,
                               root_invocation_registry: Any, root_controller_custody: Any,
                               root_journal: Any) -> "RootApplicationWorkloadAuthority":
        from .service import AuthorityService
        if not isinstance(service, AuthorityService):
            raise AuthorityDenied("application.authority", "application authority requires the active root service")
        objects = (selected_application_catalog, component_source_receipt_registry,
                   application_runtime_receipt_registry, root_invocation_registry,
                   root_controller_custody, root_journal)
        if any(item is None for item in objects):
            raise AuthorityDenied("application.authority", "root application registries are incomplete")
        authority = cls(service, *objects)
        attach = getattr(service, "attach_root_application_workload_authority", None)
        if not callable(attach):
            raise AuthorityDenied("application.authority", "AuthorityService application binding is unavailable")
        attach(authority)
        return authority

    def resolve_application_step(self, admission_handle: str, step_id: str) -> RootApplicationSelectedStep:
        if not _handle(admission_handle) or not isinstance(step_id, str) or not step_id:
            raise AuthorityDenied("application.step", "selected application step selector is malformed")
        with self._lock:
            probe = self._probe_steps.get(admission_handle)
            preparations = self._application_preparations
        if probe is not None:
            selection, step = probe
            if (step.step_id != step_id or step.admission_handle != admission_handle
                    or not self._probe_selection_current(selection, step, preparations)):
                raise AuthorityDenied("application.step", "pre-active runtime probe step is stale")
            return step
        resolve = getattr(self.journal, "resolve_application_step", None)
        handle_for_step = getattr(self.journal, "application_step_handle", None)
        if not callable(resolve) or not callable(handle_for_step):
            raise AuthorityDenied("application.step", "root application journal resolver is unavailable")
        step = resolve(admission_handle, step_id)
        if type(step) is not RootApplicationSelectedStep or not self.is_application_admission_current(admission_handle):
            raise AuthorityDenied("application.step", "root application step is stale or unsealed")
        if (step.handle != handle_for_step(step)
                or step.admission_handle != admission_handle or step.step_id != step_id
                or step.role not in _ROLES or not _digest(step.request_sha256)
                or not _digest(step.source_closure_sha256)
                or not _canonical(step.selection_payload)):
            raise AuthorityDenied("application.step", "root application step binding is malformed")
        return step

    def _probe_selection_current(self, selection: Any, step: RootApplicationSelectedStep,
                                 preparations: Any | None = None) -> bool:
        preparations = preparations or self._application_preparations
        if preparations is None:
            return False
        try:
            current_selection = preparations.resolve_application_runtime_preparation_selection(
                selection.handle)
            current_step = preparations.resolve_application_runtime_probe_step(selection.handle)
            current_check = getattr(preparations, "resolve_application_runtime_preparation_current", None)
            prep_type = _runtime_preparation_selection_type()
            return bool(type(selection) is prep_type
                and type(current_selection) is prep_type
                and current_selection is selection
                and type(step) is RootApplicationSelectedStep and current_step is step
                and step.role == "application-runtime-probe"
                and step.preparation_selection_handle == selection.handle
                and step.admission_handle == selection.handle
                and step.application_id == selection.application_id
                and step.source_receipt_handle == selection.source_receipt_handle
                and step.runtime_receipt_handle == selection.handle
                and step.selected_lock_receipt_handle == selection.selected_lock_receipt_handle
                and step.lock_sha256 == selection.lock_sha256
                and step.runtime_id == selection.runtime_id
                and step.runtime_manifest_sha256 == selection.runtime_manifest_sha256
                and step.controller_binding_handle == selection.controller_binding_handle
                and step.service_generation_digest == selection.service_selection_digest
                and step.deadline_monotonic <= selection.expires_monotonic
                and selection.expires_monotonic > self.service.monotonic()
                and (not callable(current_check) or current_check(selection.handle) is True))
        except Exception:
            return False

    def issue_root_application_runtime_probe_start(
            self, preparation_selection_handle: str) -> RootApplicationStartGrant:
        """Issue a fresh, one-use process.start grant for the fixed ABI probe."""
        if not _handle(preparation_selection_handle):
            raise AuthorityDenied("application.probe", "runtime preparation handle is malformed")
        with self._lock:
            preparations = self._application_preparations
        if preparations is None:
            raise AuthorityDenied("application.probe", "pre-active preparation resolver is not attached")
        try:
            selection = preparations.resolve_application_runtime_preparation_selection(
                preparation_selection_handle)
            step = preparations.resolve_application_runtime_probe_step(preparation_selection_handle)
        except Exception:
            raise AuthorityDenied("application.probe", "pre-active probe selection is unavailable") from None
        if (type(selection) is not _runtime_preparation_selection_type()
                or type(step) is not RootApplicationSelectedStep
                or not self._probe_selection_current(selection, step, preparations)):
            raise AuthorityDenied("application.probe", "pre-active probe selection or fixed step is stale")
        with self._lock:
            previous = self._probe_steps.get(preparation_selection_handle)
            if previous is not None and (previous[0] is not selection or previous[1] is not step):
                raise AuthorityDenied("application.probe", "pre-active probe selection identity changed")
            self._probe_steps[preparation_selection_handle] = (selection, step)
        return self.issue_root_application_start(preparation_selection_handle, step.step_id)

    def admit_selected_workload(self, invocation: Any, canonical_arguments: bytes) -> RootApplicationWorkloadAdmission:
        """Join original native arguments to a root-selected finite workload."""
        from hermes_installer.components.workloads import _REGISTERED, Workload
        if not isinstance(canonical_arguments, bytes) or not 1 <= len(canonical_arguments) <= 2 * 1024 * 1024:
            raise AuthorityDenied("application.arguments", "native application arguments exceed their bound")
        try:
            args = json.loads(canonical_arguments.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            raise AuthorityDenied("application.arguments", "native application arguments are malformed") from None
        if not isinstance(args, dict) or canonical_bytes(args) != canonical_arguments:
            raise AuthorityDenied("application.arguments", "native application arguments are not canonical")
        workload = None
        raw = canonical_arguments
        if (len(raw) > 2 * 1024 * 1024 or hashlib.sha256(raw).hexdigest() != getattr(invocation, "request_sha256", None)
                or getattr(invocation, "service_generation_digest", None) != self.service.service_generation_digest
                or getattr(invocation, "expires_monotonic", 0) <= self.service.monotonic()
                or not self.invocations.is_selected_application_invocation_current(invocation)):
            raise AuthorityDenied("application.invocation", "native invocation is stale or does not bind exact workload bytes")
        resolve_action = getattr(self.catalog, "resolve_selected_workload_action", None)
        if not callable(resolve_action):
            raise AuthorityDenied("application.selection", "root action-to-workload catalog mapping is unavailable")
        action = resolve_action(invocation, canonical_arguments)
        if type(action) is not RootSelectedApplicationWorkloadAction:
            raise AuthorityDenied("application.selection", "root catalog returned no typed workload selection")
        if action.workload_id not in _REGISTERED:
            raise AuthorityDenied("application.selection", "root-selected workload is outside the fixed registry")
        definition = _REGISTERED[action.workload_id]
        if set(args) != definition.argument_names:
            raise AuthorityDenied("application.arguments", "native arguments differ from the selected fixed recipe")
        workload = Workload(action.workload_id, args)
        if (action.request_sha256 != hashlib.sha256(canonical_arguments).hexdigest()
                or not _digest(action.request_schema_sha256)
                or action.profile_id != invocation.profile_id
                or action.profile_generation != invocation.profile_generation
                or action.service_generation_digest != invocation.service_generation_digest
                or action.metered_budget_usd != "0" or action.application_id == ""
                or action.source_receipt_handle not in invocation.source_receipt_handles
                or action.runtime_receipt_handle == ""):
            raise AuthorityDenied("application.selection", "selected action, workload, profile or zero-budget join differs")
        if not set(definition.capabilities).issubset(set(action.capability_ids)):
            raise AuthorityDenied("application.capability", "selected application does not grant the fixed workload capabilities")
        account_check = getattr(self.catalog, "is_selected_application_account_current", None)
        if not callable(account_check) or account_check(action) is not True:
            raise AuthorityDenied("application.account", "selected account/provider eligibility is not current")
        verify_action = getattr(self.catalog, "is_selected_workload_action_current", None)
        if not callable(verify_action) or verify_action(invocation, action) is not True:
            raise AuthorityDenied("application.selection", "selected action mapping is not current")
        selection = self.catalog.resolve_selected_application_runtime(
            action.application_id, profile_id=action.profile_id)
        from hermes_installer.authority.application_runtime import RootSelectedApplicationRuntime
        if (type(selection) is not RootSelectedApplicationRuntime or selection.enabled is not True
                or selection.max_workers != 1 or selection.metered_budget_usd != "0"
                or selection.application_id != action.application_id
                or selection.profile_generation != action.profile_generation
                or selection.operation_id != action.operation_id
                or selection.source_generation_receipt_handle != action.source_receipt_handle
                or selection.runtime_receipt_handle != action.runtime_receipt_handle
                or selection.result_schema_id != action.result_schema_id
                or selection.result_validator_artifact_id != action.result_validator_artifact_id
                or selection.result_validator_sha256 != action.result_validator_sha256
                or tuple(selection.capability_ids) != tuple(action.capability_ids)
                or tuple(selection.provider_route_ids) != tuple(action.provider_route_ids)
                or tuple(selection.credential_reference_ids) != tuple(action.credential_reference_ids)
                or selection.account_eligibility_receipt_handle != action.account_eligibility_receipt_handle):
            raise AuthorityDenied("application.selection", "selected row differs from the explicit action mapping")
        self.sources.resolve_verified_generation(action.source_receipt_handle,
            application_id=action.application_id, service_generation_digest=action.service_generation_digest)
        self.runtimes.resolve(action.runtime_receipt_handle, application_id=action.application_id,
            source_receipt_handle=action.source_receipt_handle,
            service_generation_digest=action.service_generation_digest)
        controller = self.controllers.resolve_binding(action.controller_binding_handle)
        if controller is None or not self.controllers.verify_binding(controller):
            raise AuthorityDenied("application.controller", "selected application controller is not current")
        admit = getattr(self.journal, "admit_selected_application_workload", None)
        if not callable(admit):
            raise AuthorityDenied("application.journal", "root application admission journal is unavailable")
        admission = admit(invocation=invocation, action=action, workload=workload,
                          selection=selection, request_sha256=hashlib.sha256(raw).hexdigest(),
                          source_closure_sha256=invocation.source_closure_sha256)
        if type(admission) is not RootApplicationWorkloadAdmission or not self.is_application_admission_current(
                admission.admission_handle):
            raise AuthorityDenied("application.journal", "root application journal returned no current admission")
        if (admission.application_id != action.application_id or admission.workload_id != workload.id
                or admission.profile_id != action.profile_id or admission.profile_generation != action.profile_generation
                or admission.request_sha256 != hashlib.sha256(raw).hexdigest()
                or admission.source_receipt_handle != action.source_receipt_handle
                or admission.runtime_receipt_handle != action.runtime_receipt_handle
                or admission.service_generation_digest != action.service_generation_digest
                or admission.max_steps != 1 or admission.expires_monotonic <= self.service.monotonic()):
            raise AuthorityDenied("application.journal", "application admission does not match the selected action")
        with self._lock:
            if admission.admission_handle in self._admission_invocations:
                raise AuthorityDenied("application.replay", "native invocation already admitted")
            self._admission_invocations[admission.admission_handle] = invocation
            self._admission_actions[admission.admission_handle] = action
        return admission

    def observe_selected_qualification_request(self, root_setup_session_handle: str,
                                               workflow_id: str) -> RootApplicationQualificationRequest:
        """Create the root-projected fixture request from a complete pre-active proof chain."""
        if (not _handle(root_setup_session_handle) or workflow_id not in _QUALIFICATION_WORKFLOWS):
            raise AuthorityDenied("application.qualification", "qualification selector is malformed or unsupported")
        producer = self._qualification_context_producer
        if producer is None:
            raise AuthorityDenied("application.qualification", "pre-active root qualification producer is unavailable")
        context = producer.produce(root_setup_session_handle, workflow_id)
        if type(context) is not RootApplicationQualificationContext or not producer.is_current(context, workflow_id):
            raise AuthorityDenied("application.qualification", "pre-active source/runtime/probe context is stale")
        app_id, workload_id, argument_names = _QUALIFICATION_WORKFLOWS[workflow_id]
        if (context.application_id != app_id
                or context.enclosing_service_generation_digest != self.service.service_generation_digest
                or context.revocation_epoch < 0 or not context.source_receipt_handles
                or not _digest(context.source_context_digest)
                or not _handle(context.qualification_choice_handle)
                or not _handle(context.source_preparation_selection_handle)
                or not _handle(context.prepared_source_receipt_handle)
                or not _handle(context.selected_lock_receipt_handle)
                or not _handle(context.runtime_preparation_selection_handle)
                or not _handle(context.runtime_probe_receipt_handle)
                or not _digest(context.source_generation_manifest_sha256)
                or not _digest(context.lock_sha256)
                or not _digest(context.runtime_manifest_sha256)
                or not _digest(context.observed_request_sha256)
                or not _handle(context.controller_binding_handle)
                or (context.fixture_receipt_handle and not _handle(context.fixture_receipt_handle))):
            raise AuthorityDenied("application.qualification", "root setup context does not match the finite qualification workflow")
        selection = self._application_preparations.resolve_application_runtime_preparation_selection(
            context.runtime_preparation_selection_handle)
        controller = producer.resolve_controller_binding(context.controller_binding_handle)
        if controller is None or not producer.is_controller_current(context.controller_binding_handle):
            raise AuthorityDenied("application.controller", "qualification controller proof is stale")
        arguments = {"fixture_url": context.fixture_url} if argument_names else {}
        projected = json.dumps({"id": workload_id, "arguments": arguments}, sort_keys=True,
            separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
        if hashlib.sha256(canonical_bytes(arguments)).hexdigest() != context.observed_request_sha256:
            raise AuthorityDenied("application.qualification", "projected workload arguments differ from retained setup request")
        now = self.service.monotonic()
        handle, request_id = secrets.token_urlsafe(32), secrets.token_urlsafe(24)
        request = RootApplicationQualificationRequest(
            1, handle, request_id, "installer-application-qualification", workflow_id,
            app_id, context.adapter_id, context.profile_id, context.profile_generation,
            context.principal_id, context.namespace_id,
            context.enclosing_service_generation_digest, "",
            context.setup_session_id, context.controller_binding_handle,
            context.source_receipt_handles, context.source_context_digest,
            hashlib.sha256(projected).hexdigest(), context.argument_schema_id,
            context.fixture_receipt_handle, now, min(now+120.0, controller.expires_monotonic),
            context.revocation_epoch, context.runtime_preparation_selection_handle,
            context.runtime_probe_receipt_handle, context.runtime_manifest_sha256)
        retain = getattr(self.journal, "retain_application_qualification_request", None)
        if not callable(retain):
            raise AuthorityDenied("application.qualification", "root qualification request journal is unavailable")
        retain(request, context, projected)
        with self._lock:
            if len(self._qualification_requests) >= 4096:
                raise AuthorityDenied("application.capacity", "qualification request registry is full")
            self._qualification_requests[handle] = (request, context, projected, selection, root_setup_session_handle)
        return request

    def resolve_selected_qualification_request(self, request_handle: str) -> RootApplicationQualificationRequest:
        if not _handle(request_handle):
            raise AuthorityDenied("application.qualification", "qualification handle is malformed")
        with self._lock:
            record = self._qualification_requests.get(request_handle)
        if record is None:
            raise AuthorityDenied("application.qualification", "qualification request is unavailable")
        request, context, _payload, _selection, session_handle = record
        if request.request_handle != request_handle or not self.is_selected_qualification_request_current(request_handle):
            raise AuthorityDenied("application.qualification", "qualification request is stale or consumed")
        if self.journal.resolve_application_qualification_request(request_handle) is not request:
            raise AuthorityDenied("application.qualification", "qualification request differs from root journal")
        return request

    def is_selected_qualification_request_current(self, request_handle: str) -> bool:
        return self._qualification_context_current(request_handle, require_unconsumed=True)

    def _qualification_context_current(self, request_handle: str, *, require_unconsumed: bool) -> bool:
        with self._lock:
            record = self._qualification_requests.get(request_handle)
        if record is None:
            return False
        request, context, _payload, selection, session_handle = record
        try:
            workflow = request.workflow_id
            producer = self._qualification_context_producer
            current = bool(request.expires_monotonic > self.service.monotonic()
                and request.enclosing_service_generation_digest == self.service.service_generation_digest
                and producer is not None and producer.is_current(context, workflow) is True
                and request.runtime_preparation_selection_handle == context.runtime_preparation_selection_handle
                and request.runtime_probe_receipt_handle == context.runtime_probe_receipt_handle
                and request.runtime_manifest_sha256 == context.runtime_manifest_sha256
                and request.source_receipt_handles == (context.prepared_source_receipt_handle,)
                and selection is self._application_preparations.resolve_application_runtime_preparation_selection(
                    context.runtime_preparation_selection_handle))
            if require_unconsumed:
                current = current and self.journal.is_application_qualification_request_current(request_handle) is True
            return current
        except Exception:
            return False

    def admit_selected_qualification_workload(self, request_handle: str) -> RootApplicationWorkloadAdmission:
        request = self.resolve_selected_qualification_request(request_handle)
        with self._lock:
            record = self._qualification_requests.get(request_handle)
        assert record is not None
        _request, context, workload_bytes, selection, _session = record
        consume = getattr(self.journal, "consume_application_qualification_request", None)
        admit = getattr(self.journal, "admit_selected_application_qualification_workload", None)
        if not callable(consume) or not callable(admit):
            raise AuthorityDenied("application.qualification", "one-use qualification admission journal is unavailable")
        if consume(request_handle) is not True:
            raise AuthorityDenied("application.replay", "qualification request was already consumed")
        admission = admit(request=request, context=context, workload_bytes=workload_bytes,
                          selection=selection)
        if type(admission) is not RootApplicationWorkloadAdmission:
            raise AuthorityDenied("application.qualification", "qualification journal returned no typed admission")
        if (admission.qualification_request_handle != request_handle
                or admission.observed_request_sha256 != context.observed_request_sha256
                or admission.request_sha256 != request.canonical_workload_sha256
                or admission.application_id != request.application_id
                or admission.profile_generation != request.profile_generation
                or admission.source_receipt_handle != context.prepared_source_receipt_handle
                or admission.runtime_receipt_handle != selection.handle
                or admission.service_generation_digest != request.enclosing_service_generation_digest
                or not self.is_application_admission_current(admission.admission_handle)):
            raise AuthorityDenied("application.qualification", "qualification admission differs from current root request")
        with self._lock:
            self._qualification_admissions[admission.admission_handle] = request_handle
        return admission

    def is_application_admission_current(self, admission_handle: str) -> bool:
        check = getattr(self.journal, "is_application_admission_current", None)
        try:
            if (not _handle(admission_handle) or not callable(check) or check(admission_handle) is not True
                    or self.service.service_generation_digest is None):
                return False
            with self._lock:
                invocation = self._admission_invocations.get(admission_handle)
                action = self._admission_actions.get(admission_handle)
                qualification_handle = self._qualification_admissions.get(admission_handle)
            if qualification_handle is not None:
                return self._qualification_context_current(qualification_handle, require_unconsumed=False)
            verify_action = getattr(self.catalog, "is_selected_workload_action_current", None)
            return bool(invocation is not None and action is not None
                        and self.invocations.is_selected_application_invocation_current(invocation) is True
                        and callable(verify_action) and verify_action(invocation, action) is True)
        except Exception:
            return False

    def _current(self, step: RootApplicationSelectedStep) -> bool:
        try:
            invocation = self._admission_invocations.get(step.admission_handle)
            action = self._admission_actions.get(step.admission_handle)
            qualification_handle = self._qualification_admissions.get(step.admission_handle)
            if qualification_handle is not None:
                record = self._qualification_requests.get(qualification_handle)
                if record is None or not self._qualification_context_current(
                        qualification_handle, require_unconsumed=False):
                    return False
                request = record[0]
                return (request.application_id == step.application_id
                    and request.profile_id == step.profile_id
                    and request.profile_generation == step.profile_generation
                    and request.enclosing_service_generation_digest == step.service_generation_digest
                    and self.journal.is_application_step_current(step.handle) is True
                    and self._qualification_context_producer is not None
                    and self._qualification_context_producer.is_current(
                        record[1], request.workflow_id) is True
                    and self._qualification_context_producer.is_controller_current(
                        step.controller_binding_handle) is True)
            verify_action = getattr(self.catalog, "is_selected_workload_action_current", None)
            return (self.is_application_admission_current(step.admission_handle)
                    and invocation is not None and action is not None
                    and self.invocations.is_selected_application_invocation_current(invocation) is True
                    and callable(verify_action) and verify_action(invocation, action) is True
                    and self.journal.is_application_step_current(step.handle) is True
                    and self.service.service_generation_digest == step.service_generation_digest
                    and self.sources.resolve(step.source_receipt_handle,
                        application_id=step.application_id,
                        service_generation_digest=step.service_generation_digest) is not None
                    and self.runtimes.resolve(step.runtime_receipt_handle,
                        application_id=step.application_id,
                        source_receipt_handle=step.source_receipt_handle,
                        service_generation_digest=step.service_generation_digest) is not None
                    and self.controllers.is_binding_current(step.controller_binding_handle) is True)
        except Exception:
            return False

    def issue_root_application_start(self, admission_handle: str,
                                     step_id: str) -> RootApplicationStartGrant:
        step = self.resolve_application_step(admission_handle, step_id)
        service = self.service
        is_probe = step.role == "application-runtime-probe"
        current = (self._probe_selection_current(*self._probe_steps[admission_handle],
                    self._application_preparations) if is_probe else self._current(step))
        if (step.role not in _ROLES or not current
                or service.monotonic() >= step.deadline_monotonic
                or (not is_probe and step.operation_id not in self.journal.resolve_application_admission(
                    admission_handle).operation_recipe_ids)):
            raise AuthorityDenied("application.start", "selected application admission or step is not current")
        profile = getattr(service.process_effect_handler, "profiles", {}).get(step.profile_id)
        if (profile is None or profile.generation != step.profile_generation
                or not isinstance(profile.operation_recipes, Mapping)
                or step.operation_id not in profile.operation_recipes):
            raise AuthorityDenied("application.start", "selected application process recipe is unavailable")
        recipe = profile.operation_recipes[step.operation_id]
        if (not isinstance(recipe, Mapping) or recipe.get("stdin_mode") != "closed"
                or type(recipe.get("max_output_bytes")) is not int
                or not 1 <= recipe["max_output_bytes"] <= 4 * 1024 * 1024
                or recipe.get("max_lifetime_seconds", 0) > 600):
            raise AuthorityDenied("application.recipe", "selected application recipe exceeds closed input/output/lifetime bounds")
        is_qualification = self._qualification_admissions.get(step.admission_handle) is not None
        if is_qualification and self._qualification_context_producer is not None:
            controller = self._qualification_context_producer.resolve_controller_binding(
                step.controller_binding_handle)
            controller_current = self._qualification_context_producer.is_controller_current(
                step.controller_binding_handle)
        else:
            controller = self.controllers.resolve_binding(step.controller_binding_handle)
            controller_current = (controller is not None
                and self.controllers.verify_binding(controller) is True)
        if controller is None or not controller_current:
            raise AuthorityDenied("application.start", "root application controller proof is stale")
        now = service.monotonic()
        expiry = min(now + 30.0, step.deadline_monotonic)
        if expiry <= now:
            raise AuthorityDenied("application.expired", "selected application step expired")
        nonce, grant_id, ctxid = secrets.token_hex(32), secrets.token_urlsafe(24), secrets.token_urlsafe(24)
        target = getattr(profile, "operation_targets", {}).get("process.start")
        if not isinstance(target, str) or not target:
            raise AuthorityDenied("application.target", "selected process.start target is not protected")
        context_fields = dict(
            schema=1, context_handle=ctxid, admission_handle=step.admission_handle,
            application_id=step.application_id, workload_id=step.workload_id,
            step_id=step.step_id, sequence=step.sequence, profile_id=step.profile_id,
            profile_generation=step.profile_generation,
            principal_id=getattr(controller, "principal_id", ""),
            enrollment_id=profile.enrollment_id, operation_id=step.operation_id,
            subject_uid=getattr(profile, "owner_uid", 0), subject_gid=getattr(profile, "owner_gid", -1),
            service_generation_digest=step.service_generation_digest, role=step.role,
            operation="process.start", capability=("hermes-application-runtime-probe"
                if is_probe else "hermes-application-workload-invoke"),
            target=target, request_sha256=step.request_sha256,
            source_receipt_handle=step.source_receipt_handle,
            runtime_receipt_handle=step.runtime_receipt_handle,
            source_closure_sha256=step.source_closure_sha256,
            controller_binding_handle=step.controller_binding_handle,
            issued_monotonic=now, expires_monotonic=expiry, nonce=nonce, signature="pending")
        ctx = RootApplicationExecutionContext(**context_fields)
        ctx = RootApplicationExecutionContext(**{**ctx.claims(), "signature": service._sign_root_selected(
            "root-application-execution-context-v1", ctx.claims())})
        ctx_digest = hashlib.sha256(canonical_bytes({**ctx.claims(), "signature": ctx.signature})).hexdigest()
        auth_fields = dict(
            schema=1, grant_id=grant_id, context_sha256=ctx_digest,
            admission_handle=step.admission_handle, operation="process.start",
            capability=ctx.capability, target=target,
            request_sha256=hashlib.sha256(step.selection_payload).hexdigest(), nonce=nonce,
            issued_monotonic=now, expires_monotonic=expiry, signature="pending")
        auth = RootApplicationExecutionAuthorization(**auth_fields)
        auth = RootApplicationExecutionAuthorization(**{**auth.claims(), "signature": service._sign_root_selected(
            "root-application-execution-effect-v1", auth.claims())})
        grant = RootApplicationStartGrant(ctx, auth)
        with self._lock:
            self._prune(now)
            if len(self._grants) >= 4096 or nonce in self._nonces:
                raise AuthorityDenied("application.capacity", "application grant registry is unavailable")
            self._grants[grant_id] = _GrantEntry(grant, step, profile, controller)
            self._nonces[nonce] = ("pending", expiry)
        return grant

    def _grant_step_current(self, entry: _GrantEntry) -> bool:
        if entry.step.role != "application-runtime-probe":
            return self._current(entry.step)
        with self._lock:
            retained = self._probe_steps.get(entry.step.preparation_selection_handle)
            preparations = self._application_preparations
        return bool(retained is not None and retained[1] is entry.step
                    and self._probe_selection_current(retained[0], entry.step, preparations))

    def consume_root_application_start(self, grant: RootApplicationStartGrant,
                                       canonical_selection_payload: bytes) -> VerifiedRootApplicationStart:
        if type(grant) is not RootApplicationStartGrant:
            raise AuthorityDenied("application.start", "root application grant has invalid type")
        ctx, auth = grant.context, grant.authorization
        step_payload = _canonical(canonical_selection_payload)
        now, service = self.service.monotonic(), self.service
        service._verify_root_selected_signature("root-application-execution-context-v1", ctx.claims(), ctx.signature)
        service._verify_root_selected_signature("root-application-execution-effect-v1", auth.claims(), auth.signature)
        with self._lock:
            self._prune(now)
            entry = self._grants.get(auth.grant_id)
            if (entry is None or entry.grant is not grant or entry.state != "pending"
                    or self._nonces.get(auth.nonce) != ("pending", auth.expires_monotonic)
                    or auth.request_sha256 != hashlib.sha256(canonical_selection_payload).hexdigest()
                    or entry.step.selection_payload != canonical_selection_payload
                    or auth.expires_monotonic <= now or auth.context_sha256 != hashlib.sha256(
                        canonical_bytes({**ctx.claims(), "signature": ctx.signature})).hexdigest()
                    or not self._grant_step_current(entry)):
                raise AuthorityDenied("application.start", "application grant is stale, mismatched or spent")
            if (ctx.admission_handle != entry.step.admission_handle
                    or ctx.application_id != entry.step.application_id or ctx.workload_id != entry.step.workload_id
                    or ctx.step_id != entry.step.step_id or ctx.sequence != entry.step.sequence
                    or ctx.profile_id != entry.profile.profile_id or ctx.profile_generation != entry.profile.generation
                    or ctx.request_sha256 != entry.step.request_sha256
                    or ctx.source_receipt_handle != entry.step.source_receipt_handle
                    or ctx.runtime_receipt_handle != entry.step.runtime_receipt_handle
                    or auth.operation != "process.start" or auth.target != ctx.target
                    or auth.capability != ctx.capability):
                raise AuthorityDenied("application.start", "application grant does not bind the retained step")
            self._nonces[auth.nonce] = ("consumed", auth.expires_monotonic)
            proof = VerifiedRootApplicationStart(ctx, auth, entry.profile, entry.step, self, self._seal, auth.nonce)
            entry.state, entry.proof = "consumed", proof
            return proof

    def verify_consumed_start(self, proof: VerifiedRootApplicationStart,
                              canonical_selection_payload: bytes, *, selected_step_handle: str) -> bool:
        try:
            if (type(proof) is not VerifiedRootApplicationStart or proof._issuer is not self
                    or proof._seal is not self._seal or proof._nonce != proof.authorization.nonce):
                return False
            with self._lock:
                entry = self._grants.get(proof.authorization.grant_id)
                return bool(entry and entry.state == "consumed" and entry.proof is proof
                            and entry.step.handle == selected_step_handle
                            and entry.step.selection_payload == canonical_selection_payload
                            and self._grant_step_current(entry)
                            and self.service.monotonic() < proof.authorization.expires_monotonic)
        except Exception:
            return False

    def verify_consumed_application_start(self, proof: VerifiedRootApplicationStart,
                                          canonical_selection_payload: bytes, *,
                                          selected_step_handle: str) -> bool:
        return self.verify_consumed_start(proof, canonical_selection_payload,
                                          selected_step_handle=selected_step_handle)

    def _prune(self, now: float) -> None:
        for grant_id, entry in tuple(self._grants.items()):
            if entry.grant.authorization.expires_monotonic <= now:
                self._grants.pop(grant_id, None)
        for nonce, (_, expiry) in tuple(self._nonces.items()):
            if expiry <= now:
                self._nonces.pop(nonce, None)


class ManagedApplicationWorkloadRunner:
    """Application terminal and capsule consumer; never accepts process argv."""

    def __init__(self, authority: RootApplicationWorkloadAuthority, managed_process_custodian: Any,
                 selected_validator_registry: Any, root_journal: Any):
        self.authority, self.manager = authority, managed_process_custodian
        self.validators, self.journal = selected_validator_registry, root_journal

    def start_selected_application(self, profile_id: str, verified_start: VerifiedRootApplicationStart,
                                   canonical_selection_payload: bytes, *, selected_step_handle: str,
                                   timeout: float, cancelled: Any) -> Any:
        if (type(verified_start) is not VerifiedRootApplicationStart
                or verified_start.selected_profile.profile_id != profile_id
                or not self.authority.verify_consumed_start(verified_start, canonical_selection_payload,
                                                            selected_step_handle=selected_step_handle)):
            raise AuthorityDenied("application.start", "consumed selected application grant is invalid")
        return self.manager.start_selected_application(
            profile_id, verified_start, canonical_selection_payload,
            selected_step_handle=selected_step_handle, timeout=timeout, cancelled=cancelled)

    def wait_owned_application_terminal(self, handle: Any, *, timeout: float,
                                        cancelled: Any) -> RootApplicationTerminalReceipt:
        return self.manager.wait_owned_application_terminal(handle, timeout=timeout, cancelled=cancelled)

    def run_selected_runtime_probe_step(self, selection: Any, step: RootApplicationSelectedStep,
                                        custodian: Any) -> RootApplicationRuntimeProbeReceipt:
        """Run only the setup registry's fixed ABI probe through application custody."""
        authority = self.authority
        preparations = authority._application_preparations
        if (type(selection) is not _runtime_preparation_selection_type()
                or type(step) is not RootApplicationSelectedStep or custodian is not self.manager
                or preparations is None or step.role != "application-runtime-probe"
                or step.preparation_selection_handle != selection.handle
                or not authority._probe_selection_current(selection, step, preparations)):
            raise AuthorityDenied("application.probe", "pre-active probe step is not root-selected")
        grant = authority.issue_root_application_runtime_probe_start(selection.handle)
        proof = authority.consume_root_application_start(grant, step.selection_payload)
        remaining = max(0.001, min(30.0, step.deadline_monotonic-authority.service.monotonic()))
        handle = self.start_selected_application(step.profile_id, proof, step.selection_payload,
            selected_step_handle=step.handle, timeout=remaining, cancelled=lambda: False)
        terminal = self.wait_owned_application_terminal(handle, timeout=remaining, cancelled=lambda: False)
        retained = self.manager.resolve_application_terminal(terminal.receipt_handle)
        authority.service._verify_root_selected_signature(
            "root-application-terminal-v1", retained.claims(), retained.signature)
        stdout, stderr = self.manager.resolve_application_output(retained.output_observation_handle)
        if (type(retained) is not RootApplicationTerminalReceipt
                or retained.receipt_handle != terminal.receipt_handle
                or retained.admission_handle != selection.handle
                or retained.application_id != selection.application_id
                or retained.workload_id != step.workload_id or retained.step_id != step.step_id
                or retained.profile_id != selection.profile_id
                or retained.profile_generation != selection.profile_generation
                or retained.service_generation_digest != selection.service_selection_digest
                or retained.source_receipt_handle != selection.source_receipt_handle
                or retained.runtime_receipt_handle != selection.handle
                or retained.state != "completed" or retained.exit_code != 0 or not retained.reaped
                or retained.cancelled or retained.timed_out or not retained.stdin_eof
                or len(stdout) != retained.stdout_size_bytes or len(stderr) != retained.stderr_size_bytes
                or len(stdout) > 65536 or len(stderr) > 65536
                or hashlib.sha256(stdout).hexdigest() != retained.stdout_sha256
                or hashlib.sha256(stderr).hexdigest() != retained.stderr_sha256
                or not authority._probe_selection_current(selection, step, preparations)):
            raise AuthorityDenied("application.probe", "managed probe terminal/output is incomplete or stale")
        try:
            facts = json.loads(stdout.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            raise AuthorityDenied("application.probe", "managed ABI probe output is malformed") from None
        if (not isinstance(facts, dict) or set(facts) !=
                {"python_version", "SOABI", "machine", "platform", "import_origins"}
                or any(not isinstance(facts.get(name), str) or not facts[name]
                       for name in ("python_version", "SOABI", "machine", "platform"))
                or not isinstance(facts["import_origins"], list) or not facts["import_origins"]
                or any(not isinstance(item, str) or not item.startswith("/")
                       for item in facts["import_origins"])):
            raise AuthorityDenied("application.probe", "managed ABI probe facts violate the fixed schema")
        root_resolver = getattr(preparations, "resolve_application_runtime_root", None)
        if not callable(root_resolver):
            raise AuthorityDenied("application.probe", "selected runtime root verifier is unavailable")
        try:
            root = Path(root_resolver(selection.handle)).resolve(strict=True)
            origins = tuple(Path(item).resolve(strict=True) for item in facts["import_origins"])
            if any(not item.is_relative_to(root) or item.is_symlink() for item in origins):
                raise ValueError
        except (OSError, TypeError, ValueError):
            raise AuthorityDenied("application.probe", "observed module origin escaped the selected runtime") from None
        now = authority.service.monotonic()
        fields = dict(schema=1, handle=secrets.token_urlsafe(32),
            application_id=selection.application_id,
            preparation_selection_handle=selection.handle,
            source_receipt_handle=selection.source_receipt_handle,
            lock_sha256=selection.lock_sha256,
            runtime_manifest_sha256=selection.runtime_manifest_sha256,
            toolchain_artifact_receipt_handles=selection.toolchain_artifact_receipt_handles,
            terminal_receipt_handle=retained.receipt_handle,
            python_version=facts["python_version"], SOABI=facts["SOABI"],
            machine=facts["machine"], platform=facts["platform"],
            import_origins_sha256=hashlib.sha256(canonical_bytes(facts["import_origins"])).hexdigest(),
            service_selection_digest=selection.service_selection_digest,
            issued_monotonic=now,
            expires_monotonic=min(selection.expires_monotonic, retained.expires_monotonic, now+30.0),
            signature="pending")
        unsigned = RootApplicationRuntimeProbeReceipt(**fields)
        fields["signature"] = authority.service._sign_root_selected(
            "root-application-runtime-probe-v1", unsigned.claims())
        return RootApplicationRuntimeProbeReceipt(**fields)

    def validate_selected_terminal(self, admission_handle: str,
                                   terminal_receipt_handle: str) -> RootApplicationResultCapsule:
        terminal = self.manager.resolve_application_terminal(terminal_receipt_handle)
        if (type(terminal) is not RootApplicationTerminalReceipt
                or terminal.admission_handle != admission_handle or terminal.state != "completed"
                or terminal.exit_code != 0 or not terminal.reaped or not terminal.stdin_eof
                or terminal.cancelled or terminal.timed_out or not _digest(terminal.stdout_sha256)
                or not _digest(terminal.stderr_sha256)):
            raise AuthorityDenied("application.terminal", "application terminal is unsuccessful or incomplete")
        self.authority.service._verify_root_selected_signature(
            "root-application-terminal-v1", terminal.claims(), terminal.signature)
        step = self.authority.resolve_application_step(admission_handle, terminal.step_id)
        if (terminal.application_id != step.application_id or terminal.workload_id != step.workload_id
                or terminal.sequence != step.sequence or terminal.profile_id != step.profile_id
                or terminal.profile_generation != step.profile_generation
                or terminal.service_generation_digest != step.service_generation_digest
                or terminal.request_sha256 != step.request_sha256
                or terminal.source_receipt_handle != step.source_receipt_handle
                or terminal.runtime_receipt_handle != step.runtime_receipt_handle
                or not self.authority._current(step)):
            raise AuthorityDenied("application.terminal", "application terminal differs from current selected step")
        validator = self.validators.resolve_application_result(step)
        payload = validator.validate_terminal(terminal, self.manager.resolve_application_output(
            terminal.output_observation_handle))
        raw = canonical_bytes(payload)
        if not raw or len(raw) > validator.maximum_bytes:
            raise AuthorityDenied("application.result", "validated application result exceeds its selected bound")
        now = self.authority.service.monotonic()
        fields = dict(schema=1, handle=secrets.token_urlsafe(32), admission_handle=admission_handle,
                      terminal_receipt_handle=terminal_receipt_handle,
                      application_id=step.application_id, workload_id=step.workload_id,
                      step_id=step.step_id, result_schema_id=validator.result_schema_id,
                      validator_artifact_id=validator.artifact_id, validator_sha256=validator.sha256,
                      payload_sha256=hashlib.sha256(raw).hexdigest(), payload_size_bytes=len(raw),
                      source_closure_sha256=step.source_closure_sha256,
                      service_generation_digest=step.service_generation_digest,
                      issued_monotonic=now, expires_monotonic=min(step.deadline_monotonic, now + 30.0),
                      signature="pending")
        capsule = RootApplicationResultCapsule(**fields)
        capsule = RootApplicationResultCapsule(**{**capsule.claims(), "signature":
            self.authority.service._sign_root_selected("root-application-result-capsule-v1", capsule.claims())})
        store = getattr(self.journal, "retain_application_result_capsule", None)
        if not callable(store):
            raise AuthorityDenied("application.result", "root application capsule store is unavailable")
        store(capsule, raw, terminal)
        return capsule

    def resolve_selected_result_capsule(self, handle: str) -> tuple[RootApplicationResultCapsule, bytes]:
        resolve = getattr(self.journal, "resolve_application_result_capsule", None)
        if not _handle(handle) or not callable(resolve):
            raise AuthorityDenied("application.result", "root application result capsule resolver is unavailable")
        value = resolve(handle)
        if (not isinstance(value, tuple) or len(value) != 2
                or type(value[0]) is not RootApplicationResultCapsule
                or not isinstance(value[1], bytes)):
            raise AuthorityDenied("application.result", "root application result capsule is malformed")
        capsule, payload = value
        self.authority.service._verify_root_selected_signature(
            "root-application-result-capsule-v1", capsule.claims(), capsule.signature)
        terminal = self.manager.resolve_application_terminal(capsule.terminal_receipt_handle)
        step = self.authority.resolve_application_step(capsule.admission_handle, capsule.step_id)
        if (capsule.handle != handle or capsule.expires_monotonic <= self.authority.service.monotonic()
                or hashlib.sha256(payload).hexdigest() != capsule.payload_sha256
                or len(payload) != capsule.payload_size_bytes or len(payload) > 65536
                or capsule.application_id != step.application_id or capsule.workload_id != step.workload_id
                or capsule.source_closure_sha256 != step.source_closure_sha256
                or capsule.service_generation_digest != step.service_generation_digest
                or terminal.receipt_handle != capsule.terminal_receipt_handle
                or not self.authority._current(step)):
            raise AuthorityDenied("application.result", "root result capsule is stale or differs from its terminal")
        return capsule, payload

    def run_selected_workload(self, admission_handle: str) -> RootApplicationRunReceipt:
        """Run only journal-retained steps and return the canonical public receipt."""
        if not self.authority.is_application_admission_current(admission_handle):
            raise AuthorityDenied("application.admission", "application workload admission is stale")
        list_steps = getattr(self.journal, "resolve_application_steps", None)
        resolve_admission = getattr(self.journal, "resolve_application_admission", None)
        if not callable(list_steps) or not callable(resolve_admission):
            raise AuthorityDenied("application.journal", "root application step journal is unavailable")
        admission = resolve_admission(admission_handle)
        if type(admission) is not RootApplicationWorkloadAdmission:
            raise AuthorityDenied("application.journal", "root application admission is untyped")
        steps = list_steps(admission_handle)
        if (not isinstance(steps, (tuple, list)) or not 1 <= len(steps) <= admission.max_steps
                or any(type(item) is not RootApplicationSelectedStep for item in steps)):
            raise AuthorityDenied("application.journal", "root application steps are malformed or outside bounds")
        terminal_handle = ""
        capsule_handle = ""
        state = "complete"
        for step in steps:
            if not self.authority.is_application_admission_current(admission_handle):
                state = "ambiguous"
                break
            try:
                grant = self.authority.issue_root_application_start(admission_handle, step.step_id)
                proof = self.authority.consume_root_application_start(grant, step.selection_payload)
                handle = self.start_selected_application(
                    step.profile_id, proof, step.selection_payload,
                    selected_step_handle=step.handle,
                    timeout=max(.001, min(600.0, step.deadline_monotonic-self.authority.service.monotonic())),
                    cancelled=lambda: False)
                terminal = self.wait_owned_application_terminal(
                    handle, timeout=max(.001, step.deadline_monotonic-self.authority.service.monotonic()),
                    cancelled=lambda: False)
                terminal_handle = terminal.receipt_handle
                capsule = self.validate_selected_terminal(admission_handle, terminal_handle)
                capsule_handle = capsule.handle
            except Exception:
                state = "failed"
                break
        now = self.authority.service.monotonic()
        fields = dict(
            schema=1, receipt_handle=secrets.token_urlsafe(32),
            application_id=admission.application_id, profile_id=admission.profile_id,
            profile_generation=admission.profile_generation,
            service_generation_digest=admission.service_generation_digest,
            source_receipt_handle=admission.source_receipt_handle,
            runtime_receipt_handle=admission.runtime_receipt_handle,
            operation_id=admission.operation_recipe_ids[0] if admission.operation_recipe_ids else "",
            request_sha256=admission.request_sha256,
            terminal_receipt_handle=terminal_handle, result_capsule_handle=capsule_handle,
            state=state, issued_monotonic=now,
            expires_monotonic=min(admission.expires_monotonic, now+30.0))
        return RootApplicationRunReceipt(**fields)


@dataclass(frozen=True, slots=True)
class RootApplicationRuntimeProbeReceipt:
    schema: int
    handle: str
    application_id: str
    preparation_selection_handle: str
    source_receipt_handle: str
    lock_sha256: str
    runtime_manifest_sha256: str
    toolchain_artifact_receipt_handles: tuple[str, ...]
    terminal_receipt_handle: str
    python_version: str
    SOABI: str
    machine: str
    platform: str
    import_origins_sha256: str
    service_selection_digest: str
    issued_monotonic: float
    expires_monotonic: float
    signature: str

    def claims(self) -> dict[str, Any]:
        return {name: getattr(self, name) for name in self.__dataclass_fields__ if name != "signature"}


class RootApplicationRuntimeProbeAuthority:
    """Pre-active-row bounded runtime probe receipt producer."""

    def __init__(self, service: Any, preparation_resolver: Any, runner: ManagedApplicationWorkloadRunner,
                 custodian: Any):
        self.service, self.preparations, self.runner, self.custodian = service, preparation_resolver, runner, custodian
        runner.authority.attach_application_preparation_resolver(preparation_resolver)
        self._receipts: dict[str, tuple[RootApplicationRuntimeProbeReceipt, Any]] = {}
        self._lock = threading.RLock()

    def run_selected_runtime_probe(self, preparation_selection_handle: str) -> RootApplicationRuntimeProbeReceipt:
        resolve = getattr(self.preparations, "resolve_application_runtime_preparation_selection", None)
        if not _handle(preparation_selection_handle) or not callable(resolve):
            raise AuthorityDenied("application.probe", "root preparation selection is unavailable")
        selection = resolve(preparation_selection_handle)
        if (type(selection) is not _runtime_preparation_selection_type()
                or getattr(selection, "handle", None) != preparation_selection_handle):
            raise AuthorityDenied("application.probe", "root preparation selection is stale")
        step_resolver = getattr(self.preparations, "resolve_application_runtime_probe_step", None)
        if not callable(step_resolver):
            raise AuthorityDenied("application.probe", "pre-active selection has no sealed runtime-probe step")
        step = step_resolver(preparation_selection_handle)
        if type(step) is not RootApplicationSelectedStep or step.role != "application-runtime-probe":
            raise AuthorityDenied("application.probe", "pre-active selection returned no typed probe-role step")
        # There is deliberately no generic custodian command hook. A concrete
        # probe requires a separately consumed root app-start grant and must
        # pass through the same PIDFD/cgroup/systemd start and terminal path.
        execute = getattr(self.runner, "run_selected_runtime_probe_step", None)
        if not callable(execute):
            raise AuthorityDenied("application.probe", "distinct root probe grant issuer is not attached")
        receipt = execute(selection, step, self.custodian)
        if type(receipt) is not RootApplicationRuntimeProbeReceipt:
            raise AuthorityDenied("application.probe", "runner returned no typed runtime-probe receipt")
        if (receipt.preparation_selection_handle != preparation_selection_handle
                or receipt.application_id != getattr(selection, "application_id", None)
                or receipt.terminal_receipt_handle == ""):
            raise AuthorityDenied("application.probe", "managed probe receipt differs from its preparation selection")
        self.service._verify_root_selected_signature(
            "root-application-runtime-probe-v1", receipt.claims(), receipt.signature)
        with self._lock:
            if len(self._receipts) >= 512:
                raise AuthorityDenied("application.probe", "runtime probe receipt registry is full")
            self._receipts[receipt.handle] = (receipt, selection)
        return receipt

    def resolve_application_runtime_probe(self, handle: str) -> RootApplicationRuntimeProbeReceipt:
        with self._lock:
            item = self._receipts.get(handle)
            if item is None or item[0].expires_monotonic <= self.service.monotonic():
                raise AuthorityDenied("application.probe", "runtime probe receipt is unavailable")
        receipt, retained_selection = item
        self.service._verify_root_selected_signature(
            "root-application-runtime-probe-v1", receipt.claims(), receipt.signature)
        resolve = getattr(self.preparations, "resolve_application_runtime_preparation_selection", None)
        if not callable(resolve):
            raise AuthorityDenied("application.probe", "root preparation currentness resolver is unavailable")
        current_selection = resolve(receipt.preparation_selection_handle)
        step_resolver = getattr(self.preparations, "resolve_application_runtime_probe_step", None)
        if not callable(step_resolver):
            raise AuthorityDenied("application.probe", "root fixed probe-step resolver is unavailable")
        current_step = step_resolver(receipt.preparation_selection_handle)
        if (current_selection is not retained_selection
                or type(current_step) is not RootApplicationSelectedStep
                or not self.runner.authority._probe_selection_current(
                    retained_selection, current_step, self.preparations)
                or receipt.expires_monotonic <= self.service.monotonic()):
            raise AuthorityDenied("application.probe", "runtime preparation selection changed")
        terminal = self.custodian.resolve_application_terminal(receipt.terminal_receipt_handle)
        if type(terminal) is not RootApplicationTerminalReceipt:
            raise AuthorityDenied("application.probe", "retained runtime probe terminal has invalid type")
        self.service._verify_root_selected_signature(
            "root-application-terminal-v1", terminal.claims(), terminal.signature)
        stdout, stderr = self.custodian.resolve_application_output(terminal.output_observation_handle)
        if (terminal.receipt_handle != receipt.terminal_receipt_handle
                or terminal.admission_handle != retained_selection.handle
                or terminal.application_id != retained_selection.application_id
                or terminal.workload_id != current_step.workload_id
                or terminal.step_id != current_step.step_id
                or terminal.profile_id != current_step.profile_id
                or terminal.profile_generation != current_step.profile_generation
                or terminal.service_generation_digest != retained_selection.service_selection_digest
                or terminal.source_receipt_handle != retained_selection.source_receipt_handle
                or terminal.runtime_receipt_handle != retained_selection.handle
                or terminal.state != "completed" or terminal.exit_code != 0 or not terminal.reaped
                or terminal.cancelled or terminal.timed_out or not terminal.stdin_eof
                or hashlib.sha256(stdout).hexdigest() != terminal.stdout_sha256
                or len(stdout) != terminal.stdout_size_bytes
                or hashlib.sha256(stderr).hexdigest() != terminal.stderr_sha256
                or len(stderr) != terminal.stderr_size_bytes or len(stdout) > 65536 or len(stderr) > 65536):
            raise AuthorityDenied("application.probe", "managed runtime probe terminal or output is stale")
        try:
            facts = json.loads(stdout.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            raise AuthorityDenied("application.probe", "runtime probe output is malformed") from None
        if (not isinstance(facts, dict) or set(facts) !=
                {"python_version", "SOABI", "machine", "platform", "import_origins"}
                or any(not isinstance(facts.get(name), str) or not facts[name]
                       for name in ("python_version", "SOABI", "machine", "platform"))
                or not isinstance(facts.get("import_origins"), list)
                or not facts["import_origins"]
                or any(not isinstance(origin, str) or not origin.startswith("/")
                       for origin in facts["import_origins"])):
            raise AuthorityDenied("application.probe", "runtime probe facts do not match the fixed ABI schema")
        root_resolver = getattr(self.preparations, "resolve_application_runtime_root", None)
        if not callable(root_resolver):
            raise AuthorityDenied("application.probe", "selected runtime root verifier is unavailable")
        try:
            runtime_root = root_resolver(receipt.preparation_selection_handle)
            root = Path(runtime_root).resolve(strict=True)
            origins = tuple(Path(item).resolve(strict=True) for item in facts["import_origins"])
            if any(not origin.is_relative_to(root) or origin.is_symlink() for origin in origins):
                raise ValueError
        except (OSError, TypeError, ValueError):
            raise AuthorityDenied("application.probe", "runtime import origin escaped the selected runtime root") from None
        origins_digest = hashlib.sha256(canonical_bytes(facts["import_origins"])).hexdigest()
        if (receipt.python_version != facts["python_version"] or receipt.SOABI != facts["SOABI"]
                or receipt.machine != facts["machine"] or receipt.platform != facts["platform"]
                or receipt.import_origins_sha256 != origins_digest
                or receipt.application_id != getattr(current_selection, "application_id", None)
                or receipt.source_receipt_handle != getattr(current_selection, "source_receipt_handle", None)
                or receipt.lock_sha256 != getattr(current_selection, "lock_sha256", None)
                or receipt.runtime_manifest_sha256 != getattr(current_selection, "runtime_manifest_sha256", None)
                or receipt.service_selection_digest != getattr(current_selection, "service_selection_digest", None)):
            raise AuthorityDenied("application.probe", "runtime probe receipt differs from current root observations")
        return receipt
