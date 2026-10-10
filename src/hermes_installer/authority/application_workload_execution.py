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
import secrets
import threading
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
    _BODY = b"<!doctype html><title>Hermes qualification fixture</title><p>fixture only</p>"

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

    def start(self, *, setup_session_id: str, controller_binding_handle: str) -> RootApplicationFixtureReceipt:
        if (not isinstance(setup_session_id, str) or not setup_session_id
                or not _handle(controller_binding_handle)):
            raise AuthorityDenied("application.fixture", "fixture requires a live setup session and controller")
        with self._lock:
            if self._receipt is not None:
                raise AuthorityDenied("application.fixture", "fixture listener is one-use")
            binding = self._controllers.resolve_binding(controller_binding_handle)
            if binding is None or self._controllers.verify_binding(binding) is not True:
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
        binding = self._controllers.resolve_binding(receipt.controller_binding_handle)
        if binding is None or self._controllers.verify_binding(binding) is not True:
            raise AuthorityDenied("application.fixture", "fixture controller binding is stale")
        return receipt

    def close(self) -> None:
        with self._lock:
            server, self._server, self._thread = self._server, None, None
        if server is not None:
            server.shutdown()
            server.server_close()


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
        self._qualification_requests: dict[str, tuple[RootApplicationQualificationRequest,
            RootApplicationQualificationContext, bytes, Any, str]] = {}

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
        """Create a root-projected fixture request from a live installer setup session."""
        if (not _handle(root_setup_session_handle) or workflow_id not in _QUALIFICATION_WORKFLOWS):
            raise AuthorityDenied("application.qualification", "qualification selector is malformed or unsupported")
        resolve = getattr(self.catalog, "resolve_selected_application_qualification_context", None)
        if not callable(resolve):
            raise AuthorityDenied("application.qualification", "root setup/session qualification resolver is unavailable")
        context = resolve(root_setup_session_handle, workflow_id)
        if type(context) is not RootApplicationQualificationContext:
            raise AuthorityDenied("application.qualification", "root setup resolver returned no typed qualification context")
        app_id, workload_id, argument_names = _QUALIFICATION_WORKFLOWS[workflow_id]
        if (context.application_id != app_id or context.enclosing_service_generation_digest != self.service.service_generation_digest
                or context.revocation_epoch < 0 or not context.source_receipt_handles
                or not _digest(context.selected_runtime_row_sha256)
                or not _digest(context.source_context_digest)
                or not _digest(context.observed_request_sha256)
                or not _handle(context.controller_binding_handle)
                or (context.fixture_receipt_handle and not _handle(context.fixture_receipt_handle))):
            raise AuthorityDenied("application.qualification", "root setup context does not match the finite qualification workflow")
        selection = self.catalog.resolve_selected_application_runtime(app_id, profile_id=context.profile_id)
        from hermes_installer.authority.application_runtime import RootSelectedApplicationRuntime
        if (type(selection) is not RootSelectedApplicationRuntime or selection.enabled is not True
                or selection.application_id != app_id or selection.profile_generation != context.profile_generation
                or selection.principal_id != context.principal_id or selection.adapter_id != context.adapter_id
                or selection.service_generation_digest != context.enclosing_service_generation_digest
                or selection.max_workers != 1 or selection.metered_budget_usd != "0"):
            raise AuthorityDenied("application.qualification", "selected runtime row is stale or exceeds qualification limits")
        if (not self.catalog.is_selected_application_qualification_context_current(
                root_setup_session_handle, workflow_id, context) is True
                or not self.catalog.is_selected_application_qualification_consent_current(context, workflow_id) is True):
            raise AuthorityDenied("application.qualification", "setup session, controller or qualification consent is stale")
        controller = self.controllers.resolve_binding(context.controller_binding_handle)
        if controller is None or self.controllers.verify_binding(controller) is not True:
            raise AuthorityDenied("application.controller", "qualification controller proof is stale")
        for source_handle in context.source_receipt_handles:
            self.sources.resolve(source_handle, application_id=app_id,
                service_generation_digest=context.enclosing_service_generation_digest)
        self.runtimes.resolve(selection.runtime_receipt_handle, application_id=app_id,
            source_receipt_handle=selection.source_generation_receipt_handle,
            service_generation_digest=context.enclosing_service_generation_digest)
        fixture_url = None
        if workload_id == "browser-fixture":
            fixture = self.catalog.resolve_owned_application_fixture(context.fixture_receipt_handle)
            fixture_url = getattr(fixture, "url", None)
            if (getattr(fixture, "handle", None) != context.fixture_receipt_handle
                    or not _owned_loopback_url(fixture_url)):
                raise AuthorityDenied("application.fixture", "owned loopback browser fixture receipt is unavailable")
        elif context.fixture_receipt_handle != "" and not self.catalog.is_empty_fixture_receipt_current(
                context.fixture_receipt_handle, workflow_id):
            raise AuthorityDenied("application.fixture", "empty fixture receipt differs from selected workflow")
        arguments = {"fixture_url": fixture_url} if argument_names else {}
        projected = json.dumps({"id": workload_id, "arguments": arguments}, sort_keys=True,
            separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
        now = self.service.monotonic()
        handle, request_id = secrets.token_urlsafe(32), secrets.token_urlsafe(24)
        request = RootApplicationQualificationRequest(
            1, handle, request_id, "installer-application-qualification", workflow_id,
            app_id, context.adapter_id, context.profile_id, context.profile_generation,
            context.principal_id, context.namespace_id,
            context.enclosing_service_generation_digest, context.selected_runtime_row_sha256,
            context.setup_session_id, context.controller_binding_handle,
            context.source_receipt_handles, context.source_context_digest,
            hashlib.sha256(projected).hexdigest(), context.argument_schema_id,
            context.fixture_receipt_handle, now, min(now+120.0, controller.expires_monotonic),
            context.revocation_epoch)
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
            current = bool(request.expires_monotonic > self.service.monotonic()
                and request.enclosing_service_generation_digest == self.service.service_generation_digest
                and self.catalog.is_selected_application_qualification_context_current(
                    session_handle, workflow, context) is True
                and self.catalog.is_selected_application_qualification_consent_current(context, workflow) is True
                and self.catalog.resolve_selected_application_runtime(request.application_id,
                    profile_id=request.profile_id) == selection
                and self.controllers.is_binding_current(request.controller_binding_handle) is True)
            if current:
                for source_handle in request.source_receipt_handles:
                    self.sources.resolve(source_handle, application_id=request.application_id,
                        service_generation_digest=request.enclosing_service_generation_digest)
                self.runtimes.resolve(selection.runtime_receipt_handle,
                    application_id=request.application_id,
                    source_receipt_handle=selection.source_generation_receipt_handle,
                    service_generation_digest=request.enclosing_service_generation_digest)
                if request.workflow_id == "qualify-browser-use-v1":
                    fixture = self.catalog.resolve_owned_application_fixture(request.fixture_receipt_handle)
                    if (getattr(fixture, "handle", None) != request.fixture_receipt_handle
                            or not _owned_loopback_url(getattr(fixture, "url", None))):
                        return False
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
                or admission.source_receipt_handle != selection.source_generation_receipt_handle
                or admission.runtime_receipt_handle != selection.runtime_receipt_handle
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
                    and self.sources.resolve(step.source_receipt_handle,
                        application_id=step.application_id,
                        service_generation_digest=step.service_generation_digest) is not None
                    and self.runtimes.resolve(step.runtime_receipt_handle,
                        application_id=step.application_id,
                        source_receipt_handle=step.source_receipt_handle,
                        service_generation_digest=step.service_generation_digest) is not None
                    and self.controllers.is_binding_current(step.controller_binding_handle) is True)
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
        if (step.role != "application-workload" or not self._current(step)
                or service.monotonic() >= step.deadline_monotonic
                or step.operation_id not in self.journal.resolve_application_admission(
                    admission_handle).operation_recipe_ids):
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
        controller = self.controllers.resolve_binding(step.controller_binding_handle)
        if controller is None or self.controllers.verify_binding(controller) is not True:
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
            operation="process.start", capability="hermes-application-workload-invoke",
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
                    or not self._current(entry.step)):
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
                            and self._current(entry.step)
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
        self._receipts: dict[str, tuple[RootApplicationRuntimeProbeReceipt, Any]] = {}
        self._lock = threading.RLock()

    def run_selected_runtime_probe(self, preparation_selection_handle: str) -> RootApplicationRuntimeProbeReceipt:
        resolve = getattr(self.preparations, "resolve_application_runtime_preparation_selection", None)
        if not _handle(preparation_selection_handle) or not callable(resolve):
            raise AuthorityDenied("application.probe", "root preparation selection is unavailable")
        selection = resolve(preparation_selection_handle)
        if selection is None or getattr(selection, "handle", None) != preparation_selection_handle:
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
        if current_selection != retained_selection:
            raise AuthorityDenied("application.probe", "runtime preparation selection changed")
        terminal = self.custodian.resolve_application_terminal(receipt.terminal_receipt_handle)
        self.service._verify_root_selected_signature(
            "root-application-terminal-v1", terminal.claims(), terminal.signature)
        stdout, stderr = self.custodian.resolve_application_output(terminal.output_observation_handle)
        if (terminal.state != "completed" or terminal.exit_code != 0 or not terminal.reaped
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
        runtime_root = getattr(current_selection, "runtime_root", None)
        try:
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
