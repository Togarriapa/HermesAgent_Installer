"""Setup-time account choices and guarded runtime-adapter assembly.

This module keeps durable setup references in the private installer journal.
It does not make protected enrollment decisions: provider/MCP/memory setup is
ready only when a component's real protected service can prove the selected
connection and the root authority admits it.
"""
from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any, Callable


_NAMESPACES = frozenset({"providers", "mcp", "memory"})
_REFERENCE = re.compile(r"(?:keyring|secret|file|env)://[^\s\x00]{1,1024}\Z")
_FINGERPRINT = re.compile(r"[a-f0-9]{8,64}\Z")
_SELECTIONS = frozenset({"service_id", "resource_id", "provider_id", "backend_variant"})
_SAFE_SELECTION = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,255}\Z")


class SetupStateError(ValueError):
    """A setup checkpoint would contain an unsafe or non-resumable value."""


class JournalSetupStateStore:
    """Small namespaced store for credential references and selected IDs.

    The journal is already inside the installer-owned mode-0700 state root.
    Secret bytes never pass through this API. References are intentionally
    retained so a later setup command can reuse an earlier successful account
    check without prompting for the credential again.
    """

    operation_id = "installer:setup"

    def __init__(self, journal: Any, namespace: str):
        if namespace not in _NAMESPACES:
            raise SetupStateError("setup state namespace is not supported")
        if not callable(getattr(journal, "operation", None)) or not callable(getattr(journal, "checkpoint", None)):
            raise SetupStateError("a private installer journal is required for resumable account setup")
        self.journal = journal
        self.namespace = namespace

    def _payload(self) -> dict[str, Any]:
        operation = self.journal.operation(self.operation_id)
        payload = operation.get("payload") if isinstance(operation, Mapping) else None
        return dict(payload) if isinstance(payload, Mapping) else {}

    def _section(self, payload: Mapping[str, Any] | None = None) -> dict[str, Any]:
        source = payload if payload is not None else self._payload()
        state = source.get("setup_state", {})
        section = state.get(self.namespace, {}) if isinstance(state, Mapping) else {}
        return dict(section) if isinstance(section, Mapping) else {}

    def _write(self, section: Mapping[str, Any]) -> None:
        operation = self.journal.operation(self.operation_id)
        payload = self._payload()
        state = payload.get("setup_state", {})
        state = dict(state) if isinstance(state, Mapping) else {}
        state[self.namespace] = dict(section)
        payload["setup_state"] = state
        status = operation.get("status", "pending") if isinstance(operation, Mapping) else "pending"
        self.journal.checkpoint(self.operation_id, str(status), payload)

    def get_reference(self, name: str) -> str | None:
        value = self._section().get("references", {}).get(name)
        return value if isinstance(value, str) and _REFERENCE.fullmatch(value) else None

    def put_reference(self, name: str, reference: str, *, status: str,
                      account_fingerprint: str | None = None) -> None:
        if (not isinstance(name, str) or not re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", name)
                or not isinstance(reference, str) or not _REFERENCE.fullmatch(reference)):
            raise SetupStateError("only an opaque secure credential reference may be checkpointed")
        if status not in {"reference-stored", "account-probe-passed", "pending"}:
            raise SetupStateError("setup credential status is not supported")
        if account_fingerprint is not None and (not isinstance(account_fingerprint, str)
                or not _FINGERPRINT.fullmatch(account_fingerprint)):
            raise SetupStateError("account fingerprint must be a short hexadecimal digest")
        section = self._section()
        refs = section.get("references", {})
        refs = dict(refs) if isinstance(refs, Mapping) else {}
        refs[name] = reference
        section["references"] = refs
        statuses = section.get("account_checks", {})
        statuses = dict(statuses) if isinstance(statuses, Mapping) else {}
        row: dict[str, str] = {"state": status}
        if account_fingerprint is not None:
            row["account_fingerprint"] = account_fingerprint
        statuses[name] = row
        section["account_checks"] = statuses
        self._write(section)

    def get_selection(self, name: str) -> str | None:
        value = self._section().get("selections", {}).get(name)
        return value if isinstance(value, str) and _SAFE_SELECTION.fullmatch(value) else None

    def put_selection(self, name: str, value: str) -> None:
        if name not in _SELECTIONS or not isinstance(value, str) or not _SAFE_SELECTION.fullmatch(value):
            raise SetupStateError("selected account/resource identifier is invalid")
        section = self._section()
        selections = section.get("selections", {})
        selections = dict(selections) if isinstance(selections, Mapping) else {}
        selections[name] = value
        section["selections"] = selections
        self._write(section)

    def clear_selection(self, name: str) -> None:
        if name not in _SELECTIONS:
            raise SetupStateError("selected account/resource identifier is invalid")
        section = self._section()
        selections = section.get("selections", {})
        if not isinstance(selections, Mapping) or name not in selections:
            return
        selections = dict(selections)
        selections.pop(name, None)
        section["selections"] = selections
        self._write(section)

    def persist_provider_reference(self, provider: str, reference: str, observation: Any) -> None:
        """Persist only the proven reference and a short account digest."""
        if provider != "openrouter":
            raise SetupStateError("provider setup reference is outside the reviewed catalog")
        fingerprint = getattr(observation, "account_fingerprint", None)
        if fingerprint == "":
            fingerprint = None
        self.put_reference("openrouter_api_key_ref", reference,
                           status="account-probe-passed", account_fingerprint=fingerprint)


def _answer(input_fn: Callable[[str], str], output_fn: Callable[[str], None],
            prompt: str, choices: tuple[str, ...], default: str | None = None) -> str:
    while True:
        raw = input_fn(f"{prompt} ({'/'.join(choices)}){f' [{default}]' if default else ''}: ").strip().casefold()
        selected = raw or default
        if selected in choices:
            return selected
        output_fn(f"Choose one of: {', '.join(choices)}.")


class MCPSelectionAdapter:
    """Capture a reviewed service/resource choice without claiming a connection.

    Live protocol checks require the root-enrolled credential, endpoint, fixed
    tool schema, selected resource and account eligibility receipt. This
    adapter deliberately does not accept raw tokens or caller endpoints.
    """

    name = "mcp"

    _GUIDANCE = {
        "figma": ("Figma", "https://developers.figma.com/docs/figma-mcp-server/tools-and-prompts/",
                  "Figma account login and access to one selected file are required.",
                  "Select a file you can read. Setup does not modify a design."),
        "revenuecat": ("RevenueCat", "https://www.revenuecat.com/docs/tools/mcp/tools-reference",
                       "RevenueCat OAuth or a scoped API v2 key and one selected project are required.",
                       "Select a project. Setup tests read-only project data only."),
        "google-gmail": ("Google Gmail", "https://developers.google.com/workspace/gmail/api/reference/mcp",
                         "Google Workspace Developer Preview eligibility and minimal read-only OAuth scopes are required.",
                         "Select one message or thread. Setup will not send mail."),
        "google-drive": ("Google Drive", "https://developers.google.com/workspace/drive/api/reference/mcp",
                         "Google Workspace Developer Preview eligibility and minimal read-only OAuth scopes are required.",
                         "Select one Drive file. Setup will not edit files."),
        "google-docs": ("Google Docs", "https://developers.google.com/workspace/docs/api/reference/mcp",
                        "Google Workspace Developer Preview eligibility and minimal read-only OAuth scopes are required.",
                        "Select one document. Setup will not edit documents."),
        "google-sheets": ("Google Sheets", "https://developers.google.com/workspace/sheets/api/reference/mcp",
                          "Google Workspace Developer Preview eligibility and minimal read-only OAuth scopes are required.",
                          "Select one spreadsheet. Setup will not change cells."),
        "google-calendar": ("Google Calendar", "https://developers.google.com/workspace/calendar/api/v3/reference/mcp",
                            "Google Workspace Developer Preview eligibility and minimal read-only OAuth scopes are required.",
                            "Select one event or calendar. Setup will not create meetings."),
        "google-contacts": ("Google Contacts", "https://developers.google.com/people/api/mcp",
                            "Google Workspace Developer Preview eligibility and minimal read-only OAuth scopes are required.",
                            "Select one person. Setup will not modify contacts."),
        "home-assistant": ("Home Assistant", "https://www.home-assistant.io/integrations/mcp_server",
                           "An existing instance and a root-held credential for its documented MCP endpoint are required.",
                           "Select exact exposed entity IDs. Setup will read state only; it will not control devices."),
        "google-community": ("Google Workspace community server", "https://github.com/taylorwilsdon/google_workspace_mcp",
                             "This is a separately maintained community option, not Google's official server.",
                             "Choose only after reviewing its source, scopes, and selected read-only resource."),
        "playwright": ("Playwright", "https://playwright.dev/docs/getting-started-mcp",
                       "The pinned local MCP and a sandboxed supported ARM64 browser must be installed.",
                       "Only a local fixture page may be used for setup verification."),
    }

    def __init__(self, state: JournalSetupStateStore):
        self.state = state

    def configure(self, config: Mapping[str, Any], *, input_fn: Callable[[str], str],
                  output_fn: Callable[[str], None], secret_reader: Callable[[str], str],
                  credential_store: Any, remote_journal: Any = None,
                  setup_state_store: JournalSetupStateStore | None = None) -> Any:
        from .mcp.adapters import SERVICES
        from .setup_wizard import AdapterResult

        ids = tuple(sorted(SERVICES))
        previous_service = self.state.get_selection("service_id")
        output_fn("Choose an MCP account/service. Each option remains separately labeled.")
        service_id = _answer(input_fn, output_fn, "MCP service", ids, default=previous_service)
        if service_id not in SERVICES:
            return AdapterResult("failed", "The selected MCP service is not in the reviewed catalog.",
                                 {}, ("Choose an exact service ID from `hermes-installer configure mcp --help`.",))
        title, url, prerequisite, step = self._GUIDANCE[service_id]
        output_fn(f"{title} — {SERVICES[service_id].auth_kind}.")
        output_fn(f"  Why: Authenticate one scoped account and test a harmless read of the selected resource.")
        output_fn(f"  Official setup: {url}")
        output_fn(f"  Before starting: {prerequisite}")
        output_fn(f"  1. {step}")
        resource = self.state.get_selection("resource_id")
        if previous_service and previous_service != service_id:
            # Resource identifiers are scoped to the selected service.
            self.state.clear_selection("resource_id")
            resource = None
        if service_id != "playwright" and not resource:
            raw = input_fn(f"Selected resource identifier for {service_id} (blank means configure later): ").strip()
            if raw:
                if not _SAFE_SELECTION.fullmatch(raw):
                    return AdapterResult("failed", "Selected resource identifier has unsupported characters.",
                                         {}, ("Choose one exact resource ID; do not enter a URL or credential.",))
                resource = raw
        self.state.put_selection("service_id", service_id)
        if resource:
            self.state.put_selection("resource_id", resource)
        if not resource and service_id != "playwright":
            return AdapterResult("pending", f"{title} account setup was deferred; no resource was selected.", {},
                                 ("Choose a resource and run `hermes-installer configure mcp` to resume.",))
        return AdapterResult("pending", f"{title} selection was saved; no connection is claimed.", {},
                             ("A root-enrolled MCP credential, endpoint, fixed read-only tool schema, selected-resource binding, and account-eligibility receipt are required before the bounded protocol and harmless-read probe can run. Resume with `hermes-installer configure mcp` after that enrollment is available.",))

    def configure_noninteractive(self, config: Mapping[str, Any], *, credential_store: Any,
                                 setup_state_store: JournalSetupStateStore | None = None) -> Any:
        from .setup_wizard import AdapterResult
        service = self.state.get_selection("service_id")
        resource = self.state.get_selection("resource_id")
        if service and (resource or service == "playwright"):
            return AdapterResult("pending", f"MCP {service} is selected, but protected connection readiness is unavailable.", {},
                                 ("Complete root enrollment of the selected account, credential, endpoint and read-only resource, then resume.",))
        return AdapterResult("pending", "No reviewed MCP service and resource are selected.", {},
                             ("Run `hermes-installer configure mcp` in a terminal to select one.",))

    def test_connection(self, config: Mapping[str, Any]) -> Any:
        from .setup_wizard import AdapterResult
        service = self.state.get_selection("service_id")
        if not service:
            return AdapterResult("pending", "No MCP service is selected; no connection was attempted.", {},
                                 ("Run `hermes-installer configure mcp` to select a service and resource.",))
        return AdapterResult("pending", f"MCP {service} has no current root-enrolled functional test binding.", {},
                             ("The exact credential, endpoint, account eligibility, selected resource and read-only tool schema must be root-enrolled before `test-connection mcp` can perform a bounded initialize/discovery/harmless-read test.",))


class MemorySelectionAdapter:
    """Remember one memory-provider choice without claiming active persistence."""

    name = "memory"
    OPTIONS = {
        "openviking": ("OpenViking", "https://docs.openviking.ai/en/agent-integrations/05-hermes",
                       "A separately isolated service plus eligible private extraction and embedding routes are required."),
        "claude-mem": ("claude-mem", "https://github.com/thedotmack/claude-mem",
                       "Select the SQLite or PostgreSQL server variant; a single automatic memory owner is enforced per profile."),
        "agent-memory": ("Agent Memory", "https://github.com/rohitg00/agentmemory",
                         "The exact source, service and private extraction/embedding routes must be enrolled for this profile."),
    }

    def __init__(self, state: JournalSetupStateStore, *, runtime_inputs: Mapping[str, Any] | None = None):
        self.state = state
        self.runtime_inputs = dict(runtime_inputs or {})

    def configure(self, config: Mapping[str, Any], *, input_fn: Callable[[str], str],
                  output_fn: Callable[[str], None], secret_reader: Callable[[str], str],
                  credential_store: Any, remote_journal: Any = None,
                  setup_state_store: JournalSetupStateStore | None = None) -> Any:
        from .setup_wizard import AdapterResult

        choice = self.state.get_selection("provider_id")
        if not choice:
            choice = _answer(input_fn, output_fn, "Single automatic memory provider",
                             tuple(self.OPTIONS), None)
        if choice not in self.OPTIONS:
            return AdapterResult("failed", "The selected memory provider is not supported.", {},
                                 ("Choose OpenViking, claude-mem, or Agent Memory.",))
        title, url, prerequisite = self.OPTIONS[choice]
        output_fn(f"{title} memory — one automatic capture owner per active profile.")
        output_fn("  Why: Persist private, namespaced long-term memory across sessions while preserving Hermes session memory.")
        output_fn(f"  Official setup: {url}")
        output_fn(f"  Before starting: {prerequisite}")
        self.state.put_selection("provider_id", choice)
        if choice == "claude-mem" and not self.state.get_selection("backend_variant"):
            variant = _answer(input_fn, output_fn, "claude-mem backend", ("server-v1-sqlite", "server-v1-postgres", "worker-observation"))
            self.state.put_selection("backend_variant", variant)
        return AdapterResult("pending", f"{title} is selected; memory is not active until the protected service enrollment and cross-session functional test succeed.", {},
                             ("Root service enrollment and lifecycle must bind the selected profile, private store, one-owner generation, extraction/embedding routes and credential refs. No memory service was started or counted as connected; resume setup after enrollment.",))

    def configure_noninteractive(self, config: Mapping[str, Any], *, credential_store: Any,
                                 setup_state_store: JournalSetupStateStore | None = None) -> Any:
        from .setup_wizard import AdapterResult
        provider = self.state.get_selection("provider_id")
        if provider not in self.OPTIONS:
            return AdapterResult("pending", "No supported memory provider is selected.", {},
                                 ("Run setup in a terminal or select a protected memory enrollment, then resume.",))
        return AdapterResult("pending", f"{provider} is selected, but its protected service and functional memory test are unavailable.", {},
                             ("Run the protected memory enrollment and cross-session synthetic-fact test, then resume.",))

    def test_connection(self, config: Mapping[str, Any]) -> Any:
        from .setup_wizard import AdapterResult
        provider = self.state.get_selection("provider_id")
        # A runtime factory assembles real handlers, but their current data
        # plane deliberately reports unavailable until fixed compound IPC and
        # provider eligibility are enrolled. Construction alone is not proof.
        if self.runtime_inputs:
            from .memory.broker import build_memory_runtime
            try:
                runtime = build_memory_runtime(**self.runtime_inputs)
            except Exception:
                return AdapterResult("pending", "Protected memory runtime could not be assembled; no synthetic data was written.", {},
                                     ("Check exact root service enrollment and resume after the host memory connector is active.",))
            if runtime.get("targets"):
                return AdapterResult("pending", f"{provider or 'Selected memory'} has a protected target, but the root memory data plane does not currently expose a qualified functional read/write canary.", {},
                                     ("Complete the protected compound IPC and private extraction/embedding eligibility path before enabling memory.",))
        return AdapterResult("pending", "No protected memory runtime is available; no memory service was probed.", {},
                             ("Complete root service enrollment, then run the synthetic capture/extraction/restart/retrieval test.",))


def build_setup_adapters(*, journal: Any, credential_store: Any = None,
                         provider_probe_factory: Any = None,
                         memory_runtime_inputs: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Build native setup adapters without inventing protected credentials.

    A normal user process can collect choices and run account-safe provider
    discovery. Protected MCP and memory readiness remains unavailable until a
    host enrollment/runtime binding is supplied by the installed authority.
    """
    from .setup_wizard import CloudflareDesktopAdapter

    adapters: dict[str, Any] = {"remote_desktop": CloudflareDesktopAdapter()}
    if journal is None:
        # Do not prompt for or store a reusable account token without durable
        # private state capable of preserving its opaque reference.
        return adapters

    provider_state = JournalSetupStateStore(journal, "providers")
    try:
        from .provider_setup_adapters import build_provider_setup_adapter
    except ModuleNotFoundError as exc:
        # A staged integration may not yet include this adapter. Never mask
        # an import failure raised from inside an adapter that is present.
        if exc.name != f"{__package__}.provider_setup_adapters":
            raise
    else:
        options: dict[str, Any] = {
            "persist_reference": provider_state.persist_provider_reference,
            "credential_reference": provider_state.get_reference("openrouter_api_key_ref"),
        }
        if provider_probe_factory is not None:
            options["probe_factory"] = provider_probe_factory
        adapters["providers"] = build_provider_setup_adapter(**options)

    adapters["mcp"] = MCPSelectionAdapter(JournalSetupStateStore(journal, "mcp"))
    adapters["memory"] = MemorySelectionAdapter(
        JournalSetupStateStore(journal, "memory"), runtime_inputs=memory_runtime_inputs)
    return adapters
