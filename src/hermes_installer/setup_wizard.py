"""Guided terminal setup with secret-safe account enrollment.

The wizard owns choices and presentation. Component adapters own real
connection checks; an unavailable adapter is reported as pending instead of
being treated as a successful configuration.
"""
from __future__ import annotations

import getpass
import os
import stat
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol

from .credentials import CredentialError, read_hidden_token, resolve_secret
from .remote.config import RemoteConfigError, collect_remote_setup
from .state import OwnedRoot, OwnershipError


@dataclass(frozen=True, slots=True)
class AccountField:
    name: str
    what: str
    why: str
    official_url: str
    steps: tuple[str, ...]
    prerequisite: str = ""
    secret: bool = False


@dataclass(frozen=True, slots=True)
class AdapterResult:
    state: str
    message: str
    config: Mapping[str, Any] = field(default_factory=dict)
    next_steps: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.state not in {"ready", "pending", "failed"}:
            raise ValueError("adapter state must be ready, pending, or failed")


class CredentialStore(Protocol):
    def put(self, name: str, value: str) -> str: ...


class SetupAdapter(Protocol):
    """An actual integration with explanatory fields and a real test path."""

    name: str
    fields: tuple[AccountField, ...]

    def configure(self, config: Mapping[str, Any], *, input_fn: Callable[[str], str],
                  output_fn: Callable[[str], None], secret_reader: Callable[[str], str],
                  credential_store: CredentialStore) -> AdapterResult: ...


@dataclass(frozen=True, slots=True)
class WizardResult:
    state: str
    selected_components: Mapping[str, bool]
    config: Mapping[str, Any]
    message: str
    resume_command: str | None
    next_steps: tuple[str, ...] = ()
    account_states: Mapping[str, str] = field(default_factory=dict)
    exit_code: int = 0

    def __post_init__(self) -> None:
        if self.state not in {"ready", "pending", "failed"}:
            raise ValueError("wizard state must be ready, pending, or failed")
        if self.state == "failed" and self.exit_code == 0:
            object.__setattr__(self, "exit_code", 1)
        if self.state == "pending" and self.exit_code == 0:
            object.__setattr__(self, "exit_code", 4)


class PrivateFileCredentialStore:
    """Store credentials only under a verified private installer state root."""

    def __init__(self, state_root: Path):
        self.root = OwnedRoot(state_root)

    def put(self, name: str, value: str) -> str:
        if not isinstance(name, str) or not name or any(ch not in "abcdefghijklmnopqrstuvwxyz0123456789-_" for ch in name):
            raise CredentialError("Credential name is invalid")
        if not isinstance(value, str) or not value or len(value) > 4096 or any(ord(ch) < 32 for ch in value):
            raise CredentialError("Credential value is invalid")
        self.root.ensure()
        directory = self.root.path("credentials")
        directory.mkdir(mode=0o700, exist_ok=True)
        info = directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
            raise CredentialError("Credential directory ownership or permissions are unsafe")
        credential_id = uuid.uuid4().hex
        target = self.root.path(f"credentials/{name}-{credential_id}.secret")
        temporary = self.root.path(f"credentials/.{name}.{credential_id}.tmp")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        try:
            fd = os.open(temporary, flags, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                stream.write(value + "\n")
                stream.flush()
                os.fsync(stream.fileno())
            # Publish without replacing a pre-existing file, even if another
            # process races this credential directory.
            os.link(temporary, target, follow_symlinks=False)
            temporary.unlink()
            parent_fd = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(parent_fd)
            finally:
                os.close(parent_fd)
        except OSError:
            try:
                temporary.unlink()
            except OSError:
                pass
            raise CredentialError("Credential could not be stored safely") from None
        return target.as_uri()


class CloudflareDesktopAdapter:
    name = "remote_desktop"
    fields = (
        AccountField("hostname", "The full hostname users will open in a browser.",
                     "Cloudflare routes this exact name to the protected Hermes Desktop gateway.",
                     "https://developers.cloudflare.com/dns/manage-dns-records/how-to/create-dns-records/",
                     ("Choose a hostname in a zone you control.", "Enter the complete name, such as desktop.example.com.", "Leave it blank to configure remote access later.")),
        AccountField("allowed_emails", "Email addresses allowed to receive a one-time login code.",
                     "Cloudflare Access must authenticate each user before any Desktop content is sent.",
                     "https://developers.cloudflare.com/cloudflare-one/policies/access/",
                     ("List only the people who should reach this Desktop.", "Separate multiple addresses with commas.", "Check that each person can receive email codes.")),
        AccountField("management_token_ref", "A scoped Cloudflare setup token.",
                     "The installer uses it to discover your account and zone, then provision only the selected hostname's owned resources.",
                     "https://developers.cloudflare.com/fundamentals/api/get-started/create-token/",
                     ("Create a custom API token for the chosen account and zone.", "For the selected account, grant Cloudflare Tunnel Edit, Access: Apps and Policies Edit, and Access: Organizations, Identity Providers, and Groups Edit.", "For the selected zone, grant DNS Edit and Zone Read so the installer can discover and configure only that hostname.", "Do not paste a global API key. The value is hidden and stored in the private installer credential store."),
                     "A Cloudflare account with an active zone and Access available is required. No paid certificate or plan will be purchased.", True),
        AccountField("policy_read_token_ref", "A separate minimum-read token for checking Access policy before and during sessions.",
                     "The live-session verifier must re-read Access policy without receiving the setup-management token.",
                     "https://developers.cloudflare.com/fundamentals/api/get-started/create-token/",
                     ("Create a second custom token with Account Access: Apps and Policies Read and Access: Organizations, Identity Providers, and Groups Read.", "Grant Zone Read only if needed to discover the selected zone. Keep all permissions read-only and separate from the setup token.", "The app-specific authorization check runs after installer-owned Access resources exist."),
                     "This token must already exist; setup does not mint or broaden credentials automatically.", True),
    )

    def __init__(self, client_factory=None):
        if client_factory is None:
            from .remote.cloudflare import CloudflareClient
            client_factory = CloudflareClient
        self.client_factory = client_factory

    @staticmethod
    def _show_field(field: AccountField, output_fn: Callable[[str], None]) -> None:
        output_fn(f"{field.name}: {field.what}")
        output_fn(f"  Why: {field.why}")
        output_fn(f"  Official setup: {field.official_url}")
        for index, step in enumerate(field.steps, 1):
            output_fn(f"  {index}. {step}")
        if field.prerequisite:
            output_fn(f"  Before starting: {field.prerequisite}")

    def configure(self, config: Mapping[str, Any], *, input_fn: Callable[[str], str],
                  output_fn: Callable[[str], None], secret_reader: Callable[[str], str],
                  credential_store: CredentialStore) -> AdapterResult:
        from .remote.config import validate_emails, validate_hostname

        remote = dict(config.get("remote_desktop", {}))
        output_fn("Remote Desktop account setup")
        self._show_field(self.fields[0], output_fn)
        hostname_raw = remote.get("hostname")
        if not hostname_raw:
            hostname_raw = input_fn("Hostname (blank means configure later): ").strip()
        if not hostname_raw:
            return AdapterResult("pending", "Remote Desktop setup was deferred; no hostname was selected.",
                                 {"remote_desktop": {**remote, "hostname": ""}},
                                 ("hermes-installer configure remote-desktop",))
        try:
            hostname = validate_hostname(str(hostname_raw))
        except RemoteConfigError as exc:
            return AdapterResult("failed", str(exc), {"remote_desktop": remote},
                                 ("Correct the hostname, then run hermes-installer configure remote-desktop.",))

        self._show_field(self.fields[1], output_fn)
        email_raw = remote.get("allowed_emails")
        if not email_raw:
            email_raw = input_fn("Allowed email addresses (comma-separated): ").split(",")
        elif isinstance(email_raw, str):
            email_raw = email_raw.split(",")
        try:
            emails = validate_emails(email_raw)
        except (RemoteConfigError, TypeError) as exc:
            return AdapterResult("failed", str(exc), {"remote_desktop": remote},
                                 ("Enter a valid Access allowlist, then resume remote setup.",))

        self._show_field(self.fields[2], output_fn)
        setup_ref = remote.get("management_token_ref")
        if not setup_ref:
            answer = input_fn("Configure Cloudflare now, or type 'later' to continue: ").strip().casefold()
            if answer == "later":
                return AdapterResult("pending", "Cloudflare setup was deferred; remote access remains disabled.",
                                     {"remote_desktop": {**remote, "hostname": hostname, "allowed_emails": list(emails)}},
                                     ("Provide a scoped setup token, then run hermes-installer configure remote-desktop.",))
            try:
                token = secret_reader("Cloudflare setup token (input hidden): ")
                setup_ref = credential_store.put("cloudflare-setup", token)
            except (CredentialError, OSError, OwnershipError) as exc:
                return AdapterResult("failed", str(exc), {"remote_desktop": remote},
                                     ("Check private installer state permissions, then resume setup.",))

        selected = {**remote, "hostname": hostname, "allowed_emails": list(emails),
                    "management_token_ref": setup_ref}
        try:
            setup = collect_remote_setup(interactive=False, config=selected,
                                         client_factory=self.client_factory)
        except (RemoteConfigError, CredentialError, OSError, RuntimeError, ValueError) as exc:
            # The reference is durable so the user can correct scope or network
            # conditions and resume without pasting the successful input again.
            return AdapterResult("pending", f"Cloudflare connection test did not complete: {exc}",
                                 {"remote_desktop": selected},
                                 ("Check the token scope and network, then run hermes-installer configure remote-desktop.",))

        output_fn(f"Cloudflare connection test passed: active zone {setup.zone.name}, account {setup.zone.account_id}; Access organization {setup.auth_domain} is reachable.")
        selected["zone_id"] = setup.zone.zone_id
        # Access API setup permission cannot be inferred from a successful read.
        # The actual owned-resource provisioning adapter verifies it before writes.
        policy_ref = selected.get("policy_read_token_ref")
        if not policy_ref:
            self._show_field(self.fields[3], output_fn)
            answer = input_fn("Enter a separate existing read-only token now, or type 'later': ").strip().casefold()
            if answer == "later":
                return AdapterResult("pending", "Cloudflare account discovery passed; the separate policy-read credential is still required before activation.",
                                     {"remote_desktop": selected},
                                     ("Provide a minimum-read Access credential, then run hermes-installer configure remote-desktop.",))
            try:
                read_token = secret_reader("Cloudflare Access policy-read token (input hidden): ")
                policy_ref = credential_store.put("cloudflare-policy-read", read_token)
                self._test_policy_read(policy_ref, setup)
            except (CredentialError, RemoteConfigError, OSError, ValueError) as exc:
                return AdapterResult("pending", f"Separate policy-read connection test did not complete: {exc}",
                                     {"remote_desktop": selected},
                                     ("Check the read-only token scope, then resume remote setup.",))
            selected["policy_read_token_ref"] = policy_ref
        else:
            try:
                self._test_policy_read(policy_ref, setup)
            except (CredentialError, RemoteConfigError, OSError, ValueError) as exc:
                return AdapterResult("pending", f"Separate policy-read connection test did not complete: {exc}",
                                     {"remote_desktop": selected},
                                     ("Check the read-only token scope, then resume remote setup.",))
            selected["policy_read_token_ref"] = policy_ref
        return AdapterResult("ready", "Cloudflare account, active zone, and separate policy-read authority were tested; owned resource provisioning remains an install step.",
                             {"remote_desktop": selected},
                             ("Run hermes-installer install to provision only the owned tunnel, DNS, Access, and email-code resources.",))

    def _test_policy_read(self, reference: str, setup: Any) -> None:
        """Exercise the distinct read token against the exact discovered account."""
        verifier = self.client_factory(resolve_secret(reference))
        zones = verifier.discover_zones(setup.hostname)
        if not any(zone.zone_id == setup.zone.zone_id for zone in zones):
            raise RemoteConfigError("Policy-read credential cannot see the selected active zone")
        org = verifier.organization(setup.zone.account_id)
        if org.get("auth_domain") != setup.auth_domain:
            raise RemoteConfigError("Policy-read credential resolved a different Access organization")


def _choice(input_fn: Callable[[str], str], output_fn: Callable[[str], None], prompt: str,
            choices: tuple[str, ...], default: str | None = None) -> str:
    labels = "/".join(choices)
    while True:
        raw = input_fn(f"{prompt} [{labels}]{' (' + default + ')' if default else ''}: ").strip().casefold()
        selected = raw or default
        if selected in choices:
            return selected
        output_fn(f"Choose one of: {', '.join(choices)}.")


def run_setup_wizard(config: Mapping[str, Any] | None = None, *,
                     input_fn: Callable[[str], str] = input,
                     output_fn: Callable[[str], None] = print,
                     secret_reader: Callable[[str], str] | None = None,
                     adapters: Mapping[str, SetupAdapter] | None = None,
                     credential_store: CredentialStore | None = None,
                     journal: Any = None,
                     interactive: bool = True,
                     resume_command: str = "hermes-installer setup") -> WizardResult:
    """Run setup prompts and return an installable config plus pending selections.

    Incomplete components stay outside `config.components`; their user choices
    remain in `selected_components` and the private state journal for resume.
    """
    from .config import validate_config

    current = dict(config or {"schema_version": 1})
    current.setdefault("schema_version", 1)
    current.setdefault("paths", {})
    current.setdefault("components", {})
    current.setdefault("privacy", {"additional_metered_budget": 0})
    current.setdefault("remote_desktop", {"hostname": "", "allowed_emails": []})
    selected_components = dict(current["components"])
    states: dict[str, str] = {}
    pending: list[str] = []
    failures: list[str] = []
    next_steps: list[str] = []

    if interactive:
        output_fn("Hermes Agent guided setup")
        install_mode = _choice(input_fn, output_fn, "Installation type", ("fresh", "adopt"),
                               "adopt" if current.get("components") else "fresh")
        output_fn("Existing data and services will be inventoried before installation changes.")
        selected_components.setdefault("hermes_agent", True)
        selected_components.setdefault("hermes_desktop", True)
        component_names = tuple(sorted({*selected_components, "remote_desktop", "providers", "mcp", "memory", "registry", "colibri", "coral"}))
        descriptions = {
            "hermes_agent": "Official Hermes Agent backend",
            "hermes_desktop": "Official native Hermes Desktop app",
            "registry": "Bundled profiles, skills, and reviewed resource definitions",
            "providers": "Model accounts and privacy/budget-gated provider routes",
            "mcp": "Selected external MCP connections",
            "memory": "One selected long-term memory service",
            "colibri": "Experimental local GLM-5.2 runtime; large download remains opt-in",
            "coral": "Separate TPU delegate for supported quantized TensorFlow Lite models",
            "remote_desktop": "Access-protected remote view of the official Hermes Desktop app",
        }
        for name in component_names:
            default = "yes" if selected_components.get(name, name in {"hermes_agent", "hermes_desktop", "registry"}) else "no"
            selected_components[name] = _choice(input_fn, output_fn, f"Select {name.replace('_', ' ')} — {descriptions.get(name, 'optional integration')}", ("yes", "no"), default) == "yes"
        data_root = current["paths"].get("data_root", "~/HermesInstaller/data")
        state_root = current["paths"].get("state_root", "~/HermesInstaller/state")
        model_root = current["paths"].get("model_root", "~/HermesInstaller/models")
        current["paths"] = {**current["paths"], "data_root": input_fn(f"Installer data path [{data_root}]: ").strip() or data_root,
                             "state_root": input_fn(f"Private installer state path [{state_root}]: ").strip() or state_root,
                             "model_root": input_fn(f"Optional model storage path [{model_root}]: ").strip() or model_root}
        output_fn("Additional metered budget remains $0. Paid services stay disabled until separately configured.")
    else:
        install_mode = str(current.get("setup_mode", "adopt" if current.get("components") else "fresh"))
        if install_mode not in {"fresh", "adopt"}:
            return WizardResult("failed", selected_components, current, "setup_mode must be fresh or adopt", resume_command, exit_code=2)
        selected_components.update({k: bool(v) for k, v in current.get("components", {}).items()})

    adapters_by_name: dict[str, SetupAdapter] = dict(adapters or {})
    if selected_components.get("remote_desktop") and "remote_desktop" not in adapters_by_name:
        adapters_by_name["remote_desktop"] = CloudflareDesktopAdapter()
    secret_reader = secret_reader or (lambda prompt: read_hidden_token(prompt=prompt))
    state_root = Path(current["paths"].get("state_root", "~/HermesInstaller/state")).expanduser()
    credential_store = credential_store or PrivateFileCredentialStore(state_root)

    # Validate all non-secret install settings without promoting incomplete
    # component selections into the installable config.
    installable = dict(current)
    deferred_accounts = {"remote_desktop", "providers", "mcp", "memory"}
    installable["components"] = {k: v for k, v in selected_components.items()
                                 if v and k not in deferred_accounts}
    if not selected_components.get("remote_desktop"):
        installable["remote_desktop"] = dict(current.get("remote_desktop", {}))
    try:
        validate_config(installable)
    except (ValueError, TypeError) as exc:
        return WizardResult("failed", selected_components, installable, str(exc), resume_command,
                            ("Correct the configuration and rerun setup.",), exit_code=2)

    if selected_components.get("remote_desktop"):
        adapter = adapters_by_name.get("remote_desktop")
        if adapter is None:
            states["remote_desktop"] = "pending"
            pending.append("remote_desktop")
            next_steps.append("Install or select a verified Cloudflare account adapter, then rerun setup.")
        elif interactive:
            result = adapter.configure(installable, input_fn=input_fn, output_fn=output_fn,
                                       secret_reader=secret_reader, credential_store=credential_store)
            states["remote_desktop"] = result.state
            installable.update(result.config)
            if result.state == "ready":
                installable["components"]["remote_desktop"] = True
            if result.state != "ready":
                pending.append("remote_desktop")
            if result.state == "failed":
                failures.append("remote_desktop")
            next_steps.extend(result.next_steps)
        else:
            # Noninteractive mode tests only explicit secure references and
            # never asks for values or silently starts account mutations.
            remote = dict(installable.get("remote_desktop", {}))
            policy_ref = remote.get("policy_read_token_ref")
            if not policy_ref:
                states["remote_desktop"] = "pending"
                pending.append("remote_desktop")
                next_steps.append(f"Add a separate policy_read_token_ref, then run {resume_command}.")
                setup = None
            else:
                adapter = adapters_by_name["remote_desktop"]
                client_factory = getattr(adapter, "client_factory", None)
                try:
                    setup = collect_remote_setup(interactive=False, config=remote,
                        client_factory=client_factory) if client_factory else collect_remote_setup(interactive=False, config=remote)
                except (RemoteConfigError, CredentialError, OSError, RuntimeError, ValueError) as exc:
                    states["remote_desktop"] = "pending"
                    pending.append("remote_desktop")
                    next_steps.append(f"{exc}; provide hostname, allowed_emails and secure token references, then run {resume_command}.")
                    setup = None
                if setup is not None:
                    try:
                        adapter._test_policy_read(policy_ref, setup)
                    except (CredentialError, RemoteConfigError, OSError, RuntimeError, ValueError) as exc:
                        states["remote_desktop"] = "pending"
                        pending.append("remote_desktop")
                        next_steps.append(f"Policy-read connection test failed: {exc}; correct its reference, then run {resume_command}.")
                        setup = None
            if setup is not None:
                states["remote_desktop"] = "ready"
                installable["components"]["remote_desktop"] = True
                remote["zone_id"] = setup.zone.zone_id
                installable["remote_desktop"] = remote

    for name in sorted(key for key, enabled in selected_components.items() if enabled and key != "remote_desktop"):
        adapter = adapters_by_name.get(name)
        if adapter is None:
            if name in {"providers", "mcp", "memory"}:
                states.setdefault(name, "pending")
                pending.append(name)
                next_steps.append(f"{name.replace('_', ' ')} account setup remains pending; run {resume_command} after its verified connector is available.")
            continue
        if name == "remote_desktop":
            continue
        if interactive:
            result = adapter.configure(installable, input_fn=input_fn, output_fn=output_fn,
                                       secret_reader=secret_reader, credential_store=credential_store)
        else:
            configure_noninteractive = getattr(adapter, "configure_noninteractive", None)
            if not callable(configure_noninteractive):
                states[name] = "pending"
                pending.append(name)
                next_steps.append(f"{name.replace('_', ' ')} has no validated noninteractive setup path; run {resume_command} in a terminal.")
                continue
            result = configure_noninteractive(installable, credential_store=credential_store)
        states[name] = result.state
        installable.update(result.config)
        if result.state == "ready":
            installable["components"][name] = True
        if result.state != "ready":
            pending.append(name)
        if result.state == "failed":
            failures.append(name)
        next_steps.extend(result.next_steps)

    # Persist only non-secret selections and adapter state through the caller's
    # private journal. Credential references and values are deliberately omitted.
    if journal is not None:
        payload = {"mode": install_mode, "selected_components": selected_components,
                   "paths": installable.get("paths", {}), "account_states": states}
        journal.checkpoint("installer:setup", "failed" if failures else "pending" if pending else "ready", payload)

    if not pending:
        try:
            validate_config(installable)
        except (ValueError, TypeError) as exc:
            return WizardResult("failed", selected_components, installable, str(exc), resume_command,
                                ("Correct the configuration and rerun setup.",), states, exit_code=2)
    state = "failed" if failures else "pending" if pending else "ready"
    message = ("One or more account checks failed; correct the listed settings and resume." if failures
               else "Setup choices saved; selected account adapters determine readiness." if pending
               else "Selected setup adapters completed their connection checks.")
    return WizardResult(state, selected_components, installable,
                        message, resume_command if pending or failures else None,
                        tuple(dict.fromkeys(next_steps)), states,
                        exit_code=1 if failures else 4 if pending else 0)
