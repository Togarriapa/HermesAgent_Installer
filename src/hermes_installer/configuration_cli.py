"""User-facing account/configuration command adapter dispatch.

The CLI owns locking and secure root paths; this layer performs only the
selected account flow, returns structured state and never alters services.
"""
from __future__ import annotations

import inspect
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Callable

from .results import CommandResult, Finding, OutcomeState
from .setup_runtime_adapters import JournalSetupStateStore, build_setup_adapters
from .setup_wizard import AdapterResult, PrivateFileCredentialStore


def _outcome(result: AdapterResult, *, command: str, resume_command: str,
             details: Mapping[str, Any] | None = None) -> CommandResult:
    state = {"ready": OutcomeState.READY, "pending": OutcomeState.PENDING,
             "failed": OutcomeState.FAILED}[result.state]
    combined = dict(details or {})
    combined.update({"account_state": result.state, "next_steps": list(result.next_steps),
                     "config": dict(result.config)})
    exit_code = 0 if result.state == "ready" else 4 if result.state == "pending" else 1
    return CommandResult(command, state, result.message,
                         (Finding(f"{command}.account", result.message, state, combined),),
                         resume_command, exit_code)


def _get_adapter(adapters: Mapping[str, Any], target: str | None, name: str | None) -> tuple[str, Any]:
    if target == "provider":
        key = "providers"
    elif target == "mcp":
        key = "mcp"
    elif target == "remote-desktop":
        key = "remote_desktop"
    elif target == "memory":
        key = "memory"
    else:
        raise ValueError("configuration target is unsupported")
    try:
        return key, adapters[key]
    except KeyError:
        return key, None


def run_configuration_command(action: str, *, config_data: Mapping[str, Any],
                              journal: Any, credential_store: Any,
                              interactive: bool, resume_command: str,
                              target: str | None = None, name: str | None = None,
                              choice: str | None = None, url: str | None = None,
                              input_fn: Callable[[str], str] = input,
                              output_fn: Callable[[str], None] = print,
                              secret_reader: Callable[[str], str] | None = None,
                              adapters: Mapping[str, Any] | None = None,
                              remote_journal: Any = None) -> CommandResult:
    """Run `configure`, `test-connection`, or `select-memory` without relocking.

    The caller must hold the installer process lock and pass its verified
    private Journal and credential store. Network waits occur under the CLI
    process lifetime but no second state lock is acquired here.
    """
    from .credentials import read_hidden_token
    from .config import ConfigError, validate_config

    if action not in {"configure", "test-connection", "select-memory", "resolve-source"}:
        raise ValueError("configuration command action is unsupported")
    current = dict(config_data)
    secret_reader = secret_reader or (lambda prompt: read_hidden_token(prompt=prompt))
    store = credential_store or PrivateFileCredentialStore(
        Path(current.get("paths", {}).get("state_root", "~/HermesInstaller/state")).expanduser())
    registered = dict(build_setup_adapters(journal=journal, credential_store=store))
    registered.update(adapters or {})

    if action == "resolve-source":
        # Revision discovery is deliberately not inferred from a URL. Keep
        # arbitrary repositories out of the live configuration until the user
        # provides an exact immutable GitHub commit and component selection.
        message = "A source URL alone does not identify immutable source bytes; no repository was fetched or executed."
        finding = Finding("source.resolution", message, OutcomeState.PENDING,
            {"url_supplied": bool(url), "resolved_revision": None,
             "next_step": "Select a component and provide its exact HTTPS GitHub owner/repository plus a full 40-character commit SHA."})
        return CommandResult(action, OutcomeState.PENDING, message, (finding,), resume_command, 4)

    if action == "select-memory":
        key, adapter = _get_adapter(registered, "memory", None)
        if adapter is None:
            result = AdapterResult("pending", "The protected memory setup adapter is not available.", {},
                ("Install the memory enrollment owner, then rerun `hermes-installer select-memory`.",))
        else:
            state_store = JournalSetupStateStore(journal, "memory")
            if choice:
                aliases = {"agent-memory": "agent-memory", "agentmemory": "agent-memory"}
                selected = aliases.get(choice.casefold(), choice.casefold())
                if selected not in getattr(adapter, "OPTIONS", {}):
                    result = AdapterResult("failed", "Memory choice is not in the reviewed provider catalog.", {},
                                           ("Choose openviking, claude-mem, or agent-memory.",))
                    return _outcome(result, command=action, resume_command=resume_command)
                state_store.put_selection("provider_id", selected)
            if interactive:
                result = _invoke_configure(adapter, current, interactive=True,
                    input_fn=input_fn, output_fn=output_fn, secret_reader=secret_reader,
                    credential_store=store, setup_state_store=state_store)
            else:
                configure_noninteractive = getattr(adapter, "configure_noninteractive", None)
                result = (configure_noninteractive(current, credential_store=store)
                          if callable(configure_noninteractive) else
                          AdapterResult("pending", "Memory selection has no validated non-interactive setup path.", {},
                              ("Run the guided memory selection in a terminal, then resume.",)))
        return _outcome(result, command=action, resume_command=resume_command,
                        details={"selected_memory_provider": JournalSetupStateStore(journal, "memory").get_selection("provider_id")})

    key, adapter = _get_adapter(registered, target, name)
    if adapter is None:
        result = AdapterResult("pending", f"The {key.replace('_', ' ')} adapter is not available.", {},
            (f"Complete protected {key.replace('_', ' ')} enrollment, then run `hermes-installer {action} {target or key}`.",))
        return _outcome(result, command=action, resume_command=resume_command)

    if action == "test-connection":
        test = getattr(adapter, "test_connection", None)
        if not callable(test):
            result = AdapterResult("pending", f"{key.replace('_', ' ')} has no protected functional connection probe.", {},
                ("Complete root-owned account enrollment and bind the fixed harmless connection test, then retry.",))
        else:
            try:
                result = test(current)
            except Exception as exc:
                result = AdapterResult("pending", f"Connection test remains pending ({type(exc).__name__}); no credential or response body was reported.", {},
                    (f"Check the selected {target or key} account and resume with `hermes-installer test-connection {target or key}`.",))
        if not isinstance(result, AdapterResult):
            raise TypeError("connection probe must return a typed AdapterResult")
        return _outcome(result, command=action, resume_command=resume_command,
                        details={"target": target, "name": name})

    if target == "provider" and name and hasattr(adapter, "select_provider"):
        try:
            adapter.select_provider(name)
        except ValueError as exc:
            result = AdapterResult("failed", str(exc), {},
                ("Choose the provider name listed by this installer build.",))
            return _outcome(result, command=action, resume_command=resume_command)
    if target == "mcp" and name:
        from .mcp.adapters import SERVICES
        if name not in SERVICES:
            result = AdapterResult("failed", "MCP service name is not in the reviewed service catalog.", {},
                ("Choose one exact service ID from the installed MCP service catalog.",))
            return _outcome(result, command=action, resume_command=resume_command)
        state_store = JournalSetupStateStore(journal, "mcp")
        state_store.put_selection("service_id", name)
    if not interactive:
        configure_noninteractive = getattr(adapter, "configure_noninteractive", None)
        if not callable(configure_noninteractive):
            result = AdapterResult("pending", f"{key.replace('_', ' ')} has no validated non-interactive setup path.", {},
                (f"Run `hermes-installer configure {target or key}` in a terminal, then save the validated secret references.",))
        else:
            kwargs = {"credential_store": store}
            state_store = _component_state_store(journal, key)
            if state_store is not None:
                kwargs["setup_state_store"] = state_store
            result = configure_noninteractive(current, **_accepted_kwargs(configure_noninteractive, kwargs))
    else:
        state_store = _component_state_store(journal, key)
        result = _invoke_configure(adapter, current, interactive=True, input_fn=input_fn,
            output_fn=output_fn, secret_reader=secret_reader, credential_store=store,
            setup_state_store=state_store, remote_journal=remote_journal)
    if not isinstance(result, AdapterResult):
        raise TypeError("setup adapter must return a typed AdapterResult")

    output = dict(current)
    output.update(result.config)
    components = dict(output.get("components", {}))
    if result.state == "ready" and key in {"providers", "mcp", "memory", "remote_desktop"}:
        components[key] = True
    else:
        components[key] = False
    output["components"] = components
    try:
        validate_config(output)
    except (ConfigError, TypeError, ValueError) as exc:
        # Pending account setup may contain non-installable state, but anything
        # presented as a saved config must remain valid under the strict schema.
        return CommandResult(action, OutcomeState.FAILED,
            f"The setup result did not produce a valid installer configuration: {exc}",
            exit_code=2)
    return _outcome(result, command=action, resume_command=resume_command,
                    details={"target": target, "name": name, "account_state": result.state})


def _component_state_store(journal: Any, key: str) -> JournalSetupStateStore | None:
    namespace = key if key in {"providers", "mcp", "memory"} else None
    if namespace is None or journal is None:
        return None
    return JournalSetupStateStore(journal, namespace)


def _accepted_kwargs(function: Callable[..., Any], offered: Mapping[str, Any]) -> dict[str, Any]:
    try:
        signature = inspect.signature(function)
    except (TypeError, ValueError):
        return {}
    if any(parameter.kind == inspect.Parameter.VAR_KEYWORD
           for parameter in signature.parameters.values()):
        return dict(offered)
    return {name: value for name, value in offered.items() if name in signature.parameters}


def _invoke_configure(adapter: Any, config: Mapping[str, Any], *, interactive: bool,
                      input_fn: Callable[[str], str], output_fn: Callable[[str], None],
                      secret_reader: Callable[[str], str], credential_store: Any,
                      setup_state_store: JournalSetupStateStore | None,
                      remote_journal: Any = None) -> AdapterResult:
    configure = getattr(adapter, "configure", None)
    if not callable(configure):
        return AdapterResult("pending", "The selected account adapter has no configure operation.", {},
                             ("Complete the adapter's protected enrollment API, then resume.",))
    offered = {"input_fn": input_fn, "output_fn": output_fn,
               "secret_reader": secret_reader, "credential_store": credential_store,
               "setup_state_store": setup_state_store, "remote_journal": remote_journal}
    result = configure(config, **_accepted_kwargs(configure, offered))
    if not isinstance(result, AdapterResult):
        raise TypeError("setup adapter must return a typed AdapterResult")
    return result
