"""One fixed Root-enrolled no-tools chat on the selected new Hermes Core peer."""
from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path
from typing import Any

from .core_native_observer import (
    CoreNativeObservationClient,
    CoreNativeObservationUnavailable,
    LifecycleStartupProbeContext,
    lifecycle_startup_probe_scope,
    take_lifecycle_startup_terminal,
)
from .native_child_adapter import NativeChildMode, apply_native_child_tool_closure

_METHOD = "jarvis.lifecycle_startup_probe"
_RPC_ERROR_CODE = -32000
_RPC_ERROR_MESSAGE = "lifecycle startup probe refused"
_RPC_DIAGNOSTIC_SCHEMA = 1
_RPC_DIAGNOSTIC_STAGES = frozenset({
    "parameters", "root_claim", "primary_identity", "route", "account",
    "agent_setup", "prompt", "conversation", "terminal", "response",
})
_RPC_DIAGNOSTIC_EXCEPTION_TYPES = frozenset({
    "CoreNativeObservationUnavailable", "ImportError", "ModuleNotFoundError", "NameError",
    "AttributeError", "TypeError", "ValueError", "OSError", "TimeoutError", "RuntimeError",
    "other",
})
_PROMPT_PREFIX = "Reply with exactly JARVIS-STARTUP-"
_PROMPT_SUFFIX = ". Do not use tools."
_RESPONSE_PREFIX = "JARVIS-STARTUP-"
_MAX_SOUL_BYTES = 1024 * 1024
_UNSET_STARTUP_PROMPT_CACHE = object()


class _StartupProbeRefusal(Exception):
    """Closed, per-call refusal metadata with no original exception text."""

    def __init__(self, stage: str, exception_type: str):
        self.stage = stage
        self.exception_type = exception_type


def _startup_refusal_data(stage: str, exception_type: str) -> str:
    if stage not in _RPC_DIAGNOSTIC_STAGES or exception_type not in _RPC_DIAGNOSTIC_EXCEPTION_TYPES:
        raise CoreNativeObservationUnavailable("startup refusal diagnostic is outside the fixed schema")
    data = json.dumps({"schema": _RPC_DIAGNOSTIC_SCHEMA, "stage": stage,
                       "exception_type": exception_type}, ensure_ascii=True,
                      sort_keys=True, separators=(",", ":"), allow_nan=False)
    encoded = data.encode("ascii", "strict")
    if len(encoded) > 512:
        raise CoreNativeObservationUnavailable("startup refusal diagnostic exceeded its fixed bound")
    return data


def _startup_exception_type(exc: Exception) -> str:
    exception_type = type(exc)
    if exception_type is CoreNativeObservationUnavailable:
        return "CoreNativeObservationUnavailable"
    for allowed_type in (ImportError, ModuleNotFoundError, NameError, AttributeError,
                         TypeError, ValueError, OSError, TimeoutError, RuntimeError):
        if exception_type is allowed_type:
            return allowed_type.__name__
    return "other"


def _read_primary_identity(home: Path) -> tuple[bytes, tuple[int, ...]]:
    path = home / "SOUL.md"
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                 | getattr(os, "O_CLOEXEC", 0))
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
                or before.st_nlink != 1 or before.st_size > _MAX_SOUL_BYTES):
            raise CoreNativeObservationUnavailable("selected primary identity custody differs")
        content = bytearray()
        while len(content) <= _MAX_SOUL_BYTES:
            block = os.read(fd, min(65536, _MAX_SOUL_BYTES + 1 - len(content)))
            if not block:
                break
            content.extend(block)
        parent = os.open(home, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                         | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
        try:
            named = os.stat("SOUL.md", dir_fd=parent, follow_symlinks=False)
        finally:
            os.close(parent)
        signature = lambda item: (item.st_dev, item.st_ino, item.st_mode, item.st_uid,
            item.st_gid, item.st_nlink, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
        after = os.fstat(fd)
        if (len(content) != before.st_size or signature(before) != signature(after)
                or signature(before) != signature(named)):
            raise CoreNativeObservationUnavailable("selected primary identity changed while read")
        return bytes(content), signature(before)
    finally:
        os.close(fd)


def _startup_agent_matches_fixed_route(agent: Any,
                                       context: LifecycleStartupProbeContext) -> bool:
    return (
        getattr(agent, "provider", None) == context.provider
        and getattr(agent, "model", None) == context.model
        and getattr(agent, "api_mode", None) == context.api_mode
        and getattr(agent, "enabled_toolsets", None) == []
        and getattr(agent, "tools", None) == []
        and tuple(sorted(getattr(agent, "valid_tool_names", ()))) == ()
        and getattr(agent, "skip_context_files", None) is True
        and getattr(agent, "load_soul_identity", None) is False
        and getattr(agent, "skip_background_review", None) is True
        and getattr(agent, "_memory_store", None) is None
        and getattr(agent, "_memory_manager", None) is None
        and getattr(agent, "_session_db", None) is None
        and getattr(getattr(agent, "_checkpoint_mgr", None), "enabled", None) is False
        and getattr(agent, "prefill_messages", None) in (None, [])
    )


def _run_probe(params: Any, *, client: CoreNativeObservationClient) -> dict[str, Any]:
    stage = "parameters"
    agent = None
    try:
        if (type(params) is not dict or set(params) != {"probe_handle"}
                or type(client) is not CoreNativeObservationClient):
            raise CoreNativeObservationUnavailable("fixed startup probe parameters are required")

        stage = "root_claim"
        context = client.claim_lifecycle_startup_probe(params["probe_handle"])
        if type(context) is not LifecycleStartupProbeContext or not context.is_root_issued():
            raise CoreNativeObservationUnavailable("Root startup probe context is unavailable")
        if os.geteuid() <= 0:
            raise CoreNativeObservationUnavailable("startup probe requires the selected Hermes account")

        stage = "primary_identity"
        from hermes_constants import get_hermes_home
        from agent.prompt_builder import load_soul_md

        home = Path(get_hermes_home()).resolve(strict=True)
        raw_before, signature_before = _read_primary_identity(home)
        identity = load_soul_md(home_override=home)
        raw_after, signature_after = _read_primary_identity(home)
        if (raw_before != raw_after or signature_before != signature_after
                or hashlib.sha256(raw_before).hexdigest() != context.primary_source_sha256
                or not isinstance(identity, str) or not identity.strip()
                or "[...truncated SOUL.md:" in identity
                or hashlib.sha256(identity.encode("utf-8", "strict")).hexdigest()
                   != context.active_soul_sha256):
            raise CoreNativeObservationUnavailable("loaded primary identity differs from Root readback")

        stage = "route"
        from hermes_cli.runtime_provider import resolve_runtime_provider
        runtime = resolve_runtime_provider(requested=context.provider, target_model=context.model)
        if (not isinstance(runtime, dict) or runtime.get("provider") != context.provider
                or runtime.get("api_mode") != context.api_mode
                or runtime.get("base_url", "").rstrip("/") != context.base_url):
            raise CoreNativeObservationUnavailable("selected Codex route changed before startup probe")

        stage = "account"
        from hermes_cli.auth_codex import resolve_codex_runtime_credentials
        from .core_native_observer import _codex_account_fingerprint
        credentials = resolve_codex_runtime_credentials(read_only=True)
        account = _codex_account_fingerprint(lambda: credentials)
        if account != context.account_fingerprint:
            raise CoreNativeObservationUnavailable("selected Codex account changed before startup probe")

        stage = "agent_setup"
        from run_agent import AIAgent
        agent = AIAgent(
            base_url=runtime["base_url"], api_key=runtime.get("api_key"),
            provider=context.provider, api_mode=context.api_mode, model=context.model,
            max_iterations=1, max_tokens=64, enabled_toolsets=[],
            skip_memory=True, skip_context_files=True, skip_background_review=True,
            session_db=None, checkpoints_enabled=False, load_soul_identity=False,
            ephemeral_system_prompt=identity, session_id=context.session_id,
            save_trajectories=False, quiet_mode=True,
        )
        apply_native_child_tool_closure(agent, NativeChildMode.PLANNER)
        if not _startup_agent_matches_fixed_route(agent, context):
            raise CoreNativeObservationUnavailable("ephemeral startup agent is not the fixed no-tools route")

        stage = "prompt"
        prompt = _PROMPT_PREFIX + context.nonce + _PROMPT_SUFFIX
        if getattr(agent, "_cached_system_prompt", _UNSET_STARTUP_PROMPT_CACHE) is not None:
            raise CoreNativeObservationUnavailable("fresh startup agent already has native prompt state")
        from agent.conversation_loop import _restore_or_build_system_prompt
        _restore_or_build_system_prompt(agent, None, [])
        native_base = getattr(agent, "_cached_system_prompt", None)
        if (not isinstance(native_base, str) or not native_base
                or not _startup_agent_matches_fixed_route(agent, context)):
            raise CoreNativeObservationUnavailable("native startup initialization changed the fixed agent")
        from agent.codex_runtime import _codex_developer_instructions
        expected_instructions = _codex_developer_instructions(agent)
        if (not isinstance(expected_instructions, str) or not expected_instructions
                or identity not in expected_instructions
                or len(expected_instructions) > 256 * 1024):
            raise CoreNativeObservationUnavailable("native startup prompt does not contain the selected identity")
        expected_instructions.encode("utf-8", "strict")
        stage = "conversation"
        with lifecycle_startup_probe_scope(
                context, identity=identity, expected_instructions=expected_instructions):
            result = agent.run_conversation(
                user_message=prompt, conversation_history=[])

        stage = "terminal"
        if (type(result) is not dict or result.get("completed") is not True
                or result.get("failed") is True or result.get("partial") is True
                or result.get("interrupted") is True or result.get("error") not in (None, "")
                or not isinstance(result.get("final_response"), str)
                or result["final_response"] != _RESPONSE_PREFIX + context.nonce):
            raise CoreNativeObservationUnavailable("native startup conversation did not complete exactly")
        terminal = take_lifecycle_startup_terminal(context)

        stage = "response"
        response = result["final_response"].encode("utf-8", "strict")
        response_sha256 = hashlib.sha256(response).hexdigest()
        if response_sha256 != terminal["response_text_sha256"]:
            raise CoreNativeObservationUnavailable("native and provider startup terminals differ")
        return {
            "schema": 1, "probe_handle": context.probe_handle,
            "completion_handle": terminal["completion_handle"],
            "status": "completed", "response_sha256": response_sha256,
        }
    except _StartupProbeRefusal:
        raise
    except Exception as exc:
        raise _StartupProbeRefusal(stage, _startup_exception_type(exc)) from None
    finally:
        if agent is not None:
            try:
                agent.close()
            except Exception as exc:
                raise _StartupProbeRefusal("response", _startup_exception_type(exc)) from None


def register_lifecycle_startup_probe(server_module: Any, *,
                                     client: CoreNativeObservationClient) -> None:
    """Register exactly one private handler at the pinned native gateway seam."""
    register = getattr(server_module, "register_method", None)
    make_error = getattr(server_module, "_err", None)
    if (not callable(register) or not callable(make_error)
            or type(client) is not CoreNativeObservationClient):
        raise CoreNativeObservationUnavailable("pinned native register_method seam is unavailable")

    def lifecycle_startup_probe(rid: Any, params: Any) -> dict[str, Any]:
        try:
            result = _run_probe(params, client=client)
        except _StartupProbeRefusal as refusal:
            return make_error(rid, _RPC_ERROR_CODE, _RPC_ERROR_MESSAGE,
                              _startup_refusal_data(refusal.stage, refusal.exception_type))
        make_ok = getattr(server_module, "_ok", None)
        if not callable(make_ok):
            raise CoreNativeObservationUnavailable("pinned native JSON-RPC response seam is unavailable")
        return make_ok(rid, result)

    register(_METHOD, lifecycle_startup_probe)
