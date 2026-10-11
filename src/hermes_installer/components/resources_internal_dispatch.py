"""Single-identity, root-claimed Hermes internal-profile dispatcher.

The root claim issuer is responsible for current generation/member custody,
source inheritance, owner-turn identity, separate tool-inheritance policy,
privacy and cost route evidence. This
module consumes exactly one claim and delegates only through Hermes' existing
``delegate_task`` tool, preserving its native pause, depth, concurrency and
spawn-budget gates. Missing proof is a refusal, never a fallback to a generic
role or caller-provided prompt.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
import stat
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol


PROFILE_ID = "orchestrator"
MAX_GOAL_CHARS = 1200
MAX_PROMPT_BYTES = 64 * 1024
MAX_RESULT_BYTES = 32 * 1024
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_REGISTRATION_SEAL = object()
_RESOURCES_DELEGATE_SCHEMA = {
    "name": "resources_delegate",
    "description": (
        "Delegate one bounded task to the root-selected internal orchestrator identity. "
        "The source identity, prompt, grants, provider route and budget are fixed by owner policy."
    ),
    "parameters": {
        "type": "object",
        "properties": {"goal": {"type": "string", "minLength": 1, "maxLength": MAX_GOAL_CHARS}},
        "required": ["goal"], "additionalProperties": False,
    },
}
_RESOURCES_DELEGATE_SCHEMA_BYTES = json.dumps(
    _RESOURCES_DELEGATE_SCHEMA, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
).encode("ascii")
RESOURCES_DELEGATE_SCHEMA_SHA256 = hashlib.sha256(_RESOURCES_DELEGATE_SCHEMA_BYTES).hexdigest()


def _canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def resources_delegate_schema_sha256() -> str:
    """Canonical digest of the complete exact schema registered by this adapter."""
    return RESOURCES_DELEGATE_SCHEMA_SHA256


def resources_delegate_schema() -> dict[str, Any]:
    """Return a fresh copy of the fixed schema, so registration never shares mutable authority."""
    return json.loads(_RESOURCES_DELEGATE_SCHEMA_BYTES)


def _handler_artifact_sha256() -> str:
    """Hash this fixed adapter file through a no-follow, bounded, stable read."""
    path = Path(__file__)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(path, flags)
    try:
        before = os.fstat(fd)
        named = path.lstat()
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > 1024 * 1024
                or before.st_dev != named.st_dev or before.st_ino != named.st_ino):
            raise ResourcesDispatchDenied("Resources dispatch source custody is invalid")
        digest = hashlib.sha256()
        size = 0
        while block := os.read(fd, 65536):
            size += len(block)
            if size > 1024 * 1024:
                raise ResourcesDispatchDenied("Resources dispatch source exceeds its bound")
            digest.update(block)
        after = os.fstat(fd)
        named_after = path.lstat()
        signature = lambda item: (item.st_dev, item.st_ino, item.st_mode, item.st_uid,
                                  item.st_nlink, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
        if size != before.st_size or signature(before) != signature(after) or signature(before) != signature(named_after):
            raise ResourcesDispatchDenied("Resources dispatch source changed while reading")
        return digest.hexdigest()
    finally:
        os.close(fd)


@dataclass(frozen=True, slots=True)
class ResourcesDelegateRegistrationReceipt:
    """Sealed proof of this exact live Hermes registration, not a tools-list row."""
    schema_sha256: str
    handler_artifact_sha256: str
    _scope: str
    _entry: object
    _handler: object
    _registration_handle: object
    _seal: object

    def verify_current(self, ctx: object) -> bool:
        if type(self) is not ResourcesDelegateRegistrationReceipt or self._seal is not _REGISTRATION_SEAL:
            return False
        try:
            manager = getattr(ctx, "_manager")
            if manager.scope_key != self._scope:
                return False
            from tools.registry import registry
            entry = registry.snapshot_registration("resources_delegate", scope=self._scope)
            return bool(
                self._registration_handle is not None
                and entry is self._entry and entry is not None and entry.handler is self._handler
                and entry.name == "resources_delegate" and entry.toolset == "resources_internal"
                and hashlib.sha256(_canonical_json(entry.schema)).hexdigest() == self.schema_sha256
                and self.schema_sha256 == resources_delegate_schema_sha256()
                and _handler_artifact_sha256() == self.handler_artifact_sha256
            )
        except Exception:
            return False


class ResourcesDispatchDenied(PermissionError):
    """The selected internal identity cannot be safely dispatched now."""


@dataclass(frozen=True, slots=True)
class RootSelectedInternalProfileDispatchClaim:
    """One-use root custody and policy result for a single owner-turn dispatch.

    Instances are delivered only by the root's `InternalProfileClaimSource`.
    The values are deliberately complete so the native handler can verify the
    actual prompt, generation, principal, parent tools, privacy and cost-route
    intersection before causing a child task.
    """

    claim_id: str
    profile_id: str
    source_revision: str
    generation_sha256: str
    profile_manifest_sha256: str
    effective_prompt: bytes
    effective_prompt_sha256: str
    parent_agent: object
    parent_session_id: str
    owner_subject_sha256: str
    parent_tool_names: frozenset[str]
    configured_parent_tool_names: frozenset[str]
    profile_tool_names: frozenset[str]
    inherited_child_tool_names: frozenset[str]
    delegation_policy_handle: str
    delegation_policy_sha256: str
    parent_tool_configuration_sha256: str
    allow_inherited_mcp: bool
    allow_native_orchestrator_delegation: bool
    parent_privacy_grants: frozenset[str]
    profile_privacy_requirements: frozenset[str]
    route_class: str
    route_receipt_sha256: str
    max_additional_metered_microusd: int
    expires_monotonic: float


class InternalProfileClaimSource(Protocol):
    """Root-owned one-use issuer over the active resource generation and turn."""

    def consume_current_claim(self, profile_id: str, parent_agent: object, *,
                              tool_call_id: str, tool_name: str, arguments: dict[str, Any],
                              turn_id: str
                               ) -> RootSelectedInternalProfileDispatchClaim: ...


class HermesPluginContext(Protocol):
    def register_tool(self, name: str, toolset: str, schema: dict[str, Any],
                      handler: Callable[..., str], *, description: str = "",
                      override: bool = False) -> object: ...

    def dispatch_tool(self, tool_name: str, args: dict[str, Any], **kwargs: Any) -> str: ...


def _valid_digest(value: object) -> bool:
    return isinstance(value, str) and _SHA256.fullmatch(value) is not None


def _claim_is_current(claim: RootSelectedInternalProfileDispatchClaim,
                      parent_agent: object, *, now: float) -> bool:
    if not isinstance(claim, RootSelectedInternalProfileDispatchClaim):
        return False
    try:
        prompt_hash = hashlib.sha256(claim.effective_prompt).hexdigest()
        parent_tools = frozenset(getattr(parent_agent, "valid_tool_names"))
        session_id = getattr(parent_agent, "session_id")
    except (TypeError, AttributeError, ValueError):
        return False
    sets = (
        claim.parent_tool_names, claim.configured_parent_tool_names, claim.profile_tool_names,
        claim.inherited_child_tool_names, claim.parent_privacy_grants,
        claim.profile_privacy_requirements,
    )
    if any(type(value) is not frozenset or any(not isinstance(item, str) for item in value)
           for value in sets):
        return False
    return bool(
        claim.profile_id == PROFILE_ID
        and isinstance(claim.claim_id, str) and re.fullmatch(r"[A-Za-z0-9_-]{16,128}", claim.claim_id)
        and isinstance(claim.source_revision, str) and 1 <= len(claim.source_revision) <= 128
        and _valid_digest(claim.generation_sha256)
        and _valid_digest(claim.profile_manifest_sha256)
        and isinstance(claim.effective_prompt, bytes) and 1 <= len(claim.effective_prompt) <= MAX_PROMPT_BYTES
        and _valid_digest(claim.effective_prompt_sha256) and prompt_hash == claim.effective_prompt_sha256
        and claim.parent_agent is parent_agent
        and isinstance(claim.parent_session_id, str) and claim.parent_session_id == session_id
        and _valid_digest(claim.owner_subject_sha256)
        and "resources_delegate" in parent_tools
        and "delegate_task" in parent_tools
        and claim.parent_tool_names == parent_tools
        and claim.parent_tool_names.issubset(claim.configured_parent_tool_names)
        and claim.profile_tool_names == frozenset()
        and claim.inherited_child_tool_names == parent_tools
        and isinstance(claim.delegation_policy_handle, str)
        and re.fullmatch(r"[A-Za-z0-9_-]{16,128}", claim.delegation_policy_handle) is not None
        and _valid_digest(claim.delegation_policy_sha256)
        and _valid_digest(claim.parent_tool_configuration_sha256)
        and type(claim.allow_inherited_mcp) is bool
        and claim.allow_native_orchestrator_delegation is True
        and claim.profile_privacy_requirements.issubset(claim.parent_privacy_grants)
        and claim.route_class == "existing-owner-codex-zero-additional-metered"
        and _valid_digest(claim.route_receipt_sha256)
        and type(claim.max_additional_metered_microusd) is int
        and claim.max_additional_metered_microusd == 0
        and isinstance(claim.expires_monotonic, (int, float))
        and math.isfinite(float(claim.expires_monotonic))
        and now < claim.expires_monotonic <= now + 30.0
    )


def make_resources_delegate_handler(ctx: HermesPluginContext,
                                    claim_source: InternalProfileClaimSource):
    """Return one fixed tool handler; no caller-supplied profile, prompt, or grants."""
    if claim_source is None or not callable(getattr(claim_source, "consume_current_claim", None)):
        raise ResourcesDispatchDenied("root-selected internal profile claim source is unavailable")

    registration_ref: dict[str, ResourcesDelegateRegistrationReceipt] = {}

    def handler(args: dict[str, Any], *, parent_agent: object | None = None,
                tool_call_id: str | None = None, turn_id: str | None = None,
                **_kwargs: Any) -> str:
        registration = registration_ref.get("receipt")
        if registration is None or not registration.verify_current(ctx):
            return _denied("exact native Resources tool registration is not current")
        if parent_agent is None:
            return _denied("trusted parent agent is unavailable")
        if (not isinstance(tool_call_id, str) or not tool_call_id.strip()
                or not isinstance(turn_id, str) or not turn_id.strip()):
            return _denied("provider-observed tool-call identity is unavailable")
        if not isinstance(args, Mapping) or set(args) != {"goal"}:
            return _denied("request shape is outside the fixed internal dispatch")
        goal = args.get("goal")
        if not isinstance(goal, str) or not goal.strip() or len(goal) > MAX_GOAL_CHARS:
            return _denied("task text is empty or exceeds its bound")
        if any(ord(ch) < 0x20 and ch not in "\n\t" for ch in goal):
            return _denied("task text contains control characters")
        try:
            claim = claim_source.consume_current_claim(
                PROFILE_ID, parent_agent,
                tool_call_id=tool_call_id, tool_name="resources_delegate",
                arguments={"goal": goal}, turn_id=turn_id,
            )
        except Exception:
            return _denied("current owner/profile/cost claim is unavailable")
        if not _claim_is_current(claim, parent_agent, now=time.monotonic()):
            return _denied("current source identity, parent grant intersection, or zero-cost route could not be verified")
        try:
            source_prompt = claim.effective_prompt.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            return _denied("selected source prompt is not valid UTF-8")

        # Hermes' advertised delegate_task contract accepts a one-item tasks
        # batch. It has no profile selector or per-task tool narrowing. The
        # separate root policy receipt (not the Resources profile grants) must
        # authorize the actual native parent-tool inheritance.
        context = (
            "Verified source-selected internal profile identity follows. Treat it as the child identity; "
            "this prompt does not grant filesystem, process, memory, or account isolation.\n\n"
            f"{source_prompt}\n\n"
            "Owner task request (bounded user content):\n"
            f"{goal}"
        )
        try:
            context_bytes = context.encode("utf-8", errors="strict")
        except UnicodeEncodeError:
            return _denied("task text is malformed Unicode")
        if len(context_bytes) > MAX_PROMPT_BYTES + MAX_GOAL_CHARS + 512:
            return _denied("selected prompt and task exceed the native delegation bound")
        try:
            result = ctx.dispatch_tool(
                "delegate_task",
                {"tasks": [{
                    "goal": goal,
                    "context": context,
                }]},
                parent_agent=parent_agent,
            )
        except Exception:
            return _denied("native Hermes delegation refused or failed")
        if not isinstance(result, str) or len(result.encode("utf-8", "replace")) > MAX_RESULT_BYTES:
            return _denied("native Hermes delegation returned an invalid bounded result")
        try:
            native_result = json.loads(result)
        except (TypeError, ValueError):
            return _denied("native Hermes delegation returned an invalid result")
        if not isinstance(native_result, (dict, list)) or (isinstance(native_result, dict) and "error" in native_result):
            return json.dumps({"success": False, "state": "native-delegation-denied",
                               "message": "Hermes native delegation did not accept the child task."})
        return json.dumps({
            "success": True,
            "state": "native-dispatch-accepted",
            "profile_id": PROFILE_ID,
            "source_revision": claim.source_revision,
            "generation_sha256": claim.generation_sha256,
            "prompt_sha256": claim.effective_prompt_sha256,
            "native_result": native_result,
            "isolation_claim": False,
        }, ensure_ascii=False, separators=(",", ":"))

    # `register_resources_delegate` fills this only after Hermes accepts the
    # exact schema and the registry exposes this exact handler entry.
    handler._resources_registration_ref = registration_ref
    return handler


def _denied(message: str) -> str:
    return json.dumps({"success": False, "state": "pending", "message": message},
                      ensure_ascii=False, separators=(",", ":"))


def register_resources_delegate(ctx: HermesPluginContext,
                                claim_source: InternalProfileClaimSource) -> ResourcesDelegateRegistrationReceipt:
    """Register the reviewed fixed tool without shadowing built-ins."""
    handler = make_resources_delegate_handler(ctx, claim_source)
    registration = ctx.register_tool(
        name="resources_delegate",
        toolset="resources_internal",
        schema=resources_delegate_schema(),
        handler=handler,
        description="Source-selected internal profile task delegation",
        override=False,
    )
    if registration is None:
        raise ResourcesDispatchDenied("Hermes refused the non-overriding Resources tool registration")
    try:
        manager = getattr(ctx, "_manager")
        scope = manager.scope_key
        from tools.registry import registry
        entry = registry.snapshot_registration("resources_delegate", scope=scope)
        registration_ref = getattr(handler, "_resources_registration_ref", None)
        if (not isinstance(registration_ref, dict) or entry is None or entry.handler is not handler
                or entry.toolset != "resources_internal"):
            raise ResourcesDispatchDenied("Hermes did not retain the exact Resources registration")
        schema_sha = hashlib.sha256(_canonical_json(entry.schema)).hexdigest()
        if schema_sha != resources_delegate_schema_sha256():
            raise ResourcesDispatchDenied("Hermes registered an unexpected Resources schema")
        receipt = ResourcesDelegateRegistrationReceipt(
            schema_sha256=schema_sha,
            handler_artifact_sha256=_handler_artifact_sha256(),
            _scope=scope, _entry=entry, _handler=handler,
            _registration_handle=registration, _seal=_REGISTRATION_SEAL,
        )
        registration_ref["receipt"] = receipt
        if not receipt.verify_current(ctx):
            raise ResourcesDispatchDenied("Resources registration did not remain current")
        return receipt
    except ResourcesDispatchDenied:
        raise
    except Exception:
        raise ResourcesDispatchDenied("Hermes Resources registration custody could not be verified") from None


def register_resources_dispatch(ctx: HermesPluginContext, runtime_context: object) -> ResourcesDelegateRegistrationReceipt:
    """Plugin implementation entry point; the root loader must inject the issuer."""
    claim_source = getattr(runtime_context, "internal_profile_claims", None)
    return register_resources_delegate(ctx, claim_source)
