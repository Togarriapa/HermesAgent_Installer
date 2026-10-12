"""Source contracts for the pinned native master-effect middleware."""
from __future__ import annotations

import hashlib
import time
import unittest
from unittest.mock import patch

from hermes_installer.native_invocations import NativeToolDispatch
from hermes_installer.remote.core_native_observer import ObservedNativeToolCall
from hermes_installer.remote.core_native_observer import CoreNativeObservationClient
from hermes_installer.remote.jarvis_final_effects import (
    FinalEffectPending,
    FinalEffectPermit,
    install_jarvis_final_effect_middleware,
    review_digest,
)


class _Context:
    def __init__(self):
        self.callbacks = {}

    def register_middleware(self, name, callback):
        self.callbacks[name] = callback
        return name


def _client():
    return CoreNativeObservationClient()


def _call(*, owner_handle="A" * 43, call_id="tool-call-1", name="shell",
          arguments=b'{"command":"x"}'):
    return ObservedNativeToolCall(
        handle="B" * 43, attempt_handle="C" * 43,
        owner_turn_handle=owner_handle, tool_call_id=call_id,
        tool_name=name, arguments_sha256=hashlib.sha256(arguments).hexdigest(),
        expires_monotonic=time.monotonic() + 20,
    )


def _permit(observed, args_sha, digest, *, owner_handle=None, pending_id="D" * 43):
    return FinalEffectPermit(
        pending_id=pending_id,
        owner_turn_handle=owner_handle or observed.owner_turn_handle,
        gateway_turn_id="turn-1", owner_subject_sha256="e" * 64,
        core_generation="f" * 64, core_source_generation="1" * 64,
        source_generation_sha256="2" * 64, source_profile_id="hermes",
        tool_call_id=observed.tool_call_id, tool_name=observed.tool_name,
        arguments_sha256=args_sha, review_sha256=digest,
        expires_monotonic=time.monotonic() + 10,
    )


class _CallerReceipt:
    """Small test double for the bridge's sealed root caller classification."""
    def __init__(self, observed, mode):
        self.observed = observed
        self.mode = mode
        self.source_generation_sha256 = "2" * 64

    def matches_call(self, observed, *, tool_name, arguments_sha256):
        return (observed is self.observed and observed.tool_name == tool_name
                and observed.arguments_sha256 == arguments_sha256)


class JarvisFinalEffectMiddlewareTests(unittest.TestCase):
    def _install(self, client):
        ctx = _Context()
        install_jarvis_final_effect_middleware(ctx, client)
        self.assertIn("tool_execution", ctx.callbacks)
        return ctx.callbacks["tool_execution"]

    def _run(self, client, *, args=None, dispatch_args=None, name="shell", caller_mode="master_effect",
             receipt_factory=None):
        default_arguments = {"query": "x"} if name == "web_search" else {"command": "x"}
        arguments = default_arguments
        from hermes_installer.native_invocations import canonical_tool_arguments
        canonical = canonical_tool_arguments(default_arguments)
        dispatch = NativeToolDispatch(object(), "tool-call-1", name, canonical)
        observed = _call(name=name, arguments=canonical)
        client.authorize_current_tool_call = receipt_factory or (
            lambda *, observed_call: _CallerReceipt(observed_call, caller_mode))
        calls = []
        callback = self._install(client)
        with patch("hermes_installer.native_invocations.current_native_tool_dispatch",
                   return_value=dispatch), patch(
                       "hermes_installer.remote.core_native_observer.register_tool_call_from_current_parent",
                       return_value=observed), patch(
                           "hermes_installer.remote.core_native_observer.RootVerifiedMasterReadCall",
                           _CallerReceipt, create=True):
            result = callback(tool_name=name, args=dispatch_args if dispatch_args is not None
                              else args if args is not None else arguments,
                              next_call=lambda value: calls.append(value) or {"ok": True})
        return result, calls, observed, arguments

    def test_exact_approval_executes_once_and_is_bound_to_pending_receipt(self):
        args_sha = hashlib.sha256(b'{"command":"x"}').hexdigest()
        digest = review_digest("shell", args_sha)
        pending = FinalEffectPending("D" * 43, digest, time.monotonic() + 5)
        client = _client()
        with patch.object(CoreNativeObservationClient, "request_final_effect", lambda _self, **kwargs: pending), \
                patch.object(CoreNativeObservationClient, "poll_final_effect", lambda _self, **kwargs: _permit(
                    _call(), args_sha, digest, pending_id=pending.pending_id)):
            result, calls, _observed, arguments = self._run(client)
        self.assertEqual(result, {"ok": True})
        self.assertEqual(calls, [arguments])

    def test_obsidian_promotion_scope_is_issued_after_approval_and_call_is_reclassified(self):
        from contextlib import nullcontext

        args = {
            "draft_id": "A" * 32,
            "expected_draft_sha256": "b" * 64,
            "destination": "Research/approved.md",
            "expected_base_sha256": None,
            "review_disposition": "approve",
        }
        from hermes_installer.native_invocations import canonical_tool_arguments
        canonical = canonical_tool_arguments(args)
        args_sha = hashlib.sha256(canonical).hexdigest()
        digest = review_digest("obsidian_promote_reviewed_draft", args_sha)
        pending = FinalEffectPending("D" * 43, digest, time.monotonic() + 5)
        client = _client()
        events = []
        scopes = []

        class _Scope:
            tool_name = "obsidian_promote_reviewed_draft"
            mode = "master_effect"
            source_generation_sha256 = "2" * 64

            def matches(self, observed_call, binding):
                return observed_call.tool_name == self.tool_name and binding is not None

        client.request_final_effect = lambda **kwargs: events.append("request") or pending
        client.poll_final_effect = lambda **kwargs: events.append("approve") or _permit(
            kwargs["observed_call"], args_sha, digest, pending_id=pending.pending_id)
        client.bind_obsidian_native_vault = lambda: events.append("binding") or object()

        def authorize_scope(*, observed_call, binding):
            events.append("scope")
            scope = _Scope()
            scopes.append(scope)
            return scope

        client.authorize_obsidian_call_scope = authorize_scope

        def classify(*, observed_call):
            events.append("classify")
            return _CallerReceipt(observed_call, "master_effect")

        client.authorize_current_tool_call = classify
        callback_context = _Context()
        install_jarvis_final_effect_middleware(callback_context, client)
        with patch("hermes_installer.native_invocations.current_native_tool_dispatch",
                   return_value=NativeToolDispatch(object(), "tool-call-1",
                       "obsidian_promote_reviewed_draft", canonical)), \
                patch("hermes_installer.remote.core_native_observer.register_tool_call_from_current_parent",
                      side_effect=lambda **kwargs: _call(
                          name=kwargs["tool_name"], arguments=canonical)), \
                patch("hermes_installer.remote.core_native_observer.RootVerifiedMasterReadCall",
                      _CallerReceipt, create=True), \
                patch("hermes_installer.remote.obsidian_native_tools._admit_current_obsidian_call",
                      return_value=nullcontext()):
            calls = []
            result = callback_context.callbacks["tool_execution"](
                tool_name="obsidian_promote_reviewed_draft", args=args,
                next_call=lambda value: calls.append(value) or {"saved": True})

        self.assertEqual(result, {"saved": True})
        self.assertEqual(calls, [args])
        self.assertEqual(events.count("classify"), 2)
        self.assertGreater(events.index("scope"), events.index("approve"))
        self.assertEqual(len(scopes), 1)

    def test_obsidian_promotion_does_not_issue_scope_after_owner_call_changes(self):
        args = {
            "draft_id": "A" * 32,
            "expected_draft_sha256": "b" * 64,
            "destination": "Research/approved.md",
            "expected_base_sha256": None,
            "review_disposition": "approve",
        }
        from hermes_installer.native_invocations import canonical_tool_arguments
        canonical = canonical_tool_arguments(args)
        args_sha = hashlib.sha256(canonical).hexdigest()
        digest = review_digest("obsidian_promote_reviewed_draft", args_sha)
        pending = FinalEffectPending("D" * 43, digest, time.monotonic() + 5)
        client = _client()
        events = []
        scopes = []
        client.request_final_effect = lambda **kwargs: pending
        client.poll_final_effect = lambda **kwargs: _permit(
            kwargs["observed_call"], args_sha, digest, pending_id=pending.pending_id)
        client.bind_obsidian_native_vault = lambda: object()
        client.authorize_obsidian_call_scope = lambda **kwargs: scopes.append(True)

        def classify(*, observed_call):
            receipt = _CallerReceipt(observed_call, "master_effect")
            if events:
                receipt.source_generation_sha256 = "3" * 64
            events.append("classified")
            return receipt

        client.authorize_current_tool_call = classify

        ctx = _Context()
        install_jarvis_final_effect_middleware(ctx, client)
        with patch("hermes_installer.native_invocations.current_native_tool_dispatch",
                   return_value=NativeToolDispatch(object(), "tool-call-1",
                       "obsidian_promote_reviewed_draft", canonical)), \
                patch("hermes_installer.remote.core_native_observer.register_tool_call_from_current_parent",
                      return_value=_call(name="obsidian_promote_reviewed_draft", arguments=canonical)), \
                patch("hermes_installer.remote.core_native_observer.RootVerifiedMasterReadCall",
                      _CallerReceipt, create=True):
            calls = []
            result = ctx.callbacks["tool_execution"](
                tool_name="obsidian_promote_reviewed_draft", args=args,
                next_call=lambda value: calls.append(value))

        self.assertEqual(events, ["classified", "classified"])
        self.assertFalse(scopes)
        self.assertFalse(calls)
        self.assertEqual(result["effect_executed"], "false")

    def test_obsidian_private_draft_keeps_immediate_scoped_dispatch(self):
        from contextlib import nullcontext

        args = {"title": "Research notes", "markdown": "Private working draft"}
        from hermes_installer.native_invocations import canonical_tool_arguments
        canonical = canonical_tool_arguments(args)
        client = _client()
        events = []

        class _Scope:
            tool_name = "obsidian_create_private_draft"
            mode = "master_read"
            source_generation_sha256 = "2" * 64

        client.bind_obsidian_native_vault = lambda: object()
        client.authorize_obsidian_call_scope = lambda **kwargs: events.append("scope") or _Scope()
        client.request_final_effect = lambda **kwargs: self.fail(
            "private draft must not request final-effect approval")
        client.authorize_current_tool_call = lambda *, observed_call: _CallerReceipt(
            observed_call, "master_read")

        ctx = _Context()
        install_jarvis_final_effect_middleware(ctx, client)
        with patch("hermes_installer.native_invocations.current_native_tool_dispatch",
                   return_value=NativeToolDispatch(object(), "tool-call-1",
                       "obsidian_create_private_draft", canonical)), \
                patch("hermes_installer.remote.core_native_observer.register_tool_call_from_current_parent",
                      return_value=_call(name="obsidian_create_private_draft", arguments=canonical)), \
                patch("hermes_installer.remote.core_native_observer.RootVerifiedMasterReadCall",
                      _CallerReceipt, create=True), \
                patch("hermes_installer.remote.obsidian_native_tools._admit_current_obsidian_call",
                      return_value=nullcontext()):
            calls = []
            result = ctx.callbacks["tool_execution"](
                tool_name="obsidian_create_private_draft", args=args,
                next_call=lambda value: events.append("dispatch") or calls.append(value) or {"draft": True})

        self.assertEqual(result, {"draft": True})
        self.assertEqual(calls, [args])
        self.assertEqual(events, ["scope", "dispatch"])

    def test_root_proved_expert_research_executes_without_owner_final_effect_request(self):
        client = _client()
        result, calls, _observed, arguments = self._run(
            client, name="web_search", caller_mode="expert_read")
        self.assertEqual(result, {"ok": True})
        self.assertEqual(calls, [arguments])

    def test_expert_effect_is_denied_before_final_effect_request(self):
        client = _client()
        requests = []
        client.request_final_effect = lambda **kwargs: requests.append(kwargs)
        result, calls, _observed, _arguments = self._run(client, caller_mode="expert_read")
        self.assertFalse(calls)
        self.assertFalse(requests)
        self.assertEqual(result["effect_executed"], "false")

    def test_fixed_resources_handler_receives_exact_call_without_gate_consuming_lineage(self):
        """The fixed adapter performs its own root claim/lineage checks."""
        arguments = {"goal": "research the requested topic"}
        dispatch = NativeToolDispatch(
            object(), "resources-call-1", "resources_delegate",
            b'{"goal":"research the requested topic"}',
        )
        calls = []
        callback = self._install(_client())
        with patch("hermes_installer.native_invocations.current_native_tool_dispatch",
                   return_value=dispatch), patch(
                       "hermes_installer.remote.core_native_observer.register_tool_call_from_current_parent",
                       side_effect=AssertionError("generic gate consumed handler lineage")):
            result = callback(tool_name="resources_delegate", args=arguments,
                              next_call=lambda value: calls.append(value) or {"accepted": True})
        self.assertEqual(result, {"accepted": True})
        self.assertEqual(calls, [arguments])

    def test_fixed_resources_handler_rejects_changed_arguments_before_dispatch(self):
        dispatch = NativeToolDispatch(
            object(), "resources-call-1", "resources_delegate",
            b'{"goal":"approved goal"}',
        )
        calls = []
        callback = self._install(_client())
        with patch("hermes_installer.native_invocations.current_native_tool_dispatch",
                   return_value=dispatch):
            result = callback(tool_name="resources_delegate", args={"goal": "changed goal"},
                              next_call=lambda value: calls.append(value))
        self.assertFalse(calls)
        self.assertEqual(result["effect_executed"], "false")

    def test_owner_mismatch_never_reaches_native_executor(self):
        args_sha = hashlib.sha256(b'{"command":"x"}').hexdigest()
        digest = review_digest("shell", args_sha)
        pending = FinalEffectPending("D" * 43, digest, time.monotonic() + 5)
        client = _client()
        with patch.object(CoreNativeObservationClient, "request_final_effect", lambda _self, **kwargs: pending), \
                patch.object(CoreNativeObservationClient, "poll_final_effect", lambda _self, **kwargs: _permit(
                    _call(), args_sha, digest, owner_handle="Z" * 43,
                    pending_id=pending.pending_id)):
            result, calls, _observed, _arguments = self._run(client)
        self.assertFalse(calls)
        self.assertEqual(result["effect_executed"], "false")

    def test_timeout_returns_pending_without_effect(self):
        args_sha = hashlib.sha256(b'{"command":"x"}').hexdigest()
        digest = review_digest("shell", args_sha)
        pending = FinalEffectPending("D" * 43, digest, time.monotonic() + 0.01)
        client = _client()
        with patch.object(CoreNativeObservationClient, "request_final_effect", lambda _self, **kwargs: pending), \
                patch.object(CoreNativeObservationClient, "poll_final_effect", lambda _self, **kwargs: None):
            result, calls, _observed, _arguments = self._run(client)
        self.assertFalse(calls)
        self.assertIn("pending", result["error"])

    def test_changed_arguments_fail_closed_before_request(self):
        args_sha = hashlib.sha256(b'{"command":"x"}').hexdigest()
        digest = review_digest("shell", args_sha)
        pending = FinalEffectPending("D" * 43, digest, time.monotonic() + 5)
        client = _client()
        with patch.object(CoreNativeObservationClient, "request_final_effect", lambda _self, **kwargs: pending), \
                patch.object(CoreNativeObservationClient, "poll_final_effect", lambda _self, **kwargs: None):
            result, calls, _observed, _arguments = self._run(client, args={"command": "changed"})
        self.assertFalse(calls)
        self.assertIn("arguments changed", result["error"])

    def test_observer_failure_and_cancelled_wait_return_without_effect(self):
        client = _client()
        with patch.object(CoreNativeObservationClient, "request_final_effect", lambda _self, **kwargs: (_ for _ in ()).throw(RuntimeError("offline"))), \
                patch.object(CoreNativeObservationClient, "poll_final_effect", lambda _self, **kwargs: None):
            result, calls, _observed, _arguments = self._run(client)
        self.assertFalse(calls)
        self.assertEqual(result["effect_executed"], "false")

    def test_cancelled_approval_wait_never_reaches_native_executor(self):
        args_sha = hashlib.sha256(b'{"command":"x"}').hexdigest()
        digest = review_digest("shell", args_sha)
        pending = FinalEffectPending("D" * 43, digest, time.monotonic() + 5)
        client = _client()
        with patch.object(CoreNativeObservationClient, "request_final_effect", lambda _self, **kwargs: pending), \
                patch.object(CoreNativeObservationClient, "poll_final_effect", lambda _self, **kwargs: (_ for _ in ()).throw(KeyboardInterrupt())):
            result, calls, _observed, _arguments = self._run(client)
        self.assertFalse(calls)
        self.assertEqual(result["effect_executed"], "false")

    def test_spent_approval_replay_is_rejected_by_root_client(self):
        args_sha = hashlib.sha256(b'{"command":"x"}').hexdigest()
        digest = review_digest("shell", args_sha)
        pending = FinalEffectPending("D" * 43, digest, time.monotonic() + 5)
        client = _client()
        spent = []

        def poll(_self, **kwargs):
            if spent:
                raise PermissionError("approval already spent")
            spent.append(True)
            return _permit(_call(), args_sha, digest, pending_id=pending.pending_id)

        with patch.object(CoreNativeObservationClient, "request_final_effect", lambda _self, **kwargs: pending), \
                patch.object(CoreNativeObservationClient, "poll_final_effect", poll):
            first, first_calls, _observed, _arguments = self._run(client)
            second, second_calls, _observed, _arguments = self._run(client)
        self.assertEqual(first, {"ok": True})
        self.assertEqual(len(first_calls), 1)
        self.assertFalse(second_calls)
        self.assertEqual(second["effect_executed"], "false")


if __name__ == "__main__":
    unittest.main()
