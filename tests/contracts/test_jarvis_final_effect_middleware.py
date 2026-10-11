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


def _call(*, owner_handle="A" * 43, call_id="tool-call-1", name="shell"):
    return ObservedNativeToolCall(
        handle="B" * 43, attempt_handle="C" * 43,
        owner_turn_handle=owner_handle, tool_call_id=call_id,
        tool_name=name, arguments_sha256=hashlib.sha256(b'{"command":"x"}').hexdigest(),
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


class JarvisFinalEffectMiddlewareTests(unittest.TestCase):
    def _install(self, client):
        ctx = _Context()
        install_jarvis_final_effect_middleware(ctx, client)
        self.assertIn("tool_execution", ctx.callbacks)
        return ctx.callbacks["tool_execution"]

    def _run(self, client, *, args=None, dispatch_args=None):
        arguments = args if args is not None else {"command": "x"}
        dispatch = NativeToolDispatch(object(), "tool-call-1", "shell", b'{"command":"x"}')
        observed = _call()
        calls = []
        callback = self._install(client)
        with patch("hermes_installer.native_invocations.current_native_tool_dispatch",
                   return_value=dispatch), patch(
                       "hermes_installer.remote.core_native_observer.register_tool_call_from_current_parent",
                       return_value=observed):
            result = callback(tool_name="shell", args=dispatch_args or arguments,
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
