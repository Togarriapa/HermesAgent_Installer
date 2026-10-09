from __future__ import annotations

import hashlib
import json
import sys
import time
import unittest
from dataclasses import dataclass
from types import MappingProxyType, SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[2] / "src"))

from hermes_installer.native_invocations import (
    NativeInvocationUnavailable,
    begin_observed_tool_invocation,
    canonical_tool_arguments,
    current_native_invocation_binding,
    dispatch_native_mcp_tool_call,
    _CURRENT_BINDING,
    _CURRENT_MCP_RESULT,
    _CURRENT_TOOL_CALL_ID,
    _pending_native_mcp_results,
    _native_result_lock,
    _initial_input_lock,
    _initial_input_messages,
    _store_pending_native_mcp_result,
    prepare_native_provider_request,
    read_selected_native_input,
    record_native_tool_result,
    install_observed_tool_calls,
    install_provider_response_tool_calls,
    attach_provider_stream_capture,
    finish_provider_stream_response,
    finish_selected_native_turn,
    clear_native_turn_scope,
)


class NativeInvocationBoundaryTests(unittest.TestCase):
    def tearDown(self):
        import hermes_installer.native_invocations as invocations
        with invocations._initial_input_lock:
            invocations._initial_input = None
            invocations._initial_input_failed = False
            invocations._initial_input_messages.clear()
        with invocations._native_result_lock:
            invocations._pending_native_mcp_results.clear()
        invocations.clear_native_turn_scope()

    def _metadata(self, arguments: dict):
        import hashlib

        return {
            "producer_context_handle": "p" * 40,
            "tool_call_bindings": [{
                "observed_call_handle": "c" * 40,
                "provider_tool_call_id": "call-1",
                "tool_name": "native_fixture",
                "arguments_sha256": hashlib.sha256(canonical_tool_arguments(arguments)).hexdigest(),
            }],
        }

    def test_actual_final_arguments_get_root_binding_only_in_lexical_scope(self):
        arguments = {"record": "one"}
        agent = SimpleNamespace()
        install_observed_tool_calls(agent, self._metadata(arguments))
        calls = []

        @dataclass(frozen=True)
        class Binding:
            schema: int = 1
            invocation_handle: str = "i" * 40
            package_id: str = "package-a"
            profile_id: str = "profile-a"
            generation: str = "generation-a"
            adapter_id: str = "native-fixture"
            action_id: str = "lookup"
            arguments_sha256: str = hashlib.sha256(canonical_tool_arguments(arguments)).hexdigest()
            parent_closure_digest: str = "b" * 64
            expires_monotonic: float = time.monotonic() + 100
            binding_sha256: str = "d" * 64

        class Authority:
            def begin_native_invocation(self, producer, observed, canonical):
                calls.append((producer, observed, canonical))
                return Binding()

        with begin_observed_tool_invocation(
            agent, Authority(), tool_call_id="call-1", tool_name="native_fixture", arguments=arguments,
        ) as binding:
            self.assertIs(binding, current_native_invocation_binding())
        self.assertIsNone(current_native_invocation_binding())
        self.assertEqual(calls, [("p" * 40, "c" * 40, canonical_tool_arguments(arguments))])
        self.assertEqual(agent._hermes_installer_observed_tool_calls, {})

    def test_forged_unknown_duplicate_or_argument_changed_calls_do_not_begin(self):
        agent = SimpleNamespace()
        with self.assertRaises(NativeInvocationUnavailable):
            install_observed_tool_calls(agent, {"producer_context_handle": "caller", "tool_call_bindings": []})
        install_observed_tool_calls(agent, self._metadata({"record": "one"}))
        calls = []

        class Authority:
            def begin_native_invocation(self, *_args):
                calls.append(True)
                return None

        with self.assertRaises(NativeInvocationUnavailable):
            with begin_observed_tool_invocation(
                agent, Authority(), tool_call_id="call-1", tool_name="native_fixture",
                arguments={"record": "changed"},
            ):
                self.fail("argument mismatch must not enter dispatch")
        self.assertEqual(calls, [])
        with begin_observed_tool_invocation(
            agent, Authority(), tool_call_id="unknown", tool_name="native_fixture", arguments={},
        ) as binding:
            self.assertIsNone(binding)

    def test_native_mcp_dispatch_uses_only_lexical_binding_and_exact_schema(self):
        import json
        from hermes_installer.native_invocations import _CURRENT_BINDING

        arguments = {"resource": "selected", "limit": 1}
        argument_bytes = canonical_tool_arguments(arguments)
        schema = {"name": "mcp__selected__read_selected", "description": "selected fixture tool",
                  "parameters": {
                      "type": "object", "properties": {
                          "resource": {"type": "string"}, "limit": {"type": "integer", "maximum": 5},
                      }, "required": ["resource", "limit"], "additionalProperties": False,
                  }}
        schema_digest = hashlib.sha256(json.dumps(
            schema["parameters"], ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False,
        ).encode("utf-8")).hexdigest()
        registration = SimpleNamespace(
            id="mcp.read.selected", native_tool_name="mcp__selected__read_selected",
            native_schema_sha256=schema_digest, native_schema=MappingProxyType({
                "name": "mcp__selected__read_selected", "description": "selected fixture tool",
                "parameters": MappingProxyType({
                    "type": "object", "properties": MappingProxyType({
                        "resource": MappingProxyType({"type": "string"}),
                        "limit": MappingProxyType({"type": "integer", "maximum": 5}),
                    }), "required": ("resource", "limit"), "additionalProperties": False,
                }),
            }),
            native_package_id="package-a", native_package_generation="generation-a",
            profile_id="profile-a",
        )
        binding = SimpleNamespace(
            invocation_handle="i" * 40, package_id="package-a", profile_id="profile-a",
            generation="generation-a", adapter_id="hermes-installer.native-mcp-dispatch.v1",
            action_id="mcp.read.selected", arguments_sha256=hashlib.sha256(argument_bytes).hexdigest(),
        )

        class Authority:
            def __init__(self): self.calls = []
            def dispatch_native_mcp(self, *args):
                self.calls.append(args)
                return SimpleNamespace(status=200, body=b'{"content":[{"type":"text","text":"ok"}]}',
                                       source_receipt_handle="h" * 40)

        authority = Authority()
        token = _CURRENT_BINDING.set(binding)
        call_token = _CURRENT_TOOL_CALL_ID.set("call-1")
        result_token = _CURRENT_MCP_RESULT.set(None)
        try:
            result = dispatch_native_mcp_tool_call(authority, registration, arguments)
        finally:
            _CURRENT_MCP_RESULT.reset(result_token)
            _CURRENT_TOOL_CALL_ID.reset(call_token)
            _CURRENT_BINDING.reset(token)
        self.assertEqual(result, '{"content":[{"type":"text","text":"ok"}]}')
        self.assertEqual(authority.calls, [("i" * 40, argument_bytes)])

    def test_native_mcp_dispatch_denies_forged_scope_args_and_bad_result_before_exposure(self):
        import json
        from hermes_installer.native_invocations import _CURRENT_BINDING

        arguments = {"resource": "selected"}
        encoded_schema = (b'{"additionalProperties":false,"properties":{"resource":{"type":"string"}},'
                          b'"required":["resource"],"type":"object"}')
        argument_schema = json.loads(encoded_schema)
        schema = {"description": "selected fixture tool", "name": "mcp__selected__read_selected",
                  "parameters": argument_schema}
        schema_digest = hashlib.sha256(encoded_schema).hexdigest()
        registration = SimpleNamespace(
            id="mcp.read.selected", native_tool_name="mcp__selected__read_selected",
            native_schema_sha256=schema_digest, native_schema=schema,
            native_package_id="package-a", native_package_generation="generation-a",
            profile_id="profile-a",
        )

        class Authority:
            def __init__(self, response): self.response, self.calls = response, []
            def dispatch_native_mcp(self, *args): self.calls.append(args); return self.response

        wrong_profile = SimpleNamespace(
            invocation_handle="i" * 40, package_id="package-a", profile_id="profile-b",
            generation="generation-a", adapter_id="hermes-installer.native-mcp-dispatch.v1",
            action_id="mcp.read.selected", arguments_sha256=hashlib.sha256(
                canonical_tool_arguments(arguments)).hexdigest(),
        )
        authority = Authority(SimpleNamespace(status=200, body=b"private", source_receipt_handle="h" * 40))
        token = _CURRENT_BINDING.set(wrong_profile)
        try:
            with self.assertRaises(NativeInvocationUnavailable):
                dispatch_native_mcp_tool_call(authority, registration, arguments)
        finally:
            _CURRENT_BINDING.reset(token)
        self.assertEqual(authority.calls, [])

        binding = SimpleNamespace(
            invocation_handle="i" * 40, package_id="package-a", profile_id="profile-a",
            generation="generation-a", adapter_id="hermes-installer.native-mcp-dispatch.v1",
            action_id="mcp.read.selected", arguments_sha256="0" * 64,
        )
        token = _CURRENT_BINDING.set(binding)
        try:
            with self.assertRaises(NativeInvocationUnavailable):
                dispatch_native_mcp_tool_call(authority, registration, arguments)
        finally:
            _CURRENT_BINDING.reset(token)
        self.assertEqual(authority.calls, [])

        binding.arguments_sha256 = hashlib.sha256(canonical_tool_arguments(arguments)).hexdigest()
        authority = Authority(SimpleNamespace(status=403, body=b"secret backend detail",
                                              source_receipt_handle="h" * 40))
        token = _CURRENT_BINDING.set(binding)
        try:
            with self.assertRaises(NativeInvocationUnavailable) as denied:
                dispatch_native_mcp_tool_call(authority, registration, arguments)
        finally:
            _CURRENT_BINDING.reset(token)
        self.assertNotIn("secret", str(denied.exception))

    def test_native_mcp_argument_schema_digest_ignores_envelope_and_uses_utf8(self):
        from hermes_installer.native_invocations import _CURRENT_BINDING

        arguments = {"resource": "selected"}
        parameters = {"type": "object", "properties": {"resource": {"type": "string"}},
                      "required": ["resource"], "additionalProperties": False,
                      "description": "café"}
        schema_digest = hashlib.sha256(json.dumps(
            parameters, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False,
        ).encode("utf-8")).hexdigest()
        registration = SimpleNamespace(
            id="mcp.read.selected", native_tool_name="mcp__selected__read_selected",
            native_schema_sha256=schema_digest,
            native_schema={"name": "mcp__selected__read_selected", "description": "envelope text is not pinned",
                           "parameters": parameters},
            native_package_id="package-a", native_package_generation="generation-a", profile_id="profile-a",
        )
        binding = SimpleNamespace(
            invocation_handle="i" * 40, package_id="package-a", profile_id="profile-a",
            generation="generation-a", adapter_id="hermes-installer.native-mcp-dispatch.v1",
            action_id="mcp.read.selected", arguments_sha256=hashlib.sha256(
                canonical_tool_arguments(arguments)).hexdigest(),
        )

        class Authority:
            def __init__(self): self.calls = []
            def dispatch_native_mcp(self, *args):
                self.calls.append(args)
                return SimpleNamespace(status=200, body=b"ok", source_receipt_handle="h" * 40)

        authority = Authority()
        token = _CURRENT_BINDING.set(binding)
        call_token = _CURRENT_TOOL_CALL_ID.set("call-1")
        result_token = _CURRENT_MCP_RESULT.set(None)
        try:
            self.assertEqual(dispatch_native_mcp_tool_call(authority, registration, arguments), "ok")
        finally:
            _CURRENT_MCP_RESULT.reset(result_token)
            _CURRENT_TOOL_CALL_ID.reset(call_token)
            _CURRENT_BINDING.reset(token)
        self.assertEqual(len(authority.calls), 1)

    def test_root_selected_initial_input_is_taken_after_loader_ready_and_attached_once(self):
        import io
        from hermes_installer.authority.client import AuthorityClient
        from hermes_installer import native_boundary
        import hermes_installer.native_invocations as invocations

        raw = b"root admitted prompt\n"
        delivery = SimpleNamespace(
            schema=1, source_receipt_handle="s" * 40,
            selected_execution_handle="e" * 40,
            turn_handle="t" * 40,
            input_sha256=hashlib.sha256(raw).hexdigest(), input_size_bytes=len(raw),
            expires_monotonic=time.monotonic() + 20,
        )
        calls = []
        authority = SimpleNamespace(take_selected_native_input=lambda: calls.append("take") or delivery)
        with invocations._initial_input_lock:
            invocations._initial_input = None
            invocations._initial_input_messages.clear()
        with patch("hermes_installer.native_plugin_loader.ensure_selected_native_plugins_ready",
                   return_value=SimpleNamespace(_loader_ready=True)) as ready, \
             patch.object(AuthorityClient, "for_current_process",
                          new=classmethod(lambda cls, **_kwargs: authority)):
            self.assertEqual(read_selected_native_input(io.BytesIO(raw)), "root admitted prompt\n")
            self.assertEqual(invocations._CURRENT_NATIVE_TURN_HANDLE.get(), "t" * 40)
            messages = [{"role": "user", "content": "root admitted prompt\n"}]
            saved = []
            with patch.object(native_boundary, "_save_receipt", side_effect=lambda rows, handle: saved.append((rows, handle))), \
                 patch.object(native_boundary, "prepare_provider_request", side_effect=lambda kwargs, *, purpose: dict(kwargs)):
                result = prepare_native_provider_request({"messages": messages}, purpose="native-primary")
                prepare_native_provider_request({"messages": messages}, purpose="native-primary")
        ready.assert_called_once_with()
        self.assertEqual(calls, ["take"])
        self.assertIs(result["messages"], messages)
        self.assertEqual(saved, [(messages, "s" * 40)])

    def test_turn_finish_requires_matching_root_handles_and_successful_facade_result(self):
        import hermes_installer.native_invocations as invocations
        from hermes_installer.authority.client import AuthorityClient

        calls = []
        authority = SimpleNamespace(
            finish_selected_native_turn=lambda turn, response: calls.append((turn, response)),
        )
        with patch.object(AuthorityClient, "for_current_process",
                          new=classmethod(lambda cls, **_kwargs: authority)):
            invocations._CURRENT_NATIVE_TURN_HANDLE.set("t" * 40)
            invocations._CURRENT_FINAL_RESPONSE.set(("t" * 40, "f" * 40))
            finish_selected_native_turn(SimpleNamespace(), {"final_response": "answer"})
            self.assertEqual(calls, [("t" * 40, "f" * 40)])

            invocations._CURRENT_NATIVE_TURN_HANDLE.set("t" * 40)
            invocations._CURRENT_FINAL_RESPONSE.set(("other-turn" * 4, "f" * 40))
            finish_selected_native_turn(SimpleNamespace(), {"final_response": "answer"})
            invocations._CURRENT_NATIVE_TURN_HANDLE.set("t" * 40)
            invocations._CURRENT_FINAL_RESPONSE.set(("t" * 40, "f" * 40))
            finish_selected_native_turn(SimpleNamespace(), {"interrupted": True})
        self.assertEqual(calls, [("t" * 40, "f" * 40)])
        clear_native_turn_scope()

    def test_turn_finish_uses_only_root_response_take_metadata(self):
        import hermes_installer.native_invocations as invocations
        from hermes_installer.authority.client import AuthorityClient

        calls = []
        raw_body = b'{"choices":[]}'
        root_metadata = {
            "producer_context_handle": "p" * 40,
            "tool_call_bindings": [],
            "turn_handle": "t" * 40,
            "final_response_delivery_handle": "f" * 40,
        }
        class Headers:
            def get_list(self, name):
                return {
                    "x-hermes-native-response-ref": ["r" * 43],
                    "content-encoding": ["identity"],
                    "content-length": [str(len(raw_body))],
                }.get(name, [])
        response = SimpleNamespace(headers=Headers(), content=raw_body)
        response.http_response = response
        authority = SimpleNamespace(
            take_native_response_metadata=lambda *args: calls.append(("take", args)) or root_metadata,
            finish_selected_native_turn=lambda *args: calls.append(("finish", args)),
        )
        with patch.object(AuthorityClient, "for_current_process",
                          new=classmethod(lambda cls, **_kwargs: authority)):
            invocations._CURRENT_NATIVE_TURN_HANDLE.set("t" * 40)
            install_provider_response_tool_calls(SimpleNamespace(), response, "n" * 40)
            finish_selected_native_turn(SimpleNamespace(), {"final_response": "answer"})
        self.assertEqual([name for name, _ in calls], ["take", "finish"])
        self.assertEqual(calls[0][1], ("r" * 43, hashlib.sha256(raw_body).hexdigest(), "n" * 40))
        self.assertEqual(calls[1][1], ("t" * 40, "f" * 40))
        clear_native_turn_scope()

    def test_root_selected_input_mismatch_denies_before_provider_prepare(self):
        import io
        from hermes_installer.authority.client import AuthorityClient
        from hermes_installer import native_boundary
        import hermes_installer.native_invocations as invocations

        raw = b"expected"
        delivery = SimpleNamespace(
            schema=1, source_receipt_handle="s" * 40, selected_execution_handle="e" * 40,
            turn_handle="t" * 40,
            input_sha256=hashlib.sha256(raw).hexdigest(), input_size_bytes=len(raw),
            expires_monotonic=time.monotonic() + 20,
        )
        authority = SimpleNamespace(take_selected_native_input=lambda: delivery)
        with invocations._initial_input_lock:
            invocations._initial_input = None
            invocations._initial_input_messages.clear()
        with patch("hermes_installer.native_plugin_loader.ensure_selected_native_plugins_ready"), \
             patch.object(AuthorityClient, "for_current_process",
                          new=classmethod(lambda cls, **_kwargs: authority)):
            with self.assertRaises(NativeInvocationUnavailable):
                read_selected_native_input(io.BytesIO(b"tampered"))
        with patch.object(native_boundary, "prepare_provider_request") as prepare:
            with self.assertRaises(NativeInvocationUnavailable):
                prepare_native_provider_request({"messages": [{"role": "user", "content": "tampered"}]},
                                                purpose="native-primary")
        prepare.assert_not_called()

    def test_mcp_receipt_is_taken_only_after_exact_tool_message_is_appended(self):
        import types
        from hermes_installer.authority.client import AuthorityClient
        from hermes_installer import native_boundary
        import hermes_installer.native_invocations as invocations

        body = b'{"content":"private result"}'
        agent = SimpleNamespace(_tool_result_content_for_active_model=lambda _name, result: result)
        message = {"role": "tool", "name": "mcp__selected__read", "tool_name": "mcp__selected__read",
                   "tool_call_id": "call-1", "content": body.decode("utf-8")}
        messages = [message]
        with invocations._native_result_lock:
            invocations._pending_native_mcp_results.clear()
        invocations._store_pending_native_mcp_result(
            agent, "call-1", ("mcp__selected__read", body, "h" * 40),
        )
        tool_helpers = types.ModuleType("agent.tool_dispatch_helpers")
        tool_helpers._maybe_append_elision_notice = lambda _name, value: value
        tool_helpers._maybe_wrap_untrusted = lambda _name, value: value
        consumed = []
        authority = SimpleNamespace(take_source_receipt=lambda handle: consumed.append(handle) or handle)
        saved = []
        with patch.dict(sys.modules, {"agent.tool_dispatch_helpers": tool_helpers}), \
             patch.object(AuthorityClient, "for_current_process",
                          new=classmethod(lambda cls, **_kwargs: authority)), \
             patch.object(native_boundary, "_save_receipt", side_effect=lambda rows, handle: saved.append((rows, handle))), \
             patch.object(native_boundary, "_block_conversation") as block:
            record_native_tool_result(agent, messages, message, body.decode("utf-8"))
        self.assertEqual(consumed, ["h" * 40])
        self.assertEqual(saved, [(messages, "h" * 40)])
        block.assert_not_called()

    def test_mcp_result_mutation_blocks_and_does_not_consume_root_receipt(self):
        import types
        from hermes_installer.authority.client import AuthorityClient
        from hermes_installer import native_boundary
        import hermes_installer.native_invocations as invocations

        body = b'{"content":"private result"}'
        agent = SimpleNamespace(_tool_result_content_for_active_model=lambda _name, result: result)
        message = {"role": "tool", "name": "mcp__selected__read", "tool_name": "mcp__selected__read",
                   "tool_call_id": "call-2", "content": "changed"}
        messages = [message]
        with invocations._native_result_lock:
            invocations._pending_native_mcp_results.clear()
        invocations._store_pending_native_mcp_result(
            agent, "call-2", ("mcp__selected__read", body, "h" * 40),
        )
        tool_helpers = types.ModuleType("agent.tool_dispatch_helpers")
        tool_helpers._maybe_append_elision_notice = lambda _name, value: value
        tool_helpers._maybe_wrap_untrusted = lambda _name, value: value
        authority = SimpleNamespace(take_source_receipt=lambda _handle: self.fail("must not consume"))
        with patch.dict(sys.modules, {"agent.tool_dispatch_helpers": tool_helpers}), \
             patch.object(AuthorityClient, "for_current_process",
                          new=classmethod(lambda cls, **_kwargs: authority)), \
             patch.object(native_boundary, "_block_conversation") as block:
            record_native_tool_result(agent, messages, message, body.decode("utf-8"))
        block.assert_called_once_with(messages)

    def test_root_response_call_binding_is_single_use_and_action_binding_is_checked(self):
        arguments = {"record": "one"}
        agent = SimpleNamespace()
        install_observed_tool_calls(agent, self._metadata(arguments))

        class Authority:
            def begin_native_invocation(self, *_args):
                return SimpleNamespace(
                    schema=1, invocation_handle="i" * 40, package_id="package-a",
                    profile_id="profile-a", generation="generation-a", adapter_id="native-fixture",
                    action_id="lookup", arguments_sha256="f" * 64, parent_closure_digest="b" * 64,
                    expires_monotonic=time.monotonic() + 100, binding_sha256="d" * 64,
                )

        with self.assertRaises(NativeInvocationUnavailable):
            with begin_observed_tool_invocation(
                agent, Authority(), tool_call_id="call-1", tool_name="native_fixture", arguments=arguments,
            ):
                self.fail("mismatched root binding must not enter dispatch")
        self.assertEqual(agent._hermes_installer_observed_tool_calls, {})

    def _response_fixture(self, body: bytes, metadata: object):
        from hermes_installer.authority.client import AuthorityClient

        class Headers:
            def __init__(self):
                self.rows = {
                    "x-hermes-native-response-ref": ["r" * 43],
                    "content-length": [str(len(body))],
                    "content-encoding": [],
                }

            def get_list(self, name):
                return self.rows.get(name.lower(), [])

        class Authority:
            calls = []

            def take_native_response_metadata(self, response_ref, digest, request_handle):
                self.calls.append((response_ref, digest, request_handle))
                if isinstance(metadata, BaseException):
                    raise metadata
                return metadata

        raw = SimpleNamespace(headers=Headers(), content=body)
        authority = Authority()
        return raw, authority, patch.object(AuthorityClient, "for_current_process", return_value=authority)

    def _response_metadata(self, body: bytes):
        del body  # Body digest and request correlation are validated by the root take RPC.
        rows = self._metadata({"record": "one"})["tool_call_bindings"]
        try:
            from hermes_installer.authority.types import NativeResponseMetadata, NativeToolCallBinding
        except ImportError:
            # The source-only unit checkout may not yet include the Authority
            # transport DTO commit. The merged integration run below exercises
            # this branch with the actual immutable client DTO.
            return SimpleNamespace(producer_context_handle="p" * 40, tool_call_bindings=tuple(rows))
        return NativeResponseMetadata(
            producer_context_handle="p" * 40,
            tool_call_bindings=tuple(NativeToolCallBinding(**row) for row in rows),
        )

    def test_response_header_is_only_a_lookup_and_body_digest_binds_result(self):
        arguments = {"record": "one"}
        agent = SimpleNamespace()
        body = b'{"choices":[]}'
        response = self._response_metadata(body)
        raw, authority, patcher = self._response_fixture(body, response)
        with patcher:
            install_provider_response_tool_calls(agent, SimpleNamespace(http_response=raw), "n" * 40)
        self.assertEqual(set(agent._hermes_installer_observed_tool_calls), {"call-1"})
        self.assertEqual(authority.calls, [("r" * 43, hashlib.sha256(body).hexdigest(), "n" * 40)])
        self.assertEqual(arguments, {"record": "one"})

    def test_forged_header_or_mismatched_root_response_digest_denies(self):
        agent = SimpleNamespace()
        body = b'{"choices":[]}'
        raw, authority, patcher = self._response_fixture(body, self._response_metadata(body))
        raw.headers.rows["x-hermes-native-response-ref"] = ["forged"]
        with patcher:
            with self.assertRaises(NativeInvocationUnavailable):
                install_provider_response_tool_calls(agent, SimpleNamespace(http_response=raw), "n" * 40)
        self.assertEqual(authority.calls, [])

        raw, authority, patcher = self._response_fixture(body, PermissionError("root digest mismatch"))
        with patcher:
            with self.assertRaises(NativeInvocationUnavailable):
                install_provider_response_tool_calls(agent, SimpleNamespace(http_response=raw), "n" * 40)
        self.assertEqual(len(authority.calls), 1)

    def test_stream_capture_preserves_exact_bytes_and_requires_content_length(self):
        body = b'data: {"choices":[]}\n\ndata: [DONE]\n\n'
        agent = SimpleNamespace()
        metadata = self._response_metadata(body)
        raw, authority, patcher = self._response_fixture(body, metadata)

        class StreamResponse:
            headers = raw.headers

            def iter_bytes(self, *args, **kwargs):
                del args, kwargs
                yield body[:12]
                yield body[12:]

        stream = SimpleNamespace(response=StreamResponse())
        attach_provider_stream_capture(stream, "n" * 40)
        output = b"".join(stream.response.iter_bytes())
        self.assertEqual(output, body)
        with patcher:
            finish_provider_stream_response(agent, stream)
        self.assertEqual(authority.calls, [("r" * 43, hashlib.sha256(body).hexdigest(), "n" * 40)])
        self.assertEqual(set(agent._hermes_installer_observed_tool_calls), {"call-1"})

        short_raw, _, _ = self._response_fixture(body, metadata)
        short_raw.headers.rows["content-length"] = [str(len(body) + 1)]
        incomplete = SimpleNamespace(response=type("Response", (), {
            "headers": short_raw.headers,
            "iter_bytes": lambda self: iter((body,)),
        })())
        attach_provider_stream_capture(incomplete, "n" * 40)
        tuple(incomplete.response.iter_bytes())
        with self.assertRaises(NativeInvocationUnavailable):
            finish_provider_stream_response(agent, incomplete)


if __name__ == "__main__":
    unittest.main()
