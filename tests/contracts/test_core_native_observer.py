"""Fail-closed contracts for the additive pinned-Hermes observation adapter.

Run these through the identified Pi validation path; local execution is not
authoritative for this hardware-bound integration.
"""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from hermes_installer.remote.core_native_observer import (
    CoreNativeObservationClient,
    CoreNativeObservationUnavailable,
    ObservedProviderAttempt,
    ObservedNativeToolCall,
    RootVerifiedNativeChildAuthorization,
    RootVerifiedMasterReadCall,
    _NATIVE_CHILD_AUTHORIZATION_SEAL,
    _MASTER_READ_CALL_SEAL,
    _codex_account_fingerprint,
    _mission_binding_from_wire,
    install_native_codex_process_observer,
    RootCoreNativeObservationRegistry,
)
from hermes_installer.remote.jarvis_mission_executor import MissionBinding


class _PluginContext:
    def __init__(self):
        self.middleware = {}

    def register_middleware(self, name, callback):
        self.middleware.setdefault(name, []).append(callback)
        return callback


def _native_response(output_text: str, output=None):
    if output is None:
        output = [SimpleNamespace(type="message", role="assistant", status="completed",
            content=[SimpleNamespace(type="output_text", text=output_text)])]
    return SimpleNamespace(output=output, output_text=output_text, usage=None,
        status="completed", id="resp-native-fixture", model="gpt-6-luna",
        incomplete_details=None, error=None, service_tier=None)


def test_native_response_codec_preserves_complete_fixed_namespace_digest():
    import hashlib
    import json
    from hermes_installer.remote.core_native_observer import _native_response_bytes

    response_text = "provider answer"
    response = _native_response(response_text)
    expected = {
        "output": [{"type": "message", "role": "assistant", "status": "completed",
                    "content": [{"type": "output_text", "text": response_text}]}],
        "output_text": response_text, "usage": None, "status": "completed",
        "id": "resp-native-fixture", "model": "gpt-6-luna",
        "incomplete_details": None, "error": None, "service_tier": None,
    }
    encoded = _native_response_bytes(response)
    assert encoded == json.dumps(expected, ensure_ascii=False, sort_keys=True,
        separators=(",", ":"), allow_nan=False).encode("utf-8")
    assert hashlib.sha256(encoded).hexdigest() == hashlib.sha256(
        json.dumps(expected, ensure_ascii=False, sort_keys=True,
            separators=(",", ":"), allow_nan=False).encode("utf-8")).hexdigest()


def test_native_response_codec_accepts_installed_official_sdk_nested_values():
    import hashlib
    import json
    sdk_models = pytest.importorskip("openai.types.responses")
    from hermes_installer.remote.core_native_observer import _native_response_bytes

    usage_type = getattr(sdk_models, "ResponseUsage", None)
    output_text_type = getattr(sdk_models, "ResponseOutputText", None)
    if usage_type is None or output_text_type is None:
        pytest.skip("installed official SDK exposes different Responses model names")
    usage = usage_type.model_construct(input_tokens=1, input_tokens_details={"cached_tokens": 0},
        output_tokens=2, output_tokens_details={"reasoning_tokens": 0}, total_tokens=3)
    output_text = output_text_type.model_construct(type="output_text", text="sdk text",
        annotations=[])
    response = _native_response("sdk text", output=[SimpleNamespace(
        type="message", role="assistant", status="completed", content=[output_text])])
    response.usage = usage
    expected = {
        "output": [{"type": "message", "role": "assistant", "status": "completed",
            "content": [output_text.model_dump(mode="json")]}],
        "output_text": "sdk text", "usage": usage.model_dump(mode="json"),
        "status": "completed", "id": "resp-native-fixture", "model": "gpt-6-luna",
        "incomplete_details": None, "error": None, "service_tier": None,
    }
    canonical = json.dumps(expected, ensure_ascii=False, sort_keys=True,
        separators=(",", ":"), allow_nan=False).encode("utf-8")
    assert _native_response_bytes(response) == canonical
    assert hashlib.sha256(_native_response_bytes(response)).hexdigest() == hashlib.sha256(
        canonical).hexdigest()


def test_real_openai_response_top_level_and_mixed_function_call_items():
    import hashlib
    import json
    sdk_models = pytest.importorskip("openai.types.responses")
    response_type = getattr(sdk_models, "Response", None)
    function_call_type = getattr(sdk_models, "ResponseFunctionToolCall", None)
    if response_type is None or function_call_type is None:
        pytest.skip("installed official SDK exposes different Responses model names")
    from hermes_installer.remote.core_native_observer import (
        _canonical, _native_response_bytes, _response_bytes, _response_tool_calls,
    )

    sdk_top = response_type.model_construct(id="resp-sdk", model="gpt-6-luna",
        output=[], status="completed", created_at=1, object="response")
    expected_sdk_bytes = _canonical(sdk_top.model_dump(mode="json"))
    assert _response_bytes(sdk_top) == expected_sdk_bytes

    sdk_call = function_call_type.model_construct(id="fc-sdk", call_id="call-sdk",
        name="lookup", arguments='{"query":"sdk"}', status="completed",
        type="function_call")
    native_call = SimpleNamespace(type="function_call", id=None, call_id="call-ns",
        name="lookup", status="completed", arguments='{"query":"namespace"}')
    dict_call = {"type": "function_call", "call_id": "call-dict", "name": "lookup",
        "arguments": '{"query":"dict"}'}
    response = _native_response("mixed", output=[sdk_call, dict_call, native_call])
    calls = _response_tool_calls(response)
    assert [(call_id, name) for call_id, name, _args in calls] == [
        ("call-sdk", "lookup"), ("call-dict", "lookup"), ("call-ns", "lookup")]
    encoded = _native_response_bytes(response)
    expected_native = {
        "output": [sdk_call.model_dump(mode="json"), dict_call,
            {"type": "function_call", "id": None, "call_id": "call-ns", "name": "lookup",
             "status": "completed", "arguments": '{"query":"namespace"}'}],
        "output_text": "mixed", "usage": None, "status": "completed",
        "id": "resp-native-fixture", "model": "gpt-6-luna",
        "incomplete_details": None, "error": None, "service_tier": None,
    }
    expected_native_bytes = _canonical(expected_native)
    assert encoded == expected_native_bytes
    assert hashlib.sha256(encoded).hexdigest() == hashlib.sha256(
        expected_native_bytes).hexdigest()
    assert json.loads(encoded)["output"][0]["type"] == "function_call"


def test_real_openai_nested_conversion_failure_has_no_sdk_fallback(monkeypatch):
    sdk_models = pytest.importorskip("openai.types.responses")
    usage_type = getattr(sdk_models, "ResponseUsage", None)
    if usage_type is None:
        pytest.skip("installed official SDK exposes different Responses usage model name")
    from hermes_installer.remote.core_native_observer import (
        CoreNativeObservationUnavailable, _response_bytes,
    )

    usage = usage_type.model_construct(input_tokens=1, input_tokens_details={},
        output_tokens=1, output_tokens_details={}, total_tokens=2)
    response = _native_response("native", output=[])
    response.usage = usage

    def conversion_fails(_self, *, mode):
        assert mode == "json"
        raise RuntimeError("private SDK conversion failure")

    monkeypatch.setattr(usage_type, "model_dump", conversion_fails)
    with pytest.raises(CoreNativeObservationUnavailable):
        _response_bytes(response)


@pytest.mark.parametrize("mutation", [
    lambda response: setattr(response, "extra", "private"),
    lambda response: delattr(response, "id"),
    lambda response: setattr(response, "usage", {"nested": 1 << 80}),
    lambda response: setattr(response, "error", {"nested": float("inf")}),
    lambda response: setattr(response, "output_text", 1),
    lambda response: setattr(response, "output_text", "x" * (256 * 1024 + 1)),
    lambda response: setattr(response, "output", [SimpleNamespace(
        type="output_text", text="x", extra="unknown")]),
    lambda response: setattr(response, "output", [SimpleNamespace(
        type="output_text", text=7)]),
    lambda response: setattr(response, "output", [SimpleNamespace(
        type="unknown_output", text="x")]),
    lambda response: setattr(response, "output", [SimpleNamespace(
        type="z" * 100_000, text="x")]),
    lambda response: setattr(response, "output", [SimpleNamespace(
        type="output_text", text="x" * (256 * 1024))]),
    lambda response: setattr(response, "output", [None] * 8193),
    lambda response: setattr(response, "usage", {1: "non-string key"}),
    lambda response: setattr(response, "usage", {"rows": [None] * 8180}),
])
def test_native_response_codec_refuses_unreviewed_or_non_json_shapes(mutation):
    from hermes_installer.remote.core_native_observer import (
        CoreNativeObservationUnavailable, _native_response_bytes,
    )

    response = _native_response("safe")
    mutation(response)
    with pytest.raises(CoreNativeObservationUnavailable):
        _native_response_bytes(response)


def test_native_response_codec_refuses_cycles_and_bounds_depth():
    from hermes_installer.remote.core_native_observer import (
        CoreNativeObservationUnavailable, _native_response_bytes,
    )

    cyclic = []
    cyclic.append(cyclic)
    with pytest.raises(CoreNativeObservationUnavailable):
        _native_response_bytes(_native_response("safe", output=cyclic))
    nested = "leaf"
    for _ in range(18):
        nested = [nested]
    with pytest.raises(CoreNativeObservationUnavailable):
        _native_response_bytes(_native_response("safe", output=nested))
    nested_namespace = SimpleNamespace(type="message", role="assistant",
        status="completed", content=[])
    nested_namespace.content.append(nested_namespace)
    with pytest.raises(CoreNativeObservationUnavailable):
        _native_response_bytes(_native_response("safe", output=[nested_namespace]))


def test_native_response_codec_enforces_aggregate_utf8_budget():
    from hermes_installer.remote.core_native_observer import (
        CoreNativeObservationUnavailable, _native_response_bytes,
    )

    repeated = "x" * 140_000
    response = _native_response(repeated, output=[SimpleNamespace(type="message",
        role="assistant", status="completed", content=[SimpleNamespace(
            type="output_text", text=repeated)])])
    with pytest.raises(CoreNativeObservationUnavailable):
        _native_response_bytes(response)


def test_native_response_codec_enforces_final_canonical_frame_bound():
    from hermes_installer.remote.core_native_observer import (
        CoreNativeObservationUnavailable, _native_response_bytes,
    )

    escaped = "\x01" * 50_000
    response = _native_response(escaped, output=[])
    assert len(escaped.encode("utf-8")) < 256 * 1024
    with pytest.raises(CoreNativeObservationUnavailable):
        _native_response_bytes(response)


def test_response_tool_call_extractor_handles_exact_native_json_dicts():
    import json
    from hermes_installer.remote.core_native_observer import _response_tool_calls

    response = _native_response("", output=[{
        "type": "function_call", "call_id": "call-1", "name": "lookup",
        "arguments": '{"query":"safe"}',
    }])
    calls = _response_tool_calls(response)
    assert calls == [("call-1", "lookup", json.dumps({"query": "safe"},
        sort_keys=True, separators=(",", ":")).encode())]


def test_response_tool_call_extractor_mixes_namespace_and_dict_items_and_rejects_duplicates():
    from hermes_installer.remote.core_native_observer import (
        CoreNativeObservationUnavailable, _response_tool_calls,
    )

    namespace_call = SimpleNamespace(type="function_call", call_id="call-ns",
        name="lookup", arguments='{"query":"ns"}')
    dict_call = {"type": "function_call", "call_id": "call-dict", "name": "lookup",
        "arguments": '{"query":"dict"}'}
    mixed = _response_tool_calls(_native_response("", output=[namespace_call, dict_call]))
    assert [entry[:2] for entry in mixed] == [
        ("call-ns", "lookup"), ("call-dict", "lookup")]
    with pytest.raises(CoreNativeObservationUnavailable):
        _response_tool_calls(_native_response("", output=[{
            **dict_call, "arguments": '{"query":"one","query":"two"}',
        }]))


@pytest.mark.parametrize("protected", [False, True])
@pytest.mark.parametrize("call_kind", ["dict", "namespace", "sdk"])
def test_native_dict_function_call_callback_preserves_or_refuses_root_lineage(
        tmp_path: Path, monkeypatch, protected: bool, call_kind: str):
    import hashlib
    import json
    import time
    import hermes_installer.remote.core_native_observer as observer

    client = CoreNativeObservationClient(socket_path=tmp_path / "unused.sock")
    monkeypatch.setattr(observer, "_codex_account_fingerprint", lambda _resolver: "f" * 64)
    monkeypatch.setattr(client, "planning_context_for_attempt",
        lambda **_kwargs: object() if protected else None)
    monkeypatch.setattr(client, "master_review_context_for_attempt", lambda **_kwargs: None)
    attempt = ObservedProviderAttempt("x" * 32, "o" * 32, time.monotonic() + 20)
    monkeypatch.setattr(client, "register_attempt", lambda **_kwargs: attempt)
    registered = []
    monkeypatch.setattr(client, "register_response", lambda **kwargs: registered.append(kwargs))
    ctx = _PluginContext()
    install_native_codex_process_observer(ctx, client=client)
    request = {"model": "gpt-6-luna", "tools": [{"name": "lookup"}],
        "input": [{"type": "message", "role": "user",
            "content": [{"type": "input_text", "text": "ordinary tool request"}]}]}
    if call_kind == "dict":
        call = {"type": "function_call", "call_id": "call-1", "name": "lookup",
            "arguments": '{"query":"safe"}'}
    elif call_kind == "namespace":
        call = SimpleNamespace(type="function_call", id=None, call_id="call-1",
            name="lookup", status="completed", arguments='{"query":"safe"}')
    else:
        sdk_models = pytest.importorskip("openai.types.responses")
        function_call_type = getattr(sdk_models, "ResponseFunctionToolCall", None)
        if function_call_type is None:
            pytest.skip("installed official SDK exposes a different function-call model name")
        call = function_call_type.model_construct(type="function_call", id="fc-1",
            call_id="call-1", name="lookup", status="completed",
            arguments='{"query":"safe"}')
    response = _native_response("tool output", output=[call])
    dispatched = []
    result = ctx.middleware["llm_execution"][0](
        provider="openai-codex", api_mode="codex_responses",
        base_url="https://chatgpt.com/backend-api/codex", model="gpt-6-luna",
        request=request, session_id="tool-session", turn_id="tool-turn",
        api_request_id="tool-request",
        next_call=lambda value: dispatched.append(value) or response)

    assert len(dispatched) == 1
    if protected:
        assert dispatched[0]["tools"] == []
        assert result is not response and registered == []
    else:
        assert result is response
        assert dispatched[0]["tools"] == [{"name": "lookup"}]
        assert len(registered) == 1 and registered[0]["attempt"] is attempt
        expected_args = json.dumps({"query": "safe"}, sort_keys=True,
            separators=(",", ":")).encode("utf-8")
        assert registered[0]["tool_calls"] == [{"id": "call-1", "name": "lookup",
            "arguments_sha256": hashlib.sha256(expected_args).hexdigest()}]


def test_non_native_top_level_model_dump_contract_is_unchanged():
    import json
    from hermes_installer.remote.core_native_observer import _response_bytes

    class ExistingTopLevelModelDump:
        def model_dump(self, *, mode):
            assert mode == "json"
            return {"response": "unchanged"}

    assert _response_bytes(ExistingTopLevelModelDump()) == json.dumps(
        {"response": "unchanged"}, ensure_ascii=False, sort_keys=True,
        separators=(",", ":"), allow_nan=False).encode("utf-8")


def test_native_response_subclass_and_nested_serializer_duck_are_refused():
    from hermes_installer.remote.core_native_observer import (
        CoreNativeObservationUnavailable, _native_response_bytes,
    )

    class NativeSubclass(SimpleNamespace):
        def model_dump(self, **_kwargs):
            raise AssertionError("native subclasses must not reach arbitrary serializers")

    subclass = NativeSubclass(**_native_response("safe").__dict__)
    from hermes_installer.remote.core_native_observer import _response_bytes
    with pytest.raises(CoreNativeObservationUnavailable):
        _response_bytes(subclass)

    invoked = []

    class SerializerDuck:
        def model_dump(self, **_kwargs):
            invoked.append(True)
            return {"type": "output_text", "text": "safe"}

    with pytest.raises(CoreNativeObservationUnavailable):
        _native_response_bytes(_native_response("safe", output=[SerializerDuck()]))
    assert invoked == []


def test_native_namespace_discriminator_comparison_never_calls_unsupported_equality():
    from hermes_installer.remote.core_native_observer import (
        CoreNativeObservationUnavailable, _native_response_bytes,
    )

    class EqualitySentinel:
        def __eq__(self, _other):
            raise AssertionError("unsupported fields must be refused before equality")

    item = SimpleNamespace(type="function_call", id=None, call_id="call-1", name="lookup",
        status=EqualitySentinel(), arguments="{}")
    with pytest.raises(CoreNativeObservationUnavailable):
        _native_response_bytes(_native_response("safe", output=[item]))


def test_native_namespace_field_checks_refuse_custom_keys_without_hashing():
    from hermes_installer.remote.core_native_observer import (
        CoreNativeObservationUnavailable, _native_response_bytes,
    )

    class HashSentinel:
        calls = 0

        def __hash__(self):
            type(self).calls += 1
            return 1

        def __eq__(self, _other):
            type(self).calls += 1
            return False

    response = _native_response("safe")
    response.__dict__.pop("id")
    key = HashSentinel()
    response.__dict__[key] = "private"
    HashSentinel.calls = 0
    with pytest.raises(CoreNativeObservationUnavailable):
        _native_response_bytes(response)
    assert HashSentinel.calls == 0

    nested = SimpleNamespace(type="function_call", id=None, call_id="call-1",
        name="lookup", status="completed", arguments="{}")
    nested.__dict__.pop("id")
    nested.__dict__[key] = None
    HashSentinel.calls = 0
    with pytest.raises(CoreNativeObservationUnavailable):
        _native_response_bytes(_native_response("safe", output=[nested]))
    assert HashSentinel.calls == 0


def test_non_codex_routes_pass_through_without_observation(tmp_path: Path):
    ctx = _PluginContext()
    client = CoreNativeObservationClient(socket_path=tmp_path / "unused.sock")
    install_native_codex_process_observer(ctx, client=client)
    callback = ctx.middleware["llm_execution"][0]
    seen = []

    result = callback(
        provider="openai", api_mode="chat_completions",
        base_url="https://api.openai.com/v1", request={"model": "gpt-test"},
        next_call=lambda request: seen.append(request) or {"status": "complete"},
    )

    assert result == {"status": "complete"}
    assert seen == [{"model": "gpt-test"}]


def test_selected_codex_route_disables_tools_when_root_mode_is_uncertain(
        tmp_path: Path, monkeypatch):
    import hermes_installer.remote.core_native_observer as observer

    ctx = _PluginContext()
    client = CoreNativeObservationClient(socket_path=tmp_path / "not-started.sock")
    install_native_codex_process_observer(ctx, client=client)
    monkeypatch.setattr(observer, "_codex_account_fingerprint", lambda _resolver: "a" * 64)
    request = {
        "model": "gpt-6-luna",
        "tools": [{"name": "resources_delegate"}],
        "input": [{"type": "message", "role": "user",
                   "content": [{"type": "input_text", "text": "ordinary chat"}]}],
    }
    seen = []

    result = ctx.middleware["llm_execution"][0](
        provider="openai-codex", api_mode="codex_responses",
        base_url="https://chatgpt.com/backend-api/codex", model="gpt-6-luna",
        request=request, session_id="session-1", turn_id="turn-1",
        api_request_id="request-1", next_call=lambda value: seen.append(value) or "completed",
    )

    assert result.status == "completed"
    assert "authority could not be verified" in result.output_text
    assert seen == []
    assert request["tools"] == [{"name": "resources_delegate"}]


def test_non_codex_fallback_is_not_called_for_root_planned_turn(tmp_path: Path, monkeypatch):
    import hashlib
    from hermes_installer.remote.core_gateway_inspector import PlanningContext

    ctx = _PluginContext()
    client = CoreNativeObservationClient(socket_path=tmp_path / "observer.sock")
    prompt = "root planner request"
    context = PlanningContext(1, "m" * 24, 1, "a" * 64, "b" * 64,
        hashlib.sha256(prompt.encode()).hexdigest(), "c" * 64, "d" * 64, "e" * 64, "hermes")
    monkeypatch.setattr(client, "planning_context_for_attempt", lambda **_kwargs: context)
    monkeypatch.setattr(client, "master_review_context_for_attempt", lambda **_kwargs: None)
    install_native_codex_process_observer(ctx, client=client)
    request = {"model": "gpt-test", "tools": [{"name": "resources_delegate"}],
        "input": [{"type": "message", "role": "user",
                   "content": [{"type": "input_text", "text": prompt}]}]}
    dispatched = []

    result = ctx.middleware["llm_execution"][0](
        provider="openai", api_mode="chat_completions", base_url="https://api.openai.com/v1",
        request=request, session_id="session-plan", turn_id="turn-plan",
        next_call=lambda value: dispatched.append(value) or {"status": "complete"},
    )

    assert result.status == "completed"
    assert result.output[0].type == "message"
    assert not any(item.type == "function_call" for item in result.output)
    assert dispatched == []
    assert request["tools"] == [{"name": "resources_delegate"}]


def test_planned_codex_does_not_dispatch_when_root_cannot_register_attempt(
        tmp_path: Path, monkeypatch):
    import hashlib
    import hermes_installer.remote.core_native_observer as observer
    from hermes_installer.remote.core_gateway_inspector import PlanningContext

    ctx = _PluginContext()
    client = CoreNativeObservationClient(socket_path=tmp_path / "observer.sock")
    prompt = "root planner request"
    context = PlanningContext(1, "m" * 24, 1, "a" * 64, "b" * 64,
        hashlib.sha256(prompt.encode()).hexdigest(), "c" * 64, "d" * 64, "e" * 64, "hermes")
    monkeypatch.setattr(client, "planning_context_for_attempt", lambda **_kwargs: context)
    monkeypatch.setattr(client, "register_attempt", lambda **_kwargs:
                        (_ for _ in ()).throw(CoreNativeObservationUnavailable("test denial")))
    monkeypatch.setattr(observer, "_codex_account_fingerprint", lambda _resolver: "f" * 64)
    install_native_codex_process_observer(ctx, client=client)
    request = {"model": "gpt-6-luna", "tools": [{"name": "resources_delegate"}],
        "input": [{"type": "message", "role": "user",
                   "content": [{"type": "input_text", "text": prompt}]}]}
    dispatched = []

    result = ctx.middleware["llm_execution"][0](
        provider="openai-codex", api_mode="codex_responses",
        base_url="https://chatgpt.com/backend-api/codex", model="gpt-6-luna",
        request=request, session_id="session-plan", turn_id="turn-plan",
        api_request_id="request-plan", next_call=lambda value: dispatched.append(value),
    )

    assert result.status == "completed"
    assert result.output[0].type == "message"
    assert not any(item.type == "function_call" for item in result.output)
    assert dispatched == []
    assert request["tools"] == [{"name": "resources_delegate"}]


def test_root_enrolled_planning_turn_reaches_provider_with_zero_tools(tmp_path: Path, monkeypatch):
    import hashlib
    from types import SimpleNamespace

    import hermes_installer.remote.core_native_observer as observer
    from hermes_installer.remote.core_gateway_inspector import PlanningContext

    ctx = _PluginContext()
    client = CoreNativeObservationClient(socket_path=tmp_path / "observer.sock")
    prompt = "Root-owned planning prompt"
    prompt_digest = hashlib.sha256(prompt.encode()).hexdigest()
    context = PlanningContext(1, "m" * 24, 1, "a" * 64, "b" * 64,
        prompt_digest, "c" * 64, "d" * 64, "e" * 64, "hermes")
    monkeypatch.setattr(client, "planning_context_for_attempt", lambda **_kwargs: context)
    monkeypatch.setattr(client, "master_review_context_for_attempt", lambda **_kwargs: None)
    attempt = ObservedProviderAttempt("x" * 32, "o" * 32, __import__("time").monotonic() + 20)
    monkeypatch.setattr(client, "register_attempt", lambda **_kwargs: attempt)
    receipts = []
    monkeypatch.setattr(client, "register_response", lambda **kwargs: receipts.append(kwargs))
    monkeypatch.setattr(observer, "_codex_account_fingerprint", lambda _resolver: "f" * 64)
    install_native_codex_process_observer(ctx, client=client)
    request = {
        "model": "gpt-6-luna",
        "tools": [{"name": "resources_delegate"}, {"name": "terminal"}],
        "input": [{"type": "message", "role": "user",
                   "content": [{"type": "input_text", "text": prompt}]}],
    }
    seen = []
    response = _native_response('{"execution_mode":"oneshot",'
        '"selected_source_ids":[],"plan":{}}', output=[])
    result = ctx.middleware["llm_execution"][0](
        provider="openai-codex", api_mode="codex_responses",
        base_url="https://chatgpt.com/backend-api/codex", model="gpt-6-luna",
        request=request, session_id="session-plan", turn_id="turn-plan",
        api_request_id="request-plan",
        next_call=lambda value: seen.append(value) or response,
    )

    assert result is response
    assert request["tools"] == [{"name": "resources_delegate"}, {"name": "terminal"}]
    assert seen[0]["tools"] == []
    assert seen[0]["tool_choice"] == "none"
    assert receipts[0]["response_text"] == response.output_text


@pytest.mark.parametrize("capture,expected_text", [(True, "exact provider answer"), (False, None)])
def test_observer_forwards_exact_child_output_only_for_root_admitted_capture(
        tmp_path: Path, monkeypatch, capture: bool, expected_text: str | None):
    """Root can retain exact Expert output for a sealed child, never ordinary chat text."""
    from types import SimpleNamespace
    import time
    import hermes_installer.remote.core_native_observer as observer

    client = CoreNativeObservationClient(socket_path=tmp_path / "unused.sock")
    attempt = ObservedProviderAttempt("x" * 32, "o" * 32, time.monotonic() + 20,
                                     capture_child_output=capture)
    receipts = []
    monkeypatch.setattr(client, "planning_context_for_attempt", lambda **_kwargs: None)
    monkeypatch.setattr(client, "master_review_context_for_attempt", lambda **_kwargs: None)
    monkeypatch.setattr(client, "register_attempt", lambda **_kwargs: attempt)
    monkeypatch.setattr(client, "register_response", lambda **kwargs: receipts.append(kwargs))
    monkeypatch.setattr(observer, "_codex_account_fingerprint", lambda _resolver: "f" * 64)
    ctx = _PluginContext()
    install_native_codex_process_observer(ctx, client=client)
    prompt = "child task"
    request = {"model": "gpt-6-luna", "tools": [],
        "input": [{"type": "message", "role": "user",
                   "content": [{"type": "input_text", "text": prompt}]}]}
    output = "exact provider answer"
    response = _native_response(output, output=[])

    result = ctx.middleware["llm_execution"][0](
        provider="openai-codex", api_mode="codex_responses",
        base_url="https://chatgpt.com/backend-api/codex", model="gpt-6-luna",
        request=request, session_id="child-session", turn_id="child-turn",
        api_request_id="child-request", next_call=lambda _value: response,
    )

    assert result is response
    assert len(receipts) == 1
    assert receipts[0]["response_text"] == expected_text
    import hashlib
    import json
    expected_receipt_tree = {
        "output": [], "output_text": output, "usage": None, "status": "completed",
        "id": "resp-native-fixture", "model": "gpt-6-luna",
        "incomplete_details": None, "error": None, "service_tier": None,
    }
    expected_receipt_bytes = json.dumps(expected_receipt_tree, ensure_ascii=False,
        sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    assert receipts[0]["response_sha256"] == hashlib.sha256(expected_receipt_bytes).hexdigest()
    if expected_text is not None:
        assert receipts[0]["response_text_sha256"] == __import__("hashlib").sha256(
            output.encode()).hexdigest()


def test_team_completion_excerpt_survives_child_lease_expiry_only_until_owner_bound():
    """Sequential Team work keeps observed output DATA, never a completed child lease."""
    import hermes_installer.remote.core_native_observer as observer

    registry = object.__new__(observer.RootCoreNativeObservationRegistry)
    for name in (
        "_obsidian_bindings", "_policies", "_owner_policy_handles", "_attempts",
        "_calls", "_claims", "_mission_pending", "_consumed_dispatches",
        "_child_sessions", "_planning_completions", "_expert_completions",
        "_team_completion_evidence",
        "_team_messages", "_team_bindings", "_team_completion_counts",
        "_master_selections", "_selected_source_deliveries", "_master_source_deliveries",
        "_obsidian_draft_read_deliveries", "_obsidian_draft_review_proposals",
        "_lifecycle_startup_probes", "_lifecycle_startup_attempts",
    ):
        setattr(registry, name, {})
    registry._obsidian_scoped_calls = set()
    registry._team_edge_issued = set()
    registry._child_sessions["completed-child"] = {
        "expiry": 130.0, "mode": "expert-read-research", "complete": True,
    }
    registry._expert_completions["root-completion"] = {
        "expiry": 130.0, "team_binding_id": "team-binding",
    }
    registry._team_completion_evidence["root-completion"] = {
        "completion_handle": "root-completion", "owner": object(),
        "team_binding_id": "team-binding", "profile_id": "researcher",
        "team_message_handle": None, "response_text": "exact root-observed excerpt",
        "response_text_sha256": "a" * 64, "peer": (1, 1, 1),
        "data_expires_monotonic": 600.0,
    }

    registry._prune(140.0)
    assert "completed-child" not in registry._child_sessions
    assert "root-completion" not in registry._expert_completions
    evidence = registry._team_completion_evidence["root-completion"]
    assert evidence["response_text"] == (
        "exact root-observed excerpt")
    assert not {"child", "admission_handle", "source", "final_attempt"}.intersection(evidence)

    registry._prune(600.0)
    assert "root-completion" not in registry._team_completion_evidence


def test_root_master_review_receipt_joins_exact_live_owner_result_response_and_peer(monkeypatch):
    """A review receipt is issued only from one complete zero-tool response and stays root-current."""
    import hashlib
    import threading
    import time
    from dataclasses import replace
    from types import SimpleNamespace

    import hermes_installer.remote.core_native_observer as observer

    now = time.monotonic()
    peer = (410, 996, 1000)
    raw = '{"decision":"approved","result_sha256":"' + "d" * 64 + (
        '","rationale":"The exact draft is complete."}')
    response_sha = hashlib.sha256(raw.encode()).hexdigest()
    context = SimpleNamespace(
        mission_id="M" * 24, revision=4, run_id="run_44", result_sha256="d" * 64,
        review_prompt_sha256="a" * 64, execution_core_generation="b" * 64,
        execution_core_source_generation="c" * 64, master_source_generation_sha256="6" * 64,
    )
    owner_state = {"current": True}

    def owner_current(_config, *, custody, now=None):
        return owner_state["current"] and custody.core_generation == "e" * 64

    owner = SimpleNamespace(
        owner_subject_sha256="f" * 64, owner_turn_handle="1" * 32,
        gateway_turn_id="G" * 24, core_generation="e" * 64,
        core_source_generation="2" * 64, expires_monotonic=now + 240,
        peer_gateway_pid=peer[0], peer_gateway_uid=peer[1], peer_gateway_gid=peer[2],
        master_review_context=context, is_current_sealed=owner_current,
    )
    attempt = {
        "owner": owner, "turn_id": owner.gateway_turn_id,
        "provider": observer._CODEX_PROVIDER, "api_mode": observer._CODEX_MODE,
        "base_url": observer._CODEX_ENDPOINT, "retry_count": 0,
        "parent_tool_names": (), "account": "3" * 64, "request_sha256": "4" * 64,
        "attempt_handle": "Q" * 43, "master_review_response_text": raw,
        "expiry": now + 30,
        "master_review_response_sha256": response_sha, "master_review_context": context,
        "response": ("5" * 64, {}, response_sha),
    }
    registry = object.__new__(RootCoreNativeObservationRegistry)
    registry._closed = False
    registry._custody = SimpleNamespace(core_generation="e" * 64,
                                        core_source_generation="2" * 64)
    registry._config = object()
    registry._lock = threading.RLock()
    registry._owners = {owner.owner_turn_handle: owner}
    registry._attempts = {attempt["attempt_handle"]: attempt}
    # _handle() performs the production expiry sweep before dispatch. Model the
    # empty root registries that are present on a real instance so this test
    # exercises that same closed-RPC path rather than failing on an incomplete
    # object.__new__ fixture.
    registry._obsidian_bindings = {}
    registry._obsidian_scoped_calls = set()
    registry._obsidian_draft_read_deliveries = {}
    registry._obsidian_draft_review_proposals = {}
    registry._policies = {}
    registry._owner_policy_handles = {}
    registry._calls = {}
    registry._claims = {}
    registry._mission_pending = {}
    registry._consumed_dispatches = {}
    registry._child_sessions = {}
    registry._planning_completions = {}
    registry._expert_completions = {}
    registry._team_completion_evidence = {}
    registry._team_messages = {}
    registry._team_bindings = {}
    registry._team_completion_counts = {}
    registry._team_edge_issued = set()
    registry._master_selections = {}
    registry._selected_source_deliveries = {}
    registry._master_source_deliveries = {}
    registry._master_review_completions = {}
    registry._lifecycle_startup_probes = {}
    registry._lifecycle_startup_attempts = {}
    registry._current_master_source = lambda: SimpleNamespace(generation_sha256="6" * 64)
    monkeypatch.setattr(
        "hermes_installer.remote.core_gateway_inspector._verify_master_review_context",
        lambda value, **_kwargs: value)

    registry._persist_master_review_response(attempt, raw, response_sha)
    result = registry.confirm_master_review_response(
        owner_subject_sha256=owner.owner_subject_sha256,
        gateway_turn_id=owner.gateway_turn_id, response_sha256=response_sha,
        gateway_peer=peer)

    client = CoreNativeObservationClient()

    def review_wire_roundtrip(operation, payload):
        assert operation == "verify-master-review-completion"
        assert "response_text" not in payload
        return registry._handle(peer, {
            "schema": 1, "op": operation, "nonce": "review-wire-roundtrip",
            **dict(payload),
        })

    client._rpc = review_wire_roundtrip

    receipt = observer.CoreVerifiedJarvisMasterReviewCompletion(
        owner_subject_sha256=result["owner_subject_sha256"],
        owner_turn_handle=result["owner_turn_handle"],
        gateway_turn_id=result["gateway_turn_id"],
        core_generation=result["core_generation"],
        core_source_generation=result["core_source_generation"],
        prompt_sha256=result["prompt_sha256"], response_sha256=result["response_sha256"],
        mission_id=result["mission_id"], revision=result["revision"], run_id=result["run_id"],
        result_sha256=result["result_sha256"],
        execution_core_generation=result["execution_core_generation"],
        execution_core_source_generation=result["execution_core_source_generation"],
        response_text=raw, completion_handle=result["completion_handle"],
        expires_monotonic=result["expires_monotonic"],
        owner_turn_expires_monotonic=result["owner_turn_expires_monotonic"],
        _client=client, _seal=observer._MASTER_REVIEW_COMPLETION_SEAL)
    assert receipt.is_current_sealed(registry._config, custody=registry._custody)
    attempt["master_review_response_text"] = raw + " changed"
    assert not receipt.is_current_sealed(registry._config, custody=registry._custody)
    attempt["master_review_response_text"] = raw
    assert receipt.is_current_sealed(registry._config, custody=registry._custody)
    assert not replace(receipt, mission_id="X" * 24).is_current_sealed(
        registry._config, custody=registry._custody)
    assert not replace(receipt, result_sha256="9" * 64).is_current_sealed(
        registry._config, custody=registry._custody)
    assert not replace(receipt, owner_subject_sha256="8" * 64).is_current_sealed(
        registry._config, custody=registry._custody)
    assert not replace(receipt, response_sha256="7" * 64).is_current_sealed(
        registry._config, custody=registry._custody)
    assert not replace(receipt, execution_core_source_generation="6" * 64).is_current_sealed(
        registry._config, custody=registry._custody)
    changed_client = CoreNativeObservationClient()

    def mismatched_peer_roundtrip(operation, payload):
        return registry._handle((411, 996, 1000), {
            "schema": 1, "op": operation, "nonce": "wrong-review-peer",
            **dict(payload),
        })

    changed_client._rpc = mismatched_peer_roundtrip
    receipt = replace(receipt, _client=changed_client)
    assert not receipt.is_current_sealed(registry._config, custody=registry._custody)
    receipt = replace(receipt, _client=client)
    owner_state["current"] = False
    assert not receipt.is_current_sealed(registry._config, custody=registry._custody)
    owner_state["current"] = True
    registry._master_review_completions.pop(receipt.completion_handle)
    assert not receipt.is_current_sealed(registry._config, custody=registry._custody)


def test_root_master_review_completion_denies_provider_result_not_yet_completed(monkeypatch):
    """No completion receipt is minted while the actual provider attempt is pending."""
    import threading
    import time
    from types import SimpleNamespace

    now = time.monotonic()
    peer = (410, 996, 1000)
    context = SimpleNamespace(mission_id="M" * 24, revision=1, run_id="run_1",
        result_sha256="d" * 64, review_prompt_sha256="a" * 64,
        execution_core_generation="b" * 64, execution_core_source_generation="c" * 64)
    owner = SimpleNamespace(owner_subject_sha256="f" * 64, owner_turn_handle="1" * 32,
        gateway_turn_id="G" * 24, core_generation="e" * 64,
        core_source_generation="2" * 64, expires_monotonic=now + 240,
        peer_gateway_pid=peer[0], peer_gateway_uid=peer[1], peer_gateway_gid=peer[2],
        master_review_context=context,
        is_current_sealed=lambda _config, *, custody, now=None: True)
    registry = object.__new__(RootCoreNativeObservationRegistry)
    registry._closed = False
    registry._custody = SimpleNamespace(core_generation="e" * 64,
                                        core_source_generation="2" * 64)
    registry._config = object()
    registry._lock = threading.RLock()
    registry._owners = {owner.owner_turn_handle: owner}
    registry._attempts = {"Q" * 43: {"owner": owner, "turn_id": owner.gateway_turn_id,
                                     "response": None}}
    registry._master_review_completions = {}
    registry._lifecycle_startup_probes = {}
    registry._lifecycle_startup_attempts = {}
    monkeypatch.setattr(
        "hermes_installer.remote.core_gateway_inspector._verify_master_review_context",
        lambda value, **_kwargs: value)
    with pytest.raises(CoreNativeObservationUnavailable, match="response is missing or ambiguous"):
        registry.confirm_master_review_response(
            owner_subject_sha256=owner.owner_subject_sha256,
            gateway_turn_id=owner.gateway_turn_id, response_sha256="5" * 64,
            gateway_peer=peer)
    assert registry._master_review_completions == {}


def test_native_client_rechecks_review_receipt_through_closed_root_rpc(tmp_path, monkeypatch):
    """The live-receipt check traverses the production client framing and response parser."""
    import hashlib
    import json
    import stat
    import struct
    import time
    from dataclasses import replace
    from types import SimpleNamespace

    import hermes_installer.remote.core_native_observer as observer

    receipt = observer.CoreVerifiedJarvisMasterReviewCompletion(
        owner_subject_sha256="a" * 64, owner_turn_handle="b" * 32,
        gateway_turn_id="c" * 24, core_generation="d" * 64,
        core_source_generation="e" * 64, prompt_sha256="f" * 64,
        response_sha256=hashlib.sha256(b"review response").hexdigest(),
        mission_id="M" * 24, revision=2,
        run_id="run_2", result_sha256="2" * 64,
        execution_core_generation="3" * 64,
        execution_core_source_generation="4" * 64, response_text="review response",
        completion_handle="Q" * 43, expires_monotonic=time.monotonic() + 10,
        owner_turn_expires_monotonic=time.monotonic() + 200,
        _client=object(), _seal=observer._MASTER_REVIEW_COMPLETION_SEAL)
    exchange = {"requests": [], "response_ok": True}

    class Transport:
        def __init__(self, *_args, **_kwargs):
            self.incoming = bytearray()

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def settimeout(self, _timeout):
            pass

        def connect(self, _path):
            pass

        def getsockopt(self, *_args):
            return struct.pack("3i", 999, 0, 1000)

        def sendall(self, payload):
            size = struct.unpack("!I", payload[:4])[0]
            request = json.loads(payload[4:4 + size])
            exchange["requests"].append(request)
            response = {"schema": 1, "nonce": request["nonce"], "ok": exchange["response_ok"]}
            raw = json.dumps(response, separators=(",", ":")).encode()
            self.incoming.extend(struct.pack("!I", len(raw)) + raw)

        def recv(self, size):
            result = bytes(self.incoming[:size])
            del self.incoming[:size]
            return result

        def close(self):
            pass

    socket_path = Path("/run/hermes-jarvis-native-observer/native-observer.sock")
    real_lstat = Path.lstat

    def lstat(path):
        if path == socket_path.parent:
            return SimpleNamespace(st_mode=stat.S_IFDIR | 0o750, st_uid=0, st_gid=1000)
        if path == socket_path:
            return SimpleNamespace(st_mode=stat.S_IFSOCK | 0o660, st_uid=0, st_gid=1000)
        return real_lstat(path)

    monkeypatch.setattr(Path, "lstat", lstat)
    monkeypatch.setattr(observer.socket, "socket", Transport)
    monkeypatch.setattr(observer.os, "getgroups", lambda: [1000])
    client = CoreNativeObservationClient(socket_path=socket_path)
    assert client.verify_master_review_completion(receipt) is True
    request = exchange["requests"][0]
    assert request["op"] == "verify-master-review-completion"
    assert request["completion_handle"] == receipt.completion_handle
    assert request["result_sha256"] == receipt.result_sha256
    client_receipt = replace(receipt, _client=client)
    assert client_receipt.is_current_sealed(config=object(), custody=object()) is True
    exchange["response_ok"] = False
    assert client.verify_master_review_completion(receipt) is False
    assert client_receipt.is_current_sealed(config=object(), custody=object()) is False


def test_master_plan_readback_uses_canonical_root_durable_completion_record(monkeypatch):
    """Only canonical root-published zero-tool records survive a registry restart."""
    import threading
    import hashlib
    import json

    import hermes_installer.remote.core_native_observer as observer

    registry = object.__new__(observer.RootCoreNativeObservationRegistry)
    registry._lock = threading.RLock()
    registry._master_plan_records = {}
    key = ("a" * 64, "mission_12345678901234567890", 1)
    monkeypatch.setattr(observer, "_read_root_master_plan_bytes", lambda *_args: None)
    assert registry.read_master_plan_record(
        owner_subject_sha256=key[0], mission_id=key[1], revision=key[2]) is None

    plan = {"execution_mode": "oneshot", "selected_source_ids": [], "plan": {}}
    plan_sha256 = hashlib.sha256(json.dumps(plan, ensure_ascii=False, sort_keys=True,
        separators=(",", ":"), allow_nan=False).encode("utf-8")).hexdigest()

    record = observer.RootObservedMasterPlanRecord(
        owner_subject_sha256=key[0], mission_id=key[1], revision=key[2],
        gateway_turn_id="turn_12345678901234567890", conversation_id="conversation_1234567890",
        session_id="session_12345678901234567890", native_turn_id="native_turn_1234567890",
        owner_turn_handle="o" * 32,
        core_generation="b" * 64, core_source_generation="c" * 64,
        goal_sha256="d" * 64, catalog_sha256="e" * 64, planner_prompt_sha256="f" * 64,
        master_source_generation_sha256="1" * 64, master_source_manifest_sha256="2" * 64,
        master_prompt_sha256="3" * 64, attempt_handle="h" * 32,
        api_request_id="request_1234567890123456", provider="openai-codex",
        api_mode="codex_responses", base_url="https://chatgpt.com/backend-api/codex",
        model="gpt-6-luna", account_fingerprint="6" * 64, request_sha256="7" * 64,
        retry_count=0, completed=True, request_tool_count=0, tool_call_count=0,
        plan_json="{}", plan_sha256=plan_sha256,
        response_sha256="5" * 64, selected_source_ids=(), execution_mode="oneshot",
        _seal=observer._MASTER_PLAN_RECORD_SEAL,
    )
    assert record.is_root_observed() is True
    durable = observer._master_plan_record_bytes(record)
    # A fresh registry with no in-memory completion cache recovers only the exact
    # canonical root record. The BFF row is not consulted by this method.
    monkeypatch.setattr(observer, "_read_root_master_plan_bytes", lambda *_args: durable)
    assert registry.read_master_plan_record(
        owner_subject_sha256=key[0], mission_id=key[1], revision=key[2]) == record
    changed = json.loads(durable)
    changed["tool_call_count"] = 1
    changed_bytes = json.dumps(changed, ensure_ascii=False, sort_keys=True,
        separators=(",", ":"), allow_nan=False).encode("utf-8")
    assert observer._root_master_plan_record_from_bytes(changed_bytes,
        owner_subject_sha256=key[0], mission_id=key[1], revision=key[2]) is None
    monkeypatch.setattr(observer, "_read_root_master_plan_bytes", lambda *_args: durable + b" ")
    assert registry.read_master_plan_record(
        owner_subject_sha256=key[0], mission_id=key[1], revision=key[2]) is None


def test_obsidian_origin_journal_binds_owner_draft_bytes_and_rejects_replay_or_tamper():
    import hermes_installer.remote.core_native_observer as observer

    record = {
        "draft_id": "D" * 43, "owner_subject_sha256": "a" * 64,
        "registration_sha256": "b" * 64, "origin_execution_id": "child_session_123456",
        "origin_source_id": "expert_alpha", "origin_source_revision": "source-r17",
        "source_generation_sha256": "c" * 64, "mission_sha256": "d" * 64,
        "content_sha256": "e" * 64, "base_sha256": None, "state": "private-draft",
    }
    record["origin_record_sha256"] = observer._obsidian_origin_record_digest(record)
    raw = observer._canonical({"schema": 1, "records": [record]})

    recovered = observer._obsidian_origin_snapshot_from_bytes(raw)

    assert recovered[("a" * 64, "D" * 43)] == record
    changed = dict(record, content_sha256="f" * 64)
    assert observer._obsidian_origin_snapshot_from_bytes(
        observer._canonical({"schema": 1, "records": [changed]})) is None
    assert observer._obsidian_origin_snapshot_from_bytes(
        observer._canonical({"schema": 1, "records": [record, record]})) is None


def test_exact_private_draft_markdown_reader_is_master_only_not_in_expert_child_closure():
    import hermes_installer.remote.core_native_observer as observer
    from hermes_installer.remote.obsidian_native_tools import _EXPERT_TOOLS, _TOOL_NAMES

    assert observer._OBSIDIAN_READ_TOOL_NAMES == _EXPERT_TOOLS
    assert "obsidian_read_private_draft" not in observer._OBSIDIAN_READ_TOOL_NAMES
    assert "obsidian_read_private_draft" in observer._OBSIDIAN_MASTER_READ_TOOL_NAMES
    assert set(_TOOL_NAMES) == set(observer._OBSIDIAN_TOOL_NAMES)
    assert "obsidian_promote_reviewed_draft" not in observer._OBSIDIAN_READ_TOOL_NAMES


def test_obsidian_origin_sidecar_atomic_readback_and_restart_load(tmp_path, monkeypatch):
    import os
    import hermes_installer.remote.core_native_observer as observer

    if os.geteuid() != 0:
        pytest.skip("root-owned Obsidian journal custody is qualified on the Pi")
    directory = tmp_path / "core-runtime"
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    monkeypatch.setattr(observer, "_open_root_master_plan_store",
                        lambda: os.open(directory, flags))
    record = {
        "draft_id": "R" * 43, "owner_subject_sha256": "a" * 64,
        "registration_sha256": "b" * 64, "origin_execution_id": "JarvisTurn_123456",
        "origin_source_id": "hermes", "origin_source_revision": "master-r8",
        "source_generation_sha256": "c" * 64, "mission_sha256": None,
        "content_sha256": "d" * 64, "base_sha256": None, "state": "private-draft",
    }
    record["origin_record_sha256"] = observer._obsidian_origin_record_digest(record)
    raw = observer._canonical({"schema": 1, "records": [record]})

    observer._publish_root_obsidian_origin_bytes(raw)

    assert observer._read_root_obsidian_origin_bytes() == raw
    assert observer._load_root_obsidian_origin_snapshot()[("a" * 64, "R" * 43)] == record
    assert set(path.name for path in directory.iterdir()) == {observer._OBSIDIAN_ORIGIN_STORE_NAME}
    assert b"private markdown" not in raw


def test_obsidian_completion_history_and_tombstone_join_without_retaining_markdown():
    import hashlib
    import hermes_installer.remote.core_native_observer as observer

    origin = {
        "draft_id": "D" * 43, "owner_subject_sha256": "a" * 64,
        "registration_sha256": "b" * 64, "origin_execution_id": "child_session_123456",
        "origin_source_id": "expert_alpha", "origin_source_revision": "source-r17",
        "source_generation_sha256": "c" * 64, "mission_sha256": "d" * 64,
        "content_sha256": "e" * 64, "base_sha256": None, "state": "private-draft",
    }
    origin["origin_record_sha256"] = observer._obsidian_origin_record_digest(origin)
    history_body = {
        "record_id": "H" * 43, "origin": origin,
        "proposal": {"proposal_sha256": "f" * 64},
        "approval": {"pending_id": "P" * 43, "review_sha256": "1" * 64},
        "result": {"destination": "Notes/Expert.md", "note_id": "N" * 43,
                   "title": "Expert", "content_sha256": "e" * 64, "state": "promoted"},
        "completed_at": 12.5,
    }
    history_record = {**history_body,
        "record_sha256": hashlib.sha256(observer._canonical(history_body)).hexdigest()}
    history = observer._canonical({"schema": 1, "records": [history_record]})

    assert observer._obsidian_history_from_bytes(history) == [history_record]
    tampered = dict(history_record, result={**history_record["result"], "markdown": "private"})
    tampered_body = {key: value for key, value in tampered.items() if key != "record_sha256"}
    tampered["record_sha256"] = hashlib.sha256(observer._canonical(tampered_body)).hexdigest()
    assert observer._obsidian_history_from_bytes(
        observer._canonical({"schema": 1, "records": [tampered]})) is None

    tombstone = {
        "owner_subject_sha256": "a" * 64, "draft_id": "D" * 43,
        "origin_record_sha256": origin["origin_record_sha256"],
        "history_record_id": history_record["record_id"],
        "history_record_sha256": history_record["record_sha256"],
        "destination": "Notes/Expert.md", "note_id": "N" * 43,
        "content_sha256": "e" * 64, "completed_at": 12.5,
    }
    tombstone["completed_record_sha256"] = hashlib.sha256(
        observer._canonical(tombstone)).hexdigest()
    assert observer._reserved_origin_tombstone(history_record) == tombstone
    state = observer._canonical({"schema": 2, "records": [], "completed": [tombstone]})
    assert observer._obsidian_origin_state_from_bytes(state) == (
        {}, {("a" * 64, "D" * 43): tombstone})
    assert observer._obsidian_origin_state_from_bytes(observer._canonical({
        "schema": 2, "records": [origin], "completed": [tombstone]})) is None


def test_typed_obsidian_origin_is_short_lived_and_exact_owner_registration_digest():
    import time

    from hermes_installer.remote.obsidian_native_scope import (
        _decode_draft_origin, ObsidianRootScopeUnavailable,
    )

    issued = time.monotonic()
    row = {"schema": 1, "nonce": "fresh", "ok": True,
        "draft_id": "D" * 43, "owner_subject_sha256": "a" * 64,
        "registration_sha256": "b" * 64, "origin_execution_id": "expert_session_123",
        "origin_source_id": "expert_alpha", "origin_source_revision": "source-r17",
        "source_generation_sha256": "c" * 64, "mission_sha256": "d" * 64,
        "content_sha256": "e" * 64, "base_sha256": None,
        "origin_record_sha256": "f" * 64, "state": "private-draft",
        "issued_monotonic": issued, "expires_monotonic": issued + 4,
    }
    origin = _decode_draft_origin(row)
    assert origin.matches(draft_id="D" * 43, owner_subject_sha256="a" * 64,
                          registration_sha256="b" * 64, content_sha256="e" * 64,
                          base_sha256=None)
    assert not origin.matches(draft_id="D" * 43, owner_subject_sha256="9" * 64,
                              registration_sha256="b" * 64, content_sha256="e" * 64,
                              base_sha256=None)
    with pytest.raises(ObsidianRootScopeUnavailable, match="stale"):
        _decode_draft_origin({**row, "expires_monotonic": issued})


def test_root_observed_expert_draft_origin_resolves_only_for_current_master_promotion(monkeypatch):
    import hashlib
    import os
    import threading
    import time
    from types import SimpleNamespace

    import hermes_installer.remote.core_native_observer as observer

    # This fixture exercises the fixed UID-1000 native client while the suite
    # may itself be launched by root on the Pi.
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    monkeypatch.setattr(os, "getegid", lambda: 1000)

    owner_sha, registration_sha = "a" * 64, "b" * 64
    draft_id = "D" * 43
    markdown = "# Expert draft\nObserved private bytes.\n"
    content_sha = hashlib.sha256(markdown.encode()).hexdigest()
    generation = "c" * 64
    source = SimpleNamespace(source_revision="r17", generation_sha256=generation)
    source.is_current_sealed = lambda *_args, **_kwargs: True
    mission = MissionBinding(
        schema=2, mission_id="mission_" + "1" * 24, revision=1,
        plan_sha256="d" * 64, task_sha256="e" * 64,
        source_profile_id="hermes", execution_mode="oneshot",
        autonomy_mode="approval_required", selected_source_ids=("expert_alpha",),
        scope_sha256="2" * 64,
    )
    owner = SimpleNamespace(
        owner_subject_sha256=owner_sha, owner_turn_handle="T" * 43,
        gateway_turn_id="gateway-turn",
        core_generation="f" * 64, core_source_generation="1" * 64,
        expires_monotonic=time.monotonic() + 30, mission_binding=mission,
    )
    child = {"session_id": "expert_session_123", "profile_id": "expert_alpha",
             "source_generation_sha256": generation, "source": source}
    current_master_source = SimpleNamespace(
        profile_id="hermes", source_revision="master-current-r18", generation_sha256="9" * 64,
    )
    current_master_source.is_current_sealed = lambda *_args, **_kwargs: True
    draft = SimpleNamespace(
        execution_id=child["session_id"], source_instance_id=child["profile_id"],
        title="Expert draft", base_note_id=None, base_sha256=None, citations=(),
        content_sha256=content_sha,
    )
    review = SimpleNamespace(draft=draft, markdown=markdown)
    active = {}

    registry = object.__new__(RootCoreNativeObservationRegistry)
    registry._lock = threading.RLock()
    registry._closed = False
    registry._custody = SimpleNamespace(
        core_pid=os.getpid(), core_start_ticks="5678", core_generation=owner.core_generation,
        core_source_generation=owner.core_source_generation,
    )
    registry._config = SimpleNamespace(core_uid=1000, core_gid=1000)
    registry._obsidian_origin_store_ok = True
    registry._obsidian_draft_origins = {}
    registry._obsidian_completed_drafts = {}
    registry._obsidian_resolved_origin_calls = set()
    registry._obsidian_scoped_calls = set()
    registry._obsidian_draft_read_deliveries = {}
    registry._obsidian_draft_review_proposals = {}
    registry._ensure_open = lambda: None
    registry._prune = lambda _now: None
    registry._classify_current_call = lambda _handle, _peer, **_kwargs: active["classification"]
    peer = (os.getpid(), os.geteuid(), os.getegid())
    startup_binding = {"binding_id": "B" * 43, "expiry": time.monotonic() + 20,
        "peer": peer, "owner_subject_sha256": owner_sha,
        "registration_sha256": registration_sha, "core_generation": owner.core_generation,
        "core_source_generation": owner.core_source_generation,
        "core_pid": os.getpid(), "core_start_ticks": "5678"}
    startup_bindings = {startup_binding["binding_id"]: startup_binding}

    def validate_binding(*, binding_id, **_kwargs):
        row = startup_bindings[binding_id]
        if row["expiry"] <= time.monotonic():
            raise ValueError("startup binding expired")
        return (Path("/home/admin/.hermes/jarvis-second-brain"), owner_sha,
                registration_sha, row)

    registry._validate_obsidian_origin_binding = validate_binding
    registry._read_obsidian_owner_draft = lambda *_args, **_kwargs: review
    registry._persist_obsidian_origin = lambda records: active.update(persisted=records)
    create_arguments = observer._canonical({"title": draft.title, "markdown": markdown})
    create_call = {"handle": "C" * 43, "tool_name": "obsidian_create_private_draft",
                   "arguments": create_arguments, "expiry": time.monotonic() + 20}
    active["classification"] = (create_call, owner, child, "expert_read")

    created = registry._handle(peer, {
        "schema": 1, "op": "record-obsidian-draft-origin", "nonce": "record",
        "observed_call_handle": create_call["handle"],
        "startup_binding_id": "B" * 43, "draft_id": draft_id,
    })

    assert created["ok"] is True
    assert active["persisted"][(owner_sha, draft_id)]["origin_execution_id"] == child["session_id"]

    read_args = {"draft_id": draft_id, "expected_draft_sha256": content_sha}
    read_call = {"handle": "R" * 43, "tool_name": "obsidian_read_private_draft",
                 "tool_call_id": "read-draft-call",
                 "arguments": observer._canonical(read_args),
                 "arguments_sha256": hashlib.sha256(observer._canonical(read_args)).hexdigest(),
                 "expiry": time.monotonic() + 20}
    registry._obsidian_scoped_calls.add(read_call["handle"])
    active["classification"] = (read_call, owner, current_master_source, "master_read")
    read_result = registry._handle(peer, {
        "schema": 1, "op": "read-obsidian-private-draft", "nonce": "read",
        "observed_call_handle": read_call["handle"],
        "startup_binding_id": "B" * 43, "draft_id": draft_id,
        "expected_content_sha256": content_sha,
    })
    assert read_result["review_complete"] is True
    assert read_result["markdown"] == markdown
    assert read_result["content_sha256"] == content_sha
    assert read_result["origin_execution_id"] == child["session_id"]
    assert read_result["origin_source_id"] == child["profile_id"]
    assert read_result["delivery"]["complete"] is True
    assert read_result["delivery"]["returned_content_sha256"] == content_sha

    promote_arguments = {"draft_id": draft_id, "expected_draft_sha256": content_sha,
        "destination": "Notes/Expert.md", "expected_base_sha256": None,
        "review_disposition": "approve"}
    promote_call = {"handle": "P" * 43, "tool_call_id": "promote-draft-call",
        "tool_name": "obsidian_promote_reviewed_draft",
        "arguments": observer._canonical(promote_arguments),
        "arguments_sha256": hashlib.sha256(observer._canonical(promote_arguments)).hexdigest(),
        "expiry": time.monotonic() + 20}
    active["classification"] = (promote_call, owner, current_master_source, "master_effect")
    with pytest.raises(ValueError, match="complete draft bytes were not delivered"):
        registry._propose_obsidian_draft_review(
            call=promote_call, owner=owner, source=current_master_source, peer=peer,
            startup_binding_id="B" * 43)

    from unittest.mock import patch
    from hermes_installer.native_invocations import NativeToolDispatch, canonical_tool_arguments
    from hermes_installer.remote.obsidian_native_scope import (
        RootObsidianCallScope, RootSelectedObsidianVaultBinding,
        _BINDING_SEAL, _SCOPE_SEAL, _decode_draft_review,
    )
    from hermes_installer.remote.obsidian_native_tools import (
        ObsidianNativeTools, _admit_current_obsidian_call,
    )
    from hermes_installer.remote.obsidian_second_brain import ObsidianVaultStore

    issued = time.monotonic()
    binding = RootSelectedObsidianVaultBinding(
        binding_id="B" * 43, registration_sha256=registration_sha,
        owner_subject_sha256=owner_sha, core_generation=owner.core_generation,
        core_source_generation=owner.core_source_generation, core_pid=os.getpid(),
        core_start_ticks="5678", selected_owner_uid=os.geteuid(),
        vault_root="/home/admin/.hermes/jarvis-second-brain",
        issued_monotonic=issued, expires_monotonic=issued + 20,
        _seal=_BINDING_SEAL)
    observed_read = ObservedNativeToolCall(
        handle=read_call["handle"], attempt_handle="A" * 43,
        owner_turn_handle=owner.owner_turn_handle, tool_call_id=read_call["tool_call_id"],
        tool_name=read_call["tool_name"],
        arguments_sha256=hashlib.sha256(read_call["arguments"]).hexdigest(),
        expires_monotonic=read_call["expiry"])
    scope = RootObsidianCallScope(
        observed_call_handle=observed_read.handle, owner_turn_handle=owner.owner_turn_handle,
        tool_call_id=observed_read.tool_call_id, tool_name=observed_read.tool_name,
        arguments_sha256=observed_read.arguments_sha256, owner_subject_sha256=owner_sha,
        registration_sha256=registration_sha, startup_binding_id=binding.binding_id,
        core_generation=owner.core_generation, core_source_generation=owner.core_source_generation,
        source_generation_sha256=current_master_source.generation_sha256,
        mode="master_read", execution_id=owner.owner_turn_handle,
        source_instance_id="hermes", mission_binding=None, selected_note_ids=None,
        issued_monotonic=issued, expires_monotonic=issued + 4, _seal=_SCOPE_SEAL)

    native_client = CoreNativeObservationClient()
    native_client._rpc = lambda operation, payload: registry._handle(peer, {
        "schema": 1, "op": operation, "nonce": "native-client",
        **dict(payload),
    })

    native_dispatch = NativeToolDispatch(
        object(), observed_read.tool_call_id, observed_read.tool_name,
        canonical_tool_arguments(read_args))
    native_store = object.__new__(ObsidianVaultStore)
    native_store._config = SimpleNamespace(owner_scope_sha256=owner_sha)
    native_handler = ObsidianNativeTools(native_store).handler("obsidian_read_private_draft")
    # obsidian_native_tools imports this context accessor directly, so patch
    # the consumer binding used by the native handler itself.
    active["classification"] = (read_call, owner, current_master_source, "master_read")
    with patch("hermes_installer.remote.obsidian_native_tools.current_native_tool_dispatch",
               return_value=native_dispatch):
        with _admit_current_obsidian_call(
                observed_call=observed_read, scope=scope, binding=binding,
                observer_client=native_client):
            native_result = native_handler(read_args)

    active["classification"] = (read_call, owner, current_master_source, "master_read")
    altered_result = {**native_result, "markdown": "altered"}
    with pytest.raises(ValueError, match="native result differs"):
        native_client.confirm_obsidian_draft_read_delivery(
            observed_call=observed_read, binding=binding, tool_result=altered_result)
    native_client.confirm_obsidian_draft_read_delivery(
        observed_call=observed_read, binding=binding, tool_result=native_result)

    # The old startup binding has expired, while its receipt remains eligible
    # as provenance data under a new binding with the same process/custody facts.
    startup_binding["expiry"] = time.monotonic() - 1
    fresh_startup = {**startup_binding, "binding_id": "N" * 43,
                     "expiry": time.monotonic() + 20}
    startup_bindings[fresh_startup["binding_id"]] = fresh_startup
    active["classification"] = (promote_call, owner, current_master_source, "master_effect")
    from hermes_installer.remote.jarvis_final_effects import review_digest
    registry._final_effect_ledger = lambda: SimpleNamespace(issue_pending=lambda **values:
        SimpleNamespace(pending_id="P" * 43,
            review_sha256=values["review_sha256"], expires_monotonic=time.monotonic() + 15))
    promotion_review_sha = review_digest(
        promote_call["tool_name"], hashlib.sha256(promote_call["arguments"]).hexdigest())
    request_result = registry._handle(peer, {
        "schema": 1, "op": "request-final-effect", "nonce": "proposal-request",
        "observed_call_handle": promote_call["handle"],
        "review_sha256": promotion_review_sha, "startup_binding_id": "N" * 43,
    })
    assert request_result["ok"] is True
    proposal = registry._obsidian_draft_review_proposals[promote_call["handle"]]
    assert proposal["read_delivery_receipt_id"] == native_result["read_delivery"]["receipt_id"]
    assert proposal["read_delivery_output_sha256"] == hashlib.sha256(
        observer._canonical(native_result)).hexdigest()
    assert proposal["origin_record_sha256"] == active["persisted"][(owner_sha, draft_id)]["origin_record_sha256"]
    assert proposal["disposition"] == "approve"

    changed_facts = {**fresh_startup, "core_start_ticks": "changed-start"}
    startup_bindings[changed_facts["binding_id"]] = changed_facts
    changed_fact_call = dict(promote_call, handle="W" * 43)
    active["classification"] = (
        changed_fact_call, owner, current_master_source, "master_effect")
    with pytest.raises(ValueError, match="complete draft bytes were not delivered"):
        registry._propose_obsidian_draft_review(
            call=changed_fact_call, owner=owner, source=current_master_source, peer=peer,
            startup_binding_id="N" * 43)
    startup_bindings["N" * 43] = fresh_startup

    confirmed_receipt_id = native_result["read_delivery"]["receipt_id"]
    registry._obsidian_draft_read_deliveries[confirmed_receipt_id]["complete"] = False
    registry._obsidian_draft_read_deliveries[confirmed_receipt_id]["covered_byte_length"] = 0
    changed_promote = dict(promote_call, handle="Q" * 43)
    active["classification"] = (changed_promote, owner, current_master_source, "master_effect")
    with pytest.raises(ValueError, match="complete draft bytes were not delivered"):
        registry._propose_obsidian_draft_review(
            call=changed_promote, owner=owner, source=current_master_source, peer=peer,
            startup_binding_id="N" * 43)

    changed_args = {**read_args, "expected_draft_sha256": "9" * 64}
    changed_call = {**read_call, "handle": "Z" * 43,
                    "arguments": observer._canonical(changed_args)}
    changed_call["arguments_sha256"] = hashlib.sha256(changed_call["arguments"]).hexdigest()
    registry._obsidian_scoped_calls.add(changed_call["handle"])
    active["classification"] = (changed_call, owner, current_master_source, "master_read")
    with pytest.raises(ValueError, match="retained pending private origin"):
        registry._handle(peer, {
            "schema": 1, "op": "read-obsidian-private-draft", "nonce": "digest-denied",
            "observed_call_handle": changed_call["handle"],
            "startup_binding_id": "N" * 43, "draft_id": draft_id,
            "expected_content_sha256": "9" * 64,
        })

    expert_read = dict(read_call, handle="X" * 43)
    active["classification"] = (expert_read, owner, child, "expert_read")
    with pytest.raises(ValueError, match="only the current Jarvis master read"):
        registry._handle(peer, {
            "schema": 1, "op": "read-obsidian-private-draft", "nonce": "expert-read-denied",
            "observed_call_handle": expert_read["handle"],
            "startup_binding_id": "N" * 43, "draft_id": draft_id,
            "expected_content_sha256": content_sha,
        })


    promote_args = {"draft_id": draft_id, "expected_draft_sha256": content_sha,
                    "destination": "Notes/Expert.md", "expected_base_sha256": None,
                    "review_disposition": "approve"}
    promote_call = {"handle": "P" * 43, "tool_name": "obsidian_promote_reviewed_draft",
                    "arguments": observer._canonical(promote_args),
                    "expiry": time.monotonic() + 20}
    active["classification"] = (promote_call, owner, current_master_source, "master_effect")
    resolved = registry._handle(peer, {
        "schema": 1, "op": "resolve-obsidian-draft-origin", "nonce": "resolve",
        "observed_call_handle": promote_call["handle"],
        "startup_binding_id": "N" * 43, "draft_id": draft_id,
        "expected_content_sha256": content_sha,
    })
    assert resolved["ok"] is True
    assert resolved["origin_execution_id"] == child["session_id"]
    assert resolved["origin_source_id"] == child["profile_id"]
    assert resolved["source_generation_sha256"] == generation
    assert resolved["source_generation_sha256"] != current_master_source.generation_sha256

    with pytest.raises(ValueError, match="replayed"):
        registry._handle(peer, {
            "schema": 1, "op": "resolve-obsidian-draft-origin", "nonce": "replay",
            "observed_call_handle": promote_call["handle"],
            "startup_binding_id": "N" * 43, "draft_id": draft_id,
            "expected_content_sha256": content_sha,
        })

    expert_promote = dict(promote_call, handle="X" * 43)
    active["classification"] = (expert_promote, owner, child, "expert_read")
    with pytest.raises(ValueError, match="only the current Jarvis owner promotion"):
        registry._handle(peer, {
            "schema": 1, "op": "resolve-obsidian-draft-origin", "nonce": "expert-denied",
            "observed_call_handle": expert_promote["handle"],
            "startup_binding_id": "N" * 43, "draft_id": draft_id,
            "expected_content_sha256": content_sha,
        })


def test_obsidian_read_delivery_client_uses_allowlisted_protocol_transport(monkeypatch):
    """Exercise the real public client method, framing, allowlist, and response decoder."""
    import json
    import os
    import stat
    import struct
    import time
    from types import SimpleNamespace

    import hermes_installer.remote.core_native_observer as observer
    # Model the enrolled UID-1000 native client independently of the UID that
    # owns the Pi test runner; the fake SO_PEERCRED still models root as server.
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    monkeypatch.setattr(os, "getegid", lambda: 1000)
    from hermes_installer.remote.obsidian_native_scope import (
        RootSelectedObsidianVaultBinding, _BINDING_SEAL,
    )

    observed = ObservedNativeToolCall(
        handle="H" * 43, attempt_handle="A" * 43, owner_turn_handle="T" * 43,
        tool_call_id="draft-read", tool_name="obsidian_read_private_draft",
        arguments_sha256="a" * 64, expires_monotonic=time.monotonic() + 20)
    now = time.monotonic()
    binding = RootSelectedObsidianVaultBinding(
        binding_id="B" * 43, registration_sha256="b" * 64,
        owner_subject_sha256="c" * 64, core_generation="d" * 64,
        core_source_generation="e" * 64, core_pid=os.getpid(),
        core_start_ticks="987", selected_owner_uid=os.geteuid(),
        vault_root="/home/admin/.hermes/jarvis-second-brain",
        issued_monotonic=now, expires_monotonic=now + 20, _seal=_BINDING_SEAL)
    returned = {"receipt_id": "R" * 43, "receipt_sha256": "f" * 64,
                "complete": True, "covered_byte_length": 3}
    exchange = {}

    class Transport:
        def __init__(self, *_args):
            self.incoming = bytearray()

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def settimeout(self, _timeout):
            pass

        def connect(self, _path):
            pass

        def getsockopt(self, *_args):
            return struct.pack("3i", 999, 0, 1000)

        def sendall(self, payload):
            size = struct.unpack("!I", payload[:4])[0]
            request = json.loads(payload[4:4 + size])
            exchange.setdefault("requests", []).append(request)
            if request["op"] == "confirm-obsidian-draft-read-delivery":
                response = {"schema": 1, "nonce": request["nonce"], "ok": True,
                            "confirmed": True, "receipt_sha256": returned["receipt_sha256"]}
            else:
                response = {"schema": 1, "nonce": request["nonce"], "ok": True,
                    "pending_id": "P" * 43, "review_sha256": request["review_sha256"],
                    "expires_monotonic": time.monotonic() + 20}
            raw = json.dumps(response, separators=(",", ":")).encode()
            self.incoming.extend(struct.pack("!I", len(raw)) + raw)

        def recv(self, size):
            result = bytes(self.incoming[:size])
            del self.incoming[:size]
            return result

    socket_path = Path("/run/hermes-jarvis-native-observer/native-observer.sock")
    real_lstat = Path.lstat

    def lstat(path):
        if path == socket_path.parent:
            return SimpleNamespace(st_mode=stat.S_IFDIR | 0o750, st_uid=0, st_gid=1000)
        if path == socket_path:
            return SimpleNamespace(st_mode=stat.S_IFSOCK | 0o660, st_uid=0, st_gid=1000)
        return real_lstat(path)

    monkeypatch.setattr(Path, "lstat", lstat)
    monkeypatch.setattr(observer.socket, "socket", Transport)
    monkeypatch.setattr(observer.os, "getgroups", lambda: [1000])
    client = CoreNativeObservationClient(socket_path=socket_path)
    result = {"draft_id": "D" * 43, "byte_length": 3, "review_complete": True,
              "read_delivery": returned}
    client.confirm_obsidian_draft_read_delivery(
        observed_call=observed, binding=binding, tool_result=result)
    confirmation = exchange["requests"][0]
    assert confirmation["op"] == "confirm-obsidian-draft-read-delivery"
    assert confirmation["receipt_id"] == returned["receipt_id"]
    import hashlib
    assert confirmation["tool_result_sha256"] == hashlib.sha256(
        json.dumps(result, ensure_ascii=False, sort_keys=True,
                   separators=(",", ":"), allow_nan=False).encode()).hexdigest()
    client.request_final_effect(
        observed_call_handle=observed.handle, review_sha256="9" * 64,
        startup_binding_id=binding.binding_id)
    approval_request = exchange["requests"][1]
    assert approval_request["op"] == "request-final-effect"
    assert approval_request["startup_binding_id"] == binding.binding_id

    incomplete = {**result, "title": "Large draft", "markdown": None,
        "content_sha256": "a" * 64, "byte_length": 32_769,
        "review_complete": False,
        "next_step": "Use the owner draft review flow to reduce the draft before Jarvis reviews it.",
        "read_delivery": {"receipt_id": returned["receipt_id"],
            "receipt_sha256": returned["receipt_sha256"], "complete": False,
            "covered_byte_length": 0}}
    client.confirm_obsidian_draft_read_delivery(
        observed_call=observed, binding=binding, tool_result=incomplete)
    assert exchange["requests"][2]["op"] == "confirm-obsidian-draft-read-delivery"
    assert exchange["requests"][2]["tool_result_sha256"] == hashlib.sha256(
        json.dumps(incomplete, ensure_ascii=False, sort_keys=True,
                   separators=(",", ":"), allow_nan=False).encode()).hexdigest()


@pytest.mark.parametrize("retry_count", [None, -1, 1, True])
def test_codex_attempt_rejects_unknown_or_retry_count_before_ipc(tmp_path: Path, retry_count):
    client = CoreNativeObservationClient(socket_path=tmp_path / "unused.sock")
    with pytest.raises(CoreNativeObservationUnavailable):
        client.register_attempt(
            session_id="session-1", turn_id="turn-1", api_request_id="request-1",
            provider="openai-codex", model="gpt-6-luna",
            base_url="https://chatgpt.com/backend-api/codex",
            api_mode="codex_responses", account_fingerprint="a" * 64,
            request_sha256="b" * 64, parent_tool_names=("delegate_task",),
            prompt_sha256="c" * 64, retry_count=retry_count,
        )


def test_credential_pool_or_api_bearer_never_counts_as_selected_subscription():
    with pytest.raises(CoreNativeObservationUnavailable):
        _codex_account_fingerprint(lambda: {
            "provider": "openai-codex", "base_url": "https://chatgpt.com/backend-api/codex",
            "api_key": "not-a-real-token", "source": "credential_pool",
            "auth_mode": "api_key",
        })


def test_provider_attempt_receipt_can_cover_original_owner_turn_deadline():
    import time

    now = time.monotonic()
    attempt = ObservedProviderAttempt(
        handle="a" * 32, owner_turn_handle="o" * 32, expires_monotonic=now + 300,
    )
    assert attempt.expires_monotonic > now + 30
    with pytest.raises(CoreNativeObservationUnavailable):
        ObservedProviderAttempt(
            handle="b" * 32, owner_turn_handle="o" * 32, expires_monotonic=now + 601,
        )


def test_initial_planner_admission_accepts_no_parent_turn_but_rejects_tool_drift():
    from types import SimpleNamespace
    from hermes_installer.remote.native_child_adapter import NativeChildMode

    parent = SimpleNamespace(
        session_id="owner-session", _current_turn_id=None,
        provider="openai-codex", api_mode="codex_responses",
        base_url="https://chatgpt.com/backend-api/codex", model="gpt-6-luna",
    )
    child = SimpleNamespace(
        session_id="planner-session", _current_turn_id=None, valid_tool_names=set(),
        provider="openai-codex", api_mode="codex_responses",
        base_url="https://chatgpt.com/backend-api/codex", model="gpt-6-luna",
    )
    source = SimpleNamespace(
        profile_id="hermes", generation_sha256="a" * 64,
        source_member_manifest_sha256="b" * 64, effective_prompt_sha256="c" * 64,
    )
    now = __import__("time").monotonic()
    authorization = RootVerifiedNativeChildAuthorization(
        owner_turn_handle="o" * 32, gateway_turn_id="gateway-turn",
        owner_subject_sha256="d" * 64, core_generation="e" * 64,
        core_source_generation="f" * 64, parent_session_id=parent.session_id,
        parent_turn_id="", child_session_id=child.session_id, profile_id="hermes",
        source_generation_sha256=source.generation_sha256,
        source_manifest_sha256=source.source_member_manifest_sha256,
        prompt_sha256=source.effective_prompt_sha256,
        goal_sha256=__import__("hashlib").sha256(b"bounded plan").hexdigest(),
        account_fingerprint="1" * 64, mode=NativeChildMode.PLANNER.value,
        allowed_tool_names=(), tool_closure_sha256=__import__("hashlib").sha256(b"[]").hexdigest(),
        additional_metered_budget=0, admission_handle="h" * 32,
        expires_monotonic=now + 20, initial_owner_turn=True,
        _parent_agent=parent, _child_agent=child, _source=source,
        _seal=_NATIVE_CHILD_AUTHORIZATION_SEAL,
    )

    assert authorization.matches_child(
        parent_agent=parent, child=child, source=source,
        mode=NativeChildMode.PLANNER, goal="bounded plan", now=now,
    )
    child.valid_tool_names.add("delegate_task")
    assert not authorization.matches_child(
        parent_agent=parent, child=child, source=source,
        mode=NativeChildMode.PLANNER, goal="bounded plan", now=now,
    )


def test_owner_turn_registration_is_not_available_from_core_worker_socket(tmp_path: Path):
    client = CoreNativeObservationClient(socket_path=tmp_path / "unused.sock")
    # Owner turns are accepted only by the inspector's authenticated gateway op,
    # which independently validates Access and consumes the one-use ingress proof.
    # The native worker socket cannot mint owner authority from caller metadata.
    with pytest.raises(CoreNativeObservationUnavailable):
        client._rpc("register-owner-turn", {"gateway_turn_id": "caller-selected"})


def test_mission_binding_roundtrips_only_the_root_sealed_typed_wire_shape():
    binding = MissionBinding(
        schema=2, mission_id="m" * 24, revision=3,
        plan_sha256="a" * 64, task_sha256="b" * 64,
        source_profile_id="hermes", execution_mode="oneshot",
        autonomy_mode="approval_required", selected_source_ids=("orchestrator",),
        scope_sha256="c" * 64, authorization_sha256=None,
    )
    assert _mission_binding_from_wire(None) is None
    assert _mission_binding_from_wire(binding.to_wire()) == binding
    with pytest.raises(CoreNativeObservationUnavailable):
        _mission_binding_from_wire({**binding.to_wire(), "owner_subject_sha256": "c" * 64})
    with pytest.raises(CoreNativeObservationUnavailable):
        _mission_binding_from_wire({**binding.to_wire(), "mission_id": "mission-17"})


def test_root_caller_receipt_binds_exact_observed_tool_effect_and_expiry():
    now = __import__("time").monotonic()
    call = ObservedNativeToolCall(
        handle="h" * 32, attempt_handle="a" * 32, owner_turn_handle="o" * 32,
        tool_call_id="call-1", tool_name="web_search", arguments_sha256="b" * 64,
        expires_monotonic=now + 10,
    )
    receipt = RootVerifiedMasterReadCall(
        observed_call_handle=call.handle, owner_turn_handle=call.owner_turn_handle,
        tool_call_id=call.tool_call_id, tool_name=call.tool_name,
        arguments_sha256=call.arguments_sha256, source_generation_sha256="c" * 64,
        mode="expert_read", expires_monotonic=now + 5, _seal=_MASTER_READ_CALL_SEAL,
    )

    assert receipt.matches_call(call, tool_name="web_search", arguments_sha256="b" * 64, now=now)
    assert not receipt.matches_call(call, tool_name="terminal", arguments_sha256="b" * 64, now=now)
    assert not receipt.matches_call(call, tool_name="web_search", arguments_sha256="d" * 64, now=now)
    assert not receipt.matches_call(call, tool_name="web_search", arguments_sha256="b" * 64,
                                    now=receipt.expires_monotonic)
