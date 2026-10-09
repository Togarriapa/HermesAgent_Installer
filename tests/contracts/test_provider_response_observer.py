from __future__ import annotations

import hashlib
import json
import unittest

from hermes_installer.provider_response_observer import (
    ProviderResponseObservationDenied,
    parse_successful_provider_tool_calls,
)


class ProviderResponseObserverTests(unittest.TestCase):
    def test_openrouter_calls_are_canonical_and_have_exact_argument_digest(self):
        body = (b'{"choices":[{"message":{"tool_calls":[{"id":"call-1","type":"function",'
                b'"function":{"name":"lookup","arguments":"{ \\"q\\": 1 }"}}]},'
                b'"finish_reason":"tool_calls"}]}')
        parsed = parse_successful_provider_tool_calls(
            "openrouter", 200, {"Content-Type": "application/json; charset=utf-8"}, body)
        self.assertEqual(len(parsed), 1)
        self.assertEqual(parsed[0].provider_tool_call_id, "call-1")
        self.assertEqual(parsed[0].tool_name, "lookup")
        self.assertEqual(parsed[0].canonical_arguments, b'{"q":1}')
        self.assertEqual(parsed[0].arguments_sha256, hashlib.sha256(b'{"q":1}').hexdigest())

    def test_codex_calls_are_extracted_only_from_completed_sse(self):
        event = {
            "type": "response.completed",
            "response": {
                "id": "resp-1", "status": "completed",
                "usage": {"input_tokens": 5, "output_tokens": 7},
                "output": [{"type": "function_call", "call_id": "call-2",
                            "name": "lookup", "arguments": "{\"q\":1}"}],
            },
        }
        body = b"event: response.completed\ndata: " + json.dumps(event).encode() + b"\n\n"
        parsed = parse_successful_provider_tool_calls(
            "codex", 200, {"Content-Type": "text/event-stream; charset=utf-8"}, body)
        self.assertEqual(len(parsed), 1)
        self.assertEqual(parsed[0].provider_tool_call_id, "call-2")
        self.assertEqual(parsed[0].arguments_sha256, hashlib.sha256(b'{"q":1}').hexdigest())

    def test_invalid_or_ambiguous_response_never_creates_calls(self):
        cases = (
            ("openrouter", 200, {"Content-Type": "application/json"},
             b'{"choices":[{"message":{"tool_calls":[{"id":"x","type":"function",'
             b'"function":{"name":"lookup","arguments":"{\\"x\\":1,\\"x\\":2}"}}]},'
             b'"finish_reason":"tool_calls"}]}'),
            ("openrouter", 503, {"Content-Type": "application/json"}, b'{"choices":[]}'),
            ("codex", 200, {"Content-Type": "text/event-stream"},
             b'event: response.incomplete\ndata: {"type":"response.incomplete"}\n\n'),
        )
        for provider, status, headers, body in cases:
            with self.subTest(provider=provider, status=status), self.assertRaises(ProviderResponseObservationDenied):
                parse_successful_provider_tool_calls(provider, status, headers, body)

    def test_duplicate_call_ids_and_unbounded_call_sets_are_rejected(self):
        duplicate = b'{"choices":[{"message":{"tool_calls":[' + \
            b'{"id":"x","type":"function","function":{"name":"a","arguments":"{}"}},' + \
            b'{"id":"x","type":"function","function":{"name":"b","arguments":"{}"}}]},' + \
            b'"finish_reason":"tool_calls"}]}'
        with self.assertRaises(ProviderResponseObservationDenied):
            parse_successful_provider_tool_calls("openrouter", 200, {"Content-Type": "application/json"}, duplicate)


if __name__ == "__main__":
    unittest.main()
