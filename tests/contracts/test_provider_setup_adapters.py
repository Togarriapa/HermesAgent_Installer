from __future__ import annotations

import json
import unittest
from dataclasses import dataclass
from typing import Any

from hermes_installer.network import HTTPResult
from hermes_installer.provider_setup_adapters import (
    OPENROUTER_API, OPENROUTER_MODEL, OpenRouterAccountProbe,
    build_provider_setup_adapter,
)


@dataclass
class _Network:
    responses: list[HTTPResult]
    calls: list[tuple[str, str, dict[str, str], bytes | None]]

    def request(self, url: str, *, method: str, headers: dict[str, str], body=None):
        self.calls.append((url, method, dict(headers), body))
        return self.responses.pop(0)


def _json_reply(value: Any, status: int = 200) -> HTTPResult:
    return HTTPResult(status, {"Content-Type": "application/json; charset=utf-8"},
                      json.dumps(value).encode())


class ProviderSetupAdapterTests(unittest.TestCase):
    def test_probe_authenticates_reads_exact_model_and_never_posts_generation(self):
        key = {"data": {"creator_user_id": "user-private", "is_free_tier": True,
                        "usage": 0, "limit_remaining": 1}}
        model = {"id": OPENROUTER_MODEL, "pricing": {"prompt": "0", "completion": "0"},
                 "supported_parameters": ["tools", "tool_choice"],
                 "context_length": 1_000_000, "max_completion_tokens": 4096}
        network = _Network([_json_reply(key), _json_reply({"data": [model]})], [])
        probe = OpenRouterAccountProbe(network_factory=lambda **_kwargs: network)
        result = probe.check("sk-secret-fixture")

        self.assertTrue(result.catalog_probe_passed)
        self.assertTrue(result.is_free_tier)
        self.assertEqual(result.context_length, 1_000_000)
        self.assertEqual([call[0] for call in network.calls],
                         [OPENROUTER_API + "/key", OPENROUTER_API + "/models"])
        self.assertTrue(all(call[1] == "GET" and call[3] is None for call in network.calls))
        self.assertTrue(all(call[2]["Authorization"] == "Bearer sk-secret-fixture" for call in network.calls))
        self.assertEqual(result.account_fingerprint, __import__("hashlib").sha256(b"user-private").hexdigest()[:20])

    def test_setup_stores_only_after_read_only_probe_and_stays_pending(self):
        events: list[str] = []
        secret = "sk-secret-fixture"

        class Probe:
            def check(self, value):
                self_value = value
                events.append("probe")
                assert self_value == secret
                return __import__("hermes_installer.provider_setup_adapters", fromlist=["OpenRouterProbeResult"]).OpenRouterProbeResult(
                    True, True, True, True, True, True, 1024, 128, "a" * 20)

        class Store:
            def put(self, name, value):
                events.append("store")
                assert name == "openrouter-provider"
                assert value == secret
                return "secret://provider/openrouter/account"

        saved = []
        adapter = build_provider_setup_adapter(
            probe_factory=Probe,
            persist_reference=lambda provider, reference, observation: saved.append(
                (provider, reference, observation.catalog_probe_passed)))
        output: list[str] = []
        result = adapter.configure({}, input_fn=lambda _: "now", output_fn=output.append,
            secret_reader=lambda _prompt: secret, credential_store=Store())

        self.assertEqual(result.state, "pending")
        self.assertEqual(events, ["probe", "store"])
        self.assertEqual(saved, [("openrouter", "secret://provider/openrouter/account", True)])
        self.assertEqual(result.config, {"privacy": {"additional_metered_budget": 0}})
        self.assertNotIn(secret, "\n".join(output))
        self.assertNotIn(secret, repr(result))
        self.assertTrue(any("No inference was sent" in item for item in output))

    def test_probe_failure_does_not_store_key_or_echo_provider_body(self):
        secret = "sk-secret-fixture"
        output: list[str] = []
        class Probe:
            def check(self, _credential):
                raise RuntimeError("provider leaked " + secret)
        class Store:
            def put(self, *_args):
                raise AssertionError("credential must not be persisted before a successful check")
        adapter = build_provider_setup_adapter(probe_factory=Probe)
        result = adapter.configure({}, input_fn=lambda _: "now", output_fn=output.append,
            secret_reader=lambda _prompt: secret, credential_store=Store())
        self.assertEqual(result.state, "pending")
        self.assertNotIn(secret, result.message + repr(result.config) + "\n".join(output))

    def test_missing_private_state_sink_does_not_store_orphaned_key(self):
        class Probe:
            def check(self, _credential):
                from hermes_installer.provider_setup_adapters import OpenRouterProbeResult
                return OpenRouterProbeResult(True, True, True, True, True, True, 1024, 128, "a" * 20)
        class Store:
            def put(self, *_args):
                raise AssertionError("no private reference sink means no credential write")
        result = build_provider_setup_adapter(probe_factory=Probe).configure(
            {}, input_fn=lambda _: "now", output_fn=lambda _: None,
            secret_reader=lambda _: "sk-secret-fixture", credential_store=Store())
        self.assertEqual(result.state, "pending")
        self.assertIn("key was not stored", result.message)

    def test_test_connection_repeats_only_read_only_probe_and_never_stores_or_enables_route(self):
        events = []

        class Probe:
            def check_reference(self, reference, *, secret_resolver):
                events.append(("probe", reference, secret_resolver(reference)))
                return __import__("hermes_installer.provider_setup_adapters", fromlist=["OpenRouterProbeResult"]).OpenRouterProbeResult(
                    True, True, True, True, True, True, 2048, 256, "a" * 20)

        adapter = build_provider_setup_adapter(probe_factory=Probe,
            credential_reference="secret://openrouter/account/key",
            secret_resolver=lambda reference: "fixture-private-key")
        result = adapter.test_connection({"components": {"providers": False}})

        self.assertEqual(events, [("probe", "secret://openrouter/account/key", "fixture-private-key")])
        self.assertEqual(result.state, "pending")
        self.assertIn("account-specific admission", result.message)
        self.assertNotIn("fixture-private-key", repr(result))

    def test_duplicate_json_keys_and_nonzero_prices_fail_closed(self):
        duplicate = HTTPResult(200, {"Content-Type": "application/json"},
                               b'{"data":{"creator_user_id":"a","creator_user_id":"b"}}')
        network = _Network([duplicate], [])
        probe = OpenRouterAccountProbe(network_factory=lambda **_kwargs: network)
        with self.assertRaisesRegex(RuntimeError, "malformed JSON"):
            probe.check("sk-secret-fixture")

        self.assertFalse(__import__("hermes_installer.provider_setup_adapters", fromlist=["_zero_price"])._zero_price("0.0000001"))
        self.assertFalse(__import__("hermes_installer.provider_setup_adapters", fromlist=["_zero_price"])._zero_price("unknown"))


if __name__ == "__main__":
    unittest.main()
