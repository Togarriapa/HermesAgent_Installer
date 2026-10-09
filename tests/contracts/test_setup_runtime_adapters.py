from __future__ import annotations

import unittest
import tempfile
from pathlib import Path

from hermes_installer.setup_runtime_adapters import (
    JournalSetupStateStore,
    MCPSelectionAdapter,
    MemorySelectionAdapter,
    SetupStateError,
    build_setup_adapters,
)


class FakeJournal:
    def __init__(self):
        self.rows = {}

    def operation(self, operation):
        return self.rows.get(operation)

    def checkpoint(self, operation, status, payload):
        self.rows[operation] = {"status": status, "payload": payload}


class SetupRuntimeAdapterTests(unittest.TestCase):
    def test_private_state_preserves_only_credential_reference_and_selection(self):
        journal = FakeJournal()
        providers = JournalSetupStateStore(journal, "providers")
        providers.put_reference("openrouter_api_key_ref", "file:///private/state/key",
                                status="account-probe-passed", account_fingerprint="a" * 16)
        self.assertEqual(providers.get_reference("openrouter_api_key_ref"),
                         "file:///private/state/key")
        self.assertEqual(journal.operation("installer:setup")["payload"]["setup_state"]["providers"]["account_checks"]["openrouter_api_key_ref"],
                         {"state": "account-probe-passed", "account_fingerprint": "a" * 16})
        self.assertNotIn("token-value", repr(journal.rows))

        mcp = JournalSetupStateStore(journal, "mcp")
        mcp.put_selection("service_id", "figma")
        self.assertEqual(mcp.get_selection("service_id"), "figma")
        payload = journal.operation("installer:setup")["payload"]
        self.assertIn("providers", payload["setup_state"])
        self.assertIn("mcp", payload["setup_state"])

    def test_private_state_rejects_raw_credentials_and_arbitrary_selection_keys(self):
        store = JournalSetupStateStore(FakeJournal(), "providers")
        for value in ("plaintext-token", "Bearer abc", "https://example.test/key"):
            with self.subTest(value=value), self.assertRaises(SetupStateError):
                store.put_reference("openrouter_api_key_ref", value, status="pending")
        with self.assertRaises(SetupStateError):
            store.put_selection("endpoint", "https://attacker.test")

    def test_default_factory_uses_real_provider_adapter_and_persists_only_reference(self):
        from hermes_installer.provider_setup_adapters import OpenRouterProbeResult

        journal = FakeJournal()
        events = []

        class Probe:
            def check(self, credential):
                events.append(("probe", credential))
                return OpenRouterProbeResult(True, None, True, True, True, True,
                                             2048, 256, "")

        class CredentialStore:
            def put(self, name, value):
                events.append(("store", name, value))
                return "secret://openrouter/account/key"

        adapters = build_setup_adapters(journal=journal, credential_store=CredentialStore(),
                                        provider_probe_factory=Probe)
        self.assertEqual(type(adapters["providers"]).__name__, "OpenRouterSetupAdapter")
        result = adapters["providers"].configure({}, input_fn=lambda _prompt: "now",
            output_fn=lambda _line: None, secret_reader=lambda _prompt: "fixture-private-key",
            credential_store=CredentialStore())
        self.assertEqual(result.state, "pending")
        self.assertEqual(events, [("probe", "fixture-private-key"),
                                  ("store", "openrouter-provider", "fixture-private-key")])
        state = journal.operation("installer:setup")["payload"]["setup_state"]["providers"]
        self.assertEqual(state["references"]["openrouter_api_key_ref"],
                         "secret://openrouter/account/key")
        self.assertEqual(state["account_checks"]["openrouter_api_key_ref"]["state"],
                         "account-probe-passed")
        self.assertNotIn("fixture-private-key", repr(journal.rows))

    def test_real_private_journal_redacts_secret_shaped_fields_but_keeps_opaque_reference(self):
        from hermes_installer.state import Journal, OwnedRoot

        with tempfile.TemporaryDirectory() as temporary:
            root = OwnedRoot(Path(temporary) / "installer-state")
            root.ensure()
            journal = Journal(root.path("journal.sqlite3"))
            store = JournalSetupStateStore(journal, "providers")
            store.put_reference("openrouter_api_key_ref", "file:///private/state/key",
                                status="account-probe-passed", account_fingerprint="b" * 20)
            payload = journal.operation("installer:setup")["payload"]
            provider_state = payload["setup_state"]["providers"]
            self.assertEqual(provider_state["references"]["openrouter_api_key_ref"],
                             "file:///private/state/key")
            self.assertEqual(provider_state["account_checks"]["openrouter_api_key_ref"],
                             {"state": "account-probe-passed", "account_fingerprint": "b" * 20})
            self.assertNotIn("secret", journal.path.read_text(encoding="utf-8", errors="ignore"))

    def test_mcp_selection_records_intent_but_never_claims_connection_or_reads_secret(self):
        journal = FakeJournal()
        adapter = MCPSelectionAdapter(JournalSetupStateStore(journal, "mcp"))
        prompts = iter(("figma", "file-123"))
        output = []
        result = adapter.configure({}, input_fn=lambda _prompt: next(prompts),
            output_fn=output.append, secret_reader=lambda _prompt: self.fail("MCP setup has no root credential intake"),
            credential_store=object())
        self.assertEqual(result.state, "pending")
        self.assertIn("no connection is claimed", result.message)
        self.assertEqual(JournalSetupStateStore(journal, "mcp").get_selection("service_id"), "figma")
        self.assertEqual(JournalSetupStateStore(journal, "mcp").get_selection("resource_id"), "file-123")
        self.assertTrue(any("developers.figma.com" in line for line in output))
        test_result = adapter.test_connection({})
        self.assertEqual(test_result.state, "pending")
        self.assertIn("root-enrolled", test_result.next_steps[0])

    def test_changing_mcp_service_discards_service_scoped_resource(self):
        journal = FakeJournal()
        state = JournalSetupStateStore(journal, "mcp")
        state.put_selection("service_id", "figma")
        state.put_selection("resource_id", "file-123")
        adapter = MCPSelectionAdapter(state)
        prompts = iter(("google-drive", "drive-file-456"))
        result = adapter.configure({}, input_fn=lambda _prompt: next(prompts),
            output_fn=lambda _line: None,
            secret_reader=lambda _prompt: self.fail("MCP setup must not read secrets"),
            credential_store=object())
        self.assertEqual(result.state, "pending")
        self.assertEqual(state.get_selection("service_id"), "google-drive")
        self.assertEqual(state.get_selection("resource_id"), "drive-file-456")

    def test_memory_selection_is_single_owner_intent_and_remains_pending_without_runtime(self):
        journal = FakeJournal()
        adapter = MemorySelectionAdapter(JournalSetupStateStore(journal, "memory"))
        prompts = iter(("claude-mem", "server-v1-sqlite"))
        output = []
        result = adapter.configure({}, input_fn=lambda _prompt: next(prompts),
            output_fn=output.append, secret_reader=lambda _prompt: self.fail("memory setup has no approved secret intake"),
            credential_store=object())
        self.assertEqual(result.state, "pending")
        self.assertIn("not active", result.message)
        state = JournalSetupStateStore(journal, "memory")
        self.assertEqual(state.get_selection("provider_id"), "claude-mem")
        self.assertEqual(state.get_selection("backend_variant"), "server-v1-sqlite")
        self.assertEqual(adapter.test_connection({}).state, "pending")
        self.assertTrue(any("github.com/thedotmack/claude-mem" in line for line in output))


if __name__ == "__main__":
    unittest.main()
