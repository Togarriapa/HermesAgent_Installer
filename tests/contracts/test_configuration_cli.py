from __future__ import annotations

import unittest

from hermes_installer.configuration_cli import run_configuration_command
from hermes_installer.setup_runtime_adapters import JournalSetupStateStore
from hermes_installer.setup_wizard import AdapterResult


class FakeJournal:
    def __init__(self):
        self.rows = {}

    def operation(self, operation):
        return self.rows.get(operation)

    def checkpoint(self, operation, status, payload):
        self.rows[operation] = {"status": status, "payload": payload}


class FakeStore:
    def put(self, _name, _value):
        raise AssertionError("no secret should be requested for this probe")


class ConfigurationCLITests(unittest.TestCase):
    def test_unknown_provider_name_fails_before_hidden_input_or_network(self):
        result = run_configuration_command("configure", config_data={"schema_version": 1},
            journal=FakeJournal(), credential_store=FakeStore(), interactive=True,
            resume_command="hermes-installer configure provider bogus", target="provider",
            name="bogus", secret_reader=lambda _prompt: self.fail("must reject before secret input"),
            input_fn=lambda _prompt: self.fail("must reject before prompt"))
        self.assertEqual(result.state.value, "failed")
        self.assertEqual(result.exit_code, 1)

    def test_unknown_mcp_name_does_not_become_a_persisted_selection(self):
        journal = FakeJournal()
        result = run_configuration_command("configure", config_data={"schema_version": 1},
            journal=journal, credential_store=FakeStore(), interactive=False,
            resume_command="hermes-installer configure mcp unknown", target="mcp",
            name="unknown")
        self.assertEqual(result.state.value, "failed")
        self.assertIsNone(JournalSetupStateStore(journal, "mcp").get_selection("service_id"))

    def test_mcp_test_connection_stays_pending_until_root_binding(self):
        journal = FakeJournal()
        JournalSetupStateStore(journal, "mcp").put_selection("service_id", "figma")
        selected_config = {"schema_version": 1, "components": {"mcp": False}}
        result = run_configuration_command("test-connection", config_data=selected_config,
            journal=journal, credential_store=FakeStore(), interactive=False,
            resume_command="hermes-installer test-connection mcp", target="mcp")
        self.assertEqual(result.state.value, "pending")
        self.assertEqual(result.exit_code, 4)
        self.assertIn("root-enrolled", result.findings[0].details["next_steps"][0])
        self.assertEqual(result.findings[0].details["config"], selected_config)

    def test_provider_test_connection_runs_only_the_fixed_read_only_probe(self):
        from hermes_installer.provider_setup_adapters import OpenRouterProbeResult, build_provider_setup_adapter

        calls = []

        class Probe:
            def check_reference(self, reference, *, secret_resolver):
                calls.append((reference, secret_resolver(reference)))
                return OpenRouterProbeResult(True, True, True, True, True, True,
                                             2048, 256, "a" * 20)

        adapter = build_provider_setup_adapter(probe_factory=Probe,
            credential_reference="secret://openrouter/account/key",
            secret_resolver=lambda _reference: "private-fixture-key")
        result = run_configuration_command("test-connection", config_data={"schema_version": 1},
            journal=FakeJournal(), credential_store=FakeStore(), interactive=False,
            resume_command="hermes-installer test-connection provider openrouter",
            target="provider", name="openrouter", adapters={"providers": adapter})
        self.assertEqual(calls, [("secret://openrouter/account/key", "private-fixture-key")])
        self.assertEqual(result.state.value, "pending")
        self.assertIn("account-specific admission", result.message)
        self.assertNotIn("private-fixture-key", repr(result))

    def test_memory_cli_choice_persists_and_returns_pending_not_false_ready(self):
        journal = FakeJournal()
        result = run_configuration_command("select-memory", config_data={"schema_version": 1},
            journal=journal, credential_store=FakeStore(), interactive=False,
            resume_command="hermes-installer select-memory openviking", choice="openviking")
        self.assertEqual(result.state.value, "pending")
        self.assertEqual(result.exit_code, 4)
        self.assertEqual(JournalSetupStateStore(journal, "memory").get_selection("provider_id"), "openviking")

    def test_source_url_alone_is_not_reported_as_immutable_revision(self):
        result = run_configuration_command("resolve-source", config_data={"schema_version": 1},
            journal=FakeJournal(), credential_store=FakeStore(), interactive=False,
            resume_command="hermes-installer resolve-source https://github.com/example/project",
            url="https://github.com/example/project")
        self.assertEqual(result.state.value, "pending")
        self.assertIsNone(result.findings[0].details["resolved_revision"])
        self.assertEqual(result.exit_code, 4)


if __name__ == "__main__":
    unittest.main()
