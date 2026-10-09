import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from hermes_installer.network import HTTPResult
from hermes_installer.plugin_accounts_broker import (
    CodexManagedRunnerAdapter,
    CodexWorkspaceBinding,
    ComposioToolBackend,
    GitHubRESTBackend,
    PluginEffectDenied,
    PluginAccountEnrollment,
    PluginAccountEnrollment,
    SQLitePluginEffectLedger,
)


class RecordingNetwork:
    def __init__(self, response):
        self.response = response
        self.calls = []

    def request(self, url, **kwargs):
        self.calls.append((url, kwargs))
        if isinstance(self.response, list):
            return self.response.pop(0)
        return self.response


def test_github_uses_fixed_host_allowlisted_repo_and_verifies_content():
    content = "hello\n"
    encoded = __import__("base64").b64encode(content.encode()).decode()
    write_receipt = {"content": {"path": "docs/readme.md", "sha": "b" * 40, "size": len(content),
                                  "html_url": "https://github.com/team/repo/blob/main/docs/readme.md"},
                     "commit": {"sha": "c" * 40}}
    verify_value = {"type": "file", "path": "docs/readme.md", "sha": "b" * 40,
                    "size": len(content), "content": encoded, "encoding": "base64"}
    network = RecordingNetwork([
        HTTPResult(200, {}, __import__("json").dumps(write_receipt).encode()),
        HTTPResult(200, {}, __import__("json").dumps(verify_value).encode()),
    ])
    backend = GitHubRESTBackend(network)
    enrollment = SimpleNamespace(repositories=frozenset({"team/repo"}))
    action = SimpleNamespace(action_id="content.put", operation="plugin.github.write")
    args = {"repository": "team/repo", "path": "docs/readme.md", "content": content,
            "message": "update", "sha": "a" * 40}
    result = backend.invoke(enrollment=enrollment, action=action, arguments=args,
        credential="secret-token", idempotency_key="attempt-1", timeout=2, cancelled=lambda: False)
    assert result["path"] == "docs/readme.md" and result["commit_sha"] == "c" * 40
    url, request = network.calls[0]
    assert url == "https://api.github.com/repos/team/repo/contents/docs/readme.md"
    assert request["method"] == "PUT"
    assert request["headers"]["Authorization"] == "Bearer secret-token"
    assert backend.verify(enrollment=enrollment, action=action, arguments=args,
        credential="secret-token", idempotency_key="attempt-1", response=result,
        timeout=2, cancelled=lambda: False)


def test_github_refuses_repo_outside_protected_allowlist():
    backend = GitHubRESTBackend(RecordingNetwork(HTTPResult(200, {}, b"{}")))
    with pytest.raises(PluginEffectDenied):
        backend.invoke(enrollment=SimpleNamespace(repositories=frozenset({"team/allowed"})),
            action=SimpleNamespace(action_id="repo.get", operation="plugin.github.read"),
            arguments={"repository": "attacker/other"}, credential="x", idempotency_key=None,
            timeout=2, cancelled=lambda: False)


def test_github_issue_create_uses_idempotency_marker_and_exact_remote_verification():
    import json

    marker = "<!-- hermes-idempotency:attempt-issue -->"
    created = {"number": 17, "title": "report", "state": "open",
               "html_url": "https://github.com/team/repo/issues/17", "body": "details\n\n" + marker}
    network = RecordingNetwork([
        HTTPResult(201, {}, json.dumps(created).encode()),
        HTTPResult(200, {}, json.dumps(created).encode()),
    ])
    backend = GitHubRESTBackend(network)
    enrollment = SimpleNamespace(repositories=frozenset({"team/repo"}))
    action = SimpleNamespace(action_id="issue.create", operation="plugin.github.write")
    arguments = {"repository": "team/repo", "title": "report", "body": "details"}
    receipt = backend.invoke(enrollment=enrollment, action=action, arguments=arguments,
        credential="vault-token", idempotency_key="attempt-issue", timeout=2,
        cancelled=lambda: False)
    assert receipt == {"number": 17, "title": "report", "state": "open",
                       "html_url": "https://github.com/team/repo/issues/17"}
    assert backend.verify(enrollment=enrollment, action=action, arguments=arguments,
        credential="vault-token", idempotency_key="attempt-issue", response=receipt,
        timeout=2, cancelled=lambda: False)
    post_url, post_request = network.calls[0]
    assert post_url == "https://api.github.com/repos/team/repo/issues"
    assert marker.encode() in post_request["body"]


def test_composio_url_connection_and_version_are_enrollment_bound():
    network = RecordingNetwork(HTTPResult(200, {}, b'{"data":{"ok":true},"successful":true}'))
    backend = ComposioToolBackend(network)
    enrollment = SimpleNamespace(composio_connections={"GITHUB_GET_REPO": "ca_123"},
                                 toolkit_versions={"GITHUB_GET_REPO": "20260101_01"},
                                 composio_argument_schemas={"GITHUB_GET_REPO": {
                                     "type": "object", "properties": {"owner": {"type": "string"}},
                                     "required": ["owner"], "additionalProperties": False}},
                                 composio_result_schemas={"GITHUB_GET_REPO": {
                                     "type": "object", "properties": {"ok": {"type": "boolean"}},
                                     "required": ["ok"], "additionalProperties": False}},
                                 composio_mutating_actions=frozenset())
    result = backend.invoke(enrollment=enrollment,
        action=SimpleNamespace(action_id="invoke.read", mutating=False),
        arguments={"tool_slug": "GITHUB_GET_REPO", "arguments": {"owner": "team"}},
        credential="api-key", idempotency_key=None, timeout=2, cancelled=lambda: False)
    assert result == {"ok": True}
    url, req = network.calls[0]
    assert url == "https://backend.composio.dev/api/v3.1/tools/execute/GITHUB_GET_REPO"
    assert req["headers"]["x-api-key"] == "api-key"
    assert b'"connected_account_id":"ca_123"' in req["body"]
    assert b'"version":"20260101_01"' in req["body"]


def test_composio_rejects_a_slug_outside_the_protected_action_schema_maps():
    backend = ComposioToolBackend(RecordingNetwork(HTTPResult(200, {}, b'{}')))
    enrollment = SimpleNamespace(composio_connections={"GITHUB_GET_REPO": "ca_1"},
        toolkit_versions={"GITHUB_GET_REPO": "20260101_01"},
        composio_argument_schemas={"GITHUB_GET_REPO": {"type": "object"}},
        composio_result_schemas={"GITHUB_GET_REPO": {"type": "object"}},
        composio_mutating_actions=frozenset())
    with pytest.raises(PluginEffectDenied):
        backend.invoke(enrollment=enrollment,
            action=SimpleNamespace(action_id="invoke.read", mutating=False),
            arguments={"tool_slug": "GITHUB_DELETE_REPO", "arguments": {}},
            credential="api-key", idempotency_key=None, timeout=2, cancelled=lambda: False)


def test_composio_root_enrollment_requires_matching_connection_version_and_io_schemas():
    with pytest.raises(ValueError):
        PluginAccountEnrollment(adapter_id="composio", enrollment_id="enrollment-1",
            principal_id="principal-1", profile_id="profile-1", recipient="recipient-1",
            credential_reference_id="vault-composio-key", credential_scope="composio-tool-exec",
            account_id="account-1", action_ids=frozenset({"invoke.read"}),
            composio_connections={"GITHUB_GET_REPO": "connection-1"},
            toolkit_versions={"GITHUB_GET_REPO": "20260101_01"},
            composio_argument_schemas={"GITHUB_GET_REPO": {"type": "object"}},
            composio_result_schemas={}, composio_mutating_actions=frozenset())


def test_codex_adapter_passes_only_enrolled_workspace_and_prompt_to_managed_runner():
    class Runner:
        toolchain_lock_sha256 = "a" * 64
        architecture = "arm64"

        def run_managed(self, *, workspace, prompt, idempotency_key, timeout, cancelled):
            self.seen = (workspace, prompt, idempotency_key, timeout)
            return {"exit_code": 0, "summary": "done"}

    runner = Runner()
    adapter = CodexManagedRunnerAdapter(runner, toolchain_lock_sha256="a" * 64, architecture="arm64")
    binding = CodexWorkspaceBinding("assigned", Path("/protected/workspace"), "b" * 64,
                                    True, "profile")
    enrollment = SimpleNamespace(codex_workspaces={"assigned": binding}, profile_id="profile")
    result = adapter.invoke(enrollment=enrollment, action=SimpleNamespace(action_id="run"),
        arguments={"workspace_id": "assigned", "prompt": "inspect tests"}, credential=None,
        idempotency_key="run-1", timeout=5, cancelled=lambda: False)
    assert result["exit_code"] == 0
    assert runner.seen == (binding, "inspect tests", "run-1", 5)

    with pytest.raises(PluginEffectDenied):
        adapter.invoke(enrollment=enrollment, action=SimpleNamespace(action_id="run"),
            arguments={"workspace_id": "../../etc", "prompt": "inspect"}, credential=None,
            idempotency_key="run-1", timeout=5, cancelled=lambda: False)


def test_codex_refuses_unpinned_or_non_arm64_runner():
    class Runner:
        toolchain_lock_sha256 = "a" * 64
        architecture = "x86_64"

    with pytest.raises(ValueError):
        CodexManagedRunnerAdapter(Runner(), toolchain_lock_sha256="a" * 64, architecture="arm64")


def test_durable_write_ledger_prevents_blind_retry_and_digest_rebinding(tmp_path):
    state = tmp_path / "private"
    state.mkdir(mode=0o700)
    ledger = SQLitePluginEffectLedger(state / "effects.sqlite")
    key, digest, operation = (hashlib.sha256(value).hexdigest()
                              for value in (b"key", b"request", b"operation"))
    assert ledger.claim(key, digest, operation)["state"] == "new"
    ledger.finish(key, "ambiguous", {"action_id": "write", "secret": "must-not-persist"})
    prior = ledger.claim(key, digest, hashlib.sha256(b"retry").hexdigest())
    assert prior["state"] == "ambiguous"
    assert prior["receipt"]["secret"] == "[redacted]"
    with pytest.raises(PluginEffectDenied):
        ledger.claim(key, hashlib.sha256(b"different").hexdigest(), operation)
