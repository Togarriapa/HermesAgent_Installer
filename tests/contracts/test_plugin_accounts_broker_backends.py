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
    SQLitePluginEffectLedger,
)


class RecordingNetwork:
    def __init__(self, response):
        self.response = response
        self.calls = []

    def request(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return self.response


def test_github_uses_fixed_host_allowlisted_repo_and_verifies_content():
    content = "hello\n"
    encoded = __import__("base64").b64encode(content.encode()).decode()
    network = RecordingNetwork(HTTPResult(200, {}, __import__("json").dumps({"content": encoded}).encode()))
    backend = GitHubRESTBackend(network)
    enrollment = SimpleNamespace(repositories=frozenset({"team/repo"}))
    action = SimpleNamespace(action_id="content.put", operation="plugin.github.write")
    args = {"repository": "team/repo", "path": "docs/readme.md", "content": content,
            "message": "update", "sha": "a" * 40}
    result = backend.invoke(enrollment=enrollment, action=action, arguments=args,
        credential="secret-token", idempotency_key="attempt-1", timeout=2, cancelled=lambda: False)
    assert result == {"content": encoded}
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


def test_composio_url_connection_and_version_are_enrollment_bound():
    network = RecordingNetwork(HTTPResult(200, {}, b'{"data":{"ok":true}}'))
    backend = ComposioToolBackend(network)
    enrollment = SimpleNamespace(composio_connections={"GITHUB_GET_REPO": "ca_123"},
                                 toolkit_versions={"GITHUB_GET_REPO": "20260101_01"})
    result = backend.invoke(enrollment=enrollment,
        action=SimpleNamespace(action_id="GITHUB_GET_REPO"), arguments={"owner": "team"},
        credential="api-key", idempotency_key=None, timeout=2, cancelled=lambda: False)
    assert result == {"data": {"ok": True}}
    url, req = network.calls[0]
    assert url == "https://backend.composio.dev/api/v3.1/tools/execute/GITHUB_GET_REPO"
    assert req["headers"]["Authorization"] == "Bearer api-key"
    assert b'"connected_account_id":"ca_123"' in req["body"]
    assert b'"version":"20260101_01"' in req["body"]


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
