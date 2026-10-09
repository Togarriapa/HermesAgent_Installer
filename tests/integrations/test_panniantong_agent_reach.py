from __future__ import annotations

import asyncio
import json
import subprocess
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from hermes_installer.components.panniantong_agent_reach import (
    COMPONENT_ID,
    UPSTREAM_IDENTITY,
    UPSTREAM_PACKAGE,
    UPSTREAM_REVISION,
    UPSTREAM_URL,
    AgentReachError,
    agent_reach_contract,
    agent_reach_skill_spec,
    build_agent_reach_doctor_invocation,
    build_agent_reach_install_invocation,
    diagnose_selected_channels,
    discover_agent_reach_skills,
    run_agent_reach_diagnostic,
    verify_agent_reach_source,
)


class _FixtureHandler(BaseHTTPRequestHandler):
    requests_seen = 0

    def do_GET(self) -> None:
        type(self).requests_seen += 1
        body = b"agent-reach-local-fixture-ok\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args) -> None:
        return


class _ProcessSupervisor:
    def __init__(self) -> None:
        self.invocations = []

    async def invoke(self, invocation):
        self.invocations.append(invocation)
        completed = subprocess.run(
            invocation.argv,
            cwd=invocation.cwd,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        return {"exit_code": completed.returncode, "stdout": completed.stdout,
                "stderr": completed.stderr}


def _upstream_files() -> dict[str, bytes]:
    return {
        "pyproject.toml": b'''[project]
name = "agent-reach"
version = "1.5.0"
requires-python = ">=3.10"
license = {text = "MIT"}

[project.scripts]
agent-reach = "agent_reach.cli:main"

[project.urls]
Repository = "https://github.com/Panniantong/agent-reach"
''',
        "agent_reach/skill/SKILL_en.md": b"---\nname: agent-reach\ndescription: selected channel diagnostics\n---\n# Agent Reach\n[Channel reference](references/channels.md)\n",
        "agent_reach/skill/SKILL.md": b"---\nname: agent-reach\ndescription: selected channel diagnostics\n---\n# Agent Reach\n[Channel reference](references/channels.md)\n",
        "agent_reach/skill/references/channels.md": b"Reference stays inside the selected source tree.\n",
    }


def test_pinned_upstream_identity_and_skill_tree_are_checked() -> None:
    contract = agent_reach_contract()
    spec = agent_reach_skill_spec()
    assert contract.source_identity == UPSTREAM_IDENTITY
    assert contract.selected_source_url == UPSTREAM_URL
    assert contract.revision == UPSTREAM_REVISION
    assert spec.id == COMPONENT_ID and spec.revision == UPSTREAM_REVISION
    assert verify_agent_reach_source(
        _upstream_files(), source_identity=UPSTREAM_IDENTITY, revision=UPSTREAM_REVISION
    ) == ("agent_reach/skill/SKILL.md", "agent_reach/skill/SKILL_en.md")
    discovery = discover_agent_reach_skills(_upstream_files())
    assert discovery.revision == UPSTREAM_REVISION
    assert discovery.skills[0].skill_file == "agent_reach/skill/SKILL.md"
    assert "agent_reach/skill/references/channels.md" in discovery.skills[0].references

    with pytest.raises(AgentReachError, match="selected Panniantong"):
        verify_agent_reach_source(
            _upstream_files(), source_identity="somebody/agent-reach", revision=UPSTREAM_REVISION
        )
    wrong_package = _upstream_files()
    wrong_package["pyproject.toml"] = wrong_package["pyproject.toml"].replace(
        b"https://github.com/Panniantong/agent-reach",
        b"https://github.com/unrelated/agent-reach",
    )
    with pytest.raises(AgentReachError, match="metadata"):
        verify_agent_reach_source(
            wrong_package, source_identity=UPSTREAM_IDENTITY, revision=UPSTREAM_REVISION
        )


def test_install_invocation_is_pinned_and_inside_component_environment() -> None:
    invocation = build_agent_reach_install_invocation(
        "/opt/hermes/tools/uv", "/opt/hermes/components/agent-reach",
        "/opt/hermes/components/agent-reach/.venv/bin/python",
    )
    assert invocation.executable == "/opt/hermes/tools/uv"
    assert invocation.argv[-1] == UPSTREAM_PACKAGE
    assert "pip" in invocation.argv and "--python" in invocation.argv
    assert "PyPI" not in invocation.argv[-1]
    with pytest.raises(AgentReachError, match="inside"):
        build_agent_reach_install_invocation(
            "/opt/hermes/tools/uv", "/opt/hermes/components/agent-reach",
            "/opt/hermes/venv/bin/python",
        )


def test_upstream_doctor_and_local_mock_read_keep_states_separate() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        runtime = Path(temporary) / "agent-reach"
        runtime.mkdir()
        cli = runtime / "bin" / "agent-reach"
        cli.parent.mkdir()
        # This controlled executable uses the upstream doctor --json wire shape.
        # It performs no network or credential access; the selected read below
        # goes only to the local HTTP fixture.
        cli.write_text(
            "#!/usr/bin/env python3\n"
            "import json, sys\n"
            "assert sys.argv[1:] == ['doctor', '--json']\n"
            "print(json.dumps({"
            "'web': {'status': 'ok', 'name': 'web', 'message': 'safe'},"
            "'reddit': {'status': 'warn', 'name': 'reddit', 'message': 'needs login'}"
            "}))\n",
            encoding="utf-8",
        )
        cli.chmod(0o700)

        _FixtureHandler.requests_seen = 0
        server = ThreadingHTTPServer(("127.0.0.1", 0), _FixtureHandler)
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()
        try:
            fixture_url = f"http://127.0.0.1:{server.server_port}/read"
            supervisor = _ProcessSupervisor()
            result = asyncio.run(run_agent_reach_diagnostic(
                supervisor,
                str(cli),
                str(runtime),
                ["web", "reddit"],
                fixture_reads={"web": (fixture_url, "agent-reach-local-fixture-ok")},
                credential_statuses={"web": "configured", "reddit": "missing"},
            ))
        finally:
            server.shutdown()
            server.server_close()
            server_thread.join(timeout=2)

    web, reddit = result
    assert supervisor.invocations[0].argv == (str(cli), "doctor", "--json")
    assert supervisor.invocations[0].network == "localhost"
    assert supervisor.invocations[0].credential_references == ()
    assert _FixtureHandler.requests_seen == 1
    assert web.doctor_status == "ok"
    assert web.functional_read_status == "fixture_passed"
    assert web.functional_read_scope == "fixture"
    assert web.credential_status == "configured"
    assert web.account_status == "pending"
    assert reddit.doctor_status == "warn"
    assert reddit.functional_read_status == "pending"
    assert reddit.functional_read_scope == "pending"
    assert reddit.credential_status == "missing"
    assert reddit.account_status == "pending"


def test_local_failure_does_not_promote_doctor_or_account_state() -> None:
    reports = diagnose_selected_channels(
        json.dumps({"web": {"status": "ok", "active_backend": "Jina Reader",
                            "message": "must not be forwarded"}}),
        ["web"],
        fixture_reads={"web": ("http://127.0.0.1:1/unavailable", "expected")},
        credential_statuses={"web": "configured"},
    )
    report = reports[0]
    assert report.doctor_status == "ok"
    assert report.functional_read_status == "failed"
    assert report.credential_status == "configured"
    assert report.account_status == "pending"
    assert "message" not in report.__dataclass_fields__
