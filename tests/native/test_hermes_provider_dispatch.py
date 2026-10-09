"""Native Hermes provider dispatch acceptance using an external PM worker.

The parent owns the recording gateway and disposable profile so a Hermes PM
bootstrap re-exec cannot destroy the listener or bypass cleanup.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
import uuid
from pathlib import Path

INSTALLER_SRC = Path(__file__).resolve().parents[2] / "src"
sys.path.insert(0, str(INSTALLER_SRC))

from hermes_installer.policy import BudgetLedger, DispatchPolicy, Dispatcher, ProviderResponse, Route, Sensitivity, default_public_route
from hermes_installer.provider_gateway import LocalProviderGateway, materialize_hermes_profile_config, materialize_hermes_provider_plugin
from hermes_installer.state import OwnedRoot

MODEL = "nvidia/nemotron-3-ultra-550b-a55b:free"
HERMES_PIN = "7085fbf7753266fc4943c55ac04926186bc90005"
FIXTURE_KEY = "native-local-fixture-key-0123456789abcdef"
OPTIONS = {}
for item in list(sys.argv[1:]):
    if item.startswith("--hermes-source="):
        OPTIONS["source"] = item.split("=", 1)[1]
        sys.argv.remove(item)
    elif item.startswith("--installer-data-root="):
        OPTIONS["data"] = item.split("=", 1)[1]
        sys.argv.remove(item)


class RecordingTransport:
    def __init__(self):
        self.calls = []
        self.stream_calls = 0
        self.response_actions = []

    def __call__(self, route, model, payload, *, output_token_limit, timeout, trace_id, cancelled=lambda: False):
        request = json.loads(payload)
        self.calls.append((route.name, model, payload))
        tool_names = [
            item.get("function", {}).get("name")
            for item in request.get("tools", []) if isinstance(item, dict)
        ]
        tool_results = [
            item.get("name") for item in request.get("messages", [])
            if isinstance(item, dict) and item.get("role") == "tool"
        ]
        stream_index = None
        if request.get("stream") is True:
            stream_index = self.stream_calls
            self.stream_calls += 1
        tool_call = None
        if stream_index == 0:
            tool_call = ("tool_search", {"queries": ["fixture_echo"], "limit": 5})
        elif stream_index == 1:
            tool_call = ("tool_describe", {"names": ["fixture_echo"]})
        elif stream_index == 2:
            tool_call = ("tool_call", {"calls": [{
                "name": "fixture_echo",
                "arguments": {"text": "SYNTHETIC_PRIVATE_CANARY_7f4c"},
            }]})
        self.response_actions.append(tool_call[0] if tool_call else "final-text")
        response_text = (
            "private fixture tool result received"
            if stream_index is not None and stream_index >= 3 else "native fixture response"
        )
        completion_id = "chatcmpl-native-fixture"
        if request.get("stream") is True:
            if tool_call is not None:
                name, arguments = tool_call
                delta = {"role": "assistant", "tool_calls": [{
                    "index": 0, "id": "call-fixture-" + str(len(self.calls)),
                    "type": "function", "function": {
                        "name": name, "arguments": json.dumps(arguments, separators=(",", ":")),
                    },
                }]}
                finish = "tool_calls"
            else:
                delta = {"role": "assistant", "content": response_text}
                finish = "stop"
            chunk = {
                "id": completion_id, "object": "chat.completion.chunk", "created": 1,
                "model": MODEL, "choices": [{"index": 0, "delta": delta,
                                               "finish_reason": finish}],
            }
            body = ("data: " + json.dumps(chunk, separators=(",", ":")) + "\n\n"
                    + "data: [DONE]\n\n").encode("utf-8")
            return ProviderResponse(200, body, {"Content-Type": "text/event-stream"}, 5, 3)
        message = {"role": "assistant", "content": response_text}
        body = json.dumps({
            "id": completion_id, "object": "chat.completion", "created": 1,
            "model": MODEL, "choices": [{"index": 0, "message": message, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 5, "completion_tokens": 3, "total_tokens": 8},
        }, separators=(",", ":")).encode("utf-8")
        return ProviderResponse(200, body, {"Content-Type": "application/json"}, 5, 3)


class NativeHermesProviderDispatchTests(unittest.TestCase):
    def test_primary_and_auxiliary_use_selected_pm_profile_and_local_gateway(self):
        source_value = OPTIONS.get("source") or os.environ.get("HERMES_AGENT_SOURCE_ROOT", "")
        data_value = OPTIONS.get("data") or os.environ.get("HERMES_INSTALLER_DATA_ROOT", "")
        if not (source_value and data_value):
            self.skipTest("pass --hermes-source and --installer-data-root for native acceptance")
        source = Path(source_value).resolve(strict=True)
        self.assertEqual(subprocess.run(
            ["git", "-C", str(source), "rev-parse", "HEAD"], cwd=source, check=True,
            capture_output=True, text=True, timeout=3,
            env={"PATH": "/usr/bin:/bin", "GIT_CONFIG_NOSYSTEM": "1",
                 "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_OPTIONAL_LOCKS": "0"},
        ).stdout.strip(), HERMES_PIN)
        data_path = Path(data_value).resolve(strict=True)
        marker = data_path / ".hermes-installer-owned"
        self.assertTrue(marker.is_file() and not marker.is_symlink())
        self.assertEqual(marker.read_bytes(), b"schema=1\n")
        self.assertEqual(data_path.stat().st_uid, os.geteuid())
        self.assertEqual(data_path.stat().st_mode & 0o077, 0)
        profile_relative = "profiles/hermes-installer-native-" + uuid.uuid4().hex
        with tempfile.TemporaryDirectory(prefix="hermes-native-parent-") as scratch:
            root = OwnedRoot(Path(scratch) / "budget")
            root.ensure()
            old_home = os.environ.get("HOME")
            old_hermes_home = os.environ.get("HERMES_HOME")
            plugin = None
            profile_home = None
            gateway = None
            source_on_path = False
            try:
                os.environ["HOME"] = str(Path(scratch))
                os.environ["HERMES_HOME"] = str(data_path / "profiles" / "default")
                sys.path.insert(0, str(source))
                source_on_path = True
                from pm.environments import committed_venv, venv_command
                data_root = OwnedRoot(data_path)
                plugin = materialize_hermes_provider_plugin(
                    data_root, profile_relative=profile_relative, port=None, model=MODEL)
                profile_home = Path(plugin["home"])
                materialize_hermes_profile_config(
                    data_root, home_relative=profile_relative, port=int(plugin["port"]), model=MODEL)
                # This disposable native fixture is a real user plugin loaded by the pinned
                # PluginManager and invoked through AIAgent's ordinary tool-call executor.
                fixture_plugin = profile_home / "plugins" / "hermes-installer-native-fixture"
                fixture_plugin.mkdir(parents=True, mode=0o700)
                (fixture_plugin / "plugin.yaml").write_text("""name: hermes-installer-native-fixture
version: 1.0.0
description: Native dispatch fixture
""", encoding="utf-8")
                (fixture_plugin / "schemas.py").write_text('''FIXTURE_ECHO = {
    "name": "fixture_echo",
    "description": "Return synthetic fixture content",
    "parameters": {
        "type": "object",
        "properties": {"text": {"type": "string"}},
        "required": ["text"],
    },
}
''', encoding="utf-8")
                (fixture_plugin / "tools.py").write_text('''import json, os
def fixture_echo(args, **kwargs):
    marker = os.environ.get("HERMES_FIXTURE_MARKER")
    if not marker:
        raise RuntimeError("fixture marker path missing")
    with open(marker, "a", encoding="utf-8") as stream:
        stream.write("fixture_echo_invoked\n")
    return json.dumps({"result": "SYNTHETIC_PRIVATE_CANARY_7f4c"})
''', encoding="utf-8")
                (fixture_plugin / "__init__.py").write_text('''from .schemas import FIXTURE_ECHO
from .tools import fixture_echo
def register(ctx):
    ctx.register_tool(name="fixture_echo", toolset="hermes-installer-fixture",
                      schema=FIXTURE_ECHO, handler=fixture_echo)
''', encoding="utf-8")
                config_path = profile_home / "config.yaml"
                config_path.write_text(config_path.read_text(encoding="utf-8") +
                    """
plugins:
  enabled:
    - hermes-installer-native-fixture
""", encoding="utf-8")
                config_path.chmod(0o600)
                os.environ["HERMES_HOME"] = str(profile_home)
                profile_env = {
                    "HOME": str(Path(scratch)),
                    "HERMES_HOME": str(profile_home),
                    "HERMES_AGENT_SOURCE_ROOT": str(source),
                    "HERMES_RUNTIME_DIR": str(data_path / "tools"),
                    "PATH": "/usr/bin:/bin",
                    "UV_NO_CONFIG": "1",
                    "PYTHONNOUSERSITE": "1",
                    "PYTHONPATH": str(source),
                }
                selected_venv = committed_venv(source)
                self.assertIsNotNone(selected_venv, "pinned source has no committed PM environment")
                command_prefix = venv_command(source, selected_venv)
                self.assertTrue(command_prefix)
                # This is verification only. PM dependency repair is a separately completed,
                # bounded installer stage and must never be opportunistically run by acceptance.
                preparation = subprocess.run(
                    [*command_prefix, "-c",
                     "import ruamel.yaml, openai; print('PM_CORE_DEPENDENCIES_READY')"],
                    cwd=str(source), env=profile_env, capture_output=True, text=True, timeout=20,
                )
                self.assertEqual(preparation.returncode, 0,
                    "Selected profile PM environment is not ready: " + preparation.stderr[-1500:])
                self.assertIn("PM_CORE_DEPENDENCIES_READY", preparation.stdout)
                if old_hermes_home is None:
                    os.environ.pop("HERMES_HOME", None)
                else:
                    os.environ["HERMES_HOME"] = old_hermes_home
                sys.path.remove(str(source))
                source_on_path = False

                transport = RecordingTransport()
                private_fixture = Route(
                    "synthetic-private-fixture", "https://recording.invalid/v1",
                    frozenset({MODEL}), Sensitivity.PRIVATE, False, True, 0, 0)
                dispatcher = Dispatcher(
                    DispatchPolicy({"public": default_public_route(), "fixture-private": private_fixture},
                                   "public", private_route="fixture-private"),
                    BudgetLedger(root), transport,
                )
                gateway = LocalProviderGateway(
                    dispatcher, token=FIXTURE_KEY, profile_id="native-fixture-private",
                    sensitivity=Sensitivity.PRIVATE, model=MODEL, port=int(plugin["port"]),
                )
                fixture_marker = Path(scratch) / "fixture-called"
                worker_env = {
                    "HERMES_FIXTURE_MARKER": str(fixture_marker),
                    "HOME": str(Path(scratch)),
                    "HERMES_HOME": str(profile_home),
                    "HERMES_AGENT_SOURCE_ROOT": str(source),
                    "HERMES_RUNTIME_DIR": str(data_path / "tools"),
                    "PYTHONDONTWRITEBYTECODE": "1",
                    "PATH": "/usr/bin:/bin",
                    "PYTHONPATH": str(INSTALLER_SRC) + os.pathsep + str(source),
                    "HERMES_INSTALLER_DISPATCH_KEY": FIXTURE_KEY,
                }
                gateway.start()
                result = subprocess.run(
                    [*command_prefix, str(Path(__file__).resolve()), "--native-worker",
                     "--source-root=" + str(source), "--home=" + str(profile_home),
                     "--expected-sha=" + HERMES_PIN, "--model=" + MODEL],
                    env=worker_env, cwd=str(source), capture_output=True, text=True, timeout=75,
                )
                request_summaries = []
                for route_name, _model, raw_payload in transport.calls:
                    payload_summary = json.loads(raw_payload)
                    messages = payload_summary.get("messages", [])
                    request_summaries.append({
                        "response_action": transport.response_actions[len(request_summaries)]
                            if len(request_summaries) < len(transport.response_actions) else None,
                        "route": route_name,
                        "tool_names": [item.get("function", {}).get("name")
                                       for item in payload_summary.get("tools", [])
                                       if isinstance(item, dict)],
                        "tool_schemas": [
                            {"name": item.get("function", {}).get("name"),
                             "parameters": item.get("function", {}).get("parameters")}
                            for item in payload_summary.get("tools", [])
                            if isinstance(item, dict) and isinstance(item.get("function"), dict)
                            and item["function"].get("name") in {"tool_search", "tool_describe", "tool_call"}
                        ],
                        "assistant_tool_calls": [
                            {"name": call.get("function", {}).get("name"),
                             "arguments": call.get("function", {}).get("arguments")}
                            for message in messages if isinstance(message, dict)
                            and message.get("role") == "assistant"
                            for call in message.get("tool_calls", []) if isinstance(call, dict)
                        ],
                        "tool_results": [
                            {"name": item.get("name"), "tool_call_id": item.get("tool_call_id"),
                             "content": str(item.get("content", ""))[:240]}
                            for item in messages if isinstance(item, dict)
                            and item.get("role") == "tool"
                        ],
                    })
                self.assertEqual(result.returncode, 0,
                    result.stdout[-2500:] + result.stderr[-4000:]
                    + " recording_requests=" + json.dumps(request_summaries, sort_keys=True))
                self.assertTrue(fixture_marker.is_file(),
                    "native AIAgent cycle did not invoke the real fixture tool handler")
                self.assertEqual(fixture_marker.read_text(encoding="utf-8"), "fixture_echo_invoked\n")
                self.assertIn("NATIVE_DISPATCH_OK", result.stdout)
                self.assertEqual(len(transport.calls), 6)
                self.assertEqual([call[0] for call in transport.calls],
                                 ["synthetic-private-fixture"] * 6)
                self.assertEqual([call[1] for call in transport.calls], [MODEL] * 6)
                conversation_payloads = [json.loads(call[2]) for call in transport.calls[:4]]
                tool_messages = [message for message in conversation_payloads[3]["messages"]
                                 if message.get("role") == "tool"]
                self.assertTrue(any("SYNTHETIC_PRIVATE_CANARY_7f4c" in
                                    str(message.get("content", "")) for message in tool_messages))
                self.assertNotIn("SYNTHETIC_PRIVATE_CANARY_7f4c",
                                 json.dumps([call for call in transport.calls
                                             if call[0] == "openrouter-nemotron-free"]))
                direct_payloads = [json.loads(call[2]) for call in transport.calls[4:]]
                self.assertEqual([payload["messages"][0]["content"] for payload in direct_payloads],
                                 ["native primary fixture", "native auxiliary fixture"])
                self.assertEqual(transport.response_actions[:4],
                                 ["tool_search", "tool_describe", "tool_call", "final-text"])
                self.assertFalse((Path(plugin["plugin"]) / "__pycache__").exists())
                print("NATIVE_PROVIDER_PROBE_RESULT=" + json.dumps({
                    "hermes_source_commit": HERMES_PIN,
                    "profile_sensitivity": "PRIVATE",
                    "upstream": "synthetic recording transport only",
                    "agent_executor": "AIAgent.run_conversation",
                    "deferred_tools": transport.response_actions[:3],
                    "handler_invocations": 1,
                    "gateway_requests": len(transport.calls),
                    "routes": [call[0] for call in transport.calls],
                    "primary_and_title_generation_auxiliary": "recorded",
                    "external_account_or_provider_request": False,
                }, sort_keys=True))
            finally:
                if gateway is not None:
                    gateway.close()
                if profile_home is not None and profile_home.exists() and not profile_home.is_symlink():
                    marker_path = profile_home / ".hermes-installer-home-owned"
                    if marker_path.is_file() and not marker_path.is_symlink() and marker_path.read_bytes() == b"hermes-installer-managed-home-v1\n":
                        import shutil
                        shutil.rmtree(profile_home)
                if source_on_path and str(source) in sys.path:
                    sys.path.remove(str(source))
                if old_home is None:
                    os.environ.pop("HOME", None)
                else:
                    os.environ["HOME"] = old_home
                if old_hermes_home is None:
                    os.environ.pop("HERMES_HOME", None)
                else:
                    os.environ["HERMES_HOME"] = old_hermes_home


def _run_native_worker():
    def arg(name):
        prefix = "--" + name + "="
        for item in sys.argv[1:]:
            if item.startswith(prefix):
                return item[len(prefix):]
        raise SystemExit("missing worker argument " + name)

    source = Path(arg("source-root")).resolve(strict=True)
    home = Path(arg("home")).resolve(strict=True)
    expected = arg("expected-sha")
    model = arg("model")
    actual = subprocess.run(
        ["git", "-C", str(source), "rev-parse", "HEAD"], cwd=source, check=True,
        capture_output=True, text=True, timeout=3,
        env={"PATH": "/usr/bin:/bin", "GIT_CONFIG_NOSYSTEM": "1",
             "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_OPTIONAL_LOCKS": "0"},
    ).stdout.strip()
    if actual != expected:
        raise SystemExit("pinned Hermes source identity mismatch")
    os.environ["HERMES_HOME"] = str(home)
    os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
    sys.dont_write_bytecode = True

    # The selected PM generation is read-only at process boot; attach its committed
    # packages before Hermes config/provider imports, matching the supported launcher.
    from pm.environments import activate_dependencies, committed_venv
    selected_venv = committed_venv(source)
    print("NATIVE_WORKER_IDENTITY=" + json.dumps({
        "executable": sys.executable,
        "python": sys.version.split()[0],
        "prefix": sys.prefix,
        "selected_venv": str(selected_venv) if selected_venv else None,
    }, sort_keys=True))
    if selected_venv is None:
        raise SystemExit("pinned PM environment is not committed for this Hermes source")
    activate_dependencies(source)
    import importlib.util
    if importlib.util.find_spec("ruamel") is None:
        raise SystemExit("selected PM environment lacks core ruamel package after activation")

    from providers import get_provider_profile
    provider_name = "hermes-installer-dispatch"
    profile = get_provider_profile(provider_name)
    if profile is None:
        raise SystemExit("managed Hermes provider profile was not discovered")
    if profile.default_aux_model != model:
        raise SystemExit("managed Hermes provider auxiliary model mismatch")
    from hermes_cli.config import load_config_readonly
    config = load_config_readonly()
    model_config = config.get("model") if isinstance(config.get("model"), dict) else {}
    provider_configs = config.get("providers") if isinstance(config.get("providers"), dict) else {}
    print("NATIVE_CONFIG_SELECTION=" + json.dumps({
        "model_provider": model_config.get("provider"),
        "model_default": model_config.get("default"),
        "configured_provider_ids": sorted(str(key) for key in provider_configs),
        "plugin_name": profile.name,
        "plugin_aux_model": profile.default_aux_model,
    }, sort_keys=True))
    configured_provider = model_config.get("provider")
    configured_model = model_config.get("default")
    if configured_provider != provider_name or configured_model != model:
        raise SystemExit("managed Hermes config model selection is malformed")
    # Match the pinned CLI path: requested=None reads model.provider from config.
    # Do not hardcode a provider or model into AIAgent and accidentally mask
    # configuration/routing errors.
    from hermes_cli.runtime_provider import resolve_runtime_provider
    runtime = resolve_runtime_provider(requested=None, target_model=configured_model)
    if runtime.get("provider") != configured_provider:
        raise SystemExit("Hermes runtime provider resolution bypassed the managed profile")
    if not isinstance(runtime.get("base_url"), str) or not runtime["base_url"].startswith("http://127.0.0.1:"):
        raise SystemExit("Hermes runtime provider did not resolve to the owned loopback gateway")
    from run_agent import AIAgent
    from agent.iteration_budget import IterationBudget
    agent = None
    try:
        agent = AIAgent(
            base_url=runtime["base_url"], api_key=runtime.get("api_key"),
            provider=runtime["provider"], api_mode=runtime.get("api_mode"),
            model=configured_model,
            iteration_budget=IterationBudget(5),
            quiet_mode=True, enabled_toolsets=["hermes-installer-fixture"],
            skip_context_files=True, load_soul_identity=False, skip_memory=True,
            skip_background_review=True, max_iterations=5,
        )
        if agent.provider != configured_provider or agent.model != configured_model:
            raise SystemExit("Hermes native config selection mismatch: provider="
                             + str(agent.provider) + ", model=" + str(agent.model))
        tool_names = sorted(getattr(agent, "valid_tool_names", set()))
        from hermes_cli.plugins import get_plugin_manager
        plugin_rows = get_plugin_manager().list_plugins()
        fixture_plugins = [{
            key: row.get(key) for key in ("name", "enabled", "status", "source", "tools")
            if key in row
        } for row in plugin_rows if "native-fixture" in str(row.get("name", ""))]
        plugin_tool_names = sorted(getattr(get_plugin_manager(), "_plugin_tool_names", set()))
        print("NATIVE_TOOL_AVAILABILITY=" + json.dumps({
            "fixture_echo": "fixture_echo" in tool_names,
            "count": len(tool_names),
            "fixture_plugin_rows": fixture_plugins,
            "registered_plugin_tools": plugin_tool_names,
        }, sort_keys=True))
        cycle = agent.run_conversation("Use fixture_echo once and report its returned result.")
        if cycle.get("completed") is not True or "private fixture tool result received" not in str(cycle.get("final_response", "")):
            summary = {key: cycle.get(key) for key in
                       ("completed", "failed", "partial", "error", "final_response", "api_calls")
                       if key in cycle}
            if isinstance(summary.get("final_response"), str):
                summary["final_response"] = summary["final_response"][:500]
            raise SystemExit("native AIAgent tool cycle did not complete: "
                             + json.dumps(summary, sort_keys=True))
        primary = agent.client.chat.completions.create(
            model=model, messages=[{"role": "user", "content": "native primary fixture"}],
            max_tokens=24,
        )
        if primary.choices[0].message.content != "native fixture response":
            raise SystemExit("primary route response mismatch")
        from agent.auxiliary_client import call_llm
        auxiliary = call_llm(
            task="title_generation", main_runtime=None,
            messages=[{"role": "user", "content": "native auxiliary fixture"}],
            max_tokens=24, timeout=5,
        )
        if "native fixture response" not in str(auxiliary):
            raise SystemExit("auxiliary route response mismatch")
        print("NATIVE_DISPATCH_OK")
    finally:
        if agent is not None:
            agent.close()


if __name__ == "__main__":
    if "--native-worker" in sys.argv:
        _run_native_worker()
    else:
        unittest.main()
