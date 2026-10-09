"""Native Hermes provider dispatch acceptance using an external PM worker.

The parent owns the recording gateway and disposable profile so a Hermes PM
bootstrap re-exec cannot destroy the listener or bypass cleanup.
"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
import uuid
from pathlib import Path

INSTALLER_SRC = Path(__file__).resolve().parents[2] / "src"
sys.path.insert(0, str(INSTALLER_SRC))

from hermes_installer.policy import BudgetLedger, DispatchPolicy, Dispatcher, ProviderResponse, Sensitivity, default_public_route
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

    def __call__(self, route, model, payload, *, output_token_limit, timeout, trace_id, cancelled=lambda: False):
        self.calls.append((route.name, model, payload))
        import json
        body = json.dumps({
            "id": "chatcmpl-native-fixture", "object": "chat.completion", "created": 1,
            "model": MODEL,
            "choices": [{"index": 0, "message": {"role": "assistant", "content": "native fixture response"}, "finish_reason": "stop"}],
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
            # Keep HOME outside the shared data root while materializing the
            # exact profile HERMES_HOME will use in the isolated worker.
            old_home = os.environ.get("HOME")
            old_hermes_home = os.environ.get("HERMES_HOME")
            os.environ["HOME"] = str(Path(scratch))
            os.environ["HERMES_HOME"] = str(data_path / "profiles" / "default")
            sys.path.insert(0, str(source))
            try:
                from pm.environments import committed_venv, venv_command
                data_root = OwnedRoot(data_path)
                plugin = materialize_hermes_provider_plugin(
                    data_root, profile_relative=profile_relative, port=None, model=MODEL)
                profile_home = Path(plugin["home"])
                materialize_hermes_profile_config(
                    data_root, home_relative=profile_relative, port=int(plugin["port"]), model=MODEL)
                # Reconcile dependencies only through Hermes' pinned PM runtime
                # path; runtime-only avoids publishing shell config or launchers.
                prep_env = {
                    "HOME": str(Path(scratch)),
                    "HERMES_HOME": str(profile_home),
                    "HERMES_AGENT_SOURCE_ROOT": str(source),
                    "PATH": "/usr/bin:/bin",
                    "UV_NO_CONFIG": "1",
                    "PYTHONNOUSERSITE": "1",
                }
                preparation = subprocess.run(
                    [str(source / "scripts" / "run-in-hermes-env"), "python3", "-c",
                     "import ruamel.yaml, openai; print('PM_CORE_DEPENDENCIES_READY')"],
                    cwd=str(source), env=prep_env, capture_output=True, text=True, timeout=600,
                )
                self.assertEqual(preparation.returncode, 0,
                    "Pinned PM runtime dependency preparation failed: " + preparation.stderr[-3000:])
                self.assertIn("PM_CORE_DEPENDENCIES_READY", preparation.stdout)
                selected_venv = committed_venv(source)
                self.assertIsNotNone(selected_venv, "pinned source has no committed PM environment")
                command_prefix = venv_command(source, selected_venv)
                self.assertTrue(command_prefix)
            finally:
                if old_home is None:
                    os.environ.pop("HOME", None)
                else:
                    os.environ["HOME"] = old_home
                if old_hermes_home is None:
                    os.environ.pop("HERMES_HOME", None)
                else:
                    os.environ["HERMES_HOME"] = old_hermes_home
                sys.path.remove(str(source))
            transport = RecordingTransport()
            dispatcher = Dispatcher(
                DispatchPolicy({"public": default_public_route()}, "public"),
                BudgetLedger(root), transport,
            )
            gateway = LocalProviderGateway(
                dispatcher, token=FIXTURE_KEY, profile_id="native-fixture-public",
                sensitivity=Sensitivity.PUBLIC,
                model=MODEL, port=int(plugin["port"]),
            )
            worker = Path(__file__).with_name("hermes_dispatch_worker.py")
            env = {
                "HOME": str(Path(scratch)),
                "HERMES_HOME": str(profile_home),
                "HERMES_AGENT_SOURCE_ROOT": str(source),
                "PYTHONDONTWRITEBYTECODE": "1",
                "PATH": "/usr/bin:/bin",
                "PYTHONPATH": str(INSTALLER_SRC) + os.pathsep + str(source),
                "HERMES_INSTALLER_DISPATCH_KEY": FIXTURE_KEY,
            }
            try:
                gateway.start()
                result = subprocess.run(
                    [*command_prefix, str(worker), "--source-root=" + str(source),
                     "--home=" + str(profile_home), "--expected-sha=" + HERMES_PIN,
                     "--model=" + MODEL],
                    env=env, cwd=str(source), capture_output=True, text=True, timeout=75,
                )
                self.assertEqual(result.returncode, 0, result.stdout[-2000:] + result.stderr[-4000:])
                self.assertIn("NATIVE_DISPATCH_OK", result.stdout)
                self.assertEqual(len(transport.calls), 2)
                self.assertEqual([call[0] for call in transport.calls], ["openrouter-nemotron-free"] * 2)
                self.assertEqual([call[1] for call in transport.calls], [MODEL, MODEL])
                import json
                self.assertEqual([json.loads(call[2])["messages"][0]["content"] for call in transport.calls],
                                 ["native primary fixture", "native auxiliary fixture"])
                self.assertFalse((Path(plugin["plugin"]) / "__pycache__").exists())
            finally:
                gateway.close()
                marker_path = profile_home / ".hermes-installer-home-owned"
                self.assertTrue(marker_path.is_file() and not marker_path.is_symlink())
                self.assertEqual(marker_path.read_bytes(), b"hermes-installer-managed-home-v1\n")
                import shutil
                shutil.rmtree(profile_home)


if __name__ == "__main__":
    unittest.main()
