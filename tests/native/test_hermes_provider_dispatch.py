"""Native selected-Hermes primary and auxiliary dispatch acceptance probe.

Run only in the pinned Hermes PM interpreter with HERMES_AGENT_SOURCE_ROOT set
to the selected upstream checkout. All upstream responses terminate at a
recording transport; no provider account, credential, or external request is used.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
import shutil
import uuid
from pathlib import Path

# Hermes bootstrap may re-exec this test after dependency preparation. Derive
# our own source path before importing the installer, even with a sanitized env.
INSTALLER_SRC = Path(__file__).resolve().parents[2] / "src"
sys.path.insert(0, str(INSTALLER_SRC))

from hermes_installer.policy import BudgetLedger, DispatchPolicy, Dispatcher, ProviderResponse, Sensitivity, default_public_route
from hermes_installer.provider_gateway import (
    LOCAL_KEY_ENV, LOCAL_PROVIDER_NAME, LocalProviderGateway,
    materialize_hermes_profile_config, materialize_hermes_provider_plugin,
)
from hermes_installer.state import OwnedRoot

MODEL = "nvidia/nemotron-3-ultra-550b-a55b:free"
HERMES_PIN = "7085fbf7753266fc4943c55ac04926186bc90005"
FIXTURE_KEY = "native-local-fixture-key-0123456789abcdef"


class RecordingTransport:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, bytes]] = []

    def __call__(self, route, model, payload, *, output_token_limit, timeout, trace_id, cancelled=lambda: False):
        self.calls.append((route.name, model, payload))
        body = json.dumps({
            "id": "chatcmpl-native-fixture",
            "object": "chat.completion",
            "created": 1,
            "model": MODEL,
            "choices": [{"index": 0, "message": {"role": "assistant", "content": "native fixture response"}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 5, "completion_tokens": 3, "total_tokens": 8},
        }, separators=(",", ":")).encode("utf-8")
        return ProviderResponse(200, body, {"Content-Type": "application/json"}, 5, 3)


class NativeHermesProviderDispatchTests(unittest.TestCase):
    def test_real_primary_and_auxiliary_entrypoints_route_through_local_gate(self):
        source_value = os.environ.get("HERMES_AGENT_SOURCE_ROOT", "")
        if not source_value:
            self.skipTest("set HERMES_AGENT_SOURCE_ROOT to the exact selected Hermes source checkout")
        source = Path(source_value).resolve(strict=True)
        commit = subprocess.run(
            ["git", "-C", str(source), "rev-parse", "HEAD"],
            cwd=source, check=True, capture_output=True, text=True,
            env={"PATH": "/usr/bin:/bin", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_OPTIONAL_LOCKS": "0"},
            timeout=3,
        ).stdout.strip()
        self.assertEqual(commit, HERMES_PIN, "native source must match the selected immutable Hermes pin")

        data_value = os.environ.get("HERMES_INSTALLER_DATA_ROOT", "")
        if not data_value:
            # Hermes' dependency bootstrap may sanitize custom environment keys
            # before re-executing this test. Derive the expected data root only
            # from the exact pinned source checkout, then verify its ownership
            # marker before any managed-profile write.
            data_root_candidate = source.parents[1]
            marker = data_root_candidate / ".hermes-installer-owned"
            if (data_root_candidate.name != "data" or marker.is_symlink()
                    or not marker.is_file() or marker.read_bytes() != b"schema=1\n"
                    or data_root_candidate.stat().st_uid != os.geteuid()
                    or data_root_candidate.stat().st_mode & 0o077):
                self.skipTest("pinned source has no validated installer-owned data root")
            data_value = str(data_root_candidate)
        original_environment = os.environ.copy()
        inserted = False
        agent = None
        with tempfile.TemporaryDirectory(prefix="hermes-native-dispatch-") as temporary:
            root = OwnedRoot(Path(temporary) / "owned")
            installer_src = Path(__file__).resolve().parents[2] / "src"
            self.assertTrue((installer_src / "hermes_installer").is_dir())
            root.ensure()
            data_root_path = Path(data_value).resolve(strict=True)
            marker = data_root_path / ".hermes-installer-owned"
            if (data_root_path.is_symlink() or marker.is_symlink()
                    or not marker.is_file() or marker.read_bytes() != b"schema=1\\n"
                    or data_root_path.stat().st_uid != os.geteuid()
                    or data_root_path.stat().st_mode & 0o077):
                self.skipTest("installer data root ownership marker is invalid")
            data_root = OwnedRoot(data_root_path)
            # OwnedRoot rejects an install root that contains the current HOME.
            # Use the separate disposable probe root for process HOME; HERMES_HOME
            # remains the validated profile below.
            os.environ["HOME"] = str(root.root)
            profile_relative = "profiles/hermes-installer-native-probe"
            plugin = materialize_hermes_provider_plugin(data_root, profile_relative=profile_relative, port=None, model=MODEL)
            home = Path(plugin["home"])
            materialize_hermes_profile_config(data_root, home_relative=profile_relative, port=int(plugin["port"]), model=MODEL)
            transport = RecordingTransport()
            dispatcher = Dispatcher(
                DispatchPolicy({"public": default_public_route()}, "public"),
                BudgetLedger(root), transport,
            )
            gateway = LocalProviderGateway(
                dispatcher, token=FIXTURE_KEY, profile_id="native-fixture-public",
                sensitivity=Sensitivity.PUBLIC, model=MODEL, port=int(plugin["port"]),
            )
            os.environ.clear()
            os.environ.update({
                "HOME": str(home),
                "HERMES_HOME": str(home),
                "HERMES_AGENT_SOURCE_ROOT": str(source),
                "HERMES_INSTALLER_DATA_ROOT": str(data_root.root),
                LOCAL_KEY_ENV: FIXTURE_KEY,
                "PYTHONDONTWRITEBYTECODE": "1",
                "PATH": "/usr/bin:/bin",
                # Hermes bootstrap may re-exec after imports. Preserve only the
                # pinned source/data identities and this installer module path.
                "PYTHONPATH": str(installer_src) + os.pathsep + str(source),
            })
            sys.dont_write_bytecode = True
            sys.path.insert(0, str(source))
            inserted = True
            try:
                # Imports that can invoke PM bootstrap happen before a live
                # fixture listener exists. The profile path is deterministic so
                # a bootstrap re-exec reconciles the same owned fixture.
                from providers import get_provider_profile
                from run_agent import AIAgent
                from agent.auxiliary_client import call_llm

                profile = get_provider_profile(LOCAL_PROVIDER_NAME)
                self.assertIsNotNone(profile, "Hermes native plugin discovery must load the managed ProviderProfile")
                self.assertEqual(profile.base_url, f"http://127.0.0.1:{plugin['port']}/v1")
                self.assertEqual(profile.default_aux_model, MODEL)

                gateway.start()
                agent = AIAgent(
                    quiet_mode=True,
                    enabled_toolsets=[], skip_context_files=True, load_soul_identity=False,
                    skip_memory=True, skip_background_review=True,
                )
                self.assertEqual(agent.provider, LOCAL_PROVIDER_NAME)
                self.assertEqual(agent.model, MODEL)
                primary = agent.client.chat.completions.create(
                    model=MODEL, messages=[{"role": "user", "content": "native primary fixture"}],
                    max_tokens=24,
                )
                self.assertEqual(primary.choices[0].message.content, "native fixture response")

                auxiliary = call_llm(
                    task="title_generation",
                    main_runtime=None,
                    messages=[{"role": "user", "content": "native auxiliary fixture"}],
                    max_tokens=24, timeout=5,
                )
                self.assertIn("native fixture response", str(auxiliary))
                self.assertEqual(len(transport.calls), 2)
                self.assertEqual([call[0] for call in transport.calls], ["openrouter-nemotron-free"] * 2)
                self.assertEqual([call[1] for call in transport.calls], [MODEL, MODEL])
                self.assertEqual(
                    [json.loads(call[2])["messages"][0]["content"] for call in transport.calls],
                    ["native primary fixture", "native auxiliary fixture"],
                )
                self.assertFalse((Path(plugin["plugin"]) / "__pycache__").exists(),
                                 "managed launcher must suppress plugin bytecode side effects")
            finally:
                if agent is not None:
                    agent.close()
                gateway.close()
                marker = home / ".hermes-installer-home-owned"
                if home.exists():
                    if (home.parent.resolve() != data_root.path("profiles").resolve()
                            or marker.is_symlink()
                            or marker.read_bytes() != b"hermes-installer-managed-home-v1\n"):
                        raise AssertionError("Refusing to remove a profile without the exact disposable fixture marker")
                    shutil.rmtree(home)
                if inserted:
                    sys.path.remove(str(source))
                os.environ.clear()
                os.environ.update(original_environment)


if __name__ == "__main__":
    unittest.main()
