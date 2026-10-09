from __future__ import annotations
import json, tempfile, unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from hermes_installer.cli import run
from hermes_installer.config import validate_config
from hermes_installer.results import OutcomeState

def write_config(path, data_root, state_root, components=None):
    value={"schema_version":1,"paths":{"data_root":str(data_root),"state_root":str(state_root)},
           "components":components or {"hermes_agent":True,"hermes_desktop":True}}
    path.write_text(json.dumps(value))
    return path

class CliLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.host=SimpleNamespace(supported_arm64_linux=True,package_locks=(),package_lock_probe_errors=())
    def test_dry_run_does_not_create_roots_or_start_bootstrap(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); config=write_config(root/"config.json",root/"data",root/"state")
            args=SimpleNamespace(command="install",config=config,dry_run=True)
            with patch("hermes_installer.cli.discover_host",return_value=self.host), \
                 patch("hermes_installer.cli._host_findings",return_value=()), \
                 patch("hermes_installer.cli.HermesBootstrap") as bootstrap:
                result=run(args)
            self.assertEqual(result.state,OutcomeState.READY)
            self.assertFalse((root/"data").exists())
            self.assertFalse((root/"state").exists())
            bootstrap.assert_not_called()
    def test_resume_without_durable_operation_is_denied_before_bootstrap(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); config=write_config(root/"config.json",root/"data",root/"state")
            args=SimpleNamespace(command="resume",config=config)
            with patch("hermes_installer.cli.discover_host",return_value=self.host), \
                 patch("hermes_installer.cli.HermesBootstrap") as bootstrap:
                result=run(args)
            self.assertEqual(result.state,OutcomeState.FAILED)
            self.assertIn("no installer operation",result.message)
            bootstrap.assert_not_called()
    def test_selected_config_is_durable_and_mismatch_resume_is_denied(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); config=write_config(root/"config.json",root/"data",root/"state")
            report=SimpleNamespace(commit="a"*40,generation=str(root/"data"/"generation"),
                hermes_home=str(root/"data"/"profile"),agent_ready=True,desktop_built=True,
                configuration_state="provider setup pending")
            with patch("hermes_installer.cli.discover_host",return_value=self.host), \
                 patch("hermes_installer.cli.HermesBootstrap") as bootstrap:
                bootstrap.return_value.install.return_value=report
                first=run(SimpleNamespace(command="install",config=config,dry_run=False))
                self.assertEqual(first.state,OutcomeState.PENDING)
                self.assertIn("./install.sh resume --config",first.resume_command)
                changed=write_config(root/"changed.json",root/"data",root/"state",{"hermes_agent":True,"hermes_desktop":False})
                second=run(SimpleNamespace(command="resume",config=changed))
                self.assertEqual(second.state,OutcomeState.FAILED)
                self.assertIn("differs",second.message)
                self.assertEqual(bootstrap.return_value.install.call_count,1)

if __name__=="__main__": unittest.main()
