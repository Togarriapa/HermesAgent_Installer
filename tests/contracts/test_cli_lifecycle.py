from __future__ import annotations
import json, tempfile, unittest
from pathlib import Path
import stat
import sys
import types
from types import SimpleNamespace
from unittest.mock import patch
from hermes_installer.cli import run
from hermes_installer.config import validate_config
from hermes_installer.results import OutcomeState
from hermes_installer.lifecycle import GenerationStore
from hermes_installer.state import Journal, OwnedRoot

def write_config(path, data_root, state_root, components=None):
    value={"schema_version":1,"paths":{"data_root":str(data_root),"state_root":str(state_root)},
           "components":components or {"hermes_agent":True,"hermes_desktop":True}}
    path.write_text(json.dumps(value))
    return path

class CliLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.host=SimpleNamespace(supported_arm64_linux=True,package_locks=(),package_lock_probe_errors=())
    def test_resources_status_reports_native_roots_without_claiming_target_discovery(self):
        result=run(SimpleNamespace(command="resources",action="status",config=None))
        self.assertEqual(result.state,OutcomeState.PENDING)
        finding=next(item for item in result.findings if item.code=="resources.native-crosswalk")
        self.assertEqual(finding.details["native_profile_root"],"HERMES_HOME/profiles/<profile_id>/")
        self.assertEqual(finding.details["native_skill_root"],"HERMES_HOME/skills/<skill_id>/SKILL.md")
        self.assertEqual(finding.details["target_discovery"],"not-probed-by-this-read-only-command")
        self.assertFalse(finding.details["target_verified"])
    def test_dry_run_does_not_create_roots_or_start_bootstrap(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); config=write_config(root/"config.json",root/"data",root/"state")
            args=SimpleNamespace(command="install",config=config,dry_run=True)
            with patch("hermes_installer.cli.discover_host",return_value=self.host), \
                 patch("hermes_installer.cli._host_findings",return_value=()):
                result=run(args)
            self.assertEqual(result.state,OutcomeState.READY)
            self.assertFalse((root/"data").exists())
            self.assertFalse((root/"state").exists())
    def test_resume_without_user_mode_checkpoint_uses_root_launcher_status(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); config=write_config(root/"config.json",root/"data",root/"state")
            args=SimpleNamespace(command="resume",config=config)
            with patch("hermes_installer.cli.discover_host",return_value=self.host), \
                 patch("hermes_installer.root_setup.launcher_status",return_value=SimpleNamespace(
                     state="unverified",blocker_code="ROOT_ATTESTATION_REQUIRED",
                     message="The installed launcher has not been verified by its root actor.")):
                result=run(args)
            self.assertEqual(result.state,OutcomeState.PENDING)
            self.assertIn("not been verified",result.message)
            self.assertEqual(result.resume_command,"hermes-installer status")
            self.assertFalse((root/"data").exists())
            self.assertFalse((root/"state").exists())
    def test_install_does_not_use_user_mode_bootstrap_or_create_state_roots(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); config=write_config(root/"config.json",root/"data",root/"state")
            with patch("hermes_installer.cli.discover_host",return_value=self.host), \
                 patch("hermes_installer.root_setup.launcher_status",return_value=SimpleNamespace(
                     state="unverified",blocker_code="ROOT_ATTESTATION_REQUIRED",
                     message="The installed launcher has not been verified by its root actor.")):
                first=run(SimpleNamespace(command="install",config=config,dry_run=False))
                self.assertEqual(first.state,OutcomeState.PENDING)
                self.assertEqual(first.resume_command,"hermes-installer status")
                self.assertIn("not been verified",first.message)
                self.assertFalse((root/"data").exists())
                self.assertFalse((root/"state").exists())

    def test_update_apply_stays_pending_without_root_owned_lifecycle_effects(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); config=write_config(root/"config.json",root/"data",root/"state")
            with patch("hermes_installer.cli.discover_host",return_value=self.host), \
                 patch("hermes_installer.root_setup.launcher_status",return_value=SimpleNamespace(
                     state="unverified",blocker_code="ROOT_ATTESTATION_REQUIRED",
                     message="The installed launcher has not been verified by its root actor.")):
                result=run(SimpleNamespace(command="update",action="apply",config=config))
            self.assertEqual(result.state,OutcomeState.PENDING)
            self.assertFalse((root/"data").exists())
            self.assertFalse((root/"state").exists())
            self.assertTrue(result.findings[0].details["effects_started"] is False)

    def test_install_shows_fixed_root_command_only_after_launcher_verification(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); config=write_config(root/"config.json",root/"data",root/"state")
            with patch("hermes_installer.cli.discover_host",return_value=self.host), \
                 patch("hermes_installer.root_setup.launcher_status",return_value=SimpleNamespace(
                     state="verified",blocker_code=None,
                     message="The current process matches the installed root launcher.")):
                result=run(SimpleNamespace(command="install",config=config,dry_run=False))
            self.assertEqual(result.state,OutcomeState.PENDING)
            self.assertEqual(result.resume_command,"sudo -- hermes-installer-root-setup install")
            self.assertFalse((root/"data").exists())
            self.assertFalse((root/"state").exists())

    def test_update_check_verifies_active_generation_without_creating_state(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); data=OwnedRoot(root/"data"); data.ensure()
            state=OwnedRoot(root/"state"); state.ensure()
            journal=Journal(state.path("journal.sqlite3"))
            store=GenerationStore(data,journal)
            generation=store.stage("agent-v1",{"bin/hermes":b"pinned fixture"})
            store.activate(generation,health_check=lambda item:item.files==1)
            config=write_config(root/"config.json",data.root,state.root)
            with patch("hermes_installer.cli.discover_host",return_value=self.host):
                result=run(SimpleNamespace(command="update",action="check",config=config))
            self.assertEqual(result.state,OutcomeState.PENDING)
            self.assertEqual(result.findings[0].details["active_generation"],"agent-v1")
            self.assertFalse(result.findings[0].details["candidate_available"])
            self.assertEqual(store.current().identity,"agent-v1")

    def test_data_backup_and_restore_preserve_conflicts_and_journal_results(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); data=OwnedRoot(root/"data"); data.ensure()
            state=OwnedRoot(root/"state"); state.ensure()
            journal=Journal(state.path("journal.sqlite3"))
            existing=data.path("profiles/default/SOUL.md")
            missing=data.path("overlays/memory.md")
            existing.parent.mkdir(parents=True); missing.parent.mkdir(parents=True)
            existing.write_bytes(b"user version one")
            missing.write_bytes(b"restore this memory")
            config=write_config(root/"config.json",data.root,state.root)
            with patch("hermes_installer.cli.discover_host",return_value=self.host):
                backed=run(SimpleNamespace(command="data",action="backup",config=config,
                    include_database=True,restore_database=False,overwrite=False))
            self.assertEqual(backed.state,OutcomeState.READY)
            backup=Path(backed.findings[0].details["backup"])
            existing.write_bytes(b"new user edit")
            missing.unlink()
            with patch("hermes_installer.cli.discover_host",return_value=self.host):
                restored=run(SimpleNamespace(command="data",action="restore",config=config,
                    backup=backup,overwrite=False,restore_database=True))
            self.assertEqual(restored.state,OutcomeState.PENDING)
            self.assertEqual(existing.read_bytes(),b"new user edit")
            self.assertEqual(missing.read_bytes(),b"restore this memory")
            self.assertEqual(restored.findings[0].details["conflicts_preserved"],
                ["data/profiles/default/SOUL.md"])
            self.assertTrue(Journal(state.path("journal.sqlite3")).events("lifecycle:restore:"+backup.name))

    def test_data_uninstall_waits_for_verified_service_and_generation_shutdown(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); data=OwnedRoot(root/"data"); data.ensure()
            state=OwnedRoot(root/"state"); state.ensure()
            journal=Journal(state.path("journal.sqlite3"))
            generation=GenerationStore(data,journal).stage("agent-v1",{"bin/hermes":b"pinned fixture"})
            GenerationStore(data,journal).activate(generation,health_check=lambda item:True)
            journal.record_owned("service","hermes-agent.service","active")
            config=write_config(root/"config.json",data.root,state.root)
            with patch("hermes_installer.cli.discover_host",return_value=self.host):
                result=run(SimpleNamespace(command="data",action="uninstall",config=config))
            self.assertEqual(result.state,OutcomeState.PENDING)
            self.assertTrue(generation.exists())
            self.assertTrue(data.path("active-generation.json").exists())

    def test_setup_noninteractive_uses_private_lease_and_writes_new_config(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); state=root/"state"; config=root/"input.json"; output=root/"result.json"
            config.write_text(json.dumps({"schema_version":1,"paths":{"state_root":str(state),
                "data_root":str(root/"data")},"components":{},"privacy":{"additional_metered_budget":0}}))
            result=run(SimpleNamespace(command="setup",config=config,non_interactive=True,
                save_config=output,json=True))
            self.assertEqual(result.state,OutcomeState.READY)
            self.assertEqual(stat.S_IMODE(output.stat().st_mode),0o600)
            self.assertEqual(json.loads(output.read_text())["schema_version"],1)
            self.assertEqual(Journal(state/"journal.sqlite3").operation("installer:setup-command")["status"],"ready")
            again=run(SimpleNamespace(command="setup",config=config,non_interactive=True,
                save_config=output,json=True))
            self.assertEqual(again.state,OutcomeState.FAILED)
            self.assertEqual(json.loads(output.read_text())["schema_version"],1)

    def test_remote_setup_enrolls_owned_access_only_when_explicitly_selected(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); config=root/"input.json"
            config.write_text(json.dumps({"schema_version":1,"paths":{"state_root":str(root/"state")}}))
            wizard = SimpleNamespace(state="pending", selected_components={"remote_desktop":True},
                config={"schema_version":1,"paths":{"state_root":str(root/"state")},
                    "remote_desktop":{"hostname":"desktop.example.test",
                        "allowed_emails":["owner@example.test"],
                        "management_token_ref":"file:///private/token-ref",
                        "policy_read_token_ref":"file:///private/read-ref"}},
                message="Remote setup pending", resume_command="hermes-installer setup",
                next_steps=(), account_states={"remote_desktop":"pending"}, exit_code=4)
            calls=[]
            enrollment_state={"value":"pending"}
            enrollment_module=types.ModuleType("hermes_installer.remote.enrollment")
            def enroll(received_config, journal, **kwargs):
                calls.append((received_config, journal, kwargs))
                return SimpleNamespace(state=enrollment_state["value"], access_state="ready",
                    policy_read_state="verified", route_state="pending", phase="access-verified",
                    message="Access is verified; route activation awaits an enrolled origin.",
                    next_steps=("Enroll the protected origin, then resume install.",),
                    resource_ids={"access_app":"owned-app-id"},
                    component_installable=enrollment_state["value"] == "pending")
            enrollment_module.run_remote_desktop_enrollment=enroll
            with patch.dict(sys.modules, {"hermes_installer.remote.enrollment":enrollment_module}), \
                 patch("hermes_installer.setup_wizard.run_setup_wizard", return_value=wizard):
                result=run(SimpleNamespace(command="setup",config=config,non_interactive=True,
                    save_config=None,json=True))
                self.assertEqual(Journal(root/"state"/"journal.sqlite3").operation("installer:setup-command")["status"],"pending")
                enrollment_state["value"]="failed"
                failed=run(SimpleNamespace(command="setup",config=config,non_interactive=True,
                    save_config=None,json=True))
            self.assertEqual(len(calls),2)
            self.assertIsInstance(calls[0][1],Journal)
            self.assertFalse(calls[0][2]["activate_route"])
            self.assertEqual(result.state,OutcomeState.PENDING)
            self.assertEqual(result.message,"Access is verified; route activation awaits an enrolled origin.")
            self.assertEqual(result.findings[0].details["account_states"]["remote_desktop_access"],"ready")
            self.assertEqual(result.findings[0].details["account_states"]["remote_desktop_policy_read"],"verified")
            self.assertTrue(result.findings[0].details["config"]["components"]["remote_desktop"])
            self.assertEqual(len(calls),2)
            self.assertEqual(failed.state,OutcomeState.FAILED)
            self.assertEqual(failed.exit_code,1)

    def test_interactive_setup_without_tty_has_no_filesystem_effect(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); config=write_config(root/"config.json",root/"data",root/"state")
            with patch("hermes_installer.cli.sys.stdin.isatty",return_value=False):
                result=run(SimpleNamespace(command="setup",config=config,non_interactive=False,
                    save_config=None,json=False))
            self.assertEqual(result.state,OutcomeState.FAILED)
            self.assertFalse((root/"state").exists())

    def test_select_memory_routes_through_locked_configuration_adapter(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); config=write_config(root/"config.json",root/"data",root/"state")
            saved=root/"selected.json"
            adapter=SimpleNamespace(OPTIONS={"openviking": object()})
            def configure_noninteractive(current, **kwargs):
                from hermes_installer.setup_wizard import AdapterResult
                return AdapterResult("pending", "Memory runtime awaits protected enrollment.", {})
            adapter.configure_noninteractive=configure_noninteractive
            with patch("hermes_installer.cli.discover_host",return_value=self.host), \
                 patch("hermes_installer.configuration_cli.build_setup_adapters",return_value={"memory":adapter}):
                result=run(SimpleNamespace(command="select-memory",choice="openviking",config=config,
                    save_config=saved))
            self.assertEqual(result.state,OutcomeState.PENDING)
            self.assertEqual(result.findings[0].details["selected_memory_provider"],"openviking")
            operation=Journal(root/"state"/"journal.sqlite3").operation("installer:setup")
            self.assertEqual(operation["payload"]["setup_state"]["memory"]["selections"]["provider_id"],"openviking")
            self.assertEqual(stat.S_IMODE(saved.stat().st_mode),0o600)
            self.assertFalse(json.loads(saved.read_text())["components"]["memory"])

if __name__=="__main__": unittest.main()
