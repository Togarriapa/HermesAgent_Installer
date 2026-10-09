from __future__ import annotations
import hashlib, json, tempfile, unittest
from pathlib import Path
from hermes_installer.bootstrap import (BootstrapError, EXPECTED_STAGES, HERMES_COMMIT,
    HermesBootstrap, git_blob_sha1)
from hermes_installer.state import Journal, OwnedRoot

SCRIPT=b"#!/usr/bin/env bash\necho fixture\n"
def good_network(*args, **kwargs):
    from hermes_installer.network import HTTPResult
    return HTTPResult(200, {}, SCRIPT)
class FakeNetwork:
    def request(self,*args,**kwargs):
        from hermes_installer.network import HTTPResult
        return HTTPResult(200, {}, SCRIPT)
class FakeRunner:
    def __init__(self, fail_once=None): self.calls=[]; self.fail_once=fail_once
    def __call__(self,args,*,timeout,capture=False):
        self.calls.append((args,timeout,capture))
        if capture:
            return 0,json.dumps({"protocol_version":1,"stages":[{"name":n} for n in EXPECTED_STAGES]}).encode()
        if "--stage" in args:
            stage=args[args.index("--stage")+1]
            directory=Path(args[args.index("--dir")+1])
            if stage=="repository":
                (directory/".git").mkdir(parents=True)
                (directory/".git"/"HEAD").write_text(HERMES_COMMIT)
            if stage=="complete":
                (directory/".hermes"/"bin").mkdir(parents=True)
                (directory/".hermes"/"bin"/"hermes").write_text("#!/bin/sh\\n")
                (directory/".hermes-bootstrap-complete").write_text(json.dumps({"pinnedCommit":HERMES_COMMIT}))
            if stage=="products" and self.fail_once==stage:
                self.fail_once=None
                return 1,b""
            if stage=="products":
                (directory/"apps"/"desktop"/"release"/"linux-arm64-unpacked").mkdir(parents=True)
        return 0,b""

class BootstrapTests(unittest.TestCase):
    def test_git_blob_identity_is_content_sensitive(self):
        self.assertEqual(git_blob_sha1(SCRIPT),hashlib.sha1(b"blob "+str(len(SCRIPT)).encode()+b"\0"+SCRIPT).hexdigest())
        self.assertNotEqual(git_blob_sha1(SCRIPT),git_blob_sha1(SCRIPT+b"x"))
    def test_only_exact_official_manifest_stages_are_accepted_and_journaled(self):
        with tempfile.TemporaryDirectory() as td:
            data=OwnedRoot(Path(td)/"data");data.ensure()
            state_root=OwnedRoot(Path(td)/"state");state_root.ensure()
            journal=Journal(state_root.path("journal.sqlite3"))
            runner=FakeRunner()
            bootstrap=HermesBootstrap(data,journal,network=FakeNetwork(),runner=runner,expected_script_blob=git_blob_sha1(SCRIPT))
            bootstrap.install(include_desktop=True)
            first_stage_count=sum(1 for call in runner.calls if "--stage" in call[0])
            bootstrap.install(include_desktop=True)
            stages=[call[0][call[0].index("--stage")+1] for call in runner.calls if "--stage" in call[0]]
            self.assertEqual(sum(1 for call in runner.calls if "--stage" in call[0]),first_stage_count)
            self.assertEqual(stages,list(EXPECTED_STAGES))
            self.assertTrue(all("--non-interactive" in call[0] for call in runner.calls if "--stage" in call[0]))
            self.assertTrue(all("--skip-browser" in call[0] and "--skip-computer-use" in call[0] for call in runner.calls if "--stage" in call[0]))
            self.assertEqual(journal.operation("hermes-agent:"+HERMES_COMMIT)["status"],"complete")
    def test_failed_stage_can_resume_and_skip_verified_stages(self):
        with tempfile.TemporaryDirectory() as td:
            data=OwnedRoot(Path(td)/"data");data.ensure(); state_root=OwnedRoot(Path(td)/"state");state_root.ensure()
            journal=Journal(state_root.path("journal.sqlite3")); runner=FakeRunner(fail_once="products")
            boot=HermesBootstrap(data,journal,network=FakeNetwork(),runner=runner,expected_script_blob=git_blob_sha1(SCRIPT))
            with self.assertRaisesRegex(BootstrapError,"stage products"):
                boot.install()
            prior=sum(1 for call in runner.calls if "--stage" in call[0])
            report=boot.install()
            self.assertTrue(report.agent_ready)
            second=[call[0][call[0].index("--stage")+1] for call in runner.calls[prior:] if "--stage" in call[0]]
            self.assertEqual(second,["products","setup","gateway","complete"])
    def test_changed_pinned_source_head_is_preserved_and_denied(self):
        with tempfile.TemporaryDirectory() as td:
            data=OwnedRoot(Path(td)/"data");data.ensure(); state_root=OwnedRoot(Path(td)/"state");state_root.ensure()
            runner=FakeRunner(); journal=Journal(state_root.path("journal.sqlite3"))
            boot=HermesBootstrap(data,journal,network=FakeNetwork(),runner=runner,expected_script_blob=git_blob_sha1(SCRIPT))
            boot.install()
            head=boot.install_dir/".git"/"HEAD"; head.write_text("0"*40)
            with self.assertRaisesRegex(Exception,"resumable"):
                boot.install()
            self.assertEqual(head.read_text(),"0"*40)
    def test_agent_only_install_can_add_desktop_later(self):
        with tempfile.TemporaryDirectory() as td:
            data=OwnedRoot(Path(td)/"data");data.ensure(); state_root=OwnedRoot(Path(td)/"state");state_root.ensure()
            runner=FakeRunner(); boot=HermesBootstrap(data,Journal(state_root.path("journal.sqlite3")),network=FakeNetwork(),runner=runner,expected_script_blob=git_blob_sha1(SCRIPT))
            boot.install(include_desktop=False)
            desktop_before=sum(1 for call in runner.calls if "include-desktop" in call[0])
            report=boot.install(include_desktop=True)
            desktop_after=sum(1 for call in runner.calls if "include-desktop" in call[0])
            self.assertTrue(report.desktop_built)
            self.assertEqual(desktop_after,desktop_before+1)
    def test_manifest_change_stops_before_any_stage(self):
        with tempfile.TemporaryDirectory() as td:
            data=OwnedRoot(Path(td)/"data");data.ensure()
            state_root=OwnedRoot(Path(td)/"state");state_root.ensure()
            class BadRunner(FakeRunner):
                def __call__(self,args,*,timeout,capture=False):
                    self.calls.append((args,timeout,capture))
                    return (0,json.dumps({"protocol_version":1,"stages":[{"name":"other"}]}).encode()) if capture else (0,b"")
            runner=BadRunner()
            boot=HermesBootstrap(data,Journal(state_root.path("journal.sqlite3")),network=FakeNetwork(),runner=runner,expected_script_blob=git_blob_sha1(SCRIPT))
            with self.assertRaisesRegex(BootstrapError,"stage protocol changed"): boot.install()
            self.assertFalse(any("--stage" in call[0] for call in runner.calls))
    def test_modified_script_is_rejected_before_execution(self):
        with tempfile.TemporaryDirectory() as td:
            data=OwnedRoot(Path(td)/"data");data.ensure()
            state_root=OwnedRoot(Path(td)/"state");state_root.ensure()
            boot=HermesBootstrap(data,Journal(state_root.path("journal.sqlite3")),network=FakeNetwork(),runner=FakeRunner())
            with self.assertRaisesRegex(BootstrapError,"object identity"): boot.prepare()
            self.assertFalse(boot.script_path.exists())

if __name__ == "__main__": unittest.main()
