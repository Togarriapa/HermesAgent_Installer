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
    def __init__(self): self.calls=[]
    def __call__(self,args,*,timeout,capture=False):
        self.calls.append((args,timeout,capture))
        if capture:
            return 0,json.dumps({"protocol_version":1,"stages":[{"name":n} for n in EXPECTED_STAGES]}).encode()
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
            stages=[call[0][call[0].index("--stage")+1] for call in runner.calls if "--stage" in call[0]]
            self.assertEqual(stages,list(EXPECTED_STAGES))
            self.assertTrue(all("--non-interactive" in call[0] for call in runner.calls if "--stage" in call[0]))
            self.assertTrue(all("--skip-browser" in call[0] and "--skip-computer-use" in call[0] for call in runner.calls if "--stage" in call[0]))
            self.assertEqual(journal.operation("hermes-agent:"+HERMES_COMMIT)["status"],"complete")
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
