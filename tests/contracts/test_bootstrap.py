from __future__ import annotations
import hashlib, json, os, subprocess, sys, tempfile, threading, time, unittest
from pathlib import Path
from hermes_installer.bootstrap import (BootstrapError, EXPECTED_STAGES, HERMES_COMMIT,
    HermesBootstrap, git_blob_sha1, _stop_group)
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
    def __init__(self, fail_once=None, partial_repository=False): self.calls=[]; self.fail_once=fail_once; self.partial_repository=partial_repository
    def __call__(self,args,*,timeout,capture=False):
        self.calls.append((args,timeout,capture))
        if capture and "--manifest" in args:
            return 0,json.dumps({"protocol_version":1,"stages":[{"name":n} for n in EXPECTED_STAGES]}).encode()
        if "--stage" in args:
            stage=args[args.index("--stage")+1]
            directory=Path(args[args.index("--dir")+1])
            if stage=="repository":
                if directory.exists() and any(directory.iterdir()):
                    head=directory/".git"/"HEAD"
                    if not head.is_file() or head.read_text()!=HERMES_COMMIT:
                        directory.rename(directory.with_name(directory.name+".broken-fixture"))
                    else:
                        return 77,b""
                if self.fail_once==stage:
                    self.fail_once=None
                    if self.partial_repository:
                        (directory/".git").mkdir(parents=True,exist_ok=True)
                    return 1,b""
                directory.mkdir(parents=True,exist_ok=True)
                (directory/".git").mkdir(parents=True)
                (directory/".git"/"HEAD").write_text(HERMES_COMMIT)
            if stage=="complete":
                (directory/".hermes"/"bin").mkdir(parents=True)
                (directory/".hermes"/"bin"/"hermes").write_text("#!/bin/sh\necho Hermes fixture version\n")
                (directory/".hermes"/"bin"/"hermes").chmod(0o700)
                (directory/".hermes-bootstrap-complete").write_text(json.dumps({"pinnedCommit":HERMES_COMMIT}))
            if stage=="products" and self.fail_once==stage:
                self.fail_once=None
                return 1,b""
            if stage=="products" and "--include-desktop" in args:
                (directory/"apps"/"desktop"/"release"/"linux-arm64-unpacked").mkdir(parents=True)
        return 0,b""

def fake_desktop(data):
    def build(*, timeout):
        desktop=data.path("generations/hermes-agent-"+HERMES_COMMIT[:12]+"/apps/desktop")
        dist=desktop/"dist"
        dist.mkdir(parents=True,exist_ok=True); (dist/"index.html").write_text("<html>"+"x"*200+"</html>")
        package=desktop/"release/linux-arm64-unpacked"
        (package/"resources").mkdir(parents=True,exist_ok=True)
        (package/"resources/app.asar").write_bytes(b"x"*2048)
        executable=package/"Hermes"
        executable.write_text("#!/bin/sh\nexit 0\n"); executable.chmod(0o755)
        (package/"chrome-sandbox").write_bytes(b"sandbox fixture")
        return 0,b""
    return build

class BootstrapTests(unittest.TestCase):
    @unittest.skipUnless(hasattr(os, "waitid"), "process custody probe requires Linux child inspection")
    def test_actual_agent_version_probe_requires_pinned_head_and_successful_entrypoint(self):
        with tempfile.TemporaryDirectory() as td:
            data=OwnedRoot(Path(td)/"data");data.ensure(); state_root=OwnedRoot(Path(td)/"state");state_root.ensure()
            boot=HermesBootstrap(data,Journal(state_root.path("journal.sqlite3")),network=FakeNetwork(),runner=FakeRunner(),expected_script_blob=git_blob_sha1(SCRIPT))
            boot.install_dir.mkdir(parents=True)
            (boot.install_dir/".git").mkdir(); (boot.install_dir/".git"/"HEAD").write_text(HERMES_COMMIT)
            bin_dir=boot.install_dir/".hermes"/"bin";bin_dir.mkdir(parents=True)
            hermes=bin_dir/"hermes";hermes.write_text("#!/bin/sh\necho Hermes 1.0\n");hermes.chmod(0o700)
            self.assertTrue(boot._verify_agent_runtime())
            hermes.write_text("#!/bin/sh\nexit 1\n");hermes.chmod(0o700)
            self.assertFalse(boot._verify_agent_runtime())
    def test_git_blob_identity_is_content_sensitive(self):
        self.assertEqual(git_blob_sha1(SCRIPT),hashlib.sha1(b"blob "+str(len(SCRIPT)).encode()+b"\0"+SCRIPT).hexdigest())
        self.assertNotEqual(git_blob_sha1(SCRIPT),git_blob_sha1(SCRIPT+b"x"))
    def test_only_exact_official_manifest_stages_are_accepted_and_journaled(self):
        with tempfile.TemporaryDirectory() as td:
            data=OwnedRoot(Path(td)/"data");data.ensure()
            state_root=OwnedRoot(Path(td)/"state");state_root.ensure()
            journal=Journal(state_root.path("journal.sqlite3"))
            runner=FakeRunner()
            def desktop_build(*,timeout):
                out=Path(runner.calls[0][0][runner.calls[0][0].index("--dir")+1])/"apps/desktop/dist"
                out.mkdir(parents=True,exist_ok=True); (out/"index.html").write_text("<html>"+"x"*200+"</html>")
                return 0,b""
            bootstrap=HermesBootstrap(data,journal,network=FakeNetwork(),runner=runner,desktop_builder=fake_desktop(data),agent_probe=lambda:True,expected_script_blob=git_blob_sha1(SCRIPT))
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
            boot=HermesBootstrap(data,journal,network=FakeNetwork(),runner=runner,desktop_builder=fake_desktop(data),agent_probe=lambda:True,expected_script_blob=git_blob_sha1(SCRIPT))
            with self.assertRaisesRegex(BootstrapError,"stage products"):
                boot.install()
            prior=sum(1 for call in runner.calls if "--stage" in call[0])
            report=boot.install()
            self.assertTrue(report.agent_ready)
            second=[call[0][call[0].index("--stage")+1] for call in runner.calls[prior:] if "--stage" in call[0]]
            self.assertEqual(second,["products","products","setup","gateway","complete"])

    def test_failed_stage_records_scrubbed_diagnostics_and_effects(self):
        with tempfile.TemporaryDirectory() as td:
            data=OwnedRoot(Path(td)/"data"); data.ensure()
            state_root=OwnedRoot(Path(td)/"state"); state_root.ensure()
            journal=Journal(state_root.path("journal.sqlite3"))
            class DiagnosticRunner(FakeRunner):
                def __call__(self,args,*,timeout,capture=False):
                    if "--stage" in args and args[args.index("--stage")+1] == "products":
                        stage = args[args.index("--stage")+1]
                        if self.fail_once == stage:
                            self.fail_once = None
                            diagnostic = data.path(f"runtime/logs/hermes-agent-{HERMES_COMMIT[:12]}/{stage}.log")
                            diagnostic.parent.mkdir(parents=True,exist_ok=True)
                            diagnostic.write_text("[stderr] build failed token=secret-value\n[stderr] npm ERR! exit 1\n")
                            return 1,b""
                    return super().__call__(args,timeout=timeout,capture=capture)
            runner=DiagnosticRunner(fail_once="products")
            boot=HermesBootstrap(data,journal,network=FakeNetwork(),runner=runner,desktop_builder=fake_desktop(data),agent_probe=lambda:True,expected_script_blob=git_blob_sha1(SCRIPT))
            with self.assertRaisesRegex(BootstrapError,"diagnostics: runtime/logs"):
                boot.install()
            log=data.path(f"runtime/logs/hermes-agent-{HERMES_COMMIT[:12]}/products.log")
            boot._persist_diagnostic(f"runtime/logs/hermes-agent-{HERMES_COMMIT[:12]}/products.log", bytearray(b"token=secret-value\n"), False)
            self.assertNotIn("secret-value",log.read_text())
            operation=journal.operation("hermes-agent:"+HERMES_COMMIT)
            self.assertEqual(operation["status"],"failed:products")
            self.assertEqual(operation["payload"]["exit_code"],1)
            events=journal.events("hermes-agent:"+HERMES_COMMIT)
            failed=[event for event in events if event["step"]=="products" and event["event"]=="failed"]
            self.assertEqual(len(failed),1)
            self.assertEqual(failed[0]["details"]["exit_code"],1)
            self.assertIn("effects_after",failed[0]["details"])

    def test_interrupted_operation_is_durable_and_resumable_after_power_loss(self):
        with tempfile.TemporaryDirectory() as td:
            data=OwnedRoot(Path(td)/"data"); data.ensure()
            state_root=OwnedRoot(Path(td)/"state"); state_root.ensure()
            journal=Journal(state_root.path("journal.sqlite3"))
            runner=FakeRunner()
            boot=HermesBootstrap(data,journal,network=FakeNetwork(),runner=runner,desktop_builder=fake_desktop(data),agent_probe=lambda:True,expected_script_blob=git_blob_sha1(SCRIPT))
            boot.prepare()
            journal.checkpoint(boot.operation,"running:products",{"stage":"products","commit":HERMES_COMMIT})
            journal.event(boot.operation,"products","started",{"generation":str(boot.install_dir)})
            # Reopen the journal as a new process would after power was lost.
            recovered=Journal(state_root.path("journal.sqlite3"))
            self.assertEqual(recovered.operation(boot.operation)["status"],"running:products")
            report=HermesBootstrap(data,recovered,network=FakeNetwork(),runner=runner,desktop_builder=fake_desktop(data),agent_probe=lambda:True,expected_script_blob=git_blob_sha1(SCRIPT)).install(include_desktop=False)
            self.assertTrue(report.agent_ready)
            self.assertEqual(recovered.operation(boot.operation)["status"],"complete")

    def test_cancellation_records_safe_resume_and_preserves_private_overlay(self):
        with tempfile.TemporaryDirectory() as td:
            data=OwnedRoot(Path(td)/"data"); data.ensure()
            overlay=data.path("profiles/default/SOUL.md")
            overlay.parent.mkdir(parents=True); overlay.write_text("user overlay")
            state_root=OwnedRoot(Path(td)/"state"); state_root.ensure()
            journal=Journal(state_root.path("journal.sqlite3"))
            class CancelRunner(FakeRunner):
                def __call__(self,args,*,timeout,capture=False):
                    if "--stage" in args and args[args.index("--stage")+1] == "repository":
                        raise KeyboardInterrupt()
                    return super().__call__(args,timeout=timeout,capture=capture)
            boot=HermesBootstrap(data,journal,network=FakeNetwork(),runner=CancelRunner(),desktop_builder=fake_desktop(data),agent_probe=lambda:True,expected_script_blob=git_blob_sha1(SCRIPT))
            with self.assertRaises(KeyboardInterrupt): boot.install(include_desktop=False)
            self.assertEqual(journal.operation(boot.operation)["status"],"cancelled:repository")
            self.assertEqual(overlay.read_text(),"user overlay")
    def test_repository_failures_before_and_during_clone_resume(self):
        for partial in (False, True):
            with self.subTest(partial=partial), tempfile.TemporaryDirectory() as td:
                data=OwnedRoot(Path(td)/"data");data.ensure(); state_root=OwnedRoot(Path(td)/"state");state_root.ensure()
                runner=FakeRunner(fail_once="repository",partial_repository=partial)
                boot=HermesBootstrap(data,Journal(state_root.path("journal.sqlite3")),network=FakeNetwork(),runner=runner,desktop_builder=fake_desktop(data),agent_probe=lambda:True,expected_script_blob=git_blob_sha1(SCRIPT))
                with self.assertRaisesRegex(BootstrapError,"stage repository"):
                    boot.install()
                boot.install(include_desktop=False)
                self.assertEqual(boot._source_head(),HERMES_COMMIT)
    def test_changed_pinned_source_head_is_preserved_and_denied(self):
        with tempfile.TemporaryDirectory() as td:
            data=OwnedRoot(Path(td)/"data");data.ensure(); state_root=OwnedRoot(Path(td)/"state");state_root.ensure()
            runner=FakeRunner(); journal=Journal(state_root.path("journal.sqlite3"))
            boot=HermesBootstrap(data,journal,network=FakeNetwork(),runner=runner,desktop_builder=fake_desktop(data),agent_probe=lambda:True,expected_script_blob=git_blob_sha1(SCRIPT))
            boot.install()
            head=boot.install_dir/".git"/"HEAD"; head.write_text("0"*40)
            with self.assertRaisesRegex(Exception,"resumable"):
                boot.install()
            self.assertEqual(head.read_text(),"0"*40)
    def test_agent_only_install_can_add_desktop_later(self):
        with tempfile.TemporaryDirectory() as td:
            data=OwnedRoot(Path(td)/"data");data.ensure(); state_root=OwnedRoot(Path(td)/"state");state_root.ensure()
            runner=FakeRunner(); boot=HermesBootstrap(data,Journal(state_root.path("journal.sqlite3")),network=FakeNetwork(),runner=runner,desktop_builder=fake_desktop(data),agent_probe=lambda:True,expected_script_blob=git_blob_sha1(SCRIPT))
            boot.install(include_desktop=False)
            desktop_calls=[]
            def build(*,timeout):
                desktop_calls.append(timeout)
                return fake_desktop(data)(timeout=timeout)
            boot.desktop_builder=build
            boot.install(include_desktop=True)
            self.assertTrue(boot.status()["complete"])
            self.assertEqual(len(desktop_calls),1)

    def test_partial_desktop_dist_is_not_reported_as_built(self):
        with tempfile.TemporaryDirectory() as td:
            data=OwnedRoot(Path(td)/"data"); data.ensure()
            state_root=OwnedRoot(Path(td)/"state"); state_root.ensure()
            runner=FakeRunner()
            def partial(*,timeout):
                dist=data.path("generations/hermes-agent-"+HERMES_COMMIT[:12]+"/apps/desktop/dist")
                dist.mkdir(parents=True,exist_ok=True)
                (dist/"index.html").write_text("<html>"+"x"*200+"</html>")
                return 1,b"packaging failed"
            boot=HermesBootstrap(data,Journal(state_root.path("journal.sqlite3")),network=FakeNetwork(),runner=runner,desktop_builder=partial,agent_probe=lambda:True,expected_script_blob=git_blob_sha1(SCRIPT))
            with self.assertRaisesRegex(BootstrapError,"partial dist files do not establish a build"):
                boot.install(include_desktop=True)
            self.assertEqual(boot.status()["operation"]["status"],"failed:desktop-product-build")
    def test_manifest_change_stops_before_any_stage(self):
        with tempfile.TemporaryDirectory() as td:
            data=OwnedRoot(Path(td)/"data");data.ensure()
            state_root=OwnedRoot(Path(td)/"state");state_root.ensure()
            class BadRunner(FakeRunner):
                def __call__(self,args,*,timeout,capture=False):
                    self.calls.append((args,timeout,capture))
                    return (0,json.dumps({"protocol_version":1,"stages":[{"name":"other"}]}).encode()) if capture else (0,b"")
            runner=BadRunner()
            boot=HermesBootstrap(data,Journal(state_root.path("journal.sqlite3")),network=FakeNetwork(),runner=runner,desktop_builder=fake_desktop(data),agent_probe=lambda:True,expected_script_blob=git_blob_sha1(SCRIPT))
            with self.assertRaisesRegex(BootstrapError,"stage protocol changed"): boot.install()
            self.assertFalse(any("--stage" in call[0] for call in runner.calls))
    def test_modified_script_is_rejected_before_execution(self):
        with tempfile.TemporaryDirectory() as td:
            data=OwnedRoot(Path(td)/"data");data.ensure()
            state_root=OwnedRoot(Path(td)/"state");state_root.ensure()
            boot=HermesBootstrap(data,Journal(state_root.path("journal.sqlite3")),network=FakeNetwork(),runner=FakeRunner())
            with self.assertRaisesRegex(BootstrapError,"object identity"): boot.prepare()
            self.assertFalse(boot.script_path.exists())

    @unittest.skipUnless(hasattr(os, "waitid"), "process custody probe requires Linux child inspection")
    def test_manifest_capture_stops_at_the_output_bound(self):
        with tempfile.TemporaryDirectory() as td:
            data=OwnedRoot(Path(td)/"data"); data.ensure()
            state_root=OwnedRoot(Path(td)/"state"); state_root.ensure()
            boot=HermesBootstrap(data,Journal(state_root.path("journal.sqlite3")),network=FakeNetwork(),expected_script_blob=git_blob_sha1(SCRIPT))
            boot.script_path.parent.mkdir(parents=True,exist_ok=True)
            boot.script_path.write_text("#!/usr/bin/env bash\npython3 -c 'import sys;sys.stdout.write(\"x\"*200000)'\n")
            started=time.monotonic()
            with self.assertRaisesRegex(BootstrapError,"output bound"):
                boot._run_process(["--manifest"],timeout=5,capture=True)
            self.assertLess(time.monotonic()-started,3)

    @unittest.skipUnless(hasattr(os, "waitid"), "process custody probe requires Linux child inspection")
    def test_manifest_capture_checks_overflow_after_fast_child_exit(self):
        with tempfile.TemporaryDirectory() as td:
            data=OwnedRoot(Path(td)/"data"); data.ensure()
            state_root=OwnedRoot(Path(td)/"state"); state_root.ensure()
            boot=HermesBootstrap(data,Journal(state_root.path("journal.sqlite3")),network=FakeNetwork(),expected_script_blob=git_blob_sha1(SCRIPT))
            boot.script_path.parent.mkdir(parents=True,exist_ok=True)
            boot.script_path.write_text("#!/usr/bin/env bash\nprintf '%200000s' x\n")
            started=time.monotonic()
            with self.assertRaisesRegex(BootstrapError,"output bound"):
                boot._run_process(["--manifest"],timeout=5,capture=True)
            self.assertLess(time.monotonic()-started,3)

    def test_capture_does_not_block_closing_when_reader_lacks_eof(self):
        from unittest.mock import patch
        entered=threading.Event()
        release=threading.Event()
        class BlockingStream:
            closed=False
            def read(self, size):
                entered.set()
                release.wait(3)
                return b""
            def close(self):
                self.closed=True
        class FakeProc:
            pid=999999
            returncode=None
            def __init__(self):
                self.stdout=BlockingStream()
                self.stderr=BlockingStream()
        proc=FakeProc()
        with tempfile.TemporaryDirectory() as td:
            data=OwnedRoot(Path(td)/"data"); data.ensure()
            state_root=OwnedRoot(Path(td)/"state"); state_root.ensure()
            boot=HermesBootstrap(data,Journal(state_root.path("journal.sqlite3")),network=FakeNetwork(),expected_script_blob=git_blob_sha1(SCRIPT))
            boot.script_path.parent.mkdir(parents=True,exist_ok=True)
            boot.script_path.write_text("#!/usr/bin/env bash\n")
            started=time.monotonic()
            with patch("hermes_installer.bootstrap.subprocess.Popen",return_value=proc), \
                 patch("hermes_installer.bootstrap._child_state",return_value="lost"), \
                 patch("hermes_installer.bootstrap._stop_group",return_value=False):
                with self.assertRaisesRegex(BootstrapError,"custody was lost"):
                    boot._run_process(["--manifest"],timeout=5,capture=True)
            self.assertTrue(entered.is_set())
            self.assertLess(time.monotonic()-started,1)
            self.assertFalse(proc.stdout.closed)
            release.set()

    @unittest.skipUnless(hasattr(os, "waitid"), "process custody probe requires Linux child inspection")
    def test_stop_group_cleans_only_its_owned_descendants(self):
        with tempfile.TemporaryDirectory() as td:
            pid_file=Path(td)/"child.pid"
            child_code="import subprocess,sys,time,pathlib; p=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)']); pathlib.Path(sys.argv[1]).write_text(str(p.pid)); time.sleep(60)"
            proc=subprocess.Popen([sys.executable,"-c",child_code,str(pid_file)],stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True)
            proc._hermes_cleanup_lock=threading.Lock()
            deadline=time.monotonic()+3
            while not pid_file.exists() and time.monotonic()<deadline: time.sleep(0.02)
            self.assertTrue(pid_file.exists())
            child_pid=int(pid_file.read_text())
            self.assertEqual(os.getpgid(child_pid),proc.pid)
            self.assertTrue(_stop_group(proc))
            self.assertIsNotNone(proc.returncode)
            end=time.monotonic()+2
            running=True
            while running and time.monotonic()<end:
                stat_path=Path("/proc")/str(child_pid)/"stat"
                try:
                    raw=stat_path.read_text()
                    state=raw[raw.rfind(")")+2:].split()[0]
                    running=state!="Z"
                except OSError:
                    running=False
                if running: time.sleep(0.02)
            self.assertFalse(running,"owned descendant remained executable after group cleanup")

    @unittest.skipUnless(hasattr(os, "waitid"), "process custody probe requires Linux child inspection")
    def test_lost_child_custody_never_authorizes_group_signal(self):
        from types import SimpleNamespace
        from unittest.mock import patch
        proc=SimpleNamespace(pid=987654,returncode=None,_hermes_cleanup_lock=threading.Lock())
        with patch("hermes_installer.bootstrap.os.waitid",side_effect=ChildProcessError), \
             patch("hermes_installer.bootstrap.os.killpg") as signal_group:
            self.assertFalse(_stop_group(proc))
            signal_group.assert_not_called()

if __name__ == "__main__": unittest.main()
