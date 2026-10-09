"""Linux root integration for the fixed output interpreter probe.

The executable is a controlled fixture copy of the Linux CI builder Python.
This proves isolated root execution and custody joins only; it is not a
CPython 3.9 or ARM64 qualification result.
"""
from __future__ import annotations

import os
import base64
import dataclasses
import json
import unittest
from types import SimpleNamespace

from hermes_installer.authority.build_probe import RootManagedCPython39Probe
from tests.contracts import test_managed_build_custody_linux


class BuildProbeLinuxTests(unittest.TestCase):
    def test_selected_output_probe_uses_root_terminal_and_readonly_output_mount(self):
        fixture_type = test_managed_build_custody_linux.BuildCustodyLinuxTests
        try:
            fixture_type.setUpClass()
        except unittest.SkipTest as exc:
            self.skipTest(str(exc))
        fixture = fixture_type("test_build_runs_under_real_isolation_and_emits_terminal_cleanup_proof")
        fixture.setUp()
        peer_pidfd = None
        try:
            fixture.target = "coral-cpython-build:start"
            fixture.profile = fixture.profile.__class__(
                **{
                    field: getattr(fixture.profile, field)
                    for field in fixture.profile.__dataclass_fields__
                    if field != "operation_targets"
                },
                operation_targets={"process.start": fixture.target},
            )
            fixture.manager.profiles = {fixture.profile.profile_id: fixture.profile}
            fixture.inputs.target_id = fixture.target
            fixture.inputs.operation_id = "coral-cpython39-source-build-v1"
            fixture.inputs.output_owner_gid = fixture.gid

            # Copy only the already-selected builder executable into the
            # unique output directory. It intentionally is the CI Python, not
            # a fabricated 3.9 build, so this test cannot imply ABI acceptance.
            code = (
                "import os,pathlib,shutil\n"
                "target=pathlib.Path('/run/hermes-installer/build/output/runtime/bin/python3.9')\n"
                "target.parent.mkdir(parents=True,exist_ok=True)\n"
                "shutil.copyfile('/run/hermes-installer/build/builder',target)\n"
                "target.chmod(0o755)\n"
                "print('fixture-output-ready',flush=True)\n"
                # A successful build receipt includes live MainPID, PIDFD,
                # cgroup and namespace observations. Keep this tiny fixture
                # process alive long enough for the real manager to capture
                # those facts; an instant exit is correctly unattestable.
                "import time; time.sleep(1.0)\n"
            )
            code_arg = "exec(__import__('base64').b64decode('" + base64.b64encode(code.encode()).decode() + "'))"
            fixture.inputs.argv_recipe = (
                {"build_path": {"mount_id": "builder", "relative_path": ""}},
                {"literal": "-c"}, {"literal": code_arg},
            )
            payload = json.dumps({
                "schema": 1, "enrollment_id": fixture.context.enrollment_id,
                "generation": fixture.inputs.generation,
                "operation_id": fixture.inputs.operation_id, "parameters": {},
            }, sort_keys=True, separators=(",", ":")).encode("ascii")
            from hermes_installer.authority.types import canonical_digest
            digest = canonical_digest(payload)
            fixture.inputs.selection_digest = digest
            fixture.context = dataclasses.replace(fixture.context, final_payload_digest=digest)
            fixture.authorization = dataclasses.replace(
                fixture.authorization, target=fixture.target, request_digest=digest,
                final_payload_digest=digest, context_digest=canonical_digest(fixture.context.claims()))
            peer_pidfd = os.pidfd_open(os.getpid(), 0)
            build_result = fixture.runner.run_selected_build(
                fixture.inputs, context=fixture.context, authorization=fixture.authorization,
                peer_pid=os.getpid(), peer_pidfd=peer_pidfd, timeout=20, cancelled=lambda: False,
            )
            self.assertEqual(build_result.exit_code, 0)
            self.assertTrue(build_result.cleanup_verified)
            self.assertTrue(build_result.terminal_success_record_id)

            probe = fixture.runner.run_attested_cpython39_probe(
                fixture.inputs, build_result, timeout=15, cancelled=lambda: False)
            facts = RootManagedCPython39Probe(fixture.runner).inspect_cpython39(
                SimpleNamespace(target_id=fixture.target, generation=fixture.inputs.generation),
                fixture.output / "runtime/bin/python3.9", build_result=build_result,
                build_inputs=fixture.inputs, cancelled=lambda: False,
            )
            self.assertEqual(probe.terminal_success_record_id,
                             facts["probe_execution"]["terminal_success_record_id"])
            self.assertEqual(probe.build_terminal_success_record_id, build_result.terminal_success_record_id)
            self.assertTrue(probe.cleanup_verified)
            self.assertEqual(probe.uid, fixture.uid)
            self.assertEqual(probe.gid, fixture.gid)
            self.assertEqual(probe.output_root_inode, fixture.output.stat().st_ino)
            self.assertIn("python_version", facts)
            self.assertEqual(fixture.manager._pids(probe.cgroup_id), [])
        finally:
            if peer_pidfd is not None:
                os.close(peer_pidfd)
            fixture.tearDown()
