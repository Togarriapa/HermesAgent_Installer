from __future__ import annotations

import base64
import hashlib
import json
import sys
import tempfile
import types
import unittest
from pathlib import Path
from types import SimpleNamespace

from hermes_installer.bootstrap_custody import BootstrapCustody


class BootstrapCustodyContractTests(unittest.TestCase):
    def test_artifact_fetch_uses_pinned_id_digest_and_one_use_grant(self):
        content = b"pinned artifact fixture"
        digest = hashlib.sha256(content).hexdigest()

        class Client:
            def __init__(self):
                self.calls = []

            def context(self, **kwargs):
                self.calls.append(("context", kwargs))
                return SimpleNamespace(profile_id="installer-profile")

            def authorize_effect(self, context, **kwargs):
                self.calls.append(("authorize", kwargs))
                return "one-use-grant"

            def fetch_artifact(self, grant, **kwargs):
                self.calls.append(("fetch", grant, kwargs))
                body = json.dumps({"artifact_id": kwargs["artifact_id"],
                    "version": "1", "sha256": kwargs["sha256"],
                    "size_bytes": len(content),
                    "store_id": f"artifact:{kwargs['artifact_id']}:{kwargs['sha256']}"}).encode()
                return SimpleNamespace(status=200, body=body, receipt_id="artifact-receipt")

        client = Client()
        store_id, receipt = BootstrapCustody(client).fetch_artifact(
            artifact_id="hermes-installer-fixture", sha256=digest, max_bytes=1024)
        self.assertEqual(store_id, f"artifact:hermes-installer-fixture:{digest}")
        self.assertEqual(receipt, "artifact-receipt")
        context_call = next(call for call in client.calls if call[0] == "context")
        self.assertEqual(context_call[1]["purpose"], "hermes-bootstrap")
        self.assertEqual(context_call[1]["operation"], "artifact.fetch")
        grant_call = next(call for call in client.calls if call[0] == "authorize")
        self.assertEqual(grant_call[1]["capability"], "installer-bootstrap")
        self.assertEqual(grant_call[1]["target"], f"artifact:hermes-installer-fixture:{digest}")
        request = json.dumps({"schema": 1, "artifact_id": "hermes-installer-fixture",
            "sha256": digest, "max_bytes": 1024}, sort_keys=True,
            separators=(",", ":"), ensure_ascii=True).encode("ascii")
        self.assertEqual(grant_call[1]["request_digest"], hashlib.sha256(request).hexdigest())
        self.assertEqual(next(call for call in client.calls if call[0] == "fetch")[1], "one-use-grant")

    def test_root_selected_recipe_uses_opaque_handle_controls_and_verified_stop(self):
        class Client:
            def __init__(self):
                self.selected = []
                self.controls = []
                self.reads = {"stdout": False, "stderr": False}

            def start_enrolled_process_operation(self, **kwargs):
                self.selected.append(kwargs)
                receipt = {"process_id": "a" * 32, "generation": "g-1", "uid": 1234}
                return SimpleNamespace(status=200, body=json.dumps(receipt).encode(),
                                       receipt_id="start-receipt")

            def process_control_operation(self, operation, *, process_id, generation,
                                          fields=None, timeout=5.0, cancelled=None):
                self.controls.append((operation, process_id, generation, fields or {}))
                if operation == "process.status":
                    return SimpleNamespace(state="exited", result={"exit_code": 0})
                if operation == "process.read":
                    stream = fields["stream"]
                    data = b"ok\n" if stream == "stdout" else b""
                    self.reads[stream] = True
                    return SimpleNamespace(state="exited", result={
                        "data_bytes": base64.b64encode(data).decode(), "eof": True,
                        "redacted": False})
                if operation == "process.stop":
                    return SimpleNamespace(state="stopped", result={
                        "closed": True, "reap_state": "complete"})
                raise AssertionError(operation)

        client = Client()
        result = BootstrapCustody(client).run_selected_operation(
            enrollment_id="enrollment-a", generation="generation-a",
            operation_id="hermes-agent-health-v1", timeout=5)
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(result.stdout, b"ok\n")
        self.assertTrue(result.cleanup_verified)
        self.assertEqual(client.selected[0]["parameters"], {})
        self.assertEqual(client.selected[0]["operation_id"], "hermes-agent-health-v1")
        self.assertEqual([call[0] for call in client.controls], [
            "process.status", "process.read", "process.read", "process.stop"])
        self.assertTrue(all(call[1] == "a" * 32 and call[2] == "g-1"
                            for call in client.controls))
        self.assertEqual(client.controls[-1][3], {"reason": "shutdown", "grace_seconds": 5})

    def test_physical_path_launch_is_rejected(self):
        from hermes_installer.bootstrap_custody import BootstrapCustodyError
        with self.assertRaisesRegex(BootstrapCustodyError, "Physical-path process launch is disabled"):
            BootstrapCustody(object()).run_process(executable="/bin/bash", argv=["/bin/bash", "-c", "id"])

    def test_stop_without_root_cleanup_receipt_does_not_report_success(self):
        class Client:
            def start_enrolled_process_operation(self, **kwargs):
                return SimpleNamespace(status=200,
                    body=json.dumps({"process_id": "b" * 32, "generation": "g-2", "uid": 1234}).encode(),
                    receipt_id="start-receipt")
            def process_control_operation(self, operation, **kwargs):
                if operation == "process.status":
                    return SimpleNamespace(state="exited", result={"exit_code": 0})
                if operation == "process.read":
                    return SimpleNamespace(state="exited", result={"data_bytes": "", "eof": True})
                return SimpleNamespace(state="stopped", result={"closed": False, "reap_state": "unverified"})
        from hermes_installer.bootstrap_custody import BootstrapCustodyError
        with self.assertRaises(BootstrapCustodyError):
            BootstrapCustody(Client()).run_selected_operation(
                enrollment_id="enrollment-a", generation="generation-a",
                operation_id="hermes-agent-stage-v1", timeout=5)

    def test_selected_operation_output_overflow_stops_owned_handle(self):
        class Client:
            stopped = False
            def start_enrolled_process_operation(self, **kwargs):
                return SimpleNamespace(status=200,
                    body=json.dumps({"process_id": "c" * 32, "generation": "g-3", "uid": 1234}).encode(),
                    receipt_id="start-receipt")
            def process_control_operation(self, operation, **kwargs):
                if operation == "process.status":
                    return SimpleNamespace(state="exited", result={"exit_code": 0})
                if operation == "process.read":
                    return SimpleNamespace(state="exited",
                        result={"data_bytes": base64.b64encode(b"xx").decode(), "eof": True})
                self.stopped = True
                return SimpleNamespace(state="stopped", result={
                    "closed": True, "reap_state": "complete"})
        from hermes_installer.bootstrap_custody import BootstrapCustodyError
        client = Client()
        with self.assertRaises(BootstrapCustodyError) as raised:
            BootstrapCustody(client).run_selected_operation(
                enrollment_id="enrollment-a", generation="generation-a", stdout_return_limit=1,
                operation_id="hermes-agent-stage-v1", timeout=5, output_limit=1)
        self.assertIs(raised.exception.cleanup_verified, True)
        self.assertTrue(client.stopped)

    def test_cancelled_control_still_runs_uncancelled_cleanup(self):
        class Client:
            stopped = False
            def start_enrolled_process_operation(self, **kwargs):
                return SimpleNamespace(status=200,
                    body=json.dumps({"process_id": "d" * 32, "generation": "g-4", "uid": 1234}).encode(),
                    receipt_id="start-receipt")
            def process_control_operation(self, operation, *, cancelled=None, **kwargs):
                if operation == "process.status":
                    if cancelled and cancelled():
                        raise RuntimeError("cancelled")
                if operation == "process.stop":
                    self.stopped = True
                    return SimpleNamespace(state="stopped", result={
                        "closed": True, "reap_state": "complete"})
                raise AssertionError(operation)
        client = Client()
        from hermes_installer.bootstrap_custody import BootstrapCustodyError
        with self.assertRaises(BootstrapCustodyError) as raised:
            BootstrapCustody(client).run_selected_operation(
                enrollment_id="enrollment-a", generation="generation-a",
                operation_id="hermes-agent-health-v1", timeout=5,
                cancelled=lambda: True)
        self.assertIs(raised.exception.cleanup_verified, True)
        self.assertTrue(client.stopped)


if __name__ == "__main__":
    unittest.main()
