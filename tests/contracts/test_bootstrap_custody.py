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
        grant_call = next(call for call in client.calls if call[0] == "authorize")
        self.assertEqual(grant_call[1]["target"], f"artifact:hermes-installer-fixture:{digest}")
        request = json.dumps({"schema": 1, "artifact_id": "hermes-installer-fixture",
            "sha256": digest, "max_bytes": 1024}, sort_keys=True,
            separators=(",", ":"), ensure_ascii=True).encode("ascii")
        self.assertEqual(grant_call[1]["request_digest"], hashlib.sha256(request).hexdigest())
        self.assertEqual(next(call for call in client.calls if call[0] == "fetch")[1], "one-use-grant")

    def test_process_start_status_and_reads_use_fresh_canonical_control_grants(self):
        fake_authority = types.ModuleType("hermes_installer.authority")

        def canonical_profile_target(profile_id, executable, data_root):
            return f"hermes-profile-invoke:{profile_id}:{executable.resolve()}:{hashlib.sha256(executable.read_bytes()).hexdigest()}:{data_root.resolve()}"

        def profile_launch_envelope(*, child_artifact_refs=None, **kwargs):
            if child_artifact_refs is not None:
                kwargs["child_artifact_refs"] = child_artifact_refs
            return {"schema": 1, **{key: str(value) if isinstance(value, Path) else list(value) if key == "argv" else dict(value) if key == "env_allowlist" else value for key, value in kwargs.items()}}

        def canonical_digest(value):
            payload = value if isinstance(value, bytes) else json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
            return hashlib.sha256(payload).hexdigest()

        fake_authority.canonical_profile_target = canonical_profile_target
        fake_authority.profile_launch_envelope = profile_launch_envelope
        fake_authority.canonical_digest = canonical_digest
        prior = sys.modules.get("hermes_installer.authority")
        sys.modules["hermes_installer.authority"] = fake_authority
        try:
            with tempfile.TemporaryDirectory() as td:
                root = Path(td)
                executable = root / "hermes"
                executable.write_bytes(b"fixture executable")
                data_root = root / "data"
                data_root.mkdir()
                (root / "artifacts").mkdir()

                class Client:
                    def __init__(self):
                        self.context_count = 0
                        self.grants = []
                        self.control_calls = []

                    def context(self, **kwargs):
                        self.context_count += 1
                        return SimpleNamespace(profile_id="profile-a")

                    def authorize_effect(self, context, **kwargs):
                        self.grants.append(kwargs)
                        return f"grant-{len(self.grants)}"

                    def process_start(self, grant, *, target, launch, timeout):
                        self.launch = launch
                        receipt = {"process_id": "process-1", "generation": "gen-1",
                            "pid": 123, "uid": 456, "namespace_id": "ns-1",
                            "started_at_monotonic": 1.0, "stdout_cursor": 0,
                            "stderr_cursor": 0, "expires_at_monotonic": 60.0}
                        return SimpleNamespace(status=200,
                            body=json.dumps(receipt).encode(), receipt_id="start-receipt")

                    def process_control(self, grant, *, operation, target, payload, timeout):
                        self.control_calls.append((operation, target, payload))
                        request = json.loads(payload)
                        if operation == "process.status":
                            body = {"state": "exited", "exit_code": 0,
                                "stdout_cursor": 3, "stderr_cursor": 0}
                        elif request["stream"] == "stdout":
                            body = {"data": base64.b64encode(b"ok\n").decode(),
                                "cursor": 3, "eof": True}
                        else:
                            body = {"data": "", "cursor": 0, "eof": True}
                        return SimpleNamespace(status=200, body=json.dumps(body).encode(),
                                               receipt_id=f"{operation}-receipt")

                client = Client()
                store_id = "artifact:hermes-installer-fixture:" + "a" * 64
                result = BootstrapCustody(client).run_process(profile_id="profile-a",
                    executable=executable, artifact_root=root / "artifacts", cwd=root,
                    data_root=data_root, argv=[str(executable), store_id, "--version"],
                    env_allowlist={"PATH": "/usr/bin:/bin"}, timeout=10,
                    child_artifact_refs={store_id: "a" * 64})
                self.assertEqual(result.exit_code, 0)
                self.assertEqual(result.stdout, b"ok\n")
                self.assertTrue(result.cleanup_verified)
                self.assertEqual(result.process_id, "process-1")
                self.assertEqual(client.launch["child_artifact_refs"], {store_id: "a" * 64})
                self.assertEqual(client.context_count, 3)
                self.assertEqual([call[0] for call in client.control_calls],
                                 ["process.status", "process.read"])
                self.assertTrue(all(call[1] == f"hermes-profile-control:profile-a:{data_root.resolve()}" for call in client.control_calls))
                self.assertTrue(all(grant["capability"] == "hermes-bootstrap" for grant in client.grants))
                status_payload = client.control_calls[0][2]
                self.assertEqual(client.grants[1]["request_digest"], canonical_digest(status_payload))
        finally:
            if prior is None:
                sys.modules.pop("hermes_installer.authority", None)
            else:
                sys.modules["hermes_installer.authority"] = prior


if __name__ == "__main__":
    unittest.main()
