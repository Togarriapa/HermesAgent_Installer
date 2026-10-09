"""AF_UNIX integration for selected start and root-resolved process controls.

This uses an in-memory handle/effect fixture. Kernel process/cgroup effects are
covered only by the separate privileged Linux custody integration suite.
"""
from __future__ import annotations

import base64
import json
import os
import platform
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace

from hermes_installer.authority.client import AuthorityClient
from hermes_installer.authority.service import AuthorityService, EffectRule, PrincipalBinding
from hermes_installer.authority.types import Sensitivity
from hermes_installer.authority.client import canonical_digest


class _Policy:
    revision = "process-control-af-unix-fixture"

    def classify(self, *, purpose, intent, source_contexts, binding):
        return Sensitivity.PRIVATE, canonical_digest({"fixture": purpose, "profile": binding.profile_id})

    def allow_effect(self, *, context, rule, request_digest, retry_index):
        return (context.sensitivity is Sensitivity.PRIVATE and retry_index == 0
                and rule.capability in {"hermes-profile-invoke", "hermes-process-control"})


@unittest.skipUnless(platform.system() == "Linux" and hasattr(os, "pidfd_open"),
                     "AF_UNIX peer PIDFD is required")
class SelectedProcessControlsUnixTests(unittest.TestCase):
    def test_selected_start_then_status_read_stop_uses_root_handle_registry(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            socket_path = root / "authority.sock"
            uid = os.getuid()
            generation = "fixture-generation-1"
            process_id = "a" * 32
            profile_id = "profile:fixture"
            start_target = "profile:fixture:operation:run"
            targets = {
                "process.status": "profile:fixture:control:status",
                "process.read": "profile:fixture:control:read",
                "process.stop": "profile:fixture:control:stop",
            }
            profile = SimpleNamespace(profile_id=profile_id, generation=generation,
                                      operation_targets=targets)

            class HandleRegistry:
                active = False
                resolutions = []

                def resolve_process_operation(self, selected_id, selected_generation, operation, *,
                                              peer_uid, peer_pid, peer_pidfd):
                    self.resolutions.append((selected_id, selected_generation, operation,
                                             peer_uid, peer_pid, peer_pidfd))
                    if (not self.active or selected_id != process_id
                            or selected_generation != generation or peer_uid != uid
                            or peer_pid <= 0 or peer_pidfd is None):
                        return None
                    return profile, targets.get(operation)

            registry = HandleRegistry()
            verified_effects = []

            def response_body(operation, result, *, state):
                return json.dumps({
                    "schema": 1, "process_id": process_id, "generation": generation,
                    "operation": operation, "state": state, "result": result,
                    "expires_monotonic": time.monotonic() + 4.0,
                }, sort_keys=True, separators=(",", ":")).encode("ascii")

            def start_handler(*, context, authorization, payload, timeout,
                              peer_pid, peer_pidfd, cancelled):
                selected = json.loads(payload)
                assert selected == {"schema": 1, "enrollment_id": "enrollment:fixture",
                                   "generation": generation, "operation_id": "run",
                                   "parameters": {}}
                assert context.operation == authorization.operation == "process.start"
                assert authorization.target == start_target
                registry.active = True
                verified_effects.append(("process.start", authorization.target,
                                         authorization.request_digest))
                body = json.dumps({"process_id": process_id, "generation": generation},
                                  sort_keys=True, separators=(",", ":")).encode("ascii")
                return {"status": 200, "body": body, "headers": {}, "receipt_id": "start-receipt"}

            def control_handler(operation, target, result, state):
                def handler(*, context, authorization, payload, timeout,
                            peer_pid, peer_pidfd, cancelled):
                    request = json.loads(payload)
                    assert request["operation"] == operation
                    assert request["process_id"] == process_id
                    assert request["generation"] == generation
                    assert authorization.target == target
                    assert context.final_payload_digest == authorization.request_digest
                    verified_effects.append((operation, target, authorization.request_digest))
                    if operation == "process.stop":
                        registry.active = False
                    return {"status": 200, "body": response_body(operation, result, state=state),
                            "headers": {"content-type": "application/json"},
                            "receipt_id": operation + "-receipt"}
                return handler

            rules = [EffectRule("hermes-profile-invoke", "process.start", start_target)]
            rules.extend(EffectRule("hermes-process-control", operation, target)
                         for operation, target in targets.items())
            handlers = {("process.start", start_target): start_handler,
                        ("process.status", targets["process.status"]): control_handler(
                            "process.status", targets["process.status"], {"exit_code": None}, "running"),
                        ("process.read", targets["process.read"]): control_handler(
                            "process.read", targets["process.read"],
                            {"data_bytes": base64.b64encode(b"ready").decode("ascii"),
                             "eof": True, "redacted": False}, "running"),
                        ("process.stop", targets["process.stop"]): control_handler(
                            "process.stop", targets["process.stop"],
                            {"closed": True, "reap_state": "complete"}, "stopped")}
            binding = PrincipalBinding(uid, "principal:fixture", profile_id, "namespace:fixture",
                                       frozenset({"hermes-profile-invoke", "hermes-process-control"}))
            selected_resolver = lambda enrollment, gen, operation, operation_id: SimpleNamespace(
                operation=operation, operation_id=operation_id, profile_id=profile_id,
                principal_id=binding.principal_id, service_uid=uid,
                enrollment_id=enrollment, generation=gen, target=start_target)
            service = AuthorityService(
                signing_key=b"p" * 32, key_id="process-controls-unix-fixture",
                bindings_by_uid={uid: binding},
                rules={(rule.capability, rule.operation, rule.target): rule for rule in rules},
                handlers=handlers, policy=_Policy(), profile_generations={profile_id: generation},
                process_effect_handler=registry, selected_operation_resolver=selected_resolver,
            )
            stopped = threading.Event()
            errors = []

            def serve():
                try:
                    service.serve_unix(socket_path, socket_gid=os.getgid(), stop_event=stopped,
                                       expected_uid=uid, max_clients=16)
                except BaseException as exc:
                    errors.append(exc)

            server = threading.Thread(target=serve, daemon=True)
            server.start()
            try:
                deadline = time.monotonic() + 3
                while not socket_path.exists() and time.monotonic() < deadline:
                    time.sleep(.01)
                self.assertTrue(socket_path.exists())
                client = AuthorityClient(socket_path, server_uid=uid, timeout=2)
                started = client.start_enrolled_process_operation(
                    enrollment_id="enrollment:fixture", generation=generation,
                    operation_id="run", parameters={}, timeout=5,
                )
                self.assertEqual(json.loads(started.body)["process_id"], process_id)
                self.assertIsNone(client.process_control_operation(
                    "process.status", process_id=process_id, generation=generation,
                ).result["exit_code"])
                read = client.process_control_operation(
                    "process.read", process_id=process_id, generation=generation,
                    fields={"stream": "stdout", "maximum_bytes": 64},
                )
                self.assertEqual(base64.b64decode(read.result["data_bytes"]), b"ready")
                stopped_response = client.process_control_operation(
                    "process.stop", process_id=process_id, generation=generation,
                    fields={"reason": "shutdown", "grace_seconds": 1},
                )
                self.assertTrue(stopped_response.result["closed"])
                self.assertFalse(registry.active)
                self.assertEqual([item[2] for item in registry.resolutions],
                                 ["process.status", "process.read", "process.stop"])
                self.assertEqual([item[0] for item in verified_effects],
                                 ["process.start", "process.status", "process.read", "process.stop"])
                self.assertTrue(all(item[1] in {start_target, *targets.values()}
                                    for item in verified_effects))
                self.assertTrue(all(item[2] and len(item[2]) == 64 for item in verified_effects))
            finally:
                stopped.set()
                server.join(timeout=2)
            self.assertFalse(server.is_alive())
            self.assertEqual(errors, [])


if __name__ == "__main__":
    unittest.main()
