from __future__ import annotations

import base64
import json
import unittest

from hermes_installer.authority.process_controls import process_control_operation
from hermes_installer.authority.types import AuthorityDenied


class RecordingAuthorityClient:
    def __init__(self, result=None):
        self.result = result
        self.calls = []
        self.monotonic = lambda: 100.0

    def _rpc(self, operation, payload, *, timeout=None, cancelled=None):
        self.calls.append((operation, payload, timeout, cancelled))
        default_result = {}
        fields = payload["fields"]
        if payload["operation"] == "process.status":
            default_result = {"exit_code": None}
        elif payload["operation"] == "process.read":
            default_result = {"data_bytes": "", "eof": True, "redacted": False}
        elif payload["operation"] == "process.write":
            default_result = {"accepted_bytes": len(base64.b64decode(fields["data_bytes"])),
                              "sequence": fields["sequence"] + 1}
        elif payload["operation"] == "process.stop":
            default_result = {"closed": True, "reap_state": "complete"}
        body = self.result or {
            "schema": 1, "process_id": payload["process_id"],
            "generation": payload["generation"], "operation": payload["operation"],
            "state": "running", "result": default_result, "expires_monotonic": 120.0,
        }
        return {"status": 200,
                "body": base64.b64encode(json.dumps(body).encode("ascii")).decode("ascii"),
                "headers": {}, "receipt_id": "receipt:fixture"}


class ProcessControlContracts(unittest.TestCase):
    def test_selected_status_contains_only_opaque_handle_and_fixed_operation(self):
        client = RecordingAuthorityClient()
        response = process_control_operation(
            client, "process.status", "a" * 32, "gen:7",
        )
        self.assertEqual(response.state, "running")
        operation, payload, timeout, _ = client.calls[0]
        self.assertEqual(operation, "process.control")
        self.assertEqual(payload, {
            "schema": 1, "operation": "process.status", "process_id": "a" * 32,
            "generation": "gen:7", "fields": {},
        })
        self.assertNotIn("target", payload)
        self.assertNotIn("capability", payload)
        self.assertNotIn("authorization", payload)
        self.assertEqual(timeout, 5.0)

    def test_read_and_write_are_bounded_typed_selections(self):
        client = RecordingAuthorityClient()
        process_control_operation(client, "process.read", "a" * 32, "gen:7", {
                                      "stream": "stderr", "maximum_bytes": 32,
                                  })
        raw = b"input"
        process_control_operation(client, "process.write", "a" * 32, "gen:7", {
                                      "sequence": 0, "data_bytes": raw,
                                  })
        self.assertEqual(client.calls[0][1]["fields"]["maximum_bytes"], 32)
        self.assertEqual(client.calls[1][1]["fields"]["data_bytes"], "aW5wdXQ=")

    def test_rejects_caller_target_extra_fields_unbounded_data_and_stale_inputs(self):
        client = RecordingAuthorityClient()
        invalid = [
            ("process.status", {"target": "profile:other"}),
            ("process.read", {"stream": "stdout", "maximum_bytes": 1_048_577}),
            ("process.write", {"sequence": 0, "data_bytes": b"x" * 262_145}),
            ("process.stop", {"reason": "arbitrary", "grace_seconds": 0}),
        ]
        for operation, fields in invalid:
            with self.subTest(operation=operation, fields=tuple(fields)):
                with self.assertRaises(AuthorityDenied):
                    process_control_operation(client, operation, "a" * 32,
                                              "gen:7", fields)
        with self.assertRaises(AuthorityDenied):
            process_control_operation(client, "process.stop", "foreign", "gen:7",
                                      {"reason": "cancel", "grace_seconds": 0})
        inspected = process_control_operation(client, "process.inspect", "a" * 32, "gen:7")
        self.assertEqual(inspected.operation, "process.inspect")
        self.assertEqual(len(client.calls), 1)

    def test_cancellation_and_malformed_or_oversized_response_fail_closed(self):
        client = RecordingAuthorityClient()
        with self.assertRaises(AuthorityDenied):
            process_control_operation(client, "process.stop", "a" * 32, "gen:7",
                                      {"reason": "cancel", "grace_seconds": 0},
                                      cancelled=lambda: True)
        self.assertEqual(client.calls, [])
        for result in (
            {"schema": 1, "process_id": "b" * 32, "generation": "gen:7",
             "operation": "process.stop", "state": "stopped", "result": {}, "expires_monotonic": 120.0},
            {"schema": 1, "process_id": "a" * 32, "generation": "stale",
             "operation": "process.stop", "state": "stopped", "result": {}, "expires_monotonic": 120.0},
            {"schema": 1, "process_id": "a" * 32, "generation": "gen:7",
             "operation": "process.stop", "state": "stopped", "result": {}, "expires_monotonic": 99.0},
            {"schema": 1, "process_id": "a" * 32, "generation": "gen:7",
             "operation": "process.stop", "state": "stopped", "result": {},
             "expires_monotonic": 120.0, "target": "x"},
        ):
            with self.subTest(result_keys=tuple(result)):
                with self.assertRaises(AuthorityDenied):
                    process_control_operation(RecordingAuthorityClient(result), "process.stop",
                                              "a" * 32, "gen:7",
                                              {"reason": "cancel", "grace_seconds": 0})


if __name__ == "__main__":
    unittest.main()
