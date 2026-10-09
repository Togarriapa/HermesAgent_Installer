from __future__ import annotations

import base64
import unittest

from hermes_installer.authority.process_controls import process_control_operation
from hermes_installer.authority.types import AuthorityDenied


class RecordingAuthorityClient:
    def __init__(self, result=None):
        self.result = result or {
            "status": 200, "body": base64.b64encode(b'{"schema":1}').decode("ascii"),
            "headers": {}, "receipt_id": "receipt:fixture",
        }
        self.calls = []

    def _rpc(self, operation, payload, *, timeout=None, cancelled=None):
        self.calls.append((operation, payload, timeout, cancelled))
        return self.result


class ProcessControlContracts(unittest.TestCase):
    def test_selected_status_contains_only_opaque_handle_and_fixed_operation(self):
        client = RecordingAuthorityClient()
        response = process_control_operation(
            client, "process.status", process_id="a" * 32, generation="gen:7",
        )
        self.assertEqual(response.status, 200)
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
        process_control_operation(client, "process.read", process_id="a" * 32,
                                  generation="gen:7", fields={
                                      "stream": "stderr", "after_cursor": 9, "max_bytes": 32,
                                  })
        raw = b"input"
        process_control_operation(client, "process.write", process_id="a" * 32,
                                  generation="gen:7", fields={
                                      "stdin_cursor": 4,
                                      "data": base64.b64encode(raw).decode("ascii"),
                                  })
        self.assertEqual(client.calls[0][1]["fields"]["max_bytes"], 32)
        self.assertEqual(base64.b64decode(client.calls[1][1]["fields"]["data"]), raw)

    def test_rejects_caller_target_extra_fields_unbounded_data_and_stale_inputs(self):
        client = RecordingAuthorityClient()
        invalid = [
            ("process.status", {"target": "profile:other"}),
            ("process.read", {"stream": "stdout", "after_cursor": 0, "max_bytes": 65537}),
            ("process.write", {"stdin_cursor": 0,
                                "data": base64.b64encode(b"x" * 65537).decode("ascii")}),
        ]
        for operation, fields in invalid:
            with self.subTest(operation=operation, fields=tuple(fields)):
                with self.assertRaises(AuthorityDenied):
                    process_control_operation(client, operation, process_id="a" * 32,
                                              generation="gen:7", fields=fields)
        with self.assertRaises(AuthorityDenied):
            process_control_operation(client, "process.stop", process_id="foreign",
                                      generation="gen:7")
        with self.assertRaises(AuthorityDenied):
            process_control_operation(client, "process.inspect", process_id="a" * 32,
                                      generation="gen:7")
        self.assertEqual(client.calls, [])

    def test_cancellation_and_malformed_or_oversized_response_fail_closed(self):
        client = RecordingAuthorityClient()
        with self.assertRaises(AuthorityDenied):
            process_control_operation(client, "process.stop", process_id="a" * 32,
                                      generation="gen:7", cancelled=lambda: True)
        self.assertEqual(client.calls, [])
        for result in (
            {"status": 200, "body": "%%%", "headers": {}, "receipt_id": "r"},
            {"status": 200, "body": base64.b64encode(b"x" * 8193).decode(),
             "headers": {}, "receipt_id": "r"},
            {"status": 200, "body": "", "headers": {}, "receipt_id": "r", "target": "x"},
        ):
            with self.subTest(result_keys=tuple(result)):
                with self.assertRaises(AuthorityDenied):
                    process_control_operation(RecordingAuthorityClient(result), "process.stop",
                                              process_id="a" * 32, generation="gen:7")


if __name__ == "__main__":
    unittest.main()
