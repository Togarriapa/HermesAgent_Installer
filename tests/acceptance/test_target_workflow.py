"""Target workflows require explicit, current owner authorization and scope."""

from datetime import datetime, timedelta, timezone
import hashlib
import unittest

from hermes_installer.verification.acceptance import AuthorizedTarget, TargetWorkflowRunner


def target(**changes):
    value = {
        "target_id": "pi5-test-01",
        "platform": "raspberry-pi-5-arm64",
        "owner": "owner-123",
        "authorization_reference": "enrollment-42",
        "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
        "allowed_acceptance": ["AC01"],
    }
    value.update(changes)
    return AuthorizedTarget.parse(value, manifest_sha256=hashlib.sha256(b"manifest").hexdigest())


class TargetWorkflowTests(unittest.TestCase):
    def test_unenrolled_target_is_rejected_before_probe(self):
        called = []
        runner = TargetWorkflowRunner({"AC01": lambda *_: called.append(True)}, authorize=lambda _: False)
        with self.assertRaisesRegex(PermissionError, "could not be verified"):
            runner.run("AC01", target(), "a" * 40, "/tmp/evidence")
        self.assertEqual(called, [])

    def test_workflow_is_scoped_to_authorized_acceptance_id(self):
        runner = TargetWorkflowRunner({}, authorize=lambda _: True)
        with self.assertRaisesRegex(PermissionError, "does not include"):
            runner.run("AC02", target(), "a" * 40, "/tmp/evidence")

    def test_missing_adapter_is_explicitly_pending(self):
        result = TargetWorkflowRunner({}, authorize=lambda _: True).run("AC01", target(), "a" * 40, "/tmp/evidence")
        self.assertEqual(result.state.value, "pending")
        self.assertIn("no target effects occurred", result.message)


if __name__ == "__main__":
    unittest.main()
