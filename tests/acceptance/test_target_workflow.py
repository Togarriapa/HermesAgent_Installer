"""Target workflows require explicit, current owner authorization and scope."""

from datetime import datetime, timedelta, timezone
import hashlib

import pytest

from hermes_installer.evidence import EvidenceRecord
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


def test_unlisted_or_unenrolled_target_is_rejected_before_probe():
    called = []
    runner = TargetWorkflowRunner({"AC01": lambda *_: called.append(True)}, authorize=lambda _: False)
    with pytest.raises(PermissionError, match="could not be verified"):
        runner.run("AC01", target(), "a" * 40, "/tmp/evidence")
    assert called == []


def test_workflow_is_scoped_to_authorized_acceptance_id():
    runner = TargetWorkflowRunner({}, authorize=lambda _: True)
    with pytest.raises(PermissionError, match="does not include"):
        runner.run("AC02", target(), "a" * 40, "/tmp/evidence")


def test_missing_adapter_is_explicitly_pending():
    result = TargetWorkflowRunner({}, authorize=lambda _: True).run("AC01", target(), "a" * 40, "/tmp/evidence")
    assert result.state.value == "pending"
    assert "no target effects occurred" in result.message
