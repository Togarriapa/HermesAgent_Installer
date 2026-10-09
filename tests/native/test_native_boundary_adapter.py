"""HI08 unit tests: native bytes may be captured privately; labels never grant trust."""
from __future__ import annotations

import hashlib
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

INSTALLER_SRC = Path(__file__).resolve().parents[2] / "src"
sys.path.insert(0, str(INSTALLER_SRC))

from hermes_installer import native_boundary as boundary
from hermes_installer.native_boundary_patch import (
    HERMES_SOURCE_COMMIT,
    NativePatchError,
    apply_native_boundary_overlay,
    verify_native_boundary_overlay,
)

UPSTREAM = Path("/tmp/hermes-agent-hi08")
EXPECTED = {
    "agent/chat_completion_helpers.py": "81f26a93ff1591dba15246f6552d32df7e331533cf758b653a79a1aa225790f9",
    "agent/auxiliary_client.py": "5915b0d05f45316cb691871c6b88edc7e17590571e4529d90836239369b51261",
    "agent/tool_executor.py": "fd671a435cbeda36cfbec3a2b278ff34f66f8cbe37a8a87b0a372a5170e777aa",
}


class NativeBoundaryAdapterTests(unittest.TestCase):
    def test_provider_attempt_captures_exact_canonical_messages_and_adds_opaque_header(self):
        messages = [{"role": "user", "content": "local fixture"}]
        kwargs = {"messages": messages, "model": "fixture"}
        captured = []

        def prepare(payload, *, parent_receipt_handles, purpose, intent_id, trace_id, retry_index):
            captured.append((payload, tuple(parent_receipt_handles), purpose, retry_index))
            return "evt.fixture.handle.00000001"

        with patch.object(boundary, "_prepare_native_event", side_effect=prepare):
            result = boundary.prepare_provider_request(kwargs, purpose="native-primary")

        self.assertEqual(captured, [(
            b'{"messages":[{"content":"local fixture","role":"user"}],"model":"fixture"}',
            (), "native-primary", 0)])
        self.assertEqual(result["extra_headers"], {
            "X-Hermes-Installer-Context": "evt.fixture.handle.00000001"})
        self.assertNotIn("extra_headers", kwargs)

    def test_retry_gets_fresh_event_handle_and_never_replays_receipts(self):
        messages = [{"role": "tool", "name": "fixture", "content": "private"}]
        captured = []
        issued = iter(("evt.fixture.handle.00000002", "evt.fixture.handle.00000003"))

        def capture(payload, *, parent_receipt_handles=()):
            captured.append(("source", payload, tuple(parent_receipt_handles)))
            return "evt.fixture.handle.00000001"

        def prepare(payload, *, parent_receipt_handles, purpose, intent_id, trace_id, retry_index):
            captured.append(("event", tuple(parent_receipt_handles), purpose, retry_index,
                             intent_id, trace_id))
            return next(issued)

        with patch.object(boundary, "_capture_source", side_effect=capture), \
                patch.object(boundary, "_prepare_native_event", side_effect=prepare):
            boundary.record_tool_result(messages, {
                "role": "tool", "name": "fixture", "content": "private"})
            first = boundary.prepare_provider_request({"messages": messages}, purpose="native-primary")
            retry = boundary.prepare_provider_request({"messages": messages}, purpose="native-primary")

        self.assertNotEqual(first["extra_headers"], retry["extra_headers"])
        self.assertEqual(captured[0][0], "source")
        self.assertEqual(captured[1][:4], ("event", ("evt.fixture.handle.00000001",),
                                           "native-primary", 0))
        self.assertEqual(captured[2][:4], ("event", ("evt.fixture.handle.00000001",),
                                           "native-primary", 1))
        self.assertEqual(captured[1][4:], captured[2][4:])

    def test_worker_cannot_supply_context_or_source_classification(self):
        messages = [{"role": "user", "content": "fixture"}]
        with patch.object(boundary, "_prepare_native_event") as prepare:
            for headers in (
                {"X-Hermes-Installer-Context": "evt.fixture.handle.00000004"},
                {"x-hermes-installer-context": "evt.fixture.handle.00000004"},
            ):
                with self.assertRaises(boundary.NativeBoundaryUnavailable):
                    boundary.prepare_provider_request(
                        {"messages": messages, "extra_headers": headers}, purpose="native-primary")
            with self.assertRaises(boundary.NativeBoundaryUnavailable):
                boundary.prepare_provider_request(
                    {"messages": messages, "source_kind": "public"}, purpose="public")
            prepare.assert_not_called()

    def test_missing_or_malformed_authority_handle_fails_before_provider_call(self):
        messages = [{"role": "user", "content": "fixture"}]
        with patch.object(boundary, "_prepare_native_event", side_effect=boundary.NativeBoundaryUnavailable("offline")):
            with self.assertRaises(boundary.NativeBoundaryUnavailable):
                boundary.prepare_provider_request({"messages": messages}, purpose="native-primary")
        with patch.object(boundary, "_prepare_native_event", return_value="not a handle"):
            with self.assertRaises(boundary.NativeBoundaryUnavailable):
                boundary.prepare_provider_request({"messages": messages}, purpose="native-primary")

    def test_patch_is_hash_pinned_atomic_read_only_and_compilable(self):
        if not UPSTREAM.is_dir():
            self.skipTest("exact official Hermes source checkout is not available")
        self.assertEqual(
            __import__("subprocess").run(
                ["git", "-C", str(UPSTREAM), "rev-parse", "HEAD"],
                check=True, capture_output=True, text=True, timeout=5,
                env={"PATH": "/usr/bin:/bin", "GIT_CONFIG_NOSYSTEM": "1",
                     "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_OPTIONAL_LOCKS": "0"},
            ).stdout.strip(), HERMES_SOURCE_COMMIT)
        with tempfile.TemporaryDirectory(prefix="hi08-native-overlay-") as scratch:
            scratch_path = Path(scratch)
            source = scratch_path / "source"
            overlay = scratch_path / "overlay"
            for relative in EXPECTED:
                target = source / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(UPSTREAM / relative, target)
            original = {relative: (source / relative).read_bytes() for relative in EXPECTED}

            self.assertEqual(apply_native_boundary_overlay(source, overlay), EXPECTED)
            self.assertEqual(verify_native_boundary_overlay(source, overlay), EXPECTED)
            for relative, digest in EXPECTED.items():
                self.assertEqual(hashlib.sha256((overlay / relative).read_bytes()).hexdigest(), digest)
                self.assertEqual((source / relative).read_bytes(), original[relative])
                self.assertEqual((overlay / relative).stat().st_mode & 0o222, 0)
                compile((overlay / relative).read_bytes(), relative, "exec")

            # Drift is rejected before any target in a fresh overlay is written.
            (source / "agent/tool_executor.py").write_bytes(b"modified upstream")
            untouched = scratch_path / "rejected-overlay"
            with self.assertRaises(NativePatchError):
                apply_native_boundary_overlay(source, untouched)
            self.assertFalse(untouched.exists())

    def test_patch_rejects_tampered_or_linked_overlay_target(self):
        if not UPSTREAM.is_dir():
            self.skipTest("exact official Hermes source checkout is not available")
        with tempfile.TemporaryDirectory(prefix="hi08-native-overlay-guard-") as scratch:
            scratch_path = Path(scratch)
            source = scratch_path / "source"
            overlay = scratch_path / "overlay"
            for relative in EXPECTED:
                target = source / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(UPSTREAM / relative, target)
            apply_native_boundary_overlay(source, overlay)
            target = overlay / next(iter(EXPECTED))
            os.chmod(target, target.stat().st_mode | 0o200)
            with self.assertRaises(NativePatchError):
                verify_native_boundary_overlay(source, overlay)
            os.chmod(target, target.stat().st_mode & ~0o222)
            target.unlink()
            target.symlink_to(source / next(iter(EXPECTED)))
            with self.assertRaises(NativePatchError):
                verify_native_boundary_overlay(source, overlay)


if __name__ == "__main__":
    unittest.main()
