"""HI08 unit tests: native bytes may be captured privately; labels never grant trust."""
from __future__ import annotations

import hashlib
import os
import shutil
import sys
import tempfile
import unittest
from types import SimpleNamespace
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
    "hermes_cli/__init__.py": "84d0d7f5b6d8340897c4c53947890f88f93de146fcc228d4f4fdd096f2a8d81b",
    "hermes_cli/plugins.py": "11d8e9606b2b274a30f11384233bee36cd44a683abdaca674201c30a9319ca86",
    "agent/__init__.py": "067ee01cbc088b572cbdabbbe4116d9bec0939acc0bd30ac67b287cb5d6743e6",
    "agent/chat_completion_helpers.py": "0f234b4f9bf3e2fd29c6e2da517b1302de4c1bc3e6780d443080526fb69d9ef9",
    "agent/auxiliary_client.py": "876a97cc1c81fb1e4bc97d92872e03ceb0b1d8f43680d551d974b4376e8950c6",
    "agent/tool_executor.py": "289df099d066e296e4dd3a08b8a0bfb0b2cb9b8bc329ac8ffd70fe60f3c86eb0",
    "tools/__init__.py": "cd92cb5947a7ceeff2cce118857e7e6285eafefb2c32a0a119afdc33865b7ffe",
    "tools/mcp_tool_registration.py": "4e9cbd62da220be24e8a2ec9b140f28914642e7968eb59a92a5127875c43af2a",
    "tools/mcp_tool_discovery.py": "283939251074fc02244f98fb5339f0be8a670653a1f662e0e155f0e3b4f87900",
}


class NativeBoundaryAdapterTests(unittest.TestCase):
    def test_pinned_plugin_manager_overlay_calls_root_selected_bootstrap_in_discovery(self):
        if not UPSTREAM.is_dir():
            self.skipTest("exact official Hermes source checkout is not available")
        source = UPSTREAM / "hermes_cli/plugins.py"
        with tempfile.TemporaryDirectory(prefix="hi08-native-discovery-source-") as scratch:
            copy = Path(scratch) / "plugins.py"
            copy.write_bytes(source.read_bytes())
            patched = __import__("hermes_installer.native_boundary_patch", fromlist=["_transform"])._transform(
                "hermes_cli/plugins.py", copy.read_bytes()).decode("utf-8")
        self.assertIn("manifests = install_selected_native_plugins(self, manifests)", patched)
        self.assertLess(patched.index("install_selected_native_plugins(self, manifests)"),
                        patched.index("winners = resolve_manifest_winners(manifests)"))
        self.assertIn("finish_selected_native_plugin_discovery(self)", patched)
        self.assertGreater(patched.index("finish_selected_native_plugin_discovery(self)"),
                           patched.index("self._notify_plugin_loaded(loaded_before)"))
        self.assertIn("_predeclared_modules", (UPSTREAM / "hermes_cli/plugins_loader.py").read_text())

    def test_overlay_package_initializers_extend_real_pinned_source_path(self):
        if not UPSTREAM.is_dir():
            self.skipTest("exact official Hermes source checkout is not available")
        with tempfile.TemporaryDirectory(prefix="hi08-native-package-overlay-") as scratch:
            source = Path(scratch) / "source"
            overlay = Path(scratch) / "overlay"
            for relative in EXPECTED:
                target = source / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(UPSTREAM / relative, target)
            actual = apply_native_boundary_overlay(source, overlay)
            for relative in ("hermes_cli/__init__.py", "agent/__init__.py", "tools/__init__.py"):
                self.assertIn("extend_path(__path__, __name__)", (overlay / relative).read_text())
            self.assertEqual(actual, EXPECTED)

    def test_mcp_registration_is_gated_before_config_and_later_candidate_registration(self):
        if not UPSTREAM.is_dir():
            self.skipTest("exact official Hermes source checkout is not available")
        for relative, expected in (
            ("tools/mcp_tool_discovery.py", "return list(prepare_native_mcp_candidate_discovery())"),
            ("tools/mcp_tool_registration.py", "filter_unselected_native_mcp_candidates(name, candidates)"),
        ):
            patched = __import__("hermes_installer.native_boundary_patch", fromlist=["_transform"])._transform(
                relative, (UPSTREAM / relative).read_bytes()).decode("utf-8")
            self.assertIn(expected, patched)
            if relative.endswith("mcp_tool_discovery.py"):
                self.assertLess(patched.index(expected), patched.index("with _owner_secret_scope():"))

    def test_provider_attempt_prepares_exact_full_body_and_adds_opaque_header(self):
        messages = [{"role": "user", "content": "local fixture"}]
        kwargs = {"messages": messages, "model": "fixture", "tools": [{"name": "lookup"}],
                  "stream": False, "timeout": 10}
        captured = []

        def prepare(payload, *, parent_receipt_handles, purpose, intent_id, trace_id, retry_index):
            captured.append((payload, tuple(parent_receipt_handles), purpose, retry_index))
            return "native_evt_000000000000000000000000000001", boundary.time.monotonic() + 30

        with patch.object(boundary, "_prepare_native_event", side_effect=prepare):
            result = boundary.prepare_provider_request(kwargs, purpose="native-primary")

        self.assertEqual(captured, [(
            b'{"messages":[{"content":"local fixture","role":"user"}],"model":"fixture","stream":false,"tools":[{"name":"lookup"}]}',
            (), "native-primary", 0)])
        self.assertEqual(result["extra_headers"], {
            "X-Hermes-Installer-Context": "native_evt_000000000000000000000000000001",
            "X-Hermes-Installer-Retry-Index": "0"})
        self.assertEqual(result["max_retries"], 0)
        self.assertGreater(result["timeout"], 0)
        self.assertNotIn("extra_headers", kwargs)

    def test_retry_gets_fresh_event_handle_without_inventing_source_receipts(self):
        messages = [{"role": "user", "content": "private fixture"}]
        captured = []
        issued = iter(("native_evt_000000000000000000000000000002",
                       "native_evt_000000000000000000000000000003"))

        def prepare(payload, *, parent_receipt_handles, purpose, intent_id, trace_id, retry_index):
            captured.append(("event", tuple(parent_receipt_handles), purpose, retry_index,
                             intent_id, trace_id))
            return next(issued), boundary.time.monotonic() + 30

        with patch.object(boundary, "_prepare_native_event", side_effect=prepare):
            first = boundary.prepare_provider_request({"messages": messages}, purpose="native-primary")
            retry = boundary.prepare_provider_request({"messages": messages}, purpose="native-primary")

        self.assertNotEqual(first["extra_headers"], retry["extra_headers"])
        self.assertEqual(first["extra_headers"][boundary.RETRY_INDEX_HEADER], "0")
        self.assertEqual(retry["extra_headers"][boundary.RETRY_INDEX_HEADER], "1")
        self.assertEqual(captured[0][:4], ("event", (), "native-primary", 0))
        self.assertEqual(captured[1][:4], ("event", (), "native-primary", 1))
        self.assertEqual(captured[0][4:], captured[1][4:])

    def test_worker_cannot_supply_context_or_source_classification(self):
        messages = [{"role": "user", "content": "fixture"}]
        with patch.object(boundary, "_prepare_native_event") as prepare:
            for headers in (
                {"X-Hermes-Installer-Context": "native_evt_000000000000000000000000000004"},
                {"x-hermes-installer-context": "native_evt_000000000000000000000000000004"},
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

    def test_failed_tool_result_capture_blocks_later_provider_dispatch(self):
        messages = [{"role": "tool", "name": "fixture", "content": "private"}]
        with patch.object(boundary, "_capture_source", side_effect=boundary.NativeBoundaryUnavailable("offline")), \
                patch.object(boundary, "_prepare_native_event") as prepare:
            boundary.record_tool_result(messages, {
                "role": "tool", "name": "fixture", "content": "private"})
            with self.assertRaises(boundary.NativeBoundaryUnavailable):
                boundary.prepare_provider_request({"messages": messages}, purpose="native-primary")
            prepare.assert_not_called()

    def test_native_event_bridge_requires_exact_root_method_and_live_lease(self):
        client = SimpleNamespace(prepare_native_event=None)
        with patch.object(boundary, "_authority_client", return_value=client):
            with self.assertRaises(boundary.NativeBoundaryUnavailable):
                boundary._prepare_native_event(
                    b"{}", parent_receipt_handles=(), purpose="native-primary",
                    intent_id="intent-fixture", trace_id="trace-fixture", retry_index=0)

        calls = []
        client.prepare_native_event = lambda payload, **kwargs: (
            calls.append((payload, kwargs)) or SimpleNamespace(
                native_event_handle="native_evt_000000000000000000000000000009",
                expires_monotonic=__import__("time").monotonic() + 30))
        with patch.object(boundary, "_authority_client", return_value=client):
            result = boundary._prepare_native_event(
                b'{"messages":[]}', parent_receipt_handles=("native_receipt_00000000000000000000000009",),
                purpose="native-primary", intent_id="intent-fixture",
                trace_id="trace-fixture", retry_index=1)
        self.assertEqual(result[0], "native_evt_000000000000000000000000000009")
        self.assertGreater(result[1], boundary.time.monotonic())
        self.assertEqual(calls, [(b'{"messages":[]}', {
            "parent_receipt_handles": ("native_receipt_00000000000000000000000009",),
            "purpose": "native-primary", "intent_id": "intent-fixture",
            "trace_id": "trace-fixture", "retry_index": 1})])

        client.prepare_native_event = lambda *_args, **_kwargs: SimpleNamespace(
            native_event_handle="native_evt_000000000000000000000000000010",
            expires_monotonic=__import__("time").monotonic() - 1)
        with patch.object(boundary, "_authority_client", return_value=client):
            with self.assertRaises(boundary.NativeBoundaryUnavailable):
                boundary._prepare_native_event(
                    b"{}", parent_receipt_handles=(), purpose="native-primary",
                    intent_id="intent-fixture", trace_id="trace-fixture", retry_index=0)

    def test_patch_is_hash_pinned_validated_before_write_and_read_only(self):
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

            outside = scratch_path / "outside"
            outside.mkdir()
            linked_overlay = scratch_path / "linked-overlay"
            linked_overlay.mkdir()
            (linked_overlay / "agent").symlink_to(outside, target_is_directory=True)
            with self.assertRaises(NativePatchError):
                apply_native_boundary_overlay(source, linked_overlay)
            self.assertFalse(list(outside.iterdir()))


if __name__ == "__main__":
    unittest.main()
