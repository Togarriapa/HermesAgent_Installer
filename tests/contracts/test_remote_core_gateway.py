"""Core-mode gateway proof binding and protected HTTP middleware contracts."""
from __future__ import annotations

import asyncio
import dataclasses
import hashlib
import json
import os
import time
import runpy
import stat
import struct
import tempfile
import time
import unittest
import warnings
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer
from yarl import URL

from hermes_installer.remote import core_gateway, core_gateway_inspector
from hermes_installer.remote.gateway import Principal, RemotePolicy


class CoreGatewayInspectorClientTests(unittest.TestCase):
    def test_skill_restore_ids_are_bound_to_the_selected_source_kind(self):
        resources_id = "a" * 64
        owner_id = "restore-token_0123456789"
        self.assertTrue(core_gateway_inspector._valid_profile_skill_restore_id(
            resources_id, "resources"))
        self.assertFalse(core_gateway_inspector._valid_profile_skill_restore_id(
            resources_id, "owner-added"))
        self.assertTrue(core_gateway_inspector._valid_profile_skill_restore_id(
            owner_id, "owner-added"))
        self.assertFalse(core_gateway_inspector._valid_profile_skill_restore_id(
            owner_id, "resources"))
        self.assertFalse(core_gateway_inspector._valid_profile_skill_restore_id(
            owner_id, "untrusted-source"))
        self.assertTrue(core_gateway_inspector._valid_profile_skill_restore_candidate(owner_id))
        self.assertTrue(core_gateway_inspector._valid_profile_skill_restore_candidate(resources_id))
        self.assertFalse(core_gateway_inspector._valid_profile_skill_restore_candidate("short"))

    def test_owner_turn_mission_binding_requires_typed_value_and_spent_row_match(self):
        from hermes_installer.remote import jarvis_mission_executor

        self.assertIsNone(core_gateway_inspector._mission_binding_from_wire(None))
        self.assertIsNone(core_gateway_inspector._mission_binding_wire(None))
        binding = jarvis_mission_executor.MissionBinding.from_wire({
            "schema": 2, "mission_id": "m" * 24, "revision": 2,
            "plan_sha256": "a" * 64, "task_sha256": "b" * 64,
            "source_profile_id": "hermes", "execution_mode": "oneshot",
            "autonomy_mode": "approval_required", "selected_source_ids": ["orchestrator"],
            "scope_sha256": "c" * 64, "authorization_sha256": None,
        })
        self.assertEqual(core_gateway_inspector._mission_binding_wire(binding), binding.to_wire())
        with self.assertRaises(core_gateway_inspector.CoreInspectionDenied):
            core_gateway_inspector._mission_binding_wire(binding.to_wire())

        reader = object()
        seen = {}

        def resolve(store, resolved_binding, **kwargs):
            seen.update(store=store, binding=resolved_binding, **kwargs)
            return True

        def reader_for_fixed_path(*, path):
            seen["ledger_path"] = path
            return reader

        with patch.object(jarvis_mission_executor, "MissionLedgerReader",
                          side_effect=reader_for_fixed_path), \
             patch.object(jarvis_mission_executor, "resolve_spent_mission_binding", resolve):
            verified = core_gateway_inspector._resolve_spent_mission_binding(
                binding, owner_subject_sha256="c" * 64, gateway_turn_id="d" * 24,
                core_generation="e" * 64, core_source_generation="f" * 64,
                deadline=time.monotonic() + 5)
        self.assertEqual(verified.to_wire(), binding.to_wire())
        self.assertIs(seen["store"], reader)
        self.assertEqual(str(seen["ledger_path"]), "/var/lib/hermes-jarvis-chat/chat.sqlite3")
        self.assertEqual(seen["gateway_turn_id"], "d" * 24)
        self.assertEqual(seen["owner_subject_sha256"], "c" * 64)
        self.assertEqual(seen["core_generation"], "e" * 64)
        self.assertEqual(seen["core_source_generation"], "f" * 64)

        with patch.object(jarvis_mission_executor, "MissionLedgerReader",
                          side_effect=reader_for_fixed_path), \
             patch.object(jarvis_mission_executor, "resolve_spent_mission_binding",
                          return_value=False), \
             self.assertRaises(core_gateway_inspector.CoreInspectionDenied):
            core_gateway_inspector._resolve_spent_mission_binding(
                binding, owner_subject_sha256="c" * 64, gateway_turn_id="d" * 24,
                core_generation="e" * 64, core_source_generation="f" * 64,
                deadline=time.monotonic() + 5)

    def test_retained_ingress_proof_is_one_use_and_bound_to_peer_generation(self):
        config = _config()
        now = time.monotonic()
        proof = {
            "nonce": "d" * 64, "proof_sha256": "e" * 64,
            "issued_monotonic": now - 0.01, "expires_monotonic": now + 3.0,
            "peer_pid": 551, "peer_uid": 63324, "peer_gid": 63324,
            "origin_socket_device": 11, "origin_socket_inode": 12,
            "core_generation": "f" * 64, "config_sha256": config.config_sha256,
            "boot_id": config.boot_id,
        }
        with core_gateway_inspector._RETAINED_INGRESS_LOCK:
            core_gateway_inspector._RETAINED_INGRESS_ISSUES.clear()
        try:
            core_gateway_inspector._retain_ingress_issue(
                caller_pid=440, caller_start_ticks="88", proof=proof)
            retained = core_gateway_inspector._consume_ingress_issue(
                caller_pid=440, caller_start_ticks="88", nonce=proof["nonce"],
                proof_sha256=proof["proof_sha256"], peer=(551, 63324, 63324),
                core_generation=proof["core_generation"], config=config)
            self.assertEqual(retained.issued_monotonic, proof["issued_monotonic"])
            with self.assertRaises(core_gateway_inspector.CoreInspectionDenied):
                core_gateway_inspector._consume_ingress_issue(
                    caller_pid=440, caller_start_ticks="88", nonce=proof["nonce"],
                    proof_sha256=proof["proof_sha256"], peer=(551, 63324, 63324),
                    core_generation=proof["core_generation"], config=config)
        finally:
            with core_gateway_inspector._RETAINED_INGRESS_LOCK:
                core_gateway_inspector._RETAINED_INGRESS_ISSUES.clear()

    def test_skill_learning_candidate_projection_checks_content_digest_and_bounds(self):
        diff = "+ review only\n"
        candidate = {
            "opaque_id": "a" * 24, "revision_sha256": "b" * 64,
            "action": "edit", "created_at": 1.25, "skill_label": "Calendar",
            "summary": "Add an optional event parser.", "diff_text": diff,
            "diff_sha256": hashlib.sha256(diff.encode("utf-8")).hexdigest(),
            "truncated": False, "state": "pending-review",
        }
        self.assertTrue(core_gateway_inspector._valid_learning_candidates(
            [candidate], "read-only-native-review"))
        truncated = dict(candidate, diff_text="short preview", diff_sha256="f" * 64, truncated=True)
        self.assertTrue(core_gateway_inspector._valid_learning_candidates(
            [truncated], "partial"))
        corrupted = dict(candidate, diff_sha256="c" * 64)
        self.assertFalse(core_gateway_inspector._valid_learning_candidates(
            [corrupted], "read-only-native-review"))
        self.assertFalse(core_gateway_inspector._valid_learning_candidates(
            [candidate, candidate], "partial"))
        self.assertFalse(core_gateway_inspector._valid_learning_candidates(
            [candidate], "unavailable"))
        oversized = dict(candidate, diff_text="x" * (256 * 1024 + 1))
        oversized["diff_sha256"] = hashlib.sha256(oversized["diff_text"].encode()).hexdigest()
        self.assertFalse(core_gateway_inspector._valid_learning_candidates(
            [oversized], "partial"))

    def test_learning_pending_reasons_are_closed_and_unique(self):
        accepted = ["pending_member_invalid", "pending_record_skipped"]
        self.assertTrue(core_gateway_inspector._valid_learning_reasons(accepted))
        self.assertFalse(core_gateway_inspector._valid_learning_reasons(
            ["pending_member_invalid", "pending_member_invalid"]))
        self.assertFalse(core_gateway_inspector._valid_learning_reasons(["internal_error"]))

    def test_root_native_tool_reader_uses_exact_live_session_tools_list(self):
        from hermes_installer.remote.core_client import CoreRpcClient

        rows = [
            {"name": "web", "description": "safe public reads", "tool_count": 2,
             "enabled": True, "tools": ["web_search", "web_fetch"]},
            {"name": "terminal", "description": "local command tools", "tool_count": 1,
             "enabled": False, "tools": ["terminal"]},
        ]
        calls = []

        async def fixed_tools_rpc(_client, method, params):
            calls.append((method, params))
            return {"toolsets": rows}

        with patch.object(CoreRpcClient, "_rpc", fixed_tools_rpc):
            names = core_gateway_inspector._read_session_tool_configuration(
                "jarvis-session-123", selected_toolsets=("web",),
                deadline=time.monotonic() + 5)
        self.assertEqual(calls, [("tools.list", {"session_id": "jarvis-session-123"})])
        self.assertEqual(names, ("web_fetch", "web_search"))

        disabled_metadata = [dict(row, enabled=True) for row in rows]
        async def ambiguous_tools_rpc(_client, method, params):
            return {"toolsets": disabled_metadata}
        with patch.object(CoreRpcClient, "_rpc", ambiguous_tools_rpc):
            selected = core_gateway_inspector._read_session_tool_configuration(
                "jarvis-session-123", selected_toolsets=("terminal",),
                deadline=time.monotonic() + 5)
        self.assertEqual(selected, ("terminal",))

    def test_native_tool_projection_only_uses_explicit_configured_toolsets(self):
        raw = (
            b"platform_toolsets:\n  cli: [web, terminal]\n"
        )
        selected, digest = core_gateway_inspector._parse_native_inheritance_config(raw)
        self.assertEqual(selected, ("terminal", "web"))
        self.assertEqual(digest, hashlib.sha256(raw).hexdigest())

        ambiguous = b"inherit_mcp_toolsets: true\ndelegation:\n  orchestrator_enabled: true\n"
        with self.assertRaises(core_gateway_inspector.CoreInspectionDenied):
            core_gateway_inspector._parse_native_inheritance_config(ambiguous)

    def test_skill_learning_ipc_observation_validates_jwt_and_consumes_real_one_use_issue(self):
        config = _config()
        issued = time.monotonic() - 0.05
        proof = {
            "nonce": "1" * 64, "proof_sha256": "2" * 64,
            "issued_monotonic": issued, "expires_monotonic": issued + 4.8,
            "peer_pid": 551, "peer_uid": 996, "peer_gid": 981,
            "origin_socket_device": 11, "origin_socket_inode": 12,
            "core_generation": "3" * 64, "config_sha256": config.config_sha256,
            "boot_id": config.boot_id,
        }
        with core_gateway_inspector._RETAINED_INGRESS_LOCK:
            core_gateway_inspector._RETAINED_INGRESS_ISSUES.clear()
        core_gateway_inspector._retain_ingress_issue(
            caller_pid=440, caller_start_ticks="88", proof=proof)
        current = {key: proof[key] for key in
                   ("proof_sha256", "core_generation", "boot_id", "config_sha256")}
        native = {"state": "read-only-native-review", "pending_reasons": [],
                  "candidates": [], "candidate_count": 0, "diff_bytes": 0}
        principal = Principal("owner@example.test", "owner-subject", time.time() + 60, "4" * 64)
        request = {
            "schema": 1, "op": "observe-skill-learning", "nonce": "5" * 64,
            "peer_pid": 551, "peer_uid": 996, "peer_gid": 981,
            "access_jwt": "forwarded-owner-jwt", "core_generation": proof["core_generation"],
            "ingress_nonce": proof["nonce"], "ingress_proof_sha256": proof["proof_sha256"],
        }
        class IPCConnection:
            def __init__(self, request_body):
                raw = json.dumps(request_body, separators=(",", ":")).encode("utf-8")
                self.incoming = bytearray(struct.pack("!I", len(raw)) + raw)
                self.outgoing = bytearray()
                self.closed = False

            def settimeout(self, _timeout):
                pass

            def getsockopt(self, _level, _option, _length):
                return struct.pack("3i", 440, 996, 981)

            def recv(self, size):
                chunk = bytes(self.incoming[:size])
                del self.incoming[:size]
                return chunk

            def sendall(self, value):
                self.outgoing.extend(value)

            def close(self):
                self.closed = True

        connection = IPCConnection(request)
        try:
            core_gateway_inspector._SERVER_SLOTS.acquire()
            with patch.object(core_gateway_inspector, "_proc_start_ticks", return_value="88"), \
                 patch.object(core_gateway_inspector, "observe_current_ingress", return_value=current) as observe, \
                 patch.object(core_gateway_inspector, "_learning_jwks", return_value=object()), \
                 patch("hermes_installer.remote.gateway.validate_access_jwt", return_value=principal) as validate, \
                 patch.object(core_gateway_inspector, "_run_native_skill_learning_probe", return_value=native) as probe:
                core_gateway_inspector._serve_connection(connection, config)
            frame_size = struct.unpack("!I", connection.outgoing[:4])[0]
            result = json.loads(connection.outgoing[4:4 + frame_size].decode("utf-8"))
            self.assertEqual(frame_size, len(connection.outgoing) - 4)
            self.assertEqual(observe.call_count, 2)
            self.assertEqual(validate.call_args.args[0], request["access_jwt"])
            self.assertTrue(probe.called)
            self.assertEqual(result["readiness"], native["state"])
            self.assertEqual(result["ingress_proof_sha256"], proof["proof_sha256"])
            self.assertTrue(connection.closed)
            with self.assertRaises(core_gateway_inspector.CoreInspectionDenied):
                core_gateway_inspector._consume_ingress_issue(
                    caller_pid=440, caller_start_ticks="88", nonce=proof["nonce"],
                    proof_sha256=proof["proof_sha256"], peer=(551, 996, 981),
                    core_generation=proof["core_generation"], config=config)
        finally:
            with core_gateway_inspector._RETAINED_INGRESS_LOCK:
                core_gateway_inspector._RETAINED_INGRESS_ISSUES.clear()

    def test_skill_learning_jwt_rejection_consumes_issue_without_running_native_helper(self):
        config = _config()
        issued = time.monotonic() - 0.05
        proof = {
            "nonce": "6" * 64, "proof_sha256": "7" * 64,
            "issued_monotonic": issued, "expires_monotonic": issued + 4.8,
            "peer_pid": 551, "peer_uid": 996, "peer_gid": 981,
            "origin_socket_device": 11, "origin_socket_inode": 12,
            "core_generation": "8" * 64, "config_sha256": config.config_sha256,
            "boot_id": config.boot_id,
        }
        with core_gateway_inspector._RETAINED_INGRESS_LOCK:
            core_gateway_inspector._RETAINED_INGRESS_ISSUES.clear()
        core_gateway_inspector._retain_ingress_issue(
            caller_pid=440, caller_start_ticks="88", proof=proof)
        current = {"proof_sha256": proof["proof_sha256"],
                   "core_generation": proof["core_generation"],
                   "boot_id": proof["boot_id"], "config_sha256": proof["config_sha256"]}
        request = {
            "schema": 1, "op": "observe-skill-learning", "nonce": "9" * 64,
            "peer_pid": 551, "peer_uid": 996, "peer_gid": 981,
            "access_jwt": "rejected-owner-jwt", "core_generation": proof["core_generation"],
            "ingress_nonce": proof["nonce"], "ingress_proof_sha256": proof["proof_sha256"],
        }
        try:
            with patch.object(core_gateway_inspector, "_proc_start_ticks", return_value="88"), \
                 patch.object(core_gateway_inspector, "observe_current_ingress", return_value=current), \
                 patch.object(core_gateway_inspector, "_learning_jwks", return_value=object()), \
                 patch("hermes_installer.remote.gateway.validate_access_jwt",
                       side_effect=core_gateway.CoreGatewayDenied("invalid")), \
                 patch.object(core_gateway_inspector, "_run_native_skill_learning_probe") as probe:
                with self.assertRaises(core_gateway.CoreGatewayDenied):
                    core_gateway_inspector.observe_skill_learning(
                        config, request=request, caller_pid=440, caller_uid=996, caller_gid=981,
                        peer_pid=551, peer_uid=996, peer_gid=981)
            self.assertFalse(probe.called)
            with self.assertRaises(core_gateway_inspector.CoreInspectionDenied):
                core_gateway_inspector._consume_ingress_issue(
                    caller_pid=440, caller_start_ticks="88", nonce=proof["nonce"],
                    proof_sha256=proof["proof_sha256"], peer=(551, 996, 981),
                    core_generation=proof["core_generation"], config=config)
        finally:
            with core_gateway_inspector._RETAINED_INGRESS_LOCK:
                core_gateway_inspector._RETAINED_INGRESS_ISSUES.clear()

    def test_skill_learning_helper_expiry_does_not_extend_original_ingress_deadline(self):
        config = _config()
        start = time.monotonic()
        clock = [start]
        proof = {
            "nonce": "a" * 64, "proof_sha256": "b" * 64,
            "issued_monotonic": start - 0.05, "expires_monotonic": start + 4.5,
            "peer_pid": 551, "peer_uid": 996, "peer_gid": 981,
            "origin_socket_device": 11, "origin_socket_inode": 12,
            "core_generation": "c" * 64, "config_sha256": config.config_sha256,
            "boot_id": config.boot_id,
        }
        with core_gateway_inspector._RETAINED_INGRESS_LOCK:
            core_gateway_inspector._RETAINED_INGRESS_ISSUES.clear()
        core_gateway_inspector._retain_ingress_issue(
            caller_pid=440, caller_start_ticks="88", proof=proof)
        current = {"proof_sha256": proof["proof_sha256"],
                   "core_generation": proof["core_generation"],
                   "boot_id": proof["boot_id"], "config_sha256": proof["config_sha256"]}
        principal = Principal("owner@example.test", "owner-subject", time.time() + 60, "d" * 64)
        request = {
            "schema": 1, "op": "observe-skill-learning", "nonce": "e" * 64,
            "peer_pid": 551, "peer_uid": 996, "peer_gid": 981,
            "access_jwt": "forwarded-owner-jwt", "core_generation": proof["core_generation"],
            "ingress_nonce": proof["nonce"], "ingress_proof_sha256": proof["proof_sha256"],
        }

        def native_read(*, deadline):
            self.assertEqual(deadline, proof["expires_monotonic"])
            clock[0] = deadline
            return {"state": "partial", "pending_reasons": ["pending_custody_changed"],
                    "candidates": [], "candidate_count": 0, "diff_bytes": 0}

        try:
            with patch.object(core_gateway_inspector.time, "monotonic", side_effect=lambda: clock[0]), \
                 patch.object(core_gateway_inspector, "_proc_start_ticks", return_value="88"), \
                 patch.object(core_gateway_inspector, "observe_current_ingress", return_value=current), \
                 patch.object(core_gateway_inspector, "_learning_jwks", return_value=object()), \
                 patch("hermes_installer.remote.gateway.validate_access_jwt", return_value=principal), \
                 patch.object(core_gateway_inspector, "_run_native_skill_learning_probe", side_effect=native_read):
                with self.assertRaises(core_gateway_inspector.CoreInspectionDenied):
                    core_gateway_inspector.observe_skill_learning(
                        config, request=request, caller_pid=440, caller_uid=996, caller_gid=981,
                        peer_pid=551, peer_uid=996, peer_gid=981)
            self.assertFalse(core_gateway_inspector._RETAINED_INGRESS_ISSUES)
        finally:
            with core_gateway_inspector._RETAINED_INGRESS_LOCK:
                core_gateway_inspector._RETAINED_INGRESS_ISSUES.clear()

    def test_native_skill_learning_probe_fails_closed_on_helper_pin_mismatch(self):
        directory = SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0)
        helper = SimpleNamespace(st_mode=stat.S_IFREG | 0o644, st_uid=0, st_nlink=1,
                                 st_size=core_gateway_inspector.NATIVE_SKILL_LEARNING_SIZE)
        with patch.object(core_gateway_inspector.os, "lstat",
                          side_effect=lambda path: helper if Path(path).name ==
                          "native_skill_learning_probe.py" else directory), \
             patch.object(core_gateway_inspector, "_protected_file_sha", return_value="0" * 64), \
             patch.object(core_gateway_inspector.subprocess, "Popen") as spawn:
            with self.assertRaisesRegex(ValueError, "helper custody differs"):
                core_gateway_inspector._run_native_skill_learning_probe(
                    deadline=time.monotonic() + 3.0)
        self.assertFalse(spawn.called)

    def test_module_entry_delegates_to_canonical_gateway_module(self):
        called = []

        def canonical_entry():
            called.append(core_gateway.CoreGatewayConfig)

        with patch.object(core_gateway, "main", canonical_entry), \
             warnings.catch_warnings():
            warnings.simplefilter("ignore", RuntimeWarning)
            executed = runpy.run_module(
                "hermes_installer.remote.core_gateway", run_name="__main__")

        self.assertEqual(called, [core_gateway.CoreGatewayConfig])
        # -m still creates a duplicate __main__ class namespace, but does not
        # use it to construct runtime state or invoke its duplicate main().
        self.assertIsNot(executed["CoreGatewayConfig"], core_gateway.CoreGatewayConfig)

    def test_inspector_module_entry_uses_canonical_custody_for_native_registry(self):
        from hermes_installer.remote import core_native_observer as observer

        accepted = []

        def canonical_entry():
            custody = object.__new__(core_gateway_inspector.CoreNativeObserverCustody)
            with patch.object(observer, "_load_root_obsidian_origin_state",
                              return_value=({}, {})), \
                 patch.object(observer, "_load_root_obsidian_history", return_value=[]), \
                 patch.object(observer, "_read_root_native_activity_bytes", return_value=None), \
                 patch("hermes_installer.components.resources_active_profile_source."
                       "RootVerifiedJarvisMasterSource.current_master_source",
                       return_value=None):
                registry = observer.RootCoreNativeObservationRegistry.from_current_core_custody(
                    custody, config=object())
            accepted.append((custody, registry))

        with patch.object(core_gateway_inspector, "main", canonical_entry), \
             warnings.catch_warnings():
            warnings.simplefilter("ignore", RuntimeWarning)
            executed = runpy.run_module(
                "hermes_installer.remote.core_gateway_inspector", run_name="__main__")

        self.assertEqual(len(accepted), 1)
        custody, registry = accepted[0]
        self.assertIs(type(custody), core_gateway_inspector.CoreNativeObserverCustody)
        self.assertIs(registry._custody, custody)
        self.assertIsNot(executed["CoreNativeObserverCustody"], type(custody))

    def test_real_ingress_verifier_denies_unowned_inspector_socket(self):
        config = _config()
        wrong_socket = SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=0,
                                       st_gid=config.gateway_gid)
        with patch.object(core_gateway, "_read_config_current", return_value=None), \
             patch.object(core_gateway_inspector.os, "lstat", return_value=wrong_socket):
            with self.assertRaises(core_gateway.CoreGatewayDenied):
                core_gateway_inspector.verify_current_ingress(
                    config, peer_pid=431, peer_uid=63324, peer_gid=63324)

    def test_core_overview_projection_rejects_unreviewed_provider_strings_and_tampering(self):
        config = _config()
        projection = {
            "core_version": "7085fbf77532", "provider": "https://secret.example/v1",
            "model": None, "account_state": "unknown", "resources_state": "pending",
            "resource_counts": None, "resources_revision": None, "artifact_sha256": None,
            "discovery_observed_at_utc": None, "active_prompt_matches_bundled_primary": None,
        }
        claims = {
            "schema": 1, "nonce": "d" * 64, "boot_id": config.boot_id,
            "issued_monotonic": 10.0, "expires_monotonic": 11.0,
            "config_sha256": config.config_sha256, "core_generation": "e" * 64,
            "core_source_generation": "f" * 64, "projection": projection,
        }
        observation = core_gateway_inspector.CoreVerifiedOverviewObservation(
            **claims, proof_sha256=core_gateway_inspector._overview_digest(claims),
            _seal=core_gateway_inspector._OVERVIEW_PROOF_SEAL)

        self.assertFalse(observation.verify_current(config, peer_pid=431, peer_uid=996,
            peer_gid=981, accepted_ingress=None, now=10.5))
        changed = dataclasses.replace(observation, core_generation="0" * 64)
        self.assertFalse(changed.verify_current(config, peer_pid=431, peer_uid=996,
            peer_gid=981, accepted_ingress=None, now=10.5))

    def test_fixed_model_projection_returns_only_safe_labels_from_private_yaml(self):
        raw = (b"model:\n  provider: zai\n  default: zai/glm-5.2\n"
               b"  api_key: never-project-this\n  base_url: https://secret.invalid\n")
        with patch.object(core_gateway_inspector, "_fixed_model_config_bytes", return_value=raw):
            provider, model, digest = core_gateway_inspector._fixed_model_config_projection()
        self.assertEqual((provider, model), ("zai", "zai/glm-5.2"))
        self.assertEqual(digest, hashlib.sha256(raw).hexdigest())

        invalid = b"model:\n  provider: https://secret.invalid\n  default: /private/path\n"
        with patch.object(core_gateway_inspector, "_fixed_model_config_bytes", return_value=invalid):
            self.assertEqual(core_gateway_inspector._fixed_model_config_projection(),
                             (None, None, hashlib.sha256(invalid).hexdigest()))

    def test_fixed_model_projection_rejects_duplicate_yaml_keys(self):
        raw = b"model:\n  provider: safe\n  provider: shadow\n  default: model-x\n"
        with patch.object(core_gateway_inspector, "_fixed_model_config_bytes", return_value=raw):
            provider, model, digest = core_gateway_inspector._fixed_model_config_projection()
        self.assertEqual((provider, model), (None, None))
        self.assertEqual(digest, hashlib.sha256(raw).hexdigest())

    def test_core_overview_proof_expires_before_dashboard_can_reuse_it(self):
        config = _config()
        accepted = _accepted_observation(config, now=10.0, lease_seconds=2.0)
        projection = {
            "core_version": "7085fbf77532", "provider": None, "model": None,
            "account_state": "unknown", "resources_state": "pending",
            "resource_counts": None, "resources_revision": None, "artifact_sha256": None,
            "discovery_observed_at_utc": None, "active_prompt_matches_bundled_primary": None,
        }
        claims = {
            "schema": 1, "nonce": "e" * 64, "boot_id": config.boot_id,
            "issued_monotonic": 10.0, "expires_monotonic": 11.0,
            "config_sha256": config.config_sha256, "core_generation": accepted.core_generation,
            "core_source_generation": accepted.root_observation.core_source_generation,
            "projection": projection,
        }
        observation = core_gateway_inspector.CoreVerifiedOverviewObservation(
            **claims, proof_sha256=core_gateway_inspector._overview_digest(claims),
            _seal=core_gateway_inspector._OVERVIEW_PROOF_SEAL)

        with patch.object(core_gateway.CoreAcceptedIngressObservation,
                          "verify_current", return_value=True), \
             patch.object(core_gateway_inspector.time, "monotonic", return_value=10.5):
            self.assertTrue(observation.verify_current(config, peer_pid=440, peer_uid=996,
                peer_gid=981, accepted_ingress=accepted))
        with patch.object(core_gateway.CoreAcceptedIngressObservation,
                          "verify_current", return_value=True), \
             patch.object(core_gateway_inspector.time, "monotonic", return_value=11.0):
            self.assertFalse(observation.verify_current(config, peer_pid=440, peer_uid=996,
                peer_gid=981, accepted_ingress=accepted))

    def test_real_ingress_verifier_wraps_ipc_failure_without_nameerror(self):
        config = _config()
        owned_socket = SimpleNamespace(st_mode=stat.S_IFSOCK | 0o660, st_uid=0,
                                       st_gid=config.gateway_gid)

        class ConnectFailureSocket:
            def settimeout(self, _seconds):
                pass

            def connect(self, _path):
                raise OSError("private socket detail must not escape")

            def close(self):
                pass

        with patch.object(core_gateway, "_read_config_current", return_value=None), \
             patch.object(core_gateway_inspector.os, "lstat", return_value=owned_socket), \
             patch.object(core_gateway_inspector.socket, "socket", return_value=ConnectFailureSocket()):
            with self.assertRaisesRegex(core_gateway.CoreGatewayDenied,
                                        "root core ingress proof is unavailable"):
                core_gateway_inspector.verify_current_ingress(
                    config, peer_pid=431, peer_uid=63324, peer_gid=63324)


def _config():
    digest = "a" * 64
    return core_gateway.CoreGatewayConfig(
        hostname="jarvis.example.test", issuer="https://team.cloudflareaccess.com",
        audience="core-test-audience", allowed_emails=frozenset({"owner@example.test"}),
        gateway_uid=996, gateway_gid=981, core_uid=1000, core_gid=1000,
        boot_id="12345678-1234-1234-1234-123456789012",
        gateway_unit_sha256=digest, gateway_python_sha256=digest,
        tunnel_unit_sha256=digest, cloudflared_binary_sha256=digest,
        core_unit_sha256=digest, core_launcher_sha256=digest,
        core_python=core_gateway_inspector.CORE_PYTHON_LINK,
        core_python_sha256=core_gateway_inspector.CORE_PYTHON_SHA256,
        ingress_socket=core_gateway.CORE_INGRESS_SOCKET,
        config_path=core_gateway.CORE_CONFIG, config_sha256=digest)


def _root_observation(config, *, now=10.0, peer_uid=996, peer_gid=981):
    nonce = "b" * 64
    core_pid, start_ticks, listener_inode = 330, "77", 8822
    invocation = "12345678-1234-1234-1234-123456789012"
    source_generation = _expected_source_generation(config)
    generation = hashlib.sha256(
        b"hermes-jarvis-core-generation-v1\0" +
        f"{invocation}\0{core_pid}\0{start_ticks}\0{listener_inode}\0{source_generation}".encode("ascii")
    ).hexdigest()
    claims = {
        "schema": 1, "nonce": nonce, "boot_id": config.boot_id,
        "issued_monotonic": now, "expires_monotonic": now + 5.0,
        "peer_pid": 440, "peer_uid": peer_uid, "peer_gid": peer_gid,
        "peer_start_ticks": "88", "tunnel_invocation_id": invocation,
        "tunnel_unit_sha256": config.tunnel_unit_sha256,
        "tunnel_executable_sha256": config.cloudflared_binary_sha256,
        "origin_socket_device": 1, "origin_socket_inode": 2,
        "gateway_unit_sha256": config.gateway_unit_sha256,
        "core_unit_sha256": config.core_unit_sha256,
        "core_invocation_id": invocation, "core_pid": core_pid,
        "core_start_ticks": start_ticks, "core_listener_inode": listener_inode,
        "core_source_generation": source_generation,
        "core_generation": generation, "config_sha256": config.config_sha256,
    }
    proof_sha = core_gateway_inspector._observation_digest(claims)
    return core_gateway_inspector.CoreVerifiedIngressObservation(
        **claims, proof_sha256=proof_sha, _seal=core_gateway_inspector._PROOF_SEAL)


def _expected_source_generation(config):
    inspector = core_gateway_inspector
    if config.core_python != inspector.CORE_PYTHON_LINK:
        raise AssertionError("fixture must use the reviewed PM Python link")
    closure = {
        "source_revision": inspector.CORE_SOURCE_REVISION,
        "files": dict(inspector.CORE_SOURCE_FILES),
        "pyvenv_cfg_sha256": inspector.CORE_PYVENV_CFG_SHA256,
        "python_sha256": inspector.CORE_PYTHON_SHA256,
    }
    canonical = json.dumps(closure, sort_keys=True, separators=(",", ":")).encode("ascii")
    return hashlib.sha256(b"hermes-jarvis-core-source-generation-v1\0" + canonical).hexdigest()


def _accepted_observation(config, *, now, lease_seconds=4.0, peer_uid=996, peer_gid=981):
    root = _root_observation(config, now=now - 0.01, peer_uid=peer_uid, peer_gid=peer_gid)
    principal = Principal("owner@example.test", "owner-subject", time.time() + 120, "c" * 64)
    jwt_expiry = now + 100.0
    expiry = min(now + lease_seconds, root.expires_monotonic, jwt_expiry)
    claims = dict(principal=principal, jwt_expiry=jwt_expiry, root_proof=root,
        peer=(440, peer_uid, peer_gid), listener=(1, 2), issued=now - 0.01, expiry=expiry,
        core_generation=root.core_generation, config_sha256=config.config_sha256)
    return core_gateway.CoreAcceptedIngressObservation(
        principal, jwt_expiry, root, 440, peer_uid, peer_gid, 1, 2, now - 0.01, expiry,
        root.core_generation, config.config_sha256,
        core_gateway._accepted_claim_digest(**claims), core_gateway._ACCEPTED_INGRESS_SEAL)


def _overview_observation(config, accepted, *, now):
    """Create a sealed test proof tied to the real accepted-ingress fixture."""
    projection = {
        "core_version": core_gateway_inspector.CORE_SOURCE_REVISION[:12],
        "provider": None, "model": None, "account_state": "unknown",
        "resources_state": "pending", "resource_counts": None,
        "resources_revision": None, "artifact_sha256": None,
        "discovery_observed_at_utc": None,
        "active_prompt_matches_bundled_primary": None,
    }
    claims = {
        "schema": 1, "nonce": "a" * 64, "boot_id": config.boot_id,
        "issued_monotonic": now,
        "expires_monotonic": min(now + 3.0, accepted.expires_monotonic),
        "config_sha256": config.config_sha256,
        "core_generation": accepted.core_generation,
        "core_source_generation": accepted.root_observation.core_source_generation,
        "projection": projection,
    }
    return core_gateway_inspector.CoreVerifiedOverviewObservation(
        **claims, proof_sha256=core_gateway_inspector._overview_digest(claims),
        _seal=core_gateway_inspector._OVERVIEW_PROOF_SEAL)


def _jarvis_service(launch, store_path):
    from hermes_installer.remote.jarvis_chat import JarvisChatService, JarvisChatStore
    from hermes_installer.remote.core_client import CoreRpcClient

    class FixedStatusClient(CoreRpcClient):
        async def list_profiles(self):
            return []

        async def list_schedules(self):
            return []

        async def list_plugins(self):
            return []

        async def mcp_status(self):
            return {"servers": [], "checked_at": None}

    return JarvisChatService(
        JarvisChatStore(Path(store_path)), FixedStatusClient(),
        principal_from_request=launch.principal_from_request,
    )


class CoreGatewayProofTests(unittest.TestCase):
    def test_dynamic_tunnel_peer_is_accepted_only_when_bound_to_root_proof(self):
        config = _config()
        dynamic_uid = 63_324
        dynamic_gid = 63_324
        accepted = _accepted_observation(config, now=12.0,
                                         peer_uid=dynamic_uid, peer_gid=dynamic_gid)
        fake_stat = SimpleNamespace(st_mode=stat.S_IFSOCK | 0o660, st_dev=1, st_ino=2,
                                    st_uid=config.gateway_uid, st_gid=config.gateway_gid)
        with patch.object(core_gateway_inspector, "_boot_id", return_value=config.boot_id), \
             patch.object(core_gateway.os, "lstat", return_value=fake_stat), \
             patch.object(core_gateway, "_read_config_current"):
            self.assertIs(accepted.verify_current(config, now=13.0), True)
            changed = dataclasses.replace(accepted, peer_uid=config.gateway_uid,
                                          peer_gid=config.gateway_gid)
            self.assertIs(changed.verify_current(config, now=13.0), False)

        class TunnelPeer:
            family = core_gateway.socket.AF_UNIX

            def getsockname(self):
                return str(config.ingress_socket)

            def getsockopt(self, *_args):
                return struct.pack("3i", 440, dynamic_uid, dynamic_gid)

        request = SimpleNamespace(transport=SimpleNamespace(
            get_extra_info=lambda name: TunnelPeer() if name == "socket" else None))
        with patch.object(core_gateway.os, "lstat", return_value=fake_stat):
            self.assertEqual(core_gateway._request_peer(request, config, (1, 2)),
                             (440, dynamic_uid, dynamic_gid, (1, 2)))

    def test_config_load_accepts_only_actual_pinned_core_python_path(self):
        document = {
            "schema": 1, "hostname": "jarvis.example.test",
            "issuer": "https://team.cloudflareaccess.com", "audience": "core-test-audience",
            "allowed_emails": ["owner@example.test"], "gateway_uid": 996,
            "gateway_gid": 981, "core_uid": 1000, "core_gid": 1000,
            "boot_id": "12345678-1234-1234-1234-123456789012",
            "gateway_unit_sha256": "a" * 64, "gateway_python_sha256": "b" * 64,
            "tunnel_unit_sha256": "c" * 64, "cloudflared_binary_sha256": "d" * 64,
            "core_unit_sha256": "e" * 64, "core_launcher_sha256": "f" * 64,
            "core_python": str(core_gateway_inspector.CORE_PYTHON_LINK),
            "core_python_sha256": core_gateway_inspector.CORE_PYTHON_SHA256,
            "ingress_socket": str(core_gateway.CORE_INGRESS_SOCKET),
        }
        with tempfile.TemporaryDirectory() as temporary:
            config_path = Path(temporary) / "gateway.json"
            config_path.write_text(json.dumps(document), encoding="utf-8")
            config_path.chmod(0o600)
            parent_info = SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0, st_gid=0)
            real_lstat = os.lstat

            def lstat(path, *args, **kwargs):
                if Path(path) == config_path.parent:
                    return parent_info
                return real_lstat(path, *args, **kwargs)

            with patch.object(core_gateway, "CORE_CONFIG", config_path), \
                 patch.object(core_gateway, "CORE_CONFIG_DIR", config_path.parent), \
                 patch.object(core_gateway.os, "lstat", side_effect=lstat):
                loaded = core_gateway.CoreGatewayConfig.load(
                    path=config_path, expected_owner_uid=os.getuid())
                self.assertEqual(loaded.core_python, core_gateway_inspector.CORE_PYTHON_LINK)
                self.assertEqual(loaded.allowed_emails, frozenset({"owner@example.test"}))

                document["allowed_emails"] = [
                    " Owner@Example.Test ", "member-one@example.test", "member-two@example.test",
                ]
                config_path.write_text(json.dumps(document), encoding="utf-8")
                household = core_gateway.CoreGatewayConfig.load(
                    path=config_path, expected_owner_uid=os.getuid())
                self.assertEqual(household.allowed_emails, frozenset({
                    "owner@example.test", "member-one@example.test", "member-two@example.test",
                }))
                max_length_email = "x" * 249 + "@a.co"
                document["allowed_emails"] = [max_length_email]
                config_path.write_text(json.dumps(document), encoding="utf-8")
                self.assertEqual(core_gateway.CoreGatewayConfig.load(
                    path=config_path, expected_owner_uid=os.getuid()).allowed_emails,
                    frozenset({max_length_email}))
                document["allowed_emails"] = [f"member{index}@example.test" for index in range(32)]
                config_path.write_text(json.dumps(document), encoding="utf-8")
                self.assertEqual(len(core_gateway.CoreGatewayConfig.load(
                    path=config_path, expected_owner_uid=os.getuid()).allowed_emails), 32)

                invalid_allowlists = (
                    [], ["owner@example.test", " OWNER@example.test "],
                    ["owner@example.test", "bad address@example.test"],
                    ["owner@example.test\nother@example.test"],
                    ["x" * 255 + "@example.test"],
                    [f"member{index}@example.test" for index in range(33)],
                    ["owner@example.test", "", "member@example.test"],
                )
                for invalid in invalid_allowlists:
                    with self.subTest(allowed_emails=invalid):
                        document["allowed_emails"] = invalid
                        config_path.write_text(json.dumps(document), encoding="utf-8")
                        with self.assertRaises(core_gateway.CoreGatewayDenied):
                            core_gateway.CoreGatewayConfig.load(
                                path=config_path, expected_owner_uid=os.getuid())

                document["core_python"] = (
                    "/home/admin/HermesInstaller/data/installs/" + "0" * 24 +
                    "/environments/" + "0" * 32 + "/venv/bin/python")
                config_path.write_text(json.dumps(document), encoding="utf-8")
                with self.assertRaises(core_gateway.CoreGatewayDenied):
                    core_gateway.CoreGatewayConfig.load(
                        path=config_path, expected_owner_uid=os.getuid())

                document["core_python"] = str(core_gateway_inspector.CORE_PYTHON_LINK)
                config_path.write_text(json.dumps(document), encoding="utf-8")
                hardlink = Path(temporary) / "linked-config.json"
                os.link(config_path, hardlink)
                with self.assertRaises(core_gateway.CoreGatewayDenied):
                    core_gateway.CoreGatewayConfig.load(
                        path=config_path, expected_owner_uid=os.getuid())

    def test_root_and_accepted_proofs_bind_exact_claims_and_original_deadline(self):
        config = _config()
        fake_stat = SimpleNamespace(st_mode=stat.S_IFSOCK | 0o660, st_dev=1, st_ino=2,
                                    st_uid=config.gateway_uid, st_gid=config.gateway_gid)
        with patch.object(core_gateway_inspector, "_boot_id", return_value=config.boot_id), \
             patch.object(core_gateway.os, "lstat", return_value=fake_stat), \
             patch.object(core_gateway, "_read_config_current"):
            root = _root_observation(config)
            self.assertIs(root.verify_current(config, peer_pid=440, peer_uid=996, peer_gid=981,
                listener_identity=(1, 2), now=12.0), True)
            self.assertIs(root.verify_current(config, peer_pid=441, peer_uid=996, peer_gid=981,
                listener_identity=(1, 2), now=12.0), False)
            self.assertIs(root.verify_current(config, peer_pid=440, peer_uid=996, peer_gid=981,
                listener_identity=(1, 2), now=15.0), False)
            changed = dataclasses.replace(root, peer_uid=1000)
            self.assertIs(changed.verify_current(config, peer_pid=440, peer_uid=1000, peer_gid=981,
                listener_identity=(1, 2), now=12.0), False)
            accepted = _accepted_observation(config, now=12.0)
            self.assertIs(accepted.verify_current(config, now=13.0), True)
            expanded_config = dataclasses.replace(config, allowed_emails=frozenset({
                "owner@example.test", "member-one@example.test", "member-two@example.test",
            }), config_sha256="9" * 64)
            self.assertIs(accepted.verify_current(expanded_config, now=13.0), False)
            extended = dataclasses.replace(accepted, expires_monotonic=accepted.issued_monotonic + 30)
            self.assertIs(extended.verify_current(config, now=13.0), False)

    def test_core_process_environment_binds_official_source_and_session_reference(self):
        secret = b"private-session-token-value-never-reported-1234"
        environment = {
            b"HOME": b"/home/admin", b"HERMES_HOME": b"/home/admin/.hermes",
            b"PATH": core_gateway_inspector.CORE_PATH.encode(),
            b"HERMES_DISABLE_LAZY_INSTALLS": b"1", b"PYTHONNOUSERSITE": b"1",
            b"PYTHONDONTWRITEBYTECODE": b"1",
            b"PYTHONPATH": core_gateway_inspector._core_pythonpath().encode(),
            b"CREDENTIALS_DIRECTORY": core_gateway_inspector.CORE_CREDENTIALS_DIRECTORY.encode(),
            b"HERMES_DASHBOARD_SESSION_TOKEN": secret,
        }
        core_gateway_inspector._validate_core_process_environment(environment, secret)
        for key, value in ((b"PYTHONPATH", b"/tmp/unreviewed"),
                           (b"PYTHONPATH", (core_gateway_inspector._core_pythonpath() + ":/tmp/extra").encode()),
                           (b"HERMES_DISABLE_LAZY_INSTALLS", b"0"),
                           (b"CREDENTIALS_DIRECTORY", b"/tmp/elsewhere")):
            changed = dict(environment)
            changed[key] = value
            with self.assertRaises(core_gateway_inspector.CoreInspectionDenied):
                core_gateway_inspector._validate_core_process_environment(changed, secret)
        changed = dict(environment)
        changed[b"PYTHONHOME"] = b"/tmp/python"
        with self.assertRaises(core_gateway_inspector.CoreInspectionDenied):
            core_gateway_inspector._validate_core_process_environment(changed, secret)

    def test_native_adapter_source_generation_is_closed_over_fixed_files(self):
        inspector = core_gateway_inspector
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "src"
            module = source / "hermes_installer" / "remote" / "core_gateway_inspector.py"
            module.parent.mkdir(parents=True)
            module.write_text("fixed inspector source fixture")
            reported = dict(inspector.CORE_NATIVE_ADAPTER_SOURCE_FILES)

            def fixed_digest(path, **_kwargs):
                relative = path.relative_to(source).as_posix()
                return reported[relative]

            with patch.object(inspector, "__file__", str(module)), \
                 patch.object(inspector, "CORE_NATIVE_ADAPTER_SOURCE", source), \
                 patch.object(inspector, "_root_immutable_directory", lambda _path: None), \
                 patch.object(inspector, "_protected_file_sha", side_effect=fixed_digest):
                deadline = time.monotonic() + 5
                valid = inspector._current_native_adapter_generation(deadline=deadline)
                self.assertRegex(valid, r"^[0-9a-f]{64}$")
                changed_member = next(iter(reported))
                reported[changed_member] = "0" * 64
                with self.assertRaises(inspector.CoreInspectionDenied):
                    inspector._current_native_adapter_generation(deadline=deadline)

    def test_calendar_and_native_settings_sources_are_pinned(self):
        inspector = core_gateway_inspector
        pins = inspector.CORE_NATIVE_ADAPTER_SOURCE_FILES
        source = inspector.CORE_NATIVE_ADAPTER_SOURCE
        for relative in (
                "hermes_installer/remote/owner_calendar_native.py",
                "hermes_installer/remote/jarvis_calendar.py",
                "hermes_installer/remote/jarvis_settings_admin.py"):
            with self.subTest(relative=relative):
                self.assertIn(relative, pins)
                self.assertEqual(hashlib.sha256((source / relative).read_bytes()).hexdigest(),
                                 pins[relative])

    def test_proc_environment_reader_returns_hashable_bytes_and_rejects_bad_entries(self):
        environment = core_gateway_inspector._read_proc_environment(
            os.getpid(), deadline=time.monotonic() + 2)
        self.assertTrue(environment)
        self.assertTrue(all(type(key) is bytes and type(value) is bytes
                            for key, value in environment.items()))

        for raw in (b"BROKEN\0", b"DUP=one\0DUP=two\0"):
            with self.subTest(raw=raw), \
                 patch.object(core_gateway_inspector.os, "open", return_value=17), \
                 patch.object(core_gateway_inspector.os, "read", side_effect=[raw, b""]), \
                 patch.object(core_gateway_inspector.os, "close"):
                with self.assertRaises(core_gateway_inspector.CoreInspectionDenied):
                    core_gateway_inspector._read_proc_environment(
                        99, deadline=time.monotonic() + 2)

    def test_source_proof_checks_exact_git_and_reviewed_file_closure(self):
        config = _config()
        expected = {str(core_gateway_inspector.CORE_SOURCE / relative): digest
                    for relative, digest in core_gateway_inspector.CORE_SOURCE_FILES.items()}
        expected[str(config.core_python.parent.parent / "pyvenv.cfg")] = (
            core_gateway_inspector.CORE_PYVENV_CFG_SHA256)
        source_dir = SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=1000, st_gid=1000)

        def digest(path, **_kwargs):
            return expected[str(path)]

        with patch.object(core_gateway_inspector.os, "lstat", return_value=source_dir), \
             patch.object(core_gateway_inspector, "_run_source_git", side_effect=[
                 (core_gateway_inspector.CORE_SOURCE_REVISION + "\n").encode(), b""]), \
             patch.object(core_gateway_inspector, "_protected_file_sha", side_effect=digest):
            proof = core_gateway_inspector._current_core_source(config, deadline=time.monotonic() + 5)
        self.assertRegex(proof, r"^[0-9a-f]{64}$")

    def test_source_proof_rejects_dirty_tree_wrong_revision_and_expired_budget(self):
        config = _config()
        source_dir = SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=1000, st_gid=1000)
        with patch.object(core_gateway_inspector.os, "lstat", return_value=source_dir), \
             patch.object(core_gateway_inspector, "_run_source_git", side_effect=[
                 (core_gateway_inspector.CORE_SOURCE_REVISION + "\n").encode(), b" M pm/lock.json\n"]):
            with self.assertRaises(core_gateway_inspector.CoreInspectionDenied):
                core_gateway_inspector._current_core_source(config, deadline=time.monotonic() + 5)
        with patch.object(core_gateway_inspector.os, "lstat", return_value=source_dir), \
             patch.object(core_gateway_inspector, "_run_source_git", return_value=b"0" * 40 + b"\n"):
            with self.assertRaises(core_gateway_inspector.CoreInspectionDenied):
                core_gateway_inspector._current_core_source(config, deadline=time.monotonic() + 5)
        with patch.object(core_gateway_inspector.os, "lstat", return_value=source_dir):
            with self.assertRaises(core_gateway_inspector.CoreInspectionDenied):
                core_gateway_inspector._current_core_source(config, deadline=time.monotonic() - 1)

    def test_unit_process_checks_fixed_gateway_and_tunnel_launch_contracts(self):
        config = dataclasses.replace(_config(), gateway_unit_sha256="1" * 64,
            gateway_python_sha256="2" * 64, tunnel_unit_sha256="3" * 64,
            cloudflared_binary_sha256="4" * 64)
        cases = (
            (core_gateway_inspector.CORE_GATEWAY_UNIT, 440, None, None,
                config.gateway_unit_sha256, {
                "FragmentPath": str(core_gateway_inspector.CORE_GATEWAY_UNIT_PATH),
                "User": str(config.gateway_uid), "Group": str(config.gateway_gid),
            }, core_gateway_inspector.GATEWAY_EXECUTABLE,
                (core_gateway_inspector.GATEWAY_ARGV[0], *core_gateway_inspector.GATEWAY_ARGV[1:]),
                config.gateway_uid, config.gateway_gid, config.gateway_python_sha256),
            (core_gateway_inspector.TUNNEL_UNIT, 441, 998, config.gateway_gid,
                config.tunnel_unit_sha256, {
                "FragmentPath": str(core_gateway_inspector.TUNNEL_UNIT_PATH),
                "DynamicUser": "yes", "SupplementaryGroups": str(config.gateway_gid),
            }, core_gateway_inspector.TUNNEL_EXECUTABLE,
                core_gateway_inspector.TUNNEL_ARGV, 998, config.gateway_gid,
                config.cloudflared_binary_sha256),
        )
        for unit, pid, peer_uid, peer_gid, unit_digest, properties, executable, argv, uid, gid, digest in cases:
            with self.subTest(unit=unit):
                properties = {"MainPID": str(pid),
                              "ControlGroup": f"/system.slice/{unit}",
                              "InvocationID": "12345678-1234-1234-1234-123456789012",
                              **properties}
                deadline = time.monotonic() + 2
                with patch.object(core_gateway_inspector, "_unit_properties",
                                  return_value=properties), \
                     patch.object(core_gateway_inspector, "_protected_file_sha",
                                  return_value=unit_digest) as hash_file, \
                     patch.object(core_gateway_inspector, "_process",
                                  return_value=(17, "88")) as process:
                    result = core_gateway_inspector._check_unit_process(config, unit=unit,
                        pid=pid, deadline=deadline, peer_uid=peer_uid, peer_gid=peer_gid)
                self.assertEqual(result, (17, "88", properties["InvocationID"]))
                hash_file.assert_called_once_with(Path(properties["FragmentPath"]), deadline=deadline)
                kwargs = process.call_args.kwargs
                self.assertEqual(kwargs["uid"], uid)
                self.assertEqual(kwargs["gid"], gid)
                self.assertEqual(kwargs["argv"], argv)
                self.assertEqual(kwargs["executable"], executable)
                self.assertEqual(kwargs["executable_sha256"], digest)
                self.assertEqual(kwargs["cgroup"], properties["ControlGroup"])

        bad = {"MainPID": "440", "ControlGroup": f"/system.slice/{core_gateway_inspector.CORE_GATEWAY_UNIT}",
               "InvocationID": "12345678-1234-1234-1234-123456789012",
               "FragmentPath": "/tmp/unreviewed.service", "User": str(config.gateway_uid),
               "Group": str(config.gateway_gid)}
        with patch.object(core_gateway_inspector, "_unit_properties", return_value=bad):
            with self.assertRaises(core_gateway_inspector.CoreInspectionDenied):
                core_gateway_inspector._check_unit_process(config,
                    unit=core_gateway_inspector.CORE_GATEWAY_UNIT, pid=440,
                    deadline=time.monotonic() + 2)


class CoreGatewayIngressTests(unittest.IsolatedAsyncioTestCase):
    async def test_denial_diagnostics_keep_only_fixed_stage_and_exception_type(self):
        config = _config()
        policy = RemotePolicy(config.hostname, config.issuer, config.audience,
                              config.allowed_emails, {})
        token_secret = "jwt-value-never-log-91af"
        identity_secret = "private-owner@example.test"
        values = {
            "Host": [config.hostname], "Cf-Access-Jwt-Assertion": [token_secret], "Origin": [],
        }
        headers = SimpleNamespace(getall=lambda name, default=(): values.get(name, default),
                                  get=lambda *_args, **_kwargs: "")
        request = SimpleNamespace(headers=headers, method="GET", app={})

        async def reject_jwt(*_args, **_kwargs):
            raise core_gateway.GatewayDenied(f"{token_secret} {identity_secret}")

        with patch.object(core_gateway, "_validate_jwt", side_effect=reject_jwt):
            with self.assertLogs("hermes_installer.remote.core_gateway", level="WARNING") as captured:
                with self.assertRaises(core_gateway.CoreGatewayDenied):
                    await core_gateway.accept_core_ingress(request, config, policy)
        jwt_log = "\n".join(captured.output)
        self.assertIn("stage=jwt", jwt_log)
        self.assertIn("exception=GatewayDenied", jwt_log)
        self.assertNotIn(token_secret, jwt_log)
        self.assertNotIn(identity_secret, jwt_log)

        launch = core_gateway.CoreGatewayLaunch(config, policy)
        app = web.Application(middlewares=[web.middleware(core_gateway._core_ingress_middleware)])
        app["core_gateway_launch"] = launch
        app.router.add_get("/private", lambda _request: web.Response(text="private"))
        client = TestClient(TestServer(app))
        await client.start_server()
        try:
            with patch.object(core_gateway, "_read_config_current"), \
                 patch.object(core_gateway, "accept_core_ingress",
                              side_effect=core_gateway.CoreGatewayDenied(
                                  f"{token_secret} {identity_secret}")):
                with self.assertLogs("hermes_installer.remote.core_gateway",
                                     level="WARNING") as middleware_capture:
                    response = await client.get("/private", headers={"Host": config.hostname})
            self.assertEqual(response.status, 403)
            middleware_log = "\n".join(middleware_capture.output)
            self.assertIn("stage=accept_ingress", middleware_log)
            self.assertIn("exception=CoreGatewayDenied", middleware_log)
            self.assertNotIn(token_secret, middleware_log)
            self.assertNotIn(identity_secret, middleware_log)
        finally:
            await client.close()

    async def test_wrong_host_is_denied_before_jwt_or_root_observation(self):
        config = _config()
        policy = RemotePolicy(config.hostname, config.issuer, config.audience,
                              config.allowed_emails, {})

        async def unexpected_jwt(*_args, **_kwargs):
            raise AssertionError("JWT validation must not run for a wrong Host")

        headers = SimpleNamespace(getall=lambda key, default=():
            ["attacker.example.test"] if key == "Host" else ["x"])
        request = SimpleNamespace(headers=headers, method="POST", app={})
        with patch.object(core_gateway, "_validate_jwt", unexpected_jwt):
            with self.assertRaises(core_gateway.CoreGatewayDenied):
                await core_gateway.accept_core_ingress(request, config, policy)

    async def test_household_mutation_still_requires_exact_same_origin_before_jwt(self):
        config = _config()
        policy = RemotePolicy(config.hostname, config.issuer, config.audience,
                              frozenset({"owner@example.test", "member@example.test"}), {})
        for origin in (None, "https://attacker.example.test"):
            calls = []

            async def unexpected_jwt(*_args, **_kwargs):
                calls.append(True)
                raise AssertionError("CSRF rejection must precede JWT/root work")

            values = {"Host": [config.hostname],
                      "Cf-Access-Jwt-Assertion": ["signed-token-fixture"],
                      "Origin": [] if origin is None else [origin]}
            headers = SimpleNamespace(
                getall=lambda key, default=(): values.get(key, default),
                get=lambda *_args, **_kwargs: "")
            request = SimpleNamespace(headers=headers, method="POST", app={})
            with self.subTest(origin=origin), \
                 patch.object(core_gateway, "_validate_jwt", side_effect=unexpected_jwt):
                with self.assertRaises(core_gateway.CoreGatewayDenied):
                    await core_gateway.accept_core_ingress(request, config, policy)
                self.assertEqual(calls, [])

    async def test_http_middleware_serves_finite_current_response(self):
        config = _config()
        launch = core_gateway.CoreGatewayLaunch(config, RemotePolicy(
            config.hostname, config.issuer, config.audience, config.allowed_emails, {}))
        now = time.monotonic()
        accepted = _accepted_observation(config, now=now)
        listener = SimpleNamespace(st_mode=stat.S_IFSOCK | 0o660, st_dev=1, st_ino=2,
                                   st_uid=config.gateway_uid, st_gid=config.gateway_gid)
        real_lstat = os.lstat
        def lstat(path, *args, **kwargs):
            return listener if Path(path) == config.ingress_socket else real_lstat(path, *args, **kwargs)

        hits = []
        async def private_handler(_request):
            hits.append((_request["core_ingress"].principal.subject,
                         _request.headers.get("X-Forwarded-For")))
            return web.Response(text="private core response")

        app = web.Application(middlewares=[web.middleware(core_gateway._core_ingress_middleware)])
        app["core_gateway_launch"] = launch
        app["core_listener_identity"] = (1, 2)
        app.router.add_get("/private", private_handler)
        app.on_response_prepare.append(core_gateway._verify_ingress_before_response_bytes)
        with patch.object(core_gateway_inspector, "_boot_id", return_value=config.boot_id), \
             patch.object(core_gateway.os, "lstat", side_effect=lstat), \
             patch.object(core_gateway, "_read_config_current"), \
             patch.object(core_gateway, "accept_core_ingress", return_value=accepted):
            client = TestClient(TestServer(app))
            await client.start_server()
            try:
                response = await client.get("/private", headers={
                    "Host": config.hostname, "X-Forwarded-For": "203.0.113.18",
                    "Forwarded": "for=203.0.113.18;host=untrusted.invalid"})
                self.assertEqual(response.status, 200)
                self.assertEqual(await response.text(), "private core response")
                self.assertEqual(response.headers["Cache-Control"], "no-store")
                self.assertEqual(hits, [("owner-subject", "203.0.113.18")])
            finally:
                await client.close()

    async def test_http_middleware_denies_before_handler_and_late_response(self):
        config = _config()
        launch = core_gateway.CoreGatewayLaunch(config, RemotePolicy(
            config.hostname, config.issuer, config.audience, config.allowed_emails, {}))
        hits = []

        async def private_handler(_request):
            hits.append(True)
            return web.Response(text="private core response")

        async def slow_handler(_request):
            hits.append(True)
            await asyncio.sleep(0.35)
            return web.Response(text="private core response")

        app = web.Application(middlewares=[web.middleware(core_gateway._core_ingress_middleware)])
        app["core_gateway_launch"] = launch
        app["core_listener_identity"] = (1, 2)
        app.router.add_get("/private", private_handler)
        app.router.add_get("/slow", slow_handler)
        client = TestClient(TestServer(app))
        await client.start_server()
        try:
            with patch.object(core_gateway, "_read_config_current"), \
                 patch.object(core_gateway, "accept_core_ingress",
                              side_effect=core_gateway.CoreGatewayDenied("denied")):
                denied = await client.get("/private", headers={"Host": config.hostname})
            self.assertEqual(denied.status, 403)
            self.assertEqual(await denied.text(), "Forbidden")
            self.assertEqual(hits, [])

            now = time.monotonic()
            accepted = _accepted_observation(config, now=now, lease_seconds=0.2)
            listener = SimpleNamespace(st_mode=stat.S_IFSOCK | 0o660, st_dev=1, st_ino=2,
                                       st_uid=config.gateway_uid, st_gid=config.gateway_gid)
            real_lstat = os.lstat
            def lstat(path, *args, **kwargs):
                return listener if Path(path) == config.ingress_socket else real_lstat(path, *args, **kwargs)
            with patch.object(core_gateway_inspector, "_boot_id", return_value=config.boot_id), \
                 patch.object(core_gateway.os, "lstat", side_effect=lstat), \
                 patch.object(core_gateway, "_read_config_current"), \
                 patch.object(core_gateway_inspector, "verify_current_core_overview",
                    return_value=SimpleNamespace(core_generation=accepted.core_generation,
                        projection={"core_version":"7085fbf77532", "provider":None, "model":None,
                            "account_state":"unknown", "resources_state":"pending", "resource_counts":None,
                            "resources_revision":None, "artifact_sha256":None,
                            "discovery_observed_at_utc":None,
                            "active_prompt_matches_bundled_primary":None})), \
                 patch.object(core_gateway, "accept_core_ingress", return_value=accepted):
                late = await client.get("/slow", headers={"Host": config.hostname})
            self.assertEqual(late.status, 403)
            self.assertEqual(await late.text(), "Forbidden")
            self.assertEqual(hits, [True])
        finally:
            await client.close()

    async def test_core_app_protects_redirect_and_only_reviewed_chat_assets(self):
        from hermes_installer.remote.jarvis_chat_assets import (
            FEATURE_CHUNK_PATHS, FEATURE_CSS_CHUNK_PATHS, reviewed_chat_asset,
        )
        import hermes_installer.remote.jarvis_chat as jarvis_chat

        config = _config()
        launch = core_gateway.CoreGatewayLaunch(config, RemotePolicy(
            config.hostname, config.issuer, config.audience, config.allowed_emails, {}))
        now = time.monotonic()
        accepted = _accepted_observation(config, now=now, lease_seconds=4.5)
        listener = SimpleNamespace(st_mode=stat.S_IFSOCK | 0o660, st_dev=1, st_ino=2,
                                   st_uid=config.gateway_uid, st_gid=config.gateway_gid)
        real_lstat = os.lstat

        def lstat(path, *args, **kwargs):
            return listener if Path(path) == config.ingress_socket else real_lstat(path, *args, **kwargs)

        with tempfile.TemporaryDirectory(prefix="jarvis-dashboard-gateway-") as temporary:
            service = _jarvis_service(launch, Path(temporary) / "chat.sqlite3")
            overview = _overview_observation(config, accepted, now=now)
            with patch.object(jarvis_chat, "build_jarvis_chat_service", return_value=service), \
                 patch.object(core_gateway_inspector, "_boot_id", return_value=config.boot_id), \
                 patch.object(core_gateway_inspector, "verify_current_core_overview",
                              return_value=overview), \
                 patch.object(core_gateway.os, "lstat", side_effect=lstat), \
                 patch.object(core_gateway, "_read_config_current"), \
                 patch.object(core_gateway, "accept_core_ingress", return_value=accepted):
                app = core_gateway.create_core_gateway_app(launch)
                app["core_listener_identity"] = (1, 2)
                for path in (*FEATURE_CHUNK_PATHS, *FEATURE_CSS_CHUNK_PATHS):
                    with self.subTest(asset_path=path):
                        routes = [route for route in app.router.routes()
                                  if getattr(route.resource, "canonical", None) == path]
                        self.assertEqual([route.method for route in routes], ["GET"])
                ecosystem_routes = [route for route in app.router.routes()
                                    if getattr(route.resource, "canonical", None)
                                    == "/chat/api/ecosystem"]
                self.assertEqual(sorted(route.method for route in ecosystem_routes), ["GET", "HEAD"])
                decision_routes = [
                    route for route in app.router.routes()
                    if getattr(route.resource, "canonical", None)
                    == "/chat/api/turns/{turn_id}/final-effects/decision"
                ]
                self.assertEqual(len(decision_routes), 1)
                self.assertEqual(decision_routes[0].method, "POST")
                client = TestClient(TestServer(app))
                await client.start_server()
                try:
                    headers = {"Host": config.hostname}
                    home = await client.get("/", headers=headers, allow_redirects=False)
                    self.assertEqual(home.status, 302)
                    self.assertEqual(home.headers["Location"], "/chat")
                    self.assertEqual(home.headers["Cache-Control"], "no-store")

                    overview_response = await client.get("/chat/api/overview", headers=headers)
                    self.assertEqual(overview_response.status, 200)
                    overview = await overview_response.json()
                    self.assertEqual(overview["core"]["status"], "process-observed")
                    self.assertEqual(overview["chat"]["turnCounts"]["total"], 0)
                    self.assertEqual(len(overview["chat"]["turnCountsByDay"]), 7)

                    for path in ("/chat", "/chat/", "/chat/assets/app.css", *FEATURE_CSS_CHUNK_PATHS,
                                 *FEATURE_CHUNK_PATHS,
                                 "/chat/assets/features.js",
                                 "/chat/assets/app.js", "/chat/manifest.webmanifest",
                                 "/chat/assets/jarvis-app-icon.svg"):
                        with self.subTest(path=path):
                            expected_type, expected_body = reviewed_chat_asset(path)
                            response = await client.get(path, headers=headers)
                            self.assertEqual(response.status, 200)
                            self.assertEqual(response.headers["Content-Type"], expected_type)
                            self.assertEqual(await response.read(), expected_body)
                            self.assertEqual(response.headers["Cache-Control"], "no-store")
                            if path in {"/chat", "/chat/"}:
                                csp = response.headers["Content-Security-Policy"]
                                self.assertIn("script-src 'self'", csp)
                                self.assertIn("style-src 'self'", csp)
                                self.assertIn("manifest-src 'self'", csp)
                                self.assertNotIn("unsafe-inline", csp)
                                self.assertNotIn("unsafe-eval", csp)
                    for path in ("/chat/assets/not-reviewed.js", "/chat/assets/app.js?x=1",
                                 "/chat/manifest.webmanifest?x=1", "/chat/assets/jarvis-app-icon.svg?x=1",
                                 "/chat/assets/%61pp.js"):
                        with self.subTest(path=path):
                            target = URL(path, encoded=True) if "%" in path else path
                            response = await client.get(target, headers=headers)
                            self.assertEqual(response.status, 404)
                            self.assertNotIn(b"JARVIS", await response.read())
                finally:
                    await client.close()

    async def test_chat_asset_route_does_not_reveal_page_before_ingress(self):
        import hermes_installer.remote.jarvis_chat as jarvis_chat
        from hermes_installer.remote.jarvis_chat_assets import (
            FEATURE_CHUNK_PATHS, FEATURE_CSS_CHUNK_PATHS,
        )

        config = _config()
        launch = core_gateway.CoreGatewayLaunch(config, RemotePolicy(
            config.hostname, config.issuer, config.audience, config.allowed_emails, {}))
        with tempfile.TemporaryDirectory(prefix="jarvis-dashboard-denied-") as temporary:
            service = _jarvis_service(launch, Path(temporary) / "chat.sqlite3")
            with patch.object(jarvis_chat, "build_jarvis_chat_service", return_value=service), \
                 patch.object(core_gateway, "_read_config_current"), \
                 patch.object(core_gateway, "accept_core_ingress",
                              side_effect=core_gateway.CoreGatewayDenied("denied")):
                app = core_gateway.create_core_gateway_app(launch)
                app["core_listener_identity"] = (1, 2)
                client = TestClient(TestServer(app))
                await client.start_server()
                try:
                    for path in ("/chat", "/chat/api/overview", *FEATURE_CHUNK_PATHS,
                                 *FEATURE_CSS_CHUNK_PATHS, "/chat/assets/features.js",
                                 "/chat/assets/app.css", "/chat/assets/app.js"):
                        with self.subTest(path=path):
                            response = await client.get(path, headers={"Host": config.hostname})
                            self.assertEqual(response.status, 403)
                            self.assertEqual(await response.text(), "Forbidden")
                finally:
                    await client.close()


class ProfileAdminSingletonHttpTests(unittest.IsolatedAsyncioTestCase):
    async def test_profiles_fail_closed_under_email_union_without_narrowing_family_reads(self):
        from hermes_installer.remote.core_gateway_inspector import CoreGatewayInspector
        from hermes_installer.remote.jarvis_ecosystem import install_jarvis_ecosystem_routes
        from hermes_installer.remote.jarvis_profiles_admin import (
            JarvisProfileAdmin, ProfileAdminDescriptor, install_jarvis_profiles_admin_routes,
        )

        class CountingProvider:
            def __init__(self):
                self.calls = []

            def list_profiles(self, **_kwargs):
                self.calls.append("list")
                return (ProfileAdminDescriptor("hermes", "Jarvis", "jarvis", "f" * 64, ("soul",)),)

            def read_file(self, **_kwargs):
                self.calls.append("read")
                raise AssertionError("profile provider must not be reached for denied authority")

            def write_generation(self, **_kwargs):
                self.calls.append("write")
                raise AssertionError("profile provider must not be reached for denied authority")

        def accepted_for(config, *, email, token):
            base = _accepted_observation(config, now=time.monotonic())
            principal = dataclasses.replace(base.principal, email=email,
                token_fingerprint=hashlib.sha256(token.encode("ascii")).hexdigest())
            claim = core_gateway._accepted_claim_digest(principal=principal,
                jwt_expiry=base.jwt_expires_monotonic, root_proof=base.root_observation,
                peer=(base.peer_pid, base.peer_uid, base.peer_gid),
                listener=(base.listener_device, base.listener_inode),
                issued=base.issued_monotonic, expiry=base.expires_monotonic,
                core_generation=base.core_generation, config_sha256=base._config_sha256)
            return dataclasses.replace(base, principal=principal, _claim_sha256=claim)

        def make_app(config, accepted, provider, store_path):
            from hermes_installer.remote.jarvis_profiles_admin import JarvisProfileAdmin
            launch = core_gateway.CoreGatewayLaunch(config, RemotePolicy(
                config.hostname, config.issuer, config.audience, config.allowed_emails, {}))
            service = _jarvis_service(launch, store_path)
            service.inspector = CoreGatewayInspector(config)
            app = web.Application(middlewares=[web.middleware(core_gateway._core_ingress_middleware)])
            app["core_gateway_launch"] = launch
            service.install(app)
            install_jarvis_profiles_admin_routes(app, service, JarvisProfileAdmin(provider))
            install_jarvis_ecosystem_routes(app, service)
            return app

        token = "current-approved-access-token"
        union = frozenset({"owner@example.test", "member@example.test", "guest@example.test"})
        union_config = dataclasses.replace(_config(), allowed_emails=union)
        union_accepted = accepted_for(union_config, email="owner@example.test", token=token)
        denied_provider = CountingProvider()
        observed_at = time.time()
        mission_id = "m" * 24
        sender_key, recipient_key = "sender-execution-key-0001", "recipient-execution-key-01"

        def activity_instance(execution_key, profile_id, alias):
            timestamp = observed_at - 10
            return {
                "execution_key": execution_key, "display_alias": alias,
                "gateway_turn_id": ("t" * 24 if profile_id == "expert-one" else "u" * 24),
                "mission_id": mission_id, "mission_revision": 3,
                "profile_id": profile_id, "source_revision": "reviewed-profile-r3",
                "source_generation_sha256": "a" * 64, "status": "completed", "stale": False,
                "created_at": timestamp, "updated_at": observed_at,
                "tool_count": 2,
                "events": [{"kind": "completed", "status": "completed", "at": observed_at,
                            "duration_ms": 120, "tool_count": 2}],
            }

        team_key, relation_key = "team-execution-key-00001", "relation-execution-key-001"
        activity = {
            "schema": 2, "observed_at": observed_at, "window_seconds": 604800,
            "coverage": "observed-callbacks", "partial": False,
            "instances": [activity_instance(sender_key, "expert-one", "Expert One"),
                          activity_instance(recipient_key, "expert-two", "Expert Two")],
            "team_instances": [{
                "team_execution_key": team_key, "team_id": "reviewed-team",
                "source_revision": "reviewed-profile-r3", "mission_id": mission_id,
                "mission_revision": 3, "members": [sender_key, recipient_key],
                "state": "current", "coverage": "observed-callbacks",
            }],
            "relations": [{
                "relation_key": relation_key, "team_execution_key": team_key,
                "mission_id": mission_id, "mission_revision": 3,
                "sender_execution_key": sender_key, "recipient_execution_key": recipient_key,
                "kind": "completed_message", "event_at": observed_at,
                "state": "current", "coverage": "observed-callbacks",
            }],
        }
        with tempfile.TemporaryDirectory(prefix="jarvis-profile-union-") as temporary:
            app = make_app(union_config, union_accepted, denied_provider,
                           Path(temporary) / "union.sqlite3")
            client = TestClient(TestServer(app))
            await client.start_server()
            headers = {"Host": union_config.hostname, "Cf-Access-Jwt-Assertion": token}
            try:
                with patch.object(core_gateway, "_read_config_current"), \
                     patch.object(core_gateway, "accept_core_ingress", return_value=union_accepted), \
                     patch.object(core_gateway.CoreAcceptedIngressObservation,
                                  "verify_current", return_value=True), \
                     patch.object(CoreGatewayInspector, "read_native_activity", return_value=activity):
                    conversations = await client.get("/chat/api/conversations", headers=headers)
                    self.assertEqual(conversations.status, 200)
                    ecosystem = await client.get("/chat/api/ecosystem", headers=headers)
                    self.assertEqual(ecosystem.status, 200)
                    snapshot = await ecosystem.json()
                    self.assertEqual(snapshot["schema"], 2)
                    self.assertEqual(snapshot["pending"], {
                        "team_membership": "verified", "communication_edges": "verified",
                    })
                    self.assertEqual(snapshot["teams"][0]["team_execution_key"], team_key)
                    self.assertEqual(snapshot["teams"][0]["members"], [sender_key, recipient_key])
                    self.assertEqual(snapshot["relations"][0]["id"], relation_key)
                    self.assertEqual(snapshot["relations"][0]["from"], sender_key)
                    self.assertEqual(snapshot["relations"][0]["to"], recipient_key)
                    self.assertEqual({item["profile_id"] for item in snapshot["top_experts"]},
                                     {"expert-one", "expert-two"})
                    same_origin = {**headers, "Origin": f"https://{union_config.hostname}",
                                   "Sec-Fetch-Site": "same-origin"}
                    with patch.object(core_gateway_inspector, "verify_current_core_overview",
                                      side_effect=AssertionError("union admin must deny before Core overview")) as overview:
                        responses = [
                            await client.get("/chat/api/profiles", headers=headers),
                            await client.get("/chat/api/profiles/hermes/files/soul", headers=headers),
                            await client.post("/chat/api/profiles/hermes/preview", headers=same_origin, json={}),
                            await client.post("/chat/api/profiles/hermes/save", headers=same_origin, json={}),
                        ]
                    self.assertTrue(all(response.status == 403 for response in responses),
                                    [response.status for response in responses])
                    messages = [await response.text() for response in responses]
                    self.assertTrue(all("Administrator access setup is pending" in message
                                        for message in messages))
                    overview.assert_not_called()
                    self.assertEqual(denied_provider.calls, [])
            finally:
                await client.close()

        # With one configured email and that exact current principal, the reviewed list reaches
        # its provider. A singleton is a narrow admission condition, not an original-admin role.
        single_config = _config()
        single_accepted = accepted_for(single_config, email="owner@example.test", token=token)
        allowed_provider = CountingProvider()
        with tempfile.TemporaryDirectory(prefix="jarvis-profile-single-") as temporary:
            app = make_app(single_config, single_accepted, allowed_provider,
                           Path(temporary) / "single.sqlite3")
            client = TestClient(TestServer(app))
            await client.start_server()
            headers = {"Host": single_config.hostname, "Cf-Access-Jwt-Assertion": token}
            overview = SimpleNamespace(core_generation=single_accepted.core_generation,
                                       verify_current=lambda _config, **kwargs: (
                                           _config is single_config
                                           and kwargs.get("peer_pid") == single_accepted.peer_pid
                                           and kwargs.get("peer_uid") == single_accepted.peer_uid
                                           and kwargs.get("peer_gid") == single_accepted.peer_gid
                                           and kwargs.get("accepted_ingress") is single_accepted))
            try:
                with patch.object(core_gateway, "_read_config_current"), \
                     patch.object(core_gateway, "accept_core_ingress", return_value=single_accepted), \
                     patch.object(core_gateway.CoreAcceptedIngressObservation,
                                  "verify_current", return_value=True), \
                     patch.object(core_gateway_inspector, "verify_current_core_overview",
                                  return_value=overview):
                    response = await client.get("/chat/api/profiles", headers=headers)
                self.assertEqual(response.status, 200)
                self.assertEqual(allowed_provider.calls, ["list"])
            finally:
                await client.close()

        # A singleton configured owner does not admit another currently approved union member.
        mismatch = accepted_for(single_config, email="member@example.test", token=token)
        mismatch_provider = CountingProvider()
        with tempfile.TemporaryDirectory(prefix="jarvis-profile-mismatch-") as temporary:
            app = make_app(single_config, mismatch, mismatch_provider,
                           Path(temporary) / "mismatch.sqlite3")
            client = TestClient(TestServer(app))
            await client.start_server()
            headers = {"Host": single_config.hostname, "Cf-Access-Jwt-Assertion": token}
            try:
                with patch.object(core_gateway, "_read_config_current"), \
                     patch.object(core_gateway, "accept_core_ingress", return_value=mismatch), \
                     patch.object(core_gateway.CoreAcceptedIngressObservation,
                                  "verify_current", return_value=True), \
                     patch.object(core_gateway_inspector, "verify_current_core_overview",
                                  side_effect=AssertionError("caller mismatch must deny before Core overview")):
                    response = await client.get("/chat/api/profiles", headers=headers)
                self.assertEqual(response.status, 403)
                self.assertIn("Administrator access setup is pending", await response.text())
                self.assertEqual(mismatch_provider.calls, [])
            finally:
                await client.close()

    def test_profile_admin_inspector_allows_matching_singleton_before_native_list(self):
        config = _config()
        token = "single-owner-profile-token"
        principal = Principal("owner@example.test", "owner-subject", time.time() + 60,
                              hashlib.sha256(token.encode("ascii")).hexdigest())
        core_generation = "c" * 64
        source_generation = "d" * 64
        proof_sha256 = "e" * 64
        now = time.monotonic()
        retained = SimpleNamespace(expires_monotonic=now + 4, nonce="f" * 64,
            issued_monotonic=now, caller_start_ticks="88", proof_sha256=proof_sha256,
            owner_subject_sha256=hashlib.sha256(b"owner-subject").hexdigest())
        current = {"proof_sha256": proof_sha256, "core_generation": core_generation,
                   "core_source_generation": source_generation}
        custody = SimpleNamespace(core_generation=core_generation,
            core_source_generation=source_generation, _core_pidfd=91)
        catalog = {"sources": {"hermes": object()}, "manifest": {}}
        current_rows = [{"profile_id": "hermes", "files": [{"kind": "soul"}]}]
        request = {"schema": 1, "op": "owner-profile-admin", "action": "list",
            "nonce": "a" * 64, "peer_pid": 551, "peer_uid": 996, "peer_gid": 981,
            "access_jwt": token, "core_generation": core_generation,
            "ingress_nonce": "b" * 64, "ingress_proof_sha256": "9" * 64}
        with patch.object(core_gateway_inspector, "_proc_start_ticks", return_value="88"), \
             patch.object(core_gateway_inspector, "_consume_ingress_issue", return_value=retained), \
             patch.object(core_gateway_inspector, "observe_current_ingress", return_value=current), \
             patch.object(core_gateway_inspector, "_check_unit_process",
                          return_value=(92, "88", "gateway-invocation")), \
             patch.object(core_gateway_inspector.os, "close"), \
             patch.object(core_gateway_inspector, "_learning_jwks", return_value={}), \
             patch("hermes_installer.remote.gateway.validate_access_jwt", return_value=principal), \
             patch("hermes_installer.components.resources_active_profile_source._read_catalog",
                   return_value=catalog), \
             patch.object(core_gateway_inspector, "capture_current_core_native_custody",
                          side_effect=[custody, custody]), \
             patch("hermes_installer.remote.jarvis_profile_source_adapter.current_profile_files",
                   return_value=current_rows) as list_native:
            result = core_gateway_inspector.observe_profile_admin(config, request=request,
                caller_pid=440, caller_uid=996, caller_gid=981,
                peer_pid=551, peer_uid=996, peer_gid=981)
        self.assertEqual(result["action"], "list")
        self.assertEqual(result["result"], current_rows)
        list_native.assert_called_once_with(("hermes",))
        wrong_principal = Principal("member@example.test", "owner-subject", time.time() + 60,
                                    hashlib.sha256(token.encode("ascii")).hexdigest())
        with patch.object(core_gateway_inspector, "_proc_start_ticks", return_value="88"), \
             patch.object(core_gateway_inspector, "_consume_ingress_issue", return_value=retained), \
             patch.object(core_gateway_inspector, "observe_current_ingress", return_value=current), \
             patch.object(core_gateway_inspector, "_check_unit_process",
                          return_value=(92, "88", "gateway-invocation")), \
             patch.object(core_gateway_inspector.os, "close"), \
             patch.object(core_gateway_inspector, "_learning_jwks", return_value={}), \
             patch("hermes_installer.remote.gateway.validate_access_jwt",
                   return_value=wrong_principal), \
             patch("hermes_installer.components.resources_active_profile_source._read_catalog",
                   side_effect=AssertionError("wrong caller must be denied before catalog access")), \
             patch.object(core_gateway_inspector, "capture_current_core_native_custody",
                          side_effect=AssertionError("wrong caller must be denied before native custody")) as custody_call:
            with self.assertRaisesRegex(core_gateway_inspector.CoreInspectionDenied,
                                        "Profile administration owner is unavailable"):
                core_gateway_inspector.observe_profile_admin(config, request=request,
                    caller_pid=440, caller_uid=996, caller_gid=981,
                    peer_pid=551, peer_uid=996, peer_gid=981)
        custody_call.assert_not_called()
