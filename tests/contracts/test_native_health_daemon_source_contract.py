from __future__ import annotations

from pathlib import Path
import ast
import threading
from types import SimpleNamespace
import unittest

from hermes_installer.authority.installer_release import VerifiedReleaseFile
from hermes_installer.authority.native_health_daemon import (
    RootDaemonNativeHealthMaterialRegistry, RootDaemonNativeHealthRunRegistry,
)
from hermes_installer.authority.native_health_source import _MEMBERS, _strict_json
from hermes_installer.authority.types import AuthorityDenied


REPO = Path(__file__).resolve().parents[2]
_IDS = (
    "hermes-agent-health-fixture-v1",
    "hermes-agent-health-request-v1",
    "hermes-agent-health-seed-v1",
    "hermes-agent-health-expected-result-v1",
    "hermes-agent-health-overlay-read-result-v1",
)


class _CurrentReviewedRelease:
    def __init__(self):
        self.rows = {}
        for artifact_id, (relative, digest, size) in _MEMBERS.items():
            self.rows[artifact_id] = VerifiedReleaseFile(
                artifact_id, ("native-health-fixture",), relative, digest, size,
                10, 20, 0o444,
            )

    def resolve_reviewed_source_artifact(self, artifact_id: str) -> VerifiedReleaseFile:
        return self.rows[artifact_id]


def _definition() -> dict[str, object]:
    recipe_path = REPO / "src/hermes_installer/native_health_fixture/recipe.json"
    recipe = _strict_json(recipe_path.read_bytes())
    values: dict[str, object] = {
        "health_recipe_artifact_id": _IDS[0],
        "health_recipe_sha256": _MEMBERS[_IDS[0]][1],
        "health_recipe_receipt_handle": "a" * 40,
        "health_request_artifact_id": _IDS[1],
        "health_request_sha256": _MEMBERS[_IDS[1]][1],
        "health_request_receipt_handle": "b" * 40,
        "health_seed_artifact_id": _IDS[2],
        "health_seed_sha256": _MEMBERS[_IDS[2]][1],
        "health_seed_receipt_handle": "c" * 40,
        "health_expected_result_artifact_id": _IDS[3],
        "health_expected_result_sha256": _MEMBERS[_IDS[3]][1],
        "health_expected_result_receipt_handle": "d" * 40,
        "health_result_schema_id": "hermes-agent-health-overlay-read-result-v1",
        "health_result_schema_sha256": _MEMBERS[_IDS[4]][1],
        "health_result_schema_receipt_handle": "e" * 40,
        "health_action_id": recipe["action_id"],
        "operation_id": "hermes-agent-health-v1",
        "provider_required": True,
    }
    return values


class NativeHealthDaemonSourceContracts(unittest.TestCase):
    def test_run_registry_event_methods_are_not_shadowed_and_consume_ids(self) -> None:
        tree = ast.parse((REPO / "src/hermes_installer/authority/native_health_daemon.py").read_text())
        registry_class = next(
            node for node in tree.body
            if isinstance(node, ast.ClassDef) and node.name == "RootDaemonNativeHealthRunRegistry"
        )
        names = [node.name for node in registry_class.body if isinstance(node, ast.FunctionDef)]
        self.assertEqual(names.count("_record_health_event"), 1)
        self.assertEqual(names.count("_resolve_owner_invocation"), 1)

        class Observer:
            def __init__(self):
                self.observed = []

            def observe_health_event(self, observation_handle, event_id):
                self.observed.append((observation_handle, event_id))

        registry = object.__new__(RootDaemonNativeHealthRunRegistry)
        registry.runtime = SimpleNamespace(service=SimpleNamespace(monotonic=lambda: 10.0))
        registry._lock = threading.RLock()
        registry._events = {}
        registry._event_sources = {}
        registry.observer = Observer()
        run = SimpleNamespace(
            operation_id="hermes-agent-health-v1", enrollment_id="enrollment:health",
            profile_id="profile:health", process_generation="generation:health",
            service_generation_digest="a" * 64, process_id="process:health",
            process_pid=321, process_uid=2001, package_id="package:health",
            compiled_closure_sha256="b" * 64, expires_monotonic=40.0,
        )
        loader_id = "L" * 40
        loader = RootDaemonNativeHealthRunRegistry._record_health_event(
            registry, "O" * 40, "C" * 40, run, kind="loader-ready",
            native_handle="H" * 40, native_digest="c" * 64,
            ancestry_kind="custody-event-v1", parent_closure_digest=None,
            event_id=loader_id, self_reference_fields=("loader_ready_event_id",),
            loaded_proof_id="d" * 64,
        )
        self.assertEqual(loader.event_id, loader_id)
        self.assertEqual(loader.loader_ready_event_id, loader_id)

        request = RootDaemonNativeHealthRunRegistry._record_health_event(
            registry, "O" * 40, "C" * 40, run, kind="native-request",
            native_handle="R" * 40, native_digest="e" * 64,
            ancestry_kind="host-context-lineage-v1", parent_closure_digest="f" * 64,
            causal_parents=(loader_id,), self_reference_fields=("native_request_event_id",),
            source_handles=("S" * 40,), source_ids=("receipt:health",),
            provider_result_event_id="P" * 40,
        )
        self.assertEqual(request.native_request_event_id, request.event_id)
        self.assertEqual(registry.observer.observed,
                         [("O" * 40, loader_id), ("O" * 40, request.event_id)])
        with self.assertRaises(AuthorityDenied):
            RootDaemonNativeHealthRunRegistry._record_health_event(
                registry, "O" * 40, "C" * 40, run, kind="native-request",
                native_handle="R" * 40, native_digest="e" * 64,
                ancestry_kind="host-context-lineage-v1", parent_closure_digest="f" * 64,
                self_reference_fields=("native_request_event_id",),
                native_request_event_id="caller-supplied",
            )

    def test_current_reviewed_release_resolves_all_five_fixed_source_rows(self) -> None:
        rows = RootDaemonNativeHealthMaterialRegistry._health_release_rows(
            _CurrentReviewedRelease(), _definition(),
        )
        self.assertEqual(tuple(row["artifact_id"] for row in rows), _IDS)
        self.assertEqual({row["receipt_handle"] for row in rows},
                         {char * 40 for char in "abcde"})
        self.assertTrue(all(row["relative_path"].startswith("fixtures/native-health/")
                            and row["kind"] == "regular-file"
                            and row["owner_uid"] == row["owner_gid"] == 0
                            and row["mode"] == 0o444
                            and row["link_target"] is None for row in rows))

    def test_daemon_source_rejects_wrong_role_hash_or_missing_receipt_handle(self) -> None:
        release = _CurrentReviewedRelease()
        definition = _definition()
        release.rows[_IDS[0]] = VerifiedReleaseFile(
            _IDS[0], ("native-source-module",), _MEMBERS[_IDS[0]][0],
            _MEMBERS[_IDS[0]][1], _MEMBERS[_IDS[0]][2], 10, 20, 0o444,
        )
        with self.assertRaises(ValueError):
            RootDaemonNativeHealthMaterialRegistry._health_release_rows(release, definition)

        release = _CurrentReviewedRelease()
        release.rows[_IDS[1]] = VerifiedReleaseFile(
            _IDS[1], ("native-health-fixture",), _MEMBERS[_IDS[1]][0],
            "0" * 64, _MEMBERS[_IDS[1]][2], 10, 20, 0o444,
        )
        with self.assertRaises(ValueError):
            RootDaemonNativeHealthMaterialRegistry._health_release_rows(release, definition)

        definition.pop("health_seed_receipt_handle")
        with self.assertRaises(ValueError):
            RootDaemonNativeHealthMaterialRegistry._health_release_rows(
                _CurrentReviewedRelease(), definition,
            )

    def test_daemon_source_definition_checks_actual_bytes_and_required_provider(self) -> None:
        bodies = {
            artifact_id: (REPO / "src/hermes_installer/native_health_fixture"
                          / _MEMBERS[artifact_id][0].rsplit("/", 1)[-1]).read_bytes()
            for artifact_id in _IDS
        }
        RootDaemonNativeHealthMaterialRegistry._validate_health_definition(_definition(), bodies)
        changed = dict(_definition())
        changed["provider_required"] = False
        with self.assertRaises(ValueError):
            RootDaemonNativeHealthMaterialRegistry._validate_health_definition(changed, bodies)


if __name__ == "__main__":
    unittest.main()
