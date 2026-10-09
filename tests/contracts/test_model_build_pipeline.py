"""HW-T03 selection and receipt contracts (fixtures are not native build proof)."""
from __future__ import annotations

import hashlib
import json

import unittest

from hermes_installer.authority.types import AuthorityDenied, BrokeredEffectResponse
from hermes_installer.models.build_pipeline import (
    COLIBRI_BUILD, CORAL_CPYTHON_BUILD, parse_native_build_receipt,
    run_fixed_native_build,
)


def receipt(operation: str, *, generation: str = "service-gen-4") -> dict:
    if operation == COLIBRI_BUILD:
        target = "colibri-source-build:start"
        source_id = "colibri-source"
        source_sha = "7cc79d4bfdc851efb27b67295ceac1370312b5cd414d869887715d30b2d13174"
        outputs = [{"relative_path": "c/colibri", "kind": "file", "sha256": "a" * 64,
            "size_bytes": 2_000_000, "executable_role": "colibri-engine",
            "observed_target_facts": {"elf_class": 64, "elf_machine": "EM_AARCH64",
                "os": "linux", "required_runtime_dependencies": ["libgomp.so.1", "libm", "libc"],
                "resolved_dependency_closure": [
                    {"name": name, "sha256": "b" * 64, "owner_uid": 0,
                     "absolute_path": f"/usr/lib/aarch64-linux-gnu/{name}", "mode": 0o644}
                    for name in ("libgomp.so.1", "libm", "libc")],
                "instruction_policy": "actual target compatible ARM64 flags; no x86 default or unmeasured CPUflags"},
            "tree_file_manifest_sha256": None}]
    else:
        target = "coral-cpython-build:start"
        source_id = "coral-python39-source"
        source_sha = "00e07d7c0f2f0cc002432d1ee84d2a40dae404a99303e3f97701c10966c91834"
        outputs = [
            {"relative_path": "runtime/bin/python3.9", "kind": "file", "sha256": "c" * 64,
                "size_bytes": 5_000_000, "executable_role": "coral-cpython39",
                "observed_target_facts": {"elf_class": 64, "elf_machine": "EM_AARCH64",
                    "python_version": "3.9.25", "soabi": "cpython-39-aarch64-linux-gnu",
                    "debug": False, "glibc_minimum": "2.34 for selected TFLite wheel",
                    "observed_glibc_version": "2.36",
                    "resolved_dependency_closure": [{"name": "libc.so.6", "sha256": "6" * 64,
                        "owner_uid": 0, "absolute_path": "/lib/aarch64-linux-gnu/libc.so.6", "mode": 0o644}]},
                "tree_file_manifest_sha256": None},
            {"relative_path": "runtime/lib/python3.9", "kind": "tree", "sha256": "d" * 64,
                "size_bytes": 40_000_000, "executable_role": "cpython-stdlib-and-extension-closure",
                "observed_target_facts": {"python_version": "3.9.25", "target": "linux-aarch64",
                    "all_native_extensions": "ELF64EM_AARCH64, actual dependency closure verified",
                    "native_extension_manifest": [{"relative_path": "lib-dynload/example.so", "sha256": "5" * 64,
                        "elf_class": 64, "elf_machine": "EM_AARCH64", "os": "linux",
                        "resolved_dependency_closure": [{"name": "libc.so.6", "absolute_path": "/lib/aarch64-linux-gnu/libc.so.6",
                            "sha256": "6" * 64, "owner_uid": 0, "mode": 0o644}]}]},
                "tree_file_manifest_sha256": "e" * 64},
        ]
    value = {"schema": 1, "receipt_id": "build-receipt-1", "build_target_id": target,
        "enrollment_id": "enroll-1", "build_generation": generation, "operation_id": operation,
        "service_generation_digest": "f" * 64,
        "recipe_digest": "1" * 64, "source_artifact_id": source_id, "source_sha256": source_sha,
        "toolchain_artifact_id": "toolchain-arm64", "toolchain_sha256": "2" * 64,
        "builder_artifact_id": "builder-fixed", "builder_sha256": "3" * 64,
        "process_identity_digest": "4" * 64, "terminal_success_record_id": "terminal-1",
        "output_records": outputs,
        "execution": {"process_id": "process-1", "uid": 1002, "pid": 456,
            "start_ticks": 123456, "exit_code": 0, "cleanup_verified": True,
            "started_monotonic": 99.0, "finished_monotonic": 99.5,
            "kernel_limits": {"PrivateNetwork": "yes", "ProtectSystem": "strict"},
            "cgroup_id": "unit-1", "mount_namespace_inode": 321,
            "network_namespace_inode": 654, "bounded_log_digest": "9" * 64,
            "log_bytes": 128},
        "issued_monotonic": 100.0, "expires_monotonic": 110.0,
        "receipt_digest": "0" * 64, "root_signature": "fixture-only-not-a-signature"}
    unsigned = {key: item for key, item in value.items()
        if key not in {"receipt_digest", "root_signature"}}
    value["receipt_digest"] = hashlib.sha256(json.dumps(unsigned, sort_keys=True,
        separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()).hexdigest()
    return value


class ModelBuildPipelineTests(unittest.TestCase):
    def test_fixed_build_call_sends_only_empty_selected_operation_and_checks_receipt(self) -> None:
        for operation in (COLIBRI_BUILD, CORAL_CPYTHON_BUILD):
            with self.subTest(operation=operation):
                body = receipt(operation)
                response = BrokeredEffectResponse(200, json.dumps(body).encode(),
                    {"content-type": "application/json"}, "build-receipt-1")
                calls = []

                class Client:
                    def start_enrolled_build_operation(self, **request):
                        calls.append(request)
                        return response

                result = run_fixed_native_build(Client(), operation_id=operation,
                    enrollment_id="enroll-1", generation="service-gen-4", now=lambda: 101.0)
                self.assertEqual(calls, [{"enrollment_id": "enroll-1", "generation": "service-gen-4",
                    "operation_id": operation, "parameters": {}, "timeout": 600, "cancelled": None}])
                self.assertEqual(result.source_sha256, body["source_sha256"])
                self.assertEqual(len(result.outputs), len(body["output_records"]))

    def test_build_receipt_rejects_cpu_wrong_generation_bad_digest_and_incomplete_facts(self) -> None:
        for mutate, message in (
            (lambda value: value["output_records"][0]["observed_target_facts"].update(elf_machine="EM_X86_64"), "target facts"),
            (lambda value: value.update(build_generation="stale"), "generation"),
            (lambda value: value.update(receipt_digest="f" * 64), "digest"),
            (lambda value: value["output_records"].clear(), "output set"),
        ):
            with self.subTest(message=message):
                value = receipt(COLIBRI_BUILD)
                mutate(value)
                response = BrokeredEffectResponse(200, json.dumps(value).encode(),
                    {"content-type": "application/json"}, "build-receipt-1")
                with self.assertRaisesRegex(AuthorityDenied, message):
                    parse_native_build_receipt(response, operation_id=COLIBRI_BUILD,
                        enrollment_id="enroll-1", generation="service-gen-4", now=lambda: 101.0)

    def test_build_receipt_requires_terminal_success_and_verified_cleanup(self) -> None:
        for field, value in (("exit_code", 1), ("cleanup_verified", False)):
            body = receipt(COLIBRI_BUILD)
            body["execution"][field] = value
            unsigned = {key: item for key, item in body.items()
                if key not in {"receipt_digest", "root_signature"}}
            body["receipt_digest"] = hashlib.sha256(json.dumps(unsigned, sort_keys=True,
                separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()).hexdigest()
            response = BrokeredEffectResponse(200, json.dumps(body).encode(),
                {"content-type": "application/json"}, "build-receipt-1")
            with self.subTest(field=field), self.assertRaisesRegex(AuthorityDenied, "terminal process evidence|bounded custody"):
                parse_native_build_receipt(response, operation_id=COLIBRI_BUILD,
                    enrollment_id="enroll-1", generation="service-gen-4", now=lambda: 101.0)

    def test_build_client_never_dispatches_unknown_recipe_or_cancellation(self) -> None:
        class Client:
            def __init__(self): self.called = False
            def start_enrolled_build_operation(self, **_request): self.called = True
            def start_enrolled_process_operation(self, **_request): self.called = True

        client = Client()
        with self.assertRaisesRegex(ValueError, "two fixed"):
            run_fixed_native_build(client, operation_id="arbitrary-shell", enrollment_id="e", generation="g")
        with self.assertRaisesRegex(AuthorityDenied, "cancelled"):
            run_fixed_native_build(client, operation_id=COLIBRI_BUILD, enrollment_id="e", generation="g",
                cancelled=lambda: True)
        self.assertFalse(client.called)

    def test_generic_live_process_start_is_never_used_as_build_completion(self) -> None:
        class LegacyClient:
            def __init__(self): self.called = False
            def start_enrolled_process_operation(self, **_request): self.called = True

        client = LegacyClient()
        with self.assertRaisesRegex(AuthorityDenied, "terminal build client"):
            run_fixed_native_build(client, operation_id=COLIBRI_BUILD,
                enrollment_id="enroll-1", generation="service-gen-4")
        self.assertFalse(client.called)


if __name__ == "__main__":
    unittest.main()
