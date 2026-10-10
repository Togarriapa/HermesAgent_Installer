from __future__ import annotations

import math
import unittest
from types import SimpleNamespace

from hermes_installer.authority.application_build_admission import (
    ApplicationBuildAdmissionDenied,
    RootApplicationBuildAdmissionRegistry,
    RootApplicationBuildInputMember,
    RootApplicationSetupBuildGrantIssuer,
    _APP_BUILD_PROFILES,
    _INPUTS_SEAL,
    _canonical,
    _opaque,
)


class ApplicationBuildAdmissionContracts(unittest.TestCase):
    def test_fixed_profiles_are_finite_and_hyperframes_is_not_a_python_build(self) -> None:
        self.assertEqual(set(_APP_BUILD_PROFILES), {
            "graphify", "browser-use", "hyperframes", "scrapegraph-ai",
        })
        self.assertEqual(_APP_BUILD_PROFILES["hyperframes"][1], "node")
        with self.assertRaises(TypeError):
            _APP_BUILD_PROFILES["unreviewed"] = ("workflow", "python", "profile", "target")

    def test_only_minted_input_members_can_cross_the_root_boundary(self) -> None:
        with self.assertRaises(TypeError):
            RootApplicationBuildInputMember(
                "packages/example.whl", 17, "a" * 64, 1, False, "r" * 32,
            )
        member = RootApplicationBuildInputMember._mint(
            relative_path="packages/example-1.0.whl", fd=17,
            sha256="a" * 64, size_bytes=1, executable=False,
            receipt_handle="r" * 32, kind="file",
        )
        self.assertIs(member._seal, _INPUTS_SEAL)
        self.assertEqual(member.kind, "file")
        self.assertIsNone(member.link_target)

    def test_opaque_handles_and_recipe_encoding_reject_ambiguous_values(self) -> None:
        self.assertEqual(_opaque("a" * 32, "test"), "a" * 32)
        for malformed in ("", "../" + "a" * 32, "a" * 31, "a" * 32 + "/"):
            with self.subTest(malformed=malformed), self.assertRaises(ApplicationBuildAdmissionDenied):
                _opaque(malformed, "test")
        with self.assertRaises(ValueError):
            _canonical({"non-finite": math.nan})

    def test_app_recipe_digest_commits_all_build_input_receipts(self) -> None:
        prep = SimpleNamespace(
            application_id="graphify", build_profile_id="application-graphify-runtime-prepare-v1",
            operation_id="application-graphify-runtime-prepare-v1",
            target_id="application-graphify-runtime-prepare:start",
            runtime_toolchain_receipt_handles=("p" * 32, "u" * 32),
        )
        source = SimpleNamespace(receipt_handle="s" * 32,
                                 source_generation_manifest_sha256="1" * 64)
        lock = SimpleNamespace(receipt_handle="l" * 32, lock_sha256="2" * 64)
        package = SimpleNamespace(receipt_handle="c" * 32, package_closure_sha256="3" * 64)
        backend = SimpleNamespace(receipt_handle="b" * 32, backend_closure_sha256="4" * 64)
        driver = SimpleNamespace(receipt_handle="d" * 32, sha256="5" * 64)
        output = SimpleNamespace(output_root_id="o" * 32)
        facts = {"prep": prep, "source": source, "lock": lock, "package": package,
                 "backend": backend, "driver": driver, "output": output,
                 "pm_runtime": SimpleNamespace(runtime_sha256="7" * 64),
                 "pm_uv": SimpleNamespace(receipt_handle="u" * 32, sha256="8" * 64),
                 "pm_projection": SimpleNamespace(base_closure_sha256="6" * 64)}
        original = RootApplicationBuildAdmissionRegistry._recipe_digest(facts)
        facts["pm_projection"] = SimpleNamespace(base_closure_sha256="7" * 64)
        self.assertNotEqual(original, RootApplicationBuildAdmissionRegistry._recipe_digest(facts))
        facts["pm_projection"] = SimpleNamespace(base_closure_sha256="6" * 64)
        facts["backend"] = SimpleNamespace(receipt_handle="b" * 32, backend_closure_sha256="8" * 64)
        self.assertNotEqual(original, RootApplicationBuildAdmissionRegistry._recipe_digest(facts))

    def test_setup_grant_factory_rejects_a_non_admission_object(self) -> None:
        with self.assertRaises(ApplicationBuildAdmissionDenied):
            RootApplicationSetupBuildGrantIssuer.from_root_setup(object(), object())

    def test_registry_never_accepts_untyped_or_missing_root_journal(self) -> None:
        with self.assertRaises(ApplicationBuildAdmissionDenied):
            RootApplicationBuildAdmissionRegistry.from_root_setup(
                object(), object(), object(), object(), object(), object(), object(),
            )


if __name__ == "__main__":
    unittest.main()
