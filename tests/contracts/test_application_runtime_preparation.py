from __future__ import annotations

import hashlib
import io
import json
import dataclasses
import os
from pathlib import Path
import tempfile
import unittest
import zipfile
from unittest.mock import patch

from hermes_installer.authority.service import AuthorityService, PrincipalBinding
from hermes_installer.authority.application_runtime_preparation import (
    ApplicationRuntimePreparationDenied,
    RootApplicationLockedPackageArtifactReceipt,
    RootApplicationOfflinePackageClosureRegistry,
    RootApplicationPackageLicenseObservation,
    _PackageArtifactEntry,
    _PackageLicenseEntry,
    _FrozenClaimMap,
    observe_python_wheel_license,
    select_locked_python_wheels,
)


def _wheel_row(name: str, filename: str) -> str:
    digest = hashlib.sha256(filename.encode()).hexdigest()
    return (
        '[[package]]\n'
        f'name = "{name}"\n'
        'version = "1.0.0"\n'
        'source = { registry = "https://pypi.org/simple" }\n'
        f'wheels = [{{ url = "https://files.pythonhosted.org/packages/{filename}", '
        f'hash = "sha256:{digest}", size = 123 }}]\n'
    )


class ApplicationRuntimePreparationTests(unittest.TestCase):
    def test_authority_signer_retains_exact_pending_package_observations(self):
        uid = os.getuid() or 1
        service = AuthorityService(
            signing_key=b"k" * 32, key_id="package-test-key",
            bindings_by_uid={uid: PrincipalBinding(
                uid, "principal", "profile", "namespace", frozenset({"test"}))},
            rules={}, handlers={},
        )
        registry = object.__new__(RootApplicationOfflinePackageClosureRegistry)
        registry.authority_service = service
        registry._pending_artifacts = {}
        registry._pending_licenses = {}
        registry._artifact_entries = {}
        registry._license_entries = {}
        # Exercise the real AuthorityService signer/retention path. Full
        # source, lock, controller and CAS verification remains mandatory and
        # is tested by the production callbacks, but needs the root setup CI
        # fixture rather than fabricated setup receipts in this unit test.
        registry._verify_artifact_observation = lambda _receipt: None
        registry._verify_license_observation = lambda _receipt: None
        with tempfile.TemporaryFile() as held:
            held.write(b"wheel")
            held.flush()
            handle = "a" * 48
            now = 10.0
            artifact = RootApplicationLockedPackageArtifactReceipt(
                receipt_handle=handle, artifact_id="app-runtime-package-" + "b" * 64,
                application_id="graphify", source_preparation_selection_handle="s" * 48,
                qualification_choice_handle="c" * 48,
                qualification_consent_receipt_handle="p" * 48,
                setup_session_id="setup", transaction_handle="transaction",
                plan_sha256="1" * 64, prepared_generation_digest="2" * 64,
                lock_receipt_handle="l" * 48, lock_sha256="3" * 64,
                lock_member_id="uv.lock", package_name="sample", package_version="1.0",
                artifact_kind="wheel", platform_tags=("cp314-cp314-manylinux_2_36_aarch64",),
                origin_policy_id="installer-locked-public-package-origin-v1",
                source_url="https://files.pythonhosted.org/packages/sample.whl",
                lock_integrity_algorithm="sha256", lock_integrity_digest="4" * 64,
                artifact_sha256="b" * 64, size_bytes=5,
                cas_device=os.fstat(held.fileno()).st_dev,
                cas_inode=os.fstat(held.fileno()).st_ino, cas_mode=0o444,
                controller_binding_handle="controller", issued_monotonic=now,
                expires_monotonic=now + 60, signature="",
            )
            registry._pending_artifacts[handle] = artifact
            registry._artifact_entries[handle] = _PackageArtifactEntry(
                artifact, None, os.dup(held.fileno()), object())
            service.attach_application_package_closure_registry(registry)
            signer = service.application_package_observation_signer()
            signed = signer.issue_locked_package_artifact(artifact)
            self.assertEqual(registry._artifact_entries[handle].receipt, signed)
            self.assertTrue(signer.verify_locked_package_artifact(signed))
            forged = dataclasses.replace(signed, artifact_sha256="5" * 64)
            with self.assertRaises(Exception):
                signer.verify_locked_package_artifact(forged)
            with patch.object(registry, "_verify_artifact_observation", side_effect=PermissionError):
                with self.assertRaises(Exception):
                    signer.verify_locked_package_artifact(signed)

            license_handle = "d" * 48
            license_observation = RootApplicationPackageLicenseObservation(
                receipt_handle=license_handle, artifact_receipt_handle=handle,
                artifact_sha256=artifact.artifact_sha256, package_name=artifact.package_name,
                package_version=artifact.package_version, metadata_kind="python-core-metadata",
                metadata_member_path="sample.dist-info/METADATA",
                metadata_member_sha256="6" * 64, declared_license_expression=None,
                license_member_records=(_FrozenClaimMap(path="LICENSE", sha256="7" * 64,
                                                         size_bytes=3),),
                evidence_sha256="8" * 64, eligibility="unavailable",
                review_policy_receipt_handle=None, issued_monotonic=now,
                expires_monotonic=now + 60, signature="",
            )
            registry._pending_licenses[license_handle] = license_observation
            registry._license_entries[license_handle] = _PackageLicenseEntry(
                license_observation, None, handle)
            signed_license = signer.issue_package_license_observation(license_observation)
            self.assertTrue(signer.verify_package_license_observation(signed_license))
            self.assertEqual(registry._license_entries[license_handle].receipt, signed_license)
            os.close(registry._artifact_entries[handle].fd)
            registry._artifact_entries[handle].fd = -1

    def test_locked_package_origin_is_exact_https_public_wheel_origin(self):
        allowed = "https://files.pythonhosted.org/packages/ab/cd/example.whl"
        self.assertTrue(RootApplicationOfflinePackageClosureRegistry._url_is_allowed(allowed))
        for url in (
            "http://files.pythonhosted.org/packages/example.whl",
            "https://example.com/packages/example.whl",
            "https://user@files.pythonhosted.org/packages/example.whl",
            "https://files.pythonhosted.org:444/packages/example.whl",
            "https://files.pythonhosted.org/pypi/example.whl",
            "https://files.pythonhosted.org/packages/example.whl?token=secret",
            "https://files.pythonhosted.org/packages/example.whl#fragment",
            "https://files.pythonhosted.org\\@example.com/packages/example.whl",
        ):
            with self.subTest(url=url):
                self.assertFalse(RootApplicationOfflinePackageClosureRegistry._url_is_allowed(url))

    def test_signed_nested_claim_records_are_immutable_and_json_compatible(self):
        row = _FrozenClaimMap(path="dist-info/licenses/LICENSE", sha256="a" * 64,
                              size_bytes=12)
        self.assertEqual(json.loads(json.dumps(row)), dict(row))
        with self.assertRaises(TypeError):
            row["sha256"] = "b" * 64

    @staticmethod
    def _license_wheel() -> bytes:
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("sample_pkg-1.0.0.dist-info/METADATA",
                             "Metadata-Version: 2.4\nName: Sample_Pkg\nVersion: 1.0.0\n"
                             "License-Expression: MIT\nLicense-File: LICENSE.txt\n\n")
            archive.writestr("sample_pkg-1.0.0.dist-info/licenses/LICENSE.txt", b"MIT notice\n")
            archive.writestr("sample_pkg/__init__.py", b"# not executed\n")
        return output.getvalue()

    def test_license_observer_hashes_actual_metadata_and_referenced_license(self):
        wheel = self._license_wheel()
        digest = hashlib.sha256(wheel).hexdigest()
        observed = observe_python_wheel_license(
            wheel, expected_artifact_sha256=digest,
            expected_package_name="sample-pkg", expected_package_version="1.0.0")
        self.assertEqual(observed.metadata_kind, "python-core-metadata")
        self.assertEqual(observed.declared_license_expression, "MIT")
        self.assertEqual(observed.license_member_records,
                         (("sample_pkg-1.0.0.dist-info/licenses/LICENSE.txt",
                           hashlib.sha256(b"MIT notice\n").hexdigest(), 11),))
        self.assertEqual(observed.eligibility, "observed-declaration")
        self.assertEqual(len(observed.evidence_sha256), 64)

    def test_license_observer_never_converts_invalid_or_missing_evidence_to_approval(self):
        wheel = self._license_wheel()
        digest = hashlib.sha256(wheel).hexdigest()
        with self.assertRaises(ApplicationRuntimePreparationDenied):
            observe_python_wheel_license(
                wheel, expected_artifact_sha256="0" * 64,
                expected_package_name="sample-pkg", expected_package_version="1.0.0")
        with self.assertRaises(ApplicationRuntimePreparationDenied):
            observe_python_wheel_license(
                wheel, expected_artifact_sha256=digest,
                expected_package_name="different-package", expected_package_version="1.0.0")

        output = io.BytesIO()
        with zipfile.ZipFile(output, "w") as archive:
            archive.writestr("sample_pkg-1.0.0.dist-info/METADATA",
                             "Metadata-Version: 2.4\nName: sample-pkg\nVersion: 1.0.0\n\n")
        body = output.getvalue()
        evidence = observe_python_wheel_license(
            body, expected_artifact_sha256=hashlib.sha256(body).hexdigest(),
            expected_package_name="sample-pkg", expected_package_version="1.0.0")
        self.assertEqual(evidence.eligibility, "unavailable")

    def test_license_observer_rejects_unsafe_zip_member_paths(self):
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w") as archive:
            archive.writestr("../sample_pkg-1.0.0.dist-info/METADATA",
                             "Metadata-Version: 2.4\nName: sample-pkg\nVersion: 1.0.0\n\n")
        body = output.getvalue()
        with self.assertRaises(ApplicationRuntimePreparationDenied):
            observe_python_wheel_license(
                body, expected_artifact_sha256=hashlib.sha256(body).hexdigest(),
                expected_package_name="sample-pkg", expected_package_version="1.0.0")

    def test_selects_only_default_transitive_arm64_cp314_wheels(self):
        lock = (
            'version = 1\n'
            '[[package]]\nname = "demo-app"\nversion = "1.0.0"\n'
            'source = { editable = "." }\n'
            'dependencies = [{ name = "shared" }, '
            '{ name = "mac-only", marker = "sys_platform == \'darwin\'" }]\n'
            + _wheel_row("shared", "shared-1.0.0-cp314-cp314-manylinux_2_28_aarch64.whl")
        )
        selected = select_locked_python_wheels(lock.encode(), application_id="graphify")
        self.assertTrue(selected.complete, selected.blockers)
        self.assertEqual([item.package_name for item in selected.wheels], ["shared"])
        self.assertEqual(selected.wheels[0].selected_tag,
                         "cp314-cp314-manylinux_2_28_aarch64")

    def test_accepts_only_exact_sha256_or_sha512_lock_integrity(self):
        filename = "shared-1.0.0-py3-none-any.whl"
        sha512 = hashlib.sha512(filename.encode()).hexdigest()
        lock = (
            'version = 1\n[[package]]\nname = "demo-app"\nversion = "1.0.0"\n'
            'source = { editable = "." }\ndependencies = [{ name = "shared" }]\n'
            '[[package]]\nname = "shared"\nversion = "1.0.0"\n'
            'source = { registry = "https://pypi.org/simple" }\n'
            f'wheels = [{{ url = "https://files.pythonhosted.org/packages/{filename}", '
            f'hash = "sha512:{sha512}", size = 123 }}]\n'
        )
        selected = select_locked_python_wheels(lock.encode(), application_id="graphify")
        self.assertTrue(selected.complete, selected.blockers)
        self.assertEqual(selected.wheels[0].integrity_algorithm, "sha512")
        self.assertEqual(selected.wheels[0].integrity_digest, sha512)

        malformed = lock.replace(sha512, sha512[:-1])
        selected = select_locked_python_wheels(malformed.encode(), application_id="graphify")
        self.assertFalse(selected.complete)
        self.assertEqual(selected.wheels, ())

    def test_sdist_only_and_untrusted_artifact_origin_are_blockers(self):
        lock = (
            'version = 1\n'
            '[[package]]\nname = "demo-app"\nversion = "1.0.0"\n'
            'source = { editable = "." }\n'
            'dependencies = [{ name = "sdist-only" }, { name = "bad-origin" }]\n'
            '[[package]]\nname = "sdist-only"\nversion = "1.0.0"\n'
            'source = { registry = "https://pypi.org/simple" }\nwheels = []\n'
            '[[package]]\nname = "bad-origin"\nversion = "1.0.0"\n'
            'source = { registry = "https://pypi.org/simple" }\n'
            'wheels = [{ url = "https://evil.example/bad-origin-1.0.0-py3-none-any.whl", '
            'hash = "sha256:' + "0" * 64 + '", size = 10 }]\n'
        )
        selected = select_locked_python_wheels(lock.encode(), application_id="scrapegraph-ai")
        self.assertEqual(selected.wheels, ())
        self.assertIn("sdist-only:no-compatible-cp314-aarch64-wheel", selected.blockers)
        self.assertIn("bad-origin:no-compatible-cp314-aarch64-wheel", selected.blockers)

    def test_rejects_wrong_profile_and_malformed_lock(self):
        with self.assertRaises(ApplicationRuntimePreparationDenied):
            select_locked_python_wheels(b"version = 1", application_id="hyperframes")
        with self.assertRaises(ApplicationRuntimePreparationDenied):
            select_locked_python_wheels(b"not = [toml", application_id="graphify")

    def test_real_browser_use_lock_accepts_compatible_stable_abi_wheels(self):
        lock = Path("src/hermes_installer/components/runtime_locks/browser-use/uv.lock").read_bytes()
        selected = select_locked_python_wheels(lock, application_id="browser-use")
        self.assertTrue(selected.complete, selected.blockers)
        by_name = {item.package_name: item for item in selected.wheels}
        self.assertIn("cp311-abi3-manylinux", by_name["cryptography"].selected_tag)
        self.assertIn("cp36-abi3-manylinux", by_name["psutil"].selected_tag)


if __name__ == "__main__":
    unittest.main()
