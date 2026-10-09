from __future__ import annotations

import hashlib
import io
import json
import os
import tempfile
import tarfile
import time
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace

from hermes_installer.artifacts import (
    ArtifactCatalog,
    ArtifactSpec,
    PackageSpec,
    TreeFile,
    build_artifact_handlers,
    load_protected_catalog,
    load_protected_package_sets,
    sign_package_set_manifest,
)
from hermes_installer.authority.types import AuthorityDenied, canonical_digest


class _Response:
    def __init__(self, data: bytes, status: int = 200, headers: dict[str, str] | None = None):
        self.stream = io.BytesIO(data)
        self.status = status
        self.code = status
        self.headers = headers or {"Content-Length": str(len(data))}

    def read(self, size: int = -1) -> bytes:
        return self.stream.read(size)

    def close(self) -> None:
        self.stream.close()


class ArtifactBrokerContracts(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.root = self.base / "stage"
        self.root.mkdir(mode=0o700)
        self.uid = os.getuid()

    def tearDown(self):
        self.temp.cleanup()

    def spec(self, data: bytes, **kwargs) -> ArtifactSpec:
        return ArtifactSpec(
            artifact_id="fixture-source", version="1.0.0",
            sha256=hashlib.sha256(data).hexdigest(),
            source_url="https://downloads.example.test/pinned.bin",
            max_bytes=max(1, len(data)), size_bytes=len(data), filename="source.bin",
            **kwargs,
        )

    def test_vendored_resources_source_is_an_exact_offline_catalog_artifact(self):
        catalog_file = Path(__file__).parents[2] / "src/hermes_installer/authority/artifact-catalog.json"
        catalog_copy = self.base / "artifact-catalog.json"
        catalog_copy.write_bytes(catalog_file.read_bytes())
        catalog_copy.chmod(0o600)
        catalog = load_protected_catalog(catalog_copy, expected_uid=self.uid)
        artifact_id = "resources-source-113f42d33be9e0c8f0f47f5ca998e687323dec83"
        digest = "b09459b609676cff30f151ac7db1fc405039b8871486b483af563ba7f63e7cd1"
        spec = catalog._artifact(artifact_id, digest)
        self.assertEqual(spec.size_bytes, 295368)
        self.assertEqual(spec.version, "113f42d33be9e0c8f0f47f5ca998e687323dec83")
        self.assertEqual(len(spec.tree_files), 739)
        self.assertEqual(spec.archive_format, "tar.gz")

        archive = Path(__file__).parents[2] / "src/hermes_installer/registry/bundle_data/hermes-agent-resources-2.3.1.tar.gz"
        self.assertEqual(hashlib.sha256(archive.read_bytes()).hexdigest(), digest)
        staged = self.root / "objects" / artifact_id / digest / spec.filename
        staged.parent.mkdir(parents=True, mode=0o700)
        staged.write_bytes(archive.read_bytes())
        staged.chmod(0o444)
        resolved = catalog.materialize_tree(artifact_id, digest, self.root, expected_uid=self.uid)
        self.assertEqual(len(resolved.tree_files), 739)
        self.assertEqual(resolved.tree_manifest_sha256, spec.tree_manifest_sha256)
        self.assertTrue((resolved.path / "catalog.yaml").is_file())

    def request(self, spec: ArtifactSpec):
        payload = json.dumps({"schema": 1, "artifact_id": spec.artifact_id,
                              "sha256": spec.sha256, "max_bytes": spec.max_bytes},
                             sort_keys=True, separators=(",", ":")).encode()
        grant = SimpleNamespace(target=f"artifact:{spec.artifact_id}:{spec.sha256}",
                                request_digest=canonical_digest(payload),
                                monotonic_expires_at=time.monotonic() + 20,
                                policy_revision="policy-1", principal_id="principal",
                                profile_id="profile", namespace_id="namespace", uid=self.uid,
                                retry_index=0)
        return grant, payload

    @staticmethod
    def context(grant):
        return SimpleNamespace(monotonic_expires_at=grant.monotonic_expires_at,
                               policy_revision=grant.policy_revision,
                               principal_id=grant.principal_id, profile_id=grant.profile_id,
                               namespace_id=grant.namespace_id, uid=grant.uid)

    def test_fetch_streams_checks_pin_and_returns_receipt_not_artifact_bytes(self):
        data = b"installer fixture payload"
        spec = self.spec(data)
        catalog = ArtifactCatalog.from_records((spec,))
        calls = []

        def opener(request, *, timeout, allowed_hosts):
            calls.append((request.full_url, timeout, allowed_hosts))
            return _Response(data)

        handlers = build_artifact_handlers(catalog, self.root, expected_uid=self.uid, opener=opener)
        grant, payload = self.request(spec)
        response = handlers[("artifact.fetch", grant.target)](
            context=self.context(grant), authorization=grant, payload=payload, timeout=20,
            peer_pid=1, cancelled=lambda: False)
        body = json.loads(response["body"])
        self.assertEqual(response["status"], 200)
        self.assertEqual(body["sha256"], spec.sha256)
        self.assertEqual(body["size_bytes"], len(data))
        self.assertEqual(body["store_id"], f"artifact:{spec.artifact_id}:{spec.sha256}")
        self.assertEqual(calls[0][0], spec.source_url)
        self.assertIn("downloads.example.test", calls[0][2])
        resolved = catalog.resolve(spec.artifact_id, spec.sha256, self.root, expected_uid=self.uid)
        self.assertEqual(resolved.path.read_bytes(), data)
        self.assertEqual(catalog.resolve_store_id(body["store_id"], self.root,
                                                  expected_uid=self.uid).path, resolved.path)
        self.assertEqual(resolved.path.stat().st_mode & 0o222, 0)
        self.assertNotEqual(response["body"], data)

    def test_interrupted_download_resumes_from_owned_partial_file(self):
        data = b"abcdefghij"
        spec = self.spec(data)
        partial = self.root / "objects" / spec.artifact_id / spec.sha256 / "source.bin.part"
        partial.parent.mkdir(parents=True, mode=0o700)
        partial.write_bytes(data[:4])
        partial.chmod(0o600)
        catalog = ArtifactCatalog.from_records((spec,))
        seen = []

        def opener(request, *, timeout, allowed_hosts):
            seen.append(request.headers.get("Range"))
            return _Response(data[4:], 206, {
                "Content-Length": str(len(data) - 4),
                "Content-Range": f"bytes 4-9/{len(data)}"})

        handlers = build_artifact_handlers(catalog, self.root, expected_uid=self.uid, opener=opener)
        grant, payload = self.request(spec)
        handlers[("artifact.fetch", grant.target)](
            context=self.context(grant), authorization=grant, payload=payload, timeout=5,
            peer_pid=1, cancelled=lambda: False)
        self.assertEqual(seen, ["bytes=4-"])
        self.assertEqual(catalog.resolve(spec.artifact_id, spec.sha256, self.root,
                                         expected_uid=self.uid).path.read_bytes(), data)

    def test_cancellation_keeps_only_resumable_partial_and_preserves_sibling(self):
        data = b"abcdef"
        spec = self.spec(data)
        sentinel = self.root / "unrelated.txt"
        sentinel.write_text("preserve", encoding="utf-8")
        catalog = ArtifactCatalog.from_records((spec,))

        def opener(request, *, timeout, allowed_hosts):
            return _Response(data)

        handlers = build_artifact_handlers(catalog, self.root, expected_uid=self.uid, opener=opener)
        grant, payload = self.request(spec)
        calls = 0

        def cancelled():
            nonlocal calls
            calls += 1
            return calls > 4

        with self.assertRaises(AuthorityDenied) as denied:
            handlers[("artifact.fetch", grant.target)](
                context=self.context(grant), authorization=grant, payload=payload, timeout=5,
                peer_pid=1, cancelled=cancelled)
        self.assertEqual(denied.exception.code, "artifact.cancelled")
        partial = self.root / "objects" / spec.artifact_id / spec.sha256 / "source.bin.part"
        self.assertTrue(partial.exists())
        self.assertEqual(sentinel.read_text(encoding="utf-8"), "preserve")
        with self.assertRaises(AuthorityDenied):
            catalog.resolve(spec.artifact_id, spec.sha256, self.root, expected_uid=self.uid)

    def test_payload_cannot_choose_url_or_digest_and_pin_failure_is_not_published(self):
        data = b"expected"
        spec = self.spec(data)
        catalog = ArtifactCatalog.from_records((spec,))
        invoked = []

        def opener(request, *, timeout, allowed_hosts):
            invoked.append(request.full_url)
            return _Response(b"attacker")

        handlers = build_artifact_handlers(catalog, self.root, expected_uid=self.uid, opener=opener)
        grant, payload = self.request(spec)
        forged = json.dumps({"schema": 1, "artifact_id": spec.artifact_id,
                             "sha256": spec.sha256, "max_bytes": spec.max_bytes,
                             "url": "https://attacker.test/"}, sort_keys=True,
                            separators=(",", ":")).encode()
        grant = SimpleNamespace(**{**grant.__dict__, "request_digest": canonical_digest(forged)})
        with self.assertRaises(AuthorityDenied):
            handlers[("artifact.fetch", grant.target)](
                context=self.context(grant), authorization=grant, payload=forged, timeout=5,
                peer_pid=1, cancelled=lambda: False)
        self.assertEqual(invoked, [])

        grant, payload = self.request(spec)
        with self.assertRaises(AuthorityDenied) as denied:
            handlers[("artifact.fetch", grant.target)](
                context=self.context(grant), authorization=grant, payload=payload, timeout=5,
                peer_pid=1, cancelled=lambda: False)
        self.assertEqual(denied.exception.code, "artifact.digest")
        self.assertFalse((self.root / "objects" / spec.artifact_id / spec.sha256 / spec.filename).exists())

    def test_cancellation_during_preparation_denies_before_network_open(self):
        data = b"prepared payload"
        spec = self.spec(data)
        catalog = ArtifactCatalog.from_records((spec,))
        opened = []
        handlers = build_artifact_handlers(
            catalog, self.root, expected_uid=self.uid,
            opener=lambda *args, **kwargs: opened.append(True),
        )
        grant, payload = self.request(spec)
        checks = 0

        def cancelled():
            nonlocal checks
            checks += 1
            return checks > 1

        with self.assertRaises(AuthorityDenied) as denied:
            handlers[("artifact.fetch", grant.target)](
                context=self.context(grant), authorization=grant, payload=payload,
                timeout=5, peer_pid=1, cancelled=cancelled)
        self.assertEqual(denied.exception.code, "effect.cancelled")
        self.assertEqual(opened, [])

    def test_expired_grant_cannot_resume_or_publish_partial_bytes(self):
        data = b"abcdefghij"
        spec = self.spec(data)
        partial = self.root / "objects" / spec.artifact_id / spec.sha256 / "source.bin.part"
        partial.parent.mkdir(parents=True, mode=0o700)
        partial.write_bytes(data[:4])
        partial.chmod(0o600)
        catalog = ArtifactCatalog.from_records((spec,))
        opened = []
        handlers = build_artifact_handlers(
            catalog, self.root, expected_uid=self.uid,
            opener=lambda *args, **kwargs: opened.append(True),
        )
        grant, payload = self.request(spec)
        grant.monotonic_expires_at = time.monotonic() - 1
        with self.assertRaises(AuthorityDenied) as denied:
            handlers[("artifact.fetch", grant.target)](
                context=self.context(grant), authorization=grant, payload=payload,
                timeout=5, peer_pid=1, cancelled=lambda: False)
        self.assertEqual(denied.exception.code, "grant.stale")
        self.assertEqual(partial.read_bytes(), data[:4])
        self.assertEqual(opened, [])

    def test_generation_revalidation_denies_immediately_before_connect(self):
        data = b"pinned payload"
        spec = self.spec(data)
        catalog = ArtifactCatalog.from_records((spec,))
        opened = []
        rechecked = []

        def authorization_check(context, authorization, *, operation, request_digest, retry_index):
            rechecked.append((operation, request_digest, retry_index))
            raise AuthorityDenied("grant.stale", "policy generation changed")

        handlers = build_artifact_handlers(
            catalog, self.root, expected_uid=self.uid,
            opener=lambda *args, **kwargs: opened.append(True),
            authorization_check=authorization_check,
        )
        grant, payload = self.request(spec)
        with self.assertRaises(AuthorityDenied) as denied:
            handlers[("artifact.fetch", grant.target)](
                context=self.context(grant), authorization=grant, payload=payload,
                timeout=5, peer_pid=1, cancelled=lambda: False)
        self.assertEqual(denied.exception.code, "grant.stale")
        self.assertEqual(rechecked, [("artifact.fetch", grant.request_digest, 0)])
        self.assertEqual(opened, [])

    def test_cached_receipt_revalidates_fresh_policy_without_opening_network(self):
        data = b"already verified"
        spec = self.spec(data)
        catalog = ArtifactCatalog.from_records((spec,))
        final = self.root / "objects" / spec.artifact_id / spec.sha256 / spec.filename
        final.parent.mkdir(parents=True, mode=0o700)
        final.write_bytes(data)
        final.chmod(0o444)
        calls = []

        def authorization_check(context, authorization, *, operation, request_digest, retry_index):
            calls.append((operation, request_digest, retry_index))
            if len(calls) > 1:
                raise AuthorityDenied("policy.changed", "authorization was revoked")

        def opener(*args, **kwargs):
            self.fail("a cached artifact must not open a network request")

        handlers = build_artifact_handlers(catalog, self.root, expected_uid=self.uid,
                                           opener=opener, authorization_check=authorization_check)
        grant, payload = self.request(spec)
        with self.assertRaises(AuthorityDenied) as denied:
            handlers[("artifact.fetch", grant.target)](
                context=self.context(grant), authorization=grant, payload=payload,
                timeout=5, peer_pid=1, cancelled=lambda: False)
        self.assertEqual(denied.exception.code, "policy.changed")
        self.assertEqual(calls, [("artifact.fetch", grant.request_digest, 0),
                                 ("artifact.fetch", grant.request_digest, 0)])

    def test_catalog_loader_rejects_mutable_or_unpinned_catalog(self):
        record = {
            "schema": 1,
            "artifacts": [{"artifact_id": "fixture", "version": "1", "sha256": "a" * 64,
                           "source_url": "https://example.test/a", "max_bytes": 10,
                           "size_bytes": 10, "redirect_hosts": [], "filename": "a.bin",
                           "tree_files": [], "archive_format": None, "archive_root": None,
                           "max_tree_bytes": 1024}],
            "packages": [],
        }
        path = self.base / "catalog.json"
        path.write_text(json.dumps(record), encoding="utf-8")
        path.chmod(0o600)
        loaded = load_protected_catalog(path, expected_uid=self.uid)
        with self.assertRaises(TypeError):
            loaded.artifacts["new"] = loaded.artifacts["fixture"]
        path.chmod(0o644)
        with self.assertRaises(AuthorityDenied):
            load_protected_catalog(path, expected_uid=self.uid)

    def test_reviewed_seed_catalog_loads_exact_source_and_toolchain_pins(self):
        source = Path(__file__).parents[2] / "src/hermes_installer/authority/artifact-catalog.json"
        target = self.base / "reviewed-catalog.json"
        target.write_bytes(source.read_bytes())
        target.chmod(0o600)
        catalog = load_protected_catalog(target, expected_uid=self.uid)
        expected = {
            "hermes-pm-python314-linux-arm64": "30f1cc489be654477d895b441e196bb080738bf0456da82080ad4ab66a22d80f",
            "hermes-pm-uv-linux-arm64": "bb66cb52e7b1823aed1183630d8d8e5c958840d584a4c55ec10a4cfc168dcca2",
            "hermes-pm-node-linux-arm64": "afc7a004018485092ac8985b817b0d5684472bd9472e0b57d2ab88737e50090d",
            "coral-python39-source": "00e07d7c0f2f0cc002432d1ee84d2a40dae404a99303e3f97701c10966c91834",
            "coral-tflite-runtime-cp39-arm64": "be198b7dc4401204be54a15884d9e336389790eb707439524540f5a9329fdd02",
            "coral-numpy-cp39-arm64": "d5241e0a80d808d70546c697135da2c613f30e28251ff8307eb72ba696945764",
            "coral-compiled-sample": "4315ee115507aab28c78809c0f384e5296527dd6a5dd53a1751b3eb9c91db6aa",
        }
        for artifact_id, digest in expected.items():
            self.assertEqual(catalog.artifacts[artifact_id].sha256, digest)
        self.assertEqual(len(catalog.artifacts["coral-python39-source"].tree_files), 4266)
        self.assertEqual(catalog.artifacts["hermes-pm-node-linux-arm64"].archive_format, "tar.xz")
        self.assertFalse(catalog.packages)

    def test_signed_coral_package_set_binds_only_enrolled_source_runtime_and_two_wheels(self):
        seed = Path(__file__).parents[2] / "src/hermes_installer/authority/artifact-catalog.json"
        catalog_path = self.base / "catalog.json"
        catalog_path.write_bytes(seed.read_bytes())
        catalog_path.chmod(0o600)
        catalog = load_protected_catalog(catalog_path, expected_uid=self.uid)
        key = b"test-only-package-set-signing-key-material-32"
        manifest = {
            "schema": 1, "package_set_id": "coral-cp39-runtime-v1",
            "enrollment_id": "pi-coral", "generation": "gen-4",
            "runtime_artifact_id": "coral-python39-source",
            "runtime_build_attestation_digest": "a" * 64,
            "runtime_executable_sha256": "b" * 64,
            "abi": "cp39/aarch64", "target_glibc_min": "2.34",
            "service_uid": max(1, self.uid), "venv_root_id": "coral-venv-root",
            "wheel_entries": [
                {"identity": "tensorflow/tflite-runtime", "version": "2.14.0",
                 "artifact_id": "coral-tflite-runtime-cp39-arm64",
                 "artifact_sha256": "be198b7dc4401204be54a15884d9e336389790eb707439524540f5a9329fdd02",
                 "artifact_bytes": 2_325_666, "license": "Apache-2.0"},
                {"identity": "numpy/numpy", "version": "1.26.4",
                 "artifact_id": "coral-numpy-cp39-arm64",
                 "artifact_sha256": "d5241e0a80d808d70546c697135da2c613f30e28251ff8307eb72ba696945764",
                 "artifact_bytes": 14_226_281, "license": "BSD-3-Clause"},
            ],
            "reviewed_installer_artifact_id": "hermes-installer-artifact-broker-v1",
            "policy_revision": "policy-12",
        }
        signed = sign_package_set_manifest(manifest, signing_key=key, key_id="test-enrollment")
        path = self.base / "package-sets.json"
        path.write_text(json.dumps({"schema": 1, "package_sets": [signed]}), encoding="utf-8")
        path.chmod(0o600)
        loaded = load_protected_package_sets(path, catalog=catalog, signing_key=key,
                                            key_id="test-enrollment", expected_uid=self.uid)
        self.assertEqual(tuple(loaded), ("coral-cp39-runtime-v1",))
        self.assertEqual(len(loaded["coral-cp39-runtime-v1"].wheel_entries), 2)

        signed["wheel_entries"].append(dict(signed["wheel_entries"][0]))
        path.write_text(json.dumps({"schema": 1, "package_sets": [signed]}), encoding="utf-8")
        path.chmod(0o600)
        with self.assertRaises(AuthorityDenied):
            load_protected_package_sets(path, catalog=catalog, signing_key=key,
                                       key_id="test-enrollment", expected_uid=self.uid)

    def test_package_install_enrollment_requires_tree_and_exact_artifact_digest(self):
        spec = self.spec(b"archive")
        with self.assertRaises(ValueError):
            ArtifactCatalog.from_records((spec,), (PackageSpec(
                "runtime", "1", spec.artifact_id, "f" * 64, "hermes-py314",
                "/opt/hermes/python", "/var/lib/hermes/runtimes"),))
        with self.assertRaises(ValueError):
            TreeFile("../escape.whl", "a" * 64, 1)

    def test_materialized_archive_tree_checks_each_file_and_freezes_output(self):
        tree_bytes = {"requirements.txt": b"example==1.0 --hash=sha256:" + b"b" * 64 + b"\n",
                      "example-1.0-py3-none-any.whl": b"wheel fixture",
                      "install.sh": b"#!/bin/sh\nexit 0\n"}
        archive_bytes = io.BytesIO()
        with zipfile.ZipFile(archive_bytes, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for name, content in tree_bytes.items():
                archive.writestr(name, content)
        raw = archive_bytes.getvalue()
        tree = tuple(TreeFile(name, hashlib.sha256(content).hexdigest(), len(content),
                              executable=name == "install.sh")
                     for name, content in tree_bytes.items())
        spec = ArtifactSpec("wheelhouse", "1.0", hashlib.sha256(raw).hexdigest(),
                            "https://downloads.example.test/wheels.zip", len(raw), len(raw),
                            filename="wheels.zip", tree_files=tree, archive_format="zip",
                            max_tree_bytes=sum(item.size_bytes for item in tree))
        catalog = ArtifactCatalog.from_records((spec,))

        def opener(request, *, timeout, allowed_hosts):
            return _Response(raw)

        handlers = build_artifact_handlers(catalog, self.root, expected_uid=self.uid, opener=opener)
        grant, payload = self.request(spec)
        handlers[("artifact.fetch", grant.target)](
            context=self.context(grant), authorization=grant, payload=payload, timeout=5,
            peer_pid=1, cancelled=lambda: False)
        materialized = catalog.materialize_tree(spec.artifact_id, spec.sha256, self.root,
                                                expected_uid=self.uid)
        self.assertTrue(materialized.path.is_dir())
        self.assertEqual({path.relative_to(materialized.path).as_posix()
                          for path in materialized.path.rglob("*") if path.is_file()},
                         set(tree_bytes))
        self.assertTrue(all(path.stat().st_mode & 0o222 == 0 for path in materialized.path.rglob("*") if path.is_file()))
        self.assertTrue(materialized.path.joinpath("install.sh").stat().st_mode & 0o111)

    def test_tar_xz_materialization_preserves_only_enrolled_internal_symlinks(self):
        target = b"python runtime"
        link = "python3.14"
        archive_bytes = io.BytesIO()
        with tarfile.open(fileobj=archive_bytes, mode="w:xz") as archive:
            link_info = tarfile.TarInfo("runtime/bin/python")
            link_info.type = tarfile.SYMTYPE
            link_info.linkname = link
            archive.addfile(link_info)
            file_info = tarfile.TarInfo("runtime/bin/python3.14")
            file_info.size = len(target)
            file_info.mode = 0o755
            archive.addfile(file_info, io.BytesIO(target))
        raw = archive_bytes.getvalue()
        tree = (
            TreeFile("bin/python", hashlib.sha256(link.encode()).hexdigest(), len(link),
                     kind="symlink", link_target=link),
            TreeFile("bin/python3.14", hashlib.sha256(target).hexdigest(), len(target), True),
        )
        spec = ArtifactSpec("python-runtime-fixture", "3.14", hashlib.sha256(raw).hexdigest(),
                            "https://downloads.example.test/python.tar.xz", len(raw), len(raw),
                            filename="python.tar.xz", tree_files=tree, archive_format="tar.xz",
                            archive_root="runtime/", max_tree_bytes=1024)
        catalog = ArtifactCatalog.from_records((spec,))
        handlers = build_artifact_handlers(catalog, self.root, expected_uid=self.uid,
                                           opener=lambda request, **kwargs: _Response(raw))
        grant, payload = self.request(spec)
        handlers[("artifact.fetch", grant.target)](
            context=self.context(grant), authorization=grant, payload=payload, timeout=5,
            peer_pid=1, cancelled=lambda: False)
        resolved = catalog.materialize_store_id(f"artifact:{spec.artifact_id}:{spec.sha256}",
                                                self.root, expected_uid=self.uid)
        link_path = resolved.path / "bin/python"
        self.assertTrue(link_path.is_symlink())
        self.assertEqual(os.readlink(link_path), link)
        self.assertEqual(link_path.read_bytes(), target)
        self.assertEqual(len(resolved.tree_files), 2)

        with self.assertRaises(ValueError):
            ArtifactSpec("unsafe-tree", "1", spec.sha256, spec.source_url, len(raw), len(raw),
                         tree_files=(TreeFile("bin", hashlib.sha256(b"runtime").hexdigest(), 7,
                                              kind="symlink", link_target="runtime"),
                                     tree[1]), archive_format="tar.xz", archive_root="runtime/",
                         max_tree_bytes=1024)

    def test_tar_archive_requires_and_strips_only_enrolled_root_prefix(self):
        content = b"pinned source"
        archive_bytes = io.BytesIO()
        with tarfile.open(fileobj=archive_bytes, mode="w:gz") as archive:
            info = tarfile.TarInfo("source-commit/")
            info.type = tarfile.DIRTYPE
            archive.addfile(info)
            info = tarfile.TarInfo("source-commit/src/main.py")
            info.size = len(content)
            info.mode = 0o755
            archive.addfile(info, io.BytesIO(content))
        raw = archive_bytes.getvalue()
        tree = (TreeFile("src/main.py", hashlib.sha256(content).hexdigest(), len(content), True),)
        spec = ArtifactSpec("source-tree", "commit", hashlib.sha256(raw).hexdigest(),
                            "https://downloads.example.test/source.tar.gz", len(raw), len(raw),
                            filename="source.tar.gz", tree_files=tree, archive_format="tar.gz",
                            archive_root="source-commit/", max_tree_bytes=len(content))
        catalog = ArtifactCatalog.from_records((spec,))

        def opener(request, *, timeout, allowed_hosts):
            return _Response(raw)

        handlers = build_artifact_handlers(catalog, self.root, expected_uid=self.uid, opener=opener)
        grant, payload = self.request(spec)
        handlers[("artifact.fetch", grant.target)](
            context=self.context(grant), authorization=grant, payload=payload, timeout=5,
            peer_pid=1, cancelled=lambda: False)
        resolved = catalog.materialize_tree(spec.artifact_id, spec.sha256, self.root,
                                            expected_uid=self.uid)
        script = resolved.path / "src/main.py"
        self.assertEqual(script.read_bytes(), content)
        self.assertTrue(script.stat().st_mode & 0o111)

        escaped = io.BytesIO()
        with tarfile.open(fileobj=escaped, mode="w:gz") as archive:
            info = tarfile.TarInfo("other-root/src/main.py")
            info.size = len(content)
            archive.addfile(info, io.BytesIO(content))
        from hermes_installer.artifacts import _extract_archive
        escaped_path = self.base / "escaped.tar.gz"
        escaped_path.write_bytes(escaped.getvalue())
        extracted = self.base / "extract"
        extracted.mkdir(mode=0o700)
        with self.assertRaises(AuthorityDenied):
            _extract_archive(escaped_path, "tar.gz", "source-commit/", tree,
                             len(content), extracted, self.uid)


if __name__ == "__main__":
    unittest.main()
