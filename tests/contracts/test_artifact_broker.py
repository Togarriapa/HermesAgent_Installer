from __future__ import annotations

import hashlib
import io
import json
import os
import tempfile
import tarfile
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

    @staticmethod
    def request(spec: ArtifactSpec):
        payload = json.dumps({"schema": 1, "artifact_id": spec.artifact_id,
                              "sha256": spec.sha256, "max_bytes": spec.max_bytes},
                             sort_keys=True, separators=(",", ":")).encode()
        grant = SimpleNamespace(target=f"artifact:{spec.artifact_id}:{spec.sha256}",
                                request_digest=canonical_digest(payload))
        return grant, payload

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
            context=None, authorization=grant, payload=payload, timeout=20,
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
            context=None, authorization=grant, payload=payload, timeout=5,
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
            return calls > 1

        with self.assertRaises(AuthorityDenied) as denied:
            handlers[("artifact.fetch", grant.target)](
                context=None, authorization=grant, payload=payload, timeout=5,
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
        grant = SimpleNamespace(target=grant.target, request_digest=canonical_digest(forged))
        with self.assertRaises(AuthorityDenied):
            handlers[("artifact.fetch", grant.target)](
                context=None, authorization=grant, payload=forged, timeout=5,
                peer_pid=1, cancelled=lambda: False)
        self.assertEqual(invoked, [])

        grant, payload = self.request(spec)
        with self.assertRaises(AuthorityDenied) as denied:
            handlers[("artifact.fetch", grant.target)](
                context=None, authorization=grant, payload=payload, timeout=5,
                peer_pid=1, cancelled=lambda: False)
        self.assertEqual(denied.exception.code, "artifact.digest")
        self.assertFalse((self.root / "objects" / spec.artifact_id / spec.sha256 / spec.filename).exists())

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
            context=None, authorization=grant, payload=payload, timeout=5,
            peer_pid=1, cancelled=lambda: False)
        materialized = catalog.materialize_tree(spec.artifact_id, spec.sha256, self.root,
                                                expected_uid=self.uid)
        self.assertTrue(materialized.path.is_dir())
        self.assertEqual({path.relative_to(materialized.path).as_posix()
                          for path in materialized.path.rglob("*") if path.is_file()},
                         set(tree_bytes))
        self.assertTrue(all(path.stat().st_mode & 0o222 == 0 for path in materialized.path.rglob("*") if path.is_file()))
        self.assertTrue(materialized.path.joinpath("install.sh").stat().st_mode & 0o111)

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
            context=None, authorization=grant, payload=payload, timeout=5,
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
