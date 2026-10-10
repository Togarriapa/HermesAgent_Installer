"""Actual systemd Xauthority bind-mount custody on disposable Linux CI."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import platform
import secrets
import shutil
import sys
import time
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

from hermes_installer.authority.native_display_startup import (
    SelectedDisplayStartup,
    XauthorityStartupRegistry,
)


def _fixture_type():
    from test_managed_process_custody_linux import ManagedProcessRootAuthorityIntegrationTests
    return ManagedProcessRootAuthorityIntegrationTests


class _FixtureSigner:
    def __init__(self) -> None:
        self.key = os.urandom(32)

    def sign(self, payload: bytes) -> bytes:
        return hmac.new(self.key, payload, hashlib.sha256).digest()

    def verify(self, payload: bytes, signature: bytes) -> bool:
        return hmac.compare_digest(self.sign(payload), signature)


@unittest.skipUnless(
    platform.system() == "Linux" and hasattr(os, "pidfd_open") and os.geteuid() == 0,
    "requires the isolated Linux root systemd fixture",
)
class XauthorityMountKernelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        _fixture_type().setUpClass()

    def setUp(self) -> None:
        self.fixture = _fixture_type()(methodName="runTest")
        self.fixture.setUp()
        self.registry_root = self.fixture.stage / "xauthority-root"
        self.registry_root.mkdir(mode=0o700)
        os.chown(self.registry_root, 0, 0)
        os.chmod(self.registry_root, 0o700)
        self.registry = XauthorityStartupRegistry(
            root=self.registry_root,
            signer=_FixtureSigner(),
            custody=SimpleNamespace(resolve_active_process_handle=lambda *_args: None),
        )
        self.prepared = None
        self.source_lease = None
        self.xauthority_stage = None

    def tearDown(self) -> None:
        try:
            handler = self.fixture.handler
            if handler is not None:
                for handle in tuple(handler._handles.values()):
                    handler._stop(handle, timeout=5)
            if self.xauthority_stage is not None and self.xauthority_stage.exists():
                handler._remove_native_staging(self.xauthority_stage)
            if self.source_lease is not None:
                self.source_lease.close()
            if self.prepared is not None:
                self.registry.discard_prepared(self.prepared)
            shutil.rmtree(self.registry_root, ignore_errors=True)
        finally:
            self.fixture.tearDown()

    def test_selected_display_mount_is_readonly_pinned_and_removed_on_stop(self) -> None:
        fixture = self.fixture
        selected = SelectedDisplayStartup(
            # Reuse the active fixture enrollment/profile/generation as the
            # selected subject. These values are issued by the real disposable
            # service-profile fixture, rather than synthetic display IDs.
            remote_enrollment_id=fixture.enrollment_id,
            native_profile_id=fixture.profile.profile_id,
            native_generation=fixture.profile.generation,
            display_profile_id=fixture.profile.profile_id,
            display_generation=fixture.profile.generation,
            display_name=":0",
            receipt_handle=secrets.token_urlsafe(32),
            display_uid=fixture.uid,
            display_gid=fixture.gid,
            xauthority_reader_gid=fixture.gid,
        )
        self.prepared = self.registry.prepare(selected)
        binding = self.registry.mount_binding(self.prepared)
        self.assertTrue(self.registry.verify_mount_binding(binding))

        handler = fixture.handler
        assert handler is not None
        stage, stage_receipt, self.source_lease = handler._prepare_xauthority_mount(
            fixture.profile, binding, self.registry)
        self.xauthority_stage = stage
        self.assertEqual(stage_receipt.source_sha256, binding.source_sha256)
        self.assertEqual(stage_receipt.source_size_bytes, binding.source_size)
        self.assertEqual(stage_receipt.owner_gid, fixture.gid)
        source_stat = os.fstat(self.source_lease.file_fd)
        self.assertEqual((source_stat.st_dev, source_stat.st_ino, source_stat.st_size),
                         (binding.source_device, binding.source_inode, binding.source_size))
        self.assertEqual(self.source_lease.content_sha256, binding.source_sha256)
        self.assertEqual(
            hashlib.sha256(os.pread(self.source_lease.file_fd, binding.source_size, 0)).hexdigest(),
            binding.source_sha256,
        )
        self.assertTrue(self.registry.verify_mount_source(self.source_lease, binding))

        report_relative = "xauthority-mount-report.json"
        report_path = fixture.data_root / report_relative
        source = (
            "import hashlib,json,os,time\n"
            "p='/run/hermes-installer/display/Xauthority'\n"
            "raw=open(p,'rb').read()\n"
            "line=next(x.split() for x in open('/proc/self/mountinfo') if x.split()[4]==p)\n"
            "sep=line.index('-'); opts=set(line[5].split(',')); prop=line[6:sep]\n"
            "try: open(p,'ab').write(b'x'); denied=False\n"
            "except OSError: denied=True\n"
            f"r={{'sha256':hashlib.sha256(raw).hexdigest(),'size':len(raw),"
            f"'device':os.stat(p).st_dev,'inode':os.stat(p).st_ino,"
            f"'ro':'ro' in opts,'nosuid':'nosuid' in opts,'nodev':'nodev' in opts,"
            f"'noexec':'noexec' in opts,'private':not any(x.startswith(('shared:','master:','propagate_from:')) for x in prop),"
            f"'write_denied':denied}}\n"
            f"open('/hermes/profiles/{fixture.profile.profile_id}/{report_relative}','w').write(json.dumps(r))\n"
            "time.sleep(30)\n"
        )
        source_id, source_digest, _script = fixture._enroll_script("xauthority-mount", source)
        original_resolver = fixture._resolve_artifact
        handler.artifact_resolver = lambda artifact_id, digest: (
            _script if artifact_id == source_id and digest == source_digest
            else original_resolver(artifact_id, digest))
        recipe = fixture._operation_recipe(source_id, source_digest, "xauthority-mount")
        recipe["environment"] = {**recipe["environment"], "DISPLAY": ":0"}
        profile = replace(
            fixture.profile,
            child_artifact_refs={**fixture.profile.child_artifact_refs, source_id: source_digest},
            operation_recipes={**fixture.profile.operation_recipes, "xauthority-mount": recipe},
        )
        handler.profiles[profile.profile_id] = profile
        target_data = profile.data_root / report_relative
        target_data.unlink(missing_ok=True)
        payload = json.dumps({
            "schema": 1, "enrollment_id": profile.enrollment_id,
            "generation": profile.generation, "operation_id": "xauthority-mount",
            "parameters": {},
        }, sort_keys=True, separators=(",", ":")).encode("ascii")
        daemon_fd = os.pidfd_open(os.getpid(), 0)
        try:
            response = handler.start_selected_operation(
                profile,
                SimpleNamespace(principal_id="root-fixture", namespace_id="root-fixture"),
                SimpleNamespace(monotonic_expires_at=time.monotonic() + 30),
                payload,
                timeout=15, peer_pid=os.getpid(), peer_pidfd=None,
                cancelled=lambda: False,
                _root_selected_effect=SimpleNamespace(
                    role="display", expires_monotonic=time.monotonic() + 30),
                _xauthority_mount_source=stage,
                _daemon_liveness_pidfd=daemon_fd,
            )
        finally:
            os.close(daemon_fd)
        body = json.loads(response["body"].decode("ascii"))
        process_id = body["process_id"]
        handle = handler._handles[process_id]
        self.assertEqual(handle.xauthority_mount_receipt, stage_receipt)
        self.assertEqual(handle.xauthority_mount_source, stage)

        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and not target_data.exists():
            time.sleep(0.025)
        self.assertTrue(target_data.is_file(), "selected child did not inspect the mounted credential")
        observed = json.loads(target_data.read_text())
        self.assertEqual(observed["sha256"], binding.source_sha256)
        self.assertEqual(observed["size"], binding.source_size)
        self.assertEqual((observed["device"], observed["inode"]),
                         (stage_receipt.mount_source_device, stage_receipt.mount_source_inode))
        for flag in ("ro", "nosuid", "nodev", "noexec", "private", "write_denied"):
            self.assertTrue(observed[flag], flag)

        cleanup = handler._stop(handle, timeout=5)
        self.assertTrue(cleanup.cleanup_verified)
        self.assertFalse(stage.exists(), "credential staging survived process cleanup")
        self.assertEqual(handle.xauthority_mount_receipt, stage_receipt)


if __name__ == "__main__":
    unittest.main()
