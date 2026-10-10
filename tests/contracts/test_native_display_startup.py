from __future__ import annotations

import hashlib
import os
import stat
import tempfile
import time
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

from hermes_installer.authority.native_display_startup import (
    NativeDisplayStartupDenied,
    RootSelectedStartupGrant,
    SelectedDisplayStartup,
    XAUTHORITY_MOUNT_TARGET,
    XauthorityStartupRegistry,
    encode_xauthority,
    selected_start_payload,
)
from hermes_installer.authority.remote_origin import HMACReceiptSigner
from hermes_installer.authority.types import (
    RootSelectedServiceContext, RootSelectedServiceEffectGrant, Sensitivity,
)
from hermes_installer.managed_process_custodian import ManagedProcessIdentityLease


class _Custody:
    def __init__(self, identity=None):
        self.identity = identity

    def resolve_active_process_handle(self, _profile_id, _generation):
        if self.identity is None:
            raise AssertionError("this preparation-only test must not inspect a process")
        read_fd, write_fd = os.pipe()
        os.close(write_fd)
        return ManagedProcessIdentityLease(**{**self.identity, "pidfd": read_fd})


class XauthorityEncodingTests(unittest.TestCase):
    def test_selected_start_payload_is_exact_parameters_empty_envelope(self):
        self.assertEqual(
            selected_start_payload("display-enrollment", "generation-1", "native-display-start-v1"),
            b'{"enrollment_id":"display-enrollment","generation":"generation-1",'
            b'"operation_id":"native-display-start-v1","parameters":{},"schema":1}',
        )
        with self.assertRaises(NativeDisplayStartupDenied):
            selected_start_payload("display-enrollment", "generation-1", "other-operation")

    def test_startup_grant_cannot_change_role_operation(self):
        payload = selected_start_payload(
            "display-enrollment", "generation-1", "native-display-start-v1",
        )
        context = RootSelectedServiceContext(
            schema=1, context_id="ctx", admission_handle="a" * 43,
            admission_kind="startup", controller_proof_sha256="d" * 64,
            selected_principal_id="principal", selected_profile_id="profile",
            selected_generation="generation-1", selected_namespace_identity="namespace",
            selected_subject_uid=1001, selected_subject_gid=1001,
            service_generation_digest="e" * 64, role="display", action="start",
            enrollment_id="display-enrollment", operation_id="native-display-start-v1",
            operation="process.start", capability="hermes-profile-invoke",
            target="profile:profile", source_closure_sha256="f" * 64,
            sensitivity=Sensitivity.PUBLIC, recipient=None, policy_revision="revision",
            authority_epoch="epoch", issued_monotonic=1.0, expires_monotonic=2.0,
            nonce="1" * 64, signature="2" * 64,
        )
        context_digest = hashlib.sha256(
            __import__("json").dumps(context.to_wire(), sort_keys=True,
                                      separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        ).hexdigest()
        grant = RootSelectedServiceEffectGrant(
            schema=1, grant_id="grant", context_sha256=context_digest,
            admission_handle="a" * 43, operation="process.start",
            capability="hermes-profile-invoke", target="profile:profile",
            request_sha256=hashlib.sha256(payload).hexdigest(), nonce="3" * 64,
            issued_monotonic=1.0, expires_monotonic=2.0, signature="4" * 64,
        )
        valid = RootSelectedStartupGrant(
            schema=1, startup_authorization_handle="a" * 43, role="display",
            service_enrollment_id="display-enrollment", generation="generation-1",
            operation_id="native-display-start-v1",
            selection_payload_sha256=hashlib.sha256(payload).hexdigest(),
            controller_proof_handle="b" * 43, controller_proof_sha256="d" * 64,
            context=context, effect_grant=grant,
            issued_monotonic=1.0, expires_monotonic=2.0,
        )
        self.assertEqual(valid.selection_payload(), payload)
        with self.assertRaises(NativeDisplayStartupDenied):
            RootSelectedStartupGrant(
                schema=1, startup_authorization_handle="a" * 43, role="display",
                service_enrollment_id="display-enrollment", generation="generation-1",
                operation_id="native-desktop-app-start-v1", selection_payload_sha256="b" * 64,
                controller_proof_handle="c" * 43, controller_proof_sha256="d" * 64,
                context=context, effect_grant=grant,
                issued_monotonic=1.0, expires_monotonic=2.0,
            )

    def test_xauthority_is_a_single_familywild_cookie_entry(self):
        cookie = b"c" * 32
        encoded = encode_xauthority(":98.1", cookie)
        self.assertEqual(encoded[:2], b"\xff\xff")
        offset = 2
        fields = []
        for _ in range(4):
            size = int.from_bytes(encoded[offset:offset + 2], "big")
            offset += 2
            fields.append(encoded[offset:offset + size])
            offset += size
        self.assertEqual(offset, len(encoded))
        self.assertEqual(fields, [b"", b"98", b"MIT-MAGIC-COOKIE-1", cookie])

    def test_display_name_and_cookie_are_strictly_bounded(self):
        with self.assertRaises(ValueError):
            encode_xauthority("tcp/attacker:98", b"c" * 32)
        with self.assertRaises(ValueError):
            encode_xauthority(":98", b"short")


class XauthorityPreparationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        self.uid, self.gid = os.getuid(), os.getgid()
        self.selection = SelectedDisplayStartup(
            remote_enrollment_id="remote-enrollment", native_profile_id="hermes-desktop",
            native_generation="native-gen-1", display_profile_id="hermes-display",
            display_generation="display-gen-1", display_name=":98",
            receipt_handle="r" * 43, display_uid=self.uid, display_gid=self.gid,
            xauthority_reader_gid=self.gid)
        self.registry = XauthorityStartupRegistry(
            root=self.root, signer=HMACReceiptSigner(b"s" * 32),
            custody=_Custody(), writer_uid=self.uid)

    def tearDown(self):
        self.temp.cleanup()

    def test_prepare_writes_private_cookie_and_redacts_repr(self):
        prepared = self.registry.prepare(self.selection)
        self.assertEqual(prepared.owner_uid, self.uid)
        self.assertEqual(prepared.owner_gid, self.gid)
        self.assertEqual(prepared.mode, 0o640)
        info = prepared.path.stat()
        self.assertEqual((info.st_dev, info.st_ino), (prepared.device, prepared.inode))
        self.assertEqual(stat.S_IMODE(info.st_mode), 0o640)
        data = prepared.path.read_bytes()
        self.assertEqual(hashlib.sha256(data).hexdigest(), prepared.content_sha256)
        self.assertEqual(data[-32:].__len__(), 32)
        self.assertNotIn(data[-32:].hex(), repr(prepared))
        self.assertNotIn(data[-32:].hex(), repr(self.registry))
        mount = self.registry.mount_binding(prepared)
        self.assertEqual(mount.target_path, XAUTHORITY_MOUNT_TARGET)
        self.assertEqual(mount.environment, {
            "DISPLAY": self.selection.display_name,
            "XAUTHORITY": "/run/hermes-installer/display/Xauthority",
        })
        self.assertTrue(mount.read_only and mount.nofollow and mount.nosuid and mount.nodev)
        self.assertEqual(mount.source_inode, prepared.inode)
        self.assertTrue(self.registry.verify_mount_binding(mount))
        source_lease = self.registry.open_mount_source(mount)
        try:
            self.assertEqual(os.fstat(source_lease.file_fd).st_ino, prepared.inode)
            self.assertEqual(os.pread(source_lease.file_fd, source_lease.size_bytes, 0), data)
            self.assertEqual(source_lease.content_sha256, prepared.content_sha256)
            self.assertNotIn(data[-32:].hex(), repr(source_lease))
            self.assertTrue(self.registry.verify_mount_source(source_lease, mount))
        finally:
            source_lease.close()
        with self.assertRaises(OSError):
            os.fstat(source_lease.file_fd)
        self.assertFalse(self.registry.verify_mount_source(source_lease, mount))
        self.assertFalse(self.registry.verify_mount_binding(
            replace(mount, target_path=Path("/run/hermes-installer/other"))))
        self.registry.discard_prepared(prepared)
        self.assertFalse(prepared.path.exists())

    def test_existing_startup_file_is_never_overwritten_or_deleted(self):
        prepared = self.registry.prepare(self.selection)
        original = prepared.path.read_bytes()
        with self.assertRaises(FileExistsError):
            self.registry.prepare(self.selection)
        self.assertEqual(prepared.path.read_bytes(), original)
        self.registry.discard_prepared(prepared)

    def test_symlinked_profile_directory_is_rejected(self):
        import hashlib as _hashlib
        directory_name = _hashlib.sha256(self.selection.display_profile_id.encode()).hexdigest()[:32]
        outside = self.root / "outside"
        outside.mkdir()
        (self.root / directory_name).symlink_to(outside, target_is_directory=True)
        with self.assertRaises((OSError, NativeDisplayStartupDenied)):
            self.registry.prepare(self.selection)
        self.assertEqual(list(outside.iterdir()), [])

    def test_receipt_seals_and_rechecks_current_typed_custody_lease(self):
        identity = {
            "process_id": "managed-display-process", "profile_id": "hermes-display",
            "generation": "display-gen-1", "uid": self.uid, "gid": self.gid,
            "pid": 2345, "start_ticks": 987654, "executable_device": 1,
            "executable_inode": 234, "executable_sha256": "a" * 64,
            "cgroup_identity": "hermes-display.service", "mount_namespace_inode": 10,
            "network_namespace_inode": 11, "expires_monotonic": time.monotonic() + 300.0,
        }
        self.registry.custody = _Custody(identity)
        prepared = self.registry.prepare(self.selection)
        receipt = self.registry.seal_started_display(prepared)
        self.assertEqual(receipt.pid_start_ticks, identity["start_ticks"])
        self.assertEqual(receipt.xauthority_sha256, prepared.content_sha256)
        self.assertNotIn(prepared.path.read_bytes()[-32:].hex(), repr(receipt))
        catalog_row = SimpleNamespace(
            remote_enrollment_id=self.selection.remote_enrollment_id,
            native_profile_id=self.selection.native_profile_id,
            native_generation=self.selection.native_generation,
            display_server_profile_id=self.selection.display_profile_id,
            display_server_generation=self.selection.display_generation,
            display_name=self.selection.display_name,
            xauthority_receipt_handle=receipt.receipt_handle,
        )
        catalog = SimpleNamespace(selected_native_window=lambda _remote_id: catalog_row)
        from_catalog = self.registry.resolve_catalog_selection(
            catalog, self.selection.remote_enrollment_id)
        from_catalog.close()
        selected = self.registry.resolve_selected(
            receipt.receipt_handle,
            remote_enrollment_id=self.selection.remote_enrollment_id,
            native_profile_id=self.selection.native_profile_id,
            native_generation=self.selection.native_generation,
            display_profile_id=self.selection.display_profile_id,
            display_generation=self.selection.display_generation,
            display_name=self.selection.display_name,
        )
        try:
            self.assertEqual(os.fstat(selected.file_fd).st_ino, prepared.inode)
            self.assertGreaterEqual(selected.pidfd, 0)
        finally:
            selected.close()
        self.assertTrue(self.registry.revoke(receipt.receipt_handle))
        self.assertFalse(prepared.path.exists())
        with self.assertRaises(NativeDisplayStartupDenied):
            self.registry.resolve_selected(
                receipt.receipt_handle,
                remote_enrollment_id=self.selection.remote_enrollment_id,
                native_profile_id=self.selection.native_profile_id,
                native_generation=self.selection.native_generation,
                display_profile_id=self.selection.display_profile_id,
                display_generation=self.selection.display_generation,
                display_name=self.selection.display_name,
            )

    def test_receipt_rejects_process_identity_drift(self):
        identity = {
            "process_id": "managed-display-process", "profile_id": "hermes-display",
            "generation": "display-gen-1", "uid": self.uid, "gid": self.gid,
            "pid": 2345, "start_ticks": 987654, "executable_device": 1,
            "executable_inode": 234, "executable_sha256": "a" * 64,
            "cgroup_identity": "hermes-display.service", "mount_namespace_inode": 10,
            "network_namespace_inode": 11, "expires_monotonic": time.monotonic() + 300.0,
        }
        self.registry.custody = _Custody(identity)
        prepared = self.registry.prepare(self.selection)
        receipt = self.registry.seal_started_display(prepared)
        self.registry.custody.identity = {**identity, "start_ticks": 987655}
        with self.assertRaises(NativeDisplayStartupDenied):
            self.registry.resolve_selected(
                receipt.receipt_handle,
                remote_enrollment_id=self.selection.remote_enrollment_id,
                native_profile_id=self.selection.native_profile_id,
                native_generation=self.selection.native_generation,
                display_profile_id=self.selection.display_profile_id,
                display_generation=self.selection.display_generation,
                display_name=self.selection.display_name,
            )


if __name__ == "__main__":
    unittest.main()
