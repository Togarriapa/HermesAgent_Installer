from __future__ import annotations

import hashlib
import os
import stat
import tempfile
import unittest
from pathlib import Path

from hermes_installer.authority.native_display_startup import (
    NativeDisplayStartupDenied,
    SelectedDisplayStartup,
    XauthorityStartupRegistry,
    encode_xauthority,
)
from hermes_installer.authority.remote_origin import HMACReceiptSigner


class _Custody:
    def resolve_active_process_handle(self, _profile_id, _generation):
        raise AssertionError("this preparation-only test must not inspect a process")


class XauthorityEncodingTests(unittest.TestCase):
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
            receipt_handle="r" * 43, display_uid=self.uid, display_gid=self.gid)
        self.registry = XauthorityStartupRegistry(
            root=self.root, signer=HMACReceiptSigner(b"s" * 32),
            custody=_Custody(), writer_uid=self.uid)

    def tearDown(self):
        self.temp.cleanup()

    def test_prepare_writes_private_cookie_and_redacts_repr(self):
        prepared = self.registry.prepare(self.selection)
        self.assertEqual(prepared.owner_uid, self.uid)
        self.assertEqual(prepared.owner_gid, self.gid)
        self.assertEqual(prepared.mode, 0o440)
        info = prepared.path.stat()
        self.assertEqual((info.st_dev, info.st_ino), (prepared.device, prepared.inode))
        self.assertEqual(stat.S_IMODE(info.st_mode), 0o440)
        data = prepared.path.read_bytes()
        self.assertEqual(hashlib.sha256(data).hexdigest(), prepared.content_sha256)
        self.assertEqual(data[-32:].__len__(), 32)
        self.assertNotIn(data[-32:].hex(), repr(prepared))
        self.assertNotIn(data[-32:].hex(), repr(self.registry))
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


if __name__ == "__main__":
    unittest.main()
