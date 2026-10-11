"""Verify temporary fresh identity descriptors close on stale-receipt denial."""
from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from hermes_installer.authority.native_worker_recipes import (
    NativeWorkerRecipeUnavailable,
    RootPreparedServiceIdentityReceipt,
    verify_prepared_service_identity,
)


class NativeWorkerIdentityCleanupTests(unittest.TestCase):
    def test_mismatched_identity_closes_all_fresh_observation_fds(self) -> None:
        with tempfile.NamedTemporaryFile() as file:
            descriptors = tuple(os.open(file.name, os.O_RDONLY) for _ in range(3))
        seal = object()
        current = RootPreparedServiceIdentityReceipt(
            service_user="hermes-agent-native", service_uid=41001, service_gid=41001,
            identity_marker_sha256="a" * 64, profile_id="hermes-agent-native-v1",
            generation="prepared-1", home_root_id="home", work_root_id="work",
            data_root_id="data", home_root=Path("/home"), work_root=Path("/work"),
            data_root=Path("/data"), roots_device_inode=((1, 1), (1, 2), (1, 3)),
            receipt_handle="current-receipt", home_root_fd=descriptors[0],
            work_root_fd=descriptors[1], data_root_fd=descriptors[2],
            issued_monotonic=1.0, expires_monotonic=9999999999.0,
            _marker_device_inode=(1, 4), _issuer=seal,
        )
        stale = RootPreparedServiceIdentityReceipt(
            service_user="hermes-agent-native", service_uid=41001, service_gid=41001,
            identity_marker_sha256="a" * 64, profile_id="hermes-agent-native-v1",
            generation="prepared-1", home_root_id="home", work_root_id="work",
            data_root_id="data", home_root=Path("/home"), work_root=Path("/work"),
            data_root=Path("/data"), roots_device_inode=((9, 1), (9, 2), (9, 3)),
            receipt_handle="stale-receipt", home_root_fd=-1, work_root_fd=-1,
            data_root_fd=-1, issued_monotonic=1.0, expires_monotonic=9999999999.0,
            _marker_device_inode=(9, 4), _issuer=seal,
        )
        binding = SimpleNamespace(_session=SimpleNamespace(_seal=seal))
        with patch("hermes_installer.authority.native_worker_recipes.observe_prepared_service_identity",
                   return_value=current):
            with self.assertRaises(NativeWorkerRecipeUnavailable):
                verify_prepared_service_identity(binding, stale)
        for descriptor in descriptors:
            with self.assertRaises(OSError):
                os.fstat(descriptor)


if __name__ == "__main__":
    unittest.main()
