"""Producer effects for the v264 shared native observation lease."""
import time
import unittest
from types import SimpleNamespace
from unittest import mock

from hermes_installer.remote import manual_stage_inspector as inspector


def _config():
    return SimpleNamespace(
        gateway_uid=996, gateway_gid=981, xpra_uid=18001,
        boot_id="12345678-1234-1234-1234-123456789abc",
        config_sha256="a" * 64, unit_fragment=inspector.DISPLAY_UNIT_PATH,
        unit_sha256="b" * 64, appdir=inspector.Path("/opt/hermes-jarvis-mvp-20261011/Hermes-Desktop.AppDir"),
        appdir_manifest_sha256="c" * 64,
    )


class NativeObservationProducerTests(unittest.TestCase):
    def setUp(self):
        self.config = _config()
        self.old_snapshot = inspector._NATIVE_OBSERVATION_SNAPSHOT
        self.old_running = inspector._NATIVE_OBSERVATION_SCAN_RUNNING
        with inspector._NATIVE_OBSERVATION_CONDITION:
            inspector._NATIVE_OBSERVATION_SNAPSHOT = None
            inspector._NATIVE_OBSERVATION_SCAN_RUNNING = False
            inspector._NATIVE_OBSERVATION_CONDITION.notify_all()

    def tearDown(self):
        with inspector._NATIVE_OBSERVATION_CONDITION:
            inspector._NATIVE_OBSERVATION_SNAPSHOT = self.old_snapshot
            inspector._NATIVE_OBSERVATION_SCAN_RUNNING = self.old_running
            inspector._NATIVE_OBSERVATION_CONDITION.notify_all()

    def _patch_runtime(self, key):
        patches = [
            mock.patch("hermes_installer.remote.manual_stage._read_config_current"),
            mock.patch.object(inspector, "_native_currentness_key", side_effect=lambda *_a, **_kw: key()),
            mock.patch.object(inspector, "_authenticate_gateway_inspector_peer",
                              return_value=(909, "424242")),
            mock.patch.object(inspector, "_pid_start_ticks", return_value="424242"),
            mock.patch.object(inspector, "_pidfd_exited", return_value=False),
            mock.patch.object(inspector.os, "geteuid", return_value=0),
            mock.patch.object(inspector.os, "close"),
        ]
        return patches

    def _observe(self, nonce):
        return inspector.observe_current_native_observation(self.config, nonce=nonce,
            caller_pid=901, caller_uid=self.config.gateway_uid, caller_gid=self.config.gateway_gid)

    def test_expired_or_changed_key_forces_new_fullscan_and_old_lease_is_never_restamped(self):
        key = [(("1" * 64), 456, self.config.boot_id)]
        issued = []
        def fullscan(_config, *, nonce):
            stamp = time.monotonic()
            issued.append(stamp)
            return {"schema": 1, "nonce": nonce, "proof_sha256": f"{len(issued):064x}",
                "boot_id": self.config.boot_id, "issued_monotonic": stamp,
                "expires_monotonic": stamp + 4.8}
        patches = self._patch_runtime(lambda: key[0])
        with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6], \
             mock.patch.object(inspector, "observe_stage", side_effect=fullscan):
            first = self._observe("1" * 64)
            with inspector._NATIVE_OBSERVATION_CONDITION:
                inspector._NATIVE_OBSERVATION_SNAPSHOT["expires_monotonic"] = time.monotonic() - 0.01
            expired_refresh = self._observe("2" * 64)
            self.assertGreater(expired_refresh["issued_monotonic"], first["issued_monotonic"])
            self.assertNotEqual(expired_refresh["native_observation_sha256"],
                                first["native_observation_sha256"])
            key[0] = ("2" * 64, 457, self.config.boot_id)
            changed_refresh = self._observe("3" * 64)
        self.assertEqual(len(issued), 3)
        self.assertGreater(changed_refresh["issued_monotonic"], expired_refresh["issued_monotonic"])

    def test_failed_refresh_and_late_fullscan_leave_no_cached_proof(self):
        key = ("1" * 64, 456, self.config.boot_id)
        fresh = {"schema": 1, "nonce": "1" * 64, "proof_sha256": "e" * 64,
                 "boot_id": self.config.boot_id, "issued_monotonic": time.monotonic(),
                 "expires_monotonic": time.monotonic() + 4.8}
        patches = self._patch_runtime(lambda: key)
        with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6]:
            with mock.patch.object(inspector, "observe_stage", return_value=fresh):
                old = self._observe("1" * 64)
            with inspector._NATIVE_OBSERVATION_CONDITION:
                inspector._NATIVE_OBSERVATION_SNAPSHOT["expires_monotonic"] = time.monotonic() - 0.01
            with mock.patch.object(inspector, "observe_stage", side_effect=RuntimeError("failed")):
                with self.assertRaises(inspector.StageInspectionDenied):
                    self._observe("2" * 64)
            self.assertIsNone(inspector._NATIVE_OBSERVATION_SNAPSHOT)
            late = dict(fresh, nonce="3" * 64, issued_monotonic=time.monotonic(),
                        expires_monotonic=time.monotonic() + 0.01)
            with mock.patch.object(inspector, "observe_stage", return_value=late):
                with self.assertRaises(inspector.StageInspectionDenied):
                    self._observe("3" * 64)
            self.assertIsNone(inspector._NATIVE_OBSERVATION_SNAPSHOT)
        self.assertGreater(old["expires_monotonic"], old["issued_monotonic"])

    def test_watchdog_margin_forces_genuine_refresh_then_shares_fresh_lease(self):
        key = ("1" * 64, 456, self.config.boot_id)
        clock = [2.1]
        starting_snapshot = {
            "key": key, "config_sha256": self.config.config_sha256,
            "boot_id": self.config.boot_id, "native_observation_sha256": "a" * 64,
            "issued_monotonic": 0.0, "expires_monotonic": 5.0,
        }
        with inspector._NATIVE_OBSERVATION_CONDITION:
            inspector._NATIVE_OBSERVATION_SNAPSHOT = dict(starting_snapshot)
        scans = []
        def fullscan(_config, *, nonce):
            issued = clock[0]
            scans.append(nonce)
            return {"schema": 1, "nonce": nonce, "proof_sha256": f"{len(scans):064x}",
                "boot_id": self.config.boot_id, "issued_monotonic": issued,
                "expires_monotonic": issued + 5.0}
        patches = self._patch_runtime(lambda: key)
        with mock.patch.object(inspector.time, "monotonic", side_effect=lambda: clock[0]), \
             patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6], \
             mock.patch.object(inspector, "observe_stage", side_effect=fullscan):
            refreshed = self._observe("1" * 64)
            self.assertEqual(refreshed["issued_monotonic"], 2.1)
            self.assertEqual(refreshed["expires_monotonic"], 7.1)
            clock[0] = 2.2
            joined = self._observe("2" * 64)
        self.assertEqual(len(scans), 1)
        self.assertEqual(joined["issued_monotonic"], refreshed["issued_monotonic"])
        self.assertEqual(joined["expires_monotonic"], refreshed["expires_monotonic"])
        self.assertNotEqual(joined["nonce"], refreshed["nonce"])

    def test_native_server_overload_denies_immediately_at_fixed_worker_bound(self):
        acquired = []
        try:
            for _ in range(inspector.MAX_INSPECTION_CONNECTIONS):
                self.assertTrue(inspector._try_acquire_observation_slot())
                acquired.append(True)
            start = time.monotonic()
            self.assertFalse(inspector._try_acquire_observation_slot())
            self.assertLess(time.monotonic() - start, 0.05)
        finally:
            for _ in acquired:
                inspector._OBSERVATION_SERVER_SLOTS.release()

if __name__ == "__main__":
    unittest.main()
