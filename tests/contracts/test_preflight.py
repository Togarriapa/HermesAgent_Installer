from __future__ import annotations

import fcntl
import multiprocessing
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from hermes_installer.preflight import _disk_facts, _held_package_locks, _ports, _coral_facts, _resolve_dns, _linux_release_supported, _runtime_platform_ready, _matching_service_units


def _hold_file_lock(path: str, ready, release) -> None:
    with open(path, "r+") as stream:
        fcntl.lockf(stream.fileno(), fcntl.LOCK_EX)
        ready.set()
        release.wait(5)
        fcntl.lockf(stream.fileno(), fcntl.LOCK_UN)


class PreflightContractTests(unittest.TestCase):
    def test_existing_apt_lock_file_is_not_mistaken_for_an_active_lock(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "dpkg.lock"
            path.touch()
            self.assertEqual(_held_package_locks((path,)), ())
            ready, release = multiprocessing.Event(), multiprocessing.Event()
            holder = multiprocessing.Process(target=_hold_file_lock, args=(str(path), ready, release))
            holder.start()
            try:
                self.assertTrue(ready.wait(2))
                self.assertEqual(_held_package_locks((path,)), (str(path),))
            finally:
                release.set()
                holder.join(2)
                if holder.is_alive():
                    holder.terminate()
                    holder.join()

    def test_disk_probe_reports_mount_filesystem_capacity_and_transport(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            mountpoint = Path(temporary) / "data"
            mountpoint.mkdir()
            mountinfo = Path(temporary) / "mountinfo"
            mountinfo.write_text(f"36 25 0:32 / {mountpoint.resolve()} rw,relatime - ext4 /dev/mmcblk0p2 rw\n")
            devices = {"blockdevices": [{"path": "/dev/mmcblk0", "type": "disk", "tran": "mmc", "children": [{"path": "/dev/mmcblk0p2", "type": "part", "mountpoints": [str(mountpoint)], "fstype": "ext4"}]}]}
            facts = _disk_facts(False, mountinfo, (mountpoint,), devices)
            self.assertEqual(len(facts), 1)
            self.assertEqual(facts[0].filesystem, "ext4")
            self.assertEqual(facts[0].connection_type, "mmc")
            self.assertGreater(facts[0].total_bytes, 0)
            self.assertGreaterEqual(facts[0].available_bytes, 0)

    def test_coral_probe_matches_exact_supported_identifiers_only(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            sysroot = Path(temporary)
            usb = sysroot / "bus/usb/devices"
            for name, vendor, product in (("valid", "18d1", "9302"), ("wrong-google-device", "18d1", "4ee7")):
                item = usb / name
                item.mkdir(parents=True)
                (item / "idVendor").write_text(vendor)
                (item / "idProduct").write_text(product)
            pci = sysroot / "bus/pci/devices/0000:01:00.0"
            pci.mkdir(parents=True)
            (pci / "vendor").write_text("0x1ac1")
            (pci / "device").write_text("0x089a")
            facts = _coral_facts(sysroot)
            self.assertEqual({fact.bus for fact in facts}, {"usb", "pci"})
            self.assertEqual(len(facts), 2)

    def test_port_probe_counts_only_bound_listeners(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            net = Path(temporary) / "net"
            net.mkdir()
            (net / "tcp").write_text("sl local_address rem_address st\n0: 0100007F:1F90 00000000:0000 0A\n1: 0100007F:C350 0100007F:1F90 01\n")
            (net / "tcp6").write_text("sl local_address rem_address st\n")
            (net / "udp").write_text("sl local_address rem_address st\n0: 0100007F:0035 00000000:0000 07\n1: 0100007F:C351 0100007F:0035 01\n")
            (net / "udp6").write_text("sl local_address rem_address st\n")
            self.assertEqual(_ports(Path(temporary)), (53, 8080))

    def test_dns_probe_has_a_hard_deadline(self) -> None:
        import time
        from unittest.mock import patch

        with patch("hermes_installer.preflight.socket.getaddrinfo", side_effect=lambda *args, **kwargs: time.sleep(0.2)):
            start = time.monotonic()
            self.assertIsNone(_resolve_dns(timeout=0.02))
            self.assertLess(time.monotonic() - start, 0.1)

    def test_support_matrix_checks_distribution_version_glibc_systemd_and_fhs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            os_release = Path(temporary) / "os-release"
            os_release.write_text('ID=debian\nVERSION_ID="13"\n')
            self.assertTrue(_linux_release_supported(os_release))
            os_release.write_text('ID=debian\nVERSION_ID="10"\n')
            self.assertFalse(_linux_release_supported(os_release))
            fhs = tuple(Path(temporary) / name for name in ("etc", "usr", "var"))
            for path in fhs:
                path.mkdir()
            self.assertTrue(_runtime_platform_ready(("glibc", "2.36"), True, fhs))
            self.assertFalse(_runtime_platform_ready(("glibc", "2.17"), True, fhs))
            self.assertFalse(_runtime_platform_ready(("glibc", "2.36"), False, fhs))

    def test_service_inventory_matches_only_relevant_existing_units(self) -> None:
        output = "home-assistant@homeassistant.service loaded active running Home Assistant\nollama.service loaded inactive dead Model server\nssh.service loaded active running Secure shell\n"
        self.assertEqual(_matching_service_units(output), ("home-assistant@homeassistant.service", "ollama.service"))


if __name__ == "__main__":
    unittest.main()
