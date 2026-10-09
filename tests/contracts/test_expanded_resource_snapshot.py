from __future__ import annotations

import json
import stat
import unittest
from pathlib import Path
from unittest.mock import patch

from hermes_installer.registry.source import BundledRegistrySource, PinnedSource


ROOT = Path(__file__).resolve().parents[2]
ARCHIVE = ROOT / "resources/upstream/hermes-agent-resources-2.3.1.tar.gz"
PIN = ROOT / "resources/upstream/hermes-agent-resources.pin.json"
SNAPSHOT = ROOT / "resources/vendor/hermes-agent-resources-2.3.1"


class ExpandedResourceSnapshotTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.pin = PinnedSource.from_mapping(json.loads(PIN.read_text(encoding="utf-8")))
        cls.verified = BundledRegistrySource(cls.pin).load(ARCHIVE.read_bytes())

    def test_expanded_snapshot_matches_every_pinned_file_byte_and_mode(self) -> None:
        actual = {
            path.relative_to(SNAPSHOT).as_posix(): (
                path.read_bytes(), stat.S_IMODE(path.stat().st_mode)
            )
            for path in SNAPSHOT.rglob("*") if path.is_file()
        }
        self.assertEqual(len(self.verified.files), self.pin.snapshot_file_count)
        self.assertEqual(set(actual), set(self.verified.files))
        for name, content in self.verified.files.items():
            with self.subTest(path=name):
                self.assertEqual(actual[name][0], content)
                self.assertEqual(actual[name][1], self.verified.file_modes[name])

    def test_bundle_load_is_offline_when_upstream_transport_is_unavailable(self) -> None:
        with patch("urllib.request.urlopen", side_effect=AssertionError("network access")):
            verified = BundledRegistrySource(self.pin).load(ARCHIVE.read_bytes())
        self.assertEqual(verified.revision, self.pin.commit)
        self.assertEqual(verified.source_tree, self.pin.git_tree)
        self.assertEqual(len(verified.files), 739)


if __name__ == "__main__":
    unittest.main()
