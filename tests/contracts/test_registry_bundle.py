"""The installed source snapshot remains complete and usable offline."""
import json
import unittest
from pathlib import Path
from hermes_installer.registry.source import BundledRegistrySource, PinnedSource, RegistrySourceError

class VendoredRegistryTests(unittest.TestCase):
    def setUp(self):
        root=Path(__file__).resolve().parents[2]
        pin=json.loads((root/"resources/upstream/hermes-agent-resources.pin.json").read_text())
        self.pin=PinnedSource.from_mapping(pin)
        self.archive=(root/"resources/upstream/hermes-agent-resources-2.3.1.tar.gz").read_bytes()
    def test_complete_snapshot_is_verified_without_network(self):
        source=BundledRegistrySource(self.pin).load(self.archive)
        self.assertEqual(source.revision,"113f42d33be9e0c8f0f47f5ca998e687323dec83")
        self.assertEqual(len(source.files),739)
        self.assertEqual(sum(path.startswith("profiles/") for path in source.files),208)
        self.assertEqual(sum(path.startswith("skills/") for path in source.files),396)
        self.assertIn("catalog.yaml",source.files)
        self.assertIn("QUALITY_POLICY.yaml",source.files)
        self.assertIn("SPEC.md",source.files)
        self.assertNotIn(".git/config",source.files)
        self.assertEqual(source.content_digest and len(source.content_digest),64)
    def test_modified_or_truncated_archive_fails_before_materialization(self):
        loader=BundledRegistrySource(self.pin)
        with self.assertRaises(RegistrySourceError): loader.load(self.archive[:-1])
        corrupt=bytearray(self.archive); corrupt[-10]^=1
        with self.assertRaises(RegistrySourceError): loader.load(bytes(corrupt))

if __name__=="__main__": unittest.main()
