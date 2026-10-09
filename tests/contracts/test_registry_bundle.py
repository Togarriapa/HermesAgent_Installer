"""The installed source snapshot remains complete and usable offline."""
import json
import unittest
from pathlib import Path
from hermes_installer.registry.source import BundledRegistrySource, PinnedSource, RegistrySourceError, load_bundled_source

class VendoredRegistryTests(unittest.TestCase):
    def setUp(self):
        root=Path(__file__).resolve().parents[2]
        bundle=root/"src/hermes_installer/registry/bundle_data"
        pin=json.loads((bundle/"hermes-agent-resources.pin.json").read_text())
        self.pin=PinnedSource.from_mapping(pin)
        self.archive=(bundle/"hermes-agent-resources-2.3.1.tar.gz").read_bytes()
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
        profile = source.files["profiles/3d-model-designer.yaml"].splitlines()
        self.assertTrue(any(line.strip() == b"kind: Profile" for line in profile))
        self.assertTrue(any(line.strip() == b"name: 3d-model-designer" for line in profile))
    def test_modified_or_truncated_archive_fails_before_materialization(self):
        loader=BundledRegistrySource(self.pin)
        with self.assertRaises(RegistrySourceError): loader.load(self.archive[:-1])
        corrupt=bytearray(self.archive); corrupt[-10]^=1
        with self.assertRaises(RegistrySourceError): loader.load(bytes(corrupt))
    def test_packaged_loader_uses_the_installed_offline_bundle(self):
        source=load_bundled_source()
        self.assertEqual(source.revision,self.pin.commit)
        self.assertEqual(len(source.content_digest),64)

if __name__=="__main__": unittest.main()
