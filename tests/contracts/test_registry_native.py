"""Pinned snapshot discovery, effective merges and safe generation staging."""
import json,unittest
from pathlib import Path
from hermes_installer.registry.native import NativeRegistry
from hermes_installer.registry.source import BundledRegistrySource,PinnedSource
class NativeRegistryTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  base=Path("resources/upstream")
  pin=PinnedSource.from_mapping(json.loads((base/"hermes-agent-resources.pin.json").read_text()))
  source=BundledRegistrySource(pin).load((base/"hermes-agent-resources-2.3.1.tar.gz").read_bytes())
  cls.registry=NativeRegistry.from_verified_source(source)
 def test_discovers_all_pinned_manifests_across_eight_roots(self):
  result=self.registry.discover_all()
  self.assertEqual(sum(self.registry.root_counts.values()),692)
  self.assertEqual(len(result.resources),692)
  self.assertEqual(set(self.registry.root_counts),{"profiles","skills","plugins","mcps","bundles","channels","crons","webhooks"})
 def test_bundle_imports_enter_typed_dependency_closure(self):
  result=self.registry.discover(["bundles/traditional-remedies-research-team"])
  bundle=next(item for item in result.resources if item.resource.kind.value=="bundles")
  self.assertIn("profiles/traditional-remedies-researcher"," ".join(bundle.dependencies))
  self.assertGreater(len(result.resources),1)
 def test_quality_overlay_applies_to_effective_body_not_flat_capability_authority(self):
  result=self.registry.discover_all()
  matches=[item for item in result.resources if item.applied_overlays]
  self.assertTrue(matches)
  structured=[item for item in result.resources if isinstance((item.effective_spec or {}).get("capabilities"),dict)]
  self.assertTrue(structured)
  self.assertTrue(all(not item.resource.capabilities for item in structured))
 def test_update_crons_use_installer_bundle_only(self):
  rendered=self.registry.materialize()
  for name in ("resource-sync","daily-resource-reconcile"):
   import yaml
   doc=yaml.safe_load(rendered[f"crons/{name}.yaml"])
   action=doc["spec"]["action"]
   self.assertEqual(action["type"],"installer-resource-candidate-assessment")
   self.assertEqual(action["source"]["kind"],"installer-bundle")
   self.assertEqual(action["source"]["revision"],self.registry.source.revision)
   self.assertNotIn("repository",action)
   self.assertNotIn("ref",action)
 def test_materialization_applies_policy_without_claiming_authority(self):
  files=self.registry.materialize()
  self.assertEqual(len(files),692)
  self.assertTrue(all(path.split("/",1)[0] in self.registry.root_counts for path in files))
  sample=next(data for path,data in files.items() if path.startswith("skills/"))
  self.assertIn(b"host-authorization-applied",sample)
  self.assertIn(b"secrets-resolved",sample)
  self.assertNotIn(b"host-authorization-applied: true",sample)
if __name__=="__main__": unittest.main()
