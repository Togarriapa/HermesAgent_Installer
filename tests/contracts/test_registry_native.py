"""Pinned snapshot discovery, effective merges and safe generation staging."""
import json,unittest
from pathlib import Path
from hermes_installer.registry.native import NativeRegistry
from hermes_installer.registry.source import BundledRegistrySource,PinnedSource
class NativeRegistryTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  base=Path(__file__).parents[2]/"src/hermes_installer/registry/bundle_data"
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
  self.assertGreaterEqual(len(files),1803)  # source declarations, native profiles/skills, adapter inventory, catalog/policy, and crosswalk
  self.assertEqual({path.split("/",1)[0] for path in files if path.split("/",1)[0] in self.registry.root_counts},set(self.registry.root_counts))
  self.assertIn("catalog.yaml",files)
  self.assertIn("installer-registry/crosswalk.json",files)
  ledger=json.loads(files["installer-registry/crosswalk.json"])
  native_map=ledger["native_materialization"]
  self.assertEqual(native_map["destination_root"],"data_root")
  self.assertTrue(native_map["preserve_existing"])
  self.assertTrue(any(entry["target"]=="profiles/ai-developer/SOUL.md" for entry in native_map["files"]))
  self.assertTrue(any(entry["target"]=="profiles/default/skills/agent-skill-vetting/SKILL.md" for entry in native_map["files"]))
  sample=next(data for path,data in files.items() if path.startswith("skills/"))
  self.assertIn(b"host-authorization-applied",sample)
  self.assertIn(b"secrets-resolved",sample)
  self.assertNotIn(b"host-authorization-applied: true",sample)
 def test_profiles_and_skills_compile_to_hermes_discovery_contracts(self):
  files=self.registry.materialize()
  self.assertIn("homes/profiles/ai-developer/SOUL.md",files)
  self.assertIn("homes/profiles/ai-developer/config.yaml",files)
  self.assertIn("homes/profiles/ai-developer/profile.yaml",files)
  self.assertIn(b"Role instructions",files["homes/profiles/ai-developer/SOUL.md"])
  self.assertIn("homes/default/skills/agent-skill-vetting/SKILL.md",files)
  self.assertIn("homes/profiles/ai-developer/skills/ai-application-engineering/SKILL.md",files)
  skill=files["homes/default/skills/agent-skill-vetting/SKILL.md"]
  self.assertTrue(skill.startswith(b"---\nname: agent-skill-vetting\n"))
  self.assertIn(b"Read the complete skill source",skill)
  self.assertIn(b"Complete registry skill declaration",skill)
  self.assertIn(b"procedure:",skill)
  soul=files["homes/profiles/ai-developer/SOUL.md"]
  self.assertIn(b"Complete registry profile declaration",soul)
  self.assertIn(b"instructions:",soul)
 def test_crosswalk_has_an_explicit_binding_or_reason_for_every_declaration(self):
  entries=self.registry.crosswalk()
  self.assertEqual(len(entries),692)
  self.assertEqual(len({(item.kind,item.resource_id,item.version) for item in entries}),692)
  profiles=[item for item in entries if item.kind=="profiles"]
  skills=[item for item in entries if item.kind=="skills"]
  unresolved=[item for item in entries if item.kind not in {"profiles","skills"}]
  self.assertEqual(len(profiles),208)
  self.assertEqual(len(skills),396)
  self.assertTrue(all(item.native_path for item in entries))
  self.assertTrue(all(item.adapter_id for item in profiles+skills))
  self.assertTrue(all(item.adapter_id is None for item in unresolved))
  self.assertTrue(all(item.blockers for item in unresolved))
  self.assertEqual({item.discoverability for item in profiles},{"Hermes native HERMES_HOME selected by the internal orchestrator"})
  self.assertEqual({item.discoverability for item in skills},{"Hermes SKILL.md discovery"})
if __name__=="__main__": unittest.main()
