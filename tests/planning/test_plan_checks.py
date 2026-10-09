"""Negative integrity/coverage tests; these establish planning checks only."""
import importlib.util,json,shutil,tempfile,unittest,subprocess,hashlib,sys
from pathlib import Path
spec=importlib.util.spec_from_file_location('check_plan',Path('scripts/check_plan.py'));checks=importlib.util.module_from_spec(spec);spec.loader.exec_module(checks)
class PlanningChecks(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.base=Path(self.temp.name)/'baseline';shutil.copytree('plans/2026-10-09-v1',self.base)
 def tearDown(self):self.temp.cleanup()
 def change(self,mutate):
  p=self.base/'planning/traceability.json';data=json.loads(p.read_text());mutate(data);p.write_text(json.dumps(data))
 def test_valid_frozen_scope(self):
  self.assertEqual(checks.check_coverage(self.base)['acceptance_criteria'],12);self.assertGreater(checks.check_integrity(self.base),50)
 def test_dropped_source_line_rejected(self):
  self.change(lambda d:d['source_line_mapping'].pop());self.assertRaises(AssertionError,checks.check_coverage,self.base)
 def test_missing_acceptance_links_rejected(self):
  self.change(lambda d:d['acceptance'][0].update(requirement_ids=[]));self.assertRaises(AssertionError,checks.check_coverage,self.base)
 def test_task_dependency_cycle_rejected(self):
  self.change(lambda d:d['tasks'][0]['depends_on'].append(d['tasks'][0]['id']));self.assertRaises(AssertionError,checks.check_coverage,self.base)
 def test_changed_or_extra_baseline_file_rejected(self):
  (self.base/'original-prompt.md').write_text('changed');self.assertRaises(AssertionError,checks.check_integrity,self.base)
 def test_removed_baseline_file_rejected(self):
  (self.base/'planning/model-roles.json').unlink();self.assertRaises(AssertionError,checks.check_integrity,self.base)
 def test_extra_baseline_file_rejected(self):
  (self.base/'unexpected-file').write_text('extra');self.assertRaises(AssertionError,checks.check_integrity,self.base)
 def test_rewriting_hashes_and_contents_does_not_bypass_tag(self):
  temp=Path(self.temp.name)
  def git(*args):subprocess.run(['git',*args],cwd=temp,check=True,capture_output=True)
  git('init');git('add','baseline');git('-c','user.name=Planning Check','-c','user.email=planning-check@example.invalid','commit','-m','Baseline fixture');git('tag','immutable-test')
  target=self.base/'BASELINE.md';target.write_text(target.read_text()+'changed')
  hp=self.base/'hashes.json';manifest=json.loads(hp.read_text());manifest['files']['BASELINE.md']=hashlib.sha256(target.read_bytes()).hexdigest();hp.write_text(json.dumps(manifest))
  checks.check_integrity(self.base)
  result=subprocess.run([sys.executable,str(Path('scripts/check_plan.py').resolve()),'--baseline','baseline','--tag','immutable-test'],cwd=temp,capture_output=True,text=True)
  self.assertNotEqual(result.returncode,0)
 def test_dropped_direct_user_addition_rejected(self):
  self.change(lambda d:d['additional_sources'].clear());self.assertRaises(AssertionError,checks.check_coverage,self.base)
 def test_missing_remote_acceptance_rejected(self):
  self.change(lambda d:d['additional_acceptance'].pop());self.assertRaises(AssertionError,checks.check_coverage,self.base)
if __name__=='__main__':unittest.main()
