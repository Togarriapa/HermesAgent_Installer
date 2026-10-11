"""Current-scope coverage failures; execute only on the authorized Pi."""
import importlib.util
import json
import shutil
import tempfile
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location('check_plan', Path('scripts/check_plan.py'))
checks = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checks)


class PlanningChecks(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        (self.base / 'requirements').mkdir()
        shutil.copy('requirements/current-scope.json', self.base / 'requirements/current-scope.json')
        shutil.copy('CURRENT-PLAN.md', self.base / 'CURRENT-PLAN.md')
        shutil.copytree('openspec/changes/jarvis-core-platform', self.base / 'openspec/changes/jarvis-core-platform')

    def tearDown(self):
        self.temp.cleanup()

    def change(self, mutate):
        path = self.base / 'requirements/current-scope.json'
        data = json.loads(path.read_text())
        mutate(data)
        path.write_text(json.dumps(data))

    def rejected(self):
        self.assertRaises(checks.PlanError, checks.check_coverage, self.base)

    def test_current_scope_preserves_inventory_without_historical_head_files(self):
        result = checks.check_coverage(self.base)
        self.assertEqual(result['inventory_records'], 62)
        self.assertEqual(result['acceptance_criteria'], 18)
        self.assertEqual(result['requirements'], 219)
        self.assertEqual(result['tasks'], 8)
        self.assertEqual(result['current_artifacts'], 4)
        self.assertFalse((self.base / 'plans').exists())

    def test_dropped_original_functional_requirement_denied(self):
        self.change(lambda data: data['requirements'].__setitem__(slice(None), [r for r in data['requirements'] if r['id'] != 'R0001']))
        self.rejected()

    def test_core_security_lease_obligation_omission_denied(self):
        self.change(lambda data: data['requirements'].__setitem__(slice(None), [r for r in data['requirements'] if r['id'] != 'CORE-LEASE']))
        self.rejected()

    def test_duplicate_requirement_id_denied(self):
        self.change(lambda data: data['requirements'].append(dict(data['requirements'][0])))
        self.rejected()

    def test_component_replaced_with_equal_count_denied(self):
        self.change(lambda data: data['components'][0].update(id='invented-component'))
        self.rejected()

    def test_requested_alias_omission_denied(self):
        self.change(lambda data: next(c for c in data['components'] if c['id'] == 'playwright-mcp').update(aliases=['playwright']))
        self.rejected()

    def test_missing_access_acceptance_denied(self):
        self.change(lambda data: data['acceptance'].__setitem__(slice(None), [a for a in data['acceptance'] if a['id'] != 'AC13']))
        self.rejected()

    def test_missing_resources_policy_or_host_acceptance_denied(self):
        for missing in ('AC16', 'AC17', 'AC18'):
            with self.subTest(missing=missing):
                path = self.base / 'requirements/current-scope.json'
                original = path.read_text()
                self.change(lambda data: data['acceptance'].__setitem__(slice(None), [a for a in data['acceptance'] if a['id'] != missing]))
                self.rejected()
                path.write_text(original)

    def test_current_host_and_policy_obligations_omission_denied(self):
        for missing in ('CORE-HOST', 'CORE-POLICY'):
            with self.subTest(missing=missing):
                path = self.base / 'requirements/current-scope.json'
                original = path.read_text()
                self.change(lambda data: data['requirements'].__setitem__(slice(None), [r for r in data['requirements'] if r['id'] != missing]))
                self.rejected()
                path.write_text(original)

    def test_acceptance_false_completion_denied(self):
        self.change(lambda data: data['acceptance'][0].update(status='PASS'))
        self.rejected()

    def test_account_component_false_readiness_denied(self):
        self.change(lambda data: data['components'][0].update(acceptance='READY'))
        self.rejected()

    def test_broken_security_requirement_task_link_denied(self):
        self.change(lambda data: data['requirements'][0].update(task_id='unknown-task'))
        self.rejected()

    def test_empty_effect_verification_denied(self):
        self.change(lambda data: data['requirements'][0].update(verification_method=''))
        self.rejected()

    def test_task_cycle_denied(self):
        self.change(lambda data: data['tasks'][0]['depends_on'].append(data['tasks'][0]['id']))
        self.rejected()

    def test_missing_spec_requirement_denied(self):
        path = self.base / 'openspec/changes/jarvis-core-platform/specs/jarvis-core-platform/spec.md'
        path.write_text(path.read_text().replace('Requirement: R0001', 'Requirement: removed-R0001'))
        self.rejected()

    def test_missing_task_checkbox_denied(self):
        path = self.base / 'openspec/changes/jarvis-core-platform/tasks.md'
        path.write_text(path.read_text().replace('- [ ] BD-T266.1', '- Historical BD-T266.1'))
        self.rejected()

    def test_second_active_change_denied(self):
        (self.base / 'openspec/changes/obsolete-product').mkdir()
        self.rejected()

    def test_missing_design_denied(self):
        (self.base / 'openspec/changes/jarvis-core-platform/design.md').unlink()
        self.rejected()

    def test_unknown_component_requirement_denied(self):
        self.change(lambda data: data['components'][0].update(requirement_ids=['invented-requirement']))
        self.rejected()


if __name__ == '__main__':
    unittest.main()
