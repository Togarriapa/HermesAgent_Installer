"""Source-specific structural checks for isolated application lockfiles."""
import unittest
import tempfile
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))

from hermes_installer.components.isolated_locks import lockfile_errors
from apply_browser_use_uv_overlay import PLATFORM, apply_overlay


class IsolatedLockTests(unittest.TestCase):
    def test_browser_use_platform_overlay_extends_existing_uv_table_without_rewriting_it(self):
        source = '[project]\nname = "browser-use"\n\n[tool.uv]\n# keep upstream policy\ndev-dependencies = []\n'
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "pyproject.toml"
            path.write_text(source, encoding="utf-8")
            apply_overlay(path)
            output = path.read_text(encoding="utf-8")
        self.assertEqual(1, output.count("[tool.uv]"))
        self.assertIn("# keep upstream policy", output)
        self.assertIn(f'environments = ["{PLATFORM}"]', output)
        self.assertIn("dev-dependencies = []", output)

    def test_browser_use_overlay_rejects_conflicting_existing_environment(self):
        source = '[tool.uv]\nenvironments = ["sys_platform == \'linux\'"]\n'
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "pyproject.toml"
            path.write_text(source, encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "requires explicit review"):
                apply_overlay(path)
            self.assertEqual(source, path.read_text(encoding="utf-8"))

    def test_uv_lock_requires_resolved_package_identity(self):
        valid = b'version = 1\nrequires-python = ">=3.10"\n\n[[package]]\nname = "graphifyy"\nversion = "0.9.82"\n'
        self.assertEqual((), lockfile_errors("uv.lock", valid))
        self.assertTrue(lockfile_errors("uv.lock", b'version = 1\n'))

    def test_npm_lock_requires_root_and_resolved_entries(self):
        valid = b'{"lockfileVersion":3,"packages":{"":{"name":"app"},"node_modules/x":{"version":"1.0.0"}}}'
        self.assertEqual((), lockfile_errors("package-lock.json", valid))
        self.assertTrue(lockfile_errors("package-lock.json", b'{"lockfileVersion":3}'))

    def test_bun_lock_binds_both_hyperframes_workspaces_and_external_package(self):
        valid = b'{"lockfileVersion":1,"workspaces":{"":{"name":"hyperframes"},"packages/cli":{"name":"@hyperframes/cli"}},"packages":{"react":["react@19.0.0"]}}'
        self.assertEqual((), lockfile_errors("bun.lock", valid))
        self.assertTrue(lockfile_errors("bun.lock", b'{"lockfileVersion":1}'))

    def test_pnpm_lock_requires_resolved_project_sections(self):
        valid = b"lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      react:\n        specifier: ^19.0.0\n        version: 19.0.0\npackages:\n  react@19.0.0: {}\n"
        self.assertEqual((), lockfile_errors("frontend/pnpm-lock.yaml", valid))
        self.assertTrue(lockfile_errors("frontend/pnpm-lock.yaml", b"lockfileVersion: '9.0'\n"))

    def test_poetry_lock_needs_metadata_and_packages(self):
        valid = b'[[package]]\nname = "flask"\nversion = "3.0.0"\n\n[metadata]\nlock-version = "2.0"\n'
        self.assertEqual((), lockfile_errors("backend/poetry.lock", valid))
        self.assertTrue(lockfile_errors("backend/poetry.lock", b'[[package]]\nname = "flask"\n'))


if __name__ == "__main__":
    unittest.main()
