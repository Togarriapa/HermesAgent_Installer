from __future__ import annotations

import hashlib
from pathlib import Path
import unittest

from hermes_installer.authority.application_runtime_preparation import (
    ApplicationRuntimePreparationDenied,
    select_locked_python_wheels,
)


def _wheel_row(name: str, filename: str) -> str:
    digest = hashlib.sha256(filename.encode()).hexdigest()
    return (
        '[[package]]\n'
        f'name = "{name}"\n'
        'version = "1.0.0"\n'
        'source = { registry = "https://pypi.org/simple" }\n'
        f'wheels = [{{ url = "https://files.pythonhosted.org/packages/{filename}", '
        f'hash = "sha256:{digest}", size = 123 }}]\n'
    )


class ApplicationRuntimePreparationTests(unittest.TestCase):
    def test_selects_only_default_transitive_arm64_cp314_wheels(self):
        lock = (
            'version = 1\n'
            '[[package]]\nname = "demo-app"\nversion = "1.0.0"\n'
            'source = { editable = "." }\n'
            'dependencies = [{ name = "shared" }, '
            '{ name = "mac-only", marker = "sys_platform == \'darwin\'" }]\n'
            + _wheel_row("shared", "shared-1.0.0-cp314-cp314-manylinux_2_28_aarch64.whl")
        )
        selected = select_locked_python_wheels(lock.encode(), application_id="graphify")
        self.assertTrue(selected.complete, selected.blockers)
        self.assertEqual([item.package_name for item in selected.wheels], ["shared"])
        self.assertEqual(selected.wheels[0].selected_tag,
                         "cp314-cp314-manylinux_2_28_aarch64")

    def test_sdist_only_and_untrusted_artifact_origin_are_blockers(self):
        lock = (
            'version = 1\n'
            '[[package]]\nname = "demo-app"\nversion = "1.0.0"\n'
            'source = { editable = "." }\n'
            'dependencies = [{ name = "sdist-only" }, { name = "bad-origin" }]\n'
            '[[package]]\nname = "sdist-only"\nversion = "1.0.0"\n'
            'source = { registry = "https://pypi.org/simple" }\nwheels = []\n'
            '[[package]]\nname = "bad-origin"\nversion = "1.0.0"\n'
            'source = { registry = "https://pypi.org/simple" }\n'
            'wheels = [{ url = "https://evil.example/bad-origin-1.0.0-py3-none-any.whl", '
            'hash = "sha256:' + "0" * 64 + '", size = 10 }]\n'
        )
        selected = select_locked_python_wheels(lock.encode(), application_id="scrapegraph-ai")
        self.assertEqual(selected.wheels, ())
        self.assertIn("sdist-only:no-compatible-cp314-aarch64-wheel", selected.blockers)
        self.assertIn("bad-origin:no-compatible-cp314-aarch64-wheel", selected.blockers)

    def test_rejects_wrong_profile_and_malformed_lock(self):
        with self.assertRaises(ApplicationRuntimePreparationDenied):
            select_locked_python_wheels(b"version = 1", application_id="hyperframes")
        with self.assertRaises(ApplicationRuntimePreparationDenied):
            select_locked_python_wheels(b"not = [toml", application_id="graphify")

    def test_real_browser_use_lock_accepts_compatible_stable_abi_wheels(self):
        lock = Path("src/hermes_installer/components/runtime_locks/browser-use/uv.lock").read_bytes()
        selected = select_locked_python_wheels(lock, application_id="browser-use")
        self.assertTrue(selected.complete, selected.blockers)
        by_name = {item.package_name: item for item in selected.wheels}
        self.assertIn("cp311-abi3-manylinux", by_name["cryptography"].selected_tag)
        self.assertIn("cp36-abi3-manylinux", by_name["psutil"].selected_tag)


if __name__ == "__main__":
    unittest.main()
