from __future__ import annotations

import hashlib
import unittest

from hermes_installer.authority.application_runtime_relocation import (
    BUILD_INTERPRETER,
    SOURCE_CONSOLE_SCRIPTS,
    RuntimeRelocationError,
    normalize_console_script_bytes,
    normalize_selected_python_entrypoints,
    normalize_selected_pyvenv_config,
)
from hermes_installer.authority import application_environment_builder as builder


class ApplicationRuntimeRelocationTests(unittest.TestCase):
    final = "/var/lib/hermes-installer/runtime/generation-1/environment/bin/python3.14"

    def test_builder_and_root_relocator_share_exact_reviewed_console_scripts(self):
        self.assertEqual(
            SOURCE_CONSOLE_SCRIPTS,
            {application_id: profile[3] for application_id, profile in builder.PYTHON_APPS.items()},
        )

    @staticmethod
    def _wrapper(module: str, function: str) -> bytes:
        return (
            f"#!{BUILD_INTERPRETER}\n"
            "# -*- coding: utf-8 -*-\n"
            "import sys\n"
            f"from {module} import {function}\n"
            "if __name__ == '__main__':\n"
            "    if sys.argv[0].endswith('-script.pyw'):\n"
            "        sys.argv[0] = sys.argv[0][:-11]\n"
            "    elif sys.argv[0].endswith('.exe'):\n"
            "        sys.argv[0] = sys.argv[0][:-4]\n"
            f"    sys.exit({function}())\n"
        ).encode("utf-8")

    def test_normalizes_only_exact_source_owned_graphify_wrappers(self):
        originals = {
            "environment/bin/graphify": (self._wrapper("graphify.__main__", "main"), 0o755),
            "environment/bin/graphify-mcp": (self._wrapper("graphify.serve", "_main"), 0o755),
        }
        normalized, rows = normalize_selected_python_entrypoints(
            "graphify", originals, final_interpreter=self.final)
        self.assertEqual(set(normalized), set(originals))
        self.assertEqual(len(rows), 2)
        for name, (source, mode) in originals.items():
            result, result_mode = normalized[name]
            self.assertEqual(result_mode, mode)
            self.assertEqual(result, source.replace(
                ("#!" + BUILD_INTERPRETER).encode(), ("#!" + self.final).encode(), 1))
        self.assertEqual(rows[0].original_sha256,
                         hashlib.sha256(originals[rows[0].path][0]).hexdigest())
        self.assertEqual(rows[0].normalized_sha256,
                         hashlib.sha256(normalized[rows[0].path][0]).hexdigest())
        self.assertEqual(rows[0].size_bytes, len(normalized[rows[0].path][0]))

    def test_browser_use_uses_only_its_five_exact_source_entrypoints(self):
        functions = {
            "browser-use": "main", "browseruse": "main", "bu": "main",
            "browser": "main", "browser-use-tui": "browser_use_tui_main",
        }
        items = {
            f"environment/bin/{name}": (self._wrapper("browser_use.cli", function), 0o755)
            for name, function in functions.items()
        }
        _, rows = normalize_selected_python_entrypoints(
            "browser-use", items, final_interpreter=self.final)
        self.assertEqual(len(rows), 5)

    def test_scrapegraph_has_no_invented_cli_and_returns_empty_receipt_rows(self):
        result, rows = normalize_selected_python_entrypoints(
            "scrapegraph-ai", {}, final_interpreter=self.final)
        self.assertEqual(result, {})
        self.assertEqual(rows, ())

    def test_rejects_ambient_temporary_wrong_final_or_unreviewed_shebang(self):
        good = self._wrapper("graphify.__main__", "main")
        bad_shebang = good.replace(BUILD_INTERPRETER.encode(), b"/usr/bin/env python3", 1)
        for body, final in ((bad_shebang, self.final), (good, "/usr/bin/python3")):
            with self.subTest(final=final):
                with self.assertRaises(RuntimeRelocationError):
                    normalize_console_script_bytes(
                        "graphify", "environment/bin/graphify", body,
                        final_interpreter=final, mode=0o755)

    def test_rejects_wrong_source_callable_or_extra_code(self):
        wrong_callable = self._wrapper("attacker", "main")
        extra_code = self._wrapper("graphify.__main__", "main") + b"import os\n"
        for body in (wrong_callable, extra_code):
            with self.subTest(body=body[-20:]):
                with self.assertRaises(RuntimeRelocationError):
                    normalize_console_script_bytes(
                        "graphify", "environment/bin/graphify", body,
                        final_interpreter=self.final, mode=0o755)

    def test_rejects_extra_missing_wrongly_named_and_writable_members(self):
        one = self._wrapper("graphify.__main__", "main")
        with self.assertRaises(RuntimeRelocationError):
            normalize_selected_python_entrypoints("graphify", {
                "environment/bin/graphify": (one, 0o755),
                "environment/bin/extra": (one, 0o755),
            }, final_interpreter=self.final)
        with self.assertRaises(RuntimeRelocationError):
            normalize_selected_python_entrypoints("graphify", {
                "environment/bin/graphify": (one, 0o777),
                "environment/bin/graphify-mcp": (
                    self._wrapper("graphify.serve", "_main"), 0o755),
            }, final_interpreter=self.final)

    def test_rejects_long_shebang_and_noncanonical_member(self):
        body = self._wrapper("graphify.__main__", "main")
        with self.assertRaises(RuntimeRelocationError):
            normalize_console_script_bytes(
                "graphify", "environment/bin/graphify", body,
                final_interpreter="/" + ("x" * 120) + "/environment/bin/python3.14",
                mode=0o755)
        with self.assertRaises(RuntimeRelocationError):
            normalize_console_script_bytes(
                "graphify", "environment/bin/../graphify", body,
                    final_interpreter=self.final, mode=0o755)

    def test_actual_uv_0123_pyvenv_template_changes_only_held_base_home(self):
        source_home = "/run/hermes-installer/build/python-runtime/bin"
        final_home = "/var/lib/hermes-installer/runtime/generation-1/python-runtime/bin"
        original = (
            f"home = {source_home}\nimplementation = CPython\nuv = 0.12.3\n"
            "version_info = 3.14.7\ninclude-system-site-packages = false\n"
        ).encode("ascii")
        normalized, row = normalize_selected_pyvenv_config(
            original, expected_base_bin=source_home, final_base_bin=final_home,
            python_version="3.14.7")
        self.assertEqual(normalized, original.replace(source_home.encode(), final_home.encode(), 1))
        self.assertTrue(original.endswith(b"include-system-site-packages = false\n"))
        self.assertEqual(row.normalized_sha256, hashlib.sha256(normalized).hexdigest())

    def test_pyvenv_template_rejects_extra_keys_wrong_uv_and_wrong_home(self):
        original = (
            b"home = /run/hermes-installer/build/python-runtime/bin\n"
            b"implementation = CPython\nuv = 0.12.3\nversion_info = 3.14.7\n"
            b"include-system-site-packages = false\n"
        )
        args = dict(expected_base_bin="/run/hermes-installer/build/python-runtime/bin",
                    final_base_bin="/var/lib/hermes-installer/runtime/generation-1/python-runtime/bin",
                    python_version="3.14.7")
        for changed in (original + b"system-site-packages = true\n",
                        original.replace(b"uv = 0.12.3", b"uv = 0.13.0"),
                        original.replace(b"home = /run", b"home = /other")):
            with self.subTest(changed=changed[-32:]), self.assertRaises(RuntimeRelocationError):
                normalize_selected_pyvenv_config(changed, **args)


if __name__ == "__main__":
    unittest.main()
