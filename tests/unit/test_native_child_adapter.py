"""Effect-oriented checks for the fixed native child capability closures."""
from __future__ import annotations

import unittest

from hermes_installer.remote.core_native_observer import _native_delegate_execution_gate
from hermes_installer.remote.native_child_adapter import (
    NativeChildMode,
    apply_native_child_tool_closure,
)


def _definition(name: str) -> dict:
    return {"type": "function", "function": {"name": name, "parameters": {"type": "object"}}}


class NativeChildAdapterTests(unittest.TestCase):
    def test_planner_has_no_callable_tools_even_when_builder_added_escape_tools(self):
        names = {
            "web_search", "web_extract", "todo_list", "skills_list", "skill_view",
            "delegate_task", "terminal", "write_file", "send_email", "mcp__mail__send",
        }
        child = type("Child", (), {})()
        child.tools = [_definition(name) for name in sorted(names)]
        child.valid_tool_names = set(names)

        retained = apply_native_child_tool_closure(child, NativeChildMode.PLANNER)

        self.assertEqual(retained, frozenset())
        self.assertEqual(child.tools, [])
        self.assertEqual(child.valid_tool_names, set())
        self.assertTrue({"delegation", "kanban"}.issubset(child.disabled_toolsets))

    def test_expert_closure_keeps_only_fixed_read_research_tools(self):
        names = {
            "web_search", "web_extract", "todo_list", "skills_list", "skill_view",
            "delegate_task", "terminal", "write_file", "send_email", "mcp__mail__send",
        }
        child = type("Child", (), {})()
        child.tools = [_definition(name) for name in sorted(names)]
        child.valid_tool_names = set(names)

        retained = apply_native_child_tool_closure(child, NativeChildMode.EXPERT_READ_RESEARCH)

        expected = frozenset({"web_search", "web_extract", "skills_list", "skill_view"})
        self.assertEqual(retained, expected)
        self.assertEqual(child.valid_tool_names, set(expected))
        self.assertEqual({item["function"]["name"] for item in child.tools}, set(expected))
        self.assertNotIn("delegate_task", child.valid_tool_names)
        self.assertFalse(any(name.startswith("mcp__") for name in child.valid_tool_names))

    def test_direct_builtin_delegation_is_denied_without_calling_executor(self):
        called = []

        result = _native_delegate_execution_gate(
            tool_name="delegate_task", args={"tasks": [{"goal": "escape"}]},
            next_call=lambda args: called.append(args) or "executed",
        )

        self.assertEqual(called, [])
        self.assertIn("native-delegation-requires-resources-policy", result)

    def test_non_delegation_tool_execution_continues_normally(self):
        args = {"query": "bounded research"}
        called = []

        result = _native_delegate_execution_gate(
            tool_name="web_search", args=args,
            next_call=lambda received: called.append(received) or "ok",
        )

        self.assertEqual(called, [args])
        self.assertEqual(result, "ok")


if __name__ == "__main__":
    unittest.main()
