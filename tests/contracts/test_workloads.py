"""Effects and fail-closed behavior for registered component workload recipes."""
import unittest
from decimal import Decimal

from hermes_installer.components.workloads import Workload, WorkloadScheduler


class WorkloadSchedulerTests(unittest.TestCase):
    def setUp(self):
        self.calls = []

        def run(invocation):
            self.calls.append(invocation)
            return {"exit_code": 0, "output": "fixture-complete"}

        self.scheduler = WorkloadScheduler(
            run,
            frozenset({
                "component.browser-use.local-fixture", "network:localhost",
                "component.graphify.read-fixture", "component.graphify.write-private-work",
                "component.graphify.read-private-work",
            }),
            runtime_roots={
                "browser-use": "/owned/browser/bin/python",
                "graphify": "/owned/graphify",
            },
            work_roots={
                "browser-use": "/owned/work/browser",
                "graphify": "/owned/work/graphify",
                "graphify-fixture": "/owned/fixtures/graphify",
            },
            memory_budget_mb=2048,
            max_workers=1,
            metered_budget_usd=Decimal("0"),
        )

    def test_registered_browser_fixture_uses_fixed_python_and_local_sandboxed_recipe(self):
        result = self.scheduler.execute(Workload(
            "browser-fixture", {"fixture_url": "http://127.0.0.1:8765/fixture"}
        ))
        self.assertEqual("fixture-complete", result["output"])
        invocation = self.calls[0]
        self.assertEqual("/owned/browser/bin/python", invocation.executable)
        self.assertEqual("browser-use", invocation.component_id)
        self.assertEqual("localhost", invocation.network)
        self.assertIn("chromium_sandbox=True", invocation.argv[2])
        self.assertEqual(180, invocation.timeout_seconds)
        self.assertEqual(2048, invocation.memory_limit_mb)
        self.assertEqual(Decimal("0"), self.scheduler.metered_spend_usd)

    def test_unregistered_ids_and_caller_supplied_argv_cannot_reach_runner(self):
        with self.assertRaisesRegex(PermissionError, "not in the installer-owned registry"):
            self.scheduler.execute(Workload("arbitrary", {"argv": ["/bin/sh", "-c", "id"]}))
        with self.assertRaises(TypeError):
            Workload("browser-fixture", argv=("/bin/sh", "-c", "id"))
        self.assertEqual([], self.calls)

    def test_fixed_builder_rejects_unsafe_or_extra_parameters_before_effect(self):
        cases = (
            Workload("browser-fixture", {"fixture_url": "https://example.com/"}),
            Workload("browser-fixture", {"fixture_url": "http://127.0.0.1:8765/../../etc/passwd"}),
            Workload("browser-fixture", {"fixture_url": "http://127.0.0.1:8765/fixture", "argv": ["/bin/sh"]}),
            Workload("graphify-code-fixture", {"work_root": "/tmp/untrusted"}),
        )
        for request in cases:
            with self.subTest(request=request), self.assertRaises(ValueError):
                self.scheduler.execute(request)
        self.assertEqual([], self.calls)

    def test_missing_capability_and_empty_grants_have_no_effect(self):
        scheduler = WorkloadScheduler(
            lambda invocation: self.calls.append(invocation), frozenset(),
            runtime_roots={"browser-use": "/owned/python"},
            work_roots={"browser-use": "/owned/work"}, memory_budget_mb=4096,
        )
        with self.assertRaisesRegex(PermissionError, "capability denied"):
            scheduler.execute(Workload("browser-fixture", {"fixture_url": "http://127.0.0.1:9000/"}))
        self.assertEqual([], self.calls)

    def test_graphify_invocations_are_sequenced_and_dependent_query_stops_on_failure(self):
        self.scheduler.execute(Workload("graphify-code-fixture"))
        self.assertEqual(2, len(self.calls))
        self.assertEqual(("extract", "/owned/fixtures/graphify", "--code-only", "--no-cluster", "--out", "/owned/work/graphify"), self.calls[0].argv)
        self.assertEqual("query", self.calls[1].argv[0])

        failed_calls = []
        def fail_first(invocation):
            failed_calls.append(invocation)
            return {"exit_code": 1}
        scheduler = WorkloadScheduler(
            fail_first, self.scheduler.granted,
            runtime_roots={"graphify": "/owned/graphify"},
            work_roots={"graphify": "/owned/work/graphify", "graphify-fixture": "/owned/fixtures/graphify"},
            memory_budget_mb=2048,
        )
        with self.assertRaisesRegex(RuntimeError, "dependent stages were not launched"):
            scheduler.execute(Workload("graphify-code-fixture"))
        self.assertEqual(1, len(failed_calls))


if __name__ == "__main__":
    unittest.main()
