"""Effect and denial contracts for on-demand component scheduling."""
from decimal import Decimal
import unittest

from hermes_installer.components.workloads import Workload, WorkloadScheduler


class WorkloadSchedulerTests(unittest.TestCase):
    def setUp(self):
        self.calls = []

        def run(argv, environment, **limits):
            self.calls.append((argv, environment, limits))
            return {"exit_code": 0, "output": "fixture-complete"}

        self.scheduler = WorkloadScheduler(
            run,
            frozenset({"fixture.read", "network:localhost"}),
            memory_budget_mb=1024,
            max_workers=1,
            metered_budget_usd=Decimal("0.02"),
            eligible_accounts=frozenset({"local-fixture"}),
        )

    def test_on_demand_invocation_reaches_managed_runner_with_bounded_effects(self):
        work = Workload(
            "browser-fixture",
            ("/owned/browser/bin/python", "-m", "fixture"),
            {"FIXTURE_MODE": "local"},
            frozenset({"fixture.read", "network:localhost"}),
            memory_mb=384,
            timeout_seconds=45,
            network_scope="localhost",
            metered_cost_usd=Decimal("0.01"),
            account_requirement="local-fixture",
            credential_references=("vault://profile/browser",),
        )
        result = self.scheduler.execute(work)
        self.assertEqual("fixture-complete", result["output"])
        self.assertEqual((("/owned/browser/bin/python", "-m", "fixture"), {"FIXTURE_MODE": "local"}), self.calls[0][:2])
        self.assertEqual(45, self.calls[0][2]["timeout"])
        self.assertEqual("localhost", self.calls[0][2]["network_scope"])
        self.assertEqual(("vault://profile/browser",), self.calls[0][2]["credential_references"])
        self.assertEqual(Decimal("0.01"), self.scheduler.metered_spend_usd)

    def test_missing_capability_account_budget_and_unapproved_start_have_no_effect(self):
        denied = (
            Workload("denied", ("/bin/true",), capabilities=frozenset({"filesystem.write"})),
            Workload("account", ("/bin/true",), account_requirement="cloud-account"),
            Workload("budget", ("/bin/true",), metered_cost_usd=Decimal("0.03")),
            Workload("boot", ("/bin/true",), starts_at_boot=True),
            Workload("coordinator", ("/bin/true",), replaces_coordinator=True),
        )
        for work in denied:
            with self.subTest(work=work.id), self.assertRaises(PermissionError):
                self.scheduler.execute(work)
        self.assertEqual([], self.calls)
        self.assertEqual(Decimal("0"), self.scheduler.metered_spend_usd)

    def test_secret_values_cannot_cross_the_environment_boundary(self):
        for key in ("PROVIDER_API_KEY", "ProviderApiKey", "AUTHORIZATION_HEADER", "db_passwd"):
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "protected credential reference"):
                self.scheduler.execute(Workload("unsafe", ("/bin/true",), environment={key: "plaintext"}))
        self.assertEqual([], self.calls)

    def test_non_decimal_cost_estimates_are_rejected_before_runner_effect(self):
        for value in (0.01, "0.01", None):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, "finite and non-negative"):
                self.scheduler.execute(Workload("bad-cost", ("/bin/true",), metered_cost_usd=value))
        self.assertEqual([], self.calls)

    def test_estimated_metered_cost_is_reserved_even_when_runner_fails(self):
        def fail(*_args, **_kwargs):
            raise RuntimeError("managed process failed after dispatch")

        scheduler = WorkloadScheduler(
            fail, frozenset(), memory_budget_mb=1024, metered_budget_usd=Decimal("0.01")
        )
        with self.assertRaisesRegex(RuntimeError, "after dispatch"):
            scheduler.execute(Workload("possibly-charged", ("/bin/true",), metered_cost_usd=Decimal("0.01")))
        self.assertEqual(Decimal("0.01"), scheduler.metered_spend_usd)


if __name__ == "__main__":
    unittest.main()
