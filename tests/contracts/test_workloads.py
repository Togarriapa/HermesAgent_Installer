"""Effects and fail-closed behavior for registered component workload recipes."""
import unittest
import json
import os
import tempfile
from decimal import Decimal
from pathlib import Path

from hermes_installer.components.workloads import Workload, WorkloadScheduler


class WorkloadSchedulerTests(unittest.TestCase):
    def setUp(self):
        self.calls = []

        def run(invocation):
            self.calls.append(invocation)
            if invocation.component_id == "browser-use":
                return {
                    "exit_code": 0,
                    "stdout": 'HERMES_BROWSER_USE_PROOF={"navigation":true,"interaction":"interaction-ok","screenshot_bytes":128}\n',
                }
            if invocation.executable.endswith("/ffprobe"):
                return {"exit_code": 0, "stdout": '{"streams":[{"codec_type":"video","codec_name":"h264","width":640,"height":360,"nb_read_frames":"120"}],"format":{"duration":"5.0"}}'}
            return {"exit_code": 0, "output": "fixture-complete"}

        self.scheduler = WorkloadScheduler(
            run,
            frozenset({
                "component.browser-use.local-fixture", "network:localhost",
                "component.graphify.read-fixture", "component.graphify.write-private-work",
                "component.graphify.read-private-work",
                "component.hyperframes.read-fixture", "component.hyperframes.write-private-work",
                "component.hyperframes.read-private-work",
            }),
            runtime_roots={
                "browser-use": "/owned/browser/bin/python",
                "graphify": "/owned/graphify",
                "hyperframes": "/owned/hyperframes",
                "ffprobe": "/owned/tools/ffprobe",
            },
            work_roots={
                "browser-use": "/owned/work/browser",
                "graphify": "/owned/work/graphify",
                "graphify-fixture": "/owned/fixtures/graphify",
                "hyperframes": "/owned/hyperframes",
                "hyperframes-fixture": "/owned/fixtures/hyperframes",
            },
            memory_budget_mb=2048,
            max_workers=1,
            metered_budget_usd=Decimal("0"),
        )

    def test_registered_browser_fixture_uses_fixed_python_and_local_sandboxed_recipe(self):
        result = self.scheduler.execute(Workload(
            "browser-fixture", {"fixture_url": "http://127.0.0.1:8765/fixture"}
        ))
        self.assertEqual(True, result["navigation"])
        self.assertEqual("interaction-ok", result["interaction"])
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

    def test_browser_process_success_without_interaction_screenshot_proof_is_rejected(self):
        calls = []
        scheduler = WorkloadScheduler(
            lambda invocation: calls.append(invocation) or {"exit_code": 0, "stdout": ""},
            self.scheduler.granted,
            runtime_roots={"browser-use": "/owned/browser/bin/python"},
            work_roots={"browser-use": "/owned/work/browser"},
            memory_budget_mb=2048,
        )
        with self.assertRaisesRegex(RuntimeError, "did not prove navigation"):
            scheduler.execute(Workload("browser-fixture", {"fixture_url": "http://127.0.0.1:8765/fixture"}))
        self.assertEqual(1, len(calls))

    def test_graphify_invocations_are_sequenced_and_dependent_query_stops_on_failure(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            fixtures, work = (base / "fixtures").resolve(), (base / "work").resolve()
            fixtures.mkdir(mode=0o700); work.mkdir(mode=0o700)
            os.chmod(fixtures, 0o700); os.chmod(work, 0o700)
            calls = []
            def run(invocation):
                calls.append(invocation)
                if invocation.argv[0] == "query":
                    output = work / "graphify-out"
                    output.mkdir(mode=0o700)
                    document = {
                        "nodes": [
                            {"id": "entry", "source_file": "entrypoint.py"},
                            {"id": "helper", "source_file": "helper.py"},
                        ],
                        "edges": [{"source": "entry", "target": "helper"}],
                    }
                    (output / "graph.json").write_text(json.dumps(document), encoding="utf-8")
                    os.chmod(output / "graph.json", 0o600)
                return {"exit_code": 0}
            scheduler = WorkloadScheduler(
                run, self.scheduler.granted,
                runtime_roots={"graphify": "/owned/graphify"},
                work_roots={"graphify": str(work), "graphify-fixture": str(fixtures)},
                memory_budget_mb=2048,
            )
            proof = scheduler.execute(Workload("graphify-code-fixture"))
            self.assertEqual(True, proof["fixture_connection"])
            self.assertEqual(2, proof["fixture_sources"])
            self.assertEqual(2, len(calls))
            self.assertEqual(("extract", str(fixtures), "--code-only", "--no-cluster", "--out", str(work)), calls[0].argv)
            self.assertEqual("query", calls[1].argv[0])
            self.assertEqual(("entrypoint.py", "helper.py"), tuple(sorted(p.name for p in fixtures.iterdir())))

            failed_calls = []
            def fail_first(invocation):
                failed_calls.append(invocation)
                return {"exit_code": 1}
            failed = WorkloadScheduler(
                fail_first, self.scheduler.granted,
                runtime_roots={"graphify": "/owned/graphify"},
                work_roots={"graphify": str(work), "graphify-fixture": str(fixtures)},
                memory_budget_mb=2048,
            )
            with self.assertRaisesRegex(RuntimeError, "dependent stages were not launched"):
                failed.execute(Workload("graphify-code-fixture"))
            self.assertEqual(1, len(failed_calls))

    def test_hyperframes_fixture_is_fixed_private_on_demand_and_unmetered(self):
        result = self.scheduler.execute(Workload("hyperframes-render-fixture"))
        self.assertEqual(120, result["frames"])
        self.assertEqual(5.0, result["duration_seconds"])
        invocation, probe = self.calls
        self.assertEqual("hyperframes", invocation.component_id)
        self.assertEqual("/owned/hyperframes/bin/hyperframes", invocation.executable)
        self.assertEqual(("render", "-c", "/owned/fixtures/hyperframes/composition.html",
                          "-o", "/owned/hyperframes/rendered.mp4"), invocation.argv)
        self.assertEqual("deny", invocation.network)
        self.assertEqual(180, invocation.timeout_seconds)
        self.assertEqual(2048, invocation.memory_limit_mb)
        self.assertEqual("/owned/tools/ffprobe", probe.executable)
        self.assertIn("/owned/hyperframes/rendered.mp4", probe.argv)
        self.assertEqual(Decimal("0"), self.scheduler.metered_spend_usd)

    def test_hyperframes_fixture_rejects_caller_paths_and_missing_capabilities(self):
        with self.assertRaisesRegex(ValueError, "parameters do not match"):
            self.scheduler.execute(Workload("hyperframes-render-fixture", {"output": "/tmp/x.mp4"}))
        denied = WorkloadScheduler(
            lambda invocation: self.calls.append(invocation), frozenset(),
            runtime_roots={"hyperframes": "/owned/hyperframes"},
            work_roots={"hyperframes-fixture": "/owned/fixtures/hyperframes",
                        "hyperframes": "/owned/hyperframes"},
            memory_budget_mb=4096,
        )
        with self.assertRaisesRegex(PermissionError, "capability denied"):
            denied.execute(Workload("hyperframes-render-fixture"))
        self.assertEqual([], self.calls)

    def test_hyperframes_success_requires_bounded_video_metadata(self):
        calls = []
        def run(invocation):
            calls.append(invocation)
            if invocation.executable.endswith("/ffprobe"):
                return {"exit_code": 0, "stdout": '{"streams":[{"codec_type":"video","codec_name":"h264","width":640,"height":360,"nb_read_frames":"0"}],"format":{"duration":"0"}}'}
            return {"exit_code": 0}
        scheduler = WorkloadScheduler(
            run, self.scheduler.granted,
            runtime_roots={"hyperframes": "/owned/hyperframes", "ffprobe": "/owned/tools/ffprobe"},
            work_roots={"hyperframes-fixture": "/owned/fixtures/hyperframes",
                        "hyperframes": "/owned/hyperframes"},
            memory_budget_mb=2048,
        )
        with self.assertRaisesRegex(RuntimeError, "outside fixture bounds"):
            scheduler.execute(Workload("hyperframes-render-fixture"))
        self.assertEqual(2, len(calls))

    def test_graphify_zero_exit_without_fixture_edge_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            fixtures, work = (base / "fixtures").resolve(), (base / "work").resolve()
            fixtures.mkdir(mode=0o700); work.mkdir(mode=0o700)
            os.chmod(fixtures, 0o700); os.chmod(work, 0o700)
            def run(invocation):
                if invocation.argv[0] == "query":
                    output = work / "graphify-out"
                    output.mkdir(mode=0o700)
                    document = {"nodes": [
                        {"id": "entry", "source_file": "entrypoint.py"},
                        {"id": "helper", "source_file": "helper.py"},
                    ], "edges": []}
                    graph = output / "graph.json"
                    graph.write_text(json.dumps(document), encoding="utf-8")
                    os.chmod(graph, 0o600)
                return {"exit_code": 0}
            scheduler = WorkloadScheduler(
                run, self.scheduler.granted, runtime_roots={"graphify": "/owned/graphify"},
                work_roots={"graphify": str(work), "graphify-fixture": str(fixtures)},
                memory_budget_mb=2048,
            )
            with self.assertRaisesRegex(RuntimeError, "does not connect"):
                scheduler.execute(Workload("graphify-code-fixture"))


if __name__ == "__main__":
    unittest.main()
