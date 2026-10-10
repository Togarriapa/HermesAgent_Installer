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
        self.hyperframes_temp = tempfile.TemporaryDirectory()
        self.hyperframes_work = Path(self.hyperframes_temp.name, "work").resolve()
        self.hyperframes_work.mkdir(mode=0o700)
        self.hyperframes_fixtures = Path(self.hyperframes_temp.name, "fixtures").resolve()
        self.hyperframes_fixtures.mkdir(mode=0o700)

        def run(invocation):
            self.calls.append(invocation)
            if invocation.component_id == "browser-use":
                proof = {
                    "schema_version": 1,
                    "navigation_url": invocation.argv[2],
                    "navigation_succeeded": True,
                    "page_title": "Hermes qualification fixture",
                    "initial_text": "ready",
                    "click_succeeded": True,
                    "interaction_text": "interaction-ok",
                    "screenshot_format": "png",
                    "screenshot_bytes": 128,
                    "screenshot_sha256": "a" * 64,
                }
                return {"exit_code": 0,
                        "stdout": "HERMES_BROWSER_USE_PROOF=" + json.dumps(proof) + "\n"}
            if invocation.component_id == "hyperframes" and invocation.executable.endswith("/bin/hyperframes"):
                Path(self.hyperframes_work, "rendered.mp4").write_bytes(b"fixture-mp4-proof")
                return {"exit_code": 0, "stdout": "", "stderr": ""}
            if invocation.executable.endswith("/ffprobe"):
                return {"exit_code": 0, "stdout": '{"streams":[{"index":0,"codec_name":"h264","codec_type":"video","width":320,"height":180,"pix_fmt":"yuv420p","avg_frame_rate":"24/1","nb_read_frames":"48"}],"format":{"duration":"2.000000","size":"1234"}}', "stderr": ""}
            if invocation.executable.endswith("/ffmpeg"):
                return {"exit_code": 0, "stdout": "#tb 0: 1/24\n#dimensions 0: 320x180\n#stream#, dts,        pts, duration,     size, hash\n0, 12, 12, 1, 86400, 11111111111111111111111111111111\n0, 36, 36, 1, 86400, 22222222222222222222222222222222\n", "stderr": ""}
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
                "hyperframes": str(self.hyperframes_work),
                "hyperframes-fixture": str(self.hyperframes_fixtures),
            },
            memory_budget_mb=2048,
            max_workers=1,
            metered_budget_usd=Decimal("0"),
        )

    def test_registered_browser_fixture_uses_fixed_python_and_local_sandboxed_recipe(self):
        result = self.scheduler.execute(Workload(
            "browser-fixture", {"fixture_url": "http://127.0.0.1:8765/fixture"}
        ))
        self.assertEqual(True, result["navigation_succeeded"])
        self.assertEqual("interaction-ok", result["interaction_text"])
        invocation = self.calls[0]
        self.assertEqual("/owned/browser/bin/python", invocation.executable)
        self.assertEqual("browser-use", invocation.component_id)
        self.assertEqual("localhost", invocation.network)
        self.assertTrue(invocation.argv[1].endswith("browser_use_qualification_probe.py"))
        self.assertIn("chromium_sandbox=True", Path(invocation.argv[1]).read_text(encoding="utf-8"))
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
        self.assertEqual(48, result["media"]["frame_count"])
        self.assertEqual(2.0, result["media"]["duration_seconds"])
        self.assertEqual("functional_local_render_passed", result["fixture_state"])
        self.assertEqual(2, result["distinct_sampled_frames"])
        invocation, probe, framehash = self.calls
        self.assertEqual("hyperframes", invocation.component_id)
        self.assertEqual("/owned/hyperframes/bin/hyperframes", invocation.executable)
        self.assertEqual(("render", "-c", str(self.hyperframes_fixtures / "composition.html"),
                          "-o", str(self.hyperframes_work / "rendered.mp4"), "--format", "mp4",
                          "--fps", "24", "--quality", "draft", "--workers", "1", "--no-browser-gpu"), invocation.argv)
        self.assertEqual("deny", invocation.network)
        self.assertEqual(180, invocation.timeout_seconds)
        self.assertEqual(2048, invocation.memory_limit_mb)
        self.assertEqual("/owned/tools/ffprobe", probe.executable)
        self.assertIn(str(self.hyperframes_work / "rendered.mp4"), probe.argv)
        self.assertEqual("/owned/tools/ffmpeg", framehash.executable)
        self.assertEqual("deny", framehash.network)
        self.assertEqual(Decimal("0"), self.scheduler.metered_spend_usd)
        self.assertEqual("fc20eaf85de0fe9bbc63bf4b315892a4fb0934d19819eb8b9450fa5bb7ed6052", result["source_asset_sha256"])

    def test_hyperframes_fixture_rejects_caller_paths_and_missing_capabilities(self):
        with self.assertRaisesRegex(ValueError, "parameters do not match"):
            self.scheduler.execute(Workload("hyperframes-render-fixture", {"output": "/tmp/x.mp4"}))
        denied = WorkloadScheduler(
            lambda invocation: self.calls.append(invocation), frozenset(),
            runtime_roots={"hyperframes": "/owned/hyperframes"},
            work_roots={"hyperframes-fixture": str(self.hyperframes_fixtures),
                        "hyperframes": str(self.hyperframes_work)},
            memory_budget_mb=4096,
        )
        with self.assertRaisesRegex(PermissionError, "capability denied"):
            denied.execute(Workload("hyperframes-render-fixture"))
        self.assertEqual([], self.calls)

    def test_hyperframes_success_requires_bounded_video_metadata(self):
        calls = []
        def run(invocation):
            calls.append(invocation)
            if invocation.executable.endswith("/bin/hyperframes"):
                Path(self.hyperframes_work, "rendered.mp4").write_bytes(b"fixture-mp4-proof")
                return {"exit_code": 0, "stdout": "", "stderr": ""}
            if invocation.executable.endswith("/ffprobe"):
                return {"exit_code": 0, "stdout": '{"streams":[{"index":0,"codec_name":"h264","codec_type":"video","width":320,"height":180,"pix_fmt":"yuv420p","avg_frame_rate":"24/1","nb_read_frames":"0"}],"format":{"duration":"0","size":"1234"}}', "stderr": ""}
            if invocation.executable.endswith("/ffmpeg"):
                return {"exit_code": 0, "stdout": "", "stderr": ""}
            return {"exit_code": 0, "stderr": ""}
        scheduler = WorkloadScheduler(
            run, self.scheduler.granted,
            runtime_roots={"hyperframes": "/owned/hyperframes", "ffprobe": "/owned/tools/ffprobe"},
            work_roots={"hyperframes-fixture": str(self.hyperframes_fixtures),
                        "hyperframes": str(self.hyperframes_work)},
            memory_budget_mb=2048,
        )
        with self.assertRaisesRegex(RuntimeError, "fixed fixture|unexpected schema"):
            scheduler.execute(Workload("hyperframes-render-fixture"))
        self.assertEqual(3, len(calls))

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

    def test_scrapegraph_requires_installer_bound_source_before_launch(self):
        calls = []
        scheduler = WorkloadScheduler(
            lambda invocation: calls.append(invocation),
            frozenset({"component.scrapegraph-ai.read-fixture",
                       "component.scrapegraph-ai.fixture-model"}),
            runtime_roots={"scrapegraph-ai-python": "/owned/scrapegraph/bin/python"},
            work_roots={"scrapegraph-ai": "/owned/work/scrapegraph-ai"},
            memory_budget_mb=2048,
        )
        with self.assertRaisesRegex(RuntimeError, "source generation is not enrolled"):
            scheduler.execute(Workload("scrapegraph-local-fixture"))
        with self.assertRaisesRegex(ValueError, "fixed registered recipe"):
            scheduler.execute(Workload("scrapegraph-local-fixture", {"source_root": "/tmp/source"}))
        self.assertEqual([], calls)


if __name__ == "__main__":
    unittest.main()
