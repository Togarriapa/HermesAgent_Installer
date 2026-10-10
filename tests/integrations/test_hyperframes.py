"""Local media-pipeline test for Hyperframes' fixed bounded probe contract.

This exercises real FFmpeg/H.264 output and frame-change evidence. It does not
claim that the Hyperframes Node/browser renderer is installed or accepted.
"""
from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from hermes_installer.components.probes.hyperframes_probe import (
    HYPERFRAMES_FIXTURE_RELATIVE_PATH,
    build_hyperframes_framehash_invocation,
    hyperframes_probe_asset,
    stage_hyperframes_fixture,
    verify_hyperframes_probe_results,
)
from hermes_installer.components.application_handlers import build_hyperframes_probe_invocation


@unittest.skipUnless(shutil.which("ffmpeg") and shutil.which("ffprobe"), "FFmpeg tools unavailable")
class HyperframesProbeIntegrationTests(unittest.TestCase):
    def test_fixed_asset_stages_and_real_media_pipeline_proves_two_distinct_scenes(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp).resolve()
            fixture, work = base / "fixture", base / "work"
            fixture.mkdir(mode=0o700)
            work.mkdir(mode=0o700)
            asset = stage_hyperframes_fixture(str(fixture))
            staged = fixture / HYPERFRAMES_FIXTURE_RELATIVE_PATH
            self.assertEqual(asset.sha256, hyperframes_probe_asset().sha256)
            self.assertEqual(asset.size_bytes, staged.stat().st_size)
            html = staged.read_text(encoding="utf-8")
            self.assertIn('data-composition-id="root"', html)
            self.assertIn('data-start="0" data-duration="1"', html)
            self.assertIn('data-start="1" data-duration="1"', html)
            self.assertNotIn("http://", html)
            self.assertNotIn("https://", html)

            output = work / "rendered.mp4"
            ffmpeg = shutil.which("ffmpeg")
            ffprobe = shutil.which("ffprobe")
            render = subprocess.run(
                [ffmpeg, "-hide_banner", "-v", "error",
                 "-f", "lavfi", "-i", "color=c=red:s=320x180:r=24:d=1",
                 "-f", "lavfi", "-i", "color=c=blue:s=320x180:r=24:d=1",
                 "-filter_complex", "[0:v][1:v]concat=n=2:v=1:a=0,format=yuv420p[v]",
                 "-map", "[v]", "-an", "-c:v", "libx264", "-pix_fmt", "yuv420p",
                 "-r", "24", "-y", str(output)],
                capture_output=True, text=True, timeout=30, check=False,
            )
            self.assertEqual(0, render.returncode, render.stderr[-1000:])
            os.chmod(output, 0o600)
            probe_invocation = build_hyperframes_probe_invocation(ffprobe, str(work))
            frame_invocation = build_hyperframes_framehash_invocation(ffmpeg, str(work))
            probe = subprocess.run(
                [probe_invocation.executable, *probe_invocation.argv],
                capture_output=True, text=True, timeout=10, check=False,
            )
            framehash = subprocess.run(
                [frame_invocation.executable, *frame_invocation.argv],
                capture_output=True, text=True, timeout=10, check=False,
            )
            stages = (
                {"exit_code": 0, "stdout": "", "stderr": ""},
                {"exit_code": probe.returncode, "stdout": probe.stdout, "stderr": probe.stderr},
                {"exit_code": framehash.returncode, "stdout": framehash.stdout, "stderr": framehash.stderr},
            )
            work_roots = {"hyperframes": str(work)}
            proof = verify_hyperframes_probe_results(
                stages,
                work_roots,
            )
            self.assertEqual(48, proof["media"]["frame_count"])
            self.assertEqual(2.0, proof["media"]["duration_seconds"])
            self.assertEqual(2, proof["distinct_sampled_frames"])
            self.assertNotEqual("0" * 64, proof["render_output_sha256"])
            same_framehash = stages[2]["stdout"].replace(
                stages[2]["stdout"].splitlines()[-1].rsplit(",", 1)[-1].strip(),
                stages[2]["stdout"].splitlines()[-2].rsplit(",", 1)[-1].strip(),
            )
            with self.assertRaisesRegex(RuntimeError, "visually distinct"):
                verify_hyperframes_probe_results(
                    (stages[0], stages[1], {**stages[2], "stdout": same_framehash}),
                    work_roots,
                )
            malformed_probe = stages[1]["stdout"].replace('"format":', '"unexpected":true,"format":')
            with self.assertRaisesRegex(RuntimeError, "unexpected schema"):
                verify_hyperframes_probe_results(
                    (stages[0], {**stages[1], "stdout": malformed_probe}, stages[2]),
                    work_roots,
                )


if __name__ == "__main__":
    unittest.main()
