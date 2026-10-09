"""Source-specific offline invocation contract for Hyperframes."""
import unittest

from hermes_installer.components.application_handlers import (
    RuntimeProfileError,
    build_hyperframes_render_fixture,
)


class HyperframesInvocationTests(unittest.TestCase):
    def test_render_is_bounded_private_local_and_uses_documented_cli(self):
        invocation = build_hyperframes_render_fixture(
            "/owned/envs/hyperframes",
            "/owned/fixtures/tiny-video",
            "/owned/work/hyperframes",
        )
        self.assertEqual("/owned/envs/hyperframes/bin/hyperframes", invocation.executable)
        self.assertEqual(
            ("render", "-c", "/owned/fixtures/tiny-video/composition.html",
             "-o", "/owned/work/hyperframes/rendered.mp4"),
            invocation.argv,
        )
        self.assertEqual("PRIVATE", invocation.sensitivity)
        self.assertEqual("deny", invocation.network)
        self.assertFalse(invocation.credential_references)
        self.assertEqual(180, invocation.timeout_seconds)
        self.assertEqual(2048, invocation.memory_limit_mb)
        self.assertIn("component.hyperframes.write-private-work", invocation.capability_scopes)

    def test_render_rejects_traversing_paths(self):
        with self.assertRaises(RuntimeProfileError):
            build_hyperframes_render_fixture(
                "/owned/envs/hyperframes", "/owned/../outside", "/owned/work/hyperframes"
            )


if __name__ == "__main__":
    unittest.main()
