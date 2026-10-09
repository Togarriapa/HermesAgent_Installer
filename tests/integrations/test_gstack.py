"""R0081: gstack's pinned Hermes tier is instruction-only."""
import unittest

from hermes_installer.components.gstack import (
    GstackAdapterError,
    bind_gstack_profile_instructions,
)


def pinned_tree() -> dict[str, bytes]:
    # Minimal source fixture copied from the selected upstream package/host
    # contract; the digest body is synthetic so the test proves byte-preserving
    # profile composition without redistributing the upstream instruction file.
    return {
        "package.json": b'{"name":"gstack","version":"1.91.68","license":"MIT"}',
        "hosts/hermes.ts": b"const hermes = defineHost({\n  name: 'hermes',\n  displayName: 'Hermes',\n  tier: 'instruction-only',\n});",
        "agents-digest/gstack-AGENTS.md": b"# Selected gstack instructions\n\nUse the reviewed digest.\n",
    }


class GstackAdapterTests(unittest.TestCase):
    def test_binds_exact_digest_to_selected_profile_and_keeps_invocation_disabled(self):
        source = pinned_tree()
        binding = bind_gstack_profile_instructions("analyst", source)
        profile = binding.append_to("Existing profile role.")
        self.assertTrue(profile.startswith("Existing profile role.\n\n## gstack instructions (20eb6202fa8ea83a882e7c0463b722cd8a31af1e)"))
        self.assertTrue(profile.endswith(source["agents-digest/gstack-AGENTS.md"].decode()))
        self.assertEqual("analyst", binding.profile_id)
        self.assertFalse(binding.native_invocation_available)
        self.assertIn("instruction-only", binding.native_invocation_reason)

    def test_refuses_executable_tier_and_malformed_profile(self):
        source = pinned_tree()
        source["hosts/hermes.ts"] = source["hosts/hermes.ts"].replace(b"instruction-only", b"full")
        with self.assertRaisesRegex(GstackAdapterError, "instruction-only"):
            bind_gstack_profile_instructions("analyst", source)
        with self.assertRaisesRegex(GstackAdapterError, "profile id"):
            bind_gstack_profile_instructions("../outside", pinned_tree())


if __name__ == "__main__":
    unittest.main()
