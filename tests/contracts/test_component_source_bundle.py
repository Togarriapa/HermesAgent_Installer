"""Effect and failure tests for pinned component archive staging."""
import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path

from hermes_installer.components.adapters import resolve_component_adapter
from hermes_installer.components.source_bundle import (
    ComponentSourceError,
    GitHubComponentSourceFetcher,
    HttpResponse,
)
from hermes_installer.registry.generation import GenerationStore
from hermes_installer.state import Journal, OwnedRoot, process_lock
from hermes_installer.registry.source import _git_tree


class FakeTransport:
    def __init__(self, responses):
        self.responses = list(responses)
        self.requested = []

    def get(self, url, *, max_bytes, timeout_seconds):
        self.requested.append((url, max_bytes, timeout_seconds))
        return self.responses.pop(0)


def archive_bytes(identity, revision, entries):
    owner, repo = identity.split("/", 1)
    prefix = f"{owner}-{repo}-{revision[:7]}"
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        root = tarfile.TarInfo(prefix + "/")
        root.type = tarfile.DIRTYPE
        archive.addfile(root)
        for name, body, mode, kind in entries:
            member = tarfile.TarInfo(prefix + "/" + name)
            member.mode = mode
            if kind == "symlink":
                member.type = tarfile.SYMTYPE
                member.linkname = body
                archive.addfile(member)
            else:
                member.size = len(body)
                archive.addfile(member, io.BytesIO(body))
    return buffer.getvalue()


class ComponentSourceBundleTests(unittest.TestCase):
    IDENTITY = "affaan-m/ECC"
    REVISION = "ef648e01899ba3e8dc6371642deaaf64b4477775"

    def fixture_archive(self):
        return archive_bytes(self.IDENTITY, self.REVISION, [
            ("LICENSE", b"MIT license fixture\n", 0o644, "file"),
            ("skills/demo/SKILL.md",
             b"[helper](scripts/check.py)\n[shared](../../README.md)\n",
             0o644, "file"),
            ("skills/demo/scripts/check.py", b"print('ok')\n", 0o755, "file"),
            ("README.md", b"shared root data\n", 0o644, "file"),
        ])

    def make_fetcher(self, archive):
        files = {
            "LICENSE": b"MIT license fixture\\n",
            "skills/demo/SKILL.md": b"[helper](scripts/check.py)\\n[shared](../../README.md)\\n",
            "skills/demo/scripts/check.py": b"print('ok')\\n",
            "README.md": b"shared root data\\n",
        }
        modes = {name: (0o755 if name.endswith(".py") and name != "skills/demo/SKILL.md" else 0o644) for name in files}
        tree_sha, _ = _git_tree(files, modes)
        commit_url = f"https://api.github.com/repos/{self.IDENTITY}/commits/{self.REVISION}"
        commit_body = json.dumps({
            "sha": self.REVISION,
            "html_url": f"https://github.com/{self.IDENTITY}/commit/{self.REVISION}",
            "commit": {"tree": {"sha": tree_sha}},
        }).encode("utf-8")
        responses = [
            HttpResponse(200, commit_url, commit_body),
            HttpResponse(
                200,
                f"https://codeload.github.com/{self.IDENTITY}/legacy.tar.gz/{self.REVISION}",
                archive,
            ),
        ]
        transport = FakeTransport(responses)
        return GitHubComponentSourceFetcher(transport), transport

    def test_fetches_exact_selected_pin_and_stages_complete_private_generation(self):
        contract = resolve_component_adapter("affaan-m/ECC")
        fetcher, transport = self.make_fetcher(self.fixture_archive())
        source = fetcher.fetch(contract)

        self.assertEqual(self.IDENTITY, source.source_identity)
        self.assertEqual(self.REVISION, source.revision)
        self.assertIn("skills/demo/scripts/check.py", source.files)
        self.assertIn("README.md", source.files)
        self.assertIn("LICENSE", source.license_files)
        self.assertEqual(
            f"https://api.github.com/repos/{self.IDENTITY}/commits/{self.REVISION}",
            transport.requested[0][0],
        )
        self.assertEqual(
            f"https://codeload.github.com/{self.IDENTITY}/legacy.tar.gz/{self.REVISION}",
            transport.requested[1][0],
        )
        self.assertEqual(40, len(source.source_tree_sha))

        with tempfile.TemporaryDirectory() as temporary:
            owned = OwnedRoot(Path(temporary) / "managed")
            owned.ensure()
            with process_lock(owned.path("installer.lock")):
                journal = Journal(owned.path("journal.sqlite3"))
                store = GenerationStore(owned, journal, mutation_locked=True)
                staged = source.stage(store)
                repeated = source.stage(store)
                self.assertEqual(staged, repeated)
                self.assertEqual(
                    b"print('ok')\n",
                    (staged / "skills/demo/scripts/check.py").read_bytes(),
                )
                self.assertTrue((staged / "INSTALLER-SOURCE-PROVENANCE.json").is_file())
                self.assertEqual(
                    "staged",
                    journal.owned("generation")[0]["state"],
                )

    def test_rejects_path_escape_and_symlinks(self):
        contract = resolve_component_adapter("affaan-m/ECC")
        escape = archive_bytes(self.IDENTITY, self.REVISION, [
            ("../outside.py", b"pass\n", 0o644, "file"),
        ])
        with self.assertRaisesRegex(ComponentSourceError, "unsafe path"):
            self.make_fetcher(escape)[0].fetch(contract)

        linked = archive_bytes(self.IDENTITY, self.REVISION, [
            ("skills/demo/SKILL.md", b"# Demo\n", 0o644, "file"),
            ("skills/demo/helper.py", "../outside.py", 0o777, "symlink"),
        ])
        with self.assertRaisesRegex(ComponentSourceError, "unsupported link"):
            self.make_fetcher(linked)[0].fetch(contract)

    def test_rejects_archive_content_that_differs_from_pinned_git_tree(self):
        contract = resolve_component_adapter("affaan-m/ECC")
        changed = archive_bytes(self.IDENTITY, self.REVISION, [
            ("README.md", b"unexpected content\\n", 0o644, "file"),
        ])
        with self.assertRaisesRegex(ComponentSourceError, "differ from the pinned Git tree"):
            self.make_fetcher(changed)[0].fetch(contract)

    def test_rejects_archive_from_another_repository(self):
        contract = resolve_component_adapter("affaan-m/ECC")
        wrong = archive_bytes("other/project", self.REVISION, [
            ("README.md", b"not the pinned repository\n", 0o644, "file"),
        ])
        with self.assertRaisesRegex(ComponentSourceError, "pinned repository"):
            self.make_fetcher(wrong)[0].fetch(contract)

    def test_broken_skill_reference_fails_before_generation_staging(self):
        contract = resolve_component_adapter("affaan-m/ECC")
        broken = archive_bytes(self.IDENTITY, self.REVISION, [
            ("skills/demo/SKILL.md", b"[missing](scripts/missing.py)\n", 0o644, "file"),
        ])
        with self.assertRaisesRegex(ComponentSourceError, "referenced file or directory is missing"):
            self.make_fetcher(broken)[0].fetch(contract)


if __name__ == "__main__":
    unittest.main()
