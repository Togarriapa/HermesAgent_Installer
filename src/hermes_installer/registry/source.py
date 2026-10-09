"""Fetch only the pinned declarative resource roots into private in-memory staging.

No upstream manifest is executed. The source repo has no declared redistribution
license, so callers persist imported bytes only in the user's installer-owned
runtime area after host authorization.
"""
from __future__ import annotations
import hashlib
import io
import json
import re
import tarfile
from dataclasses import dataclass
from typing import Mapping

from hermes_installer.network import BoundedNetwork, HTTPResult


class RegistrySourceError(RuntimeError):
    """Pinned registry source failed integrity, bounds, or schema validation."""


@dataclass(frozen=True, slots=True)
class PinnedSource:
    repository: str
    commit: str
    git_tree: str
    catalog_blob: str
    quality_policy_blob: str
    root_trees: Mapping[str, str]
    root_counts: Mapping[str, int]

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> "PinnedSource":
        try:
            if value.get("schema") != 1:
                raise ValueError
            repository = value["repository"]
            commit = value["commit"]
            tree = value["git_tree"]
            catalog = value["catalog"]["git_blob"]
            quality = value["quality_policy"]["git_blob"]
            roots = value["resource_roots"]
            root_trees = {name: item["git_tree"] for name, item in roots.items()}
            counts = {name: item["manifests"] for name, item in roots.items()}
        except (KeyError, TypeError, AttributeError):
            raise RegistrySourceError("source pin document is incomplete") from None
        if repository != "https://github.com/Togarriapa/HermesAgent_Resources":
            raise RegistrySourceError("registry source repository is outside the reviewed pin")
        if not _sha(commit) or not _sha(tree) or not _sha(catalog) or not _sha(quality):
            raise RegistrySourceError("source pin contains an invalid Git object ID")
        if set(root_trees) != {"profiles", "skills", "plugins", "mcps", "bundles", "channels", "crons", "webhooks"}:
            raise RegistrySourceError("source pin does not declare all eight non-recursive catalog roots")
        if any(not _sha(item) for item in root_trees.values()) or any(not isinstance(n, int) or n < 0 for n in counts.values()):
            raise RegistrySourceError("source pin root tree/count is invalid")
        return cls(repository, commit, tree, catalog, quality, root_trees, counts)


@dataclass(frozen=True, slots=True)
class VerifiedSource:
    revision: str
    source_tree: str
    files: Mapping[str, bytes]
    file_blob_ids: Mapping[str, str]
    content_digest: str


def _sha(value: object) -> bool:
    return isinstance(value, str) and bool(re.fullmatch(r"[a-f0-9]{40}", value))


def _json_response(response: HTTPResult, label: str) -> Mapping[str, object]:
    if response.status != 200:
        raise RegistrySourceError(f"registry {label} request failed with HTTP {response.status}")
    try:
        data = json.loads(response.body)
    except (ValueError, UnicodeDecodeError):
        raise RegistrySourceError(f"registry {label} response is not valid JSON") from None
    if not isinstance(data, dict):
        raise RegistrySourceError(f"registry {label} response has an invalid shape")
    return data


def _git_blob_sha(content: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(content)).encode() + b"\0" + content).hexdigest()


class RegistrySourceFetcher:
    """HTTPS-only bounded loader with commit, root-tree and per-blob verification."""
    MAX_ARCHIVE_BYTES = 8 * 1024 * 1024
    MAX_EXPANDED_BYTES = 16 * 1024 * 1024
    ROOTS = frozenset({"profiles", "skills", "plugins", "mcps", "bundles", "channels", "crons", "webhooks"})

    def __init__(self, network: BoundedNetwork):
        self.network = network

    def _get(self, url: str, *, cancelled=None) -> HTTPResult:
        try:
            return self.network.request(url, method="GET", headers={"Accept": "application/vnd.github+json"},
                                        body=None, cancelled=cancelled)
        except Exception as error:
            raise RegistrySourceError(f"bounded source request failed ({type(error).__name__})") from None

    def fetch(self, pin: PinnedSource, *, cancelled=None) -> VerifiedSource:
        api = "https://api.github.com/repos/Togarriapa/HermesAgent_Resources"
        commit = _json_response(self._get(f"{api}/git/commits/{pin.commit}", cancelled=cancelled), "commit")
        if commit.get("sha") != pin.commit or not isinstance(commit.get("tree"), dict) or commit["tree"].get("sha") != pin.git_tree:
            raise RegistrySourceError("selected commit/tree differs from the reviewed source pin")
        tree = _json_response(self._get(f"{api}/git/trees/{pin.git_tree}?recursive=1", cancelled=cancelled), "tree")
        entries = tree.get("tree")
        if tree.get("truncated") is not False or not isinstance(entries, list):
            raise RegistrySourceError("source tree is truncated or malformed")
        roots = {}
        expected: dict[str, str] = {}
        for entry in entries:
            if not isinstance(entry, dict):
                raise RegistrySourceError("source tree entry is malformed")
            path, mode, kind, sha = entry.get("path"), entry.get("mode"), entry.get("type"), entry.get("sha")
            if not isinstance(path, str) or not _sha(sha):
                raise RegistrySourceError("source tree path or object ID is malformed")
            if path in {"catalog.yaml", "QUALITY_POLICY.yaml"}:
                expected[path] = sha
                continue
            root, slash, rest = path.partition("/")
            if root in self.ROOTS:
                if not slash or "/" in rest or not rest.endswith(".yaml") or kind != "blob" or mode != "100644":
                    raise RegistrySourceError(f"catalog root must contain only regular top-level YAML manifests: {path}")
                expected[path] = sha
            elif root in self.ROOTS:
                raise RegistrySourceError(f"unexpected path in catalog root: {path}")
            if not slash and kind == "tree" and root in self.ROOTS:
                roots[root] = sha
        if roots != dict(pin.root_trees):
            raise RegistrySourceError("catalog root tree IDs differ from the reviewed pin")
        for path, expected_sha in (("catalog.yaml", pin.catalog_blob), ("QUALITY_POLICY.yaml", pin.quality_policy_blob)):
            if expected.get(path) != expected_sha:
                raise RegistrySourceError(f"pinned control document changed: {path}")
        observed_counts = {root: sum(path.startswith(root + "/") for path in expected) for root in self.ROOTS}
        if observed_counts != dict(pin.root_counts):
            raise RegistrySourceError("catalog manifest counts differ from source pin")

        archive = self._get(f"https://codeload.github.com/Togarriapa/HermesAgent_Resources/tar.gz/{pin.commit}", cancelled=cancelled)
        if archive.status != 200 or len(archive.body) > self.MAX_ARCHIVE_BYTES:
            raise RegistrySourceError("pinned source archive failed status or size bound")
        selected: dict[str, bytes] = {}
        expanded = 0
        prefix = "HermesAgent_Resources-" + pin.commit[:7] + "/"
        try:
            with tarfile.open(fileobj=io.BytesIO(archive.body), mode="r:gz") as bundle:
                for member in bundle:
                    name = member.name
                    if name == prefix[:-1]:
                        if not member.isdir():
                            raise RegistrySourceError("archive root is not a directory")
                        continue
                    if not name.startswith(prefix):
                        raise RegistrySourceError("archive has an unexpected top-level directory")
                    relative = name[len(prefix):]
                    if not relative or relative.startswith("/") or "\\" in relative or any(part in {"", ".", ".."} for part in relative.split("/")):
                        raise RegistrySourceError("archive contains an unsafe path")
                    if member.isdir():
                        if relative.split("/", 1)[0] in self.ROOTS and "/" in relative:
                            raise RegistrySourceError("catalog roots must not be recursive")
                        continue
                    if not member.isfile():
                        raise RegistrySourceError("archive contains a link or special file")
                    if relative not in expected:
                        # Upstream governance, docs, CI and repository metadata are not imported.
                        continue
                    if relative in selected:
                        raise RegistrySourceError("archive contains duplicate selected path")
                    stream = bundle.extractfile(member)
                    if stream is None:
                        raise RegistrySourceError("selected source blob is unreadable")
                    data = stream.read(self.MAX_EXPANDED_BYTES + 1)
                    expanded += len(data)
                    if expanded > self.MAX_EXPANDED_BYTES:
                        raise RegistrySourceError("expanded registry roots exceed size bound")
                    if _git_blob_sha(data) != expected[relative]:
                        raise RegistrySourceError(f"selected blob does not match pinned Git tree: {relative}")
                    selected[relative] = data
        except (tarfile.TarError, OSError, EOFError):
            raise RegistrySourceError("pinned registry archive is malformed") from None
        if set(selected) != set(expected):
            missing = sorted(set(expected) - set(selected))
            raise RegistrySourceError(f"pinned archive is missing selected resources ({len(missing)} files)")
        framed = hashlib.sha256()
        for path in sorted(selected):
            blob = expected[path]
            name = path.encode()
            framed.update(len(name).to_bytes(4, "big") + name + bytes.fromhex(blob))
        return VerifiedSource(pin.commit, pin.git_tree, selected, expected, framed.hexdigest())
