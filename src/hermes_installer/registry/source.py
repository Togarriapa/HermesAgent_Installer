"""Offline, integrity-checked reader for the vendored upstream source archive."""
from __future__ import annotations
import hashlib
import io
import json
import re
import tarfile
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Mapping

class RegistrySourceError(RuntimeError):
    """Pinned vendored registry source failed integrity or schema validation."""

@dataclass(frozen=True, slots=True)
class PinnedSource:
    repository: str
    catalog_version: str
    commit: str
    git_tree: str
    archive_sha256: str
    archive_size: int
    archive_git_blob: str
    snapshot_file_count: int
    catalog_blob: str
    quality_policy_blob: str
    root_trees: Mapping[str, str]
    root_counts: Mapping[str, int]

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> "PinnedSource":
        try:
            if value.get("schema") != 1: raise ValueError
            repository, version = value["repository"], value["catalog_version"]
            commit, tree = value["commit"], value["git_tree"]
            archive = value["archive"]
            archive_hash, archive_size, archive_blob = archive["sha256"], archive["size"], archive["git_blob"]
            snapshot_count = value["snapshot_file_count"]
            catalog, quality = value["catalog"]["git_blob"], value["quality_policy"]["git_blob"]
            roots = value["resource_roots"]
            root_trees = {name: item["git_tree"] for name,item in roots.items()}
            counts = {name: item["manifests"] for name,item in roots.items()}
        except (KeyError, TypeError, AttributeError):
            raise RegistrySourceError("vendored source pin is incomplete") from None
        expected_roots = {"profiles","skills","plugins","mcps","bundles","channels","crons","webhooks"}
        ids = [commit,tree,archive_blob,catalog,quality,*root_trees.values()]
        if repository != "https://github.com/Togarriapa/HermesAgent_Resources" or not isinstance(version,str):
            raise RegistrySourceError("upstream repository identity is not pinned")
        if any(not isinstance(item,str) or not re.fullmatch(r"[a-f0-9]{40}",item) for item in ids):
            raise RegistrySourceError("source pin contains an invalid Git object ID")
        if not isinstance(archive_hash,str) or not re.fullmatch(r"[a-f0-9]{64}",archive_hash):
            raise RegistrySourceError("archive SHA-256 is invalid")
        if (set(root_trees) != expected_roots or set(counts) != expected_roots
            or any(not isinstance(count,int) or count < 0 for count in counts.values())
            or not isinstance(archive_size,int) or archive_size <= 0
            or not isinstance(snapshot_count,int) or snapshot_count <= 0):
            raise RegistrySourceError("source pin has invalid roots or bounds")
        return cls(repository,version,commit,tree,archive_hash,archive_size,archive_blob,snapshot_count,
                   catalog,quality,root_trees,counts)

@dataclass(frozen=True, slots=True)
class VerifiedSource:
    repository: str
    revision: str
    source_tree: str
    catalog_version: str
    files: Mapping[str, bytes]
    file_modes: Mapping[str, int]
    content_digest: str

def _git_blob(content: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(content)).encode() + b"\0" + content).hexdigest()

def _git_tree(files: Mapping[str, bytes], modes: Mapping[str, int]):
    """Recompute the source commit tree from path, executable bit and Git blob IDs."""
    root: dict[str, object] = {}
    for path, content in files.items():
        node = root
        parts = PurePosixPath(path).parts
        for part in parts[:-1]:
            child = node.setdefault(part, {})
            if not isinstance(child, dict):
                raise RegistrySourceError("file and directory names collide")
            node = child
        if parts[-1] in node:
            raise RegistrySourceError("duplicate path in vendored Git tree")
        node[parts[-1]] = (content, modes[path])
    subtrees = {}
    def digest(node, prefix=""):
        entries = []
        for name, value in node.items():
            if isinstance(value, dict):
                mode = "40000"
                object_id = digest(value, prefix + name + "/")
                subtrees[prefix + name] = object_id
                directory = True
            else:
                content, file_mode = value
                mode = "100755" if file_mode == 0o755 else "100644" if file_mode == 0o644 else ""
                if not mode:
                    raise RegistrySourceError("unexpected tracked source file mode")
                object_id = _git_blob(content)
                directory = False
            order = name.encode() + (b"/" if directory else b"")
            entries.append((order, mode, name, object_id))
        payload = b"".join(mode.encode() + b" " + name.encode() + b"\\0" + bytes.fromhex(object_id)
                           for _, mode, name, object_id in sorted(entries, key=lambda item: item[0]))
        return hashlib.sha1(b"tree " + str(len(payload)).encode() + b"\\0" + payload).hexdigest()
    return digest(root), subtrees


class BundledRegistrySource:
    """Verifies the committed archive offline; it makes no upstream requests."""
    MAX_ARCHIVE_BYTES = 8 * 1024 * 1024
    MAX_EXPANDED_BYTES = 16 * 1024 * 1024
    ROOTS = frozenset({"profiles","skills","plugins","mcps","bundles","channels","crons","webhooks"})

    def __init__(self, pin: PinnedSource):
        self.pin = pin

    def load(self, archive_bytes: bytes) -> VerifiedSource:
        if not isinstance(archive_bytes,bytes) or len(archive_bytes)!=self.pin.archive_size or len(archive_bytes)>self.MAX_ARCHIVE_BYTES:
            raise RegistrySourceError("vendored archive size differs from the pin")
        if hashlib.sha256(archive_bytes).hexdigest()!=self.pin.archive_sha256:
            raise RegistrySourceError("vendored archive SHA-256 does not match the pin")
        if _git_blob(archive_bytes) != self.pin.archive_git_blob:
            raise RegistrySourceError("vendored archive Git blob ID does not match the pin")
        files, modes = {}, {}
        expanded = 0
        try:
            with tarfile.open(fileobj=io.BytesIO(archive_bytes),mode="r:gz") as archive:
                for member in archive:
                    raw_name=member.name
                    name=raw_name[:-1] if member.isdir() and raw_name.endswith("/") else raw_name
                    path=PurePosixPath(name)
                    if (not name or path.is_absolute() or "\\" in name or any(part in {"","..","."} for part in path.parts)):
                        raise RegistrySourceError("vendored archive contains an unsafe path")
                    if name in files or name in modes: raise RegistrySourceError("vendored archive contains a duplicate path")
                    if member.isdir():
                        modes[name]=0o040000
                        continue
                    if not member.isfile() or member.mode & 0o7000:
                        raise RegistrySourceError("vendored snapshot contains a symlink or special file")
                    if member.mode & 0o777 not in {0o644,0o755}:
                        raise RegistrySourceError("vendored source file has an unexpected mode")
                    stream=archive.extractfile(member)
                    if stream is None: raise RegistrySourceError("vendored source file cannot be read")
                    data=stream.read(self.MAX_EXPANDED_BYTES+1)
                    expanded+=len(data)
                    if expanded>self.MAX_EXPANDED_BYTES: raise RegistrySourceError("vendored source exceeds expansion limit")
                    files[name]=data
                    modes[name]=member.mode & 0o777
        except RegistrySourceError:
            raise
        except (tarfile.TarError,OSError,EOFError):
            raise RegistrySourceError("vendored source archive is malformed") from None
        if len(files)!=self.pin.snapshot_file_count:
            raise RegistrySourceError("vendored source file count differs from the pinned commit")
        computed_tree, computed_roots = _git_tree(files, modes)
        if computed_tree != self.pin.git_tree or any(computed_roots.get(root) != tree for root, tree in self.pin.root_trees.items()):
            raise RegistrySourceError("vendored source Git tree IDs differ from the selected upstream commit")
        for root,count in self.pin.root_counts.items():
            entries=[path for path in files if path.startswith(root+"/")]
            if len(entries)!=count or any("/" in path[len(root)+1:] or not path.endswith(".yaml") for path in entries):
                raise RegistrySourceError(f"vendored catalog root differs from its pinned manifest set: {root}")
        if files.get("catalog.yaml") is None or _git_blob(files["catalog.yaml"])!=self.pin.catalog_blob:
            raise RegistrySourceError("vendored catalog document differs from the source pin")
        if files.get("QUALITY_POLICY.yaml") is None or _git_blob(files["QUALITY_POLICY.yaml"])!=self.pin.quality_policy_blob:
            raise RegistrySourceError("vendored quality policy differs from source pin")
        framed=hashlib.sha256()
        for name in sorted(files):
            path=name.encode(); blob=bytes.fromhex(_git_blob(files[name]))
            framed.update(len(path).to_bytes(4,"big")+path+len(blob).to_bytes(2,"big")+blob)
        file_modes = {path: modes[path] for path in files}
        return VerifiedSource(self.pin.repository,self.pin.commit,self.pin.git_tree,self.pin.catalog_version,
                              files,file_modes,framed.hexdigest())
