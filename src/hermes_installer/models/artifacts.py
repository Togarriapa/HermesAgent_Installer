"""Pinned GLM-5.2 Colibri package identity and integrity metadata."""
from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

MODEL_ID = "mastouri/GLM-5.2-colibri-int4-g64-with-int8-mtp"
MODEL_REVISION = "6bbb01ed3e515a8730b694dfae73aadfd6774581"
MODEL_BYTES = 429_276_220_139
MODEL_SIZE_CLAIM = 429_276_080_522
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
GIT_SHA1_RE = re.compile(r"^[0-9a-f]{40}$")


class ArtifactError(ValueError):
    """The selected model does not match its reviewed artifact identity."""


@dataclass(frozen=True, slots=True)
class ArtifactFile:
    name: str
    size: int
    digest: str | None
    digest_algorithm: str | None
    url: str

    def verify(self, path: Path) -> None:
        if self.digest is None or self.digest_algorithm is None:
            raise ArtifactError(f"no verified digest is available for {self.name}; activation is blocked")
        if path.is_symlink() or not path.is_file():
            raise ArtifactError(f"model file is missing or unsafe: {self.name}")
        if path.stat().st_size != self.size:
            raise ArtifactError(f"model file size mismatch: {self.name}")
        hasher = hashlib.sha256() if self.digest_algorithm == "sha256" else hashlib.sha1()
        if self.digest_algorithm == "git-sha1":
            hasher.update(f"blob {self.size}\0".encode("ascii"))
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                hasher.update(block)
        if hasher.hexdigest() != self.digest:
            raise ArtifactError(f"model file digest mismatch: {self.name}")


@dataclass(frozen=True, slots=True)
class ArtifactManifest:
    model_id: str
    revision: str
    quantization: str
    mtp: str
    files: tuple[ArtifactFile, ...]
    declared_storage_bytes: int

    @property
    def total_bytes(self) -> int:
        return sum(item.size for item in self.files)

    @property
    def fingerprint(self) -> str:
        payload = {
            "model_id": self.model_id,
            "revision": self.revision,
            "files": [
                {"name": f.name, "size": f.size, "algorithm": f.digest_algorithm, "digest": f.digest}
                for f in self.files
            ],
        }
        return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

    @property
    def fully_verifiable(self) -> bool:
        return bool(self.files) and all(f.digest and f.digest_algorithm for f in self.files)

    @classmethod
    def from_metadata(cls, path: Path) -> "ArtifactManifest":
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ArtifactError(f"cannot read pinned model metadata: {exc}") from exc
        if raw.get("modelId") != MODEL_ID or raw.get("sha") != MODEL_REVISION:
            raise ArtifactError("GLM artifact identity or revision differs from the reviewed GLM-5.2 pin")
        tags = set(raw.get("tags", ()))
        if "license:mit" not in tags:
            raise ArtifactError("the pinned GLM-5.2 artifact does not declare the expected MIT license")
        if "GLM-5.2" not in raw.get("config", {}).get("architectures", [""])[0] and raw.get("config", {}).get("model_type") != "glm_moe_dsa":
            raise ArtifactError("the artifact configuration is not GLM-5.2 compatible")
        result: list[ArtifactFile] = []
        seen: set[str] = set()
        for sibling in raw.get("siblings", ()):
            name = sibling.get("rfilename", "")
            rel = PurePosixPath(name)
            if not name or rel.is_absolute() or ".." in rel.parts or "\\" in name or name in seen:
                raise ArtifactError(f"unsafe or duplicate path in model metadata: {name!r}")
            seen.add(name)
            size = sibling.get("lfs", {}).get("size", sibling.get("size"))
            if isinstance(size, bool) or not isinstance(size, int) or size < 0:
                raise ArtifactError(f"missing or invalid file size for {name}")
            lfs_sha = sibling.get("lfs", {}).get("sha256")
            blob = sibling.get("blobId")
            if lfs_sha is not None:
                if not SHA256_RE.fullmatch(str(lfs_sha)):
                    raise ArtifactError(f"invalid SHA-256 in pinned metadata for {name}")
                digest, algorithm = str(lfs_sha), "sha256"
            elif blob is not None and GIT_SHA1_RE.fullmatch(str(blob)):
                # Non-LFS siblings carry Git's typed blob SHA-1. Verify that exact algorithm;
                # never relabel it as SHA-256 or fabricate a missing checksum.
                digest, algorithm = str(blob), "git-sha1"
            else:
                digest, algorithm = None, None
            result.append(ArtifactFile(name, size, digest, algorithm,
                f"https://huggingface.co/{MODEL_ID}/resolve/{MODEL_REVISION}/{name}?download=true"))
        if len(result) != 149 or sum(item.size for item in result) != MODEL_BYTES:
            raise ArtifactError("the pinned GLM-5.2 file inventory or exact byte total has drifted")
        declared = raw.get("usedStorage")
        if declared != MODEL_SIZE_CLAIM:
            raise ArtifactError("the upstream package-size claim has changed; revalidate before selecting it")
        if not result or not any(item.name == "out-mtp-00000.safetensors" for item in result):
            raise ArtifactError("the required int8 MTP artifact is missing")
        return cls(MODEL_ID, MODEL_REVISION, "int4-group-scaled-g64", "int8", tuple(result), declared)

    def verify_directory(self, directory: Path) -> None:
        if not self.fully_verifiable:
            missing = next(f.name for f in self.files if not f.digest or not f.digest_algorithm)
            raise ArtifactError(f"no verified digest is available for {missing}; activation is blocked")
        for item in self.files:
            item.verify(directory / item.name)
        expected = {item.name for item in self.files}
        allowed = expected | {".hermes-model-generation.json"}
        observed: set[str] = set()
        for current, dirs, files in os.walk(directory, followlinks=False):
            current_path = Path(current)
            if any((current_path / name).is_symlink() for name in dirs):
                raise ArtifactError("model directory contains a symlinked subdirectory")
            for name in files:
                path = current_path / name
                if path.is_symlink() or not path.is_file():
                    raise ArtifactError("model directory contains a symlink or non-regular file")
                observed.add(path.relative_to(directory).as_posix())
        unexpected = observed - allowed
        missing = expected - observed
        if unexpected or missing:
            raise ArtifactError(f"model inventory differs from the pinned manifest (missing={len(missing)}, unexpected={len(unexpected)})")
