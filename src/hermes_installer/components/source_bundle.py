"""Fetch and stage complete pinned GitHub component source trees safely."""
from __future__ import annotations

import hashlib
import io
import json
import re
import tarfile
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Mapping, Protocol
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from hermes_installer.components.adapters import ComponentAdapterContract
from hermes_installer.components.skill_refs import audit_skill_file_map


class ComponentSourceError(RuntimeError):
    """A pinned component source could not be verified or safely staged."""


@dataclass(frozen=True, slots=True)
class HttpResponse:
    status: int
    url: str
    body: bytes


class SourceTransport(Protocol):
    def get(self, url: str, *, max_bytes: int, timeout_seconds: int) -> HttpResponse: ...


class UrllibSourceTransport:
    """TLS-verified unauthenticated transport for public immutable source archives."""

    def get(self, url: str, *, max_bytes: int, timeout_seconds: int) -> HttpResponse:
        request = Request(
            url,
            headers={
                "Accept": "application/vnd.github+json",
                "User-Agent": "HermesAgentInstaller/1",
            },
            method="GET",
        )
        with urlopen(request, timeout=timeout_seconds) as response:
            final_url = response.geturl()
            status = response.status
            body = response.read(max_bytes + 1)
        if len(body) > max_bytes:
            raise ComponentSourceError("upstream source archive exceeds the compressed size limit")
        return HttpResponse(status=status, url=final_url, body=body)


@dataclass(frozen=True, slots=True)
class VerifiedComponentSource:
    component_id: str
    source_identity: str
    revision: str
    files: Mapping[str, bytes]
    file_modes: Mapping[str, int]
    archive_sha256: str
    content_sha256: str
    license: str | None
    license_files: tuple[str, ...]
    redistribution_license_review_required: bool

    @property
    def generation_id(self) -> str:
        return f"component-{self.component_id}-{self.revision[:12]}"

    def stage(self, store):
        """Stage under the caller's existing installer mutation lock and journal."""
        target = store.root / self.generation_id
        if target.exists() or target.is_symlink():
            try:
                existing, manifest, _ = store._verify(self.generation_id)
            except Exception as exc:
                raise ComponentSourceError("existing component generation is not verified") from exc
            expected = {}
            for name, content in self.files.items():
                mode = store._private_mode(self.file_modes[name])
                expected[name] = {
                    "sha256": hashlib.sha256(content).hexdigest(),
                    "mode": mode,
                }
            if manifest.get("files") != expected:
                raise ComponentSourceError("pinned component generation conflicts with owned data")
            return existing
        return store.stage(self.generation_id, self.files, file_modes=self.file_modes)


class GitHubComponentSourceFetcher:
    def __init__(
        self,
        transport: SourceTransport | None = None,
        *,
        max_archive_bytes: int = 64 * 1024 * 1024,
        max_unpacked_bytes: int = 512 * 1024 * 1024,
        max_file_bytes: int = 64 * 1024 * 1024,
        max_files: int = 50000,
        timeout_seconds: int = 30,
    ):
        if min(max_archive_bytes, max_unpacked_bytes, max_file_bytes, max_files, timeout_seconds) <= 0:
            raise ValueError("source limits must be positive")
        self.transport = transport or UrllibSourceTransport()
        self.max_archive_bytes = max_archive_bytes
        self.max_unpacked_bytes = max_unpacked_bytes
        self.max_file_bytes = max_file_bytes
        self.max_files = max_files
        self.timeout_seconds = timeout_seconds

    @staticmethod
    def _identity(contract: ComponentAdapterContract) -> tuple[str, str]:
        identity, revision = contract.source_identity, contract.revision
        if not identity or not revision or not re.fullmatch(r"[a-f0-9]{40}", revision):
            raise ComponentSourceError("component source lacks a verified owner/repository and full commit")
        if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", identity):
            raise ComponentSourceError("component source identity is not an owner/repository")
        return identity, revision

    def fetch(self, contract: ComponentAdapterContract) -> VerifiedComponentSource:
        if contract.unresolved_reason():
            raise ComponentSourceError(contract.unresolved_reason())
        identity, revision = self._identity(contract)
        url = f"https://api.github.com/repos/{identity}/tarball/{revision}"
        try:
            response = self.transport.get(
                url, max_bytes=self.max_archive_bytes, timeout_seconds=self.timeout_seconds
            )
        except ComponentSourceError:
            raise
        except Exception as exc:
            raise ComponentSourceError("pinned component source download failed") from exc
        final = urlsplit(response.url)
        if final.scheme != "https" or final.hostname not in {"api.github.com", "codeload.github.com"}:
            raise ComponentSourceError("component archive redirected outside the approved GitHub hosts")
        if response.status != 200:
            raise ComponentSourceError(f"pinned component source returned HTTP {response.status}")
        if not response.body or len(response.body) > self.max_archive_bytes:
            raise ComponentSourceError("component archive is empty or exceeds the compressed size limit")

        files, modes = self._unpack(response.body, identity, revision)
        if not files:
            raise ComponentSourceError("refusing an empty component source tree")
        audit = audit_skill_file_map(files)
        if audit.problems:
            first = audit.problems[0]
            raise ComponentSourceError(
                f"broken skill reference in {first.source_path}:{first.line}: "
                f"{first.target!r} ({first.reason})"
            )

        archive_digest = hashlib.sha256(response.body).hexdigest()
        content_digest = hashlib.sha256()
        for name in sorted(files):
            content_digest.update(name.encode("utf-8") + b"\0")
            content_digest.update(f"{modes[name]:o}".encode("ascii") + b"\0")
            content_digest.update(hashlib.sha256(files[name]).digest())
        license_files = tuple(sorted(
            name for name in files
            if PurePosixPath(name).name.casefold().startswith(("license", "copying", "notice"))
        ))
        provenance = {
            "schema": 1,
            "component_id": contract.component_id,
            "source_identity": identity,
            "source_url": contract.selected_source_url,
            "revision": revision,
            "source_selection": contract.source_selection,
            "source_archive_sha256": archive_digest,
            "source_content_sha256": content_digest.hexdigest(),
            "declared_license": contract.license,
            "license_files": license_files,
            "redistribution_license_review_required": contract.redistribution_license_review_required,
        }
        provenance_name = "INSTALLER-SOURCE-PROVENANCE.json"
        if provenance_name in files:
            raise ComponentSourceError("source tree conflicts with the installer provenance filename")
        files[provenance_name] = (
            json.dumps(provenance, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
        )
        modes[provenance_name] = 0o644
        return VerifiedComponentSource(
            component_id=contract.component_id,
            source_identity=identity,
            revision=revision,
            files=files,
            file_modes=modes,
            archive_sha256=archive_digest,
            content_sha256=content_digest.hexdigest(),
            license=contract.license,
            license_files=license_files,
            redistribution_license_review_required=contract.redistribution_license_review_required,
        )

    def _unpack(self, archive: bytes, identity: str, revision: str) -> tuple[dict[str, bytes], dict[str, int]]:
        owner, repo = identity.split("/", 1)
        expected_prefix = f"{owner}-{repo}-".casefold()
        files: dict[str, bytes] = {}
        modes: dict[str, int] = {}
        root_name: str | None = None
        total_size = 0
        try:
            stream = tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz")
            with stream:
                members = stream.getmembers()
                if len(members) > self.max_files * 2:
                    raise ComponentSourceError("component archive has too many entries")
                for member in members:
                    raw_name = member.name
                    if not raw_name or "\x00" in raw_name or "\\" in raw_name:
                        raise ComponentSourceError("component archive contains an invalid path")
                    parts = raw_name.rstrip("/").split("/")
                    if not parts or any(part in {"", ".", ".."} for part in parts):
                        raise ComponentSourceError("component archive contains an unsafe path")
                    if root_name is None:
                        root_name = parts[0]
                        prefix_suffix = root_name[len(expected_prefix):] if root_name.casefold().startswith(expected_prefix) else ""
                        if len(prefix_suffix) < 7 or not re.fullmatch(r"[a-fA-F0-9]+", prefix_suffix):
                            raise ComponentSourceError("archive root does not match the pinned repository and commit")
                        if not revision.startswith(prefix_suffix.casefold()):
                            raise ComponentSourceError("archive root commit does not match the pinned revision")
                    if parts[0] != root_name:
                        raise ComponentSourceError("component archive contains more than one root")
                    relative_parts = parts[1:]
                    if not relative_parts:
                        if member.isdir():
                            continue
                        raise ComponentSourceError("archive root entry is not a directory")
                    relative = "/".join(relative_parts)
                    safe = PurePosixPath(relative)
                    if safe.is_absolute() or safe.as_posix() != relative:
                        raise ComponentSourceError("component archive path is not normalized")
                    if member.isdir():
                        continue
                    if member.issym() or member.islnk():
                        raise ComponentSourceError(f"component archive contains unsupported link: {relative}")
                    if not member.isfile():
                        raise ComponentSourceError(f"component archive contains a special file: {relative}")
                    if relative in files:
                        raise ComponentSourceError(f"component archive repeats path: {relative}")
                    if member.size < 0 or member.size > self.max_file_bytes:
                        raise ComponentSourceError(f"component source file exceeds limit: {relative}")
                    total_size += member.size
                    if total_size > self.max_unpacked_bytes:
                        raise ComponentSourceError("component source exceeds the unpacked size limit")
                    source = stream.extractfile(member)
                    if source is None:
                        raise ComponentSourceError(f"component source file cannot be read: {relative}")
                    body = source.read(self.max_file_bytes + 1)
                    if len(body) != member.size or len(body) > self.max_file_bytes:
                        raise ComponentSourceError(f"component source file length is inconsistent: {relative}")
                    files[relative] = body
                    modes[relative] = 0o755 if member.mode & 0o111 else 0o644
                    if len(files) > self.max_files:
                        raise ComponentSourceError("component source has too many files")
        except ComponentSourceError:
            raise
        except (OSError, tarfile.TarError, EOFError) as exc:
            raise ComponentSourceError("pinned component archive is invalid or truncated") from exc
        return files, modes
