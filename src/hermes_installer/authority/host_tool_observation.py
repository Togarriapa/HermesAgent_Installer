"""Read-only root observation of finite, signed nftables host-tool variants.

No package is installed. The selected nft executable and its live dependency
closure are held by descriptor and rechecked against the current OS/package
database, distribution trust root and fresh signed archive metadata.
"""
from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import secrets
import shutil
import stat
import struct
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

from hermes_installer.authority.private_loopback_network import (
    RootResolvedHostTool, _SHA, _linux_root,
)
from hermes_installer.authority.types import AuthorityDenied


CATALOG_ID = "installer-private-loopback-nft-tool-variants-v2"
CATALOG_SHA256 = "cff8290d93cd03a7ccf383e48f8867ae9c144d22c8763f5d32b72b4547217b51"
CATALOG_SIZE = 3491
CATALOG_PATH = Path(__file__).resolve().parents[3] / "templates" / "nft-tool-variants-v2.json"
INSTALLED_NFT = Path("/usr/sbin/nft")
OBSERVATION_ROOT = Path("/run/hermes-installer/host-tool-observations")
_VARIANT_ID = re.compile(r"nft-[A-Za-z0-9_.-]{1,120}\Z")
_PACKAGE_LINE = re.compile(r"^([^:]+):\s+(.+)$")
_MAX_TOOL_OUTPUT = 64 * 1024
_MAX_ELF_BYTES = 128 * 1024 * 1024
_MAX_LEASE_SECONDS = 30.0
_SIGNERS = {
    "ubuntu": {"F6ECB3762474EDA9D21B7022871920D1991BC93C"},
    "debian": {
        "04B54C3CDCA79751B16BC6B5225629DF75B188BD",
        "5E04A1E3223A19A20706E20F9904613D4CCE68C6",
        "41587F7DB8C774BCCF131416762F67A0B2C39DE4",
    },
}


class HostToolObservationDenied(AuthorityDenied):
    """Selected host nft tool could not be proven from current signed packages."""


def _read_bounded(path: Path, limit: int) -> bytes:
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise HostToolObservationDenied("host_tool.catalog", "protected host-tool catalog is not a bounded regular file")
        chunks: list[bytes] = []
        remain = info.st_size
        while remain:
            chunk = os.read(fd, min(remain, 64 * 1024))
            if not chunk:
                raise HostToolObservationDenied("host_tool.catalog", "protected host-tool catalog changed during read")
            chunks.append(chunk)
            remain -= len(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)


def _platform() -> tuple[str, str, str]:
    try:
        release = Path("/etc/os-release").read_text(encoding="utf-8")
        values = {}
        for line in release.splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                values[key] = value.strip().strip('"')
    except OSError:
        raise HostToolObservationDenied("host_tool.platform", "current Linux distribution identity is unavailable") from None
    architecture = {"x86_64": "amd64", "aarch64": "arm64"}.get(platform.machine(), "")
    distribution = values.get("ID", "")
    version = values.get("VERSION_ID", "")
    if os.name != "posix" or not architecture or distribution not in {"debian", "ubuntu"} or not version:
        raise HostToolObservationDenied("host_tool.platform", "host platform has no finite measured nft tool variant")
    return distribution, version, architecture


def _run(argv: list[str], *, env: Mapping[str, str], cwd: Path | None = None,
         input_bytes: bytes | None = None, timeout: float = 120.0) -> bytes:
    try:
        process = subprocess.run(
            argv, input=input_bytes, cwd=cwd, env=dict(env), stdin=subprocess.DEVNULL if input_bytes is None else None,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True, shell=False,
            timeout=timeout, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise HostToolObservationDenied("host_tool.command", "fixed host package observation command failed") from None
    if (process.returncode != 0 or len(process.stdout) > _MAX_TOOL_OUTPUT
            or len(process.stderr) > _MAX_TOOL_OUTPUT):
        raise HostToolObservationDenied("host_tool.command", "fixed host package observation command was rejected")
    return process.stdout


def _sha_fd(fd: int) -> str:
    digest = hashlib.sha256()
    offset = 0
    while True:
        chunk = os.pread(fd, 1024 * 1024, offset)
        if not chunk:
            break
        digest.update(chunk)
        offset += len(chunk)
    return digest.hexdigest()


def _owned_regular(path: Path, *, expected_sha256: str | None = None) -> tuple[int, os.stat_result]:
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
        info = os.fstat(fd)
    except OSError:
        raise HostToolObservationDenied("host_tool.file", "selected root package member is unavailable") from None
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022
            or (expected_sha256 is not None and _sha_fd(fd) != expected_sha256)):
        os.close(fd)
        raise HostToolObservationDenied("host_tool.file", "selected root package member changed or is not root-owned")
    return fd, info


def _apt_configuration(distribution: str, architecture: str, directory: Path) -> tuple[Path, Path]:
    """Create fixed official archive sources, rooted only in the private state dir."""
    sources = directory / "sources.list"
    lists = directory / "lists"
    lists.mkdir(mode=0o700)
    (lists / "partial").mkdir(mode=0o700)
    if distribution == "debian":
        if architecture != "arm64":
            raise HostToolObservationDenied("host_tool.platform", "Debian nft tool is pinned only for arm64")
        keyring = Path("/usr/share/keyrings/debian-archive-keyring.gpg")
        lines = [f"deb [arch=arm64 signed-by={keyring}] https://deb.debian.org/debian trixie main",
                 f"deb [arch=arm64 signed-by={keyring}] https://security.debian.org/debian-security trixie-security main"]
        if Path("/usr/share/keyrings/debian-archive-keyring.gpg").exists() is False:
            raise HostToolObservationDenied("host_tool.keyring", "official Debian archive keyring is unavailable")
    else:
        keyring = Path("/usr/share/keyrings/ubuntu-archive-keyring.gpg")
        archive = "https://ports.ubuntu.com/ubuntu-ports" if architecture == "arm64" else "https://archive.ubuntu.com/ubuntu"
        lines = [f"deb [arch={architecture} signed-by={keyring}] {archive} noble main",
                 f"deb [arch={architecture} signed-by={keyring}] {archive} noble-updates main",
                 f"deb [arch={architecture} signed-by={keyring}] https://security.ubuntu.com/ubuntu noble-security main"]
        if Path("/usr/share/keyrings/ubuntu-archive-keyring.gpg").exists() is False:
            raise HostToolObservationDenied("host_tool.keyring", "official Ubuntu archive keyring is unavailable")
    key_fd, _key_info = _owned_regular(keyring)
    os.close(key_fd)
    fd = os.open(sources, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        os.write(fd, ("\n".join(lines) + "\n").encode("ascii"))
        os.fsync(fd)
    finally:
        os.close(fd)
    return sources, lists


def _apt_options(sources: Path, lists: Path, directory: Path, architecture: str) -> list[str]:
    return [
        "-o", "Dir::Etc::sourcelist=" + str(sources),
        "-o", "Dir::Etc::sourceparts=-",
        "-o", "Dir::State::lists=" + str(lists) + "/",
        "-o", "Dir::State::status=/var/lib/dpkg/status",
        "-o", "Dir::Cache::archives=" + str(directory / "archives") + "/",
        "-o", "Dir::Cache::pkgcache=" + str(directory / "pkgcache.bin"),
        "-o", "Dir::Cache::srcpkgcache=" + str(directory / "srcpkgcache.bin"),
        "-o", "APT::Architecture=" + architecture,
        "-o", "APT::Architectures::=" + architecture,
        "-o", "APT::Get::AllowUnauthenticated=false",
        "-o", "Acquire::Languages=none",
    ]


def _installed_package(package: str, architecture: str, *, env: Mapping[str, str]) -> str:
    raw = _run(["/usr/bin/dpkg-query", "-W", "-f=${Version}\t${Architecture}\t${db:Status-Abbrev}", package], env=env)
    fields = raw.decode("utf-8", "strict").split("\t")
    if len(fields) != 3 or fields[1] not in (architecture, "all") or not fields[2].startswith("ii"):
        raise HostToolObservationDenied("host_tool.package", "required package is not installed for the selected architecture")
    return fields[0]


def _elf_dynamic(path: Path) -> tuple[str | None, tuple[str, ...]]:
    """Read ELF interpreter/DT_NEEDED without executing the package binary."""
    if path.stat().st_size > _MAX_ELF_BYTES:
        raise HostToolObservationDenied("host_tool.elf", "host package ELF exceeds the fixed file bound")
    body = path.read_bytes()
    if len(body) < 64 or body[:4] != b"\x7fELF" or body[5] not in (1, 2):
        raise HostToolObservationDenied("host_tool.elf", "host package dependency is not a supported ELF file")
    endian = "<" if body[5] == 1 else ">"
    elf_class = body[4]
    if elf_class == 2:
        phoff = struct.unpack_from(endian + "Q", body, 32)[0]
        phentsize, phnum = struct.unpack_from(endian + "HH", body, 54)
        ph_format, dyn_format, word = endian + "IIQQQQQQ", endian + "qQ", 8
    elif elf_class == 1:
        phoff = struct.unpack_from(endian + "I", body, 28)[0]
        phentsize, phnum = struct.unpack_from(endian + "HH", body, 42)
        ph_format, dyn_format, word = endian + "IIIIIIII", endian + "iI", 4
    else:
        raise HostToolObservationDenied("host_tool.elf", "host package ELF class is unsupported")
    if phnum > 4096 or phentsize < struct.calcsize(ph_format) or phoff + phnum * phentsize > len(body):
        raise HostToolObservationDenied("host_tool.elf", "host package ELF program headers exceed bounds")
    segments: list[tuple[int, int, int, int]] = []
    interp = None
    dynamic: tuple[int, int] | None = None
    for index in range(phnum):
        values = struct.unpack_from(ph_format, body, phoff + index * phentsize)
        if elf_class == 2:
            kind, _flags, offset, vaddr, _paddr, filesz, _memsz, _align = values
        else:
            kind, offset, vaddr, _paddr, filesz, _memsz, _flags, _align = values
        if offset + filesz > len(body):
            raise HostToolObservationDenied("host_tool.elf", "host package ELF segment exceeds bounds")
        if kind == 1:
            segments.append((vaddr, vaddr + filesz, offset, filesz))
        elif kind == 2:
            dynamic = (offset, filesz)
        elif kind == 3:
            raw = body[offset:offset + filesz].split(b"\0", 1)[0]
            try:
                interp = raw.decode("ascii")
            except UnicodeDecodeError:
                raise HostToolObservationDenied("host_tool.elf", "ELF interpreter path is malformed") from None
    needed_offsets: list[int] = []
    string_table = string_size = None
    if dynamic is not None:
        offset, size = dynamic
        entry_size = struct.calcsize(dyn_format)
        if size > 4 * 1024 * 1024 or size % entry_size:
            raise HostToolObservationDenied("host_tool.elf", "host package ELF dynamic table exceeds bounds")
        for position in range(offset, offset + size, entry_size):
            tag, value = struct.unpack_from(dyn_format, body, position)
            if tag == 0:
                break
            if tag == 1:
                needed_offsets.append(value)
            elif tag == 5:
                string_table = value
            elif tag == 10:
                string_size = value
            elif tag in (15, 29):  # DT_RPATH / DT_RUNPATH: never honor worker-controlled lookup paths.
                raise HostToolObservationDenied("host_tool.elf", "host package ELF has an unreviewed runtime search path")
    if not needed_offsets:
        return interp, ()
    if string_table is None or string_size is None or string_size > len(body):
        raise HostToolObservationDenied("host_tool.elf", "host package ELF lacks a bounded dynamic string table")
    string_offset = next((fileoff + (string_table - start) for start, end, fileoff, _size in segments
                          if start <= string_table < end), None)
    if string_offset is None or string_offset + string_size > len(body):
        raise HostToolObservationDenied("host_tool.elf", "host package ELF dynamic strings are not file-backed")
    names: list[str] = []
    for position in needed_offsets:
        if position >= string_size:
            raise HostToolObservationDenied("host_tool.elf", "host package ELF dependency string is out of range")
        raw = body[string_offset + position:string_offset + string_size].split(b"\0", 1)[0]
        try:
            name = raw.decode("ascii")
        except UnicodeDecodeError:
            raise HostToolObservationDenied("host_tool.elf", "host package ELF dependency name is malformed") from None
        if not re.fullmatch(r"[A-Za-z0-9_.+-]{1,256}", name):
            raise HostToolObservationDenied("host_tool.elf", "host package ELF dependency name is invalid")
        names.append(name)
    return interp, tuple(names)


def _elf_dependency_closure(binary: Path, *, architecture: str, env: Mapping[str, str],
                            expected: Mapping[str, str]) -> tuple[str, tuple[tuple[str, int, int, str], ...]]:
    """Resolve a bounded ELF closure from distro library roots without ldd."""
    triplet = {"amd64": "x86_64-linux-gnu", "arm64": "aarch64-linux-gnu"}[architecture]
    roots = tuple(Path(item) for item in (f"/lib/{triplet}", f"/usr/lib/{triplet}", "/lib", "/usr/lib"))
    pending = [binary]
    seen: set[Path] = set()
    while pending:
        current = pending.pop()
        real = current.resolve(strict=True)
        if real in seen:
            continue
        seen.add(real)
        if len(seen) > 4096:
            raise HostToolObservationDenied("host_tool.dependencies", "ELF dependency closure exceeds its fixed file bound")
        interpreter, needed = _elf_dynamic(real)
        names = list(needed)
        if interpreter is not None:
            names.append(interpreter)
        for name in names:
            if name.startswith("/"):
                candidate = Path(name)
                candidates = (candidate,)
            else:
                candidates = tuple(root / name for root in roots)
            match = None
            for candidate in candidates:
                try:
                    resolved = candidate.resolve(strict=True)
                    if any(resolved == root or root in resolved.parents for root in roots):
                        match = resolved
                        break
                except OSError:
                    continue
            if match is None:
                raise HostToolObservationDenied("host_tool.dependencies", "ELF dependency is absent from fixed distro library roots")
            pending.append(match)
    rows: list[dict[str, Any]] = []
    identities: list[tuple[str, int, int, str]] = []
    for path in sorted(seen):
        fd, info = _owned_regular(path)
        try:
            digest = _sha_fd(fd)
            owner = _run(["/usr/bin/dpkg-query", "-S", str(path)], env=env).decode("utf-8", "strict").strip()
            match = _PACKAGE_LINE.fullmatch(owner)
            if match is None:
                raise HostToolObservationDenied("host_tool.dependencies", "runtime ELF member has no exact dpkg package owner")
            package_name = match.group(1).split(":", 1)[0]
            package_version = _installed_package(package_name, architecture, env=env)
            rows.append({"path": str(path), "sha256": digest, "package": package_name,
                         "version": package_version, "device": info.st_dev, "inode": info.st_ino})
            identities.append((str(path), info.st_dev, info.st_ino, digest))
        finally:
            os.close(fd)
    for package, constraint in expected.items():
        version = _installed_package(package, architecture, env=env)
        operator, required = ("=", constraint[1:]) if constraint.startswith("=") else (">=", constraint[2:])
        _run(["/usr/bin/dpkg", "--compare-versions", version, operator, required], env=env)
    canonical = json.dumps(rows, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest(), tuple(identities)


@dataclass(frozen=True, slots=True, repr=False)
class VerifiedHostToolPackageObservation:
    observation_handle: str
    network_key: tuple[str, str, str]
    variant: Mapping[str, Any]
    package_set_receipt_handle: str
    dependency_closure_sha256: str
    executable_fd: int = field(repr=False)
    executable_device: int
    executable_inode: int
    dependency_files: tuple[tuple[str, int, int, str], ...]
    held_fds: tuple[tuple[str, int, int, int, int, str], ...]
    source_file_hashes: tuple[tuple[str, str], ...]
    keyring_identity: tuple[int, int, str]
    workspace: Path = field(repr=False)
    observed_monotonic: float
    expires_monotonic: float

    def __repr__(self) -> str:
        return "VerifiedHostToolPackageObservation(<root-current>)"


class HostToolObservationRegistry:
    """Root-only one-use producer and resolver for measured nft host tools."""

    def __init__(self, *, variants: tuple[Mapping[str, Any], ...], release_receipt: Any,
                 root_journal: Any, allow_fixture_release: bool = False):
        _linux_root()
        self._variants = variants
        self._release = release_receipt
        self._journal = root_journal
        self._allow_fixture_release = allow_fixture_release
        self._observations: dict[str, VerifiedHostToolPackageObservation] = {}
        self._catalog_fd = -1
        self._closed = False

    @classmethod
    def from_root_runtime(cls, verified_installer_release: Any,
                          selected_host_tool_variant_catalog: str,
                          root_journal: Any) -> "HostToolObservationRegistry":
        """Bind the catalog to the held signed release before any host query."""
        from hermes_installer.authority.installer_release import VerifiedInstallerReleaseReceipt
        from hermes_installer.state import Journal

        if (not isinstance(verified_installer_release, VerifiedInstallerReleaseReceipt)
                or selected_host_tool_variant_catalog != CATALOG_ID or not isinstance(root_journal, Journal)):
            raise HostToolObservationDenied("host_tool.registry", "verified root release, fixed tool catalog and protected journal are required")
        verified_installer_release.verify_current()
        fd = verified_installer_release.open_file(CATALOG_ID)
        try:
            info = os.fstat(fd)
            body = os.read(fd, CATALOG_SIZE + 1)
            if info.st_size != CATALOG_SIZE or hashlib.sha256(body).hexdigest() != CATALOG_SHA256:
                raise HostToolObservationDenied("host_tool.catalog", "root release nft variant catalog differs from its pin")
            value = json.loads(body)
            if (not isinstance(value, dict) or value.get("artifact_id") != CATALOG_ID
                    or value.get("schema") != 1 or not isinstance(value.get("variants"), list)):
                raise HostToolObservationDenied("host_tool.catalog", "root release nft variant catalog is malformed")
            variants = tuple(row for row in value["variants"] if isinstance(row, dict))
        finally:
            os.close(fd)
        registry = cls(variants=variants, release_receipt=verified_installer_release,
                       root_journal=root_journal)
        registry._catalog_fd = verified_installer_release.open_file(CATALOG_ID)
        return registry

    @classmethod
    def for_linux_fixture(cls) -> "HostToolObservationRegistry":
        """CI-only construction; still performs signed package and installed-byte verification."""
        body = _read_bounded(CATALOG_PATH, CATALOG_SIZE)
        if hashlib.sha256(body).hexdigest() != CATALOG_SHA256:
            raise HostToolObservationDenied("host_tool.catalog", "CI fixture catalog differs from its pin")
        variants = tuple(json.loads(body)["variants"])
        return cls(variants=variants, release_receipt=None, root_journal=None, allow_fixture_release=True)

    def observe_selected_nft_tool(self, selected_network_binding: Any) -> str:
        if self._closed or (self._release is None and not self._allow_fixture_release):
            raise HostToolObservationDenied("host_tool.registry", "root host-tool observation authority is unavailable")
        from hermes_installer.authority.private_loopback_network import PrivateLoopbackNetwork

        if not isinstance(selected_network_binding, PrivateLoopbackNetwork):
            raise HostToolObservationDenied("host_tool.selection", "protected selected network binding is required")
        if self._release is not None:
            try:
                self._release.verify_current()
            except Exception:
                raise HostToolObservationDenied("host_tool.release", "verified installer release changed") from None
        distribution, version, architecture = _platform()
        variant = next((row for row in self._variants
                        if row.get("distribution") == distribution and row.get("architecture") == architecture
                        and row.get("release") == version and row.get("executable_sha256")), None)
        if (variant is None or not _VARIANT_ID.fullmatch(str(variant.get("id", "")))
                or variant.get("package_name") != "nftables" or variant.get("executable_member") != "usr/sbin/nft"):
            raise HostToolObservationDenied("host_tool.variant", "current OS has no exact executable-measured nft variant")
        parent = OBSERVATION_ROOT.parent
        try:
            parent_info = parent.lstat()
            if (not stat.S_ISDIR(parent_info.st_mode) or parent_info.st_uid != 0 or parent_info.st_mode & 0o022):
                raise OSError("runtime parent is not root-protected")
            OBSERVATION_ROOT.mkdir(mode=0o700, exist_ok=True)
            observation_root_info = OBSERVATION_ROOT.lstat()
            if (not stat.S_ISDIR(observation_root_info.st_mode) or observation_root_info.st_uid != 0
                    or stat.S_IMODE(observation_root_info.st_mode) != 0o700):
                raise OSError("observation root is not protected")
            workspace = Path(os.path.realpath(OBSERVATION_ROOT)) / secrets.token_hex(16)
            workspace.mkdir(mode=0o700)
        except OSError:
            raise HostToolObservationDenied("host_tool.workspace", "private package observation workspace is unavailable") from None
        env = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C", "APT_CONFIG": "/dev/null"}
        opened_fd = -1
        held_fds: list[tuple[str, int, int, int, int, str]] = []
        try:
            sources, lists = _apt_configuration(distribution, architecture, workspace)
            options = _apt_options(sources, lists, workspace, architecture)
            _run(["/usr/bin/apt-get", *options, "update"], env=env, timeout=300)
            archives = workspace / "archives"
            archives.mkdir(mode=0o700)
            package = workspace / "nftables.deb"
            package_spec = f"nftables:{architecture}={variant['version']}"
            _run(["/usr/bin/apt-get", *options, "download", package_spec], env=env, cwd=workspace, timeout=180)
            candidates = tuple(workspace.glob("nftables_*.deb"))
            if len(candidates) != 1:
                raise HostToolObservationDenied("host_tool.package", "signed archive did not yield one selected nft package")
            downloaded = candidates[0]
            deb_fd, deb_info = _owned_regular(downloaded, expected_sha256=variant["package_sha256"])
            try:
                if deb_info.st_size != variant["package_size_bytes"]:
                    raise HostToolObservationDenied("host_tool.package", "downloaded nft package size differs from its pin")
            finally:
                os.close(deb_fd)
            installed_version = _installed_package("nftables", architecture, env=env)
            if installed_version != variant["version"]:
                raise HostToolObservationDenied("host_tool.package", "installed nft package differs from the signed selected variant")
            package_info = _run(["/usr/bin/dpkg-deb", "-f", str(downloaded), "Package", "Version", "Architecture"], env=env).decode("utf-8", "strict").splitlines()
            if package_info != ["nftables", variant["version"], architecture]:
                raise HostToolObservationDenied("host_tool.package", "signed nft archive metadata differs from the selected platform")
            extracted = workspace / "extract"
            extracted.mkdir(mode=0o700)
            _run(["/usr/bin/dpkg-deb", "-x", str(downloaded), str(extracted)], env=env, timeout=30)
            package_member_fd, _member_info = _owned_regular(
                extracted / "usr/sbin/nft", expected_sha256=variant["executable_sha256"],
            )
            os.close(package_member_fd)
            owner = _run(["/usr/bin/dpkg-query", "-S", str(INSTALLED_NFT)], env=env).decode("utf-8", "strict").strip()
            if owner != "nftables: /usr/sbin/nft":
                raise HostToolObservationDenied("host_tool.package", "installed nft executable is not owned by the selected package")
            opened_fd, executable_info = _owned_regular(INSTALLED_NFT, expected_sha256=variant["executable_sha256"])
            dependency_sha256, dependency_files = _elf_dependency_closure(
                INSTALLED_NFT, architecture=architecture, env=env,
                expected=variant.get("dependency_requirements", {}),
            )
            index_rows = []
            source_file_hashes = [(str(downloaded), variant["package_sha256"])]
            for inrelease in sorted(lists.glob("*InRelease")):
                status = _run([
                    "/usr/bin/gpgv", "--status-fd=1", "--keyring", str(keyring), str(inrelease)
                ], env=env)
                valid = [line.split()[2].decode("ascii").upper() for line in status.splitlines()
                         if len(line.split()) > 2 and b"[GNUPG:] VALIDSIG " in line]
                if not valid or not any(fingerprint in _SIGNERS[distribution] for fingerprint in valid):
                    raise HostToolObservationDenied("host_tool.signature", "archive InRelease signer is outside the pinned official set")
                expiry_text = _run([
                    "/usr/bin/grep", "^Valid-Until:", str(inrelease)
                ], env=env).decode("ascii", "strict").strip()
                if not expiry_text:
                    raise HostToolObservationDenied("host_tool.index", "signed index has no freshness bound")
                index_fd, info = _owned_regular(inrelease)
                try:
                    index_digest = _sha_fd(index_fd)
                    index_rows.append({"name": inrelease.name, "sha256": index_digest, "size": info.st_size,
                                       "signer_fingerprints": valid, "valid_until": expiry_text})
                    source_file_hashes.append((str(inrelease), index_digest))
                    held_fds.append((str(inrelease), os.dup(index_fd), info.st_dev, info.st_ino,
                                     info.st_uid, index_digest))
                finally:
                    os.close(index_fd)
            if not index_rows:
                raise HostToolObservationDenied("host_tool.index", "signed archive InRelease metadata was not retained")
            handle = "host-nft-observation:" + secrets.token_hex(24)
            network_key = (selected_network_binding.network_id, selected_network_binding.generation,
                           selected_network_binding.service_generation_digest)
            keyring_path = Path("/usr/share/keyrings/debian-archive-keyring.gpg" if distribution == "debian"
                                else "/usr/share/keyrings/ubuntu-archive-keyring.gpg")
            keyring_fd, keyring_info = _owned_regular(keyring_path)
            try:
                keyring_identity = (keyring_info.st_dev, keyring_info.st_ino, _sha_fd(keyring_fd))
                held_fds.append((str(keyring_path), os.dup(keyring_fd), keyring_info.st_dev,
                                 keyring_info.st_ino, keyring_info.st_uid, keyring_identity[2]))
            finally:
                os.close(keyring_fd)
            status_path = Path("/var/lib/dpkg/status")
            status_fd, status_info = _owned_regular(status_path)
            try:
                status_digest = _sha_fd(status_fd)
                held_fds.append((str(status_path), os.dup(status_fd), status_info.st_dev,
                                 status_info.st_ino, status_info.st_uid, status_digest))
            finally:
                os.close(status_fd)
            # Retain every actual ELF object (including loader and interpreter),
            # not merely the top-level executable, for the full observation lease.
            for dependency_path, device, inode, digest in dependency_files:
                dep_fd, dep_info = _owned_regular(Path(dependency_path), expected_sha256=digest)
                held_fds.append((dependency_path, dep_fd, device, inode, dep_info.st_uid, digest))
            observation = VerifiedHostToolPackageObservation(
                handle, network_key, dict(variant), handle, dependency_sha256,
                opened_fd, executable_info.st_dev, executable_info.st_ino, dependency_files,
                tuple(held_fds),
                tuple(source_file_hashes), keyring_identity,
                workspace, time.monotonic(), time.monotonic() + _MAX_LEASE_SECONDS,
            )
            if self._journal is not None:
                self._journal.event("private-loopback-host-tool", "observe", "verified", {
                    "observation_handle": handle, "variant_id": variant["id"],
                    "package_sha256": variant["package_sha256"],
                    "executable_sha256": variant["executable_sha256"],
                    "dependency_closure_sha256": dependency_sha256,
                })
            self._observations[handle] = observation
            return handle
        except BaseException:
            if opened_fd >= 0:
                os.close(opened_fd)
            for _path, held_fd, *_rest in held_fds:
                try:
                    os.close(held_fd)
                except OSError:
                    pass
            shutil.rmtree(workspace, ignore_errors=True)
            raise

    def resolve_selected_nft_tool(self, observation_handle: str,
                                  selected_network_binding: Any) -> RootResolvedHostTool:
        from hermes_installer.authority.private_loopback_network import PrivateLoopbackNetwork

        observation = self._observations.get(observation_handle)
        if (not isinstance(observation, VerifiedHostToolPackageObservation)
                or not isinstance(selected_network_binding, PrivateLoopbackNetwork)
                or observation.network_key != (selected_network_binding.network_id,
                    selected_network_binding.generation, selected_network_binding.service_generation_digest)):
            raise HostToolObservationDenied("host_tool.observation", "current nft package observation does not belong to this selected network")
        if time.monotonic() >= observation.expires_monotonic:
            self.revoke_observation(observation_handle)
            raise HostToolObservationDenied("host_tool.expired", "current nft package observation expired")
        variant = observation.variant
        tool = RootResolvedHostTool(
            variant["id"], variant["package_name"], variant["version"], variant["distribution"],
            variant["release"], variant["architecture"], variant["package_sha256"],
            "nft-executable:" + variant["id"], variant["executable_sha256"],
            observation.dependency_closure_sha256, observation.package_set_receipt_handle,
            observation.expires_monotonic, INSTALLED_NFT, os.dup(observation.executable_fd),
            observation.executable_device, observation.executable_inode,
            self, observation_handle, observation.network_key,
        )
        return tool

    def revalidate_current(self, observation_handle: str,
                           network_key: tuple[str, str, str] | None = None) -> None:
        observation = self._observations.get(observation_handle)
        if (not isinstance(observation, VerifiedHostToolPackageObservation)
                or self._closed or time.monotonic() >= observation.expires_monotonic
                or (network_key is not None and network_key != observation.network_key)):
            raise HostToolObservationDenied("host_tool.expired", "held nft host package observation is no longer current")
        try:
            if self._release is not None:
                self._release.verify_current()
            info = os.fstat(observation.executable_fd)
            current = INSTALLED_NFT.stat(follow_symlinks=False)
            if ((info.st_dev, info.st_ino) != (observation.executable_device, observation.executable_inode)
                    or (current.st_dev, current.st_ino) != (observation.executable_device, observation.executable_inode)
                    or _sha_fd(observation.executable_fd) != observation.variant["executable_sha256"]):
                raise OSError("installed nft identity changed")
            env = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C", "APT_CONFIG": "/dev/null"}
            distribution, version, architecture = _platform()
            if (distribution != observation.variant["distribution"]
                    or version != observation.variant["release"]
                    or architecture != observation.variant["architecture"]
                    or _installed_package("nftables", architecture, env=env) != observation.variant["version"]):
                raise OSError("installed nft package identity changed")
            owner = _run(["/usr/bin/dpkg-query", "-S", str(INSTALLED_NFT)], env=env).decode("utf-8", "strict").strip()
            if owner != "nftables: /usr/sbin/nft":
                raise OSError("installed nft ownership changed")
            distribution = observation.variant["distribution"]
            keyring_path = Path("/usr/share/keyrings/debian-archive-keyring.gpg" if distribution == "debian"
                                else "/usr/share/keyrings/ubuntu-archive-keyring.gpg")
            keyring_fd, keyring_info = _owned_regular(keyring_path)
            try:
                if (keyring_info.st_dev, keyring_info.st_ino, _sha_fd(keyring_fd)) != observation.keyring_identity:
                    raise OSError("distribution trust keyring changed")
            finally:
                os.close(keyring_fd)
            for raw_path, expected_hash in observation.source_file_hashes:
                source_fd, _source_info = _owned_regular(Path(raw_path), expected_sha256=expected_hash)
                os.close(source_fd)
            for raw_path, held_fd, device, inode, uid, digest in observation.held_fds:
                held_info = os.fstat(held_fd)
                path_info = Path(raw_path).stat(follow_symlinks=False)
                if ((held_info.st_dev, held_info.st_ino, held_info.st_uid) != (device, inode, uid)
                        or (path_info.st_dev, path_info.st_ino, path_info.st_uid) != (device, inode, uid)
                        or uid != 0 or held_info.st_mode & 0o022 or _sha_fd(held_fd) != digest):
                    raise OSError("held host tool evidence changed")
            dependency_hash, dependency_files = _elf_dependency_closure(
                INSTALLED_NFT, architecture=architecture,
                env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C", "APT_CONFIG": "/dev/null"},
                expected=observation.variant.get("dependency_requirements", {}),
            )
            if dependency_hash != observation.dependency_closure_sha256 or dependency_files != observation.dependency_files:
                raise OSError("nft runtime dependency closure changed")
        except Exception:
            raise HostToolObservationDenied("host_tool.current", "current root nft package or dependency proof changed") from None

    def revoke_observation(self, observation_handle: str) -> None:
        observation = self._observations.pop(observation_handle, None)
        if observation is None:
            return
        os.close(observation.executable_fd)
        for _path, fd, *_rest in observation.held_fds:
            os.close(fd)
        shutil.rmtree(observation.workspace, ignore_errors=True)

    def close(self) -> None:
        if self._closed:
            return
        for handle in tuple(self._observations):
            self.revoke_observation(handle)
        if self._catalog_fd >= 0:
            os.close(self._catalog_fd)
            self._catalog_fd = -1
        self._closed = True
