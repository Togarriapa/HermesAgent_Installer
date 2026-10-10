"""Read-only root observation of finite, signed nftables host-tool variants.

No package is installed. The selected nft executable and its live dependency
closure are held by descriptor and rechecked against the current OS/package
database, distribution trust root and fresh signed archive metadata.
"""
from __future__ import annotations

import hashlib
import io
import json
import lzma
import os
import platform
import re
import secrets
import shutil
import stat
import struct
import subprocess
import time
from datetime import timezone
from email.utils import parsedate_to_datetime
import urllib.error
import urllib.parse
import urllib.request
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
_PACKAGE_LINE = re.compile(r"^([^:]+)(?::[^:]+)?:\s+(.+)$")
_MAX_TOOL_OUTPUT = 64 * 1024
_MAX_ELF_BYTES = 128 * 1024 * 1024
_MAX_LEASE_SECONDS = 30.0
_MAX_METADATA_BYTES = 64 * 1024 * 1024
_MAX_INDEX_EXPANDED_BYTES = 512 * 1024 * 1024
_MAX_PACKAGE_BYTES = 128 * 1024 * 1024
_SIGNERS = {
    "ubuntu": {"F6ECB3762474EDA9D21B7022871920D1991BC93C"},
    "debian": {
        "04B54C3CDCA79751B16BC6B5225629DF75B188BD",
        "5E04A1E3223A19A20706E20F9904613D4CCE68C6",
        "41587F7DB8C774BCCF131416762F67A0B2C39DE4",
    },
}


def _keyring_path(distribution: str) -> Path:
    return Path("/usr/share/keyrings/debian-archive-keyring.pgp" if distribution == "debian"
                else "/usr/share/keyrings/ubuntu-archive-keyring.gpg")


class _NoCrossOriginRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        before, after = urllib.parse.urlsplit(request.full_url), urllib.parse.urlsplit(new_url)
        if (before.scheme != "https" or after.scheme != "https" or before.hostname != after.hostname
                or after.username or after.password or after.port not in (None, 443)):
            raise HostToolObservationDenied("host_tool.origin", "archive redirected outside its exact HTTPS origin")
        return super().redirect_request(request, response, code, message, headers, new_url)


def _repositories(distribution: str, architecture: str) -> tuple[tuple[str, str, str], ...]:
    if distribution == "debian" and architecture == "arm64":
        return (("https://deb.debian.org/debian", "trixie", "debian"),
                ("https://security.debian.org/debian-security", "trixie-security", "debian"))
    if distribution == "ubuntu" and architecture in {"amd64", "arm64"}:
        main = "https://ports.ubuntu.com/ubuntu-ports" if architecture == "arm64" else "https://archive.ubuntu.com/ubuntu"
        return ((main, "noble", "ubuntu"), (main, "noble-updates", "ubuntu"),
                ("https://security.ubuntu.com/ubuntu", "noble-security", "ubuntu"))
    raise HostToolObservationDenied("host_tool.platform", "no finite signed package repositories for this platform")


def _fetch_https(url: str, *, limit: int, opener: urllib.request.OpenerDirector) -> bytes:
    parsed = urllib.parse.urlsplit(url)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
            or parsed.port not in (None, 443) or parsed.fragment):
        raise HostToolObservationDenied("host_tool.origin", "fixed official archive URL is malformed")
    try:
        with opener.open(urllib.request.Request(url, headers={"Accept-Encoding": "identity"}), timeout=30) as response:
            if response.status != 200:
                raise HostToolObservationDenied("host_tool.download", "official archive returned an unexpected status")
            declared = response.headers.get("Content-Length")
            if declared and int(declared) > limit:
                raise HostToolObservationDenied("host_tool.download", "official archive exceeds its signed size bound")
            body = response.read(limit + 1)
            if len(body) > limit:
                raise HostToolObservationDenied("host_tool.download", "official archive exceeds its fixed byte bound")
            return body
    except HostToolObservationDenied:
        raise
    except (OSError, ValueError, urllib.error.URLError):
        raise HostToolObservationDenied("host_tool.download", "fixed official archive fetch failed") from None


def _dearmor_inrelease(body: bytes) -> bytes:
    marker = b"-----BEGIN PGP SIGNED MESSAGE-----\n"
    if not body.startswith(marker):
        raise HostToolObservationDenied("host_tool.index", "signed archive metadata is not clear-signed InRelease")
    header_end = body.find(b"\n\n", len(marker))
    signature = body.find(b"\n-----BEGIN PGP SIGNATURE-----", header_end + 2)
    if header_end < 0 or signature < 0:
        raise HostToolObservationDenied("host_tool.index", "clear-signed archive metadata is malformed")
    cleartext = body[header_end + 2:signature]
    return b"\n".join(line[2:] if line.startswith(b"- ") else line for line in cleartext.split(b"\n"))


def _fields(stanza: bytes) -> dict[str, str]:
    values: dict[str, str] = {}
    current = ""
    try:
        lines = stanza.decode("utf-8", "strict").splitlines()
    except UnicodeDecodeError:
        raise HostToolObservationDenied("host_tool.index", "archive package metadata is not UTF-8") from None
    for line in lines:
        if line.startswith((" ", "\t")):
            if current:
                values[current] += "\n" + line[1:]
            continue
        if ":" not in line:
            raise HostToolObservationDenied("host_tool.index", "archive package metadata field is malformed")
        current, value = line.split(":", 1)
        if current in values:
            raise HostToolObservationDenied("host_tool.index", "archive package metadata repeats a field")
        values[current] = value.lstrip()
    return values


def _date(value: str) -> Any:
    try:
        result = parsedate_to_datetime(value)
    except (TypeError, ValueError, OverflowError):
        raise HostToolObservationDenied("host_tool.index", "signed archive date is malformed") from None
    if result.tzinfo is None:
        raise HostToolObservationDenied("host_tool.index", "signed archive date lacks a timezone")
    return result


def _release_package_index(body: bytes, *, suite: str, arch: str, gpgv: bytes,
                           signer_allowlist: set[str]) -> tuple[str, int, str, str | None, str, str, str, str]:
    clear = _dearmor_inrelease(body)
    fields = _fields(clear.split(b"\nSHA256:\n", 1)[0])
    expected_codename = (
        "trixie" if suite == "trixie" else "trixie-security" if suite == "trixie-security"
        else "noble" if suite in {"noble", "noble-updates", "noble-security"} else suite
    )
    expected_suite = (
        {"stable", "trixie"} if suite == "trixie"
        else {"stable-security", "trixie-security"} if suite == "trixie-security"
        else {suite}
    )
    if (not fields.get("Date") or fields.get("Codename") != expected_codename
            or fields.get("Suite") not in expected_suite):
        raise HostToolObservationDenied("host_tool.index", "signed archive suite or observation date is unexpected")
    valid_signers: set[str] = set()
    for line in gpgv.splitlines():
        parts = line.split()
        if len(parts) > 2 and b"[GNUPG:] VALIDSIG " in line:
            for candidate in (parts[2], parts[-1]):
                if re.fullmatch(rb"[0-9A-Fa-f]{40,64}", candidate):
                    valid_signers.add(candidate.decode("ascii").upper())
    if not valid_signers or not (valid_signers & signer_allowlist):
        raise HostToolObservationDenied("host_tool.signature", "archive InRelease signer is outside the pinned official set")
    relative = f"main/binary-{arch}/Packages.xz"
    sha_section = clear.split(b"\nSHA256:\n", 1)
    if len(sha_section) != 2:
        raise HostToolObservationDenied("host_tool.index", "signed archive metadata lacks SHA256 index records")
    row = re.search(rb"(?m)^\s*([0-9a-fA-F]{64})\s+([0-9]+)\s+" + re.escape(relative.encode("ascii")) + rb"\s*$", sha_section[1])
    if row is None:
        raise HostToolObservationDenied("host_tool.index", "signed InRelease does not select the fixed Packages index")
    signed_date = fields["Date"]
    date = _date(signed_date)
    if date.tzinfo is None or date.timestamp() > time.time() + 300:
        raise HostToolObservationDenied("host_tool.index", "signed archive date is malformed or in the future")
    signer = next((item for item in valid_signers if item in signer_allowlist), None)
    if signer is None:
        raise HostToolObservationDenied("host_tool.signature", "archive signer does not match its distribution allowlist")
    return (row.group(1).decode("ascii").lower(), int(row.group(2)), relative,
            fields.get("Valid-Until"), signed_date, signer, fields["Suite"], fields["Codename"])


def _package_stanzas(lines: Any, needed: set[str]) -> dict[str, dict[str, str]]:
    result: dict[str, dict[str, str]] = {}
    stanza = bytearray()
    expanded = 0
    for line in lines:
        expanded += len(line)
        if expanded > _MAX_INDEX_EXPANDED_BYTES:
            raise HostToolObservationDenied("host_tool.index", "expanded package index exceeds its fixed bound")
        if line in (b"\n", b"\r\n"):
            if stanza:
                row = _fields(bytes(stanza))
                name = row.get("Package")
                if name in needed:
                    if name in result:
                        raise HostToolObservationDenied("host_tool.index", "package appears more than once in one signed index")
                    row["_stanza_sha256"] = hashlib.sha256(bytes(stanza).rstrip(b"\r\n")).hexdigest()
                    result[name] = row
                stanza.clear()
        else:
            stanza.extend(line)
            if len(stanza) > 1024 * 1024:
                raise HostToolObservationDenied("host_tool.index", "package stanza exceeds its fixed bound")
    if stanza:
        row = _fields(bytes(stanza))
        if row.get("Package") in needed:
            row["_stanza_sha256"] = hashlib.sha256(bytes(stanza).rstrip(b"\r\n")).hexdigest()
            result[row["Package"]] = row
    return result


def _write_private_file(path: Path, body: bytes) -> tuple[int, os.stat_result, str]:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        view = memoryview(body)
        while view:
            written = os.write(fd, view)
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)
    held, info = _owned_regular(path)
    return held, info, _sha_fd(held)


def _expand_index(body: bytes) -> bytes:
    try:
        output = lzma.decompress(body, memlimit=_MAX_METADATA_BYTES)
    except (lzma.LZMAError, ValueError, EOFError):
        raise HostToolObservationDenied("host_tool.index", "signed package index is malformed or exceeds its bound") from None
    if len(output) > _MAX_INDEX_EXPANDED_BYTES:
        raise HostToolObservationDenied("host_tool.index", "expanded package index exceeds its fixed bound")
    return output


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


def _sha_fd_from_path(path: Path) -> str:
    fd, _info = _owned_regular(path)
    try:
        return _sha_fd(fd)
    finally:
        os.close(fd)


def _read_fd_bounded(fd: int, limit: int) -> bytes:
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
        raise HostToolObservationDenied("host_tool.file", "held source witness exceeds its fixed bound")
    chunks: list[bytes] = []
    offset = 0
    while offset < info.st_size:
        chunk = os.pread(fd, min(1024 * 1024, info.st_size - offset), offset)
        if not chunk:
            raise HostToolObservationDenied("host_tool.file", "held source witness changed during read")
        chunks.append(chunk)
        offset += len(chunk)
    return b"".join(chunks)


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
        keyring = _keyring_path(distribution)
        lines = [f"deb [arch=arm64 signed-by={keyring}] https://deb.debian.org/debian trixie main",
                 f"deb [arch=arm64 signed-by={keyring}] https://security.debian.org/debian-security trixie-security main"]
        if not keyring.exists():
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


def _installed_package_record(package: str, architecture: str, *, env: Mapping[str, str]) -> tuple[str, str]:
    raw = _run(["/usr/bin/dpkg-query", "-W", "-f=${Version}\t${Architecture}\t${db:Status-Abbrev}", package], env=env)
    fields = raw.decode("utf-8", "strict").split("\t")
    if len(fields) != 3 or fields[1] not in (architecture, "all") or not fields[2].startswith("ii"):
        raise HostToolObservationDenied("host_tool.package", "required package is not installed for the selected architecture")
    return fields[0], fields[1]


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
                            expected: Mapping[str, str]) -> tuple[str, tuple[tuple[str, int, int, str], ...], dict[str, tuple[str, str]]]:
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
    packages: dict[str, tuple[str, str]] = {}
    for path in sorted(seen):
        fd, info = _owned_regular(path)
        try:
            digest = _sha_fd(fd)
            owner = _run(["/usr/bin/dpkg-query", "-S", str(path)], env=env).decode("utf-8", "strict").strip()
            match = _PACKAGE_LINE.fullmatch(owner)
            if match is None:
                raise HostToolObservationDenied("host_tool.dependencies", "runtime ELF member has no exact dpkg package owner")
            package_name = match.group(1).split(":", 1)[0]
            package_version, package_arch = _installed_package_record(package_name, architecture, env=env)
            prior = packages.get(package_name)
            if prior is not None and prior != (package_version, package_arch):
                raise HostToolObservationDenied("host_tool.dependencies", "ELF members have conflicting installed package identities")
            packages[package_name] = (package_version, package_arch)
            rows.append({"path": str(path), "sha256": digest, "package": package_name,
                         "version": package_version, "architecture": package_arch,
                         "device": info.st_dev, "inode": info.st_ino})
            identities.append((str(path), info.st_dev, info.st_ino, digest))
        finally:
            os.close(fd)
    for package, constraint in expected.items():
        version = _installed_package(package, architecture, env=env)
        operator, required = ("=", constraint[1:]) if constraint.startswith("=") else (">=", constraint[2:])
        _run(["/usr/bin/dpkg", "--compare-versions", version, operator, required], env=env)
    canonical = json.dumps(rows, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest(), tuple(identities), packages


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
    signed_index_records: tuple[Mapping[str, Any], ...]
    package_records: tuple[Mapping[str, Any], ...]
    source_file_hashes: tuple[tuple[str, str], ...]
    keyring_identity: tuple[int, int, str]
    dpkg_status_sha256: str
    workspace: Path = field(repr=False)
    observed_monotonic: float
    expires_monotonic: float

    def __repr__(self) -> str:
        return "VerifiedHostToolPackageObservation(<root-current>)"


def _verify_signed_package_records(observation: VerifiedHostToolPackageObservation,
                                  keyring_path: Path, env: Mapping[str, str]) -> None:
    """Recheck the signed index row chain from held root files on each use."""
    if _sha_fd_from_path(keyring_path) != observation.keyring_identity[2]:
        raise HostToolObservationDenied("host_tool.keyring", "distribution trust keyring changed")
    by_release = {str(row["inrelease_sha256"]): row for row in observation.signed_index_records}
    for release_sha, record in by_release.items():
        inrelease_path = Path(str(record["inrelease_path"]))
        packages_path = Path(str(record["packages_path"]))
        in_fd, _ = _owned_regular(inrelease_path, expected_sha256=release_sha)
        packages_fd, packages_info = _owned_regular(packages_path, expected_sha256=str(record["packages_witness_sha256"]))
        try:
            inrelease = _read_fd_bounded(in_fd, 4 * 1024 * 1024)
            packages_body = _read_fd_bounded(packages_fd, _MAX_METADATA_BYTES)
            packages_digest = hashlib.sha256(packages_body).hexdigest()
        finally:
            os.close(in_fd)
            os.close(packages_fd)
        status = _run(["/usr/bin/gpgv", "--status-fd=1", "--keyring", str(keyring_path), str(inrelease_path)], env=env)
        signed_sha, signed_size, relative, valid_until, signed_date, signer, signed_suite, codename = _release_package_index(
            inrelease, suite=str(record["suite"]), arch=str(observation.variant["architecture"]),
            gpgv=status, signer_allowlist=_SIGNERS[str(observation.variant["distribution"])],
        )
        if (signer != record["signer_fingerprint"] or signed_suite != record["signed_suite"]
                or codename != record["codename"] or signed_sha != record["packages_sha256"]
                or signed_size != record["packages_size_bytes"] or relative != record["packages_relative_path"]
                or valid_until != record["valid_until"] or signed_date != record["signed_date"]
                or packages_info.st_size != signed_size
                or packages_digest != signed_sha
                ):
            raise HostToolObservationDenied("host_tool.index", "held signed InRelease-to-Packages link changed")
        signed_at = _date(signed_date)
        if signed_at.timestamp() > time.time() + 300:
            raise HostToolObservationDenied("host_tool.index", "signed package index date is malformed or future-dated")
        if valid_until is not None:
            expiry = _date(valid_until)
            if expiry.timestamp() <= time.time():
                raise HostToolObservationDenied("host_tool.index", "signed package index expired during the selected lease")
        package_rows = [row for row in observation.package_records
                        if row["index_inrelease_sha256"] == release_sha]
        if package_rows:
            parsed = _package_stanzas(io.BytesIO(_expand_index(packages_body)),
                                      {str(row["package_name"]) for row in package_rows})
            for receipt in package_rows:
                package = parsed.get(str(receipt["package_name"]))
                if (package is None
                        or package.get("Version") != receipt["version"]
                        or package.get("Architecture") != receipt["architecture"]
                        or package.get("Filename") != receipt["package_relative_path"]
                        or package.get("SHA256") != receipt["package_sha256"]
                        or package.get("Size") != str(receipt["package_size_bytes"])
                        or package.get("_stanza_sha256") != receipt["index_record_sha256"]):
                    raise HostToolObservationDenied("host_tool.package", "held signed Packages row differs from the exact selected package receipt")
    for receipt in observation.package_records:
        release_sha = str(receipt["index_inrelease_sha256"])
        signed_record = by_release.get(release_sha)
        if (signed_record is None or receipt["packages_sha256"] != signed_record["packages_sha256"]
                or not _SHA.fullmatch(str(receipt["index_record_sha256"]))
                or not _SHA.fullmatch(str(receipt["package_sha256"]))):
            raise HostToolObservationDenied("host_tool.package", "selected package record lost its signed-index membership")


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
            runtime_info = parent.parent.lstat()
            if (not stat.S_ISDIR(runtime_info.st_mode) or runtime_info.st_uid != 0
                    or runtime_info.st_mode & 0o022):
                raise OSError("runtime parent is not root-protected")
            try:
                parent.mkdir(mode=0o700)
            except FileExistsError:
                pass
            parent_info = parent.lstat()
            if (not stat.S_ISDIR(parent_info.st_mode) or parent_info.st_uid != 0 or parent_info.st_mode & 0o022):
                raise OSError("observation parent is not protected")
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
            installed_version = _installed_package("nftables", architecture, env=env)
            if installed_version != variant["version"]:
                raise HostToolObservationDenied("host_tool.package", "installed nft package differs from the selected finite variant")
            owner = _run(["/usr/bin/dpkg-query", "-S", str(INSTALLED_NFT)], env=env).decode("utf-8", "strict").strip()
            if owner != "nftables: /usr/sbin/nft":
                raise HostToolObservationDenied("host_tool.package", "installed nft executable is not owned by the selected package")
            opened_fd, executable_info = _owned_regular(INSTALLED_NFT, expected_sha256=variant["executable_sha256"])
            dependency_sha256, dependency_files, needed_packages = _elf_dependency_closure(
                INSTALLED_NFT, architecture=architecture, env=env,
                expected=variant.get("dependency_requirements", {}),
            )
            handle = "host-nft-observation:" + secrets.token_hex(24)
            network_key = (selected_network_binding.network_id, selected_network_binding.generation,
                           selected_network_binding.service_generation_digest)
            keyring_path = _keyring_path(distribution)
            key_fd, _ = _owned_regular(keyring_path)
            os.close(key_fd)
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoCrossOriginRedirect())
            signed_index_records: list[Mapping[str, Any]] = []
            package_rows: dict[str, tuple[dict[str, str], Mapping[str, Any]]] = {}
            source_file_hashes: list[tuple[str, str]] = []
            metadata_bytes = package_bytes = 0
            for origin, suite, _distro in _repositories(distribution, architecture):
                inrelease_url = f"{origin}/dists/{suite}/InRelease"
                inrelease_body = _fetch_https(inrelease_url, limit=4 * 1024 * 1024, opener=opener)
                metadata_bytes += len(inrelease_body)
                if metadata_bytes > _MAX_METADATA_BYTES:
                    raise HostToolObservationDenied("host_tool.limit", "signed metadata exceeds the v105 total byte limit")
                index_name = f"inrelease-{suite}"
                inrelease_path = workspace / index_name
                held, inrelease_info, inrelease_digest = _write_private_file(inrelease_path, inrelease_body)
                status = _run(["/usr/bin/gpgv", "--status-fd=1", "--keyring", str(keyring_path), str(inrelease_path)], env=env)
                packages_sha, packages_size, packages_relative, valid_until, signed_date, signer, signed_suite, codename = _release_package_index(
                    inrelease_body, suite=suite, arch=architecture, gpgv=status,
                    signer_allowlist=_SIGNERS[distribution],
                )
                signed_at = _date(signed_date)
                if signed_at.timestamp() > time.time() + 300:
                    raise HostToolObservationDenied("host_tool.index", "signed package index date is malformed or future-dated")
                if valid_until is not None:
                    expiry = _date(valid_until)
                    if int(expiry.timestamp()) <= int(time.time()):
                        raise HostToolObservationDenied("host_tool.index", "signed package index is expired")
                index_url = f"{origin}/dists/{suite}/{packages_relative}"
                if packages_size > _MAX_METADATA_BYTES or metadata_bytes + packages_size > _MAX_METADATA_BYTES:
                    raise HostToolObservationDenied("host_tool.limit", "signed package index exceeds the v105 metadata byte limit")
                packages_body = _fetch_https(index_url, limit=packages_size, opener=opener)
                if len(packages_body) != packages_size or hashlib.sha256(packages_body).hexdigest() != packages_sha:
                    raise HostToolObservationDenied("host_tool.index", "Packages index does not match its signed InRelease row")
                metadata_bytes += len(packages_body)
                packages_path = workspace / f"packages-{suite}.xz"
                packages_fd, packages_info, packages_digest = _write_private_file(packages_path, packages_body)
                held_fds.extend([
                    (str(inrelease_path), held, inrelease_info.st_dev, inrelease_info.st_ino,
                     inrelease_info.st_uid, inrelease_digest),
                    (str(packages_path), packages_fd, packages_info.st_dev, packages_info.st_ino,
                     packages_info.st_uid, packages_digest),
                ])
                source_file_hashes.extend(((str(inrelease_path), inrelease_digest),
                                           (str(packages_path), packages_digest)))
                clear_index = _expand_index(packages_body)
                index_rows = _package_stanzas(io.BytesIO(clear_index), set(needed_packages) | {"nftables"})
                index_record = {
                    "origin": origin, "suite": suite, "inrelease_sha256": inrelease_digest,
                    "signer_fingerprint": signer, "keyring_sha256": _sha_fd_from_path(keyring_path),
                    "signed_suite": signed_suite, "codename": codename,
                    "packages_relative_path": packages_relative, "packages_sha256": packages_sha,
                    "packages_size_bytes": packages_size, "valid_until": valid_until,
                    "signed_date": signed_date,
                    "packages_witness_sha256": packages_digest,
                    "inrelease_path": str(inrelease_path), "packages_path": str(packages_path),
                }
                signed_index_records.append(index_record)
                for package_name in index_rows:
                    row = index_rows[package_name]
                    expected_version, expected_arch = (variant["version"], architecture) if package_name == "nftables" else needed_packages[package_name]
                    if (row.get("Version") != expected_version or row.get("Architecture") != expected_arch
                            or not row.get("Filename") or not re.fullmatch(r"pool/[A-Za-z0-9+._/-]+\.deb", row["Filename"])
                            or ".." in Path(row["Filename"]).parts
                            or not re.fullmatch(r"[0-9a-f]{64}", row.get("SHA256", ""))):
                        continue
                    try:
                        row_size = int(row["Size"])
                    except (KeyError, ValueError):
                        continue
                    if row_size <= 0 or row_size > _MAX_PACKAGE_BYTES:
                        continue
                    package_entry = {"package_name": package_name, "version": expected_version,
                                     "architecture": expected_arch, "package_relative_path": row["Filename"],
                                     "package_sha256": row["SHA256"], "package_size_bytes": row_size,
                                     "index_record_sha256": row["_stanza_sha256"],
                                     "index_inrelease_sha256": inrelease_digest,
                                     "packages_sha256": packages_sha,
                                     "installed_status_sha256": ""}
                    prior = package_rows.get(package_name)
                    if prior is not None:
                        comparable_prior = {key: value for key, value in prior[1].items()
                                            if key not in {"index_inrelease_sha256", "packages_sha256"}}
                        comparable_new = {key: value for key, value in package_entry.items()
                                          if key not in {"index_inrelease_sha256", "packages_sha256"}}
                        if comparable_prior != comparable_new:
                            raise HostToolObservationDenied("host_tool.index", "selected package has ambiguous signed source rows")
                    else:
                        package_rows[package_name] = (row, package_entry)
            required_packages = set(needed_packages) | {"nftables"}
            if required_packages - package_rows.keys():
                raise HostToolObservationDenied("host_tool.package", "an installed nft dependency has no exact row in the current signed indexes")
            if (package_rows["nftables"][1]["package_relative_path"] != variant["package_path"]
                    or package_rows["nftables"][1]["package_sha256"] != variant["package_sha256"]
                    or package_rows["nftables"][1]["package_size_bytes"] != variant["package_size_bytes"]):
                raise HostToolObservationDenied("host_tool.package", "signed nft package row differs from the measured finite variant")
            status_path = Path("/var/lib/dpkg/status")
            status_fd, status_info = _owned_regular(status_path)
            try:
                status_digest = _sha_fd(status_fd)
                held_fds.append((str(status_path), os.dup(status_fd), status_info.st_dev,
                                 status_info.st_ino, status_info.st_uid, status_digest))
            finally:
                os.close(status_fd)
            package_receipts: list[Mapping[str, Any]] = []
            extracted = workspace / "extract"
            extracted.mkdir(mode=0o700)
            package_directory = workspace / "deb"
            package_directory.mkdir(mode=0o700)
            installed_files = {path: digest for path, _device, _inode, digest in dependency_files}
            installed_files[str(INSTALLED_NFT)] = variant["executable_sha256"]
            owner_packages: dict[str, set[str]] = {"nftables": {str(INSTALLED_NFT)}}
            for path, _device, _inode, _digest in dependency_files:
                owner = _run(["/usr/bin/dpkg-query", "-S", path], env=env).decode("utf-8", "strict").strip()
                match = _PACKAGE_LINE.fullmatch(owner)
                if match is None:
                    raise HostToolObservationDenied("host_tool.package", "dependency file has no exact installed package owner")
                owner_packages.setdefault(match.group(1).split(":", 1)[0], set()).add(path)
            for package_name in sorted(required_packages):
                row, receipt = package_rows[package_name]
                origin = next(index["origin"] for index in signed_index_records
                              if index["inrelease_sha256"] == receipt["index_inrelease_sha256"])
                archive_body = _fetch_https(f"{origin}/{row['Filename']}", limit=int(row["Size"]), opener=opener)
                if len(archive_body) != int(row["Size"]) or hashlib.sha256(archive_body).hexdigest() != row["SHA256"]:
                    raise HostToolObservationDenied("host_tool.package", "downloaded .deb differs from its exact signed Packages row")
                package_path = package_directory / f"{package_name}.deb"
                deb_fd, deb_info, deb_digest = _write_private_file(package_path, archive_body)
                package_bytes += len(archive_body)
                if package_bytes > 512 * 1024 * 1024:
                    os.close(deb_fd)
                    raise HostToolObservationDenied("host_tool.limit", "signed dependency archives exceed the total byte limit")
                held_fds.append((str(package_path), deb_fd, deb_info.st_dev, deb_info.st_ino,
                                 deb_info.st_uid, deb_digest))
                source_file_hashes.append((str(package_path), deb_digest))
                deb_info_fields = _run(["/usr/bin/dpkg-deb", "-f", str(package_path),
                                        "Package", "Version", "Architecture"], env=env).decode("utf-8", "strict")
                deb_identity = dict(line.split(": ", 1) for line in deb_info_fields.splitlines() if ": " in line)
                if deb_identity != {"Package": package_name, "Version": row["Version"],
                                    "Architecture": row["Architecture"]}:
                    raise HostToolObservationDenied("host_tool.package", "downloaded archive control identity differs from signed Packages row")
                _run(["/usr/bin/dpkg-deb", "-x", str(package_path), str(extracted)], env=env, timeout=60)
                for member_path in owner_packages.get(package_name, set()):
                    expected_digest = installed_files[member_path]
                    member_fd, _member_info = _owned_regular(extracted / member_path.lstrip("/"), expected_sha256=expected_digest)
                    os.close(member_fd)
                package_receipts.append({**receipt, "installed_status_sha256": status_digest})
            for path, digest in installed_files.items():
                extracted_member = extracted / path.lstrip("/")
                member_fd, _member_info = _owned_regular(extracted_member, expected_sha256=digest)
                os.close(member_fd)
            held_exec, exec_info = _owned_regular(INSTALLED_NFT, expected_sha256=variant["executable_sha256"])
            os.close(opened_fd)
            opened_fd = held_exec
            executable_info = exec_info
            keyring_fd, keyring_info = _owned_regular(keyring_path)
            try:
                keyring_identity = (keyring_info.st_dev, keyring_info.st_ino, _sha_fd(keyring_fd))
                held_fds.append((str(keyring_path), os.dup(keyring_fd), keyring_info.st_dev,
                                 keyring_info.st_ino, keyring_info.st_uid, keyring_identity[2]))
            finally:
                os.close(keyring_fd)
            # Retain every actual ELF object (including loader and interpreter),
            # not merely the top-level executable, for the full observation lease.
            for dependency_path, device, inode, digest in dependency_files:
                dep_fd, dep_info = _owned_regular(Path(dependency_path), expected_sha256=digest)
                held_fds.append((dependency_path, dep_fd, device, inode, dep_info.st_uid, digest))
            observation = VerifiedHostToolPackageObservation(
                handle, network_key, dict(variant), handle, dependency_sha256,
                opened_fd, executable_info.st_dev, executable_info.st_ino, dependency_files,
                tuple(held_fds), tuple(signed_index_records), tuple(package_receipts),
                tuple(source_file_hashes), keyring_identity, status_digest,
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
            keyring_path = _keyring_path(distribution)
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
            status_fd, status_info = _owned_regular(Path("/var/lib/dpkg/status"),
                                                     expected_sha256=observation.dpkg_status_sha256)
            os.close(status_fd)
            _verify_signed_package_records(observation, keyring_path, env)
            installed_packages: dict[str, tuple[str, str]] = {}
            for package_record in observation.package_records:
                package_name = str(package_record["package_name"])
                package_identity = _installed_package_record(package_name, architecture, env=env)
                if package_identity != (package_record["version"], package_record["architecture"]):
                    raise OSError("installed package identity changed")
                installed_packages[package_name] = package_identity
            dependency_hash, dependency_files, current_packages = _elf_dependency_closure(
                INSTALLED_NFT, architecture=architecture,
                env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C", "APT_CONFIG": "/dev/null"},
                expected=observation.variant.get("dependency_requirements", {}),
            )
            if (dependency_hash != observation.dependency_closure_sha256
                    or dependency_files != observation.dependency_files
                    or current_packages != installed_packages
                    or set(installed_packages) != {str(row["package_name"]) for row in observation.package_records}):
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
