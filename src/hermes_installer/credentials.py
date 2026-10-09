"""Secret references and hidden setup input; values are never serialized by this module."""
from __future__ import annotations
import getpass, os, re, stat, sys, warnings
from pathlib import Path
from typing import Callable, Mapping
from urllib.parse import unquote, urlparse

class CredentialError(RuntimeError):
    """Safe credential error containing no secret material."""

def _valid_token(value):
    return isinstance(value, str) and 1 <= len(value) <= 4096 and not any(ord(ch) < 32 for ch in value)

def resolve_secret(reference: str, *, environ: Mapping[str, str] | None = None,
                   keyring_lookup: Callable[[str], str | None] | None = None,
                   secret_lookup: Callable[[str], str | None] | None = None) -> str:
    """Resolve only an explicit reference. File refs must be private regular files owned by this user."""
    if not isinstance(reference, str) or len(reference) > 2048:
        raise CredentialError("A valid secret reference is required")
    if reference.startswith("env://"):
        key = reference[6:]
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", key):
            raise CredentialError("Invalid environment secret reference")
        value = (os.environ if environ is None else environ).get(key)
    elif reference.startswith("file://"):
        parsed = urlparse(reference)
        if parsed.netloc or parsed.query or parsed.fragment or not parsed.path.startswith("/"):
            raise CredentialError("File secret reference must be an absolute local path without query or fragment")
        parts = [unquote(p) for p in parsed.path.split("/") if p]
        if not parts or any(p in {".", ".."} or chr(0) in p or "/" in p or chr(92) in p for p in parts):
            raise CredentialError("Invalid secret file path")
        flags_dir = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        current = os.open("/", flags_dir)
        try:
            for part in parts[:-1]:
                nxt = os.open(part, flags_dir, dir_fd=current)
                os.close(current)
                current = nxt
            flags_file = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
            fd = os.open(parts[-1], flags_file, dir_fd=current)
            try:
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077 or info.st_size > 4096:
                    raise CredentialError("Secret file must be a small user-owned regular file with mode 0600 or stricter")
                with os.fdopen(fd, "r", encoding="utf-8", closefd=False) as stream:
                    value = stream.read(4097).rstrip("\r\n")
            finally:
                os.close(fd)
        except OSError:
            raise CredentialError("Secret file could not be read safely") from None
        finally:
            os.close(current)
    elif reference.startswith("keyring://"):
        key = reference[10:]
        if not key or len(key) > 512 or keyring_lookup is None:
            raise CredentialError("Keyring secret reference is unavailable")
        try:
            value = keyring_lookup(key)
        except Exception:
            raise CredentialError("Keyring secret lookup failed") from None
    elif reference.startswith("secret://"):
        key = reference[9:]
        if not key or len(key) > 512 or secret_lookup is None:
            raise CredentialError("Secret-store reference is unavailable")
        try:
            value = secret_lookup(key)
        except Exception:
            raise CredentialError("Secret-store lookup failed") from None
    else:
        raise CredentialError("Use keyring://, secret://, file:// or env:// reference")
    if not _valid_token(value):
        raise CredentialError("Referenced secret is missing or invalid")
    return value

def read_hidden_token(*, prompt="Cloudflare API token (input hidden): ",
                      reader: Callable[[str], str] = getpass.getpass) -> str:
    if reader is getpass.getpass and not sys.stdin.isatty():
        raise CredentialError("Hidden token input requires a terminal")
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            value = reader(prompt)
    except (getpass.GetPassWarning, OSError):
        raise CredentialError("Could not read the token without echo") from None
    if not _valid_token(value):
        raise CredentialError("A valid Cloudflare API token is required")
    return value.strip()
