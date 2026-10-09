"""Secret references and hidden setup input; values are never serialized by this module."""
from __future__ import annotations
import getpass, os, re, stat
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
        path = Path(unquote(parsed.path))
        if parsed.netloc or not path.is_absolute():
            raise CredentialError("File secret reference must be an absolute local path")
        try:
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
                raise CredentialError("Secret file must be a non-symlink regular file")
            if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
                raise CredentialError("Secret file must be user-owned with mode 0600 or stricter")
            value = path.read_text(encoding="utf-8").rstrip("\r\n")
        except OSError:
            raise CredentialError("Secret file could not be read") from None
    elif reference.startswith("keyring://"):
        key = reference[10:]
        if not key or len(key) > 512 or keyring_lookup is None:
            raise CredentialError("Keyring secret reference is unavailable")
        value = keyring_lookup(key)
    elif reference.startswith("secret://"):
        key = reference[9:]
        if not key or len(key) > 512 or secret_lookup is None:
            raise CredentialError("Secret-store reference is unavailable")
        value = secret_lookup(key)
    else:
        raise CredentialError("Use keyring://, secret://, file:// or env:// reference")
    if not _valid_token(value):
        raise CredentialError("Referenced secret is missing or invalid")
    return value

def read_hidden_token(*, prompt="Cloudflare API token (input hidden): ",
                      reader: Callable[[str], str] = getpass.getpass) -> str:
    value = reader(prompt)
    if not _valid_token(value):
        raise CredentialError("A valid Cloudflare API token is required")
    return value.strip()
