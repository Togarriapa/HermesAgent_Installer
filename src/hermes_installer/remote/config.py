"""Remote setup prompts and explicit noninteractive inputs."""
from __future__ import annotations
import getpass, re
from dataclasses import dataclass, field
from typing import Callable, Iterable
from ..credentials import CredentialError, read_hidden_token, resolve_secret
from .cloudflare import CloudflareClient, CloudflareZone

_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_HOST = re.compile(rf"(?=^.{{1,253}}$)(?:{_LABEL}\.)*{_LABEL}$")
_EMAIL = re.compile(r"[^@\s]+@[^@\s.]+(?:\.[^@\s.]+)+$")

class RemoteConfigError(ValueError):
    """Safe setup error without token material."""

@dataclass(frozen=True)
class RemoteSetup:
    hostname: str
    allowed_emails: tuple[str, ...]
    zone: CloudflareZone
    auth_domain: str
    management_token: str = field(repr=False, compare=False)
    # A locator for the isolated verifier's minimum-read token. It is never
    # resolved by the setup client and cannot inherit the management token.
    policy_read_token_ref: str | None = field(default=None, repr=False, compare=False)

def validate_policy_read_reference(value: object) -> str | None:
    if value in (None, ""):
        return None
    if (not isinstance(value, str) or len(value) > 2048 or
            not value.startswith(("keyring://", "secret://", "file://")) or
            any(ord(ch) < 32 for ch in value)):
        raise RemoteConfigError("Use a separate reference; it must be a secure protected keyring://, secret:// or file:// policy-read token reference")
    return value

def validate_hostname(value: str) -> str:
    value = value.strip().lower().rstrip(".")
    if not _HOST.fullmatch(value):
        raise RemoteConfigError("Enter a complete DNS hostname; no default hostname is supplied")
    return value

def validate_emails(values: Iterable[str]) -> tuple[str, ...]:
    items = tuple(dict.fromkeys(v.strip().lower() for v in values if v.strip()))
    if not items or any(not _EMAIL.fullmatch(item) for item in items):
        raise RemoteConfigError("Enter one or more valid allowed email addresses")
    return items

def collect_remote_setup(*, interactive: bool, config: dict | None = None,
        input_fn: Callable[[str], str] = input, hidden_reader: Callable[[str], str] | None = None,
        environ=None, keyring_lookup=None, secret_lookup=None,
        client_factory=CloudflareClient) -> RemoteSetup:
    data = config or {}
    remote = data.get("remote_desktop", data)
    if not isinstance(remote, dict):
        raise RemoteConfigError("remote_desktop configuration must be an object")
    if interactive:
        hostname_raw = input_fn("Hostname to publish (leave blank to cancel): ")
        if not hostname_raw.strip():
            raise RemoteConfigError("A hostname is required; no default was selected")
        hostname = validate_hostname(hostname_raw)
        emails = validate_emails(input_fn("Allowed email addresses (comma-separated): ").split(","))
        token = read_hidden_token(prompt="Cloudflare API token (input hidden): ", reader=hidden_reader or getpass.getpass)
        if not token:
            raise CredentialError("A valid Cloudflare API token is required")
        policy_read_ref = validate_policy_read_reference(input_fn(
            "Minimum-read Access policy token reference (protected keyring://, secret:// or file://; blank to configure later): "
        ).strip())
    else:
        try:
            hostname = validate_hostname(remote["hostname"])
            emails = validate_emails(remote["allowed_emails"])
            token = resolve_secret(remote["management_token_ref"], environ=environ,
                                   keyring_lookup=keyring_lookup, secret_lookup=secret_lookup)
            policy_read_ref = validate_policy_read_reference(remote.get("policy_read_token_ref"))
            if policy_read_ref is not None and policy_read_ref == remote["management_token_ref"]:
                raise RemoteConfigError("Policy-read token must use a separate reference from the setup-management token")
        except (KeyError, TypeError) as exc:
            raise RemoteConfigError("Noninteractive remote setup requires hostname, allowed_emails and management_token_ref") from None
    client = client_factory(token)
    zones = client.discover_zones(hostname)
    if not zones:
        raise RemoteConfigError("No accessible active Cloudflare zone matches the explicit hostname")
    longest = len(zones[0].name)
    matches = tuple(z for z in zones if len(z.name) == longest)
    selected_id = remote.get("zone_id")
    if selected_id:
        matches = tuple(z for z in matches if z.zone_id == selected_id)
    if selected_id and not matches:
        raise RemoteConfigError("The explicitly selected zone_id does not match an accessible active zone")
    if len(matches) > 1:
        if not interactive:
            raise RemoteConfigError("Several equally specific zones match; add explicit zone_id and resume")
        choices = ", ".join(f"{i + 1}) {zone.name} ({zone.account_id})" for i, zone in enumerate(matches))
        answer = input_fn("Choose an accessible Cloudflare zone: " + choices + " ")
        if not answer.isdigit() or not 1 <= int(answer) <= len(matches):
            raise RemoteConfigError("A valid zone selection is required")
        zone = matches[int(answer) - 1]
    else:
        zone = matches[0]
    organization = client.organization(zone.account_id)
    auth_domain = organization.get("auth_domain")
    return RemoteSetup(hostname, emails, zone, auth_domain, token, policy_read_ref)
