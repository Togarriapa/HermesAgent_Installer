"""Separate least-privilege Access-policy credential custodian.

The gateway never imports this module. The host supervisor starts it as its dedicated
non-root UID and supplies only a non-secret config path; the secret reference is
resolved inside the custodian process through an injected host credential provider.
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol

from .cloudflare import CloudflareClient
from .gateway import RemotePolicy
from .policy import AccessPolicyIdentity, FreshAccessPolicyAuthority
from .verifier_ipc import (
    PROFILE_ID, PolicyVerifierService, VerifierRuntime, verifier_config_digest,
)


class SecretResolver(Protocol):
    def __call__(self, reference: str) -> str: ...


@dataclass(frozen=True, slots=True)
class VerifierServiceConfig:
    """Non-secret data provisioned by the installer's durable journal."""

    socket_path: Path
    config_path: Path
    gateway_uid: int
    service_uid: int
    service_gid: int
    identity: AccessPolicyIdentity
    issuer: str
    jwks: Mapping[str, Mapping[str, Any]]
    credential_ref: str
    profile_id: str = PROFILE_ID

    @classmethod
    def load(cls, path: Path) -> "VerifierServiceConfig":
        if not path.is_absolute():
            raise ValueError("verifier config path must be absolute")
        info = os.stat(path, follow_symlinks=False)
        if (not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077
                or info.st_uid not in {0, os.geteuid()}):
            raise PermissionError("verifier config must be root/service-owned and mode 0600")
        raw = path.read_bytes()
        if not raw or len(raw) > 65_536:
            raise ValueError("verifier config exceeds its strict size bound")
        value = json.loads(raw)
        if not isinstance(value, dict) or set(value) != {
            "version", "socket_path", "gateway_uid", "service_uid", "service_gid",
            "identity", "issuer", "jwks", "credential_ref", "profile_id",
        } or type(value.get("version")) is not int or value["version"] != 1:
            raise ValueError("invalid exact verifier config schema")
        identity = value["identity"]
        required_identity = {
            "account_id", "application_id", "policy_id", "identity_provider_id",
            "hostname", "application_name", "policy_name", "identity_provider_name",
            "allowed_emails", "audience",
        }
        if not isinstance(identity, dict) or set(identity) != required_identity:
            raise ValueError("invalid exact Access identity schema")
        result = cls(
            socket_path=Path(value["socket_path"]),
            config_path=path,
            gateway_uid=value["gateway_uid"],
            service_uid=value["service_uid"],
            service_gid=value["service_gid"],
            identity=AccessPolicyIdentity(
                account_id=identity["account_id"], application_id=identity["application_id"],
                policy_id=identity["policy_id"], identity_provider_id=identity["identity_provider_id"],
                hostname=identity["hostname"], application_name=identity["application_name"],
                policy_name=identity["policy_name"], identity_provider_name=identity["identity_provider_name"],
                allowed_emails=frozenset(identity["allowed_emails"]), audience=identity["audience"],
            ),
            issuer=value["issuer"], jwks=value["jwks"], credential_ref=value["credential_ref"],
            profile_id=value["profile_id"],
        )
        result.validate()
        return result

    def validate(self) -> None:
        if (not self.socket_path.is_absolute() or not self.config_path.is_absolute()
                or type(self.gateway_uid) is not int or self.gateway_uid <= 0
                or type(self.service_uid) is not int or self.service_uid <= 0
                or type(self.service_gid) is not int or self.service_gid <= 0
                or self.gateway_uid == self.service_uid or self.service_uid == 0
                or self.profile_id != PROFILE_ID):
            raise ValueError("distinct dedicated non-root verifier identity and fixed paths required")
        if not re.fullmatch(r"https://[a-z0-9-]+\.cloudflareaccess\.com", self.issuer):
            raise ValueError("fixed Cloudflare Access issuer required")
        if not isinstance(self.credential_ref, str) or not re.fullmatch(
            r"[A-Za-z0-9_.:/-]{1,256}", self.credential_ref
        ):
            raise ValueError("separate verifier read-token reference required")
        if not isinstance(self.jwks, Mapping) or not 1 <= len(self.jwks) <= 16:
            raise ValueError("bounded pinned JWKS set required")
        for kid, key in self.jwks.items():
            if not isinstance(kid, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", kid):
                raise ValueError("invalid JWKS key identifier")
            if not isinstance(key, Mapping) or key.get("kid") != kid or key.get("alg") != "RS256":
                raise ValueError("only exact RSA RS256 keys are accepted")


@dataclass(frozen=True, slots=True)
class VerifierManagedServiceDescriptor:
    """Secret-free handoff facts consumed by the shared owned-service supervisor."""

    service_id: str
    executable: Path
    executable_sha256: str
    owned_root: Path
    cwd: Path
    config_path: Path
    socket_path: Path
    gateway_uid: int
    verifier_uid: int
    verifier_gid: int
    startup_timeout_seconds: float = 10.0
    max_lifetime_seconds: float = 86_400.0
    stdout_limit: int = 4096
    stderr_limit: int = 8192
    stdin_limit: int = 0

    def validate(self) -> None:
        if (self.service_id != "hermes-remote-policy-verifier"
                or not self.executable.is_absolute() or not self.owned_root.is_absolute()
                or not self.cwd.is_absolute() or not self.config_path.is_absolute()
                or not self.socket_path.is_absolute()):
            raise ValueError("invalid fixed verifier service identity or paths")
        if not re.fullmatch(r"[0-9a-f]{64}", self.executable_sha256):
            raise ValueError("pinned verifier executable digest required")
        if (self.verifier_uid <= 0 or self.gateway_uid <= 0
                or self.verifier_uid == self.gateway_uid or self.verifier_gid <= 0
                or not 1 <= self.startup_timeout_seconds <= 60
                or not 60 <= self.max_lifetime_seconds <= 86_400
                or self.stdout_limit > 4096 or self.stderr_limit > 8192 or self.stdin_limit != 0):
            raise ValueError("invalid bounded verifier custody settings")

    def runner_spec(self, *, pin_type, spec_type, operation_id: str, now_monotonic: float,
                    runtime_env: Mapping[str, str]):
        """Adapt to wiring's typed ManagedProcessSpec without sharing credentials.

        'pin_type' and 'spec_type' are injected to avoid a circular dependency while
        the shared runner module is being completed. The systemd user scope, cgroup
        custody, exact executable digest and child identity remain the supervisor's
        responsibility.
        """
        self.validate()
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", operation_id):
            raise ValueError("invalid bounded operation identifier")
        env = dict(runtime_env)
        if set(env) != {"HOME", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME"}:
            raise ValueError("verifier may receive only its dedicated private runtime paths")
        if any(not Path(value).is_absolute() or not Path(value).is_relative_to(self.owned_root)
               for value in env.values()):
            raise ValueError("verifier runtime paths must be confined to its owned root")
        if (not self.cwd.is_relative_to(self.owned_root)
                or not self.executable.is_relative_to(self.owned_root)):
            raise ValueError("verifier executable and working directory must be inside its owned root")
        argv = (
            str(self.executable.resolve(strict=True)), "-I", "-m",
            "hermes_installer.remote.custodian", "--config", str(self.config_path),
        )
        return spec_type(
            service_id=self.service_id, operation_id=operation_id, argv=argv,
            executable=pin_type(path=self.executable, sha256=self.executable_sha256),
            owned_root=self.owned_root, cwd=self.cwd, env=env,
            env_allowlist=frozenset(env),
            startup_deadline_monotonic=now_monotonic + self.startup_timeout_seconds,
            max_lifetime_monotonic=now_monotonic + self.max_lifetime_seconds,
            max_stdout_bytes=self.stdout_limit, max_stderr_bytes=self.stderr_limit,
            max_stdin_bytes=self.stdin_limit,
        )


def build_runtime(config: VerifierServiceConfig, *, resolve_secret: SecretResolver,
                  client_factory: Callable[[str], CloudflareClient] = CloudflareClient) -> VerifierRuntime:
    """Construct the secret-bearing reader only inside the verifier's custodian UID."""
    config.validate()
    if os.geteuid() != config.service_uid:
        raise PermissionError("only the dedicated verifier service UID may resolve policy credentials")
    audience = config.identity.audience
    policy = RemotePolicy(
        hostname=config.identity.hostname, issuer=config.issuer, audience=audience,
        allowed_emails=config.identity.allowed_emails, jwks=config.jwks,
    )
    authority = FreshAccessPolicyAuthority(
        config.identity, config.credential_ref, resolve_secret, client_factory,
    )
    digest = verifier_config_digest(
        config.identity, issuer=config.issuer, audience=audience, profile_id=config.profile_id,
    )
    return VerifierRuntime(policy, authority, config.profile_id, digest)


async def serve(config: VerifierServiceConfig, *, resolve_secret: SecretResolver,
                client_factory: Callable[[str], CloudflareClient] = CloudflareClient,
                stop_event: asyncio.Event | None = None) -> None:
    runtime = build_runtime(config, resolve_secret=resolve_secret, client_factory=client_factory)
    service = PolicyVerifierService(
        runtime, gateway_uid=config.gateway_uid, service_uid=config.service_uid,
        service_gid=config.service_gid,
    )
    await service.start(config.socket_path)
    try:
        if stop_event is None:
            await asyncio.Event().wait()
        else:
            await stop_event.wait()
    finally:
        await service.close()


def main(argv: list[str] | None = None) -> None:
    """Installed module entrypoint; no CLI accepts or prints credential values."""
    import argparse
    import signal

    parser = argparse.ArgumentParser(prog="hermes-access-policy-verifier")
    parser.add_argument("--config", required=True)
    args = parser.parse_args(argv)
    config = VerifierServiceConfig.load(Path(args.config))
    # The existing resolver enforces owner/mode checks for file references and
    # explicit reference schemes. Resolution occurs only after euid verification.
    from ..credentials import resolve_secret

    async def run():
        stop = asyncio.Event()
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, stop.set)
        await serve(config, resolve_secret=resolve_secret, stop_event=stop)

    asyncio.run(run())


if __name__ == "__main__":
    main()
