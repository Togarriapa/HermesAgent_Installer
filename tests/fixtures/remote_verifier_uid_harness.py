#!/usr/bin/env python3
"""Disposable Linux CI subprocesses for the two-UID verifier IPC boundary.

All account responses and the read-token resolver below are fixtures. This helper has
no outbound service client and is never installed on a target host.
"""
from __future__ import annotations

import asyncio
import json
import os
import signal
import sys
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from hermes_installer.remote.gateway import RemotePolicy, validate_access_jwt
from hermes_installer.remote.policy import AccessPolicyIdentity, FreshAccessPolicyAuthority
from hermes_installer.remote.verifier_ipc import PolicyVerifierClient, PolicyVerifierService, VerifierRuntime, verifier_config_digest


class FixtureAccount:
    def __init__(self, payload):
        self.payload = payload
        self.read_count = 0

    def request(self, method, path):
        self.read_count += 1
        if method != "GET":
            raise AssertionError("fixture verifier attempted a write")
        if path.endswith("/access/apps/app-1"):
            return self.payload["app"]
        if path.endswith("/access/identity_providers/idp-1"):
            return self.payload["idp"]
        if "/policies?" in path:
            return [self.payload["policy"]]
        raise AssertionError("fixture verifier attempted an unreviewed endpoint")


def _identity(data):
    return AccessPolicyIdentity(
        account_id=data["account_id"], application_id="app-1", policy_id="policy-1",
        identity_provider_id="idp-1", hostname=data["hostname"],
        application_name=data["application_name"], policy_name=data["policy_name"],
        identity_provider_name=data["idp_name"], allowed_emails=frozenset({data["email"]}),
        audience=data["audience"],
    )


async def serve_fixture(path):
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    identity = _identity(payload)
    account = FixtureAccount(payload)
    authority = FreshAccessPolicyAuthority(
        identity, "fixture://access-read-token",
        lambda reference: "fixture-only-cloudflare-read-token" if reference == "fixture://access-read-token" else "",
        lambda token: account if token == "fixture-only-cloudflare-read-token" else None,
    )
    policy = RemotePolicy(
        payload["hostname"], payload["issuer"], payload["audience"],
        frozenset({payload["email"]}), {"ci-test": payload["jwk"]},
    )
    digest = verifier_config_digest(identity, issuer=policy.issuer, audience=policy.audience)
    runtime = VerifierRuntime(policy, authority, "hermes-desktop", digest)
    service = PolicyVerifierService(
        runtime, gateway_uid=payload["gateway_uid"], service_uid=os.geteuid(),
        service_gid=payload["gateway_gid"],
    )
    await service.start(Path(payload["socket_path"]))
    stopped = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stopped.set)
    await stopped.wait()
    await service.close()
    print(json.dumps({"fixture_get_count": account.read_count}), flush=True)


async def use_gateway(payload):
    issuer = payload["issuer"]
    policy = RemotePolicy(
        payload["hostname"], issuer, payload["audience"],
        frozenset({payload["email"]}), {"ci-test": payload["jwk"]},
    )
    expected = validate_access_jwt(payload["jwt"], policy=policy)
    digest = payload["config_digest"]
    client = PolicyVerifierClient(
        Path(payload["socket_path"]), verifier_uid=payload["verifier_uid"],
        config_digest=digest,
    )
    grant = await client.authorize(
        action="issue", session_id=payload["session_id"], access_jwt=payload["jwt"],
        expected=expected,
    )
    print(json.dumps({
        "decision": "allow", "action": grant.action, "subject": grant.principal.subject,
        "profile_id": "hermes-desktop",
    }), flush=True)


async def probe_as_foreign_peer(payload):
    reader, writer = await asyncio.open_unix_connection(payload["socket_path"])
    writer.write(b'{"version":1,"action":"issue","nonce":"AAAAAAAAAAAAAAAAAAAA",'
                 b'"profile_id":"hermes-desktop","session_id":"BBBBBBBBBBBBBBBBBBBB",'
                 b'"config_digest":"' + b"0" * 64 + b'","access_jwt":"fixture"}\n')
    await writer.drain()
    try:
        response = await asyncio.wait_for(reader.readline(), timeout=1)
    except (asyncio.TimeoutError, ConnectionResetError, BrokenPipeError):
        response = b""
    writer.close()
    try:
        await asyncio.wait_for(writer.wait_closed(), timeout=1)
    except (asyncio.TimeoutError, ConnectionResetError, BrokenPipeError):
        pass
    print(json.dumps({"response_bytes": len(response)}), flush=True)


def main():
    mode = sys.argv[1]
    if mode == "service":
        asyncio.run(serve_fixture(sys.argv[2]))
        return
    payload = json.loads(sys.stdin.read())
    if mode == "gateway":
        asyncio.run(use_gateway(payload))
    elif mode == "foreign":
        asyncio.run(probe_as_foreign_peer(payload))
    else:
        raise SystemExit("unsupported fixture mode")


if __name__ == "__main__":
    main()
