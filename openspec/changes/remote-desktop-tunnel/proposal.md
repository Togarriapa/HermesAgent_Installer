# Proposal

## Why

The user needs authenticated browser access from a Cloudflare Tunnel to the genuine Hermes Desktop on the Pi without exposing the host desktop or management services. Automatic secure setup must start from a blank user-selected hostname and scoped token.

## What Changes

- Add native app-only browser streaming through an authenticated loopback gateway.
- Automatically provision/reuse only owned Cloudflare tunnel/DNS/Access/email-code resources with transaction/resume/recovery.
- Enforce page/asset/WS authorization, JWT validation, principal isolation and bounded live socket expiry/revocation.
- Preserve original twelve acceptance criteria and add AC13..15 for this direct-user extension.

## Capabilities

### New Capabilities

- `remote-desktop-access`: Automatic owned Cloudflare enrollment and protected browser-only official native Hermes Desktop streaming.

### Modified Capabilities

None; earlier installer capabilities remain active proposals. Their integration DAG/evidence now includes this change.

## Impact

src/hermes_installer/remote/, secure credential/config/lifecycle adapters, dedicated application session/services, Cloudflare API/Access/tunnel configuration, browser tests and docs. No live Pi/account/DNS mutation is performed by this planning change.

Root-observed remote session bridge HI13: plans/amendments/2026-10-09-remote-root-session-bridge-v1.md and planning/remote-root-session-bridge-contract.json specify actual JWT/current policy/root principal binding, no gateway selfsigned claim substitute, fixed allbytes connector lease and active revocation. Management/read/tunnel credential separation preserved; native/account evidence open.

HI13 remote root wire v2: plans/amendments/2026-10-09-remote-root-session-wire-v2.md defines typed opaque responses/challenge/rootselectedconnectorframes, distinct one-shotasset/leasedWS, internal freshHI12grant enforcement. ExistingHI-T13/RT-F03 and actualtarget evidence remainopen.

Protected runtime assembly v1: plans/amendments/2026-10-09-protected-runtime-assembly-v1.md and planning/protected-runtime-assembly-contract.json define rootactivegeneration catalog, exact native closure/import/mount, devicekernelpolicy, dynamicbuild outputreceipt and fullcanonical effectdigest/rootpeeridentity. ExistingHI07/08/09/11/13/HW02/03 tasks/evidence remainopen.
