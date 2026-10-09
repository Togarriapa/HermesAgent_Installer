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
