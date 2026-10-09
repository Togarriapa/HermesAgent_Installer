# Remote desktop setup state

The Cloudflare adapter discovers active zones with a setup-only scoped token using a wall-clock-bounded HTTPS client. It derives account IDs from zone responses, matches DNS suffixes at label boundaries, and requires an enrolled Zero Trust organization before Access configuration. Token values remain in process memory and are excluded from URLs and errors.

This adapter does not yet create Cloudflare resources or activate DNS. Existing DNS, tunnels, Access applications, policies and identity providers are preserved. Plan, doctor and verify send no DNS or tunnel mutations.

Hostname input has no default; noninteractive use must provide an explicit validated value. Account, zone, OTP email list and a secure API-token reference are target inputs, not repository configuration. If there is no enrolled Zero Trust organization or the hostname is outside the existing certificate coverage, remote access remains unavailable with an actionable explanation. No purchase is initiated by setup.

Recording-transport tests prove bounded request cancellation, redacted errors and zone discovery only. They do not prove live account permissions, Access behavior, DNS, tunneling, native Desktop confinement or revocation. Live acceptance remains pending.
