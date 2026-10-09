# Guided setup and account enrollment

`hermes-installer setup` is the terminal entry point for a fresh install or an
existing Hermes installation. It records the chosen components and data,
state, and optional model paths, then reports account integrations separately
from the install selection. An account component that is incomplete remains
pending and disabled; its selection is retained in the setup journal so resume
does not repeat completed checks.

The wizard uses the same validated JSON configuration as the lifecycle CLI.
Noninteractive callers supply a complete configuration and secret references;
the installer never accepts a raw credential from a configuration file,
argument, journal, diagnostic output, or command output. A pending interactive
setup should show the exact command in `WizardResult.resume_command` or
`next_steps`.

For each account field, the wizard explains what it controls, why it is needed,
links the official setup page, gives concrete steps, states account or billing
prerequisites, and runs an adapter's actual bounded connection check. A missing
adapter or skipped credential is reported as pending. A catalog entry or
credential reference alone does not mean the account is authenticated or
functionally usable.

## Remote Desktop account

The hostname prompt starts blank. Enter the complete DNS name you control, or
leave it blank and resume later. The wizard asks for the email allowlist, then
explains the scoped setup token and separate read-only policy token before
collecting either through hidden terminal input. The setup token and policy
read token are saved separately under the verified private installer state
root in mode `0600`; configuration retains only `file://` references. The
setup token is used for account and zone discovery. That discovery and storing
the second token are only an enrollment checkpoint; the Remote Desktop choice
remains pending until the resource stage has checkpointed this operation's
Access app, email policy, and OTP identity-provider IDs. The separate read
token must then pass the same fresh app, complete-policy-set, and OTP-provider
reads used by the runtime verifier. A foreign app or account-wide listing
cannot satisfy this check. Only after this exact read probe passes may the
remote-access stage continue toward the protected local gateway and publish no
route before its origin is ready.

The lifecycle continuation stores remote ownership in the private installer
operation journal before making Cloudflare writes. Its resumable operation is
keyed to the explicitly selected hostname and contains only the operation ID,
resource IDs, phase, and safe error code. It first stages the installer-owned
OTP identity provider, Access application, and exact allow-email policy. It
then checks the separate read token against those exact journaled IDs and the
complete policy set. A denied or incomplete read keeps the owned Access
checkpoint for resume and does not create a tunnel or DNS record. A passed
policy probe makes the component eligible for the later install stage, but the
setup result remains pending while the public route is inactive.

Route activation requires both a real protected-origin readiness check and an
enrolled host-owned token sink. The tunnel token is written through that
protected sink before DNS is created; the enrollment coordinator neither
constructs the sink nor returns the token. Missing origin readiness, token
storage, or current policy reads keeps the route pending. Foreign or changed
resources fail closed and remain untouched.

The scoped setup token needs account access for Cloudflare Tunnel Edit,
Access: Apps and Policies Edit, and Access: Organizations, Identity Providers,
and Groups Edit, plus zone access for DNS Edit and Zone Read. The read token
uses Access: Apps and Policies Read and Access: Organizations, Identity
Providers, and Groups Read; add Zone Read only when required for zone discovery.
Names can change; check Cloudflare's [current API token permission
reference](https://developers.cloudflare.com/fundamentals/api/reference/permissions/)
and [Tunnel setup guide](https://developers.cloudflare.com/tunnel/get-started/)
before creating a token. The wizard does not create or broaden tokens
automatically, buy a plan, or request an account-wide API key.

## Results and recovery

`WizardResult` has `state` (`ready`, `pending`, or `failed`), the validated
installable `config`, original `selected_components`, per-account states,
`resume_command`, and concrete `next_steps`. Incomplete remote choices remain
outside `config.components`, so ordinary install validation cannot activate
them. The remote setup journal checkpoints owned Cloudflare resource IDs so a
resume can retry the policy-read probe without recreating resources or asking
for successful inputs again. The private setup journal records only component
selections, paths, and redacted account states; it does not receive credential
values or references.

The CLI maps pending setup to exit code `4`, invalid setup to `2`, and failed
account checks to a nonzero failure result. JSON output uses the same structured
result as the terminal summary. Local setup checks do not establish live Pi,
Cloudflare route, authenticated user, or Desktop application acceptance.
