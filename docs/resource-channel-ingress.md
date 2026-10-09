# Selected channel ingress

`authority.resource_channel_ingress` contains bounded root-side ingress adapters
for authenticated events. All active adapters require the protected selected
channel row, current generation, account/session proof, exact route or native
connector proof, durable replay storage, and the attached `ResourceEventContextIssuer`
and `RootResourceControllerRegistry`. A constructible `MessageEvent`, raw user
ID, or boolean is never an authority credential. Captured payload bytes are
canonical and are bound to the issuer proof, source receipt, selected channel
resource, observer enrollment, and generation.

`ComposioV3WebhookIngress.accept_request(request)` implements the Composio V3
webhook path for the protected selected WhatsApp row. The injected route reader
must return a root-owned route proof that revalidates the exact raw request and
selected route; the secret reader resolves a vault reference without exposing
secrets outside root memory; account/schema readers must return current
revalidatable proofs. The adapter verifies the V3 HMAC over the raw body,
signature timestamp window, unique-key JSON envelope, selected trigger/account
metadata, discovered-and-selected schema digest, event age, and explicit
sender-number mapping against the protected E.164 allowlist. It then reserves
the provider event identity in the durable replay ledger, mints one source
proof, and atomically captures it through root ingress custody. On capture
failure it rolls back the reservation so the provider can retry; a committed
duplicate returns the prior event handle only when its raw-body digest matches.
A conflicting body under the same provider ID is rejected. Catalog discovery
alone is not an active selection. An absent trigger schema, protected account,
route, or secret keeps the path unavailable with a specific failure reason. No
outbound message is sent. Signature encoding and V3 envelope fields follow the
[official Composio receiving-events contract](https://docs.composio.dev/docs/setting-up-triggers/subscribing-to-events).

`NativeChannelIngressProducer` wraps the pinned Hermes Telegram and Discord
SDK callbacks and accepted-event seam. Telegram callbacks must be the selected
PTB `Application`'s registered adapter handlers; Discord must be the selected
`commands.Bot`'s registered `on_message` callback. A delivery must join the exact
SDK message/update, Hermes normalized `SessionSource`/`MessageEvent`, selected
scope, current account-vault binding, and revalidated loaded Hermes package
evidence. It also reserves provider identity durably before minting a proof.
However, the root event issuer and registry are in the root service process,
while Hermes native channel callbacks execute in the profile process. No
worker-to-root authenticated source-event intake exists in this change. The
native producer therefore works only when root composition can install it in
the actual root-selected channel controller process with in-process issuer and
registry objects; profile-process callbacks must remain unavailable until a
fixed, separately authorized root-authenticated event path is composed. Passing
an issuer object or callback across a process boundary is not an IPC design.

HTTP and local-audio ingress have separate v40 selected-proof validators in
`components.plugin_channel_provenance` and root observers in
`authority.channel_provenance`. The HTTP observer requires a root-selected
listener to provide the raw request and the selected JWT/session verifier to
issue a current subject receipt. The audio observer requires root consent,
device, capture, and sealed-artifact services. These producer/observer APIs
remain unavailable until runtime composition supplies those concrete root
services and their source-receipt resolver. The
`provider-message-received` manifest label is not treated as a verified
Composio trigger slug or schema.

## Validation

Run `PYTHONPATH=src python3 -m pytest -q tests/contracts/test_resource_channel_ingress.py`
for fixture-only HMAC, route, allowlist, callback, selection, replay, and failure
coverage. These fixtures do not establish live account setup or target acceptance.
