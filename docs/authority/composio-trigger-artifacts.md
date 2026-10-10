# Composio trigger discovery artifacts

`RootComposioCatalogReader` performs the pinned, root-authorized Composio
WhatsApp trigger catalog reads. Its `inspect_and_persist_selected_type`
callpoint passes only the selected list row's slug and the actual detail GET
exchange receipt to `RootComposioTriggerArtifactRegistry`.

The registry reopens the receipt and exact response bytes from the root
exchange authority, checks the live setup session, project/principal,
toolkit-version and policy joins, and requires the detail slug to be present in
the authenticated list. It emits the schema artifact from the finite source
fields in the selected detail response. The semantic document hash excludes
the `sha256` property and final newline; the immutable CAS digest covers the
complete canonical UTF-8 document including that newline. The signed receipt
binds both digest domains and the actual exchange request/response digests.

The derived object is written only under the protected artifact staging root;
its signed receipt is journaled beneath the selected root journal. The
`active_catalog_binding` is a typed, root-produced tuple of artifact ID, exact
CAS digest, trigger slug and toolkit version for a root compiler to consume.
This code does not add the object to the static source catalog or mutate an
active generation. A prepared/active compiler publication must still bind
that result into the selected Composio channel enrollment before ingress can
resolve it.

Catalog discovery is not account setup. It does not prove a connected
WhatsApp Business account, configured trigger, webhook subscription/route,
signing-secret reference, or permitted sender-number mapping. Those remain
separate protected enrollment steps, and inbound delivery stays unavailable
until each is selected and verified.

Tests use synthetic trigger rows only. No live Composio account or outbound
message is used by this path.
