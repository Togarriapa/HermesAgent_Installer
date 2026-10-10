# Protected resource jobs

`hermes_installer.registry.resource_jobs` provides the root-side durable state
machine for a selected, immutable cron, webhook, channel, or bundle DAG.
Enrollment is built from protected installation state and pins the resource
generation, principal/profile, consent revision, action and target allowlists,
recipient scope, source policy, DAG, and hard limits. The admission API accepts
only an event identity plus opaque source receipt IDs; it does not accept a
caller-supplied URL, account, credential, path, executable, UID, PID, schedule,
or mutable graph.

`ResourceJobLedger.admit_job` atomically records one source event and creates
one pending child slot per approved DAG node. Its bounded SQLite ledger keeps
event claims through terminal job states and fails closed when full. It does
not prune historical claims, so capacity exhaustion needs a reviewed
root-owned retention policy before production ingress. Each
`admit_child` call atomically consumes exactly one child slot after checking
the active generation, job deadline, concurrency, graph prerequisites, and
exact result receipt lineage. `start_child`, `finish_child`, `retry_child`, and
`revoke_generation` enforce the remaining state transitions. Retry requests are
root-internal decisions, get a new admission ID and incremented retry index,
and are bounded by the enrollment's aggregate `max_children` quota. Each
attempt must therefore obtain its own fresh child context and one-use grant.
Generation
revocation invalidates pending, admitted, and running work in the ledger. The
effect runner must pass `is_active` as its cancellation predicate so the
broker can stop or reap owned work at its next cancellation check. Failed
nodes cancel transitive dependents while unrelated children and terminal
result receipts remain recorded. If context or grant minting fails, the
authority handler must call `fail_child_admission`; it may create a new
admission through `retry_child` only under the same root-selected retry policy.
Once the bounded attempts are exhausted, it calls `fail_node` to cancel
descendants.

The child admission contains the exact selected operation, target, recipient,
payload digest, source receipts, and completed-parent receipts. It is not an
authority context or effect grant. The root AuthorityService must validate the
signed source receipts before calling `admit_job`, then use each child
admission to create a fresh reduced-scope context and one-use grant for that
exact operation and payload. Runtime `WebhookReceipt` objects are unsigned and are
not accepted in place of root-issued receipt IDs. No channel send or live
account action is performed by these fixture tests.

Receipt-ID parameters are private root-service inputs. Passing an ID to this
ledger does not authenticate it; AuthorityService must verify each signed
receipt and bind its event body before making the call. Likewise,
`finish_child` must receive only IDs issued by the root after it validates the
broker response. These methods are not safe to expose as worker RPCs.

Current state: the SQLite admission/DAG backend and root handler-factory draft
are implemented. The parser joins active per-node backend, scope, validator,
body recipe, source issuer, and observer records; it rejects an observer whose
origin, action, or capture schema does not match the selected route. The
admission handler resolves the exact signed source receipt through the
root-private `SourceObserverRegistry`, consumes its one-use payload capsule,
and retains only recipe-selected fields that pass protected validators. The
retained event projection is bounded, job-expiring, and scrubbed when the job
terminates, expires, or is revoked. Caller-supplied event bytes and unsigned
webhook receipts cannot supply recipe values.

Root ingress now has a separate `ResourceJobAuthority.admit_root_resource_event()`
entry point. Producers pass only the exact in-process `RootResourceEventHandle`
returned by the selected root controller registry; the method rechecks the
active resource generation and consent, signed parent context, full source
receipt closure, event digest, root controller lease, deadline and cancellation
before writing the replay-keyed job row. It retains the validated event fields
and source closure under the resulting job ID. This does not expose admission
over worker RPC and does not make target or account acceptance evidence.

The v66 predecessor-result closure is still required before a root dispatcher
can safely advance dependent DAG nodes. Until the shared resolver and fresh
root task/controller path are attached, admission alone does not establish
that a job ran; RB-T08/EV-RB07 remain open.

For a selected profile task, the private admission row retains the actual
verified `_JobEvent`, signed parent context, and complete source receipt
objects beside the one-use node handle. `resolve_admitted_task_source()` is
available only after consuming that exact handle and rechecks the current
resource/profile generation, consent, child attempt, lease, parent closure,
and protected process/native recipe joins. It returns immutable event/result
projections and neutral `RootAdmittedTask` / `RootAdmittedTaskSource` DTOs.
The source DTO carries only root-private opaque receipt handles, canonical
signed receipt wires, lineage, subject metadata, and a controller lookup
handle; `_JobEvent`, `HostContext`, and receipt objects stay in the authority's
private registry. The controller resolver rechecks a worker producer through
the attached `SourceObserverRegistry` and transfers one duplicated PIDFD in
the typed `RootTaskController`. Timer, webhook, and channel controller
resolvers remain absent, so those event classes remain unavailable. The
closure digest binds the signed context/receipts, source-capsule provenance,
selected scope IDs, event fields, and predecessor result fields.

Admission and child handlers remain unavailable unless root composition joins
the current protected catalogs and installs the concrete selected process-task
launcher and terminal/result capsule consumer. Each fixed process task is
specified to use a separate root `process.start` grant. In particular, the
current checkout has no `AuthorityService.launch_resource_profile_task` or
result-capsule completion path, and no root timer/webhook/channel controller
issuer. Profile-task nodes and dependent DAG nodes must not be reported as
functional. Dynamic result/scope recipes fail closed. Fixture tests exercise
ledger/parser behavior and typed root source/controller resolution; they do
not establish cron, webhook, channel, bundle, Hermes process custody, or target
effects.
# Root source-event authority

Root timer, webhook, and channel adapters must be attached to the active
`ResourceEventContextIssuer` inside the authority process by
`register_selected_source_producer(producer, selected_ingress_binding=...)`.
The issuer accepts only the exact protected `RootSelectedIngressBinding` and a
concrete producer with a one-use `consume_verified_raw_observation` method;
there is no caller-supplied boolean validator or caller-selected mint API.
After live custody resolution, the producer passes its exact pending opaque
observation to `mint_selected_source_proof(capability,
controller_proof=proof, raw_observation=observation)`. The issuer creates a
sealed immutable raw snapshot and one-use `RootResourceSourceEventProof` whose
payload is the exact original input bytes. It separately derives the canonical
v67 envelope from the selected schema and validated event fields; the signed
receipt covers the envelope while the retained record binds the raw bytes,
digest, replay key, and observation time. Webhook event schemas are selected by
the root-only `selected_protocol_schema(resource_id, generation,
source_issuer_id, source_kind)` resolver and checked against the pinned
artifact IDs/hashes; an absent or unknown mapping denies registration. Before an
event or receipt exists, `RootResourceControllerRegistry` resolves the
selected role/issuer/backend through `resolve_selected_ingress_controller` and
retains a one-use `RootIngressControllerProof` backed by live systemd MainPID,
PIDFD, executable, namespace, and loaded-role evidence. The registry's
`capture_selected_ingress` consumes that retained proof and the exact producer
observation together. The issuer rechecks current resource generation and
consent, the selected observer and source policy, and the live controller
proof, then signs the original private `HostContext` and source receipt. For
HTTP and audio ingress, JWT/session and consent/device/capture proofs remain
typed root-retained transport evidence, not fabricated `SourceReceipt`s. The
selected observer revalidates and consumes the exact opaque observation at
capture; a genuine initial event may therefore have an empty parent-receipt
chain. If an active source policy supplies actual signed parent receipts, the
issuer verifies their signature, current profile/principal/generation,
source-kind policy, expiry, and complete closure before including them. The
v94 HTTP/audio schemas are pinned as `channel-http-observed-event-v1`
(`7626756c12b9020248423114e0df294fc7c2c5c74def36e535244de81bd4452c`) and
`channel-audio-observed-event-v1`
(`cfbd9c9a41299293776666201298e4cdf3be388e91ec7c8ff05d2931520965fb`). Audio
event payload contains metadata and artifact digests only; captured PCM stays
in its separately bounded, root-owned artifact and never enlarges the event
payload ceiling. The event context carries any verified parents and the event
receipt together, so the registry can verify the full signed closure without
trusting receipt objects supplied in an RPC or event DTO. Missing resolver
wiring fails closed. The registry atomically retains that signed closure as the root event; child-node
issuance separately revalidates the selected backend/body recipe and current
controller custody.

The proof/capsule interfaces are root-internal only. Worker RPCs, reconstructed
dataclasses, caller-supplied root contexts, event labels, and serialized HMAC
or timer claims cannot enter this path. A producer without a concrete native
provenance verifier and the root registry's pre-event custody proof remains
unavailable. HTTP and audio channel inputs use distinct v40 typed selection
and observation proofs; they cannot reuse Telegram/Discord or webhook proof.

The selected webhook adapter preserves the exact signed HTTP body separately
from the parsed protocol fields. It checks the selected GitHub/registry event
schema and root-selected repository scope before claiming a durable replay key
bound to resource ID, resource generation, and delivery ID. The returned
object is retained by identity and can be consumed once by its issuer-registered
per-route producer while a matching live ingress-controller PIDFD proof is in
force. The issuer, not this adapter, mints the v67 source proof and canonical
event envelope. `accept_request` alone still does not create a source receipt,
admit a job, or dispatch a task; production requires root composition to attach
the selected bindings, issuer, custody registry, and durable replay store.
