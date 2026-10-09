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
`ResourceEventContextIssuer` inside the authority process. An attached producer
receives an opaque per-instance capability and can create a one-use
`RootResourceSourceEventProof` only at its native accepted-event seam. The
proof is not serializable and carries the exact canonical event bytes plus an
opaque producer observation that is revalidated when consumed. Before an
event or receipt exists, `RootResourceControllerRegistry` resolves the
selected role/issuer/backend through `resolve_selected_ingress_controller` and
retains a one-use `RootIngressControllerProof` backed by live systemd MainPID,
PIDFD, executable, namespace, and loaded-role evidence. The registry's
`capture_selected_ingress` consumes that retained proof and the exact producer
observation together. The issuer rechecks current resource generation and
consent, the selected observer and source policy, and the live controller
proof, then signs the original private `HostContext` and source receipt. The
HTTP/audio adapter's exact proof-bound receipt handles are resolved once by
its root observer to actual service-signed `SourceReceipt` objects; the issuer
rechecks signature, current profile/principal/generation, source-kind policy,
expiry, and complete parent closure before signing the event receipt with those
parents. The event context carries the sorted parent receipts and event receipt
together, so the registry can verify the full signed closure without trusting
receipt objects supplied in an RPC or event DTO. Missing resolver wiring fails
closed. The registry atomically retains that signed closure as the root event; child-node
issuance separately revalidates the selected backend/body recipe and current
controller custody.

The proof/capsule interfaces are root-internal only. Worker RPCs, reconstructed
dataclasses, caller-supplied root contexts, event labels, and serialized HMAC
or timer claims cannot enter this path. A producer without a concrete native
provenance verifier and the root registry's pre-event custody proof remains
unavailable. HTTP and audio channel inputs use distinct v40 typed selection
and observation proofs; they cannot reuse Telegram/Discord or webhook proof.
