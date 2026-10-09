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
are implemented. The parser has been aligned with per-node backend IDs and the
`execution_binding` process-task record; each fixed process task is specified
to use a separate root `process.start` grant. The current checkout still does
not assemble active scope/validator/schema catalogs, a root source observer and
result-capsule path, the process-task launcher, or a concrete selected native
backend. Those missing joins keep admission and child effect handlers
unregistered. Dynamic event/result/scope recipes fail closed. The fixture
tests establish ledger and parser behavior only; no cron, webhook, channel,
bundle, or Hermes profile task effect is established.
