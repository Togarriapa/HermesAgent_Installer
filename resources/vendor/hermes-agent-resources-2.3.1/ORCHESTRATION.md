# Parallel and Hierarchical Orchestration

Hermes orchestration is dependency-graph based, not sequential by default. The objective is to recruit the **smallest competent structure that can safely satisfy the request**, then scale only where independent work or specialist review creates real value.

## Execution model

For every non-trivial Epic, Orchestrator builds a dependency DAG and one ephemeral Kanban. Work packages should identify:

- objective and acceptance criteria;
- dependencies and blocking inputs;
- assigned Profile instance/team;
- bounded context and relevant evidence;
- required tools/permissions/account scope;
- expected artifact/result;
- verification method;
- risks and rollback/containment where state may change;
- status, retry/failure state, and handoff destination.

Independent nodes may execute concurrently. Sequencing is introduced only by actual dependency, shared-state, resource, authority, or safety constraints.

## Recruitment and team formation

Orchestrator and authorized Team Leaders may recruit any registered Profile, including outside the active Bundle. Bundles are starting compositions rather than ceilings.

Recruitment follows these preferences:

1. reuse an already-active competent specialist when doing so does not create overload or context collision;
2. prefer the smallest team that covers the required responsibilities;
3. add independent reviewers for material risk, contested evidence, or irreversible decisions;
4. create additional instances when work packages are genuinely parallelizable;
5. release specialists when their assignment/handoff is complete.

A specialist's absence from the starting Bundle is not a reason to make a less-qualified Profile improvise outside scope.

## Elastic Profile instances

The registry does not impose a numeric maximum on instances of a Profile. Orchestrator may instantiate multiple copies when parallel capacity is useful—for example, multiple Developers for independent code packages or multiple Analysts for a broad research universe.

Each instance has:

- a unique runtime identity and correlation ID;
- one bounded assignment/context;
- the original Profile's effective quality contract and permissions;
- separate state/workspace where concurrent writes could collide;
- an explicit lifecycle and parent coordinator.

Actual concurrency is constrained by host CPU/RAM/storage, workspace isolation, provider/API limits, credentials, account scope, rate limits, cost policy, user/host authorization, and physical-system safety.

**Scaling creates capacity, never authority.** Ten instances do not collectively acquire a permission that one instance lacks.

## Parallel technical/state-changing work

Concurrent writers must not mutate the same uncontrolled state. Code/configuration work uses isolated branches/worktrees/workspaces and reconciles through an explicit integration/review gate.

For other shared state, Orchestrator must choose one of:

- partitioned ownership with non-overlapping targets;
- a single serialized writer with parallel read/analysis workers;
- transactional/lock-aware coordination supported by the target system;
- proposal-only parallel work followed by one authorized execution step.

State-changing work records pre-state, requested change, permission used, result, verification, and rollback/compensation when feasible.

## Resource budgets and backpressure

Parallelism should stop increasing when marginal value is lower than resource/cost/rate-limit/context overhead. Orchestrator may throttle, queue, or collapse work when:

- provider limits are approached;
- the host is memory/CPU/storage constrained;
- concurrent tasks contend for the same state;
- evidence gathering has reached diminishing returns;
- the next useful action depends on user input/permission;
- additional instances would duplicate rather than diversify work.

A resource limit should become an explicit blocked/risk state, not silent degradation.

## Failure, retry, cancellation, and partial completion

A failed work package is classified before retry:

- transient tool/network/provider failure → bounded retry/backoff;
- invalid input/evidence → correct or escalate;
- permission/authorization failure → stop and return exact permission needed;
- unsafe/regulated boundary → stop and recruit/escalate;
- deterministic implementation defect → fix/review rather than blind retry;
- dependency failure → block downstream nodes and reassess the DAG.

Cancellation propagates to descendants that no longer have a valid purpose. Completed independent results are preserved when still useful. Orchestrator reports partial completion explicitly rather than representing an incomplete Epic as done.

## Deliberation and reconciliation

When material trade-offs, ambiguity, or conflicting evidence exist, Orchestrator may use the deliberation protocol in `DELIBERATION.md`. Independent first-pass positions should be collected before cross-influence where practical.

Reconciliation should preserve:

- supporting evidence and source dates;
- assumptions and uncertainty;
- material dissent and thesis-break conditions;
- unresolved contradictions;
- exact permissions needed for the selected next action.

Majority vote is not the reconciliation rule.

## Epic Kanban lifecycle

Each Epic board contains relevant `Epic`, `User Story`, `Task`, `Defect`, `Spike`, `Risk`, and `Decision` items. Canonical states are `Backlog`, `Ready`, `In Progress`, `Review`, `Blocked`, and `Done`.

The board should make dependencies, ownership, verification status, blockers, material decisions, and required permissions visible to the orchestration layer. Repository-backed work may use GitHub Projects v2; other work uses a local ephemeral backend.

Completion requires:

1. required work packages complete or explicitly accepted as out-of-scope/deferred;
2. acceptance criteria verified;
3. material dissent/risks captured;
4. state changes reconciled and failures disclosed;
5. a concise completion summary archived.

Only after accepted completion is the ephemeral board deleted.

## User-facing topology

Orchestration depth never changes the user path:

`User <-> Hermes <-> Orchestrator <-> Teams / Specialists`

Clarifications, progress requiring user attention, material failures, permission requests, and final results return upward through Orchestrator to Hermes. Internal Profiles never become direct user endpoints.

## Effective quality and authorization

Every Profile/Skill/Bundle involved in orchestration is materialized with `QUALITY_POLICY.yaml`. Orchestration may select, compose, or parallelize capabilities, but it cannot grant them. Host/runtime policy remains the absolute authorization ceiling.
