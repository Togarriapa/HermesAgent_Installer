# Hermes Conversation Topology

The canonical conversational topology is:

`User <-> Hermes <-> Orchestrator <-> Specialist Profiles / Team bundles`

The transport may be text, audio, or an authenticated messaging adapter, but the conversational identity, authorization boundary, and routing do not change.

## Single point of contact

`hermes` is the **only** Profile permitted to bind to user-facing channels or communicate directly with the end user. All other Profiles are internal-only.

Current user-facing channels are web, Telegram, Discord, WhatsApp Business, and local voice/audio.

Every user-facing channel must:

- authenticate the connection or enforce an explicit sender/chat/guild allowlist appropriate to the transport;
- bind a verified external identity to one Hermes conversation/session context;
- route inbound messages/transcripts to `hermes`;
- reject client attempts to select another Profile directly;
- deliver outbound user-visible text/speech only through `hermes`;
- route scheduled notifications, webhook outcomes, alerts, clarification requests, and specialist follow-ups through `hermes` when intended for the user;
- prevent cross-user/session context leakage;
- apply bounded payload/rate/attachment handling and message/event deduplication where the transport supports identifiers;
- redact secrets/sensitive values from operational logs.

WhatsApp does not turn Personal Assistant or another Profile into a direct contact. Voice does not turn Home Assistant Optimizer or Smart Home & IoT Engineer into a voice endpoint.

## Hermes responsibilities

Hermes owns conversation intake, modality handling, user identity/session correlation, clarification, permission/confirmation presentation, and final delivery—not specialist execution.

Hermes preserves the request, constraints, relevant context, input modality, desired output, correlation IDs, and current user authority, then hands work-bearing requests to Orchestrator.

For voice:

`Audio -> STT -> Hermes -> Orchestrator -> ... -> Hermes -> TTS -> Audio`

For WhatsApp:

`WhatsApp Business -> Hermes -> Orchestrator -> ... -> Hermes -> WhatsApp Business`

Hermes does not directly recruit specialists. Orchestrator owns decomposition, routing, recruitment, team composition, parallelism, deliberation/conflict resolution, execution coordination, and synthesis.

If more information is required, the internal chain returns a structured clarification request to Hermes. Hermes asks the user through the active authenticated channel and returns the answer into the same correlated orchestration flow.

## Orchestrator responsibilities

Orchestrator accepts user-originating work only through Hermes. It may recruit any registered specialist Profile or suitable team Bundle, including outside the initial roster.

It may:

- run dependency-independent work concurrently;
- create multiple instances of the same Profile;
- delegate Epic branches to Team Leaders/nested subteams;
- maintain the dependency graph and ephemeral Kanban;
- run adaptive deliberation;
- reconcile parallel results and state changes;
- return structured result, contributor, dissent, verification, and required-permission metadata to Hermes.

Nested orchestration never changes the user-facing route. Deep internal results flow upward to Orchestrator and then Hermes.

## Specialist responsibilities

Specialist Profiles are internal roles with bounded expertise and authority. They receive only the context/tools/permissions needed for the delegated assignment and should return:

- result/artifact;
- evidence/material sources;
- assumptions/uncertainty;
- verification status;
- material risks/dissent;
- state changes performed;
- missing permissions or next handoff.

They may collaborate only through authorized internal orchestration paths. Their expertise may be named in Hermes' final answer, but the conversational identity remains Hermes.

## Session and correlation security

Each user-originated request should carry an internal correlation identity separate from untrusted client-supplied Profile names or task IDs.

The runtime should prevent:

- one user/channel identity resuming another user's private context;
- replayed inbound messages creating duplicate privileged actions;
- a webhook/event ID being confused with a user confirmation;
- stale confirmations being reused for changed transaction/action payloads;
- specialist output being delivered to a different conversation without explicit correlation.

Permission/confirmation objects should be one-shot, payload-bound where material, and expire according to the action's risk.

For infrastructure-changing requests, the correlated authenticated Hermes principal must be mapped to Authentik and freshly verified as an effective member of `System` before the target tool call. User-supplied identity/group fields in the request are never authoritative.

## Scheduled and event-driven results

Cron jobs and webhooks are internal triggers, not alternate user identities. Receipt of a schedule tick or webhook event does not grant authority beyond the resource/host policy.

When their outcome is user-visible, the normal route is:

`Cron/Webhook -> internal handler/Orchestrator -> Hermes -> authenticated user channel`

Infrastructure alarms add a recipient-authorization step:

`health/event signal -> internal triage -> fresh Authentik effective System resolution -> Hermes -> authenticated channel(s) for verified System members`

An infrastructure alarm is not delivered to a non-`System` user merely because that user has an active Hermes session, received a prior alarm, appears on a static recipient list, or triggered the original diagnostic request. If current recipient authorization cannot be verified, alarm delivery fails closed.

## WhatsApp constraints

WhatsApp support is limited to supported WhatsApp Business integration. Personal-account automation is not an accepted route. Account/contact administration and destructive actions are denied by default. Proactive outbound communication requires separately delegated/template-authorized behavior.

## Voice constraints

Voice is local-first through Home Assistant/Wyoming. Raw audio is not retained by default and cloud fallback is denied. Speech transcription enters Hermes like any other input; spoken output is generated only from Hermes output. Safety-sensitive Home Assistant actions retain normal authorization/confirmation requirements.

Wake-word recognition or physical presence is **not by itself** sufficient authorization for privileged operations unless host policy explicitly establishes an appropriate trusted-presence mechanism.

## Authority and quality

Conversation topology does not expand permissions. Hermes cannot grant Orchestrator or specialists capabilities that host policy denies. Recruitment, multiple instances, Bundles, learned overlays, channel messages, and user confirmation cannot exceed the resource/host authorization ceiling.

`QUALITY_POLICY.yaml` supplies default session, failure, privacy, observability, and authority-non-escalation behavior. The runtime/provisioner must enforce topology and effective policy structurally rather than relying only on prompt instructions. Direct user-channel addressing of a non-Hermes Profile fails closed.
