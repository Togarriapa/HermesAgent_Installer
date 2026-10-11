## ADDED Requirements

### Requirement: Core-only component selection
The installer SHALL accept explicit core-only selection, resolve only official Agent and required isolated PM runtime prerequisites, and separate core preflight from graphical/Desktop gates.

#### Scenario: Core selected without graphical session
- **WHEN** the user selects core only
- **THEN** graphical/Desktop requirements do not block the selected core prerequisites.

### Requirement: Adoption preserves existing state
The installer MUST inventory and journal homes, memory, configuration, authentication references and owned services. It MUST preserve Codex auth without duplication and stage reviewed pinned upstream installation in installer-owned roots rather than reset an adopted tree.

#### Scenario: Adopt existing core safely
- **WHEN** an existing home and authenticated runtime are present
- **THEN** adoption verifies ownership and current bytes, retains existing state and secret references, and proves real core health and harmless chat before switching owned service pointers.

### Requirement: Reversible owned-service retirement
Desktop SHALL leave the active installation/Pi path only after independent core service proof and recoverable owned-service retirement.

#### Scenario: Missing dependency or failed migration
- **WHEN** runtime/account proof is missing or a switch fails
- **THEN** status is pending with exact resume/recovery, old data/auth and unrelated services remain intact, and no plan/source-only READY is returned.

### Requirement: Incremental capability preservation
The product MUST retain the original functional obligations while porting actual capabilities individually: Bots DM and full durable groups/relay, skills, plugins/MCP, messaging, jobs, tool progress, approvals, browser use, menus/settings, artifacts/files, profiles/memory and voice. Electron-specific conveniences MUST receive an explicit alternative or pending status rather than an unsupported parity claim. No original declaration inventory substitutes for functional evidence.

#### Scenario: Bot group survives Desktop retirement
- **WHEN** a group capability is declared available
- **THEN** server-owned full room and orchestration state plus actual relay survive restart; a bounded ui_meta mirror alone cannot pass.

### Requirement: Private core bridge
The core bridge MUST use the existing private authenticated hermes serve /api/ws JSON-RPC runtime with pinned session.create, prompt.submit, session.history/replay and session.interrupt contracts. It SHALL NOT substitute the separate API-server platform or expose raw RPC/tokens/system parameters.

#### Scenario: Browser submits a chat request
- **WHEN** an authenticated browser requests chat
- **THEN** a finite server-side adapter invokes the pinned runtime contract without disclosing backend credentials or accepting arbitrary RPC methods.

### Requirement: Responsive principal-owned Jarvis
The UI SHALL use a real HTML mobile composer and finite server-side core adapters, with authenticated principal-derived conversation/run ownership and explicit owner/family permissions. Shared runtime conversation ownership SHALL NOT imply filesystem/tool/global-memory isolation.

#### Scenario: Family requests private state
- **WHEN** a different principal requests a private conversation
- **THEN** the request is denied and private capabilities remain unavailable until real isolation/grants exist.

### Requirement: Protected public transport
Jarvis MUST retain Cloudflare OTP/binding protection, JWT-before-bytes, same-origin CSRF, bounded active-stream expiry/revocation and protected loopback backend credentials. Raw backend RPC, shell, arbitrary URLs and management endpoints SHALL NOT be public proxies.

#### Scenario: Authorization expires or revokes
- **WHEN** authorization expires or revokes
- **THEN** the request/stream is denied, including further bytes and input.

### Requirement: Phased evidence and preserved scope
Core precedes individual capabilities, UI, full Resources enrichment and end-to-end review. Useful increments SHALL ship without waiting for every original task, with exact pending feature status. All 208 Resources source identities and original budget/privacy/model/Coral obligations remain tracked. HA live configuration remains deferred. Tests/fixtures/validation SHALL run only on the identified Pi via root browser.

#### Scenario: Initial useful increment
- **WHEN** core and one actual capability are verified
- **THEN** UI work may proceed while other capability and full acceptance tasks remain OPEN; no complete parity is claimed.

### Requirement: Server-owned stored-session resume
The private bridge SHALL retain principal/conversation ownership of stored_session_id. On core restart or generation change it MUST invalidate stale live IDs and use pinned official session.resume to bind a fresh runtime session_id to the same owned conversation. History/replay and interrupt MUST use that fresh ID; browser-supplied IDs SHALL NOT confer ownership.

#### Scenario: Resume after core restart
- **WHEN** an authenticated owner opens a retained conversation after restart
- **THEN** the server resumes the exact stored session privately and uses the validated fresh runtime ID.

#### Scenario: Unknown or stale resume state
- **WHEN** ownership/state is unknown, ambiguous, malformed or the runtime changes during resume
- **THEN** the bridge denies without creating replacement history or exposing another conversation.

### Requirement: Concrete finite root installer action
The selected-target user/root terminal action SHALL execute the actual reviewed finite core install/resume/rollback adapter. The adapter MUST verify source, PM executable/lock, owned unit/config/token custody, loopback, owner and journal. It SHALL NOT accept arbitrary commands, units, credentials or unowned services, or wait on a nonexistent callback.

#### Scenario: Owned core switch and recovery
- **WHEN** the authorized selected-target action switches or rolls back core
- **THEN** only journaled owned files/pointers/services change and existing home/Codex auth, backups and unrelated services remain intact.
