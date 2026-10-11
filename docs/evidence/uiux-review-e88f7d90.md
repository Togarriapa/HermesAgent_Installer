# UI/UX review checkpoint: candidate e88f7d90

This is a candidate-bound **pending** review for `e88f7d907c36cae9ccaa03680ee3a3e7a87a1a38`, mapped to `jarvis-core-platform`, R0203, RT-T266.3, and VD-T266.5. Full-shell and focused review are required because this candidate changes several primary flows. Pi validation/rendering is still in progress; no actual candidate UI review or clearance is claimed.

## Candidate and evidence state

- Candidate source SHA: `e88f7d907c36cae9ccaa03680ee3a3e7a87a1a38`
- Pi source archive: `hermes-jarvis-core-source-native-owner-final-v3.tar.gz`
- Archive SHA-256: `86c16c119331746551290c0ae11afde84c6a7dffebbe34bca28c07f8b7e21f30`
- Target: identified Pi; exact render time/reviewer/capture paths are pending Root's Pi run.
- Candidate checks/rendering: in progress; the expected check directory is `/var/tmp/hermes-jarvis-core-checks-20261011/final3-source/`. No final result was supplied when this record was written.
- Historical context only: related `6a7d66488` reported 417 passed, 11 skipped, and one stale asset assertion failure. Candidate source runtime is reported byte-identical to that earlier source; the change is test-only. Neither result qualifies the e88 UI.
- Current live target remains the earlier `dabdc` UI. It has not been replaced by e88; migration is held.

## Review scope and planned captures

Review the actual e88 candidate in a non-public Pi view before deployment. The preview method and candidate render are pending Root's Pi run. Capture the affected route and state at phone, tablet, and desktop sizes; record exact viewport dimensions and redacted capture paths. The sizes have not yet been selected or observed, so none are asserted here. Include a full-shell navigation pass and focused captures for each affected flow below.

| Area | Planned interaction and states | Status / capture |
| --- | --- | --- |
| Overview reactor | Check motion pause/visibility, hidden/offline state, and the current protected GET telemetry provenance. | Not reviewed on e88; capture pending. |
| Navigation/assets | Traverse finite/chunked feature assets and each destination; inspect labels, duplicate entries, focus order, and load/error states. | Not reviewed on e88; capture pending. |
| Projects | Inspect context menus and restore flow, including confirmation, conflict/error, and resulting state. | Not reviewed on e88; capture pending. |
| Per-message model selection | Inspect placement, naming, selected-for-message state, failure/unavailable state, and whether the UI accurately describes persistence. | Not reviewed on e88; capture pending. |
| Obsidian graph/vault | Inspect graph navigation, vault/context selection, data retention, and any write/delete consequences before use. | Not reviewed on e88; capture pending. |
| Profiles/Extensions | Inspect create/update/delete guards, target naming, authorization, destructive consequences, and recoverable/error states. | Not reviewed on e88; capture pending. |

## Cross-cutting UX checks

All remain **not reviewed on e88** until actual rendered captures and interaction observations are attached:

- Placement, naming, hierarchy, and duplicate navigation across the full shell.
- Phone/tablet/desktop reflow and touch target sizing at actual viewport dimensions.
- Keyboard navigation, focus visibility/order, and mobile text-entry behavior.
- Reduced-motion behavior, including reactor pause/visibility changes.
- Loading, empty, error, offline, unavailable, and recovery states for every changed flow.
- Confirmation and recovery for destructive project restore, vault, profile, and extension operations.
- Data retention and user-visible effects of Obsidian graph/vault actions.
- Capability labels and status claims match the exact protected API/backend provenance and do not imply unverified effects.

The focused view captures, full-shell walkthrough, and each changed interaction must be reviewed against this record after the Pi run. Fixtures and source tests can support implementation checks but do not clear the UI gate. The record remains **pending**, not ready for deployment review, until the actual e88 render, findings, and blockers are recorded. All 219 requirements, eight broad groups, and overall acceptance remain open.
