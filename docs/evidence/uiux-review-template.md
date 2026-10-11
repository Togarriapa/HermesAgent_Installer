# UI/UX review record

Copy this file to a candidate-specific evidence path and complete it before deploying a user-visible change. This record is a focused usability review, not release acceptance, test proof, or permission to claim unverified behavior.

## Candidate and scope

- Candidate commit SHA:
- Review date/time and timezone:
- Reviewer:
- Change / requirement / task IDs:
- Changed visible features, routes, menus, settings, and affected source paths:
- Review type: focused screens / full shell
- Why this review type is sufficient; if full-shell review is required, list the shell journeys and surfaces reviewed:
- Exact Pi/runtime/browser and viewport(s) used:

## View evidence

For each relevant view, identify the route and user-visible state, the action used to reach it, and the redacted screenshot or capture path. Do not include credentials, tokens, private messages, personal email addresses, or other secrets.

| Route and state | Action / interaction | Capture reference | Candidate and viewport |
| --- | --- | --- | --- |
|  |  |  |  |

## Review findings

For each item, use `observed`, `issue`, or `not reviewed`; briefly state what was actually seen and any required follow-up. Do not mark an item observed based only on source, mocks, fixtures, labels, or inferred behavior.

| Review item | Status | Observation or blocker / follow-up |
| --- | --- | --- |
| Placement and naming; labels match the user task |  |  |
| Navigation placement, hierarchy, and duplicate destinations |  |  |
| Desktop layout and responsive reflow |  |  |
| Tablet layout and touch targets |  |  |
| Phone layout and touch targets |  |  |
| Keyboard navigation, focus order, and visible focus |  |  |
| Reduced-motion behavior |  |  |
| Loading, empty, error, unavailable, and recovery states |  |  |
| Destructive or consequential actions, confirmation, undo/recovery |  |  |
| Data retention, import/export, and deletion effects (including integration-specific content) |  |  |
| Capability claims match the actual API, authorization, and effects |  |  |

## Review disposition

- Blocking UX issues and owners:
- Behavior kept unavailable or pending:
- Follow-up evidence required:
- Disposition: ready for the deployment gate / blocked / partial with named unavailable behavior
- Explicitly not established by this review:

Do not use “accepted,” “release ready,” or “all requirements passed” as a UI/UX review disposition. Release and target acceptance remain governed by the current OpenSpec scope and separate exact-candidate evidence.
