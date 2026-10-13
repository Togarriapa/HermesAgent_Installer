# Owned parallel delivery branches

The active implementation specification is `openspec/changes/jarvis-core-platform/`.
GitHub Issues are the backlog; each issue records its owner and acceptance evidence.

| Integration branch | Purpose | Owner |
| --- | --- | --- |
| `codex/epic-core-runtime` | Core installation, adoption, preservation and recovery | Root, with Luna implementation and Sol review |
| `codex/epic-jarvis-ui` | Jarvis command centre, Experts, voice and Obsidian interface | Root, with independently owned Luna task branches |

UI task branches target `codex/epic-jarvis-ui`:

- `codex/task-17-reactor-dashboard`: Issue #17, authored command centre and reactor.
- `codex/task-18-agent-fleet`: Issue #18, named Expert and Team activity.
- `codex/task-19-voice-dock`: Issue #19, operational foreground voice controls.
- `codex/task-20-obsidian-explorer`: Issue #20, interactive vault graph.

Use `codex/fix-<issue>-<description>` for scoped corrections and link the owning issue.
Branch creation is not implementation or acceptance. Publish concrete source in draft
PRs, review dependencies, then run required tests and visual checks on the authorized
Pi. Local source and Git operations are allowed; local runtime tests are not.
Checkpoint commits use `[skip ci]` while the Pi evidence is pending, without claiming
a skipped check passed. Root integrates reviewed work, deploys accepted candidates,
and removes task/fix branches after merge. Preserve active and unmerged work.

These branches organize the existing scope; they do not change runtime authority,
authentication, spending limits, canonical verified specifications or completion gates.
