# Proposal

## Why

The user's immutable plan needs mechanical drift/coverage checks and a pinned OpenSpec workflow so later development cannot silently drop scope.

## What Changes

- Pin development tooling and generated Codex integration.
- Deliver original source mappings, model-role/source selection evidence and frozen baseline hashes.
- Add strict specification/coverage/hash/tag checks to pinned CI plus meaningful negative planning-check tests.

## Capabilities

### New Capabilities

- `development-governance`: Reproducible planning validation and immutable-scope drift detection.

### Modified Capabilities

None.

## Impact

package/lock, AGENTS.md, OpenSpec config/workflows, planning artifacts, scripts/check_plan.py, CI and planning-check tests. This implements planning support only; no installer runtime is claimed.
