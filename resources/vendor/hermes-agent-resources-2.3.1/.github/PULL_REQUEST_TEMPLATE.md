## Purpose

Describe the registry behavior/capability change and why it belongs in this PR.

## Resource changes

- [ ] Every new/changed resource uses the canonical kind template and valid semantic version.
- [ ] Every changed existing resource bumps `metadata.version`.
- [ ] Resource dependencies/inheritance resolve and do not broaden authority implicitly.
- [ ] Catalog version is bumped when the resource set changes.
- [ ] No secret, credential, private learned overlay, or user-specific data is committed.

## Quality and safety

- [ ] Relevant domain boundaries and failure modes are explicit.
- [ ] User-facing routing remains Hermes-only.
- [ ] State-changing/destructive/external actions retain explicit authorization and verification.
- [ ] Tests/regression cases were updated for changed invariants.

## Documentation

- [ ] Existing canonical docs were updated where behavior changed.
- [ ] No versioned/supplemental root docs were added instead of updating a canonical document.
- [ ] Local Markdown links remain valid.

## Verification

- [ ] `python scripts/check_catalog_consistency.py`
- [ ] `python scripts/check_pr_quality.py` (in PR CI)
- [ ] Full registry validation/materialization suite
