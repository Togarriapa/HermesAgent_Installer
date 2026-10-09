# development-governance Specification

## Purpose
Preserve complete installer requirements and a reproducible frozen planning baseline while allowing explicitly traced development and separate refinements.

## Requirements

### Requirement: Exact pinned planning toolchain
The repository SHALL pin OpenSpec1.14.1 with a lockfile and supported Node version, generated Codex workflows, project context and strict local/CI validation.

#### Scenario: Reproducible specification check
- **WHEN** the developer installs the locked dependencies and runs validate:specs
- **THEN** all canonical and active OpenSpec items SHALL be strictly validated without implying installer functional success.

### Requirement: Complete requirement coverage validation
The planning checker SHALL reject missing original nonempty source lines, requirement/task/evidence or item/alias/acceptance links and dependency cycles.

#### Scenario: Full scoped coverage
- **WHEN** a complete plan is checked
- **THEN** every mapped original line, unique component/alias and twelve acceptance criteria SHALL have linked requirements/tasks/evidence.

#### Scenario: Dropped obligation or cyclic task
- **WHEN** a required mapping is removed or task dependencies form a cycle
- **THEN** validation SHALL fail with an actionable planning error.

### Requirement: Frozen baseline integrity validation
The checker SHALL validate exact frozen file set and SHA256 digests, and CI SHALL compare the complete baseline tree to its unique annotated tag.

#### Scenario: Edited baseline contents
- **WHEN** a frozen baseline file is edited, removed or added
- **THEN** integrity validation SHALL fail rather than accepting altered scope.

#### Scenario: Hashes rewritten with contents
- **WHEN** both baseline contents and local hash manifest are changed after the tag
- **THEN** the complete baseline Git-tree comparison SHALL reject drift from the tag.

### Requirement: Honest planning status
Planning validation SHALL report that runtime acceptance is not established; no fixture or artifact-complete status SHALL claim Pi/account/integration success.

#### Scenario: Successful planning checks
- **WHEN** specification, coverage and integrity checks pass
- **THEN** the result SHALL distinguish planning validation from unperformed installer/account/hardware acceptance.
