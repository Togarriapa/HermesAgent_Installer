# Design

## Context

This authorized repository is initially empty. Runtime work belongs to Luna; Sol owns planning and refinement. See proposal.md for motivation.

## Goals / Non-Goals

Goals: reproducible source coverage/DAG and frozen-tree drift checks, meaningful negative checker tests, scoped model handoff.
Non-Goals: installer implementation or claims that hashes prevent a repository administrator from rewriting remote tags.

## Decisions

scripts/check_plan.py uses standard-library JSON/SHA256 and validates source lines, real spec/task links, component/alias/AC coverage, task DAG and exact hashed file set. A Git tag tree diff detects rewriting contents together with hashes. This is stronger than self-declared hashes alone; external tag/branch enforcement remains separate. CI pins action SHAs and Node/OpenSpec/Python versions. The original user prompt and later authorized star-policy selection evidence are separate provenance.

Planning checker tests copy a draft baseline into temporary directories and inject missing lines, AC links, dependency cycles and changed/removed files. These prove planning validation only. No test is presented as runtime enforcement or installation acceptance.

## Risks / Trade-offs

- GitHub admins can override ref controls -> describe actual CI drift assurance without absolute immutability claims.
- Toolchain audit finding -> recorded upstream advisory with trusted bounded local inputs and Sol-owned compatible update.
- Tests/specs reflect future plans -> status explicitly reports runtime acceptance not established.

## Migration Plan

Prepare complete draft baseline, run strict validation/checker tests, archive only implemented planning support, snapshot final canonical/active OpenSpec artifacts and validation outputs, hash, commit/tag/push and verify remote refs. Thereafter baseline/tag never change; live artifacts and append-only Sol amendments evolve independently.
