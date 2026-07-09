# Requirements Checklist: L0/L1 Consistency Hardening SpecKit Baseline

**Feature**: `docs/spec/006-l0-l1-consistency-hardening`

**Created**: 2026-07-08

**Scope**: Docs-only C-00 baseline for epic #1685 and PBI #1708.

## Content Quality

- [x] The feature directory contains `spec.md`, `plan.md`, `tasks.md`, `quickstart.md`, and this checklist.
- [x] The specification has concrete user stories, acceptance scenarios, functional requirements, entities, success criteria, and assumptions.
- [x] The plan records source inputs, scope constraints, issue map, natural dependency DAG, and verification plan.
- [x] The task list is PR/PBI-level and uses real issue numbers #1708 and #1686..#1707.
- [x] The quickstart explains how to validate C-00 and how to start later `/ship` work.

## Issue and DAG Integrity

- [x] C-00 #1708 is marked as the only issue closed by this docs-only PR.
- [x] Shared carrier PBIs #1686, #1687, and #1688 are listed before L0/L1 fan-out.
- [x] L0 PBIs #1689..#1696 are grouped under effect-proven LocalOnly.
- [x] L1 PBIs #1697..#1706 are grouped under executable LocalTx validation.
- [x] C-04 #1707 is reserved for final implementation docs/verify closeout.
- [x] Maximum natural parallelism is documented without a wave-size cap.

## Scope Control

- [x] The baseline states that Rust code, contract schemas, generated files, migrations, and `docs/rules/**` rule bodies are out of scope.
- [x] The expected PR diff is limited to `.specify/feature.json` and `docs/spec/006-l0-l1-consistency-hardening/**`.
- [x] The L0 and L1 downloaded SpecKit packages are cited as inputs, not copied wholesale into runtime-facing paths.
- [x] The PR benchmark line is specified as docs-only with no runtime, codegen, or interface comparison required.

## Verification

- [x] Placeholder-marker scan is part of the test plan.
- [x] `cargo xtask verify --fast` is part of the test plan.
- [x] Diff allowlist validation is part of the test plan.
- [x] `.specify/feature.json` points to `docs/spec/006-l0-l1-consistency-hardening`.
