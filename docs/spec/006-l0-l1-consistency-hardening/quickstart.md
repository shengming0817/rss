# Quickstart: L0/L1 Consistency Hardening Baseline

This quickstart is for the docs-only C-00 PR and later `/ship` execution of the implementation PBIs.

## C-00 Docs-Only PR

Tracking:

- Epic: #1685
- Docs-only PBI: #1708
- Branch: `docs/1708-l0-l1-spec-baseline`
- Worktree: `worktrees/docs/1708-l0-l1-spec-baseline`

Validate the baseline from the worktree:

```bash
patterns='NEEDS CLAR''IFICATION|\[FEATURE NAME\]|TO''DO|T''BD'
if rg -n "$patterns" docs/spec/006-l0-l1-consistency-hardening .specify/feature.json; then
  echo "unresolved template marker found"
  exit 1
else
  echo "placeholder scan passed"
fi
cargo xtask verify --fast
/usr/bin/git diff --name-only origin/develop...HEAD
```

Expected diff allowlist:

```text
.specify/feature.json
docs/spec/006-l0-l1-consistency-hardening/**
```

The PR body must include:

```text
本 PR 无需对标：docs-only SpecKit baseline，未改 runtime/codegen/interface
```

Close only #1708 from the PR body. Do not close #1686..#1707.

## Starting Follow-Up Work

Start with the shared carrier chain:

```text
/ship --level=L2 #1686
/ship --level=L2 #1687
/ship --level=L2 #1688
```

After #1688 lands, the natural fan-out is:

```text
/ship --level=L2 #1689
/ship --level=L2 #1690
/ship --level=L2 #1691
/ship --level=L2 #1692
/ship --level=L2 #1697
/ship --level=L2 #1698
```

Continue according to `tasks.md` dependency stages. Do not start #1707 until #1686..#1706 are complete.

## L0-08 Consistency / Effect Breaking Review

From the #1696 worktree, validate the current manifests and compare against the PR base:

```bash
cargo run -q -p xtask -- contract validate
cargo run -q -p xtask -- contract breaking --against origin/develop
```

Expected review behavior:

- `LOCAL_ONLY_BOUNDARY_CHANGED`, `EFFECT_ADDED`, and `EFFECT_REMOVED` remain deterministic warn findings;
  active findings fail closed without the exact `Contract-Review-Ack` trailer printed by the command.
- Review the complete rule/subject/detail set, then place the exact trailer in the change commit or a follow-up
  commit. A base or finding change invalidates the old fingerprint.
- A non-L0 consistency drift or any other active breaking rule remains deny; mixed warn + deny output fails.
- Draft contracts are skipped and deprecated findings remain non-blocking warn without an acknowledgement.
- Missing, empty, duplicate, or unknown HTTP effect profiles fail before a trustworthy comparison is emitted.

Run the focused regression surface before the full ship funnel:

```bash
cargo test -p xtask contract::breaking::tests::
cargo test -p xtask --test consistency_report_cli
cargo clippy -p xtask --all-targets -- -D warnings
```

## Using Another SpecKit Feature

`.specify/feature.json` now points to this feature. For older feature work, use a separate branch or worktree and treat `SPECIFY_FEATURE_DIRECTORY` as a persistent pointer override, not a purely temporary shell override:

```bash
SPECIFY_FEATURE_DIRECTORY=docs/spec/001-runtime-assembly-plan <speckit-command>
/usr/bin/git diff -- .specify/feature.json
```

If `.specify/feature.json` changed only for the older feature command, restore or commit that pointer change intentionally before leaving the worktree. Replace the path with the feature directory required by that work item.

## Source Material

- L0 planning package: imported SpecKit source for effect-proven LocalOnly; relevant planning content is folded into this feature directory.
- L1 planning package: imported SpecKit source for executable LocalTx hardening; relevant planning content is folded into this feature directory.
- Repo baseline: `docs/spec/006-l0-l1-consistency-hardening/`
