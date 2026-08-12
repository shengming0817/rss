# Implementation Plan: Platform vNext atomic cutover

This file is the single source for the implementation DAG and AI-HARD carrier handoff. Backlog disposition remains
exclusively in [`research.md`](research.md).

## Atomic DAG

```text
#2102 owner decision
  └─ #2107 open PR produces immutable candidate bundle
       └─ #2108 rss-incubator registry-only first-green
            └─ #2107 binds exact receipt and merges the atomic cutover
```

#2107 is the sole RSS implementation owner. One PR extracts both Foundation packages, migrates all IDs, changes
Platform to its async waist, moves Auth authority and RuntimeExec projection bridges, updates composition, Release API
and package proof, and replaces the pre-cutover 0.2 API/baseline in place while retaining experimental package version
0.2.0. Partial merges and compatibility stages are forbidden.

#2124/#2127 and #2125/#2128 start only after #2107/#2108 complete and their own evidence plans pass. They are not in
this implementation wave.

## AI-HARD carrier handoff

Every new or changed carrier is **planned, not active** until its implementation owner lands it. Rows explicitly
marked existing remain active and are only reused/reverified. This decision adds no unenforced `INVARIANT` and no
Markdown scanner.

| Invariant | Primary carrier | Landing owner |
|-----------|-----------------|---------------|
| Foundation/Platform dependency direction | Cargo/rustc graph Hard; `layer-deps`/deny and release-closure negative proof Medium | #2107 |
| Unique ID owner | Single definitions, private fields and deletion of mirror types Hard; trybuild/public-api exact surface Medium | #2107 |
| Trusted context cannot be forged | Private constructors and sealed mint capability Hard; external compile-fail plus AuthN/AuthZ T2 fail-closed matrix Medium | #2107 |
| Platform does not own JWT/JWKS | No Platform crypto/JWT/provider Cargo edges Hard; WorkspaceFacts dependency assertion and leakage proof Medium | #2107 |
| Platform does not own lifecycle | Required host port and no concrete runtime constructor Hard; structural guard against Condvar/runtime/signal owner plus bridge T2 Medium | #2107 |
| Runtime inventory has one source | Existing `RuntimeInventoryMint` visibility/Cargo edge Hard; RuntimeExec reader/publisher and provenance tests Medium | Existing + #2107 |
| Async dispatch/cancellation | Async trait consumes Foundation typed cancellation/deadline and returns closed dispatch errors Hard; success/error/cancel/draining T1 matrix Medium | #2107 |
| Release topology | Cargo graph Hard; existing closure planner, release-check and package-proof exact-set Medium | Existing carriers reused |
| Real external consumption | ADR-026 canonical same-result receipt, registry-only resolution and canonical CI first-green T2 Medium | #2108 |

## Cutover increment over ADR-026

[`ADR-026`](../../architecture/202608111253-026-rss-incubator-ownership-migration.md) uniquely owns the canonical
cross-repository first-green receipt shape and immutable artifact lifecycle. This plan only adds the Platform vNext
cutover checks; it does not define a smaller receipt or a second rollback protocol.

1. #2107's final candidate HEAD first passes the existing RSS Release Surface artifact proof and produces the dynamic
   artifact exact-set.
2. Once published, that versioned registry bundle is immutable. #2108 resolves only it and emits ADR-026's canonical
   same-result receipt from the canonical incubator CI.
3. Before merge, #2107 exact-checks that the receipt's RSS commit equals its final candidate HEAD, the incubator commit
   equals the CI checkout, the artifact exact-set equals the candidate Release Surface, every package version/checksum/
   archive VCS revision matches the produced `.crate`, the independent root lock is registry-only, and locked/offline
   check, test and clippy all succeeded at the linked canonical CI URL.
4. #2107 then binds that receipt and merges every RSS owner/baseline change together. The result remains linked from
   the issue/PR; it is not copied into a committed receipt, evidence database or release registry.

Rollback also consumes ADR-026. Before registry publication, reject the candidate and retain the pre-cutover revision. After publication,
never “discard” or reuse the immutable version: block product release, return the incubator pin/root lock to the last
known-green artifact and re-run canonical CI, then publish a fixed RSS version or yank the defective version when the
registry permits. If the RSS cutover already merged, those consumer/artifact steps happen before any whole-revision
RSS revert. No rollback restores the RSS-owned submodule, a compatibility path, partial vNext or dual owners.

## Verification protocol

- Human architecture review checks that ADR/rules/spec have one normative target model and label pre-cutover 0.2 only as history;
  Markdown wording is not an enforcement carrier or merge gate.
- Existing focused checks re-prove dependency-first release closure, package-proof selected/planned/executed equality,
  Release API forbidden leakage and RuntimeExec inventory mint/reader ownership.
- Board status, comments and dependency protocol are read back after mutation.
- The docs PR runs `git diff --check`, then one complete `make ci CI_BASE=origin/develop` after all changes are committed.
  On failure, collect the whole result, batch fixes, and re-run once; do not run `make ci-full`.
