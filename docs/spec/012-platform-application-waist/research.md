# Research: Platform vNext owner rebaseline

This file is the single source for the complete RSS-CP disposition. ADR-024, rules, plan and issue comments may link
here but must not copy this mapping.

## Current-head findings

The pre-cutover 0.2 implementation places static ES256/JWKS verification and a synchronous handler/drain state machine inside
Platform, while contract and request identities are duplicated across public/internal vocabularies. RuntimeExec
already has the authoritative inventory mint/reader path. Keeping the old Platform owners while extracting the new
ones would create dual authority, dual IDs or a non-compiling intermediate revision.

Release topology is already complete: Cargo metadata feeds `release_surface::plan_publish_closure` and
`stable_publish_order`; `publicapi::run_release_check` owns the release check; package-proof asserts exact equality of
selected, planned and executed packages. A new release group, registry, runner, schema or order list would only create
a second truth source.

## Complete RSS-CP disposition

| External item | Final disposition | Reason / owner |
|---------------|-------------------|----------------|
| CP-001, CP-005 | Merge into #2102 | vNext architecture and owner decision |
| CP-002 | Merge into #2096/#2099 | Existing domain-governance owners |
| CP-003 | Absorbed by closed #2042/#2048 | Existing release topology and proof |
| CP-004, CP-006, CP-007, CP-025–CP-028 | Architecture decided by #2102; implementation merged into #2107 | Must land in the atomic RSS cutover |
| CP-030 composition subset | Architecture decided by #2102; implementation merged into #2107 | Assembly remains sole composition owner |
| CP-029 | Keep as #2108 | Real external authoring/registry-only consumer |
| CP-012 | Absorbed by closed #2053–#2056 | Existing implementation owners |
| CP-034 | Keep as #2124 | Independent post-cutover T3 evidence plan |
| CP-035 | Keep as #2127 | Independent post-cutover T3 evidence plan |
| CP-036 | Keep as #2125 | Independent post-cutover T3 evidence plan |
| CP-037 | Keep as #2128 | Independent post-cutover T3 evidence plan |
| CP-008–CP-011, CP-013–CP-024, CP-031–CP-033, CP-038–CP-048 | Drop | No-consumer publicization, Eventing/TestKit, unauthorized relocation, unmet trigger or External capability |

“Drop” means the external PBI is neither imported nor implemented. It does not authorize deletion of an existing
internal capability.

## Decision

Use two minimal Foundation value packages below Platform, move verification/mint authority to Official
OIDC/AuthN/AuthZ, retain RuntimeExec's lifecycle/inventory authority, and make assembly the only wiring owner. Execute
the breaking change as the single cutover defined in [`plan.md`](plan.md). Reuse all existing release and package-proof
carriers.
