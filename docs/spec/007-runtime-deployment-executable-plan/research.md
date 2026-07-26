# Research: Runtime Deployment Executable Plan

## 当前事实

Repository inspection establishes a brownfield gap rather than a missing naming layer:

- `assemblies/runtime/src/plan.rs` validates manifest facts but exposes a summary-oriented RuntimePlan.
- `assemblies/runtime/src/lib.rs::run` creates that plan and then performs substantial handwritten provider, domain, listener, and lifecycle wiring.
- serving configuration still reads ambient environment values from several runtime modules.
- `settingsonly` and `identityaudit` prove manifest/generated/Cargo closure but do not launch.
- `deploy/docker-compose.yml` is the demo stack documented by `docs/ops/202606271438-003-container-image.md`; no DeploymentPlan-derived Helm tree or runtime inventory HTTP contract exists.
- the local typed CI/evidence funnel exists, while Azure remains the active forge and no deployment/release required check is active.

The older `docs/spec/001-runtime-assembly-plan/` is superseded, immutable audit lineage. Editing it would erase the boundary between that lineage and this executable/deployment target.

## Direct SpecKit benchmark

No directly equivalent Rust SpecKit was found that joins assembly identity, one-shot runtime configuration, executable topology, Kubernetes rendering, protected inventory, OCI provenance, and same-head evidence. The design therefore uses source-level benchmarks for three narrower seams and keeps RSS ownership explicit.

## Source benchmarks and decisions

### Package manifest as an assembly graph

`ref: oxidecomputer/omicron package-manifest.toml@cc4e95c57bdf029086c30d0e4c6cc930d75fa947`

Omicron separates local, prebuilt, composite, and manual package sources, declares composite dependencies, and lets tooling derive build/deploy artifacts from one manifest. RSS adopts the fact-chain direction and digestable assembly identity, but not Omicron's package kinds, zone format, or target model.

### Typed service startup boundary

`ref: oxidecomputer/omicron nexus/src/lib.rs@cc4e95c57bdf029086c30d0e4c6cc930d75fa947`

Nexus separates partially initialized internal service state from external readiness and passes typed configuration into startup. RSS adopts explicit phase ownership and required typed inputs; it does not copy Nexus APIs or introduce a general server container.

### Parsed configuration and dependency order

`ref: oxidecomputer/omicron-package src/config/imp.rs@d5209f95f89a30fb8cac404bbd832dff7f491538`

`omicron-package` parses a closed configuration model, derives target build/deploy sets, and topologically batches composite packages while rejecting cycles and missing producers. RSS applies that pattern to the 31-node implementation DAG and to future plan/artifact closure, without creating a generic package engine.

### Canonical bytes and provenance identity

[RFC 8785](https://www.rfc-editor.org/rfc/rfc8785.html) defines deterministic JSON primitive serialization, recursive property ordering, preserved array order, and final UTF-8 bytes. RSS adopts JCS for the unsigned stage objects and adds exact ASCII stage tags plus a NUL separator because JCS alone does not provide domain separation or define an artifact's input universe.

[SLSA Build Provenance v1.2](https://slsa.dev/spec/v1.2/build-provenance) separates output `subject` digests from `resolvedDependencies`. RSS adopts the directional identity principle—RuntimePlan is a distinct subject and DeploymentPlan depends on its digest—without importing the permissive SLSA wire schema or making it the canonicalization algorithm.

Repository precedents are `xtask/src/codegen.rs::schema_hash`, which frames a version tag and declared file set, and `consistency::OutboxFactIdentity`, which freezes versioned canonical bytes and committed vectors. The deployment protocol follows those properties with RFC 8785 rather than inventing another implicit serializer.

## Decisions

1. Introduce 007 as the only active SpecKit pointer; preserve 001 byte-for-byte as audit lineage.
2. Freeze four Draft-07 target schemas plus schema cases, fingerprint vectors, and one exact task baseline. Do not add runtime readers/types, generators, or deployment output in #1779.
3. Bind every target to an owner and a Hard or Medium planned carrier. Do not present an unlanded carrier as current enforcement.
4. Give RuntimePlan its own domain-separated fingerprint, carry it into DeploymentPlan/inventory/receipts, and retain #1794 as a blocker for #1802 so deployment identity derives only after live RuntimePlan cutover.
5. Treat subset config schemas as #1796/#1797 artifacts, closing the binary/image/config/probe/journey matrix.
6. Extend the existing local `ci-gate` in #1809. Do not add forge workflow activation or branch-protection scope.
7. Require #1806 to add an authorized HTTP contract with only `permission|serviceOwned` auth and explicit `tenantScoped|global` resource sharing; reject `public|bootstrap|clientsOnly` and never imply the design schema is the wire source.
8. Expose #1779's fail-closed repository machine-input checks through `cargo xtask runtime-deployment-spec`, and register its selftest as a typed Meta/NoCompile member of `cargo xtask verify --fast`. Automatic active-PR scheduling and same-head receipt closure remain #1809 and are not claimed here.

## Rejected alternatives

| Alternative | Rejection |
|---|---|
| Rewrite 001 in place | destroys immutable implementation lineage and makes old/new semantics indistinguishable |
| Read both schema generations | creates compatibility state and two sources of runtime truth |
| Add a generic deployment abstraction now | fields beyond owned downstream PBIs would be speculative and harder to remove |
| Leave “canonical” to each owner | independent producers/verifiers could choose different bytes, domain tags, or input membership |
| Skip RuntimePlan identity | the same AssemblyLock plus different typed configuration can produce different live topology without a downstream-verifiable subject |
| Treat docs schemas as runtime proof | JSON design does not prove Rust construction, live consumption, rendering, or authorization |
| Keep #1779's carrier outside the aggregate | Medium governance carriers must enter a stable repository aggregate; typed `verify --fast` membership is distinct from #1809 same-head receipts and forge scheduling |
| Carry secret strings with redaction guidance | material would remain representable and could leak into stable artifacts |

## 目标能力

The target is a three-fingerprint assembly-to-release chain with one configuration snapshot, closed executable plans, reusable launch, derived deployment, protected inventory, and same-head local evidence. The architecture and schemas define only interfaces demanded by #1780–#1809.

## 缺口与 owner

Implementation remains entirely downstream: #1780–#1781 identity, #1782–#1787 config, #1788–#1794 execution plans, #1795–#1798 launch/artifacts, #1799–#1801 production security, #1802–#1805 deployment, #1806 inventory, and #1807–#1809 release evidence.
