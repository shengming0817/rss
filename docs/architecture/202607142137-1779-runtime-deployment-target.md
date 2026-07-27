# Runtime Deployment Target Architecture (#1779)

**Status**: target baseline

**Date**: 2026-07-14

**Active planning entry**: `docs/spec/007-runtime-deployment-executable-plan/`

## 当前事实

| Fact | Repository evidence | Consequence |
|---|---|---|
| RuntimePlan drives the live typed topology | `assembly-schema` owns the closed v1 protocol/strict reader and provider registry; each assembly compiles a generated typed provider constructor catalog, and the unique runtime phase chain consumes listener, domain, placement, and auth facts without a handwritten compatibility path | plan identity and live topology are closed by the landed #1789–#1794 carriers |
| Serving configuration is one captured generation | `RuntimeConfigSnapshot` and the runtime environment funnel cover serving/operator consumers; RuntimePlan receives only the borrowed snapshot capability | raw configuration and secrets cannot enter the plan artifact |
| Settings-only assembly is an executable fail-closed closure | `assemblies/settingsonly` owns `settingsonly-server`, a closed config parser and Draft-07 schema, Primary and domain-free Health listeners, Postgres/Vault/JWKS/Settings probes, the `runtimeexec` launch path, a SIGTERM journey, and the `settingsonly-runtime` image target | Settings can be deployed as an independently runnable closure; Identity and Audit are intentionally absent, so invalid credentials receive 401 and every verified credential receives 403 |
| Identity-audit assembly is an executable subset closure | `assemblies/identityaudit` owns its launch binary, closed configuration schema, probes, image target, SIGTERM journey, and shared `runtimeexec` lifecycle | Identity/Audit has an independently runnable, fail-closed assembly profile |
| Runtime-bound DeploymentPlan is landed | `assembly-schema` compiles the exact RuntimePlan identity with closed deployment facts; `cargo xtask deployment plan render|check` owns the committed runtime, settingsonly, and identityaudit JSON exact set | deployment identity and raw-byte drift are the sole input to the static Helm projection |
| Static multi-assembly Helm projection is landed | one chart bundles the three verified plans; closed profile values/schema and render goldens are owned by the DeploymentPlan gate and Helm 4.2.0 | rendered Kubernetes YAML is deterministic, but policy/kind runtime acceptance is not yet claimed |
| CI evidence is local/shadow | `README.md` records the typed `ci-gate` and Azure active forge, while the gate is not a required forge check | future evidence must extend the local gate without claiming branch protection |

`docs/spec/001-runtime-assembly-plan/` is superseded, immutable audit lineage. It is not an active reader, schema version, alias, or compatibility surface.

## 目标能力

The downstream PBIs will establish one directional fact chain:

```text
assembly.toml + generated modules/providers + contracts
  -> AssemblyLock [assemblyFingerprint]
  -> RuntimeConfigSnapshot
  -> RuntimePlan [runtimePlanFingerprint]
  -> runtimeexec launch
  -> DeploymentPlan [deploymentFingerprint]
  -> Helm and immutable OCI artifacts
  -> RuntimeInventory
  -> same-head local ci-gate receipts
```

- **AssemblyLock** identifies the assembly and digests manifest, generated, and contract inputs (#1780–#1781).
- **RuntimeConfigSnapshot** is constructed once and passed as a required typed input; serving ambient reads are closed (#1782–#1787).
- **RuntimePlan** closes and fingerprints provider, listener, domain, lifecycle, and placement decisions (#1788). The closed generated provider constructor catalog (#1791) enters assembly identity without constructing instances; #1792–#1794 make the plan/catalog drive the live root.
- **runtimeexec** owns provider-independent startup and typed lifecycle transitions for the full
  runtime and settingsonly. The identityaudit executable closure and the existing cross-assembly
  artifact-matrix boundary remain with #1797–#1798.
- Production security posture closes persistent revocation, Vault allowlists, and production manifest requirements through the landed #1799–#1801 carriers.
- **DeploymentPlan** derives typed deployment facts from the exact RuntimePlan identity and renders three committed canonical JSON plans (#1802). #1803 projects them through one drift-checked Helm chart; #1804 policy/secret/sidecar closure and #1805 kind acceptance remain downstream.
- **RuntimeInventory** will expose authorized typed runtime evidence. Its design schema here is not the HTTP wire source; #1806 must add the formal `contracts/http/**` contract with auth mode `permission|serviceOwned` and explicit resource sharing `tenantScoped|global`; `public|bootstrap|clientsOnly` are rejected.
- OCI evidence and the existing local `ci-gate` will verify exact source SHA, assembly/runtime-plan/deployment fingerprints, and same-head receipts (#1807–#1809).

## Architecture boundaries

1. Facts flow forward. RuntimePlan binds the assembly identity and its stable execution facts; DeploymentPlan binds that RuntimePlan identity; inventory and receipts carry all three stage fingerprints. No stage may reconstruct or override upstream identity.
2. Types, private constructors, typestate, schema/codegen, and golden output are preferred Hard carriers. Medium source/policy gates require synthetic red and anti-vacuity evidence.
3. AI delivery skills invoke repository-owned gates; a skill, prompt, checklist, or forge setting is not itself a carrier.
4. Secrets are typed references only. No lock, plan, inventory, receipt, log, rendered golden, or schema permits secret material.
5. Set-like collections use a documented stable order. Domain composition and lifecycle sequences preserve declaration order because their order has runtime meaning.
6. Version `1` is the only accepted target version. Unknown versions fail; there is no old-schema reader, shim, alias, fallback, or dual write.
7. MDM/L4 is outside this Epic's production surface and remains owned by separate PBIs; this baseline adds no prohibition against future integration.

## Target schema boundary

The four Draft-07 files under the active SpecKit freeze only the minimum downstream interfaces:

| Schema | Frozen boundary | First implementation owner |
|---|---|---|
| `assembly-lock.schema.json` | assembly identity, three input digests, assembly fingerprint | #1780 |
| `runtime-plan.schema.json` | assembly/runtime-plan fingerprints and provider/listener/domain/placement plans | #1788 |
| `deployment-plan.schema.json` | assembly/runtime-plan/deployment fingerprints, immutable images, workloads/services/probes/identities/secret refs/resources | #1802 |
| `runtime-inventory.schema.json` | build identity, all three fingerprints, domains/listeners/provider posture/placements | #1806 |

AssemblyLock, RuntimePlan, and DeploymentPlan now have matching Rust types, strict readers,
generators/compilers, and goldens. RuntimeInventory remains a design contract; this table does not
claim its endpoint or downstream policy/kind runtime evidence already exists. #1803's Helm evidence is
limited to repository-static lint/render/profile closure.

## 缺口与 owner

| Gap | Owner | Planned carrier |
|---|---|---|
| RFC 8785 canonical assembly identity, exact input universe, and drift check | #1780–#1781 | Hard type/schema/codegen/golden; Medium generate/check |
| one configuration read and no serving ambient reads | #1782–#1787 | Hard snapshot and required inputs; Medium AST guard |
| fingerprinted typed plan identity | #1788 | Hard private protocol/compiler/reader/schema/golden |
| plan-driven live cutover | #1792–#1794 | Landed: Hard typed dispatch/domain capability; Medium bijection, aggregate closure, and root ratchet |
| reusable launch and settingsonly runnable closure | #1795–#1796 | Landed: Hard runtimeexec graph and closed Settings launch types; Medium schema, journey, and image closure |
| identityaudit runnable closure and cross-assembly artifact matrix | #1797–#1798 | Landed: Hard assembly launch path; Medium artifact closure |
| production security posture | #1799–#1801 | Landed: Hard types, database constraints, and manifest validation |
| Runtime-bound DeploymentPlan | #1802 | Landed: Hard schema/compiler/bound reader; Medium exact artifact closure |
| Kubernetes static render | #1803 | Landed: closed profile/schema/plan projection; Medium Helm lint/render drift |
| Kubernetes policy and kind acceptance | #1804–#1805 | Planned Hard policy types; Medium policy/kind runtime acceptance |
| protected inventory wire surface | #1806 | Hard DTO/codegen plus Medium authorization verification |
| release and aggregate evidence | #1807–#1809 | Medium OCI verifier and extended local `ci-gate` |

Rows explicitly marked Landed describe current repository carriers; the remaining rows describe
planned capability and must not be represented as present production closure.

## Consequences

- 007 directly replaces 001 as the active plan, while 001 remains unchanged for audit lineage.
- DeploymentPlan follows the landed #1794 live RuntimePlan cutover; the tracker and 52-edge DAG retain this dependency for audit lineage.
- #1779 established the repository specification carrier and registered its selftest in the typed
  `verify --fast` Meta aggregate. Subsequent owners through #1802 landed the RuntimePlan execution
  chain, three runnable assembly profiles, generated DeploymentPlan output, and #1803's static Helm
  profile/render closure. Secret mapping/sidecars/policy, kind execution, RuntimeInventory, and OCI
  same-head/signature receipts remain with their downstream owners. Reverting #1803 removes only
  repository chart/tooling/generated carriers; it performs no cluster, database, or secret rollback.
