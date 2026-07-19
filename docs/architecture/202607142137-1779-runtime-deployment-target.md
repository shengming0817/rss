# Runtime Deployment Target Architecture (#1779)

**Status**: target baseline

**Date**: 2026-07-14

**Active planning entry**: `docs/spec/007-runtime-deployment-executable-plan/`

## 当前事实

| Fact | Repository evidence | Consequence |
|---|---|---|
| Runtime plan has typed identity but does not yet drive live wiring | `assembly-schema` owns the closed v1 protocol/strict reader and provider registry; each assembly compiles a generated typed provider constructor catalog, while `assemblies/runtime/src/plan/**` compiles the bundled manifest, lock, and snapshot-backed listener auth before startup continues through handwritten wiring | plan/catalog identity and diagnostics are stable; #1792–#1794 still close live topology |
| Serving configuration is one captured generation | `RuntimeConfigSnapshot` and the runtime environment funnel cover serving/operator consumers; RuntimePlan receives only the borrowed snapshot capability | raw configuration and secrets cannot enter the plan artifact |
| Subset assemblies are compile-time closures | `assemblies/settingsonly` and `assemblies/identityaudit` have manifests and generated module/provider catalogs but no launch binary | build closure is not runtime or deployment closure |
| Deployment is demo-oriented | `deploy/docker-compose.yml` is the supported demo stack (`docs/ops/202606271438-003-container-image.md`); no `deploy/helm/rss` tree exists | assembly identity cannot be checked against Kubernetes output |
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
- **runtimeexec** will own provider-independent startup and typed lifecycle transitions used by all runnable assemblies (#1795–#1798).
- Production security posture will close persistent revocation, Vault allowlists, and production manifest requirements (#1799–#1801).
- **DeploymentPlan** will derive renderable deployment facts from assembly identity; Helm, policy, and kind acceptance will detect drift (#1802–#1805).
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

AssemblyLock and RuntimePlan now have matching Rust types, strict readers, generators/compilers and
goldens. DeploymentPlan and RuntimeInventory remain design contracts; this table does not claim
their renderers, endpoints, or gates already exist.

## 缺口与 owner

| Gap | Owner | Planned carrier |
|---|---|---|
| RFC 8785 canonical assembly identity, exact input universe, and drift check | #1780–#1781 | Hard type/schema/codegen/golden; Medium generate/check |
| one configuration read and no serving ambient reads | #1782–#1787 | Hard snapshot and required inputs; Medium AST guard |
| fingerprinted typed plan identity | #1788 | Hard private protocol/compiler/reader/schema/golden |
| plan-driven live cutover | #1792–#1794 | Hard typed dispatch; Medium bijection and root ratchet |
| reusable launch and runnable subset closure | #1795–#1798 | Hard runtimeexec graph; Medium artifact closure |
| production security posture | #1799–#1801 | Hard types, database constraints, and manifest validation |
| Kubernetes deployment fact chain | #1802–#1805 | Hard plan schema-to-golden; Medium Helm drift/policy/kind acceptance |
| protected inventory wire surface | #1806 | Hard DTO/codegen plus Medium authorization verification |
| release and aggregate evidence | #1807–#1809 | Medium OCI verifier and extended local `ci-gate` |

Until each owner lands its carrier, the row describes a planned capability only and must not be represented as present production closure.

## Consequences

- 007 directly replaces 001 as the active plan, while 001 remains unchanged for audit lineage.
- DeploymentPlan cannot precede the #1794 live RuntimePlan cutover; the tracker and 52-edge DAG carry this dependency.
- #1779 implements the repository specification carrier, registers its selftest in the typed `verify --fast` Meta aggregate, and supplies schemas, fixtures, and target documents only. Runtime Rust types, generated deployment output, Helm, workflows, active-PR scheduling, and branch protection remain with downstream owners.
