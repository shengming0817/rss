# Data Model: Runtime Deployment Fact Chain

## 当前事实

The repository has `AssemblyManifest`, generated domain modules, and a summary-oriented RuntimePlan, but no canonical AssemblyLock, process configuration snapshot, DeploymentPlan, protected RuntimeInventory contract, or cross-stage fingerprint chain. These entities below are target models, not current Rust types.

## 目标能力

```text
AssemblyIdentity --locks--> AssemblyLock [assemblyFingerprint]
AssemblyLock + RuntimeConfigSnapshot --plans--> RuntimePlan [runtimePlanFingerprint]
RuntimePlan --launches--> RuntimeInstance
RuntimePlan + image facts --renders--> DeploymentPlan [deploymentFingerprint]
RuntimeInstance + DeploymentPlan --reports--> RuntimeInventory
assembly + runtime-plan + deployment fingerprints + source SHA --attest--> EvidenceReceipt
```

### AssemblyLock

Required fields:

- `schemaVersion`: exactly `1`.
- `identity`: closed assembly `name` and `profile`.
- `digests`: canonical manifest, generated-module, and contract digests.
- `fingerprint`: the `rss-assembly-lock-v1` stage fingerprint of `{schemaVersion, identity, digests}`; the result field is absent from its own preimage. #1780 owns changed-input, exact-input-universe, and self-field-exclusion red tests.

#1780 owns the closed Rust type, shared typed contract discovery, schema/codegen, and golden. #1781 owns deterministic generate/check drift behavior and composes the existing R1–R24 business-validation gate before writing a lock.

### RuntimeConfigSnapshot

One process-level value will contain all serving configuration after parsing and secret-reference resolution boundaries are established. It will be constructed once before planning, passed as a required typed input, and never rebuilt by providers, routes, listeners, or workers. Secret material handling remains outside stable plan serialization.

### RuntimePlan

Required fields:

- `schemaVersion`, upstream `assemblyFingerprint`, and `runtimePlanFingerprint`.
- `providerPlans`: stable set of typed constructors and output channels.
- `listenerPlans`: stable listener identities plus declared domain/auth facts.
- `domainPlans`: declaration-ordered domains and lifecycle phases.
- `placementPlans`: stable domain-to-workload placements.

Private constructors and typestate will prevent partially finalized plans. Domain and lifecycle arrays preserve declaration order; set-like outputs and placements sort by stable identity.
`runtimePlanFingerprint` covers the stable, serializable plan facts and excludes itself. It does not hash the raw RuntimeConfigSnapshot or secret material; a configuration change affects the fingerprint only when it changes a typed, non-secret execution fact.

### DeploymentPlan

Required fields:

- `schemaVersion`, `assemblyFingerprint`, `runtimePlanFingerprint`, and `deploymentFingerprint`.
- workloads with immutable image digests, identity references, resource facts, probes, and typed secret references.
- services with workload references and closed port facts.

`deploymentFingerprint` covers `{schemaVersion, assemblyFingerprint, runtimePlanFingerprint, workloads, services}` and excludes itself. Rendering must not infer identities, secrets, or resources; probe completeness is closed by #1802/#1805 policy per assembly rather than forcing all three probe kinds on every workload. #1802 owns changed-input/self-field red tests and schema-to-render golden.

### RuntimeInventory

Required fields:

- assembly, runtime-plan, and deployment fingerprints;
- build identity with source SHA and image digest;
- declaration-ordered domains;
- stable listeners, provider posture, and placements.

Inventory is a protected observation, not a planning input. This schema is not the wire source; #1806 must define the authorized `contracts/http/**` DTO with auth mode `permission|serviceOwned`, explicit resource sharing `tenantScoped|global`, and rejection of `public|bootstrap|clientsOnly`.

### EvidenceReceipt

#1807–#1809 will bind release and gate evidence to exact source SHA plus assembly/runtime-plan/deployment fingerprints. A receipt from another HEAD, a missing receipt, or any fingerprint mismatch must be invalid rather than reusable.

## Canonical bytes and input universe

Every stage fingerprint is `sha256:` plus lowercase hex of `SHA-256(ASCII(stageTag) || 0x00 || RFC8785(unsignedObject))`. RFC 8785 produces the UTF-8 bytes: no BOM, whitespace, trailing newline, or Unicode normalization is added; duplicate keys, invalid Unicode, and non-I-JSON numbers are rejected. The unsigned object omits its result field rather than encoding an empty value. The exact stage tags are:

| Artifact | Stage tag | Unsigned object |
|---|---|---|
| AssemblyLock | `rss-assembly-lock-v1` | `{schemaVersion, identity, digests}` |
| RuntimePlan | `rss-runtime-plan-v1` | `{schemaVersion, assemblyFingerprint, providerPlans, listenerPlans, domainPlans, placementPlans}` |
| DeploymentPlan | `rss-deployment-plan-v1` | `{schemaVersion, assemblyFingerprint, runtimePlanFingerprint, workloads, services}` |

AssemblyLock closes its three child digest universes with the same tag/NUL/RFC-8785 framing:

- `manifest`: tag `rss-assembly-manifest-v1`; the unsigned value is `CanonicalAssemblyManifestV1`. TOML key/table layout is irrelevant; `domains`, `listeners`, each listener's `domains`, and `frameworkContracts` retain semantic declaration order, while `diportProviders` sort by `(port,provider,providerCrate,consumer)` and provider `requiredFeatures`/`outputs` sort as duplicate-free sets. Codegen consumes this same read-only value and records its digest as `Source-Manifest-Digest`.
- `generated`: tag `rss-assembly-generated-v1`; the value is the non-empty path-sorted array of `{path,digest}` for every generator-owned regular file recursively below the discovered assembly's `src/generated/`. Paths are repository-relative UTF-8 with `/`; symlinks, traversal, duplicate paths, unowned files, and non-files fail closed; each child digest hashes its raw bytes.
- `contracts`: tag `rss-assembly-contracts-v1`; the value is the tuple-sorted array of `{domain,id,version,schemaHash,semanticsHash}` for every repository-discovered contract whose domain is declared by the assembly, plus the exact IDs in `frameworkContracts`. `schemaHash` reuses the existing declared-schema-file digest contract. `semanticsHash` uses `rss-contract-runtime-semantics-v1 || NUL || RFC8785(typed projection)` and binds every `ContractManifest` runtime field; set-like effect, subscription, projection, and outbox emission declarations are sorted with duplicate identities rejected, while saga steps remain ordered. #1780 owns the single typed parser/discovery/catalog funnel and separates `ParsedAssemblyLock` from `RepositoryVerifiedAssemblyLock`; no raw binding or digest constructor is public. The verified compiler accepts only a repository root and an exact repository-relative `assemblies/<name>` directory, reads that directory's `assembly.toml`, and requires its canonical name to equal the directory name, so a caller cannot pair one manifest with another assembly's generated files. “Repository verified” proves deterministic input-universe completeness, not R1–R24 business validity; #1781 composes that existing validator and drives generate/check.

JSON objects are closed recursively and version 1 is the only accepted version. Set-like arrays are sorted by their documented stable identity before RFC 8785 and reject duplicate identities; RFC 8785 itself never reorders arrays. Domain and lifecycle arrays preserve declaration order because it determines construction, readiness, and shutdown behavior.

V1 directly carries `assemblyFingerprint` into RuntimePlan, `runtimePlanFingerprint` into DeploymentPlan, and all three fingerprints into inventory/receipts. A downstream stage compares the supplied upstream fingerprint; it never reconstructs upstream identity from partial fields.

## State transitions

```text
Declared -> Locked -> Configured -> Planned -> Launched -> Deployed -> Observed -> Attested
```

- `Declared -> Locked` fails on missing/unknown manifest, generated, or contract facts.
- `Locked -> Configured` fails on invalid config or unresolved required typed references.
- `Configured -> Planned` fails on incomplete providers, listeners, domains, lifecycle, or placement.
- `Planned -> Launched` is a typed runtimeexec transition; no handwritten fallback path remains after #1794.
- `Planned -> Deployed` fails on mutable images or incomplete workload/service closure.
- `Deployed -> Observed` requires matching fingerprints and authorized inventory access.
- `Observed -> Attested` requires same-head OCI and aggregate evidence receipts.

## Secret boundary

Only a closed `SecretRef` object crosses stable artifacts. It identifies a supported reference kind, name, and key. Inline material, generic maps, free-form provider payloads, or debug representations are outside every target schema.

## Version and compatibility

There is no migration graph in this baseline. Consumers will accept version 1 and reject every other value. The program does not provide a v0 reader, 001 alias, version negotiation, permissive unknown-field mode, shim, fallback, or dual write.

## 缺口与 owner

| Entity/transition | Owner | Planned strength |
|---|---|---|
| AssemblyLock | #1780–#1781 | Hard model/codegen/golden; Medium drift check |
| RuntimeConfigSnapshot | #1782–#1787 | Hard required input; Medium ambient-read guard |
| RuntimePlan and live transition | #1788–#1794 | Hard closed types/typestate/catalog; Medium closure ratchets |
| runtimeexec and subset artifacts | #1795–#1798 | Hard launch graph; Medium artifact matrix |
| production security state | #1799–#1801 | Hard type/database/manifest constraints |
| DeploymentPlan and Helm | #1802–#1805 | Hard schema/render; Medium deployment acceptance |
| RuntimeInventory | #1806 | Hard DTO/codegen; Medium authorization surface |
| EvidenceReceipt | #1807–#1809 | Medium OCI and local aggregate verifiers |
