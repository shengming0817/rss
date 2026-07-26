# Data Model: Runtime Deployment Fact Chain

## 当前事实

The repository has canonical AssemblyLock generation/check, a process-lifetime
`RuntimeConfigSnapshot`, and a closed typed RuntimePlan v1 carrying the upstream
`assemblyFingerprint` and its own `runtimePlanFingerprint`. DeploymentPlan v1 is also a closed
typed protocol with three committed RuntimePlan-bound generated plans. Protected RuntimeInventory
and the complete live/deployment evidence chain remain target models.

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

One process-level value contains all serving configuration. It is captured once before planning,
passed through the private `SnapshotConfig` capability, and never rebuilt by providers, routes,
listeners, or workers. Secret material remains outside stable plan serialization.

### RuntimePlan

Required fields:

- `schemaVersion`, upstream `assemblyFingerprint`, and `runtimePlanFingerprint`.
- `providerPlans`: stable set of typed constructors and output channels.
- `listenerPlans`: stable listener identities plus declared domain/auth facts; external listeners
  carry the exact closed `rssAccessToken` or `federatedAccessToken` trust profile rather than a
  generic JWT category.
- `domainPlans`: declaration-ordered domains and lifecycle phases.
- `placementPlans`: stable domain-to-workload placements.

Private constructors prevent partially finalized plans. `ProviderConstructor` is the manifest,
RuntimePlan, and xtask metadata registry single source, so an unknown constructor cannot enter a
canonical manifest or be accepted by the strict reader. The candidate API accepts only
non-derivable facts: listener IDs are derived as `{kind}-main`, and domain lifecycle is materialized
internally as `construct → ready → shutdown`. Domain arrays preserve declaration order; set-like
outputs and placements sort by stable identity.
`runtimePlanFingerprint` covers the stable, serializable plan facts and excludes itself. It does not hash the raw RuntimeConfigSnapshot or secret material; a configuration change affects the fingerprint only when it changes a typed, non-secret execution fact.

#1788 implements this contract in `assembly-schema`: the strict reader rejects unknown
versions/fields/enums, non-canonical set arrays, keyed duplicates, dangling references, invalid
lifecycle/auth combinations, and fingerprint mismatch. The validated compiler binds the exact
canonical manifest name/profile/digest to the embedded AssemblyLock. Provider IDs are explicit
required kebab-case manifest facts; provider/listener plans sort by ID, domains retain manifest
order, placements sort by wire domain/workload, and lifecycle is exactly
`construct → ready → shutdown`. Strict JSON errors expose only a closed stage/category and a
sanitized known-field path; input keys and values are never retained. Bundled manifest and lock
errors keep their repository-owned source chain behind fixed top-level messages. Runtime currently
uses the plan for stable identity and startup diagnostics; #1789–#1794 own the final plan-driven
live transition.

### DeploymentPlan

Required fields:

- `schemaVersion`, `assemblyFingerprint`, `runtimePlanFingerprint`, and `deploymentFingerprint`.
- workloads with immutable image digests, identity references, resource facts, probes, and typed secret references.
- services with workload references and closed port facts. Every RuntimePlan listener has an
  explicit port exposure: Primary/Admin/Health use `serviceExposed`, while Internal uses
  `workloadOnly`; no listener disappears through renderer convention.

`deploymentFingerprint` covers `{schemaVersion, assemblyFingerprint, runtimePlanFingerprint, workloads, services}` and excludes itself. `DeploymentPlan::compile_v1` is the only compiler and copies both upstream fingerprints from a validated RuntimePlan. The only public reader receives that RuntimePlan and exact-matches both identities before returning a plan. Rendering consumes the verified artifact matrix plus the closed deployment block in `assemblies/artifacts.toml`; it does not infer identities, secrets, or resources. The committed runtime/settingsonly/identityaudit JSON files are an exact generated set guarded by raw-byte drift checks. Probe completeness remains assembly-specific rather than forcing all probe kinds on every workload.

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

RuntimePlan carries no secret reference, endpoint, URL, allow-set, presence bit, token, key, or raw
snapshot value. Later deployment artifacts may carry only a closed `SecretRef` identifier. Inline
material, generic maps, free-form provider payloads, or secret-bearing debug/error representations
are outside every stable schema and fingerprint preimage.

## Version and compatibility

There is no migration graph in this baseline. Consumers will accept version 1 and reject every other value. The program does not provide a v0 reader, 001 alias, version negotiation, permissive unknown-field mode, shim, fallback, or dual write.

## 缺口与 owner

| Entity/transition | Owner | Planned strength |
|---|---|---|
| AssemblyLock | #1780–#1781 | Hard model/codegen/golden; Medium drift check |
| RuntimeConfigSnapshot | #1782–#1787 | Hard required input; Medium ambient-read guard |
| RuntimePlan identity and diagnostics | #1788 | Hard private fields/validated compiler/strict reader/schema/golden |
| RuntimePlan-driven live transition | #1789–#1794 | Landed Hard typestate/catalog/domain capability; Medium closure and root ratchets |
| runtimeexec and subset artifacts | #1795–#1798 | Hard launch graph; Medium artifact matrix |
| production security state | #1799–#1801 | Hard type/database/manifest constraints |
| DeploymentPlan | #1802 | Landed Hard protocol/compiler/strict bound reader/schema; Medium exact generated-set drift gate |
| Helm and deployment acceptance | #1803–#1805 | Hard render/policy types; Medium deployment acceptance |
| RuntimeInventory | #1806 | Hard DTO/codegen; Medium authorization surface |
| EvidenceReceipt | #1807–#1809 | Medium OCI and local aggregate verifiers |
