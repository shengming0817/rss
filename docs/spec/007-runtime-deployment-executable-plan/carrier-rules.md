# Runtime Deployment Carrier Rules

Feature-scoped carrier selection rules for #1779. This document belongs to the SpecKit feature, not to `docs/rules/`: it records the current runtime-deployment fact baseline, target capabilities, and open gaps, which is spec shape rather than standing repository rule shape.

It supplements `docs/rules/architecture.md`, `docs/rules/runtime-assembly-plan.md`, and `docs/rules/runtime-wiring.md`; it does not copy their implemented carrier inventory.

## 当前事实

- Assembly manifest validation, generated domain ordering, generated typed provider constructor catalogs, and committed v1 AssemblyLock drift are governed by typed repository gates. The assembly-crate-internal provider catalog drives live construction through one-shot typed permits and sealed lifecycle-output batches.
- Both binaries capture one closed process-level configuration generation through a typed preparation profile before tracing and provider construction. Serving enters through `runtime::prepare_runtime()`; RSS operators enter through `runtime::operator::prepare_runtime()` and cannot carry the serving-only password-policy capability. Tracing/serving-OIDC, the operator OIDC static provider, provider material, listener addresses and mTLS material, every PostgreSQL/Redis/Vault/S3/event/domain/DLX/worker consumer, composition settings, and settings maintenance are capability-only and snapshot-backed. The crate-wide ambient-reader closure is landed under #1787. RuntimePlan v1 is typed, fingerprinted, retained by the unique consuming runtime phase chain, and is now the sole source of listener membership, ordered domain placement, and auth selection. `runtimeexec` owns the provider-independent launch/signal/drain kernel and stable opaque probe/inventory hooks. #1796 and #1797 landed the executable `settingsonly` and `identityaudit` subset closures; #1798 adds their repository artifact closure alongside `runtime`. No DeploymentPlan, Helm, public RuntimeInventory, or same-head deployment/release evidence chain exists yet.
- RSS Access has no trusted-kind setting: it accepts only grant-bound User claims with a complete `sid/jti/auth_time/authn_epoch` quartet. The configurable allowlist belongs only to Federated Access; `RSS_ACCESS_TOKEN_TRUSTED_KINDS` is a startup tombstone and causes fail-fast rejection instead of being ignored or carried as inert configuration.
- Serving Vault secret resolution requires `RSS_VAULT_TENANT_STORE_ALLOWLIST_JSON` in the one process snapshot. Its only accepted schema is a strict root `{"bindings":[...]}` whose strict entries contain exactly `tenantId`, `storeId`, `mount`, and `kvPathPrefix`; the set must be non-empty and unique by `(tenantId, storeId)`, and physical namespaces may not overlap across tenants. There is no alias, default or compatibility reader. The validated map is also the sole source of the closed KV readiness target set: every binding resolves the reserved `.rss-readiness` key through the same resolver.
- `rss vault-allowlist validate --file <path>|--stdin` is the sole offline preflight. The RSS binary dispatches it before `operator::prepare_runtime`; it reuses the serving typed parser, reads no ambient configuration, constructs no provider, performs no network I/O, and emits only closed static categories. Runtime-baseline exact AST locks this exception without admitting a serving or maintenance alternate source.
- `cargo xtask archrules list` and its generated matrix derive implemented rules from real carrier anchors. Planning documents are not a second index.
- The active forge does not make the existing `ci-gate` a required check.

## Process configuration snapshot

The private runtime preparation kernel consumes `EnvConfigSource` once into an owned
`RuntimeConfigSnapshot`, derives the `RUST_LOG` filter and optional OTLP exporter from that same
generation, and installs the subscriber. It then returns one of two opaque, mutually exclusive
carriers: `ServingRuntimeInputs` from `runtime::prepare_runtime()` or `OperatorRuntimeInputs` from
`runtime::operator::prepare_runtime()`. The source is passed by value and is not retained as a closure,
trait object, reload handle, or fallback. Both carriers have private fields and crate-private
constructors and always own a non-optional snapshot; only `ServingRuntimeInputs` owns the mandatory
password blocklist and type-checks at `run()`. A
runtime lifecycle owner retains the optional trace exporter until it is transferred into the
launch plan; every pre-handoff startup result then crosses one terminal funnel that explicitly
shuts down any exporter still owned. Launch registers every owned lifecycle output before it can
return a validation, bind, or shutdown-trigger error, and every launch result drains the one
`runtimeexec`-owned `ShutdownStack` exactly once. Assemblies can only register prepared listeners
through `LaunchRegistrar`; they cannot construct the stack or obtain its root cancellation token.
The RSS binary classifies its closed command family before acquiring
profile input; serving transfers ownership to `run()`, while all operator arms converge on one
explicit `runtime::operator::shutdown_runtime()` call.

`SnapshotConfig<'_>` is a crate-private borrowed capability with a private field. Only
`RuntimeConfigSnapshot::view()` can mint it. Serving OIDC/JWKS and provider construction, listener
address policy and mTLS material, launch, and the private PostgreSQL/Redis/Vault/S3 typed
configuration constructors accept this capability directly, so an ambient getter cannot
type-check at those production boundaries. RSS operator commands accept the already prepared
`OperatorRuntimeInputs` and borrow the same capability; OIDC JWKS export and Vault-backed settings
maintenance do the same. The runtime crate exposes no migrated PostgreSQL/Redis/Vault/S3
environment or generic getter builder. When the inbound Internal
listener resolves to mTLS, route assembly requires and validates a captured, non-empty
`SPIFFE_ENDPOINT_SOCKET`, parses the allow-set once, and carries the endpoint as a non-optional
value with the allow-set and readiness slot in `ListenerTransport::Mtls`; launch always passes that
exact endpoint explicitly and has no configuration-source fallback. Plaintext and non-mTLS
listeners do not require it. Unknown listener/auth states and invalid required values fail closed.
Outbound domain transport resolves its URL/mTLS targets and mandatory non-empty
`SPIFFE_ENDPOINT_SOCKET` from the same serving snapshot. Its typed carrier owns the endpoint and
always passes it explicitly to the HTTP adapter, so the upstream `spiffe` ambient endpoint fallback
is unreachable from runtime production wiring.
The integration-only test-support façade selects a closed listener kind from a committed,
fingerprint-verified RuntimePlan fixture and calls the same projection/finalization core. It
accepts neither raw auth values nor a handwritten scheme and is absent from the default production
library API.

The catalog is an explicit runtime configuration universe: fixed listener/auth/OIDC/tracing,
PG/Redis, Vault/S3, identity/audit, event/DLX/worker keys; the required Vault tenant/store allowlist
JSON; generated event-domain AMQP keys; the
fixed domain-transport URL/mTLS allow-set family (`RSS_<DOMAIN>_DOMAIN_TRANSPORT_URL`, optional
shared `RSS_DOMAIN_TRANSPORT_URL` under `durable-shared`, per-domain SPIFFE allow-sets, and local
client SPIFFE id); placement workload funnel facts
(`RSS_<DOMAIN>_DOMAIN_PLACEMENT_WORKLOAD`) that decide Local composition vs Remote outbound binding
and enter the RuntimePlan fingerprint; and the operator OIDC static provider. It never calls
`vars_os()`. Exactly four named command-specific maintenance grant sources are outside this
catalog; no other runtime production ambient reader is accepted. Missing and non-Unicode values
both preserve the existing `std::env::var(...).ok()` result; empty strings, whitespace, and case
are not normalized by capture. Invalid placement-workload or domain-transport syntax is retained
and reported later by the existing builders, preserving decision and error order.

All captured UTF-8 values use `secure::SecretText`: private storage, opaque `Debug`, no
`Clone`/`Display`/serialization, and drop-time zeroization. Snapshot `Debug` and capture errors are
closed and do not expose keys, presence, or values. Configuration material is runtime state: it is
never serialized into AssemblyLock/RuntimePlan/DeploymentPlan, included directly in their
fingerprints, or written to deployment evidence. Only closed non-secret listener selections enter
RuntimePlan: Primary/Admin carry `rssAccessToken` or `federatedAccessToken`, Internal carries
`mtls` or `serviceToken`, and Health is fixed to `noAuth`. Secret-only snapshot changes leave its
fingerprint unchanged.

The Vault allowlist is validated while mapping the serving snapshot, before provider construction or
listener bind. Missing, non-Unicode, empty, malformed, unknown-field, invalid UUID/path, duplicate
`(tenantId, storeId)`, and cross-tenant overlapping physical namespace inputs are startup errors.
After startup, a missing mapping is request-level `Forbidden` before network I/O and cannot mutate
readiness. Transit failure is represented by `keyprovider_ready`; KV mount, ACL, canary, timeout, or
reachability failure is represented independently by `vault_secret_resolver_ready`. Either unhealthy
probe makes `/readyz` return 503, while a request-level Forbidden leaves the last sampler state intact.
These states must not be collapsed.

`SecretText::expose` and `into_string` are explicit disclosure/ownership boundaries, not a claim
that callers cannot copy. Runtime allocation handoff uses named move/copy funnels; Medium
`SECRET-TEXT-TRANSFER-LIVE-01` closes them to seven zeroizing-owner moves plus two required
zeroizing-owner copies for the Vault signer and resolver.

The active carriers are Hard `SECRET-TEXT-OPAQUE-01` and
`RUNTIME-CONFIG-SNAPSHOT-01` (`SnapshotConfig`), plus Medium
`RUNTIME-CONFIG-SNAPSHOT-LIVE-01`, `RUNTIME-BINARY-SNAPSHOT-LIFECYCLE-01` in
`runtime-baseline`, and `RUNTIME-ENV-FUNNEL-01`. The fast exact-inventory carrier is executed by
`cargo xtask runtime-env guard`; the registered `rss_runtime_env_funnel` Dylint supplies the
macro-expansion and name-resolved HIR backstop during full verification. The Hard carrier combines
the private concrete process source and generic capture primitive behind the zero-argument
`RuntimeConfigSnapshot::capture_process_snapshot()` factory, the mutually exclusive owned profile
inputs, unforgeable
`SnapshotConfig` consumer signatures, and the mTLS transport carrier; omission or capability
forgery at those boundaries, or minting from an alternate source, is therefore not expressible.
The crate-visible process factory is additionally restricted by the Medium inventory/HIR gates:
the production module graph must contain exactly one factory reference and call in the canonical
owner, plus profile-specific input construction and typed PostgreSQL/Redis/Vault/S3 mappings with
their consuming builders, and it
rejects ambient environment reads in a `SnapshotConfig` consumer or its crate-wide conservatively
reachable call graph. Protected aliases, direct and function-item environment aliases, local and
cross-file wrappers, UFCS, transitive macro and re-export indirection, ambiguous same-name shadows,
macro-generated production modules, compile-time environment macros, included source, and
compliant bait fail closed through the combined inventory/HIR gate. It also proves that the
snapshot-derived `RUST_LOG` filter is
installed in the subscriber and that the exact outer runtime owner always finishes the unique
inner startup result through one pending-exporter cleanup while preserving the primary error. The
binary lifecycle carrier separately proves one ownership-complete terminal path per command:
serving transfers the exact serving input to `run()`, and every RSS operator reaches the sole
exact operator-input shutdown after pre-acquisition closed command classification. Synthetic reds cover
duplicate/discarded/wrong generations, detached-module promotion, owner and cleanup bypasses,
binary wrong bindings and early returns (including the exact prepared input passed to every
PostgreSQL operator), ambient filter restoration, transitive reachable ambient
reader variants, and compliant unrelated-name bait.

Ownership after #1786/#1787 is explicit: PostgreSQL/Redis/Vault/S3, event/domain/DLX/worker,
composition settings, serving and operator OIDC providers, OIDC JWKS export, and Vault-backed
settings maintenance are snapshot-backed. The four command-specific maintenance grant sources
remain deliberately named and outside the catalog; each reader requires the unforgeable
operator-only `OperatorRuntimeCapability`, while `RUNTIME-ENV-FUNNEL-01` fixes its exact caller.
Operator commands bind no listener and use neither serving OIDC/JWKS nor password-policy capability.
This section records the boundary; it is not a second or Soft enforcement mechanism.

## 目标能力

Downstream runtime-deployment work must apply these principles:

1. **Single fact chain**: v1 fingerprints AssemblyLock, RuntimePlan, and DeploymentPlan separately; each downstream stage carries its immediate upstream identity, while inventory and receipts carry all three.
2. **Closed versions**: target JSON objects require `schemaVersion = 1`, reject unknown fields and versions, and add no compatibility reader, alias, fallback, shim, or dual write.
3. **Typed secret boundary**: plans and inventory carry typed references only; material must not enter schemas, stable output, logs, receipts, or generated deployment artifacts.
4. **Semantic ordering**: set-like collections are deterministically sorted; domain and lifecycle sequences preserve declared execution order.
5. **Wire ownership**: a SpecKit design schema cannot substitute for a production `contracts/http/**` contract.
6. **Local evidence**: AI delivery skills call the repository's gates. Forge configuration and the skills themselves are not enforcement carriers.
7. **Canonical identity**: stage fingerprints hash `ASCII(stageTag) || NUL || RFC8785(unsignedObject)` with SHA-256; the result field is omitted from its own preimage, and every aggregate input universe is closed before hashing.

## Carrier selection

Choose the first applicable carrier and bind it to an owner PBI:

| Priority | Strength | Use when | Required proof |
|---|---|---|---|
| 1 | Hard | invalid states can be excluded by types, visibility, crate graph, schema/codegen, derive, or golden output | compile failure or exact generated/golden drift |
| 2 | Medium | source, deployment, OCI, or receipt semantics remain expressible | fail-closed gate plus synthetic red and anti-vacuity case |

If neither carrier is credible, shrink or defer the target. A prose convention, naming preference, prompt, reviewer memory, or manual checklist is not an acceptable new mechanism.

New target work must record:

- owner issue and affected fact-chain stage;
- Hard or Medium strength and concrete repository carrier;
- nearest invalid state and its red evidence;
- command that executes the carrier;
- upstream and downstream fingerprints it verifies.

This file maintains the principles and selection algorithm only. Implemented instances remain discoverable through `archrules`; planned instances remain in the active SpecKit task matrix until their owner lands.

## Schema baseline

The four #1779 schemas are target boundaries, not claims of runtime implementation. Their common requirements are Draft-07, version 1 only, recursively closed objects, RFC 8785 UTF-8 fingerprint bytes with stage domain separation, typed secret references, and explicit ordering semantics. V1 is replaced in place before downstream implementation; no prior fingerprint reader, alias, shim, fallback, or dual write exists.

Schema ownership is exclusive:

- #1780 owns the AssemblyLock v1 schema and repository-verified compiler protocol; #1781 owns its committed golden generation and aggregate drift gate.
- #1788 owns RuntimePlan implementation and `runtimePlanFingerprint` golden parity.
- #1802 owns DeploymentPlan implementation, consumes `runtimePlanFingerprint`, and produces `deploymentFingerprint`.
- #1806 owns RuntimeInventory, carries assembly/runtime-plan/deployment fingerprints, and adds a separate authorized HTTP contract: auth mode is `permission|serviceOwned`, resource sharing is explicit `tenantScoped|global`, and `public|bootstrap|clientsOnly` are invalid.
- #1796 and #1797 own the landed subset launch paths and closed JSON configuration schemas. #1798 owns the cross-assembly artifact classification and exact closure gate.

The landed #1788 Hard carrier is `RUNTIME-PLAN-CONSTRUCTION-01`: protocol fields are private,
`RuntimePlan::compile_v1` validates canonical manifest/lock identity and declaration bijections,
`ProviderConstructor` is the exhaustive manifest/plan/xtask registry, candidate authoring cannot
supply derived listener IDs or lifecycle phases, and `ParsedRuntimePlan` is the only wire reader.
Its diagnostics retain only a closed category and sanitized known-field path. Draft-07 validation
of the real writer, writer-to-reader round-trip, shared RFC8785 vector, compile-fail privacy tests,
and the bundled full-plan JSON golden freeze the same v1 facts.
Downstream stages must carry the supplied upstream fingerprint and must not reconstruct Assembly
identity from partial RuntimePlan fields.

The landed #1789 Hard carrier is `RUNTIME-PHASE-TRANSITION-01`: private phase-state fields,
non-Clone/non-Copy/non-Debug/non-Default lifecycle ownership, consuming transition receivers, and
transition return signatures bound directly to exact associated `Next` types make only
`Planned → ProvidersBuilt → InfraBuilt → DomainsWired → Finalized →
runtimeexec::RuntimeOutputs`
representable. The private `PhaseContext` retains the serving input and owned `RuntimePlan`;
callers cannot supply a phase label, extract a lifecycle owner, skip a state, or reuse a consumed
state. `phase::execute` is the sole production chain and `run_startup` has one call into it.

The landed #1791 provider-catalog Hard carrier is the closed `ProviderRole`,
`ProviderConsumer`, and `ProviderFactorySymbol` universe, the private role registry and capability
evidence, and `ProviderCatalogEntry::checked` const validation compiled into each assembly. Its
Medium/codegen backstop is exact manifest-to-registry validation, the restricted data-only
`providers_gen.rs` grammar, rustc typecheck, committed goldens, and a separate provider drift gate.
The landed #1792 carrier exact-joins that catalog with `RuntimePlan`, mints 14 non-interchangeable
one-shot permits, and accepts construction evidence only through eight sealed `ProviderOutput`
batches. `ProviderBuild` derives actual lifecycle channels from owned `DomainModuleResult`s,
aggregates every missing receipt, retains provider and domain outputs through all fallible phases,
and asynchronously rolls them back in dependency-safe LIFO order. The old static binding,
generic receipt constructor, string lookup, handwritten bypass, and synchronous-drop paths do not
exist.

The landed #1790 Hard carrier is `RUNTIME-LISTENER-PLAN-EXECUTION-01`.
`RuntimePlan` is the sole mint for private `ListenerExecutionPlan` and
`ListenerExecutionSpec` values; the single finalizer consumes that capability and alone produces
the private-field finalized launch input, which carries both `FinalizedListenerSet` and the
assembly-private `FinalizedProbeReceipt` into `Finalized`. Assembly listener/auth conversion is exhaustive. No public
listener constructor, raw-value assembler, manual Health append, compatibility wrapper, or plain
listener vector can re-enter the chain. Compile-fail tests lock all three construction boundaries.

The landed #1793 Hard carrier is `RUNTIME-PLACEMENT-PLAN-EXECUTION-01`.
`RuntimePlan` is the sole mint for private `PlacementExecutionPlan`. Local domains compose
in-process modules; Remote domains bind outbound contract transport only and must not appear on
local listeners. The remote placement set is the exclusive transport required-domain set;
`RSS_DOMAIN_TRANSPORT_REQUIRED_DOMAINS` is deleted. Placement workloads are non-secret funnel facts
(`RSS_<DOMAIN>_DOMAIN_PLACEMENT_WORKLOAD`) that change the RuntimePlan fingerprint.

The landed #1794 Hard carrier is `DomainExecutionPlan`. `RuntimePlan` alone mints it from the
declared domain plans and the already-validated placement projection. The capability is carried
through `InfraBuilt`, consumes the generated `Vec<DomainBinding>`, and admits only the exact local
domain projection in declaration order. Missing, extra, duplicate, reordered, or remotely placed
bindings fail before composition; the failed capability returns the owned bindings so their
`DomainModuleResult`s remain inside the existing asynchronous LIFO provider rollback. Only the
private `ValidatedDomainBindings` wrapper can reach the canonical composition helper. No public
constructor, domain loop, root re-export, alias, or compatibility path exists.

Medium `RUNTIME-LISTENER-PLAN-EXECUTION-LIVE-01` binds the type proof to dynamic facts. Domain
wiring validates plan, generated `DOMAIN_LISTENER_BINDINGS`, and live registry membership and
per-listener order exactly. Finalization rejects undeclared live groups, missing declared
non-empty groups, duplicate/incorrect kind or auth, provider-presence drift, transport drift, and
leftovers before address resolution or socket bind. Domain-free Internal plans produce an empty
router and still finalize auth/transport. Health is created only for plan-declared
`Health + NoAuth`, after non-Health finalization and mTLS probe registration. Synthetic reds cover
legacy config decisions, raw-value assembly, manual Health construction, plain-vector launch,
duplicate projection/finalizer calls, alternate finalizer/set constructors, and trait conversion
seams. The complete production-module AST inventory locks the unique canonical owners and call
sites, the exact `pub(crate)` capability types with inherited-private fields, the sole set literal,
and the absence of public re-exports independently of spelling; the workspace green case is the
anti-vacuity proof.

Launch consumes the finalized set into a private, consuming `BoundListenerSet`. It resolves and
binds every socket and prepares every transport before any serve task exists. Only after the set is
complete does activation publish mTLS readiness, start non-Health listeners, and start Health last.
Any address, bind, transport, or activation-preflight failure therefore exposes zero partially
started HTTP listeners and drops the prepared sockets before lifecycle cleanup completes.

Medium `RUNTIME-PHASE-TRANSITION-LIVE-01` binds that type-level proof to production source. Its
crate-wide production AST inventory verifies the unique entry, five-step order, consuming
receivers, associated closed phase labels, common redaction funnel, closed state trait impls, and
sole `Finalized` launch-plan handoff. Request-budget validation must succeed before trace/PG/domain
handoff. Synthetic reds reject missing or reordered transitions, early plan drop, the old tuple
path, assembly-owned or aliased launch executors, direct `ShutdownStack` construction, cross-file state impls, macros,
dead branches, and compliant comment/test bait. The lifecycle contract remains unchanged:
pre-launch trace cleanup stays in `RuntimeLifecycleOwner`, while the top-level launch executor
in `runtimeexec` creates and consumes the only `ShutdownStack`.

Medium `RUNTIME-PLAN-LIVE-CLOSURE-01` joins the four RuntimePlan declaration families to the one
production phase chain and freezes the aggregate declaration/projection/live inventories for
providers, listeners, domains, and placements. Its AST evidence rejects summary `.len()` calls,
dead helpers, macro expansion, comments/strings, and test bait. `RUNTIME-ROOT-RATCHET-01` separately
parses the runtime root and an append-only schema-v1 history policy, requiring every recorded LOC,
responsibility, and public-surface metric to be component-wise non-increasing. A missing, truncated,
raised, unknown-field, or unparsable policy/root fails closed through the sole
`cargo xtask runtime-root guard` command.

#1795 adds `RUNTIMEEXEC-LAUNCH-OWNERSHIP-01`: private `LaunchPlan` fields, a mandatory opaque probe
receipt, a single `LaunchAdapter`, assembly-private prepared/inventory states, restricted
`LaunchRegistrar`, and a private `RuntimeOutputs` constructor make plan reuse, preflight bypass,
completion forgery, and raw stack access unavailable at production call sites. The full runtime
keeps HTTP/mTLS/address preparation in its private adapter; `runtimeexec` depends only on
provider-independent lifecycle layers. Medium layer-deps, public-api, and runtime-baseline gates
pin the exact dependency closure and single-owner production handoff with synthetic-red and
anti-vacuity tests. There is no old executor, alias, re-export, facade, or compatibility path.

#1796 and #1797 consume that kernel in the `settingsonly` and `identityaudit` binaries. Each subset
has a closed Draft-07 configuration schema, a dedicated nonroot distroless Docker stage, exact
Health listener/inventory ownership, and a non-ignored lifecycle journey. Their domain-specific
provider, authentication, readiness, and behavior guards remain the semantic owners for those
assemblies rather than being replaced by a generic artifact presence check.

#1798 adds Medium `ASSEMBLY-ARTIFACT-MATRIX-01`. `assemblies/artifacts.toml` is the sole schema-v1
classification of the dynamically discovered `assemblies/*` universe. A `supported` row must close
binary, image, configuration carrier, Health inventory, and journey identities; a `compile-only`
row must instead carry a non-empty reason and cannot carry deployable artifacts. The validator in
`xtask/src/assembly_artifacts.rs` rejects unknown fields and versions, missing/extra/duplicate
assemblies, reused artifact identities, unsafe paths, and semantic bait, then exposes only a
fully checked `VerifiedArtifactMatrix`. `runtime` binds its typed environment catalog and Compose
smoke journey; the two subset assemblies bind their closed JSON schemas and Cargo journeys.
The production ratchet requires `identityaudit`, `runtime`, and `settingsonly` to remain
`supported`; a future discovered assembly may enter as an explicit `compile-only` row, but none of
these three can use that lifecycle as a rollback or review bypass. Image validation also rejects
runtime-stage `USER` overrides and requires an unswallowed `cargo build --release --locked`.
The accepted build instruction is a closed token sequence for the declared package/binary (plus
the runtime image's required `rss` operator binary), so help/version, feature, or other extra Cargo
options cannot masquerade as a build. Rust journey and launch witnesses never descend into
closures, async/const blocks, or nested items. Compose build/up/health witnesses must be top-level
commands; readiness is accepted only in the exact outer polling loop, and nested
if/case/loop/group/subshell scopes cannot contribute it. Only teardown may live in the exact
`cleanup()` function reached by `trap cleanup EXIT`.
`cargo xtask assembly artifacts check` is the only CLI and emits one stably sorted observed matrix
before returning its static-carrier verdict. That verdict explicitly excludes same-head test,
image-build, and deployment execution receipts.

This matrix is a `Planned → Deployed` repository carrier. It is deliberately outside canonical
`AssemblyManifest`, generated module/provider inputs, AssemblyLock, and RuntimePlan, so adding or
checking artifact evidence does not rotate their identities. Its health/inventory column is
internal launch evidence, not the authorized public RuntimeInventory owned by #1806, and the
presence of a supported `runtime` row does not claim the production posture owned by #1801.
Likewise, the journey column proves an exact non-vacuous test or smoke carrier, not a same-head
execution receipt; release-time immutable image and execution evidence remain owned by #1802.

#1798 changes no RuntimePlan schema or fingerprint, AssemblyLock, generated module/provider catalog,
public wire contract, database, secret, or configuration identity. Rollback removes the matrix,
scanner, CLI, typed gate, CI report, and these documentation changes as one whole-change revert; it
must not downgrade `supported` to `compile-only` or add an old reader, dual format, alias, fallback,
or compatibility feature.

## AssemblyLock committed workflow

AssemblyLock is generated repository identity, never a hand-maintained input. After changing an assembly manifest, contract, schema, or generated module carrier, run generation in this order:

```bash
cargo xtask assembly generate-modules
cargo xtask assembly generate-providers
cargo xtask assembly lock generate
```

Review the raw inputs and generated layers in the same diff, then run the focused sequence
`assembly validate` → `assembly artifacts check` → `assembly generate-modules --check` →
`assembly generate-providers --check` → `assembly lock check` →
`graph assembly --check`. The aggregate typed plans preserve the same
validate → artifacts → modules → providers → lock → graph order. Do not edit `assembly.lock.json` by hand;
regenerate it from verified inputs.

A reserved `assembly.lock.json` below a direct `assemblies/*/` directory without its `assembly.toml` ownership marker is an orphan. Both lock actions fail and leave it untouched. Recovery is explicit: restore the matching manifest if removal was accidental, or inspect and manually delete the orphan before regenerating.

The committed lock contains deterministic repository identities and digests only. It must not contain secret material, environment values, tenant/device state, or other runtime configuration. Its fingerprint proves repository-input integrity; it is not a signature, authorization decision, deployment receipt, or runtime-state proof.

Provider catalog rollout and rollback are pure code/identity operations: no database, secret,
configuration, or external contract migration is introduced. A rollback reverts the generated
catalogs, consuming binaries, locks, and rotated fingerprints together; it cannot introduce an old
reader, alias, dual write, free-form factory path, or runtime fallback.

Vault allowlist rollout is a separate atomic binary/config operation: publish the consuming binary
and its exact `RSS_VAULT_TENANT_STORE_ALLOWLIST_JSON` bundle plus every binding's reserved
`<kvPathPrefix>/.rss-readiness` key/ACL as one generation, never a partial set. Rollback restores the
exact previous binary, config, canary, and ACL bundle together and waits for
their readiness before traffic returns. The mapping changes no database schema, persisted value, or
ciphertext format, so rollback performs no database/persistence mutation. An old variable alias,
dual reader, implicit empty/default mapping, or compatibility fallback is forbidden. Because the
allowlist is runtime configuration material, it is not serialized into AssemblyLock or RuntimePlan
and does not change their fingerprints.

The catalog approach keeps
[Typify's programmatic codegen](https://github.com/oxidecomputer/typify/blob/aec3da53c4319164542b393a86d552424be24384/typify/src/lib.rs)
and [Omicron's explicit manifest](https://github.com/oxidecomputer/omicron/blob/9932e3633a3417d130af44dfce12672eb8e0ec00/package-manifest.toml)
as external comparison points; RSS does not adopt either project's public schema or package model.

## 缺口与 owner

The active owner/carrier matrix in `docs/spec/007-runtime-deployment-executable-plan/tasks.md` is planning guidance, not a machine-enforced mirror. The latest `pm:epic-wave` comment on #1778 is the dynamic schedule source. A target remains planned until its owner supplies the carrier and machine evidence.

## Validation

Run `cargo xtask verify --fast` for the repository aggregate; its typed Meta registry invokes the `runtime-deployment-spec` selftest in-process and fail-closed. Use `cargo xtask runtime-deployment-spec --selftest` to validate the committed machine inputs. #1809 separately owns same-head receipt aggregation, so #1779 must not claim active-PR scheduling, forge activation, or receipt closure. Runtime and deployment owners add the validation command named in their PBI.
