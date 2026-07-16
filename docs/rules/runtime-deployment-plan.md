# Runtime Deployment Plan Rules

This rule governs how runtime-deployment target constraints select enforcement carriers. It supplements `docs/rules/architecture.md`, `runtime-assembly-plan.md`, and `runtime-wiring.md`; it does not copy their implemented carrier inventory.

## 当前事实

- Assembly manifest validation, generated domain ordering, and committed v1 AssemblyLock drift are governed by typed repository gates.
- Both serving binaries now enter through `prepare_runtime()`, which captures one closed process-level configuration generation before tracing and provider construction. Listener/auth/tracing/serving-OIDC and every PostgreSQL/Redis consumer are capability-only; remaining serving migrations are owned by #1785–#1787. RuntimePlan is still summary-oriented, subset assemblies are non-runnable, and no DeploymentPlan/Helm/inventory evidence chain exists.
- `cargo xtask archrules list` and its generated matrix derive implemented rules from real carrier anchors. Planning documents are not a second index.
- The active forge does not make the existing `ci-gate` a required check.

## Process configuration snapshot

`runtime::prepare_runtime()` consumes `EnvConfigSource` once into an owned
`RuntimeConfigSnapshot`, derives the `RUST_LOG` filter and optional OTLP exporter from that same
generation, installs the subscriber, and returns an opaque `RuntimeInputs`. The source is passed
by value and is not retained as a closure, trait object, reload handle, or fallback.
`RuntimeInputs` has private fields and a crate-private constructor but is public as the opaque
cross-crate carrier used by the thin binaries; it always owns a non-optional snapshot. `run()`
consumes that carrier, so serving phases cannot be entered without a captured generation. A
runtime lifecycle owner retains the optional trace exporter until it is transferred into the
launch plan; every pre-handoff startup result then crosses one terminal funnel that explicitly
shuts down any exporter still owned. Launch registers every owned lifecycle output before it can
return a validation, bind, or shutdown-trigger error, and every launch result drains the one
`ShutdownStack` exactly once. The RSS binary classifies its closed command family before acquiring
`RuntimeInputs`; serving transfers ownership to `run()`, while all operator arms converge on one
explicit `shutdown_runtime()` call.

`SnapshotConfig<'_>` is a crate-private borrowed capability with a private field. Only
`RuntimeConfigSnapshot::view()` can mint it. Serving OIDC/JWKS construction, listener auth,
listener address policy, route assembly, launch, and the private PostgreSQL/Redis typed
configuration constructors accept this capability directly, so an ambient getter cannot
type-check at those production boundaries. The RSS operator commands that need PostgreSQL accept
the already prepared `RuntimeInputs` and borrow the same capability; the runtime crate exposes no
PostgreSQL/Redis environment or generic getter builder. When the inbound Internal
listener resolves to mTLS, route assembly requires and validates a captured, non-empty
`SPIFFE_ENDPOINT_SOCKET`, parses the allow-set once, and carries the endpoint as a non-optional
value with the allow-set and readiness slot in `ListenerTransport::Mtls`; launch always passes that
exact endpoint explicitly and has no configuration-source fallback. Plaintext and non-mTLS
listeners do not require it. Unknown listener/auth states and invalid required values fail closed.
The outbound domain-transport path still permits the `spiffe` crate's ambient endpoint fallback;
that separate consumer belongs to the subsequent runtime snapshot migration issues and is not an
exception for inbound listener assembly.
The explicit-value route-assembly core used by the identity wire e2e is compiled only under the
test-only `integration` feature; it is absent from the default production library API.

The catalog is an explicit serving universe: fixed listener/auth/OIDC/tracing, PG/Redis,
Vault/S3, identity/audit, event/DLX/worker keys; generated event-domain AMQP keys; and the
domain-transport URL/mTLS families derived in a second step from the captured required-domain
value. It never calls `vars_os()` and excludes the four maintenance grant keys, CI/Forge
credentials, AWS default-chain dynamic credentials, and SPIFFE rotation material. Missing and
non-Unicode values both preserve the existing `std::env::var(...).ok()` result; empty strings,
whitespace, and case are not normalized by capture. Invalid required-domain syntax is retained and
reported later by the existing builder, preserving decision and error order.

All captured UTF-8 values use `secure::SecretText`: private storage, opaque `Debug`, no
`Clone`/`Display`/serialization, and drop-time zeroization. Snapshot `Debug` and capture errors are
closed and do not expose keys, presence, or values. Configuration material is runtime state: it is
never serialized into AssemblyLock/RuntimePlan/DeploymentPlan, included in their fingerprints, or
written to deployment evidence.

`SecretText::expose` and `into_string` are explicit disclosure/ownership boundaries, not a claim
that callers cannot copy. Runtime allocation transfer uses one named funnel; Medium
`SECRET-TEXT-TRANSFER-LIVE-01` closes it to the four Vault/S3 zeroizing-owner handoffs.

The active carriers are Hard `SECRET-TEXT-OPAQUE-01` and
`RUNTIME-CONFIG-SNAPSHOT-01`, plus Medium `RUNTIME-CONFIG-SNAPSHOT-LIVE-01` and
`RUNTIME-BINARY-SNAPSHOT-LIFECYCLE-01` in `runtime-baseline`. The Hard carrier combines owned `RuntimeInputs`, unforgeable
`SnapshotConfig` consumer signatures, and the mTLS transport carrier; omission or capability
forgery at those boundaries is therefore not expressible. It does not claim that a Rust function
body cannot name an ambient API. The Medium AST check proves the production module graph contains
exactly one capture, `RuntimeInputs` construction, typed PostgreSQL/Redis mapping, and the remaining
snapshot-backed Vault/S3 calls, and it
rejects ambient environment reads in a `SnapshotConfig` consumer or its crate-wide conservatively
reachable call graph. Protected aliases, direct and function-item environment aliases, local and
cross-file wrappers, UFCS, transitive macro and re-export indirection, ambiguous same-name shadows,
and compliant bait fail closed. It also proves that the snapshot-derived `RUST_LOG` filter is
installed in the subscriber and that the exact outer runtime owner always finishes the unique
inner startup result through one pending-exporter cleanup while preserving the primary error. The
binary lifecycle carrier separately proves one ownership-complete terminal path per command:
serving transfers the exact prepared input to `run()`, and every RSS operator reaches the sole
exact-binding shutdown after pre-acquisition closed command classification. Synthetic reds cover
duplicate/discarded/wrong generations, detached-module promotion, owner and cleanup bypasses,
binary wrong bindings and early returns (including the exact prepared input passed to every
PostgreSQL operator), ambient filter restoration, transitive reachable ambient
reader variants, and compliant unrelated-name bait.

Ownership after #1784 is explicit: PostgreSQL/Redis are fully snapshot-backed; #1785 covers
Vault/S3, #1786 covers event/domain/DLX/worker and composition settings, and #1787 closes the final ambient-read AST
guard. Static OIDC env construction used only by non-serving operator/maintenance commands remains
outside #1783; those commands bind no listener and do not use the serving OIDC/JWKS provider.
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
- #1796 and #1797 each own their subset assembly config schema and artifact closure.

## AssemblyLock committed workflow

AssemblyLock is generated repository identity, never a hand-maintained input. After changing an assembly manifest, contract, schema, or generated module carrier, run generation in this order:

```bash
cargo xtask assembly generate-modules
cargo xtask assembly lock generate
```

Review the raw inputs and both generated layers in the same diff, then run the focused sequence `assembly validate` → `assembly generate-modules --check` → `assembly lock check` → `graph assembly --check`. The aggregate typed plans preserve the same modules → lock → graph order. Do not edit `assembly.lock.json` by hand; regenerate it from verified inputs.

A reserved `assembly.lock.json` below a direct `assemblies/*/` directory without its `assembly.toml` ownership marker is an orphan. Both lock actions fail and leave it untouched. Recovery is explicit: restore the matching manifest if removal was accidental, or inspect and manually delete the orphan before regenerating.

The committed lock contains deterministic repository identities and digests only. It must not contain secret material, environment values, tenant/device state, or other runtime configuration. Its fingerprint proves repository-input integrity; it is not a signature, authorization decision, deployment receipt, or runtime-state proof.

## 缺口与 owner

The active owner/carrier matrix is `docs/spec/007-runtime-deployment-executable-plan/tasks.md`; its exact machine mirror is `fixtures/task-baseline.json`. The latest `pm:epic-wave` comment on #1778 is the dynamic schedule source. A target remains planned until its owner supplies the carrier and machine evidence.

## Validation

Run `cargo xtask verify --fast` for the repository aggregate; its typed Meta registry invokes the `runtime-deployment-spec` selftest in-process and fail-closed. Use `cargo xtask runtime-deployment-spec --selftest --against origin/develop` as the focused PR-scope check. #1809 separately owns same-head receipt aggregation, so #1779 must not claim active-PR scheduling, forge activation, or receipt closure. Runtime and deployment owners add the focused command named in their PBI.
