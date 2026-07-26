# Feature Specification: Executable Runtime Deployment Plan

**Status**: Planned baseline

**Tracking**: Epic #1778, baseline #1779, downstream #1780–#1809

## 当前事实

- `RuntimePlan` is a closed typed v1 protocol with an exhaustive provider-constructor registry,
  internally derived listener IDs/lifecycle, strict redacted parsing diagnostics, stable
  provider/listener/domain/placement facts, an upstream AssemblyFingerprint, and a domain-separated
  RuntimePlanFingerprint. Startup consumes all four plan families through the sole typed phase
  chain; #1789–#1794 now close live provider, listener, domain, and placement execution without a
  handwritten compatibility path.
- serving and operator paths capture one immutable process-wide RuntimeConfigSnapshot; the runtime environment funnel rejects serving ambient reads outside named maintenance boundaries.
- `settingsonly` is an executable, deliberately fail-closed Settings closure. It owns a standalone
  binary, closed configuration parser and Draft-07 schema, Primary and Health listeners, real
  Postgres/Vault/JWKS/Settings readiness, the shared `runtimeexec` lifecycle, a SIGTERM journey,
  and a dedicated distroless image target. Identity and Audit are absent by design: missing or
  invalid credentials receive 401, while every successfully verified credential receives 403.
- `identityaudit` is an executable Identity/Audit subset closure with a standalone binary, closed
  Draft-07 configuration schema, authenticated Primary and unauthenticated Health listeners,
  real readiness, the shared `runtimeexec` lifecycle, a SIGTERM journey, and a dedicated nonroot
  distroless image target. #1796 and #1797 are landed facts rather than future assembly work.
- `assemblies/artifacts.toml` classifies the exact discovered assembly universe. #1798 validates
  the binary, image, configuration carrier, Health inventory, and journey closure for all three
  currently supported assemblies through one typed xtask gate. This repository artifact inventory
  is not the authorized public RuntimeInventory owned by #1806 and does not establish #1801's
  production posture.
- deployment is Compose-oriented and not derived from assembly identity; protected inventory and same-head deployment/release receipts do not exist.
- 001 is superseded, immutable audit lineage. 007 is the active planning entry and provides no compatibility path back to 001.

## 目标能力

### Story 1 — Lock one assembly identity

As a runtime builder, I can derive one canonical AssemblyLock from manifest, generated modules, and contracts so every later artifact names the same fingerprint. Independent acceptance is deterministic generate/check with a changed-input red case (#1780–#1781).

### Story 2 — Execute one closed runtime plan

As a runtime owner, I can parse configuration once, construct and fingerprint a closed provider/listener/domain/placement plan, and consume it through typed phases without ambient serving reads or handwritten fallback. Independent acceptance is snapshot, RFC-8785 fingerprint golden, AST-guard, typestate, output-bijection, and live-root evidence (#1782–#1794).

### Story 3 — Launch every declared assembly

As an assembly owner, I can launch full, settingsonly, and identityaudit through one provider-independent runtimeexec graph with binary/image/config/probe/journey closure. Independent acceptance is per-assembly startup and artifact-matrix evidence (#1795–#1798).

### Story 4 — Derive and observe deployment

As an operator, I can render drift-checked Helm from a DeploymentPlan bound to the exact RuntimePlan, inspect an authorized RuntimeInventory carrying all stage fingerprints, and verify immutable OCI/same-head receipts through the existing local gate (#1799–#1809).

## Requirements

- **FR-001**: AssemblyLock MUST close the exact manifest/generated/contracts input universes and fingerprint RFC 8785 UTF-8 bytes with the `rss-assembly-lock-v1` domain tag.
- **FR-002**: Serving configuration MUST be read once into a required typed snapshot; ambient reads MUST be rejected outside named maintenance boundaries.
- **FR-003**: RuntimePlan MUST close provider, listener, domain, lifecycle, and placement facts before launch and produce a `runtimePlanFingerprint` over those stable facts.
- **FR-004**: The live root MUST consume RuntimePlan with no handwritten compatibility path after #1794.
- **FR-005**: All three assemblies MUST close binary, exact image build target, configuration carrier, probes, and journey artifacts through an exact, lifecycle-classified artifact matrix. Digest-bound immutable OCI evidence remains owned by #1802.
- **FR-006**: Production posture MUST require persistent revocation, typed Vault allowlists, and production manifest constraints.
- **FR-007**: DeploymentPlan MUST carry assembly/runtime-plan/deployment fingerprints and complete workload/service/probe/identity/secret-reference/resource facts; its fingerprint MUST bind `runtimePlanFingerprint`.
- **FR-008**: Stable artifacts MUST reject unknown versions/fields and MUST NOT represent secret material.
- **FR-009**: Set-like collections MUST sort deterministically; domain and lifecycle sequences MUST preserve declaration order.
- **FR-010**: RuntimeInventory MUST gain a separate authorized `contracts/http/**` source with auth mode `permission|serviceOwned` and explicit resource sharing `tenantScoped|global`; it MUST reject `public|bootstrap|clientsOnly`, and this design schema MUST NOT become the wire source.
- **FR-011**: Inventory, release, and aggregate evidence MUST carry assembly/runtime-plan/deployment fingerprints and bind exact source SHA; missing, cross-HEAD, or mismatched receipts MUST fail closed.
- **FR-012**: Every target MUST name its owner and Hard/Medium planned carrier; unlanded capability MUST be described in future tense.

## 缺口与 owner

The owner groups are #1780–#1781 identity, #1782–#1787 configuration, #1788–#1794 executable planning, #1795–#1798 launch/artifacts, #1799–#1801 production security, #1802–#1805 deployment, #1806 inventory, and #1807–#1809 release evidence. Exact dependencies, budgets, validation, mutexes, and carrier strength are in `tasks.md`; the latest `pm:epic-wave` comment on #1778 remains the dynamic schedule source.

## Success criteria

- The active SpecKit resolver returns spec, plan, research, data-model, quickstart, tasks, and four contracts.
- The task graph contains exactly #1779–#1809, 52 unique edges, no dangling/self/duplicate edge, no cycle, and depth 20.
- All four schemas are valid Draft-07 version-1 closed objects; stage fingerprints use the frozen RFC-8785/domain-tag protocol, and stable artifacts represent typed secret references only.
- #1779 changes only the tracker-declared exact diff allowlist and new feature tree; 001 has zero diff.
- The repository specification carrier, its mutation selftests, typed fast-aggregate membership, repository fast/all-target checks, and zero-generated-churn check pass. This approved Cx3 correction has no LOC cap.

## Out of scope

Runtime Rust carriers, generated deployment output, Helm, active-PR scheduling, branch protection, MDM/L4 production surface, schema migration readers, aliases, shims, fallbacks, and dual writes are owned elsewhere or intentionally absent. The `runtime-deployment-spec` xtask and its typed `verify --fast` membership are in scope only as #1779's repository specification carrier.
