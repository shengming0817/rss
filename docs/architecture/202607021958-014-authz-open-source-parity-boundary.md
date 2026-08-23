# ADR-014：open-source AuthZ parity boundary

- **状态**：Accepted（#1587：TENANCY-10 open-source authz parity matrix and boundary ADR）
- **日期**：2026-07-02
- **关联**：Feature #1576 · PBI #1587 · ADR-006（内置 typed authplan / OPA 取舍）· `TenantId`、`RowScope`、`pg_tenant_tx_guard` 与 PostgreSQL RLS/ACL · `docs/guides/202607090202-1596-tenancy-consumer-migration.md`
- **归属**：framework / tenancy / authorization governance
- **AI-robust 评级**：Medium（`cargo xtask tenancy-closeout` 锁本 ADR、规则引用、矩阵维度与误导表述）

## 1. 决策

RSS 的 open-source AuthZ parity 定义为：same security objective carried by RSS typed/in-process mechanisms。
它不是第三方产品、API、策略语言或运行时部署模型的兼容承诺。

本 ADR 固定以下边界：

- no external PDP process；RSS 不引入 OPA / SpiceDB / OpenFGA 这类独立授权服务或 sidecar。
- no Rego runtime；OPA 只作为外置 PDP / bundle / decision log 的对标参考。
- no Cedar/Casbin DSL runtime；RSS 不加载 Cedar policy set、Casbin conf matcher 或 watcher/distributed enforcer。
- no SpiceDB/OpenFGA tuple graph service；RSS 不建设 relationship tuple store、ZedToken / consistency-token 语义或 graph check 网络调用。
- RLS does not replace RouteAuthorizer；PostgreSQL RLS 只承载数据层 tenant boundary。
- ABAC is not the tenant boundary；ABAC route policy 只能决定 coarse route/resource allow/deny，不能扩大数据行可见性。

RSS 的授权边界由现有机制组合承载：`diport::Pdp` 是 credential verification / claims port；
`httpserve::RouteAuthorizer` 是 route authorization 决策入口；tenant isolation 由 typed `TenantId`、
service-token tenant binding、`SET LOCAL rss.tenant_id` funnel、FORCE RLS 与 non-bypass serving role 承担；
RowVisibility / FieldMask 经 sealed obligation 和 `ResourceProjection` 消费。

## 2. Parity matrix

| framework | policy model | decision evaluation | relationship/attribute source | tenant isolation | row/field obligation | auditability | governance gate | operational tradeoff | rss position |
|-----------|--------------|---------------------|-------------------------------|------------------|----------------------|--------------|-----------------|----------------------|--------------|
| OPA | Rego policy + bundle/data document | OPA API / sidecar/server or embedded Rego eval | request input + data documents | input/context convention, not a native tenant boundary | policy result can carry structured data, not RSS sealed obligations | decision log and bundle revision are first-class concepts | bundle distribution and policy tests | hot policy update and non-Rust authoring cost extra infra and language surface | adopt PEP/PDP separation and audit vocabulary; deviate from sidecar/server and Rego runtime |
| Cedar | PARC model: principal, action, resource, context + entities | in-process `Authorizer` over policy set and entities | entity graph and request context | modeled in entities/context by application convention | diagnostics and forbid/permit semantics; no RSS `RowVisibility` or `ResourceProjection` carrier | authorization response diagnostics help explain decisions | schema validation before policy use | embedded evaluation, but policy language and entity model become another runtime surface | adopt embedded typed evaluation shape; deviate from Cedar DSL and entity runtime |
| SpiceDB | Zanzibar-style relationship and permission graph | service graph check over relationships and caveats | relationship tuple store + caveat context | namespace/store/model partitioning by deployment convention | caveats can condition decisions; no direct RSS field projection | request tracing and consistency tokens support audit correlation | schema validation, tuple writes, consistency controls | central graph service adds operational dependency and consistency model | adopt subject-resource-permission vocabulary; deviate from graph service, tuple store, and token consistency |
| OpenFGA | authorization model + relationship tuples + conditions | API check / list queries over tuple store | tuple store + contextual tuples + request context | store/model namespace convention | conditions influence check; no RSS sealed row/field obligation | API responses and model/tuple history can support audit | model validation and tuple write validation | product service gives flexible relationship modeling with extra datastore/API operation | adopt model/check vocabulary; deviate from server, store, and API dependency |
| Casbin | PERM model: request, policy, effect, matcher | embedded enforcer evaluates matcher/effect over policy | adapter-loaded policy + request attributes + role manager | domain/RBAC fields by model convention | matcher result is boolean or explain data; no RSS sealed obligations | enforce logs / explain feature are adapter-dependent | model syntax + adapter/watcher discipline | lightweight embedded engine, but matcher DSL and enforcement toggles add drift risk | adopt PERM vocabulary and embedded-enforcer comparison; deviate from conf matcher DSL and watcher runtime |
| PostgreSQL RLS | SQL policy on tables | database policy evaluation during query execution | table rows + session GUC via `current_setting` | FORCE RLS + `SET LOCAL rss.tenant_id` + non-bypass role | row filtering / write check only; no route or field obligation | database role, statement, and durable app audit provide evidence | `PG-TX-CAPABILITY-SEAL-01`, `TENANCY-PG-CATALOG-PROOF-01`, `TENANCY-PG-BEHAVIOR-PROOF-01`, `pg-tenant-tx-guard`, startup `verify_rls_capability()` | strongest data boundary, but cannot decide route permission or field projection | adopt as tenant data boundary; keep separate from route Authorizer |
| RSS | typed permission + durable tenant ABAC policy + sealed obligations | in-process `RouteAuthorizer` and credential verification via `diport::Pdp` port | contract-derived route metadata, verified principal, tenant PG policy store, typed resource scope | typed `TenantId`, service-token tenant binding, `SET LOCAL rss.tenant_id` funnel, FORCE RLS, non-bypass serving role | `RowVisibility` / audited cross-tenant visibility / `ResourceProjection` | durable audit for cross-tenant access plus tracing/metrics for decisions | codegen, dylint, xtask gates, startup gates, this ADR via `tenancy-closeout` | less runtime policy dynamism; stronger compile-time and governance boundaries | reference implementation for RSS safety objective |

## 3. Boundary mapping

- **Policy model**：RSS maps third-party policy language capability to contract-derived permissions, sealed permission accessors, and tenant-scoped durable ABAC policy. It does not promise third-party policy syntax support.
- **Decision evaluation**：RSS keeps route authorization in process. External service calls for authorization are a future architectural decision, not part of #1587.
- **Relationship / attribute source**：owner/self/device ownership is contract-derived route metadata plus verified subject/resource attributes. RSS does not materialize an independent relationship graph.
- **Tenant isolation**：tenant boundary remains typed tenant + PG RLS + serving-role gates. Route policy failure or policy-store failure must not widen tenant data access.
- **Row / field obligation**：`RowScope::All` is audited and target-tenant scoped; `ResourceProjection` masks sensitive fields by default.
- **Auditability**：cross-tenant reads require durable audit before capability issuance. Decision logs from OPA-style systems are an observability comparison, not a replacement for durable audit.
- **Governance gate**：`cargo xtask tenancy-closeout` keeps this ADR, `TenantId`、`RowScope`、`pg_tenant_tx_guard` 与 PostgreSQL RLS/ACL, and ADR-006 linked and checks matrix coverage.
- **Operational tradeoff**：RSS accepts redeploy-based typed policy evolution in exchange for fewer moving parts and stronger local boundaries in the current pre-GA architecture.

## 4. Scope exclusions

This ADR defines an authorization parity boundary; it does not authorize or promise delivery of adjacent capabilities.
In particular, explicit-subject/background authorization bridges, a registry runtime control plane, credential revocation,
audit-ledger tamper evidence, field protection at rest, and gRPC transport parity are adjacent concerns whose ownership and
implementation status are outside this ADR. Listing them here neither asserts that a tracker or executable carrier exists
nor makes a delivery commitment. Where a tracker, ADR, or current carrier exists, its live state is authoritative; historical
pointers include #1317/#1353 for credential revocation and #1465–#1467 plus ADR-011 for field protection.

For gRPC, `TenantId`, `RowScope`, `pg_tenant_tx_guard` and PostgreSQL RLS/ACL define the target tenancy rule. Any
implementation claim must cite its own contract/codegen/runtime evidence. None of these exclusions changes this ADR's
in-process `RouteAuthorizer` decision or its no-external-PDP boundary.

## 5. Enforcement

This ADR is a documentation boundary, so true type-system Hard enforcement is not applicable. The strongest useful
carrier is Medium:

- `cargo xtask tenancy-closeout` requires this ADR file, the matrix frameworks, the matrix dimensions, and the explicit boundary claims.
- The same gate requires `TenantId`、`RowScope`、`pg_tenant_tx_guard` 与 PostgreSQL RLS/ACL, ADR-006, and `docs/guides/202607090202-1596-tenancy-consumer-migration.md` to stay linked.
- The same gate rejects selected misleading compatibility phrases in governed #1587 docs.

## 6. 对标证据（ref）

- `ref: open-policy-agent/opa v1/rego/rego.go@main` — Rego preparation/evaluation path, used as external PDP and policy-as-data contrast.
- `ref: cedar-policy/cedar cedar-policy/src/api.rs@main` — embedded `Authorizer` API shape, used as in-process authorization contrast.
- `ref: authzed/spicedb internal/graph/check.go@main` — graph check execution over relationships and caveats, used as Zanzibar/ReBAC contrast.
- `ref: openfga/openfga pkg/server/commands/check_command.go@main` — authorization model / tuple / check command path, used as OpenFGA contrast.
- `ref: apache/casbin-rs src/enforcer.rs@master` — embedded PERM enforcer and matcher/effect evaluation, used as RBAC/ABAC DSL contrast.
- `doc: https://www.postgresql.org/docs/current/ddl-rowsecurity.html` — PostgreSQL RLS policy semantics, used as data-boundary contrast.
