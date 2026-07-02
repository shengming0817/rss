# 多租户 / ABAC / 行列级数据权限规则

本文件只保留当前行为约束。设计历史、分阶段计划和未来工作归 ADR、spec 或
GitHub Issues。

## TenantID

`tenant::TenantId` 是隔离域边界类型。空值和 nil UUID 非法；非空必须是 canonical
UUID。repo 和 service API 使用 typed tenant 参数，不传裸 `String`。

## RowScope / RowVisibility

`tenant::RowScope` 取值为 self、device、tenant、all，无默认（无 `Default` impl，构造即定）。
`tenant::RowVisibility` 是 sealed obligation（私有字段 + sealed 构造入口），由构造器生成：

- self / device 必须带 subject。
- tenant / all 不带 subject。
- `sql_predicate` / `allows` 是纯翻译器，不决定 all 是否可用。

`tenant::RowVisibility::new` 拒绝 `RowScope::All`。跨租户可见性只能由
`tenant::RowVisibility::new_cross_tenant()` 生产；跨租户读取 API 必须接收 sealed
`tenant::CrossTenantVisibility` 位置参，不能接收普通 `RowVisibility` 或裸 scope。
`RowScope::All` 只能从 `authn` 的 super-admin 派生路径进入业务；派生必须与强制审计同址：跨租户 super-admin 访问**必须写持久 audit ledger**（字段至少含 tenant / principal / resource / action / request / correlation），tracing span 仅作关联信号、不替代持久审计。「同址」由 `authn` audited 派生 funnel 类型层强制——先写审计成功才签发 All-scope，audit 写失败 fail-closed（INVARIANT: TENANCY-CROSSTENANT-AUDIT-01，封闭符号见 `crates/authn/src/lib.rs`）；裸同步 `Principal::row_visibility` 的 super-admin 分支不再签发 All-scope（无 `AuditSink` 无法同址，返回 deny）。runtime JWT verify bridge 在认证成功后把具体 `Arc<authn::Principal>` 写入 request extension；跨租户 audit read handler 使用该 principal 做 SuperAdmin 判定和 durable audit。

audit read 不传 `tenantId` 时只读 ambient `runctx` 租户。传 `tenantId` 时是**指定租户**读取：只允许已验证 SuperAdmin，普通 admin/user/device/service 即使目标是同租户也拒绝；不提供全租户全局列表。读取前必须先 durable append `action="audit:list-cross-tenant"`、`resource_kind="audit_entries"`、`resource_id=<targetTenant>`，append 失败不读取。cross-tenant cursor 必须绑定 target tenant，cursor 与请求 `tenantId` 不一致返回 400。行/租户可见性通过后仍必须应用 `ResourceProjection`：SuperAdmin 只扩大 row scope，不自动获得字段明文。

audit read 的 serving 池对 `RowScope::All` 始终 fail-closed。指定租户的 super-admin audit read 只能走专用
`rss_audit_admin` admin 读取池；该池直连固定 LOGIN 角色 `rss_audit_admin`，角色必须非 superuser、
`NOBYPASSRLS`，并且只拥有 `audit_entries` SELECT。该池不授写权限、不授其它 public relation 权限、不增加
allow-all RLS policy，而是在只读事务内 `SET LOCAL rss.tenant_id = targetTenant` 复用现有 tenant-isolation RLS。
admin 池未配置时返回 501 `ERR_CORE_NOT_IMPLEMENTED`；配置不完整或权限不安全则启动 fail-fast。

## Tenant source（认证通道，非 request body）

tenant scope 只能来自**声明过的入口**：JWT tenant claim（→ ctx）或 `X-Tenant-ID` header。
`X-Tenant-ID = "populate-only"` 仅用于 public / pre-auth 填充路径（如 login），由
contract/codegen/header-shape + handler fail-closed 解析保证形态，**不是** cryptographic header
authenticity；service-token 路径必须使用 `service-token-tenant-bound`，runtime bridge 将 canonical
`X-Tenant-ID` 纳入 HS256 MAC 输入（缺 header / 错 header / 旧 unsigned token 均 401），防跨 tenant replay。
**HTTP request body 不得携带 `tenantId`**——body 不在 service-token tenant header MAC 绑定入口内，body tenant
是未认证维度。契约 schema/codegen/validate 在不可绕的 request 路径拒绝 ambient `tenantId` 来源：
upstream schema→DTO 拒绝是 **Hard**（codegen funnel + golden drift），downstream 单一 sanctioned
call-site 是 **behavior-locked Medium**（reject 用例驱动真实入口，删调用即测试失败；单 site 无需独立
call-site 强制）。唯一例外是 `audit.list-entries` GET 顶层 query `tenantId`，它表示 target tenant for
audited SuperAdmin read，不是 ambient tenant source；例外由 contract validate 和 codegen 共用窄 helper 锁定
到 contract id / method / path。符号 / 评级 / 盲区见契约 codegen 的 tenant-in-body guard 模块 rustdoc。

## Broker tenant authority

broker delivery metadata 中的 `tenantId` 只是传输属性，不具备认证强度。durable event transport 的可信
tenant 绑定来自 relay 写入的 reserved `tenantAuthority` token：HMAC payload 固定绑定
`iss/aud/tenantId/domain/contractId/topic/messageId/iat/exp`。consumer 写 app DLX 前必须验签并同时校验
issuer/audience、TTL、topic、contract、message id 与 tenant；失败时不信任 metadata tenant、不写 app DLX，
释放 claim 后 broker `Reject`。这条规则只覆盖 broker→consumer→DLX 信任边界；HTTP `X-Tenant-ID` /
service-token tenant MAC 仍按上一节治理。

## Principal claim source

JWT tenant claim 在 auth 边界解析并写入 context。service principal 无 tenant。
`Principal::row_visibility(ctx)` 是身份到 row-scope 的框架级派生入口：

- normal user -> self
- device -> device
- admin -> tenant
- super-admin -> fail-closed（裸同步 `row_visibility` 不签发 All-scope；跨租户 All 仅经 `Principal::audited_cross_tenant_visibility(...)` 同址审计派生，见上文 §RowScope）
- service / anonymous / unknown -> fail-closed

## RLS 与 PG scope

PG tenant scope 使用 `SET LOCAL` 注入当前事务。tenant-scoped repository 不持有 raw
`sqlx::PgPool`，只持有 opaque `PgTenantPool`；读写入口只能是
`PgTenantPool::{read, write, co_tx_with_outbox}`。`PgTenantPool` 不暴露 `begin`、`acquire`、
raw `PgPool` 或 `Executor`，因此 tenant 表路径在类型层先被收口到 scoped transaction funnel。
绕过该类型入口直接借连接或走 global transaction 必须 fail-fast。

`cargo xtask schema-rls`（INVARIANT `TENANCY-RLS-FORCE-01`，接入 `cargo xtask verify` / `ci`，
Medium）机器强制：含 `tenant_id` 列的表必须有 `ENABLE ROW LEVEL SECURITY` +
`FORCE ROW LEVEL SECURITY` + tenant-isolation policy（目标态 `USING/WITH CHECK (tenant_id =
NULLIF(current_setting('rss.tenant_id', true), '')::uuid)`，旧迁移可经前向迁移升级）；缺失即门红。

app-serving role `rss_app` 已 provision 为非 owner、NOBYPASSRLS，并按各 tenant 表最小授权 DML
（sessions / config_entries / roles / secret_refs / credentials / refresh_tokens / abac_policies；audit_entries 仅
SELECT+INSERT；dead_letter 仅 SELECT+INSERT；outbox 仅 SELECT+INSERT，relay settlement/retention
不得直接授 UPDATE/DELETE）；`FORCE ROW LEVEL SECURITY` 使 owner 连接亦受 policy 约束。durable
bootstrap 使用 dual-pool：migrator pool 只用于迁移与启动前检查，长期 serving pool 必须以 `rss_app`
连接；启动期 RLS 能力门会拒绝 owner/superuser、BYPASSRLS 角色以及任何非 `rss_app` serving role。
注：superuser 连接永远绕过 RLS（含 FORCE）；serving role rss_app 为非 superuser 故受 policy 约束；
生产 owner 须为非 superuser。

outbox 是 tenant-scoped 表：`tenant_id uuid NOT NULL` 与 metadata `tenantId` 同源落库，并受
`ENABLE/FORCE ROW LEVEL SECURITY` + `tenant_isolation` policy 约束。emit-only 路径和 co-tx 路径必须
先在事务内 `SET LOCAL rss.tenant_id`，且 co-tx 会拒绝 envelope tenant 与事务 tenant 不一致。ordered delivery
的 head-of-partition gating 按 `(tenant_id, domain, partition_key)` 判队头；同一 business key 下，tenant A
进入 dlx 的队头不得阻塞 tenant B 的同 key 投递。跨租 relay / retention / backlog 维护不得给 `rss_app`
开放 outbox 全表 UPDATE/DELETE，只能调用迁移安装的固定 `SECURITY DEFINER` 函数；函数 owner 为 NOLOGIN
BYPASSRLS 维护角色，函数签名是运行期唯一全域 outbox DML 通道。

saga_journal / projection_events 仍是无 `tenant_id` 列的全局表，不在 `schema-rls` 检查范围；它们依赖
seq 全局顺序、owner checkpoint / consumer group 隔离与上层 envelope tenant authority，不承载 outbox
partition liveness 语义。

> partition key（如 sessionId）可能含**凭据级** bearer 标识，故 `PartitionKey` 的 `Debug`
> 脱敏（`<redacted>`），不以明文进日志（F3，#1211 review；同 `SessionId`）——见 `observability.md` §Outbox Envelope。

## 持久化模式 tenant 作用域合约（PERSIST-016 / #1437 RLS 解锁器）

**作用域来源**：`TenantId`（`vocab`，fail-closed 解析，空值 / nil / 非 canonical UUID 非法）
从声明过的认证/预认证通道（JWT tenant claim 或 `X-Tenant-ID` populate-only header，见 §Tenant source）
流入，经 `adapters/postgres/src/cotx.rs` 的类型化 funnel
（`set_local_tenant` / `tenant_scoped_read` / `co_tx_with_outbox`）注入当前 PG 事务；
永不从 HTTP request body 读取。

**缺失 SET LOCAL 的行为（预期 default-deny）**：若 `SET LOCAL rss.tenant_id` 未注入，
`current_setting('rss.tenant_id', true)` 返回 NULL，`tenant_id = NULL` 永不匹配任何行——
所有 tenant 表**行不可见、写操作被拒**。这是设计预期的 fail-closed 默认拒绝，不是故障；
无隐式 fallback 或 anonymous 租户。

**单 funnel 强制**：postgres 生产路径所有 `SET LOCAL rss.tenant_id` 注入只经 `cotx.rs`
helper 进行；`INVARIANT TENANCY-SETLOCAL-FUNNEL-01`（`cargo xtask setlocal-funnel`，Medium
内容扫描）机器强制：字面量 `set_config('rss.tenant_id'` 仅允许出现在
`adapters/postgres/src/cotx.rs`（测试代码豁免）。tenant repository 的 Hard 载体是
`PgTenantPool` + `tenant: TenantId`：非 `TenantId` 类型无法通过编译进入 funnel，tenant repo
也无法直接调用 raw pool transaction / connection API。

**raw-pool / TxManager bypass 守卫**：`INVARIANT TENANCY-PG-TX-FUNNEL-01` 由两层承载。
Hard 层是 `PgTenantPool`，tenant 表 adapter（sessions / config / roles / secret_refs /
credentials / refresh_tokens / audit_entries / tenant dead_letter/DLQ 路径）只存该 wrapper。
Medium backstop 是 `cargo xtask pg-tenant-tx-guard`（接入 `verify` / `ci`）：从迁移派生
tenant 表集合，扫描生产 Rust SQL site，禁止 tenant 表 SQL 通过 raw `pool.begin` /
`pool.acquire` / `&self.pool` executor / `run_global_transaction` 访问，并带 anti-vacuity 与 stale
allowlist 测试。raw `PgPool` 只允许在 `PgStore` setup、migration、readiness/RLS capability probe、
global infra adapter 和命名维护例外中出现。

**命名维护例外**：tenant 表 raw-pool 维护例外只允许在 `pg-tenant-tx-guard` 中按窄形状显式登记，并带
stale-allowlist 测试。当前 Rust raw-pool 例外只有两类：`config_entries` startup legacy plaintext probe
（serving pool 接受前由 migrator/owner 连接只统计 encryption migration debt），以及 `rss
settings-config-values maintenance` 的 `config_entries` backfill/rewrap。后者只能经
`PgRuntimeDeps::setup_maintenance` 的 migrator/owner 连接执行，SQL 形状限定为按
`(tenant_id, config_key, version)` 稳定扫描 `protection_scheme = 0|1`、原地 CAS `UPDATE` 同一版本行、统计
remaining plaintext；runtime 必须验签 operator service-token，用已验证 service principal subject 写入
`auth_audit_events` job start/finish durable audit。维护 AAD 只能经 `ConfigValueMaintenanceCapability` 派生，
普通 serving 读写路径不能读取
scheme=0 plaintext。`dead_letter` retention sweep 和 outbox relay/retention/backlog 不保留 owner/maintenance
长期连接，也不授 `rss_app` 直接 DELETE/UPDATE；
它们由迁移安装的窄 `SECURITY DEFINER` 函数承载，函数 owner 是 NOLOGIN BYPASSRLS 维护角色，只开放固定
参数的全域维护能力。runtime 仍经 `rss_app` 调用这些函数；outbox relay 将 publish 失败写入 `dead_letter`
前必须从 outbox metadata 取 tenant，并在同一事务内经 `set_local_tenant` 注入 tenant scope 后写入。

**启动期 RLS 能力门控**：`PgRuntimeDeps::setup` 在迁移完成后调用
`PgStore::verify_rls_capability()`，动态派生含 `tenant_id` 列的表集合，断言每张表满足
`relrowsecurity AND relforcerowsecurity`、至少一条 tenant isolation policy，且
`rss.tenant_id` GUC 可正确 round-trip；任一断言失败则 durable 模式**启动 fail-fast**（数据库
RLS 状态无法在编译期校验，载体为 Medium 运行期门）。`RlsReadyProbe` 是对应的 readyz
backstop probe：启动验证通过后标记 `Healthy`（→ 200）；未通过标记 `Unhealthy`（→ 503）。

**解锁器边界说明（#1437 是 PERSIST-016 解锁器）**：本 issue 落地统一的 typed cotx funnel
（Hard）与 xtask setlocal-funnel / pg-tenant-tx-guard 守卫（Medium）及启动能力门控（Medium），
为以下同批 issue 提供稳定底座：

- **#1581**：outbox tenant 注入已落地（`tenant_id` + RLS + 固定 SECURITY DEFINER 维护函数）；inbox tenant 维度仍单列跟踪。
- **#1582**：tenant repo conformance 已纳入真实 postgres repos（config seed + role / audit / dead_letter 等），完整 CAS / rollback / co-tx 扩展仍按后续 conformance 范围推进。
- **#1436 / #1580**：PG tx funnel / raw-pool guard（`TxManager` 旁路保护）。

dual-pool（`rss_app` serving 非 superuser 角色）接线见上文 §RLS 与 PG scope；`rss_app
NOBYPASSRLS` 已 provision，bootstrap serving pool 已由启动期 RLS 能力门强制。

## ABAC authz 接线（permission-based）

业务端点授权走 PDP 决策，不在 handler 硬编 role-name 字面量。

- HTTP 路由门禁用 generated `HttpSpec` 派生 `httpserve::RoutePermission`，经
  `httpserve::RouteAuthorizer` 单一入口授权；handler 只消费 route gate 插入的
  `httpserve::AuthorizedSubject`，不用 `authn::any_role` / `authn::self_or` /
  `authn::require_any_role` 做授权分支。Admin listener 的 audit read 因保持 Admin
  `Route` 类型语义，读取前用同一 `RouteAuthorizer` 做等价 `audit:read` read gate。
- `authz::Permission` 是 sealed 闭值集（枚举 / sealed 类型）；业务代码经 accessor 函数
  （如 `authz::perm_audit_read()`）取得 permission，不传 role 字符串。
- handler 不手写 `Principal::has_role` 或遍历 `Principal.roles` 做授权。
- `Effect::Allow` 规则必须声明至少一个 action；空 action 只允许用于
  `Effect::Deny` 的 deny-all。写侧和读侧都必须 fail-closed。
- 路由门禁只做 coarse allow/deny；recognized FieldMask obligation 经 sealed
  `ResourceProjection` 传给 read projection layer 消费。未知 obligation、RowScope obligation 或不能识别的
  field obligation 必须 fail-closed。

## ResourceProjection / FieldMask

字段级数据权限由 `httpserve::ResourceProjection` 承载，字段集合来自闭枚举
`vocab::ProjectionField`，不得用裸字符串、wildcard 或 handler-local bool 表达。粗粒度
`audit:read` 缺 Authorizer 或被 Authorizer deny 时必须拒绝读取；读取已 allow 后，缺 projection、
缺字段权限或未知未来字段时，敏感字段默认 mask。

audit read 当前默认 mask `actor` 与 `resourceId`，以 `"<redacted>"` 保持 required string schema；`entryHash`、
`seq`、`tenantId`、`actorKind`、`action`、`resourceKind`、`outcome`、`recordedAt`、`nextCursor`、`hasMore`
保持明文。显式 unmask 只能由 `RouteAuthorizationDecision` 携带的 projection 进入 handler；audit handler
只消费 projection，不读取角色、permission 字符串或 policy 细节。

## Resource ownership

path-param 标识的 resource ownership 是 PDP ABAC 决策，不是 handler 短路。owner-scoped /
self-scoped gate **contract-derived**：契约声明 `endpoints.http.resource:
<pathParam>`（owner-scoped）或 `endpoints.http.selfScoped: true`（self-scoped），生成
handler 经 `httpserve::PrimaryRoute::permission` + `RouteResourceScope` funnel 派生
path-param resource / self subject resource——业务 handler / 域 crate 不手写 gate。
`resource`/`selfScoped` 各 ⇒ permission、二者互斥（contract validate、codegen check
和 `cargo xtask` 治理校验）。owner-scoped gate 把 canonical resource id（self-scoped 把
调用者自身 subject）转发给 PDP。

当前 HTTP `RouteResource` canonical parser 只接受 lowercase-hyphenated、非 nil UUID 字符串；空值、
非 UUID、非 canonical UUID 在 route gate 内 fail-closed，且不调用 PDP。按 contract 声明不同
resource type 的 typed parser/codegen 是后续架构项。

- baseline ownership 用 `subject.sub == resource.id` 判定。
- **owner vs admin 同 permission**：同一 owner-scoped action（如 `user:write`）既用于带
  resource 的 owner 路由（改自己），也用于不带 resource 的 admin 路由（coarse，改任意）。
  故 HTTP **不照搬** gRPC 侧「owner-scoped permission ⇒ resource 必填」规则（会误拒 admin
  路由）；`resource` 是 per-route 授权选择，不从 permission 派生。
- 空或非 canonical path-param 不等于 self；resource 不可解析时规则不命中并
  fail-closed。
- delegated ownership 用 `subject.sub == resource.owner`，owner 由 PIP lookup 供给。
- device 读自身状态必须 kind-gated：`subject.kind == device AND subject.sub == resource.id`。
- owner-scoped route gate 的 baseline allow surface 是 `{owner, admin}`；owner/self
  不扩大数据访问，数据可见性仍由 principal 派生的 `RowScope` 独立治理。

query-param self scoping 仍留在 handler / service：例如 audit 的空 `actorId` 对 admin
表示全 actor permissioned 读，不是隐式 self；只有显式 `param == subject` 才走 PDP
ownership 规则。

## Authorizer 与 PDP

Authorizer 经组合根注入 request context：runtime assembly 从 identity domain 取得
`Arc<dyn httpserve::RouteAuthorizer>`，Primary listener 用
`httpserve::finalize_primary_auth_with_audit` 装配；Admin listener 也注入同一 Authorizer，供 audit read
请求 sealed field projection。域 crate 不依赖兄弟域 crate 的 Authorizer。

强依赖缺失必须 fail-fast；可解析的 Authorizer 在 runtime router build（Init 后、
serve 前）预解析。生产 Primary active route 通过必填 authorizer finalizer 装配；缺失 provider
在启动期 fail-fast（构造器必填参数缺失即编译期 / 启动期报错），而不是首请求暴露。

PDP 默认 fail-closed：缺 Authorizer、缺租户或 store 不可用都 deny；无适用 durable permit
只表示 durable source 不授予权限，若没有独立 baseline allow 则 deny。
baseline authorization source 是既有 self/RBAC/builtin 路由授权；其中 RBAC baseline 是
action-scoped + role-conditioned 的 allow 规则，不是 allow-all。租户 durable policy 是独立
route-scoped source，可以叠加 allow / deny；deny 与 durable store/load failure 优先于 baseline。

新装环境的 active settings publish API 在 role 管理面完整前有窄兜底：trusted `Admin` 主体对
generated settings `config-publish` / `secret-publish` 两条无 resource route 内置 Allow；其它权限仍必须经
role binding 命中，普通 user/device/service 不享有该兜底。

租户 allow 可以放宽路由门禁，但不能扩大数据访问。读端点的数据可见性由 principal
派生的 `RowScope` 决定；写端点没有 RowScope 维度，必须依赖 typed tenant 参数和 FORCE
RLS 维护 tenant 边界。

## Open-source AuthZ parity boundary

开源授权对标边界单源见
`docs/architecture/202607021958-014-authz-open-source-parity-boundary.md`。RSS 只承诺同一安全目标由
typed / in-process 机制承载，不承诺第三方产品、API 或策略语言兼容。

术语固定如下：

- `diport::Pdp` 是 credential verification / claims port，负责验签、校验 claims 并产出已验证身份材料。
- `httpserve::RouteAuthorizer` 是 route authorization 决策入口，负责 contract-derived permission / resource /
  self-scoped gate。
- tenant isolation 是 typed `TenantId` + service-token tenant binding + `SET LOCAL rss.tenant_id` funnel +
  FORCE RLS + non-bypass serving role 的组合边界。
- `RowVisibility` / `ResourceProjection` 是 RSS sealed obligation；OPA、Cedar、Casbin、SpiceDB、OpenFGA 或
  PostgreSQL RLS 的对标能力不得被描述成这些类型的运行时兼容层。

边界不变：RLS does not replace RouteAuthorizer；ABAC is not the tenant boundary。租户 durable policy 可影响
coarse route allow / deny，但不能扩大 tenant rows、跨租户可见性或字段明文投影。

## Durable ABAC policy store

ABAC policy store 是 tenant-scoped durable PG store：每条 policy 必须带 `tenant_id`，
并受 `ENABLE/FORCE ROW LEVEL SECURITY` + tenant-isolation policy 约束。生产读写入口必须经
typed tenant 参数和 PG tenant scope funnel 注入当前租户；不得提供全局 current policy 读取路径。

policy 以 version + effective window 表达生效集。查询 active policy 时只加载当前租户中
`effective_from <= now < effective_until`（无上界按 open-ended 处理）的版本；未生效、已过期或已删除
版本不参与 PDP current active set。delete 必须保留 tombstone 并推进 version；普通 create 不复活同 id
tombstone，也不得把 version 水位重置回 1。版本推进必须单调；同一租户内的更新不得影响其它租户同 key policy。

policy load 必须 fail-closed：缺租户、store 不可用、反序列化失败、malformed JSON、未知字段、
版本窗口非法或 storage error 都视为不可用 / 无有效 permit，PDP 和 route gate 返回 deny，不回退到
内置 allow-all、旧缓存 allow 或跨租户默认值。malformed / unknown-field 输入必须在写侧拒绝落库；
读侧遇到既有坏数据也必须拒绝授权。

baseline semantics 保持最小允许面：durable active set 为空或没有命中时不授予权限，只允许既有
self/RBAC/builtin baseline 独立判定；RBAC baseline 仍是 action-scoped + role-conditioned allow。
tenant policy 可以叠加路由 coarse allow / deny，`Deny` 和 durable load/decode failure 覆盖 baseline，
但不能扩大数据行可见性；数据可见性仍由 `RowScope` / FORCE RLS 独立治理。

obligation 必须 round-trip 持久化，不得在 store 层静默丢弃或默认化。HTTP route gate 的默认语义仍是
coarse allow/deny；唯一例外是 recognized FieldMask obligation 可转成 sealed `ResourceProjection`
交给读模型渲染层。RowScope、未知 field obligation、或非 projection 路由上的 FieldMask obligation
都必须 fail-closed deny。

## gRPC 授权

非 public gRPC RPC 进入 runtime 后由 auth 拦截器（tower layer）调同一 `authn::Authorizer`
做 PDP gate，不在 handler 手写谓词。

- method -> permission 由契约 `endpoints.grpc.methods[].permission` overlay 派生。
- 非 public 方法缺 permission overlay 必须 fail-closed，并在生成或注册期拒绝上线。
- 未知 permission 必须启动 fail-fast。
- owner-scoped permission 必须声明 `endpoints.grpc.methods[].resource`，拦截器
  从请求消息字段提取 resource 并 canonicalize 后转发给 PDP。
- unary RPC 在入口取 resource；server-streaming owner-scoped RPC 将 permission gate
  延后到首个 `recv_msg`。
- resource 提取失败（非 proto message、字段不存在、非 string）必须 deny，不回退到
  full method；空或非 UUID 值转发给 PDP。提取值不得写入 ErrorInfo metadata。
- `passwordResetExempt: true` 只允许用于非 public 且声明 permission 的方法。
- 每个 deny 必须携带 sealed `google.rpc.ErrorInfo`，metadata 不含 subject / token /
  resource value 等 PII。
- gRPC 与 HTTP 使用同一 PDP 决策指标 family，不新增 transport 分叉。

## HTTP 授权

HTTP route gate 与 gRPC 同源。HTTP route -> permission 由契约
`endpoints.http.auth.permission` overlay 派生。codegen 将契约渲染为 `generated::http::HttpSpec`
的 `auth.permission` / `resource` / `self_scoped`，域 route 装配只能经
`PrimaryRoute::permission(RoutePermission { permission, scope })` 声明进入 primary route gate。
`httpserve::RouteAuthorizer` 在 handler 前做统一判定，允许后插入 `AuthorizedSubject`；handler 只消费
该授权主体上下文，不回读 `Authenticated`。owner-scoped（`endpoints.http.resource`）/ self-scoped
（`endpoints.http.selfScoped`）由 `RouteResourceScope::{PathParam,SelfSubject}` 三分支派生，见
§Resource ownership。

每个 `lifecycle: active` 且 `codegen` 的 HTTP 契约必须声明恰好一个 AuthZ mode：

- ABAC 默认：`endpoints.http.auth.permission`
- 显式 opt-out：`public` / `bootstrap` / `clientsOnly` / `serviceOwned`

opt-out 必须带非空 `endpoints.http.auth.reason`。ABAC mode 不带 reason；
reason-without-opt-out 必须拒绝。permission 与 opt-out mode 互斥。
HTTP `passwordResetExempt` 不是 AuthZ mode；单独声明仍是 modeless，必须拒绝。

契约 codegen 的 `build_http_spec` 是 codegen 完整性门：modeless route 不得被渲染上线。
`cargo xtask` / governance 规则只做纵深检查，不能替代 codegen 强制门。

## Governance reverse self-check

`cargo xtask tenancy-closeout` 是本规则的最终 no-compile 反向自检，并接入
`cargo xtask verify` / `cargo xtask ci`。它不重做业务测试，而是锁以下 governance 锚点：

- verify/ci plan 必须包含 tenant/RLS/AuthZ 相关门：`contract-validate`、`codegen-check`、
  `schema-rls`、`setlocal-funnel`、`pg-tenant-tx-guard`、`pdp-allow-guard`、
  `tenancy-closeout`，以及实际可用时的 `dylint`。
- RLS 静态与运行期纵深必须同时可见：迁移 DDL 由 `schema-rls` 守，SET LOCAL 注入由
  `setlocal-funnel` 守，tenant 表 raw-pool / `TxManager` bypass 由 `pg-tenant-tx-guard` 守，
  durable startup 由 `verify_rls_capability()` 守。
- AuthZ 路由 gate 必须经 `RouteAuthorizer`，handler 只消费 `AuthorizedSubject`，不回退到
  handler-local role/self 分支。
- 字段级数据权限必须从 contract projection fields 派生到 generated spec，经
  `RouteAuthorizationDecision::AllowWithProjection` 传入 `ResourceProjection`，并由 audit read
  response rendering 消费；缺 projection 时敏感字段默认 mask。
- open-source AuthZ parity boundary 必须在
  `docs/architecture/202607021958-014-authz-open-source-parity-boundary.md` 记录，且本规则文件与
  ADR-006 必须引用该 ADR。
- tenant/AuthZ/projection dylint 注册清单必须在根 `Cargo.toml`、`lints/Cargo.toml`、
  `docs/rules/architecture.md` 和 `lints/README.md` 中一致。
- governed closeout docs 不得把 #1577-#1585 已完成的 tenant/RLS/AuthZ/projection 项继续描述成
  future work。
