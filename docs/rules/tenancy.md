# 多租户 / ABAC / 行列级数据权限规则

本文件只写当前行为约束。设计历史、分阶段计划与未来工作归 ADR、spec 或 GitHub Issues；
角色 provision、连接参数与 CLI flag 的完整清单归 adapter rustdoc 与运维文档。

## TenantID

- `tenant::TenantId` 是隔离域边界类型。空值与 nil UUID 非法，非空必须是 canonical UUID。
- service / auth 边界使用 typed tenant 参数，不传裸 `String`。
- tenant-scoped repo API 使用各域本地 opaque `TenantRepoScope`，不接收裸 `TenantId`。

## RowScope / RowVisibility

- `tenant::RowScope` 取值为 self / device / tenant / all，无默认（构造即定）。
- `tenant::RowVisibility` 是 sealed obligation：self / device 必须带 subject，tenant / all 不带；
  `sql_predicate` / `allows` 是纯翻译器，不决定 all 是否可用。
- 常规构造入口在类型层排除 `RowScope::All`。跨租户可见性只能由专用 cross-tenant 构造器生产，
  跨租户读取 API 必须接收 sealed `CrossTenantVisibility` 位置参，不接受普通 `RowVisibility` 或裸 scope。
- `RowScope::All` 只能从 audit 域的 durable-receipt scope mint 进入业务：先签发不含 visibility 的
  target-bound grant，audit 应用层经 route-specific typed appender 成功后铸造模块私有 receipt，
  cross-tenant read scope 只接受该 receipt。
- 跨租户访问必须写持久 audit ledger（tenant / principal / resource / action / request / correlation），
  tracing 不替代 ledger；append 失败 fail-closed。裸同步 `Principal::row_visibility` 永不签发 All-scope。
- 载体：`rss_crosstenant_callsite` dylint 守 All-scope mint callsite。

### Audit read 边界

- 常规 audit 列表只读 ambient `runctx` 租户，query 仅允许分页参数；request 携带 tenant 输入返回 400。
- 指定租户读取只走独立 path-param 路由，仅 verified SuperAdmin 可用；普通 admin / user / device / service
  即使目标是同租户也拒绝，不提供全租户列表。
- 读取前必须先 durable append 跨租户读审计，append 失败不读取。cross-tenant cursor 必须绑定 path tenant。
- 通过行可见性后仍应用 `ResourceProjection`，SuperAdmin 不自动获得字段明文。
- serving 池对 `RowScope::All` 始终 fail-closed；指定租户读只能走专用只读 admin 池。
  该池必须非 superuser、`NOBYPASSRLS`、只持 audit 表 SELECT，且在只读事务内 `SET LOCAL rss.tenant_id`
  复用现有 tenant-isolation RLS，不新增 allow-all policy。未配置返回 501，配置不完整或权限不安全启动 fail-fast。
- operator full-chain verify 复用同一只读 capability，只接受单租户目标，operator 身份来自 tenant-bound
  service-token 且必须是 closed maintenance caller；grant 只精确匹配目标 tenant，不接受 caller/subject 字符串。
  不接受全租户或 namespace flag——schema 无 namespace 列，接受会让调用方误以为存在该隔离维度。
  start / finish 必须写审计事件。

| owner | ledger / outcome |
|-------|------------------|
| authn `cross_tenant_audit_grant` | grant / Success only；`NotSuperAdmin` → `Err`，不写 ledger |
| audit domain handler | **authenticated** final cross-tenant deny → target-bound durable `Failure`（deny-before-grant）；identity-less early 403 不入该 ledger |
| httpserve authz | coarse route Deny → `http_route` Failure |

> 上表仅为所有权索引；闭包证据是 audit crate 的 Medium tripwire 测试（`AUDIT-CROSS-TENANT-DENY-BEFORE-GRANT-01` 认证后 deny-before-grant；`target_tenant_identity_less_403_has_empty_deny_ledger` 锁 identity-less early 403 空 deny ledger），文档不是唯一载体。

## Tenant source（认证通道，非 request body）

tenant scope 只能来自声明过且已认证的入口：listener-fixed verified tenant claim，或 service-token
MAC-bound canonical `X-Tenant-ID`。

`INVARIANT: TENANCY-SERVICE-IDENTITY-SCOPE-01`：service-token MAC-bound tenant scope is the only service
identity tenant assertion。mTLS/SPIFFE service identity is not a tenant source——`VerifiedMtlsPeer` /
SPIFFE-ID 只证明 workload service principal，经 exact allow-set 与 `RouteAuthorizer` 做 route allow/deny，
不隐式建立 ambient tenant scope。

- `X-Tenant-ID = "populate-only"` 仅用于 public / pre-auth 填充路径，由 contract/codegen/header-shape +
  handler fail-closed 解析保证形态，**不是** cryptographic header authenticity。
- service-token 路径必须使用 `service-token-tenant-bound`：runtime bridge 将 canonical `X-Tenant-ID`
  纳入 MAC 输入，缺 header、错 header 或旧 unsigned token 均 401，防跨 tenant replay。
- **HTTP request body 不得携带 `tenantId`**：body 不在 MAC 绑定入口内，是未认证维度。
  所有 HTTP request schema 一律禁止，指定租户只通过已声明的 path 参数进入专用路由。
- 载体：upstream schema→DTO 拒绝是 Hard（codegen funnel + golden drift）；downstream 单一 sanctioned
  call-site 是 behavior-locked Medium（reject 用例驱动真实入口，删调用即测试失败）。

## Broker tenant authority

- broker delivery metadata 中的 `tenantId` 只是传输属性，不具备认证强度。
- durable event transport 的可信 tenant 绑定来自 relay 写入的 reserved `tenantAuthority` token。
- consumer 写 app DLX 前必须验签并同时校验 issuer/audience、TTL、topic、contract、message id 与 tenant；
  失败时不信任 metadata tenant、不写 app DLX，释放 claim 后 broker `Reject`。
- 本节只覆盖 broker→consumer→DLX 信任边界；HTTP 侧按上一节治理。

## Principal claim source

- 生产 access token 只能经 typed issuer 签发且只接受 User，必须携带 `TenantId` 与完整 grant quartet。
- 联邦 access 只有 typed verifier、没有 issuer。User / Device / Admin variant 必须携带 `TenantId`；
  SuperAdmin variant 不暴露 tenant 字段，也不会直接产生 `RowScope::All`。缺失或多余 tenant claim 均拒绝。
- service-token 不进入 access issuer，单独走 tenant-bound profile 并把 canonical `X-Tenant-ID` 纳入 MAC 输入。
- listener profile、issuer、audience 与 key source 共同决定 trust domain。
- JWT tenant claim 在 auth 边界解析并写入 context。service principal 与 service-token principal 自身无 tenant；
  mTLS/SPIFFE service principal 不携带 tenant assertion。

`Principal::row_visibility(ctx)` 是身份到 row-scope 的框架级派生入口：

| principal | row scope |
|---|---|
| normal user | self |
| device | device |
| admin | tenant |
| super-admin | fail-closed（跨租户读仅经 grant → typed append → durable receipt → scope） |
| service / anonymous / unknown | fail-closed |

## RLS 与 PG scope

- PG tenant scope 使用 `SET LOCAL` 注入当前事务。
- tenant-scoped repository 不持有 raw `sqlx::PgPool` / `PgStore`，只持有所需的 exact sealed lane：
  `TenantDb<ServingReadLane>`、`TenantDb<ServingWriteLane>` 或命名的 admin / maintenance lane；普通 repo
  入口只能接收本地 `TenantRepoScope` / `RowRepoScope`，
  不能接收裸 `TenantId`、`RowVisibility`、`RowScope` 或 `ScopedTenant`。
- 独立查询只经 read pool；mutation、deadline、retry 与 co-tx 只经 write pool。
  reader 必须原子发送 `BEGIN READ ONLY` 后再 `SET LOCAL`；写事务内部为 CAS/锁定所需的 SELECT 仍属同一 writer transaction。
- `TenantDb` 不暴露 `begin`、`acquire`、raw pool/store 或通用 executor。完成 `SET LOCAL` 后才由 funnel
  私有铸造 `TenantTx<ServingReadLane>`、`TenantTx<ServingWriteLane>` 或对应的 admin / maintenance lane；
  通用事务只在 `cotx` 内核可见，repository closure 仅收到 lane + concern 双重封闭的 capability，
  不能恢复 `PgConnection`、提交任意 SQL、开启嵌套事务或调用 commit/rollback。exact lane 与 DB
  read-only/ACL/RLS 共同约束可执行操作；绕过类型入口直接借连接或走 global transaction 必须 fail-fast。
- 含 `tenant_id` 列的表必须有 `ENABLE ROW LEVEL SECURITY` + `FORCE ROW LEVEL SECURITY` + tenant-isolation
  policy；缺失即门红。新增 tenant relation 必须在同一 migration 显式授予 reader SELECT，
  reader DML 与 `ALTER DEFAULT PRIVILEGES` 一律门红。
- 载体：`INVARIANT: TENANCY-RLS-FORCE-01` / `TENANCY-PG-READER-ACL-01`（`cargo xtask schema-rls`）。

### 连接面与角色

- durable bootstrap 使用三个独立连接面：migrator pool 只用于迁移与启动前检查，writer serving pool 与
  reader serving pool 分别以专用 LOGIN 角色直连。
- reader 不从 writer 凭据 fallback，也不通过 `SET ROLE` 复用连接。
- 两个 serving role 必须非 owner、非 superuser、`NOBYPASSRLS`，并按表最小授权；
  append-only 表只授 `SELECT, INSERT`，relay settlement 与 retention 不得直接授 UPDATE/DELETE。
- reader 只具 CONNECT、schema USAGE 与 tenant relations SELECT，且默认事务只读。
- 部署连接预算必须按 `migrator + writer + reader + 命名 maintenance pools` 求和，不能沿用单 serving pool 预算。
- readiness 同时采样 writer/reader 并取最差状态；任一未验证或不可用返回 503。
- 注：superuser 连接永远绕过 RLS（含 FORCE），故生产 owner 与 serving role 均须为非 superuser。

### 各 durable 表的 tenant 约束

- **append-only 版本表**（如 `secret_refs`）：`rss_app` 仅 `SELECT, INSERT`，DB CHECK 拒绝直接
  `UPDATE/DELETE`，删除只允许追加 tombstone。Hard 载体是 `SecretTx<ServingWriteLane>` 上封闭的
  `SecretWrite::lock_key` façade；它按 canonical 坐标取得 advisory lock 并返回私有 `LockedSecretKey`，
  CAS 与 tombstone 只能消费该 capability 内的坐标。
  载体：`TENANCY-SECRET-KEY-MUTATION-01`（`cargo xtask pg-tenant-tx-guard`）。
- **outbox**：`tenant_id` 与 metadata `tenantId` 同源落库并受 RLS 约束。emit-only 与 co-tx 路径都必须先
  `SET LOCAL`，co-tx 拒绝 envelope tenant 与事务 tenant 不一致。head-of-partition gating 按
  `(tenant_id, domain, partition_key)` 判队头，tenant A 的 DLX 队头不得阻塞 tenant B 的同 key 投递。
  跨租 relay / retention / backlog 维护不得开放全表 UPDATE/DELETE，只能调用迁移安装的固定
  `SECURITY DEFINER` 函数；函数 owner 为 NOLOGIN BYPASSRLS 维护角色。
- **inbox_receipts**：tenant-scoped mutable receipt 表，主键含 tenant，受 RLS 约束，不保留 dual write 或回填路径。
- **saga 表**：instance 表持 lease token/epoch，journal 主键含 tenant 且 append-only（仅 `SELECT, INSERT`）。
  所有状态变更必须经 write pool 注入 tenant scope，并由 DB 侧 `tenant_id + saga_id + lease_token + epoch +
  expires_at` CAS fence，不能依赖调用方约定。
- **projection_events**：无 `tenant_id` 列的全局表，不在 `schema-rls` 范围。`rss_app` 无任何表级 DML，
  只能执行固定 `SECURITY DEFINER` 函数；append 函数校验 metadata tenant 为 canonical non-nil UUID、
  参数匹配同事务可见 outbox row，且该 row 命中部署期由唯一 migration Job 写入的 DB binding registry；
  serving 仅校验编译进 binary 的 generation，不能取得 registry 注册能力。
  它依赖全局 LSN 顺序与上层 envelope tenant authority，不承载 outbox partition liveness 语义。

> partition key 可能含凭据级 bearer 标识，故 `PartitionKey` 的 `Debug` 脱敏，不以明文进日志。
> 见 `observability.md` §Outbox Envelope。

## 持久化模式 tenant 作用域合约

**作用域来源**：`TenantId` 从声明过的认证 / 预认证通道流入；域内从已认证授权证据派生本地
`TenantRepoScope`，repo 与 tenant read/write capability 只接收该 sealed handle。
adapter 内有唯一 lower 点从 scope handle 取 `TenantId` 并注入当前 PG 事务；永不从 HTTP request body 读取。

**缺失 SET LOCAL 的行为（预期 default-deny）**：未注入时 `current_setting` 返回 NULL，
`tenant_id = NULL` 永不匹配任何行——所有 tenant 表行不可见、写操作被拒。
这是设计预期的 fail-closed 默认拒绝，不是故障；无隐式 fallback 或 anonymous 租户。

**单 funnel 强制**：生产路径所有 tenant GUC 注入只经唯一 helper 模块进行。
Hard 载体是各域 scope 类型加 typed pool：外部代码不能从裸 `TenantId` 构造 scope，
tenant repo 也无法直接调用 raw pool 的 transaction / connection API。
载体：`INVARIANT: TENANCY-SETLOCAL-FUNNEL-01`（`cargo xtask setlocal-funnel`）。

**raw-pool / TxManager bypass 守卫**：`INVARIANT: TENANCY-PG-TX-FUNNEL-01` 由两层承载。
Hard 层是 sealed `TenantDb<ServingReadLane>` / `TenantDb<ServingWriteLane>` 及对应的 admin / maintenance lane，
与其 private-mint `TenantTx<Lane>`——tenant 表 adapter 按行为只存
所需 exact lane，closure 只能取得一个不可互换的 concern capability；混合 repo 显式存多个精确 lane，
不保留已删除 pool alias、access brand、通用 executor 或兼容构造器。Medium backstop 从迁移派生 tenant 表集合并扫描生产 SQL site，
禁止 tenant 表 SQL 经 raw `begin` / `acquire` / pool executor / 全局事务访问，并带 anti-vacuity 与 stale
allowlist 测试。写事务内 SELECT 由 writer capability 所有，不被误判为独立读。
载体：`TENANCY-PG-TX-FUNNEL-01`（`cargo xtask pg-tenant-tx-guard`）。

**repo scope 签名守卫**：禁止普通 tenant/row-scoped repo 方法重新引入裸 `TenantId`、`RowVisibility`、
`RowScope` 或 `ScopedTenant` 参数；admin / maintenance 专用 port 保持独立入口。
载体：`INVARIANT: TENANCY-REPO-SCOPE-SIGNATURE-01`（`cargo xtask repo-scope-guard`）。

**命名维护例外**：tenant 表 raw-pool 维护例外只允许在守卫中按窄形状显式登记，并带 stale-allowlist 测试。
每条例外必须限定连接面（migrator/owner）、限定 SQL 形状、验签 operator service-token，并写 durable
start/finish 审计。维护专用 AAD 只能经专用 capability 派生，普通 serving 路径不能读取历史明文。
DLX lifecycle 拆为三个独立长期登录角色（archive / verify / purge），三者都必须非 superuser、
`NOBYPASSRLS`、无任何表级 DML/DDL，且 serving role 对 lifecycle 函数全部无权；
runtime 用三组独立凭据建 pool，启动时精确验证 current role 与能力集合，repository 内部按方法路由且不暴露 raw pool。
raw 连接只允许在 setup、migration、readiness/capability probe、global infra adapter 与命名维护例外中出现。

**启动期 serving 能力门控**：迁移完成后分别验证 writer 与 reader 直连池。两者都动态派生含 `tenant_id`
列的表集合，断言每张表 `relrowsecurity AND relforcerowsecurity`、至少一条 tenant isolation policy，
且 GUC 可正确 round-trip。writer 另核验 current role 精确为 serving writer 角色且非 owner/superuser/BYPASSRLS；
reader 另核验角色、role flags、默认只读与有效 ACL 精确集合。
任一断言失败则 durable 模式启动 fail-fast——数据库状态无法在编译期校验，故载体是 Medium 运行期门。

## ABAC authz 接线（permission-based）

业务端点授权走 PDP 决策，不在 handler 硬编 role-name 字面量。

- HTTP 路由门直接消费 generated route evidence，由 generated endpoint 从 evidence 推导 route permission，
  经 `httpserve::RouteAuthorizer` 单一入口授权；handler 只消费 route gate 插入的 `AuthorizedSubject`。
- `vocab::RoutePermissionId` 是 active route permission 与 audit projection permission 的闭值集；
  `vocab::GrantPermission` 是 role 可持有授权项的闭值集。contract / storage 以字符串承载 wire 格式，
  但进入 route gate、contract authorizer 或 role hydrate 前必须解析成 typed permission；
  未知值视为损坏数据 fail-closed，不保留字符串授权 fallback。
- handler 不手写 role 判定、不遍历 roles、不比较 principal kind 或 role-name 字面量做授权。
- `Effect::Allow` 规则必须声明至少一个 action；空 action 只允许用于 `Effect::Deny` 的 deny-all。
- 路由门禁只做 coarse allow/deny；recognized FieldMask obligation 经 sealed `ResourceProjection`
  传给 read projection layer。未知 obligation、RowScope obligation 或不能识别的 field obligation 必须 fail-closed。

## ResourceProjection / FieldMask

- 字段级数据权限由 `httpserve::ResourceProjection` 承载，字段集合来自闭枚举 `vocab::ProjectionField`，
  不得用裸字符串、wildcard 或 handler-local bool 表达。
- active GET response 中声明 `x-pii` 或字段名为 `tenantId` 的 protected 字段必须在 contract projection
  enrollment 中声明 response path；由 contract validate R23 按 schema 精确覆盖校验，
  generated projection spec 是 handler 与 authorizer 的单源。
- 粗粒度 route permission 缺 Authorizer 或被 deny 时必须拒绝读取。
- 读取已 allow 后，缺 projection、缺字段权限或遇未知未来字段时，protected 字段默认 mask 为 `"<redacted>"`
  以保持 required string schema。
- 显式 unmask 只能由授权决策携带的 projection 进入 handler；handler 只消费 projection，
  不读取角色、permission 字符串或 policy 细节。

## Resource ownership

- path-param 标识的 resource ownership 是 PDP ABAC 决策，不是 handler 短路。
- owner-scoped / self-scoped gate 是 contract-derived：契约声明 resource path param 或 self-scoped 标志，
  generated endpoint 从同一 route evidence 派生 resource 或 self subject。业务 handler 与域 crate 不手写 gate。
- 两种声明各自蕴含 permission、彼此互斥，由 contract validate、codegen check 与治理校验共同强制。
- canonical resource parser 只接受 lowercase-hyphenated、非 nil UUID；空值、非 UUID、非 canonical
  在 route gate 内 fail-closed 且不调用 PDP。
- 动态 `resource.*` 属性来自 tenant-scoped durable attribute store，不是 handler 本地拼接。
  store key 空间固定，其中 permission 段读侧必须解析回 typed permission 后才参与授权。
  `resource.id` 是 route gate synthetic attribute，不能作为动态属性落库。
- resolver 只返回闭枚举 `Known` / `Missing` / `Stale`；缺失、过期、store 不可用、reserved key 冲突或
  非 canonical resource id 都在 baseline 前 deny，不用空集合表达失败，也不回退跨租户默认值。
- 契约可显式声明 shared/global resource opt-out，必须带非空 reason 且仍声明 canonical route resource。
  global route 不读全局属性表、不支持 tenant NULL fallback，也不允许租户 durable policy 使用动态
  `resource.*` 属性。默认模式是 tenant-scoped。

判定规则：

- baseline ownership 用 `subject.sub == resource.id`；delegated ownership 用 `subject.sub == resource.owner`，
  owner 由 PIP lookup 供给。
- device 读自身状态必须 kind-gated：subject kind 为 device 且 sub 等于 resource id。
- 空或非 canonical path-param 不等于 self；resource 不可解析时规则不命中并 fail-closed。
- **owner vs admin 同 permission**：同一 owner-scoped action 既用于带 resource 的 owner 路由，
  也用于不带 resource 的 admin 路由。故 HTTP 不照搬 gRPC 的「owner-scoped permission ⇒ resource 必填」
  规则（会误拒 admin 路由）；resource 是 per-route 授权选择，不从 permission 派生。
- owner-scoped route gate 的 baseline allow surface 是 `{owner, admin}`；owner/self 不扩大数据访问，
  数据可见性仍由 principal 派生的 `RowScope` 独立治理。
- query-param self scoping 仍留在 handler / service：空 actor 参数对 admin 表示全 actor permissioned 读，
  不是隐式 self；只有显式相等才走 PDP ownership 规则。

## Authorizer 与 PDP

- Authorizer 经组合根注入 request context，域 crate 不依赖兄弟域 crate 的 Authorizer。
- 强依赖缺失必须 fail-fast；可解析的 Authorizer 在 router build（Init 后、serve 前）预解析。
  生产 active route 通过必填 finalizer 装配，缺失 provider 在启动期报错，而不是首请求暴露。
- PDP 默认 fail-closed：缺 Authorizer、缺租户或 store 不可用都 deny。
  无适用 durable permit 只表示 durable source 不授权；若无独立 baseline allow 则 deny。
- baseline 是既有 self/RBAC/builtin 路由授权，其中 RBAC baseline 是 action-scoped + 命中 route grant 的
  allow 规则，不是 allow-all，也不读取 role name。
- 租户 durable policy 是独立 route-scoped source，可叠加 allow / deny；deny 与 durable load failure 优先于 baseline。
- 租户 allow 可以放宽路由门禁，但不能扩大数据访问。读端点可见性由 `RowScope` 决定；
  写端点没有 RowScope 维度，必须依赖 typed tenant 参数与 FORCE RLS 维护 tenant 边界。

## Open-source AuthZ parity boundary

开源授权对标边界单源见
`docs/architecture/202607021958-014-authz-open-source-parity-boundary.md`。
RSS 只承诺同一安全目标由 typed / in-process 机制承载，不承诺第三方产品、API 或策略语言兼容。

术语固定如下：

- `diport::Pdp` 是 credential verification / claims port，负责验签、校验 claims 并产出已验证身份材料。
- `httpserve::RouteAuthorizer` 是 route authorization 决策入口，负责 contract-derived permission /
  resource / self-scoped gate。
- tenant isolation 是 typed `TenantId` + service-token tenant binding + `SET LOCAL rss.tenant_id` funnel +
  FORCE RLS + non-bypass serving role 的组合边界。
- `RowVisibility` / `ResourceProjection` 是 RSS sealed obligation，对标产品的相近能力不得被描述成
  这些类型的运行时兼容层。

边界不变：RLS does not replace RouteAuthorizer；ABAC is not the tenant boundary。
租户 durable policy 可影响 coarse route allow / deny，但不能扩大 tenant rows、跨租户可见性或字段明文投影。

## Durable ABAC policy store

- policy store 是 tenant-scoped durable PG store：每条 policy 必须带 `tenant_id` 并受 RLS 约束。
  生产读写入口必须经 repo scope handle 与 tenant scope funnel 注入当前租户，不提供全局 current policy 读取路径。
- policy 以 version + effective window 表达生效集；只加载当前租户中处于有效窗口的版本。
  未生效、已过期或已删除版本不参与 PDP active set。
- delete 必须保留 tombstone 并推进 version；create 不复活同 id tombstone，也不得把 version 水位重置。
  版本推进必须单调，同租户更新不得影响其它租户同 key policy。
- policy load 必须 fail-closed：缺租户、store 不可用、反序列化失败、malformed JSON、未知字段、
  版本窗口非法或 storage error 都视为无有效 permit 并 deny，不回退到内置 allow-all、旧缓存 allow
  或跨租户默认值。malformed / unknown-field 输入必须在写侧拒绝落库，读侧遇既有坏数据也必须拒绝授权。
- durable policy 引用动态 `resource.*` 条件时，Authorizer 必须先取当前有效属性再进入规则求值；
  resolver 返回 `Missing` / `Stale` 或存储错误时直接 deny，且发生在 baseline 之前。
  global route 禁止动态 `resource.*` 条件，防止 shared 资源通过 tenant-local PIP 数据得到伪隔离判断。
- `EqAttr` 的 RHS 只能引用内置 PIP 属性键闭集（`principal.kind` / `principal.id` / `tenant.id` /
  `contract.id` / `permission` / `resource.id`）。域类型为 `PipAttributeKey`；HTTP active v1
  schema 将 `eqAttr.attribute` 收紧为同闭枚举；写侧 wire 与读侧 hydrate 均经 `parse` fail-closed，
  非 PIP 键不可表达、不得落库或参与求值（堵住属性存在性侦察）。
- obligation 必须 round-trip 持久化，不得在 store 层静默丢弃或默认化。

## gRPC 授权

- 非 public RPC 由 auth 拦截器调同一 Authorizer 做 PDP gate，不在 handler 手写谓词。
- method → permission 由契约 overlay 派生；非 public 方法缺 permission overlay 必须 fail-closed
  并在生成或注册期拒绝上线；未知 permission 必须启动 fail-fast。
- owner-scoped permission 必须声明 resource；拦截器从请求消息字段提取并 canonicalize 后转发 PDP。
- unary RPC 在入口取 resource；server-streaming owner-scoped RPC 将 permission gate 延后到首个消息接收。
- resource 提取失败（非 message、字段不存在、非 string）必须 deny，不回退到 full method；
  空或非 UUID 值转发给 PDP。提取值不得写入错误 metadata。
- 每个 deny 必须携带 sealed 结构化错误信息，metadata 不含 subject / token / resource value 等 PII。
- gRPC 与 HTTP 使用同一 PDP 决策指标 family，不新增 transport 分叉。

## HTTP 授权

- HTTP route gate 与 gRPC 同源，route → permission 由契约 overlay 派生。
  codegen 将 contract/path/method/auth/resource/selfScoped/consistency/effects 原子渲染为 generated binding。
- 普通 Primary route 只能经 generated endpoint 构造器与同契约 route marker 进入 route gate；
  `OutboxFact` producer 只能经 producer 构造器与同契约 move-only producer marker 进入。
  producer 构造器安装私有 route-bound witness，witness 缺失时 extractor fail-closed。
  handler 必须消费 marker 铸造的 receipt 再交给 producer funnel。generated spec 的 route 字段仅用于元数据查询。
- `RouteAuthorizer` 在 handler 前统一判定，允许后插入 `AuthorizedSubject`；handler 只消费该授权主体，
  不回读认证态。

每个 active 且 codegen 的 HTTP 契约必须声明恰好一个 AuthZ mode：

- ABAC 默认：声明 permission。
- 显式 opt-out：`public` / `bootstrap` / `clientsOnly` / `serviceOwned`，且必须带非空 reason。

ABAC mode 不带 reason；reason-without-opt-out 必须拒绝；permission 与 opt-out mode 互斥。
`passwordResetExempt` 不是 AuthZ mode，单独声明仍是 modeless 并必须拒绝，且只允许用于已声明 permission 的方法。

契约 codegen 是完整性门：modeless route 不得被渲染上线；active permission 必须能解析为 typed permission；
generated spec 与 route 装配不一致或出现未知 permission 时 fail-closed。
治理规则只做纵深检查，不能替代 codegen 强制门。

## Governance reverse self-check

`cargo xtask tenancy-closeout` 是本规则的反向自检，接入 `cargo xtask verify` / `ci full`。
它不重做业务测试，只锁 governance 锚点：verify/ci plan 的门成员、dylint 注册一致性、
projection contract → generated spec → rendering 的完整链路，以及 ADR 中不得残留已完成项的 future-work 措辞。

该命令不要求任何规则文档包含指定句子。本文件描述约束，不是它的 carrier。
