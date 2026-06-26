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
`RowScope::All` 只能从 `authn` 的 super-admin 派生路径进入业务；派生必须与强制审计同址：跨租户 super-admin 访问**必须写持久 audit ledger**（字段至少含 tenant / principal / resource / action / request / correlation），tracing span 仅作关联信号、不替代持久审计。「同址」由 `authn` audited 派生 funnel 类型层强制——先写审计成功才签发 All-scope，audit 写失败 fail-closed（INVARIANT: TENANCY-CROSSTENANT-AUDIT-01，封闭符号见 `crates/authn/src/lib.rs`）；裸同步 `Principal::row_visibility` 的 super-admin 分支不再签发 All-scope（无 `AuditSink` 无法同址，返回 deny）。live httpserve middleware 注入与持久 postgres audit adapter 是独立 follow-up（#1014）。

audit read 的 serving 池对 `RowScope::All` 始终 fail-closed，返回
`RowScopeAllUnsupportedError` / 501。super-admin 跨租户 audit read 只能走专用
`rss_audit_admin` admin 读取池；该池必须使用角色限定 permissive RLS policy，
不得使用 BYPASSRLS。admin 池未 provision 时返回 501，不 fail-open。

## Tenant source（认证通道，非 request body）

tenant scope 只能来自**已认证通道**：JWT tenant claim（→ ctx）或 service-token MAC 签名的
`X-Tenant-ID` header（internal / pre-auth 路径，经 `endpoints.http.headers.X-Tenant-ID`
populate-only 派生，adapter `tenant::parse_tenant_id` fail-closed）。**HTTP request body 不得携带
`tenantId`**——body 是唯一不被 service-token MAC 覆盖的入口，body tenant 是未认证维度。契约 codegen
（`build_http_dtos`）在不可绕的 request 路径拒绝任何声明 `tenantId` 的 HTTP request schema：upstream
schema→DTO 拒绝是 **Hard**（codegen funnel + golden drift），downstream 单一 sanctioned call-site 是
**behavior-locked Medium**（reject 用例驱动真实入口，删调用即测试失败；单 site 无需独立 call-site
强制）；无豁免。符号 / 评级 / 盲区见 契约 codegen 的 tenant-in-body guard 模块 rustdoc。

## Principal claim source

JWT tenant claim 在 auth 边界解析并写入 context。service principal 无 tenant。
`Principal::row_visibility(ctx)` 是身份到 row-scope 的框架级派生入口：

- normal user -> self
- device -> device
- admin -> tenant
- super-admin -> fail-closed（裸同步 `row_visibility` 不签发 All-scope；跨租户 All 仅经 `Principal::audited_cross_tenant_visibility(...)` 同址审计派生，见上文 §RowScope）
- service / anonymous / unknown -> fail-closed

## RLS 与 PG scope

PG tenant scope 使用 `SET LOCAL` 注入当前事务，读路径（`tenant_scoped_read`）与写路径
（`tenant_scoped` / `co_tx_with_outbox`）均经受控 helper 注入；绕过 TxManager 直接借连接
必须 fail-fast。

`cargo xtask schema-rls`（INVARIANT `TENANCY-RLS-FORCE-01`，接入 `cargo xtask verify` / `ci`，
Medium）机器强制：含 `tenant_id` 列的表必须有 `ENABLE ROW LEVEL SECURITY` +
`FORCE ROW LEVEL SECURITY` + tenant-isolation policy（`USING/WITH CHECK (tenant_id =
current_setting('rss.tenant_id', true)::uuid)`）；缺失即门红。

app-serving role `rss_app` 已 provision 为非 owner、NOBYPASSRLS，仅授三张 tenant 表
（sessions / config_entries / roles）的 DML；`FORCE ROW LEVEL SECURITY` 使 owner 连接亦受
policy 约束。业务池以 rss_app 连接的 dual-pool 接线是 follow-up（bootstrap 接线未落地）。
注：superuser 连接永远绕过 RLS（含 FORCE）；serving role rss_app 为非 superuser 故受 policy 约束；
生产 owner 须为非 superuser。

outbox / saga_journal / projection_events 是**无 `tenant_id` 列的全局表**，不在 `schema-rls` 检查
范围。这些表以其它机制保证数据隔离：saga_journal / projection_events 依赖 seq 全局顺序 + consumer
group 隔离；outbox 依赖 partition_key routing。因此，outbox `partition_key` 若用于有序投递**必须自带
tenant scope**（含 tenantId 或全局唯一如 sessionId），否则同 `(domain, partition_key)` 跨租户碰撞
致 liveness DoS（队头阻塞传播到另一租户的投递队列）。架构强制（outbox 加 `tenant_id` 列 + RLS，或
typed `PartitionKey::for_tenant(TenantId, ..)` 让 tenant scope 进类型层）见 issue **#1405**。

> tenant-scoped key（如 `<tenantId>:<sessionId>`）可能含**凭据级** bearer 标识，故 `PartitionKey` 的 `Debug`
> 脱敏（`<redacted>`），不以明文进日志（F3，#1211 review；同 `SessionId`）——见 `observability.md` §Outbox Envelope。

## ABAC authz 接线（permission-based）

业务端点授权走 PDP 决策，不在 handler 硬编 role-name 字面量。

- 路由门禁用 `authn::require_permission(authz::Permission)`、
  `authn::require_permission_for_resource(path_param, perm)` 或
  `authn::require_permission_for_contract(...)`，不用 `authn::any_role` / `authn::self_or` /
  `authn::require_any_role` 做授权分支。
- `authz::Permission` 是 sealed 闭值集（枚举 / sealed 类型）；业务代码经 accessor 函数
  （如 `authz::perm_audit_read()`）取得 permission，不传 role 字符串。
- handler 不手写 `Principal::has_role` 或遍历 `Principal.roles` 做授权。
- `Effect::Allow` 规则必须声明至少一个 action；空 action 只允许用于
  `Effect::Deny` 的 deny-all。写侧和读侧都必须 fail-closed。
- 路由门禁只做 coarse allow/deny，不执行 RowScope / FieldMask obligation。Allow
  规则携带非零 obligation 时必须 fail-closed。

## Resource ownership

path-param 标识的 resource ownership 是 PDP ABAC 决策，不是 handler 短路。owner-scoped /
self-scoped gate **contract-derived**：契约声明 `endpoints.http.resource:
<pathParam>`（owner-scoped）或 `endpoints.http.selfScoped: true`（self-scoped），生成
handler 经单一 `authn::require_permission_for_contract(contract_spec, resolver)` funnel 派生
`require_permission_for_resource(path_param, perm)` / `require_permission_for_self(perm)`——业务
handler / 域 crate 不手写 gate。`resource`/`selfScoped` 各 ⇒ permission、二者互斥（schema + `ContractSpec::validate`
+ `cargo xtask` 治理校验 三重）。owner-scoped gate 把 canonical resource id（self-scoped 把
调用者自身 subject）转发给 PDP。

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

Authorizer 经组合根（bootstrap 的 `with_primary_authorizer`）注入 primary listener
request context。域 crate 不依赖兄弟域 crate 的 Authorizer。

强依赖缺失必须 fail-fast；可解析的 Authorizer 在 bootstrap router build（Init 后、
serve 前）预解析。缺失的 provider 在启动期 fail-fast（构造器必填参数缺失即编译期 / 启动期
报错），而不是首请求暴露。

PDP 默认 fail-closed：缺 Authorizer、缺租户、store 不可用或无适用 permit 都 deny。
baseline 是 action-scoped + role-conditioned 的 allow 规则，不是 allow-all。租户 policy
可以叠加 allow / deny；deny 优先。

租户 allow 可以放宽路由门禁，但不能扩大数据访问。读端点的数据可见性由 principal
派生的 `RowScope` 决定；写端点没有 RowScope 维度，必须依赖 typed tenant 参数和 FORCE
RLS 维护 tenant 边界。

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
`endpoints.http.permission` overlay 派生，生成 handler 通过
`authn::require_permission_for_contract(contract_spec, resolver)` 解析并进入同一 PDP 路径。owner-scoped
（`endpoints.http.resource`）/ self-scoped（`endpoints.http.selfScoped`）由该同一 funnel 按
`contract_spec.{resource, self_scoped}` 三分支派生，见 §Resource ownership。

每个 `lifecycle: active` 且 `codegen` 的 HTTP 契约必须声明恰好一个 AuthZ mode：

- ABAC 默认：`endpoints.http.permission`
- 显式 opt-out：`public` / `bootstrap` / `clientsOnly` / `serviceOwned`

opt-out 必须带非空 `endpoints.http.auth.reason`。ABAC mode 不带 reason；
reason-without-opt-out 必须拒绝。permission 与 opt-out mode 互斥。
HTTP `passwordResetExempt` 不是 AuthZ mode；单独声明仍是 modeless，必须拒绝。

契约 codegen 的 `build_http_spec` 是 codegen 完整性门：modeless route 不得被渲染上线。
`cargo xtask` / governance 规则只做纵深检查，不能替代 codegen 强制门。
