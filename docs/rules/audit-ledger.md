# 审计哈希链字节格式规则（audit ledger）

> 单一事实源 · keyed HMAC 审计链的**冻结字节布局** + 验证语义。代码实现见
> `crates/audit/src/domain/mod.rs`（`canonical_message` / `AuditChainHasher`），golden 字节测试
> `canonical_message_golden_full_bytes` 守。改本文件即改链 wire 语义——须同步代码 + golden + PR 说明动机。

## 协议

审计条目构成**每租户线性 keyed HMAC 哈希链**（对标 sigstore/sigstore-rs rekor transparency log，
偏离 Merkle 树 → 线性链）。链节点哈希：

```
entry_hash = HMAC-SHA256(key, prev_hash ‖ canonical(entry_content))
```

- `key`：≥32B 的 MAC 密钥（[`primitives::MacKey`]），经 `AuditChainHasher::new` 构造器注入——**无 key
  不可造 hasher**，且**短于 32B 即 fail-closed 拒绝构造**（`AuditChainHasher::new -> Option`，弱 key 不可造
  hasher；公开入口 `AuditDomain::new` 映射为 `AuditDomainError::WeakKey`，组合根 fail-fast）。key 强度
  收口在构造器（任何构造路径均校验，非仅 callsite）。真实 `sha2`/`hmac` 的 [`primitives::MacVerifier`]
  实现是 follow-up adapter；域逻辑泛型于 `MacVerifier`。
- `prev_hash`：前一条目的 `entry_hash`；链首（`seq=0`，genesis）为全零 `[0u8;32]`。
- 比较一律走 [`primitives::constant_time_eq`]（防时序侧信道；`Mac`/`EntryHash` 禁裸 `==`）。

## 冻结字节布局（INVARIANT: AUDIT-LEDGER-BYTES-01）

`canonical_message = prev_hash(32) ‖ DOMAIN_TAG ‖ 字段序`。变长字段 `u32` BE 长度前缀 + 原始字节
（消歧：`kind="ab",id="c"` 与 `kind="a",id="bc"` 不撞）；定宽字段 BE 无前缀；枚举单 `u8` 固定 tag
（非字符串名 ⇒ rename-stable，`#[non_exhaustive]` 加变体不挪旧 tag）。

| # | 字段 | 编码 |
|---|------|------|
| — | DOMAIN_TAG | `b"rss.audit.v1\x00"`（13B 字面量，锁布局版本；v2 产生不相交哈希） |
| 1 | `tenant` | `TenantId` uuid bytes，16B（首位 ⇒ 绑定子链、防跨租户重放） |
| 2 | `seq` | `u64` BE，8B |
| 3 | `actor` | `UserId` uuid bytes，16B |
| 4 | `actor_kind` | 1 tag：`User=1 Device=2 Admin=3 SuperAdmin=4 Service=5 Anonymous=6`（未知=0 fail-closed） |
| 5 | `action` | `len(u32 BE) ‖ action.as_str().as_bytes()` |
| 6 | `resource.kind` | `len(u32 BE) ‖ bytes` |
| 7 | `resource.id` | `len(u32 BE) ‖ bytes` |
| 8 | `outcome` | 1 tag：`Success=1 Denied=2 Error=3` |
| 9 | `recorded_at` | `u64` BE unix-secs(8B) ‖ `u32` BE subsec-nanos(4B)；epoch 前 fail-closed 落 `(0,0)` |

枚举 tag 由 `enum_tag_mapping_is_total_and_nonzero` 测试守（已知变体非零唯一；跨 `#[non_exhaustive]` crate
边界的穷尽性编译期不可得，由测试补——盲区：本 crate 视野外新增的 `PrincipalKind` 变体落 tag 0）。

## 验证语义（`AuditChainHasher::verify`）

输入：**单租户、按 `seq` 升序**的条目切片（调用方须先按租户分区并排序）。逐条 fail-closed：

| 检查 | 违反 → 错误 |
|------|-------------|
| (A) 全条目同 `tenant`（防御纵深） | `ChainBroken` |
| (B) 首条 `seq=0`；后续 `seq = prev.seq + 1`（gap/dup/溢出均判） | `SequenceGap` |
| (B') 首条 `prev_hash = genesis([0;32])` | `ChainBroken` |
| (C) `prev_hash = 上一条 entry_hash`（常数时间） | `ChainBroken` |
| (D) 重算 `entry_hash` 与存储一致（常数时间；错 key / 篡改命中） | `HashMismatch` |

## 持久化与跨租户读

`identity.session-created` 的 `sessionId` 是 bearer，不得进入审计链。该事件的 session resource id 只由
独立、canonical UUID v4 `MessageId` 构造，冻结为 `event:<lowercase-uuid-v4>`；EventId 与 SessionId 相等、
非 v4 或非 canonical 时消费 fail-closed。`0018` 的
`audit_entries_session_event_resource_check` 在数据库层重复固定该形态。resource id 继续进入上述 V1
canonical bytes，但其内容不再携带 bearer。

in-mem 每租户子链 store 与确定性 verifier 只经 `audit::test_support` 暴露；默认生产 feature graph 无
`InMemAuditRepo` 构造面。
生产持久化由 `adapters/postgres` provider 承载：每租户 genesis、advisory-lock 串行 append、FORCE RLS、
`(tenant_id, seq)` 唯一，读路径复用同一 keyed HMAC 链验证语义。
普通仓储入口通过共享 `Arc<PgAuditRepo>` 分别擦除为 `DynAuditWriteRepo` / `DynAuditReadRepo`；生产事件
订阅不经过 ambient `AuditDomain` 的仓储字段，而由 owner-sealed `PgAuditConsumerTx` 在同一个 PostgreSQL
事务内完成链 append 与 inbox commit，其公开 handler 擦除路径固定分类为 `BusinessWriteEffect`。

**跨租户 admin 读**只支持“指定租户”读取
（`GET /api/v1/audit/tenants/{tenantId}/entries`），不提供全租户全局列表。旧
`GET /api/v1/audit/entries?tenantId=...` 不兼容并返回 400。
handler 必须先 durable append cross-tenant audit event，append 成功后才调用 admin repo 读取；append 失败
fail-closed 不读取。append 是该 LocalTx 的唯一写 UoW；read 在提交成功后执行，不与 append 构成同一事务。
该 route 的 contract 继续声明 `business-write + business-transaction + cross-tenant-audit`，不得因读取阶段使用
provider-owned transaction 而降级为 LocalOnly 或 operational effect。
handler 将 audited `RowVisibility` 消费成 sealed `CrossTenantReadScope`，`AuditAdminRepo::list_tenant` 不接受裸
tenant。Postgres admin repo 使用可选专用 `rss_audit_admin` 只读池：直连角色必须为
`rss_audit_admin` LOGIN 角色、非 superuser、`NOBYPASSRLS`，且仅有 `audit_entries` SELECT 权限。读取时在
provider-owned read-path transaction 中 `SET LOCAL rss.tenant_id = targetTenant`，复用现有 tenant-isolation
RLS policy；helper 不承诺 PostgreSQL `READ ONLY` 或稳定 snapshot，限制写能力依赖专用角色/授权。不得授写权限、
其它 public relation 权限，也不得新增 allow-all RLS policy。admin 池未配置时 privileged audit read 返回
501 `ERR_CORE_NOT_IMPLEMENTED`，配置不完整或权限不安全则启动失败。

## Operator full-chain verify

生产运维入口是 `rss` binary：

```
rss audit-ledger verify \
  --operator-service-token-stdin \
  --operator-tenant <uuid> \
  --tenant <uuid> \
  [--batch-size <1..500>] \
  < /run/secrets/rss-operator-service-token
```

该命令只验证一个指定 tenant 的完整链，不提供 `--all-tenants`、`--namespace` 或旧 alias。当前
`audit_entries` schema 没有 namespace 维度；接受 namespace flag 会制造虚假隔离语义，因此必须 fail-closed。

命令使用 `AuditAdminRepo::verify_tenant(tenant: TenantId, batch: vocab::Limit)`，而不是 tenant-scoped
`AuditReadRepo` / `AuditWriteRepo`。Postgres 实现只经 `rss_audit_admin` 只读池分页扫描整条 tenant chain：任何 seq gap / dup、
prev 链接错误、entry_hash mismatch 或混租户行进入窗口都返回 `AuditError`。`verify_tail` 仍只是 bootstrap /
诊断用的尾部窗口验证，不能代表 full-chain verify。

operator 授权需要同时满足：

- service-token 验签成功，且 token tenant 绑定到 `--operator-tenant`。
- 验出的 principal 必须是 service principal，且 typed caller 精确为
  `ServiceCallerDomain::MaintenanceOperator`（canonical `sub=rss-maintenance-operator`）。
- 必填环境变量 `RSS_AUDIT_LEDGER_VERIFY_OPERATOR_GRANTS=tenant,...` 中存在
  `tenant == --tenant` 的 grant。caller 不从配置字符串选择；无 wildcard、无 namespace、无 action fallback。

命令 start / finish 都写 `auth_audit_events`，`resource_kind="audit.ledger.verify"`，action 固定为
`audit.ledger.verify.start|finish`。失败原因使用固定枚举字符串，例如 `operator_auth`、
`operator_authorization`、`operator_grants`、`operator_provider_config`、`run_error`。
