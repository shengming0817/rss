# Tenant Persistence 规则

本文拥有 PostgreSQL tenant transaction、RLS/ACL、repository signature 与 durable table isolation。

## Typed transaction funnel

`INVARIANT: TENANCY-PG-TX-FUNNEL-01`：serving 与 maintenance 使用不可互换的 typed lanes；raw pool、connection、
transaction 与 executor 只在 adapter 内核可见。

- verified tenant 在 acquire 后立即以 transaction-local binding 安装；setup 成功前不得向 closure 暴露 capability。
- closure 只取得 concern-specific transaction capability；不得跨 concern、跨 attempt 或并行复用。
- commit/rollback 明确 ACK 才解除 lease；取消、unknown 或 settlement failure 必须 quarantine/close connection。
- `pg-tenant-tx-guard`、schema/RLS checks 与真实 PostgreSQL behavior proof 提供 Medium 纵深。

## Repository signature

`INVARIANT: TENANCY-REPO-SCOPE-SIGNATURE-01`：tenant-owned repository operation 必须在签名中消费 typed tenant
transaction/scope；禁止无 scope overload、ambient fallback 与 raw pool constructor。

## RLS 与角色

- 每个 tenant-owned durable relation 在创建 migration 内同时 ENABLE/FORCE RLS，并使用 canonical tenant policy。
- serving writer/read roles 只有最小列/函数权限；PUBLIC 无关系权限，reader 不得写。
- global discovery/maintenance 只能经固定 SECURITY DEFINER function、独立 NOLOGIN/BYPASSRLS owner、固定
  `search_path` 和闭值输入；serving role 不得取得 raw bypass capability。
- schema、policy、ACL、function owner/signature 漂移启动或 gate fail-closed。

## Durable table classification

- tenant-owned/global/provider-owned 是 typed/manifest 分类，不在文档维护表名清单。
- tenant-owned primary/unique/index/foreign-key 必须包含 tenant identity，防止跨租户碰撞和引用。
- append-only journal/receipt 对 serving role revoke UPDATE/DELETE；清理由独立 maintenance capability 完成。
- encrypted payload 的 AAD 必须绑定 tenant 与业务 identity；普通 serving 路径不能读取历史明文或 maintenance key。

## Failure

- tenant bind、RLS、ACL、transaction setup、query、commit 或 audit 失败都返回脱敏错误，不得降级到 unscoped read/write。
- replica lag 不得用于安全决定；授权、revocation 与 write-after-read correctness 使用 authoritative transaction。
- Hard：typed lanes/capabilities、private constructors、database PK/CHECK/RLS/ACL。
- Medium：schema/transaction guards、catalog proof 与真实 tenant isolation/concurrency tests。
