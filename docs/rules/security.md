# Security rules

本文件记录设备证书撤销的生产不变式。tenant/RLS 通用规则仍以
[`tenancy.md`](./tenancy.md) 为单一事实源；本文只收窄 `diport::RevocationStore` 与 PostgreSQL
持久实现。

## 证书撤销 scope 与 key

- 撤销精确键固定为 `(tenant_id, device_id, serial)`。tenant、device、serial 任一不同都不是同一条记录。
- `CertScope` 是 port 的必填位置参数；adapter 不从 ambient request、全局变量或裸连接推导 tenant。
- `CertSerial` 只允许 1–20 bytes。证书轮转必须生成新的 serial；本模型没有 issuer/CA-generation
  兼容键，也不允许复用 serial 绕开旧记录。

## Expiry 与冲突

- `CertNotAfter` 是私有字段、fallible constructor 的秒精度 newtype。epoch 前、亚秒和持久层无法表达的
  值在类型入口被拒绝；撤销时刻与证书到期时刻不可混用。
- `not_after <= provider authoritative now` 的写入必须失败。查询在 `not_after <= now` 时返回 `false`，
  无需等待物理清理。
- 同一精确键、同一 `not_after` 的重复和并发写入幂等，且保留数据库首次生成的 `revoked_at`。
- 同一精确键但 `not_after` 不同是数据冲突；禁止截短、延长、覆盖或“取最大值”。

## Fail closed

- 存储获取、tenant transaction、写入、读取或提交失败都返回脱敏 `RevocationStoreError`。
- `is_revoked` 不得把 provider 故障、reader lag 或缺 tenant scope 降级为 `false`。安全决策使用
  authoritative writer transaction，不读取可能滞后的 replica。
- runtime 只有在 revocation schema/RLS/ACL/maintenance functions capability gate 全部通过后才可构造
  PostgreSQL store 与 retention worker。

## PostgreSQL 权限与 retention

- `certificate_revocations` 在建表 migration 内同时启用并强制 RLS，使用 canonical tenant policy。
- `rss_app` 只有 SELECT 与受限列 INSERT；`rss_app_read` 只有 SELECT。两者均无 UPDATE/DELETE，PUBLIC
  无关系权限。
- `revoked_at` 由数据库默认值生成，serving role 不具备写入该列的权限。
- 物理清理与全局 backlog 采样分别由两个固定零参数 `SECURITY DEFINER` 函数执行；
  函数 owner 均是独立 `rss_revocation_maintenance` NOLOGIN/BYPASSRLS role，固定
  `search_path=pg_catalog, pg_temp`。`rss_app` 只有两函数的 EXECUTE，没有 raw DELETE；
  sample 与删除共用同一 transaction/deadline，sample 失败必须回滚删除。
- 单次清理最多 1,000 行，使用稳定排序与 `FOR UPDATE SKIP LOCKED`；只有
  `not_after <= clock_timestamp() - interval '5 minutes'` 的行可物理删除。

## Carrier

| 不变式 | 载体 | 等级 |
|---|---|---|
| typed scope / serial / expiry，runtime receipt 与非可选 concrete store | Rust 私有字段、闭集构造器、编译测试 | Hard |
| PK/RLS/CHECK/ACL/maintenance owner 与两个固定函数 | PostgreSQL catalog + startup capability gate | Hard |
| provider-neutral 行为、broken fake、防错误降级、并发/重启/retention | conformance 与 PostgreSQL integration | Medium |
| migration、RLS、tenant transaction 与 assembly/codegen 漂移 | `cargo xtask` governance gates | Medium |

Hard carrier 让缺依赖、错类型和未获 capability 的状态不可构造；Medium carrier 对外部数据库状态及运行期
故障做可执行纵深验证。二者必须同时存在，文档本身不是生产证据。
