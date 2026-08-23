# Certificate Revocation 规则

本文只拥有 `RevocationStore` 与 PostgreSQL 证书撤销语义，不拥有通用 tenant transaction。

## Scope 与 identity

- 精确键为 `(tenant_id, device_id, serial)`；任一维度不同即不同记录。
- typed scope 是 port 必填参数；adapter 不从 ambient context、全局变量或 raw connection 推导 tenant。
- serial 为受限 bytes newtype；轮转产生新 serial，不存在 issuer/generation 兼容键或 serial 复用。

## Expiry 与冲突

- certificate not-after 是 fallible、秒精度 newtype；epoch 前、亚秒或数据库不可表达值在入口拒绝。
- 已过期证书的 revoke 写入失败；读取在 `not_after <= authoritative now` 时返回未撤销，无需等待物理清理。
- 同 key/同 expiry 幂等并保留首次 `revoked_at`；同 key/不同 expiry 是冲突，禁止覆盖、截短或延长。

## Fail closed

- store acquire、tenant transaction、读写或 commit 失败返回脱敏错误；不得把 provider fault/replica lag 降级为 false。
- 安全决定使用 authoritative writer transaction。
- runtime 只有在 schema/RLS/ACL/maintenance capability 全部通过后才能构造 store/worker。

## PostgreSQL 与 retention

- relation 创建时 ENABLE/FORCE RLS；serving role 只有最小 SELECT/INSERT，不能 UPDATE/DELETE `revoked_at`。
- cleanup/sample 由独立 maintenance owner 的固定 SECURITY DEFINER function 执行，固定 search path；sample 与
  delete 同 transaction，sample failure 回滚删除。
- 清理必须有界、稳定排序并使用 skip-locked；只删除超过安全余量的 expired row。

## Carrier

- Hard：typed scope/serial/expiry、private constructors、PK/CHECK/RLS/ACL 与 concrete store capability。
- Medium：provider-neutral conformance、真实 PostgreSQL concurrency/restart/retention 与 migration/catalog gates。
- 文档不是生产证据。
