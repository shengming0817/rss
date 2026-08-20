# ADR-030：PostgreSQL 显式私有 CA 独占信任根

- **Status**：Accepted
- **Date**：2026-08-19
- **Tracking**：#1954
- **Scope**：Postgres adapter、生产 assemblies、独立 migration operator 与 SQLx TLS 接缝

## Context

SQLx 0.8.6 的 rustls 实现会先以 Mozilla WebPKI roots 初始化 `RootCertStore`，再追加
`ssl_root_cert`。因此旧 `PgConfig` 即使传入私有 CA，仍然信任公共 CA；正确私有 CA 成功与错误私有 CA
失败只能证明证书被追加，不能证明公共根被排除。`PgConnectOptions` 只暴露 path/inline PEM setter，不能注入
自建 `ClientConfig` 或空 `RootCertStore`。SQLx 当前上游讨论与 draft API 尚未形成可消费的 release。

生产 runtime 已要求 CA 文件，但 adapter 仍暴露可选 root、TLS mode builder 与默认 WebPKI 路径；
`settingsonly`、`identityaudit` 还允许配置 `sslMode`。独立 migration operator 也只检查 DSN 的
`verify-full`，没有把唯一 CA 文件转换为启动时快照。这些入口共同构成 downgrade/bypass 面。

## Decision

精确锁定 SQLx `=0.8.6`，将 crates.io 发布包的 `sqlx-core` 以原许可证 vendor 到仓库，并通过
`[patch.crates-io]` 使用本地版本。下游 feature `rss-exclusive-explicit-roots` 只改变显式根存在时的初始化：
从空 store 开始，再加入 PEM bundle；没有显式根时保持 SQLx 原 WebPKI 行为。补丁公开
`ExclusiveExplicitRoots` capability marker，Postgres adapter 与 migration operator 必须持有该 witness；
删除补丁或 feature 会使生产代码无法编译，而不是静默退回 overlay。

Postgres adapter 以 `PgPrivateCa::from_pem(Vec<u8>)` 作为唯一生产 trust funnel。它在网络连接前要求至少
一个 PEM certificate、验证每张证书可加入空 rustls store，并只保存不可变启动快照；错误与 `Debug` 均不输出
PEM。`PgConfig::new` 必须接收该值并固定 `VerifyFull`。旧 `PgSslMode`、可选 CA、TLS builder 和默认 TLS
常量全部删除，不提供 alias、deprecated shim 或 fallback。明文构造器只存在于测试 feature，且 shipped
feature-graph guard 禁止其进入任何生产 artifact。

`runtime`、`settingsonly`、`identityaudit` 在配置阶段各读取一次必填 CA 文件并复用同一 `PgPrivateCa` 快照；
后两者的 schema 删除 `sslMode` 并拒绝旧字段。独立 migration operator 保留单 DSN 接口，但要求唯一、
非空、绝对且无 parent traversal 的 `sslrootcert`，固定 `sslmode=verify-full`，读取并验证 PEM 后改用 inline
snapshot。目录、缺失/重复/相对路径、空文件和坏 PEM 都在首次网络尝试前失败。

不建立 `TypedEgressTlsProfile`：AMQP、Redis、S3 与 PG 的上游 TLS 构造形状不同，当前没有多个真实 SPI
证明值得抽取共同 provider vocabulary。本变更也不更换 driver、不使用 native-tls、TLS proxy、外部 git fork
或伪造 WebPKI crate。

## Proof and ownership

| 边界 | 级别 | 证明 |
|------|------|------|
| 生产 `PgConfig` 必填有效 `PgPrivateCa`，固定 VerifyFull | Hard + T1 | 构造器签名、closed trust enum、PEM 单测 |
| 显式 bundle 排除全部公共根；无 bundle 保留上游默认 | T1 | vendored core 精确 store-size 测试 |
| 生产图不得启用明文测试构造 | Medium | shipped feature-graph guard + synthetic red |
| 所有固定 PG roles 使用同一 trust funnel | Medium + T2 | assembly AST guard；真实 PostgreSQL TLS fixture 覆盖 writer/reader/migrator/maintenance lanes |
| migration DSN 不能绕过唯一私有 CA | T1 | URL/path/PEM fail-fast tests |

仓库承担 vendored SQLx 的升级审计、安全回补与许可证维护责任。每次 SQLx 升级必须重新对比 TLS root-store
构造、更新来源元数据并重跑上述证明。只有正式上游 release 提供等价的 exclusive-root API，且在一个原子变更中
删除 vendor/marker、切换 adapter/operator 并保持全部证明通过时，才能替换本补丁。

## Consequences

这是有意的不向后兼容切换：旧 `sslMode` 配置和省略 CA 的生产构造立即失败；由公共 CA 签发但不在显式
bundle 中的 PostgreSQL 服务证书也会被拒绝。证书轮换需要发布包含新旧私有根的完整 bundle 并重启以取得新
快照，确认所有服务 leaf 已切换后再发布移除旧根的 bundle。

## References

- `ref: launchbadge/sqlx sqlx-core/src/net/tls/tls_rustls.rs@bab1b022bd56a64f9a08b46b36b97c5cff19d77e`
- `ref: launchbadge/sqlx sqlx-postgres/src/options/mod.rs@bab1b022bd56a64f9a08b46b36b97c5cff19d77e`
- SQLx upstream issue `transact-rs/sqlx#4049` and draft PR `#4051`（未发布，不作为能力依据）
