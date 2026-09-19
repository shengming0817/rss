# RSS

RSS 是面向 Rust 社区的一致性与持久化执行 library workspace。按需选择组件及 provider adapter；
业务、认证授权、应用装配、生产迁移与产品验收由消费产品拥有，边界见[项目范围](docs/rules/project-scope.md)。
实际产品仓及职责见[仓库说明](AGENTS.md#本地仓库与参考目录)。

## 选择组件

以下是使用入口；具体 API、feature 与依赖由各组件文档和 Cargo manifest 持有。

| 使用场景 | 组件入口 |
|---|---|
| 公共值与请求上下文 | [Contract](crates/contract/README.md)、[Request Context](crates/request-context/README.md) |
| 诊断与数据保护 | [诊断上下文](crates/diagctx/README.md)、[Trace](crates/tracewire/README.md)、[Redact](crates/redact/README.md)、[Data Protection](crates/data-protection/README.md) |
| 执行与协议适配 | [Runtime](crates/runtime/README.md)、[Platform](crates/platform/README.md)、[Axum](crates/axum/README.md) |
| 事务消息 | [消息核心](crates/transactional-messaging/README.md)、[执行循环](crates/transactional-messaging-runtime/README.md)、[PostgreSQL](crates/transactional-messaging-postgres/README.md) |
| 消息传输与恢复 | [AMQP](crates/transactional-messaging-amqp/README.md)、[Kafka](crates/transactional-messaging-kafka/README.md)、[MQTT](crates/mqtt/README.md)、[Recovery](crates/transactional-messaging-recovery/README.md)、[S3 Archive](crates/transactional-messaging-recovery-s3/README.md) |
| 持久化执行 | [Saga](crates/saga/README.md) / [PG](crates/saga-postgres/README.md)、[Projection](crates/projection/README.md) / [PG](crates/projection-postgres/README.md)、[Reconcile](crates/reconcile/README.md) / [PG](crates/reconcile-postgres/README.md)、[Device Command](crates/device-command/README.md) / [PG](crates/device-command-postgres/README.md) |
| 可靠观察与追加账本 | [Observation](crates/observation/README.md)、[Ledger](crates/ledger/README.md)及其 [Observation PG](crates/observation-postgres/README.md)、[Ledger PG](crates/ledger-postgres/README.md) |

## 最小源码消费

例如仅使用消息身份、事务结果与预算类型，在独立 consumer 的 `Cargo.toml` 中声明：

```toml
[dependencies]
rss-transactional-messaging = { path = "../rss/crates/transactional-messaging", default-features = false }
```

该相对路径假设 consumer 与 RSS checkout 是同级目录，按实际位置调整。
需要写入/发布接口时添加 `features = ["producer"]`，需要接收/消费接口时添加
`features = ["consumer"]`；两者可组合。执行循环、存储和传输按需显式添加对应组件。
本地源码依赖不表示包已发布；候选发布范围以根 [Cargo.toml](Cargo.toml) 的 Release Surface
及实际 Cargo 依赖闭包为准，实际发布须有对应版本与 artifact 证据。

## 运行示例与验证

从 RSS 仓库根目录运行无需外部服务的基础示例：

```sh
cargo run --locked -p rss-examples --features core
```

更多场景、provider 环境要求与独立消费命令见[示例说明](crates/examples/README.md)。
`rss-examples` 不发布；独立 consumer 的可再生产物位于 `rss-external-check/`，隔离要求遵循
[验证范围](docs/rules/verification-scope.md#示例与隔离消费目录)。

- T1 证明类型、状态机和组件不变量；T2 证明真实 provider、事务与 transport 接缝。
- 源码构建成功、固定候选 artifact 可消费和实际发布分别提供证据，不能互相替代。
- 产品 T3、部署配置与生产验收归消费产品；库级示例和 T1/T2 不代替产品验收。

贡献前阅读[协作说明](CLAUDE.md)；本地验证入口为 `make ci CI_BASE=origin/develop`，
实际范围由[验证规则](docs/rules/verification-scope.md)和既有选择器决定。
