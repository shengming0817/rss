# Rust 编码规范

> 架构概念 / 域 crate / contract / 一致性等级 如何映射到 crate 见 `docs/rules/architecture.md`。本文件只讲 Rust 语言层规范。

## 分层依赖（crate 图 + deny.toml 编译期强制）

分组划分、允许 / 禁止依赖矩阵以 `docs/rules/architecture.md` §分层 为**单一事实源**，本文件不复制（避免第二结构真源）。Rust 语言层要点：cargo 拒绝循环依赖；禁依赖用 `cargo-deny`(deny.toml)、多余 / 未声明用 `cargo-udeps`、外部 API 面用 `cargo public-api` 守。

## DDD 分层（crate 内 module）

- `handler`（http）：参数绑定、鉴权结果消费、响应返回。
- `application`：业务编排。
- `domain`：实体、值对象、领域服务，不依赖框架。
- `repository` / `ports`：持久化 trait 与实现，不放业务判断。

domain 实体经 DTO 转换出 wire（`From`/`TryFrom` impl）。跨聚合通过 EventBus 或 contract 解耦。
**domain 类型不 derive `Serialize`**——只有 contract / DTO 类型可序列化到 wire，从类型层杜绝 "把 entity 直接序列化"。

## 一致性级别

| 级别 | 语义 | 测试要求 |
|------|------|----------|
| L0 | 本地纯计算 | 表驱动单元测试（`rstest` 参数化） |
| L1 | 单域 crate 本地事务 | 事务完整性测试 |
| L2 | 本地事务 + outbox | outbox 原子性 + consumer 幂等 |
| L3 | 跨域最终一致 | replay + 投影重建 |
| L4 | 长延迟设备闭环 | 状态机、超时、重试、迟到消息 |

级别声明在 `contract.toml` 的 `consistencyLevel` 字段（与 wire 语义同源），由 `cargo xtask` 校验。L2 覆盖由 `cargo xtask` 原子性+幂等治理测试（Medium）守。

## 工程护栏

- clippy 认知复杂度 ≤ 15（`#![warn(clippy::cognitive_complexity)]`）。
- 同义字符串重复三次及以上抽 `const`。
- no-op、fallback、空实现必须写业务理由（`// reason:`）。
- 必填 service 依赖走构造器**必填参数**（非 `Option`）——缺失即编译错误，替代 gocell 的 `gocell:"required"` 生成校验。
- `Clock` 是构造器位置参（trait 对象 / 泛型）；禁止用 builder option 或 Config 字段传 clock，禁止默认取系统时钟。
- 优先 `&[T]` / `impl Iterator` 入参；避免无谓 `clone`；公共错误类型用 `thiserror`。
- `unsafe` 必须带 `// SAFETY:` 注释并经 review；默认 `#![forbid(unsafe_code)]`，例外按 crate 解禁。

## 命名

- DB 字段 snake_case。
- JSON、query、path、event header 字段 camelCase（`#[serde(rename_all = "camelCase")]`）。
- 错误使用 `vocab`(error) + `thiserror`。
- mock 放 `#[cfg(test)]` 模块或 `mockall`；域 crate 单测不依赖平台 adapter crate。
- 集成测试用 `tests/` 目录 + `#[cfg(feature = "integration")]` feature 明确隔离（替代 Go build tag）。

## 覆盖率

- 引擎与基础 crate（`consistency` / `primitives` / `vocab` / `ids`）≥ 90%。
- 新增或修改代码 ≥ 80%（`cargo-llvm-cov`）。
- handler 用 `axum::http` / `tower::ServiceExt::oneshot` 覆盖参数校验、鉴权、错误码。

## 数据库迁移

- 已提交 migration 只增不改；例外必须有 ADR 说明。
- 新字段必须有默认值或允许 NULL。
- 索引形态按阶段：pre-GA / 有序 migration 集 / 新建或空表用普通 `CREATE INDEX`（留在事务型 migration）；
  `CONCURRENTLY` 仅用于 post-GA 给已填充、有在线流量的生产表加索引。详见 `adapters/postgres/migrations/` 的 README（迁移规范，随 postgres adapter 落地）。
- 文件命名：`{序号}_{动词}_{对象}.sql`。

## 安全检查点

- 新端点加 JWT 或显式 `httpserve::Route { public: true }`。
- `/internal/v1/` 必须声明 caller、鉴权和网络隔离。
- 列表接口强制分页，`limit` 上限 500。
- 生产配置禁止 localhost fallback 和 noop publisher。

## API

- 资源用复数名词，动作由 HTTP method 表达。
- 状态码：200 GET/PUT/PATCH，201 POST，202 async，204 DELETE。
- 列表响应：`data`、`nextCursor`、`hasMore`。
- 错误响应使用 shared error schema。
