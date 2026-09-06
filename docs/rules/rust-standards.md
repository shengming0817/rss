# Rust 编码规范

> 本文件只拥有 Rust 语言层规范，不拥有架构、contract 或一致性分类。

crate 划分、依赖方向及模块边界只按[架构与依赖规则](dependency-policy.md)判断，
本文件不规定业务分层或目录布局。

## 工程护栏

- clippy 认知复杂度 ≤ 15（`#![warn(clippy::cognitive_complexity)]`）。
- 同义字符串重复三次及以上抽 `const`。
- no-op、fallback、空实现必须写业务理由（`// reason:`）。
- 必填 service 依赖走构造器**必填参数**（非 `Option`）——缺失即编译错误。
- `Clock` 是构造器位置参（trait 对象 / 泛型）；禁止用 builder option 或 Config 字段传 clock，禁止默认取系统时钟。
- 优先 `&[T]` / `impl Iterator` 入参；避免无谓 `clone`；公共错误类型用 `thiserror`。
- `unsafe` 必须带 `// SAFETY:` 注释并经 review；默认 `#![forbid(unsafe_code)]`，例外按 crate 解禁。

## 命名

- DB 字段 snake_case。
- JSON、query、path、event header 字段 camelCase（`#[serde(rename_all = "camelCase")]`）。
- 错误使用 `vocab`(error) + `thiserror`。
- 日志和追踪使用结构化字段与关联上下文，输出遵循[错误处理](error-handling.md)的脱敏边界。
- mock 放 `#[cfg(test)]` 模块或 `mockall`；crate 的 dependency/dev-dependency 边界由 Cargo manifest 显式声明。
- 真实 provider 集成测试放在 `tests/*-integration` 的 `publish=false` workspace package；该 package
  直接依赖被测 adapter、testkit，并显式启用 adapter 所需的测试 feature。Cargo 反向依赖图
  自然负责选择，不维护 provider catalog、lane 或 shard 表。

## 覆盖率

- 完整 workspace 行覆盖率 ≥ 80%（`cargo-llvm-cov`）。

## 数据库迁移

- 已提交 migration 只增不改；例外必须有 ADR 说明。
- 新字段必须有默认值或允许 NULL。
- 索引形态按阶段：pre-GA / 有序 migration 集 / 新建或空表用普通 `CREATE INDEX`（留在事务型 migration）；
  `CONCURRENTLY` 仅用于 post-GA 给已填充、有在线流量的生产表加索引。消息专属 SQL artifact 与外部执行边界见 `crates/transactional-messaging-postgres/README.md`。
- 文件命名：`{序号}_{动词}_{对象}.sql`。
