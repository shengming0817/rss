# Requirements Quality Checklist — identity 域 crate

> spec.md / plan.md 自检；ship 阶段 reviewer 复核。

## 范围与边界

- [x] In/Out 明确：identity 域 crate 本体 in；authn 原语 / 持久化 / EST / vocab Obligations 列 Out + blocker。
- [x] 不越界到兄弟 W 单元（#1003 authn / adapter）；blocked-by 只挂彼此 + #999，不错挂 authn/adapter。
- [x] 每个 PR ≤2000 行（PR5 例外条款明确：超则拆 5a/5b）。

## 用户故事质量

- [x] 5 个用户故事各自独立可测、独立可 ship（MVP 切片）。
- [x] 每个用户故事有优先级（P1×2 / P2×3）+ Why + Independent Test + Acceptance Scenarios（Given/When/Then）。
- [x] 用户故事边界 = PR 边界 = 独占文件归属（解耦并行）。

## 需求可验证性

- [x] FR-001..FR-015 均 MUST/MUST NOT、可机器或测试验证。
- [x] SC-001..SC-006 可度量（覆盖率 / clippy / contract validate / 跨租 fail-closed / 密码零泄漏）。
- [x] 安全不变式显式：跨租 fail-closed（IDENTITY-AUTHZ-TENANT-01）、密码不落明文、public 降级仅 PrimaryRoute。

## AI-HARD / 治理对齐

- [x] 不弱化 #997 冻结签名 / `pub(crate)` 字段 / funnel / sealed。
- [x] 不给 domain 类型 derive Serialize（`rss_domain_no_serialize`）。
- [x] 域形 repo port 归属 ADR-005 Option 2（`identity::ports`，非 diport）。
- [x] 新契约走 contract-fanout 闭环。
- [x] 不新增 Soft 治理机制。

## 对标

- [x] 有真实 `ref:`（`casbin/casbin-rs src/effector.rs@fc425d4` deny-overrides + `src/model/default_model.rs` RBAC），实拉源码。
- [x] 偏离理由记录（typed operator 枚举 vs Polar DSL；typed 域类型 vs 字符串策略矩阵；更严 fail-closed 缺省）。

## 待实施期确认（非 spec 阻塞）

- [ ] `secure` crate 是否已提供 argon2/bcrypt（PR3 实施时确认；未提供则最小封装 + ref）。
- [ ] `vocab::Decision` 是否需 Obligations/FieldMask（PR2 实施时确认；需要则最小扩展 + PR body 标注）。
- [ ] 端点最终集合（PR5 实施时按 gocell accesscore 映射定稿，data-model.md 表为锚点）。
