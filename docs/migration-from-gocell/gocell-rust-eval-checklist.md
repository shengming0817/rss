# GoCell 以 Rust 为主：软件工程 / 系统工程评估清单

> **归档·冻结** · 2026-06-21 GoCell→Rust 迁移评估快照（target 命名已对齐 RSS）· **非现行规则**。
> 现行架构单源见 `Cargo.toml`、`xtask/src/layers.rs`、`deny.toml` 与 `cargo xtask layer-deps`；本批只读冻结，仅供迁移评估溯源。
>
> 生成日期：2026-06-21 · 前 6 篇覆盖技术层（取舍/结构/顺序/CI/迁移方案）；本篇补方法论盲区——按"是否阻塞放行 W 宽扇出"分级
> 配套文档：[gocell-package-overview.md](./gocell-package-overview.md) · [gocell-rust-tradeoff.md](./gocell-rust-tradeoff.md) · [gocell-rewrite-sequence.md](./gocell-rewrite-sequence.md) · [gocell-rust-crate-mapping.md](./gocell-rust-crate-mapping.md) · [gocell-rust-directory-structure.md](./gocell-rust-directory-structure.md) · [gocell-rust-ci-plan.md](./gocell-rust-ci-plan.md)

## 定位

已产出 = 技术层（Go↔Rust 取舍、crate 映射、目录结构、9 阶段顺序、最大并行迁移方案、CI 适配、rss epic #991 + 25 Feature）。本篇是**方法论层面仍未评估的维度**：每项给「评估什么 / 为什么 / 产出物·方法」，末尾给放行 W 宽扇出前的 gating 子集。

---

## A. 立项与决策依据（gating）

| 项 | 评估什么 | 产出物 · 方法 |
|---|---|---|
| A1 决策记录 | 是否真要全量重写——非"技术上更自洽"而是"加权后净收益为正" | go/no-go ADR + **加权 trade study**（备选：留 Go 收紧治理 / 仅 L4 边缘 Rust / 全量 Rust） |
| A2 成功标准 | 程序级 DoD（可度量），不止 per-Feature close | 量化验收（性能/安全/覆盖/journey 全绿）写进 epic |
| A3 退出/回退 | 卡在 60% 怎么办；沉没成本暴露 | 阶段性 kill-criteria + 回退到 Go 的判据 |
| A4 second-system | "never rewrite from scratch"（Spolsky）/ 第二系统效应 | 显式风险条目 + 缓解（追踪弹先验、薄切片） |

## B. 迁移 / 切换与兼容（gating · 可能颠覆 greenfield 假设）

| 项 | 评估什么 | 产出物 · 方法 |
|---|---|---|
| B1 与 gocell 关系 | 替换 / 共存？有无运行实例与**生产数据**？ | 明确 greenfield vs strangler；有数据则补**数据迁移**方案 |
| B2 cutover | big-bang vs 增量；回滚 | cutover plan + rollback runbook |
| B3 wire 兼容 | 过渡期 Rust↔Go/TS 互通需 byte 兼容（rss 已有 #735/#754 wire 议题） | 契约 byte-parity 测试；过渡期版本目录策略 |
| B4 切换验证 | shadow / dual-run / 差分流量 | 影子流量比对而非一刀切 |

## C. 安全与威胁模型重做（gating · zero-trust/MDM）

| 项 | 评估什么 | 产出物 · 方法 |
|---|---|---|
| C1 威胁模型 | gocell 安全模型（RLS/ABAC/tenant 隔离/mTLS/fail-closed）**不随类型系统自动迁移** | **重做 STRIDE / 威胁矩阵**，逐 ADR 重评安全属性 |
| C2 逻辑安全 | Rust 只保内存安全，不保越权/跨租户读/授权旁路 | 安全用例（negative test）独立于编译保证 |
| C3 secrets/PKI | PAT / CA 私钥 / key provider 在 Rust 栈落点与 fail-closed | 密钥管理 ADR + 启动期 fail-fast |

## D. V&V / 正确性保证（高杠杆）

| 项 | 评估什么 | 产出物 · 方法 |
|---|---|---|
| D1 等价/差分 | journeys & fixtures 语言无关 → 同时驱动 Go 与 Rust 比对输出（迁移期最强 oracle） | 差分测试 harness，纳入 G1 追踪弹设计 |
| D2 属性/模型 | L3/L4 状态机（saga/outbox/reconcile）不变量 | **proptest** + lock-free 用 `loom` + 协议级可选 TLA+ |
| D3 oracle 充分性 | journeys 是否覆盖 L0–L4 语义边界 | 验收覆盖审查 |

## E. 质量属性 / NFR（systems-eng -ilities）

| 项 | 评估什么 | 产出物 · 方法 |
|---|---|---|
| E1 性能/容量 | tradeoff 称性能"次要"但无度量 → 无基线无法证明低足迹兑现 | **criterion** 基准 + 预算 + 回归门 |
| E2 可靠性 | L4 设备闭环 / reconcile 失效模式 | **FMEA** + SLO |
| E3 可运维性 | dashboard/alert/runbook（gocell 有 saga-runbook）、probe 命名运维契约、发布/回滚演练 | 运维就绪评审 |
| E4 资源足迹 | 内存 / 二进制大小（Rust 卖点需量化） | 足迹目标 + 度量 |

## F. 过程 / 项目治理（PM 严谨度）

| 项 | 评估什么 | 产出物 · 方法 |
|---|---|---|
| F1 风险登记册 | 风险目前散在各文档，无集中册 | **risk register**（likelihood×impact×mitigation×owner） |
| F2 阶段评审门 | G0 签名是一个；缺 G1 后 go/no-go、每 wave review、Join 收敛门 | stage-gate 评审清单 |
| F3 估算/排期 | 临界路径时长、**AI 迭代速度**（慢编译税累积）、**token 成本预算**（全量重写对 AI 是大账） | 临界路径估算 + AI 速度/成本基线 |
| F4 配置/发布 | rss 仓分支策略、版本、forge 目标（rss vs gocell）长期归属 | 配置管理 ADR |

## G. 依赖 / 供应链选型治理

| 项 | 评估什么 | 产出物 · 方法 |
|---|---|---|
| G1 选型 trade study | sqlx vs sea-orm、fred vs redis-rs、runtime 等：维护性/许可/审计/MSRV/传递依赖/锁定 | 选型 ADR（cargo-deny 管许可+漏洞，但理由要单独定论） |
| G2 生态成熟度 | otel-rust 动荡、CodeQL-Rust preview、AFIT 的 dyn 限制 | 登记为风险条目（接 F1） |
| G3 构建可复现 | MSRV / edition / toolchain 固定 | rust-toolchain.toml + MSRV 策略 |

## H. 知识迁移 / 可持续

| 项 | 评估什么 | 产出物 · 方法 |
|---|---|---|
| H1 制度知识 | gocell 的 ADR / archtest godoc / rules **重定位**（非丢弃） | rss 的 ADR/guide/rules 目录 + 迁移映射 |
| H2 AI 连续性 | AI-implementer 跨会话连续、文档作为单源 | rss 文档架构 + memory/ADR 约定 |

---

## 放行 W 宽扇出前必须先评的 4 个（gating）

1. **A 立项决策 + trade study** — 否则在未定前提上扇出 30 单元。
2. **B 迁移/共存/数据/wire** — 可能直接颠覆 greenfield 假设（进而改 G0/G1）。
3. **C 安全威胁模型重做** — 零信任不可后补，且会反推 trait 签名（影响 G0 冻结）。
4. **D 等价性验证策略** — 决定 G1 追踪弹与 journeys 的 oracle 设计。

E / F / G / H 可与 W 同波推进，但 **F1 风险登记册 + F2 阶段评审门应在 G0 就立**（对应"引入约束同 PR 闭环 / 治理早立"原则）。

> 落地建议：A–D 可作为 rss epic #991 下的**前置 Feature**，blocked-by 接到 G0/G1 之前；E–H 作为贯穿 Feature 与 W 同波。
