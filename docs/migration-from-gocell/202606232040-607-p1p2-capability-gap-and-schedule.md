# RSS 能力盘点 · P1/P2 缺口分析 · 实施排期

> 生成日期：2026-06-23 · 输入：83 个 P1/P2 work item + `deep-research-report.md`（Rust 企业级平台内核愿景）
> 对照现状。配套：[gocell-rewrite-sequence.md](./gocell-rewrite-sequence.md)（G0→G1→W→Join 阶段模型）·
> [架构单源 docs/rules/architecture.md](../rules/architecture.md) · epic #991 `pm:epic-wave` 评论（滚动 wave 单源）。
> 本文件是本轮缺口识别 + 排期的溯源快照。

## 0. 定位

RSS = GoCell 的 Rust greenfield 重写，domain-native 治理框架，pre-GA 无外部 wire 消费方。迁移模型
**G0 接缝冻结(临界路径) → G1 追踪弹验接缝 → W 宽扇出 → Join 单点收敛**。当前：**G0 已冻结、G1(#999) 已绿**，
W 部分完成（base #1000 + httpserve/authn/bootstrap/observ #1002/1003/1004/1006 = Done），其余服务/域/adapter/
eventexec/Join 为 New。

## 1. 当前能力盘点

处于「接缝冻结 + 追踪弹绿」阶段——**签名已冻结、body 多为 `todo!()`**。Feature 标 Done 多指其签名冻结 PR
或 W 切片 PR 已合，非整 crate body 完工。

- **已有真实 body（约 28–30 crate）**：基础 vocab/ids/secure/support/runctx 全实；引擎 primitives 实、consistency
  的 idempotency/outbox 接口冻结（saga/reconcile/projection body 仍 `todo!()`）；diport 基本实（audit_sink 余 1 处 todo）；
  服务 httpserve/authn 较实、observ 已实（#1006）、bootstrap shutdown/registry 核心实（domain 组合根余 todo）、eventexec 部分；
  域 identity/audit application 切片实；adapter memory 全实、**postgres 已有连接池/migrator/tx body**（#1009 In-Progress，
  `todo!()` 仅存于 `#[cfg(test)]` 的 RoleRepo edge proof）；generated/xtask/journeys 实。
- **仅签名冻结 stub（约 20 crate）**：consistency 的 saga/reconcile/projection body、distributed/deviceloop；域 domain 模块
  （identity RBAC/ABAC、settings、audit 哈希链、contractreg、syshealth）；**其余 11 个外部 adapter**
  （redis/amqp/mqtt/oidc/vault/softca/grpc/otel/prometheus/ratelimit/s3）4–7 行 stub。
- **能跑通**：`journeys/tests/identity_login_audit_journey.rs`——identity 登录 → in-mem outbox → audit append 绿。
  **做不了**：生产持久化、真实 JWT 签验/密码哈希、分布式协调、可观测链路、任何部署。
- **治理底座成型**：deny.toml 分层禁依赖 + clippy disallowed-* + dylint 自写 lint + xtask
  layer-deps/contract/codegen + insta golden + cargo public-api/semver-checks。

## 2. P1/P2 issue 分析（83 项）

状态分布：Done ≈ 38、New ≈ 23、Approved ≈ 18、Removed ≈ 4。结构性观察：

1. 瓶颈从「签名冻结」转移到「W body 并行铺开」。剩余 New 主体 = eventexec(#1114–1124)、域(#1012–1016)、
   adapter(#1009–1011)、distributed(#1007)、deviceloop(#1008)、Join（已由 #1249–#1257、#1320 等分解闭合；runtime 聚合子项 #1431）。
2. eventexec(#1005) 已 speckit-002 拆成 11 PBI(#1114–1124，Hierarchy 子项 + 4 wave)，但 epic wave 快照仍以
   #1005 粗粒度记账——本轮排期已下钻纳入。
3. 大量 Approved/New 治理硬化 follow-up（#1034/1036/1039/1054/1055/1057/1077/1087/1090/1092/1095/1097/1101/
   1103/1105/1109/1110/1113）**不在交付临界路径上**，应**随对应 crate W body 搭车**，不独立占 wave。
4. authn/identity/audit/tenancy 接缝与规则真实，但**外部 adapter 全 stub**——安全「声明完整、落地为零」。
5. CI / 部署 / 契约测试 harness / 零信任底座选型 4 类系统性盲区**0 个 issue 覆盖**（见 §3）。

## 3. 设计缺陷与未规划好的能力（对照 deep-research-report）

### A. 真实缺口 → 本轮已登记（Feature #1131 下 9 个 PBI）

| 缺口 | 证据 | 新 issue |
|---|---|---|
| CI/CD 未落地 | `gocell-rust-ci-plan.md` 归档·冻结；无 pipeline 文件；`AZURE_HAS_CI=false`；治理全靠本地 `make verify`——AI 协作下无自动门 | **#1132**(p1) |
| 供应链安全门未落地 | ci-plan 设计 `cargo-deny advisories`+`cargo-audit` 无 live lane | **#1133**(p2) |
| 云原生部署产物缺失 | 无 Dockerfile/deploy/Helm/K8s；syshealth 探针无 manifest 接线 | **#1134**→**#1135**(p2) |
| 契约/集成测试 harness 缺失 | domain-patterns 要求 per-contract 测试，仅 1 条 journey；无 testkit/testcontainers | **#1136**→**#1137**(p2) |
| 零信任底座选型未决 | docs 全无 opa/rego/spiffe；当前内置 authplan/PDP + service-token | **#1138**(OPA,p1) · **#1139**(SPIFFE,p1) |
| wire 破坏式变更检测门仅概念 | api-versioning 有 pre-GA 窗口(至 2026-12-31)+cargo public-api(轴 A)，但 wire(轴 B) 无 Buf 式自动门 | **#1140**(p2) |

### B. 报告提到但有意识延后/超范围（不登记，备查）

- **MDM 业务内核**（血缘/match-merge/survivorship/golden record/质量 DSL/参考数据）——报告自身明确为业务能力，
  框架只供执行骨架；settings crate 已覆盖版本化配置。延后到平台稳定后的业务域阶段。
- **ES snapshot/temporal query**——projection replay 已在 eventexec #1122；完整快照按「选择性采用」延后。
- **Wasm 沙箱/热加载、Actor(ractor)、AI Provider SPI、外部 gRPC/grpc-web**——报告自评低优先级，Phase 2+ 或按需。

## 4. 实施排期

MVP 边界 = **可部署·durable 单进程平台**：W body + eventexec **L0–L2** + 核心 adapter(pg/redis/amqp) +
域(identity/audit/settings/syshealth) + Join durable journey + CI + Dockerfile。
**Phase 4 延后**：L3/L4(saga #1121/projection #1122/reconcile/command #1124)、deviceloop #1008、distributed #1007、
device/rest adapter(#1010/#1011 除 oidc/vault)、wire-gate #1140、按 ADR 落地的 OPA/SPIFFE 实现。

> 滚动 wave（≤4/wave 容量装箱、pri 优先、Done 不动）以 epic #991 `pm:epic-wave` 评论为准。下为稳定相位模型。

- **Phase 0 · 即刻解锁（无代码依赖、最高杠杆）** — 并行 3：`#1138(ADR-OPA)` ∥ `#1139(ADR-SPIFFE)` ∥
  `#1132(CI 核心 lane)`。ADR 定 authz/服务身份方向须先于域 body 硬化；CI 给 W 大并行兜底自动门。
- **Phase 1 · W 地基 / eventexec wave1（durable 底座）** — 真并行最大独立组 = 4：`#1114(consistency L0–L2)` ∥
  `#1116(postgres 基座)` ∥ `#1009(adapters core·redis)` ∥ `#1009(adapters core·amqp)`（#1009 = pg/redis/amqp umbrella，
  In-Progress，可按 provider 切并行）→ 串 `#1115(consistency L3–L4 类型)`。
- **Phase 2 · W durable 主干 / eventexec wave2–3 + 域铺开（最大并行点）** — 容量装箱 4/wave：
  脊柱 `#1117(outbox+relay+sweeper)` ∥ `#1118(idempotency)` ∥ `#1119(amqp transport)` → `#1120(ConsumerBase+DLX)`
  → `#1100(durable 闭环)`；域并行 `#1012 identity(+#1109/#1110)` ∥ `#1014 audit` ∥ `#1013 settings` ∥
  `#1016 syshealth`；`#1136(testkit)` 随域并行。
- **Phase 3 · Join 收敛 → 🏁 MVP** — 并行 4：`Join（已由 #1249–#1257、#1320 等分解闭合；runtime 聚合子项 #1431）` ∥ `#1133(供应链门)` ∥ `#1137(testcontainers)` ∥
  `#1134→#1135(Dockerfile→K8s/Helm)`；`#1015 contractreg`（无功能 blocked-by、优先级最低域 crate，容量有余追加）搭车。
  **MVP = 可部署·durable·治理绿单进程平台**。
- **Phase 4 · Post-MVP（L3–L4 + 设备 + 分布式 + 零信任落地）**：`#1121 saga` ∥ `#1122 projection(需 #1121)` ∥
  `#1124 command`+reconcile；`#1008 deviceloop`+`#1010(mqtt/softca)`；`#1007 distributed`；`#1011 其余 adapter`；
  `#1140(wire-gate，2026-12-31 前)`；按 #1138/#1139 决策落地 OPA/SPIFFE adapter。

### 最大并行结论

- **单一最大并行点 = Phase 1–2（W 宽扇出）**：迁移模型称 ~25 单元扇出。硬约束脊柱 =
  `postgres 基座(#1116) → outbox/idempotency → consumer → durable 闭环(#1100) → Join（已由 #1249–#1257、#1320 等分解闭合；runtime 聚合子项 #1431）`，其余全挂脊柱旁并行。
- **实际同时活跃 = 4**（≤4/wave 容量装箱，pri 优先）；真并行独立组示例 = Phase 1 的
  `{consistency-L0L2(#1114), postgres(#1116), redis/amqp(#1009 umbrella)}`。

## 5. 本轮登记产物

Feature **#1131** `[RW-W-infra] 平台工程底座`（← epic #991，标签 area-tooling·pri-p1，容器层不带 cx/type）下 9 个 PBI：

| # | issue | area·pri·type |
|---|---|---|
| #1132 | CI lane（make verify 全门） | tooling·p1·enhancement |
| #1133 | 供应链安全门 lane | tooling·p2·enhancement |
| #1134 | bins/server Dockerfile | tooling·p2·enhancement |
| #1135 | 最小 K8s/Helm + 探针接线 | tooling·p2·enhancement |
| #1136 | platform testkit + per-contract 模板 | tooling·p2·enhancement |
| #1137 | testcontainers adapter 真集成 | data·p2·enhancement |
| #1138 | ADR 外置 PDP(OPA) vs 内置 authplan | auth·p1·arch-opt |
| #1139 | ADR 服务身份 SPIFFE/mTLS vs service-token | auth·p1·arch-opt |
| #1140 | ADR wire 破坏式变更检测门 | tooling·p2·arch-opt |

> **标签规范**（`hack/automation/issue-labels.sh validate` 闭值集，建单须经此 funnel）：容器层 Epic/Feature 只带
> `area/pri/backlog`、**不带 `cx-*`/`type-*`**；PBI 叶子四轴齐全，`type-*` 取闭值集
> （`enhancement/bug/refactor/arch-opt/doc/test/debt/fu`，**无 `type-feat`**）。本批登记初次经 `forge.sh issue-create`
> 误贴 `type-feat` / 容器叶子标签，已按 validator 校正（PR #201 fix）；根因「issue-create 写路径未强制 validator」另立 issue 跟踪。
