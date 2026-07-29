# Issue #1836 settingsonly L2 Production Assembly 收敛计划

**Branch**: `feature/1836-settingsonly-l2-production` | **Date**: 2026-07-29 | **Tracking**: #1836

## 目标与范围

#1836 的交付边界是把 `settingsonly` 收敛为无 demo fallback 的 L2 production assembly：

- `settingsonly` 只生成并启动 production / durable-isolated topology；缺失持久 provider 时在监听前失败，运行期必要依赖失败时 readiness 为非 ready。
- Settings publish/delete/rollback 进入同一 PG business transaction + outbox funnel，经 settings 专属 AMQP 发布 fact，再由 AckableSubscriber + `PgSettingsConsumerTx` + inbox 完成消费和去重。
- SIGTERM 先停止新 delivery，再允许在途 ConsumerTx commit/Ack，最后由现有 runtime LIFO 关闭 channel/connection。
- production provider 使用 PG、settings AMQP、Redis、Vault 与 S3/WORM；不允许 demo、ephemeral provider、ambient secret 或共享 AMQP fallback。
- settingsonly 的 Federated JWT 使用 typed permission，并对 Settings 路由执行 permission/tenant 精确授权；inventory 仅执行精确 permission 授权。

本 PR 不做全 workspace readiness 重构；但六维首审批量处置决定在当前 PR 内统一 Settings/Redis provider readiness ownership，因此允许共享 provider schema、runtime 与 identityaudit 为同一 typed receipt funnel 做必要联动。仍不以自建 Docker 编排脚本替代现有分层测试。

## 四原则复核

- **彻底**：删除 settingsonly demo/fixed-403/nonactivated subscriber/fallback，闭合真实 outbox→AMQP→ConsumerTx/inbox 与 provider/readiness/drain 链路。
- **不向后兼容**：Federated permissions、settings config 与 AMQP cancel 采用新语义，不保留旧 token shape、构造器、channel-close-on-token 或配置 alias。
- **优雅简洁**：只复用现有 PG/AMQP/Redis/Vault/S3、ConsumerTx、runtime lifecycle 和 assembly codegen；不新增框架、crate、migration、runtimeexec API 或独立编排层。
- **AI-HARD**：typed Federated evidence、非可选 production receipts 和 generated assembly closure 承载 Hard 约束；settingsonly 专属 static/golden gate 承载无法类型化的 run-reachable closure，并包含 synthetic-red/anti-vacuity。

## 当前状态与最小增删范围

### 保留并收敛

1. `assemblies/settingsonly/**`：production provider closure、readiness、DLX/S3、eventing activation 与两阶段 drain。
2. `adapters/amqp/**`：persistent delivery mode、稳定 consumer tag 的 `basic_cancel`、cancel/Ack 串行化与 publisher/subscriber readiness。
3. `composition/eventing/**`、`crates/eventexec/**`：ConsumerTx 在取消后完成当前 transaction/proof/Ack，并停止领取下一条 delivery。
4. `composition/settings/**`：三个 CUD operation 的同事务 outbox 与稳定 event ID。
5. settingsonly 必需的 Federated typed-permission funnel和 `xtask/src/assembly.rs` production closure gate。
6. adapter 层 AMQP/Redis private-CA integration tests；它们直接验证各自 transport，不引入第二套 production assembly。

### 删除或联动边界

1. runtime/identityaudit 只允许因 Settings Vault、auth-audit 与 Redis provider receipt 输出统一而产生的必要联动；禁止附带其他 assembly 重构。
2. `crates/assembly-schema/src/provider.rs` 将上述共享 active provider role 收敛为统一 P/R/W 输出，并重新生成三套受影响 artifact。
3. 将 `xtask/src/assembly_lock.rs` 的 Generate-mode 自举放行收窄为唯一的
   `settingsonly field=lock-runtime-plan` stale finding；Check 模式及其他 finding 继续 fail closed，并以反误放单测守住。
4. 删除 journey 专用日志级别抬升；产品代码日志恢复原有级别。
5. 删除已提交的 settingsonly private-CA Docker journey wrapper及其 Cargo/shard 注册；保留 adapter integration coverage。
6. 不恢复已经删除的 monolithic `settingsonly-production-journey.sh` 和 `settingsonly_production_runtime.rs`。

### 唯一允许新增的 journey

如现有测试无法承载 issue 的三项端到端验收，仅新增
`journeys/tests/settingsonly_l2_production.rs`，且只覆盖：

1. publish/delete/rollback → outbox fact → AMQP → inbox done；
2. delivery-before-Ack 重启后相同 event ID 去重；
3. SIGTERM 后不领取第二条消息，在途 transaction commit/Ack 后退出。

该 journey 不重复覆盖 outage matrix、TLS/WORM、JWT/config schema、SPIRE、镜像构建、shell grep 或 assembly artifact 检查；不新增 Docker 编排脚本和 CI shard。

实施盘点结论：不新增该文件。真实 AMQP cancel/Ack integration、ConsumerTx terminal-proof/去重单测、Settings CUD/outbox 测试与现有非 Docker `settingsonly_runtime` SIGTERM journey 已形成分层证据；再建全后端 carrier 会重复引入独立编排面，不符合本次最小收敛范围。

六维首审批量处置：真实五后端 production journey 明确 defer，后续以独立 issue 跟踪；本 PR 不恢复 Docker carrier。
跟踪项已创建为 #1875（`[1836-FU] settingsonly 五后端 production journey`）。

## 测试发现与处置

1. **S3 readiness 恢复**：required probe 保持 fail closed，成功探测可恢复 Healthy；已由定向单元测试覆盖，不再扩大修改。
2. **偶发 PG writer acquire 30 秒失败**：仅在已删除的历史 full journey 两次出现、随后未复现。当前没有产品根因证据；不增加 fallback、重试框架，也不继续循环完整 journey。
3. **完整 CI 首轮结果**：唯一一次 `make ci` 暴露 assembly graph drift、event transport guard、runtime baseline、runtime deps guard、L2 assurance 五个失败门；一次性按根因批量修复。
4. **CI 修复范围**：只增加 ConsumerTx 所需的 move-only PG inbox/DLX bundle、精确 readiness deps policy 例外，并同步 AMQP 双 TLS 连接 owner 的现有 guard 与生成/baseline artifact；未修改 runtimeexec API 或恢复 Docker carrier。
5. **复核结果**：上述五个失败门已在同一条 targeted verify 中全部通过；guard green/red、settingsonly 51 个单测和相关 crate 编译通过。遵守一次完整 CI 预算，不再运行第二次 `make ci`。
6. **验收 carrier**：复用已有 adapter/assembly/ConsumerTx tests；五后端 production journey 已独立 defer 到 #1875。

## 实施复核记录

- provider ownership 已收敛：Settings PG/Vault 与 Redis 的 probe/resource/worker 由同一生成 receipt 持有；runtime、identityaudit、settingsonly 的 manifest/lock/runtime-plan/generated code 已同源再生成。
- Settings composition 已删除 embedded/preverified 双构造路径，只保留非可选 `SettingsReadinessDeps` 构造；required PG saturated、Vault Forbidden 均 fail closed，并验证恢复。
- settingsonly startup transaction 已在异步下游验证前取得 PG、AMQP 与 DLX Vault resource 的 rollback owner，成功完成 role closure 后才激活运行期 owner。
- AMQP cancel integration 已改为第二条消息在 cancel 前排队，证明 broker cancel barrier 后旧 consumer 不再领取，而替代 consumer 可继续处理余量。
- Vault client 显式禁用 built-in roots/proxy，仅信任配置的 private CA；secret bundle 对缺失、未知、空字段给出不含值的结构诊断。
- runbook 已同步 exact inventory permission、Primary authorizer、闭合 secret 字段和 AMQP/Redis/S3 CA mounts。
- Medium gate 已剥离字符串字面量证据并加入 string-bait synthetic red；真实 workspace anti-vacuity、assembly validate 与 lock drift check 通过。

## 再审处置（PR #608）

- 再审基于旧 HEAD `e2187793`；对仍适用于当前实现的 finding 逐项复核，不因 stale HEAD 直接丢弃。
- Cx3 批量处置两分钟无人工回答，按项目约定采用“最小当前 PR 范围”：
  - 当前 PR：删除 request extension 中无人消费的完整 `VerifiedFederatedAccess`；Settings composition 增加私有闭值 route surface，settingsonly 仅挂 publish/delete/rollback；保留已批准的破坏性 non-empty typed-permission profile，不恢复旧 token shape。
  - 当前 PR：保留独立 runtime-plan drift gate和 settingsonly exact closure facts。二者分别约束 manifest/lock 未覆盖的 listener auth/placement artifact 与“额外 provider/config”拒绝语义；合并或删除会削弱本计划明确要求的 Medium synthetic-red，不按“门数量”做表面删除。
  - defer #1876：publisher/subscriber AMQP identity 与 ACL 分离；该项超出已批准的单 settings AMQP secret bundle。
  - defer #1875：五后端 production fixture 与 TLS execution receipt；不恢复 Docker journey。
  - 当前 PR 只把 container grace 改为 90 秒；通用 managed-worker primitive defer #1877，保持“不新增 runtimeexec API”约束。
- Cx1/Cx2 最小修复：runbook 补全 required probe catalog；启动 readiness timeout 输出每个失败 probe 的闭值诊断；Redis、S3/DLX key/lifecycle 只在健康状态变化时输出结构化 transition event。
- 定向验证发现 `settings --lib` 有 9 个既有 LocalOnly auth 测试返回 401；同一精确用例在干净 `develop` 复现，确认非本 PR 回归，OOS 记录为 #1878，不修改当前产品范围。
- `rss_authenticated_callsite` UI carrier 在本机因缺少 `rustc-dev/rust-src/llvm-tools-preview` 未能构建；未安装工具或循环重试。其相关 source closure 由 assembly validate 的真实 green 与 full-access/raw-reparse synthetic-red 定向通过。

## 实施 DAG

### Wave 1：范围回退与生成物收敛

- Owner: assembly/governance。
- 删除 Docker private-CA journey wrapper；统一 runtime/identityaudit/settingsonly 的 provider readiness receipt ownership，并保留且收窄 lock/runtime-plan 的必要自举放行。
- 重新运行现有 assembly generate/check，使 manifest、lock、runtime plan 和 generated Rust 同源。
- 最小验证：assembly schema/lock/production closure 定向测试。

### Wave 2：产品链路未决修复

- Owner: eventing/readiness。
- 验证并完成 S3 readiness 可恢复语义。
- 审核 AMQP cancel/Ack、persistent delivery、ConsumerTx terminal cancellation 与 settings outbox event ID；只修测试能证明的剩余问题。
- 最小验证：AMQP unit/integration、eventexec/composition tests、settingsonly readiness/lifecycle tests。

Wave 2 依赖 Wave 1 确定最终 provider closure；同一文件不并行编辑。

### Wave 3：最小验收证据

- 对照 #1836 验收矩阵盘点现有测试。
- 缺口存在时才新增一个 focused Rust journey；先观察目标失败，再实现最少 test support。
- 每个定向命令最多重复一次用于确认修复；再次失败改做根因诊断，不切回完整 journey 循环。

### Wave 4：Ship review 与交付

- 检查计划覆盖、生成物 drift 和 diff 范围。
- 创建 PR并进入 `pr-status/in-progress`，按净 diff 执行六维内置 review。
- 一次性修复 IN_SCOPE Cx1/Cx2；Cx3/Cx4 按项目规则只发起一次批量处置。
- 完成 push、冲突预检、artifact 与 label 后，唯一一次运行
  `make -C <worktree> ci CI_BASE=<active-forge-remote>/develop`。
- 切换 `pr-status/needs-review-again` 并按流程启动延迟监控。

## TDD 与验证预算

1. 单元/compile/static gate：每个行为先有精确 red/green 证据。
2. 组件 integration：仅针对 AMQP cancel/Ack、private CA、S3 readiness 和 PG ConsumerTx。
3. focused journey：仅在现有证据不足时运行，一次用于验收；失败后改跑最小复现，不反复重启整套后端。
4. 完整 `make ci`：所有实现、生成物和内置 review findings 收敛后只运行一次；若失败，失败项一次性批量修复并只复跑对应 targeted gates，不再次触发完整 CI。

## 明确不做

- 不新增 dependency、crate、migration、ADR、runtimeexec API、feature flag、shim 或 TODO/follow-up。
- 不修改 runtime/identityaudit 的业务行为；只做共享 provider readiness receipt 单 funnel 所必需的联动。
- 不新增 monolithic shell journey、Docker Compose 生产仿真、测试专用 product logging 或长期 CI shard。
- 不用文档、命名或人工 review 充当 enforcement carrier。
