# L3 一致性生产闭环需求基线

**状态**：已吸收，待 #1913–#1929 分步实现

**外部输入日期**：2026-07-14

**仓库吸收日期**：2026-07-29

**Epic**：#1911

**基线与裁决 owner**：#1912

本文只持有 L3 production closeout 的需求标识、边界和验收意图。当前实现事实与外部 snapshot 的差异见
[`source-baseline.md`](source-baseline.md)，单一 PBI 与最低充分验证 owner 见
[`traceability.md`](traceability.md)，logical data identities 见 [`data-model.md`](data-model.md)。

项目范围、分层、现有 contract 生命周期、投递语义、assembly 和 CI inventory 不在本文复制，分别以
[`project-scope.md`](../../rules/project-scope.md)、[`architecture.md`](../../rules/architecture.md)、
[`contracts/README.md`](../../../contracts/README.md)、[`eventbus.md`](../../rules/eventbus.md)、
[`saga.md`](../../rules/saga.md) 与机器 registry 为准。本文不是 enforcement carrier；后续 PBI 必须把约束落到
类型、schema/codegen、provider conformance、真实 adapter 或 production journey 中。

## 目标

在不改变 Settings v4 authoritative path 的前提下，把现有 Projection/Saga L3 primitive 闭合为：

- assembly 显式激活、disabled/omitted 零副作用；
- tenant-safe、metadata-only、可 replay/promote/rollback 且实际服务 Settings v3 eventual query 的首个
  active Projection；
- 具备 definition pinning、durable receipt、unknown-outcome 恢复与 fencing 的 Saga adoption safety；
- 只声明 at-least-once delivery + scoped idempotent effect，不声明 active/runtime exactly-once；
- 每个独立 hazard 只有一个最低充分 T1/T2/T3 主证明，并合并进既有 typed CI/evidence 流程。

## 当前必须保持的边界

- `settings.config-projection` v3 仍为 draft，直到 #1913–#1921 逐步满足激活条件。
- Settings v4 `settings.config-get` 保持 active、LocalOnly、authoritative；pointer 变化不得影响其 contract 或数据路径。
- `billing.checkout` 保持 draft、未生产激活/接线；generated/test fixture 可以保留，但不得据此宣称 billing capability。
- billing 产品、Temporal/BPMN、workflow 管理 UI/API、通用 CI/runner 平台、托管监控与数据库运维面均在范围外。
- 全局 commit-order lock 在容量证据触发 X01 前保留；普通 sequence 不能替代 commit-order 证明。
- LOC 只作设计拆分与 review 信号，不建立 Markdown、行数或 case-count enforcement。

## Functional Requirements

### Activation 与 assembly

- **FR-001**：contract lifecycle 与 assembly activation 必须是两个独立维度。
- **FR-002**：Projection activation 必须是闭值 `disabled | capture-only | shadow | active`。
- **FR-003**：Saga activation 必须是闭值 `disabled | active`。
- **FR-004**：未声明、omitted 或 disabled workflow 对 runtime、DB capture、worker、route 和 serving 必须零副作用。
- **FR-005**：`draft + active` 必须非法；不得以 runtime flag 或手写旁路豁免。
- **FR-006**：shadow/active Projection 缺 source、target、checkpoint、DLQ、worker 或 probe 时必须在启动前失败。
- **FR-007**：active Saga 缺 typed actions、journal、instance/receipt/checkpoint/dead-letter store、lock/fencing、worker 或 probe 时必须在启动前失败。
- **FR-008**：global generated catalog 只描述 definition，不决定 assembly deployment activation。
- **FR-009**：production path 不得用 blanket unsupported marker 代替 active/shadow capability coverage。

### Projection storage 与 security

- **FR-010**：Projection serving、writer、reader 与 operator 必须使用最小且互相区分的 capability。
- **FR-011**：通用 serving capability 不得读取 raw projection source payload。
- **FR-012**：source read 必须在数据库边界按 tenant、projection 与 definition/generation binding 收窄。
- **FR-013**：status/promote 所需 high-water 必须是 O(1) 或固定查询次数，不得扫描历史事件。
- **FR-014**：相关 `SECURITY DEFINER` 函数必须固定 `search_path`、校验参数并撤销 `PUBLIC` 权限。
- **FR-015**：Settings Projection V1 read model 必须 metadata-only，不得保存 config value、secret、token 或 raw payload。
- **FR-016**：Settings read model 必须启用 RLS/FORCE RLS，并按 tenant/generation/source-event 保持唯一与隔离。
- **FR-017**：target dedupe receipt 与 read-model mutation 必须在同一本地事务中提交。
- **FR-018**：每个 production ProjectionTarget 必须通过唯一 canonical conformance suite。

### Projection execution 与 serving

- **FR-019**：shadow/active Projection worker 必须由 assembly 正式拥有 start/readiness/drain/shutdown 生命周期。
- **FR-020**：worker fatal exit 不得静默，必须使 readiness 失败并留下诊断证据。
- **FR-021**：lag、checkpoint age、apply failure、DLQ backlog 与 replay throughput 必须使用低基数指标。
- **FR-022**：promote 前必须验证 target health、definition/schema identity 与 selected high-water catch-up。
- **FR-023**：active pointer 必须以 CAS/fencing 方式更新。
- **FR-024**：Settings v3 eventual query 必须经 typed active-pointer resolver 选择 generation。
- **FR-025**：一个 request/unit of work 必须绑定一个 generation snapshot，不得中途混用 generation。
- **FR-026**：Settings v4 authoritative contract、handler 与数据路径必须保持不变。
- **FR-027**：operator 必须通过受控 surface 提供 status、pause/resume、replay、promote/rollback，并执行 authz/audit。
- **FR-028**：只有容量基准越过明确阈值，才可创建 X01 设计替换全局 commit-order lock。

### Saga correctness

- **FR-029**：每个 effectful step 必须声明 receipt schema、idempotency class、compensation input 与 retry class。
- **FR-030**：idempotency key 必须从 tenant、instance、pinned definition、step 与 effect scope 确定性生成。
- **FR-031**：durable receipt 必须持有 external operation identity 与恢复所需的受保护 output/reference。
- **FR-032**：receipt 与 Completed/Compensated journal transition 必须原子可见，或具有等价、可证明的恢复协议。
- **FR-033**：同 receipt key 的内容或 digest 冲突必须 fail-closed 并进入 operator-required 状态。
- **FR-034**：resume/compensate 必须从 durable receipt 恢复 typed input/reference，不得从新 action 猜测。
- **FR-035**：effect outcome unknown 必须显式持久化并 probe/repair，不得作为普通 transient 盲重试。
- **FR-036**：Saga instance 必须固定 definition ID/version/schema digest 与 action registry generation。
- **FR-037**：retry 必须有 attempt/time budget、backoff/jitter 与闭合 retryability 分类。
- **FR-038**：stale lease/epoch worker 不得写 receipt、journal、checkpoint 或终态。
- **FR-039**：`billing.checkout` 在真实 domain/provider/assembly adoption 前必须保持 draft 且未激活。
- **FR-040**：production Rustdoc、API 与运维文档不得声明 active/runtime exactly-once Saga execution。

### Evidence 与 CI

- **FR-041**：Projection 真实后端证明必须覆盖其独立 commit-unknown、pointer race、rollback、cross-tenant 与 multi-worker hazard。
- **FR-042**：Saga 真实后端证明必须覆盖 effect/compensation uncertainty、lease loss、receipt conflict、retry exhaustion 与 old-definition resume。
- **FR-043**：fixture、runner 与 evidence receipt 必须 exact parity；一个 invariant 只有一个主证明。
- **FR-044**：active L3 变更必须由既有 impact planner 选择其 affected activation/security/fault/assembly owner，不新增平行 lane。
- **FR-045**：active forge 具备完整 CI 后，既有 aggregate gate 才启用 same-head required check；当前 Azure 窄 CI 不得被误写为已满足。
- **FR-046**：外部 pack 的 LOC blocking gate 被裁决为非约束；PR 规模只作设计拆分与 review 输入，不产生行数 enforcement。

## Non-Functional Requirements

- **NFR-001 Security**：跨租户 read/mutation、stale writer 与越权 operator 必须 fail-closed。
- **NFR-002 Privacy**：read model/receipt 默认不保存敏感明文；日志、Debug 与指标不得泄露 payload/tenant 高基数值。
- **NFR-003 Availability**：worker crash 必须可见；serving 在 promote 失败时继续使用上一 active generation。
- **NFR-004 Recoverability**：Projection 可从 source 重建；Saga 可从 pinned definition、journal 与 receipt 恢复到明确状态。
- **NFR-005 Performance**：high-water 固定查询次数；resolver 额外延迟目标由 #1922 的可重复基准和 SLO 持有。
- **NFR-006 Scalability**：容量基准必须测量 lock wait、tenant fairness、throughput 与业务事务延迟。
- **NFR-007 Operability**：人工操作只经窄、授权、审计、fenced 的 API/CLI，不要求直接修改数据库。
- **NFR-008 Compatibility**：Settings v4 authoritative contract 不发生 breaking change。
- **NFR-009 Evolvability**：Projection generation 与 Saga definition identity 必须显式、版本化、可审计。
- **NFR-010 Reviewability**：依赖、owner 与 evidence 可机器追踪；不以 LOC、Markdown 或 case 数量充当证明。

## Success Criteria

- disabled/omitted workflow 的 runtime、DB、worker、route 与 serving 零副作用证明通过。
- Settings metadata Projection 在 production-capable assembly 中完成 shadow、active、promote/rollback 与 v3 serving journey。
- Settings v4 authoritative regression 保持不变。
- Projection 与 Saga 的 cross-tenant、uncertainty、fencing 和恢复 hazard 各有唯一最低充分主证明。
- Saga platform 达到 ready-for-adoption，但 `billing.checkout` 不出现在 active inventory/evidence 中。
- L3 evidence 合并既有 typed planner/gate；当前 forge 能力不足之处保持条件性，不制造“已 required”假结论。
