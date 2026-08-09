# Implementation Plan: 首批 Standalone Components 候选发布闭环

## 本规格 PR

#2041 只固化候选范围、依赖 DAG、失败语义和 proof owner。任何 Cargo/package/API、外部 repository、RC 或发布动作均由
独立后续 PBI 交付。

## 后续交付 DAG

```text
#2043 governance -> #2046 public naming ----------+
#2048 release-check --------------------------------+-> #2050 Cargo closure -> #2051 mechanics
                                                                               |
#2044 Standalone API design ----------------------------------------------------+-> #2053 diag + final proof
                                                                               +-> #2054 trace + final proof
                                                                                           |
                                                                  #2053 + #2054 -> #2055 consumer
                                                                      |
                                                                   #2056 closeout
```

## 阶段

### Phase A — Governance 与 naming（#2043、#2046）

- 维护者确认许可证、copyright/owner、安全报告、维护责任和发布/弃用/yank/回滚流程。
- 只检查两个实际候选的公开名称；不预占未来名称，不批量改 internal crate。

### Phase B — Shared package mechanics（#2050、#2051）

- #2050 只修改候选及其最小公开依赖，计算 publish closure 和顺序。
- #2051 复用既有 release-check 验证生成、解包、workspace 外构建和 local-registry 流程；它只证明 mechanics，不拥有
  最终候选的 digest、内容或 canonical artifact verdict，也不建发布服务。

### Phase C — Candidate APIs（#2053、#2054）

- #2044 先按 [`spec.md` 的 NW-003 契约](spec.md#nw-003-规范性窄腰契约) 冻结唯一 allowlist，并以
  `DIAGCTX-NOT-AUTH-SOURCE-01` 提供当前最低充分静态边界；不提前修改 publish/selection 或实现候选 façade。
- 两个 PBI 在 #2044 与 #2051 完成后并行，各自拥有独立 crate/API/test 文件，并从完成后的同一 revision 生成 `.crate`
  与执行 workspace 外 canonical proof；API 改动会使先前 artifact proof 失效。
- diag candidate 固化诊断 context 的 fail-open、非授权边界。
- trace candidate 固化验证后的 TraceParent、SDK 隐藏、闭值诊断 outcome 和 malformed/roundtrip 行为。
- 两项均直接删除 internal 旧路径/签名，不保留兼容 shim；trace test helpers 迁到 publish=false dev-only 内部载体。

### Phase D — Consumer 与 closeout（#2055、#2056）

- 独立 Plain Rust repository 只从 #2053/#2054 的 final-HEAD 候选 package 消费两个组件，证明业务 API 和升级边界。
- closeout 只核对 canonical proof、CHANGELOG、owner 与 rollback；任一前置缺失时阻塞并退回其 canonical owner，
  不在 closeout 补建 artifact。任何 publish 仍需人工执行。

## 回滚与兼容

每个阶段可独立回滚。候选发布前没有外部 SemVer consumer，不保留 internal API shim、旧 package alias 或双 package
发布；已发布后的兼容与弃用从实际 Release API 和 consumer baseline 开始计算。
