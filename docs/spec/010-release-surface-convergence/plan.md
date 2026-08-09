# Implementation Plan: Release Surface 收敛

## 本规格 PR

#2041 只入库设计文档和后续 PBI traceability。它不实现 Release Surface、API allowlist、baseline 或 release-check，
也不修改 ADR、规则、Cargo 或 assembly facts。

## 后续交付 DAG

```text
#2041 Specs 基线
   |
   v
#2042 最小 Release Surface 派生模型
   |
   +--------------------+
   v                    v
#2044 Standalone API  #2045 Platform API
   +--------------------+
             |
             v
#2047 internal/release baseline 分离
             |
             v
#2048 compatibility + leakage 接入既有 release-check
```

## 阶段与证明

### Phase A — 正向发布集合（#2042）

- 只列实际发布项，未列 package 默认 internal。
- 从 Cargo 和 assembly/profile facts 校验或派生，不增加逐包声明。
- 复用 workspacefacts 与既有 assembly governance，结构化诊断定位选中项及冲突事实。

### Phase B — 双窄腰 API 设计（#2044、#2045）

- 两个 PBI 可并行，但分别只拥有 Standalone 与 Platform API。
- Standalone 约束公共依赖、默认 feature、MSRV 和失败语义。
- Standalone 的唯一 allowlist 位于 Spec 011；诊断信道非授权边界由 HIR Dylint 承载，不由 Markdown enforcement。
- Platform 约束应用入口、可信只读 context、生命周期观察面与 internal 泄漏边界。
- 两者只做设计和最低充分编译边界证明，不发布 artifact。

### Phase C — API baseline 分离（#2047）

- 保留既有 internal signature proof。
- Release API baseline 只消费 #2042 的正向发布集合和 Phase B 的窄腰决策。
- 复用现有 nightly pin、解析和 `cargo public-api` 入口，不维护两套工具实现。

### Phase D — Compatibility 与 leakage（#2048）

- 将 release-selected API drift、SemVer、公共依赖和 forbidden-type proof 接入现有 release-check。
- 新 proof 必须绑定发布独有 hazard，并复用或替换已有 proof；不得扫描 Markdown 或全 workspace 产品分类。

## 回滚与迁移

每个后续 PBI 独立交付和回滚。由于旧草案从未成为发布事实，本系列没有 metadata/schema migration、兼容 reader、
目录 alias 或双写期。轴 B wire contract 与现有 runtime behavior 不受影响。
