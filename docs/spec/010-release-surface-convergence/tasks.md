# Tasks: Release Surface 收敛

本文件只记录稳定 PBI identity、outcome、依赖和 proof owner。实时状态、优先级与标签以激活 forge 为准。

| Logical ID | PBI | Outcome | Blocked-by | Canonical proof |
|---|---:|---|---|---|
| RSS-NW-002 | #2042 | 最小 Release Surface 派生模型；未选 package 默认 internal | #2041 | Cargo/assembly facts exact-set + workspacefacts/release-check focused tests |
| RSS-NW-003 | #2044 | Standalone Component 窄 API、依赖预算和失败语义 | #2042 | public dependency/type boundary + focused component tests |
| RSS-NW-004 | #2045 | Platform Application waist 与 internal 泄漏边界 | #2042 | compile-positive/negative fixtures + API design evidence |
| RSS-NW-005 | #2047 | internal signature 与 release-selected API baseline 分离 | #2044, #2045 | `cargo public-api` 两类 owner 的非重叠证明 |
| RSS-NW-006 | #2048 | Release API compatibility、SemVer 与泄漏接入既有 release-check | #2047 | release-check positive/synthetic negative fixtures |

## #2041 入库任务

- [x] 保留已占用的 Spec 009，并把三份产品化 Spec 从 010 开始编号。
- [x] 删除全 workspace 显式分类、平行 package metadata/schema 和动态数量 golden。
- [x] 固化正向 Release Surface、双窄腰、internal/release API 语义与 AI-HARD owner。
- [x] 使用真实 Azure PBI ID 回填后续 DAG，不复制 tracker 实时状态。
- [x] 保持本 PR 为 docs-only，不实现后续 PBI。

## 后续 PBI 共同约束

- 开始实施前回读对应 issue、当前 Cargo/assembly facts 与本规格；不得按本文推测实时状态。
- 新 public surface 必须有 owner、版本、release artifact、真实 workspace 外 consumer 和退出路径。
- 可由 Cargo/visibility 表达的边界使用 Hard；其它发布 hazard 进入既有 canonical Medium proof。
- 不创建通用 Provider SPI、第二 runner/scanner/registry 或 Markdown enforcement。
