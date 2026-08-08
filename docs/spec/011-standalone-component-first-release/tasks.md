# Tasks: 首批 Standalone Components 候选发布闭环

本文件只记录稳定 identity、outcome、依赖和 canonical proof；实时 tracker 状态不在 Markdown 复制。

| Logical ID | PBI | Outcome | Blocked-by | Canonical proof |
|---|---:|---|---|---|
| RSS-NW-007 | #2043 | 许可证、安全、维护和发布治理基线 | — | owner-approved governance + package inclusion evidence |
| RSS-NW-008 | #2046 | 公开品牌、前缀与两个候选名称 | #2043 | registry conflict/ownership review |
| RSS-NW-009 | #2050 | 候选 Cargo metadata 与最小 publish closure | #2048, #2046 | Cargo metadata + closure exact-set |
| RSS-NW-010 | #2051 | 共享 packaging mechanics，不授予 final artifact verdict | #2050 | release-check generate/unpack/external-build fixtures |
| RSS-NW-011 | #2053 | diag-context candidate 与同 revision final-artifact proof | #2044, #2051 | unit/doctest + release API + actual `.crate` external proof |
| RSS-NW-012 | #2054 | trace-context candidate 与同 revision final-artifact proof | #2044, #2051 | closed outcome + malformed/roundtrip + release API + actual `.crate` external proof |
| RSS-NW-013 | #2055 | 独立 Plain Rust component consumer | #2053, #2054 | final-artifact-only repository build/test + forbidden dependency check |
| RSS-NW-014 | #2056 | RC、CHANGELOG 与 rollback closeout | #2055 | canonical proof readback + human approval |

## #2041 入库任务

- [x] 将首批候选限定为诊断上下文和 trace context，不扩张全 workspace 发布范围。
- [x] 把法律条款、品牌、最终名称和发布批准保留给明确 owner。
- [x] 分离共享 packaging mechanics 与逐候选 final-artifact proof，并固化独立 consumer、人工 closeout 的不可跳步顺序。
- [x] 明确诊断/trace 信道 fail-open、非授权和 SDK 隐藏边界。
- [x] 不导入 package/release receipt schema、发布控制面或动态 inventory。

## 后续 PBI 共同约束

- 每个 PBI 开始前从当前 Cargo metadata、源码和 tracker 回读事实，不使用历史数量或路径假设。
- candidate、Release Candidate 与 published 必须保持不同语义；任何 registry 上传都需要人工批准。
- 公开依赖、默认 feature、MSRV 和失败语义必须由实际 package 与 consumer 共同证明。
- 新 proof 接入既有 release-check，不创建通用 CI/release 平台。
- mechanics 结果不得跨 API revision 复用；#2055/#2056 只回读 #2053/#2054 同一 revision 的 final artifact evidence。
