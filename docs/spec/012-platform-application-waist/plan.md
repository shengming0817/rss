# Implementation Plan: Platform Public 高风险单波次

## 单波次闭包

1. 建立 compile-negative、验证矩阵、typed dispatch、并发 drain 与 shutdown 红测。
2. 新建零 workspace 生产依赖的 `rss-platform`，并登记最低位 `PlatformPublic` layer。
3. 从 canonical framework-owned active HTTP set 生成 sealed marker 与 façade-owned DTO。
4. 原子删除 #2045 fixture/harness/UI、core/eventing marker 与所有兼容入口。
5. 将 package 选入 experimental Release Surface 并生成首个 release API baseline。
6. 用真实 `.crate`、本地 registry、独立 Git/Cargo.lock 与 locked/offline T2 consumer 闭合 #2051/#2052。
7. 仅在定向门稳定后运行一次完整 `make ci CI_BASE=origin/develop`，批量处置结果。

任一 authority、dispatch、drain、codegen、release 或 package proof 失败，整个波次不可合并。
