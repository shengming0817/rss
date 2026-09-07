# 验证范围

本文拥有 library workspace 的最低充分证明与测试选择边界；它不授权产品进程、部署或生产验收面。

## 证明层级

| 层 | 独有风险 | 典型 carrier |
|---|---|---|
| T1 | 类型、状态机、schema、组件不变量 | Cargo/rustc、类型、codegen、组件测试 |
| T2 | 真实 provider/transaction/transport seam | conformance、真实 DB/broker/identity integration |

- 约束强度与证据归属遵循[AI-robust 规则](ai-robust.md)，不由验证深度推导。
- 高层只证明低层无法观察的接缝风险。
- 按独立风险选择最低充分验证，不做全组合穷举或重复证明。
- 组件恢复决策归 T1，真实后端事务与持久化恢复语义归 T2；使用真实后端或验证进程中断不自动成为产品 T3。
- 产品完整生产闭环归产品 T3；产品进程、应用镜像、部署配置、production profile 与产品级 recovery 不属于本仓验证面。

## 独立消费与组合

- 独立消费、必要 feature 组合与真实 provider 行为分别提供证据，不用其中一种代替其它证明。
- 覆盖基础能力、真实独立选择及有交互风险的支持组合；隔离依赖解析，避免其它消费者补齐缺失能力。
- 构建成功、artifact 可消费和实际发布是不同事实；发布证明绑定被验证的版本与 artifact 身份。
- package 与依赖闭包以构建事实验证；文档不充当包清单、删除完成证明或运行记录。

### 示例与隔离消费目录

- `crates/examples/` 持有不发布的最小使用示例，通过能力的公共 API 消费；不进入 Release Surface，
  不承接产品模型、认证策略、部署或生产 T3。各场景显式选择必要依赖与 feature；共享示例 package 的
  编译结果不能证明 feature 隔离。已有示例按相关实施项复用或迁移，不保留重复维护的同一场景。
- 按风险依次验证仓内可运行示例及结果断言、独立源码 consumer、固定候选 artifact consumer。
  优先复用同一场景源码；完整故障矩阵由已有组件 T1/T2 承担，artifact 层运行最低充分的消费路径。
- 仓库根目录 `rss-external-check/` 为 gitignore 的可再生执行目录。测试源码、模板与脚本仍提交在
  `crates/examples/`、对应测试 owner 或 `hack/`；该目录不持有唯一源码或唯一验收记录。
- 目录虽位于 Git checkout 内，consumer 必须各自声明独立 `[workspace]`、显式依赖和独立 lock，
  不加入主 workspace。各运行使用独立子目录和显式 `CARGO_TARGET_DIR`，核验祖先 Cargo 配置不会引入
  原源码依赖或隐式 feature；不得以 `.gitignore` 或目录名称代替隔离证明。
- 源码阶段可显式引用待验证源码；artifact 阶段仅允许精确候选包及其闭包，可使用指向解包 artifact 的
  path patch，禁止回到原 workspace 源码、internal package 或其它消费者补齐的依赖。正式验收绑定固定
  revision、version、archive digest 与实际命令结果；`cargo check` 不代表行为运行通过。
- RSS 拥有库级 example、T1/T2 和 package correctness；rss-incubator 保留实际产品孵化、独立 pin/lock、
  产品 CI 与接入验收，不作为所有 RSS 包的通用必经门禁。其 registry-only 消费约束不因主仓 artifact
  proof 使用解包 path patch 而放宽；产品生产验收仍由产品 owner 按明确范围承担。

## 默认选择

- 普通 PR 运行 affected T1 与必要 T2；rename/copy、全局输入、未知路径或分析异常必须 fail-full。
- 全工作区回退、develop 和显式 full 执行完整测试与 80% 行覆盖率门禁；affected 不判定全工作区覆盖率。
- 范围与深度独立：deny 属于 develop 或显式 full；SemVer 由同一选择器按明确兼容承诺及影响闭包独立选择，
  PR/develop 使用 affected，显式 full 检查全部适用受保护包。未知影响保守扩大适用范围，不创建实验包兼容承诺。
- 不设置人为 CI 总时限；测试与资源操作保持有界等待。performance 须另有明确验证需求。
- candidate/release final-HEAD identity 验证只覆盖已接纳的 package artifact 与 release metadata；
  消费方应用装配、配置和运行计划漂移属于 External。
- performance 必须绑定已接纳的 library SLO；Markdown、聚合 receipt 和静态 inventory 不得冒充运行证据。

## No-new-work closeout

Closeout 只回读既有代码、测试和 JobResult，核对 canonical owner/selector，更新 traceability 并记录缺口。
不得新增产品代码、test carrier、benchmark、schema、selector、CI gate 或 receipt database。
缺 proof 时退回原 implementation owner；没有 owner 时另立实现项，closeout 不接管。
