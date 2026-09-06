# RSS 项目能力与范围

本文是能力处置与项目边界的规划真源，不是运行证据或 Markdown enforcement carrier。精确 package、target 与
依赖边由 Cargo facts 派生；Release Surface 由维护者依据职责、公共 API 和闭合 package 事实明确接纳。

## 项目目标

RSS 是面向 Rust 社区的 provider-neutral 消息一致性 library workspace。它提供可独立消费的契约、事件、事务一致性、
运行算法与 conformance 语义，并接纳显式选择的独立 provider adapter；不拥有消费方业务、应用装配或生产交付。

最终仓库只保留公共一致性语义所需的 library crates、最低充分 T1/T2、发布证明、法律文件和使用这些 crate 所必需的
最小文档。当前目录或依赖存在不构成保留依据；最终 package 集合由职责唯一性、Cargo 闭合依赖和维护者接纳确认。

## 处置状态

| 状态 | 含义 | 允许变更 |
|---|---|---|
| Evolve | provider-neutral 消息一致性核心 | 收敛公共语义、依赖方向、可消费性与正确性 |
| Complete | 已接纳的公共 primitive 或 conformance 尚缺最低充分闭环 | 只完成既定 T1/T2 与发布闭环，不扩展产品面 |
| Freeze | 已发布且尚未按弃用/退出规则终止的旧公共承诺 | 仅兼容、安全、弃用与退出；不得成为内部旧实现的保留理由 |
| External | 事实和生命周期由消费方、provider 或交付系统拥有 | RSS 不实现；只消费成熟上游或由外部消费者通过公共 crate 集成 |

未发布的仓内 `pub`、internal crate、测试便利或历史治理载体不属于 Freeze，可以在 owner 切换时直接删除。
External 能力不得以 archive、legacy、plugin、compatibility façade 或改名后的内部副本继续留在 RSS。

## 核心能力

| 能力 | Evolve / Complete | External 边界 |
|---|---|---|
| 公共契约与事件 | provider/domain-neutral identity、envelope、metadata、显式 outcome 与算法必需的窄 event port | 业务 endpoint、领域 wire model、generated product binding |
| 消息一致性 | LocalTx、Outbox/Inbox、幂等、settlement/ambiguity、lease/fencing、bounded retry 与窄 transaction/store port | 业务 Saga、projection、reconcile、command workflow 与领域状态机 |
| 公共运行算法 | provider-neutral 处理顺序、ACK-after-commit、取消、bounded drain 与 settlement callback | 进程启动、配置、listener、health/readiness、assembly 与部署生命周期 |
| Conformance | 黑盒公共不变量 assertion、已接纳 adapter 的真实后端 T2 与有界临时 fixture/driver | 生产数据库或 broker 管理、产品 journey、T3 与 evidence 平台 |
| PostgreSQL adapter | 独立 PostgreSQL transactional messaging package、消息专属 schema 与 fresh-install SQL artifact | 迁移执行、角色预建/授权、业务表、operator、部署与数据库运营 |
| AMQP adapter | 独立 AMQP transactional messaging package、publisher confirms、ambiguity、manual settlement、private CA 与真实 broker T2 | broker 运维、凭据发放、生产装配、health/readiness |
| 发布 | 独立 package、SemVer、文档、Release Surface、registry candidate 与人工发布 | 应用 binary/image、生产 profile、部署、迁移、运营与 release control plane |

## 仓库边界

- 生产代码只允许存在于经最终发布闭包确认的 library crate；不得保留 domain、未经接纳的 provider adapter、composition、assembly、
  binary、进程入口或承担产品装配职责的 executable example。
- RSS 不拥有 Dockerfile、部署资产、业务 SQL migration、业务 contract/generated 代码、T3/profile/journey、消费者源码、
  git submodule、provider 管理脚本或自定义通用 CI/evidence 平台。
- crate 自包含测试只证明其公共不变量。已接纳 adapter 通过独立 integration package 验证真实后端语义；
  产品配置、生产 join 和消费者验收由仓外 owner 承担，并只通过发布 artifact 消费 RSS。
- 标准 Cargo/rustc、fmt、clippy、deny、SemVer、package/doc 与最小 CI 组合优先；不得为已删除产品面保留自定义 runner、
  inventory、snapshot 或兼容 gate。
- 历史实现只通过不可变 Git 历史恢复；仓库不维护迁移副本、归档目录、双 owner、alias、shim、双读或 fallback。

## 公共消费边界

- internal `pub`、workspace package、路径依赖或 generated artifact 不自动成为 Release API。
- Release Surface 明确接纳与 package artifact 闭合共同选择公共 package；Release API 兼容性归
  `api-versioning.md`。
- crate 划分、依赖方向与公共 port 设计遵循[架构与依赖规则](dependency-policy.md)。
- package 数量、名称和依赖 DAG 由职责边界、最终 Cargo metadata 与维护者接纳确认，不能从既有目录、临时抽取路径
  或本文反推。

## 验证边界

验证深度、消费组合与发布收尾由[验证范围](verification-scope.md)持有；
约束强度与证据要求由[AI-robust 规则](ai-robust.md)持有。

## 能力准入

新增或保留能力必须同时回答：

1. 是否属于公共消息一致性语义或其已明确接纳的 provider 实现，而不是应用、领域、环境或交付事实？
2. 是否存在稳定 owner，且不能直接使用成熟上游或更小的现有公共类型？
3. 是否被最终候选的公开 API 或明确的跨仓使用场景直接需要？
4. 是否能在不依赖 workspace path、internal crate、业务 generated 类型或未发布 package 的情况下独立打包和消费？
5. 是否有最低充分 Hard/Medium carrier、SemVer owner 与删除路径？

任一答案为否时默认不进入 RSS；历史存在、潜在消费者、测试便利和“完整框架体验”都不是保留理由。
