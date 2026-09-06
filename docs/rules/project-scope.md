# RSS 项目能力与范围

RSS 是面向 Rust 社区的一致性与持久化执行 library workspace。主仓保留可复用机制，产品仓拥有业务与生产责任。

## 主仓拥有

- 公共契约、事务消息、Saga、事件投影、状态收敛，以及明确接纳的设备命令与 Observation 基础库。
- 上述能力的模型、公共接口、执行与恢复算法、独立 provider adapter、组件专属 schema 和必要升级定义。
- 组件验证、独立消费与发布所需的最小代码和文档。

Observation 核心拥有来自离线、多来源生产者的可靠接收、报告语义、流身份与快照/增量完整性；
`rss-observation-postgres` 拥有组件 schema 和原子持久化。核心不依赖 provider、命令库或 telemetry。

rss-axum 拥有已接纳公共能力到 Axum 的可选协议适配：类型化契约绑定、请求处理预算与
只读上下文、安全错误投影和 listener 到 rss-runtime 的资源交接。认证授权、协议编解码、
最终路由组合、响应流限制与产品 readiness 由消费方拥有，不恢复通用 Web/装配平台。

## 产品拥有

- 业务流程、读模型、设备认证与协议、MDM 策略和准入判定。
- Observation 的采集定义/执行/调度、来源授权、注册生命周期、事实解释、多源优先级、Inventory 与合规判定。
- 应用装配、进程入口、配置、业务表、生产迁移执行、部署运维和产品 T3。

## 准入与退出

- 能力须有明确消费需求、唯一职责与 owner、可独立消费的公共边界；优先复用成熟上游。
- 设备命令基础库的接纳不扩展为整个设备管理域。历史存在和同仓开发不构成保留或依赖理由。
- Evolve 演进已接纳机制；Complete 补齐既定闭环；Freeze 仅维护受保护旧承诺；External 由仓外 owner 持有。
  退出不留副本、alias、shim 或双 owner。
- 范围接纳不等于实现完成或发布接纳；发布包由 Release Surface 与 Cargo 闭包共同确认。

crate 与依赖设计、验证、版本兼容分别遵循[架构与依赖](dependency-policy.md)、[验证范围](verification-scope.md)、
[版本规则](api-versioning.md)。
