# RSS 项目能力与范围

RSS 是面向 Rust 社区的一致性与持久化执行 library workspace。主仓保留可复用机制，产品仓拥有业务与生产责任。

## 主仓拥有

- 公共契约、事务消息及其恢复基础库、Saga、事件投影、状态收敛，以及明确接纳的设备命令与 Observation 基础库。
- 上述能力的模型、公共接口、执行与恢复算法、独立 provider adapter、组件专属 schema 和必要升级定义。
- 组件验证、独立消费与发布所需的最小代码和文档。

Observation 核心拥有来自离线、多来源生产者的可靠接收、报告语义、流身份与快照/增量完整性；
`rss-observation-postgres` 拥有组件 schema 和原子持久化。核心不依赖 provider、命令库或 telemetry。

rss-runtime 拥有局部生命周期作用域、即时资源接管、阶段注册、普通/deferred 取消、
受控任务与专用线程、有界 LIFO 关闭、可恢复等待及独立的执行/关闭结果。
显式关键任务的本地终止监视和不可复制 permit 的准入排空属于执行机制；
产品决定开放条件、认证授权、readiness、信号来源与原 runtime 的驱动生命周期。
计数归零、取消或 timeout 不证明任务真正终止；资源清理不回滚外部业务效果。
不恢复中央装配、全局 supervisor、自动重启或跨进程 admission controller。

rss-axum 拥有已接纳公共能力到 Axum 的可选协议适配：类型化契约绑定、请求处理预算与
只读上下文、安全错误投影和 listener 到 rss-runtime 的资源交接；可选 H1/H2/Auto transport
复用 Hyper/hyper-util 的协议实现并拥有连接生命周期；产品异步 transport 准备、连接 guard 与
HTTP futures 由同一 owner 持有，执行产品明确选择的容量与时限，并绑定真实 TCP peer 与产品 metadata。TLS/ALPN、认证授权、产品协议与业务编解码、
最终路由组合、响应流限制与产品 readiness 由消费方拥有，不恢复通用 Web/装配平台。

消息 recovery 拥有已接纳的 consumer 死信归档格式、验证证明与安全清理算法；PG owner 持有组件归档 schema 和原子持久化，专属 S3 adapter 实现 Object Lock port。产品拥有保留/hold 决策、密钥、调度和 bucket 生命周期。

消息 DR 核心拥有外部选定的有界计划、精确授权、终止、回执及带闭合阻断原因的进度；PG owner 拥有原子应用和
storage lineage / tenant epoch 持久化 fencing，并约束正常消息、恢复与归档执行。
成功 Published / Consumer terminal 事实及原投递期限保留，不引入产品 admission controller。

可校验追加账本由 rss-audit 仓库唯一持有，作为审计可选完整性增强；RSS 不再维护或发布 Ledger core/PG adapter，也不反向依赖审计组件。

Webhook 出站 adapter 已接纳：`rss-transactional-messaging-webhook` 拥有单目标 HTTPS、
Standard Webhooks 签名、宿主授权地址限制的实际执行及 HTTP 接收结果分类；复用事务消息 Outbox、
relay、期限和 recovery。产品拥有订阅/fanout、当前租户与资源授权、目标版本、DNS、密钥托管和生产运行。
不恢复订阅平台、通用 connector 或独立 Webhook 持久化/重试引擎。

时序核心已接纳：`rss-timeseries` 拥有开放的类型化序列定义、版本与退休规则、
样本/固定批次身份及摘要、数值/时间/维度预算校验，以及写入回执、有界查询和维护的窄接口。
产品拥有指标含义、认证授权、有效来源/代际、采集配置与调度、保留/覆盖策略和生产运行。
`rss-timeseries-postgres` 拥有组件 schema、显式时间分区、定义持久化、原子批次/样本去重、
持久回执、有界历史/latest/聚合查询、迟到重算及分层保留、删除恢复和关闭流身份回收；
核心持有共享的充分统计与有界计算，PG adapter 持有事务、屏障与维护进度。
可选 TimescaleDB profile 复用同一引擎：共享 RLS 使用行存；固定单租户数据库可使用原生整数 Gauge
持续聚合和 raw 列存，adapter 持有能力准入、刷新发布与物理缓存清理。
`rss-timeseries-clickhouse` 拥有独立 PG 控制 schema、固定批次准入与发布、ClickHouse raw/汇总存储，
以及通过 PG 只读许可关闭迟到投影的恢复和清理协议。单节点共享表采用租户绑定的只读身份；
PG 持有控制事实与临时恢复内容，不保留第二份长期时序数据。不引入通用队列或后台调度器。
产品提供保留、覆盖和恢复期限并拥有数据库/凭据隔离、扩展安装、许可证、分区准备及维护调度。
后端 adapter 拥有并发隔离、持久化/可见性与恢复证明；核心不承诺统一跨后端事务，
不恢复 Inventory、通用采集平台或消息平台。能力准入与实际发布分别提供证据。

同库消息投影由 `rss-transactional-messaging-postgres` 持有：静态 effect、Inbox 回执和源
Outbox 终态在同一实际 PostgreSQL 事务中结算，复用租约、fencing、隔离和恢复；固定消费
domain/group 的数据库权限归该 provider。宿主持有 effect 含义、来源真实性和 worker 生命周期，
不引入跨数据库原子提交或通用审计平台。

## 产品拥有

- 消息 DR 的证据 authority、恢复点和成员选择、数据库/broker restore、跨进程 pause/drain/resume 与部署准入。
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
