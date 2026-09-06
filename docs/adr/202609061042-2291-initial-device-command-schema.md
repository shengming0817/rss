# ADR #2291：未发布初始 schema 的终态约束修正

状态：已接受；PR #930 内置 review F1，用户已确认当前 PR 完整修复。

本次仅允许重写 PR #930 新增、尚未合入或发布的
`crates/device-command-postgres/migrations/0001_create_device_command.sql`。
修改将 deadline 的约束限定为 TimedOut 不得早于 deadline、Applied 不得晚于 deadline；
明确取消、覆盖和设备拒绝可在 deadline 后记录，但终态不重新打开，时间仍须单调。
核心 reducer、SQL 约束及 T1/T2 在同一 PR 同步修改。

该例外不改动既有 transactional-messaging migration，不迁入历史数据、不引入双 schema。
本 PR 合入后的 migration 遵循只增不改规则；未来持久化升级由组件 owner 单独提供。

安全模型仍由精确 scope/coordinate、事务行锁与版本 CAS、强制租户 RLS 共同承载；
改变终态原因不赋予设备执行成功、撤回已发布消息或绕过设备侧防重放的权限。

## PR #930 外部 review F2/F3 的已确认修订

用户确认在当前 PR 采用私有 runtime 来源校验与持久化 exact domain。允许本 PR 尚未发布的
初始 migration 增加 `outbox_domain`，并同步更新 enqueue 签名与 probe 合同。没有旧列回填、
兼容函数或双读路径；消息组件既有 migration 仍不修改。runtime 来源为进程内私有借用，
不写入持久化状态；重新连接后重建同源 store。恢复使用原始 domain/message/fingerprint，
不从当前 relay 的默认 domain 推导。
