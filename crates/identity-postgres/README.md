# rss-identity-postgres

宿主提供已绑定 storage lineage 与 tenant epoch 的 PgRuntime、共享 PasswordKdf、ManagementPolicy 和请求入口冻结的 rss_request_context::Deadline。身份操作直接将该截止传入 PgRuntime::local_tx_until，证明有效期使用宿主给 PgRuntime 的执行时钟，持久期限以 PostgreSQL 墙钟为准。用 AuthorityConfig::new(instance, sessions, integrity, audit_budget) 装配实例。Integrity 和 WriteBudget 来自同一 RSS revision 的 rss-audit-postgres。每个宿主容量域建立一个 WriteBudget，给所有使用它的写入者传入克隆；Identity 单次变更多至八条审计事件；配置至少需要 8 行、1,048,576 字节的批次容量，aggregate 容量至少覆盖一个完整批次。

## 全新安装与权限

在 PostgreSQL 17 上按所选 RSS revision 安装事务消息 schema，再以独立的 NOLOGIN、NOSUPERUSER、NOBYPASSRLS owner 安装 Audit schema。选择 Ledger 时一并安装 Ledger schema，并赋予实际写入角色对应的读取和函数执行权限。由宿主迁移程序以安装权限执行 install 和 grant_profile，后者包括 Plain 所需的 Audit schema USAGE、记录读取与 append_batch 函数执行权限。在安装事务内 SET LOCAL ROLE 到实际目标角色再调用 verify_profile。该入口核对 Identity 的 schema 与权限，连接 Authority 时再验证完整 Audit 写入准入。日常服务使用 Runtime 角色；Maintenance 只执行初始化和维护动作；Provisioning 在调用方拥有的目标事务内工作。各角色以自己的凭据运行启动探针。schema、授权 SQL 和签名均随本 crate 提交。

如需复算 schema-signature.sha256，在一次性空 PG 中执行 migrations/0001_authority.sql，再以 search_path=pg_catalog 执行 src/schema-signature.sql。嵌入宿主可调用 schema_signature 在自己的连接上计算相同结果。生产安装调用库的公开 API。

## 会话与事务

Authority 接收可信 ExecutionBinding，签发后在原 scope 下复核会话。宿主借用事务用 recheck_authenticated_session_on 和 consume_step_up_on 完成当前会话与用途验证。业务写入和 Audit 共用原 PgTransaction 与截止时间。Ledger 先锁链头，再取业务锁。准备好的审计批次通过共享预算即时准入；容量不足或追加失败会传播给原事务 owner。只有提交已确认后才交付凭据，提交不确定时调用方须处理该结算结果。

FederationConfig.callback 由宿主按生产路由生成。配置需要带主机的 HTTPS URL，排除用户信息、查询和 fragment；注册的 redirect_uri 必须与这个完整字符串匹配。WebAuthn 的可信 RP、Origin 和代际由宿主在装配时提供，挑战与操作证明在事务内消费。WebAuthn 0.5.5 的验证路径使用系统 OpenSSL，独立构建环境需提供其开发库和构建工具。
