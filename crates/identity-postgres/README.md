# rss-identity-postgres

宿主提供已绑定 storage lineage 与 tenant epoch 的 PgRuntime、共享 PasswordKdf、ManagementPolicy 和逐操作时限。用 AuthorityConfig::new(instance, sessions, integrity, audit_budget) 装配实例。Integrity 和 WriteBudget 来自同一 RSS revision 的 rss-audit-postgres。每个宿主容量域建立一个 WriteBudget，给所有使用它的写入者传入克隆；Identity 单次变更多至八条审计事件。

## 全新安装与权限

按所选 RSS revision 安装事务消息 schema，再以独立的 NOLOGIN、NOSUPERUSER、NOBYPASSRLS owner 安装 Audit schema。选择 Ledger 时一并安装 Ledger schema，并赋予实际写入角色对应的读取和函数执行权限。由宿主迁移程序在安装事务内调用 install、grant_profile 和 verify_profile。日常服务使用 Runtime 角色；Maintenance 只执行初始化和维护动作；Provisioning 在调用方拥有的目标事务内工作。各角色以自己的凭据运行启动探针。schema、授权 SQL 和签名均随本 crate 提交。

如需复算 schema-signature.sha256，在一次性空 PG 中执行 migrations/0001_authority.sql，再用 psql -XAt 执行 src/schema-signature.sql。生产安装调用库的公开 API。

## 会话与事务

Authority 接收可信 ExecutionBinding，签发后在原 scope 下复核会话。宿主借用事务用 recheck_authenticated_session_on 和 consume_step_up_on 完成当前会话与用途验证。业务写入和 Audit 共用原 PgTransaction 与截止时间。Ledger 先锁链头，再取业务锁。准备好的审计批次通过共享预算即时准入；容量不足或追加失败会传播给原事务 owner。只有提交已确认后才交付凭据，提交不确定时调用方须处理该结算结果。

FederationConfig.callback 由宿主按生产路由生成。配置需要带主机的 HTTPS URL，排除用户信息、查询和 fragment；注册的 redirect_uri 必须与这个完整字符串匹配。WebAuthn 的可信 RP、Origin 和代际由宿主在装配时提供，挑战与操作证明在事务内消费。WebAuthn 0.5.5 的验证路径使用系统 OpenSSL，独立构建环境需提供其开发库和构建工具。
