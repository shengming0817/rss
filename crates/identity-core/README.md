# rss-identity-core

该库定义实例、租户内主体、账户、会话呈现、联邦身份声明和用途绑定的 step-up 上下文。宿主使用同一 RSS Git URL 和完整 revision 引入需要的 Identity 包。四个包当前版本为 0.1.0，通过 Git 消费。

会话、用户资料、组和部门事实均保留来源与期限。宿主在当前请求内取得证明，按产品权限判定能否访问资源。密码校验采用有界的 Argon2 工作区，宿主按进程容量提供共享 PasswordKdf。上游身份协议接口和报告值通过 Rust 类型提供，真实会话结算由 [PostgreSQL adapter](../identity-postgres/README.md) 执行。
