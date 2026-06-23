//! 用户仓储 in-memory 实现（RW-G1 追踪弹）。生产持久化（postgres adapter）留 W。

use std::collections::HashMap;

use super::ports::{UserAccount, UserRepo};

/// in-memory 用户仓储：用户名 → 账户。
pub(crate) struct InMemUserRepo {
    users: HashMap<String, UserAccount>,
}

impl InMemUserRepo {
    /// 以单个种子用户构造（追踪弹只需一条登录路径）。
    pub(crate) fn with_user(
        username: impl Into<String>,
        password: impl Into<String>,
        subject: impl Into<String>,
        tenant_id: impl Into<String>,
    ) -> Self {
        let mut users = HashMap::new();
        users.insert(
            username.into(),
            UserAccount {
                subject: subject.into(),
                tenant_id: tenant_id.into(),
                password: password.into(),
            },
        );
        Self { users }
    }
}

impl UserRepo for InMemUserRepo {
    fn find(&self, username: &str) -> Option<UserAccount> {
        self.users.get(username).cloned()
    }
}
