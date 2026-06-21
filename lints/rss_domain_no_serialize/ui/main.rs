// rss_domain_no_serialize UI fixture（dylint_testing::ui_test_example 消费）。
// golden 见 main.stderr：仅 `domain` 模块内 derive serde 的两个正例触发；dto 模块 / 无-derive 不触发。
#![allow(dead_code)]

mod domain {
    // 正例 1：`domain` 模块内的域实体 derive Serialize → 触发。
    #[derive(serde::Serialize)]
    pub struct UserEntity {
        pub id: u64,
    }

    // 正例 2：域实体 derive Deserialize → 触发（证明 Deserialize 分支非空转）。
    #[derive(serde::Deserialize)]
    pub struct AuditRecord {
        pub seq: u64,
    }

    // 反例 B：域内普通类型无 derive → 不触发（lint 盯 derive，不盯模块名）。
    pub struct PlainEntity {
        pub id: u64,
    }
}

mod dto {
    // 反例 A：dto 模块类型 derive Serialize → 不触发（不在 `domain` 模块）。
    #[derive(serde::Serialize)]
    pub struct UserDto {
        pub id: u64,
    }
}

fn main() {}
