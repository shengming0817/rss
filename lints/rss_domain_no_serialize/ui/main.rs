// rss_domain_no_serialize UI fixture（dylint_testing::ui_test_example 消费）。
// golden 见 main.stderr：仅 `domain` 模块（含嵌套 `*::domain::*`）内 derive serde 的正例触发；
// dto 模块 / 无-derive / 手写 impl / item-level `#[allow]` 逃生门 / 模块名含 `domain` 子串（段名≠domain）均不触发。
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

    // 反例 C：手写 `impl Serialize`（非 derive）→ 不触发（守 `automatically_derived` 门回归）。
    pub struct HandWritten {
        pub id: u64,
    }
    impl serde::Serialize for HandWritten {
        fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            serializer.serialize_u64(self.id)
        }
    }

    // 反例 D：item-level `#[allow]` 逃生门 → 不触发（守逃生门：lint 已知、allow 生效）。
    #[allow(rss_domain_no_serialize)] // reason: UI fixture 验证逃生门
    #[derive(serde::Serialize)]
    pub struct AllowedEntity {
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

// 反例 E：模块名含 `domain` 子串但段名 ≠ `domain` → 不触发（守段精确匹配、非子串边界）。
mod cross_domain {
    #[derive(serde::Serialize)]
    pub struct Telemetry {
        pub id: u64,
    }
}

// 正例 3：嵌套 `*::domain::*` 形态 → 触发（守 `in_domain_module` 对 def-path 任意段匹配）。
mod outer {
    pub mod domain {
        #[derive(serde::Serialize)]
        pub struct NestedEntity {
            pub id: u64,
        }
    }
}

fn main() {}
