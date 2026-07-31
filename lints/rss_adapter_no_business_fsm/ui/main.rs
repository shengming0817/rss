// rss_adapter_no_business_fsm UI fixture（CARGO_PKG_NAME == lint package ⇒ 激活）。
// golden 见 main.stderr：
//   RED：*State + transition
//   RED：use / path 段含 `statig`（本地同名 mod，不引真实 crate）
//   GREEN：非匹配名 / item-level allow / 无过渡方法的 *Phase 标签枚举
// allow(unknown_lints)：普通 cargo build 本 example 时不认本 lint（仅 dylint driver 认）。
#![allow(unused, unknown_lints)]

// R1：业务过渡表形态（State + transition）→ 触发。
enum SessionState {
    Idle,
    Active,
}

impl SessionState {
    fn transition(self) -> Self {
        match self {
            Self::Idle => Self::Active,
            Self::Active => Self::Active,
        }
    }
}

// R2：`use` / path 含 `statig` → 触发（与 deny.toml ban 双保险）。
mod statig {
    pub struct Machine;
}

use statig::Machine as ImportedStatigMachine;

fn path_mentions_statig() -> ImportedStatigMachine {
    statig::Machine
}

// G1（specificity）：非 State/Phase/Lifecycle 后缀 + 同名方法 → 不触发。
enum SessionKind {
    Idle,
    Active,
}

impl SessionKind {
    fn transition(self) -> Self {
        self
    }
}

// G2（逃生门）：item-level #[allow] 抑制。
enum AllowedState {
    A,
    B,
}

#[allow(rss_adapter_no_business_fsm)] // reason: UI fixture 验证逃生门
impl AllowedState {
    fn next(self) -> Self {
        Self::B
    }
}

// G3（标签枚举）：*Phase 但无 next/transition/advance/step → 不触发。
enum DeliveryPhase {
    PreSend,
    Confirm,
}

impl DeliveryPhase {
    fn as_str(self) -> &'static str {
        match self {
            Self::PreSend => "pre_send",
            Self::Confirm => "confirm",
        }
    }
}

fn main() {}
