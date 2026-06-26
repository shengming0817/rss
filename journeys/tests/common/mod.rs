//! Shared journey test helpers: [`CapturingVerifier`], [`audit_domain`], [`single_subscription`],
//! and shared constants ([`CANON_TENANT`] / [`AUDIT_KEY`] / …).
//!
//! This module is compiled into each including test binary separately (via `mod common;`). Items
//! unused in one binary would trigger `dead_code` under `-D warnings` — `#![allow(dead_code)]`
//! is the standard Rust idiom for shared integration-test helper modules.
#![allow(dead_code)]

use std::sync::{Arc, Mutex};

use audit::ports::{AuditChainHasher, DynAuditRepo};
use audit::{AuditDomain, InMemAuditRepo};
use primitives::{Mac, MacAlgorithm, MacKey, MacVerifier};

/// canonical UUID 种子租户（TenantId::parse 接受形态）。
pub const CANON_TENANT: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
/// session-created event 契约 topic（identity 发布 / audit 订阅）。
pub const SESSION_CREATED_TOPIC: &str = "identity.session-created";
/// 登录种子密码。
pub const PASSWORD: &str = "correct-horse";
/// 登录标识（`request.username`）——#1277 F1：可为任意非 uuid 用户名，仅作凭据查找键，不写 wire/audit。
pub const LOGIN_USERNAME: &str = "alice";
/// canonical actor subject（credential 携带的 `ids::UserId`）——登录成功后写 payload/envelope/session
/// subject + 审计 actor。与登录标识解耦（#1277 F1）。
pub const CANON_USER: &str = "11111111-2222-4333-8444-555555555555";
/// journey 审计链 HMAC key（固定 32B）。
pub const AUDIT_KEY: [u8; 32] = [0x5a; 32];
/// 固定登录时刻（确定性断言）。
pub const NOW_SECS: u64 = 1_000;
/// 会话 ttl（确定性断言）。
pub const TTL_SECS: u64 = 3_600;

const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

/// 审计链 HMAC 测试 verifier：捕获每次 `sign` 调用的 message（append **AND** verify 路径均会调用 `sign`，
/// 不止 append），并以确定性折叠产出 32B 标签（链一致）。`audited().len()` 计的是全部 `sign` 调用次数，
/// 含 `verify_integrity` 在内的读路径——非仅 append 次数。W 阶段审计落**域内哈希链**（无外部 sink），
/// journey 经注入此 verifier 端到端断言审计 sign 次数 + 内容贯穿。非加密——journey 只需确定性 + 可计数/可检视。
#[derive(Clone, Default)]
pub struct CapturingVerifier {
    messages: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl CapturingVerifier {
    pub fn audited(&self) -> Vec<Vec<u8>> {
        self.messages
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    pub fn is_empty(&self) -> bool {
        self.messages
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_empty()
    }
}

impl MacVerifier for CapturingVerifier {
    fn sign(&self, key: &MacKey, _algorithm: MacAlgorithm, message: &[u8]) -> Mac {
        self.messages
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(message.to_vec());
        // 确定性折叠（FNV-1a 变体；journey 只需链一致）。
        let mut acc = FNV_OFFSET;
        for &b in key.as_bytes().iter().chain(message) {
            acc ^= u64::from(b);
            acc = acc.wrapping_mul(FNV_PRIME);
        }
        let mut out = [0u8; 32];
        for chunk in out.chunks_mut(8) {
            chunk.copy_from_slice(&acc.to_be_bytes());
            acc = acc.wrapping_mul(FNV_PRIME);
        }
        Mac::from_bytes(out.to_vec())
    }

    fn verify(&self, key: &MacKey, algorithm: MacAlgorithm, message: &[u8], tag: &Mac) -> bool {
        primitives::constant_time_eq(
            self.sign(key, algorithm, message).as_bytes(),
            tag.as_bytes(),
        )
    }
}

/// 构造 journey 用 audit 域 + 共享捕获句柄（注入捕获 verifier + 固定 32B key）。
///
/// API（#1230）：`AuditDomain` 不再泛型；经 `AuditChainHasher::new`（`Option`，弱 key → `None`）+
/// `InMemAuditRepo::new` + `Arc::from(DynAuditRepo::new_box(...))` 装配后经 `AuditDomain::new`
/// （不可失败）注入——组合根装配路径与生产 `PgAuditRepo` 同形。
#[allow(clippy::expect_used)]
pub fn audit_domain() -> (AuditDomain, CapturingVerifier) {
    let verifier = CapturingVerifier::default();
    let hasher = AuditChainHasher::new(verifier.clone(), MacKey::from_bytes(AUDIT_KEY.to_vec()))
        .expect("32B audit key satisfies MIN_KEY_LEN");
    let repo: Arc<DynAuditRepo<'static>> =
        Arc::from(DynAuditRepo::new_box(InMemAuditRepo::new(hasher)));
    let domain = AuditDomain::new(repo);
    (domain, verifier)
}

/// 取唯一 session-created 订阅绑定（断言恰一个）。
pub fn single_subscription(
    registry: bootstrap::Registry,
) -> anyhow::Result<bootstrap::SubscriberBinding> {
    let mut subs = registry.into_subscribers();
    anyhow::ensure!(subs.len() == 1, "恰一个 session-created 订阅");
    subs.pop().ok_or_else(|| anyhow::anyhow!("订阅缺失"))
}
