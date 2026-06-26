//! secure::password — argon2id 密码哈希原语（hash / constant-time verify）。
//!
//! 基础层 L0：crypto 原语集中在 `secure`（与 aead/cookie/redaction 同 crate），域 crate 不直接依赖 argon2。
//! [`PasswordHash`] 是 PHC 字符串 newtype（字段私有、`Debug` 脱敏、不 derive serde）——哈希物料是离线
//! 爆破目标，按敏感值收口；明文密码**永不存入**此类型（仅作 [`hash_password`] 入参，返回即丢弃）。验签
//! 经 argon2 内建 constant-time 比对（再哈希候选 + 常时比较），fail-closed：任何解析失败 / 不匹配均
//! 返回 `false`，不区分以免侧信道枚举「无此哈希」与「密码错」。
//!
//! ref: RustCrypto/argon2 argon2/src/lib.rs@master（`Argon2::hash_password` / `verify_password` PHC 范式）

use argon2::Argon2;
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{
    PasswordHash as PhcHash, PasswordHasher, PasswordVerifier, SaltString,
};

/// 密码哈希错误（库错误枚举，const-literal message，无 PII——error-handling.md §Message 与 PII）。
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PasswordError {
    /// argon2 哈希计算失败（盐生成 / KDF 内部错误，理论不可达）或回读时 PHC 串非法（fail-closed）。
    #[error("password hash failed")]
    Hash,
}

/// argon2id 密码哈希（PHC 字符串：`$argon2id$v=19$...$<salt>$<hash>`）。
///
/// 字段私有 + `Debug` 脱敏 + **不 derive serde**：哈希物料是离线爆破目标，按敏感值收口。明文密码永不
/// 进入此类型。[`as_str`](Self::as_str) 暴露 PHC 供持久化（adapter 存库 / [`parse`](Self::parse) 回读），
/// 但 `Debug` 始终脱敏，杜绝随结构体打印泄漏。
/// `Debug` 经 `#[derive(Redactable)]` 字段级脱敏（PHC 物料 → `<redacted>`，渲染 `PasswordHash(<redacted>)`），
/// 替换手写 impl（#1360）。
#[derive(Clone, PartialEq, Eq, secure::Redactable)]
pub struct PasswordHash(#[redact(sensitivity = secret)] String);

impl PasswordHash {
    /// 持久化 PHC 字符串（adapter 存库时读取——不含明文，含 argon2 摘要 + 参数 + 盐）。
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// 从已存 PHC 字符串回读（postgres adapter 加载凭据时重建）。
    /// 非法 / 非 well-formed PHC → [`PasswordError::Hash`]（fail-closed，拒绝注入任意串绕过哈希语义）。
    pub fn parse(phc: &str) -> Result<Self, PasswordError> {
        // 校验 well-formed PHC（拒绝任意串伪装哈希）；解析仅借用，存储 owned 原串。
        PhcHash::new(phc).map_err(|_| PasswordError::Hash)?;
        Ok(Self(phc.to_string()))
    }

    /// 仅测试：绕过校验直接包裹（覆盖 [`verify_password`] 对损坏 PHC 的 fail-closed 分支）。
    #[cfg(test)]
    fn from_unchecked(raw: &str) -> Self {
        Self(raw.to_string())
    }
}

/// 对明文密码做 argon2id 哈希（随机盐，`OsRng`）。返回 PHC 字符串 newtype；明文入参函数返回即丢弃。
///
/// **KDF 参数 = `Argon2::default()`**（argon2 0.5：Argon2id v0x13，`m_cost=19 MiB` / `t_cost=2` / `p_cost=1`，
/// 输出 32B）——恰为 OWASP ASVS V2.2 / Password Storage Cheatsheet 的 Argon2id **最低**推荐档（19 MiB,2,1）。
/// 升级路径：若运维需提高强度（如 46 MiB），显式 `Argon2::new(Algorithm::Argon2id, Version::V0x13,
/// Params::new(..)?)` 替换 `default()`；PHC 串自带参数 ⇒ 旧哈希仍可验签（再哈希用存串参数），无需迁移。
pub fn hash_password(plaintext: &str) -> Result<PasswordHash, PasswordError> {
    let salt = SaltString::generate(&mut OsRng);
    let phc = Argon2::default()
        .hash_password(plaintext.as_bytes(), &salt)
        .map_err(|_| PasswordError::Hash)?
        .to_string();
    Ok(PasswordHash(phc))
}

/// constant-time 验签：argon2 再哈希候选明文 + 常时比对存储摘要。
/// fail-closed——解析失败 / 不匹配均返回 `false`（不区分以免侧信道）。
pub fn verify_password(plaintext: &str, hash: &PasswordHash) -> bool {
    // 损坏的存储串不可能经构造 funnel（parse 已校验），此 Err 分支为纵深防御；落 false 不 panic。
    let Ok(parsed) = PhcHash::new(&hash.0) else {
        return false;
    };
    Argon2::default()
        .verify_password(plaintext.as_bytes(), &parsed)
        .is_ok()
}

/// 恒定成本验签（消登录枚举时序侧信道）：无论凭据是否存在，候选明文**总跑一次 argon2 KDF**。
///
/// `Some(hash)` → 正常验签；`None`（查无凭据）→ 仍对候选跑一次等价成本的 argon2（`hash_password`
/// 与 `verify_password` 均以 argon2 KDF 为主导成本、同 `Argon2::default()` 参数 ⇒ 时延等价），结果丢弃、
/// 返回 `false`。消除「无此主体（跳过 KDF，快返回）」与「密码错（跑 KDF）」之间可被计时区分的 user
/// enumeration discrepancy。ref: OWASP Authentication Cheatsheet（登录处理时间差 = 枚举信号）。
pub fn verify_password_constant_time(plaintext: &str, hash: Option<&PasswordHash>) -> bool {
    match hash {
        Some(h) => verify_password(plaintext, h),
        None => {
            // 等价成本 argon2 KDF（丢弃产物）；即便哈希失败也 fail-closed 返回 false。
            let _ = hash_password(plaintext);
            false
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::{PasswordError, PasswordHash, hash_password, verify_password};

    #[test]
    fn hash_then_verify_correct_password() {
        let h = hash_password("correct-horse-battery-staple").expect("hash ok");
        assert!(verify_password("correct-horse-battery-staple", &h));
    }

    #[test]
    fn verify_rejects_wrong_password() {
        let h = hash_password("correct-horse").expect("hash ok");
        assert!(!verify_password("wrong", &h));
    }

    #[test]
    fn verify_rejects_empty_candidate_against_nonempty() {
        let h = hash_password("nonempty").expect("hash ok");
        assert!(!verify_password("", &h));
    }

    #[test]
    fn empty_password_hashes_and_verifies() {
        // argon2 不对明文做长度策略（策略属域/handler 边界）；空密码正向路径可达——锁住此边界，
        // 防未来给 hash_password 加入口校验时静默改变空串语义。
        let h = hash_password("").expect("hash ok");
        assert!(verify_password("", &h));
        assert!(!verify_password("x", &h));
    }

    #[test]
    fn same_password_hashes_differ_by_random_salt() {
        let h1 = hash_password("same").expect("hash ok");
        let h2 = hash_password("same").expect("hash ok");
        assert_ne!(h1.as_str(), h2.as_str(), "随机盐 ⇒ 两次哈希 PHC 不同");
        assert!(verify_password("same", &h1));
        assert!(verify_password("same", &h2));
    }

    #[test]
    fn debug_redacts_phc_no_leak() {
        let h = hash_password("secret-pw").expect("hash ok");
        let dbg = format!("{h:?}");
        assert_eq!(dbg, "PasswordHash(<redacted>)");
        assert!(!dbg.contains("argon2"), "Debug 不得泄哈希算法/摘要");
        assert!(!dbg.contains("secret-pw"), "Debug 不得泄明文");
    }

    #[test]
    fn parse_roundtrips_valid_phc() {
        let h = hash_password("roundtrip").expect("hash ok");
        let phc = h.as_str().to_string();
        let reparsed = PasswordHash::parse(&phc).expect("parse ok");
        assert_eq!(reparsed.as_str(), phc);
        assert!(verify_password("roundtrip", &reparsed));
    }

    #[test]
    fn parse_rejects_garbage_phc() {
        let err = PasswordHash::parse("not-a-phc-string").expect_err("must reject");
        assert!(matches!(err, PasswordError::Hash));
    }

    #[test]
    fn verify_returns_false_on_corrupt_hash_no_panic() {
        // fail-closed：内部 PHC 解析失败也须 false（损坏的存储串不可能经 parse，故用测试 seam 构造）。
        let corrupt = PasswordHash::from_unchecked("$argon2id$garbage");
        assert!(!verify_password("anything", &corrupt));
    }

    #[test]
    fn constant_time_verify_matches_normal_and_misses_false() {
        use super::verify_password_constant_time;
        let h = hash_password("correct").expect("hash ok");
        // 有哈希：等同 verify_password。
        assert!(verify_password_constant_time("correct", Some(&h)));
        assert!(!verify_password_constant_time("wrong", Some(&h)));
        // 无哈希（查无凭据）：返回 false（且内部已跑等价 argon2，无 panic）。
        assert!(!verify_password_constant_time("anything", None));
    }
}
