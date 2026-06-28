//! trybuild 回归锁（Hard 类型墙的 synthetic red case，#1469 / ADR-011 §D2）。
//!
//! fail（aad-derive-from-ctx）：envelope 存储的标识 AAD（`&ProtectionAad`，经 `env.aad()`）回灌给
//! `Aead::open`（要 `&DerivedAad`，只能经 `ProtectionContext::derive` 受信派生）必须类型不匹配编译失败——
//! 杜绝攻击者复制 `(ciphertext, stored_aad)` 跨租，用 stored AAD 自洽验签的重放绕过。anti-vacuity：
//! 若 `open` 接受 `&ProtectionAad` 即编译通过、红例失效。
//!
//! INVARIANT: FIELDPROT-AAD-DERIVE-FROM-CTX-01
//!
//! 维护提示：`.stderr` 是 rustc 版本敏感的精确诊断快照（措辞/格式随 toolchain 漂移）。bump
//! `rust-toolchain.toml` 后若本测试 mismatch，跑 `TRYBUILD=overwrite cargo test -p secure --test trybuild`
//! 重生成（类型墙本身永远成立，漂移仅在诊断文本）。

#[test]
fn ui() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/open_rejects_stored_aad.rs");
    t.compile_fail("tests/ui/open_rejects_stored_aad_rederived.rs");
    t.compile_fail("tests/ui/open_rejects_raw_plaintext_vec.rs");
}
