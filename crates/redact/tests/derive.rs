#[derive(rss_redact::Redact)]
struct Credential {
    #[allow(dead_code)]
    #[redact(sensitivity = secret)]
    value: String,
}

#[test]
fn facade_reexports_a_working_redact_derive() {
    let value = Credential {
        value: "do-not-log".to_owned(),
    };
    assert_eq!(format!("{value:?}"), "Credential { value: <redacted> }");
}

use rss_redact::RedactScope;

// Public derive integration: generated Debug and field policies.

#[allow(dead_code)]
#[derive(rss_redact::Redact)]
struct DerivedNewtype(#[redact(sensitivity = secret)] Vec<u8>);

#[derive(rss_redact::Redact)]
// `gone`（mode = "drop"）经 F2 后取 RedactValue::Absent、不被 redact 读取 ⇒ field never read。
#[allow(dead_code)]
struct DerivedMixed {
    #[redact(sensitivity = public, mode = "show")]
    visible: String,
    #[redact(sensitivity = secret)]
    secret: String,
    #[redact(sensitivity = pii_phone, mode = "last4")]
    card: String,
    #[redact(sensitivity = pii_email, mode = "email_mask")]
    email: String,
    #[redact(sensitivity = secret, mode = "drop")]
    gone: String,
}

// F2 回归（#1360）：自定义类型字段标显式 `mode = "fixed"`/`drop` **不要求** impl `RedactField`
//（compile-pass 即证）——对标 serde `skip` 字段不走默认 Serialize bound。
struct NotRedactField; // 故意不 impl RedactField

#[derive(rss_redact::Redact)]
#[allow(dead_code)] // fixed/drop 字段取 Absent、不被读取
struct CustomFixedDrop {
    #[redact(sensitivity = secret, mode = "fixed")]
    a: NotRedactField,
    #[redact(sensitivity = secret, mode = "drop")]
    b: NotRedactField,
}

#[test]
fn derive_fixed_drop_needs_no_redact_field_bound() {
    let v = CustomFixedDrop {
        a: NotRedactField,
        b: NotRedactField,
    };
    // a: Fixed → <redacted>；b: Drop → 剔除；NotRedactField 无 RedactField impl。
    assert_eq!(format!("{v:?}"), "CustomFixedDrop { a: <redacted> }");
}

#[test]
fn derive_newtype_debug_is_opaque() {
    let v = DerivedNewtype(vec![0xDE, 0xAD]);
    assert_eq!(format!("{v:?}"), "DerivedNewtype(<redacted>)");
}

#[test]
fn derive_mixed_debug_applies_per_field_policy() {
    let v = DerivedMixed {
        visible: "ok".to_string(),
        secret: "topsecret".to_string(),
        card: "4242424242424242".to_string(),
        email: "alice@example.com".to_string(),
        gone: "vanish".to_string(),
    };
    let dbg = format!("{v:?}");
    // Show 字段 `visible` 经 Debug-转义（#1360 F3）：`ok` → `"ok"`；其余 mode 产物不转义。
    assert_eq!(
        dbg,
        "DerivedMixed { visible: \"ok\", secret: <redacted>, card: ****4242, email: a***@example.com }"
    );
    assert!(!dbg.contains("topsecret"));
    assert!(!dbg.contains("vanish"));
    assert!(!dbg.contains("gone"));
}

#[test]
fn derive_impls_redact_trait() {
    // 派生实现 trait `Redact::redact_scoped`（Debug 委托它）；返回脱敏 String（非 Redacted，#1360 F1）。
    let v = DerivedNewtype(vec![1]);
    let r: String = rss_redact::Redact::redact_scoped(&v, RedactScope::ServerLog);
    assert_eq!(r, "DerivedNewtype(<redacted>)");
}

#[test]
fn derive_forwards_scope_to_the_runtime_policy() {
    let value = DerivedMixed {
        visible: "ok".to_owned(),
        secret: "topsecret".to_owned(),
        card: "4242424242424242".to_owned(),
        email: "alice@example.com".to_owned(),
        gone: "vanish".to_owned(),
    };
    let server = rss_redact::safe(&value, RedactScope::ServerLog);
    let wire = rss_redact::safe(&value, RedactScope::Wire);
    assert_eq!(server, format!("{value:?}"));
    assert!(server.contains("card: ****4242"));
    assert!(server.contains("email: a***@example.com"));
    assert_eq!(
        wire,
        "DerivedMixed { visible: \"ok\", secret: <redacted>, card: <redacted>, email: <redacted> }"
    );
    assert_eq!(
        rss_redact::LastError::from_redactable(&value, RedactScope::Wire).as_str(),
        wire
    );
}
