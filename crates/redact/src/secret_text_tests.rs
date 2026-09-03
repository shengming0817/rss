use crate::{Redact, RedactScope, SecretText};

fn assert_runtime_secret_traits<T: Send + Sync + 'static + zeroize::ZeroizeOnDrop>() {}

#[test]
fn secret_text_preserves_owned_text_and_transfers_ownership() {
    let secret = SecretText::from_string("  MiXeD secret  ".to_owned());
    assert_eq!(secret.expose(), "  MiXeD secret  ");
    assert_eq!(secret.into_string(), "  MiXeD secret  ");
}

#[test]
fn secret_text_debug_and_redact_hide_all_material() {
    let bait = "postgres://user:dsn-password@db/vault-token.jwt-hmac.PEM";
    let secret = SecretText::from_string(bait.to_owned());

    let debug = format!("{secret:?}");
    let redacted = secret.redact_scoped(RedactScope::ServerLog);

    assert_eq!(debug, "SecretText(<redacted>)");
    assert_eq!(redacted, "SecretText(<redacted>)");
    for fragment in ["dsn-password", "vault-token", "jwt-hmac", "PEM"] {
        assert!(!debug.contains(fragment));
        assert!(!redacted.contains(fragment));
    }
}

#[test]
fn secret_text_is_an_owned_process_lifetime_zeroizing_value() {
    assert_runtime_secret_traits::<SecretText>();
}
