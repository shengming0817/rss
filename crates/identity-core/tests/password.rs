use rss_identity_core::account::{LoginKey, Password, PasswordEncoding, PasswordKdf};
#[tokio::test]
async fn passwords_and_login_keys_are_bounded() {
    assert!(LoginKey::parse(" alice").is_err());
    assert!(LoginKey::parse("Ａlice").is_err());
    assert_eq!(LoginKey::parse("ALICE").unwrap().as_str(), "alice");
    assert!(Password::new("short".into()).is_err());
    assert!(LoginKey::parse(&"x".repeat(255)).is_ok());
    assert!(LoginKey::parse(&"x".repeat(256)).is_err());
    let kdf = PasswordKdf::new(
        std::num::NonZeroUsize::new(4).unwrap(),
        std::num::NonZeroU64::new(128 * 1024 * 1024).unwrap(),
    )
    .unwrap();
    let hash = kdf
        .hash(Password::new("correct horse battery staple".into()).unwrap())
        .await
        .unwrap();
    assert!(
        kdf.verify(
            Password::new("correct horse battery staple".into()).unwrap(),
            hash.clone()
        )
        .await
        .unwrap()
    );
    assert!(
        !kdf.verify(
            Password::new("different horse battery staple".into()).unwrap(),
            hash
        )
        .await
        .unwrap()
    );
    assert!(PasswordEncoding::from_storage("$argon2id$v=19$m=999999999,t=2,p=1$c2FsdHNhbHRzYWx0c2FsdA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into()).is_err());
}

#[test]
fn password_work_reservation_is_checked_without_allocating_it() {
    use rss_identity_core::account::PasswordPolicy;
    use std::num::{NonZeroU64, NonZeroUsize};
    for count in [1, 8] {
        let concurrency = NonZeroUsize::new(count).unwrap();
        let nominal = PasswordPolicy::MEMORY_BYTES * count as u64;
        assert!(PasswordKdf::new(concurrency, NonZeroU64::new(nominal).unwrap()).is_err());
        assert!(
            PasswordKdf::new(concurrency, NonZeroU64::new(nominal + 1024 * 1024).unwrap()).is_ok()
        );
    }
    assert!(
        PasswordKdf::new(
            NonZeroUsize::new(usize::MAX).unwrap(),
            NonZeroU64::new(u64::MAX).unwrap()
        )
        .is_err()
    );
}
