//! Consumer-owned, ephemeral AES-GCM key; no KMS, persistence or authentication policy.
use ring::rand::{SecureRandom, SystemRandom};
use rss_data_protection::{
    Aead, AeadError, CiphertextEnvelope, ProtectionContext,
};
use rss_request_context::TenantId;

use rss_examples::ephemeral::EphemeralKey;

pub(super) fn run() -> anyhow::Result<()> {
    let mut bytes = [0; 32];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| AeadError::Seal)?;
    let key = EphemeralKey::from_bytes(&bytes, "ephemeral-example")?;
    // Fixture coordinates only; the application must authorize them before constructing context.
    let tenant = TenantId::parse("11111111-2222-4333-8444-555555555555")?;
    let other = TenantId::parse("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee")?;
    let context = ProtectionContext::new(tenant, "db.dsn", "password", 1)?.derive();
    let envelope = key.seal(b"do-not-log", &context)?;
    let plaintext = key.open(&envelope, &context)?;
    assert_eq!(plaintext.expose(), b"do-not-log");
    assert!(!format!("{plaintext:?}").contains("do-not-log"));
    for (tenant, field) in [(other, "password"), (tenant, "other-field")] {
        let wrong = ProtectionContext::new(tenant, "db.dsn", field, 1)?.derive();
        assert!(matches!(key.open(&envelope, &wrong), Err(AeadError::Open)));
    }
    let corrupted = CiphertextEnvelope::new(
        envelope.alg(),
        envelope.mode(),
        envelope.kid(),
        envelope.key_version(),
        envelope.nonce().to_vec(),
        vec![0; envelope.ciphertext().len()],
        envelope.tag().to_vec(),
        envelope.aad().clone(),
    )?;
    assert!(matches!(
        key.open(&corrupted, &context),
        Err(AeadError::Open)
    ));
    Ok(())
}
