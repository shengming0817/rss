//! Private key-provider-backed DLX archive encryption service.

use diport::key_provider::KeyProviderErrorKind;
use diport::{
    DLX_MAX_ARCHIVE_CIPHERTEXT_BYTES, DlxLifecycleError, DlxLifecycleOperation, DlxLifecycleReason,
    KeyProvider, RedactedBytes,
};
use secure::{Plaintext, ProtectionContext};

use crate::dlx_lifecycle::{DlxArchiveKeyName, DlxArchiveObjectKey};
use diport::DlxArchiveCiphertext;

/// Concrete archive cipher. The typed key and typed tenant/object coordinates make hot-key
/// substitution and cross-tenant ciphertext replay unrepresentable at this boundary.
pub(crate) struct DlxArchiveCrypto<K> {
    provider: K,
    archive_key: DlxArchiveKeyName,
}

impl<K> DlxArchiveCrypto<K>
where
    K: KeyProvider,
{
    pub(crate) fn new(provider: K, archive_key: DlxArchiveKeyName) -> Self {
        Self {
            provider,
            archive_key,
        }
    }

    pub(crate) async fn seal(
        &self,
        tenant: rss_request_context::TenantId,
        plaintext: Plaintext,
        object_key: &DlxArchiveObjectKey,
    ) -> Result<DlxArchiveCiphertext, DlxLifecycleError> {
        let aad = archive_aad(tenant, object_key, DlxLifecycleOperation::EncryptArchive)?;
        let output = self
            .provider
            .encrypt(self.archive_key.as_key_name().clone(), plaintext, aad)
            .await
            .map_err(|error| {
                map_key_provider_error(DlxLifecycleOperation::EncryptArchive, error)
            })?;
        if !output.key().name().ct_eq(self.archive_key.as_key_name()) {
            return Err(DlxLifecycleError::new(
                DlxLifecycleOperation::EncryptArchive,
                DlxLifecycleReason::KeyMismatch,
            ));
        }
        if output.ciphertext().len() > DLX_MAX_ARCHIVE_CIPHERTEXT_BYTES {
            return Err(DlxLifecycleError::new(
                DlxLifecycleOperation::EncryptArchive,
                DlxLifecycleReason::SizeLimitExceeded,
            ));
        }
        Ok(DlxArchiveCiphertext::new(
            RedactedBytes::new(output.ciphertext().to_vec()),
            output.key().clone(),
        ))
    }

    pub(crate) async fn open(
        &self,
        tenant: rss_request_context::TenantId,
        ciphertext: DlxArchiveCiphertext,
        object_key: &DlxArchiveObjectKey,
    ) -> Result<Plaintext, DlxLifecycleError> {
        if !ciphertext
            .key_ref()
            .name()
            .ct_eq(self.archive_key.as_key_name())
        {
            return Err(DlxLifecycleError::new(
                DlxLifecycleOperation::DecryptArchive,
                DlxLifecycleReason::KeyMismatch,
            ));
        }
        let aad = archive_aad(tenant, object_key, DlxLifecycleOperation::DecryptArchive)?;
        self.provider
            .decrypt(
                ciphertext.ciphertext().clone(),
                ciphertext.key_ref().clone(),
                aad,
            )
            .await
            .map_err(|error| map_key_provider_error(DlxLifecycleOperation::DecryptArchive, error))
    }
}

fn archive_aad(
    tenant: rss_request_context::TenantId,
    object_key: &DlxArchiveObjectKey,
    operation: DlxLifecycleOperation,
) -> Result<secure::DerivedAad, DlxLifecycleError> {
    const ARCHIVE_FIELD: &str = "canonical_archive";
    const ARCHIVE_SCHEMA_VERSION: u32 = 1;
    ProtectionContext::authorized_maintenance(
        tenant,
        object_key.as_str(),
        ARCHIVE_FIELD,
        ARCHIVE_SCHEMA_VERSION,
    )
    .map(|context| context.derive())
    .map_err(|_| DlxLifecycleError::new(operation, DlxLifecycleReason::InternalInvariant))
}

fn map_key_provider_error(
    operation: DlxLifecycleOperation,
    error: diport::KeyProviderError,
) -> DlxLifecycleError {
    let reason = match error.kind() {
        KeyProviderErrorKind::Unavailable => DlxLifecycleReason::ProviderUnavailable,
        KeyProviderErrorKind::Timeout => DlxLifecycleReason::ProviderTimeout,
        KeyProviderErrorKind::NotFound => DlxLifecycleReason::KeyNotFound,
        KeyProviderErrorKind::Forbidden => DlxLifecycleReason::KeyForbidden,
        KeyProviderErrorKind::Rejected => DlxLifecycleReason::KeyRejected,
        _ => DlxLifecycleReason::UnexpectedProviderResponse,
    };
    DlxLifecycleError::new(operation, reason)
}

#[cfg(test)]
mod tests {
    use diport::key_provider::KeyProviderErrorKind;
    use diport::{
        DlxArchiveCiphertext, DlxLifecycleOperation, DlxLifecycleReason, EncryptOutput, KeyName,
        KeyProvider, KeyProviderError, KeyRef, KeyVersion, RedactedBytes,
    };
    use secure::{DerivedAad, Plaintext};

    use super::{DlxArchiveCrypto, archive_aad, map_key_provider_error};
    use crate::{DeadLetterId, DlxArchiveKeyName, DlxArchiveObjectKey};
    use diport::DlxLifecycleErrorKind;

    struct TestKeyProvider {
        failure: Option<KeyProviderErrorKind>,
    }

    impl TestKeyProvider {
        fn successful() -> Self {
            Self { failure: None }
        }

        fn failing(kind: KeyProviderErrorKind) -> Self {
            Self {
                failure: Some(kind),
            }
        }

        fn maybe_fail(&self) -> Result<(), KeyProviderError> {
            self.failure.map_or(Ok(()), |kind| {
                Err(KeyProviderError::new(
                    kind,
                    std::io::Error::other("provider"),
                ))
            })
        }
    }

    impl KeyProvider for TestKeyProvider {
        async fn encrypt(
            &self,
            key: KeyName,
            plaintext: Plaintext,
            aad: DerivedAad,
        ) -> Result<EncryptOutput, KeyProviderError> {
            self.maybe_fail()?;
            let aad_bytes = aad.as_canonical_bytes();
            let aad_len = u32::try_from(aad_bytes.len()).map_err(|_| {
                KeyProviderError::new(
                    KeyProviderErrorKind::Rejected,
                    std::io::Error::other("test aad too long"),
                )
            })?;
            let mut bound = Vec::with_capacity(
                8usize
                    .saturating_add(aad_bytes.len())
                    .saturating_add(plaintext.expose().len()),
            );
            bound.extend_from_slice(&9u32.to_be_bytes());
            bound.extend_from_slice(&aad_len.to_be_bytes());
            bound.extend_from_slice(aad_bytes);
            bound.extend_from_slice(plaintext.expose());
            Ok(EncryptOutput::new(
                bound,
                KeyRef::new(key, KeyVersion::new(9)),
            ))
        }

        async fn decrypt(
            &self,
            ciphertext: RedactedBytes,
            key: KeyRef,
            aad: DerivedAad,
        ) -> Result<Plaintext, KeyProviderError> {
            self.maybe_fail()?;
            let bytes = ciphertext.into_bytes();
            let Some(version_bytes) = bytes.get(..4).and_then(|raw| raw.try_into().ok()) else {
                return Err(test_rejected("test ciphertext version"));
            };
            let persisted_version = KeyVersion::new(u32::from_be_bytes(version_bytes));
            if !persisted_version.ct_eq(&key.version()) {
                return Err(test_rejected("test ciphertext key version mismatch"));
            }
            let Some(length_bytes) = bytes.get(4..8).and_then(|raw| raw.try_into().ok()) else {
                return Err(test_rejected("test ciphertext header"));
            };
            let aad_len = usize::try_from(u32::from_be_bytes(length_bytes))
                .map_err(|_| test_rejected("test aad length"))?;
            let Some(stored_aad) = bytes.get(8..8usize.saturating_add(aad_len)) else {
                return Err(test_rejected("test ciphertext aad"));
            };
            if stored_aad != aad.as_canonical_bytes() {
                return Err(test_rejected("test aad mismatch"));
            }
            let Some(plaintext) = bytes.get(8usize.saturating_add(aad_len)..) else {
                return Err(test_rejected("test ciphertext body"));
            };
            Ok(Plaintext::new(plaintext.to_vec()))
        }

        async fn rewrap(
            &self,
            ciphertext: RedactedBytes,
            key: KeyRef,
            _aad: DerivedAad,
        ) -> Result<EncryptOutput, KeyProviderError> {
            self.maybe_fail()?;
            Ok(EncryptOutput::new(ciphertext.into_bytes(), key))
        }

        async fn shutdown(&self) -> Result<(), KeyProviderError> {
            self.maybe_fail()
        }
    }

    fn test_rejected(message: &'static str) -> KeyProviderError {
        KeyProviderError::new(
            KeyProviderErrorKind::Rejected,
            std::io::Error::other(message),
        )
    }

    fn tenant(raw: &str) -> Result<rss_request_context::TenantId, Box<dyn std::error::Error>> {
        Ok(rss_request_context::TenantId::parse(raw)?)
    }

    fn object_key(raw: &str) -> Result<DlxArchiveObjectKey, Box<dyn std::error::Error>> {
        Ok(DlxArchiveObjectKey::from_dead_letter(&DeadLetterId::parse(
            raw,
        )?))
    }

    fn archive_key() -> Result<DlxArchiveKeyName, Box<dyn std::error::Error>> {
        Ok(DlxArchiveKeyName::try_new("dlx-archive")?)
    }

    #[test]
    fn archive_aad_binds_tenant_and_typed_object_key() -> Result<(), Box<dyn std::error::Error>> {
        let key_a = object_key("018f31a8-893d-7a52-8e17-3ca9df50120b")?;
        let key_b = object_key("018f31a8-893d-7a52-8e17-3ca9df50120c")?;
        let tenant_a = tenant("11111111-2222-4333-8444-555555555555")?;
        let tenant_b = tenant("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee")?;
        let aad_a = archive_aad(tenant_a, &key_a, DlxLifecycleOperation::EncryptArchive)?;
        let aad_b = archive_aad(tenant_b, &key_a, DlxLifecycleOperation::EncryptArchive)?;
        let aad_c = archive_aad(tenant_a, &key_b, DlxLifecycleOperation::EncryptArchive)?;
        assert_ne!(aad_a.as_canonical_bytes(), aad_b.as_canonical_bytes());
        assert_ne!(aad_a.as_canonical_bytes(), aad_c.as_canonical_bytes());
        Ok(())
    }

    #[test]
    fn key_provider_failures_map_to_closed_lifecycle_classes() {
        for kind in [
            KeyProviderErrorKind::Unavailable,
            KeyProviderErrorKind::Timeout,
        ] {
            let error = KeyProviderError::new(kind, std::io::Error::other("provider"));
            assert_eq!(
                map_key_provider_error(DlxLifecycleOperation::EncryptArchive, error).kind(),
                DlxLifecycleErrorKind::Transient
            );
        }
        for kind in [
            KeyProviderErrorKind::NotFound,
            KeyProviderErrorKind::Forbidden,
            KeyProviderErrorKind::Rejected,
        ] {
            let error = KeyProviderError::new(kind, std::io::Error::other("provider"));
            assert_eq!(
                map_key_provider_error(DlxLifecycleOperation::DecryptArchive, error).kind(),
                DlxLifecycleErrorKind::Invariant
            );
        }
    }

    #[tokio::test]
    async fn concrete_cipher_seals_and_opens_plaintext_with_archive_key()
    -> Result<(), Box<dyn std::error::Error>> {
        let cipher = DlxArchiveCrypto::new(TestKeyProvider::successful(), archive_key()?);
        let tenant = tenant("11111111-2222-4333-8444-555555555555")?;
        let object_key = object_key("018f31a8-893d-7a52-8e17-3ca9df50120b")?;
        let sealed = cipher
            .seal(
                tenant,
                Plaintext::new(b"canonical-record".to_vec()),
                &object_key,
            )
            .await?;
        assert_ne!(sealed.ciphertext().as_bytes(), b"canonical-record");
        assert_eq!(sealed.key_ref().version().as_u32(), 9);
        let opened = cipher.open(tenant, sealed, &object_key).await?;
        assert_eq!(opened.expose(), b"canonical-record");
        Ok(())
    }

    #[tokio::test]
    async fn concrete_cipher_rejects_wrong_tenant_and_object_key()
    -> Result<(), Box<dyn std::error::Error>> {
        let cipher = DlxArchiveCrypto::new(TestKeyProvider::successful(), archive_key()?);
        let tenant_a = tenant("11111111-2222-4333-8444-555555555555")?;
        let tenant_b = tenant("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee")?;
        let object_a = object_key("018f31a8-893d-7a52-8e17-3ca9df50120b")?;
        let object_b = object_key("018f31a8-893d-7a52-8e17-3ca9df50120c")?;

        let wrong_tenant = cipher
            .seal(
                tenant_a,
                Plaintext::new(b"canonical-record".to_vec()),
                &object_a,
            )
            .await?;
        assert!(matches!(
            cipher
                .open(tenant_b, wrong_tenant, &object_a)
                .await
                .map_err(|error| error.kind()),
            Err(DlxLifecycleErrorKind::Invariant)
        ));

        let wrong_object = cipher
            .seal(
                tenant_a,
                Plaintext::new(b"canonical-record".to_vec()),
                &object_a,
            )
            .await?;
        assert!(matches!(
            cipher
                .open(tenant_a, wrong_object, &object_b)
                .await
                .map_err(|error| error.kind()),
            Err(DlxLifecycleErrorKind::Invariant)
        ));
        Ok(())
    }

    #[tokio::test]
    async fn concrete_cipher_maps_provider_failures_without_leaking_details()
    -> Result<(), Box<dyn std::error::Error>> {
        let tenant = tenant("11111111-2222-4333-8444-555555555555")?;
        let object_key = object_key("018f31a8-893d-7a52-8e17-3ca9df50120b")?;
        let transient = DlxArchiveCrypto::new(
            TestKeyProvider::failing(KeyProviderErrorKind::Unavailable),
            archive_key()?,
        );
        let error = transient
            .seal(
                tenant,
                Plaintext::new(b"canonical-record".to_vec()),
                &object_key,
            )
            .await;
        assert!(matches!(
            error.map_err(|error| error.kind()),
            Err(DlxLifecycleErrorKind::Transient)
        ));

        let invariant = DlxArchiveCrypto::new(
            TestKeyProvider::failing(KeyProviderErrorKind::Rejected),
            archive_key()?,
        );
        let ciphertext = DlxArchiveCiphertext::new(
            RedactedBytes::new(b"cipher".to_vec()),
            KeyRef::new(archive_key()?.as_key_name().clone(), KeyVersion::new(9)),
        );
        let error = invariant.open(tenant, ciphertext, &object_key).await;
        assert!(matches!(
            error.map_err(|error| error.kind()),
            Err(DlxLifecycleErrorKind::Invariant)
        ));
        Ok(())
    }

    #[tokio::test]
    async fn concrete_cipher_rejects_persisted_key_version_mismatch()
    -> Result<(), Box<dyn std::error::Error>> {
        let cipher = DlxArchiveCrypto::new(TestKeyProvider::successful(), archive_key()?);
        let tenant = tenant("11111111-2222-4333-8444-555555555555")?;
        let object_key = object_key("018f31a8-893d-7a52-8e17-3ca9df50120b")?;
        let sealed = cipher
            .seal(
                tenant,
                Plaintext::new(b"canonical-record".to_vec()),
                &object_key,
            )
            .await?;
        let wrong_ref = KeyRef::new(archive_key()?.as_key_name().clone(), KeyVersion::new(8));
        let wrong = DlxArchiveCiphertext::new(sealed.ciphertext().clone(), wrong_ref);
        let error = match cipher.open(tenant, wrong, &object_key).await {
            Err(error) => error,
            Ok(_) => {
                return Err(std::io::Error::other(
                    "fake accepted a mismatched persisted key version",
                )
                .into());
            }
        };
        assert_eq!(error.operation(), DlxLifecycleOperation::DecryptArchive);
        assert_eq!(error.reason(), DlxLifecycleReason::KeyRejected);
        Ok(())
    }
}
