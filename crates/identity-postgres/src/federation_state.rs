//! Signed continuation of one exact Identity execution scope.
//! ref: RustCrypto/MACs hmac/src/lib.rs@hmac-v0.12.1.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use hmac::{Hmac, Mac};
use rand_core::{OsRng, RngCore};
use rss_identity_core::{InstanceId, federation::FederationError};
use rss_request_context::TenantId;
use rss_transactional_messaging::fence::{Epoch, ExecutionBinding, StorageIdentity};
use sha2::Sha256;
use uuid::Uuid;
use zeroize::Zeroizing;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Purpose {
    Login,
    Reauthenticate,
    Link,
}

impl Purpose {
    pub fn code(self) -> u8 {
        match self {
            Self::Login => 0,
            Self::Reauthenticate => 1,
            Self::Link => 2,
        }
    }

    pub fn from_code(code: u8) -> Result<Self, FederationError> {
        match code {
            0 => Ok(Self::Login),
            1 => Ok(Self::Reauthenticate),
            2 => Ok(Self::Link),
            _ => Err(FederationError::Rejected),
        }
    }
}

/// Separate from all client and session secrets. One current key; rotation cancels pending flows.
pub struct StateSigner {
    key: Zeroizing<[u8; 32]>,
    origin: String,
}

pub(crate) struct StateLocator {
    binding: ExecutionBinding,
    id: [u8; 32],
    purpose: Purpose,
}

impl StateLocator {
    pub(crate) fn binding(&self) -> ExecutionBinding {
        self.binding
    }
    pub fn tenant(&self) -> TenantId {
        self.binding.tenant()
    }

    pub fn id(&self) -> &[u8; 32] {
        &self.id
    }

    pub fn purpose(&self) -> Purpose {
        self.purpose
    }
}

impl StateSigner {
    pub fn new(key: [u8; 32], origin: &str) -> Result<Self, FederationError> {
        if key == [0; 32] || origin.is_empty() || origin.len() > 2048 {
            return Err(FederationError::Configuration);
        }

        Ok(Self {
            key: Zeroizing::new(key),
            origin: origin.into(),
        })
    }

    fn mac(&self, instance: InstanceId, payload: &[u8]) -> Hmac<Sha256> {
        let mut mac =
            Hmac::<Sha256>::new_from_slice(self.key.as_ref()).expect("HMAC accepts 32-byte keys");

        mac.update(b"rss-identity.oidc.state.v2\0");

        mac.update(&(self.origin.len() as u32).to_be_bytes());

        mac.update(self.origin.as_bytes());

        mac.update(instance.as_uuid().as_bytes());
        mac.update(payload);

        mac
    }

    pub(crate) fn issue(
        &self,
        instance: InstanceId,
        binding: ExecutionBinding,
        purpose: Purpose,
    ) -> Result<String, FederationError> {
        let mut payload = vec![2, purpose.code()];

        let tenant = Uuid::parse_str(&binding.tenant().to_string())
            .map_err(|_| FederationError::Rejected)?;

        payload.extend_from_slice(tenant.as_bytes());
        payload.extend_from_slice(&binding.storage().target());
        payload.extend_from_slice(&binding.storage().lineage());
        payload.extend_from_slice(&binding.epoch().get().to_be_bytes());

        let mut id = [0; 32];

        OsRng
            .try_fill_bytes(&mut id)
            .map_err(|_| FederationError::Unavailable)?;

        payload.extend_from_slice(&id);

        let tag = self.mac(instance, &payload).finalize().into_bytes();

        payload.extend_from_slice(&tag);

        Ok(B64.encode(payload))
    }

    pub(crate) fn verify(
        &self,
        instance: InstanceId,
        state: &str,
    ) -> Result<StateLocator, FederationError> {
        if state.len() != 163 {
            return Err(FederationError::Rejected);
        }

        let bytes = B64.decode(state).map_err(|_| FederationError::Rejected)?;

        if bytes.len() != 122 || B64.encode(&bytes) != state || bytes[0] != 2 {
            return Err(FederationError::Rejected);
        }

        self.mac(instance, &bytes[..90])
            .verify_slice(&bytes[90..])
            .map_err(|_| FederationError::Rejected)?;

        let purpose = Purpose::from_code(bytes[1])?;

        let tenant = TenantId::parse(
            &Uuid::from_slice(&bytes[2..18])
                .map_err(|_| FederationError::Rejected)?
                .to_string(),
        )
        .map_err(|_| FederationError::Rejected)?;

        let storage = StorageIdentity::new(
            bytes[18..34]
                .try_into()
                .map_err(|_| FederationError::Rejected)?,
            bytes[34..50]
                .try_into()
                .map_err(|_| FederationError::Rejected)?,
        )
        .map_err(|_| FederationError::Rejected)?;
        let epoch = Epoch::new(i64::from_be_bytes(
            bytes[50..58]
                .try_into()
                .map_err(|_| FederationError::Rejected)?,
        ))
        .map_err(|_| FederationError::Rejected)?;
        Ok(StateLocator {
            binding: ExecutionBinding::new(storage, tenant, epoch),
            id: bytes[58..90]
                .try_into()
                .map_err(|_| FederationError::Rejected)?,
            purpose,
        })
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn state_authentication_precedes_tenant_use_and_separates_purpose() {
        use super::*;
        let tenant =
            rss_request_context::TenantId::parse("11111111-1111-4111-8111-111111111111").unwrap();
        let signer = StateSigner::new([7; 32], "https://identity.example.test").unwrap();
        let instance = InstanceId::generate();
        let binding = ExecutionBinding::new(
            StorageIdentity::new([1; 16], [2; 16]).unwrap(),
            tenant,
            Epoch::new(7).unwrap(),
        );
        let state = signer.issue(instance, binding, Purpose::Login).unwrap();
        let decoded = signer.verify(instance, &state).unwrap();
        assert_eq!(decoded.tenant(), tenant);
        assert_eq!(decoded.binding(), binding);
        assert!(signer.verify(InstanceId::generate(), &state).is_err());
        assert_eq!(decoded.purpose(), Purpose::Login);
        assert!(
            StateSigner::new([8; 32], "https://identity.example.test")
                .unwrap()
                .verify(instance, &state)
                .is_err()
        );
        assert!(
            StateSigner::new([7; 32], "https://other.example.test")
                .unwrap()
                .verify(instance, &state)
                .is_err()
        );
        for i in 0..state.len() {
            let mut tampered = state.clone().into_bytes();
            tampered[i] = if tampered[i] == b'A' { b'B' } else { b'A' };
            assert!(
                signer
                    .verify(instance, std::str::from_utf8(&tampered).unwrap())
                    .is_err()
            );
        }
    }
}
