//! Provider credential storage. ref: ring 0.17.14 src/aead/less_safe_key.rs.
use crate::{
    AuthorityError,
    storage::authority_id,
    transaction::{MutationError, corrupt},
};
use ring::{
    aead,
    rand::{SecureRandom, SystemRandom},
};
use rss_identity_core::federation::MAX_PROVIDERS;
use rss_identity_core::federation::{FederationError, ProviderCredentials, ProviderId};
use rss_request_context::TenantId;
use rss_transactional_messaging::fence::ExecutionBinding;
use rss_transactional_messaging::policy::OperationDeadline;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use uuid::Uuid;
use zeroize::Zeroizing;

/// File-loaded encryption keys; never inferred from persisted provider values.
pub struct CredentialKeys {
    active: String,
    keys: BTreeMap<String, aead::LessSafeKey>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Sealed {
    version: u32,
    key_id: String,
    nonce: [u8; 12],
    ciphertext: Vec<u8>,
}
#[derive(Serialize)]
struct Context<'a> {
    authority: Uuid,
    tenant: String,
    provider: String,
    credential_version: i64,
    purpose: &'a str,
}
impl CredentialKeys {
    pub fn new(active: String, keys: Vec<(String, [u8; 32])>) -> Result<Self, AuthorityError> {
        if keys.is_empty() || keys.len() > 8 {
            return Err(AuthorityError::Configuration);
        }
        let mut values = BTreeMap::new();
        let mut digests = std::collections::BTreeSet::new();
        for (id, raw) in keys {
            let raw = Zeroizing::new(raw);
            if id.is_empty()
                || id.len() > 64
                || !id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
                || raw.iter().all(|b| *b == 0)
                || !digests.insert({
                    use sha2::Digest;
                    <[u8; 32]>::from(sha2::Sha256::digest(raw.as_ref()))
                })
            {
                return Err(AuthorityError::Configuration);
            }
            let key = aead::UnboundKey::new(&aead::AES_256_GCM, raw.as_ref())
                .map_err(|_| AuthorityError::Configuration)?;
            if values.insert(id, aead::LessSafeKey::new(key)).is_some() {
                return Err(AuthorityError::Configuration);
            }
        }
        if !values.contains_key(&active) {
            return Err(AuthorityError::Configuration);
        }
        Ok(Self {
            active,
            keys: values,
        })
    }
    pub fn active_key_id(&self) -> &str {
        &self.active
    }
    pub fn has_key(&self, id: &str) -> bool {
        self.keys.contains_key(id)
    }
    fn reencrypt_value(
        &self,
        authority: Uuid,
        tenant: TenantId,
        provider: ProviderId,
        version: i64,
        value: serde_json::Value,
    ) -> Result<serde_json::Value, AuthorityError> {
        let sealed: Sealed =
            serde_json::from_value(value).map_err(|_| AuthorityError::Unavailable)?;
        if !self.has_key(&sealed.key_id) {
            return Err(AuthorityError::Unavailable);
        }
        let plain = self.open(authority, tenant, provider, version, &sealed)?;
        if sealed.key_id == self.active {
            return serde_json::to_value(sealed).map_err(|_| AuthorityError::Unavailable);
        }
        serde_json::to_value(self.seal(authority, tenant, provider, version, &plain)?)
            .map_err(|_| AuthorityError::Unavailable)
    }
    /// Re-encrypt all provider credentials in one tenant, authenticating even active-key values.
    /// Requires the schema owner's transaction. The host must establish its execution fence and
    /// statement/lock budgets before calling, and owns commit/rollback and unknown settlement.
    /// The component holds the same tenant guard as provider writers and enforces their capacity.
    /// An uninitialized tenant has no credentials and is a successful empty operation.
    pub async fn reencrypt_tenant(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        instance: rss_identity_core::InstanceId,
        tenant: TenantId,
    ) -> Result<usize, AuthorityError> {
        let owner: bool = sqlx::query_scalar("SELECT nspowner=(SELECT oid FROM pg_roles WHERE rolname=current_user) FROM pg_namespace WHERE nspname='identity_authority'")
            .fetch_one(&mut **tx).await.map_err(|_| AuthorityError::Unavailable)?;
        if !owner {
            return Err(AuthorityError::Configuration);
        }
        if authority_id(tx)
            .await
            .map_err(|_| AuthorityError::Unavailable)?
            != instance.as_uuid()
        {
            return Err(AuthorityError::Configuration);
        }
        sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
            .bind(tenant.to_string())
            .execute(&mut **tx)
            .await
            .map_err(|_| AuthorityError::Unavailable)?;
        sqlx::query(
            "SELECT tenant_id FROM identity_authority.tenants WHERE tenant_id=$1::uuid FOR UPDATE",
        )
        .bind(tenant.to_string())
        .fetch_optional(&mut **tx)
        .await
        .map_err(|_| AuthorityError::Unavailable)?;
        let rows: Vec<(Uuid, i64, serde_json::Value)> = sqlx::query_as("SELECT provider_id,credential_version,sealed FROM identity_authority.provider_credentials WHERE tenant_id=$1::uuid ORDER BY provider_id LIMIT $2 FOR UPDATE")
            .bind(tenant.to_string()).bind(i64::from(MAX_PROVIDERS) + 1).fetch_all(&mut **tx).await.map_err(|_| AuthorityError::Unavailable)?;
        if rows.len() > usize::from(MAX_PROVIDERS) {
            return Err(AuthorityError::Configuration);
        }
        let count = rows.len();
        for (id, version, value) in rows {
            let provider =
                ProviderId::parse(&id.to_string()).map_err(|_| AuthorityError::Unavailable)?;
            let sealed =
                self.reencrypt_value(instance.as_uuid(), tenant, provider, version, value)?;
            sqlx::query("UPDATE identity_authority.provider_credentials SET sealed=$3 WHERE tenant_id=$1::uuid AND provider_id=$2")
                .bind(tenant.to_string()).bind(id).bind(sealed).execute(&mut **tx).await.map_err(|_| AuthorityError::Unavailable)?;
        }
        Ok(count)
    }
    fn aad(
        authority: Uuid,
        tenant: TenantId,
        provider: ProviderId,
        version: i64,
    ) -> Result<Vec<u8>, AuthorityError> {
        if version < 1 {
            return Err(AuthorityError::InvalidInput);
        }
        serde_json::to_vec(&Context {
            authority,
            tenant: tenant.to_string(),
            provider: provider.to_string(),
            credential_version: version,
            purpose: "oidc-client-secret",
        })
        .map_err(|_| AuthorityError::Unavailable)
    }
    pub(crate) fn seal(
        &self,
        authority: Uuid,
        tenant: TenantId,
        provider: ProviderId,
        version: i64,
        value: &ProviderCredentials,
    ) -> Result<Sealed, AuthorityError> {
        let aad = Self::aad(authority, tenant, provider, version)?;
        #[derive(Serialize)]
        struct Plain<'a> {
            secret: &'a str,
            ca: Option<&'a str>,
        }
        let mut bytes = Zeroizing::new(
            serde_json::to_vec(&Plain {
                secret: value.client_secret(),
                ca: value.ca_pem(),
            })
            .map_err(|_| AuthorityError::Unavailable)?,
        );
        let mut nonce = [0; 12];
        SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| AuthorityError::Unavailable)?;
        self.keys[&self.active]
            .seal_in_place_append_tag(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::from(aad),
                &mut *bytes,
            )
            .map_err(|_| AuthorityError::Unavailable)?;
        Ok(Sealed {
            version: 1,
            key_id: self.active.clone(),
            nonce,
            ciphertext: bytes.to_vec(),
        })
    }
    pub(crate) fn open(
        &self,
        authority: Uuid,
        tenant: TenantId,
        provider: ProviderId,
        version: i64,
        value: &Sealed,
    ) -> Result<ProviderCredentials, AuthorityError> {
        if value.version != 1 || value.ciphertext.len() > 32768 {
            return Err(AuthorityError::Unavailable);
        }
        let aad = Self::aad(authority, tenant, provider, version)?;
        let key = self
            .keys
            .get(&value.key_id)
            .ok_or(AuthorityError::Unavailable)?;
        let mut bytes = Zeroizing::new(value.ciphertext.clone());
        let plain = key
            .open_in_place(
                aead::Nonce::assume_unique_for_key(value.nonce),
                aead::Aad::from(aad),
                &mut bytes,
            )
            .map_err(|_| AuthorityError::Unavailable)?;
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Plain {
            secret: String,
            ca: Option<String>,
        }
        let value: Plain =
            serde_json::from_slice(plain).map_err(|_| AuthorityError::Unavailable)?;
        ProviderCredentials::new(value.secret, value.ca).map_err(|_| AuthorityError::Unavailable)
    }
}
impl crate::Federation {
    /// Authenticate provider credentials for this exact target only. The host owns paging,
    /// concurrent-writer exclusion and the decision to retire an old key.
    pub async fn check_credential_keys(
        &self,
        binding: ExecutionBinding,
        deadline: OperationDeadline,
    ) -> Result<(), AuthorityError> {
        let keys = self.credential_keys.clone();
        let budget = crate::Budget::new(deadline)?;
        let tenant = binding.tenant();
        self.authority.read_sql(binding,budget.remaining(),move|c|Box::pin(async move {
                let authority=authority_id(c).await?;
                let rows:Vec<(Uuid,i64,serde_json::Value)>=sqlx::query_as("SELECT provider_id,credential_version,sealed FROM identity_authority.provider_credentials WHERE tenant_id=$1::uuid LIMIT $2").bind(tenant.to_string()).bind(i64::from(MAX_PROVIDERS) + 1).fetch_all(c).await?;
                if rows.len() > usize::from(MAX_PROVIDERS) {return Err(corrupt().into());}
                for (provider,version,value) in rows {
                    let provider=ProviderId::parse(&provider.to_string()).map_err(|_|corrupt())?;
                    let sealed:Sealed=serde_json::from_value(value).map_err(|_|corrupt())?;
                    keys.open(authority,tenant,provider,version,&sealed).map_err(|_|corrupt())?;
                }
                Ok(())
            })).await?;
        Ok(())
    }
    pub(crate) async fn installed_provider(
        &self,
        binding: ExecutionBinding,
        view: &rss_identity_core::federation::ProviderView,
        deadline: OperationDeadline,
    ) -> Result<rss_identity_core::federation::BoundProvider, AuthorityError> {
        let tenant = binding.tenant();
        let revision = view.revision(self.authority.instance(), tenant);
        let credential_version = view.credential_version;
        let settings = view.settings.clone();
        let keys = self.credential_keys.clone();
        let oidc = self.oidc.clone();
        self.authority.read_sql(binding,deadline,move |c| Box::pin(async move {
            let authority = authority_id(c).await?;
            // Serialize snapshot admission with configuration changes, before releasing this
            // transaction. No database lock or secret is retained by the HTTP cache.
            let row: Option<(i64, i64, serde_json::Value)> = sqlx::query_as(
                "SELECT p.config_version,k.credential_version,k.sealed FROM identity_authority.providers p JOIN identity_authority.provider_credentials k USING(tenant_id,provider_id) WHERE p.tenant_id=$1::uuid AND p.provider_id=$2::uuid AND p.credential_version=k.credential_version FOR SHARE OF p"
            ).bind(tenant.to_string()).bind(revision.provider.to_string()).fetch_optional(&mut *c).await?;
            let (version, current, sealed) = row.ok_or(FederationError::Rejected)?;
            if version != revision.version || current != credential_version { return Err(FederationError::StaleConfiguration.into()); }
            let sealed: Sealed = serde_json::from_value(sealed).map_err(|_| corrupt())?;
            let credentials = keys.open(authority, tenant, revision.provider, current, &sealed).map_err(|_| MutationError::Storage(corrupt()))?;
            Ok(oidc.revisions().install(revision,settings,credentials)?)
        })).await
    }
}

pub(crate) async fn write_credentials(
    c: &mut sqlx::PgConnection,
    keys: &CredentialKeys,
    tenant: TenantId,
    provider: ProviderId,
    version: i64,
    value: &ProviderCredentials,
) -> Result<(), MutationError> {
    let authority = authority_id(c).await?;
    let sealed = keys
        .seal(authority, tenant, provider, version, value)
        .map_err(|_| corrupt())?;
    sqlx::query("INSERT INTO identity_authority.provider_credentials VALUES($1::uuid,$2::uuid,$3,$4) ON CONFLICT(tenant_id,provider_id) DO UPDATE SET credential_version=EXCLUDED.credential_version,sealed=EXCLUDED.sealed").bind(tenant.to_string()).bind(provider.to_string()).bind(version).bind(serde_json::to_value(sealed).map_err(|_|corrupt())?).execute(c).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn credentials_are_authenticated_to_their_owner_and_version() {
        let keys = CredentialKeys::new("first".into(), vec![("first".into(), [1; 32])]).unwrap();
        let a = Uuid::new_v4();
        let t = TenantId::parse("11111111-1111-4111-8111-111111111111").unwrap();
        let p = ProviderId::generate();
        let plain = ProviderCredentials::new("private-client-secret".into(), None).unwrap();
        let mut sealed = keys.seal(a, t, p, 1, &plain).unwrap();
        assert_eq!(
            keys.open(a, t, p, 1, &sealed).unwrap().client_secret(),
            plain.client_secret()
        );
        assert!(keys.open(Uuid::new_v4(), t, p, 1, &sealed).is_err());
        assert!(keys.open(a, t, ProviderId::generate(), 1, &sealed).is_err());
        assert!(keys.open(a, t, p, 2, &sealed).is_err());
        let other_tenant = TenantId::parse("22222222-2222-4222-8222-222222222222").unwrap();
        assert!(keys.open(a, other_tenant, p, 1, &sealed).is_err());
        let encoded = serde_json::to_string(&sealed).unwrap();
        assert!(!encoded.contains(plain.client_secret()));
        sealed.ciphertext[0] ^= 1;
        assert!(keys.open(a, t, p, 1, &sealed).is_err());
        let rotated = CredentialKeys::new(
            "next".into(),
            vec![("first".into(), [1; 32]), ("next".into(), [2; 32])],
        )
        .unwrap();
        let old = keys.seal(a, t, p, 1, &plain).unwrap();
        assert!(rotated.open(a, t, p, 1, &old).is_ok());
        let removed = CredentialKeys::new("next".into(), vec![("next".into(), [2; 32])]).unwrap();
        assert!(removed.open(a, t, p, 1, &old).is_err());
        let new = rotated
            .seal(a, t, p, 1, &rotated.open(a, t, p, 1, &old).unwrap())
            .unwrap();
        assert!(removed.open(a, t, p, 1, &new).is_ok());
    }
}
