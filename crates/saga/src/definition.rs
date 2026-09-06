//! Exact definitions. ref: oxidecomputer/steno src/saga_action_generic.rs@main
use crate::{Error, Phase, Scope};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

/// Application-owned action implementation generation, distinct from a contract schema digest.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ActionGeneration(rss_contract::SchemaDigest);
impl ActionGeneration {
    /// Parse the canonical sha256 digest of the application's action generation.
    pub fn parse(value: &str) -> Result<Self, Error> {
        rss_contract::SchemaDigest::parse(value)
            .map(Self)
            .map_err(|_| Error::new(crate::ErrorKind::Definition))
    }
    /// Canonical wire representation, retained in historical effect and receipt coordinates.
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "IdentityWire", into = "IdentityWire")]
/// Pinned canonical contract values and application-owned action generation.
pub struct Identity {
    contract: rss_contract::ContractId,
    version: rss_contract::ContractVersion,
    schema: rss_contract::SchemaDigest,
    generation: ActionGeneration,
}
impl Identity {
    /// Pin already validated canonical values without replacing their owners.
    pub const fn new(
        contract: rss_contract::ContractId,
        version: rss_contract::ContractVersion,
        schema: rss_contract::SchemaDigest,
        generation: ActionGeneration,
    ) -> Self {
        Self {
            contract,
            version,
            schema,
            generation,
        }
    }
    /// Canonical contract identity pinned for the lifetime of the instance.
    pub fn contract(&self) -> &rss_contract::ContractId {
        &self.contract
    }
    /// Exact contract version; recovery never substitutes another version.
    pub const fn version(&self) -> rss_contract::ContractVersion {
        self.version
    }
    /// Pinned canonical schema digest.
    pub fn schema(&self) -> &rss_contract::SchemaDigest {
        &self.schema
    }
    /// Application-supplied identity of the exact action implementation generation.
    pub fn generation(&self) -> &ActionGeneration {
        &self.generation
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct IdentityWire {
    contract: String,
    version: String,
    schema: String,
    generation: String,
}
impl From<Identity> for IdentityWire {
    fn from(id: Identity) -> Self {
        Self {
            contract: id.contract.to_string(),
            version: id.version.to_string(),
            schema: id.schema.to_string(),
            generation: id.generation.as_str().into(),
        }
    }
}
impl TryFrom<IdentityWire> for Identity {
    type Error = Error;
    fn try_from(wire: IdentityWire) -> Result<Self, Error> {
        let invalid = |_| Error::new(crate::ErrorKind::Definition);
        Ok(Self::new(
            rss_contract::ContractId::parse(&wire.contract).map_err(invalid)?,
            rss_contract::ContractVersion::parse(&wire.version).map_err(invalid)?,
            rss_contract::SchemaDigest::parse(&wire.schema).map_err(invalid)?,
            ActionGeneration::parse(&wire.generation)?,
        ))
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
/// One ordered action binding and its limit on proven forward execution failures.
pub struct StepSpec {
    name: String,
    receipt_schema: String,
    forward_scope: String,
    compensation_scope: String,
    max_failures: u32,
}
impl StepSpec {
    /// Validate nonempty bounded action/schema/effect names and a positive proven-failure limit.
    pub fn new(
        name: &str,
        receipt_schema: &str,
        forward_scope: &str,
        compensation_scope: &str,
        max_failures: u32,
    ) -> Result<Self, Error> {
        for value in [name, receipt_schema, forward_scope, compensation_scope] {
            validate_name(value)?;
        }
        if max_failures == 0 {
            return Err(Error::new(crate::ErrorKind::Definition));
        }
        Ok(Self {
            name: name.into(),
            receipt_schema: receipt_schema.into(),
            forward_scope: forward_scope.into(),
            compensation_scope: compensation_scope.into(),
            max_failures,
        })
    }
    /// Stable step identity, independent of Rust type or crate names.
    pub fn name(&self) -> &str {
        &self.name
    }
    /// Schema identifier of the associated typed receipt.
    pub fn receipt_schema(&self) -> &str {
        &self.receipt_schema
    }
    /// Maximum proven forward failures. Negative recovery probes do not consume this limit.
    pub fn max_failures(&self) -> u32 {
        self.max_failures
    }
}
fn validate_name(value: &str) -> Result<(), Error> {
    if value.is_empty()
        || value.len() > 255
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))
    {
        return Err(Error::new(crate::ErrorKind::Definition));
    }
    Ok(())
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
/// Validated immutable Saga metadata and its deterministic semantic fingerprint.
pub struct Definition {
    owner: String,
    identity: Identity,
    steps: Vec<StepSpec>,
    fingerprint: [u8; 32],
}
impl Definition {
    /// Validate unique ordered steps and compute the fingerprint of all declared execution metadata.
    pub fn new(owner: &str, identity: Identity, steps: Vec<StepSpec>) -> Result<Self, Error> {
        validate_name(owner)?;
        if steps.is_empty() || steps.len() > 1024 {
            return Err(Error::new(crate::ErrorKind::Definition));
        }
        let mut names = std::collections::HashSet::new();
        for step in &steps {
            StepSpec::new(
                &step.name,
                &step.receipt_schema,
                &step.forward_scope,
                &step.compensation_scope,
                step.max_failures,
            )?;
            if !names.insert(&step.name) {
                return Err(Error::new(crate::ErrorKind::Definition));
            }
        }
        let bytes = serde_json_canonicalizer::to_vec(&(owner, &identity, &steps))
            .map_err(|_| Error::new(crate::ErrorKind::Definition))?;
        let fingerprint = Sha256::digest(bytes).into();
        Ok(Self {
            owner: owner.into(),
            identity,
            steps,
            fingerprint,
        })
    }
    /// Validate untrusted storage data, including its recorded fingerprint.
    pub fn validate(&self) -> Result<(), Error> {
        let expected = Self::new(&self.owner, self.identity.clone(), self.steps.clone())?;
        if &expected != self {
            return Err(Error::new(crate::ErrorKind::Definition));
        }
        Ok(())
    }
    /// Application capability owner included in receipt authentication coordinates.
    pub fn owner(&self) -> &str {
        &self.owner
    }
    /// Exact contract/schema/action-generation identity; unchanged during recovery.
    pub fn identity(&self) -> &Identity {
        &self.identity
    }
    /// Ordered action bindings; successful effects are compensated in reverse order.
    pub fn steps(&self) -> &[StepSpec] {
        &self.steps
    }
    /// Deterministic metadata digest; it does not attest to executable code.
    pub fn fingerprint(&self) -> &[u8; 32] {
        &self.fingerprint
    }
    /// Derive the historical v1 key from tenant, instance, pinned identity, step and phase. Attempts are excluded.
    pub fn effect_key(&self, scope: Scope, step: usize, phase: Phase) -> Result<EffectKey, Error> {
        let step = self
            .steps
            .get(step)
            .ok_or(Error::new(crate::ErrorKind::Integrity))?;
        let tenant = scope.tenant().to_string();
        let version = self.identity.version.to_string();
        let effect = match phase {
            Phase::Forward => &step.forward_scope,
            Phase::Compensation => &step.compensation_scope,
        };
        let mut hash = Sha256::new();
        hash.update(b"rss.saga.idempotency-key.v1");
        for bytes in [
            tenant.as_bytes(),
            scope.id().as_bytes(),
            self.identity.contract.as_str().as_bytes(),
            version.as_bytes(),
            self.identity.schema.as_str().as_bytes(),
            self.identity.generation.as_str().as_bytes(),
            step.name.as_bytes(),
            phase.as_str().as_bytes(),
            effect.as_bytes(),
        ] {
            hash.update((bytes.len() as u64).to_be_bytes());
            hash.update(bytes);
        }
        Ok(EffectKey(hash.finalize().into()))
    }
}
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
/// Opaque retry-stable external idempotency key; Debug always redacts its bytes.
pub struct EffectKey([u8; 32]);
impl EffectKey {
    /// Exact durable 32-byte representation. Treat it as opaque and never log it.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
    /// Canonical hexadecimal transport representation for external provider deduplication.
    pub fn to_hex(&self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }
}
impl std::fmt::Debug for EffectKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EffectKey(<redacted>)")
    }
}
