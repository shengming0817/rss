use crate::{Digest, Error, Id, NumberKind, Value, digest};
use rss_request_context::TenantId;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Tenant and namespace are mandatory scope, not authentication evidence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "ScopeDto", into = "ScopeDto")]
pub struct Scope {
    tenant: TenantId,
    namespace: Id,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ScopeDto {
    tenant: String,
    namespace: Id,
}
impl TryFrom<ScopeDto> for Scope {
    type Error = Error;
    fn try_from(v: ScopeDto) -> Result<Self, Error> {
        Ok(Self::new(
            TenantId::parse(&v.tenant).map_err(|_| Error::InvalidInput)?,
            v.namespace,
        ))
    }
}
impl From<Scope> for ScopeDto {
    fn from(v: Scope) -> Self {
        Self {
            tenant: v.tenant.to_string(),
            namespace: v.namespace,
        }
    }
}
impl Scope {
    pub const fn new(tenant: TenantId, namespace: Id) -> Self {
        Self { tenant, namespace }
    }
    pub const fn tenant(&self) -> TenantId {
        self.tenant
    }
    pub const fn namespace(&self) -> &Id {
        &self.namespace
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Temporality {
    Cumulative,
    Delta,
}

/// Open metric names share these closed, provider-neutral operations.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
pub enum Metric {
    Gauge {
        number: NumberKind,
    },
    Counter {
        number: NumberKind,
        temporality: Temporality,
    },
    Bool,
    State {
        members: BTreeSet<Id>,
    },
}
impl Metric {
    pub fn accepts(&self, value: &Value) -> bool {
        match (self, value) {
            (Self::Gauge { number }, Value::Number(n)) => *number == n.kind(),
            (Self::Counter { number, .. }, Value::Number(n)) => {
                *number == n.kind() && !n.is_negative()
            }
            (Self::Bool, Value::Bool(_)) => true,
            (Self::State { members }, Value::State(v)) => members.contains(v),
            _ => false,
        }
    }
    fn extends(&self, old: &Self) -> bool {
        match (self, old) {
            (Self::State { members: new }, Self::State { members: old }) => new.is_superset(old),
            _ => self == old,
        }
    }
}

/// Per-definition admission budgets; limits can only widen in a new version.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DimensionRules {
    pub allowed: BTreeSet<Id>,
    pub required: BTreeSet<Id>,
    pub max_count: u16,
    pub max_value_bytes: u16,
    pub max_total_bytes: u32,
}
impl DimensionRules {
    fn validate(&self) -> Result<(), Error> {
        if self.allowed.len() > 64
            || self.max_count > 64
            || self.required.len() > usize::from(self.max_count)
            || !self.required.is_subset(&self.allowed)
            || self.max_value_bytes == 0
            || self.max_value_bytes > 256
            || self.max_total_bytes == 0
            || self.max_total_bytes > 32768
        {
            return Err(Error::InvalidInput);
        }
        Ok(())
    }
    pub fn validate_values(&self, values: &BTreeMap<Id, Id>) -> Result<(), Error> {
        self.validate()?;
        if values.len() > usize::from(self.max_count) {
            return Err(Error::BudgetExceeded);
        }
        if !self.required.iter().all(|k| values.contains_key(k))
            || !values.keys().all(|k| self.allowed.contains(k))
        {
            return Err(Error::InvalidInput);
        }
        let mut bytes = 0usize;
        for (key, value) in values {
            if value.as_str().len() > usize::from(self.max_value_bytes) {
                return Err(Error::BudgetExceeded);
            }
            bytes += key.as_str().len() + value.as_str().len();
        }
        if bytes > self.max_total_bytes as usize {
            return Err(Error::BudgetExceeded);
        }
        Ok(())
    }
    fn extends(&self, old: &Self) -> bool {
        self.allowed.is_superset(&old.allowed)
            && self.required == old.required
            && self.max_count >= old.max_count
            && self.max_value_bytes >= old.max_value_bytes
            && self.max_total_bytes >= old.max_total_bytes
    }
}

/// An input DTO, not a validated definition. The unit is exact, not implicitly converted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DefinitionSpec {
    pub scope: Scope,
    pub key: Id,
    pub version: u64,
    pub unit: Id,
    pub metric: Metric,
    pub dimensions: DimensionRules,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "DefinitionSpec", into = "DefinitionSpec")]
pub struct Definition(Box<DefinitionSpec>);
impl TryFrom<DefinitionSpec> for Definition {
    type Error = Error;
    fn try_from(v: DefinitionSpec) -> Result<Self, Error> {
        Self::new(v)
    }
}
impl From<Definition> for DefinitionSpec {
    fn from(v: Definition) -> Self {
        *v.0
    }
}
impl Definition {
    pub fn new(spec: DefinitionSpec) -> Result<Self, Error> {
        if spec.version == 0 {
            return Err(Error::InvalidInput);
        }
        spec.dimensions.validate()?;
        if let Metric::State { members } = &spec.metric
            && (members.is_empty() || members.len() > 256)
        {
            return Err(Error::InvalidInput);
        }
        Ok(Self(Box::new(spec)))
    }
    pub const fn spec(&self) -> &DefinitionSpec {
        &self.0
    }
    pub fn digest(&self) -> Result<Digest, Error> {
        digest(b"definition", self)
    }
    /// Compare against the existing exact key, before a provider's atomic registration.
    /// Every stored version remains immutable. A new version does not retire its predecessor.
    pub fn compare(&self, old: &Self) -> Result<DefinitionChange, Error> {
        if self.0.scope != old.0.scope || self.0.key != old.0.key {
            return Err(Error::InvalidInput);
        }
        if self.0.version == old.0.version {
            return if self == old {
                Ok(DefinitionChange::Replay)
            } else {
                Err(Error::Conflict)
            };
        }
        if self.0.version < old.0.version
            || self.0.unit != old.0.unit
            || !self.0.metric.extends(&old.0.metric)
            || !self.0.dimensions.extends(&old.0.dimensions)
        {
            return Err(Error::IncompatibleDefinition);
        }
        Ok(DefinitionChange::CompatibleVersion)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DefinitionChange {
    Replay,
    CompatibleVersion,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DefinitionState {
    Active,
    Retired,
}
impl DefinitionState {
    /// `already_accepted` must come from a matching durable identity/content record,
    /// never from a client flag. A replay cannot admit additional samples.
    pub fn admit(self, already_accepted: bool) -> Result<(), Error> {
        if self == Self::Retired && !already_accepted {
            return Err(Error::Retired);
        }
        Ok(())
    }
}
