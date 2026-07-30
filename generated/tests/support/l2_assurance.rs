#![allow(dead_code)]
// reason: this typed schema is shared by two integration-test binaries that exercise complementary
// subsets; every field is consumed across the pair, but each binary is linted independently.

use std::collections::BTreeSet;
use std::fmt;

use serde::Deserialize;
use serde::de::{self, Deserializer, IgnoredAny, MapAccess, SeqAccess, Visitor};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct AssuranceInventory {
    pub(crate) schema_version: u32,
    pub(crate) producer_count: usize,
    pub(crate) fact_count: usize,
    pub(crate) contracts: Vec<AssuranceRecord>,
}

impl AssuranceInventory {
    pub(crate) fn parse_v3(input: &str) -> Result<Self, String> {
        let mut duplicate_check = serde_json::Deserializer::from_str(input);
        NoDuplicateKeys::deserialize(&mut duplicate_check).map_err(|error| error.to_string())?;
        duplicate_check.end().map_err(|error| error.to_string())?;

        let mut typed = serde_json::Deserializer::from_str(input);
        let inventory = Self::deserialize(&mut typed).map_err(|error| error.to_string())?;
        typed.end().map_err(|error| error.to_string())?;
        if inventory.schema_version != 3 {
            return Err("L2 assurance reader requires schemaVersion 3".to_string());
        }
        Ok(inventory)
    }
}

struct NoDuplicateKeys;

impl<'de> Deserialize<'de> for NoDuplicateKeys {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(NoDuplicateKeysVisitor)
    }
}

struct NoDuplicateKeysVisitor;

impl<'de> Visitor<'de> for NoDuplicateKeysVisitor {
    type Value = NoDuplicateKeys;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("JSON without duplicate object keys")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut keys = BTreeSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !keys.insert(key.clone()) {
                return Err(de::Error::custom(format!(
                    "duplicate JSON object key: {key}"
                )));
            }
            map.next_value::<NoDuplicateKeys>()?;
        }
        Ok(NoDuplicateKeys)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while sequence.next_element::<NoDuplicateKeys>()?.is_some() {}
        Ok(NoDuplicateKeys)
    }

    fn visit_bool<E>(self, _: bool) -> Result<Self::Value, E> {
        Ok(NoDuplicateKeys)
    }

    fn visit_i64<E>(self, _: i64) -> Result<Self::Value, E> {
        Ok(NoDuplicateKeys)
    }

    fn visit_u64<E>(self, _: u64) -> Result<Self::Value, E> {
        Ok(NoDuplicateKeys)
    }

    fn visit_f64<E>(self, _: f64) -> Result<Self::Value, E> {
        Ok(NoDuplicateKeys)
    }

    fn visit_str<E>(self, _: &str) -> Result<Self::Value, E> {
        Ok(NoDuplicateKeys)
    }

    fn visit_string<E>(self, _: String) -> Result<Self::Value, E> {
        Ok(NoDuplicateKeys)
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(NoDuplicateKeys)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(NoDuplicateKeys)
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        IgnoredAny::deserialize(deserializer)?;
        Ok(NoDuplicateKeys)
    }
}

#[derive(Debug, Deserialize)]
#[serde(tag = "role", rename_all = "camelCase", deny_unknown_fields)]
pub(crate) enum AssuranceRecord {
    #[serde(rename_all = "camelCase")]
    Producer {
        contract_id: String,
        domain: String,
        version: String,
        status: RecordStatus,
        emitted_facts: Vec<String>,
        evidence: ProducerEvidence,
    },
    #[serde(rename_all = "camelCase")]
    Fact {
        contract_id: String,
        domain: String,
        version: String,
        status: RecordStatus,
        topic: String,
        subscriptions: Vec<SubscriptionIdentity>,
        evidence: FactEvidence,
    },
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) enum RecordStatus {
    Closed,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SubscriptionIdentity {
    pub(crate) consumer: String,
    pub(crate) group: String,
    pub(crate) external_effect_policy: AssuranceExternalEffectPolicy,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum AssuranceExternalEffectPolicy {
    TransactionalOnly,
    IdempotencyKey,
    Reconcile,
    Compensated,
}

impl AssuranceExternalEffectPolicy {
    pub(crate) fn as_wire(&self) -> &'static str {
        match self {
            Self::TransactionalOnly => "transactional-only",
            Self::IdempotencyKey => "idempotency-key",
            Self::Reconcile => "reconcile",
            Self::Compensated => "compensated",
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct FactEvidence {
    pub(crate) contract: EvidenceFacet,
    pub(crate) generated: EvidenceFacet,
    pub(crate) runtime: EvidenceFacet,
    pub(crate) effect: EvidenceFacet,
    pub(crate) fault: EvidenceFacet,
}

impl FactEvidence {
    pub(crate) fn facets(&self) -> [&EvidenceFacet; 5] {
        [
            &self.contract,
            &self.generated,
            &self.runtime,
            &self.effect,
            &self.fault,
        ]
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ProducerEvidence {
    pub(crate) contract: EvidenceFacet,
    pub(crate) generated: EvidenceFacet,
    pub(crate) execution: ProducerExecution,
    pub(crate) fault: ProducerFaultEvidence,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ProducerFaultEvidence {
    pub(crate) status: FacetStatus,
    pub(crate) terminals: Vec<ProducerFaultTerminal>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ProducerFaultTerminal {
    pub(crate) fact_id: String,
    pub(crate) provider_method: EvidenceCarrier,
    pub(crate) transaction: EvidenceCarrier,
    pub(crate) rollback: EvidenceCarrier,
    pub(crate) commit_unknown: EvidenceCarrier,
    pub(crate) rollback_failed: EvidenceCarrier,
    pub(crate) no_replay: EvidenceCarrier,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ProducerExecution {
    pub(crate) status: FacetStatus,
    pub(crate) route: EvidenceCarrier,
    pub(crate) mounted_handler: EvidenceCarrier,
    pub(crate) terminals: Vec<ProducerTerminal>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ProducerTerminal {
    pub(crate) fact_id: String,
    pub(crate) domain_path: Vec<EvidenceCarrier>,
    pub(crate) port_method: EvidenceCarrier,
    pub(crate) provider_method: EvidenceCarrier,
    pub(crate) production_composition: ProductionComposition,
    pub(crate) transaction: EvidenceCarrier,
    pub(crate) capability: EvidenceCarrier,
    pub(crate) append: EvidenceCarrier,
    pub(crate) settlement: EvidenceCarrier,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ProductionComposition {
    pub(crate) runtime_entry: EvidenceCarrier,
    pub(crate) runtime_assembly: EvidenceCarrier,
    pub(crate) runtime_module: EvidenceCarrier,
    pub(crate) wire: EvidenceCarrier,
    pub(crate) service_constructor: String,
    pub(crate) provider_factory: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct EvidenceFacet {
    pub(crate) status: FacetStatus,
    pub(crate) carriers: Vec<EvidenceCarrier>,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) enum FacetStatus {
    Complete,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct EvidenceCarrier {
    pub(crate) kind: CarrierKind,
    pub(crate) path: String,
    pub(crate) symbol: String,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum CarrierKind {
    Manifest,
    RustSymbol,
    RustType,
    FaultFixture,
}
