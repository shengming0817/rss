//! Manifest-backed contract ownership promoted at the repository boundary.
//!
//! INVARIANT: CONTRACT-OWNER-PROMOTION-01 { level = "Hard", exec = "native-compile", source = "code", native = "private owner representation and crate-private fallible promotion" } — `ContractOwner` has no public constructor or variant; the crate-private promotion funnel validates domain owners through `DomainName`, while external callers can only inspect an already-promoted owner.

use crate::contract_manifest::RawContractOwner;
use vocab::{DomainName, DomainNameError};

const FRAMEWORK_OWNER: &str = "_framework";

/// Manifest-backed contract owner. Its private representation prevents external callers from
/// minting an owner without repository promotion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContractOwner(ContractOwnerKind);

#[derive(Debug, Clone, PartialEq, Eq)]
enum ContractOwnerKind {
    Domain(DomainName),
    Framework,
}

impl ContractOwner {
    /// Promote one private manifest owner through the canonical domain-name parser.
    pub(crate) fn promote(raw: &RawContractOwner) -> Result<Self, DomainNameError> {
        match raw {
            RawContractOwner::Framework => Ok(Self(ContractOwnerKind::Framework)),
            RawContractOwner::Domain(domain) => {
                DomainName::parse(domain).map(|domain| Self(ContractOwnerKind::Domain(domain)))
            }
        }
    }

    /// Return the owning domain, or `None` for the framework sentinel.
    pub fn domain(&self) -> Option<&DomainName> {
        match &self.0 {
            ContractOwnerKind::Domain(domain) => Some(domain),
            ContractOwnerKind::Framework => None,
        }
    }

    /// Whether the contract is owned by the framework sentinel.
    pub fn is_framework_owned(&self) -> bool {
        matches!(self.0, ContractOwnerKind::Framework)
    }

    /// Return the canonical manifest spelling of this owner.
    pub fn as_str(&self) -> &str {
        self.domain().map_or(FRAMEWORK_OWNER, DomainName::as_str)
    }
}
