//! Canonical execution profile identities shared by gates, tests, and integrations.

use std::{fmt, str::FromStr};

use crate::{
    ci_lanes::{GateId, GateSpec, REGISTRY},
    integration_shards::{IntegrationUnitId, IntegrationUnitSpec},
};

/// Stable identity spanning every executable gate, test scope, and integration unit.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) enum ExecutionUnitId {
    Gate(GateId),
    Integration(IntegrationUnitId),
}

impl ExecutionUnitId {
    pub(crate) const fn primary_owner(self) -> ExecutionProfile {
        match self {
            Self::Gate(id) => id.spec().primary_owner(),
            Self::Integration(id) => id.spec().primary_owner,
        }
    }
}

/// Closed execution IR. The variants retain typed executor details without
/// flattening gate and integration identities back into strings.
#[derive(Clone, Copy, Debug)]
pub(crate) enum ExecutionUnitSpec {
    Gate(&'static GateSpec),
    Integration(&'static IntegrationUnitSpec),
}

impl ExecutionUnitSpec {
    pub(crate) fn all() -> impl Iterator<Item = Self> {
        REGISTRY.iter().map(Self::Gate).chain(
            IntegrationUnitId::ALL
                .into_iter()
                .map(IntegrationUnitId::spec)
                .map(Self::Integration),
        )
    }

    pub(crate) const fn id(self) -> ExecutionUnitId {
        match self {
            Self::Gate(spec) => ExecutionUnitId::Gate(spec.id()),
            Self::Integration(spec) => ExecutionUnitId::Integration(spec.id),
        }
    }

    pub(crate) const fn primary_owner(self) -> ExecutionProfile {
        self.id().primary_owner()
    }

    const fn included_in(self, profile: ExecutionProfile) -> bool {
        match self {
            Self::Gate(spec) => spec.included_in_profile(profile),
            Self::Integration(spec) => profile.includes_owner(spec.primary_owner),
        }
    }

    /// The sole profile projection across gates and integrations.
    /// `release-check` first takes the union of every primary owner, then gate
    /// subsumption removes only units carrying a closed typed proof.
    pub(crate) fn project(profile: ExecutionProfile) -> impl Iterator<Item = Self> {
        Self::all().filter(move |spec| spec.included_in(profile))
    }
}

/// The closed set of canonical execution owners.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) enum ExecutionProfile {
    Check,
    Test,
    IntegrationCritical,
    ReleaseCheck,
}

impl ExecutionProfile {
    pub(crate) const ALL: [Self; 4] = [
        Self::Check,
        Self::Test,
        Self::IntegrationCritical,
        Self::ReleaseCheck,
    ];

    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Check => "check",
            Self::Test => "test",
            Self::IntegrationCritical => "integration-critical",
            Self::ReleaseCheck => "release-check",
        }
    }

    /// Release verification is the union projection; all other profiles select
    /// only units for which they are the primary owner.
    pub(crate) const fn includes_owner(self, owner: Self) -> bool {
        matches!(self, Self::ReleaseCheck) || self as u8 == owner as u8
    }
}

impl fmt::Display for ExecutionProfile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for ExecutionProfile {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|profile| profile.as_str() == value)
            .ok_or_else(|| anyhow::anyhow!("unknown execution profile `{value}`"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn execution_profile_names_are_exact_and_closed() -> anyhow::Result<()> {
        let names = ExecutionProfile::ALL
            .into_iter()
            .map(ExecutionProfile::as_str)
            .collect::<Vec<_>>();
        assert_eq!(
            names,
            ["check", "test", "integration-critical", "release-check"]
        );
        for profile in ExecutionProfile::ALL {
            assert_eq!(profile.as_str().parse::<ExecutionProfile>()?, profile);
        }
        for invalid in [
            "verify",
            "ci-only",
            "integration",
            "Check",
            "release_check",
            "",
        ] {
            assert!(invalid.parse::<ExecutionProfile>().is_err(), "{invalid}");
        }
        Ok(())
    }

    #[test]
    fn release_check_projects_every_primary_owner_without_aliasing() {
        for owner in ExecutionProfile::ALL {
            assert!(
                ExecutionProfile::ReleaseCheck.includes_owner(owner),
                "release-check must project owner {owner:?}"
            );
        }
        for profile in [
            ExecutionProfile::Check,
            ExecutionProfile::Test,
            ExecutionProfile::IntegrationCritical,
        ] {
            for owner in ExecutionProfile::ALL {
                assert_eq!(profile.includes_owner(owner), profile == owner);
            }
        }
    }

    #[test]
    fn execution_ir_has_one_stable_identity_and_owner_per_unit() {
        let specs = ExecutionUnitSpec::all().collect::<Vec<_>>();
        let ids = specs
            .iter()
            .map(|spec| spec.id())
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(ids.len(), specs.len());
        assert!(
            specs
                .iter()
                .all(|spec| ExecutionProfile::ALL.contains(&spec.primary_owner()))
        );
    }

    #[test]
    fn one_projection_spans_gates_and_integrations_with_release_subsumption() {
        let release =
            ExecutionUnitSpec::project(ExecutionProfile::ReleaseCheck).collect::<Vec<_>>();
        assert!(
            release
                .iter()
                .any(|unit| matches!(unit, ExecutionUnitSpec::Gate(_)))
        );
        assert!(
            release
                .iter()
                .any(|unit| matches!(unit, ExecutionUnitSpec::Integration(_)))
        );
        assert_eq!(
            release
                .iter()
                .filter_map(|unit| match unit {
                    ExecutionUnitSpec::Integration(spec) => Some(spec.id),
                    ExecutionUnitSpec::Gate(_) => None,
                })
                .collect::<std::collections::BTreeSet<_>>(),
            IntegrationUnitId::ALL.into_iter().collect()
        );
        let critical = ExecutionUnitSpec::project(ExecutionProfile::IntegrationCritical)
            .filter_map(|unit| match unit {
                ExecutionUnitSpec::Integration(spec) => Some(spec.id),
                ExecutionUnitSpec::Gate(_) => None,
            })
            .collect::<std::collections::BTreeSet<_>>();
        assert!(!critical.is_empty());
        assert!(critical.len() < IntegrationUnitId::ALL.len());
        assert!(
            critical
                .iter()
                .all(|id| { id.spec().primary_owner == ExecutionProfile::IntegrationCritical })
        );
    }
}
