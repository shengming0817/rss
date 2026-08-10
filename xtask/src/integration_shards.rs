//! Integration capability shard registry and target-level execution plans.
//!
//! INVARIANT: INTEGRATION-SHARD-REGISTRY-01 { level = "Hard", exec = "native-compile", source = "code", native = "catalog macro generates the closed enum, ALL, lookup, resources, and execution units" }.
//! INVARIANT: INTEGRATION-SHARD-SELECTOR-01 { level = "Hard", exec = "native-compile", source = "code", native = "filtersets render only from typed package/binary/kind execution units" }.
//! INVARIANT: INTEGRATION-SHARD-COVERAGE-01 { level = "Medium", exec = "release-check", source = "code", synthetic_red = "metadata_coverage_rejects_missing_duplicate_and_unknown_targets|source_and_security_provider_relations_reject_catalog_drift", anti_vacuity = "workspace_metadata_covers_legacy_integration_targets|shared_journey_relations_match_independently_discovered_module_edges|source_and_security_provider_relations_are_closed_and_non_vacuous" }.
//! INVARIANT: INTEGRATION-SHARD-ELIGIBILITY-01 { level = "Medium", exec = "release-check", source = "code", synthetic_red = "cargo_target_eligibility_rejects_missing_duplicate_path_and_feature_drift|cargo_target_eligibility_rejects_crate_level_feature_cfg", anti_vacuity = "catalog_test_and_remote_only_sets_are_non_vacuous|workspace_cargo_target_eligibility_matches_local_feature_scope" }.
//! INVARIANT: INTEGRATION-SHARD-SCHEDULING-01 { level = "Medium", exec = "release-check", source = "code", synthetic_red = "scheduling_plan_rejects_dangerous_target_parallelism|localtx_backend_execution_unit_rejects_missing_duplicate_and_drift|identityaudit_runtime_resource_closure_rejects_missing_duplicate_and_extra", anti_vacuity = "workspace_plan_freezes_resources_and_dangerous_targets|localtx_journeys_form_one_unpartitioned_serial_batch|localtx_backend_execution_unit_is_unique|identityaudit_runtime_resource_closure_is_exact_and_non_vacuous" }.

#[cfg(test)]
use crate::workspace_root;
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use workspacefacts::{TargetFacts, TargetKind as WorkspaceTargetKind, WorkspaceFacts};

use crate::execution_profiles::{ExecutionProfile, ExecutionUnitSpec};
use crate::workspace_facts::CommandWorkspaceFacts;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Resource {
    Postgres,
    Redis,
    Amqp,
    Mqtt,
    ObjectStorage,
    Vault,
}

/// Closed adapter package identities. Adapter source changes are projected through the external
/// resource they implement, never through a free-form Cargo package string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum AdapterPackage {
    Postgres,
    PostgresMigration,
    Redis,
    Amqp,
    Mqtt,
    ObjectStorage,
    Oidc,
    Vault,
}

impl AdapterPackage {
    pub(crate) const ALL: [Self; 8] = [
        Self::Postgres,
        Self::PostgresMigration,
        Self::Redis,
        Self::Amqp,
        Self::Mqtt,
        Self::ObjectStorage,
        Self::Oidc,
        Self::Vault,
    ];

    pub(crate) const fn package(self) -> &'static str {
        match self {
            Self::Postgres => "postgres",
            Self::PostgresMigration => "postgres-migration",
            Self::Redis => "redis-adapter",
            Self::Amqp => "amqp",
            Self::Mqtt => "mqtt",
            Self::ObjectStorage => "s3",
            Self::Oidc => "oidc",
            Self::Vault => "vault",
        }
    }

    pub(crate) const fn projection(self) -> AdapterProjection {
        match self {
            Self::Postgres | Self::PostgresMigration => {
                AdapterProjection::Resource(Resource::Postgres)
            }
            Self::Redis => AdapterProjection::Resource(Resource::Redis),
            Self::Amqp => AdapterProjection::Resource(Resource::Amqp),
            Self::Mqtt => AdapterProjection::Resource(Resource::Mqtt),
            Self::ObjectStorage => AdapterProjection::Resource(Resource::ObjectStorage),
            Self::Oidc => AdapterProjection::SecurityProvider(SecurityProvider::Oidc),
            Self::Vault => AdapterProjection::SecurityProvider(SecurityProvider::Vault),
        }
    }

    pub(crate) fn for_package(package: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|adapter| adapter.package() == package)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AdapterProjection {
    Resource(Resource),
    SecurityProvider(SecurityProvider),
}

impl AdapterProjection {
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Resource(resource) => resource.label(),
            Self::SecurityProvider(provider) => provider.label(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum SecurityProvider {
    Oidc,
    Vault,
}

impl SecurityProvider {
    pub(crate) const ALL: [Self; 2] = [Self::Oidc, Self::Vault];

    const fn carrier_marker(self) -> Option<ImpactMarker> {
        match self {
            Self::Oidc => Some(ImpactMarker::OidcProvider),
            Self::Vault => None,
        }
    }

    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Oidc => "security-provider:oidc",
            Self::Vault => "security-provider:vault",
        }
    }
}

/// Closed semantic relation between a changed production surface and an integration carrier.
/// Package identities are deliberately variants: unknown strings cannot enter the catalog.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum ImpactMarker {
    PostgresPackage,
    PostgresMigrationPackage,
    AuditPackage,
    AuthnPackage,
    IdentityPackage,
    IdentityCompositionPackage,
    DeviceIdentityPackage,
    IotDevicePackage,
    SettingsPackage,
    AmqpPackage,
    EventexecPackage,
    MqttPackage,
    RedisAdapterPackage,
    RuntimePackage,
    HttpdPackage,
    HttpservePackage,
    BootstrapPackage,
    DistributedPackage,
    ConsistencyPackage,
    S3Package,
    BillingContract,
    FrameworkContract,
    RuntimeSurface,
    LocalTxContract,
    OidcProvider,
}

impl ImpactMarker {
    pub(crate) const PACKAGE_RELATIONS: [(&'static str, Self); 22] = [
        ("postgres", Self::PostgresPackage),
        ("postgres-migration", Self::PostgresMigrationPackage),
        ("audit", Self::AuditPackage),
        ("authn", Self::AuthnPackage),
        ("identity", Self::IdentityPackage),
        ("identity-composition", Self::IdentityCompositionPackage),
        ("deviceidentity", Self::DeviceIdentityPackage),
        ("iotdevice", Self::IotDevicePackage),
        ("settings", Self::SettingsPackage),
        ("amqp", Self::AmqpPackage),
        ("eventexec", Self::EventexecPackage),
        ("mqtt", Self::MqttPackage),
        ("redis-adapter", Self::RedisAdapterPackage),
        ("runtime", Self::RuntimePackage),
        ("httpd", Self::HttpdPackage),
        ("httpserve", Self::HttpservePackage),
        ("bootstrap", Self::BootstrapPackage),
        ("distributed", Self::DistributedPackage),
        ("consistency", Self::ConsistencyPackage),
        ("s3", Self::S3Package),
        ("billing", Self::BillingContract),
        ("_framework", Self::FrameworkContract),
    ];

    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::PostgresPackage => "package:postgres",
            Self::PostgresMigrationPackage => "package:postgres-migration",
            Self::AuditPackage => "package:audit",
            Self::AuthnPackage => "package:authn",
            Self::IdentityPackage => "package:identity",
            Self::IdentityCompositionPackage => "package:identity-composition",
            Self::DeviceIdentityPackage => "package:deviceidentity",
            Self::IotDevicePackage => "package:iotdevice",
            Self::SettingsPackage => "package:settings",
            Self::AmqpPackage => "package:amqp",
            Self::EventexecPackage => "package:eventexec",
            Self::MqttPackage => "package:mqtt",
            Self::RedisAdapterPackage => "package:redis-adapter",
            Self::RuntimePackage => "package:runtime",
            Self::HttpdPackage => "package:httpd",
            Self::HttpservePackage => "package:httpserve",
            Self::BootstrapPackage => "package:bootstrap",
            Self::DistributedPackage => "package:distributed",
            Self::ConsistencyPackage => "package:consistency",
            Self::S3Package => "package:s3",
            Self::BillingContract => "contract:billing",
            Self::FrameworkContract => "contract:_framework",
            Self::RuntimeSurface => "runtime-surface",
            Self::LocalTxContract => "localtx-contract",
            Self::OidcProvider => "security-provider:oidc",
        }
    }

    pub(crate) fn for_package(package: &str) -> Option<Self> {
        Self::PACKAGE_RELATIONS
            .iter()
            .find_map(|(candidate, marker)| (*candidate == package).then_some(*marker))
    }
}

impl Resource {
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Postgres => "postgres",
            Self::Redis => "redis",
            Self::Amqp => "amqp",
            Self::Mqtt => "mqtt",
            Self::ObjectStorage => "object-storage",
            Self::Vault => "vault",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Scheduling {
    Serial,
    Parallel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum TargetKind {
    Lib,
    Test,
}

/// Whether a catalog Test target participates in affected local preflight.
///
/// Remote shard ownership, scheduling, and Cargo compile eligibility (`required-features`)
/// are independent facts. Cargo `[[test]]` / `required-features` remains the only target
/// eligibility owner; crate-level source `#![cfg(feature)]` / `#![cfg_attr(feature)]` must
/// not restore a second gate (item-level case cfg stays out of scope).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum LocalEligibility {
    Affected,
    RemoteOnly,
}

impl TargetKind {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Lib => "lib",
            Self::Test => "test",
        }
    }
}

impl Scheduling {
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Serial => "serial",
            Self::Parallel => "parallel",
        }
    }
}

impl LocalEligibility {
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Affected => "affected",
            Self::RemoteOnly => "remote-only",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct IntegrationUnitSpec {
    pub(crate) id: IntegrationUnitId,
    pub(crate) shard: IntegrationShard,
    pub(crate) primary_owner: ExecutionProfile,
    pub(crate) package: &'static str,
    pub(crate) target: &'static str,
    pub(crate) kind: TargetKind,
    pub(crate) scheduling: Scheduling,
    pub(crate) local_eligibility: LocalEligibility,
    pub(crate) resources: &'static [Resource],
    impact_markers: &'static [ImpactMarker],
    capabilities: &'static [Capability],
}

/// Closed package/feature identities whose integration implementations must at least compile
/// during local impact validation. Keeping the feature name behind this enum prevents the local
/// planner from reconstructing feature strings from package names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum LocalFeatureScope {
    Postgres,
    PostgresMigration,
    RedisAdapter,
    Amqp,
    Mqtt,
    DeviceIdentity,
    Journeys,
    Runtime,
    Testkit,
    JourneysFaultMatrix,
    S3,
    SettingsOnly,
    IdentityAudit,
}

impl LocalFeatureScope {
    pub(crate) const ALL: [Self; 13] = [
        Self::Postgres,
        Self::PostgresMigration,
        Self::RedisAdapter,
        Self::Amqp,
        Self::Mqtt,
        Self::DeviceIdentity,
        Self::Journeys,
        Self::Runtime,
        Self::Testkit,
        Self::JourneysFaultMatrix,
        Self::S3,
        Self::SettingsOnly,
        Self::IdentityAudit,
    ];

    pub(crate) const fn package(self) -> &'static str {
        match self {
            Self::Postgres => "postgres",
            Self::PostgresMigration => "postgres-migration",
            Self::RedisAdapter => "redis-adapter",
            Self::Amqp => "amqp",
            Self::Mqtt => "mqtt",
            Self::DeviceIdentity => "deviceidentity",
            Self::Journeys => "journeys",
            Self::Runtime => "runtime",
            Self::Testkit => "testkit",
            Self::JourneysFaultMatrix => "journeys-fault-matrix",
            Self::S3 => "s3",
            Self::SettingsOnly => "settingsonly",
            Self::IdentityAudit => "identityaudit",
        }
    }

    pub(crate) const fn feature(self) -> &'static str {
        match self {
            Self::Mqtt => "broker-tests",
            Self::DeviceIdentity => "test-support",
            Self::IdentityAudit => "artifact-acceptance",
            Self::Postgres
            | Self::PostgresMigration
            | Self::RedisAdapter
            | Self::Amqp
            | Self::Journeys
            | Self::Runtime
            | Self::Testkit
            | Self::JourneysFaultMatrix
            | Self::S3
            | Self::SettingsOnly => "integration",
        }
    }

    const fn root(self) -> &'static str {
        match self {
            Self::Postgres => "adapters/postgres",
            Self::PostgresMigration => "adapters/postgres-migration",
            Self::RedisAdapter => "adapters/redis",
            Self::Amqp => "adapters/amqp",
            Self::Mqtt => "adapters/mqtt",
            Self::DeviceIdentity => "assemblies/deviceidentity",
            Self::Journeys => "journeys",
            Self::Runtime => "assemblies/runtime",
            Self::Testkit => "crates/testkit",
            Self::JourneysFaultMatrix => "journeys-fault-matrix",
            Self::S3 => "adapters/s3",
            Self::SettingsOnly => "assemblies/settingsonly",
            Self::IdentityAudit => "assemblies/identityaudit",
        }
    }

    /// Resolve the Cargo feature for an integration batch package. Catalog packages are bijective
    /// with [`LocalFeatureScope::ALL`] (validated by `validate_local_feature_catalog`).
    pub(crate) fn for_package(package: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|scope| scope.package() == package)
    }
}

impl IntegrationUnitSpec {
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)] // synthetic catalog mutation fixtures mirror the full unit identity.
    const fn new(
        id: IntegrationUnitId,
        shard: IntegrationShard,
        primary_owner: ExecutionProfile,
        package: &'static str,
        target: &'static str,
        kind: TargetKind,
        scheduling: Scheduling,
        local_eligibility: LocalEligibility,
    ) -> Self {
        Self {
            id,
            shard,
            primary_owner,
            package,
            target,
            kind,
            scheduling,
            local_eligibility,
            resources: &[],
            impact_markers: &[],
            capabilities: &[],
        }
    }

    #[allow(clippy::too_many_arguments)] // the macro binds every closed unit dimension at one declaration site.
    const fn declared(
        id: IntegrationUnitId,
        shard: IntegrationShard,
        primary_owner: ExecutionProfile,
        package: &'static str,
        target: &'static str,
        kind: TargetKind,
        scheduling: Scheduling,
        local_eligibility: LocalEligibility,
        resources: &'static [Resource],
        impact_markers: &'static [ImpactMarker],
        capabilities: &'static [Capability],
    ) -> Self {
        Self {
            id,
            shard,
            primary_owner,
            package,
            target,
            kind,
            scheduling,
            local_eligibility,
            resources,
            impact_markers,
            capabilities,
        }
    }

    fn filter(self) -> String {
        format!(
            "package(={}) and binary(={}) and kind(={})",
            self.package,
            self.target,
            self.kind.as_str()
        )
    }
}

/// Only targets whose typed unit policy requires remote resources or production composition are
/// excluded locally. Remote orchestration ownership alone does not remove T1/component proof.
pub(crate) fn is_remote_only_test_target(package: &str, target: &str) -> bool {
    IntegrationShard::ALL.iter().any(|shard| {
        shard.spec().units.iter().any(|unit| {
            unit.kind == TargetKind::Test
                && unit.package == package
                && unit.target == target
                && unit.local_eligibility == LocalEligibility::RemoteOnly
        })
    })
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct ShardSpec {
    pub(crate) shard: IntegrationShard,
    pub(crate) units: &'static [IntegrationUnitSpec],
    pub(crate) local_feature_scopes: &'static [LocalFeatureScope],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Capability {
    Docker,
    PreparedExternalPostgres,
}

impl Capability {
    const fn label(self) -> &'static str {
        match self {
            Self::Docker => "docker",
            Self::PreparedExternalPostgres => "prepared-external-postgres",
        }
    }
}

macro_rules! integration_shard_catalog {
    ($(
        $variant:ident => {
            name: $name:literal,
            local_feature_scopes: [$($scope:ident),+ $(,)?],
            units: [$($unit:ident => (
                $wire:literal, $owner:ident, $package:literal, $target:literal,
                $kind:ident, $scheduling:ident, $local:ident,
                resources: [$($resource:ident),* $(,)?],
                impact_packages: [$($impact_marker:ident),* $(,)?],
                capabilities: [$($capability:ident),* $(,)?]
            )),+ $(,)?],
        },
    )+) => {
        #[repr(usize)]
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
        #[serde(rename_all = "kebab-case")]
        pub(crate) enum IntegrationShard { $($variant),+ }

        #[repr(usize)]
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        pub(crate) enum IntegrationUnitId { $($(#[serde(rename = $wire)] $unit),+),+ }

        const INTEGRATION_UNIT_SPECS: &[IntegrationUnitSpec] = &[$($(IntegrationUnitSpec::declared(
            IntegrationUnitId::$unit,
            IntegrationShard::$variant,
            ExecutionProfile::$owner,
            $package,
            $target,
            TargetKind::$kind,
            Scheduling::$scheduling,
            LocalEligibility::$local,
            &[$(Resource::$resource),*],
            &[$(ImpactMarker::$impact_marker),*],
            &[$(Capability::$capability),*],
        )),+),+];

        const SHARD_SPECS: &[ShardSpec] = &[$(ShardSpec {
            shard: IntegrationShard::$variant,
            local_feature_scopes: &[$(LocalFeatureScope::$scope),+],
            units: &[$(IntegrationUnitSpec::declared(
                IntegrationUnitId::$unit,
                IntegrationShard::$variant,
                ExecutionProfile::$owner,
                $package,
                $target,
                TargetKind::$kind,
                Scheduling::$scheduling,
                LocalEligibility::$local,
                &[$(Resource::$resource),*],
                &[$(ImpactMarker::$impact_marker),*],
                &[$(Capability::$capability),*],
            )),+],
        }),+];

        impl IntegrationShard {
            pub(crate) const ALL: &'static [Self] = &[$(Self::$variant),+];

            pub(crate) const fn as_str(self) -> &'static str {
                match self { $(Self::$variant => $name),+ }
            }

            pub(crate) const fn spec(self) -> &'static ShardSpec {
                &SHARD_SPECS[self as usize]
            }
        }

impl IntegrationUnitId {
            pub(crate) const ALL: [Self; [$($(stringify!($unit)),+),+].len()] = [$( $(Self::$unit),+ ),+];

            pub(crate) const fn spec(self) -> &'static IntegrationUnitSpec {
                &INTEGRATION_UNIT_SPECS[self as usize]
            }

            pub(crate) const fn as_str(self) -> &'static str {
                match self { $($(Self::$unit => $wire),+),+ }
            }

            /// Project stable IDs into their canonical public wire order. Internal `Ord` follows
            /// catalog declaration order and must not leak into serialized protocols.
            pub(crate) fn wire_order(unit_ids: &BTreeSet<Self>) -> Vec<Self> {
                let mut ordered = unit_ids.iter().copied().collect::<Vec<_>>();
                ordered.sort_unstable_by_key(|id| id.as_str());
                ordered
            }

            pub(crate) const fn impact_markers(self) -> &'static [ImpactMarker] {
                self.spec().impact_markers
            }

            pub(crate) fn capability_labels(self) -> impl Iterator<Item = &'static str> {
                self.spec().capabilities.iter().map(|capability| capability.label())
            }
        }

        impl FromStr for IntegrationShard {
            type Err = anyhow::Error;

            fn from_str(value: &str) -> Result<Self> {
                match value {
                    $($name => Ok(Self::$variant),)+
                    other => bail!(
                        "unknown integration shard `{other}`; expected one of: {}",
                        Self::ALL.iter().map(|shard| shard.as_str()).collect::<Vec<_>>().join(", ")
                    ),
                }
            }
        }

        impl FromStr for IntegrationUnitId {
            type Err = anyhow::Error;

            fn from_str(value: &str) -> Result<Self> {
                match value {
                    $($($wire => Ok(Self::$unit),)+)+
                    other => bail!("unknown integration unit ID `{other}`"),
                }
            }
        }
    };
}

pub(crate) fn critical_units_for_markers(
    markers: &BTreeSet<ImpactMarker>,
) -> BTreeSet<IntegrationUnitId> {
    IntegrationUnitId::ALL
        .into_iter()
        .filter(|id| id.spec().primary_owner == ExecutionProfile::IntegrationCritical)
        .filter(|id| {
            id.impact_markers()
                .iter()
                .any(|marker| markers.contains(marker))
        })
        .collect()
}

pub(crate) fn critical_units_for_resource(resource: Resource) -> BTreeSet<IntegrationUnitId> {
    IntegrationUnitId::ALL
        .into_iter()
        .filter(|id| id.spec().primary_owner == ExecutionProfile::IntegrationCritical)
        .filter(|id| id.spec().resources.contains(&resource))
        .collect()
}

pub(crate) fn critical_units_for_provider(
    provider: SecurityProvider,
) -> Option<BTreeSet<IntegrationUnitId>> {
    critical_units_for_provider_in(provider, INTEGRATION_UNIT_SPECS)
}

fn critical_units_for_provider_in(
    provider: SecurityProvider,
    specs: &[IntegrationUnitSpec],
) -> Option<BTreeSet<IntegrationUnitId>> {
    let marker = provider.carrier_marker()?;
    let units = specs
        .iter()
        .filter(|spec| spec.primary_owner == ExecutionProfile::IntegrationCritical)
        .filter(|spec| spec.impact_markers.contains(&marker))
        .map(|spec| spec.id)
        .collect::<BTreeSet<_>>();
    (!units.is_empty()).then_some(units)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ChangedIntegrationSource {
    Exact(BTreeSet<IntegrationUnitId>),
    ReleaseCheck,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SharedJourneySource {
    Common,
    DeviceCertificateConvergence,
    DeviceMtlsPgHarness,
    LocalTxValidation,
    IdentityAuditFixture,
    MqttBackpressureFault,
    RuntimeComposeFixture,
    SettingsOnlyProductionArtifact,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SharedJourneyRelation {
    critical_carriers: &'static [IntegrationUnitId],
    has_release_consumer: bool,
}

impl SharedJourneySource {
    const ALL: [Self; 8] = [
        Self::Common,
        Self::DeviceCertificateConvergence,
        Self::DeviceMtlsPgHarness,
        Self::LocalTxValidation,
        Self::IdentityAuditFixture,
        Self::MqttBackpressureFault,
        Self::RuntimeComposeFixture,
        Self::SettingsOnlyProductionArtifact,
    ];

    const fn path(self) -> &'static str {
        match self {
            Self::Common => "journeys/tests/common/mod.rs",
            Self::DeviceCertificateConvergence => {
                "journeys/tests/support/device_certificate_convergence.rs"
            }
            Self::DeviceMtlsPgHarness => "journeys/tests/support/device_mtls_pg_harness.rs",
            Self::LocalTxValidation => "journeys/tests/support/localtx_validation.rs",
            Self::IdentityAuditFixture => "journeys/tests/support/identityaudit_fixture.rs",
            Self::MqttBackpressureFault => "journeys/tests/support/mqtt_backpressure_fault.rs",
            Self::RuntimeComposeFixture => "journeys/tests/support/runtime_compose_fixture.rs",
            Self::SettingsOnlyProductionArtifact => {
                "journeys/tests/support/settingsonly_production_artifact.rs"
            }
        }
    }

    /// One typed source→consumer/profile relation. Selector projection and graph-drift validation
    /// must consume these two dimensions together.
    const fn relation(self) -> SharedJourneyRelation {
        match self {
            Self::Common => SharedJourneyRelation {
                critical_carriers: &[
                    IntegrationUnitId::AuditListTenantEntriesLocalTxJourney,
                    IntegrationUnitId::SettingsSecretPublishLocalTxJourney,
                    IntegrationUnitId::AmqpConsumerAtLeastOnceJourney,
                    IntegrationUnitId::IdentityLoginAuditDurableJourney,
                ],
                has_release_consumer: true,
            },
            Self::DeviceCertificateConvergence => SharedJourneyRelation {
                critical_carriers: &[IntegrationUnitId::DeviceCertificateConvergenceJourney],
                has_release_consumer: false,
            },
            Self::LocalTxValidation => SharedJourneyRelation {
                critical_carriers: &[
                    IntegrationUnitId::AuditListTenantEntriesLocalTxJourney,
                    IntegrationUnitId::SettingsSecretPublishLocalTxJourney,
                ],
                has_release_consumer: false,
            },
            Self::DeviceMtlsPgHarness => SharedJourneyRelation {
                critical_carriers: &[IntegrationUnitId::DeviceCertificateConvergenceJourney],
                has_release_consumer: true,
            },
            Self::IdentityAuditFixture
            | Self::MqttBackpressureFault
            | Self::RuntimeComposeFixture
            | Self::SettingsOnlyProductionArtifact => SharedJourneyRelation {
                critical_carriers: &[],
                has_release_consumer: true,
            },
        }
    }

    fn for_path(path: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|source| source.path() == path)
    }
}

/// Project an integration target root or a declared shared journey source to stable unit IDs.
/// Unknown journey support and release-only carriers deliberately fail closed.
pub(crate) fn changed_integration_source(path: &str) -> Option<ChangedIntegrationSource> {
    if path == "journeys/Cargo.toml" {
        let units = IntegrationUnitId::ALL
            .into_iter()
            .filter(|id| {
                id.spec().package == "journeys"
                    && id.spec().primary_owner == ExecutionProfile::IntegrationCritical
            })
            .collect::<BTreeSet<_>>();
        return Some(ChangedIntegrationSource::Exact(units));
    }
    if let Some(source) = SharedJourneySource::for_path(path) {
        let relation = source.relation();
        let units = relation
            .critical_carriers
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        return Some(if relation.has_release_consumer {
            ChangedIntegrationSource::ReleaseCheck
        } else {
            ChangedIntegrationSource::Exact(units)
        });
    }
    if path.starts_with("journeys/tests/support/") || path.starts_with("journeys/tests/common/") {
        return Some(ChangedIntegrationSource::ReleaseCheck);
    }

    for id in IntegrationUnitId::ALL {
        let spec = id.spec();
        if spec.kind != TargetKind::Test {
            continue;
        }
        let Some(scope) = LocalFeatureScope::for_package(spec.package) else {
            return Some(ChangedIntegrationSource::ReleaseCheck);
        };
        let target_path = format!("{}/tests/{}.rs", scope.root(), spec.target);
        if path == target_path {
            return Some(
                if spec.primary_owner == ExecutionProfile::IntegrationCritical {
                    ChangedIntegrationSource::Exact(BTreeSet::from([id]))
                } else {
                    ChangedIntegrationSource::ReleaseCheck
                },
            );
        }
    }
    None
}

pub(crate) fn shared_source_relation_semantics() -> Vec<String> {
    SharedJourneySource::ALL
        .into_iter()
        .map(|source| {
            let relation = source.relation();
            let carriers = source
                .relation()
                .critical_carriers
                .iter()
                .map(|id| id.as_str())
                .collect::<Vec<_>>()
                .join(",");
            format!(
                "integration-shared-source={}:{}",
                source.path(),
                if relation.has_release_consumer {
                    if carriers.is_empty() {
                        "release-check".to_owned()
                    } else {
                        format!("release-check+{carriers}")
                    }
                } else {
                    carriers
                }
            )
        })
        .collect()
}

#[cfg(test)]
pub(crate) fn critical_units_for_targets(
    targets: impl IntoIterator<Item = (impl AsRef<str>, impl AsRef<str>)>,
) -> BTreeSet<IntegrationUnitId> {
    let targets = targets
        .into_iter()
        .map(|(package, target)| (package.as_ref().to_owned(), target.as_ref().to_owned()))
        .collect::<BTreeSet<_>>();
    IntegrationUnitId::ALL
        .into_iter()
        .filter(|id| id.spec().primary_owner == ExecutionProfile::IntegrationCritical)
        .filter(|id| targets.contains(&(id.spec().package.to_owned(), id.spec().target.to_owned())))
        .collect()
}

integration_shard_catalog! {
    PostgresDomain => {
        name: "postgres-domain",
        local_feature_scopes: [Postgres, PostgresMigration, Journeys, Runtime],
        units: [
            PostgresLib => ("postgres-lib", IntegrationCritical, "postgres", "postgres", Lib, Serial, Affected, resources: [Postgres], impact_packages: [PostgresPackage], capabilities: []),
            PostgresMigrationLib => ("postgres-migration-lib", IntegrationCritical, "postgres-migration", "postgres_migration", Lib, Serial, Affected, resources: [Postgres], impact_packages: [PostgresMigrationPackage], capabilities: []),
            PostgresFeatureManifest => ("postgres-feature-manifest", ReleaseCheck, "postgres", "feature_manifest", Test, Parallel, Affected, resources: [], impact_packages: [], capabilities: []),
            PostgresDomainFeatureSurfaceTrybuild => ("postgres-domain-feature-surface-trybuild", ReleaseCheck, "postgres", "domain_feature_surface_trybuild", Test, Parallel, Affected, resources: [], impact_packages: [], capabilities: []),
            PostgresMigrationOpsContract => ("postgres-migration-ops-contract", ReleaseCheck, "postgres", "migration_ops_contract", Test, Parallel, Affected, resources: [], impact_packages: [], capabilities: []),
            PostgresMigration0067HistoricalArtifact => ("postgres-migration-0067-historical-artifact", ReleaseCheck, "postgres", "migration_0067_historical_artifact", Test, Serial, RemoteOnly, resources: [Postgres], impact_packages: [], capabilities: []),
            PostgresMigration0086HardCutover => ("postgres-migration-0086-hard-cutover", ReleaseCheck, "postgres", "migration_0086_hard_cutover", Test, Serial, RemoteOnly, resources: [Postgres], impact_packages: [], capabilities: []),
            PostgresMigration0087DeviceCommandFencing => ("postgres-migration-0087-device-command-fencing", ReleaseCheck, "postgres", "migration_0087_device_command_fencing", Test, Serial, RemoteOnly, resources: [Postgres], impact_packages: [], capabilities: []),
            PostgresMigration0087DeviceCommandFencingContract => ("postgres-migration-0087-device-command-fencing-contract", ReleaseCheck, "postgres", "migration_0087_device_command_fencing_contract", Test, Parallel, Affected, resources: [], impact_packages: [], capabilities: []),
            PostgresMigration0089SagaOperatorControl => ("postgres-migration-0089-saga-operator-control", ReleaseCheck, "postgres", "migration_0089_saga_operator_control", Test, Serial, RemoteOnly, resources: [Postgres], impact_packages: [], capabilities: []),
            PostgresMigration0090SagaOperatorLane => ("postgres-migration-0090-saga-operator-lane", ReleaseCheck, "postgres", "migration_0090_saga_operator_lane", Test, Parallel, Affected, resources: [], impact_packages: [], capabilities: []),
            PostgresMigration0092DeviceCertificateArtifacts => ("postgres-migration-0092-device-certificate-artifacts", ReleaseCheck, "postgres", "migration_0092_device_certificate_artifacts", Test, Parallel, Affected, resources: [], impact_packages: [], capabilities: []),
            PostgresMigration0094DeviceIngressUow => ("postgres-migration-0094-device-ingress-uow", ReleaseCheck, "postgres", "migration_0094_device_ingress_uow", Test, Parallel, Affected, resources: [], impact_packages: [], capabilities: []),
            PostgresMigration0095DeviceOutbox => ("postgres-migration-0095-device-outbox", ReleaseCheck, "postgres", "migration_0095_device_outbox", Test, Parallel, Affected, resources: [], impact_packages: [], capabilities: []),
            PostgresMigration0096DeviceCertificateEnrollment => ("postgres-migration-0096-device-certificate-enrollment", ReleaseCheck, "postgres", "migration_0096_device_certificate_enrollment", Test, Parallel, Affected, resources: [], impact_packages: [], capabilities: []),
            PostgresMigration0097ProjectionWorkerLifecycle => ("postgres-migration-0097-projection-worker-lifecycle", ReleaseCheck, "postgres", "migration_0097_projection_worker_lifecycle", Test, Parallel, Affected, resources: [], impact_packages: [], capabilities: []),
            PostgresMigration0097ProjectionWorkerUpgrade => ("postgres-migration-0097-projection-worker-upgrade", ReleaseCheck, "postgres", "migration_0097_projection_worker_upgrade", Test, Serial, RemoteOnly, resources: [Postgres], impact_packages: [], capabilities: []),
            PostgresMigration0098SettingsActiveServing => ("postgres-migration-0098-settings-active-serving", ReleaseCheck, "postgres", "migration_0098_settings_active_serving", Test, Parallel, Affected, resources: [], impact_packages: [], capabilities: []),
            PostgresMigration0098SettingsActiveServingUpgrade => ("postgres-migration-0098-settings-active-serving-upgrade", ReleaseCheck, "postgres", "migration_0098_settings_active_serving_upgrade", Test, Serial, RemoteOnly, resources: [Postgres], impact_packages: [], capabilities: []),
            PostgresMigration0099DeviceCredentialAuthority => ("postgres-migration-0099-device-credential-authority", ReleaseCheck, "postgres", "migration_0099_device_credential_authority", Test, Parallel, Affected, resources: [], impact_packages: [], capabilities: []),
            PostgresMigration0102AbacProfile => ("postgres-migration-0102-abac-profile", ReleaseCheck, "postgres", "migration_0102_abac_profile", Test, Parallel, Affected, resources: [], impact_packages: [], capabilities: []),
            PostgresMigration0102AbacProfileUpgrade => ("postgres-migration-0102-abac-profile-upgrade", ReleaseCheck, "postgres", "migration_0102_abac_profile_upgrade", Test, Serial, RemoteOnly, resources: [Postgres], impact_packages: [], capabilities: []),
            PostgresMigration0103DeviceCommandExpiry => ("postgres-migration-0103-device-command-expiry", ReleaseCheck, "postgres", "migration_0103_device_command_expiry", Test, Parallel, Affected, resources: [], impact_packages: [], capabilities: []),
            PostgresMigration0104AbacPolicyOperatorValues => ("postgres-migration-0104-abac-policy-operator-values", ReleaseCheck, "postgres", "migration_0104_abac_policy_operator_values", Test, Parallel, Affected, resources: [], impact_packages: [], capabilities: []),
            PostgresMigration0104AbacPolicyOperatorValuesUpgrade => ("postgres-migration-0104-abac-policy-operator-values-upgrade", ReleaseCheck, "postgres", "migration_0104_abac_policy_operator_values_upgrade", Test, Serial, RemoteOnly, resources: [Postgres], impact_packages: [], capabilities: []),
            PostgresTenantTransactionTrybuild => ("postgres-tenant-transaction-trybuild", ReleaseCheck, "postgres", "tenant_transaction_trybuild", Test, Parallel, Affected, resources: [], impact_packages: [], capabilities: []),
            AuditListTenantEntriesLocalTxJourney => ("audit-list-tenant-entries-local-tx-journey", IntegrationCritical, "journeys", "audit_list_tenant_entries_localtx_journey", Test, Serial, RemoteOnly, resources: [Postgres], impact_packages: [AuditPackage, PostgresPackage, LocalTxContract], capabilities: []),
            IdentityLogoutGrantJourney => ("identity-logout-grant-journey", ReleaseCheck, "journeys", "identity_logout_grant_journey", Test, Parallel, RemoteOnly, resources: [Postgres], impact_packages: [], capabilities: []),
            IdentityPasswordSecurityEventJourney => ("identity-password-security-event-journey", IntegrationCritical, "journeys", "identity_password_security_event_journey", Test, Serial, RemoteOnly, resources: [Postgres], impact_packages: [AuthnPackage, IdentityPackage, PostgresPackage, LocalTxContract, OidcProvider], capabilities: []),
            IdentityRefreshProducerTransactionJourney => ("identity-refresh-producer-transaction-journey", IntegrationCritical, "journeys", "identity_refresh_producer_transaction_journey", Test, Serial, RemoteOnly, resources: [Postgres], impact_packages: [AuthnPackage, IdentityPackage, PostgresPackage, LocalTxContract, OidcProvider], capabilities: []),
            SettingsSecretPublishLocalTxJourney => ("settings-secret-publish-local-tx-journey", IntegrationCritical, "journeys", "settings_secret_publish_localtx_journey", Test, Serial, RemoteOnly, resources: [Postgres], impact_packages: [SettingsPackage, PostgresPackage, LocalTxContract], capabilities: []),
            SettingsSecretE2e => ("settings-secret-e2e", IntegrationCritical, "runtime", "settings_secret_e2e", Test, Serial, RemoteOnly, resources: [Postgres], impact_packages: [SettingsPackage, PostgresPackage, RuntimePackage, RuntimeSurface], capabilities: []),
        ],
    },
    EventTransport => {
        name: "event-transport",
        local_feature_scopes: [Amqp, Mqtt, DeviceIdentity, Testkit, Journeys, Runtime],
        units: [
            AmqpLib => ("amqp-lib", IntegrationCritical, "amqp", "amqp", Lib, Parallel, Affected, resources: [Amqp], impact_packages: [AmqpPackage], capabilities: []),
            AmqpIntegration => ("amqp-integration", IntegrationCritical, "amqp", "integration", Test, Serial, RemoteOnly, resources: [Amqp], impact_packages: [AmqpPackage], capabilities: []),
            MqttLib => ("mqtt-lib", ReleaseCheck, "mqtt", "mqtt", Lib, Parallel, Affected, resources: [Mqtt], impact_packages: [], capabilities: [Docker]),
            MqttIntegration => ("mqtt-integration", IntegrationCritical, "mqtt", "integration", Test, Serial, RemoteOnly, resources: [Mqtt], impact_packages: [MqttPackage], capabilities: [Docker]),
            DeviceIdentityLib => ("deviceidentity-lib", ReleaseCheck, "deviceidentity", "deviceidentity", Lib, Parallel, Affected, resources: [], impact_packages: [], capabilities: []),
            DeviceCertificateConvergenceJourney => ("device-certificate-convergence-journey", IntegrationCritical, "journeys", "device_certificate_convergence_journey", Test, Serial, RemoteOnly, resources: [Postgres, Mqtt], impact_packages: [IotDevicePackage, IdentityCompositionPackage, DeviceIdentityPackage, EventexecPackage, IdentityPackage, MqttPackage, PostgresPackage], capabilities: [Docker]),
            MqttBackpressureFaultJourney => ("mqtt-backpressure-fault-journey", ReleaseCheck, "journeys", "mqtt_backpressure_fault_journey", Test, Serial, RemoteOnly, resources: [Postgres, Mqtt], impact_packages: [], capabilities: [Docker]),
            MqttAssertionContract => ("mqtt-assertion-contract", ReleaseCheck, "mqtt", "assertion_contract", Test, Parallel, Affected, resources: [], impact_packages: [], capabilities: []),
            MqttConfigTopic => ("mqtt-config-topic", ReleaseCheck, "mqtt", "config_topic", Test, Parallel, Affected, resources: [], impact_packages: [], capabilities: []),
            MqttOwnershipGate => ("mqtt-ownership-gate", ReleaseCheck, "mqtt", "ownership_gate", Test, Parallel, Affected, resources: [], impact_packages: [], capabilities: []),
            MqttSessionSurface => ("mqtt-session-surface", ReleaseCheck, "mqtt", "session_surface", Test, Parallel, Affected, resources: [], impact_packages: [], capabilities: []),
            MqttTlsConfig => ("mqtt-tls-config", ReleaseCheck, "mqtt", "tls_config", Test, Parallel, Affected, resources: [], impact_packages: [], capabilities: []),
            TestkitMqttMtlsFixture => ("testkit-mqtt-mtls-fixture", ReleaseCheck, "testkit", "mqtt_mtls_fixture", Test, Serial, RemoteOnly, resources: [Mqtt], impact_packages: [], capabilities: [Docker]),
            TestkitMqttOwnershipGate => ("testkit-mqtt-ownership-gate", ReleaseCheck, "testkit", "mqtt_ownership_gate", Test, Parallel, Affected, resources: [], impact_packages: [], capabilities: []),
            AmqpConsumerAtLeastOnceJourney => ("amqp-consumer-at-least-once-journey", IntegrationCritical, "journeys", "amqp_consumer_at_least_once_journey", Test, Serial, RemoteOnly, resources: [Amqp], impact_packages: [AmqpPackage, EventexecPackage], capabilities: []),
            EventTransportJourney => ("event-transport-journey", ReleaseCheck, "journeys", "eventtransport_journey", Test, Parallel, Affected, resources: [Postgres, Redis, Amqp, Mqtt], impact_packages: [], capabilities: [Docker]),
            IdentityLoginAuditDurableJourney => ("identity-login-audit-durable-journey", IntegrationCritical, "journeys", "identity_login_audit_durable_journey", Test, Serial, RemoteOnly, resources: [Postgres], impact_packages: [AuditPackage, EventexecPackage, IdentityPackage, PostgresPackage], capabilities: []),
            IdentityLoginAuditJourney => ("identity-login-audit-journey", ReleaseCheck, "journeys", "identity_login_audit_journey", Test, Parallel, Affected, resources: [Postgres, Amqp], impact_packages: [], capabilities: []),
            IdentityAuditRuntimeJourney => ("identity-audit-runtime-journey", ReleaseCheck, "journeys", "identityaudit_runtime", Test, Serial, RemoteOnly, resources: [Postgres, Redis, Amqp], impact_packages: [], capabilities: []),
            EventTransportDurableE2e => ("event-transport-durable-e2e", IntegrationCritical, "runtime", "event_transport_durable_e2e", Test, Serial, RemoteOnly, resources: [Postgres, Redis, Amqp], impact_packages: [AmqpPackage, EventexecPackage, MqttPackage, PostgresPackage, RedisAdapterPackage, RuntimePackage, RuntimeSurface], capabilities: [Docker]),
        ],
    },
    RuntimeHttpAuth => {
        name: "runtime-http-auth",
        local_feature_scopes: [Journeys, Runtime, SettingsOnly, IdentityAudit],
        units: [
            SecurityProviderCloseoutJourney => ("security-provider-closeout-journey", ReleaseCheck, "journeys", "security_provider_closeout", Test, Parallel, Affected, resources: [Postgres, Vault], impact_packages: [], capabilities: []),
            SettingsOnlyRuntimeJourney => ("settings-only-runtime-journey", ReleaseCheck, "journeys", "settingsonly_runtime", Test, Parallel, RemoteOnly, resources: [Vault], impact_packages: [], capabilities: []),
            SettingsOnlyLib => ("settings-only-lib", ReleaseCheck, "settingsonly", "settingsonly", Lib, Serial, Affected, resources: [Vault], impact_packages: [], capabilities: []),
            IdentityAuditLib => ("identity-audit-lib", ReleaseCheck, "identityaudit", "identityaudit", Lib, Serial, Affected, resources: [], impact_packages: [], capabilities: []),
            IdentityAuditArtifactAcceptance => ("identity-audit-artifact-acceptance", ReleaseCheck, "identityaudit", "artifact_acceptance", Test, Parallel, Affected, resources: [], impact_packages: [], capabilities: []),
            IdentityAuditRuntimeImageAcceptance => ("identity-audit-runtime-image-acceptance", ReleaseCheck, "identityaudit", "runtime_image_acceptance", Test, Serial, RemoteOnly, resources: [], impact_packages: [], capabilities: [Docker]),
            RuntimeLib => ("runtime-lib", ReleaseCheck, "runtime", "runtime", Lib, Serial, Affected, resources: [Postgres, Redis, Vault], impact_packages: [], capabilities: []),
            AuthE2e => ("auth-e2e", ReleaseCheck, "runtime", "auth_e2e", Test, Parallel, Affected, resources: [Postgres], impact_packages: [], capabilities: []),
            AuthBridgeStructure => ("auth-bridge-structure", ReleaseCheck, "runtime", "auth_bridge_structure", Test, Parallel, Affected, resources: [], impact_packages: [], capabilities: []),
            ServerBudgetStructure => ("server-budget-structure", ReleaseCheck, "runtime", "server_budget_structure", Test, Parallel, Affected, resources: [], impact_packages: [], capabilities: []),
            ConfigsReadyE2e => ("configs-ready-e2e", IntegrationCritical, "runtime", "configs_ready_e2e", Test, Serial, RemoteOnly, resources: [Postgres], impact_packages: [PostgresPackage, RuntimePackage, RuntimeSurface], capabilities: []),
            DomainExecutionPlanTrybuild => ("domain-execution-plan-trybuild", ReleaseCheck, "runtime", "domain_execution_plan_trybuild", Test, Parallel, Affected, resources: [], impact_packages: [], capabilities: []),
            IdentityLoginWireE2e => ("identity-login-wire-e2e", IntegrationCritical, "runtime", "identity_login_wire_e2e", Test, Serial, RemoteOnly, resources: [Postgres], impact_packages: [AuthnPackage, HttpdPackage, HttpservePackage, IdentityPackage, PostgresPackage, RuntimePackage, RuntimeSurface, OidcProvider], capabilities: []),
            InfraBuildersApi => ("infra-builders-api", ReleaseCheck, "runtime", "infra_builders_api", Test, Parallel, Affected, resources: [], impact_packages: [], capabilities: []),
            ListenerPlanTrybuild => ("listener-plan-trybuild", ReleaseCheck, "runtime", "listener_plan_trybuild", Test, Parallel, Affected, resources: [], impact_packages: [], capabilities: []),
            OperatorSurfaceTrybuild => ("operator-surface-trybuild", ReleaseCheck, "runtime", "operator_surface_trybuild", Test, Parallel, Affected, resources: [], impact_packages: [], capabilities: []),
            RefreshMintE2e => ("refresh-mint-e2e", ReleaseCheck, "runtime", "refresh_mint_e2e", Test, Parallel, Affected, resources: [Postgres], impact_packages: [], capabilities: []),
            KeyRotationE2e => ("key-rotation-e2e", ReleaseCheck, "runtime", "key_rotation_e2e", Test, Parallel, Affected, resources: [Postgres], impact_packages: [], capabilities: []),
            RuntimeOutputsTrybuild => ("runtime-outputs-trybuild", ReleaseCheck, "runtime", "runtime_outputs_trybuild", Test, Parallel, Affected, resources: [], impact_packages: [], capabilities: []),
            RuntimeServeE2e => ("runtime-serve-e2e", IntegrationCritical, "runtime", "runtime_serve_e2e", Test, Parallel, RemoteOnly, resources: [], impact_packages: [BootstrapPackage, HttpdPackage, HttpservePackage, RuntimePackage, RuntimeSurface], capabilities: []),
            ServiceTokenReplayE2e => ("service-token-replay-e2e", IntegrationCritical, "runtime", "service_token_replay_e2e", Test, Serial, RemoteOnly, resources: [Postgres], impact_packages: [AuthnPackage, IdentityPackage, PostgresPackage, RuntimePackage, RuntimeSurface, OidcProvider], capabilities: []),
            WireContractE2e => ("wire-contract-e2e", IntegrationCritical, "runtime", "wire_contract_e2e", Test, Serial, RemoteOnly, resources: [Postgres], impact_packages: [PostgresPackage, RuntimePackage, SettingsPackage, RuntimeSurface], capabilities: []),
        ],
    },
    ConsistencyFault => {
        name: "consistency-fault",
        local_feature_scopes: [Testkit, RedisAdapter, JourneysFaultMatrix],
        units: [
            TestkitLib => ("testkit-lib", ReleaseCheck, "testkit", "testkit", Lib, Serial, Affected, resources: [Redis], impact_packages: [], capabilities: []),
            TestkitCrashMatrix => ("testkit-crash-matrix", ReleaseCheck, "testkit", "crash_matrix", Test, Parallel, Affected, resources: [], impact_packages: [], capabilities: []),
            DeviceCommandConformance => ("device-command-conformance", ReleaseCheck, "testkit", "device_command_conformance", Test, Parallel, Affected, resources: [], impact_packages: [], capabilities: []),
            TestkitHarness => ("testkit-harness", ReleaseCheck, "testkit", "harness", Test, Parallel, Affected, resources: [], impact_packages: [], capabilities: []),
            TestkitLocalOnly => ("testkit-local-only", ReleaseCheck, "testkit", "local_only", Test, Parallel, Affected, resources: [], impact_packages: [], capabilities: []),
            TestkitWait => ("testkit-wait", ReleaseCheck, "testkit", "wait", Test, Parallel, Affected, resources: [], impact_packages: [], capabilities: []),
            PostgresTestLoginGovernance => ("postgres-test-login-governance", ReleaseCheck, "testkit", "postgres_test_login_governance", Test, Serial, Affected, resources: [Postgres], impact_packages: [], capabilities: []),
            ProjectionTargetConformanceTrybuild => ("projection-target-conformance-trybuild", ReleaseCheck, "testkit", "projection_target_conformance_trybuild", Test, Parallel, Affected, resources: [], impact_packages: [], capabilities: []),
            ProviderCatalogTrybuild => ("provider-catalog-trybuild", ReleaseCheck, "testkit", "provider_catalog_trybuild", Test, Parallel, Affected, resources: [], impact_packages: [], capabilities: []),
            RedisAdapterLib => ("redis-adapter-lib", ReleaseCheck, "redis-adapter", "redis", Lib, Parallel, Affected, resources: [Redis], impact_packages: [], capabilities: []),
            RedisIntegrationClaimer => ("redis-integration-claimer", IntegrationCritical, "redis-adapter", "integration_claimer", Test, Serial, RemoteOnly, resources: [Redis], impact_packages: [DistributedPackage, RedisAdapterPackage], capabilities: []),
            RedisIntegrationRateLimit => ("redis-integration-rate-limit", IntegrationCritical, "redis-adapter", "integration_rate_limit", Test, Serial, RemoteOnly, resources: [Redis], impact_packages: [RedisAdapterPackage], capabilities: []),
            RedisIntegrationSagaEffectFixture => ("redis-integration-saga-effect-fixture", ReleaseCheck, "redis-adapter", "integration_saga_effect_fixture", Test, Serial, RemoteOnly, resources: [Redis], impact_packages: [], capabilities: []),
            ConsistencyFaultMatrixJourney => ("consistency-fault-matrix-journey", ReleaseCheck, "journeys-fault-matrix", "consistency_fault_matrix_journey", Test, Serial, RemoteOnly, resources: [Postgres, Redis, Amqp], impact_packages: [], capabilities: []),
            L2DrRecoveryJourney => ("l2-dr-recovery-journey", ReleaseCheck, "journeys-fault-matrix", "l2_dr_recovery_journey", Test, Serial, RemoteOnly, resources: [Postgres, Amqp], impact_packages: [], capabilities: []),
            SagaFaultRecovery => ("saga-fault-recovery", ReleaseCheck, "journeys-fault-matrix", "saga_fault_recovery", Test, Serial, RemoteOnly, resources: [Postgres, Redis], impact_packages: [], capabilities: []),
        ],
    },
    CdcProjectionSaga => {
        name: "cdc-projection-saga",
        local_feature_scopes: [Journeys, Runtime],
        units: [
            SagaRuntimeProviderIntegration => ("saga-runtime-provider-integration", ReleaseCheck, "journeys", "saga_runtime_provider_integration", Test, Serial, RemoteOnly, resources: [Postgres], impact_packages: [EventexecPackage, PostgresPackage, RuntimePackage, RuntimeSurface], capabilities: [PreparedExternalPostgres]),
            SagaProjectionDepsJourney => ("saga-projection-deps-journey", ReleaseCheck, "journeys", "saga_projection_deps_journey", Test, Parallel, Affected, resources: [Postgres], impact_packages: [], capabilities: []),
            SettingsConfigPublishJourney => ("settings-config-publish-journey", ReleaseCheck, "journeys", "settings_config_publish_journey", Test, Parallel, Affected, resources: [Postgres], impact_packages: [], capabilities: []),
            SettingsConfigPublishDurableE2e => ("settings-config-publish-durable-e2e", IntegrationCritical, "runtime", "settings_config_publish_durable_e2e", Test, Serial, RemoteOnly, resources: [Postgres], impact_packages: [ConsistencyPackage, EventexecPackage, PostgresPackage, RuntimePackage, SettingsPackage, RuntimeSurface], capabilities: []),
        ],
    },
    ObjectStorage => {
        name: "object-storage",
        local_feature_scopes: [S3],
        units: [
            S3Lib => ("s3-lib", ReleaseCheck, "s3", "s3", Lib, Parallel, Affected, resources: [ObjectStorage], impact_packages: [], capabilities: [Docker]),
            DlxArchiveStore => ("dlx-archive-store", ReleaseCheck, "s3", "dlx_archive_store", Test, Parallel, RemoteOnly, resources: [ObjectStorage], impact_packages: [], capabilities: [Docker]),
            IntegrationObjectStore => ("integration-object-store", IntegrationCritical, "s3", "integration_object_store", Test, Serial, RemoteOnly, resources: [ObjectStorage], impact_packages: [EventexecPackage, S3Package], capabilities: [Docker]),
        ],
    },
    ProductionRuntime => {
        name: "production-runtime",
        local_feature_scopes: [Journeys],
        units: [
            SettingsOnlyProductionArtifact => ("settings-only-production-artifact", ReleaseCheck, "journeys", "settingsonly_production_artifact", Test, Serial, RemoteOnly, resources: [], impact_packages: [], capabilities: [Docker]),
            TwoReplicaRuntimeJourney => ("two-replica-runtime-journey", ReleaseCheck, "journeys", "two_replica_runtime", Test, Serial, RemoteOnly, resources: [], impact_packages: [], capabilities: [Docker]),
            ProductionRuntimeJourney => ("production-runtime-journey", ReleaseCheck, "journeys", "production_runtime", Test, Parallel, RemoteOnly, resources: [], impact_packages: [], capabilities: [Docker]),
            RuntimeInventoryJourney => ("runtime-inventory-journey", ReleaseCheck, "journeys", "runtime_inventory", Test, Parallel, RemoteOnly, resources: [], impact_packages: [], capabilities: [Docker]),
        ],
    },
}

fn validate_integration_unit_catalog(
    specs: &[IntegrationUnitSpec],
    shard_specs: &[ShardSpec],
) -> Result<()> {
    if specs.len() != IntegrationUnitId::ALL.len() {
        bail!("integration unit catalog must cover every stable ID");
    }
    let mut seen = BTreeSet::new();
    for (index, spec) in specs.iter().enumerate() {
        if !seen.insert(spec.id) {
            bail!("integration unit catalog repeats ID {:?}", spec.id);
        }
        if spec.id as usize != index || IntegrationUnitId::ALL[index] != spec.id {
            bail!("integration unit catalog ID/order drift at index {index}");
        }
        if matches!(
            spec.primary_owner,
            ExecutionProfile::Check | ExecutionProfile::Test
        ) {
            bail!(
                "integration unit {:?} has non-integration primary owner {}",
                spec.id,
                spec.primary_owner,
            );
        }
        if spec.primary_owner == ExecutionProfile::IntegrationCritical
            && spec.impact_markers.is_empty()
        {
            bail!(
                "integration-critical unit {:?} has no typed impact marker",
                spec.id
            );
        }
        if spec
            .impact_markers
            .iter()
            .copied()
            .collect::<BTreeSet<_>>()
            .len()
            != spec.impact_markers.len()
        {
            bail!("integration unit {:?} repeats an impact marker", spec.id);
        }
        if spec
            .resources
            .iter()
            .copied()
            .collect::<BTreeSet<_>>()
            .len()
            != spec.resources.len()
        {
            bail!(
                "integration unit {:?} repeats an external resource",
                spec.id
            );
        }
        if spec
            .capabilities
            .iter()
            .copied()
            .collect::<BTreeSet<_>>()
            .len()
            != spec.capabilities.len()
        {
            bail!("integration unit {:?} repeats a capability", spec.id);
        }
        if spec
            .capabilities
            .contains(&Capability::PreparedExternalPostgres)
            && !spec.resources.contains(&Resource::Postgres)
        {
            bail!(
                "integration unit {:?} declares prepared external PostgreSQL without the PostgreSQL resource",
                spec.id
            );
        }
        if spec
            .resources
            .iter()
            .any(|resource| matches!(resource, Resource::Mqtt | Resource::ObjectStorage))
            && !spec.capabilities.contains(&Capability::Docker)
        {
            bail!(
                "integration unit {:?} requires a hermetic Docker-backed resource without Docker capability",
                spec.id
            );
        }
        if spec.shard == IntegrationShard::ProductionRuntime
            && !spec.capabilities.contains(&Capability::Docker)
        {
            bail!(
                "production-runtime unit {:?} must declare Docker capability",
                spec.id
            );
        }
        if spec.kind == TargetKind::Lib && spec.local_eligibility != LocalEligibility::Affected {
            bail!(
                "integration unit {:?} library tests must remain affected-local eligible",
                spec.id
            );
        }
    }
    validate_source_and_provider_relations(specs)?;

    let mut shard_owned = BTreeSet::new();
    for shard_spec in shard_specs {
        for unit in shard_spec.units {
            if unit.shard != shard_spec.shard {
                bail!(
                    "integration unit {:?} shard identity drift: {:?} != {:?}",
                    unit.id,
                    unit.shard,
                    shard_spec.shard
                );
            }
            if !shard_owned.insert(unit.id) {
                bail!("integration unit {:?} assigned to multiple shards", unit.id);
            }
            let canonical = specs
                .get(unit.id as usize)
                .context("integration shard references an unknown stable unit ID")?;
            if canonical != unit {
                bail!(
                    "integration unit {:?} spec drift from stable catalog",
                    unit.id
                );
            }
        }
    }
    if shard_owned != seen {
        bail!("integration shard membership must exactly cover stable unit IDs");
    }
    Ok(())
}

fn validate_source_and_provider_relations(specs: &[IntegrationUnitSpec]) -> Result<()> {
    let provider_catalog = AdapterPackage::ALL
        .into_iter()
        .filter_map(|adapter| match adapter.projection() {
            AdapterProjection::SecurityProvider(provider) => Some(provider),
            AdapterProjection::Resource(_) => None,
        })
        .collect::<BTreeSet<_>>();
    if provider_catalog != SecurityProvider::ALL.into_iter().collect() {
        bail!("security provider adapter projection is incomplete or duplicated");
    }
    for provider in SecurityProvider::ALL {
        if provider.carrier_marker().is_some()
            && critical_units_for_provider_in(provider, specs).is_none()
        {
            bail!(
                "security provider {} has no integration-critical carrier",
                provider.label()
            );
        }
    }

    let mut paths = BTreeSet::new();
    for source in SharedJourneySource::ALL {
        if !paths.insert(source.path()) {
            bail!(
                "shared journey source path is duplicated: {}",
                source.path()
            );
        }
        let mut carriers = BTreeSet::new();
        for carrier in source.relation().critical_carriers {
            if !carriers.insert(*carrier) {
                bail!("shared journey source repeats carrier {carrier:?}");
            }
            let Some(spec) = specs.iter().find(|spec| spec.id == *carrier) else {
                bail!("shared journey source references unknown carrier {carrier:?}");
            };
            if spec.primary_owner != ExecutionProfile::IntegrationCritical
                || spec.package != "journeys"
                || spec.kind != TargetKind::Test
            {
                bail!("shared journey source carrier {carrier:?} is not a critical journey test");
            }
        }
    }
    Ok(())
}

fn projected_integration_units(
    profile: ExecutionProfile,
) -> impl Iterator<Item = &'static IntegrationUnitSpec> {
    ExecutionUnitSpec::project(profile).filter_map(|unit| match unit {
        ExecutionUnitSpec::Integration(spec) => Some(spec),
        ExecutionUnitSpec::Gate(_) => None,
    })
}

/// A closed, typed integration projection. Construction is private so callers cannot bypass
/// owner validation or create a partial `release-check` projection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct IntegrationSelection {
    profile: ExecutionProfile,
    unit_ids: BTreeSet<IntegrationUnitId>,
}

impl IntegrationSelection {
    fn new(profile: ExecutionProfile, unit_ids: BTreeSet<IntegrationUnitId>) -> Result<Self> {
        match profile {
            ExecutionProfile::IntegrationCritical => {
                if unit_ids.is_empty() {
                    bail!("integration-critical selection must not be empty");
                }
                if let Some(id) = unit_ids
                    .iter()
                    .find(|id| id.spec().primary_owner != ExecutionProfile::IntegrationCritical)
                {
                    bail!(
                        "integration-critical selection contains release-check unit `{}`",
                        id.as_str()
                    );
                }
            }
            ExecutionProfile::ReleaseCheck => {
                let expected = IntegrationUnitId::ALL.into_iter().collect::<BTreeSet<_>>();
                if unit_ids != expected {
                    bail!(
                        "release-check selection must expand to the complete integration catalog"
                    );
                }
            }
            ExecutionProfile::Check | ExecutionProfile::Test => {
                bail!("profile `{profile}` is not an integration selection");
            }
        }
        Ok(Self { profile, unit_ids })
    }

    pub(crate) fn for_profile(profile: ExecutionProfile) -> Result<Self> {
        let unit_ids = projected_integration_units(profile)
            .map(|spec| spec.id)
            .collect();
        Self::new(profile, unit_ids)
    }

    pub(crate) fn release_check() -> Self {
        Self {
            profile: ExecutionProfile::ReleaseCheck,
            unit_ids: IntegrationUnitId::ALL.into_iter().collect(),
        }
    }

    pub(crate) fn critical(unit_ids: impl IntoIterator<Item = IntegrationUnitId>) -> Result<Self> {
        Self::new(
            ExecutionProfile::IntegrationCritical,
            unit_ids.into_iter().collect(),
        )
    }

    /// Reconstruct the exact critical selection carried by one typed batch.
    #[cfg(test)]
    pub(crate) fn for_exact_batch(batch: &ShardBatch) -> Result<Self> {
        Self::critical(batch.unit_ids.iter().copied())
    }

    pub(crate) const fn profile(&self) -> ExecutionProfile {
        self.profile
    }

    pub(crate) const fn unit_ids(&self) -> &BTreeSet<IntegrationUnitId> {
        &self.unit_ids
    }

    pub(crate) fn unit_ids_for_shard(
        &self,
        shard: IntegrationShard,
    ) -> BTreeSet<IntegrationUnitId> {
        self.unit_ids
            .iter()
            .copied()
            .filter(|id| id.spec().shard == shard)
            .collect()
    }

    pub(crate) fn resources_for_shard(&self, shard: IntegrationShard) -> Vec<Resource> {
        self.units_for_shard(shard)
            .flat_map(|unit| unit.resources.iter().copied())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    pub(crate) fn requires_docker_for_shard(&self, shard: IntegrationShard) -> bool {
        self.units_for_shard(shard).any(unit_requires_docker)
    }

    fn units_for_shard(
        &self,
        shard: IntegrationShard,
    ) -> impl Iterator<Item = &'static IntegrationUnitSpec> + '_ {
        self.unit_ids
            .iter()
            .copied()
            .map(IntegrationUnitId::spec)
            .filter(move |spec| spec.shard == shard)
    }
}

fn unit_requires_docker(unit: &IntegrationUnitSpec) -> bool {
    unit.capabilities.contains(&Capability::Docker)
        || (unit.resources.contains(&Resource::Postgres)
            && !unit
                .capabilities
                .contains(&Capability::PreparedExternalPostgres))
}

impl fmt::Display for IntegrationSelection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.profile {
            ExecutionProfile::IntegrationCritical => {
                formatter.write_str("integration-critical:")?;
                let mut separator = "";
                for id in IntegrationUnitId::wire_order(&self.unit_ids) {
                    formatter.write_str(separator)?;
                    formatter.write_str(id.as_str())?;
                    separator = ",";
                }
                Ok(())
            }
            ExecutionProfile::ReleaseCheck => formatter.write_str("release-check"),
            ExecutionProfile::Check | ExecutionProfile::Test => unreachable!(
                "IntegrationSelection private constructor excludes non-integration profiles"
            ),
        }
    }
}

impl FromStr for IntegrationSelection {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        if value == "release-check" {
            return Self::for_profile(ExecutionProfile::ReleaseCheck);
        }
        let Some(raw_ids) = value.strip_prefix("integration-critical:") else {
            bail!("unknown integration selection `{value}`");
        };
        if raw_ids.is_empty() {
            bail!("integration-critical selection must not be empty");
        }
        let mut unit_ids = BTreeSet::new();
        for raw_id in raw_ids.split(',') {
            let id = raw_id.parse::<IntegrationUnitId>()?;
            if !unit_ids.insert(id) {
                bail!("integration selection repeats unit `{raw_id}`");
            }
        }
        let selection = Self::critical(unit_ids)?;
        if selection.to_string() != value {
            bail!("integration selection token is not canonical");
        }
        Ok(selection)
    }
}

impl Serialize for IntegrationSelection {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for IntegrationSelection {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let token = String::deserialize(deserializer)?;
        token.parse().map_err(serde::de::Error::custom)
    }
}

impl fmt::Display for IntegrationShard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PartitionPolicy {
    Unpartitioned,
    TwoWayHash,
}

impl IntegrationShard {
    pub(crate) const fn partition_policy(self) -> PartitionPolicy {
        match self {
            Self::EventTransport | Self::RuntimeHttpAuth => PartitionPolicy::TwoWayHash,
            Self::PostgresDomain
            | Self::ConsistencyFault
            | Self::CdcProjectionSaga
            | Self::ObjectStorage
            | Self::ProductionRuntime => PartitionPolicy::Unpartitioned,
        }
    }

    pub(crate) fn validate_partition(
        self,
        partition: Option<crate::nextest::HashPartition>,
    ) -> Result<()> {
        match (self.partition_policy(), partition) {
            (PartitionPolicy::Unpartitioned, None) => Ok(()),
            (PartitionPolicy::TwoWayHash, Some(value)) if value.is_two_way() => Ok(()),
            (PartitionPolicy::Unpartitioned, Some(_)) => {
                bail!("integration shard `{self}` 禁止 partition")
            }
            (PartitionPolicy::TwoWayHash, None) => Ok(()),
            (PartitionPolicy::TwoWayHash, Some(value)) => {
                bail!("integration shard `{self}` 只接受 1/2 或 2/2，收到 {value}")
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ShardBatch {
    pub(crate) unit_ids: BTreeSet<IntegrationUnitId>,
    pub(crate) scheduling: Scheduling,
    pub(crate) kind: TargetKind,
    pub(crate) package: &'static str,
    /// Cargo feature resolved from [`LocalFeatureScope`] for `package` (e.g. mqtt → `broker-tests`).
    pub(crate) feature: &'static str,
    pub(crate) targets: Vec<&'static str>,
    pub(crate) filter: String,
}

pub(crate) fn batches(
    selection: &IntegrationSelection,
    shard: IntegrationShard,
) -> Vec<ShardBatch> {
    debug_assert_eq!(shard.spec().shard, shard);
    [Scheduling::Serial, Scheduling::Parallel]
        .into_iter()
        .flat_map(|scheduling| {
            [TargetKind::Lib, TargetKind::Test]
                .into_iter()
                .flat_map(move |kind| {
                    let mut by_package = BTreeMap::<_, Vec<_>>::new();
                    for unit in selection
                        .units_for_shard(shard)
                        .copied()
                        .filter(|unit| unit.scheduling == scheduling && unit.kind == kind)
                    {
                        by_package.entry(unit.package).or_default().push(unit);
                    }
                    by_package.into_iter().filter_map(move |(package, units)| {
                        let feature = LocalFeatureScope::for_package(package)?.feature();
                        let targets = units
                            .iter()
                            .map(|unit| unit.target)
                            .collect::<BTreeSet<_>>()
                            .into_iter()
                            .collect();
                        let unit_ids = units.iter().map(|unit| unit.id).collect();
                        let filter = units
                            .into_iter()
                            .map(IntegrationUnitSpec::filter)
                            .map(|filter| format!("({filter})"))
                            .collect::<Vec<_>>()
                            .join(" or ");
                        Some(ShardBatch {
                            unit_ids,
                            scheduling,
                            kind,
                            package,
                            feature,
                            targets,
                            filter,
                        })
                    })
                })
        })
        .collect()
}

pub(crate) fn localtx_required_selection() -> Result<IntegrationSelection> {
    localtx_required_selection_from([
        IntegrationUnitId::PostgresLib,
        IntegrationUnitId::AuditListTenantEntriesLocalTxJourney,
        IntegrationUnitId::IdentityPasswordSecurityEventJourney,
        IntegrationUnitId::IdentityRefreshProducerTransactionJourney,
        IntegrationUnitId::SettingsSecretPublishLocalTxJourney,
    ])
}

fn localtx_required_selection_from(
    unit_ids: impl IntoIterator<Item = IntegrationUnitId>,
) -> Result<IntegrationSelection> {
    IntegrationSelection::critical(unit_ids)
}

pub(crate) fn postgres_transaction_journey_execution_batch(
    selection: &IntegrationSelection,
) -> Result<ShardBatch> {
    if IntegrationShard::PostgresDomain.partition_policy() != PartitionPolicy::Unpartitioned {
        bail!("Postgres transaction journey shard must remain unpartitioned");
    }
    let required = localtx_required_selection()
        .context("derive required LocalTx catalog selection for postgres journey batch")?;
    let required_journey_unit_ids = required
        .units_for_shard(IntegrationShard::PostgresDomain)
        .filter(|unit| unit.package == "journeys")
        .map(|unit| unit.id)
        .collect::<BTreeSet<_>>();
    if required_journey_unit_ids.is_empty() {
        bail!("required LocalTx catalog selection has no postgres journey units");
    }
    let matches = batches(selection, IntegrationShard::PostgresDomain)
        .into_iter()
        .filter(|batch| {
            batch.scheduling == Scheduling::Serial
                && batch.kind == TargetKind::Test
                && batch.package == "journeys"
                && batch.unit_ids == required_journey_unit_ids
        })
        .collect::<Vec<_>>();
    let [batch] = matches.as_slice() else {
        bail!(
            "Postgres transaction journeys must have exactly one postgres-domain Serial integration batch; found {}",
            matches.len()
        );
    };
    Ok(batch.clone())
}

fn localtx_backend_execution_unit_from(
    units: &[IntegrationUnitSpec],
) -> Result<IntegrationUnitSpec> {
    let expected = *IntegrationUnitId::PostgresLib.spec();
    let matches = units
        .iter()
        .copied()
        .filter(|unit| unit.id == expected.id)
        .collect::<Vec<_>>();
    let [unit] = matches.as_slice() else {
        bail!(
            "LocalTx backend evidence must have exactly one stable postgres execution unit; found {}",
            matches.len()
        );
    };
    if *unit != expected {
        bail!("LocalTx backend stable execution unit spec drift");
    }
    Ok(*unit)
}

/// Resolve the one real-backend carrier executed by the LocalTx required-evidence owner.
pub(crate) fn localtx_backend_execution_unit(
    selection: &IntegrationSelection,
) -> Result<IntegrationUnitSpec> {
    let shard = IntegrationShard::PostgresDomain;
    if shard.partition_policy() != PartitionPolicy::Unpartitioned {
        bail!("LocalTx backend evidence shard must remain unpartitioned");
    }
    let projected = selection
        .units_for_shard(shard)
        .copied()
        .collect::<Vec<_>>();
    localtx_backend_execution_unit_from(&projected)
}

const INTEGRATION_PACKAGES: &[&str] = &[
    "postgres",
    "postgres-migration",
    "redis-adapter",
    "amqp",
    "mqtt",
    "deviceidentity",
    "journeys",
    "runtime",
    "journeys-fault-matrix",
    "testkit",
    "s3",
    "settingsonly",
    "identityaudit",
];

type TargetId = (String, String, String);

fn unique_targets(
    units: impl IntoIterator<Item = IntegrationUnitSpec>,
) -> Result<BTreeSet<TargetId>> {
    let mut expected = BTreeSet::new();
    for unit in units {
        let id = (
            unit.package.to_owned(),
            unit.target.to_owned(),
            unit.kind.as_str().to_owned(),
        );
        if !expected.insert(id.clone()) {
            bail!("integration target assigned more than once: {id:?}");
        }
    }
    Ok(expected)
}

fn expected_targets() -> Result<BTreeSet<TargetId>> {
    let release = IntegrationSelection::for_profile(ExecutionProfile::ReleaseCheck)?;
    unique_targets(release.unit_ids().iter().map(|id| *id.spec()))
}

fn validate_local_feature_catalog(specs: &[ShardSpec]) -> Result<()> {
    let known_by_package = LocalFeatureScope::ALL
        .into_iter()
        .map(|scope| (scope.package(), scope))
        .collect::<BTreeMap<_, _>>();
    if known_by_package.len() != LocalFeatureScope::ALL.len()
        || known_by_package.keys().copied().collect::<BTreeSet<_>>()
            != INTEGRATION_PACKAGES
                .iter()
                .copied()
                .collect::<BTreeSet<_>>()
    {
        bail!("local feature scopes and integration package catalog must be bijective");
    }
    let mut covered = BTreeSet::new();
    for spec in specs {
        if spec.local_feature_scopes.is_empty() {
            bail!(
                "integration shard `{}` has no local feature scope",
                spec.shard
            );
        }
        let declared = spec
            .local_feature_scopes
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        if declared.len() != spec.local_feature_scopes.len() {
            bail!(
                "integration shard `{}` repeats a local feature scope",
                spec.shard
            );
        }
        for unit in spec.units {
            let scope = known_by_package.get(unit.package).ok_or_else(|| {
                anyhow::anyhow!(
                    "integration shard `{}` package `{}` has no local feature scope",
                    spec.shard,
                    unit.package
                )
            })?;
            if !declared.contains(scope) {
                bail!(
                    "integration shard `{}` omits local feature scope for package `{}`",
                    spec.shard,
                    unit.package
                );
            }
        }
        covered.extend(declared);
    }
    let missing = LocalFeatureScope::ALL
        .into_iter()
        .filter(|scope| !covered.contains(scope))
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        bail!("local feature scope catalog is incomplete: {missing:?}");
    }
    Ok(())
}

fn workspace_targets(facts: &WorkspaceFacts) -> Result<BTreeSet<TargetId>> {
    let mut actual = BTreeSet::new();
    let mut missing_packages = Vec::new();
    for &name in INTEGRATION_PACKAGES {
        let Ok(package) = facts.package_key(name) else {
            missing_packages.push(name);
            continue;
        };
        for target in facts
            .targets_for(&package)
            .with_context(|| format!("read workspace targets for integration package `{name}`"))?
        {
            let kind = match target.kind() {
                WorkspaceTargetKind::Library => "lib",
                WorkspaceTargetKind::Test => "test",
                WorkspaceTargetKind::ProcMacro
                | WorkspaceTargetKind::Binary
                | WorkspaceTargetKind::Example
                | WorkspaceTargetKind::Benchmark
                | WorkspaceTargetKind::BuildScript
                | WorkspaceTargetKind::Other => continue,
            };
            actual.insert((name.to_owned(), target.name().to_owned(), kind.to_owned()));
        }
    }
    if !missing_packages.is_empty() {
        bail!("workspace facts missing legacy integration packages: {missing_packages:?}");
    }
    Ok(actual)
}

fn validate_facts(facts: &WorkspaceFacts) -> Result<()> {
    let expected = expected_targets()?;
    let actual = workspace_targets(facts)?;
    let unassigned: Vec<_> = actual.difference(&expected).cloned().collect();
    let stale: Vec<_> = expected.difference(&actual).cloned().collect();
    if !unassigned.is_empty() || !stale.is_empty() {
        bail!("integration shard coverage mismatch; unassigned={unassigned:?}; stale={stale:?}");
    }
    Ok(())
}

/// Exact Cargo eligibility closure for catalog Test targets (`INTEGRATION-SHARD-ELIGIBILITY-01`).
///
/// Looks up each catalog Test unit uniquely as `(package, TargetKind::Test, target)` in the
/// caller-provided [`WorkspaceFacts`], then checks path bijection, `test=true`, and
/// `required_features` against [`LocalFeatureScope`].
///
/// Scheduling / remote ownership ([`LocalEligibility`]) and compile eligibility are independent:
/// `RemoteOnly` must declare the typed singleton feature; `Affected` may be default-buildable
/// (empty RF) or share the same typed singleton compile scope. Wrong or extra features fail
/// closed.
///
/// After facts checks, each catalog Test `repo_relative_src_path` is parsed with `syn` and must
/// not declare crate-level `#![cfg(... feature ...)]` / `#![cfg_attr(... feature ...)]`. Target
/// eligibility is owned only by Cargo `required-features`; source cfg must not restore a second
/// gate. Item-level `#[cfg(feature = ...)]` on individual cases is out of scope for this rule.
fn validate_test_target_eligibility(
    root: &Path,
    facts: &WorkspaceFacts,
    units: &[IntegrationUnitSpec],
) -> Result<()> {
    let mut claimed_paths = BTreeMap::<PathBuf, (&str, &str)>::new();
    let mut crate_feature_cfg_violations = Vec::new();
    for unit in units.iter().filter(|unit| unit.kind == TargetKind::Test) {
        let scope = LocalFeatureScope::for_package(unit.package).ok_or_else(|| {
            anyhow::anyhow!(
                "integration package `{}` has no local feature scope",
                unit.package
            )
        })?;
        let target = lookup_unique_test_target(facts, unit.package, unit.target)?;
        if !target.test_by_default() {
            bail!(
                "catalog test target `{}`/`{}` has test_by_default=false",
                unit.package,
                unit.target
            );
        }
        let actual_path = target.repo_relative_src_path().to_path_buf();
        if let Some((owner_package, owner_target)) =
            claimed_paths.insert(actual_path.clone(), (unit.package, unit.target))
        {
            bail!(
                "catalog test targets reuse source path `{}`: `{owner_package}`/`{owner_target}` and `{}`/`{}`",
                actual_path.display(),
                unit.package,
                unit.target
            );
        }
        let expected_path = expected_test_src_path(unit.package, unit.target)?;
        if actual_path != expected_path {
            bail!(
                "catalog test target `{}`/`{}` src_path mismatch: expected `{}`, got `{}`",
                unit.package,
                unit.target,
                expected_path.display(),
                actual_path.display()
            );
        }
        validate_required_features(unit, scope, target.required_features())?;
        if let Err(error) =
            reject_crate_level_feature_cfg(root, unit.package, unit.target, &actual_path)
        {
            crate_feature_cfg_violations.push(error.to_string());
        }
    }
    if !crate_feature_cfg_violations.is_empty() {
        bail!(
            "catalog Test targets retain crate-level feature cfg; Cargo required-features must own eligibility: {}",
            crate_feature_cfg_violations.join("; ")
        );
    }
    Ok(())
}

fn reject_crate_level_feature_cfg(
    root: &Path,
    package: &str,
    target: &str,
    repo_relative_src_path: &Path,
) -> Result<()> {
    let abs = root.join(repo_relative_src_path);
    let source = std::fs::read_to_string(&abs).with_context(|| {
        format!(
            "read catalog test target `{package}`/`{target}` source `{}`",
            repo_relative_src_path.display()
        )
    })?;
    let file = syn::parse_file(&source).with_context(|| {
        format!(
            "parse catalog test target `{package}`/`{target}` source `{}`",
            repo_relative_src_path.display()
        )
    })?;
    for attr in &file.attrs {
        if let Some(kind) = crate_attr_feature_gate_kind(attr) {
            bail!(
                "catalog test target `{package}`/`{target}` path `{}` declares crate-level `{kind}` which must not substitute Cargo required-features",
                repo_relative_src_path.display()
            );
        }
    }
    Ok(())
}

fn crate_attr_feature_gate_kind(attr: &syn::Attribute) -> Option<&'static str> {
    let ident = attr.path().get_ident()?;
    let kind = if *ident == "cfg" {
        "#![cfg(...feature...)]"
    } else if *ident == "cfg_attr" {
        "#![cfg_attr(...feature...)]"
    } else {
        return None;
    };
    let syn::Meta::List(list) = &attr.meta else {
        return None;
    };
    tokens_contain_feature_predicate(list.tokens.clone()).then_some(kind)
}

fn tokens_contain_feature_predicate(tokens: proc_macro2::TokenStream) -> bool {
    let trees: Vec<_> = tokens.into_iter().collect();
    let mut index = 0;
    while index < trees.len() {
        match &trees[index] {
            proc_macro2::TokenTree::Ident(ident) if *ident == "feature" => {
                if matches!(
                    trees.get(index + 1),
                    Some(proc_macro2::TokenTree::Punct(punct)) if punct.as_char() == '='
                ) {
                    return true;
                }
            }
            proc_macro2::TokenTree::Group(group)
                if tokens_contain_feature_predicate(group.stream()) =>
            {
                return true;
            }
            _ => {}
        }
        index += 1;
    }
    false
}

fn validate_required_features(
    unit: &IntegrationUnitSpec,
    scope: LocalFeatureScope,
    actual: &[String],
) -> Result<()> {
    let typed = scope.feature();
    let typed_singleton = [typed.to_owned()];
    match unit.local_eligibility {
        LocalEligibility::RemoteOnly => {
            if actual != typed_singleton.as_slice() {
                bail!(
                    "RemoteOnly catalog test target `{}`/`{}` required_features must equal [{typed:?}], got {actual:?}",
                    unit.package,
                    unit.target,
                );
            }
        }
        LocalEligibility::Affected => {
            // Empty = default-buildable; singleton typed feature = shared compile scope.
            // Scheduling/remote ownership stays independent of this Cargo gate.
            if actual.is_empty() || actual == typed_singleton.as_slice() {
                return Ok(());
            }
            bail!(
                "Affected catalog test target `{}`/`{}` required_features must be empty or exact [{typed:?}], got {actual:?}",
                unit.package,
                unit.target,
            );
        }
    }
    Ok(())
}

fn expected_test_src_path(package: &str, target: &str) -> Result<PathBuf> {
    let scope = LocalFeatureScope::for_package(package).ok_or_else(|| {
        anyhow::anyhow!("integration package `{package}` has no local feature scope")
    })?;
    Ok(PathBuf::from(format!("{}/tests/{target}.rs", scope.root())))
}

fn lookup_unique_test_target<'a>(
    facts: &'a WorkspaceFacts,
    package: &str,
    target: &str,
) -> Result<&'a TargetFacts> {
    let key = facts
        .package_key(package)
        .with_context(|| format!("workspace facts missing integration package `{package}`"))?;
    let matches = facts
        .targets_for(&key)
        .with_context(|| format!("read workspace targets for integration package `{package}`"))?
        .iter()
        .filter(|candidate| {
            candidate.kind() == WorkspaceTargetKind::Test && candidate.name() == target
        })
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [] => bail!("catalog test target missing from workspace facts: {package}/{target}"),
        [unique] => Ok(*unique),
        _ => bail!("catalog test target mapped more than once: {package}/{target}"),
    }
}

/// Command-bound proof that the integration catalog, workspace facts, and nextest configuration
/// were validated together. Shard execution accepts this type instead of a raw root path.
pub(crate) struct ValidatedIntegrationWorkspace<'facts> {
    root: &'facts Path,
    _facts: &'facts WorkspaceFacts,
}

impl<'facts> ValidatedIntegrationWorkspace<'facts> {
    fn new(command_facts: &'facts CommandWorkspaceFacts) -> Result<Self> {
        let root = command_facts.root();
        validate_integration_unit_catalog(INTEGRATION_UNIT_SPECS, SHARD_SPECS)?;
        validate_local_feature_catalog(SHARD_SPECS)?;
        let facts = command_facts
            .get()
            .context("load workspace facts for integration shard coverage")?;
        validate_facts(facts)?;
        validate_test_target_eligibility(root, facts, INTEGRATION_UNIT_SPECS)?;
        let nextest_config = std::fs::read_to_string(root.join(".config/nextest.toml"))
            .context("read committed nextest configuration")?;
        crate::nextest::validate_config(&nextest_config)?;
        Ok(Self {
            root,
            _facts: facts,
        })
    }

    pub(crate) fn root(&self) -> &Path {
        self.root
    }
}

/// Validate one integration command exactly once, then run its selected shards inside the
/// lifetime of the resulting proof. Callers cannot construct a proof without the full validation.
pub(crate) fn with_validated_workspace<T>(
    command_facts: &CommandWorkspaceFacts,
    run: impl FnOnce(&ValidatedIntegrationWorkspace<'_>) -> Result<T>,
) -> Result<T> {
    let workspace = ValidatedIntegrationWorkspace::new(command_facts)?;
    run(&workspace)
}

#[cfg(test)]
pub(crate) fn validate_current_workspace() -> Result<()> {
    let root = workspace_root()?;
    let command_facts = CommandWorkspaceFacts::new(&root);
    with_validated_workspace(&command_facts, |_| Ok(()))
}

pub(crate) fn external_resource_present(resource: Resource) -> bool {
    external_resource_present_from_lookup(resource, |name| std::env::var_os(name))
}

fn external_resource_present_from_lookup(
    resource: Resource,
    lookup: impl Fn(&str) -> Option<std::ffi::OsString>,
) -> bool {
    let nonempty = |name: &str| lookup(name).is_some_and(|value| !value.is_empty());

    match resource {
        Resource::Postgres => {
            nonempty("RSS_TEST_ALLOW_EXTERNAL_POSTGRES")
                && ["PGHOST", "PGPORT", "PGDATABASE"]
                    .iter()
                    .all(|name| nonempty(name))
        }
        Resource::Redis => nonempty("REDIS_TEST_URL"),
        Resource::Amqp => nonempty("RSS_AMQP_TEST_URL"),
        // The MQTT T2 always self-provisions the exact mTLS/plugin image; a URL-only external
        // broker cannot prove the fixture's PKI, ACL or assertion contract.
        Resource::Mqtt => false,
        Resource::ObjectStorage => false,
        Resource::Vault => false,
    }
}

pub(crate) fn missing_external_resources(
    selection: &IntegrationSelection,
    shard: IntegrationShard,
) -> Vec<Resource> {
    selection
        .resources_for_shard(shard)
        .into_iter()
        .filter(|resource| !external_resource_present(*resource))
        .collect()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use serde_json::{Value, json};

    #[test]
    fn neutral_saga_fixture_is_not_a_production_runtime_carrier() {
        let spec = IntegrationUnitId::SagaRuntimeProviderIntegration.spec();
        assert_eq!(spec.shard, IntegrationShard::CdcProjectionSaga);
        assert!(!spec.id.as_str().contains("production"));
        assert!(!spec.target.contains("production"));
        assert!(
            spec.capabilities
                .contains(&Capability::PreparedExternalPostgres)
        );
        assert!(!unit_requires_docker(spec));
        assert!(unit_requires_docker(IntegrationUnitId::PostgresLib.spec()));
    }

    #[test]
    fn device_certificate_convergence_is_one_exact_critical_pg_mqtt_docker_journey() {
        let spec = IntegrationUnitId::DeviceCertificateConvergenceJourney.spec();
        assert_eq!(spec.shard, IntegrationShard::EventTransport);
        assert_eq!(spec.primary_owner, ExecutionProfile::IntegrationCritical);
        assert_eq!(spec.package, "journeys");
        assert_eq!(spec.target, "device_certificate_convergence_journey");
        assert_eq!(spec.kind, TargetKind::Test);
        assert_eq!(spec.scheduling, Scheduling::Serial);
        assert_eq!(spec.local_eligibility, LocalEligibility::RemoteOnly);
        assert_eq!(spec.resources, &[Resource::Postgres, Resource::Mqtt]);
        assert_eq!(
            spec.impact_markers,
            &[
                ImpactMarker::IotDevicePackage,
                ImpactMarker::IdentityCompositionPackage,
                ImpactMarker::DeviceIdentityPackage,
                ImpactMarker::EventexecPackage,
                ImpactMarker::IdentityPackage,
                ImpactMarker::MqttPackage,
                ImpactMarker::PostgresPackage,
            ]
        );
        assert_eq!(
            IntegrationUnitId::DeviceCertificateConvergenceJourney
                .capability_labels()
                .collect::<Vec<_>>(),
            ["docker"]
        );
        assert_eq!(
            critical_units_for_targets([("journeys", "device_certificate_convergence_journey")]),
            BTreeSet::from([IntegrationUnitId::DeviceCertificateConvergenceJourney])
        );
        assert_eq!(
            changed_integration_source("journeys/tests/device_certificate_convergence_journey.rs"),
            Some(ChangedIntegrationSource::Exact(BTreeSet::from([
                IntegrationUnitId::DeviceCertificateConvergenceJourney,
            ])))
        );
        assert_eq!(
            IntegrationUnitId::ALL
                .into_iter()
                .filter(|id| {
                    let candidate = id.spec();
                    candidate.package == "journeys"
                        && candidate.target == "device_certificate_convergence_journey"
                })
                .count(),
            1,
            "device certificate convergence must have one canonical registry owner"
        );
    }

    #[test]
    fn mqtt_backpressure_fault_declares_release_check_pg_mqtt_docker_topology() {
        let id = IntegrationUnitId::MqttBackpressureFaultJourney;
        let spec = id.spec();
        assert_eq!(id.as_str(), "mqtt-backpressure-fault-journey");
        assert_eq!(spec.shard, IntegrationShard::EventTransport);
        assert_eq!(spec.primary_owner, ExecutionProfile::ReleaseCheck);
        assert_eq!(spec.package, "journeys");
        assert_eq!(spec.target, "mqtt_backpressure_fault_journey");
        assert_eq!(spec.kind, TargetKind::Test);
        assert_eq!(spec.scheduling, Scheduling::Serial);
        assert_eq!(spec.local_eligibility, LocalEligibility::RemoteOnly);
        assert_eq!(spec.resources, &[Resource::Postgres, Resource::Mqtt]);
        assert!(spec.impact_markers.is_empty());
        assert_eq!(id.capability_labels().collect::<Vec<_>>(), ["docker"]);
    }

    #[test]
    fn mqtt_backpressure_fault_has_one_release_check_registry_owner() -> Result<()> {
        let id = IntegrationUnitId::MqttBackpressureFaultJourney;
        assert_eq!(
            "mqtt-backpressure-fault-journey".parse::<IntegrationUnitId>()?,
            id
        );
        assert!(
            critical_units_for_targets([("journeys", "mqtt_backpressure_fault_journey")])
                .is_empty()
        );
        assert_eq!(
            changed_integration_source("journeys/tests/mqtt_backpressure_fault_journey.rs"),
            Some(ChangedIntegrationSource::ReleaseCheck)
        );
        assert_eq!(
            changed_integration_source("journeys/tests/support/mqtt_backpressure_fault.rs"),
            Some(ChangedIntegrationSource::ReleaseCheck)
        );

        let critical = IntegrationSelection::for_profile(ExecutionProfile::IntegrationCritical)?;
        assert!(!critical.unit_ids().contains(&id));
        assert!(
            IntegrationSelection::release_check()
                .unit_ids()
                .contains(&id)
        );
        assert_eq!(
            IntegrationUnitId::ALL
                .into_iter()
                .filter(|candidate| {
                    let candidate = candidate.spec();
                    candidate.package == "journeys"
                        && candidate.target == "mqtt_backpressure_fault_journey"
                })
                .count(),
            1,
            "mqtt backpressure fault must have one canonical registry owner"
        );
        Ok(())
    }

    #[test]
    fn saga_fault_recovery_is_one_release_check_pg_redis_owner() {
        let spec = IntegrationUnitId::SagaFaultRecovery.spec();
        assert_eq!(spec.shard, IntegrationShard::ConsistencyFault);
        assert_eq!(spec.primary_owner, ExecutionProfile::ReleaseCheck);
        assert_eq!(spec.package, "journeys-fault-matrix");
        assert_eq!(spec.target, "saga_fault_recovery");
        assert_eq!(spec.scheduling, Scheduling::Serial);
        assert_eq!(spec.local_eligibility, LocalEligibility::RemoteOnly);
        assert_eq!(spec.resources, &[Resource::Postgres, Resource::Redis]);
    }

    #[test]
    fn l2_dr_recovery_is_one_release_check_pg_amqp_owner() -> Result<()> {
        let id = IntegrationUnitId::L2DrRecoveryJourney;
        let spec = id.spec();
        assert_eq!(id.as_str(), "l2-dr-recovery-journey");
        assert_eq!("l2-dr-recovery-journey".parse::<IntegrationUnitId>()?, id);
        assert_eq!(spec.shard, IntegrationShard::ConsistencyFault);
        assert_eq!(spec.primary_owner, ExecutionProfile::ReleaseCheck);
        assert_eq!(spec.package, "journeys-fault-matrix");
        assert_eq!(spec.target, "l2_dr_recovery_journey");
        assert_eq!(spec.kind, TargetKind::Test);
        assert_eq!(spec.scheduling, Scheduling::Serial);
        assert_eq!(spec.local_eligibility, LocalEligibility::RemoteOnly);
        assert_eq!(spec.resources, &[Resource::Postgres, Resource::Amqp]);
        assert!(spec.impact_markers.is_empty());
        assert!(spec.capabilities.is_empty());
        assert!(
            critical_units_for_targets([("journeys-fault-matrix", "l2_dr_recovery_journey")])
                .is_empty()
        );

        let critical = IntegrationSelection::for_profile(ExecutionProfile::IntegrationCritical)?;
        assert!(!critical.unit_ids().contains(&id));
        assert!(
            IntegrationSelection::release_check()
                .unit_ids()
                .contains(&id)
        );
        Ok(())
    }

    #[test]
    fn integration_unit_ids_have_stable_wire_round_trips() -> Result<()> {
        let mut wire_ids = BTreeSet::new();
        for id in IntegrationUnitId::ALL {
            assert!(wire_ids.insert(id.as_str()));
            assert_eq!(id.as_str().parse::<IntegrationUnitId>()?, id);
            let encoded = serde_json::to_string(&id)?;
            assert_eq!(serde_json::from_str::<IntegrationUnitId>(&encoded)?, id);
        }
        for invalid in ["PostgresLib", "postgres_lib", "postgres", ""] {
            assert!(invalid.parse::<IntegrationUnitId>().is_err(), "{invalid}");
        }
        Ok(())
    }

    #[test]
    fn integration_selection_is_closed_canonical_and_round_trips() -> Result<()> {
        let critical = IntegrationSelection::for_profile(ExecutionProfile::IntegrationCritical)?;
        assert_eq!(critical.profile(), ExecutionProfile::IntegrationCritical);
        assert!(!critical.unit_ids().is_empty());
        assert!(critical.unit_ids().len() < IntegrationUnitId::ALL.len());
        assert!(
            critical
                .unit_ids()
                .iter()
                .all(|id| { id.spec().primary_owner == ExecutionProfile::IntegrationCritical })
        );

        let release = IntegrationSelection::for_profile(ExecutionProfile::ReleaseCheck)?;
        assert_eq!(release.profile(), ExecutionProfile::ReleaseCheck);
        assert_eq!(
            release.unit_ids(),
            &IntegrationUnitId::ALL.into_iter().collect::<BTreeSet<_>>()
        );
        assert_eq!(release.to_string(), "release-check");
        assert_eq!(
            release.to_string().parse::<IntegrationSelection>()?,
            release
        );

        let token = critical.to_string();
        assert!(token.starts_with("integration-critical:"));
        let wire_ids = token
            .strip_prefix("integration-critical:")
            .context("critical token prefix")?
            .split(',')
            .collect::<Vec<_>>();
        assert!(wire_ids.windows(2).all(|pair| pair[0] < pair[1]));
        assert_eq!(token.parse::<IntegrationSelection>()?, critical);
        assert_eq!(
            serde_json::from_str::<IntegrationSelection>(&serde_json::to_string(&critical)?)?,
            critical
        );

        let postgres = critical.unit_ids_for_shard(IntegrationShard::PostgresDomain);
        assert!(!postgres.is_empty());
        assert!(postgres.is_subset(critical.unit_ids()));
        Ok(())
    }

    #[test]
    fn critical_impact_projection_is_non_vacuous_and_exact() -> Result<()> {
        let critical = IntegrationSelection::for_profile(ExecutionProfile::IntegrationCritical)?;
        assert!(
            critical
                .unit_ids()
                .iter()
                .all(|id| !id.impact_markers().is_empty())
        );

        let mqtt = critical_units_for_markers(&BTreeSet::from([ImpactMarker::MqttPackage]));
        assert_eq!(
            mqtt,
            BTreeSet::from([
                IntegrationUnitId::MqttIntegration,
                IntegrationUnitId::DeviceCertificateConvergenceJourney,
                IntegrationUnitId::EventTransportDurableE2e,
            ])
        );
        assert!(!mqtt.contains(&IntegrationUnitId::AmqpIntegration));

        assert_eq!(
            critical_units_for_targets([("journeys", "identity_login_audit_durable_journey")]),
            BTreeSet::from([IntegrationUnitId::IdentityLoginAuditDurableJourney])
        );
        assert_eq!(
            critical_units_for_targets([("amqp", "integration")]),
            BTreeSet::from([IntegrationUnitId::AmqpIntegration]),
            "same-named targets in different packages must not alias"
        );
        assert_eq!(
            critical_units_for_targets([("mqtt", "integration")]),
            BTreeSet::from([IntegrationUnitId::MqttIntegration]),
            "same-named targets in different packages must not alias"
        );
        assert_eq!(
            critical_units_for_markers(&BTreeSet::from([ImpactMarker::DeviceIdentityPackage])),
            BTreeSet::from([IntegrationUnitId::DeviceCertificateConvergenceJourney]),
            "deviceidentity source impact must select its one canonical T2 carrier"
        );
        for marker in [
            ImpactMarker::IotDevicePackage,
            ImpactMarker::IdentityCompositionPackage,
        ] {
            assert_eq!(
                critical_units_for_markers(&BTreeSet::from([marker])),
                BTreeSet::from([IntegrationUnitId::DeviceCertificateConvergenceJourney]),
                "simulator and composition changes must select the canonical convergence journey"
            );
        }
        Ok(())
    }

    #[test]
    fn source_and_security_provider_relations_are_closed_and_non_vacuous() -> Result<()> {
        use IntegrationUnitId as Id;
        assert_eq!(
            changed_integration_source("journeys/tests/common/mod.rs"),
            Some(ChangedIntegrationSource::ReleaseCheck),
            "a common source with any release-only consumer must fail closed to ReleaseCheck"
        );
        assert_eq!(
            changed_integration_source("journeys/tests/support/localtx_validation.rs"),
            Some(ChangedIntegrationSource::Exact(BTreeSet::from([
                Id::AuditListTenantEntriesLocalTxJourney,
                Id::SettingsSecretPublishLocalTxJourney,
            ])))
        );
        assert_eq!(
            changed_integration_source("journeys/tests/support/mqtt_backpressure_fault.rs"),
            Some(ChangedIntegrationSource::ReleaseCheck)
        );
        assert_eq!(
            changed_integration_source("journeys/tests/support/unregistered.rs"),
            Some(ChangedIntegrationSource::ReleaseCheck)
        );
        assert_eq!(
            critical_units_for_provider(SecurityProvider::Oidc),
            Some(BTreeSet::from([
                Id::IdentityPasswordSecurityEventJourney,
                Id::IdentityRefreshProducerTransactionJourney,
                Id::IdentityLoginWireE2e,
                Id::ServiceTokenReplayE2e,
            ]))
        );
        assert_eq!(critical_units_for_provider(SecurityProvider::Vault), None);
        validate_source_and_provider_relations(INTEGRATION_UNIT_SPECS)
    }

    #[test]
    fn source_and_security_provider_relations_reject_catalog_drift() {
        let mut drifted = INTEGRATION_UNIT_SPECS.to_vec();
        drifted[IntegrationUnitId::IdentityLoginWireE2e as usize].impact_markers = &[];
        drifted[IntegrationUnitId::IdentityPasswordSecurityEventJourney as usize].impact_markers =
            &[];
        drifted[IntegrationUnitId::IdentityRefreshProducerTransactionJourney as usize]
            .impact_markers = &[];
        drifted[IntegrationUnitId::ServiceTokenReplayE2e as usize].impact_markers = &[];
        assert!(
            validate_source_and_provider_relations(&drifted).is_err(),
            "removing every OIDC carrier edge must invalidate the closed provider relation"
        );

        let mut wrong_owner = INTEGRATION_UNIT_SPECS.to_vec();
        wrong_owner[IntegrationUnitId::AmqpConsumerAtLeastOnceJourney as usize].primary_owner =
            ExecutionProfile::ReleaseCheck;
        assert!(
            validate_source_and_provider_relations(&wrong_owner).is_err(),
            "shared source relations cannot point at a non-critical carrier"
        );
    }

    #[test]
    fn shared_journey_relations_match_independently_discovered_module_edges() -> Result<()> {
        let root = workspace_root()?;
        let tests = root.join("journeys/tests");
        let mut discovered = SharedJourneySource::ALL
            .into_iter()
            .map(|source| (source.path().to_owned(), (BTreeSet::new(), false)))
            .collect::<BTreeMap<_, _>>();

        fn discover_sources(
            path: &std::path::Path,
            root: &std::path::Path,
            tests: &std::path::Path,
            carrier: Option<IntegrationUnitId>,
            release_consumer: bool,
            discovered: &mut BTreeMap<String, (BTreeSet<IntegrationUnitId>, bool)>,
            visited: &mut BTreeSet<std::path::PathBuf>,
        ) -> Result<()> {
            if !visited.insert(path.to_owned()) {
                return Ok(());
            }
            let source = std::fs::read_to_string(path)?;
            let mut children = Vec::new();
            if source.lines().any(|line| line.trim() == "mod common;") {
                children.push(tests.join("common/mod.rs"));
            }
            for line in source.lines() {
                let line = line.trim();
                let Some(relative) = line
                    .strip_prefix("#[path = \"")
                    .and_then(|line| line.strip_suffix("\"]"))
                else {
                    continue;
                };
                children.push(
                    path.parent()
                        .context("journey module path has no parent")?
                        .join(relative),
                );
            }
            for child in children {
                let relative = child
                    .strip_prefix(&root)
                    .context("journey module escaped workspace")?
                    .to_string_lossy()
                    .into_owned();
                if let Some((carriers, has_release_consumer)) = discovered.get_mut(&relative) {
                    if let Some(carrier) = carrier {
                        carriers.insert(carrier);
                    }
                    *has_release_consumer |= release_consumer;
                }
                if child.starts_with(tests) {
                    discover_sources(
                        &child,
                        root,
                        tests,
                        carrier,
                        release_consumer,
                        discovered,
                        visited,
                    )?;
                }
            }
            Ok(())
        }

        for entry in std::fs::read_dir(&tests)? {
            let path = entry?.path();
            if path.extension().and_then(|value| value.to_str()) != Some("rs") {
                continue;
            }
            let target = path
                .file_stem()
                .and_then(|value| value.to_str())
                .context("journey target path is not UTF-8")?;
            let consumer = IntegrationUnitId::ALL.into_iter().find(|id| {
                let spec = id.spec();
                spec.package == "journeys" && spec.target == target
            });
            let Some(consumer) = consumer else {
                continue;
            };
            let critical = (consumer.spec().primary_owner == ExecutionProfile::IntegrationCritical)
                .then_some(consumer);
            let release_consumer = consumer.spec().primary_owner == ExecutionProfile::ReleaseCheck;
            discover_sources(
                &path,
                &root,
                &tests,
                critical,
                release_consumer,
                &mut discovered,
                &mut BTreeSet::new(),
            )?;
        }

        let declared = SharedJourneySource::ALL
            .into_iter()
            .map(|source| {
                (
                    source.path().to_owned(),
                    (
                        source
                            .relation()
                            .critical_carriers
                            .iter()
                            .copied()
                            .collect::<BTreeSet<_>>(),
                        source.relation().has_release_consumer,
                    ),
                )
            })
            .collect::<BTreeMap<_, _>>();
        assert_eq!(
            discovered["journeys/tests/support/device_mtls_pg_harness.rs"],
            (
                BTreeSet::from([IntegrationUnitId::DeviceCertificateConvergenceJourney]),
                true,
            ),
            "nested support edges must discover both critical and release consumers"
        );
        assert_eq!(discovered, declared);

        let mut missing_nested_edge = declared.clone();
        missing_nested_edge
            .get_mut("journeys/tests/support/device_mtls_pg_harness.rs")
            .expect("registered nested harness")
            .0
            .clear();
        assert_ne!(
            discovered, missing_nested_edge,
            "removing the nested critical edge must be a synthetic red"
        );
        let mut missing_release_edge = declared.clone();
        missing_release_edge
            .get_mut("journeys/tests/support/device_mtls_pg_harness.rs")
            .expect("registered nested harness")
            .1 = false;
        assert_ne!(
            discovered, missing_release_edge,
            "removing the nested release-only edge must be a synthetic red"
        );

        let support_files = std::fs::read_dir(tests.join("support"))?
            .filter_map(|entry| match entry {
                Ok(entry)
                    if entry.path().extension().and_then(|value| value.to_str()) == Some("rs") =>
                {
                    Some(Ok(entry.file_name()))
                }
                Ok(_) => None,
                Err(error) => Some(Err(error)),
            })
            .map(|name| {
                let name = name?
                    .into_string()
                    .map_err(|_| anyhow::anyhow!("journey support filename is not UTF-8"))?;
                Ok(format!("journeys/tests/support/{name}"))
            })
            .collect::<Result<BTreeSet<_>>>()?;
        let declared_support = SharedJourneySource::ALL
            .into_iter()
            .map(SharedJourneySource::path)
            .filter(|path| path.starts_with("journeys/tests/support/"))
            .map(str::to_owned)
            .collect::<BTreeSet<_>>();
        assert_eq!(support_files, declared_support);
        Ok(())
    }

    #[test]
    fn adapter_resources_project_exact_critical_units_and_exclude_t3() {
        use IntegrationUnitId as Id;
        let cases = [
            (
                Resource::Postgres,
                BTreeSet::from([
                    Id::PostgresLib,
                    Id::PostgresMigrationLib,
                    Id::AuditListTenantEntriesLocalTxJourney,
                    Id::IdentityPasswordSecurityEventJourney,
                    Id::IdentityRefreshProducerTransactionJourney,
                    Id::SettingsSecretPublishLocalTxJourney,
                    Id::SettingsSecretE2e,
                    Id::DeviceCertificateConvergenceJourney,
                    Id::IdentityLoginAuditDurableJourney,
                    Id::EventTransportDurableE2e,
                    Id::ConfigsReadyE2e,
                    Id::IdentityLoginWireE2e,
                    Id::ServiceTokenReplayE2e,
                    Id::WireContractE2e,
                    Id::SettingsConfigPublishDurableE2e,
                ]),
            ),
            (
                Resource::Redis,
                BTreeSet::from([Id::EventTransportDurableE2e, Id::RedisIntegrationClaimer]),
            ),
            (
                Resource::Amqp,
                BTreeSet::from([
                    Id::AmqpLib,
                    Id::AmqpIntegration,
                    Id::AmqpConsumerAtLeastOnceJourney,
                    Id::EventTransportDurableE2e,
                ]),
            ),
            (
                Resource::Mqtt,
                BTreeSet::from([Id::MqttIntegration, Id::DeviceCertificateConvergenceJourney]),
            ),
            (
                Resource::ObjectStorage,
                BTreeSet::from([Id::IntegrationObjectStore]),
            ),
        ];
        for (resource, expected) in cases {
            let actual = critical_units_for_resource(resource);
            assert_eq!(actual, expected, "{}", resource.label());
            assert!(actual.iter().all(|id| {
                id.spec().primary_owner == ExecutionProfile::IntegrationCritical
                    && id.spec().shard != IntegrationShard::ProductionRuntime
            }));
        }
    }

    #[test]
    fn integration_selection_rejects_noncanonical_or_open_tokens() {
        for invalid in [
            "integration-critical:",
            "integration-critical:postgres-lib,postgres-lib",
            "integration-critical:postgres-migration-lib,postgres-lib",
            "integration-critical:postgres-feature-manifest",
            "integration-critical:postgres-lib,postgres-feature-manifest",
            "integration-critical:unknown",
            "integration-critical:postgres-lib,",
            "release-check:",
            "check",
            "test",
            "Integration-Critical:postgres-lib",
            "",
        ] {
            assert!(
                invalid.parse::<IntegrationSelection>().is_err(),
                "{invalid}"
            );
        }
    }

    #[test]
    fn exact_selection_derives_only_exact_batches() -> Result<()> {
        let exact = "integration-critical:audit-list-tenant-entries-local-tx-journey,identity-password-security-event-journey"
            .parse::<IntegrationSelection>()?;
        let plan = batches(&exact, IntegrationShard::PostgresDomain);
        assert_eq!(plan.len(), 1);
        assert_eq!(
            plan[0].unit_ids,
            BTreeSet::from([
                IntegrationUnitId::AuditListTenantEntriesLocalTxJourney,
                IntegrationUnitId::IdentityPasswordSecurityEventJourney,
            ])
        );
        assert_eq!(
            plan[0].targets,
            [
                "audit_list_tenant_entries_localtx_journey",
                "identity_password_security_event_journey",
            ]
        );
        assert_eq!(
            IntegrationSelection::for_exact_batch(&plan[0])?,
            exact,
            "typed batch replay must preserve exact unit identity"
        );
        assert_eq!(
            exact.resources_for_shard(IntegrationShard::PostgresDomain),
            [Resource::Postgres]
        );

        let amqp = IntegrationSelection::critical([IntegrationUnitId::AmqpIntegration])?;
        assert_eq!(
            amqp.resources_for_shard(IntegrationShard::EventTransport),
            [Resource::Amqp]
        );
        assert!(!amqp.requires_docker_for_shard(IntegrationShard::EventTransport));
        let mqtt = IntegrationSelection::critical([IntegrationUnitId::MqttIntegration])?;
        assert_eq!(
            mqtt.resources_for_shard(IntegrationShard::EventTransport),
            [Resource::Mqtt]
        );
        assert!(mqtt.requires_docker_for_shard(IntegrationShard::EventTransport));
        Ok(())
    }

    #[test]
    fn integration_unit_catalog_rejects_missing_duplicate_id_drift_and_owner_drift() -> Result<()> {
        validate_integration_unit_catalog(INTEGRATION_UNIT_SPECS, SHARD_SPECS)?;

        let missing = &INTEGRATION_UNIT_SPECS[..INTEGRATION_UNIT_SPECS.len() - 1];
        assert!(validate_integration_unit_catalog(missing, SHARD_SPECS).is_err());

        let mut duplicate = INTEGRATION_UNIT_SPECS.to_vec();
        duplicate[1] = duplicate[0];
        assert!(validate_integration_unit_catalog(&duplicate, SHARD_SPECS).is_err());

        let mut id_drift = INTEGRATION_UNIT_SPECS.to_vec();
        id_drift[0].id = IntegrationUnitId::ALL[1];
        assert!(validate_integration_unit_catalog(&id_drift, SHARD_SPECS).is_err());

        let mut owner_drift = INTEGRATION_UNIT_SPECS.to_vec();
        owner_drift[0].primary_owner = ExecutionProfile::ReleaseCheck;
        assert!(validate_integration_unit_catalog(&owner_drift, SHARD_SPECS).is_err());
        Ok(())
    }

    fn validate_identityaudit_runtime_resource_closure(resources: &[Resource]) -> Result<()> {
        let expected = [Resource::Postgres, Resource::Redis, Resource::Amqp];
        if resources.is_empty() {
            bail!("IdentityAudit runtime resource closure must be non-empty");
        }
        if resources != expected {
            bail!(
                "IdentityAudit runtime resource closure must be exactly {expected:?}, got {resources:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn identityaudit_runtime_resource_closure_is_exact_and_non_vacuous() -> Result<()> {
        validate_identityaudit_runtime_resource_closure(
            IntegrationUnitId::IdentityAuditRuntimeJourney
                .spec()
                .resources,
        )
    }

    #[test]
    fn identityaudit_runtime_resource_closure_rejects_missing_duplicate_and_extra() {
        assert!(
            validate_identityaudit_runtime_resource_closure(&[Resource::Postgres, Resource::Amqp])
                .is_err()
        );
        assert!(
            validate_identityaudit_runtime_resource_closure(&[
                Resource::Postgres,
                Resource::Redis,
                Resource::Amqp,
                Resource::Mqtt,
            ])
            .is_err()
        );

        let mut duplicate = INTEGRATION_UNIT_SPECS.to_vec();
        duplicate[IntegrationUnitId::IdentityAuditRuntimeJourney as usize].resources = &[
            Resource::Postgres,
            Resource::Redis,
            Resource::Redis,
            Resource::Amqp,
        ];
        assert!(validate_integration_unit_catalog(&duplicate, SHARD_SPECS).is_err());
    }

    #[test]
    fn release_check_covers_the_catalog_and_critical_is_a_true_subset() {
        let release = projected_integration_units(ExecutionProfile::ReleaseCheck)
            .map(|spec| spec.id)
            .collect::<BTreeSet<_>>();
        let expected = IntegrationUnitId::ALL.into_iter().collect::<BTreeSet<_>>();
        assert_eq!(release, expected);
        let critical = projected_integration_units(ExecutionProfile::IntegrationCritical)
            .map(|spec| spec.id)
            .collect::<BTreeSet<_>>();
        assert!(!critical.is_empty());
        assert!(critical.is_subset(&release));
        assert_ne!(critical, release);
        assert!(
            critical
                .iter()
                .all(|id| { id.spec().primary_owner == ExecutionProfile::IntegrationCritical })
        );
    }

    #[test]
    fn shard_names_are_closed_and_round_trip() -> Result<()> {
        let names: Vec<_> = IntegrationShard::ALL
            .iter()
            .map(|shard| shard.as_str())
            .collect();
        assert_eq!(
            names,
            [
                "postgres-domain",
                "event-transport",
                "runtime-http-auth",
                "consistency-fault",
                "cdc-projection-saga",
                "object-storage",
                "production-runtime",
            ]
        );
        for shard in IntegrationShard::ALL {
            assert_eq!(shard.as_str().parse::<IntegrationShard>()?, *shard);
            assert_eq!(shard.spec().shard, *shard);
        }
        assert!("POSTGRES-DOMAIN".parse::<IntegrationShard>().is_err());
        assert!("unknown".parse::<IntegrationShard>().is_err());
        validate_local_feature_catalog(SHARD_SPECS)?;
        Ok(())
    }

    #[test]
    fn local_feature_scope_catalog_is_non_vacuous_and_rejects_omissions() -> Result<()> {
        assert_eq!(LocalFeatureScope::ALL.len(), INTEGRATION_PACKAGES.len());
        assert_eq!(LocalFeatureScope::Mqtt.feature(), "broker-tests");
        assert_eq!(
            LocalFeatureScope::DeviceIdentity.package(),
            "deviceidentity"
        );
        assert_eq!(LocalFeatureScope::DeviceIdentity.feature(), "test-support");
        assert_eq!(
            LocalFeatureScope::DeviceIdentity.root(),
            "assemblies/deviceidentity"
        );
        assert!(LocalFeatureScope::ALL.into_iter().all(|scope| match scope {
            LocalFeatureScope::Mqtt => scope.feature() == "broker-tests",
            LocalFeatureScope::DeviceIdentity => scope.feature() == "test-support",
            LocalFeatureScope::IdentityAudit => scope.feature() == "artifact-acceptance",
            _ => scope.feature() == "integration",
        }));
        validate_local_feature_catalog(SHARD_SPECS)?;

        let mut missing = SHARD_SPECS.to_vec();
        missing[IntegrationShard::EventTransport as usize].local_feature_scopes = &[];
        assert!(validate_local_feature_catalog(&missing).is_err());

        const UNKNOWN_UNITS: &[IntegrationUnitSpec] = &[IntegrationUnitSpec::new(
            IntegrationUnitId::AmqpIntegration,
            IntegrationShard::EventTransport,
            ExecutionProfile::ReleaseCheck,
            "new-integration-package",
            "integration",
            TargetKind::Test,
            Scheduling::Serial,
            LocalEligibility::RemoteOnly,
        )];
        let mut unknown = SHARD_SPECS.to_vec();
        unknown[IntegrationShard::EventTransport as usize].units = UNKNOWN_UNITS;
        assert!(validate_local_feature_catalog(&unknown).is_err());
        Ok(())
    }

    #[test]
    fn postgres_migration_real_backend_carrier_is_unique_serial_and_feature_enabled() {
        let spec = IntegrationShard::PostgresDomain.spec();
        assert!(
            spec.local_feature_scopes
                .contains(&LocalFeatureScope::PostgresMigration)
        );
        let units = spec
            .units
            .iter()
            .filter(|unit| unit.package == "postgres-migration")
            .collect::<Vec<_>>();
        assert_eq!(
            units.len(),
            1,
            "operator integration carrier must be unique"
        );
        assert_eq!(units[0].target, "postgres_migration");
        assert_eq!(units[0].kind, TargetKind::Lib);
        assert_eq!(units[0].scheduling, Scheduling::Serial);
    }

    #[test]
    fn migration_0087_fencing_carrier_is_typed_serial_remote_postgres() {
        let unit = IntegrationUnitId::PostgresMigration0087DeviceCommandFencing.spec();
        assert_eq!(unit.shard, IntegrationShard::PostgresDomain);
        assert_eq!(unit.package, "postgres");
        assert_eq!(unit.target, "migration_0087_device_command_fencing");
        assert_eq!(unit.kind, TargetKind::Test);
        assert_eq!(unit.scheduling, Scheduling::Serial);
        assert_eq!(unit.local_eligibility, LocalEligibility::RemoteOnly);
        assert_eq!(unit.resources, &[Resource::Postgres]);
    }

    #[test]
    fn migration_0087_fencing_contract_carrier_is_typed_parallel_affected() {
        let unit = IntegrationUnitId::PostgresMigration0087DeviceCommandFencingContract.spec();
        assert_eq!(unit.shard, IntegrationShard::PostgresDomain);
        assert_eq!(unit.package, "postgres");
        assert_eq!(
            unit.target,
            "migration_0087_device_command_fencing_contract"
        );
        assert_eq!(unit.kind, TargetKind::Test);
        assert_eq!(unit.scheduling, Scheduling::Parallel);
        assert_eq!(unit.local_eligibility, LocalEligibility::Affected);
        assert!(unit.resources.is_empty());
    }

    #[test]
    fn migration_0089_saga_operator_control_carrier_is_typed_serial_remote_only() {
        let unit = IntegrationUnitId::PostgresMigration0089SagaOperatorControl.spec();
        assert_eq!(unit.shard, IntegrationShard::PostgresDomain);
        assert_eq!(unit.package, "postgres");
        assert_eq!(unit.target, "migration_0089_saga_operator_control");
        assert_eq!(unit.kind, TargetKind::Test);
        assert_eq!(unit.scheduling, Scheduling::Serial);
        assert_eq!(unit.local_eligibility, LocalEligibility::RemoteOnly);
        assert_eq!(unit.resources, &[Resource::Postgres]);
    }

    #[test]
    fn migration_0102_abac_carriers_preserve_static_and_live_execution_boundaries() {
        let static_profile = IntegrationUnitId::PostgresMigration0102AbacProfile.spec();
        assert_eq!(static_profile.shard, IntegrationShard::PostgresDomain);
        assert_eq!(static_profile.package, "postgres");
        assert_eq!(static_profile.target, "migration_0102_abac_profile");
        assert_eq!(static_profile.kind, TargetKind::Test);
        assert_eq!(static_profile.scheduling, Scheduling::Parallel);
        assert_eq!(static_profile.local_eligibility, LocalEligibility::Affected);
        assert!(static_profile.resources.is_empty());

        let live_upgrade = IntegrationUnitId::PostgresMigration0102AbacProfileUpgrade.spec();
        assert_eq!(live_upgrade.shard, IntegrationShard::PostgresDomain);
        assert_eq!(live_upgrade.package, "postgres");
        assert_eq!(live_upgrade.target, "migration_0102_abac_profile_upgrade");
        assert_eq!(live_upgrade.kind, TargetKind::Test);
        assert_eq!(live_upgrade.scheduling, Scheduling::Serial);
        assert_eq!(live_upgrade.local_eligibility, LocalEligibility::RemoteOnly);
        assert_eq!(live_upgrade.resources, &[Resource::Postgres]);
    }

    #[test]
    fn migration_0104_abac_value_carriers_preserve_static_and_live_execution_boundaries() {
        let static_contract =
            IntegrationUnitId::PostgresMigration0104AbacPolicyOperatorValues.spec();
        assert_eq!(static_contract.shard, IntegrationShard::PostgresDomain);
        assert_eq!(static_contract.package, "postgres");
        assert_eq!(
            static_contract.target,
            "migration_0104_abac_policy_operator_values"
        );
        assert_eq!(static_contract.kind, TargetKind::Test);
        assert_eq!(static_contract.scheduling, Scheduling::Parallel);
        assert_eq!(
            static_contract.local_eligibility,
            LocalEligibility::Affected
        );
        assert!(static_contract.resources.is_empty());

        let live_upgrade =
            IntegrationUnitId::PostgresMigration0104AbacPolicyOperatorValuesUpgrade.spec();
        assert_eq!(live_upgrade.shard, IntegrationShard::PostgresDomain);
        assert_eq!(live_upgrade.package, "postgres");
        assert_eq!(
            live_upgrade.target,
            "migration_0104_abac_policy_operator_values_upgrade"
        );
        assert_eq!(live_upgrade.kind, TargetKind::Test);
        assert_eq!(live_upgrade.scheduling, Scheduling::Serial);
        assert_eq!(live_upgrade.local_eligibility, LocalEligibility::RemoteOnly);
        assert_eq!(live_upgrade.resources, &[Resource::Postgres]);
    }

    #[test]
    #[allow(clippy::expect_used)] // reason: registry fixture must retain security-provider closeout unit.
    fn settingsonly_vault_backend_is_unique_serial_and_feature_enabled() {
        let spec = IntegrationShard::RuntimeHttpAuth.spec();
        let release = IntegrationSelection::release_check();
        assert!(
            release
                .resources_for_shard(IntegrationShard::RuntimeHttpAuth)
                .contains(&Resource::Vault)
        );
        assert!(
            spec.local_feature_scopes
                .contains(&LocalFeatureScope::SettingsOnly)
        );

        let units = spec
            .units
            .iter()
            .filter(|unit| {
                unit.package == "settingsonly"
                    && unit.target == "settingsonly"
                    && unit.kind == TargetKind::Lib
            })
            .collect::<Vec<_>>();
        assert_eq!(units.len(), 1, "SettingsOnly carrier must be unique");
        assert_eq!(units[0].target, "settingsonly");
        assert_eq!(units[0].kind, TargetKind::Lib);
        assert_eq!(units[0].scheduling, Scheduling::Serial);

        let closeout = spec
            .units
            .iter()
            .find(|unit| unit.id == IntegrationUnitId::SecurityProviderCloseoutJourney)
            .expect("security-provider closeout journey remains registry-owned");
        assert_eq!(closeout.scheduling, Scheduling::Parallel);
    }

    #[test]
    fn scheduling_plan_rejects_dangerous_target_parallelism() {
        let release = IntegrationSelection::for_profile(ExecutionProfile::ReleaseCheck)
            .expect("release selection");
        let expected_serial = BTreeSet::from([
            ("postgres", "postgres"),
            ("postgres", "migration_0067_historical_artifact"),
            ("postgres", "migration_0086_hard_cutover"),
            ("postgres", "migration_0087_device_command_fencing"),
            ("postgres", "migration_0089_saga_operator_control"),
            ("postgres", "migration_0097_projection_worker_upgrade"),
            ("postgres", "migration_0098_settings_active_serving_upgrade"),
            ("postgres", "migration_0102_abac_profile_upgrade"),
            (
                "postgres",
                "migration_0104_abac_policy_operator_values_upgrade",
            ),
            ("postgres-migration", "postgres_migration"),
            ("journeys", "audit_list_tenant_entries_localtx_journey"),
            ("journeys", "identity_password_security_event_journey"),
            ("journeys", "identity_refresh_producer_transaction_journey"),
            ("journeys", "settings_secret_publish_localtx_journey"),
            ("runtime", "settings_secret_e2e"),
            ("amqp", "integration"),
            ("mqtt", "integration"),
            ("journeys", "device_certificate_convergence_journey"),
            ("journeys", "mqtt_backpressure_fault_journey"),
            ("journeys", "amqp_consumer_at_least_once_journey"),
            ("journeys", "identity_login_audit_durable_journey"),
            ("journeys", "identityaudit_runtime"),
            ("runtime", "event_transport_durable_e2e"),
            ("settingsonly", "settingsonly"),
            ("identityaudit", "identityaudit"),
            ("identityaudit", "runtime_image_acceptance"),
            ("runtime", "runtime"),
            ("runtime", "configs_ready_e2e"),
            ("runtime", "identity_login_wire_e2e"),
            ("runtime", "service_token_replay_e2e"),
            ("runtime", "wire_contract_e2e"),
            ("redis-adapter", "integration_claimer"),
            ("redis-adapter", "integration_rate_limit"),
            ("redis-adapter", "integration_saga_effect_fixture"),
            ("testkit", "testkit"),
            ("testkit", "mqtt_mtls_fixture"),
            ("testkit", "postgres_test_login_governance"),
            ("journeys-fault-matrix", "consistency_fault_matrix_journey"),
            ("journeys-fault-matrix", "l2_dr_recovery_journey"),
            ("journeys-fault-matrix", "saga_fault_recovery"),
            ("runtime", "settings_config_publish_durable_e2e"),
            ("journeys", "saga_runtime_provider_integration"),
            ("s3", "integration_object_store"),
            ("journeys", "settingsonly_production_artifact"),
            ("journeys", "two_replica_runtime"),
        ]);
        let actual_serial: BTreeSet<_> = all_units()
            .into_iter()
            .filter(|unit| unit.scheduling == Scheduling::Serial)
            .map(|unit| (unit.package, unit.target))
            .collect();
        assert_eq!(actual_serial, expected_serial);

        for shard in IntegrationShard::ALL {
            let plan = batches(&release, *shard);
            assert!(!plan.is_empty());
            for batch in &plan {
                assert!(!batch.filter.contains("not "));
                assert!(!batch.filter.contains('/'));
                assert!(!batch.package.is_empty());
                assert!(!batch.targets.is_empty());
            }
            assert!(
                plan.iter()
                    .any(|batch| batch.scheduling == Scheduling::Parallel)
            );
        }
    }

    #[test]
    fn postgres_transaction_journeys_form_one_unpartitioned_serial_batch() -> Result<()> {
        let required = localtx_required_selection()?;
        let batch = postgres_transaction_journey_execution_batch(&required)?;
        assert_eq!(batch.scheduling, Scheduling::Serial);
        assert_eq!(batch.kind, TargetKind::Test);
        assert_eq!(batch.package, "journeys");
        assert_eq!(batch.unit_ids.len(), 4);
        Ok(())
    }

    #[test]
    fn localtx_backend_execution_unit_is_unique() -> Result<()> {
        let required = localtx_required_selection()?;
        let unit = localtx_backend_execution_unit(&required)?;
        assert_eq!(unit.package, LocalFeatureScope::Postgres.package());
        assert_eq!(unit.target, unit.package);
        assert_eq!(unit.kind, TargetKind::Lib);
        assert_eq!(unit.scheduling, Scheduling::Serial);
        Ok(())
    }

    #[test]
    fn localtx_backend_execution_unit_rejects_missing_duplicate_and_drift() -> Result<()> {
        let required = localtx_required_selection()?;
        let expected = localtx_backend_execution_unit(&required)?;
        let units = IntegrationShard::PostgresDomain.spec().units;

        let missing = units
            .iter()
            .copied()
            .filter(|unit| *unit != expected)
            .collect::<Vec<_>>();
        assert!(localtx_backend_execution_unit_from(&missing).is_err());

        let mut duplicate = units.to_vec();
        duplicate.push(expected);
        assert!(localtx_backend_execution_unit_from(&duplicate).is_err());

        let mut drift = units.to_vec();
        let carrier = drift
            .iter_mut()
            .find(|unit| **unit == expected)
            .context("typed LocalTx backend carrier")?;
        carrier.target = "postgres-drift";
        assert!(localtx_backend_execution_unit_from(&drift).is_err());
        Ok(())
    }

    #[test]
    fn localtx_required_selection_is_exact_and_each_unit_is_required() -> Result<()> {
        let required = localtx_required_selection()?;
        let expected = BTreeSet::from([
            IntegrationUnitId::PostgresLib,
            IntegrationUnitId::AuditListTenantEntriesLocalTxJourney,
            IntegrationUnitId::IdentityPasswordSecurityEventJourney,
            IntegrationUnitId::IdentityRefreshProducerTransactionJourney,
            IntegrationUnitId::SettingsSecretPublishLocalTxJourney,
        ]);
        assert_eq!(required.unit_ids(), &expected);
        localtx_backend_execution_unit(&required)?;
        postgres_transaction_journey_execution_batch(&required)?;

        for omitted in &expected {
            let incomplete = IntegrationSelection::critical(
                expected.iter().copied().filter(|id| id != omitted),
            )?;
            if *omitted == IntegrationUnitId::PostgresLib {
                assert!(localtx_backend_execution_unit(&incomplete).is_err());
            } else {
                assert!(
                    postgres_transaction_journey_execution_batch(&incomplete).is_err(),
                    "omitting {} must invalidate the required journey batch",
                    omitted.as_str()
                );
            }
        }
        Ok(())
    }

    #[test]
    fn localtx_required_selection_preserves_owner_profile_drift_error() {
        let error = localtx_required_selection_from([
            IntegrationUnitId::PostgresFeatureManifest,
            IntegrationUnitId::AuditListTenantEntriesLocalTxJourney,
            IntegrationUnitId::IdentityPasswordSecurityEventJourney,
            IntegrationUnitId::IdentityRefreshProducerTransactionJourney,
            IntegrationUnitId::SettingsSecretPublishLocalTxJourney,
        ])
        .context("derive required LocalTx catalog selection")
        .expect_err("release-check owner drift must fail closed");
        let chain = format!("{error:#}");
        assert!(chain.contains("derive required LocalTx catalog selection"));
        assert!(chain.contains("release-check unit `postgres-feature-manifest`"));
    }

    #[test]
    fn redis_shard_owns_one_real_testkit_container_lifecycle_target() {
        let spec = IntegrationShard::ConsistencyFault.spec();
        assert_eq!(
            spec.local_feature_scopes,
            &[
                LocalFeatureScope::Testkit,
                LocalFeatureScope::RedisAdapter,
                LocalFeatureScope::JourneysFaultMatrix,
            ]
        );
        let matches = spec
            .units
            .iter()
            .filter(|unit| {
                unit.package == "testkit"
                    && unit.target == "testkit"
                    && unit.kind == TargetKind::Lib
                    && unit.scheduling == Scheduling::Serial
            })
            .count();
        assert_eq!(
            matches, 1,
            "real Redis ownership/log/cleanup smoke must be registry-owned without copying adapter tests"
        );
    }

    #[test]
    fn workspace_plan_freezes_resources_and_dangerous_targets() {
        let release = IntegrationSelection::release_check();
        let expected = [
            (IntegrationShard::PostgresDomain, &[Resource::Postgres][..]),
            (
                IntegrationShard::EventTransport,
                &[
                    Resource::Postgres,
                    Resource::Redis,
                    Resource::Amqp,
                    Resource::Mqtt,
                ][..],
            ),
            (
                IntegrationShard::RuntimeHttpAuth,
                &[Resource::Postgres, Resource::Redis, Resource::Vault][..],
            ),
            (
                IntegrationShard::ConsistencyFault,
                &[Resource::Postgres, Resource::Redis, Resource::Amqp][..],
            ),
            (
                IntegrationShard::CdcProjectionSaga,
                &[Resource::Postgres][..],
            ),
            (
                IntegrationShard::ObjectStorage,
                &[Resource::ObjectStorage][..],
            ),
            (IntegrationShard::ProductionRuntime, &[][..]),
        ];
        assert_eq!(IntegrationShard::ALL.len(), expected.len());
        for (shard, resources) in expected {
            assert_eq!(release.resources_for_shard(shard), resources.to_vec());
            assert!(!shard.spec().units.is_empty());
        }
        assert!(release.requires_docker_for_shard(IntegrationShard::ProductionRuntime));
        assert!(release.requires_docker_for_shard(IntegrationShard::CdcProjectionSaga));

        let critical = IntegrationSelection::for_profile(ExecutionProfile::IntegrationCritical)
            .expect("critical selection");
        let critical_expected = [
            (IntegrationShard::PostgresDomain, vec![Resource::Postgres]),
            (
                IntegrationShard::EventTransport,
                vec![
                    Resource::Postgres,
                    Resource::Redis,
                    Resource::Amqp,
                    Resource::Mqtt,
                ],
            ),
            (IntegrationShard::RuntimeHttpAuth, vec![Resource::Postgres]),
            (IntegrationShard::ConsistencyFault, vec![Resource::Redis]),
            (
                IntegrationShard::CdcProjectionSaga,
                vec![Resource::Postgres],
            ),
            (
                IntegrationShard::ObjectStorage,
                vec![Resource::ObjectStorage],
            ),
            (IntegrationShard::ProductionRuntime, vec![]),
        ];
        for (shard, resources) in critical_expected {
            assert_eq!(critical.resources_for_shard(shard), resources);
        }
        assert!(critical.requires_docker_for_shard(IntegrationShard::EventTransport));
        assert!(critical.requires_docker_for_shard(IntegrationShard::ObjectStorage));
    }

    #[test]
    fn cdc_projection_saga_contains_only_executable_tests() {
        let spec = IntegrationShard::CdcProjectionSaga.spec();
        assert!(
            spec.units.iter().all(|unit| unit.kind == TargetKind::Test),
            "cdc projection/saga must not keep an empty carrier-only lib target"
        );
    }

    fn metadata_target(root: &Path, unit: &IntegrationUnitSpec) -> Value {
        let kind = unit.kind.as_str();
        let scope = LocalFeatureScope::for_package(unit.package)
            .expect("synthetic metadata requires local feature scope");
        let src_path = match unit.kind {
            TargetKind::Lib => root.join(scope.root()).join("src/lib.rs"),
            TargetKind::Test => root
                .join(scope.root())
                .join("tests")
                .join(format!("{}.rs", unit.target)),
        };
        let required_features = match (unit.kind, unit.local_eligibility) {
            (TargetKind::Test, LocalEligibility::RemoteOnly) => vec![scope.feature()],
            _ => Vec::new(),
        };
        json!({
            "name": unit.target,
            "kind": [kind],
            "crate_types": [if kind == "lib" { "lib" } else { "bin" }],
            "required-features": required_features,
            "src_path": src_path,
            "edition": "2024",
            "doctest": kind == "lib",
            "test": true,
            "doc": kind == "lib",
        })
    }

    fn metadata_from_at(root: &Path, targets: &[IntegrationUnitSpec], packages: &[&str]) -> String {
        let mut targets_by_package: BTreeMap<&str, Vec<&IntegrationUnitSpec>> = BTreeMap::new();
        for unit in targets {
            targets_by_package
                .entry(unit.package)
                .or_default()
                .push(unit);
        }
        let package_names = packages;
        let members = package_names
            .iter()
            .map(|package| format!("path+file://{}/{package}#0.0.0", root.display()))
            .collect::<Vec<_>>();
        json!({
            "packages": package_names.iter().map(|package| {
                let package_targets = targets_by_package.get(package).cloned().unwrap_or_default();
                json!({
                    "name": package,
                    "version": "0.0.0",
                    "id": format!("path+file://{}/{package}#0.0.0", root.display()),
                    "license": null,
                    "license_file": null,
                    "description": null,
                    "source": null,
                    "dependencies": [],
                    "targets": package_targets.into_iter().map(|unit| metadata_target(root, unit)).collect::<Vec<_>>(),
                    "features": {"integration": [], "broker-tests": []},
                    "manifest_path": root.join(package).join("Cargo.toml"),
                    "metadata": null,
                    "publish": [],
                    "authors": [],
                    "categories": [],
                    "keywords": [],
                    "readme": null,
                    "repository": null,
                    "homepage": null,
                    "documentation": null,
                    "edition": "2024",
                    "links": null,
                    "default_run": null,
                    "rust_version": "1.86",
                })
            }).collect::<Vec<_>>(),
            "workspace_members": members,
            "workspace_default_members": members,
            "resolve": {
                "nodes": package_names.iter().map(|package| json!({
                    "id": format!("path+file://{}/{package}#0.0.0", root.display()),
                    "dependencies": [],
                    "deps": [],
                    "features": [],
                })).collect::<Vec<_>>(),
                "root": null,
            },
            "workspace_root": root,
            "target_directory": root.join("target"),
            "build_directory": root.join("target"),
            "metadata": null,
            "version": 1,
        })
        .to_string()
    }

    fn metadata_from(targets: &[IntegrationUnitSpec], packages: &[&str]) -> String {
        metadata_from_at(Path::new("/workspace"), targets, packages)
    }

    fn facts_from(targets: &[IntegrationUnitSpec], packages: &[&str]) -> Result<WorkspaceFacts> {
        WorkspaceFacts::from_metadata_json(
            Path::new("/workspace"),
            &metadata_from(targets, packages),
        )
        .map_err(Into::into)
    }

    fn all_units() -> Vec<IntegrationUnitSpec> {
        IntegrationShard::ALL
            .iter()
            .flat_map(|shard| shard.spec().units.iter().copied())
            .collect()
    }

    #[test]
    fn metadata_coverage_rejects_missing_duplicate_and_unknown_targets() -> Result<()> {
        let units = all_units();
        validate_facts(&facts_from(&units, INTEGRATION_PACKAGES)?)?;

        let mut missing = units.clone();
        let missing_unit = missing.pop().context("synthetic catalog is non-empty")?;
        let error = validate_facts(&facts_from(&missing, INTEGRATION_PACKAGES)?)
            .expect_err("missing integration target must fail closed");
        assert_eq!(
            error.to_string(),
            format!(
                "integration shard coverage mismatch; unassigned=[]; stale={:?}",
                [(
                    missing_unit.package.to_owned(),
                    missing_unit.target.to_owned(),
                    missing_unit.kind.as_str().to_owned(),
                )]
            )
        );

        let mut unknown = units;
        let unknown_unit = IntegrationUnitSpec::new(
            IntegrationUnitId::RuntimeInventoryJourney,
            IntegrationShard::ProductionRuntime,
            ExecutionProfile::ReleaseCheck,
            "runtime",
            "new_unclassified_target",
            TargetKind::Test,
            Scheduling::Parallel,
            LocalEligibility::RemoteOnly,
        );
        unknown.push(unknown_unit);
        let error = validate_facts(&facts_from(&unknown, INTEGRATION_PACKAGES)?)
            .expect_err("unassigned integration target must fail closed");
        assert_eq!(
            error.to_string(),
            format!(
                "integration shard coverage mismatch; unassigned={:?}; stale=[]",
                [(
                    unknown_unit.package.to_owned(),
                    unknown_unit.target.to_owned(),
                    unknown_unit.kind.as_str().to_owned(),
                )]
            )
        );

        let error = validate_facts(&facts_from(
            &all_units(),
            &INTEGRATION_PACKAGES[..INTEGRATION_PACKAGES.len() - 1],
        )?)
        .expect_err("missing integration package must fail closed");
        assert_eq!(
            error.to_string(),
            "workspace facts missing legacy integration packages: [\"identityaudit\"]"
        );

        let mut duplicate = all_units();
        duplicate.push(duplicate[0]);
        let duplicate_id = (
            duplicate[0].package.to_owned(),
            duplicate[0].target.to_owned(),
            duplicate[0].kind.as_str().to_owned(),
        );
        let error = unique_targets(duplicate)
            .expect_err("duplicate integration target assignment must fail closed");
        assert_eq!(
            error.to_string(),
            format!("integration target assigned more than once: {duplicate_id:?}")
        );
        Ok(())
    }

    #[derive(Clone, Copy)]
    struct EligibilityFixture<'a> {
        package: &'a str,
        name: &'a str,
        src_path: &'a str,
        required_features: &'a [&'a str],
        test: bool,
    }

    static ELIGIBILITY_SANDBOX_SEQUENCE: std::sync::atomic::AtomicU64 =
        std::sync::atomic::AtomicU64::new(0);

    fn eligibility_unit(
        package: &'static str,
        target: &'static str,
        local_eligibility: LocalEligibility,
    ) -> IntegrationUnitSpec {
        IntegrationUnitSpec::new(
            IntegrationUnitId::PostgresFeatureManifest,
            IntegrationShard::PostgresDomain,
            ExecutionProfile::ReleaseCheck,
            package,
            target,
            TargetKind::Test,
            Scheduling::Parallel,
            local_eligibility,
        )
    }

    fn eligibility_sandbox() -> Result<PathBuf> {
        let sequence =
            ELIGIBILITY_SANDBOX_SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "rss-integration-elig-{}-{sequence}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root)?;
        Ok(root)
    }

    fn write_eligibility_source(root: &Path, rel: &str, body: &str) -> Result<()> {
        let path = root.join(rel);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, body)?;
        Ok(())
    }

    fn write_clean_eligibility_sources(
        root: &Path,
        fixtures: &[EligibilityFixture<'_>],
    ) -> Result<()> {
        for fixture in fixtures {
            write_eligibility_source(
                root,
                fixture.src_path,
                "// clean synthetic catalog target\n",
            )?;
        }
        Ok(())
    }

    fn eligibility_facts(
        root: &Path,
        targets: &[EligibilityFixture<'_>],
    ) -> Result<WorkspaceFacts> {
        use workspacefacts::testing::{
            metadata_json, path_package, path_package_id, resolve_node, target,
        };

        let mut by_package: BTreeMap<&str, Vec<&EligibilityFixture<'_>>> = BTreeMap::new();
        for fixture in targets {
            by_package.entry(fixture.package).or_default().push(fixture);
        }
        let packages = by_package
            .iter()
            .map(|(package, fixtures)| {
                let absolute = root.join(package);
                let absolute_display = absolute.display().to_string();
                path_package(
                    package,
                    &absolute_display,
                    fixtures
                        .iter()
                        .map(|fixture| {
                            target(
                                fixture.name,
                                "test",
                                &root.join(fixture.src_path).display().to_string(),
                                fixture.test,
                                fixture.required_features,
                            )
                        })
                        .collect(),
                    Vec::new(),
                    json!({"integration": [], "broker-tests": []}),
                )
            })
            .collect::<Vec<_>>();
        let member_ids = by_package
            .keys()
            .map(|package| path_package_id(&root.join(package).display().to_string()))
            .collect::<Vec<_>>();
        let nodes = member_ids
            .iter()
            .map(|id| resolve_node(id, &[]))
            .collect::<Vec<_>>();
        WorkspaceFacts::from_metadata_json(
            root,
            &metadata_json(&root.display().to_string(), packages, member_ids, nodes),
        )
        .map_err(Into::into)
    }

    fn check_eligibility(
        root: &Path,
        fixtures: &[EligibilityFixture<'_>],
        units: &[IntegrationUnitSpec],
    ) -> Result<()> {
        write_clean_eligibility_sources(root, fixtures)?;
        let facts = eligibility_facts(root, fixtures)?;
        validate_test_target_eligibility(root, &facts, units)
    }

    #[test]
    fn cargo_target_eligibility_rejects_missing_duplicate_path_and_feature_drift() -> Result<()> {
        let root = eligibility_sandbox()?;
        let remote = eligibility_unit(
            "postgres",
            "migration_0086_hard_cutover",
            LocalEligibility::RemoteOnly,
        );
        let affected = eligibility_unit("postgres", "feature_manifest", LocalEligibility::Affected);
        let mqtt_remote = eligibility_unit("mqtt", "integration", LocalEligibility::RemoteOnly);
        let postgres_remote_path = expected_test_src_path(remote.package, remote.target)?;
        let postgres_affected_path = expected_test_src_path(affected.package, affected.target)?;
        let mqtt_path = expected_test_src_path(mqtt_remote.package, mqtt_remote.target)?;
        let postgres_feature = LocalFeatureScope::for_package(remote.package)
            .expect("postgres scope")
            .feature();
        let mqtt_feature = LocalFeatureScope::for_package(mqtt_remote.package)
            .expect("mqtt scope")
            .feature();

        let valid = [
            EligibilityFixture {
                package: remote.package,
                name: remote.target,
                src_path: postgres_remote_path.to_str().expect("utf-8 path"),
                required_features: &[postgres_feature],
                test: true,
            },
            EligibilityFixture {
                package: affected.package,
                name: affected.target,
                src_path: postgres_affected_path.to_str().expect("utf-8 path"),
                required_features: &[],
                test: true,
            },
            EligibilityFixture {
                package: mqtt_remote.package,
                name: mqtt_remote.target,
                src_path: mqtt_path.to_str().expect("utf-8 path"),
                required_features: &[mqtt_feature],
                test: true,
            },
        ];
        check_eligibility(&root, &valid, &[remote, affected, mqtt_remote])
            .context("valid eligibility fixture must pass exact closure")?;

        let affected_typed = eligibility_unit("runtime", "auth_e2e", LocalEligibility::Affected);
        let affected_typed_path =
            expected_test_src_path(affected_typed.package, affected_typed.target)?;
        let runtime_feature = LocalFeatureScope::for_package(affected_typed.package)
            .expect("runtime scope")
            .feature();
        let affected_typed_ok = [EligibilityFixture {
            package: affected_typed.package,
            name: affected_typed.target,
            src_path: affected_typed_path.to_str().expect("utf-8 path"),
            required_features: &[runtime_feature],
            test: true,
        }];
        check_eligibility(&root, &affected_typed_ok, &[affected_typed])
            .context("Affected may share the typed LocalFeatureScope compile boundary")?;

        let missing = [EligibilityFixture {
            package: affected.package,
            name: affected.target,
            src_path: postgres_affected_path.to_str().expect("utf-8 path"),
            required_features: &[],
            test: true,
        }];
        let error = check_eligibility(&root, &missing, &[remote, affected])
            .expect_err("missing catalog test target must fail closed");
        assert!(
            error.to_string().contains(remote.target),
            "missing target diagnostic must name the target: {error}"
        );

        let duplicate = eligibility_facts(
            &root,
            &[
                EligibilityFixture {
                    package: remote.package,
                    name: remote.target,
                    src_path: postgres_remote_path.to_str().expect("utf-8 path"),
                    required_features: &[postgres_feature],
                    test: true,
                },
                EligibilityFixture {
                    package: remote.package,
                    name: remote.target,
                    src_path: "adapters/postgres/tests/alias_duplicate.rs",
                    required_features: &[postgres_feature],
                    test: true,
                },
            ],
        );
        let error = duplicate.expect_err(
            "duplicate Test target names must fail closed at WorkspaceFacts construction",
        );
        assert!(
            error.to_string().contains(remote.target),
            "duplicate name diagnostic must name the target: {error}"
        );

        let alias = [
            EligibilityFixture {
                package: remote.package,
                name: remote.target,
                src_path: postgres_remote_path.to_str().expect("utf-8 path"),
                required_features: &[postgres_feature],
                test: true,
            },
            EligibilityFixture {
                package: remote.package,
                name: "migration_0087_device_command_fencing",
                src_path: postgres_remote_path.to_str().expect("utf-8 path"),
                required_features: &[postgres_feature],
                test: true,
            },
        ];
        let alias_unit = eligibility_unit(
            "postgres",
            "migration_0087_device_command_fencing",
            LocalEligibility::RemoteOnly,
        );
        let error = check_eligibility(&root, &alias, &[remote, alias_unit])
            .expect_err("source path alias must fail closed");
        assert!(
            error.to_string().contains("source path"),
            "path alias diagnostic must mention source path: {error}"
        );

        let wrong_path = [EligibilityFixture {
            package: remote.package,
            name: remote.target,
            src_path: "adapters/postgres/tests/wrong_name.rs",
            required_features: &[postgres_feature],
            test: true,
        }];
        let error = check_eligibility(&root, &wrong_path, &[remote])
            .expect_err("src_path must equal LocalFeatureScope::root()/tests/{{target}}.rs");
        assert!(
            error.to_string().contains("src_path"),
            "path mismatch diagnostic must mention src_path: {error}"
        );

        let missing_features = [EligibilityFixture {
            package: remote.package,
            name: remote.target,
            src_path: postgres_remote_path.to_str().expect("utf-8 path"),
            required_features: &[],
            test: true,
        }];
        let error = check_eligibility(&root, &missing_features, &[remote])
            .expect_err("RemoteOnly required_features must be present");
        assert!(
            error.to_string().contains("required_features"),
            "missing feature diagnostic must mention required_features: {error}"
        );

        let wrong_features = [EligibilityFixture {
            package: mqtt_remote.package,
            name: mqtt_remote.target,
            src_path: mqtt_path.to_str().expect("utf-8 path"),
            required_features: &["integration"],
            test: true,
        }];
        let error = check_eligibility(&root, &wrong_features, &[mqtt_remote])
            .expect_err("RemoteOnly required_features must equal LocalFeatureScope::feature()");
        assert!(
            error.to_string().contains(mqtt_feature),
            "wrong feature diagnostic must mention typed feature `{mqtt_feature}`: {error}"
        );

        let extra_features = [EligibilityFixture {
            package: remote.package,
            name: remote.target,
            src_path: postgres_remote_path.to_str().expect("utf-8 path"),
            required_features: &[postgres_feature, "extra-gate"],
            test: true,
        }];
        let error = check_eligibility(&root, &extra_features, &[remote])
            .expect_err("RemoteOnly required_features must be a singleton");
        assert!(
            error.to_string().contains("required_features"),
            "extra feature diagnostic must mention required_features: {error}"
        );

        let test_disabled = [EligibilityFixture {
            package: remote.package,
            name: remote.target,
            src_path: postgres_remote_path.to_str().expect("utf-8 path"),
            required_features: &[postgres_feature],
            test: false,
        }];
        let error = check_eligibility(&root, &test_disabled, &[remote])
            .expect_err("test_by_default=false must fail closed");
        assert!(
            error.to_string().contains("test_by_default"),
            "disabled test diagnostic must mention test_by_default: {error}"
        );

        let affected_wrong = [EligibilityFixture {
            package: affected_typed.package,
            name: affected_typed.target,
            src_path: affected_typed_path.to_str().expect("utf-8 path"),
            required_features: &["broker-tests"],
            test: true,
        }];
        let error = check_eligibility(&root, &affected_wrong, &[affected_typed])
            .expect_err("Affected wrong feature must fail closed");
        assert!(
            error.to_string().contains(runtime_feature),
            "Affected wrong-feature diagnostic must mention typed feature `{runtime_feature}`: {error}"
        );

        let affected_extra = [EligibilityFixture {
            package: affected_typed.package,
            name: affected_typed.target,
            src_path: affected_typed_path.to_str().expect("utf-8 path"),
            required_features: &[runtime_feature, "extra-gate"],
            test: true,
        }];
        let error = check_eligibility(&root, &affected_extra, &[affected_typed])
            .expect_err("Affected extra features must fail closed");
        assert!(
            error.to_string().contains("required_features"),
            "Affected extra-feature diagnostic must mention required_features: {error}"
        );
        Ok(())
    }

    #[test]
    fn cargo_target_eligibility_rejects_crate_level_feature_cfg() -> Result<()> {
        let root = eligibility_sandbox()?;
        let unit = eligibility_unit("postgres", "feature_manifest", LocalEligibility::Affected);
        let src_path = expected_test_src_path(unit.package, unit.target)?;
        let src = src_path.to_str().expect("utf-8 path");
        let fixtures = [EligibilityFixture {
            package: unit.package,
            name: unit.target,
            src_path: src,
            required_features: &[],
            test: true,
        }];

        write_eligibility_source(
            &root,
            src,
            "#![cfg(feature = \"integration\")]\nfn case() {}\n",
        )?;
        let facts = eligibility_facts(&root, &fixtures)?;
        let error = validate_test_target_eligibility(&root, &facts, &[unit])
            .expect_err("crate-level cfg(feature) must fail closed");
        let message = error.to_string();
        assert!(
            message.contains(unit.package)
                && message.contains(unit.target)
                && message.contains(src)
                && message.contains("#![cfg(...feature...)]"),
            "cfg diagnostic must name package/target/path/attribute: {message}"
        );

        write_eligibility_source(
            &root,
            src,
            "#![cfg_attr(feature = \"integration\", allow(dead_code))]\nfn case() {}\n",
        )?;
        let facts = eligibility_facts(&root, &fixtures)?;
        let error = validate_test_target_eligibility(&root, &facts, &[unit])
            .expect_err("crate-level cfg_attr(feature) must fail closed");
        let message = error.to_string();
        assert!(
            message.contains(unit.package)
                && message.contains(unit.target)
                && message.contains(src)
                && message.contains("#![cfg_attr(...feature...)]"),
            "cfg_attr diagnostic must name package/target/path/attribute: {message}"
        );

        write_eligibility_source(
            &root,
            src,
            "#[cfg(feature = \"integration\")]\nfn optional_case() {}\n",
        )?;
        let facts = eligibility_facts(&root, &fixtures)?;
        validate_test_target_eligibility(&root, &facts, &[unit])
            .context("item-level cfg(feature) remains out of scope and must pass")?;
        Ok(())
    }

    #[test]
    fn catalog_test_and_remote_only_sets_are_non_vacuous() {
        let tests = INTEGRATION_UNIT_SPECS
            .iter()
            .filter(|unit| unit.kind == TargetKind::Test)
            .count();
        let remote_only = INTEGRATION_UNIT_SPECS
            .iter()
            .filter(|unit| {
                unit.kind == TargetKind::Test
                    && unit.local_eligibility == LocalEligibility::RemoteOnly
            })
            .count();
        assert!(tests > 0, "anti-vacuity: catalog must declare Test targets");
        assert!(
            remote_only > 0,
            "anti-vacuity: catalog must declare RemoteOnly Test targets"
        );
        assert!(
            remote_only < tests,
            "anti-vacuity: Affected Test targets must also exist"
        );
    }

    #[test]
    fn workspace_cargo_target_eligibility_matches_local_feature_scope() -> Result<()> {
        let root = workspace_root()?;
        let command_facts = CommandWorkspaceFacts::new(&root);
        let facts = command_facts
            .get()
            .context("load workspace facts for eligibility anti-vacuity")?;
        validate_test_target_eligibility(command_facts.root(), facts, INTEGRATION_UNIT_SPECS)
    }

    #[test]
    fn workspace_metadata_covers_legacy_integration_targets() -> Result<()> {
        validate_current_workspace()
    }

    #[test]
    fn command_orchestration_validates_once_and_caches_success_and_failure() -> Result<()> {
        use std::cell::Cell;
        use std::rc::Rc;

        let real_root = workspace_root()?;
        let root = eligibility_sandbox()?;
        std::fs::create_dir_all(root.join(".config"))?;
        std::fs::copy(
            real_root.join(".config/nextest.toml"),
            root.join(".config/nextest.toml"),
        )
        .context("copy nextest config into eligibility sandbox")?;
        for unit in all_units()
            .into_iter()
            .filter(|unit| unit.kind == TargetKind::Test)
        {
            let rel = expected_test_src_path(unit.package, unit.target)?;
            write_eligibility_source(
                &root,
                rel.to_str().expect("utf-8 path"),
                "// clean synthetic catalog target\n",
            )?;
        }
        let metadata = metadata_from_at(&root, &all_units(), INTEGRATION_PACKAGES).into_bytes();
        let success_calls = Rc::new(Cell::new(0));
        let success_counter = Rc::clone(&success_calls);
        let success = CommandWorkspaceFacts::with_metadata_loader(&root, move |_| {
            success_counter.set(success_counter.get() + 1);
            Ok(metadata.clone())
        });
        let executions = Cell::new(0);
        with_validated_workspace(&success, |validated| {
            for _shard in [
                IntegrationShard::PostgresDomain,
                IntegrationShard::EventTransport,
            ] {
                assert_eq!(validated.root(), root.as_path());
                executions.set(executions.get() + 1);
            }
            Ok(())
        })?;
        assert_eq!(success_calls.get(), 1);
        assert_eq!(executions.get(), 2, "anti-vacuity: both shards must run");

        let failure_calls = Rc::new(Cell::new(0));
        let failure_counter = Rc::clone(&failure_calls);
        let failure = CommandWorkspaceFacts::with_metadata_loader(&root, move |_| {
            failure_counter.set(failure_counter.get() + 1);
            Err("synthetic metadata failure".to_owned())
        });
        let failure_executions = Cell::new(0);
        for _attempt in 0..2 {
            assert!(
                with_validated_workspace(&failure, |_| {
                    failure_executions.set(failure_executions.get() + 1);
                    Ok(())
                })
                .is_err()
            );
        }
        assert_eq!(failure_calls.get(), 1);
        assert_eq!(failure_executions.get(), 0);
        Ok(())
    }

    #[test]
    fn local_test_eligibility_is_orthogonal_to_remote_shard_ownership() {
        assert!(is_remote_only_test_target("mqtt", "integration"));
        assert!(is_remote_only_test_target("testkit", "mqtt_mtls_fixture"));
        assert!(!is_remote_only_test_target("mqtt", "ownership_gate"));
        assert!(!is_remote_only_test_target(
            "journeys",
            "eventtransport_journey"
        ));
        assert!(!is_remote_only_test_target("runtime", "auth_e2e"));
        assert!(!is_remote_only_test_target("runtime", "refresh_mint_e2e"));
        assert!(!is_remote_only_test_target("runtime", "key_rotation_e2e"));
        assert!(!is_remote_only_test_target(
            "runtime",
            "auth_bridge_structure"
        ));
        assert!(is_remote_only_test_target("journeys", "production_runtime"));
        assert!(!is_remote_only_test_target(
            "xtask",
            "consistency_report_cli"
        ));
        assert!(!is_remote_only_test_target("runtime", "runtime"));
    }

    #[test]
    fn live_minio_target_is_owned_by_the_object_storage_shard() {
        let spec = IntegrationShard::ObjectStorage.spec();
        assert_eq!(
            IntegrationSelection::release_check().resources_for_shard(spec.shard),
            [Resource::ObjectStorage]
        );
        assert!(
            !external_resource_present(Resource::ObjectStorage),
            "object storage conformance must always self-provision its hermetic TLS fixture"
        );
        let live_targets: Vec<_> = spec
            .units
            .iter()
            .filter(|unit| unit.target == "integration_object_store")
            .collect();
        assert_eq!(live_targets.len(), 1);
        let live = live_targets[0];
        assert_eq!(live.package, "s3");
        assert_eq!(live.kind, TargetKind::Test);
        assert_eq!(live.scheduling, Scheduling::Serial);
    }

    #[test]
    fn production_runtime_shard_owns_one_serial_two_replica_target() {
        let spec = IntegrationShard::ProductionRuntime.spec();
        assert!(
            IntegrationSelection::release_check()
                .resources_for_shard(spec.shard)
                .is_empty(),
            "journey self-provisions Docker resources"
        );
        let matches = spec
            .units
            .iter()
            .filter(|unit| {
                unit.package == "journeys"
                    && unit.target == "two_replica_runtime"
                    && unit.kind == TargetKind::Test
                    && unit.scheduling == Scheduling::Serial
            })
            .count();
        assert_eq!(matches, 1);
        let production_artifacts = spec
            .units
            .iter()
            .filter(|unit| {
                unit.package == "journeys"
                    && unit.target == "settingsonly_production_artifact"
                    && unit.kind == TargetKind::Test
                    && unit.scheduling == Scheduling::Serial
            })
            .count();
        assert_eq!(
            production_artifacts, 1,
            "SettingsOnly production artifact carrier must be unique and serial"
        );
        assert_eq!(
            IntegrationShard::ProductionRuntime.partition_policy(),
            PartitionPolicy::Unpartitioned
        );
    }

    #[test]
    fn external_postgres_resource_uses_only_the_endpoint_triplet() {
        let mut values = std::collections::BTreeMap::from([
            ("RSS_TEST_ALLOW_EXTERNAL_POSTGRES", "true"),
            ("PGHOST", "postgres.example"),
            ("PGPORT", "5432"),
            ("PGDATABASE", "rss_test"),
        ]);
        let present = |name: &str| values.get(name).map(std::ffi::OsString::from);
        assert!(external_resource_present_from_lookup(
            Resource::Postgres,
            present
        ));

        values.insert("PGUSER", "owner-must-be-ignored");
        values.insert("PGPASSWORD", "owner-password-must-be-ignored");
        assert!(external_resource_present_from_lookup(
            Resource::Postgres,
            |name| values.get(name).map(std::ffi::OsString::from)
        ));

        values.remove("PGPORT");
        assert!(!external_resource_present_from_lookup(
            Resource::Postgres,
            |name| values.get(name).map(std::ffi::OsString::from)
        ));
    }
}
