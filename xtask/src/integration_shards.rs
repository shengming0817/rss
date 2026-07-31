//! Integration capability shard registry and target-level execution plans.
//!
//! INVARIANT: INTEGRATION-SHARD-REGISTRY-01 { level = "Hard", exec = "native-compile", source = "code", native = "catalog macro generates the closed enum, ALL, lookup, resources, and execution units" }.
//! INVARIANT: INTEGRATION-SHARD-SELECTOR-01 { level = "Hard", exec = "native-compile", source = "code", native = "filtersets render only from typed package/binary/kind execution units" }.
//! INVARIANT: INTEGRATION-SHARD-COVERAGE-01 { level = "Medium", exec = "release-check", source = "code", synthetic_red = "metadata_coverage_rejects_missing_duplicate_and_unknown_targets", anti_vacuity = "workspace_metadata_covers_legacy_integration_targets" }.
//! INVARIANT: INTEGRATION-SHARD-SCHEDULING-01 { level = "Medium", exec = "release-check", source = "code", synthetic_red = "scheduling_plan_rejects_dangerous_target_parallelism|localtx_backend_execution_unit_rejects_missing_duplicate_and_drift", anti_vacuity = "workspace_plan_freezes_resources_and_dangerous_targets|localtx_journeys_form_one_unpartitioned_serial_batch|localtx_backend_execution_unit_is_unique" }.

#[cfg(test)]
use crate::workspace_root;
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::Path;
use std::str::FromStr;

use crate::execution_profiles::{ExecutionProfile, ExecutionUnitSpec};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Resource {
    Postgres,
    Redis,
    Amqp,
    Mqtt,
    ObjectStorage,
    Vault,
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

impl TargetKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Lib => "lib",
            Self::Test => "test",
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
    Journeys,
    Runtime,
    Testkit,
    JourneysFaultMatrix,
    S3,
    SettingsOnly,
}

impl LocalFeatureScope {
    pub(crate) const ALL: [Self; 11] = [
        Self::Postgres,
        Self::PostgresMigration,
        Self::RedisAdapter,
        Self::Amqp,
        Self::Mqtt,
        Self::Journeys,
        Self::Runtime,
        Self::Testkit,
        Self::JourneysFaultMatrix,
        Self::S3,
        Self::SettingsOnly,
    ];

    pub(crate) const fn package(self) -> &'static str {
        match self {
            Self::Postgres => "postgres",
            Self::PostgresMigration => "postgres-migration",
            Self::RedisAdapter => "redis-adapter",
            Self::Amqp => "amqp",
            Self::Mqtt => "mqtt",
            Self::Journeys => "journeys",
            Self::Runtime => "runtime",
            Self::Testkit => "testkit",
            Self::JourneysFaultMatrix => "journeys-fault-matrix",
            Self::S3 => "s3",
            Self::SettingsOnly => "settingsonly",
        }
    }

    pub(crate) const fn feature(self) -> &'static str {
        match self {
            Self::Mqtt => "broker-tests",
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

    /// Resolve the Cargo feature for an integration batch package. Catalog packages are bijective
    /// with [`LocalFeatureScope::ALL`] (validated by `validate_local_feature_catalog`).
    pub(crate) fn for_package(package: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|scope| scope.package() == package)
    }
}

impl IntegrationUnitSpec {
    const fn new(
        id: IntegrationUnitId,
        shard: IntegrationShard,
        package: &'static str,
        target: &'static str,
        kind: TargetKind,
        scheduling: Scheduling,
    ) -> Self {
        Self {
            id,
            shard,
            primary_owner: ExecutionProfile::ReleaseCheck,
            package,
            target,
            kind,
            scheduling,
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

#[derive(Debug, Clone, Copy)]
pub(crate) struct ShardSpec {
    pub(crate) shard: IntegrationShard,
    pub(crate) resources: &'static [Resource],
    pub(crate) units: &'static [IntegrationUnitSpec],
    pub(crate) local_feature_scopes: &'static [LocalFeatureScope],
    capabilities: &'static [Capability],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Capability {
    Docker,
}

macro_rules! integration_shard_catalog {
    ($(
        $variant:ident => {
            name: $name:literal,
            resources: [$($resource:ident),* $(,)?],
            capabilities: [$($capability:ident),* $(,)?],
            local_feature_scopes: [$($scope:ident),+ $(,)?],
            units: [$($unit:ident => ($package:literal, $target:literal, $kind:ident, $scheduling:ident)),+ $(,)?],
        },
    )+) => {
        #[repr(usize)]
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
        #[serde(rename_all = "kebab-case")]
        pub(crate) enum IntegrationShard { $($variant),+ }

        #[repr(usize)]
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub(crate) enum IntegrationUnitId { $($($unit),+),+ }

        const INTEGRATION_UNIT_SPECS: &[IntegrationUnitSpec] = &[$($(IntegrationUnitSpec::new(
            IntegrationUnitId::$unit,
            IntegrationShard::$variant,
            $package,
            $target,
            TargetKind::$kind,
            Scheduling::$scheduling,
        )),+),+];

        const SHARD_SPECS: &[ShardSpec] = &[$(ShardSpec {
            shard: IntegrationShard::$variant,
            resources: &[$(Resource::$resource),*],
            capabilities: &[$(Capability::$capability),*],
            local_feature_scopes: &[$(LocalFeatureScope::$scope),+],
            units: &[$(IntegrationUnitSpec::new(
                IntegrationUnitId::$unit,
                IntegrationShard::$variant,
                $package,
                $target,
                TargetKind::$kind,
                Scheduling::$scheduling,
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

            pub(crate) fn requires_docker(self) -> bool {
                self.spec().capabilities.contains(&Capability::Docker)
            }
        }

        impl IntegrationUnitId {
            pub(crate) const ALL: [Self; [$($(stringify!($unit)),+),+].len()] = [$( $(Self::$unit),+ ),+];

            pub(crate) const fn spec(self) -> &'static IntegrationUnitSpec {
                &INTEGRATION_UNIT_SPECS[self as usize]
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
    };
}

integration_shard_catalog! {
    PostgresDomain => {
        name: "postgres-domain",
        resources: [Postgres],
        capabilities: [],
        local_feature_scopes: [Postgres, PostgresMigration, Journeys, Runtime],
        units: [
            PostgresLib => ("postgres", "postgres", Lib, Serial),
            PostgresMigrationLib => ("postgres-migration", "postgres_migration", Lib, Serial),
            PostgresFeatureManifest => ("postgres", "feature_manifest", Test, Parallel),
            PostgresMigrationOpsContract => ("postgres", "migration_ops_contract", Test, Parallel),
            PostgresTenantTransactionTrybuild => ("postgres", "tenant_transaction_trybuild", Test, Parallel),
            AuditListTenantEntriesLocalTxJourney => ("journeys", "audit_list_tenant_entries_localtx_journey", Test, Serial),
            IdentityLogoutGrantJourney => ("journeys", "identity_logout_grant_journey", Test, Parallel),
            IdentityPasswordSecurityEventJourney => ("journeys", "identity_password_security_event_journey", Test, Serial),
            IdentityRefreshProducerTransactionJourney => ("journeys", "identity_refresh_producer_transaction_journey", Test, Serial),
            SettingsSecretPublishLocalTxJourney => ("journeys", "settings_secret_publish_localtx_journey", Test, Serial),
            SettingsSecretE2e => ("runtime", "settings_secret_e2e", Test, Serial),
        ],
    },
    EventTransport => {
        name: "event-transport",
        resources: [Postgres, Redis, Amqp, Mqtt],
        capabilities: [],
        local_feature_scopes: [Amqp, Mqtt, Journeys, Runtime],
        units: [
            AmqpLib => ("amqp", "amqp", Lib, Parallel),
            AmqpIntegration => ("amqp", "integration", Test, Serial),
            MqttLib => ("mqtt", "mqtt", Lib, Parallel),
            MqttIntegration => ("mqtt", "integration", Test, Serial),
            AmqpConsumerAtLeastOnceJourney => ("journeys", "amqp_consumer_at_least_once_journey", Test, Serial),
            EventTransportJourney => ("journeys", "eventtransport_journey", Test, Parallel),
            IdentityLoginAuditDurableJourney => ("journeys", "identity_login_audit_durable_journey", Test, Serial),
            IdentityLoginAuditJourney => ("journeys", "identity_login_audit_journey", Test, Parallel),
            IdentityAuditRuntimeJourney => ("journeys", "identityaudit_runtime", Test, Serial),
            EventTransportDurableE2e => ("runtime", "event_transport_durable_e2e", Test, Serial),
        ],
    },
    RuntimeHttpAuth => {
        name: "runtime-http-auth",
        resources: [Postgres, Redis, Vault],
        capabilities: [],
        local_feature_scopes: [Journeys, Runtime, SettingsOnly],
        units: [
            SecurityProviderCloseoutJourney => ("journeys", "security_provider_closeout", Test, Parallel),
            SettingsOnlyRuntimeJourney => ("journeys", "settingsonly_runtime", Test, Parallel),
            SettingsOnlyLib => ("settingsonly", "settingsonly", Lib, Serial),
            RuntimeLib => ("runtime", "runtime", Lib, Serial),
            AuthE2e => ("runtime", "auth_e2e", Test, Parallel),
            AuthBridgeStructure => ("runtime", "auth_bridge_structure", Test, Parallel),
            ServerBudgetStructure => ("runtime", "server_budget_structure", Test, Parallel),
            ConfigsReadyE2e => ("runtime", "configs_ready_e2e", Test, Serial),
            DomainExecutionPlanTrybuild => ("runtime", "domain_execution_plan_trybuild", Test, Parallel),
            IdentityLoginWireE2e => ("runtime", "identity_login_wire_e2e", Test, Serial),
            InfraBuildersApi => ("runtime", "infra_builders_api", Test, Parallel),
            ListenerPlanTrybuild => ("runtime", "listener_plan_trybuild", Test, Parallel),
            OperatorSurfaceTrybuild => ("runtime", "operator_surface_trybuild", Test, Parallel),
            RefreshMintE2e => ("runtime", "refresh_mint_e2e", Test, Parallel),
            KeyRotationE2e => ("runtime", "key_rotation_e2e", Test, Parallel),
            RuntimeOutputsTrybuild => ("runtime", "runtime_outputs_trybuild", Test, Parallel),
            RuntimeServeE2e => ("runtime", "runtime_serve_e2e", Test, Parallel),
            ServiceTokenReplayE2e => ("runtime", "service_token_replay_e2e", Test, Serial),
            WireContractE2e => ("runtime", "wire_contract_e2e", Test, Serial),
        ],
    },
    ConsistencyFault => {
        name: "consistency-fault",
        resources: [Postgres, Redis, Amqp],
        capabilities: [],
        local_feature_scopes: [Testkit, RedisAdapter, JourneysFaultMatrix],
        units: [
            TestkitLib => ("testkit", "testkit", Lib, Serial),
            TestkitCrashMatrix => ("testkit", "crash_matrix", Test, Parallel),
            DeviceCommandConformance => ("testkit", "device_command_conformance", Test, Parallel),
            TestkitHarness => ("testkit", "harness", Test, Parallel),
            TestkitLocalOnly => ("testkit", "local_only", Test, Parallel),
            PostgresTestLoginGovernance => ("testkit", "postgres_test_login_governance", Test, Serial),
            ProjectionTargetConformanceTrybuild => ("testkit", "projection_target_conformance_trybuild", Test, Parallel),
            ProviderCatalogTrybuild => ("testkit", "provider_catalog_trybuild", Test, Parallel),
            RedisAdapterLib => ("redis-adapter", "redis", Lib, Parallel),
            RedisIntegrationClaimer => ("redis-adapter", "integration_claimer", Test, Serial),
            ConsistencyFaultMatrixJourney => ("journeys-fault-matrix", "consistency_fault_matrix_journey", Test, Serial),
        ],
    },
    CdcProjectionSaga => {
        name: "cdc-projection-saga",
        resources: [Postgres],
        capabilities: [],
        local_feature_scopes: [Journeys, Runtime],
        units: [
            SagaProjectionDepsJourney => ("journeys", "saga_projection_deps_journey", Test, Parallel),
            SettingsConfigPublishJourney => ("journeys", "settings_config_publish_journey", Test, Parallel),
            SettingsConfigPublishDurableE2e => ("runtime", "settings_config_publish_durable_e2e", Test, Serial),
        ],
    },
    ObjectStorage => {
        name: "object-storage",
        resources: [ObjectStorage],
        capabilities: [],
        local_feature_scopes: [S3],
        units: [
            S3Lib => ("s3", "s3", Lib, Parallel),
            DlxArchiveStore => ("s3", "dlx_archive_store", Test, Parallel),
            IntegrationObjectStore => ("s3", "integration_object_store", Test, Serial),
        ],
    },
    ProductionRuntime => {
        name: "production-runtime",
        resources: [],
        capabilities: [Docker],
        local_feature_scopes: [Journeys],
        units: [
            SettingsOnlyProductionArtifact => ("journeys", "settingsonly_production_artifact", Test, Serial),
            TwoReplicaRuntimeJourney => ("journeys", "two_replica_runtime", Test, Serial),
            ProductionRuntimeJourney => ("journeys", "production_runtime", Test, Parallel),
            RuntimeInventoryJourney => ("journeys", "runtime_inventory", Test, Parallel),
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
        if spec.primary_owner != ExecutionProfile::ReleaseCheck {
            bail!(
                "integration unit {:?} must remain release-check owned until integration-critical activation",
                spec.id
            );
        }
    }

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

fn projected_integration_units(
    profile: ExecutionProfile,
) -> impl Iterator<Item = &'static IntegrationUnitSpec> {
    ExecutionUnitSpec::project(profile).filter_map(|unit| match unit {
        ExecutionUnitSpec::Integration(spec) => Some(spec),
        ExecutionUnitSpec::Gate(_) => None,
    })
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
    pub(crate) scheduling: Scheduling,
    pub(crate) kind: TargetKind,
    pub(crate) package: &'static str,
    /// Cargo feature resolved from [`LocalFeatureScope`] for `package` (e.g. mqtt → `broker-tests`).
    pub(crate) feature: &'static str,
    pub(crate) targets: Vec<&'static str>,
    pub(crate) filter: String,
}

pub(crate) fn batches(shard: IntegrationShard) -> Vec<ShardBatch> {
    debug_assert_eq!(shard.spec().shard, shard);
    [Scheduling::Serial, Scheduling::Parallel]
        .into_iter()
        .flat_map(|scheduling| {
            [TargetKind::Lib, TargetKind::Test]
                .into_iter()
                .flat_map(move |kind| {
                    let mut by_package = BTreeMap::<_, Vec<_>>::new();
                    for unit in projected_integration_units(ExecutionProfile::ReleaseCheck)
                        .copied()
                        .filter(|unit| unit.shard == shard)
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
                        let filter = units
                            .into_iter()
                            .map(IntegrationUnitSpec::filter)
                            .map(|filter| format!("({filter})"))
                            .collect::<Vec<_>>()
                            .join(" or ");
                        Some(ShardBatch {
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

pub(crate) const POSTGRES_TRANSACTION_JOURNEY_TARGETS: &[&str] = &[
    "audit_list_tenant_entries_localtx_journey",
    "identity_password_security_event_journey",
    "identity_refresh_producer_transaction_journey",
    "settings_secret_publish_localtx_journey",
];

pub(crate) fn postgres_transaction_journey_execution_batch() -> Result<ShardBatch> {
    if IntegrationShard::PostgresDomain.partition_policy() != PartitionPolicy::Unpartitioned {
        bail!("Postgres transaction journey shard must remain unpartitioned");
    }
    let matches = batches(IntegrationShard::PostgresDomain)
        .into_iter()
        .filter(|batch| {
            batch.scheduling == Scheduling::Serial
                && batch.kind == TargetKind::Test
                && batch.package == "journeys"
                && batch.targets.as_slice() == POSTGRES_TRANSACTION_JOURNEY_TARGETS
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
pub(crate) fn localtx_backend_execution_unit() -> Result<IntegrationUnitSpec> {
    let shard = IntegrationShard::PostgresDomain;
    if shard.partition_policy() != PartitionPolicy::Unpartitioned {
        bail!("LocalTx backend evidence shard must remain unpartitioned");
    }
    let projected = projected_integration_units(ExecutionProfile::ReleaseCheck)
        .filter(|unit| unit.shard == shard)
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
    "journeys",
    "runtime",
    "journeys-fault-matrix",
    "testkit",
    "s3",
    "settingsonly",
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
    unique_targets(projected_integration_units(ExecutionProfile::ReleaseCheck).copied())
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

fn metadata_targets(metadata: &Value) -> Result<BTreeSet<TargetId>> {
    let packages = metadata
        .get("packages")
        .and_then(Value::as_array)
        .context("cargo metadata JSON missing packages array")?;
    let mut actual = BTreeSet::new();
    let mut seen_packages = BTreeSet::new();
    for package in packages {
        let name = package
            .get("name")
            .and_then(Value::as_str)
            .context("cargo metadata package missing name")?;
        if !INTEGRATION_PACKAGES.contains(&name) {
            continue;
        }
        seen_packages.insert(name);
        let targets = package
            .get("targets")
            .and_then(Value::as_array)
            .context("cargo metadata package missing targets")?;
        for target in targets {
            let target_name = target
                .get("name")
                .and_then(Value::as_str)
                .context("cargo metadata target missing name")?;
            let kinds = target
                .get("kind")
                .and_then(Value::as_array)
                .context("cargo metadata target missing kind")?;
            for kind in kinds.iter().filter_map(Value::as_str) {
                if matches!(kind, "lib" | "test") {
                    actual.insert((name.to_owned(), target_name.to_owned(), kind.to_owned()));
                }
            }
        }
    }
    let missing_packages: Vec<_> = INTEGRATION_PACKAGES
        .iter()
        .copied()
        .filter(|package| !seen_packages.contains(package))
        .collect();
    if !missing_packages.is_empty() {
        bail!("cargo metadata missing legacy integration packages: {missing_packages:?}");
    }
    Ok(actual)
}

pub(crate) fn validate_metadata(metadata: &Value) -> Result<()> {
    let expected = expected_targets()?;
    let actual = metadata_targets(metadata)?;
    let unassigned: Vec<_> = actual.difference(&expected).cloned().collect();
    let stale: Vec<_> = expected.difference(&actual).cloned().collect();
    if !unassigned.is_empty() || !stale.is_empty() {
        bail!("integration shard coverage mismatch; unassigned={unassigned:?}; stale={stale:?}");
    }
    Ok(())
}

pub(crate) fn validate_workspace(root: &Path) -> Result<()> {
    validate_integration_unit_catalog(INTEGRATION_UNIT_SPECS, SHARD_SPECS)?;
    validate_local_feature_catalog(SHARD_SPECS)?;
    let output = crate::cmd::cargo_cmd(
        crate::cmd::CargoSubcommand::Metadata,
        &["--locked", "--no-deps", "--format-version", "1"],
        &[],
        Some(root),
    )
    .output()
    .context("execute cargo metadata for integration shard coverage")?;
    if !output.status.success() {
        bail!(
            "cargo metadata for integration shard coverage failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let metadata = serde_json::from_slice(&output.stdout)
        .context("parse cargo metadata for integration shard coverage")?;
    validate_metadata(&metadata)?;
    let nextest_config = std::fs::read_to_string(root.join(".config/nextest.toml"))
        .context("read committed nextest configuration")?;
    crate::nextest::validate_config(&nextest_config)
}

#[cfg(test)]
pub(crate) fn validate_current_workspace() -> Result<()> {
    validate_workspace(&workspace_root()?)
}

pub(crate) fn external_resource_present(resource: Resource) -> bool {
    fn nonempty(name: &str) -> bool {
        std::env::var_os(name).is_some_and(|value| !value.is_empty())
    }

    match resource {
        Resource::Postgres => {
            nonempty("RSS_TEST_ALLOW_EXTERNAL_POSTGRES")
                && ["PGHOST", "PGPORT", "PGDATABASE", "PGUSER", "PGPASSWORD"]
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

pub(crate) fn missing_external_resources(shard: IntegrationShard) -> Vec<Resource> {
    shard
        .spec()
        .resources
        .iter()
        .copied()
        .filter(|resource| !external_resource_present(*resource))
        .collect()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use serde_json::json;

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
        owner_drift[0].primary_owner =
            crate::execution_profiles::ExecutionProfile::IntegrationCritical;
        assert!(validate_integration_unit_catalog(&owner_drift, SHARD_SPECS).is_err());
        Ok(())
    }

    #[test]
    fn release_check_owns_the_exact_integration_catalog_and_critical_is_inactive() {
        let release =
            projected_integration_units(crate::execution_profiles::ExecutionProfile::ReleaseCheck)
                .map(|spec| spec.id)
                .collect::<BTreeSet<_>>();
        let expected = IntegrationUnitId::ALL.into_iter().collect::<BTreeSet<_>>();
        assert_eq!(release, expected);
        assert!(
            projected_integration_units(
                crate::execution_profiles::ExecutionProfile::IntegrationCritical,
            )
            .next()
            .is_none()
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
        assert!(LocalFeatureScope::ALL.into_iter().all(|scope| {
            scope.feature()
                == if scope == LocalFeatureScope::Mqtt {
                    "broker-tests"
                } else {
                    "integration"
                }
        }));
        validate_local_feature_catalog(SHARD_SPECS)?;

        let mut missing = SHARD_SPECS.to_vec();
        missing[IntegrationShard::EventTransport as usize].local_feature_scopes = &[];
        assert!(validate_local_feature_catalog(&missing).is_err());

        const UNKNOWN_UNITS: &[IntegrationUnitSpec] = &[IntegrationUnitSpec::new(
            IntegrationUnitId::AmqpIntegration,
            IntegrationShard::EventTransport,
            "new-integration-package",
            "integration",
            TargetKind::Test,
            Scheduling::Serial,
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
    #[allow(clippy::expect_used)] // reason: registry fixture must retain security-provider closeout unit.
    fn settingsonly_vault_backend_is_unique_serial_and_feature_enabled() {
        let spec = IntegrationShard::RuntimeHttpAuth.spec();
        assert!(spec.resources.contains(&Resource::Vault));
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
        let expected_serial = BTreeSet::from([
            ("postgres", "postgres"),
            ("postgres-migration", "postgres_migration"),
            ("journeys", "audit_list_tenant_entries_localtx_journey"),
            ("journeys", "identity_password_security_event_journey"),
            ("journeys", "identity_refresh_producer_transaction_journey"),
            ("journeys", "settings_secret_publish_localtx_journey"),
            ("runtime", "settings_secret_e2e"),
            ("amqp", "integration"),
            ("mqtt", "integration"),
            ("journeys", "amqp_consumer_at_least_once_journey"),
            ("journeys", "identity_login_audit_durable_journey"),
            ("journeys", "identityaudit_runtime"),
            ("runtime", "event_transport_durable_e2e"),
            ("settingsonly", "settingsonly"),
            ("runtime", "runtime"),
            ("runtime", "configs_ready_e2e"),
            ("runtime", "identity_login_wire_e2e"),
            ("runtime", "service_token_replay_e2e"),
            ("runtime", "wire_contract_e2e"),
            ("redis-adapter", "integration_claimer"),
            ("testkit", "testkit"),
            ("testkit", "postgres_test_login_governance"),
            ("journeys-fault-matrix", "consistency_fault_matrix_journey"),
            ("runtime", "settings_config_publish_durable_e2e"),
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
            let plan = batches(*shard);
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
        let batch = postgres_transaction_journey_execution_batch()?;
        assert_eq!(batch.scheduling, Scheduling::Serial);
        assert_eq!(batch.kind, TargetKind::Test);
        assert_eq!(batch.package, "journeys");
        assert_eq!(batch.targets, POSTGRES_TRANSACTION_JOURNEY_TARGETS);
        Ok(())
    }

    #[test]
    fn localtx_backend_execution_unit_is_unique() -> Result<()> {
        let unit = localtx_backend_execution_unit()?;
        assert_eq!(unit.package, LocalFeatureScope::Postgres.package());
        assert_eq!(unit.target, unit.package);
        assert_eq!(unit.kind, TargetKind::Lib);
        assert_eq!(unit.scheduling, Scheduling::Serial);
        Ok(())
    }

    #[test]
    fn localtx_backend_execution_unit_rejects_missing_duplicate_and_drift() -> Result<()> {
        let expected = localtx_backend_execution_unit()?;
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
            assert_eq!(shard.spec().resources, resources);
            assert!(!shard.spec().units.is_empty());
        }
        assert!(IntegrationShard::ProductionRuntime.requires_docker());
        assert!(!IntegrationShard::CdcProjectionSaga.requires_docker());
    }

    #[test]
    fn cdc_projection_saga_contains_only_executable_tests() {
        let spec = IntegrationShard::CdcProjectionSaga.spec();
        assert!(
            spec.units.iter().all(|unit| unit.kind == TargetKind::Test),
            "cdc projection/saga must not keep an empty carrier-only lib target"
        );
    }

    fn metadata_from(targets: &[IntegrationUnitSpec]) -> Value {
        let mut packages: BTreeMap<&str, Vec<&IntegrationUnitSpec>> = BTreeMap::new();
        for unit in targets {
            packages.entry(unit.package).or_default().push(unit);
        }
        json!({
            "packages": INTEGRATION_PACKAGES.iter().map(|package| {
                let package_targets = packages.get(package).cloned().unwrap_or_default();
                json!({
                    "name": package,
                    "targets": package_targets.into_iter().map(|unit| json!({
                        "name": unit.target,
                        "kind": [unit.kind.as_str()],
                    })).collect::<Vec<_>>()
                })
            }).collect::<Vec<_>>()
        })
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
        validate_metadata(&metadata_from(&units))?;

        let mut missing = units.clone();
        missing.pop();
        assert!(validate_metadata(&metadata_from(&missing)).is_err());

        let mut unknown = units;
        unknown.push(IntegrationUnitSpec::new(
            IntegrationUnitId::RuntimeInventoryJourney,
            IntegrationShard::ProductionRuntime,
            "runtime",
            "new_unclassified_target",
            TargetKind::Test,
            Scheduling::Parallel,
        ));
        assert!(validate_metadata(&metadata_from(&unknown)).is_err());

        let mut duplicate = all_units();
        duplicate.push(duplicate[0]);
        assert!(unique_targets(duplicate).is_err());
        Ok(())
    }

    #[test]
    fn workspace_metadata_covers_legacy_integration_targets() -> Result<()> {
        validate_current_workspace()
    }

    #[test]
    fn live_minio_target_is_owned_by_the_object_storage_shard() {
        let spec = IntegrationShard::ObjectStorage.spec();
        assert_eq!(spec.resources, [Resource::ObjectStorage]);
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
            spec.resources.is_empty(),
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
}
