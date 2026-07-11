//! Integration capability shard registry and target-level execution plans.
//!
//! INVARIANT: INTEGRATION-SHARD-REGISTRY-01 { level = "Hard", exec = "native-compile", source = "code", native = "catalog macro generates the closed enum, ALL, lookup, resources, and execution units" }.
//! INVARIANT: INTEGRATION-SHARD-SELECTOR-01 { level = "Hard", exec = "native-compile", source = "code", native = "filtersets render only from typed package/binary/kind execution units" }.
//! INVARIANT: INTEGRATION-SHARD-COVERAGE-01 { level = "Medium", exec = "integration", source = "code", synthetic_red = "metadata_coverage_rejects_missing_duplicate_and_unknown_targets", anti_vacuity = "workspace_metadata_covers_legacy_integration_targets" }.
//! INVARIANT: INTEGRATION-SHARD-SCHEDULING-01 { level = "Medium", exec = "integration", source = "code", synthetic_red = "scheduling_plan_rejects_dangerous_target_parallelism", anti_vacuity = "workspace_plan_freezes_resources_and_dangerous_targets" }.

#[cfg(test)]
use crate::workspace_root;
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::Path;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Resource {
    Postgres,
    Redis,
    Amqp,
    Mqtt,
}

impl Resource {
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Postgres => "postgres",
            Self::Redis => "redis",
            Self::Amqp => "amqp",
            Self::Mqtt => "mqtt",
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
pub(crate) struct ExecutionUnit {
    pub(crate) package: &'static str,
    pub(crate) target: &'static str,
    pub(crate) kind: TargetKind,
    pub(crate) scheduling: Scheduling,
}

impl ExecutionUnit {
    const fn new(
        package: &'static str,
        target: &'static str,
        kind: TargetKind,
        scheduling: Scheduling,
    ) -> Self {
        Self {
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
    pub(crate) units: &'static [ExecutionUnit],
}

macro_rules! integration_shard_catalog {
    ($(
        $variant:ident => {
            name: $name:literal,
            resources: [$($resource:ident),* $(,)?],
            units: [$(($package:literal, $target:literal, $kind:ident, $scheduling:ident)),+ $(,)?],
        },
    )+) => {
        #[repr(usize)]
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
        #[serde(rename_all = "kebab-case")]
        pub(crate) enum IntegrationShard { $($variant),+ }

        const SHARD_SPECS: &[ShardSpec] = &[$(ShardSpec {
            shard: IntegrationShard::$variant,
            resources: &[$(Resource::$resource),*],
            units: &[$(ExecutionUnit::new(
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
        units: [
            ("postgres", "postgres", Lib, Serial),
            ("postgres", "tx_capability_trybuild", Test, Parallel),
            ("runtime", "settings_secret_e2e", Test, Serial),
        ],
    },
    EventTransport => {
        name: "event-transport",
        resources: [Postgres, Redis, Amqp, Mqtt],
        units: [
            ("amqp", "amqp", Lib, Parallel),
            ("amqp", "integration", Test, Serial),
            ("mqtt", "mqtt", Lib, Parallel),
            ("mqtt", "integration", Test, Serial),
            ("journeys", "amqp_consumer_at_least_once_journey", Test, Serial),
            ("journeys", "eventtransport_journey", Test, Parallel),
            ("journeys", "identity_login_audit_durable_journey", Test, Serial),
            ("journeys", "identity_login_audit_journey", Test, Parallel),
            ("runtime", "event_transport_durable_e2e", Test, Serial),
        ],
    },
    RuntimeHttpAuth => {
        name: "runtime-http-auth",
        resources: [Postgres, Redis],
        units: [
            ("runtime", "runtime", Lib, Serial),
            ("runtime", "auth_e2e", Test, Parallel),
            ("runtime", "configs_ready_e2e", Test, Serial),
            ("runtime", "identity_login_wire_e2e", Test, Serial),
            ("runtime", "infra_builders_api", Test, Parallel),
            ("runtime", "refresh_mint_e2e", Test, Parallel),
            ("runtime", "runtime_serve_e2e", Test, Parallel),
            ("runtime", "wire_contract_e2e", Test, Serial),
        ],
    },
    ConsistencyFault => {
        name: "consistency-fault",
        resources: [Postgres, Redis, Amqp],
        units: [
            ("redis-adapter", "redis", Lib, Parallel),
            ("redis-adapter", "integration_claimer", Test, Serial),
            ("journeys", "device_command_ack_timeout_journey", Test, Parallel),
            ("journeys-fault-matrix", "consistency_fault_matrix_journey", Test, Serial),
        ],
    },
    CdcProjectionSaga => {
        name: "cdc-projection-saga",
        resources: [Postgres],
        units: [
            ("journeys", "journeys", Lib, Parallel),
            ("journeys", "saga_projection_deps_journey", Test, Parallel),
            ("journeys", "settings_config_publish_journey", Test, Parallel),
            ("runtime", "settings_config_publish_durable_e2e", Test, Serial),
        ],
    },
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
            Self::PostgresDomain | Self::ConsistencyFault | Self::CdcProjectionSaga => {
                PartitionPolicy::Unpartitioned
            }
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
                    for unit in shard
                        .spec()
                        .units
                        .iter()
                        .copied()
                        .filter(|unit| unit.scheduling == scheduling && unit.kind == kind)
                    {
                        by_package.entry(unit.package).or_default().push(unit);
                    }
                    by_package.into_iter().map(move |(package, units)| {
                        let targets = units
                            .iter()
                            .map(|unit| unit.target)
                            .collect::<BTreeSet<_>>()
                            .into_iter()
                            .collect();
                        let filter = units
                            .into_iter()
                            .map(ExecutionUnit::filter)
                            .map(|filter| format!("({filter})"))
                            .collect::<Vec<_>>()
                            .join(" or ");
                        ShardBatch {
                            scheduling,
                            kind,
                            package,
                            targets,
                            filter,
                        }
                    })
                })
        })
        .collect()
}

const LEGACY_PACKAGES: &[&str] = &[
    "postgres",
    "redis-adapter",
    "amqp",
    "mqtt",
    "journeys",
    "runtime",
    "journeys-fault-matrix",
];

pub(crate) const STANDALONE_EXCLUSIONS: &[(&str, &str, TargetKind, &str)] = &[(
    "s3",
    "integration_object_store",
    TargetKind::Test,
    "requires an externally managed MinIO endpoint and was not in the legacy integration lane",
)];

type TargetId = (String, String, String);

fn unique_targets(units: impl IntoIterator<Item = ExecutionUnit>) -> Result<BTreeSet<TargetId>> {
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
    let expected = unique_targets(
        IntegrationShard::ALL
            .iter()
            .flat_map(|shard| shard.spec().units.iter().copied()),
    )?;
    for (package, target, _, reason) in STANDALONE_EXCLUSIONS {
        if reason.is_empty() {
            bail!("standalone integration exclusion {package}/{target} is missing a reason");
        }
        if expected.iter().any(|(p, t, _)| p == package && t == target) {
            bail!("standalone integration target also assigned to a shard: {package}/{target}");
        }
    }
    Ok(expected)
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
        if !LEGACY_PACKAGES.contains(&name) {
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
    let missing_packages: Vec<_> = LEGACY_PACKAGES
        .iter()
        .copied()
        .filter(|package| !seen_packages.contains(package))
        .collect();
    if !missing_packages.is_empty() {
        bail!("cargo metadata missing legacy integration packages: {missing_packages:?}");
    }
    Ok(actual)
}

fn all_metadata_targets(metadata: &Value) -> Result<BTreeSet<TargetId>> {
    let packages = metadata
        .get("packages")
        .and_then(Value::as_array)
        .context("cargo metadata JSON missing packages array")?;
    let mut actual = BTreeSet::new();
    for package in packages {
        let name = package
            .get("name")
            .and_then(Value::as_str)
            .context("cargo metadata package missing name")?;
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
    let all_actual = all_metadata_targets(metadata)?;
    let stale_exclusions: Vec<_> = STANDALONE_EXCLUSIONS
        .iter()
        .filter_map(|(package, target, kind, _)| {
            let id = (
                (*package).to_owned(),
                (*target).to_owned(),
                kind.as_str().to_owned(),
            );
            (!all_actual.contains(&id)).then_some(id)
        })
        .collect();
    if !stale_exclusions.is_empty() {
        bail!("standalone integration exclusions are stale: {stale_exclusions:?}");
    }
    Ok(())
}

pub(crate) fn validate_workspace(root: &Path) -> Result<()> {
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
        Resource::Mqtt => nonempty("RSS_MQTT_TEST_URL"),
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
    use super::*;
    use serde_json::json;

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
            ]
        );
        for shard in IntegrationShard::ALL {
            assert_eq!(shard.as_str().parse::<IntegrationShard>()?, *shard);
            assert_eq!(shard.spec().shard, *shard);
        }
        assert!("POSTGRES-DOMAIN".parse::<IntegrationShard>().is_err());
        assert!("unknown".parse::<IntegrationShard>().is_err());
        Ok(())
    }

    #[test]
    fn scheduling_plan_rejects_dangerous_target_parallelism() {
        let expected_serial = BTreeSet::from([
            ("postgres", "postgres"),
            ("runtime", "settings_secret_e2e"),
            ("amqp", "integration"),
            ("mqtt", "integration"),
            ("journeys", "amqp_consumer_at_least_once_journey"),
            ("journeys", "identity_login_audit_durable_journey"),
            ("runtime", "event_transport_durable_e2e"),
            ("runtime", "runtime"),
            ("runtime", "configs_ready_e2e"),
            ("runtime", "identity_login_wire_e2e"),
            ("runtime", "wire_contract_e2e"),
            ("redis-adapter", "integration_claimer"),
            ("journeys-fault-matrix", "consistency_fault_matrix_journey"),
            ("runtime", "settings_config_publish_durable_e2e"),
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
                &[Resource::Postgres, Resource::Redis][..],
            ),
            (
                IntegrationShard::ConsistencyFault,
                &[Resource::Postgres, Resource::Redis, Resource::Amqp][..],
            ),
            (
                IntegrationShard::CdcProjectionSaga,
                &[Resource::Postgres][..],
            ),
        ];
        assert_eq!(IntegrationShard::ALL.len(), expected.len());
        for (shard, resources) in expected {
            assert_eq!(shard.spec().resources, resources);
            assert!(!shard.spec().units.is_empty());
        }
    }

    fn metadata_from(targets: &[ExecutionUnit], include_standalone: bool) -> Value {
        let mut packages: BTreeMap<&str, Vec<&ExecutionUnit>> = BTreeMap::new();
        for unit in targets {
            packages.entry(unit.package).or_default().push(unit);
        }
        json!({
            "packages": LEGACY_PACKAGES.iter().map(|package| {
                let package_targets = packages.get(package).cloned().unwrap_or_default();
                json!({
                    "name": package,
                    "targets": package_targets.into_iter().map(|unit| json!({
                        "name": unit.target,
                        "kind": [unit.kind.as_str()],
                    })).collect::<Vec<_>>()
                })
            }).chain(include_standalone.then(|| json!({
                "name": "s3",
                "targets": [{"name": "integration_object_store", "kind": ["test"]}],
            }))).collect::<Vec<_>>()
        })
    }

    fn all_units() -> Vec<ExecutionUnit> {
        IntegrationShard::ALL
            .iter()
            .flat_map(|shard| shard.spec().units.iter().copied())
            .collect()
    }

    #[test]
    fn metadata_coverage_rejects_missing_duplicate_and_unknown_targets() -> Result<()> {
        let units = all_units();
        validate_metadata(&metadata_from(&units, true))?;

        let mut missing = units.clone();
        missing.pop();
        assert!(validate_metadata(&metadata_from(&missing, true)).is_err());

        let mut unknown = units;
        unknown.push(ExecutionUnit::new(
            "runtime",
            "new_unclassified_target",
            TargetKind::Test,
            Scheduling::Parallel,
        ));
        assert!(validate_metadata(&metadata_from(&unknown, true)).is_err());

        let mut duplicate = all_units();
        duplicate.push(duplicate[0]);
        assert!(unique_targets(duplicate).is_err());
        assert!(validate_metadata(&metadata_from(&all_units(), false)).is_err());
        Ok(())
    }

    #[test]
    fn workspace_metadata_covers_legacy_integration_targets() -> Result<()> {
        validate_current_workspace()
    }

    #[test]
    fn standalone_minio_target_is_not_smuggled_into_a_shard() {
        assert_eq!(STANDALONE_EXCLUSIONS.len(), 1);
        assert!(IntegrationShard::ALL.iter().all(|shard| {
            shard
                .spec()
                .units
                .iter()
                .all(|unit| !(unit.package == "s3" && unit.target == "integration_object_store"))
        }));
    }
}
