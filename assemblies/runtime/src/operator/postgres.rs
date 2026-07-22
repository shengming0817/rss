#![forbid(unused_imports)]
#![forbid(clippy::wildcard_imports)]

use anyhow::Context as _;
use postgres::PgRuntimeDeps;

use crate::infra::pg::build_pg_migrator_config;
use crate::phase::OperatorRuntimeInputs;

/// `rss` binary 是否请求 PostgreSQL operator namespace；具体 subcommand 由 runner 精确校验。
#[must_use]
pub fn is_postgres_command(args: &[String]) -> bool {
    matches!(args, [namespace, ..] if namespace == "postgres")
}

/// Run the release-only reader-lane migration without constructing serving pools or requiring
/// reader credentials. The postgres adapter independently verifies the exact embedded/ledger edge.
pub async fn run_postgres_reader_migration_command(
    args: &[String],
    runtime_inputs: &OperatorRuntimeInputs,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        matches!(args, [namespace, command] if namespace == "postgres" && command == "migrate-reader-lane"),
        "usage: rss postgres migrate-reader-lane"
    );
    PgRuntimeDeps::migrate_reader_lane_only(&build_pg_migrator_config(runtime_inputs.config())?)
        .await
        .context("apply exact postgres 0066 to 0067 reader-lane migration")
}
