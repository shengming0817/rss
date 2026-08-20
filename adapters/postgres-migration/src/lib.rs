//! Forward-only PostgreSQL migration operator.
//!
//! This crate is intentionally absent from every serving assembly graph. It is the only crate that
//! embeds SQL migration text or can invoke SQLx's migration executor.
//!
//! ref: launchbadge/sqlx sqlx-core/src/migrate/migrator.rs@v0.8.6
//! ref: launchbadge/sqlx sqlx-core/src/migrate/migration.rs@v0.8.6

use std::path::{Path, PathBuf};
use std::str::FromStr as _;

use rustls::RootCertStore;
use rustls_pki_types::CertificateDer;
use rustls_pki_types::pem::PemObject as _;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode};
use sqlx_core::net::tls::{ExclusiveExplicitRoots, exclusive_explicit_roots};
use tracing::Instrument as _;
use zeroize::Zeroizing;

const DATABASE_URL_FILE_ENV: &str = "RSS_PG_DATABASE_URL_FILE";
const REMOVED_DATABASE_URL_ENV: &str = "RSS_PG_DATABASE_URL";

#[derive(Debug, thiserror::Error)]
pub enum MigrationError {
    #[error("missing required postgres migration environment: {name}")]
    MissingEnvironment { name: &'static str },
    #[error("invalid postgres migration environment: {name}")]
    InvalidEnvironment { name: &'static str },
    #[error("postgres migration secret file cannot be read")]
    SecretFile(#[source] std::io::Error),
    #[error("postgres migration database URL file is invalid")]
    InvalidDatabaseUrl(#[source] sqlx::Error),
    #[error("postgres migration database URL must use sslmode=verify-full")]
    WeakTransport,
    #[error("postgres migration database URL must contain exactly one sslrootcert path")]
    MissingPrivateCa,
    #[error("postgres migration sslrootcert path is invalid")]
    InvalidPrivateCaPath,
    #[error("postgres migration private CA file cannot be read")]
    PrivateCaFile(#[source] std::io::Error),
    #[error("postgres migration private CA PEM is invalid")]
    InvalidPrivateCa,
    #[error("postgres migration connection failed")]
    Connect(#[source] sqlx::Error),
    #[error("postgres migration failed")]
    Migrate(#[source] sqlx::migrate::MigrateError),
    #[error("postgres migration ledger probe failed")]
    LedgerProbe(#[source] sqlx::Error),
    #[error("postgres projection input binding registration failed")]
    ProjectionBindings(#[source] sqlx::Error),
    #[error("postgres migration phase found legacy plaintext config rows: count={count}")]
    LegacyPlaintextPresent { count: i64 },
    #[error(
        "postgres migration ledger mismatch: expected_head={expected_head:?} actual_head={actual_head:?} expected_entries={expected_entries} actual_entries={actual_entries} first_invalid={first_invalid:?}"
    )]
    LedgerMismatch {
        expected_head: Option<i64>,
        actual_head: Option<i64>,
        expected_entries: usize,
        actual_entries: usize,
        first_invalid: Option<i64>,
    },
}

struct MigrationConfig {
    options: PgConnectOptions,
    _exclusive_roots: ExclusiveExplicitRoots,
}

impl MigrationConfig {
    fn from_process_environment() -> Result<Self, MigrationError> {
        Self::from_getter(|name| std::env::var(name).ok())
    }

    fn from_getter(get: impl Fn(&str) -> Option<String>) -> Result<Self, MigrationError> {
        let required = |name: &'static str| {
            get(name)
                .filter(|value| !value.trim().is_empty())
                .ok_or(MigrationError::MissingEnvironment { name })
        };
        if get(REMOVED_DATABASE_URL_ENV).is_some() {
            return Err(MigrationError::InvalidEnvironment {
                name: REMOVED_DATABASE_URL_ENV,
            });
        }
        let url_path = PathBuf::from(required(DATABASE_URL_FILE_ENV)?);
        if !url_path.is_absolute()
            || url_path
                .components()
                .any(|component| matches!(component, std::path::Component::ParentDir))
        {
            return Err(MigrationError::InvalidEnvironment {
                name: DATABASE_URL_FILE_ENV,
            });
        }
        let url = read_secret_file(&url_path)?;
        let mut options = PgConnectOptions::from_str(url.as_str())
            .map_err(MigrationError::InvalidDatabaseUrl)?
            .application_name("rss-postgres-migrate-all");
        if !matches!(options.get_ssl_mode(), PgSslMode::VerifyFull) {
            return Err(MigrationError::WeakTransport);
        }
        let ca_pem = private_ca_pem_from_database_url(url.as_str())?;
        options = options.ssl_root_cert_from_pem(ca_pem);
        Ok(Self {
            options,
            _exclusive_roots: exclusive_explicit_roots(),
        })
    }

    fn connect_options(&self) -> PgConnectOptions {
        self.options.clone()
    }
}

fn private_ca_pem_from_database_url(url: &str) -> Result<Vec<u8>, MigrationError> {
    let parsed = url::Url::parse(url).map_err(|_| MigrationError::InvalidPrivateCaPath)?;
    let root_paths = parsed
        .query_pairs()
        .filter_map(|(key, value)| (key == "sslrootcert").then_some(value.into_owned()))
        .collect::<Vec<_>>();
    let [root_path] = root_paths.as_slice() else {
        return Err(MigrationError::MissingPrivateCa);
    };
    let path = PathBuf::from(root_path.trim());
    if root_path.trim().is_empty()
        || !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(MigrationError::InvalidPrivateCaPath);
    }
    let metadata = std::fs::metadata(&path).map_err(MigrationError::PrivateCaFile)?;
    if !metadata.is_file() {
        return Err(MigrationError::InvalidPrivateCaPath);
    }
    let pem = std::fs::read(path).map_err(MigrationError::PrivateCaFile)?;
    let certificates = CertificateDer::pem_slice_iter(&pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| MigrationError::InvalidPrivateCa)?;
    if certificates.is_empty() {
        return Err(MigrationError::InvalidPrivateCa);
    }
    let mut roots = RootCertStore::empty();
    for certificate in certificates {
        roots
            .add(certificate.into_owned())
            .map_err(|_| MigrationError::InvalidPrivateCa)?;
    }
    Ok(pem)
}

fn read_secret_file(path: &Path) -> Result<Zeroizing<String>, MigrationError> {
    let mut value =
        Zeroizing::new(std::fs::read_to_string(path).map_err(MigrationError::SecretFile)?);
    let trimmed_len = value.trim_end_matches(['\r', '\n']).len();
    value.truncate(trimmed_len);
    if value.is_empty() {
        return Err(MigrationError::InvalidEnvironment {
            name: DATABASE_URL_FILE_ENV,
        });
    }
    Ok(value)
}

/// Apply every embedded forward migration and then require an exact successful SQLx ledger.
pub async fn migrate_all_from_process_environment() -> Result<(), MigrationError> {
    let config = MigrationConfig::from_process_environment()?;
    migrate_all(&config).await
}

async fn migrate_all(config: &MigrationConfig) -> Result<(), MigrationError> {
    let span = tracing::info_span!(target: "postgres-migration", "migrate_all");
    migrate_all_inner(config).instrument(span).await
}

async fn migrate_all_inner(config: &MigrationConfig) -> Result<(), MigrationError> {
    tracing::info!(
        target: "postgres-migration",
        migration_head = postgres_migration_inventory::MIGRATION_HEAD_FINGERPRINT,
        "postgres migrate-all started"
    );
    let pool = connect(config).await?;
    let migrator = embedded_migrator();
    let result = run_and_verify(&pool, &migrator).await;
    close_and_report(pool, result).await
}

fn embedded_migrator() -> sqlx::migrate::Migrator {
    sqlx::migrate!("../postgres/migrations")
}

async fn close_and_report(
    pool: sqlx::PgPool,
    result: Result<(), MigrationError>,
) -> Result<(), MigrationError> {
    pool.close().await;
    if result.is_ok() {
        tracing::info!(target: "postgres-migration", "postgres migrate-all completed");
    }
    result
}

async fn connect(config: &MigrationConfig) -> Result<sqlx::PgPool, MigrationError> {
    PgPoolOptions::new()
        .max_connections(1)
        .connect_with(config.connect_options())
        .await
        .inspect_err(|error| {
            tracing::error!(
                target: "postgres-migration",
                error = %secure::redact_error(error),
                "postgres migration connection failed"
            );
        })
        .map_err(MigrationError::Connect)
}

async fn run_and_verify(
    pool: &sqlx::PgPool,
    migrator: &sqlx::migrate::Migrator,
) -> Result<(), MigrationError> {
    migrator
        .run(pool)
        .await
        .inspect_err(|error| {
            tracing::error!(
                target: "postgres-migration",
                error = %secure::redact_error(error),
                "postgres migrate-all failed"
            );
        })
        .map_err(MigrationError::Migrate)?;
    verify_exact_ledger(pool).await?;
    verify_legacy_plaintext_zero_stock(pool).await?;
    register_projection_input_bindings(pool).await
}

async fn register_projection_input_bindings(pool: &sqlx::PgPool) -> Result<(), MigrationError> {
    let mut tx = pool
        .begin()
        .await
        .map_err(MigrationError::ProjectionBindings)?;
    for binding in postgres_migration_inventory::projection_inputs() {
        sqlx::query(
            "SELECT public.rss_register_projection_input_binding($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        )
            .bind(postgres_migration_inventory::projection_input_generation())
            .bind(binding.projection_id())
            .bind(binding.projection_definition_version())
            .bind(binding.projection_definition_schema_digest())
            .bind(binding.domain())
            .bind(binding.contract_id())
            .bind(binding.version())
            .bind(binding.schema_hash())
            .bind(binding.topic())
            .execute(&mut *tx)
            .await
            .map_err(MigrationError::ProjectionBindings)?;
    }
    tx.commit()
        .await
        .map_err(MigrationError::ProjectionBindings)
}

async fn verify_exact_ledger(pool: &sqlx::PgPool) -> Result<(), MigrationError> {
    let applied: Vec<(i64, bool, Vec<u8>)> = sqlx::query_as(
        "SELECT version, success, checksum FROM public._sqlx_migrations ORDER BY version",
    )
    .fetch_all(pool)
    .await
    .map_err(MigrationError::LedgerProbe)?;
    validate_exact_ledger(&applied)
}

async fn verify_legacy_plaintext_zero_stock(pool: &sqlx::PgPool) -> Result<(), MigrationError> {
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM public.config_entries WHERE protection_scheme = 0",
    )
    .fetch_one(pool)
    .await
    .map_err(MigrationError::LedgerProbe)?;
    if count == 0 {
        Ok(())
    } else {
        Err(MigrationError::LegacyPlaintextPresent { count })
    }
}

fn validate_exact_ledger(applied: &[(i64, bool, Vec<u8>)]) -> Result<(), MigrationError> {
    validate_ledger_against(applied, postgres_migration_inventory::migrations())
}

fn validate_ledger_against(
    applied: &[(i64, bool, Vec<u8>)],
    expected: &[postgres_migration_inventory::MigrationIdentity],
) -> Result<(), MigrationError> {
    let first_invalid =
        applied
            .iter()
            .zip(expected)
            .find_map(|((version, success, checksum), migration)| {
                (!*success
                    || *version != migration.version
                    || checksum.as_slice() != migration.checksum)
                    .then_some(*version)
            });
    let exact = applied.len() == expected.len() && first_invalid.is_none();
    if exact {
        Ok(())
    } else {
        let expected_head = expected.last().map(|migration| migration.version);
        let actual_head = applied.last().map(|(version, _, _)| *version);
        tracing::error!(
            target: "postgres-migration",
            expected_head,
            actual_head,
            expected_entries = expected.len(),
            actual_entries = applied.len(),
            first_invalid,
            "postgres migration ledger does not match embedded HEAD"
        );
        Err(MigrationError::LedgerMismatch {
            expected_head,
            actual_head,
            expected_entries: expected.len(),
            actual_entries: applied.len(),
            first_invalid,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    #[test]
    fn sqlx_executor_matches_the_single_typed_inventory() {
        let migrator = embedded_migrator();
        let embedded = migrator
            .iter()
            .filter(|migration| !migration.migration_type.is_down_migration())
            .collect::<Vec<_>>();
        let inventory = postgres_migration_inventory::migrations();
        assert_eq!(embedded.len(), inventory.len());
        for (actual, expected) in embedded.into_iter().zip(inventory) {
            assert_eq!(actual.version, expected.version);
            assert_eq!(actual.checksum.as_ref(), expected.checksum);
        }
    }

    fn base(path: &Path) -> HashMap<&'static str, String> {
        HashMap::from([(DATABASE_URL_FILE_ENV, path.display().to_string())])
    }

    #[allow(clippy::expect_used)]
    fn write_private_ca(label: &str) -> PathBuf {
        use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};

        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let key = KeyPair::generate().expect("generate CA key");
        let pem = params.self_signed(&key).expect("self-sign CA").pem();
        let path = std::env::temp_dir().join(format!(
            "rss-postgres-migration-{label}-{}-ca.pem",
            std::process::id()
        ));
        std::fs::write(&path, pem).expect("write CA fixture");
        path
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn database_url_is_file_only_and_trailing_newline_is_removed() {
        let path = std::env::temp_dir().join(format!(
            "rss-postgres-migration-secret-{}",
            std::process::id()
        ));
        let ca_path = write_private_ca("valid-url");
        std::fs::write(
            &path,
            format!(
                "postgres://rss_migrator:secret-value@postgres.internal:5432/rss?sslmode=verify-full&sslrootcert={}\n",
                ca_path.display()
            ),
        )
        .expect("write secret fixture");
        let values = base(&path);
        let config = MigrationConfig::from_getter(|name| values.get(name).cloned())
            .expect("file-backed migration config");
        assert!(format!("{:?}", config.connect_options()).contains("rss_migrator"));
        std::fs::remove_file(path).expect("remove secret fixture");
        std::fs::remove_file(ca_path).expect("remove CA fixture");
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn verify_full_database_url_requires_one_valid_absolute_private_ca() {
        let url_file = std::env::temp_dir().join(format!(
            "rss-postgres-migration-root-policy-{}",
            std::process::id()
        ));
        let ca_path = write_private_ca("root-policy");
        let directory_path = std::env::temp_dir().join(format!(
            "rss-postgres-migration-root-directory-{}",
            std::process::id()
        ));
        let empty_path = std::env::temp_dir().join(format!(
            "rss-postgres-migration-empty-root-{}",
            std::process::id()
        ));
        let malformed_path = std::env::temp_dir().join(format!(
            "rss-postgres-migration-malformed-root-{}",
            std::process::id()
        ));
        let missing_path = std::env::temp_dir().join(format!(
            "rss-postgres-migration-missing-root-{}",
            std::process::id()
        ));
        std::fs::create_dir(&directory_path).expect("create directory root fixture");
        std::fs::write(&empty_path, []).expect("write empty root fixture");
        std::fs::write(
            &malformed_path,
            b"-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----\n",
        )
        .expect("write malformed root fixture");
        let cases = [
            (
                "postgres://rss_migrator:secret@postgres.internal/rss?sslmode=verify-full"
                    .to_owned(),
                "missing",
            ),
            (
                format!(
                    "postgres://rss_migrator:secret@postgres.internal/rss?sslmode=verify-full&sslrootcert={}&sslrootcert={}",
                    ca_path.display(),
                    ca_path.display()
                ),
                "duplicate",
            ),
            (
                "postgres://rss_migrator:secret@postgres.internal/rss?sslmode=verify-full&sslrootcert=relative/ca.pem"
                    .to_owned(),
                "relative",
            ),
            (
                format!(
                    "postgres://rss_migrator:secret@postgres.internal/rss?sslmode=verify-full&sslrootcert={}",
                    directory_path.display()
                ),
                "directory",
            ),
            (
                format!(
                    "postgres://rss_migrator:secret@postgres.internal/rss?sslmode=verify-full&sslrootcert={}",
                    empty_path.display()
                ),
                "empty",
            ),
            (
                format!(
                    "postgres://rss_migrator:secret@postgres.internal/rss?sslmode=verify-full&sslrootcert={}",
                    malformed_path.display()
                ),
                "malformed",
            ),
            (
                format!(
                    "postgres://rss_migrator:secret@postgres.internal/rss?sslmode=verify-full&sslrootcert={}",
                    missing_path.display()
                ),
                "missing file",
            ),
        ];
        for (url, label) in cases {
            std::fs::write(&url_file, url).expect("write URL fixture");
            let values = base(&url_file);
            let error = MigrationConfig::from_getter(|name| values.get(name).cloned())
                .err()
                .expect("invalid root policy must fail");
            assert!(
                matches!(
                    error,
                    MigrationError::MissingPrivateCa
                        | MigrationError::InvalidPrivateCaPath
                        | MigrationError::PrivateCaFile(_)
                        | MigrationError::InvalidPrivateCa
                ),
                "unexpected {label} error: {error}"
            );
        }
        std::fs::remove_file(url_file).expect("remove URL fixture");
        std::fs::remove_file(ca_path).expect("remove CA fixture");
        std::fs::remove_dir(directory_path).expect("remove directory root fixture");
        std::fs::remove_file(empty_path).expect("remove empty root fixture");
        std::fs::remove_file(malformed_path).expect("remove malformed root fixture");
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn database_url_rejects_every_transport_weaker_than_verify_full() {
        for (index, suffix) in [
            "",
            "?sslmode=disable",
            "?sslmode=prefer",
            "?sslmode=require",
            "?sslmode=verify-ca",
        ]
        .into_iter()
        .enumerate()
        {
            let path = std::env::temp_dir().join(format!(
                "rss-postgres-migration-weak-transport-{}-{index}",
                std::process::id()
            ));
            std::fs::write(
                &path,
                format!("postgres://rss_migrator:secret@postgres.internal/rss{suffix}"),
            )
            .expect("write weak transport fixture");
            let values = base(&path);
            assert!(matches!(
                MigrationConfig::from_getter(|name| values.get(name).cloned()),
                Err(MigrationError::WeakTransport)
            ));
            std::fs::remove_file(path).expect("remove weak transport fixture");
        }
    }

    #[test]
    fn raw_database_url_environment_and_dual_source_are_rejected() {
        let path = std::env::temp_dir().join("rss-postgres-missing-secret");
        let mut values = base(&path);
        values.insert(REMOVED_DATABASE_URL_ENV, "forbidden".to_owned());
        for file_present in [true, false] {
            if !file_present {
                values.remove(DATABASE_URL_FILE_ENV);
            }
            assert!(matches!(
                MigrationConfig::from_getter(|name| values.get(name).cloned()),
                Err(MigrationError::InvalidEnvironment {
                    name: REMOVED_DATABASE_URL_ENV
                })
            ));
        }
    }

    #[test]
    fn relative_database_url_path_is_rejected_before_file_access() {
        let values = base(Path::new("relative/secret"));
        assert!(matches!(
            MigrationConfig::from_getter(|name| values.get(name).cloned()),
            Err(MigrationError::InvalidEnvironment {
                name: DATABASE_URL_FILE_ENV
            })
        ));
    }

    fn two_migration_head() -> [postgres_migration_inventory::MigrationIdentity; 2] {
        [
            postgres_migration_inventory::MigrationIdentity {
                version: 1,
                checksum: [1; 48],
            },
            postgres_migration_inventory::MigrationIdentity {
                version: 2,
                checksum: [2; 48],
            },
        ]
    }

    #[test]
    fn stale_ahead_fork_failed_and_checksum_ledgers_are_actionable()
    -> Result<(), Box<dyn std::error::Error>> {
        let expected = two_migration_head();
        let exact = expected
            .iter()
            .map(|migration| (migration.version, true, migration.checksum.to_vec()))
            .collect::<Vec<_>>();
        assert!(validate_ledger_against(&exact, &expected).is_ok());

        let mut cases = vec![
            ("stale", exact[..1].to_vec(), None),
            (
                "ahead",
                {
                    let mut value = exact.clone();
                    value.push((3, true, vec![3]));
                    value
                },
                None,
            ),
            (
                "fork",
                {
                    let mut value = exact.clone();
                    value[1].0 = 3;
                    value
                },
                Some(3),
            ),
            (
                "failed",
                {
                    let mut value = exact.clone();
                    value[1].1 = false;
                    value
                },
                Some(2),
            ),
            (
                "checksum",
                {
                    let mut value = exact.clone();
                    value[1].2[0] ^= 0xff;
                    value
                },
                Some(2),
            ),
        ];
        for (name, ledger, expected_invalid) in cases.drain(..) {
            let Err(error) = validate_ledger_against(&ledger, &expected) else {
                return Err(format!("{name}: ledger drift was accepted").into());
            };
            let MigrationError::LedgerMismatch { first_invalid, .. } = &error else {
                return Err(format!("{name}: unexpected error: {error}").into());
            };
            assert_eq!(*first_invalid, expected_invalid, "{name}");
            assert!(error.to_string().contains("expected_head=Some(2)"));
        }
        Ok(())
    }
}

#[cfg(all(test, feature = "integration"))]
mod integration_tests {
    use super::*;
    use sqlx::migrate::Migrate as _;

    type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;
    type HarnessResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

    struct TlsMigrationHarness {
        _fixture: testkit::PgTlsFixture,
        _network: testkit::BridgeNetwork,
        config: MigrationConfig,
        url_path: PathBuf,
        ca_path: PathBuf,
    }

    impl Drop for TlsMigrationHarness {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.url_path);
            let _ = std::fs::remove_file(&self.ca_path);
        }
    }

    fn config_from_tls_fixture(
        params: &testkit::PgConnParams,
        ca_pem: &str,
        label: &str,
    ) -> HarnessResult<(MigrationConfig, PathBuf, PathBuf)> {
        let suffix = format!("{}-{label}", std::process::id());
        let ca_path = std::env::temp_dir().join(format!("rss-migration-{suffix}-ca.pem"));
        let url_path = std::env::temp_dir().join(format!("rss-migration-{suffix}-url"));
        std::fs::write(&ca_path, ca_pem)?;
        let mut url = url::Url::parse(&format!(
            "postgres://{}:{}@{}:{}/{}",
            params.username, params.password, params.host, params.port, params.database
        ))?;
        url.query_pairs_mut()
            .append_pair("sslmode", "verify-full")
            .append_pair("sslrootcert", &ca_path.display().to_string());
        std::fs::write(&url_path, url.as_str())?;
        let config = MigrationConfig::from_getter(|name| {
            (name == DATABASE_URL_FILE_ENV).then(|| url_path.display().to_string())
        })?;
        Ok((config, url_path, ca_path))
    }

    async fn tls_harness(label: &str) -> HarnessResult<TlsMigrationHarness> {
        let network = testkit::bridge_network(&format!("rss-pg-migration-{label}")).await?;
        let dns_name = format!("{}-postgres", network.name());
        let fixture = testkit::postgres_tls(testkit::NetworkAttachment {
            network: network.name(),
            dns_name: &dns_name,
        })
        .await?;
        let (config, url_path, ca_path) =
            config_from_tls_fixture(fixture.params(), fixture.ca_pem(), label)?;
        Ok(TlsMigrationHarness {
            _fixture: fixture,
            _network: network,
            config,
            url_path,
            ca_path,
        })
    }

    async fn connection_pool(config: &MigrationConfig) -> Result<sqlx::PgPool, sqlx::Error> {
        PgPoolOptions::new()
            .max_connections(1)
            .connect_with(config.connect_options())
            .await
    }

    fn mismatch(result: Result<(), MigrationError>) -> TestResult {
        match result {
            Err(MigrationError::LedgerMismatch { .. }) => Ok(()),
            Err(other) => Err(other.into()),
            Ok(()) => Err("ledger drift was accepted".into()),
        }
    }

    async fn provision_closed_roles(pool: &sqlx::PgPool) -> Result<(), sqlx::Error> {
        for statement in [
            "CREATE ROLE rss_app NOLOGIN NOBYPASSRLS",
            "CREATE ROLE rss_app_read NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT",
        ] {
            sqlx::query(statement).execute(pool).await?;
        }
        Ok(())
    }

    async fn assert_closed_ledger_grants(pool: &sqlx::PgPool) -> TestResult {
        let grants: Vec<(String, String)> = sqlx::query_as(
            "SELECT grantee, privilege_type \
             FROM information_schema.table_privileges \
             WHERE table_schema = 'public' \
               AND table_name = '_sqlx_migrations' \
               AND grantee <> current_user \
             ORDER BY grantee, privilege_type",
        )
        .fetch_all(pool)
        .await?;
        assert_eq!(
            grants,
            vec![
                ("rss_app".to_owned(), "SELECT".to_owned()),
                ("rss_app_read".to_owned(), "SELECT".to_owned()),
                ("rss_l2_dr_recovery_auditor".to_owned(), "SELECT".to_owned(),),
                (
                    "rss_l2_dr_recovery_executor".to_owned(),
                    "SELECT".to_owned(),
                ),
                ("rss_projection_reader".to_owned(), "SELECT".to_owned()),
                ("rss_saga_operator".to_owned(), "SELECT".to_owned()),
            ]
        );
        Ok(())
    }

    async fn assert_generated_projection_bindings(pool: &sqlx::PgPool) -> TestResult {
        let rows: Vec<(String, String, String, String)> = sqlx::query_as(
            "SELECT contract_id, contract_version, schema_hash, topic \
             FROM public.projection_input_bindings WHERE generation = $1 ORDER BY contract_id",
        )
        .bind(postgres_migration_inventory::projection_input_generation())
        .fetch_all(pool)
        .await?;
        let mut expected = postgres_migration_inventory::projection_inputs()
            .iter()
            .map(|binding| {
                (
                    binding.contract_id().to_owned(),
                    binding.version().to_owned(),
                    binding.schema_hash().to_owned(),
                    binding.topic().to_owned(),
                )
            })
            .collect::<Vec<_>>();
        expected.sort();
        assert_eq!(
            rows, expected,
            "production migrator must register the generated binding set"
        );
        Ok(())
    }

    #[tokio::test]
    async fn empty_database_reaches_exact_head_and_all_ledger_drifts_fail_closed() -> TestResult {
        let harness = tls_harness("exact-head").await?;
        let config = &harness.config;
        let pool = connection_pool(config).await?;
        provision_closed_roles(&pool).await?;
        pool.close().await;
        migrate_all(config).await?;
        let pool = connection_pool(config).await?;
        let migrator = embedded_migrator();
        verify_exact_ledger(&pool).await?;
        assert_closed_ledger_grants(&pool).await?;
        assert_generated_projection_bindings(&pool).await?;

        let head = migrator
            .iter()
            .last()
            .ok_or("embedded migration head missing")?;
        let original_checksum: Vec<u8> =
            sqlx::query_scalar("SELECT checksum FROM public._sqlx_migrations WHERE version = $1")
                .bind(head.version)
                .fetch_one(&pool)
                .await?;

        sqlx::query("UPDATE public._sqlx_migrations SET checksum = decode(repeat('00', 48), 'hex') WHERE version = $1")
            .bind(head.version)
            .execute(&pool)
            .await?;
        mismatch(verify_exact_ledger(&pool).await)?;
        sqlx::query("UPDATE public._sqlx_migrations SET checksum = $1 WHERE version = $2")
            .bind(&original_checksum)
            .bind(head.version)
            .execute(&pool)
            .await?;

        sqlx::query("UPDATE public._sqlx_migrations SET version = $1 WHERE version = $2")
            .bind(head.version + 1)
            .bind(head.version)
            .execute(&pool)
            .await?;
        mismatch(verify_exact_ledger(&pool).await)?;
        sqlx::query("UPDATE public._sqlx_migrations SET version = $1 WHERE version = $2")
            .bind(head.version)
            .bind(head.version + 1)
            .execute(&pool)
            .await?;

        sqlx::query(
            "INSERT INTO public._sqlx_migrations \
             (version, description, installed_on, success, checksum, execution_time) \
             VALUES ($1, 'synthetic ahead', now(), true, $2, 0)",
        )
        .bind(head.version + 1)
        .bind(&original_checksum)
        .execute(&pool)
        .await?;
        mismatch(verify_exact_ledger(&pool).await)?;
        sqlx::query("DELETE FROM public._sqlx_migrations WHERE version = $1")
            .bind(head.version + 1)
            .execute(&pool)
            .await?;

        sqlx::query("DELETE FROM public._sqlx_migrations WHERE version = $1")
            .bind(head.version)
            .execute(&pool)
            .await?;
        mismatch(verify_exact_ledger(&pool).await)?;
        pool.close().await;
        Ok(())
    }

    #[tokio::test]
    async fn historical_ledger_is_advanced_by_the_production_operator() -> TestResult {
        let harness = tls_harness("historical-ledger").await?;
        let config = &harness.config;
        let pool = connection_pool(config).await?;
        provision_closed_roles(&pool).await?;
        let migrator = embedded_migrator();
        let mut connection = pool.acquire().await?;
        connection.ensure_migrations_table().await?;
        connection.lock().await?;
        let historical_len = migrator.iter().count().checked_sub(1).ok_or("empty head")?;
        for migration in migrator.iter().take(historical_len) {
            connection.apply(migration).await?;
        }
        connection.unlock().await?;
        drop(connection);
        pool.close().await;

        migrate_all(config).await?;
        let pool = connection_pool(config).await?;
        verify_exact_ledger(&pool).await?;
        assert_closed_ledger_grants(&pool).await?;
        assert_generated_projection_bindings(&pool).await?;
        pool.close().await;
        Ok(())
    }

    #[tokio::test]
    async fn migration_phase_rejects_legacy_plaintext_zero_stock_drift() -> TestResult {
        let harness = tls_harness("plaintext-drift").await?;
        let config = &harness.config;
        let pool = connection_pool(config).await?;
        provision_closed_roles(&pool).await?;
        pool.close().await;
        migrate_all(config).await?;

        let pool = connection_pool(config).await?;
        sqlx::query(
            "INSERT INTO public.config_entries \
             (tenant_id, config_key, version, value, protection_scheme) \
             VALUES ('00000000-0000-0000-0000-000000000001', \
                     'synthetic.legacy', 1, 'legacy-value', 0)",
        )
        .execute(&pool)
        .await?;
        pool.close().await;

        assert!(matches!(
            migrate_all(config).await,
            Err(MigrationError::LegacyPlaintextPresent { count: 1 })
        ));
        Ok(())
    }

    #[tokio::test]
    async fn production_tls_config_accepts_only_its_private_ca() -> TestResult {
        let harness = tls_harness("private-ca-policy").await?;
        let pool = connection_pool(&harness.config).await?;
        pool.close().await;

        let (wrong, wrong_url_path, wrong_ca_path) = config_from_tls_fixture(
            harness._fixture.params(),
            harness._fixture.wrong_ca_pem(),
            "wrong-private-ca-policy",
        )?;
        assert!(matches!(
            connect(&wrong).await,
            Err(MigrationError::Connect(_))
        ));
        std::fs::remove_file(wrong_url_path)?;
        std::fs::remove_file(wrong_ca_path)?;
        Ok(())
    }
}
