//! PG-TEST-OWNERSHIP-01: recursive structural backstop for the typed PostgreSQL fixture boundary.

use std::path::{Path, PathBuf};

const OLD_SURFACES: &[&str] = &[
    "PostgresTestLogin",
    "provision_postgres_test_logins",
    "setup_test_fixture(",
    "setup_test_fixture_with_projection_bindings(",
];

const CONSUMER_ROOTS: &[&str] = &[
    "adapters/postgres",
    "adapters/postgres-migration",
    "assemblies/runtime",
    "journeys",
    "journeys-fault-matrix",
];

fn workspace_root() -> Result<PathBuf, std::io::Error> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| {
            std::io::Error::other("testkit must remain under <workspace>/crates/testkit")
        })
}

fn rust_sources_under(root: &Path) -> Result<Vec<PathBuf>, std::io::Error> {
    let mut sources = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(path) = pending.pop() {
        for entry in std::fs::read_dir(&path)? {
            let entry = entry?;
            let file_type = entry.file_type()?;
            if file_type.is_symlink() {
                return Err(std::io::Error::other(format!(
                    "symlink rejected under {}: {}",
                    root.display(),
                    entry.path().display()
                )));
            }
            if file_type.is_dir() {
                pending.push(entry.path());
            } else if file_type.is_file() && entry.path().extension().is_some_and(|ext| ext == "rs")
            {
                sources.push(entry.path());
            }
        }
    }
    sources.sort();
    Ok(sources)
}

fn role_ddl(source: &str) -> bool {
    ["CREATE ROLE", "ALTER ROLE", "DROP ROLE"]
        .iter()
        .any(|needle| source.contains(needle))
}

fn migration_or_role_mutation(source: &str) -> bool {
    source.contains("run_migrations(")
        || source.contains("migrate_all(")
        || source.contains("setup_owned_test_fixture(")
        || source.contains("setup_owned_test_fixture_with_projection_bindings(")
        || role_ddl(source)
}

fn owned_proof_is_visible(source: &str) -> bool {
    [
        "OwnedPgFixture",
        "owned_postgres(",
        "into_owned(",
        "PgFixture::Owned(",
        "connect_pg(",
    ]
    .iter()
    .any(|marker| source.contains(marker))
}

fn calls_owner_mutation_entrypoint(source: &str) -> bool {
    source.contains("PgRuntimeDeps::setup_owned_test_fixture(")
        || source.contains("PgRuntimeDeps::setup_owned_test_fixture_with_projection_bindings(")
        || source.contains("migrate_all(")
}

fn braced_arm<'a>(source: &'a str, marker: &str) -> Option<&'a str> {
    let start = source.find(marker)?;
    let open = source[start..].find('{')? + start;
    let mut depth = 0_u32;
    for (offset, byte) in source[open..].bytes().enumerate() {
        match byte {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return source.get(open + 1..open + offset);
                }
            }
            _ => {}
        }
    }
    None
}

#[test]
fn old_postgres_fixture_surfaces_are_absent_recursively() -> Result<(), Box<dyn std::error::Error>>
{
    let root = workspace_root()?;
    for relative in CONSUMER_ROOTS {
        for path in rust_sources_under(&root.join(relative))? {
            let source = std::fs::read_to_string(&path)?;
            for old in OLD_SURFACES {
                assert!(
                    !source.contains(old),
                    "{} retains removed PostgreSQL test surface {old}",
                    path.display()
                );
            }
        }
    }
    Ok(())
}

#[test]
fn external_owner_credentials_and_common_mutation_paths_are_unrepresentable()
-> Result<(), Box<dyn std::error::Error>> {
    let root = workspace_root()?;
    let containers =
        std::fs::read_to_string(root.join("crates/testkit/src/containers/postgres.rs"))?;
    let parser_start = containers
        .find("fn postgres_external_endpoint_from_lookup")
        .ok_or("external endpoint parser must exist")?;
    let parser_end = containers[parser_start..]
        .find("\n/// postgres 连接参数")
        .map(|offset| parser_start + offset)
        .ok_or("external parser boundary must remain discoverable")?;
    let parser = &containers[parser_start..parser_end];
    assert!(!parser.contains("PGUSER"));
    assert!(!parser.contains("PGPASSWORD"));
    assert!(containers.contains("pub enum PgFixture"));
    assert!(containers.contains("Owned(OwnedPgFixture)"));
    assert!(containers.contains("External(ExternalPgFixture)"));
    assert!(containers.contains("pub fn owner_params(&self) -> &PgConnParams"));
    assert!(!containers.contains("impl PgFixture {\n    /// postgres 连接参数"));

    let test_pg = std::fs::read_to_string(root.join("adapters/postgres/src/test_pg.rs"))?;
    assert!(
        !role_ddl(&test_pg),
        "common adapter test connections must not own role DDL"
    );
    assert!(
        test_pg.contains("OwnedPgFixture"),
        "destructive adapter tests require the owned proof"
    );
    Ok(())
}

#[test]
fn provider_consumers_are_owned_before_migration_or_role_ddl()
-> Result<(), Box<dyn std::error::Error>> {
    let root = workspace_root()?;
    for relative in CONSUMER_ROOTS {
        for path in rust_sources_under(&root.join(relative))? {
            let source = std::fs::read_to_string(&path)?;
            let normalized = path.to_string_lossy().replace('\\', "/");
            if calls_owner_mutation_entrypoint(&source)
                && !normalized.ends_with("adapters/postgres/src/bundle.rs")
                && !normalized.ends_with("adapters/postgres/src/fault_matrix.rs")
            {
                assert!(
                    owned_proof_is_visible(&source),
                    "{} calls a migration entrypoint without a visible owned proof",
                    path.display()
                );
            }
            if source.contains("env_or_postgres(") && migration_or_role_mutation(&source) {
                if source.contains("PgFixture::External(") {
                    assert!(
                        source.contains("PgFixture::Owned("),
                        "{} must exhaustively split PostgreSQL ownership before mutation",
                        path.display()
                    );
                    let external = braced_arm(&source, "PgFixture::External(")
                        .expect("external fixture arm must have a closed body");
                    assert!(
                        !migration_or_role_mutation(external),
                        "{} routes external PostgreSQL into migration/role DDL",
                        path.display()
                    );
                    assert!(
                        external.contains("connect_prepared_test_fixture("),
                        "{} external branch must use the prepared exact-ledger path",
                        path.display()
                    );
                } else {
                    assert!(
                        source.contains(".into_owned()") || source.contains(".into_owned()?"),
                        "{} must consume an owned proof before mutation",
                        path.display()
                    );
                }
            }
        }
    }
    Ok(())
}

#[test]
fn synthetic_external_mutation_bait_is_rejected() {
    let bait = "testkit::PgFixture::External(_) => { store.run_migrations().await?; }";
    let external = braced_arm(bait, "PgFixture::External(").expect("synthetic external arm");
    assert!(migration_or_role_mutation(external));
    let laundered = "PgRuntimeDeps::setup_owned_test_fixture(&arbitrary_config, rest).await?;";
    assert!(calls_owner_mutation_entrypoint(laundered));
    assert!(!owned_proof_is_visible(laundered));
    assert!(role_ddl(
        "sqlx::query(\"ALTER ROLE rss_app PASSWORD 'bait'\")"
    ));
    assert!(!role_ddl("fixture.resolve_app_roles(specs).await?"));
}

#[cfg(feature = "containers")]
#[tokio::test]
async fn owned_resolver_rotates_quoted_credentials_and_enforces_fixed_attributes()
-> Result<(), Box<dyn std::error::Error>> {
    use sqlx::postgres::{PgConnectOptions, PgPoolOptions};

    let fixture = testkit::owned_postgres().await?;
    let params = fixture.owner_params();
    let role = "rss_test_login_\"quoted";
    fixture
        .resolve_app_roles([testkit::PgAppRoleSpec::new(role, "test_'quoted_password")])
        .await?;
    let rotated_password = "rotated_'quoted_password";
    let [login] = fixture
        .resolve_app_roles([testkit::PgAppRoleSpec::new(role, rotated_password)])
        .await?;

    let owner = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(
            PgConnectOptions::new()
                .host(&params.host)
                .port(params.port)
                .database(&params.database)
                .username(&params.username)
                .password(&params.password),
        )
        .await?;
    let attributes: (bool, bool, bool, bool, bool, bool, bool) = sqlx::query_as(
        "SELECT rolcanlogin, rolsuper, rolcreatedb, rolcreaterole, rolreplication, \
         rolbypassrls, rolinherit FROM pg_roles WHERE rolname = $1",
    )
    .bind(role)
    .fetch_one(&owner)
    .await?;
    assert_eq!(attributes, (true, false, false, false, false, false, false));

    let login_params = login.params();
    let app = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(
            PgConnectOptions::new()
                .host(&login_params.host)
                .port(login_params.port)
                .database(&login_params.database)
                .username(&login_params.username)
                .password(&login_params.password),
        )
        .await?;
    let current_user: String = sqlx::query_scalar("SELECT current_user")
        .fetch_one(&app)
        .await?;
    assert_eq!(current_user, role);
    app.close().await;
    owner.close().await;
    Ok(())
}
