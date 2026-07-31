//! PG-TEST-LOGIN-SINGLE-SOURCE-01 (Medium): recursive structural backstop keeps runtime login role
//! DDL in testkit and requires every known consumer to call the single entry exactly once.

use std::path::{Path, PathBuf};

const CALLERS: &[&str] = &[
    "adapters/postgres/src/integration_tests.rs",
    "assemblies/runtime/tests/configs_ready_e2e.rs",
    "assemblies/runtime/tests/event_transport_durable_e2e.rs",
    "assemblies/runtime/tests/identity_login_wire_e2e.rs",
    "assemblies/runtime/tests/settings_config_publish_durable_e2e.rs",
    "assemblies/runtime/tests/settings_secret_e2e.rs",
    "assemblies/runtime/tests/wire_contract_e2e.rs",
    "journeys/tests/identity_login_audit_durable_journey.rs",
    "journeys/tests/support/localtx_validation.rs",
    "journeys-fault-matrix/tests/consistency_fault_matrix_journey.rs",
];

const DDL_FREE_NON_CALLERS: &[&str] = &["adapters/postgres/src/fault_matrix.rs"];
const RECURSIVE_GOVERNANCE_ROOTS: &[&str] = &[
    "assemblies/runtime/tests",
    "journeys/tests",
    "journeys-fault-matrix/tests",
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
        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            let file_type = entry.file_type()?;
            if file_type.is_dir() {
                pending.push(entry.path());
            } else if file_type.is_file() && entry.path().extension().is_some_and(|ext| ext == "rs")
            {
                sources.push(entry.path());
            }
        }
    }
    Ok(sources)
}

fn owns_runtime_login_ddl(source: &str) -> bool {
    (source.contains("rss_app") || source.contains("rss_app_read"))
        && (source.contains("CREATE ROLE") || source.contains("ALTER ROLE"))
}

fn function_source<'a>(source: &'a str, signature: &str) -> Option<&'a str> {
    let start = source.find(signature)?;
    let remaining = &source[start + signature.len()..];
    let end = remaining.find("\nasync fn ").unwrap_or(remaining.len());
    Some(&source[start..start + signature.len() + end])
}

#[test]
fn postgres_test_login_ddl_has_one_source() -> Result<(), Box<dyn std::error::Error>> {
    let root = workspace_root()?;
    for relative in CALLERS.iter().chain(DDL_FREE_NON_CALLERS) {
        let source = std::fs::read_to_string(root.join(relative))?;
        if *relative != "adapters/postgres/src/integration_tests.rs" {
            assert!(
                !owns_runtime_login_ddl(&source),
                "{relative} must call testkit::provision_postgres_test_logins instead of owning role DDL"
            );
        }
        if CALLERS.contains(relative) {
            assert_eq!(
                source
                    .matches("testkit::provision_postgres_test_logins(")
                    .count(),
                1,
                "{relative} must have exactly one direct provisioning call (exclude *_with_private_ca)"
            );
        }
    }

    let postgres_integration =
        std::fs::read_to_string(root.join("adapters/postgres/src/integration_tests.rs"))?;
    let runtime_provisioner =
        function_source(&postgres_integration, "async fn provision_runtime_logins")
            .ok_or("postgres integration runtime login provisioner must remain discoverable")?;
    assert!(
        !owns_runtime_login_ddl(runtime_provisioner),
        "postgres integration's common provisioner must use testkit; permission and upgrade negative fixtures outside this function remain exempt"
    );

    for relative_root in RECURSIVE_GOVERNANCE_ROOTS {
        let absolute_root = root.join(relative_root);
        for source_path in rust_sources_under(&absolute_root)? {
            let source = std::fs::read_to_string(&source_path)?;
            assert!(
                !owns_runtime_login_ddl(&source),
                "{} is a newly discovered test login DDL carrier; call testkit instead",
                source_path.strip_prefix(&root)?.display()
            );
        }
    }
    Ok(())
}

#[test]
fn unknown_runtime_login_ddl_carrier_is_rejected() {
    let synthetic = "const ROLE: &str = \"rss_app\"; sqlx::query(\"CREATE ROLE rss_app LOGIN\");";
    assert!(owns_runtime_login_ddl(synthetic));
    assert!(!owns_runtime_login_ddl(
        "testkit::provision_postgres_test_logins(params, &logins).await?;"
    ));
}

#[cfg(feature = "containers")]
#[tokio::test]
async fn provisioner_binds_quoted_credentials_and_enforces_fixed_attributes()
-> Result<(), Box<dyn std::error::Error>> {
    use sqlx::postgres::{PgConnectOptions, PgPoolOptions};

    let fixture = testkit::env_or_postgres().await?;
    let params = fixture.params();
    let role = "rss_test_login_\"quoted";
    let password = "test_'quoted_password";
    testkit::provision_postgres_test_logins(
        params,
        &[testkit::PostgresTestLogin::new(role, password)],
    )
    .await?;
    let rotated_password = "rotated_'quoted_password";
    testkit::provision_postgres_test_logins(
        params,
        &[testkit::PostgresTestLogin::new(role, rotated_password)],
    )
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
        r#"
        SELECT rolcanlogin, rolsuper, rolcreatedb, rolcreaterole, rolreplication, rolbypassrls,
               rolinherit
        FROM pg_roles
        WHERE rolname = $1
        "#,
    )
    .bind(role)
    .fetch_one(&owner)
    .await?;
    assert_eq!(attributes, (true, false, false, false, false, false, false));

    let login = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(
            PgConnectOptions::new()
                .host(&params.host)
                .port(params.port)
                .database(&params.database)
                .username(role)
                .password(rotated_password),
        )
        .await?;
    let current_user: String = sqlx::query_scalar("SELECT current_user")
        .fetch_one(&login)
        .await?;
    assert_eq!(current_user, role);
    login.close().await;
    owner.close().await;
    Ok(())
}
