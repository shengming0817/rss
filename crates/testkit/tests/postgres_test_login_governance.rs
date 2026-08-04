//! PG-TEST-LOGIN-SINGLE-SOURCE-01 (Medium): recursive structural backstop keeps runtime login role
//! DDL in testkit and requires every known consumer to call the single entry exactly once.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

const CALLERS: &[&str] = &[
    "adapters/postgres/src/integration_tests/support/runtime.rs",
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
const POSTGRES_LOGIN_OWNER: &str = "adapters/postgres/src/integration_tests/support/runtime.rs";
const POSTGRES_INTEGRATION_FACADE: &str = "adapters/postgres/src/integration_tests.rs";
const POSTGRES_INTEGRATION_ROOT: &str = "adapters/postgres/src/integration_tests";
/// Closed allowlist of negative/permission fixture seams that may own `CREATE`/`ALTER ROLE`
/// near `rss_app` / `rss_app_read`. Exact-set anti-vacuity: every entry must still match, and any
/// new carrier outside this set + the login owner must fail closed.
const ROLE_DDL_FIXTURE_ALLOWLIST: &[&str] = &[
    "adapters/postgres/src/integration_tests/inbox_consumer_tests.rs",
    "adapters/postgres/src/integration_tests/migrations_tests.rs",
    "adapters/postgres/src/integration_tests/projection_events_tests.rs",
    "adapters/postgres/src/integration_tests/revocation_tests.rs",
    "adapters/postgres/src/integration_tests/saga_tests.rs",
    "adapters/postgres/src/integration_tests/tenant_rls_tests.rs",
];

const DDL_FREE_NON_CALLERS: &[&str] = &["adapters/postgres/src/fault_matrix.rs"];
const RECURSIVE_GOVERNANCE_ROOTS: &[&str] = &[
    "assemblies/runtime/tests",
    "journeys/tests",
    "journeys-fault-matrix/tests",
];
const PROVISION_CALL: &str = "testkit::provision_postgres_test_logins(";

#[derive(Debug, PartialEq, Eq)]
struct IntegrationLoginAggregate {
    total_provision_calls: usize,
    provision_owners: BTreeSet<String>,
    ddl_carriers: BTreeSet<String>,
}

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

fn owns_runtime_login_ddl(source: &str) -> bool {
    (source.contains("rss_app") || source.contains("rss_app_read"))
        && (source.contains("CREATE ROLE") || source.contains("ALTER ROLE"))
}

fn function_source<'a>(source: &'a str, signature: &str) -> Option<&'a str> {
    let start = source.find(signature)?;
    let remaining = &source[start + signature.len()..];
    let end = next_async_fn_offset(remaining).unwrap_or(remaining.len());
    Some(&source[start..start + signature.len() + end])
}

fn next_async_fn_offset(source: &str) -> Option<usize> {
    let mut search_from = 0;
    while let Some(rel) = source[search_from..].find("async fn ") {
        let idx = search_from + rel;
        let line_start = source[..idx].rfind('\n').map(|i| i + 1).unwrap_or(0);
        let prefix = source[line_start..idx].trim();
        let visibility_ok = prefix.is_empty()
            || prefix == "pub"
            || (prefix.starts_with("pub(") && prefix.ends_with(')'));
        if visibility_ok {
            return Some(if line_start == 0 {
                0
            } else {
                line_start.saturating_sub(1)
            });
        }
        search_from = idx + "async fn ".len();
    }
    None
}

fn relative_display(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .display()
        .to_string()
}

/// Aggregate login-governance facts for the thin façade plus every Rust file under
/// `integration_tests/` (including partitioned `support/`). Shared by the green workspace scan and
/// synthetic façade-bait reds so both paths exercise the same closed-set arithmetic.
fn analyze_postgres_integration_login_sources(
    sources: &[(String, String)],
    login_owner: &str,
) -> IntegrationLoginAggregate {
    let mut provision_owners = BTreeSet::new();
    let mut ddl_carriers = BTreeSet::new();
    let mut total_provision_calls = 0usize;
    for (relative, source) in sources {
        let provision_calls = source.matches(PROVISION_CALL).count();
        if provision_calls > 0 {
            provision_owners.insert(relative.clone());
            total_provision_calls += provision_calls;
        }
        if relative.as_str() != login_owner && owns_runtime_login_ddl(source) {
            ddl_carriers.insert(relative.clone());
        }
    }
    IntegrationLoginAggregate {
        total_provision_calls,
        provision_owners,
        ddl_carriers,
    }
}

fn load_postgres_integration_login_sources(
    root: &Path,
) -> Result<Vec<(String, String)>, Box<dyn std::error::Error>> {
    let mut sources = Vec::new();
    let facade = root.join(POSTGRES_INTEGRATION_FACADE);
    sources.push((
        POSTGRES_INTEGRATION_FACADE.to_owned(),
        std::fs::read_to_string(&facade)?,
    ));
    for source_path in rust_sources_under(&root.join(POSTGRES_INTEGRATION_ROOT))? {
        let relative = relative_display(root, &source_path);
        let source = std::fs::read_to_string(&source_path)?;
        sources.push((relative, source));
    }
    sources.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(sources)
}

fn expected_allowlist_carriers() -> BTreeSet<String> {
    ROLE_DDL_FIXTURE_ALLOWLIST
        .iter()
        .copied()
        .map(str::to_owned)
        .collect()
}

#[test]
fn postgres_test_login_ddl_has_one_source() -> Result<(), Box<dyn std::error::Error>> {
    let root = workspace_root()?;
    for relative in CALLERS.iter().chain(DDL_FREE_NON_CALLERS) {
        let source = std::fs::read_to_string(root.join(relative))?;
        if *relative != POSTGRES_LOGIN_OWNER {
            assert!(
                !owns_runtime_login_ddl(&source),
                "{relative} must call testkit::provision_postgres_test_logins instead of owning role DDL"
            );
        }
        if CALLERS.contains(relative) {
            assert_eq!(
                source.matches(PROVISION_CALL).count(),
                1,
                "{relative} must have exactly one direct provisioning call (exclude *_with_private_ca)"
            );
        }
    }

    let postgres_integration = std::fs::read_to_string(root.join(POSTGRES_LOGIN_OWNER))?;
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
                relative_display(&root, &source_path)
            );
        }
    }

    let allowlist: BTreeSet<&str> = ROLE_DDL_FIXTURE_ALLOWLIST.iter().copied().collect();
    assert_eq!(
        allowlist.len(),
        ROLE_DDL_FIXTURE_ALLOWLIST.len(),
        "ROLE_DDL_FIXTURE_ALLOWLIST must stay unique"
    );

    let sources = load_postgres_integration_login_sources(&root)?;
    assert!(
        sources
            .iter()
            .any(|(relative, _)| relative == POSTGRES_INTEGRATION_FACADE),
        "thin façade {POSTGRES_INTEGRATION_FACADE} must join the same aggregate as support/"
    );
    let aggregate = analyze_postgres_integration_login_sources(&sources, POSTGRES_LOGIN_OWNER);
    let facade_source = sources
        .iter()
        .find(|(relative, _)| relative == POSTGRES_INTEGRATION_FACADE)
        .map(|(_, source)| source.as_str())
        .expect("façade source must load");
    assert_eq!(
        facade_source.matches(PROVISION_CALL).count(),
        0,
        "{POSTGRES_INTEGRATION_FACADE} must stay provision-free"
    );
    assert!(
        !owns_runtime_login_ddl(facade_source),
        "{POSTGRES_INTEGRATION_FACADE} must stay runtime-login-DDL-free"
    );

    assert_eq!(
        aggregate.total_provision_calls, 1,
        "adapters/postgres integration façade+subtree must call {PROVISION_CALL} exactly once"
    );
    assert_eq!(
        aggregate.provision_owners,
        BTreeSet::from([POSTGRES_LOGIN_OWNER.to_owned()]),
        "unique provision owner must remain {POSTGRES_LOGIN_OWNER}"
    );
    assert_eq!(
        aggregate.ddl_carriers,
        expected_allowlist_carriers(),
        "role DDL fixture seams must stay an exact closed allowlist; new carriers fail closed"
    );
    for relative in ROLE_DDL_FIXTURE_ALLOWLIST {
        let source = std::fs::read_to_string(root.join(relative))?;
        assert!(
            owns_runtime_login_ddl(&source),
            "{relative} is allowlisted but no longer owns runtime login role DDL (anti-vacuity)"
        );
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

#[test]
fn postgres_integration_subtree_governance_synthetic_reds() {
    assert!(
        owns_runtime_login_ddl(
            "const ROLE: &str = \"rss_app\"; sqlx::query(\"CREATE ROLE rss_app LOGIN\");"
        ),
        "rogue DDL carrier must trip owns_runtime_login_ddl"
    );
    assert_eq!(
        "fn bait() { testkit::provision_postgres_test_logins(params, &logins); }"
            .matches(PROVISION_CALL)
            .count(),
        1,
        "rogue direct provision call must remain detectable"
    );

    let mut expected = expected_allowlist_carriers();
    expected
        .insert("adapters/postgres/src/integration_tests/rogue_ddl_carrier_tests.rs".to_owned());
    assert_ne!(
        expected,
        expected_allowlist_carriers(),
        "new DDL carrier outside the closed allowlist must fail the exact-set gate"
    );
}

#[test]
fn postgres_integration_facade_bait_fails_same_aggregate_analyzer() {
    let owner = (
        POSTGRES_LOGIN_OWNER.to_owned(),
        format!("async fn provision_runtime_logins() {{ {PROVISION_CALL}params, &logins); }}"),
    );
    let allowlisted = ROLE_DDL_FIXTURE_ALLOWLIST
        .iter()
        .map(|path| {
            (
                (*path).to_owned(),
                "const ROLE: &str = \"rss_app\"; sqlx::query(\"ALTER ROLE rss_app NOINHERIT\");"
                    .to_owned(),
            )
        })
        .collect::<Vec<_>>();

    let clean_facade = (
        POSTGRES_INTEGRATION_FACADE.to_owned(),
        "mod support;\n".to_owned(),
    );
    let mut green_sources = vec![owner.clone(), clean_facade];
    green_sources.extend(allowlisted.iter().cloned());
    let green = analyze_postgres_integration_login_sources(&green_sources, POSTGRES_LOGIN_OWNER);
    assert_eq!(green.total_provision_calls, 1);
    assert_eq!(
        green.provision_owners,
        BTreeSet::from([POSTGRES_LOGIN_OWNER.to_owned()])
    );
    assert_eq!(green.ddl_carriers, expected_allowlist_carriers());

    let provision_bait = (
        POSTGRES_INTEGRATION_FACADE.to_owned(),
        format!("fn facade_bait() {{ {PROVISION_CALL}params, &logins); }}"),
    );
    let mut provision_red = vec![owner.clone(), provision_bait];
    provision_red.extend(allowlisted.iter().cloned());
    let provision_aggregate =
        analyze_postgres_integration_login_sources(&provision_red, POSTGRES_LOGIN_OWNER);
    assert_ne!(
        provision_aggregate.total_provision_calls, 1,
        "façade provision bait must break the exact-once aggregate via the shared analyzer"
    );
    assert!(
        provision_aggregate
            .provision_owners
            .contains(POSTGRES_INTEGRATION_FACADE),
        "façade provision bait must appear as a provision owner in the shared analyzer"
    );

    let ddl_bait = (
        POSTGRES_INTEGRATION_FACADE.to_owned(),
        "const ROLE: &str = \"rss_app\"; sqlx::query(\"CREATE ROLE rss_app LOGIN\");".to_owned(),
    );
    let mut ddl_red = vec![owner, ddl_bait];
    ddl_red.extend(allowlisted);
    let ddl_aggregate = analyze_postgres_integration_login_sources(&ddl_red, POSTGRES_LOGIN_OWNER);
    assert!(
        ddl_aggregate
            .ddl_carriers
            .contains(POSTGRES_INTEGRATION_FACADE),
        "façade ROLE DDL bait must enter ddl_carriers via the shared analyzer"
    );
    assert_ne!(
        ddl_aggregate.ddl_carriers,
        expected_allowlist_carriers(),
        "façade ROLE DDL bait must fail the exact allowlist set via the shared analyzer"
    );
}

#[cfg(unix)]
#[test]
fn rust_sources_under_rejects_symlinks() -> Result<(), Box<dyn std::error::Error>> {
    let root = workspace_root()?.join("target/postgres-login-governance-symlink-red");
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root)?;
    let real = root.join("real.rs");
    std::fs::write(&real, "// real\n")?;
    let link = root.join("link.rs");
    std::os::unix::fs::symlink(&real, &link)?;
    let err =
        rust_sources_under(&root).expect_err("symlink under governance root must fail closed");
    assert!(
        err.to_string().contains("symlink rejected"),
        "unexpected symlink error: {err}"
    );
    std::fs::remove_dir_all(&root)?;
    Ok(())
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
