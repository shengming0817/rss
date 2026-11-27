use rss_identity_core::{
    InstanceId, PrincipalId,
    account::{AccountKey, LoginKey, Password},
    session::{SessionPolicy, SessionSecret},
};
use rss_identity_postgres::*;
use rss_request_context::{Clock, Deadline, ExecutionTimer, TenantId};
use rss_transactional_messaging::fence::{Epoch, ExecutionBinding, StorageIdentity};
use rss_transactional_messaging_postgres::{PgConfig, PgPassword, PgRuntime};
use sqlx::{
    PgPool,
    postgres::{PgConnectOptions, PgPoolOptions},
};
use std::{
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};
pub const SYSTEM: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
pub const A: &str = "11111111-1111-4111-8111-111111111111";
pub const B: &str = "22222222-2222-4222-8222-222222222222";
pub const PASSWORD: &str = "correct horse battery staple";
#[allow(clippy::unwrap_used, reason = "test fixture")]
pub fn password() -> Password {
    Password::new(PASSWORD.into()).unwrap()
}
#[allow(clippy::unwrap_used, reason = "test fixture")]
pub fn login(s: &str) -> LoginKey {
    LoginKey::parse(s).unwrap()
}
#[allow(clippy::unwrap_used, reason = "test fixture")]
pub fn source() -> AttemptSource {
    AttemptSource::parse("local-test").unwrap()
}
#[allow(clippy::expect_used, reason = "bounded fixture timeout")]
pub fn deadline() -> Deadline {
    Deadline::from_timeout(&Timer, Duration::from_secs(30)).expect("bounded fixture timeout")
}
#[allow(clippy::unwrap_used, reason = "test fixture")]
pub fn credential_keys() -> Arc<CredentialKeys> {
    Arc::new(CredentialKeys::new("fixture".into(), vec![("fixture".into(), [8; 32])]).unwrap())
}
pub struct Timer;
impl Clock for Timer {
    #[allow(clippy::disallowed_methods, reason = "test fixture")]
    fn now(&self) -> Instant {
        Instant::now()
    }
}
impl ExecutionTimer for Timer {
    async fn sleep_until(&self, d: Deadline) {
        tokio::time::sleep(d.remaining(self.now()).unwrap_or_default()).await;
    }
}
pub struct HostPolicy {
    pub managers: RwLock<Vec<AccountKey>>,
    pub protected: RwLock<Vec<AccountKey>>,
    pub recent: RwLock<ReauthenticationRequirement>,
}
impl ManagementPolicy for HostPolicy {
    #[allow(clippy::unwrap_used, reason = "test fixture")]
    fn authorize<'a>(
        &'a self,
        c: &'a ManagementContext<'a>,
        _connection: &'a mut sqlx::PgConnection,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<ReauthenticationRequirement, ManagementDenied>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            if !self.managers.read().unwrap().contains(&c.actor()) {
                return Err(ManagementDenied);
            }
            if c.target()
                .is_some_and(|key| self.protected.read().unwrap().contains(&key))
                && matches!(
                    c.operation(),
                    ManagementOperation::SetAccountEnabled(false)
                        | ManagementOperation::SetMembership(false)
                )
            {
                return Err(ManagementDenied);
            }
            Ok(*self.recent.read().unwrap())
        })
    }
}
pub struct Fixture {
    pub owner: PgPool,
    pub admin: PgPool,
    pub database: String,
    provider: testkit::PgConnParams,
    ca: String,
    config: AuthorityConfig,
    pub audit_budget: rss_audit_postgres::WriteBudget,
    pub runtime: Arc<PgRuntime>,
    pub maintenance_runtime: Arc<PgRuntime>,
    pub store: Authority,
    pub oidc: Arc<crate::federation_support::ScriptedOidc>,
    pub maintenance: Authority,
    pub instance: InstanceId,
    pub key: AccountKey,
    pub system_key: AccountKey,
    pub policy: Arc<HostPolicy>,
    management_cookie: tokio::sync::Mutex<Option<String>>,
}
impl Fixture {
    #[allow(clippy::unwrap_used, reason = "test fixture")]
    #[allow(
        clippy::cognitive_complexity,
        reason = "test fixture and ordered assertions"
    )]
    pub async fn new(
        pg: &testkit::PgTlsFixture,
        integrity: rss_audit_postgres::Integrity,
    ) -> anyhow::Result<Self> {
        let instance = InstanceId::generate();
        let provider = pg.params().clone();
        let ca = pg.ca_pem().to_owned();
        let audit_budget = rss_audit_postgres::WriteBudget::new(8, 1024 * 1024, 1024 * 1024)?;
        let oidc = crate::federation_support::ScriptedOidc::new();
        let config = AuthorityConfig::new(
            instance,
            SessionPolicy::new(900, 14400)?,
            integrity,
            audit_budget.clone(),
        )?
        .with_oidc(oidc.clone());
        let options = PgConnectOptions::new()
            .host(&provider.host)
            .port(provider.port)
            .username(&provider.username)
            .password(&provider.password)
            .ssl_mode(sqlx::postgres::PgSslMode::VerifyFull)
            .ssl_root_cert_from_pem(ca.as_bytes().to_vec());
        let admin = PgPoolOptions::new()
            .max_connections(1)
            .connect_with(options.clone().database("postgres"))
            .await?;
        let database = format!("identity_{}", uuid::Uuid::new_v4().simple());
        sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE {database}")))
            .execute(&admin)
            .await?;
        let owner = PgPoolOptions::new()
            .max_connections(4)
            .connect_with(options.database(&database))
            .await?;
        sqlx::raw_sql("DO $$ BEGIN IF NOT EXISTS(SELECT FROM pg_roles WHERE rolname='rss_tmsg_relay') THEN CREATE ROLE rss_tmsg_relay NOLOGIN NOBYPASSRLS; END IF; IF NOT EXISTS(SELECT FROM pg_roles WHERE rolname='identity_runtime') THEN CREATE ROLE identity_runtime LOGIN PASSWORD 'fixture-only' NOBYPASSRLS; CREATE ROLE identity_maintenance LOGIN PASSWORD 'fixture-only' NOBYPASSRLS; END IF; END $$;").execute(&owner).await?;
        sqlx::raw_sql(rss_transactional_messaging_postgres::MIGRATION_SQL)
            .execute(&owner)
            .await?;
        let mut c = owner.acquire().await?;
        install(&mut c, instance).await?;
        sqlx::raw_sql("DO $$ BEGIN IF NOT EXISTS(SELECT FROM pg_roles WHERE rolname='identity_audit_owner') THEN CREATE ROLE identity_audit_owner NOLOGIN NOSUPERUSER NOBYPASSRLS; END IF; END $$").execute(&mut *c).await?;
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!("GRANT CREATE ON DATABASE {database} TO identity_audit_owner; SET ROLE identity_audit_owner"))).execute(&mut *c).await?;
        sqlx::raw_sql(rss_audit_postgres::MIGRATION_SQL)
            .execute(&mut *c)
            .await?;
        sqlx::raw_sql(rss_ledger_postgres::MIGRATION_SQL)
            .execute(&mut *c)
            .await?;
        sqlx::raw_sql("RESET ROLE; GRANT USAGE ON SCHEMA rss_ledger TO identity_runtime,identity_maintenance; GRANT SELECT ON ALL TABLES IN SCHEMA rss_ledger TO identity_runtime,identity_maintenance; GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA rss_ledger TO identity_runtime,identity_maintenance;").execute(&mut *c).await?;

        grant_profile(&mut c, "identity_runtime", AuthorityProfile::Runtime).await?;
        grant_profile(
            &mut c,
            "identity_maintenance",
            AuthorityProfile::Maintenance,
        )
        .await?;
        drop(c);
        sqlx::query("INSERT INTO rss_transactional_messaging.storage_lineage VALUES(true,$1,$2)")
            .bind([1u8; 16].as_slice())
            .bind([2u8; 16].as_slice())
            .execute(&owner)
            .await?;
        for tenant in [SYSTEM, A, B] {
            sqlx::query("INSERT INTO rss_transactional_messaging.tenant_epoch VALUES($1::uuid,1)")
                .bind(tenant)
                .execute(&owner)
                .await?;
        }
        let runtime = connect(&provider, &ca, &database, "identity_runtime").await?;
        let maintenance_runtime =
            connect(&provider, &ca, &database, "identity_maintenance").await?;
        let key = AccountKey {
            tenant: TenantId::parse(A)?,
            principal: PrincipalId::generate(),
        };
        let system_key = AccountKey {
            tenant: TenantId::parse(SYSTEM)?,
            principal: PrincipalId::generate(),
        };
        let policy = Arc::new(HostPolicy {
            protected: RwLock::new(vec![]),
            managers: RwLock::new(vec![key, system_key]),
            recent: RwLock::new(ReauthenticationRequirement::None),
        });
        let store = Authority::connect_runtime(
            runtime.clone(),
            Arc::new(
                rss_identity_core::account::PasswordKdf::new(
                    std::num::NonZeroUsize::new(4).unwrap(),
                    std::num::NonZeroU64::new(128 * 1024 * 1024).unwrap(),
                )
                .unwrap(),
            ),
            config.clone(),
            crate::support::binding(
                rss_request_context::TenantId::parse(crate::support::A).unwrap(),
            ),
            policy.clone(),
            deadline(),
        )
        .await?;
        let maintenance = Authority::connect_maintenance(
            maintenance_runtime.clone(),
            Arc::new(
                rss_identity_core::account::PasswordKdf::new(
                    std::num::NonZeroUsize::new(4).unwrap(),
                    std::num::NonZeroU64::new(128 * 1024 * 1024).unwrap(),
                )
                .unwrap(),
            ),
            config.clone(),
            crate::support::binding(
                rss_request_context::TenantId::parse(crate::support::A).unwrap(),
            ),
            deadline(),
        )
        .await?;
        Ok(Self {
            owner,
            admin,
            database,
            provider,
            ca,
            config,
            audit_budget,
            runtime,
            maintenance_runtime,
            store,
            oidc,
            maintenance,
            instance,
            key,
            system_key,
            policy,
            management_cookie: tokio::sync::Mutex::new(None),
        })
    }
    pub fn config(&self) -> AuthorityConfig {
        self.config.clone()
    }
    pub async fn runtime_as(&self, role: &str) -> anyhow::Result<Arc<PgRuntime>> {
        connect(&self.provider, &self.ca, &self.database, role).await
    }
    pub async fn bootstrap(&self) -> anyhow::Result<()> {
        self.maintenance
            .initialize(
                crate::support::binding((self.system_key).tenant),
                self.system_key,
                login("platform"),
                password(),
                deadline(),
            )
            .await?;
        self.provision_a().await
    }
    pub async fn provision_a(&self) -> anyhow::Result<()> {
        self.maintenance
            .initialize(
                crate::support::binding((self.key).tenant),
                self.key,
                login("admin"),
                password(),
                deadline(),
            )
            .await?;
        Ok(())
    }
    pub async fn login(&self) -> anyhow::Result<IssuedSession> {
        Ok(self
            .store
            .login_local(
                crate::support::binding(self.key.tenant),
                login("admin"),
                password(),
                source(),
                None,
                deadline(),
            )
            .await?)
    }
    pub async fn actor(&self) -> anyhow::Result<AuthenticatedSession> {
        let mut cookie = self.management_cookie.lock().await;
        if let Some(value) = cookie.as_ref() {
            match self
                .store
                .inspect_session(
                    crate::support::binding(self.key.tenant),
                    SessionSecret::parse(value.clone())?,
                    deadline(),
                )
                .await
            {
                Ok(proof) => return Ok(proof),
                Err(AuthorityError::Rejected) => {}
                Err(error) => return Err(error.into()),
            }
        }
        let issued = self.login().await?;
        *cookie = Some(issued.secret().expose().into());
        Ok(self
            .store
            .inspect_session(
                crate::support::binding(self.key.tenant),
                SessionSecret::parse(issued.secret().expose().into())?,
                deadline(),
            )
            .await?)
    }
    pub async fn reset_attempts(&self) -> anyhow::Result<()> {
        sqlx::raw_sql("DELETE FROM identity_authority.attempts; DELETE FROM identity_authority.password_attempts")
            .execute(&self.owner)
            .await?;
        Ok(())
    }
    pub async fn events(&self) -> anyhow::Result<i64> {
        Ok(sqlx::query_scalar("SELECT count(*) FROM rss_audit.records")
            .fetch_one(&self.owner)
            .await?)
    }
    #[allow(clippy::unwrap_used, reason = "test fixture")]
    pub async fn close(self) {
        self.runtime.close().await;
        self.maintenance_runtime.close().await;
        self.owner.close().await;
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "DROP DATABASE {}",
            self.database
        )))
        .execute(&self.admin)
        .await
        .unwrap();
        self.admin.close().await;
    }
}
#[allow(clippy::unwrap_used, reason = "test fixture")]
pub fn binding(tenant: TenantId) -> ExecutionBinding {
    ExecutionBinding::new(
        StorageIdentity::new([1; 16], [2; 16]).unwrap(),
        tenant,
        Epoch::new(1).unwrap(),
    )
}
async fn connect(
    provider: &testkit::PgConnParams,
    ca: &str,
    database: &str,
    role: &str,
) -> anyhow::Result<Arc<PgRuntime>> {
    Ok(Arc::new(
        PgRuntime::connect_producer(
            PgConfig::new(
                &provider.host,
                provider.port,
                database,
                role,
                PgPassword::new("fixture-only"),
                rss_transactional_messaging_postgres::PgPrivateCa::from_pem(
                    ca.as_bytes().to_vec(),
                )?,
            ),
            Timer,
            StorageIdentity::new([1; 16], [2; 16])?,
        )
        .await?,
    ))
}
/// The fixture host establishes the same complete fence as a real host transaction.
pub async fn fence(c: &mut sqlx::PgConnection, binding: ExecutionBinding) -> anyhow::Result<()> {
    let hex = |bytes: [u8; 16]| {
        bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true),set_config('rss.storage_target',$2,true),set_config('rss.storage_lineage',$3,true),set_config('rss.execution_epoch',$4,true)")
        .bind(binding.tenant().to_string()).bind(hex(binding.storage().target())).bind(hex(binding.storage().lineage())).bind(binding.epoch().get().to_string())
        .execute(&mut *c).await?;

    Ok(())
}

// Observe a real backend waiting on the exact owner, rather than infer a lock from elapsed time.
pub async fn wait_for_blocked_backend(f: &Fixture, blocker: i32) -> anyhow::Result<i32> {
    tokio::time::timeout(Duration::from_secs(10),async {
        loop {
            let pid:Option<i32>=sqlx::query_scalar("SELECT pid FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND $1=ANY(pg_blocking_pids(pid))")
                .bind(blocker).fetch_optional(&f.owner).await?;
            if let Some(pid)=pid {return Ok::<_,anyhow::Error>(pid);}
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await?
}
