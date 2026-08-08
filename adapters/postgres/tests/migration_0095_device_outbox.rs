const MIGRATION: &str = include_str!("../migrations/0095_seal_device_artifact_eligibility.sql");
const IDENTITY_TX: &str = include_str!("../src/cotx/identity.rs");
const DEVICE_OUTBOX: &str = include_str!("../src/device_outbox.rs");

fn normalized_migration() -> String {
    MIGRATION.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[test]
fn device_mqtt_claim_is_exact_in_sql_and_keeps_the_governed_lease() {
    let sql = normalized_migration();

    for required in [
        "CREATE FUNCTION public.rss_claim_device_mqtt_outbox(",
        "IF p_kind NOT IN (1, 2)",
        "p_kind = 1",
        "p_kind = 2",
        "o.domain = 'identity'",
        "o.contract_id = 'identity.apply-device-certificate'",
        "o.contract_id = 'identity.device-ingress-receipted'",
        "command.artifact_eligibility = 'draft'",
        "THEN command.credential_generation",
        "ELSE (claimed.metadata->>'credentialGeneration')::bigint",
        "policy.relay_lease_ttl_ms",
        "policy.relay_publish_timeout_ms",
        "policy.relay_settle_timeout_ms",
        "policy.relay_safety_margin_ms",
        "o.status = 'publishing' AND o.lease_until <= claim_clock.claimed_at",
        "FOR UPDATE OF o SKIP LOCKED",
    ] {
        assert!(
            sql.contains(required),
            "missing exact device claim carrier: {required}"
        );
    }

    assert!(!sql.contains("rss_claim_device_mqtt_outbox( p_domain"));
    assert!(!sql.contains("rss_claim_device_mqtt_outbox( p_contract_id"));
}

#[test]
fn puback_functions_close_command_and_receipt_settlement_without_generic_inputs() {
    let sql = normalized_migration();

    for required in [
        "CREATE FUNCTION public.rss_settle_device_mqtt_command_puback(",
        "CREATE FUNCTION public.rss_settle_device_mqtt_receipt_puback(",
        "candidate.contract_id = 'identity.apply-device-certificate'",
        "candidate.contract_id = 'identity.device-ingress-receipted'",
        "rss_settle_device_command_published_core(",
        "'draft'",
        "rss_outbox_settle_published(",
        "REVOKE ALL ON FUNCTION public.rss_settle_device_command_published_draft",
        "FROM PUBLIC, rss_app, rss_app_read",
    ] {
        assert!(
            sql.contains(required),
            "missing move-only PUBACK carrier: {required}"
        );
    }

    assert!(!sql.contains("rss_settle_device_mqtt_command_puback( p_contract_id"));
    assert!(!sql.contains("rss_settle_device_mqtt_receipt_puback( p_contract_id"));
}

#[test]
fn serving_role_receives_only_exact_device_functions() {
    let sql = normalized_migration();

    for signature in [
        "public.rss_claim_device_mqtt_outbox(smallint,bigint,bigint,bigint)",
        "public.rss_settle_device_mqtt_command_puback(text,uuid,bigint,bigint)",
        "public.rss_settle_device_mqtt_receipt_puback(text,uuid,bigint)",
    ] {
        assert!(
            sql.contains(signature),
            "missing exact function privilege signature: {signature}"
        );
    }
    assert!(!sql.contains("GRANT SELECT ON public.outbox TO rss_app"));
    assert!(!sql.contains("GRANT UPDATE ON public.outbox TO rss_app"));
    assert!(!sql.contains("GRANT SELECT ON public.device_commands TO rss_outbox_maintenance"));
    assert!(sql.contains(
        "CREATE ROLE rss_device_mqtt_outbox_owner NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT"
    ));
    assert!(sql.contains(
        "GRANT SELECT (tenant_id, command_id, device_id, generation, version, state, artifact_eligibility) ON public.device_commands TO rss_device_mqtt_outbox_owner"
    ));
    assert!(sql.contains(
        "OWNER TO rss_device_mqtt_outbox_owner; REVOKE ALL ON FUNCTION public.rss_load_draft_device_mqtt_command_claim(uuid,text) FROM PUBLIC, rss_app, rss_app_read, rss_outbox_maintenance"
    ));
    assert!(!sql.contains("TO rss_app, rss_device_mqtt_outbox_owner"));
}

#[test]
fn bypassrls_owner_rejects_both_membership_directions_before_elevation() {
    let sql = normalized_migration();

    for required in [
        "DECLARE owner_oid oid",
        "FROM pg_catalog.pg_auth_members AS membership",
        "membership.roleid = owner_oid OR membership.member = owner_oid",
        "rss_device_mqtt_outbox_owner must have no role memberships",
        "ALTER ROLE rss_device_mqtt_outbox_owner NOLOGIN NOSUPERUSER BYPASSRLS",
    ] {
        assert!(
            sql.contains(required),
            "missing fail-closed outbox-owner membership gate: {required}"
        );
    }

    let membership_gate = sql
        .find("FROM pg_catalog.pg_auth_members AS membership")
        .expect("membership gate");
    let bypass_elevation = sql
        .find("ALTER ROLE rss_device_mqtt_outbox_owner NOLOGIN NOSUPERUSER BYPASSRLS")
        .expect("BYPASSRLS elevation");
    assert!(
        membership_gate < bypass_elevation,
        "membership validation must complete before BYPASSRLS elevation"
    );
}

#[test]
fn command_install_rechecks_the_exact_attempt_lease_and_wake_inside_the_funnel() {
    let sql = normalized_migration();

    for required in [
        "p_attempt_id uuid",
        "p_lease_token uuid",
        "p_epoch bigint",
        "p_wake_version bigint",
        "JOIN public.reconcile_attempts AS attempt USING (tenant_id,target_id)",
        "JOIN public.reconcile_leases AS lease USING (tenant_id,target_id)",
        "attempt.attempt_id=p_attempt_id",
        "attempt.lease_token=p_lease_token",
        "attempt.epoch=p_epoch",
        "attempt.claimed_wake_version=p_wake_version",
        "target.wake_version=p_wake_version",
        "lease.lease_token=p_lease_token",
        "lease.epoch=p_epoch",
        "lease.state='held'",
        "lease.expires_at>pg_catalog.clock_timestamp()",
        "GRANT SELECT (tenant_id,target_id,attempt_id,lease_token,epoch,claimed_wake_version) ON public.reconcile_attempts TO rss_device_command_funnel_owner",
    ] {
        assert!(
            sql.contains(required),
            "missing exact command-install fence carrier: {required}"
        );
    }
}

#[test]
fn ingress_credential_evidence_is_persisted_and_transport_scope_is_session_resolved() {
    assert!(IDENTITY_TX.contains("\"credentialGeneration\""));
    assert!(IDENTITY_TX.contains("serde_json::Value::from(credential_generation)"));
    assert!(DEVICE_OUTBOX.contains("pub async fn claim_commands("));
    assert!(DEVICE_OUTBOX.contains("pub async fn claim_receipts("));
    assert!(!DEVICE_OUTBOX.contains("pub async fn claim_batch("));
    assert!(!DEVICE_OUTBOX.contains("pub const fn credential_generation(&self) -> u64"));
}

#[cfg(feature = "integration")]
mod postgres {
    use std::borrow::Cow;
    use std::time::Duration;

    use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode};

    type TestError = Box<dyn std::error::Error + Send + Sync>;
    type TestResult = Result<(), TestError>;

    const MEMBERSHIP_FAILURE: &str = "rss_device_mqtt_outbox_owner must have no role memberships";

    fn migrations_through(max_version: i64) -> sqlx::migrate::Migrator {
        let embedded = sqlx::migrate!("./migrations");
        sqlx::migrate::Migrator {
            migrations: Cow::Owned(
                embedded
                    .iter()
                    .filter(|migration| migration.version <= max_version)
                    .cloned()
                    .collect(),
            ),
            ignore_missing: false,
            locking: true,
            no_tx: embedded.no_tx,
        }
    }

    async fn pool_for(fixture: &testkit::OwnedPgFixture) -> Result<sqlx::PgPool, TestError> {
        let params = fixture.owner_params();
        Ok(PgPoolOptions::new()
            .max_connections(2)
            .acquire_timeout(Duration::from_secs(5))
            .connect_with(
                PgConnectOptions::new()
                    .host(&params.host)
                    .port(params.port)
                    .database(&params.database)
                    .username(&params.username)
                    .password(&params.password)
                    .ssl_mode(PgSslMode::Prefer),
            )
            .await?)
    }

    fn migration_database_error(
        failure: &sqlx::migrate::MigrateError,
    ) -> Result<&(dyn sqlx::error::DatabaseError + 'static), TestError> {
        match failure {
            sqlx::migrate::MigrateError::ExecuteMigration(
                sqlx::Error::Database(database_error),
                95,
            ) => Ok(database_error.as_ref()),
            _ => Err(std::io::Error::other(format!(
                "0095 failed through an unexpected path: {failure}"
            ))
            .into()),
        }
    }

    async fn assert_membership_failure(pool: &sqlx::PgPool) -> TestResult {
        let failure = migrations_through(95)
            .run(pool)
            .await
            .expect_err("0095 must reject a pre-existing outbox-owner membership");
        let database_error = migration_database_error(&failure)?;
        assert_eq!(database_error.code().as_deref(), Some("55000"));
        assert_eq!(database_error.message(), MEMBERSHIP_FAILURE);
        let ledger: (Option<i64>, i64) = sqlx::query_as(
            "SELECT max(version), count(*) FILTER (WHERE version = 95) \
             FROM public._sqlx_migrations",
        )
        .fetch_one(pool)
        .await?;
        assert_eq!(ledger, (Some(94), 0));
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn migration_0095_rejects_both_owner_membership_directions_before_bypassrls() -> TestResult
    {
        let fixture = testkit::owned_postgres().await?;
        let mut pool = pool_for(&fixture).await?;
        migrations_through(94).run(&pool).await?;

        sqlx::raw_sql(
            "CREATE ROLE rss_device_mqtt_outbox_owner \
                 NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE \
                 NOREPLICATION NOINHERIT; \
             CREATE ROLE rss_0095_membership_attacker LOGIN; \
             CREATE ROLE rss_0095_membership_parent NOLOGIN; \
             GRANT rss_device_mqtt_outbox_owner TO rss_0095_membership_attacker;",
        )
        .execute(&pool)
        .await?;
        assert_membership_failure(&pool).await?;
        pool.close().await;
        pool = pool_for(&fixture).await?;

        sqlx::raw_sql(
            "REVOKE rss_device_mqtt_outbox_owner FROM rss_0095_membership_attacker; \
             GRANT rss_0095_membership_parent TO rss_device_mqtt_outbox_owner;",
        )
        .execute(&pool)
        .await?;
        assert_membership_failure(&pool).await?;
        pool.close().await;
        pool = pool_for(&fixture).await?;

        sqlx::query("REVOKE rss_0095_membership_parent FROM rss_device_mqtt_outbox_owner")
            .execute(&pool)
            .await?;
        migrations_through(95).run(&pool).await?;
        let installed: (bool, bool, i64) = sqlx::query_as(
            "SELECT owner.rolbypassrls, NOT owner.rolcanlogin, \
                    (SELECT count(*) FROM pg_catalog.pg_auth_members AS membership \
                     WHERE membership.roleid=owner.oid OR membership.member=owner.oid) \
             FROM pg_catalog.pg_roles AS owner \
             WHERE owner.rolname='rss_device_mqtt_outbox_owner'",
        )
        .fetch_one(&pool)
        .await?;
        assert_eq!(installed, (true, true, 0));
        pool.close().await;
        Ok(())
    }

    struct FunnelAuthority {
        tenant_id: String,
        device_id: String,
        attempt_id: String,
        lease_token: String,
        epoch: i64,
        wake_version: i64,
        artifact_id: String,
    }

    async fn install_command(
        pool: &sqlx::PgPool,
        authority: &FunnelAuthority,
        attempt_id: &str,
        lease_token: &str,
        wake_version: i64,
        command_id: &str,
    ) -> Result<String, TestError> {
        let mut tx = pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT pg_catalog.set_config('rss.tenant_id', $1, true)")
            .bind(&authority.tenant_id)
            .execute(&mut *tx)
            .await?;
        let outcome = sqlx::query_scalar(
            "SELECT public.rss_install_fenced_device_command( \
                 $1::uuid,$2::uuid,$3::uuid,$4::uuid,$5,$6,$7,1, \
                 pg_catalog.decode(pg_catalog.repeat('1',64),'hex'),4102444800, \
                 $8,pg_catalog.decode(pg_catalog.repeat('2',64),'hex'), \
                 (SELECT policy_hash FROM public.device_certificate_desired_states \
                  WHERE tenant_id=$1::uuid AND device_id=$2::uuid))",
        )
        .bind(&authority.tenant_id)
        .bind(&authority.device_id)
        .bind(attempt_id)
        .bind(lease_token)
        .bind(authority.epoch)
        .bind(wake_version)
        .bind(command_id)
        .bind(&authority.artifact_id)
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(outcome)
    }

    async fn create_funnel_authority(pool: &sqlx::PgPool) -> Result<FunnelAuthority, TestError> {
        let tenant_id = uuid::Uuid::new_v4().to_string();
        let device_id = uuid::Uuid::new_v4().to_string();
        let attempt_id = uuid::Uuid::new_v4().to_string();
        let lease_token = uuid::Uuid::new_v4().to_string();
        let epoch = 3;
        let wake_version = 7;
        let artifact_id = "draft-artifact-0001".to_owned();
        sqlx::query(
            "INSERT INTO public.device_certificate_desired_states ( \
                 tenant_id,device_id,generation,validity_seconds,renew_before_seconds, \
                 client_auth,server_auth,sans) \
             VALUES ($1::uuid,$2::uuid,1,3600,600,true,false,ARRAY[]::text[])",
        )
        .bind(&tenant_id)
        .bind(&device_id)
        .execute(pool)
        .await?;
        let target_id: String = sqlx::query_scalar(
            "INSERT INTO public.reconcile_targets ( \
                 tenant_id,reconciler_id,resource_kind,resource_id,wake_version) \
             VALUES ($1::uuid,'identity.device-certificate','device-certificate',$2,$3) \
             RETURNING target_id::text",
        )
        .bind(&tenant_id)
        .bind(&device_id)
        .bind(wake_version)
        .fetch_one(pool)
        .await?;
        sqlx::query(
            "INSERT INTO public.reconcile_leases ( \
                 tenant_id,target_id,state,lease_token,holder_id,epoch, \
                 acquired_at,expires_at,heartbeat_at) \
             VALUES ($1::uuid,$2::uuid,'held',$3::uuid,'worker',$4, \
                 pg_catalog.clock_timestamp(), \
                 pg_catalog.clock_timestamp()+interval '5 minutes', \
                 pg_catalog.clock_timestamp())",
        )
        .bind(&tenant_id)
        .bind(&target_id)
        .bind(&lease_token)
        .bind(epoch)
        .execute(pool)
        .await?;
        sqlx::query(
            "INSERT INTO public.reconcile_attempts ( \
                 tenant_id,attempt_id,target_id,lease_token,epoch,holder_id,trigger_kind, \
                 claimed_failure_streak,claimed_wake_version) \
             VALUES ($1::uuid,$2::uuid,$3::uuid,$4::uuid,$5,'worker','targeted',0,$6)",
        )
        .bind(&tenant_id)
        .bind(&attempt_id)
        .bind(&target_id)
        .bind(&lease_token)
        .bind(epoch)
        .bind(wake_version)
        .execute(pool)
        .await?;
        sqlx::query(
            "INSERT INTO public.device_certificate_authorized_artifacts ( \
                 tenant_id,device_id,generation,artifact_eligibility,policy_hash, \
                 public_key_digest,expected_state_hash,artifact_digest,artifact_id,serial,not_after) \
             SELECT desired.tenant_id,desired.device_id,desired.generation,'draft',desired.policy_hash, \
                    pg_catalog.decode(pg_catalog.repeat('3',64),'hex'), \
                    pg_catalog.decode(pg_catalog.repeat('4',64),'hex'), \
                    pg_catalog.decode(pg_catalog.repeat('2',64),'hex'),$3, \
                    pg_catalog.decode('01','hex'), \
                    pg_catalog.clock_timestamp()+interval '1 hour' \
             FROM public.device_certificate_desired_states AS desired \
             WHERE desired.tenant_id=$1::uuid AND desired.device_id=$2::uuid",
        )
        .bind(&tenant_id)
        .bind(&device_id)
        .bind(&artifact_id)
        .execute(pool)
        .await?;
        Ok(FunnelAuthority {
            tenant_id,
            device_id,
            attempt_id,
            lease_token,
            epoch,
            wake_version,
            artifact_id,
        })
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn direct_command_funnel_rejects_inexact_or_expired_authority_with_zero_writes()
    -> TestResult {
        let fixture = testkit::owned_postgres().await?;
        let pool = pool_for(&fixture).await?;
        migrations_through(95).run(&pool).await?;
        let authority = create_funnel_authority(&pool).await?;

        let stale_attempt = uuid::Uuid::new_v4().to_string();
        let stale_token = uuid::Uuid::new_v4().to_string();
        for (label, attempt_id, lease_token, wake_version) in [
            (
                "attempt",
                stale_attempt.as_str(),
                authority.lease_token.as_str(),
                authority.wake_version,
            ),
            (
                "lease",
                authority.attempt_id.as_str(),
                stale_token.as_str(),
                authority.wake_version,
            ),
            (
                "wake",
                authority.attempt_id.as_str(),
                authority.lease_token.as_str(),
                authority.wake_version - 1,
            ),
        ] {
            let outcome = install_command(
                &pool,
                &authority,
                attempt_id,
                lease_token,
                wake_version,
                &format!("stale-{label}"),
            )
            .await?;
            assert_eq!(outcome, "lost", "stale {label} authority must be rejected");
        }

        sqlx::query(
            "UPDATE public.reconcile_leases \
             SET acquired_at=pg_catalog.clock_timestamp()-interval '10 minutes', \
                 expires_at=pg_catalog.clock_timestamp()-interval '5 minutes', \
                 heartbeat_at=pg_catalog.clock_timestamp()-interval '6 minutes' \
             WHERE tenant_id=$1::uuid",
        )
        .bind(&authority.tenant_id)
        .execute(&pool)
        .await?;
        let expired = install_command(
            &pool,
            &authority,
            &authority.attempt_id,
            &authority.lease_token,
            authority.wake_version,
            "expired-lease",
        )
        .await?;
        assert_eq!(expired, "lost");

        let command_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM public.device_commands WHERE tenant_id=$1::uuid",
        )
        .bind(&authority.tenant_id)
        .fetch_one(&pool)
        .await?;
        assert_eq!(
            command_count, 0,
            "every rejected direct call must be zero-write"
        );
        pool.close().await;
        Ok(())
    }
}
