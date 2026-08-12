//! Postgres integration tests — identity_persistence seam.

use super::support::*;

#[tokio::test(flavor = "multi_thread")]
async fn service_token_replay_store_atomically_rejects_duplicate_after_restart() -> TestResult {
    use diport::{
        ServiceTokenReplayDeadline, ServiceTokenReplayDisposition, ServiceTokenReplayKey,
        ServiceTokenReplayScope, ServiceTokenReplayStore as _,
    };
    use std::sync::Arc;
    use std::time::{Duration, UNIX_EPOCH};

    let (pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let app = Arc::new(connect_pg_rss_app_role(&pg, &store).await?);
    let (session_user, current_user): (String, String) =
        sqlx::query_as("SELECT session_user, current_user")
            .fetch_one(&app.pool)
            .await?;
    assert_eq!(
        (session_user.as_str(), current_user.as_str()),
        ("rss_app", "rss_app")
    );
    let first_store = crate::PgServiceTokenReplayStore::new(Arc::clone(&app));
    let concurrent_store = crate::PgServiceTokenReplayStore::new(Arc::clone(&app));
    let token_id = format!("nonce-{}", uuid::Uuid::new_v4().simple());
    let key = ServiceTokenReplayKey::derive(ServiceTokenReplayScope {
        issuer: "https://issuer.example",
        audience: "rss-api",
        key_id: "cell-a.svc-a",
        token_id: &token_id,
    })?;
    let now_epoch: i64 = sqlx::query_scalar("SELECT extract(epoch FROM clock_timestamp())::bigint")
        .fetch_one(&app.pool)
        .await?;
    let expires_at = UNIX_EPOCH + Duration::from_secs(u64::try_from(now_epoch)?.saturating_add(60));

    let (first, concurrent) = tokio::join!(
        first_store.check_and_record(
            &key,
            expires_at,
            ServiceTokenReplayDeadline::from_timeout(Duration::from_secs(5))?
        ),
        concurrent_store.check_and_record(
            &key,
            expires_at,
            ServiceTokenReplayDeadline::from_timeout(Duration::from_secs(5))?
        )
    );
    assert!(
        matches!(
            (first?, concurrent?),
            (
                ServiceTokenReplayDisposition::Recorded,
                ServiceTokenReplayDisposition::Replayed
            ) | (
                ServiceTokenReplayDisposition::Replayed,
                ServiceTokenReplayDisposition::Recorded
            )
        ),
        "atomic insert must produce exactly one concurrent winner"
    );
    drop(first_store);
    drop(concurrent_store);
    app.shutdown().await?;
    let restarted_app = Arc::new(connect_pg_rss_app_role(&pg, &store).await?);
    let restarted_store = crate::PgServiceTokenReplayStore::new(Arc::clone(&restarted_app));
    assert_eq!(
        restarted_store
            .check_and_record(
                &key,
                expires_at,
                ServiceTokenReplayDeadline::from_timeout(Duration::from_secs(5))?,
            )
            .await?,
        ServiceTokenReplayDisposition::Replayed,
        "same scoped service-token key must stay consumed across adapter restart"
    );
    let app_has_table_access: bool = sqlx::query_scalar(
        "SELECT has_table_privilege('rss_app', 'public.service_token_replay_keys', 'SELECT') \
             OR has_table_privilege('rss_app', 'public.service_token_replay_keys', 'INSERT') \
             OR has_table_privilege('rss_app', 'public.service_token_replay_keys', 'UPDATE') \
             OR has_table_privilege('rss_app', 'public.service_token_replay_keys', 'DELETE')",
    )
    .fetch_one(&store.pool)
    .await?;
    assert!(
        !app_has_table_access,
        "rss_app must only execute the fixed function, never access replay rows directly"
    );
    let app_can_consume: bool = sqlx::query_scalar(
        "SELECT has_function_privilege( \
             'rss_app', \
             'public.rss_service_token_replay_check_and_record(bytea,timestamptz)', \
             'EXECUTE')",
    )
    .fetch_one(&store.pool)
    .await?;
    assert!(
        app_can_consume,
        "rss_app must execute the fixed consume function"
    );

    restarted_app.shutdown().await?;
    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn service_token_replay_store_outage_fails_closed_without_runtime_panic() -> TestResult {
    use diport::{
        ServiceTokenReplayDeadline, ServiceTokenReplayKey, ServiceTokenReplayScope,
        ServiceTokenReplayStore as _, ServiceTokenReplayStoreError,
    };
    use std::sync::Arc;
    use std::time::{Duration, UNIX_EPOCH};

    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let store = Arc::new(store);
    let replay_store = crate::PgServiceTokenReplayStore::new(Arc::clone(&store));
    let key = ServiceTokenReplayKey::derive(ServiceTokenReplayScope {
        issuer: "https://issuer.example",
        audience: "rss-api",
        key_id: "cell-a.svc-a",
        token_id: "outage-fixture",
    })?;
    store.shutdown().await?;

    let verdict = replay_store
        .check_and_record(
            &key,
            UNIX_EPOCH + Duration::from_secs(4_102_444_800),
            ServiceTokenReplayDeadline::from_timeout(Duration::from_secs(5))?,
        )
        .await;
    assert_eq!(
        verdict,
        Err(ServiceTokenReplayStoreError::Unavailable),
        "storage outage must remain a closed error instead of fallback or panic"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn service_token_replay_deadline_bounds_lock_waits_and_recycles_connections() -> TestResult {
    use diport::{
        ServiceTokenReplayDeadline, ServiceTokenReplayDisposition, ServiceTokenReplayKey,
        ServiceTokenReplayScope, ServiceTokenReplayStore as _, ServiceTokenReplayStoreError,
    };
    use std::sync::Arc;
    use std::time::{Duration, UNIX_EPOCH};

    let (pg, owner) = connect_pg().await?;
    owner.run_migrations().await?;
    let app = Arc::new(connect_pg_rss_app_role(&pg, &owner).await?);
    let replay_store = crate::PgServiceTokenReplayStore::new(Arc::clone(&app));
    let sweeper = crate::PgServiceTokenReplaySweeper::new(Arc::clone(&app));
    let key = ServiceTokenReplayKey::derive(ServiceTokenReplayScope {
        issuer: "https://issuer.example",
        audience: "rss-api",
        key_id: "cell-a.svc-a",
        token_id: "deadline-lock-fixture",
    })?;
    let expires_at = UNIX_EPOCH + Duration::from_secs(4_102_444_800);

    let mut row_blocker = owner.pool.begin().await?;
    sqlx::query(
        "INSERT INTO public.service_token_replay_keys (key_digest, retain_until) \
         VALUES ($1, to_timestamp($2))",
    )
    .bind(key.digest_bytes().as_slice())
    .bind(i64::try_from(
        expires_at.duration_since(UNIX_EPOCH)?.as_secs(),
    )?)
    .execute(&mut *row_blocker)
    .await?;
    let consume = tokio::time::timeout(
        Duration::from_secs(1),
        replay_store.check_and_record(
            &key,
            expires_at,
            ServiceTokenReplayDeadline::from_timeout(Duration::from_millis(100))?,
        ),
    )
    .await;
    assert!(
        matches!(consume, Ok(Err(ServiceTokenReplayStoreError::Unavailable))),
        "same-key lock wait must fail closed before the outer test oracle: {consume:?}"
    );
    row_blocker.rollback().await?;

    assert_eq!(
        replay_store
            .check_and_record(
                &key,
                expires_at,
                ServiceTokenReplayDeadline::from_timeout(Duration::from_secs(5))?,
            )
            .await?,
        ServiceTokenReplayDisposition::Recorded,
        "timed-out replay transaction must return a reusable connection"
    );

    let mut table_blocker = owner.pool.begin().await?;
    sqlx::query("LOCK TABLE public.service_token_replay_keys IN ACCESS EXCLUSIVE MODE")
        .execute(&mut *table_blocker)
        .await?;
    let sweep = tokio::time::timeout(
        Duration::from_secs(1),
        sweeper.sweep_expired(ServiceTokenReplayDeadline::from_timeout(
            Duration::from_millis(100),
        )?),
    )
    .await;
    assert!(
        matches!(sweep, Ok(Err(ServiceTokenReplayStoreError::Unavailable))),
        "sweep table-lock wait must fail closed before the outer test oracle: {sweep:?}"
    );
    table_blocker.rollback().await?;
    sweeper
        .sweep_expired(ServiceTokenReplayDeadline::from_timeout(
            Duration::from_secs(5),
        )?)
        .await?;

    app.shutdown().await?;
    owner.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn service_token_replay_deadline_bounds_pool_exhaustion() -> TestResult {
    use diport::{
        ServiceTokenReplayDeadline, ServiceTokenReplayDisposition, ServiceTokenReplayKey,
        ServiceTokenReplayScope, ServiceTokenReplayStore as _, ServiceTokenReplayStoreError,
    };
    use std::sync::Arc;
    use std::time::{Duration, UNIX_EPOCH};

    let (pg, owner) = connect_pg().await?;
    owner.run_migrations().await?;
    let app = Arc::new(
        connect_pg_rss_app_role_with_limits(&pg, &owner, 1, Duration::from_secs(5)).await?,
    );
    let held_connection = app.pool.acquire().await?;
    let replay_store = crate::PgServiceTokenReplayStore::new(Arc::clone(&app));
    let key = ServiceTokenReplayKey::derive(ServiceTokenReplayScope {
        issuer: "https://issuer.example",
        audience: "rss-api",
        key_id: "cell-a.svc-a",
        token_id: "deadline-pool-fixture",
    })?;
    let expires_at = UNIX_EPOCH + Duration::from_secs(4_102_444_800);

    let consume = tokio::time::timeout(
        Duration::from_secs(1),
        replay_store.check_and_record(
            &key,
            expires_at,
            ServiceTokenReplayDeadline::from_timeout(Duration::from_millis(100))?,
        ),
    )
    .await;
    assert!(
        matches!(consume, Ok(Err(ServiceTokenReplayStoreError::Unavailable))),
        "pool exhaustion must fail closed before the outer test oracle: {consume:?}"
    );
    drop(held_connection);

    assert_eq!(
        replay_store
            .check_and_record(
                &key,
                expires_at,
                ServiceTokenReplayDeadline::from_timeout(Duration::from_secs(5))?,
            )
            .await?,
        ServiceTokenReplayDisposition::Recorded,
        "pool must remain reusable after a deadline while acquiring"
    );

    app.shutdown().await?;
    owner.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn service_token_replay_retention_is_bounded_and_off_the_authentication_path() -> TestResult {
    use diport::ServiceTokenReplayDeadline;
    use std::sync::Arc;
    use std::time::Duration;

    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let store = Arc::new(store);
    let future_sentinel = format!("future-sentinel-{}", uuid::Uuid::new_v4().simple());
    let safety_margin_sentinel =
        format!("safety-margin-sentinel-{}", uuid::Uuid::new_v4().simple());
    sqlx::query(
        "INSERT INTO public.service_token_replay_keys (key_digest, retain_until) \
         SELECT decode(md5(i::text) || md5(i::text || '-replay'), 'hex'), \
                clock_timestamp() - interval '10 minutes' \
         FROM generate_series(1, 1001) AS generated(i)",
    )
    .execute(&store.pool)
    .await?;
    for (seed, retain_offset_seconds) in [
        (future_sentinel.as_str(), 60_i64),
        (safety_margin_sentinel.as_str(), -240_i64),
    ] {
        sqlx::query(
            "INSERT INTO public.service_token_replay_keys (key_digest, retain_until) \
             VALUES (decode(md5($1) || md5($1 || '-replay'), 'hex'), \
                     clock_timestamp() + make_interval(secs => $2))",
        )
        .bind(seed)
        .bind(retain_offset_seconds)
        .execute(&store.pool)
        .await?;
    }
    let replay_store = crate::PgServiceTokenReplaySweeper::new(Arc::clone(&store));

    assert_eq!(
        replay_store
            .sweep_expired(ServiceTokenReplayDeadline::from_timeout(
                Duration::from_secs(5),
            )?)
            .await?,
        1000
    );
    let remaining: i64 =
        sqlx::query_scalar("SELECT count(*) FROM public.service_token_replay_keys")
            .fetch_one(&store.pool)
            .await?;
    assert_eq!(
        remaining, 3,
        "one bounded sweep must leave one old row and both protected sentinels"
    );
    assert_eq!(
        replay_store
            .sweep_expired(ServiceTokenReplayDeadline::from_timeout(
                Duration::from_secs(5),
            )?)
            .await?,
        1
    );
    for (seed, message) in [
        (
            future_sentinel,
            "a replay key whose token has not expired must be retained",
        ),
        (
            safety_margin_sentinel,
            "a replay key inside the five-minute safety margin must be retained",
        ),
    ] {
        let retained: bool = sqlx::query_scalar(
            "SELECT EXISTS ( \
                 SELECT 1 FROM public.service_token_replay_keys \
                 WHERE key_digest = decode(md5($1) || md5($1 || '-replay'), 'hex'))",
        )
        .bind(seed)
        .fetch_one(&store.pool)
        .await?;
        assert!(retained, "{message}");
    }

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn credential_security_event_consumer_appends_current_and_all_without_identity_reads()
-> TestResult {
    let (fixture, owner) = connect_pg().await?;
    owner.run_migrations().await?;
    let app = std::sync::Arc::new(connect_pg_rss_app_role(&fixture, &owner).await?);
    let tenant = test_tenant();
    let stores = crate::pool::PgRuntimeStores::from_unverified_for_test(
        std::sync::Arc::clone(&app),
        std::sync::Arc::clone(&app),
    );
    let handler = std::sync::Arc::new(crate::consumer_tx::PgAuditConsumerTx::security_event(
        stores.writer_capability(),
        audit::test_support::keyed_hasher(0x5a),
    ));
    let group = ConsumerGroup::parse(&format!("audit-security-{}", uuid::Uuid::new_v4())).unwrap();
    let ctx = InboxReceiptContext::new(
        tenant,
        group,
        "identity",
        "identity.security-event",
        "identity.security-event",
        "v1",
        TEST_SCHEMA_HASH,
        None,
        None,
    )?;
    for (index, kind, target_kind, expected_action) in [
        (0_i64, "logoutCurrent", "grant", "identity:logout_current"),
        (1_i64, "logoutAll", "subject", "identity:logout_all"),
    ] {
        let event_id = unique_event_id("audit-security");
        let key = IdemKey::parse(&event_id).unwrap();
        let lease = LeaseToken::mint();
        let target = uuid::Uuid::new_v4();
        assert_eq!(
            app.inbox().try_claim(&ctx, &key, &lease).await?,
            SeenState::Fresh
        );
        let payload = serde_json::json!({
            "actor": {"keyId": 1, "kind": "service", "ref": uuid::Uuid::new_v4()},
            "kind": kind,
            "occurredAt": 1_700_000_400_i64 + index,
            "target": {"keyId": 1, "kind": target_kind, "ref": target},
            "tenantId": tenant.to_string(),
        });
        assert!(matches!(
            std::sync::Arc::clone(&handler)
                .handle(
                    diport::Message::new(&event_id, serde_json::to_vec(&payload)?),
                    ctx.clone(),
                    key.clone(),
                    lease
                )
                .await,
            crate::PgConsumerTxOutcome::Committed(_)
        ));
        let row: (String, String, String, String) = sqlx::query_as(
            "SELECT actor::text, actor_kind, action, resource_id FROM audit_entries \
             WHERE tenant_id = $1::uuid ORDER BY seq DESC LIMIT 1",
        )
        .bind(tenant.to_string())
        .fetch_one(&owner.pool)
        .await?;
        assert_ne!(row.0, target.to_string());
        assert_eq!(row.1, "service");
        assert_eq!(row.2, expected_action);
        assert_eq!(row.3, target.to_string());
        assert_eq!(
            app.inbox()
                .try_claim(&ctx, &key, &LeaseToken::mint())
                .await?,
            SeenState::Duplicate
        );
        let append_count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM audit_entries WHERE tenant_id = $1::uuid")
                .bind(tenant.to_string())
                .fetch_one(&owner.pool)
                .await?;
        assert_eq!(
            append_count,
            index + 1,
            "duplicate delivery must not append again"
        );
    }

    let invalid_id = unique_event_id("audit-security-invalid-shape");
    let invalid_key = IdemKey::parse(&invalid_id).unwrap();
    let invalid_lease = LeaseToken::mint();
    assert_eq!(
        app.inbox()
            .try_claim(&ctx, &invalid_key, &invalid_lease)
            .await?,
        SeenState::Fresh
    );
    let invalid = serde_json::json!({
        "kind": "logoutAll",
        "occurredAt": 1_700_000_500_i64,
        "target": {"kind": "grant", "ref": uuid::Uuid::new_v4()},
        "tenantId": tenant.to_string(),
    });
    assert!(matches!(
        handler
            .handle(
                diport::Message::new(&invalid_id, serde_json::to_vec(&invalid)?),
                ctx,
                invalid_key,
                invalid_lease
            )
            .await,
        crate::PgConsumerTxOutcome::Reject { .. }
    ));
    let after_failure: (i64, i64) = sqlx::query_as(
        "SELECT \
         (SELECT count(*) FROM audit_entries WHERE tenant_id = $1::uuid), \
         (SELECT count(*) FROM inbox_receipts WHERE tenant_id = $1::uuid AND event_id = $2 AND status = 'done')",
    )
    .bind(tenant.to_string())
    .bind(&invalid_id)
    .fetch_one(&owner.pool)
    .await?;
    assert_eq!(after_failure, (2, 0));
    app.shutdown().await?;
    owner.shutdown().await?;
    Ok(())
}

// ── AuthGrant expiry sweeper: fixed SECURITY DEFINER capability ─────────────────

#[tokio::test(flavor = "multi_thread")]
async fn auth_grant_sweeper_deletes_only_expired_roots_and_cascades_refresh() -> TestResult {
    let (pg, owner) = connect_pg().await?;
    owner.run_migrations().await?;
    let app = connect_pg_rss_app_role(&pg, &owner).await?;
    let tenant = test_tenant();
    let expired_user = ids::UserId::parse(&uuid::Uuid::new_v4().to_string())?;
    let future_user = ids::UserId::parse(&uuid::Uuid::new_v4().to_string())?;
    seed_auth_grant_account(&owner, tenant, expired_user).await?;
    seed_auth_grant_account(&owner, tenant, future_user).await?;
    let expired_prefix = format!("expired-{}", uuid::Uuid::new_v4());
    let future_grant = format!("future-{}", uuid::Uuid::new_v4());
    sqlx::query(
        "INSERT INTO auth_grants \
         (tenant_id, grant_id, user_id, auth_time, authn_epoch_at_issue, status, \
          expires_at, created_at, closed_at, close_reason) \
         SELECT $1::uuid, $2 || '-' || lpad(series::text, 4, '0'), $3::uuid, \
                now() - interval '2 hours', 0, 'active', now() - interval '1 hour', \
                now() - interval '2 hours', NULL, NULL \
         FROM generate_series(1, 1001) AS series",
    )
    .bind(tenant.to_string())
    .bind(&expired_prefix)
    .bind(expired_user.as_uuid().to_string())
    .execute(&owner.pool)
    .await?;
    sqlx::query(
        "INSERT INTO auth_grants \
         (tenant_id, grant_id, user_id, auth_time, authn_epoch_at_issue, status, \
          expires_at, created_at, closed_at, close_reason) \
         VALUES ($1::uuid, $2, $3::uuid, now() - interval '2 hours', 0, 'active', \
                 now() + interval '1 hour', now() - interval '2 hours', NULL, NULL)",
    )
    .bind(tenant.to_string())
    .bind(&future_grant)
    .bind(future_user.as_uuid().to_string())
    .execute(&owner.pool)
    .await?;
    sqlx::query(
        "INSERT INTO refresh_tokens \
         (id, tenant_id, auth_grant_id, user_id, authn_epoch_at_issue, auth_grant_status, \
          token_hash, parent_id, lineage_id, status, issued_at, expires_at) \
         SELECT md5(grant_id)::uuid, tenant_id, grant_id, user_id, 0, 'active', \
                decode(md5(grant_id) || md5(grant_id || '-refresh'), 'hex'), \
                NULL, md5(grant_id)::uuid, 'active', now() - interval '2 hours', \
                now() + interval '1 hour' \
         FROM auth_grants \
         WHERE tenant_id = $1::uuid AND grant_id LIKE $2",
    )
    .bind(tenant.to_string())
    .bind(format!("{expired_prefix}-%"))
    .execute(&owner.pool)
    .await?;

    let sweeper = app.auth_grant_sweeper();
    let first = sweeper
        .sweep_expired(crate::AuthGrantSweepDeadline::from_timeout(
            Duration::from_secs(5),
        )?)
        .await?;
    let after_first: (i64, i64, i64) = sqlx::query_as(
        "SELECT \
         (SELECT count(*) FROM auth_grants WHERE grant_id LIKE $1), \
         (SELECT count(*) FROM refresh_tokens WHERE auth_grant_id LIKE $1), \
         (SELECT count(*) FROM auth_grants WHERE grant_id = $2)",
    )
    .bind(format!("{expired_prefix}-%"))
    .bind(&future_grant)
    .fetch_one(&owner.pool)
    .await?;
    assert_eq!(
        first, 1000,
        "one sweep must delete exactly one bounded batch"
    );
    assert_eq!(
        after_first,
        (1, 1, 1),
        "one expired root/family and the future root must remain after the first batch"
    );

    let second = sweeper
        .sweep_expired(crate::AuthGrantSweepDeadline::from_timeout(
            Duration::from_secs(5),
        )?)
        .await?;
    let third = sweeper
        .sweep_expired(crate::AuthGrantSweepDeadline::from_timeout(
            Duration::from_secs(5),
        )?)
        .await?;
    assert_eq!((first, second, third), (1000, 1, 0));
    let counts: (i64, i64, i64) = sqlx::query_as(
        "SELECT \
         (SELECT count(*) FROM auth_grants WHERE grant_id LIKE $1), \
         (SELECT count(*) FROM refresh_tokens WHERE auth_grant_id LIKE $1), \
         (SELECT count(*) FROM auth_grants WHERE grant_id = $2)",
    )
    .bind(format!("{expired_prefix}-%"))
    .bind(&future_grant)
    .fetch_one(&owner.pool)
    .await?;
    assert_eq!(counts, (0, 0, 1));

    app.shutdown().await?;
    owner.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn auth_grant_sweeper_one_deadline_covers_every_database_stage() -> TestResult {
    use crate::auth_grant_sweeper::AuthGrantSweepStage;

    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    for stage in AuthGrantSweepStage::ALL {
        let sweeper = store
            .auth_grant_sweeper()
            .with_pause_for_test(*stage, Duration::from_millis(300));
        let result = sweeper
            .sweep_expired(crate::AuthGrantSweepDeadline::from_timeout(
                Duration::from_millis(100),
            )?)
            .await;
        assert!(
            result.is_err(),
            "the single sweep deadline must cover the {stage:?} stage"
        );
        let one: i32 = sqlx::query_scalar("SELECT 1")
            .fetch_one(&store.pool)
            .await?;
        assert_eq!(one, 1, "deadline at {stage:?} must leave the pool usable");
    }
    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn auth_grant_sweeper_server_timeout_bounds_child_cascade_lock() -> TestResult {
    let (pg, owner) = connect_pg().await?;
    owner.run_migrations().await?;
    let app = connect_pg_rss_app_role(&pg, &owner).await?;
    let tenant = rss_request_context::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
    let user = ids::UserId::parse(&uuid::Uuid::new_v4().to_string())?;
    seed_auth_grant_account(&owner, tenant, user).await?;
    let grant_id = uuid::Uuid::new_v4().to_string();
    let refresh_id = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO auth_grants \
         (tenant_id, grant_id, user_id, auth_time, authn_epoch_at_issue, status, \
          expires_at, created_at, closed_at, close_reason) \
         VALUES ($1::uuid, $2, $3::uuid, now() - interval '2 hours', 0, 'active', \
                 now() - interval '1 hour', now() - interval '2 hours', NULL, NULL)",
    )
    .bind(tenant.to_string())
    .bind(&grant_id)
    .bind(user.as_uuid().to_string())
    .execute(&owner.pool)
    .await?;
    sqlx::query(
        "INSERT INTO refresh_tokens \
         (id, tenant_id, auth_grant_id, user_id, authn_epoch_at_issue, auth_grant_status, \
          token_hash, parent_id, lineage_id, status, issued_at, expires_at) \
         VALUES ($1::uuid, $2::uuid, $3, $4::uuid, 0, 'active', $5, NULL, $1::uuid, \
                 'active', now() - interval '2 hours', now() + interval '1 hour')",
    )
    .bind(&refresh_id)
    .bind(tenant.to_string())
    .bind(&grant_id)
    .bind(user.as_uuid().to_string())
    .bind([0xA7_u8; 32].as_slice())
    .execute(&owner.pool)
    .await?;

    let mut blocker = owner.pool.begin().await?;
    sqlx::query("SELECT id FROM refresh_tokens WHERE id = $1::uuid FOR UPDATE")
        .bind(&refresh_id)
        .fetch_one(&mut *blocker)
        .await?;
    let blocked = tokio::time::timeout(
        Duration::from_secs(2),
        app.auth_grant_sweeper()
            .sweep_expired(crate::AuthGrantSweepDeadline::from_timeout(
                Duration::from_millis(100),
            )?),
    )
    .await
    .map_err(|_| "outer test oracle fired before the typed sweep deadline")?;
    assert!(
        matches!(blocked, Err(ref error) if error.is_transient()),
        "child cascade lock must fail within the typed transient deadline: {blocked:?}"
    );
    blocker.rollback().await?;

    let deleted = app
        .auth_grant_sweeper()
        .sweep_expired(crate::AuthGrantSweepDeadline::from_timeout(
            Duration::from_secs(5),
        )?)
        .await?;
    assert_eq!(deleted, 1);
    let counts: (i64, i64) = sqlx::query_as(
        "SELECT \
         (SELECT count(*) FROM auth_grants WHERE tenant_id = $1::uuid AND grant_id = $2), \
         (SELECT count(*) FROM refresh_tokens WHERE id = $3::uuid)",
    )
    .bind(tenant.to_string())
    .bind(&grant_id)
    .bind(&refresh_id)
    .fetch_one(&owner.pool)
    .await?;
    assert_eq!(counts, (0, 0));
    let one: i32 = sqlx::query_scalar("SELECT 1").fetch_one(&app.pool).await?;
    assert_eq!(
        one, 1,
        "deadline cancellation must leave rss_app pool usable"
    );

    app.shutdown().await?;
    owner.shutdown().await?;
    Ok(())
}

/// The real refresh producer locks a family before its AuthGrant root. The real sweeper must wait
/// behind that family without holding the root, so releasing an independently held root can always
/// linearize both operations without a refresh↔grant deadlock.
#[tokio::test(flavor = "multi_thread")]
async fn auth_grant_sweeper_and_refresh_family_use_one_lock_order() -> TestResult {
    let (pg, owner) = connect_pg().await?;
    owner.run_migrations().await?;
    let refresh_app =
        connect_pg_rss_app_role_with_limits(&pg, &owner, 1, Duration::from_secs(8)).await?;
    let sweeper_app =
        connect_pg_rss_app_role_with_limits(&pg, &owner, 1, Duration::from_secs(8)).await?;
    let tenant = rss_request_context::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
    let case = RefreshProducerCase::new(tenant);
    case.seed(&refresh_app, &owner).await?;
    sqlx::query(
        "UPDATE auth_grants SET expires_at = clock_timestamp() - interval '1 second' \
         WHERE tenant_id = $1::uuid AND grant_id = $2",
    )
    .bind(tenant.to_string())
    .bind(case.grant.id().to_wire())
    .execute(&owner.pool)
    .await?;

    let mut root_blocker = owner.pool.begin().await?;
    let root_blocker_backend: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *root_blocker)
        .await?;
    sqlx::query(
        "SELECT grant_id FROM auth_grants \
         WHERE tenant_id = $1::uuid AND grant_id = $2 FOR UPDATE",
    )
    .bind(tenant.to_string())
    .bind(case.grant.id().to_wire())
    .fetch_one(&mut *root_blocker)
    .await?;

    let refresh_backend: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&refresh_app.pool)
        .await?;
    let sweeper_backend: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&sweeper_app.pool)
        .await?;
    let refresh_case = case.clone();
    let refresh = tokio::spawn(async move {
        crate::PgIdentitySecurityLifecycle::from_unverified_for_test(&refresh_app)
            .execute_refresh(
                refresh_producer_receipt(),
                identity_scope(tenant),
                refresh_case.rotation_command(),
            )
            .await
    });
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let blockers: Vec<i32> = sqlx::query_scalar("SELECT unnest(pg_blocking_pids($1))")
                .bind(refresh_backend)
                .fetch_all(&owner.pool)
                .await?;
            if blockers.contains(&root_blocker_backend) {
                return Ok::<(), sqlx::Error>(());
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .map_err(|_| "refresh producer did not reach the held AuthGrant root")??;
    let sweep_deadline = crate::AuthGrantSweepDeadline::from_timeout(Duration::from_secs(7))?;
    let sweep = tokio::spawn(async move {
        sweeper_app
            .auth_grant_sweeper()
            .sweep_expired(sweep_deadline)
            .await
    });
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let blockers: Vec<i32> = sqlx::query_scalar("SELECT unnest(pg_blocking_pids($1))")
                .bind(sweeper_backend)
                .fetch_all(&owner.pool)
                .await?;
            if blockers.contains(&refresh_backend) {
                return Ok::<(), sqlx::Error>(());
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .map_err(|_| "sweeper did not reach the held refresh-family lock")??;

    root_blocker.rollback().await?;
    let refresh_outcome = tokio::time::timeout(Duration::from_secs(5), refresh)
        .await
        .map_err(|_| "refresh producer did not finish after the root lock was released")???;
    assert!(matches!(
        refresh_outcome,
        identity::ports::RefreshExecutionOutcome::Expired
    ));
    let swept = tokio::time::timeout(Duration::from_secs(5), sweep)
        .await
        .map_err(|_| "sweeper did not finish after refresh serialization")???;
    assert_eq!(
        swept, 1,
        "the expired grant must be swept after serialization"
    );

    let remaining: (i64, i64) = sqlx::query_as(
        "SELECT \
         (SELECT count(*) FROM auth_grants WHERE tenant_id = $1::uuid AND grant_id = $2), \
         (SELECT count(*) FROM refresh_tokens WHERE tenant_id = $1::uuid AND auth_grant_id = $2)",
    )
    .bind(tenant.to_string())
    .bind(case.grant.id().to_wire())
    .fetch_one(&owner.pool)
    .await?;
    assert_eq!(remaining, (0, 0));
    let facts: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM outbox WHERE tenant_id = $1::uuid AND contract_id = $2",
    )
    .bind(tenant.to_string())
    .bind(identity::ports::SECURITY_EVENT_CONTRACT.contract_id())
    .fetch_one(&owner.pool)
    .await?;
    assert_eq!(facts, 0, "expiry/sweep serialization must not emit reuse");

    owner.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn auth_grant_sweeper_is_narrow_rss_app_capability() -> TestResult {
    let (pg, owner) = connect_pg().await?;
    owner.run_migrations().await?;
    let app = connect_pg_rss_app_role(&pg, &owner).await?;
    let row: (String, bool, bool, bool, bool, String) = sqlx::query_as(
        "SELECT pg_get_userbyid(p.proowner), r.rolcanlogin, r.rolbypassrls, \
         has_function_privilege('rss_app', 'rss_sweep_expired_auth_grants()', 'EXECUTE'), \
         has_table_privilege('rss_app', 'auth_grants', 'DELETE'), pg_get_functiondef(p.oid) \
         FROM pg_proc p JOIN pg_roles r ON r.oid = p.proowner \
         WHERE p.proname = 'rss_sweep_expired_auth_grants'",
    )
    .fetch_one(&owner.pool)
    .await?;
    assert_eq!(row.0, "rss_auth_grant_maintenance");
    assert!(!row.1);
    assert!(row.2);
    assert!(row.3);
    assert!(!row.4);
    let (fixed_search_path, execute_grantees): (bool, Vec<String>) = sqlx::query_as(
        "SELECT p.proconfig = ARRAY['search_path=pg_catalog, pg_temp']::text[], \
                ARRAY( \
                    SELECT COALESCE(grantee.rolname, 'PUBLIC') \
                    FROM aclexplode(COALESCE(p.proacl, acldefault('f', p.proowner))) acl \
                    LEFT JOIN pg_roles grantee ON grantee.oid = acl.grantee \
                    WHERE acl.privilege_type = 'EXECUTE' \
                    ORDER BY COALESCE(grantee.rolname, 'PUBLIC') \
                ) \
         FROM pg_proc p \
         WHERE p.oid = 'rss_sweep_expired_auth_grants()'::regprocedure",
    )
    .fetch_one(&owner.pool)
    .await?;
    assert!(fixed_search_path, "sweeper search_path must be exact");
    assert_eq!(
        execute_grantees,
        ["rss_app", "rss_auth_grant_maintenance"],
        "sweeper EXECUTE ACL must contain only the serving role and its NOLOGIN owner"
    );
    let refresh_privileges: Vec<String> = sqlx::query_scalar(
        "SELECT ARRAY( \
             SELECT acl.privilege_type \
             FROM pg_class relation, \
                  LATERAL aclexplode(COALESCE(relation.relacl, acldefault('r', relation.relowner))) acl \
             JOIN pg_roles grantee ON grantee.oid = acl.grantee \
             WHERE relation.oid = 'public.refresh_tokens'::regclass \
               AND grantee.rolname = 'rss_auth_grant_maintenance' \
             ORDER BY acl.privilege_type \
         )",
    )
    .fetch_one(&owner.pool)
    .await?;
    assert_eq!(
        refresh_privileges,
        ["DELETE", "SELECT", "UPDATE"],
        "maintenance refresh-family privileges must be an exact, non-empty set"
    );
    let root_privileges: Vec<String> = sqlx::query_scalar(
        "SELECT ARRAY( \
             SELECT acl.privilege_type \
             FROM pg_class relation, \
                  LATERAL aclexplode(COALESCE(relation.relacl, acldefault('r', relation.relowner))) acl \
             JOIN pg_roles grantee ON grantee.oid = acl.grantee \
             WHERE relation.oid = 'public.auth_grants'::regclass \
               AND grantee.rolname = 'rss_auth_grant_maintenance' \
             ORDER BY acl.privilege_type \
         )",
    )
    .fetch_one(&owner.pool)
    .await?;
    assert_eq!(
        root_privileges,
        ["DELETE", "SELECT", "UPDATE"],
        "maintenance AuthGrant privileges must be an exact, non-empty set"
    );
    let capability_is_exact =
        |search_path: bool, execute: &[String], refresh: &[String], root: &[String]| {
            search_path
                && execute == ["rss_app", "rss_auth_grant_maintenance"]
                && refresh == ["DELETE", "SELECT", "UPDATE"]
                && root == ["DELETE", "SELECT", "UPDATE"]
        };
    assert!(capability_is_exact(
        fixed_search_path,
        &execute_grantees,
        &refresh_privileges,
        &root_privileges,
    ));
    assert!(
        !capability_is_exact(true, &[], &refresh_privileges, &root_privileges),
        "an empty ACL must not satisfy the exact capability gate"
    );
    let mut extra_grantee = execute_grantees.clone();
    extra_grantee.push("PUBLIC".to_owned());
    assert!(
        !capability_is_exact(true, &extra_grantee, &refresh_privileges, &root_privileges,),
        "an extra function grantee must fail the exact capability gate"
    );
    let mut extra_table_privilege = refresh_privileges.clone();
    extra_table_privilege.push("INSERT".to_owned());
    assert!(
        !capability_is_exact(
            true,
            &execute_grantees,
            &extra_table_privilege,
            &root_privileges,
        ),
        "an extra maintenance table privilege must fail the exact capability gate"
    );
    let family_lock = row
        .5
        .find("PERFORM refresh.id")
        .ok_or("sweeper family lock is missing")?;
    let root_delete = row
        .5
        .find("DELETE FROM public.auth_grants")
        .ok_or("sweeper root delete is missing")?;
    assert!(
        row.5.contains("LIMIT 1000")
            && row.5.contains("ORDER BY refresh.id")
            && row.5.contains("FOR UPDATE")
            && family_lock < root_delete,
        "maintenance capability must lock the ordered family before deleting the root"
    );

    let direct_delete = sqlx::query("DELETE FROM auth_grants")
        .execute(&app.pool)
        .await;
    assert!(direct_delete.is_err());
    app.shutdown().await?;
    owner.shutdown().await?;
    Ok(())
}

/// dead_letter store enrollment：统一 tenant conformance 覆盖 round-trip / cross-tenant invisible / non-interference。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
// reason: 集成测试 fixture 构造已知合法 tenant；item-level carve-out。
async fn dead_letter_tenant_conformance() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    sqlx::query("GRANT rss_app TO CURRENT_USER")
        .execute(&store.pool)
        .await?;

    let dl = store.dead_letter(test_dlx_payload_protector());
    let domain = unique_domain("dead-letter-conf");
    let message_id = unique_event_id("dead-letter-conf-msg");
    let tenant_a = rss_request_context::TenantId::parse(COTX_TENANT_A).unwrap();
    let tenant_b = rss_request_context::TenantId::parse(COTX_TENANT_B).unwrap();

    testkit::tenant_conformance::assert_tenant_isolation(
        tenant_a,
        tenant_b,
        |tenant| {
            let dl = &dl;
            let domain = domain.clone();
            let message_id = message_id.clone();
            async move {
                dl.write_dead_letter(DeadLetterRecord::new(
                    tenant,
                    &message_id,
                    diport::DeadLetterProvenance::consumer(domain.as_str(), "tenant-conf-consumer"),
                    "contract-conf",
                    "test.event",
                    Some("tenant-conf-consumer".to_string()),
                    b"payload".to_vec(),
                    diport::DeadLetterSummary::new("tenant conformance"),
                    1,
                    EnvelopeMetadata::empty(),
                ))
                .await?;
                Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
            }
        },
        |tenant| {
            let pool = store.pool.clone();
            let message_id = message_id.clone();
            async move {
                let mut tx = pool.begin().await?;
                sqlx::query("SET LOCAL ROLE rss_app")
                    .execute(&mut *tx)
                    .await?;
                crate::cotx::set_local_tenant(&mut tx, tenant).await?;
                let cnt: (i64,) =
                    sqlx::query_as("SELECT count(*) FROM dead_letter WHERE message_id = $1")
                        .bind(&message_id)
                        .fetch_one(&mut *tx)
                        .await?;
                tx.rollback().await?;
                Ok::<bool, Box<dyn std::error::Error + Send + Sync>>(cnt.0 > 0)
            }
        },
        |_| rss_conformance::ConformanceErrorCategory::Storage,
    )
    .await?;

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn auth_grant_login_commits_root_refresh_and_outbox_together() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let tenant = test_tenant();
    let user_id = ids::UserId::parse(&uuid::Uuid::new_v4().to_string())?;
    seed_auth_grant_account(&store, tenant, user_id).await?;
    let grant_id = uuid::Uuid::new_v4().to_string();
    let refresh_id = uuid::Uuid::new_v4().to_string();
    let event_id = unique_event_id("auth-grant-login");
    let (grant, refresh) = auth_grant_fixture(tenant, user_id, &grant_id, &refresh_id, [0xA1; 32]);
    let (mutation, entry, envelope) = auth_grant_login_parts(&event_id, grant, refresh);

    let _persisted = crate::PgAuthGrantLifecycle::new(&store, fixed_clock())
        .persist_login_grant(
            login_producer_receipt(),
            identity_scope(tenant),
            mutation,
            reviewed_generated_event::<generated::event::identity_v1::session_created::Contract>(
                entry, envelope,
            )
            .await?,
        )
        .await?;

    assert_eq!(
        auth_grant_login_counts(&store, &grant_id, &refresh_id, &event_id).await?,
        (1, 1, 1)
    );
    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn refresh_producer_normal_rotation_commits_child_without_security_fact() -> TestResult {
    let (pg, owner) = connect_pg().await?;
    owner.run_migrations().await?;
    let app = connect_pg_rss_app_role(&pg, &owner).await?;
    let tenant = rss_request_context::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
    let case = RefreshProducerCase::new(tenant);
    case.seed(&app, &owner).await?;

    let outcome = crate::PgIdentitySecurityLifecycle::from_unverified_for_test(&app)
        .execute_refresh(
            refresh_producer_receipt(),
            identity_scope(tenant),
            case.rotation_command(),
        )
        .await?;
    assert!(matches!(
        outcome,
        identity::ports::RefreshExecutionOutcome::Applied(_)
    ));
    assert_eq!(
        refresh_producer_snapshot(&owner, &case).await?,
        ("active".to_owned(), 1, 2, 0),
        "normal rotation consumes the source, inserts one active child, and emits no security fact"
    );

    app.shutdown().await?;
    owner.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn refresh_rotation_commit_unknown_never_returns_a_persisted_receipt() -> TestResult {
    let (pg, owner) = connect_pg().await?;
    owner.run_migrations().await?;
    let app = connect_pg_rss_app_role(&pg, &owner).await?;
    let tenant = rss_request_context::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
    let case = RefreshProducerCase::new(tenant);
    case.seed(&app, &owner).await?;

    let unknown = crate::PgIdentitySecurityLifecycle::from_unverified_for_test(&app)
        .with_fault(crate::identity_security_lifecycle::IdentitySecurityFault::CommitUnknown)
        .execute_refresh(
            refresh_producer_receipt(),
            identity_scope(tenant),
            case.rotation_command(),
        )
        .await;
    assert!(
        unknown.is_err(),
        "a lost commit acknowledgement must not return Applied or its persisted receipt"
    );
    assert_eq!(
        refresh_producer_snapshot(&owner, &case).await?,
        ("active".to_owned(), 1, 2, 0),
        "PostgreSQL may have committed the child, but the adapter must expose no releasable receipt"
    );

    app.shutdown().await?;
    owner.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn refresh_replay_containment_is_atomic_with_the_winning_rotation() -> TestResult {
    let (pg, owner) = connect_pg().await?;
    owner.run_migrations().await?;
    let app_a = connect_pg_rss_app_role(&pg, &owner).await?;
    let app_b = connect_pg_rss_app_role(&pg, &owner).await?;
    let tenant = rss_request_context::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
    let case = RefreshProducerCase::new(tenant);
    case.seed(&app_a, &owner).await?;
    let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(2));
    let lifecycle_a = crate::PgIdentitySecurityLifecycle::from_unverified_for_test(&app_a)
        .with_start_barrier(std::sync::Arc::clone(&barrier));
    let lifecycle_b = crate::PgIdentitySecurityLifecycle::from_unverified_for_test(&app_b)
        .with_start_barrier(barrier);

    let (first, second) = tokio::join!(
        lifecycle_a.execute_refresh(
            refresh_producer_receipt(),
            identity_scope(tenant),
            case.rotation_command(),
        ),
        lifecycle_b.execute_refresh(
            refresh_producer_receipt(),
            identity_scope(tenant),
            case.rotation_command(),
        ),
    );
    let outcomes = [first?, second?];
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(
                outcome,
                identity::ports::RefreshExecutionOutcome::Applied(_)
            ))
            .count(),
        1,
        "exactly one transaction may acknowledge the rotated bearer"
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(
                outcome,
                identity::ports::RefreshExecutionOutcome::ReuseContained
            ))
            .count(),
        1,
        "the CAS loser must contain reuse in its same producer transaction"
    );
    assert_eq!(
        refresh_producer_snapshot(&owner, &case).await?,
        ("compromised".to_owned(), 0, 0, 1),
        "reuse must atomically compromise the grant, revoke the family, and append one fact"
    );

    let reader = crate::PgRefreshTokenStore::from_unverified_for_test(&app_a);
    let consumed = reader
        .find_by_hash(identity_scope(tenant), case.old.token_hash().clone())
        .await?
        .ok_or("consumed source refresh is missing")?;
    let repair_evidence = consumed.clone();
    let repeated = crate::PgIdentitySecurityLifecycle::from_unverified_for_test(&app_a)
        .execute_refresh(
            refresh_producer_receipt(),
            identity_scope(tenant),
            identity::test_support::refresh_reuse_command(
                consumed,
                case.rotation.new_record().issued_at() + Duration::from_secs(1),
            ),
        )
        .await?;
    assert!(matches!(
        repeated,
        identity::ports::RefreshExecutionOutcome::AlreadyContained
    ));
    assert_eq!(refresh_producer_snapshot(&owner, &case).await?.3, 1);

    sqlx::query(
        "ALTER TABLE refresh_tokens \
         DROP CONSTRAINT refresh_tokens_terminal_grant_requires_revoked",
    )
    .execute(&owner.pool)
    .await?;
    sqlx::query(
        "UPDATE refresh_tokens SET status = 'active' \
         WHERE tenant_id = $1::uuid AND id = $2::uuid",
    )
    .bind(tenant.to_string())
    .bind(case.rotation.new_record().id().as_str())
    .execute(&owner.pool)
    .await?;
    let repaired = crate::PgIdentitySecurityLifecycle::from_unverified_for_test(&app_a)
        .execute_refresh(
            refresh_producer_receipt(),
            identity_scope(tenant),
            identity::test_support::refresh_reuse_command(
                repair_evidence,
                case.rotation.new_record().issued_at() + Duration::from_secs(2),
            ),
        )
        .await?;
    assert!(matches!(
        repaired,
        identity::ports::RefreshExecutionOutcome::AlreadyContained
    ));
    assert_eq!(
        refresh_producer_snapshot(&owner, &case).await?,
        ("compromised".to_owned(), 0, 0, 1),
        "already-contained reuse must idempotently repair a non-revoked family without a second fact"
    );

    app_a.shutdown().await?;
    app_b.shutdown().await?;
    owner.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn refresh_reuse_faults_roll_back_family_grant_and_outbox_together() -> TestResult {
    let (pg, owner) = connect_pg().await?;
    owner.run_migrations().await?;
    let app = connect_pg_rss_app_role(&pg, &owner).await?;
    let tenant = rss_request_context::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
    let case = RefreshProducerCase::new(tenant);
    case.seed(&app, &owner).await?;
    crate::PgIdentitySecurityLifecycle::from_unverified_for_test(&app)
        .execute_refresh(
            refresh_producer_receipt(),
            identity_scope(tenant),
            case.rotation_command(),
        )
        .await?;
    let reader = crate::PgRefreshTokenStore::from_unverified_for_test(&app);
    let consumed = reader
        .find_by_hash(identity_scope(tenant), case.old.token_hash().clone())
        .await?
        .ok_or("consumed source refresh is missing")?;
    let failed = crate::PgIdentitySecurityLifecycle::from_unverified_for_test(&app)
        .with_fault(crate::identity_security_lifecycle::IdentitySecurityFault::AfterGrant)
        .execute_refresh(
            refresh_producer_receipt(),
            identity_scope(tenant),
            identity::test_support::refresh_reuse_command(
                consumed.clone(),
                case.rotation.new_record().issued_at() + Duration::from_secs(1),
            ),
        )
        .await;
    assert!(failed.is_err(), "injected containment fault must fail");
    assert_eq!(
        refresh_producer_snapshot(&owner, &case).await?,
        ("active".to_owned(), 1, 2, 0),
        "family and grant writes must roll back with the absent fact"
    );

    let contained = crate::PgIdentitySecurityLifecycle::from_unverified_for_test(&app)
        .execute_refresh(
            refresh_producer_receipt(),
            identity_scope(tenant),
            identity::test_support::refresh_reuse_command(
                consumed,
                case.rotation.new_record().issued_at() + Duration::from_secs(2),
            ),
        )
        .await?;
    assert!(matches!(
        contained,
        identity::ports::RefreshExecutionOutcome::ReuseContained
    ));
    assert_eq!(
        refresh_producer_snapshot(&owner, &case).await?,
        ("compromised".to_owned(), 0, 0, 1)
    );

    app.shutdown().await?;
    owner.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn refresh_rotation_after_family_fault_rolls_back_and_can_retry_cleanly() -> TestResult {
    let (pg, owner) = connect_pg().await?;
    owner.run_migrations().await?;
    let app = connect_pg_rss_app_role(&pg, &owner).await?;
    let tenant = rss_request_context::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
    let case = RefreshProducerCase::new(tenant);
    case.seed(&app, &owner).await?;

    let failed = crate::PgIdentitySecurityLifecycle::from_unverified_for_test(&app)
        .with_fault(crate::identity_security_lifecycle::IdentitySecurityFault::AfterFamily)
        .execute_refresh(
            refresh_producer_receipt(),
            identity_scope(tenant),
            case.rotation_command(),
        )
        .await;
    assert!(
        failed.is_err(),
        "fault after consume+insert must reject normal rotation"
    );

    let rolled_back: (String, String, i64, i64, i64) = sqlx::query_as(
        "SELECT \
         (SELECT status FROM auth_grants WHERE tenant_id = $1::uuid AND grant_id = $2), \
         (SELECT status FROM refresh_tokens WHERE tenant_id = $1::uuid AND id = $3::uuid), \
         (SELECT count(*) FROM refresh_tokens WHERE tenant_id = $1::uuid AND id = $4::uuid), \
         (SELECT count(*) FROM outbox WHERE tenant_id = $1::uuid AND contract_id = $5), \
         (SELECT count(*) FROM projection_events \
          WHERE metadata ->> 'tenantId' = $1 AND contract_id = $5)",
    )
    .bind(tenant.to_string())
    .bind(case.grant.id().to_wire())
    .bind(case.old.id().as_str())
    .bind(case.rotation.new_record().id().as_str())
    .bind(identity::ports::SECURITY_EVENT_CONTRACT.contract_id())
    .fetch_one(&owner.pool)
    .await?;
    assert_eq!(
        rolled_back,
        ("active".to_owned(), "active".to_owned(), 0, 0, 0),
        "AfterFamily must roll back old consume, child insert, and every producer side effect"
    );

    let retried = crate::PgIdentitySecurityLifecycle::from_unverified_for_test(&app)
        .execute_refresh(
            refresh_producer_receipt(),
            identity_scope(tenant),
            case.rotation_command(),
        )
        .await?;
    assert!(matches!(
        retried,
        identity::ports::RefreshExecutionOutcome::Applied(_)
    ));
    let persisted: (String, String, i64, i64, i64) = sqlx::query_as(
        "SELECT \
         (SELECT status FROM auth_grants WHERE tenant_id = $1::uuid AND grant_id = $2), \
         (SELECT status FROM refresh_tokens WHERE tenant_id = $1::uuid AND id = $3::uuid), \
         (SELECT count(*) FROM refresh_tokens WHERE tenant_id = $1::uuid AND id = $4::uuid), \
         (SELECT count(*) FROM outbox WHERE tenant_id = $1::uuid AND contract_id = $5), \
         (SELECT count(*) FROM projection_events \
          WHERE metadata ->> 'tenantId' = $1 AND contract_id = $5)",
    )
    .bind(tenant.to_string())
    .bind(case.grant.id().to_wire())
    .bind(case.old.id().as_str())
    .bind(case.rotation.new_record().id().as_str())
    .bind(identity::ports::SECURITY_EVENT_CONTRACT.contract_id())
    .fetch_one(&owner.pool)
    .await?;
    assert_eq!(
        persisted,
        ("active".to_owned(), "consumed".to_owned(), 1, 0, 0),
        "fault-free retry must apply one child without emitting a security fact"
    );

    app.shutdown().await?;
    owner.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn refresh_reuse_fault_matrix_is_all_or_none_and_commit_unknown_has_no_partial_state()
-> TestResult {
    use crate::identity_security_lifecycle::IdentitySecurityFault;

    let (pg, owner) = connect_pg().await?;
    owner.run_migrations().await?;
    let app = connect_pg_rss_app_role(&pg, &owner).await?;
    for fault in [
        IdentitySecurityFault::AfterFamily,
        IdentitySecurityFault::AfterGrant,
        IdentitySecurityFault::AfterProjection,
        IdentitySecurityFault::OutboxAppend,
        IdentitySecurityFault::AfterOutboxBeforeCommit,
    ] {
        let tenant = rss_request_context::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
        let case = RefreshProducerCase::new(tenant);
        case.seed(&app, &owner).await?;
        crate::PgIdentitySecurityLifecycle::from_unverified_for_test(&app)
            .execute_refresh(
                refresh_producer_receipt(),
                identity_scope(tenant),
                case.rotation_command(),
            )
            .await?;
        let source = crate::PgRefreshTokenStore::from_unverified_for_test(&app)
            .find_by_hash(identity_scope(tenant), case.old.token_hash().clone())
            .await?
            .ok_or("consumed source refresh is missing")?;
        let failed = crate::PgIdentitySecurityLifecycle::from_unverified_for_test(&app)
            .with_fault(fault)
            .execute_refresh(
                refresh_producer_receipt(),
                identity_scope(tenant),
                identity::test_support::refresh_reuse_command(
                    source,
                    case.rotation.new_record().issued_at() + Duration::from_secs(1),
                ),
            )
            .await;
        assert!(failed.is_err(), "fault stage must reject containment");
        assert_eq!(
            refresh_producer_snapshot(&owner, &case).await?,
            ("active".to_owned(), 1, 2, 0),
            "fault stage must roll back family, grant, and security fact"
        );
        let projections: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM projection_events \
             WHERE metadata ->> 'tenantId' = $1 AND contract_id = $2",
        )
        .bind(tenant.to_string())
        .bind(identity::ports::SECURITY_EVENT_CONTRACT.contract_id())
        .fetch_one(&owner.pool)
        .await?;
        assert_eq!(
            projections, 0,
            "fault stage must roll back the real projection append boundary"
        );
    }

    let tenant = rss_request_context::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
    let case = RefreshProducerCase::new(tenant);
    case.seed(&app, &owner).await?;
    crate::PgIdentitySecurityLifecycle::from_unverified_for_test(&app)
        .execute_refresh(
            refresh_producer_receipt(),
            identity_scope(tenant),
            case.rotation_command(),
        )
        .await?;
    let source = crate::PgRefreshTokenStore::from_unverified_for_test(&app)
        .find_by_hash(identity_scope(tenant), case.old.token_hash().clone())
        .await?
        .ok_or("consumed source refresh is missing")?;
    let unknown = crate::PgIdentitySecurityLifecycle::from_unverified_for_test(&app)
        .with_fault(IdentitySecurityFault::CommitUnknown)
        .execute_refresh(
            refresh_producer_receipt(),
            identity_scope(tenant),
            identity::test_support::refresh_reuse_command(
                source,
                case.rotation.new_record().issued_at() + Duration::from_secs(1),
            ),
        )
        .await;
    assert!(
        unknown.is_err(),
        "commit unknown must never acknowledge containment"
    );
    let snapshot = refresh_producer_snapshot(&owner, &case).await?;
    assert!(
        snapshot == ("active".to_owned(), 1, 2, 0)
            || snapshot == ("compromised".to_owned(), 0, 0, 1),
        "commit unknown may settle absent or complete, never partial: {snapshot:?}"
    );

    app.shutdown().await?;
    owner.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn refresh_producer_enforces_lineage_root_lifetime_and_family_binding() -> TestResult {
    let (pg, owner) = connect_pg().await?;
    owner.run_migrations().await?;
    let app = connect_pg_rss_app_role(&pg, &owner).await?;
    let tenant = rss_request_context::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
    let root_expired = RefreshProducerCase::new(tenant);
    root_expired.seed(&app, &owner).await?;
    crate::PgIdentitySecurityLifecycle::from_unverified_for_test(&app)
        .execute_refresh(
            refresh_producer_receipt(),
            identity_scope(tenant),
            root_expired.rotation_command(),
        )
        .await?;
    let reader = crate::PgRefreshTokenStore::from_unverified_for_test(&app);
    let child = reader
        .find_by_hash(
            identity_scope(tenant),
            root_expired.rotation.new_record().token_hash().clone(),
        )
        .await?
        .ok_or("rotated child is missing")?;
    let mut second_hash = [0_u8; 32];
    second_hash[..16].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
    second_hash[16..].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
    let second_rotation = identity::test_support::refresh_rotation(
        &child,
        &uuid::Uuid::new_v4().to_string(),
        second_hash,
        child.issued_at() + Duration::from_secs(1),
    );
    let second_command = identity::test_support::refresh_rotation_command(
        child,
        root_expired.grant.clone(),
        second_rotation.clone(),
        second_rotation.new_record().issued_at(),
    );
    sqlx::query(
        "UPDATE refresh_tokens SET expires_at = clock_timestamp() - interval '1 second' \
         WHERE tenant_id = $1::uuid AND id = $2::uuid",
    )
    .bind(tenant.to_string())
    .bind(root_expired.old.id().as_str())
    .execute(&owner.pool)
    .await?;
    let expired = crate::PgIdentitySecurityLifecycle::from_unverified_for_test(&app)
        .execute_refresh(
            refresh_producer_receipt(),
            identity_scope(tenant),
            second_command,
        )
        .await?;
    assert!(matches!(
        expired,
        identity::ports::RefreshExecutionOutcome::Expired
    ));
    let inserted: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM refresh_tokens WHERE tenant_id = $1::uuid AND id = $2::uuid",
    )
    .bind(tenant.to_string())
    .bind(second_rotation.new_record().id().as_str())
    .fetch_one(&owner.pool)
    .await?;
    assert_eq!(
        inserted, 0,
        "expired lineage root must fence the child write"
    );

    let corrupt_family = RefreshProducerCase::new(tenant);
    corrupt_family.seed(&app, &owner).await?;
    crate::PgIdentitySecurityLifecycle::from_unverified_for_test(&app)
        .execute_refresh(
            refresh_producer_receipt(),
            identity_scope(tenant),
            corrupt_family.rotation_command(),
        )
        .await?;
    let child = reader
        .find_by_hash(
            identity_scope(tenant),
            corrupt_family.rotation.new_record().token_hash().clone(),
        )
        .await?
        .ok_or("rotated child is missing")?;
    let next_rotation = identity::test_support::refresh_rotation(
        &child,
        &uuid::Uuid::new_v4().to_string(),
        [0xA5; 32],
        child.issued_at() + Duration::from_secs(1),
    );
    let corrupt_command = identity::test_support::refresh_rotation_command(
        child,
        corrupt_family.grant.clone(),
        next_rotation,
        corrupt_family.rotation.new_record().issued_at() + Duration::from_secs(1),
    );
    sqlx::query(
        "UPDATE refresh_tokens SET lineage_id = $3::uuid \
         WHERE tenant_id = $1::uuid AND id = $2::uuid",
    )
    .bind(tenant.to_string())
    .bind(corrupt_family.old.id().as_str())
    .bind(uuid::Uuid::new_v4().to_string())
    .execute(&owner.pool)
    .await?;
    assert!(matches!(
        crate::PgIdentitySecurityLifecycle::from_unverified_for_test(&app)
            .execute_refresh(
                refresh_producer_receipt(),
                identity_scope(tenant),
                corrupt_command,
            )
            .await,
        Err(IdentityError::Storage(_))
    ));

    app.shutdown().await?;
    owner.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn auth_grant_validator_fences_every_durable_binding_in_one_port_call() -> TestResult {
    let (pg, owner) = connect_pg().await?;
    owner.run_migrations().await?;
    let reader = connect_pg_rss_app_read_role(&pg, &owner).await?;
    let tenant = rss_request_context::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
    let other_tenant = rss_request_context::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
    let user_id = ids::UserId::parse(&uuid::Uuid::new_v4().to_string())?;
    let other_user = ids::UserId::parse(&uuid::Uuid::new_v4().to_string())?;
    seed_auth_grant_account(&owner, tenant, user_id).await?;

    let grant_id = uuid::Uuid::new_v4().to_string();
    let refresh_id = uuid::Uuid::new_v4().to_string();
    let event_id = unique_event_id("auth-grant-validator");
    let (grant, refresh) = auth_grant_fixture(tenant, user_id, &grant_id, &refresh_id, [0xA7; 32]);
    let (mutation, entry, envelope) = auth_grant_login_parts(&event_id, grant.clone(), refresh);
    let lifecycle = crate::PgAuthGrantLifecycle::new(&owner, fixed_clock());
    let _persisted = lifecycle
        .persist_login_grant(
            login_producer_receipt(),
            identity_scope(tenant),
            mutation,
            reviewed_generated_event::<generated::event::identity_v1::session_created::Contract>(
                entry, envelope,
            )
            .await?,
        )
        .await?;

    let validator = crate::PgAuthGrantValidator::from_unverified_for_test(&reader);
    let valid_observation = grant.created_at() + Duration::from_secs(1);
    let input = auth_grant_validation_input(
        tenant,
        user_id,
        &grant_id,
        i64::try_from(TEST_OCCURRED_SECS)?,
        0,
    )
    .await?;
    assert!(
        validator
            .is_current(identity_scope(input.tenant()), &input, valid_observation)
            .await?
    );
    assert!(
        !validator
            .is_current(identity_scope(other_tenant), &input, valid_observation)
            .await?,
        "repo scope and verified receipt tenant must be inseparable"
    );

    let missing = auth_grant_validation_input(
        tenant,
        user_id,
        &uuid::Uuid::new_v4().to_string(),
        i64::try_from(TEST_OCCURRED_SECS)?,
        0,
    )
    .await?;
    assert!(
        !validator
            .is_current(
                identity_scope(missing.tenant()),
                &missing,
                valid_observation,
            )
            .await?
    );

    let wrong_subject = auth_grant_validation_input(
        tenant,
        other_user,
        &grant_id,
        i64::try_from(TEST_OCCURRED_SECS)?,
        0,
    )
    .await?;
    assert!(
        !validator
            .is_current(
                identity_scope(wrong_subject.tenant()),
                &wrong_subject,
                valid_observation,
            )
            .await?
    );

    let wrong_tenant = auth_grant_validation_input(
        other_tenant,
        user_id,
        &grant_id,
        i64::try_from(TEST_OCCURRED_SECS)?,
        0,
    )
    .await?;
    assert!(
        !validator
            .is_current(
                identity_scope(wrong_tenant.tenant()),
                &wrong_tenant,
                valid_observation,
            )
            .await?
    );

    let wrong_auth_time = auth_grant_validation_input(
        tenant,
        user_id,
        &grant_id,
        i64::try_from(TEST_OCCURRED_SECS + 1)?,
        0,
    )
    .await?;
    assert!(
        !validator
            .is_current(
                identity_scope(wrong_auth_time.tenant()),
                &wrong_auth_time,
                valid_observation,
            )
            .await?
    );

    let wrong_grant_epoch = auth_grant_validation_input(
        tenant,
        user_id,
        &grant_id,
        i64::try_from(TEST_OCCURRED_SECS)?,
        1,
    )
    .await?;
    assert!(
        !validator
            .is_current(
                identity_scope(wrong_grant_epoch.tenant()),
                &wrong_grant_epoch,
                valid_observation,
            )
            .await?
    );

    assert!(
        !validator
            .is_current(identity_scope(input.tenant()), &input, grant.expires_at())
            .await?,
        "expiry must be strictly later than the provider observation"
    );

    sqlx::query(
        "UPDATE account_security_states SET authn_epoch = 1, version = version + 1, \
         updated_at = now() WHERE tenant_id = $1::uuid AND user_id = $2::uuid",
    )
    .bind(tenant.to_string())
    .bind(user_id.as_uuid().to_string())
    .execute(&owner.pool)
    .await?;
    assert!(
        !validator
            .is_current(identity_scope(input.tenant()), &input, valid_observation)
            .await?
    );
    sqlx::query(
        "UPDATE account_security_states SET authn_epoch = 0, version = version + 1, \
         updated_at = now() WHERE tenant_id = $1::uuid AND user_id = $2::uuid",
    )
    .bind(tenant.to_string())
    .bind(user_id.as_uuid().to_string())
    .execute(&owner.pool)
    .await?;

    sqlx::query(
        "UPDATE account_security_states SET status = 'suspended', version = version + 1, \
         status_changed_at = now(), updated_at = now() \
         WHERE tenant_id = $1::uuid AND user_id = $2::uuid",
    )
    .bind(tenant.to_string())
    .bind(user_id.as_uuid().to_string())
    .execute(&owner.pool)
    .await?;
    assert!(
        !validator
            .is_current(identity_scope(input.tenant()), &input, valid_observation)
            .await?
    );
    sqlx::query(
        "UPDATE account_security_states SET status = 'active', version = version + 1, \
         status_changed_at = now(), updated_at = now() \
         WHERE tenant_id = $1::uuid AND user_id = $2::uuid",
    )
    .bind(tenant.to_string())
    .bind(user_id.as_uuid().to_string())
    .execute(&owner.pool)
    .await?;

    let logout = identity::test_support::logout_current_command(
        grant.clone(),
        grant.created_at() + Duration::from_secs(2),
    );
    let _ = execute_logout_current_route(
        &crate::PgIdentitySecurityLifecycle::from_unverified_for_test(&owner),
        tenant,
        logout,
    )
    .await?;
    assert!(
        !validator
            .is_current(identity_scope(input.tenant()), &input, valid_observation)
            .await?
    );

    reader.shutdown().await?;
    assert!(matches!(
        validator
            .is_current(identity_scope(input.tenant()), &input, valid_observation)
            .await,
        Err(IdentityError::Storage(_))
    ));
    owner.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn auth_grant_login_each_business_write_failure_rolls_back_everything() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let tenant = test_tenant();
    for (suffix, fault) in [
        (
            0xB1,
            crate::auth_grant_lifecycle::AuthGrantLoginFault::AfterGrantWrite,
        ),
        (
            0xB2,
            crate::auth_grant_lifecycle::AuthGrantLoginFault::AfterRefreshWrite,
        ),
    ] {
        let user_id = ids::UserId::parse(&uuid::Uuid::new_v4().to_string())?;
        seed_auth_grant_account(&store, tenant, user_id).await?;
        let grant_id = uuid::Uuid::new_v4().to_string();
        let refresh_id = uuid::Uuid::new_v4().to_string();
        let event_id = unique_event_id("auth-grant-login-fault");
        let (grant, refresh) =
            auth_grant_fixture(tenant, user_id, &grant_id, &refresh_id, [suffix; 32]);
        let (mutation, entry, envelope) = auth_grant_login_parts(&event_id, grant, refresh);
        let result =
            crate::PgAuthGrantLifecycle::new(&store, fixed_clock())
                .with_login_fault(&grant_id, fault)
                .persist_login_grant(
                    login_producer_receipt(),
                    identity_scope(tenant),
                    mutation,
                    reviewed_generated_event::<
                        generated::event::identity_v1::session_created::Contract,
                    >(entry, envelope)
                    .await?,
                )
                .await;
        assert!(result.is_err(), "injected write failure must surface");
        assert_eq!(
            auth_grant_login_counts(&store, &grant_id, &refresh_id, &event_id).await?,
            (0, 0, 0),
            "no partial login persistence is permitted"
        );
    }
    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn auth_grant_login_outbox_conflict_rolls_back_root_and_refresh() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let tenant = test_tenant();
    let user_id = ids::UserId::parse(&uuid::Uuid::new_v4().to_string())?;
    seed_auth_grant_account(&store, tenant, user_id).await?;
    let grant_id = uuid::Uuid::new_v4().to_string();
    let refresh_id = uuid::Uuid::new_v4().to_string();
    let event_id = unique_event_id("auth-grant-outbox-conflict");
    let seed = seed_conflicting_outbox_fact(&store, tenant, &event_id).await?;
    let (grant, refresh) = auth_grant_fixture(tenant, user_id, &grant_id, &refresh_id, [0xC1; 32]);
    let (mutation, entry, envelope) = auth_grant_login_parts(&event_id, grant, refresh);

    let conflict = crate::PgAuthGrantLifecycle::new(&store, fixed_clock())
        .persist_login_grant(
            login_producer_receipt(),
            identity_scope(tenant),
            mutation,
            reviewed_generated_event::<generated::event::identity_v1::session_created::Contract>(
                entry, envelope,
            )
            .await?,
        )
        .await
        .err()
        .expect("outbox fact conflict must reject login");
    assert_eq!(conflict.kind(), OutboxEmitErrorKind::FactConflict);
    assert_eq!(
        auth_grant_login_counts(&store, &grant_id, &refresh_id, &event_id).await?,
        (0, 0, 1)
    );
    assert_seed_fact_unchanged(&store, &event_id, &seed).await?;
    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn auth_grant_login_commit_unknown_returns_error_without_partial_state() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let tenant = test_tenant();
    let user_id = ids::UserId::parse(&uuid::Uuid::new_v4().to_string())?;
    seed_auth_grant_account(&store, tenant, user_id).await?;
    let grant_id = uuid::Uuid::new_v4().to_string();
    let refresh_id = uuid::Uuid::new_v4().to_string();
    let event_id = unique_event_id("auth-grant-commit-unknown");
    let (grant, refresh) = auth_grant_fixture(tenant, user_id, &grant_id, &refresh_id, [0xD1; 32]);
    let (mutation, entry, envelope) = auth_grant_login_parts(&event_id, grant, refresh);

    let result = crate::PgAuthGrantLifecycle::new(&store, fixed_clock())
        .with_login_fault(
            &grant_id,
            crate::auth_grant_lifecycle::AuthGrantLoginFault::CommitUnknown,
        )
        .persist_login_grant(
            login_producer_receipt(),
            identity_scope(tenant),
            mutation,
            reviewed_generated_event::<generated::event::identity_v1::session_created::Contract>(
                entry, envelope,
            )
            .await?,
        )
        .await;
    assert!(
        result.is_err(),
        "commit unknown must never acknowledge login"
    );
    let counts = auth_grant_login_counts(&store, &grant_id, &refresh_id, &event_id).await?;
    assert!(
        counts == (0, 0, 0) || counts == (1, 1, 1),
        "commit unknown may settle absent or complete, never partial: {counts:?}"
    );
    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn auth_grant_login_plain_producer_lock_wait_is_bounded_and_rolls_back() -> TestResult {
    let (pg, owner) = connect_pg().await?;
    owner.run_migrations().await?;
    let app = connect_pg_rss_app_role_with_limits(&pg, &owner, 1, Duration::from_secs(8)).await?;
    let tenant = rss_request_context::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
    let user_id = ids::UserId::parse(&uuid::Uuid::new_v4().to_string())?;
    seed_auth_grant_account(&owner, tenant, user_id).await?;

    let app_backend: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&app.pool)
        .await?;
    let mut lock_holder = owner.pool.begin().await?;
    sqlx::query(
        "SELECT user_id FROM account_security_states \
         WHERE tenant_id = $1::uuid AND user_id = $2::uuid FOR UPDATE",
    )
    .bind(tenant.to_string())
    .bind(user_id.as_uuid().to_string())
    .fetch_one(&mut *lock_holder)
    .await?;

    let grant_id = uuid::Uuid::new_v4().to_string();
    let refresh_id = uuid::Uuid::new_v4().to_string();
    let event_id = unique_event_id("auth-grant-lock-timeout");
    let (grant, refresh) = auth_grant_fixture(tenant, user_id, &grant_id, &refresh_id, [0xD4; 32]);
    let (mutation, entry, envelope) = auth_grant_login_parts(&event_id, grant, refresh);
    let started = tokio::time::Instant::now();
    let result = tokio::time::timeout(
        Duration::from_secs(7),
        crate::PgAuthGrantLifecycle::new(&app, fixed_clock()).persist_login_grant(
            login_producer_receipt(),
            identity_scope(tenant),
            mutation,
            reviewed_generated_event::<generated::event::identity_v1::session_created::Contract>(
                entry, envelope,
            )
            .await?,
        ),
    )
    .await
    .map_err(|_| "plain producer lock wait exceeded its PostgreSQL timeout")?;
    let elapsed = started.elapsed();
    assert!(result.is_err(), "held row lock must reject login");
    assert!(
        (Duration::from_secs(4)..Duration::from_secs(7)).contains(&elapsed),
        "plain producer lock timeout must fail at approximately five seconds: {elapsed:?}"
    );
    assert_eq!(
        auth_grant_login_counts(&owner, &grant_id, &refresh_id, &event_id).await?,
        (0, 0, 0),
        "lock timeout must roll back grant, refresh and outbox writes"
    );
    localtx_assert_backend_reused(
        &app.pool,
        app_backend,
        "plain producer lock timeout rollback",
    )
    .await?;

    lock_holder.rollback().await?;
    app.shutdown().await?;
    owner.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn auth_grant_login_rejects_stale_epoch_after_security_event_commits() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let tenant = rss_request_context::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
    let user = ids::UserId::parse(&uuid::Uuid::new_v4().to_string())?;
    seed_auth_grant_account(&store, tenant, user).await?;

    let state_at = SystemTime::UNIX_EPOCH + Duration::from_secs(TEST_OCCURRED_SECS);
    let state = identity::test_support::account_security_state(AccountSecuritySnapshot {
        tenant,
        user_id: user,
        status: AccountStatus::Active,
        authn_epoch: 0,
        version: 1,
        status_changed_at: state_at,
        updated_at: state_at,
    });
    let security = identity::test_support::account_credential_security_command(
        state,
        AccountSecurityEventKind::LogoutAll,
        state_at + Duration::from_secs(1),
    );
    let _security_receipt = crate::PgIdentitySecurityLifecycle::from_unverified_for_test(&store)
        .execute_test_command(identity_scope(tenant), security)
        .await?;

    let grant_id = uuid::Uuid::new_v4().to_string();
    let refresh_id = uuid::Uuid::new_v4().to_string();
    let event_id = unique_event_id("auth-grant-stale-security-epoch");
    let (grant, refresh) = auth_grant_fixture(tenant, user, &grant_id, &refresh_id, [0xD2; 32]);
    let (mutation, entry, envelope) = auth_grant_login_parts(&event_id, grant, refresh);
    let stale_login = crate::PgAuthGrantLifecycle::new(&store, fixed_clock())
        .persist_login_grant(
            login_producer_receipt(),
            identity_scope(tenant),
            mutation,
            reviewed_generated_event::<generated::event::identity_v1::session_created::Contract>(
                entry, envelope,
            )
            .await?,
        )
        .await;
    assert!(
        stale_login.is_err(),
        "stale issuance epoch must fail closed"
    );
    assert_eq!(
        auth_grant_login_counts(&store, &grant_id, &refresh_id, &event_id).await?,
        (0, 0, 0),
        "stale login must not persist a grant, refresh record, or session fact"
    );

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn auth_grant_login_account_lock_serializes_security_event_without_deadlock() -> TestResult {
    let (pg, owner) = connect_pg().await?;
    owner.run_migrations().await?;
    let login_store =
        connect_pg_rss_app_role_with_limits(&pg, &owner, 1, Duration::from_secs(5)).await?;
    let security_store =
        connect_pg_rss_app_role_with_limits(&pg, &owner, 1, Duration::from_secs(5)).await?;
    let tenant = rss_request_context::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
    let user = ids::UserId::parse(&uuid::Uuid::new_v4().to_string())?;
    seed_auth_grant_account(&owner, tenant, user).await?;

    let login_backend: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&login_store.pool)
        .await?;
    let security_backend: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&security_store.pool)
        .await?;
    assert_ne!(login_backend, security_backend);

    let grant_id = uuid::Uuid::new_v4().to_string();
    let refresh_id = uuid::Uuid::new_v4().to_string();
    let event_id = unique_event_id("auth-grant-security-interleave");
    let (grant, refresh) = auth_grant_fixture(tenant, user, &grant_id, &refresh_id, [0xD3; 32]);
    let (mutation, entry, envelope) = auth_grant_login_parts(&event_id, grant, refresh);
    let gate = crate::auth_grant_lifecycle::AuthGrantLoginLockGate::new();
    let login_gate = gate.clone();
    let login = tokio::spawn(async move {
        crate::PgAuthGrantLifecycle::new(&login_store, fixed_clock())
            .with_login_lock_gate(login_gate)
.persist_login_grant(
    login_producer_receipt(),
    identity_scope(tenant),
    mutation,
    reviewed_generated_event::<generated::event::identity_v1::session_created::Contract>(
        entry,
        envelope,
    )
    .await
    .map_err(|_| {
        diport::OutboxEmitError::new(std::io::Error::other(
            "generated session fixture review failed",
        ))
    })?,
)
            .await
    });
    gate.wait_until_locked().await;

    let state_at = SystemTime::UNIX_EPOCH + Duration::from_secs(TEST_OCCURRED_SECS);
    let state = identity::test_support::account_security_state(AccountSecuritySnapshot {
        tenant,
        user_id: user,
        status: AccountStatus::Active,
        authn_epoch: 0,
        version: 1,
        status_changed_at: state_at,
        updated_at: state_at,
    });
    let security = identity::test_support::account_credential_security_command(
        state,
        AccountSecurityEventKind::LogoutAll,
        state_at + Duration::from_secs(1),
    );
    let security_task = tokio::spawn(async move {
        crate::PgIdentitySecurityLifecycle::from_unverified_for_test(&security_store)
            .execute_test_command(identity_scope(tenant), security)
            .await
    });

    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let blockers: Vec<i32> = sqlx::query_scalar("SELECT unnest(pg_blocking_pids($1))")
                .bind(security_backend)
                .fetch_all(&owner.pool)
                .await?;
            if blockers.contains(&login_backend) {
                return Ok::<(), sqlx::Error>(());
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .map_err(|_| "security event did not wait for the login account lock")??;

    gate.release();
    let _login_receipt = login.await??;
    let _security_receipt = security_task.await??;
    let persisted: (i64, i64, String, String, i64) = sqlx::query_as(
        "SELECT s.authn_epoch, s.version, g.status, r.status, \
         (SELECT count(*) FROM outbox o WHERE o.tenant_id = s.tenant_id \
          AND o.contract_id IN ($3, $4)) \
         FROM account_security_states s \
         JOIN auth_grants g ON g.tenant_id = s.tenant_id AND g.user_id = s.user_id \
         JOIN refresh_tokens r ON r.tenant_id = g.tenant_id AND r.auth_grant_id = g.grant_id \
         WHERE s.tenant_id = $1::uuid AND s.user_id = $2::uuid",
    )
    .bind(tenant.to_string())
    .bind(user.as_uuid().to_string())
    .bind(identity::ports::SESSION_CREATED_CONTRACT.contract_id())
    .bind(identity::ports::SECURITY_EVENT_CONTRACT.contract_id())
    .fetch_one(&owner.pool)
    .await?;
    assert_eq!(
        persisted,
        (1, 2, "revoked".to_owned(), "revoked".to_owned(), 2)
    );

    owner.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn auth_grant_serving_role_has_exact_mutation_acl() -> TestResult {
    let (pg, owner) = connect_pg().await?;
    owner.run_migrations().await?;
    let app = connect_pg_rss_app_role(&pg, &owner).await?;
    let tenant = rss_request_context::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
    let user_id = ids::UserId::parse(&uuid::Uuid::new_v4().to_string())?;
    seed_auth_grant_account(&owner, tenant, user_id).await?;
    let grant_id = uuid::Uuid::new_v4().to_string();
    let refresh_id = uuid::Uuid::new_v4().to_string();
    let event_id = unique_event_id("auth-grant-exact-acl");
    let (grant, refresh) = auth_grant_fixture(tenant, user_id, &grant_id, &refresh_id, [0xE0; 32]);
    let lifecycle = crate::PgAuthGrantLifecycle::new(&app, fixed_clock());
    let (mutation, entry, envelope) = auth_grant_login_parts(&event_id, grant.clone(), refresh);
    let _persisted = lifecycle
        .persist_login_grant(
            login_producer_receipt(),
            identity_scope(tenant),
            mutation,
            reviewed_generated_event::<generated::event::identity_v1::session_created::Contract>(
                entry, envelope,
            )
            .await?,
        )
        .await?;

    let table_update_acl: (bool, bool, bool, bool) = sqlx::query_as(
        "SELECT \
         has_table_privilege('rss_app', 'public.auth_grants', 'UPDATE'), \
         has_table_privilege('rss_app', 'public.refresh_tokens', 'UPDATE'), \
         has_table_privilege('rss_app_read', 'public.auth_grants', 'UPDATE'), \
         has_table_privilege('rss_app_read', 'public.refresh_tokens', 'UPDATE')",
    )
    .fetch_one(&owner.pool)
    .await?;
    assert_eq!(
        table_update_acl,
        (false, false, false, false),
        "serving roles must not retain table-level UPDATE"
    );

    let update_columns: Vec<(String, String)> = sqlx::query_as(
        "SELECT table_name, column_name \
         FROM information_schema.columns \
         WHERE table_schema = 'public' \
           AND table_name IN ('auth_grants', 'refresh_tokens') \
           AND has_column_privilege( \
               'rss_app', format('public.%I', table_name), column_name, 'UPDATE' \
           ) \
         ORDER BY table_name, column_name",
    )
    .fetch_all(&owner.pool)
    .await?;
    assert_eq!(
        update_columns,
        vec![
            ("auth_grants".to_owned(), "close_reason".to_owned()),
            ("auth_grants".to_owned(), "closed_at".to_owned()),
            ("auth_grants".to_owned(), "status".to_owned()),
            ("refresh_tokens".to_owned(), "status".to_owned()),
        ],
        "rss_app UPDATE must be the exact provider mutation surface"
    );

    for (label, statement) in [
        (
            "refresh token hash",
            "UPDATE refresh_tokens SET token_hash = token_hash \
             WHERE tenant_id = $1::uuid AND id = $2::uuid",
        ),
        (
            "refresh user binding",
            "UPDATE refresh_tokens SET user_id = user_id \
             WHERE tenant_id = $1::uuid AND id = $2::uuid",
        ),
        (
            "refresh epoch binding",
            "UPDATE refresh_tokens SET authn_epoch_at_issue = authn_epoch_at_issue \
             WHERE tenant_id = $1::uuid AND id = $2::uuid",
        ),
        (
            "refresh root binding",
            "UPDATE refresh_tokens SET auth_grant_id = auth_grant_id \
             WHERE tenant_id = $1::uuid AND id = $2::uuid",
        ),
        (
            "refresh root-status binding",
            "UPDATE refresh_tokens SET auth_grant_status = auth_grant_status \
             WHERE tenant_id = $1::uuid AND id = $2::uuid",
        ),
    ] {
        let mut tx = app.pool.begin().await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(tenant.to_string())
            .execute(&mut *tx)
            .await?;
        let error = sqlx::query(statement)
            .bind(tenant.to_string())
            .bind(&refresh_id)
            .execute(&mut *tx)
            .await
            .expect_err("rss_app must not update immutable refresh columns");
        assert!(
            matches!(
                &error,
                sqlx::Error::Database(database)
                    if database.code().as_deref() == Some("42501")
            ),
            "{label} must fail with insufficient_privilege, got {error}"
        );
        tx.rollback().await?;
    }

    for (label, statement) in [
        (
            "AuthGrant user binding",
            "UPDATE auth_grants SET user_id = user_id \
             WHERE tenant_id = $1::uuid AND grant_id = $2",
        ),
        (
            "AuthGrant epoch binding",
            "UPDATE auth_grants SET authn_epoch_at_issue = authn_epoch_at_issue \
             WHERE tenant_id = $1::uuid AND grant_id = $2",
        ),
    ] {
        let mut tx = app.pool.begin().await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(tenant.to_string())
            .execute(&mut *tx)
            .await?;
        let error = sqlx::query(statement)
            .bind(tenant.to_string())
            .bind(&grant_id)
            .execute(&mut *tx)
            .await
            .expect_err("rss_app must not update immutable AuthGrant columns");
        assert!(
            matches!(
                &error,
                sqlx::Error::Database(database)
                    if database.code().as_deref() == Some("42501")
            ),
            "{label} must fail with insufficient_privilege, got {error}"
        );
        tx.rollback().await?;
    }

    let logout = identity::test_support::logout_current_command(
        grant,
        SystemTime::UNIX_EPOCH + Duration::from_secs(TEST_OCCURRED_SECS + 1),
    );
    let _ = execute_logout_current_route(
        &crate::PgIdentitySecurityLifecycle::from_unverified_for_test(&app),
        tenant,
        logout,
    )
    .await?;
    let closed: (String, String, String) = sqlx::query_as(
        "SELECT g.status, r.status, r.auth_grant_status \
         FROM auth_grants AS g \
         JOIN refresh_tokens AS r \
           ON r.tenant_id = g.tenant_id AND r.auth_grant_id = g.grant_id \
         WHERE g.tenant_id = $1::uuid AND g.grant_id = $2",
    )
    .bind(tenant.to_string())
    .bind(&grant_id)
    .fetch_one(&owner.pool)
    .await?;
    assert_eq!(
        closed,
        (
            "revoked".to_owned(),
            "revoked".to_owned(),
            "revoked".to_owned(),
        ),
        "legal provider close must retain status UPDATE and FK cascade capability"
    );

    app.shutdown().await?;
    owner.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn password_change_security_event_updates_credential_revokes_sessions_and_appends_one_fact()
-> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let tenant = rss_request_context::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
    let user = ids::UserId::parse(&uuid::Uuid::new_v4().to_string())?;
    let credentials = crate::PgCredentialRepo::from_unverified_for_test(&store);
    credentials
        .insert(
            identity_scope(tenant),
            make_cred(
                "alice",
                user.as_uuid().to_string().as_str(),
                "old-password-phrase",
                1,
                tenant,
            )?,
        )
        .await?;

    let grant_lifecycle = crate::PgAuthGrantLifecycle::new(&store, fixed_clock());
    for suffix in [0xc1_u8, 0xc2_u8] {
        let (grant, refresh) = auth_grant_fixture(
            tenant,
            user,
            &uuid::Uuid::new_v4().to_string(),
            &uuid::Uuid::new_v4().to_string(),
            [suffix; 32],
        );
        let (mutation, entry, envelope) =
            auth_grant_login_parts(&unique_event_id("password-security-login"), grant, refresh);
        let _ =
            grant_lifecycle
                .persist_login_grant(
                    login_producer_receipt(),
                    identity_scope(tenant),
                    mutation,
                    reviewed_generated_event::<
                        generated::event::identity_v1::session_created::Contract,
                    >(entry, envelope)
                    .await?,
                )
                .await?;
    }

    let credential = credentials
        .find_by_user_id(identity_scope(tenant), user)
        .await?
        .ok_or("seeded credential missing")?;
    let accounts = crate::PgAccountSecurityRepo::from_unverified_for_test(&store);
    let account = accounts
        .find(identity_scope(tenant), user)
        .await?
        .ok_or("seeded account state missing")?;
    let changed_at = account.updated_at() + Duration::from_secs(1);
    let validated = secure::PasswordPolicy::for_test("passwordpassword", &[])
        .validate(secure::RawPassword::new("new-password-phrase".to_owned()))?;
    let command =
        identity::test_support::password_change_command(credential, account, validated, changed_at);
    let lifecycle = crate::PgIdentitySecurityLifecycle::from_unverified_for_test(&store);
    let _receipt = lifecycle
        .execute_password_change(
            password_change_producer_receipt(),
            identity_scope(tenant),
            command,
        )
        .await?;

    let stored = credentials
        .find_by_user_id(identity_scope(tenant), user)
        .await?
        .ok_or("changed credential missing")?;
    assert_eq!(stored.version(), 2);
    assert!(password_matches(
        "new-password-phrase",
        stored.password_hash()
    )?);
    assert!(!password_matches(
        "old-password-phrase",
        stored.password_hash()
    )?);
    let state = accounts
        .find(identity_scope(tenant), user)
        .await?
        .ok_or("changed account state missing")?;
    assert_eq!(state.status(), AccountStatus::Active);
    assert_eq!(state.authn_epoch().get(), 1);
    assert_eq!(state.version().get(), 2);
    let roots: Vec<(String,)> = sqlx::query_as(
        "SELECT status FROM auth_grants WHERE tenant_id = $1::uuid AND user_id = $2::uuid",
    )
    .bind(tenant.to_string())
    .bind(user.as_uuid().to_string())
    .fetch_all(&store.pool)
    .await?;
    assert_eq!(roots.len(), 2);
    assert!(roots.iter().all(|(status,)| status == "revoked"));
    let refreshes: Vec<(String, String)> = sqlx::query_as(
        "SELECT status, auth_grant_status FROM refresh_tokens \
         WHERE tenant_id = $1::uuid AND user_id = $2::uuid",
    )
    .bind(tenant.to_string())
    .bind(user.as_uuid().to_string())
    .fetch_all(&store.pool)
    .await?;
    assert_eq!(refreshes.len(), 2);
    assert!(
        refreshes
            .iter()
            .all(|(token, root)| token == "revoked" && root == "revoked")
    );
    let facts: Vec<Vec<u8>> = sqlx::query_scalar(
        "SELECT payload FROM outbox WHERE tenant_id = $1::uuid AND contract_id = $2",
    )
    .bind(tenant.to_string())
    .bind(identity::ports::SECURITY_EVENT_CONTRACT.contract_id())
    .fetch_all(&store.pool)
    .await?;
    assert_eq!(facts.len(), 1);
    let payload: serde_json::Value = serde_json::from_slice(&facts[0])?;
    assert_eq!(payload.as_object().map(serde_json::Map::len), Some(5));
    assert_eq!(payload["kind"], "passwordChanged");
    assert_eq!(payload["target"]["kind"], "subject");
    assert!(
        payload["target"]["ref"]
            .as_str()
            .is_some_and(|value| !value.is_empty())
    );
    assert_ne!(payload["target"]["ref"], user.as_uuid().to_string());

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn password_change_concurrent_full_lifecycle_cas_has_exactly_one_winner() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let tenant = rss_request_context::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
    let user = ids::UserId::parse(&uuid::Uuid::new_v4().to_string())?;
    let credentials = crate::PgCredentialRepo::from_unverified_for_test(&store);
    credentials
        .insert(
            identity_scope(tenant),
            make_cred(
                "password-concurrent",
                user.as_uuid().to_string().as_str(),
                "old-password-phrase",
                1,
                tenant,
            )?,
        )
        .await?;

    let grant_lifecycle = crate::PgAuthGrantLifecycle::new(&store, fixed_clock());
    for suffix in [0xd1_u8, 0xd2_u8] {
        let (grant, refresh) = auth_grant_fixture(
            tenant,
            user,
            &uuid::Uuid::new_v4().to_string(),
            &uuid::Uuid::new_v4().to_string(),
            [suffix; 32],
        );
        let (mutation, entry, envelope) = auth_grant_login_parts(
            &unique_event_id("password-concurrent-login"),
            grant,
            refresh,
        );
        let _ =
            grant_lifecycle
                .persist_login_grant(
                    login_producer_receipt(),
                    identity_scope(tenant),
                    mutation,
                    reviewed_generated_event::<
                        generated::event::identity_v1::session_created::Contract,
                    >(entry, envelope)
                    .await?,
                )
                .await?;
    }

    let expected_credential = credentials
        .find_by_user_id(identity_scope(tenant), user)
        .await?
        .ok_or("seeded concurrent credential missing")?;
    let accounts = crate::PgAccountSecurityRepo::from_unverified_for_test(&store);
    let expected_account = accounts
        .find(identity_scope(tenant), user)
        .await?
        .ok_or("seeded concurrent account state missing")?;
    let changed_at = expected_account.updated_at() + Duration::from_secs(1);
    let policy = secure::PasswordPolicy::for_test("passwordpassword", &[]);
    let left_command = identity::test_support::password_change_command(
        expected_credential.clone(),
        expected_account.clone(),
        policy.validate(secure::RawPassword::new("left-password-phrase".to_owned()))?,
        changed_at,
    );
    let right_command = identity::test_support::password_change_command(
        expected_credential,
        expected_account,
        policy.validate(secure::RawPassword::new("right-password-phrase".to_owned()))?,
        changed_at + Duration::from_micros(1),
    );
    let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(3));
    let left_lifecycle = crate::PgIdentitySecurityLifecycle::from_unverified_for_test(&store)
        .with_start_barrier(std::sync::Arc::clone(&barrier));
    let right_lifecycle = crate::PgIdentitySecurityLifecycle::from_unverified_for_test(&store)
        .with_start_barrier(std::sync::Arc::clone(&barrier));
    let left = tokio::spawn(async move {
        left_lifecycle
            .execute_password_change(
                password_change_producer_receipt(),
                identity_scope(tenant),
                left_command,
            )
            .await
    });
    let right = tokio::spawn(async move {
        right_lifecycle
            .execute_password_change(
                password_change_producer_receipt(),
                identity_scope(tenant),
                right_command,
            )
            .await
    });
    barrier.wait().await;
    let outcomes = [left.await?, right.await?];
    assert_eq!(outcomes.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        outcomes
            .iter()
            .filter(|result| matches!(result, Err(IdentityError::VersionConflict)))
            .count(),
        1
    );

    let stored = credentials
        .find_by_user_id(identity_scope(tenant), user)
        .await?
        .ok_or("concurrent password winner missing")?;
    assert_eq!(stored.version(), 2, "credential CAS must advance once");
    let left_won = password_matches("left-password-phrase", stored.password_hash())?;
    let right_won = password_matches("right-password-phrase", stored.password_hash())?;
    assert_ne!(left_won, right_won, "exactly one candidate hash must win");
    assert!(!password_matches(
        "old-password-phrase",
        stored.password_hash()
    )?);
    let account = accounts
        .find(identity_scope(tenant), user)
        .await?
        .ok_or("concurrent password account state missing")?;
    assert_eq!(account.authn_epoch().get(), 1);
    assert_eq!(account.version().get(), 2);
    let closure: (i64, i64, i64) = sqlx::query_as(
        "SELECT count(*) FILTER (WHERE status = 'revoked'), \
                (SELECT count(*) FROM refresh_tokens \
                 WHERE tenant_id = $1::uuid AND user_id = $2::uuid \
                   AND status = 'revoked' AND auth_grant_status = 'revoked'), \
                (SELECT count(*) FROM outbox \
                 WHERE tenant_id = $1::uuid AND contract_id = $3) \
         FROM auth_grants WHERE tenant_id = $1::uuid AND user_id = $2::uuid",
    )
    .bind(tenant.to_string())
    .bind(user.as_uuid().to_string())
    .bind(identity::ports::SECURITY_EVENT_CONTRACT.contract_id())
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(closure, (2, 2, 1));

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn identity_security_full_snapshot_cas_rejects_timestamp_only_staleness() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let credentials = crate::PgCredentialRepo::from_unverified_for_test(&store);
    let accounts = crate::PgAccountSecurityRepo::from_unverified_for_test(&store);
    let lifecycle = crate::PgIdentitySecurityLifecycle::from_unverified_for_test(&store);

    let password_tenant = rss_request_context::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
    let password_user = ids::UserId::parse(&uuid::Uuid::new_v4().to_string())?;
    credentials
        .insert(
            identity_scope(password_tenant),
            make_cred(
                "timestamp-password",
                password_user.as_uuid().to_string().as_str(),
                "old-password-phrase",
                1,
                password_tenant,
            )?,
        )
        .await?;
    let (grant, refresh) = auth_grant_fixture(
        password_tenant,
        password_user,
        &uuid::Uuid::new_v4().to_string(),
        &uuid::Uuid::new_v4().to_string(),
        [0xe1; 32],
    );
    let (mutation, entry, envelope) =
        auth_grant_login_parts(&unique_event_id("timestamp-stale-login"), grant, refresh);
    let _ = crate::PgAuthGrantLifecycle::new(&store, fixed_clock())
        .persist_login_grant(
            login_producer_receipt(),
            identity_scope(password_tenant),
            mutation,
            reviewed_generated_event::<generated::event::identity_v1::session_created::Contract>(
                entry, envelope,
            )
            .await?,
        )
        .await?;
    let password_account = accounts
        .find(identity_scope(password_tenant), password_user)
        .await?
        .ok_or("password account missing")?;
    let password_credential = credentials
        .find_by_user_id(identity_scope(password_tenant), password_user)
        .await?
        .ok_or("password credential missing")?;
    sqlx::query(
        "UPDATE account_security_states SET updated_at = updated_at + INTERVAL '1 microsecond' \
         WHERE tenant_id = $1::uuid AND user_id = $2::uuid",
    )
    .bind(password_tenant.to_string())
    .bind(password_user.as_uuid().to_string())
    .execute(&store.pool)
    .await?;
    let validated = secure::PasswordPolicy::for_test("passwordpassword", &[])
        .validate(secure::RawPassword::new("new-password-phrase".to_owned()))?;
    let stale_password = identity::test_support::password_change_command(
        password_credential,
        password_account.clone(),
        validated,
        password_account.updated_at() + Duration::from_secs(1),
    );
    assert!(matches!(
        lifecycle
            .execute_password_change(
                password_change_producer_receipt(),
                identity_scope(password_tenant),
                stale_password,
            )
            .await,
        Err(IdentityError::VersionConflict)
    ));
    let password_rows: (i64, i64, String, String, i64) = sqlx::query_as(
        "SELECT c.version, s.version, g.status, r.status, \
         (SELECT count(*) FROM outbox o WHERE o.tenant_id = c.tenant_id AND o.contract_id = $3) \
         FROM credentials c \
         JOIN account_security_states s ON s.tenant_id = c.tenant_id AND s.user_id = c.user_id \
         JOIN auth_grants g ON g.tenant_id = c.tenant_id AND g.user_id = c.user_id \
         JOIN refresh_tokens r ON r.tenant_id = g.tenant_id AND r.auth_grant_id = g.grant_id \
         WHERE c.tenant_id = $1::uuid AND c.user_id = $2::uuid",
    )
    .bind(password_tenant.to_string())
    .bind(password_user.as_uuid().to_string())
    .bind(identity::ports::SECURITY_EVENT_CONTRACT.contract_id())
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(password_rows, (1, 1, "active".into(), "active".into(), 0));

    let state_tenant = rss_request_context::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
    let state_user = ids::UserId::parse(&uuid::Uuid::new_v4().to_string())?;
    credentials
        .insert(
            identity_scope(state_tenant),
            make_cred(
                "timestamp-state",
                state_user.as_uuid().to_string().as_str(),
                "old-password-phrase",
                1,
                state_tenant,
            )?,
        )
        .await?;
    let active = accounts
        .find(identity_scope(state_tenant), state_user)
        .await?
        .ok_or("state account missing")?;
    sqlx::query(
        "UPDATE account_security_states \
         SET status_changed_at = status_changed_at - INTERVAL '1 microsecond' \
         WHERE tenant_id = $1::uuid AND user_id = $2::uuid",
    )
    .bind(state_tenant.to_string())
    .bind(state_user.as_uuid().to_string())
    .execute(&store.pool)
    .await?;
    let stale_restriction = identity::test_support::account_status_set_command(
        active.clone(),
        AccountStatus::Suspended,
        active.updated_at() + Duration::from_secs(1),
    );
    assert!(matches!(
        lifecycle
            .execute_account_status_set(
                account_status_set_producer_receipt(),
                identity_scope(state_tenant),
                stale_restriction,
            )
            .await,
        Err(IdentityError::VersionConflict)
    ));
    let current = accounts
        .find(identity_scope(state_tenant), state_user)
        .await?
        .ok_or("current state missing")?;
    assert_eq!(current.status(), AccountStatus::Active);
    assert_eq!(current.version().get(), 1);

    let restrict = identity::test_support::account_status_set_command(
        current.clone(),
        AccountStatus::Suspended,
        current.updated_at() + Duration::from_secs(1),
    );
    let _ = lifecycle
        .execute_account_status_set(
            account_status_set_producer_receipt(),
            identity_scope(state_tenant),
            restrict,
        )
        .await?;
    let suspended = accounts
        .find(identity_scope(state_tenant), state_user)
        .await?
        .ok_or("suspended state missing")?;
    sqlx::query(
        "UPDATE account_security_states SET updated_at = updated_at + INTERVAL '1 microsecond' \
         WHERE tenant_id = $1::uuid AND user_id = $2::uuid",
    )
    .bind(state_tenant.to_string())
    .bind(state_user.as_uuid().to_string())
    .execute(&store.pool)
    .await?;
    let stale_reactivation = identity::test_support::reactivate_account_command(
        suspended.clone(),
        suspended.updated_at() + Duration::from_secs(1),
    );
    let reactivation = crate::PgAccountReactivationLifecycle::from_unverified_for_test(&store);
    assert!(matches!(
        reactivation
            .execute_reactivation(identity_scope(state_tenant), stale_reactivation)
            .await,
        Err(IdentityError::VersionConflict)
    ));
    let final_state = accounts
        .find(identity_scope(state_tenant), state_user)
        .await?
        .ok_or("final state missing")?;
    assert_eq!(final_state.status(), AccountStatus::Suspended);
    assert_eq!(final_state.version().get(), 2);
    let security_facts: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM outbox WHERE tenant_id = $1::uuid AND contract_id = $2",
    )
    .bind(state_tenant.to_string())
    .bind(identity::ports::SECURITY_EVENT_CONTRACT.contract_id())
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(
        security_facts, 1,
        "only the successful restriction emits a fact"
    );

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn password_change_security_event_fault_matrix_rolls_back_every_stage() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    for (suffix, fault) in [
        (
            0xd1_u8,
            crate::identity_security_lifecycle::IdentitySecurityFault::AfterCredential,
        ),
        (
            0xd2,
            crate::identity_security_lifecycle::IdentitySecurityFault::AfterAccount,
        ),
        (
            0xd3,
            crate::identity_security_lifecycle::IdentitySecurityFault::AfterFamily,
        ),
        (
            0xd4,
            crate::identity_security_lifecycle::IdentitySecurityFault::AfterGrant,
        ),
        (
            0xd5,
            crate::identity_security_lifecycle::IdentitySecurityFault::OutboxAppend,
        ),
        (
            0xd6,
            crate::identity_security_lifecycle::IdentitySecurityFault::AfterOutboxBeforeCommit,
        ),
    ] {
        let tenant = rss_request_context::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
        let user = ids::UserId::parse(&uuid::Uuid::new_v4().to_string())?;
        let credentials = crate::PgCredentialRepo::from_unverified_for_test(&store);
        credentials
            .insert(
                identity_scope(tenant),
                make_cred(
                    "alice",
                    user.as_uuid().to_string().as_str(),
                    "old-password-phrase",
                    1,
                    tenant,
                )?,
            )
            .await?;
        let (grant, refresh) = auth_grant_fixture(
            tenant,
            user,
            &uuid::Uuid::new_v4().to_string(),
            &uuid::Uuid::new_v4().to_string(),
            [suffix; 32],
        );
        let (mutation, entry, envelope) = auth_grant_login_parts(
            &unique_event_id("password-security-fault-login"),
            grant,
            refresh,
        );
        let _ =
            crate::PgAuthGrantLifecycle::new(&store, fixed_clock())
                .persist_login_grant(
                    login_producer_receipt(),
                    identity_scope(tenant),
                    mutation,
                    reviewed_generated_event::<
                        generated::event::identity_v1::session_created::Contract,
                    >(entry, envelope)
                    .await?,
                )
                .await?;
        let account = crate::PgAccountSecurityRepo::from_unverified_for_test(&store)
            .find(identity_scope(tenant), user)
            .await?
            .ok_or("fault account missing")?;
        let credential = credentials
            .find_by_user_id(identity_scope(tenant), user)
            .await?
            .ok_or("fault credential missing")?;
        let validated = secure::PasswordPolicy::for_test("passwordpassword", &[])
            .validate(secure::RawPassword::new("new-password-phrase".to_owned()))?;
        let command = identity::test_support::password_change_command(
            credential,
            account.clone(),
            validated,
            account.updated_at() + Duration::from_secs(1),
        );
        let result = crate::PgIdentitySecurityLifecycle::from_unverified_for_test(&store)
            .with_fault(fault)
            .execute_password_change(
                password_change_producer_receipt(),
                identity_scope(tenant),
                command,
            )
            .await;
        assert!(result.is_err(), "fault stage must not return a receipt");

        let after: (i64, i64, i64, String, String, String, i64) = sqlx::query_as(
            "SELECT c.version, s.authn_epoch, s.version, g.status, r.status, r.auth_grant_status, \
                (SELECT count(*) FROM outbox o WHERE o.tenant_id = c.tenant_id AND o.contract_id = $3) \
             FROM credentials c \
             JOIN account_security_states s ON s.tenant_id = c.tenant_id AND s.user_id = c.user_id \
             JOIN auth_grants g ON g.tenant_id = c.tenant_id AND g.user_id = c.user_id \
             JOIN refresh_tokens r ON r.tenant_id = g.tenant_id AND r.auth_grant_id = g.grant_id \
             WHERE c.tenant_id = $1::uuid AND c.user_id = $2::uuid",
        )
        .bind(tenant.to_string())
        .bind(user.as_uuid().to_string())
        .bind(identity::ports::SECURITY_EVENT_CONTRACT.contract_id())
        .fetch_one(&store.pool)
        .await?;
        assert_eq!(
            after,
            (
                1,
                0,
                1,
                "active".to_owned(),
                "active".to_owned(),
                "active".to_owned(),
                0
            ),
            "every pre-commit stage must roll back credential, account, family, grant and fact"
        );
    }
    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn account_restriction_and_reactivation_preserve_revocation_epoch_without_second_fact()
-> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let tenant = rss_request_context::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
    let user = ids::UserId::parse(&uuid::Uuid::new_v4().to_string())?;
    crate::PgCredentialRepo::from_unverified_for_test(&store)
        .insert(
            identity_scope(tenant),
            make_cred(
                "alice",
                user.as_uuid().to_string().as_str(),
                "old-password-phrase",
                1,
                tenant,
            )?,
        )
        .await?;
    let accounts = crate::PgAccountSecurityRepo::from_unverified_for_test(&store);
    let active = accounts
        .find(identity_scope(tenant), user)
        .await?
        .ok_or("seeded account state missing")?;
    let lifecycle = crate::PgIdentitySecurityLifecycle::from_unverified_for_test(&store);
    let reactivation = crate::PgAccountReactivationLifecycle::from_unverified_for_test(&store);
    let restrict = identity::test_support::account_status_set_command(
        active.clone(),
        AccountStatus::Suspended,
        active.updated_at() + Duration::from_secs(1),
    );
    let _receipt = lifecycle
        .execute_account_status_set(
            account_status_set_producer_receipt(),
            identity_scope(tenant),
            restrict,
        )
        .await?;
    let suspended = accounts
        .find(identity_scope(tenant), user)
        .await?
        .ok_or("suspended account state missing")?;
    assert_eq!(suspended.status(), AccountStatus::Suspended);
    assert_eq!(suspended.authn_epoch().get(), 1);
    assert_eq!(suspended.version().get(), 2);

    let reactivate = identity::test_support::reactivate_account_command(
        suspended.clone(),
        suspended.updated_at() + Duration::from_secs(1),
    );
    let active = reactivation
        .execute_reactivation(identity_scope(tenant), reactivate)
        .await?;
    assert_eq!(active.status(), AccountStatus::Active);
    assert_eq!(
        active.authn_epoch().get(),
        1,
        "reactivation preserves epoch"
    );
    assert_eq!(active.version().get(), 3);
    let fact_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM outbox WHERE tenant_id = $1::uuid AND contract_id = $2",
    )
    .bind(tenant.to_string())
    .bind(identity::ports::SECURITY_EVENT_CONTRACT.contract_id())
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(fact_count, 1, "reactivation must not append a fact");

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn credential_security_lifecycle_applies_account_cas_and_grant_promotion_atomically()
-> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let lifecycle = crate::PgIdentitySecurityLifecycle::from_unverified_for_test(&store);

    let account_tenant = rss_request_context::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
    let account_user = ids::UserId::parse(&uuid::Uuid::new_v4().to_string())?;
    seed_auth_grant_account(&store, account_tenant, account_user).await?;
    let account_grant_a_id = uuid::Uuid::new_v4().to_string();
    let account_grant_b_id = uuid::Uuid::new_v4().to_string();
    let account_refresh_a_id = uuid::Uuid::new_v4().to_string();
    let account_refresh_b_id = uuid::Uuid::new_v4().to_string();
    let (account_grant_a, account_refresh_a) = auth_grant_fixture(
        account_tenant,
        account_user,
        &account_grant_a_id,
        &account_refresh_a_id,
        [0x91; 32],
    );
    let (account_grant_b, account_refresh_b) = auth_grant_fixture(
        account_tenant,
        account_user,
        &account_grant_b_id,
        &account_refresh_b_id,
        [0x92; 32],
    );
    let grant_lifecycle = crate::PgAuthGrantLifecycle::new(&store, fixed_clock());
    for (event_id, grant, refresh) in [
        (
            unique_event_id("security-account-grant-a"),
            account_grant_a,
            account_refresh_a,
        ),
        (
            unique_event_id("security-account-grant-b"),
            account_grant_b,
            account_refresh_b,
        ),
    ] {
        let (mutation, entry, envelope) = auth_grant_login_parts(&event_id, grant, refresh);
        let _persisted =
            grant_lifecycle
                .persist_login_grant(
                    login_producer_receipt(),
                    identity_scope(account_tenant),
                    mutation,
                    reviewed_generated_event::<
                        generated::event::identity_v1::session_created::Contract,
                    >(entry, envelope)
                    .await?,
                )
                .await?;
    }
    let same_tenant_decoy_user = ids::UserId::parse(&uuid::Uuid::new_v4().to_string())?;
    let other_tenant = rss_request_context::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
    let other_tenant_decoy_user = ids::UserId::parse(&uuid::Uuid::new_v4().to_string())?;
    seed_auth_grant_account(&store, account_tenant, same_tenant_decoy_user).await?;
    seed_auth_grant_account(&store, other_tenant, other_tenant_decoy_user).await?;
    let same_tenant_decoy_grant_id = uuid::Uuid::new_v4().to_string();
    let other_tenant_decoy_grant_id = uuid::Uuid::new_v4().to_string();
    let (same_tenant_decoy_grant, same_tenant_decoy_refresh) = auth_grant_fixture(
        account_tenant,
        same_tenant_decoy_user,
        &same_tenant_decoy_grant_id,
        &uuid::Uuid::new_v4().to_string(),
        [0x9a; 32],
    );
    let (other_tenant_decoy_grant, other_tenant_decoy_refresh) = auth_grant_fixture(
        other_tenant,
        other_tenant_decoy_user,
        &other_tenant_decoy_grant_id,
        &uuid::Uuid::new_v4().to_string(),
        [0x9b; 32],
    );
    for (event_id, tenant, grant, refresh) in [
        (
            unique_event_id("security-account-same-tenant-decoy"),
            account_tenant,
            same_tenant_decoy_grant,
            same_tenant_decoy_refresh,
        ),
        (
            unique_event_id("security-account-other-tenant-decoy"),
            other_tenant,
            other_tenant_decoy_grant,
            other_tenant_decoy_refresh,
        ),
    ] {
        let (mutation, entry, envelope) = auth_grant_login_parts(&event_id, grant, refresh);
        let _persisted =
            grant_lifecycle
                .persist_login_grant(
                    login_producer_receipt(),
                    identity_scope(tenant),
                    mutation,
                    reviewed_generated_event::<
                        generated::event::identity_v1::session_created::Contract,
                    >(entry, envelope)
                    .await?,
                )
                .await?;
    }
    sqlx::query(
        "UPDATE refresh_tokens SET status = 'consumed' \
         WHERE tenant_id = $1::uuid AND id = $2::uuid",
    )
    .bind(account_tenant.to_string())
    .bind(&account_refresh_b_id)
    .execute(&store.pool)
    .await?;

    let state_at = SystemTime::UNIX_EPOCH + Duration::from_secs(TEST_OCCURRED_SECS);
    let account_state = identity::test_support::account_security_state(AccountSecuritySnapshot {
        tenant: account_tenant,
        user_id: account_user,
        status: AccountStatus::Active,
        authn_epoch: 0,
        version: 1,
        status_changed_at: state_at,
        updated_at: state_at,
    });
    let account_event_at = state_at + Duration::from_secs(10);
    let account_command =
        identity::test_support::logout_all_command(account_state.clone(), account_event_at);
    let stale_account_command = identity::test_support::logout_all_command(
        account_state,
        account_event_at + Duration::from_secs(1),
    );
    let _receipt = execute_logout_all_route(&lifecycle, account_tenant, account_command).await?;
    assert!(matches!(
        execute_logout_all_route(&lifecycle, account_tenant, stale_account_command).await,
        Err(IdentityError::VersionConflict)
    ));

    let account_projection: (String, i64, i64) = sqlx::query_as(
        "SELECT status, authn_epoch, version FROM account_security_states \
         WHERE tenant_id = $1::uuid AND user_id = $2::uuid",
    )
    .bind(account_tenant.to_string())
    .bind(account_user.as_uuid().to_string())
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(account_projection, ("active".to_owned(), 1, 2));
    let account_roots: Vec<(String, String, Option<String>)> = sqlx::query_as(
        "SELECT grant_id, status, close_reason FROM auth_grants \
         WHERE tenant_id = $1::uuid AND user_id = $2::uuid ORDER BY grant_id",
    )
    .bind(account_tenant.to_string())
    .bind(account_user.as_uuid().to_string())
    .fetch_all(&store.pool)
    .await?;
    assert_eq!(account_roots.len(), 2);
    assert!(account_roots.iter().all(|(_, status, reason)| {
        status == "revoked" && reason.as_deref() == Some("logout_all")
    }));
    let account_refreshes: Vec<(String, String)> = sqlx::query_as(
        "SELECT status, auth_grant_status FROM refresh_tokens \
         WHERE tenant_id = $1::uuid AND user_id = $2::uuid ORDER BY id",
    )
    .bind(account_tenant.to_string())
    .bind(account_user.as_uuid().to_string())
    .fetch_all(&store.pool)
    .await?;
    assert_eq!(
        account_refreshes,
        vec![
            ("revoked".to_owned(), "revoked".to_owned()),
            ("revoked".to_owned(), "revoked".to_owned()),
        ]
    );
    let account_security_facts: Vec<Vec<u8>> = sqlx::query_scalar(
        "SELECT payload FROM outbox WHERE tenant_id = $1::uuid AND contract_id = $2",
    )
    .bind(account_tenant.to_string())
    .bind(identity::ports::SECURITY_EVENT_CONTRACT.contract_id())
    .fetch_all(&store.pool)
    .await?;
    assert_eq!(account_security_facts.len(), 1, "stale CAS must not append");
    let payload: serde_json::Value = serde_json::from_slice(&account_security_facts[0])?;
    assert_eq!(payload.as_object().map(serde_json::Map::len), Some(5));
    assert!(
        !String::from_utf8_lossy(&account_security_facts[0])
            .contains(&account_user.as_uuid().to_string())
    );
    for (tenant, user, grant_id) in [
        (
            account_tenant,
            same_tenant_decoy_user,
            &same_tenant_decoy_grant_id,
        ),
        (
            other_tenant,
            other_tenant_decoy_user,
            &other_tenant_decoy_grant_id,
        ),
    ] {
        let decoy: (String, i64, i64, String, String) = sqlx::query_as(
            "SELECT account.status, account.authn_epoch, account.version, root.status, refresh.status \
             FROM account_security_states account \
             JOIN auth_grants root ON root.tenant_id = account.tenant_id AND root.user_id = account.user_id \
             JOIN refresh_tokens refresh ON refresh.tenant_id = root.tenant_id AND refresh.auth_grant_id = root.grant_id \
             WHERE account.tenant_id = $1::uuid AND account.user_id = $2::uuid AND root.grant_id = $3",
        )
        .bind(tenant.to_string())
        .bind(user.as_uuid().to_string())
        .bind(grant_id)
        .fetch_one(&store.pool)
        .await?;
        assert_eq!(
            decoy,
            (
                "active".to_owned(),
                0,
                1,
                "active".to_owned(),
                "active".to_owned(),
            ),
            "logout-all must not cross a user or tenant boundary"
        );
    }

    let grant_tenant = rss_request_context::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
    let grant_user = ids::UserId::parse(&uuid::Uuid::new_v4().to_string())?;
    seed_auth_grant_account(&store, grant_tenant, grant_user).await?;
    let root_id = uuid::Uuid::new_v4().to_string();
    let sibling_id = uuid::Uuid::new_v4().to_string();
    let refresh_id = uuid::Uuid::new_v4().to_string();
    let sibling_refresh_id = uuid::Uuid::new_v4().to_string();
    let (root, root_refresh) =
        auth_grant_fixture(grant_tenant, grant_user, &root_id, &refresh_id, [0x93; 32]);
    let (sibling, sibling_refresh) = auth_grant_fixture(
        grant_tenant,
        grant_user,
        &sibling_id,
        &sibling_refresh_id,
        [0x94; 32],
    );
    for (event_id, grant, refresh) in [
        (
            unique_event_id("security-grant-root"),
            root.clone(),
            root_refresh,
        ),
        (
            unique_event_id("security-grant-sibling"),
            sibling,
            sibling_refresh,
        ),
    ] {
        let (mutation, entry, envelope) = auth_grant_login_parts(&event_id, grant, refresh);
        let _persisted =
            grant_lifecycle
                .persist_login_grant(
                    login_producer_receipt(),
                    identity_scope(grant_tenant),
                    mutation,
                    reviewed_generated_event::<
                        generated::event::identity_v1::session_created::Contract,
                    >(entry, envelope)
                    .await?,
                )
                .await?;
    }
    let logout_at = root.created_at() + Duration::from_secs(1);
    let stale_logout = identity::test_support::logout_current_command(
        root.clone(),
        logout_at + Duration::from_secs(2),
    );
    let (_, revoked) = root
        .clone()
        .close(GrantSecurityEventKind::LogoutCurrent, logout_at)?
        .into_parts();
    let logout = identity::test_support::logout_current_command(root, logout_at);
    let reuse = identity::test_support::grant_credential_security_command(
        revoked,
        GrantSecurityEventKind::RefreshReuseDetected,
        logout_at + Duration::from_secs(1),
    );
    let _logout_receipt = execute_logout_current_route(&lifecycle, grant_tenant, logout).await?;
    let _reuse_receipt = lifecycle
        .execute_test_command(identity_scope(grant_tenant), reuse)
        .await?;
    assert!(matches!(
        execute_logout_current_route(&lifecycle, grant_tenant, stale_logout).await,
        Err(IdentityError::VersionConflict)
    ));
    let grant_rows: Vec<(String, String, Option<String>)> = sqlx::query_as(
        "SELECT grant_id, status, close_reason FROM auth_grants \
         WHERE tenant_id = $1::uuid AND user_id = $2::uuid ORDER BY grant_id",
    )
    .bind(grant_tenant.to_string())
    .bind(grant_user.as_uuid().to_string())
    .fetch_all(&store.pool)
    .await?;
    let promoted = grant_rows
        .iter()
        .find(|(id, _, _)| id == &root_id)
        .ok_or("promoted root missing")?;
    assert_eq!(
        promoted,
        &(
            root_id.clone(),
            "compromised".to_owned(),
            Some("refresh_reuse_detected".to_owned()),
        )
    );
    let sibling = grant_rows
        .iter()
        .find(|(id, _, _)| id == &sibling_id)
        .ok_or("sibling root missing")?;
    assert_eq!(sibling.1, "active");
    assert_eq!(sibling.2, None);
    let grant_refreshes: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT auth_grant_id, status, auth_grant_status FROM refresh_tokens \
         WHERE tenant_id = $1::uuid AND user_id = $2::uuid ORDER BY auth_grant_id",
    )
    .bind(grant_tenant.to_string())
    .bind(grant_user.as_uuid().to_string())
    .fetch_all(&store.pool)
    .await?;
    assert!(grant_refreshes.iter().any(|(id, status, root_status)| {
        id == &root_id && status == "revoked" && root_status == "compromised"
    }));
    assert!(grant_refreshes.iter().any(|(id, status, root_status)| {
        id == &sibling_id && status == "active" && root_status == "active"
    }));
    let grant_security_fact_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM outbox WHERE tenant_id = $1::uuid AND contract_id = $2",
    )
    .bind(grant_tenant.to_string())
    .bind(identity::ports::SECURITY_EVENT_CONTRACT.contract_id())
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(
        grant_security_fact_count, 2,
        "stale downgrade must not append"
    );

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn credential_security_route_transactions_linearize_duplicate_validated_commands()
-> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let grant_lifecycle = crate::PgAuthGrantLifecycle::new(&store, fixed_clock());

    let all_tenant = rss_request_context::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
    let all_user = ids::UserId::parse(&uuid::Uuid::new_v4().to_string())?;
    seed_auth_grant_account(&store, all_tenant, all_user).await?;
    let (all_grant, all_refresh) = auth_grant_fixture(
        all_tenant,
        all_user,
        &uuid::Uuid::new_v4().to_string(),
        &uuid::Uuid::new_v4().to_string(),
        [0xa1; 32],
    );
    let (mutation, entry, envelope) = auth_grant_login_parts(
        &unique_event_id("security-concurrent-all-login"),
        all_grant,
        all_refresh,
    );
    let _persisted = grant_lifecycle
        .persist_login_grant(
            login_producer_receipt(),
            identity_scope(all_tenant),
            mutation,
            reviewed_generated_event::<generated::event::identity_v1::session_created::Contract>(
                entry, envelope,
            )
            .await?,
        )
        .await?;
    let observed_at = SystemTime::UNIX_EPOCH + Duration::from_secs(TEST_OCCURRED_SECS);
    let all_state = identity::test_support::account_security_state(AccountSecuritySnapshot {
        tenant: all_tenant,
        user_id: all_user,
        status: AccountStatus::Active,
        authn_epoch: 0,
        version: 1,
        status_changed_at: observed_at,
        updated_at: observed_at,
    });
    let all_barrier = std::sync::Arc::new(tokio::sync::Barrier::new(3));
    let all_lifecycle_a = crate::PgIdentitySecurityLifecycle::from_unverified_for_test(&store)
        .with_start_barrier(std::sync::Arc::clone(&all_barrier));
    let all_lifecycle_b = crate::PgIdentitySecurityLifecycle::from_unverified_for_test(&store)
        .with_start_barrier(std::sync::Arc::clone(&all_barrier));
    let all_command_a = identity::test_support::logout_all_command(
        all_state.clone(),
        observed_at + Duration::from_secs(1),
    );
    let all_command_b =
        identity::test_support::logout_all_command(all_state, observed_at + Duration::from_secs(2));
    let all_a = tokio::spawn(async move {
        execute_logout_all_route(&all_lifecycle_a, all_tenant, all_command_a).await
    });
    let all_b = tokio::spawn(async move {
        execute_logout_all_route(&all_lifecycle_b, all_tenant, all_command_b).await
    });
    all_barrier.wait().await;
    let all_results = [all_a.await?, all_b.await?];
    assert_eq!(
        all_results.iter().filter(|result| result.is_ok()).count(),
        1
    );
    assert_eq!(
        all_results
            .iter()
            .filter(|result| matches!(result, Err(IdentityError::VersionConflict)))
            .count(),
        1
    );

    let current_tenant = rss_request_context::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
    let current_user = ids::UserId::parse(&uuid::Uuid::new_v4().to_string())?;
    seed_auth_grant_account(&store, current_tenant, current_user).await?;
    let (current_grant, current_refresh) = auth_grant_fixture(
        current_tenant,
        current_user,
        &uuid::Uuid::new_v4().to_string(),
        &uuid::Uuid::new_v4().to_string(),
        [0xa2; 32],
    );
    let (mutation, entry, envelope) = auth_grant_login_parts(
        &unique_event_id("security-concurrent-current-login"),
        current_grant.clone(),
        current_refresh,
    );
    let _persisted = grant_lifecycle
        .persist_login_grant(
            login_producer_receipt(),
            identity_scope(current_tenant),
            mutation,
            reviewed_generated_event::<generated::event::identity_v1::session_created::Contract>(
                entry, envelope,
            )
            .await?,
        )
        .await?;
    let current_barrier = std::sync::Arc::new(tokio::sync::Barrier::new(3));
    let current_lifecycle_a = crate::PgIdentitySecurityLifecycle::from_unverified_for_test(&store)
        .with_start_barrier(std::sync::Arc::clone(&current_barrier));
    let current_lifecycle_b = crate::PgIdentitySecurityLifecycle::from_unverified_for_test(&store)
        .with_start_barrier(std::sync::Arc::clone(&current_barrier));
    let current_command_a = identity::test_support::logout_current_command(
        current_grant.clone(),
        observed_at + Duration::from_secs(3),
    );
    let current_command_b = identity::test_support::logout_current_command(
        current_grant,
        observed_at + Duration::from_secs(4),
    );
    let current_a = tokio::spawn(async move {
        execute_logout_current_route(&current_lifecycle_a, current_tenant, current_command_a).await
    });
    let current_b = tokio::spawn(async move {
        execute_logout_current_route(&current_lifecycle_b, current_tenant, current_command_b).await
    });
    current_barrier.wait().await;
    let current_results = [current_a.await?, current_b.await?];
    assert_eq!(
        current_results
            .iter()
            .filter(|result| result.is_ok())
            .count(),
        1
    );
    assert_eq!(
        current_results
            .iter()
            .filter(|result| matches!(result, Err(IdentityError::VersionConflict)))
            .count(),
        1
    );

    for tenant in [all_tenant, current_tenant] {
        let fact_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM outbox WHERE tenant_id = $1::uuid AND contract_id = $2",
        )
        .bind(tenant.to_string())
        .bind(identity::ports::SECURITY_EVENT_CONTRACT.contract_id())
        .fetch_one(&store.pool)
        .await?;
        assert_eq!(fact_count, 1, "losing CAS must not append an outbox fact");
    }

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn credential_security_lifecycle_rolls_back_before_outbox_and_never_receipts_commit_unknown()
-> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let tenant = rss_request_context::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
    let other_tenant = rss_request_context::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
    let user = ids::UserId::parse(&uuid::Uuid::new_v4().to_string())?;
    seed_auth_grant_account(&store, tenant, user).await?;
    let grant_id = uuid::Uuid::new_v4().to_string();
    let refresh_id = uuid::Uuid::new_v4().to_string();
    let (grant, refresh) = auth_grant_fixture(tenant, user, &grant_id, &refresh_id, [0x95; 32]);
    let (mutation, entry, envelope) =
        auth_grant_login_parts(&unique_event_id("security-fault-root"), grant, refresh);
    let _persisted = crate::PgAuthGrantLifecycle::new(&store, fixed_clock())
        .persist_login_grant(
            login_producer_receipt(),
            identity_scope(tenant),
            mutation,
            reviewed_generated_event::<generated::event::identity_v1::session_created::Contract>(
                entry, envelope,
            )
            .await?,
        )
        .await?;
    let state_at = SystemTime::UNIX_EPOCH + Duration::from_secs(TEST_OCCURRED_SECS);
    let state = identity::test_support::account_security_state(AccountSecuritySnapshot {
        tenant,
        user_id: user,
        status: AccountStatus::Active,
        authn_epoch: 0,
        version: 1,
        status_changed_at: state_at,
        updated_at: state_at,
    });
    let failed = identity::test_support::account_credential_security_command(
        state.clone(),
        AccountSecurityEventKind::LogoutAll,
        state_at + Duration::from_secs(1),
    );
    let failed_result = crate::PgIdentitySecurityLifecycle::from_unverified_for_test(&store)
        .with_fault(crate::identity_security_lifecycle::IdentitySecurityFault::AfterProjection)
        .execute_test_command(identity_scope(tenant), failed)
        .await;
    assert!(failed_result.is_err());
    let after_rollback: (i64, i64, String, String) = sqlx::query_as(
        "SELECT s.authn_epoch, s.version, g.status, r.status \
         FROM account_security_states s \
         JOIN auth_grants g ON g.tenant_id = s.tenant_id AND g.user_id = s.user_id \
         JOIN refresh_tokens r ON r.tenant_id = g.tenant_id AND r.auth_grant_id = g.grant_id \
         WHERE s.tenant_id = $1::uuid AND s.user_id = $2::uuid",
    )
    .bind(tenant.to_string())
    .bind(user.as_uuid().to_string())
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(
        after_rollback,
        (0, 1, "active".to_owned(), "active".to_owned())
    );
    let after_rollback_facts: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM outbox WHERE tenant_id = $1::uuid AND contract_id = $2",
    )
    .bind(tenant.to_string())
    .bind(identity::ports::SECURITY_EVENT_CONTRACT.contract_id())
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(after_rollback_facts, 0);
    let after_rollback_projections: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM projection_events \
         WHERE metadata ->> 'tenantId' = $1 AND contract_id = $2",
    )
    .bind(tenant.to_string())
    .bind(identity::ports::SECURITY_EVENT_CONTRACT.contract_id())
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(
        after_rollback_projections, 0,
        "AfterProjection must execute after the mirror append and roll it back"
    );

    let mismatch = identity::test_support::account_credential_security_command(
        state.clone(),
        AccountSecurityEventKind::LogoutAll,
        state_at + Duration::from_secs(2),
    );
    assert!(
        crate::PgIdentitySecurityLifecycle::from_unverified_for_test(&store)
            .execute_test_command(identity_scope(other_tenant), mismatch)
            .await
            .is_err()
    );

    let commit_unknown = identity::test_support::account_credential_security_command(
        state,
        AccountSecurityEventKind::LogoutAll,
        state_at + Duration::from_secs(3),
    );
    let unknown_result = crate::PgIdentitySecurityLifecycle::from_unverified_for_test(&store)
        .with_fault(crate::identity_security_lifecycle::IdentitySecurityFault::CommitUnknown)
        .execute_test_command(identity_scope(tenant), commit_unknown)
        .await;
    assert!(
        unknown_result.is_err(),
        "unknown commit must not return a receipt"
    );
    let after_unknown: (i64, i64, String, String, i64) = sqlx::query_as(
        "SELECT s.authn_epoch, s.version, g.status, r.status, \
            (SELECT count(*) FROM outbox o \
             WHERE o.tenant_id = s.tenant_id AND o.contract_id = $3) \
         FROM account_security_states s \
         JOIN auth_grants g ON g.tenant_id = s.tenant_id AND g.user_id = s.user_id \
         JOIN refresh_tokens r ON r.tenant_id = g.tenant_id AND r.auth_grant_id = g.grant_id \
         WHERE s.tenant_id = $1::uuid AND s.user_id = $2::uuid",
    )
    .bind(tenant.to_string())
    .bind(user.as_uuid().to_string())
    .bind(identity::ports::SECURITY_EVENT_CONTRACT.contract_id())
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(
        after_unknown,
        (1, 2, "revoked".to_owned(), "revoked".to_owned(), 1),
        "PostgreSQL accepted the commit, but the adapter returned no replayable receipt"
    );

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn credential_security_lifecycle_real_append_and_precommit_failures_roll_back_everything()
-> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    for (suffix, fault) in [
        (
            0x96,
            crate::identity_security_lifecycle::IdentitySecurityFault::OutboxAppend,
        ),
        (
            0x97,
            crate::identity_security_lifecycle::IdentitySecurityFault::AfterOutboxBeforeCommit,
        ),
    ] {
        let tenant = rss_request_context::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
        let user = ids::UserId::parse(&uuid::Uuid::new_v4().to_string())?;
        seed_auth_grant_account(&store, tenant, user).await?;
        let grant_id = uuid::Uuid::new_v4().to_string();
        let refresh_id = uuid::Uuid::new_v4().to_string();
        let (grant, refresh) =
            auth_grant_fixture(tenant, user, &grant_id, &refresh_id, [suffix; 32]);
        let (mutation, entry, envelope) = auth_grant_login_parts(
            &unique_event_id("security-real-outbox-fault-root"),
            grant,
            refresh,
        );
        let _persisted =
            crate::PgAuthGrantLifecycle::new(&store, fixed_clock())
                .persist_login_grant(
                    login_producer_receipt(),
                    identity_scope(tenant),
                    mutation,
                    reviewed_generated_event::<
                        generated::event::identity_v1::session_created::Contract,
                    >(entry, envelope)
                    .await?,
                )
                .await?;

        let state_at = SystemTime::UNIX_EPOCH + Duration::from_secs(TEST_OCCURRED_SECS);
        let state = identity::test_support::account_security_state(AccountSecuritySnapshot {
            tenant,
            user_id: user,
            status: AccountStatus::Active,
            authn_epoch: 0,
            version: 1,
            status_changed_at: state_at,
            updated_at: state_at,
        });
        let command = identity::test_support::account_credential_security_command(
            state,
            AccountSecurityEventKind::LogoutAll,
            state_at + Duration::from_secs(1),
        );
        let result = crate::PgIdentitySecurityLifecycle::from_unverified_for_test(&store)
            .with_fault(fault)
            .execute_test_command(identity_scope(tenant), command)
            .await;
        assert!(
            result.is_err(),
            "append-boundary fault must not return a security receipt"
        );

        let after_failure: (i64, i64, String, String, i64) = sqlx::query_as(
            "SELECT s.authn_epoch, s.version, g.status, r.status, \
                (SELECT count(*) FROM outbox o \
                 WHERE o.tenant_id = s.tenant_id AND o.contract_id = $3) \
             FROM account_security_states s \
             JOIN auth_grants g ON g.tenant_id = s.tenant_id AND g.user_id = s.user_id \
             JOIN refresh_tokens r ON r.tenant_id = g.tenant_id \
                 AND r.auth_grant_id = g.grant_id \
             WHERE s.tenant_id = $1::uuid AND s.user_id = $2::uuid",
        )
        .bind(tenant.to_string())
        .bind(user.as_uuid().to_string())
        .bind(identity::ports::SECURITY_EVENT_CONTRACT.contract_id())
        .fetch_one(&store.pool)
        .await?;
        assert_eq!(
            after_failure,
            (0, 1, "active".to_owned(), "active".to_owned(), 0),
            "projection, grant, refresh and appended fact must roll back together"
        );
    }

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn auth_grant_composite_fk_rejects_every_mismatched_refresh_binding() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let tenant_a = rss_request_context::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
    let tenant_b = rss_request_context::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
    let user_a = ids::UserId::parse(&uuid::Uuid::new_v4().to_string())?;
    let user_b = ids::UserId::parse(&uuid::Uuid::new_v4().to_string())?;
    seed_auth_grant_account(&store, tenant_a, user_a).await?;
    seed_auth_grant_account(&store, tenant_a, user_b).await?;
    seed_auth_grant_account(&store, tenant_b, user_a).await?;

    let grant_id = uuid::Uuid::new_v4().to_string();
    let initial_id = uuid::Uuid::new_v4().to_string();
    let event_id = unique_event_id("auth-grant-binding-root");
    let (grant, initial) = auth_grant_fixture(tenant_a, user_a, &grant_id, &initial_id, [0x71; 32]);
    let (mutation, entry, envelope) = auth_grant_login_parts(&event_id, grant, initial);
    let _persisted = crate::PgAuthGrantLifecycle::new(&store, fixed_clock())
        .persist_login_grant(
            login_producer_receipt(),
            identity_scope(tenant_a),
            mutation,
            reviewed_generated_event::<generated::event::identity_v1::session_created::Contract>(
                entry, envelope,
            )
            .await?,
        )
        .await?;

    let invalid_bindings = [
        (
            tenant_b,
            grant_id.as_str(),
            user_a,
            0_i64,
            "active",
            "cross tenant",
        ),
        (
            tenant_a,
            grant_id.as_str(),
            user_b,
            0_i64,
            "active",
            "wrong user",
        ),
        (
            tenant_a,
            grant_id.as_str(),
            user_a,
            1_i64,
            "active",
            "wrong epoch",
        ),
        (
            tenant_a,
            grant_id.as_str(),
            user_a,
            0_i64,
            "revoked",
            "wrong root status",
        ),
        (
            tenant_a,
            "missing-auth-grant",
            user_a,
            0_i64,
            "active",
            "missing root",
        ),
    ];
    for (index, (tenant, bound_grant, user, epoch, status, label)) in
        invalid_bindings.into_iter().enumerate()
    {
        let refresh_id = uuid::Uuid::new_v4().to_string();
        let result = raw_refresh_insert(
            &store,
            tenant,
            &refresh_id,
            bound_grant,
            user,
            epoch,
            status,
            0x80 + u8::try_from(index)?,
        )
        .await;
        assert!(result.is_err(), "database accepted {label} refresh binding");
    }

    let inserted: (i64,) =
        sqlx::query_as("SELECT count(*) FROM refresh_tokens WHERE auth_grant_id = $1")
            .bind(&grant_id)
            .fetch_one(&store.pool)
            .await?;
    assert_eq!(
        inserted.0, 1,
        "only the co-transactional initial refresh may exist"
    );

    sqlx::query("DELETE FROM auth_grants WHERE tenant_id = $1::uuid AND grant_id = $2")
        .bind(tenant_a.to_string())
        .bind(&grant_id)
        .execute(&store.pool)
        .await?;
    let cascaded: (i64,) =
        sqlx::query_as("SELECT count(*) FROM refresh_tokens WHERE id = $1::uuid")
            .bind(&initial_id)
            .fetch_one(&store.pool)
            .await?;
    assert_eq!(
        cascaded.0, 0,
        "root deletion must cascade to its refresh family"
    );

    store.shutdown().await?;
    Ok(())
}

// Revision lifecycle：首次 mutation 追加 v1；同 id 内容变化追加 v2；canonical 相同则 no-op；查无 → None。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::expect_used)]
// reason: 已追加 revision 的 role 必定可查到；集成测试 happy-path；item-level carve-out（error-handling.md §Carve-out）。
async fn role_definition_revision_roundtrip_and_canonical_noop() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let repo = PgRoleRepo::from_unverified_for_test(&store);
    let lifecycle = PgRoleDefinitionLifecycle::from_unverified_for_test(&store);
    let tenant = role_tenant(ROLE_TENANT_A)?;

    // 尚无 revision → None（fail-closed，anti-vacuity 的负例基线）。
    let admin = Role::hydrate("role-admin", "Admin", &["identity:policy:read".to_string()])?;
    let admin_id = admin.id().clone();
    assert!(
        repo.find(identity_scope(tenant), admin_id.clone())
            .await?
            .is_none(),
        "无 revision → None"
    );

    // 首次 mutation → revision 1，read model 往返一致（id / name / permissions）。
    let created = lifecycle
        .create_or_update(identity_scope(tenant), role_mutation_actor(tenant), admin)
        .await?;
    assert!(created.changed());
    assert_eq!(created.revision().get(), 1);
    let got = repo
        .find(identity_scope(tenant), admin_id.clone())
        .await?
        .expect("revision 1 role visible");
    assert_eq!(got.id().as_str(), "role-admin");
    assert_eq!(got.name(), "Admin");
    assert_eq!(
        got.permission_ids().collect::<Vec<_>>(),
        vec!["identity:policy:read"]
    );

    // 同 id 内容变化 → append revision 2，latest read model 切到新快照。
    let admin_v2 = Role::hydrate(
        "role-admin",
        "Administrator",
        &[
            "identity:policy:read".to_string(),
            "identity:policy:update".to_string(),
        ],
    )?;
    let updated = lifecycle
        .create_or_update(
            identity_scope(tenant),
            role_mutation_actor(tenant),
            admin_v2,
        )
        .await?;
    assert!(updated.changed());
    assert_eq!(updated.revision().get(), 2);
    let got2 = repo
        .find(identity_scope(tenant), admin_id)
        .await?
        .expect("revision 2 role visible");
    assert_eq!(got2.name(), "Administrator", "latest revision updates name");
    assert_eq!(
        got2.permission_ids().collect::<Vec<_>>(),
        vec!["identity:policy:read", "identity:policy:update"],
        "latest revision updates permissions"
    );
    // stable role identity 始终单行；可变内容只追加到 revision history。
    let n: (i64,) =
        sqlx::query_as("SELECT count(*) FROM roles WHERE tenant_id = $1::uuid AND id = $2")
            .bind(ROLE_TENANT_A)
            .bind("role-admin")
            .fetch_one(&store.pool)
            .await?;
    assert_eq!(n.0, 1, "stable role identity remains one row");
    let revisions: (i64,) = sqlx::query_as(
        "SELECT count(*) FROM role_revisions WHERE tenant_id = $1::uuid AND role_id = $2",
    )
    .bind(ROLE_TENANT_A)
    .bind("role-admin")
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(revisions.0, 2, "每次实际变化追加 revision");
    let history: Vec<(i64, String, Vec<String>, String, String, bool)> = sqlx::query_as(
        "SELECT version, name, permissions, changed_by::text, changed_by_kind, \
                changed_at <= clock_timestamp() \
         FROM role_revisions WHERE tenant_id = $1::uuid AND role_id = $2 ORDER BY version",
    )
    .bind(ROLE_TENANT_A)
    .bind("role-admin")
    .fetch_all(&store.pool)
    .await?;
    assert_eq!(history.len(), 2);
    assert_eq!(history[0].0, 1);
    assert_eq!(history[0].1, "Admin");
    assert_eq!(history[1].0, 2);
    assert_eq!(history[1].1, "Administrator");
    assert_eq!(history[1].3, "11111111-2222-4333-8444-555555555555");
    assert_eq!(history[1].4, "admin");
    assert!(history.iter().all(|revision| revision.5));

    let reordered = Role::hydrate(
        "role-admin",
        "Administrator",
        &[
            "identity:policy:update".to_string(),
            "identity:policy:read".to_string(),
            "identity:policy:read".to_string(),
        ],
    )?;
    let no_change = lifecycle
        .create_or_update(
            identity_scope(tenant),
            role_mutation_actor(tenant),
            reordered,
        )
        .await?;
    assert!(
        !no_change.changed(),
        "canonical-equal permissions must be a no-op"
    );
    assert_eq!(no_change.revision().get(), 2);

    let mismatched = lifecycle
        .create_or_update(
            identity_scope(tenant),
            role_mutation_actor(role_tenant(ROLE_TENANT_B)?),
            Role::hydrate("wrong-tenant-actor", "Wrong", &[])?,
        )
        .await;
    assert!(
        matches!(mismatched, Err(IdentityError::PermissionDenied)),
        "actor evidence from another tenant must fail closed"
    );

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn role_revision_function_is_not_an_rss_app_mutation_path() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    sqlx::query("GRANT rss_app TO CURRENT_USER")
        .execute(&store.pool)
        .await?;
    let tenant = ROLE_TENANT_A;
    let actor = "11111111-2222-4333-8444-555555555555";

    let mut denied_function = store.pool.begin().await?;
    sqlx::query("SET LOCAL ROLE rss_app")
        .execute(&mut *denied_function)
        .await?;
    sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
        .bind(tenant)
        .execute(&mut *denied_function)
        .await?;
    let function_call = sqlx::query_as::<_, (i64, bool)>(
        "SELECT version, changed FROM rss_record_role_revision($1, $2, $3, $4::uuid, $5)",
    )
    .bind("acl-role")
    .bind("ACL Role")
    .bind(vec!["identity:role:read".to_string()])
    .bind(actor)
    .bind("admin")
    .fetch_one(&mut *denied_function)
    .await;
    assert!(
        matches!(function_call, Err(sqlx::Error::Database(ref error)) if error.code().as_deref() == Some("42501")),
        "generic rss_app must not execute the actor-attributed role revision function: {function_call:?}"
    );
    denied_function.rollback().await?;

    let mut denied = store.pool.begin().await?;
    sqlx::query("SET LOCAL ROLE rss_app")
        .execute(&mut *denied)
        .await?;
    sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
        .bind(tenant)
        .execute(&mut *denied)
        .await?;
    let direct = sqlx::query("INSERT INTO roles (tenant_id, id) VALUES ($1::uuid, $2)")
        .bind(tenant)
        .bind("forged-role")
        .execute(&mut *denied)
        .await;
    assert!(
        matches!(direct, Err(sqlx::Error::Database(ref error)) if error.code().as_deref() == Some("42501")),
        "rss_app direct role insert must be denied: {direct:?}"
    );
    denied.rollback().await?;

    for statement in [
        "UPDATE roles SET id = id WHERE tenant_id = current_setting('rss.tenant_id')::uuid",
        "DELETE FROM roles WHERE tenant_id = current_setting('rss.tenant_id')::uuid",
        "INSERT INTO role_revisions \
         (tenant_id, role_id, version, name, permissions, changed_by, changed_by_kind) \
         VALUES (current_setting('rss.tenant_id')::uuid, 'acl-role', 99, 'forged', \
                 '{}'::text[], '11111111-2222-4333-8444-555555555555'::uuid, 'admin')",
        "UPDATE role_revisions SET name = 'forged' \
         WHERE tenant_id = current_setting('rss.tenant_id')::uuid",
        "DELETE FROM role_revisions WHERE tenant_id = current_setting('rss.tenant_id')::uuid",
    ] {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(tenant)
            .execute(&mut *tx)
            .await?;
        let result = sqlx::query(statement).execute(&mut *tx).await;
        assert!(
            matches!(result, Err(sqlx::Error::Database(ref error)) if error.code().as_deref() == Some("42501")),
            "rss_app direct role mutation must be denied for {statement}: {result:?}"
        );
        tx.rollback().await?;
    }

    let catalog: (String, bool, bool, bool, bool, bool, bool) = sqlx::query_as(
        "SELECT pg_get_userbyid(proc.proowner), proc.prosecdef, \
                proc.proconfig @> ARRAY['search_path=pg_catalog, pg_temp'], \
                has_function_privilege('rss_app', proc.oid, 'EXECUTE'), \
                has_table_privilege('rss_app', 'public.role_revisions', 'INSERT,UPDATE,DELETE'), \
                owner.rolcanlogin, owner.rolbypassrls \
         FROM pg_proc AS proc JOIN pg_roles AS owner ON owner.oid = proc.proowner \
         WHERE proc.oid = 'public.rss_record_role_revision(text,text,text[],uuid,text)'::regprocedure",
    )
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(catalog.0, "rss_role_revision_owner");
    assert!(catalog.1, "function must be SECURITY DEFINER");
    assert!(catalog.2, "function search_path must be pinned");
    assert!(
        !catalog.3,
        "rss_app must not execute the role revision function"
    );
    assert!(
        !catalog.4,
        "rss_app must not insert role revisions directly"
    );
    assert!(!catalog.5, "function owner must be NOLOGIN");
    assert!(!catalog.6, "function owner must be NOBYPASSRLS");
    let owner_security: (bool, bool, bool, bool, bool, i64) = sqlx::query_as(
        "SELECT owner.rolsuper, owner.rolcreatedb, owner.rolcreaterole, \
                owner.rolreplication, owner.rolinherit, \
                (SELECT count(*) FROM pg_catalog.pg_auth_members AS membership \
                 WHERE membership.member = owner.oid OR membership.roleid = owner.oid) \
         FROM pg_catalog.pg_roles AS owner WHERE owner.rolname = 'rss_role_revision_owner'",
    )
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(
        owner_security,
        (false, false, false, false, false, 0),
        "function owner must have exact non-inheriting attributes and no memberships"
    );
    let unexpected_execute_grantees: i64 = sqlx::query_scalar(
        "SELECT count(DISTINCT privilege.grantee) \
         FROM pg_catalog.pg_proc AS proc \
         CROSS JOIN LATERAL pg_catalog.aclexplode( \
             COALESCE(proc.proacl, pg_catalog.acldefault('f', proc.proowner)) \
         ) AS privilege \
         WHERE proc.oid = 'public.rss_record_role_revision(text,text,text[],uuid,text)'::regprocedure \
           AND privilege.privilege_type = 'EXECUTE' \
           AND privilege.grantee <> proc.proowner",
    )
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(
        unexpected_execute_grantees, 0,
        "only the isolated function owner may execute the role revision function"
    );

    store.shutdown().await?;
    Ok(())
}
/// role repo enrollment：统一 tenant conformance 覆盖 round-trip / cross-tenant invisible / non-interference。
#[tokio::test(flavor = "multi_thread")]
async fn role_repo_tenant_conformance() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let repo = PgRoleRepo::from_unverified_for_test(&store);
    let lifecycle = PgRoleDefinitionLifecycle::from_unverified_for_test(&store);
    let tenant_a = role_tenant(ROLE_TENANT_A)?;
    let tenant_b = role_tenant(ROLE_TENANT_B)?;
    let role_id = Role::hydrate("tenant-conf-role", "seed", &[])?.id().clone();

    testkit::tenant_conformance::assert_tenant_isolation(
        tenant_a,
        tenant_b,
        |tenant| {
            let lifecycle = &lifecycle;
            async move {
                lifecycle
                    .create_or_update(
                        identity_scope(tenant),
                        role_mutation_actor(tenant),
                        Role::hydrate(
                            "tenant-conf-role",
                            "TenantConf",
                            &["identity:policy:read".to_string()],
                        )?,
                    )
                    .await
                    .map(|_| ())
            }
        },
        |tenant| {
            let repo = &repo;
            let role_id = role_id.clone();
            async move {
                repo.find(identity_scope(tenant), role_id)
                    .await
                    .map(|role| role.is_some())
            }
        },
        |error| conformance_retry_category(classify_identity_error(error)),
    )
    .await?;

    store.shutdown().await?;
    Ok(())
}

struct DurableOperatorCase {
    name: String,
    predicate: &'static str,
    operator: Operator,
    matching: Vec<AbacAttribute>,
    non_matching: Vec<AbacAttribute>,
}

fn profile_attribute(value: PolicyValue) -> Result<AbacAttribute, IdentityError> {
    Ok(AbacAttribute::new(
        AttributeKey::parse("principal.profile").map_err(|_| IdentityError::InvalidPolicy)?,
        value,
    ))
}

fn profile_named_attribute(key: &str, value: PolicyValue) -> Result<AbacAttribute, IdentityError> {
    Ok(AbacAttribute::new(
        AttributeKey::parse(key).map_err(|_| IdentityError::InvalidPolicy)?,
        value,
    ))
}

fn scalar_input(value: &PolicyValue) -> PolicyScalarInput {
    match value.as_ref() {
        PolicyValueRef::String(value) => PolicyScalarInput::String(value.to_string()),
        PolicyValueRef::Boolean(value) => PolicyScalarInput::Boolean(value),
        PolicyValueRef::Integer(value) => PolicyScalarInput::Integer(value),
        PolicyValueRef::Decimal(value) => PolicyScalarInput::String(value.as_str().to_string()),
    }
}

fn literal_input(value: &PolicyValue) -> ScalarOperandInput {
    ScalarOperandInput::Literal(TypedPolicyValueInput::new(
        value.value_type(),
        scalar_input(value),
    ))
}

fn hydrate_operator(input: OperatorInput) -> Result<Operator, IdentityError> {
    Operator::try_from(input).map_err(|_| IdentityError::InvalidPolicy)
}

fn durable_operator_cases()
-> Result<Vec<DurableOperatorCase>, Box<dyn std::error::Error + Send + Sync>> {
    let mut cases = Vec::new();
    let equality_values = [
        (
            "string",
            PolicyValue::string("eng")?,
            PolicyValue::string("ops")?,
        ),
        (
            "boolean",
            PolicyValue::boolean(true),
            PolicyValue::boolean(false),
        ),
        ("integer", PolicyValue::integer(7), PolicyValue::integer(8)),
        (
            "decimal",
            PolicyValue::decimal("1.25")?,
            PolicyValue::decimal("2.5")?,
        ),
    ];
    for (value_type, expected, alternative) in equality_values {
        for predicate in [EqualityPredicate::Eq, EqualityPredicate::Ne] {
            let (matching, non_matching) = match predicate {
                EqualityPredicate::Eq => (expected.clone(), alternative.clone()),
                EqualityPredicate::Ne => (alternative.clone(), expected.clone()),
            };
            cases.push(DurableOperatorCase {
                name: format!(
                    "equality-{}-{value_type}",
                    match predicate {
                        EqualityPredicate::Eq => "eq",
                        EqualityPredicate::Ne => "ne",
                    }
                ),
                predicate: match predicate {
                    EqualityPredicate::Eq => "eq",
                    EqualityPredicate::Ne => "ne",
                },
                operator: hydrate_operator(OperatorInput::Equality {
                    predicate,
                    operand: literal_input(&expected),
                })?,
                matching: vec![profile_attribute(matching)?],
                non_matching: vec![profile_attribute(non_matching)?],
            });
        }
    }
    cases.push(DurableOperatorCase {
        name: "equality-attribute-string".to_owned(),
        predicate: "eq",
        operator: hydrate_operator(OperatorInput::Equality {
            predicate: EqualityPredicate::Eq,
            operand: ScalarOperandInput::Attribute {
                value_type: PolicyValueType::String,
                attribute: "principal.id".to_string(),
            },
        })?,
        matching: vec![
            profile_attribute(PolicyValue::string("alice")?)?,
            profile_named_attribute("principal.id", PolicyValue::string("alice")?)?,
        ],
        non_matching: vec![
            profile_attribute(PolicyValue::string("alice")?)?,
            profile_named_attribute("principal.id", PolicyValue::string("bob")?)?,
        ],
    });

    let order_values = [
        (
            "integer",
            PolicyValue::integer(7),
            PolicyValue::integer(8),
            PolicyValue::integer(7),
            PolicyValue::integer(6),
        ),
        (
            "decimal",
            PolicyValue::decimal("1.5")?,
            PolicyValue::decimal("2")?,
            PolicyValue::decimal("1.5")?,
            PolicyValue::decimal("1")?,
        ),
    ];
    for (value_type, expected, greater, equal, less) in order_values {
        for (predicate, matching, non_matching, wire) in [
            (OrderingPredicate::Gt, greater.clone(), equal.clone(), "gt"),
            (OrderingPredicate::Ge, equal.clone(), less.clone(), "ge"),
            (OrderingPredicate::Lt, less.clone(), equal.clone(), "lt"),
            (OrderingPredicate::Le, equal.clone(), greater.clone(), "le"),
        ] {
            cases.push(DurableOperatorCase {
                name: format!("ordering-{wire}-{value_type}"),
                predicate: wire,
                operator: hydrate_operator(OperatorInput::Ordering {
                    predicate,
                    operand: literal_input(&expected),
                })?,
                matching: vec![profile_attribute(matching)?],
                non_matching: vec![profile_attribute(non_matching)?],
            });
        }
    }

    let membership_values = [
        (
            "string",
            vec![PolicyValue::string("eng")?, PolicyValue::string("ops")?],
            PolicyValue::string("eng")?,
            PolicyValue::string("sales")?,
        ),
        (
            "boolean",
            vec![PolicyValue::boolean(false)],
            PolicyValue::boolean(false),
            PolicyValue::boolean(true),
        ),
        (
            "integer",
            vec![PolicyValue::integer(7), PolicyValue::integer(8)],
            PolicyValue::integer(7),
            PolicyValue::integer(9),
        ),
        (
            "decimal",
            vec![PolicyValue::decimal("1.25")?, PolicyValue::decimal("2.5")?],
            PolicyValue::decimal("1.25")?,
            PolicyValue::decimal("3.75")?,
        ),
    ];
    for (value_type, values, member, outsider) in membership_values {
        for predicate in [MembershipPredicate::In, MembershipPredicate::NotIn] {
            let (matching, non_matching, wire) = match predicate {
                MembershipPredicate::In => (member.clone(), outsider.clone(), "in"),
                MembershipPredicate::NotIn => (outsider.clone(), member.clone(), "notIn"),
            };
            cases.push(DurableOperatorCase {
                name: format!("membership-{wire}-{value_type}"),
                predicate: wire,
                operator: hydrate_operator(OperatorInput::Membership {
                    predicate,
                    value_type: values[0].value_type(),
                    values: values.iter().map(scalar_input).collect(),
                })?,
                matching: vec![profile_attribute(matching)?],
                non_matching: vec![profile_attribute(non_matching)?],
            });
        }
    }

    for (predicate, pattern, matching, non_matching, wire) in [
        (
            StringPredicate::StartsWith,
            "team-",
            "team-ops",
            "ops-team",
            "startsWith",
        ),
        (
            StringPredicate::EndsWith,
            "-ops",
            "team-ops",
            "ops-team",
            "endsWith",
        ),
        (
            StringPredicate::Contains,
            "am-o",
            "team-ops",
            "team-dev",
            "contains",
        ),
        (
            StringPredicate::Glob,
            "team-*",
            "team-ops",
            "ops-team",
            "glob",
        ),
        (
            StringPredicate::Regex,
            "^team-[a-z]+$",
            "team-ops",
            "team-123",
            "regex",
        ),
    ] {
        cases.push(DurableOperatorCase {
            name: format!("string-{wire}"),
            predicate: wire,
            operator: hydrate_operator(OperatorInput::String {
                predicate,
                pattern: pattern.to_string(),
            })?,
            matching: vec![profile_attribute(PolicyValue::string(matching)?)?],
            non_matching: vec![profile_attribute(PolicyValue::string(non_matching)?)?],
        });
    }
    Ok(cases)
}

fn durable_operator_policy(
    id: &str,
    tenant: rss_request_context::TenantId,
    version: u32,
    operator: Operator,
    effect: PolicyEffect,
) -> Result<Policy, IdentityError> {
    let rules = vec![PolicyRule::with_obligations(
        PolicyCondition::new(
            AttributeKey::parse("principal.profile").map_err(|_| IdentityError::InvalidPolicy)?,
            operator,
        ),
        effect,
        PolicyObligations::empty(),
    )];
    Policy::hydrate(
        id,
        tenant,
        policy_scope()?,
        version,
        policy_time(10),
        None,
        rules,
    )
}

/// Every Common ABAC predicate/value shape crosses the real create/update JSONB path, hydrates
/// through PgPolicyRepo, and preserves the production PDP decision.
#[tokio::test(flavor = "multi_thread")]
async fn policy_repo_common_abac_profile_matrix_is_durable_and_authoritative() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let repo = PgPolicyRepo::from_unverified_for_test(&store);
    let lifecycle = PgPolicyLifecycle::new(&store, fixed_clock());
    let tenant = role_tenant(ROLE_TENANT_A)?;

    for (index, case) in durable_operator_cases()?.into_iter().enumerate() {
        let id = format!("profile-matrix-{index}");
        let created =
            durable_operator_policy(&id, tenant, 1, case.operator.clone(), PolicyEffect::Allow)?;
        policy_create_and_emit(&lifecycle, tenant, created).await?;

        let durable = repo
            .find(identity_scope(tenant), policy_id(&id)?)
            .await?
            .ok_or("created profile policy must be durable")?;
        assert_eq!(
            durable.rules()[0].operator(),
            &case.operator,
            "{}",
            case.name
        );
        let stored_predicate: String = sqlx::query_scalar(
            "SELECT rules #>> '{rules,0,condition,operator,predicate}' \
             FROM abac_policies WHERE tenant_id=$1::uuid AND id=$2",
        )
        .bind(ROLE_TENANT_A)
        .bind(&id)
        .fetch_one(&store.pool)
        .await?;
        assert_eq!(stored_predicate, case.predicate, "{}", case.name);
        assert_eq!(
            identity::test_support::evaluate_policies_for_test(
                tenant,
                &case.matching,
                std::slice::from_ref(&durable),
            ),
            vocab::Decision::Allow,
            "created {} must authorize its matching tuple",
            case.name,
        );
        assert_eq!(
            identity::test_support::evaluate_policies_for_test(
                tenant,
                &case.non_matching,
                std::slice::from_ref(&durable),
            ),
            vocab::Decision::Deny,
            "created {} must deny its non-matching tuple",
            case.name,
        );

        let updated =
            durable_operator_policy(&id, tenant, 2, case.operator.clone(), PolicyEffect::Deny)?;
        policy_update_and_emit(&lifecycle, tenant, updated, policy_version(1)?).await?;
        let durable = repo
            .find(identity_scope(tenant), policy_id(&id)?)
            .await?
            .ok_or("updated profile policy must be durable")?;
        assert_eq!(durable.version().get(), 2, "{}", case.name);
        assert_eq!(
            durable.rules()[0].operator(),
            &case.operator,
            "{}",
            case.name
        );
        assert_eq!(
            identity::test_support::evaluate_policies_for_test(
                tenant,
                &case.matching,
                std::slice::from_ref(&durable),
            ),
            vocab::Decision::Deny,
            "updated deny {} must override its matching tuple",
            case.name,
        );
    }

    store.shutdown().await?;
    Ok(())
}

/// policy repo enrollment：统一 conformance 覆盖 create/find/list/update/delete。
#[tokio::test(flavor = "multi_thread")]
async fn policy_repo_lifecycle_conformance() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let repo = PgPolicyRepo::from_unverified_for_test(&store);
    let lifecycle = PgPolicyLifecycle::new(&store, fixed_clock());
    let tenant = role_tenant(ROLE_TENANT_A)?;
    let created = policy_fixture(
        "policy-lifecycle",
        tenant,
        1,
        10,
        None,
        PolicyEffect::Allow,
        PolicyObligations::empty(),
    )?;
    let updated = policy_fixture(
        "policy-lifecycle",
        tenant,
        2,
        10,
        None,
        PolicyEffect::Deny,
        PolicyObligations::empty(),
    )?;

    testkit::policy_conformance::assert_policy_store_lifecycle(
        testkit::policy_conformance::PolicyLifecycleCase {
            tenant,
            key: "policy-lifecycle",
            created_policy: created,
            updated_policy: updated,
            create: |tenant, _key, policy| {
                let lifecycle = &lifecycle;
                async move {
                    policy_create_and_emit(lifecycle, tenant, policy)
                        .await
                        .map(|_| ())
                }
            },
            find: |tenant, key| {
                let repo = &repo;
                async move { repo.find(identity_scope(tenant), policy_id(key)?).await }
            },
            list: |tenant| {
                let repo = &repo;
                async move {
                    repo.list_effective(identity_scope(tenant), policy_scope()?, policy_time(20))
                        .await
                }
            },
            update: |tenant, _key, policy| {
                let lifecycle = &lifecycle;
                async move {
                    policy_update_and_emit(lifecycle, tenant, policy, policy_version(1)?)
                        .await
                        .map(|_| ())
                }
            },
            delete: |tenant, key| {
                let lifecycle = &lifecycle;
                async move {
                    policy_deactivate_and_emit(
                        lifecycle,
                        tenant,
                        policy_id(key)?,
                        policy_version(2)?,
                    )
                    .await
                    .map(|_| ())
                }
            },
        },
    )
    .await?;

    store.shutdown().await?;
    Ok(())
}

/// policy repo delete tombstone：删除后同 id 不允许通过普通 create 重建并重置 version。
#[tokio::test(flavor = "multi_thread")]
async fn policy_repo_delete_leaves_tombstone_conformance() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let repo = PgPolicyRepo::from_unverified_for_test(&store);
    let lifecycle = PgPolicyLifecycle::new(&store, fixed_clock());
    let tenant = role_tenant(ROLE_TENANT_A)?;
    let created = policy_fixture(
        "policy-delete-tombstone",
        tenant,
        1,
        10,
        None,
        PolicyEffect::Allow,
        PolicyObligations::empty(),
    )?;
    let recreated = policy_fixture(
        "policy-delete-tombstone",
        tenant,
        1,
        10,
        None,
        PolicyEffect::Deny,
        PolicyObligations::empty(),
    )?;

    testkit::policy_conformance::assert_policy_delete_leaves_tombstone(
        testkit::policy_conformance::PolicyDeleteTombstoneCase {
            tenant,
            key: "policy-delete-tombstone",
            created_policy: created,
            recreated_policy: recreated,
            create: |tenant, _key, policy| {
                let lifecycle = &lifecycle;
                async move {
                    policy_create_and_emit(lifecycle, tenant, policy)
                        .await
                        .map(|_| ())
                }
            },
            find: |tenant, key| {
                let repo = &repo;
                async move { repo.find(identity_scope(tenant), policy_id(key)?).await }
            },
            list: |tenant| {
                let repo = &repo;
                async move {
                    repo.list_effective(identity_scope(tenant), policy_scope()?, policy_time(20))
                        .await
                }
            },
            delete: |tenant, key| {
                let lifecycle = &lifecycle;
                async move {
                    policy_deactivate_and_emit(
                        lifecycle,
                        tenant,
                        policy_id(key)?,
                        policy_version(1)?,
                    )
                    .await
                    .map(|_| ())
                }
            },
            is_recreate_rejected: |err: &IdentityError| {
                matches!(err, IdentityError::PolicyAlreadyExists)
            },
        },
    )
    .await?;

    store.shutdown().await?;
    Ok(())
}

/// policy repo tenant isolation：同 id 在不同 tenant 下互不可见，B 的 update/delete 不影响 A。
#[tokio::test(flavor = "multi_thread")]
async fn policy_repo_tenant_isolation_conformance() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let repo = PgPolicyRepo::from_unverified_for_test(&store);
    let lifecycle = PgPolicyLifecycle::new(&store, fixed_clock());
    let tenant_a = role_tenant(ROLE_TENANT_A)?;
    let tenant_b = role_tenant(ROLE_TENANT_B)?;
    let tenant_a_policy = policy_fixture(
        "policy-tenant-isolation",
        tenant_a,
        1,
        10,
        None,
        PolicyEffect::Allow,
        PolicyObligations::empty(),
    )?;
    let tenant_b_policy = policy_fixture(
        "policy-tenant-isolation",
        tenant_b,
        1,
        10,
        None,
        PolicyEffect::Allow,
        PolicyObligations::empty(),
    )?;
    let tenant_b_updated_policy = policy_fixture(
        "policy-tenant-isolation",
        tenant_b,
        2,
        10,
        None,
        PolicyEffect::Deny,
        PolicyObligations::empty(),
    )?;

    testkit::policy_conformance::assert_policy_store_tenant_isolation(
        testkit::policy_conformance::PolicyTenantIsolationCase {
            tenant_a,
            tenant_b,
            key: "policy-tenant-isolation",
            tenant_a_policy,
            tenant_b_policy,
            tenant_b_updated_policy,
            create: |tenant, _key, policy| {
                let lifecycle = &lifecycle;
                async move {
                    policy_create_and_emit(lifecycle, tenant, policy)
                        .await
                        .map(|_| ())
                }
            },
            find: |tenant, key| {
                let repo = &repo;
                async move { repo.find(identity_scope(tenant), policy_id(key)?).await }
            },
            list: |tenant| {
                let repo = &repo;
                async move {
                    repo.list_effective(identity_scope(tenant), policy_scope()?, policy_time(20))
                        .await
                }
            },
            update: |tenant, _key, policy| {
                let lifecycle = &lifecycle;
                async move {
                    policy_update_and_emit(lifecycle, tenant, policy, policy_version(1)?)
                        .await
                        .map(|_| ())
                }
            },
            delete: |tenant, key| {
                let lifecycle = &lifecycle;
                async move {
                    policy_deactivate_and_emit(
                        lifecycle,
                        tenant,
                        policy_id(key)?,
                        policy_version(2)?,
                    )
                    .await
                    .map(|_| ())
                }
            },
        },
    )
    .await?;

    store.shutdown().await?;
    Ok(())
}

/// policy repo CAS：update/delete 必须使用 current-row version；错版冲突，不回退成 blind write。
#[tokio::test(flavor = "multi_thread")]
async fn policy_repo_cas_update_delete_conflicts() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let lifecycle = PgPolicyLifecycle::new(&store, fixed_clock());
    let tenant = role_tenant(ROLE_TENANT_A)?;
    let created = policy_fixture(
        "policy-cas",
        tenant,
        1,
        10,
        None,
        PolicyEffect::Allow,
        PolicyObligations::empty(),
    )?;
    policy_create_and_emit(&lifecycle, tenant, created).await?;

    let stale_update_event = unique_event_id("policy-cas-stale-update");
    let stale_update = policy_update_and_emit_event(
        &lifecycle,
        tenant,
        policy_fixture(
            "policy-cas",
            tenant,
            2,
            10,
            None,
            PolicyEffect::Deny,
            PolicyObligations::empty(),
        )?,
        policy_version(2)?,
        &stale_update_event,
    )
    .await;
    assert!(
        matches!(stale_update, Err(IdentityError::VersionConflict)),
        "wrong expected version must conflict, got: {stale_update:?}"
    );
    assert!(
        !policy_outbox_exists(&store, &stale_update_event).await?,
        "stale update must not write policy-updated outbox"
    );

    let stale_delete_event = unique_event_id("policy-cas-stale-delete");
    let stale_delete = policy_deactivate_and_emit_event(
        &lifecycle,
        tenant,
        policy_id("policy-cas")?,
        policy_version(2)?,
        &stale_delete_event,
    )
    .await;
    assert!(
        matches!(stale_delete, Err(IdentityError::VersionConflict)),
        "delete with wrong expected version must conflict, got: {stale_delete:?}"
    );
    assert!(
        !policy_outbox_exists(&store, &stale_delete_event).await?,
        "stale delete must not write policy-updated outbox"
    );

    let update_event = unique_event_id("policy-cas-update");
    let updated = policy_update_and_emit_event(
        &lifecycle,
        tenant,
        policy_fixture(
            "policy-cas",
            tenant,
            2,
            10,
            None,
            PolicyEffect::Deny,
            PolicyObligations::empty(),
        )?,
        policy_version(1)?,
        &update_event,
    )
    .await?;
    assert_eq!(updated.version().get(), 2, "CAS update increments version");
    assert!(
        policy_outbox_exists(&store, &update_event).await?,
        "successful update writes policy-updated outbox"
    );

    let stale_delete_after_update_event = unique_event_id("policy-cas-stale-delete-after-update");
    let stale_delete_after_update = policy_deactivate_and_emit_event(
        &lifecycle,
        tenant,
        policy_id("policy-cas")?,
        policy_version(1)?,
        &stale_delete_after_update_event,
    )
    .await;
    assert!(
        matches!(
            stale_delete_after_update,
            Err(IdentityError::VersionConflict)
        ),
        "stale delete after update must conflict, got: {stale_delete_after_update:?}"
    );
    assert!(
        !policy_outbox_exists(&store, &stale_delete_after_update_event).await?,
        "stale delete after update must not write policy-updated outbox"
    );

    let delete_event = unique_event_id("policy-cas-delete");
    assert!(
        policy_deactivate_and_emit_event(
            &lifecycle,
            tenant,
            policy_id("policy-cas")?,
            policy_version(2)?,
            &delete_event,
        )
        .await?,
        "delete at current version succeeds"
    );
    assert!(
        policy_outbox_exists(&store, &delete_event).await?,
        "successful delete writes policy-updated outbox"
    );

    let missing_delete_event = unique_event_id("policy-cas-delete-missing");
    assert!(
        !policy_deactivate_and_emit_event(
            &lifecycle,
            tenant,
            policy_id("policy-cas")?,
            policy_version(2)?,
            &missing_delete_event,
        )
        .await?,
        "delete of missing policy is idempotent false"
    );
    assert!(
        !policy_outbox_exists(&store, &missing_delete_event).await?,
        "idempotent missing delete must not write policy-updated outbox"
    );

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn policy_fact_conflict_rolls_back_policy_create() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let tenant = role_tenant(ROLE_TENANT_A)?;
    let policy_name = format!("policy-fact-conflict-{}", uuid_like());
    let policy = policy_fixture(
        &policy_name,
        tenant,
        1,
        10,
        None,
        PolicyEffect::Allow,
        PolicyObligations::empty(),
    )?;
    let event_id = unique_event_id("policy-fact-conflict");
    let seed = seed_conflicting_outbox_fact(&store, tenant, &event_id).await?;
    let (entry, envelope) = policy_lifecycle_event_with_id(
        tenant,
        policy.id().as_str(),
        "created",
        policy.version(),
        &event_id,
    )?;

    let conflict = PgPolicyLifecycle::new(&store, fixed_clock())
        .create_and_emit(
            policies_create_producer_receipt(),
            identity_scope(tenant),
            policy,
            reviewed_generated_event::<generated::event::identity_v1::policy_updated::Contract>(
                entry, envelope,
            )
            .await?,
        )
        .await;
    assert!(
        matches!(conflict, Err(IdentityError::OutboxFactConflict(_))),
        "policy adapter must preserve typed fact conflict: {conflict:?}"
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM abac_policies WHERE id = $1")
            .bind(&policy_name)
            .fetch_one(&store.pool)
            .await?,
        0,
        "outbox conflict must roll back policy creation"
    );
    assert_seed_fact_unchanged(&store, &event_id, &seed).await?;

    store.shutdown().await?;
    Ok(())
}

/// policy manage read side：list_active 按 policy id 稳定分页，deactivate 后 get/list 均不可见。
#[tokio::test(flavor = "multi_thread")]
async fn policy_repo_list_active_paginates_and_hides_deactivated() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let repo = PgPolicyRepo::from_unverified_for_test(&store);
    let lifecycle = PgPolicyLifecycle::new(&store, fixed_clock());
    let tenant = role_tenant(ROLE_TENANT_A)?;

    for id in ["policy-list-c", "policy-list-a", "policy-list-b"] {
        policy_create_and_emit(
            &lifecycle,
            tenant,
            policy_fixture(
                id,
                tenant,
                1,
                10,
                None,
                PolicyEffect::Allow,
                PolicyObligations::empty(),
            )?,
        )
        .await?;
    }

    let first = repo
        .list_active(
            identity_scope(tenant),
            PolicyPage {
                limit: vocab::Limit::new(2)?,
                after: None,
            },
        )
        .await?;
    assert_eq!(
        first
            .policies
            .iter()
            .map(|policy| policy.id().as_str())
            .collect::<Vec<_>>(),
        vec!["policy-list-a", "policy-list-b"],
        "list_active must sort by policy id"
    );
    assert!(first.has_more, "over-fetch must report has_more");

    let second = repo
        .list_active(
            identity_scope(tenant),
            PolicyPage {
                limit: vocab::Limit::new(2)?,
                after: Some(policy_id("policy-list-b")?),
            },
        )
        .await?;
    assert_eq!(
        second
            .policies
            .iter()
            .map(|policy| policy.id().as_str())
            .collect::<Vec<_>>(),
        vec!["policy-list-c"],
        "cursor must resume strictly after the last policy id"
    );
    assert!(!second.has_more, "last page must not report has_more");

    assert!(
        policy_deactivate_and_emit(
            &lifecycle,
            tenant,
            policy_id("policy-list-b")?,
            policy_version(1)?,
        )
        .await?,
        "deactivate existing policy"
    );
    assert!(
        repo.find(identity_scope(tenant), policy_id("policy-list-b")?)
            .await?
            .is_none(),
        "deactivated policy must be hidden from get"
    );

    let after_deactivate = repo
        .list_active(
            identity_scope(tenant),
            PolicyPage {
                limit: vocab::Limit::new(10)?,
                after: None,
            },
        )
        .await?;
    assert_eq!(
        after_deactivate
            .policies
            .iter()
            .map(|policy| policy.id().as_str())
            .collect::<Vec<_>>(),
        vec!["policy-list-a", "policy-list-c"],
        "deactivated policy must be hidden from list"
    );

    store.shutdown().await?;
    Ok(())
}

/// policy repo active-window：effective_from <= at < effective_until；NULL until 表示不过期。
#[tokio::test(flavor = "multi_thread")]
async fn policy_repo_active_window_conformance() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let repo = PgPolicyRepo::from_unverified_for_test(&store);
    let lifecycle = PgPolicyLifecycle::new(&store, fixed_clock());
    let tenant = role_tenant(ROLE_TENANT_A)?;
    let expired = policy_fixture(
        "policy-window-expired",
        tenant,
        1,
        10,
        Some(20),
        PolicyEffect::Allow,
        PolicyObligations::empty(),
    )?;
    let active = policy_fixture(
        "policy-window-active",
        tenant,
        1,
        20,
        Some(40),
        PolicyEffect::Allow,
        PolicyObligations::empty(),
    )?;
    let future = policy_fixture(
        "policy-window-future",
        tenant,
        1,
        50,
        Some(80),
        PolicyEffect::Allow,
        PolicyObligations::empty(),
    )?;

    testkit::policy_conformance::assert_policy_active_window(
        testkit::policy_conformance::PolicyActiveWindowCase {
            tenant,
            expired_key: "policy-window-expired",
            active_key: "policy-window-active",
            future_key: "policy-window-future",
            expired_policy: expired.clone(),
            active_policy: active.clone(),
            future_policy: future,
            instant_before: 15,
            instant_during: 30,
            instant_after: 90,
            expected_before: vec![expired],
            expected_during: vec![active],
            expected_after: Vec::new(),
            create: |tenant, _key, policy| {
                let lifecycle = &lifecycle;
                async move {
                    policy_create_and_emit(lifecycle, tenant, policy)
                        .await
                        .map(|_| ())
                }
            },
            active_at: |tenant, at| {
                let repo = &repo;
                async move {
                    repo.list_effective(
                        identity_scope(tenant),
                        policy_scope()?,
                        policy_time(at as u64),
                    )
                    .await
                }
            },
        },
    )
    .await?;

    store.shutdown().await?;
    Ok(())
}

/// Resource Security Fact PIP selects the latest revision before freshness evaluation.
struct FixedResourceFactClock(std::time::SystemTime);

impl diport::Clock for FixedResourceFactClock {
    fn now(&self) -> std::time::SystemTime {
        self.0
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn resource_security_fact_repo_latest_and_freshness_conformance() -> TestResult {
    let (pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let reader_config = rss_app_read_config(&pg, &store).await?;
    let verified_reader = crate::PgStore::connect_verified_read(&reader_config).await?;
    let repo = PgResourceSecurityFactRepo::new(&verified_reader);
    let tenant = role_tenant(ROLE_TENANT_A)?;
    let device = ids::DeviceId::parse(RESOURCE_SECURITY_FACT_DEVICE_ID)?;
    sqlx::query(
        "INSERT INTO resource_security_fact_revisions
         (tenant_id, device_id, fact_key, revision, source_id, owner_principal_id,
          observed_at, expires_at)
         VALUES ($1::uuid, $2::uuid, 'resource.owner', 1, 'test-control-plane', 'owner-a',
                 to_timestamp(10), to_timestamp(30))",
    )
    .bind(tenant.to_string())
    .bind(device.as_uuid().to_string())
    .execute(&store.pool)
    .await?;
    let device_scope =
        identity::ports::device_certificate::DeviceCertificateScope::for_test(tenant, device);

    let known = repo
        .resolve_latest(
            identity_scope(tenant),
            device_scope,
            vec![ResourceSecurityFactKey::Owner],
            policy_time(20),
        )
        .await?;
    let ResourceSecurityFactResolution::Known(facts) = known else {
        return Err(std::io::Error::other(format!(
            "expected known resource security fact, got {known:?}"
        ))
        .into());
    };
    assert_eq!(facts.len(), 1);
    assert_eq!(facts[0].revision().get(), 1);

    let pip = identity::DeviceResourceFactPip::new(
        std::sync::Arc::from(identity::ports::DynResourceSecurityFactReadRepo::new_box(
            PgResourceSecurityFactRepo::new(&verified_reader),
        )),
        std::sync::Arc::new(FixedResourceFactClock(policy_time(20))),
    );
    let attrs = pip
        .resolve(device_scope, vec![ResourceSecurityFactKey::Owner])
        .await?;
    assert_eq!(
        attrs.len(),
        1,
        "production-shaped reader must feed typed PIP"
    );
    let tenant_b = role_tenant(ROLE_TENANT_B)?;
    let tenant_b_scope =
        identity::ports::device_certificate::DeviceCertificateScope::for_test(tenant_b, device);
    assert!(
        pip.resolve(tenant_b_scope, vec![ResourceSecurityFactKey::Owner])
            .await
            .is_err(),
        "reader RLS and typed PIP must reject a cross-tenant scope"
    );

    let missing = repo
        .resolve_latest(
            identity_scope(tenant),
            device_scope,
            vec![ResourceSecurityFactKey::RiskClass],
            policy_time(20),
        )
        .await?;
    assert!(matches!(
        missing,
        ResourceSecurityFactResolution::Missing(ResourceSecurityFactKey::RiskClass)
    ));

    sqlx::query(
        "INSERT INTO resource_security_fact_revisions
         (tenant_id, device_id, fact_key, revision, source_id, owner_principal_id,
          observed_at, expires_at)
         VALUES ($1::uuid, $2::uuid, 'resource.owner', 2, 'test-control-plane', 'owner-b',
                 to_timestamp(15), to_timestamp(18))",
    )
    .bind(tenant.to_string())
    .bind(device.as_uuid().to_string())
    .execute(&store.pool)
    .await?;
    let stale = repo
        .resolve_latest(
            identity_scope(tenant),
            device_scope,
            vec![ResourceSecurityFactKey::Owner],
            policy_time(20),
        )
        .await?;
    assert!(
        matches!(
            stale,
            ResourceSecurityFactResolution::Stale(ResourceSecurityFactKey::Owner)
        ),
        "latest expired revision must not fall back to revision 1"
    );

    assert!(
        pip.resolve(device_scope, vec![ResourceSecurityFactKey::Owner])
            .await
            .is_err(),
        "typed PIP must not fall back after the latest revision expires"
    );

    drop(repo);
    drop(pip);
    verified_reader.store_arc().shutdown().await?;
    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn resource_security_fact_reader_preserves_subsecond_freshness_boundaries() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let tenant = rss_request_context::TenantId::parse(ROLE_TENANT_A)?;
    let device = ids::DeviceId::parse(RESOURCE_SECURITY_FACT_DEVICE_ID)?;
    sqlx::query(
        "INSERT INTO resource_security_fact_revisions
         (tenant_id, device_id, fact_key, revision, source_id, owner_principal_id,
          observed_at, expires_at)
         VALUES ($1::uuid, $2::uuid, 'resource.owner', 1, 'test-control-plane', 'owner-a',
                 to_timestamp(1000.1), to_timestamp(1000.5))",
    )
    .bind(tenant.to_string())
    .bind(device.as_uuid().to_string())
    .execute(&store.pool)
    .await?;
    let repo = PgResourceSecurityFactRepo::from_unverified_for_test(&store);
    let scope = identity::test_support::device_certificate_scope(tenant, device);
    let expired_at = SystemTime::UNIX_EPOCH + Duration::from_millis(1_000_600);
    assert!(matches!(
        repo.resolve_latest(
            identity_scope(tenant),
            scope,
            vec![ResourceSecurityFactKey::Owner],
            expired_at,
        )
        .await?,
        ResourceSecurityFactResolution::Stale(ResourceSecurityFactKey::Owner)
    ));

    let future_device = ids::DeviceId::parse("00000000-0000-4000-8000-000000000aac")?;
    sqlx::query(
        "INSERT INTO resource_security_fact_revisions
         (tenant_id, device_id, fact_key, revision, source_id, owner_principal_id,
          observed_at, expires_at)
         VALUES ($1::uuid, $2::uuid, 'resource.owner', 1, 'test-control-plane', 'owner-a',
                 to_timestamp(1000.5), to_timestamp(1001.5))",
    )
    .bind(tenant.to_string())
    .bind(future_device.as_uuid().to_string())
    .execute(&store.pool)
    .await?;
    let future_scope = identity::test_support::device_certificate_scope(tenant, future_device);
    let before_observation = SystemTime::UNIX_EPOCH + Duration::from_millis(1_000_400);
    assert!(matches!(
        repo.resolve_latest(
            identity_scope(tenant),
            future_scope,
            vec![ResourceSecurityFactKey::Owner],
            before_observation,
        )
        .await?,
        ResourceSecurityFactResolution::Stale(ResourceSecurityFactKey::Owner)
    ));
    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn resource_security_fact_bootstrap_cas_replay_and_acl_conformance() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let tenant = ROLE_TENANT_A;
    let device = RESOURCE_SECURITY_FACT_DEVICE_ID;

    #[allow(clippy::too_many_arguments)]
    async fn apply_fact(
        pool: &sqlx::PgPool,
        tenant: &str,
        device: &str,
        key: &str,
        revision: i64,
        source: &str,
        principal: Option<&str>,
        risk_class: Option<&str>,
        observed_at: i64,
        expires_at: i64,
    ) -> Result<String, sqlx::Error> {
        let mut tx = pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_resource_fact_bootstrap")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(tenant)
            .execute(&mut *tx)
            .await?;
        let outcome: String = sqlx::query_scalar(
            "SELECT public.rss_apply_resource_security_fact_revision(
                $1::uuid, $2::uuid, $3, $4, $5, $6,
                $7, to_timestamp($8), to_timestamp($9))::text",
        )
        .bind(tenant)
        .bind(device)
        .bind(key)
        .bind(revision)
        .bind(source)
        .bind(principal)
        .bind(risk_class)
        .bind(observed_at)
        .bind(expires_at)
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(outcome)
    }

    async fn apply_owner(
        pool: &sqlx::PgPool,
        tenant: &str,
        device: &str,
        revision: i64,
        principal: &str,
        observed_at: i64,
        expires_at: i64,
    ) -> Result<String, sqlx::Error> {
        apply_fact(
            pool,
            tenant,
            device,
            "resource.owner",
            revision,
            "test-control-plane",
            Some(principal),
            None,
            observed_at,
            expires_at,
        )
        .await
    }

    let now: i64 = sqlx::query_scalar("SELECT extract(epoch FROM clock_timestamp())::bigint")
        .fetch_one(&store.pool)
        .await?;
    let (left, right) = tokio::join!(
        apply_owner(
            &store.pool,
            tenant,
            device,
            1,
            "owner-a",
            now - 1,
            now + 300
        ),
        apply_owner(
            &store.pool,
            tenant,
            device,
            1,
            "owner-a",
            now - 1,
            now + 300
        ),
    );
    let outcomes = [left?, right?];
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| *outcome == "Applied")
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| *outcome == "Replay")
            .count(),
        1
    );

    let conflict = apply_owner(
        &store.pool,
        tenant,
        device,
        1,
        "owner-b",
        now - 1,
        now + 300,
    )
    .await;
    assert_eq!(
        conflict
            .expect_err("same revision with different payload must conflict")
            .as_database_error()
            .and_then(sqlx::error::DatabaseError::code)
            .as_deref(),
        Some("P2111")
    );
    assert_eq!(
        apply_owner(
            &store.pool,
            tenant,
            device,
            2,
            "owner-b",
            now - 1,
            now + 300
        )
        .await?,
        "Applied"
    );
    assert_eq!(
        apply_owner(
            &store.pool,
            tenant,
            device,
            2,
            "owner-b",
            now - 1,
            now + 300
        )
        .await?,
        "Replay"
    );

    for (source, principal, observed_at, expires_at, reason) in [
        (
            "other-control-plane",
            "owner-b",
            now - 1,
            now + 300,
            "source",
        ),
        ("test-control-plane", "owner-c", now - 1, now + 300, "value"),
        (
            "test-control-plane",
            "owner-b",
            now - 2,
            now + 300,
            "observed_at",
        ),
        (
            "test-control-plane",
            "owner-b",
            now - 1,
            now + 301,
            "expires_at",
        ),
    ] {
        let error = apply_fact(
            &store.pool,
            tenant,
            device,
            "resource.owner",
            2,
            source,
            Some(principal),
            None,
            observed_at,
            expires_at,
        )
        .await
        .expect_err("same revision with any changed fingerprint field must conflict");
        assert_eq!(
            error
                .as_database_error()
                .and_then(sqlx::error::DatabaseError::code)
                .as_deref(),
            Some("P2111"),
            "changed {reason} must conflict without appending"
        );
    }

    assert_eq!(
        apply_fact(
            &store.pool,
            tenant,
            device,
            "resource.riskClass",
            1,
            "test-control-plane",
            None,
            Some("restricted"),
            now - 1,
            now + 300,
        )
        .await?,
        "Applied"
    );
    assert_eq!(
        apply_fact(
            &store.pool,
            tenant,
            device,
            "resource.riskClass",
            1,
            "test-control-plane",
            None,
            Some("restricted"),
            now - 1,
            now + 300,
        )
        .await?,
        "Replay"
    );
    let risk_repo = PgResourceSecurityFactRepo::from_unverified_for_test(&store);
    let risk_scope = identity::test_support::device_certificate_scope(
        rss_request_context::TenantId::parse(tenant)?,
        ids::DeviceId::parse(device)?,
    );
    let risk = risk_repo
        .resolve_latest(
            identity_scope(rss_request_context::TenantId::parse(tenant)?),
            risk_scope,
            vec![ResourceSecurityFactKey::RiskClass],
            policy_time(u64::try_from(now)?),
        )
        .await?;
    assert!(matches!(risk, ResourceSecurityFactResolution::Known(ref facts) if facts.len() == 1));

    let expired_replay_device = "00000000-0000-4000-8000-000000000aad";
    sqlx::query(
        "INSERT INTO resource_security_fact_revisions
         (tenant_id, device_id, fact_key, revision, source_id, owner_principal_id,
          observed_at, expires_at)
         VALUES ($1::uuid, $2::uuid, 'resource.owner', 1, 'test-control-plane', 'owner-expired',
                 to_timestamp($3), to_timestamp($4))",
    )
    .bind(tenant)
    .bind(expired_replay_device)
    .bind(now - 300)
    .bind(now - 100)
    .execute(&store.pool)
    .await?;
    assert_eq!(
        apply_fact(
            &store.pool,
            tenant,
            expired_replay_device,
            "resource.owner",
            1,
            "test-control-plane",
            Some("owner-expired"),
            None,
            now - 300,
            now - 100,
        )
        .await?,
        "Replay",
        "durable exact replay remains stable after expiry"
    );

    let mut long_tx = store.pool.begin().await?;
    sqlx::query("SET LOCAL ROLE rss_resource_fact_bootstrap")
        .execute(&mut *long_tx)
        .await?;
    sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
        .bind(tenant)
        .execute(&mut *long_tx)
        .await?;
    sqlx::query("SELECT pg_sleep(0.05)")
        .execute(&mut *long_tx)
        .await?;
    let expired_during_transaction = sqlx::query(
        "SELECT public.rss_apply_resource_security_fact_revision(
            $1::uuid, '00000000-0000-4000-8000-000000000aae'::uuid,
            'resource.owner', 1, 'test-control-plane', 'owner-clock', NULL,
            transaction_timestamp(), transaction_timestamp() + interval '20 milliseconds')",
    )
    .bind(tenant)
    .execute(&mut *long_tx)
    .await
    .expect_err("acceptance uses call time, not transaction start time");
    assert_eq!(
        expired_during_transaction
            .as_database_error()
            .and_then(sqlx::error::DatabaseError::code)
            .as_deref(),
        Some("22023")
    );
    long_tx.rollback().await?;
    for (revision, observed_at, expires_at, reason) in [
        (1, now - 1, now + 300, "old revision"),
        (4, now - 1, now + 300, "revision gap"),
        (3, now + 30, now + 300, "future observation"),
        (3, now - 30, now - 1, "expired input"),
    ] {
        let error = apply_owner(
            &store.pool,
            tenant,
            device,
            revision,
            "owner-c",
            observed_at,
            expires_at,
        )
        .await
        .expect_err(reason);
        let expected = if revision == 1 || revision == 4 {
            "P2111"
        } else {
            "22023"
        };
        assert_eq!(
            error
                .as_database_error()
                .and_then(sqlx::error::DatabaseError::code)
                .as_deref(),
            Some(expected),
            "{reason} must have a stable non-transient class"
        );
    }
    let initial_gap = apply_owner(
        &store.pool,
        tenant,
        "00000000-0000-4000-8000-000000000aaa",
        2,
        "owner-a",
        now - 1,
        now + 300,
    )
    .await
    .expect_err("initial revision must be one");
    assert_eq!(
        initial_gap
            .as_database_error()
            .and_then(sqlx::error::DatabaseError::code)
            .as_deref(),
        Some("P2111")
    );

    let mut mismatch_tx = store.pool.begin().await?;
    sqlx::query("SET LOCAL ROLE rss_resource_fact_bootstrap")
        .execute(&mut *mismatch_tx)
        .await?;
    sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
        .bind(tenant)
        .execute(&mut *mismatch_tx)
        .await?;
    let mismatch = sqlx::query(
        "SELECT public.rss_apply_resource_security_fact_revision(
            $1::uuid, '00000000-0000-4000-8000-000000000aab'::uuid,
            'resource.riskClass', 1, 'test-control-plane', 'owner-a', NULL,
            clock_timestamp() - interval '1 second', clock_timestamp() + interval '5 minutes')",
    )
    .bind(tenant)
    .execute(&mut *mismatch_tx)
    .await;
    assert!(mismatch.is_err(), "key/value mismatch must be rejected");
    mismatch_tx.rollback().await?;
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM resource_security_fact_revisions
         WHERE tenant_id = $1::uuid AND device_id = $2::uuid",
    )
    .bind(tenant)
    .bind(device)
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(
        count, 3,
        "replay/conflict must not append an audit revision"
    );

    let acl: (bool, bool, bool, bool, bool, bool) = sqlx::query_as(
        "SELECT
            has_table_privilege('rss_app', 'resource_security_fact_revisions', 'SELECT'),
            has_table_privilege('rss_app', 'resource_security_fact_revisions', 'INSERT'),
            has_table_privilege('rss_app', 'resource_security_fact_revisions', 'UPDATE'),
            has_table_privilege('rss_app', 'resource_security_fact_revisions', 'DELETE'),
            has_table_privilege('rss_resource_fact_bootstrap', 'resource_security_fact_revisions', 'SELECT'),
            has_table_privilege('rss_resource_fact_bootstrap', 'resource_security_fact_revisions', 'INSERT')",
    )
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(acl, (true, false, false, false, false, false));

    for invalid_sql in [
        "INSERT INTO resource_security_fact_revisions
         (tenant_id, device_id, fact_key, revision, source_id, owner_principal_id,
          observed_at, expires_at)
         VALUES ('f47ac10b-58cc-4372-a567-0e02b2c3d479',
                 '11111111-2222-4333-8444-555555555555', 'resource.location', 1,
                 'source', 'owner', now(), now() + interval '1 minute')",
        "INSERT INTO resource_security_fact_revisions
         (tenant_id, device_id, fact_key, revision, source_id, risk_class,
          observed_at, expires_at)
         VALUES ('f47ac10b-58cc-4372-a567-0e02b2c3d479',
                 '11111111-2222-4333-8444-555555555555', 'resource.owner', 1,
                 'source', 'normal', now(), now() + interval '1 minute')",
        "INSERT INTO resource_security_fact_revisions
         (tenant_id, device_id, fact_key, revision, source_id, risk_class,
          observed_at, expires_at)
         VALUES ('f47ac10b-58cc-4372-a567-0e02b2c3d479',
                 '11111111-2222-4333-8444-555555555555', 'resource.riskClass', 1,
                 'source', 'normal', now(), now())",
    ] {
        assert!(
            sqlx::query(invalid_sql).execute(&store.pool).await.is_err(),
            "raw SQL must not bypass typed ledger constraints"
        );
    }

    store.shutdown().await?;
    Ok(())
}

/// policy repo decode is strict：语义非法与未知 JSON 字段都会使 active load fail-closed。
#[tokio::test(flavor = "multi_thread")]
async fn policy_repo_rejects_malformed_persisted_json() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let repo = PgPolicyRepo::from_unverified_for_test(&store);

    testkit::policy_conformance::assert_policy_rejects_malformed(
        (
            "policy-malformed",
            principal_kind_rule_json(r#"{"kind":"like","pattern":""}"#),
        ),
        ("policy-unknown-field", r#"{"rules":[],"unexpected":true}"#),
        |(id, rules_json)| {
            let store = &store;
            let repo = &repo;
            async move { insert_raw_policy_and_load(store, repo, id, &rules_json).await }
        },
        |(id, rules_json)| {
            let store = &store;
            let repo = &repo;
            async move { insert_raw_policy_and_load(store, repo, id, rules_json).await }
        },
        policy_rejection,
    )
    .await?;

    let mut malformed_operators = vec![
        (
            "policy-scalar-type-mismatch".to_owned(),
            r#"{"family":"equality","predicate":"eq","operand":{"kind":"literal","valueType":"boolean","value":"true"}}"#.to_owned(),
        ),
        (
            "policy-ordering-attribute".to_owned(),
            r#"{"family":"ordering","predicate":"gt","operand":{"kind":"attribute","valueType":"string","attribute":"principal.id"}}"#.to_owned(),
        ),
        (
            "policy-empty-set".to_owned(),
            r#"{"family":"membership","predicate":"in","operand":{"kind":"set","valueType":"string","values":[]}}"#.to_owned(),
        ),
        (
            "policy-duplicate-set".to_owned(),
            r#"{"family":"membership","predicate":"in","operand":{"kind":"set","valueType":"string","values":["admin","admin"]}}"#.to_owned(),
        ),
        (
            "policy-invalid-regex".to_owned(),
            r#"{"family":"string","predicate":"regex","operand":{"kind":"pattern","valueType":"string","value":"["}}"#.to_owned(),
        ),
        (
            "policy-noncanonical-decimal".to_owned(),
            r#"{"family":"ordering","predicate":"gt","operand":{"kind":"literal","valueType":"decimal","value":"1.0"}}"#.to_owned(),
        ),
    ];
    malformed_operators.push((
        "policy-oversized-set".to_owned(),
        serde_json::json!({
            "family": "membership",
            "predicate": "in",
            "operand": {
                "kind": "set",
                "valueType": "integer",
                "values": (0..=identity::ports::POLICY_VALUE_SET_MAX_ITEMS).collect::<Vec<_>>()
            }
        })
        .to_string(),
    ));
    for (id, operator) in malformed_operators {
        let rules = principal_kind_rule_json(&operator);
        let Err(error) = insert_raw_policy_and_load(&store, &repo, &id, &rules).await else {
            panic!("poisoned operator JSON unexpectedly hydrated: {id}");
        };
        assert!(
            policy_rejection(&error),
            "poisoned operator must fail closed as InvalidPolicy: {id}: {error:?}"
        );
    }

    store.shutdown().await?;
    Ok(())
}

/// policy obligations：row scope 与 field mask 必须经 JSONB 原样 round-trip。
#[tokio::test(flavor = "multi_thread")]
async fn policy_repo_obligation_round_trip_conformance() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let repo = PgPolicyRepo::from_unverified_for_test(&store);
    let lifecycle = PgPolicyLifecycle::new(&store, fixed_clock());
    let tenant = role_tenant(ROLE_TENANT_A)?;
    let obligations = PolicyObligations::new(
        Some(rss_request_context::RowScope::Tenant),
        vec![AttributeKey::parse("email").map_err(|_| IdentityError::InvalidPolicy)?],
    );
    let policy = policy_fixture(
        "policy-obligations",
        tenant,
        1,
        10,
        None,
        PolicyEffect::Allow,
        obligations.clone(),
    )?;

    testkit::policy_conformance::assert_policy_obligation_round_trip(
        testkit::policy_conformance::PolicyObligationCase {
            tenant,
            key: "policy-obligations",
            policy,
            expected_obligations: obligations,
            create: |tenant, _key, policy| {
                let lifecycle = &lifecycle;
                async move {
                    policy_create_and_emit(lifecycle, tenant, policy)
                        .await
                        .map(|_| ())
                }
            },
            find: |tenant, key| {
                let repo = &repo;
                async move { repo.find(identity_scope(tenant), policy_id(key)?).await }
            },
            obligations: first_policy_obligations,
        },
    )
    .await?;

    store.shutdown().await?;
    Ok(())
}

/// route gate conformance：durable allow 携带非空 obligations 时，当前 HTTP route gate 必须 deny。
#[tokio::test(flavor = "multi_thread")]
async fn policy_route_gate_conformance_denies_nonempty_obligations() -> TestResult {
    testkit::policy_conformance::assert_route_gate_denies_nonempty_obligations(
        PolicyObligations::empty(),
        PolicyObligations::new(Some(rss_request_context::RowScope::Tenant), Vec::new()),
        |obligations| async move { Ok::<bool, IdentityError>(obligations.is_empty()) },
    )
    .await?;
    Ok(())
}

// 并发：同 (tenant,id) 由 stable identity 行锁串行 append，revision 唯一连续且不覆盖；不同 id 互不干扰。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used, clippy::expect_used)]
// reason: tokio::spawn join 必定成功（task 正常 Ok）；converged role 必定可查到；item-level carve-out（error-handling.md §Carve-out）。
async fn role_definition_concurrent_revisions_are_contiguous() -> TestResult {
    use std::sync::Arc;

    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let repo = Arc::new(PgRoleRepo::from_unverified_for_test(&store));
    let lifecycle = Arc::new(PgRoleDefinitionLifecycle::from_unverified_for_test(&store));
    let tenant = role_tenant(ROLE_TENANT_A)?;

    // 同 id 并发 mutation：8 个 task 竞写同一 (tenant,id)。
    let mut handles = Vec::new();
    for i in 0..8 {
        let lifecycle = Arc::clone(&lifecycle);
        handles.push(tokio::spawn(async move {
            let permission = if i % 2 == 0 {
                "identity:policy:read"
            } else {
                "identity:policy:update"
            };
            let role = Role::hydrate("contended", "C", &[permission.to_string()])?;
            lifecycle
                .create_or_update(identity_scope(tenant), role_mutation_actor(tenant), role)
                .await
                .map(|_| ())
        }));
    }
    for h in handles {
        // 每个 mutation 必 Ok——stable identity 行锁串行 revision 分配，不逃逸 unique violation。
        h.await.expect("join")?;
    }
    // throwaway role 取 contended 的 RoleId（不持久化，仅为 mint id 查终态）。
    let contended_id = Role::hydrate("contended", "x", &[])?.id().clone();
    let got = repo
        .find(identity_scope(tenant), contended_id)
        .await?
        .expect("contended role converged");
    assert_eq!(got.id().as_str(), "contended");
    // name 在所有 writer 间确定（恒 "C"）→ 终态 name 一致；permissions 因 writer 非确定（read/update）不断言具体值。
    assert_eq!(got.name(), "C", "并发收敛终态 name 一致");
    let n: (i64,) =
        sqlx::query_as("SELECT count(*) FROM roles WHERE tenant_id = $1::uuid AND id = $2")
            .bind(ROLE_TENANT_A)
            .bind("contended")
            .fetch_one(&store.pool)
            .await?;
    assert_eq!(n.0, 1, "并发同 id → 终态单行");
    let versions: Vec<i64> = sqlx::query_scalar(
        "SELECT version FROM role_revisions \
         WHERE tenant_id = $1::uuid AND role_id = $2 ORDER BY version",
    )
    .bind(ROLE_TENANT_A)
    .bind("contended")
    .fetch_all(&store.pool)
    .await?;
    assert!(
        (2..=8).contains(&versions.len()),
        "two distinct snapshots must both be retained, while consecutive duplicates may no-op: {versions:?}"
    );
    assert_eq!(
        versions,
        (1..=i64::try_from(versions.len())?).collect::<Vec<_>>(),
        "concurrent revision allocation must have no duplicates or gaps"
    );

    // 不同 id 并发 mutation → 各自追加 revision（无相互干扰）。
    let mut handles2 = Vec::new();
    for i in 0..8 {
        let lifecycle = Arc::clone(&lifecycle);
        handles2.push(tokio::spawn(async move {
            let role = Role::hydrate(&format!("role-{i}"), "N", &[])?;
            lifecycle
                .create_or_update(identity_scope(tenant), role_mutation_actor(tenant), role)
                .await
                .map(|_| ())
        }));
    }
    for h in handles2 {
        h.await.expect("join")?;
    }
    let n2: (i64,) = sqlx::query_as(
        "SELECT count(*) FROM roles WHERE tenant_id = $1::uuid AND id LIKE 'role-%'",
    )
    .bind(ROLE_TENANT_A)
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(n2.0, 8, "8 个不同 id 各落一行");

    store.shutdown().await?;
    Ok(())
}

// list：按 id 升序稳定分页，cursor after 语义，且 tenant scoped。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::expect_used)]
async fn role_repo_list_paginates_and_is_tenant_scoped() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let repo = PgRoleRepo::from_unverified_for_test(&store);
    let lifecycle = PgRoleDefinitionLifecycle::from_unverified_for_test(&store);
    let tenant_a = role_tenant(ROLE_TENANT_A)?;
    let tenant_b = role_tenant(ROLE_TENANT_B)?;

    for (id, name) in [("role-a", "A"), ("role-b", "B"), ("role-c", "C")] {
        lifecycle
            .create_or_update(
                identity_scope(tenant_a),
                role_mutation_actor(tenant_a),
                Role::hydrate(id, name, &["identity:policy:read".to_string()])?,
            )
            .await?;
    }
    lifecycle
        .create_or_update(
            identity_scope(tenant_b),
            role_mutation_actor(tenant_b),
            Role::hydrate("role-aa", "TenantB", &["identity:policy:read".to_string()])?,
        )
        .await?;

    let page1 = repo
        .list(
            identity_scope(tenant_a),
            RolePage {
                limit: vocab::Limit::new(2)?,
                after: None,
            },
        )
        .await?;
    assert!(page1.has_more);
    assert_eq!(
        page1
            .roles
            .iter()
            .map(|role| role.id().as_str())
            .collect::<Vec<_>>(),
        vec!["role-a", "role-b"]
    );

    let after = page1.roles[1].id().clone();
    let page2 = repo
        .list(
            identity_scope(tenant_a),
            RolePage {
                limit: vocab::Limit::new(2)?,
                after: Some(after),
            },
        )
        .await?;
    assert!(!page2.has_more);
    assert_eq!(
        page2
            .roles
            .iter()
            .map(|role| role.id().as_str())
            .collect::<Vec<_>>(),
        vec!["role-c"]
    );

    let tenant_b_page = repo
        .list(
            identity_scope(tenant_b),
            RolePage {
                limit: vocab::Limit::new(10)?,
                after: None,
            },
        )
        .await?;
    assert_eq!(
        tenant_b_page
            .roles
            .iter()
            .map(|role| role.id().as_str())
            .collect::<Vec<_>>(),
        vec!["role-aa"],
        "tenant B 只看到自己的角色"
    );

    store.shutdown().await?;
    Ok(())
}

// RoleBindingLifecycle：经 RbacAdminService 驱动生产 Pg impl，验证 binding + outbox both-or-neither 正向路径与
// revoke 未命中不发事件。
#[tokio::test(flavor = "multi_thread")]
async fn role_binding_lifecycle_assign_revoke_writes_binding_and_outbox() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let tenant = role_tenant(ROLE_TENANT_A)?;
    let tenant_b = role_tenant(ROLE_TENANT_B)?;
    let role = Role::hydrate("role-admin", "Admin", &["identity:role:assign".to_string()])?;
    let role_id = role.id().clone();
    let lifecycle = PgRoleDefinitionLifecycle::from_unverified_for_test(&store);
    lifecycle
        .create_or_update(
            identity_scope(tenant),
            role_mutation_actor(tenant),
            role.clone(),
        )
        .await?;
    lifecycle
        .create_or_update(
            identity_scope(tenant_b),
            role_mutation_actor(tenant_b),
            role,
        )
        .await?;

    let svc = identity::RbacAdminService::new(
        Arc::from(DynRoleReadRepo::new_box(
            PgRoleRepo::from_unverified_for_test(&store),
        )),
        Arc::from(DynRoleBindingLifecycle::new_box(
            PgRoleBindingLifecycle::new(&store, fixed_clock()),
        )),
        fixed_clock(),
    );
    let actor = ids::UserId::parse("11111111-2222-4333-8444-555555555555")?;

    svc.assign_role(
        roles_assign_producer_receipt(),
        tenant,
        actor,
        rss_request_context::PrincipalKind::Admin,
        "target-user".to_string(),
        role_id.clone(),
    )
    .await?;
    let binding_count: (i64,) = sqlx::query_as(
        "SELECT count(*) FROM role_bindings WHERE tenant_id = $1::uuid AND role_id = $2 AND subject = $3",
    )
    .bind(ROLE_TENANT_A)
    .bind("role-admin")
    .bind("target-user")
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(binding_count.0, 1, "assign 写入 binding");
    let binding_reads = PgRoleBindingReadRepo::from_unverified_for_test(&store);
    let subject_bindings = binding_reads
        .list_for_subject(identity_scope(tenant), "target-user".to_string())
        .await?;
    assert_eq!(
        subject_bindings.len(),
        1,
        "窄 read repo 可读取已提交 binding"
    );
    assert_eq!(subject_bindings[0].role_id().as_str(), "role-admin");
    assert!(
        binding_reads
            .list_for_subject(identity_scope(tenant_b), "target-user".to_string())
            .await?
            .is_empty(),
        "窄 read repo 保持 tenant isolation"
    );
    let assigned_events: (i64,) =
        sqlx::query_as("SELECT count(*) FROM outbox WHERE contract_id = $1")
            .bind("identity.role-assigned")
            .fetch_one(&store.pool)
            .await?;
    assert_eq!(assigned_events.0, 1, "assign 写入 role-assigned outbox");

    let cross_tenant_revoked = svc
        .revoke_role(
            roles_revoke_producer_receipt(),
            tenant_b,
            actor,
            rss_request_context::PrincipalKind::Admin,
            role_id.clone(),
            "target-user".to_string(),
        )
        .await?;
    assert!(
        !cross_tenant_revoked,
        "tenant B revoke 隐藏 tenant A binding"
    );
    let binding_after_cross_tenant_revoke: (i64,) = sqlx::query_as(
        "SELECT count(*) FROM role_bindings WHERE tenant_id = $1::uuid AND role_id = $2 AND subject = $3",
    )
    .bind(ROLE_TENANT_A)
    .bind("role-admin")
    .bind("target-user")
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(
        binding_after_cross_tenant_revoke.0, 1,
        "tenant B revoke 不应删除 tenant A binding"
    );
    let revoked_events_before_hit: (i64,) =
        sqlx::query_as("SELECT count(*) FROM outbox WHERE contract_id = $1")
            .bind("identity.role-revoked")
            .fetch_one(&store.pool)
            .await?;
    assert_eq!(
        revoked_events_before_hit.0, 0,
        "tenant B revoke 未命中不写 role-revoked outbox"
    );

    let revoked = svc
        .revoke_role(
            roles_revoke_producer_receipt(),
            tenant,
            actor,
            rss_request_context::PrincipalKind::Admin,
            role_id.clone(),
            "target-user".to_string(),
        )
        .await?;
    assert!(revoked);
    let binding_after_revoke: (i64,) = sqlx::query_as(
        "SELECT count(*) FROM role_bindings WHERE tenant_id = $1::uuid AND role_id = $2 AND subject = $3",
    )
    .bind(ROLE_TENANT_A)
    .bind("role-admin")
    .bind("target-user")
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(binding_after_revoke.0, 0, "revoke 删除 binding");

    let revoked_again = svc
        .revoke_role(
            roles_revoke_producer_receipt(),
            tenant,
            actor,
            rss_request_context::PrincipalKind::Admin,
            role_id,
            "target-user".to_string(),
        )
        .await?;
    assert!(!revoked_again, "重复 revoke 幂等 false");
    let revoked_events: (i64,) =
        sqlx::query_as("SELECT count(*) FROM outbox WHERE contract_id = $1")
            .bind("identity.role-revoked")
            .fetch_one(&store.pool)
            .await?;
    assert_eq!(revoked_events.0, 1, "未命中 revoke 不追加 outbox");

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn role_binding_fact_conflict_rolls_back_assignment() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let tenant = role_tenant(ROLE_TENANT_A)?;
    let role_name = format!("role-fact-conflict-{}", uuid_like());
    let subject = format!("subject-fact-conflict-{}", uuid_like());
    PgRoleDefinitionLifecycle::from_unverified_for_test(&store)
        .create_or_update(
            identity_scope(tenant),
            role_mutation_actor(tenant),
            Role::hydrate(
                &role_name,
                "Fact conflict",
                &["identity:role:assign".to_string()],
            )?,
        )
        .await?;
    let event_id = unique_event_id("role-binding-fact-conflict");
    let seed = seed_conflicting_outbox_fact(&store, tenant, &event_id).await?;
    let entry = generated_entry(
        generated::event::identity_v1::role_assigned::FACT,
        &generated::event::identity_v1::role_assigned::IdentityRoleAssignedPayload {
            actor_kind: generated::event::identity_v1::role_assigned::IdentityRoleAssignedPayloadActorKind::Admin,
            assigned_by: uuid::Uuid::from_u128(0xA11CE),
            occurred_at: expected_occurred_at(),
            role_id: role_name.clone(),
            subject: subject.clone(),
            tenant_id: tenant.to_string(),
        },
        IdemKey::parse(&event_id)?,
    )?;
    let envelope = OutboxEnvelopeParts::new(
        generated::event::identity_v1::role_assigned::CONTRACT,
        tenant,
        subject_id(&subject),
        actor_for(tenant),
    );
    let binding = RoleBinding::hydrate(&subject, &role_name, tenant)?;

    let conflict = PgRoleBindingLifecycle::new(&store, fixed_clock())
        .assign_and_emit(
            roles_assign_producer_receipt(),
            identity_scope(tenant),
            binding,
            reviewed_generated_event::<generated::event::identity_v1::role_assigned::Contract>(
                entry, envelope,
            )
            .await?,
        )
        .await;
    let Err(conflict) = conflict else {
        return Err("role binding write must fail on a conflicting outbox fact".into());
    };
    assert_eq!(conflict.kind(), OutboxEmitErrorKind::FactConflict);
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM role_bindings \
             WHERE tenant_id = $1::uuid AND role_id = $2 AND subject = $3",
        )
        .bind(tenant.to_string())
        .bind(&role_name)
        .bind(&subject)
        .fetch_one(&store.pool)
        .await?,
        0,
        "outbox conflict must roll back role assignment"
    );
    assert_seed_fact_unchanged(&store, &event_id, &seed).await?;

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn credential_authentication_missing_security_state_is_storage_error() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let credentials = PgCredentialRepo::from_unverified_for_test(&store);
    let tenant = cred_tenant(CRED_TENANT_A)?;
    credentials
        .insert(
            identity_scope(tenant),
            make_cred("alice", CRED_USER_ALICE, "correct", 1, tenant)?,
        )
        .await?;

    // Fixture-only corruption: disable FK triggers only for this owner transaction, commit the
    // invalid row pair, then drive the real serving-write repository path below.
    store
        .raw_fixture_transaction::<_, _, sqlx::Error>(|connection| {
            Box::pin(async move {
                sqlx::query("SET LOCAL session_replication_role = 'replica'")
                    .execute(&mut *connection)
                    .await?;
                sqlx::query(
                    "DELETE FROM account_security_states \
                     WHERE tenant_id = $1::uuid AND user_id = $2::uuid",
                )
                .bind(CRED_TENANT_A)
                .bind(CRED_USER_ALICE)
                .execute(&mut *connection)
                .await?;
                Ok(())
            })
        })
        .await?;

    let result = credentials
        .authenticate(
            identity_scope(tenant),
            login_id("alice"),
            raw_password("correct"),
            cred_epoch(1_700_000_002),
        )
        .await;

    store
        .raw_fixture_transaction::<_, _, sqlx::Error>(|connection| {
            Box::pin(async move {
                sqlx::query(
                    "DELETE FROM credentials \
                     WHERE tenant_id = $1::uuid AND user_id = $2::uuid",
                )
                .bind(CRED_TENANT_A)
                .bind(CRED_USER_ALICE)
                .execute(&mut *connection)
                .await?;
                Ok(())
            })
        })
        .await?;
    assert!(matches!(
        result,
        Err(identity::ports::IdentityError::Storage(_))
    ));
    store.shutdown().await?;
    Ok(())
}

// CRUD：未存 → None；insert → find_by_user_id 往返一致；重复键拒绝且不覆盖 hash/version。
#[tokio::test(flavor = "multi_thread")]
async fn credential_repo_insert_find_roundtrip_and_duplicate_conflict() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let repo = PgCredentialRepo::from_unverified_for_test(&store);
    let tenant = cred_tenant(CRED_TENANT_A)?;

    // 未保存 → None（fail-closed 基线，anti-vacuity 负例）。
    assert!(
        repo.find_by_user_id(identity_scope(tenant), cred_uid(CRED_USER_ALICE)?)
            .await?
            .is_none(),
        "未保存 → None"
    );

    // insert → find_by_user_id 往返一致。
    repo.insert(
        identity_scope(tenant),
        make_cred("alice", CRED_USER_ALICE, "pw1", 1, tenant)?,
    )
    .await?;
    let Some(got) = repo
        .find_by_user_id(identity_scope(tenant), cred_uid(CRED_USER_ALICE)?)
        .await?
    else {
        return Err("saved credential visible".into());
    };
    assert_eq!(
        got.user_id(),
        cred_uid(CRED_USER_ALICE)?,
        "canonical subject 保真"
    );
    assert_eq!(got.login().as_str(), "alice", "login 查找键保真");
    assert_eq!(got.version(), 1, "version 保真");
    assert!(
        got.password_hash().as_str().starts_with("$argon2"),
        "回读 PHC 为 argon2 格式（明文永不落库）"
    );

    // 同 login 二次 insert 必须 conflict，不能覆盖现有 hash/version。
    assert!(
        repo.insert(
            identity_scope(tenant),
            make_cred("alice", CRED_USER_ALICE, "pw2", 2, tenant)?,
        )
        .await
        .is_err()
    );
    let Some(got2) = repo
        .find_by_user_id(identity_scope(tenant), cred_uid(CRED_USER_ALICE)?)
        .await?
    else {
        return Err("original credential remains visible".into());
    };
    assert_eq!(got2.version(), 1, "duplicate insert preserves version");
    assert!(password_matches("pw1", got2.password_hash())?);
    let n: (i64,) = sqlx::query_as(
        "SELECT count(*) FROM credentials WHERE tenant_id = $1::uuid AND login = $2",
    )
    .bind(CRED_TENANT_A)
    .bind("alice")
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(n.0, 1, "duplicate insert does not add a row");

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn credential_repo_insert_rebind_rolls_back_credential_and_security_together() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let credentials = PgCredentialRepo::from_unverified_for_test(&store);
    let security = PgAccountSecurityRepo::from_unverified_for_test(&store);
    let tenant = cred_tenant(CRED_TENANT_A)?;
    let scope = identity_scope(tenant);
    let user_a = cred_uid(CRED_USER_ALICE)?;
    let user_b = cred_uid(CRED_USER_BOB)?;
    credentials
        .insert(
            scope,
            make_cred("alice", CRED_USER_ALICE, "original", 7, tenant)?,
        )
        .await?;
    let initial_security = security
        .find(scope, user_a)
        .await?
        .ok_or("initial security missing")?;
    let credential_before = owner_credential_snapshot(&store, tenant, "alice")
        .await?
        .ok_or("initial credential missing")?;

    assert!(matches!(
        credentials
            .insert(
                scope,
                make_cred("alice", CRED_USER_BOB, "replacement", 99, tenant)?,
            )
            .await,
        Err(IdentityError::Storage(_))
    ));
    assert_eq!(
        owner_credential_snapshot(&store, tenant, "alice")
            .await?
            .ok_or("credential disappeared")?,
        credential_before,
        "failed user rebind must preserve the original hash and version"
    );
    assert_eq!(
        security
            .find(scope, user_a)
            .await?
            .ok_or("security disappeared")?,
        initial_security,
        "failed user rebind must preserve the original lifecycle row"
    );
    assert!(
        security.find(scope, user_b).await?.is_none(),
        "failed user rebind must not leave a security row for the rejected subject"
    );

    store.shutdown().await?;
    Ok(())
}

// authenticate 三态：已知+正确 → Authenticated(canonical user_id)；已知+错 → RejectedKnown；
// 查无凭据 → RejectedUnknown（当前档 KDF 仍跑，不 panic）。
#[tokio::test(flavor = "multi_thread")]
async fn credential_repo_authenticate_known_wrong_and_unknown() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let repo = PgCredentialRepo::from_unverified_for_test(&store);
    let tenant = cred_tenant(CRED_TENANT_A)?;
    repo.insert(
        identity_scope(tenant),
        make_cred("alice", CRED_USER_ALICE, "correct", 1, tenant)?,
    )
    .await?;
    let now = cred_epoch(CRED_BASE_SECS);

    assert_eq!(
        authenticated_user(
            repo.authenticate(
                identity_scope(tenant),
                login_id("alice"),
                raw_password("correct"),
                now
            )
            .await?
        )?,
        cred_uid(CRED_USER_ALICE)?,
        "已知+正确 → Authenticated(canonical user_id)"
    );
    assert_eq!(
        repo.authenticate(
            identity_scope(tenant),
            login_id("alice"),
            raw_password("wrong"),
            now
        )
        .await?,
        AuthOutcome::RejectedKnown,
        "已知+错 → RejectedKnown"
    );
    assert_eq!(
        repo.authenticate(
            identity_scope(tenant),
            login_id("ghost"),
            raw_password("correct"),
            now
        )
        .await?,
        AuthOutcome::RejectedUnknown,
        "查无凭据 → RejectedUnknown"
    );

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn credential_authenticate_post_write_fault_rolls_back_lockout_and_security() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let seed = PgCredentialRepo::from_unverified_for_test(&store);
    let security = PgAccountSecurityRepo::from_unverified_for_test(&store);
    let tenant = cred_tenant(CRED_TENANT_A)?;
    let scope = identity_scope(tenant);
    let user = cred_uid(CRED_USER_ALICE)?;
    seed.insert(
        scope,
        make_cred("alice", CRED_USER_ALICE, "correct", 11, tenant)?,
    )
    .await?;
    let credential_before = owner_credential_auth_state(&store, tenant, "alice")
        .await?
        .ok_or("credential missing")?;
    let security_before = security
        .find(scope, user)
        .await?
        .ok_or("security missing")?;
    let repo = PgCredentialRepo::from_unverified_for_test(&store)
        .with_authenticate_post_write_fault("alice");

    assert!(matches!(
        repo.authenticate(
            scope,
            login_id("alice"),
            raw_password("wrong"),
            cred_epoch(CRED_BASE_SECS),
        )
        .await,
        Err(IdentityError::Storage(_))
    ));
    assert_eq!(
        owner_credential_auth_state(&store, tenant, "alice")
            .await?
            .ok_or("credential missing after rollback")?,
        credential_before,
        "failure after lockout write must roll the complete credential row back"
    );
    assert_eq!(
        security
            .find(scope, user)
            .await?
            .ok_or("security missing after rollback")?,
        security_before,
        "authenticate rollback must not mutate durable lifecycle state"
    );

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn credential_authenticate_holds_credential_while_waiting_for_security_lock() -> TestResult {
    use std::sync::Arc;

    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let repo = Arc::new(PgCredentialRepo::from_unverified_for_test(&store));
    let tenant = cred_tenant(CRED_TENANT_A)?;
    let scope = identity_scope(tenant);
    repo.insert(
        scope,
        make_cred("alice", CRED_USER_ALICE, "correct", 1, tenant)?,
    )
    .await?;

    let mut security_blocker = store.pool.begin().await?;
    let _: String = sqlx::query_scalar(
        "SELECT user_id::text FROM account_security_states \
         WHERE tenant_id = $1::uuid AND user_id = $2::uuid FOR UPDATE",
    )
    .bind(CRED_TENANT_A)
    .bind(CRED_USER_ALICE)
    .fetch_one(&mut *security_blocker)
    .await?;

    let auth_repo = Arc::clone(&repo);
    let auth_task = tokio::spawn(async move {
        auth_repo
            .authenticate(
                scope,
                login_id("alice"),
                raw_password("correct"),
                cred_epoch(CRED_BASE_SECS),
            )
            .await
    });

    let mut credential_lock_observed = false;
    let mut unexpected_probe_error = None;
    for _ in 0..80 {
        let mut probe = store.pool.begin().await?;
        let result = sqlx::query(
            "SELECT user_id FROM credentials \
             WHERE tenant_id = $1::uuid AND login = $2 FOR UPDATE NOWAIT",
        )
        .bind(CRED_TENANT_A)
        .bind("alice")
        .execute(&mut *probe)
        .await;
        match result {
            Ok(_) => {
                probe.rollback().await?;
                await_delay(std::time::Duration::from_millis(25)).await;
            }
            Err(error)
                if error
                    .as_database_error()
                    .and_then(|database| database.code())
                    .is_some_and(|code| code.as_ref() == "55P03") =>
            {
                probe.rollback().await?;
                credential_lock_observed = true;
                break;
            }
            Err(error) => {
                probe.rollback().await?;
                unexpected_probe_error = Some(error);
                break;
            }
        }
    }
    security_blocker.rollback().await?;
    if let Some(error) = unexpected_probe_error {
        auth_task.abort();
        return Err(error.into());
    }
    let outcome = tokio::time::timeout(std::time::Duration::from_secs(10), auth_task).await??;
    assert!(
        credential_lock_observed,
        "authenticate must hold credentials FOR UPDATE while blocked on account security"
    );
    assert_eq!(
        authenticated_user(outcome?)?,
        cred_uid(CRED_USER_ALICE)?,
        "authentication must complete after the security lock is released"
    );

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn credential_repo_rehash_upgrades_weak_phc_without_bumping_version() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let repo = PgCredentialRepo::from_unverified_for_test(&store);
    let tenant = cred_tenant(CRED_TENANT_A)?;
    let weak =
        secure::PasswordHash::for_test_with_params(raw_password("legacy-short"), 8 * 1024, 1, 1)?;
    let weak_phc = weak.as_str().to_owned();
    repo.insert(
        identity_scope(tenant),
        make_cred_with_hash("alice", CRED_USER_ALICE, weak, 7, tenant)?,
    )
    .await?;

    assert_eq!(
        repo.authenticate(
            identity_scope(tenant),
            login_id("alice"),
            raw_password("wrong"),
            cred_epoch(CRED_BASE_SECS),
        )
        .await?,
        AuthOutcome::RejectedKnown
    );
    assert_eq!(
        owner_credential_snapshot(&store, tenant, "alice")
            .await?
            .ok_or("credential snapshot missing")?,
        (7, weak_phc.clone()),
        "failed verification must not replace PHC"
    );
    assert_eq!(
        authenticated_user(
            repo.authenticate(
                identity_scope(tenant),
                login_id("alice"),
                raw_password("legacy-short"),
                cred_epoch(CRED_BASE_SECS),
            )
            .await?
        )?,
        cred_uid(CRED_USER_ALICE)?
    );

    let (version, upgraded_phc) = owner_credential_snapshot(&store, tenant, "alice")
        .await?
        .ok_or("upgraded credential snapshot missing")?;
    let upgraded = secure::PasswordHash::parse(&upgraded_phc)?;
    assert_eq!(
        version, 7,
        "transparent rehash must preserve business version"
    );
    assert_ne!(upgraded_phc, weak_phc, "weak PHC must be replaced");
    assert!(
        !upgraded.needs_rehash()?,
        "replacement must use current profile"
    );
    assert!(password_matches("legacy-short", &upgraded)?);

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn credential_repo_rehash_preserves_current_and_stronger_phc() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let repo = PgCredentialRepo::from_unverified_for_test(&store);
    let tenant = cred_tenant(CRED_TENANT_A)?;
    let current = test_password_hash("current-password")?;
    let stronger = secure::PasswordHash::for_test_with_params(
        raw_password("stronger-password"),
        20 * 1024,
        3,
        2,
    )?;

    for (login, user, password, hash) in [
        ("current", CRED_USER_ALICE, "current-password", current),
        ("stronger", CRED_USER_BOB, "stronger-password", stronger),
    ] {
        let original_phc = hash.as_str().to_owned();
        repo.insert(
            identity_scope(tenant),
            make_cred_with_hash(login, user, hash, 11, tenant)?,
        )
        .await?;
        assert_eq!(
            authenticated_user(
                repo.authenticate(
                    identity_scope(tenant),
                    login_id(login),
                    raw_password(password),
                    cred_epoch(CRED_BASE_SECS),
                )
                .await?
            )?,
            cred_uid(user)?
        );
        let (version, stored_phc) = owner_credential_snapshot(&store, tenant, login)
            .await?
            .ok_or("credential snapshot missing")?;
        assert_eq!(version, 11, "login must preserve business version");
        assert_eq!(
            stored_phc, original_phc,
            "current/stronger PHC must not be replaced"
        );
    }

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn credential_repo_rehash_update_failure_rolls_back() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let repo = PgCredentialRepo::from_unverified_for_test(&store);
    let tenant = cred_tenant(CRED_TENANT_A)?;
    let weak =
        secure::PasswordHash::for_test_with_params(raw_password("legacy-short"), 8 * 1024, 1, 1)?;
    let weak_phc = weak.as_str().to_owned();
    repo.insert(
        identity_scope(tenant),
        make_cred_with_hash("alice", CRED_USER_ALICE, weak, 19, tenant)?,
    )
    .await?;
    sqlx::raw_sql(
        "CREATE FUNCTION reject_credential_rehash() RETURNS trigger LANGUAGE plpgsql AS $$ \
         BEGIN RAISE EXCEPTION 'injected rehash update failure'; END $$; \
         CREATE TRIGGER reject_credential_rehash BEFORE UPDATE OF password_hash ON credentials \
         FOR EACH ROW EXECUTE FUNCTION reject_credential_rehash();",
    )
    .execute(&store.pool)
    .await?;

    assert!(
        repo.authenticate(
            identity_scope(tenant),
            login_id("alice"),
            raw_password("legacy-short"),
            cred_epoch(CRED_BASE_SECS),
        )
        .await
        .is_err(),
        "rehash UPDATE failure must fail authentication closed"
    );
    let (version, stored_phc) = owner_credential_snapshot(&store, tenant, "alice")
        .await?
        .ok_or("credential snapshot missing")?;
    assert_eq!(version, 19);
    assert_eq!(
        stored_phc, weak_phc,
        "failed transaction must roll back PHC"
    );

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn credential_repo_rehash_commit_failure_rolls_back_hash_and_lockout_clear() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let repo = PgCredentialRepo::from_unverified_for_test(&store);
    let tenant = cred_tenant(CRED_TENANT_A)?;
    let weak =
        secure::PasswordHash::for_test_with_params(raw_password("legacy-short"), 8 * 1024, 1, 1)?;
    repo.insert(
        identity_scope(tenant),
        make_cred_with_hash("alice", CRED_USER_ALICE, weak, 23, tenant)?,
    )
    .await?;
    sqlx::query(
        "UPDATE credentials SET failure_count = 4, \
         lockout_window_start = to_timestamp($3), locked_until = NULL \
         WHERE tenant_id = $1::uuid AND login = $2",
    )
    .bind(tenant.to_string())
    .bind("alice")
    .bind(i64::try_from(CRED_BASE_SECS - 60)?)
    .execute(&store.pool)
    .await?;
    let before = owner_credential_auth_state(&store, tenant, "alice")
        .await?
        .ok_or("credential state missing")?;
    sqlx::raw_sql(
        "CREATE SEQUENCE credential_rehash_commit_probe; \
         CREATE FUNCTION reject_credential_rehash_on_commit() RETURNS trigger LANGUAGE plpgsql AS $$ \
         BEGIN \
           IF OLD.password_hash IS DISTINCT FROM NEW.password_hash THEN \
             IF NOT EXISTS (SELECT 1 FROM credentials WHERE tenant_id = NEW.tenant_id \
             AND login = NEW.login AND failure_count = 0 \
               AND lockout_window_start IS NULL AND locked_until IS NULL) THEN \
               RAISE EXCEPTION 'rehash lockout clear missing'; \
             END IF; \
             PERFORM nextval('credential_rehash_commit_probe'); \
             RAISE EXCEPTION 'injected rehash commit failure'; \
           END IF; \
           RETURN NEW; \
         END $$; \
         CREATE CONSTRAINT TRIGGER reject_credential_rehash_on_commit AFTER UPDATE ON credentials \
         DEFERRABLE INITIALLY DEFERRED FOR EACH ROW \
         EXECUTE FUNCTION reject_credential_rehash_on_commit();",
    )
    .execute(&store.pool)
    .await?;

    let error = match repo
        .authenticate(
            identity_scope(tenant),
            login_id("alice"),
            raw_password("legacy-short"),
            cred_epoch(CRED_BASE_SECS),
        )
        .await
    {
        Err(error) => error,
        Ok(outcome) => return Err(format!("deferred trigger allowed commit: {outcome:?}").into()),
    };
    assert!(matches!(error, IdentityError::Storage(_)));
    let probe: (i64, bool) =
        sqlx::query_as("SELECT last_value, is_called FROM credential_rehash_commit_probe")
            .fetch_one(&store.pool)
            .await?;
    assert_eq!(
        probe,
        (1, true),
        "deferred trigger must observe the lockout clear before rejecting commit"
    );
    assert_eq!(
        owner_credential_auth_state(&store, tenant, "alice")
            .await?
            .ok_or("credential state missing after rollback")?,
        before,
        "commit failure must roll back PHC, version, and pre-existing lockout"
    );

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn credential_repo_rehash_concurrent_logins_upgrade_weak_phc_once() -> TestResult {
    use std::sync::Arc;

    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let repo = Arc::new(PgCredentialRepo::from_unverified_for_test(&store));
    let tenant = cred_tenant(CRED_TENANT_A)?;
    let weak =
        secure::PasswordHash::for_test_with_params(raw_password("legacy-short"), 8 * 1024, 1, 1)?;
    repo.insert(
        identity_scope(tenant),
        make_cred_with_hash("alice", CRED_USER_ALICE, weak, 17, tenant)?,
    )
    .await?;

    sqlx::query(
        "CREATE TABLE credential_rehash_updates (login text PRIMARY KEY, updates integer NOT NULL DEFAULT 0)",
    )
    .execute(&store.pool)
    .await?;
    sqlx::query("INSERT INTO credential_rehash_updates (login) VALUES ('alice')")
        .execute(&store.pool)
        .await?;
    sqlx::query(
        "CREATE FUNCTION count_credential_rehash_update() RETURNS trigger LANGUAGE plpgsql AS $$ \
         BEGIN IF OLD.password_hash IS DISTINCT FROM NEW.password_hash THEN \
         UPDATE credential_rehash_updates SET updates = updates + 1 WHERE login = NEW.login; \
         END IF; RETURN NEW; END $$",
    )
    .execute(&store.pool)
    .await?;
    sqlx::query(
        "CREATE TRIGGER count_credential_rehash_update AFTER UPDATE OF password_hash ON credentials \
         FOR EACH ROW EXECUTE FUNCTION count_credential_rehash_update()",
    )
    .execute(&store.pool)
    .await?;

    let mut handles = Vec::new();
    for _ in 0..2 {
        let repo = Arc::clone(&repo);
        handles.push(tokio::spawn(async move {
            repo.authenticate(
                identity_scope(tenant),
                login_id("alice"),
                raw_password("legacy-short"),
                cred_epoch(CRED_BASE_SECS),
            )
            .await
        }));
    }
    for handle in handles {
        assert_eq!(
            authenticated_user(
                handle
                    .await
                    .map_err(|error| format!("join failed: {error}"))??
            )?,
            cred_uid(CRED_USER_ALICE)?
        );
    }

    let (rehash_updates,): (i32,) =
        sqlx::query_as("SELECT updates FROM credential_rehash_updates WHERE login = 'alice'")
            .fetch_one(&store.pool)
            .await?;
    assert_eq!(
        rehash_updates, 1,
        "row lock must serialize rehash to one PHC replacement"
    );
    let (version, upgraded_phc) = owner_credential_snapshot(&store, tenant, "alice")
        .await?
        .ok_or("credential snapshot missing")?;
    assert_eq!(
        version, 17,
        "transparent rehash must preserve business version"
    );
    assert!(!secure::PasswordHash::parse(&upgraded_phc)?.needs_rehash()?);

    store.shutdown().await?;
    Ok(())
}

// F2：未知主体登录失败**不建行 / 不建锁**——不可经枚举撑大 credentials 表（折叠列 ⇒ 无行即无锁，结构层成立）。
#[tokio::test(flavor = "multi_thread")]
async fn credential_repo_unknown_subject_creates_no_row() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let repo = PgCredentialRepo::from_unverified_for_test(&store);
    let tenant = cred_tenant(CRED_TENANT_A)?;
    repo.insert(
        identity_scope(tenant),
        make_cred("alice", CRED_USER_ALICE, "correct", 1, tenant)?,
    )
    .await?;
    let now = cred_epoch(CRED_BASE_SECS);

    for i in 0..20 {
        assert_eq!(
            repo.authenticate(
                identity_scope(tenant),
                login_id(&format!("ghost-{i}")),
                raw_password("x"),
                now
            )
            .await?,
            AuthOutcome::RejectedUnknown
        );
    }
    // 仅 alice 一行（未知主体未建任何行 ⇒ lockout 表不随枚举增长，F2）。
    let n: (i64,) = sqlx::query_as("SELECT count(*) FROM credentials WHERE tenant_id = $1::uuid")
        .bind(CRED_TENANT_A)
        .fetch_one(&store.pool)
        .await?;
    assert_eq!(n.0, 1, "未知主体不建行（F2：lockout 表不随枚举增长）");

    store.shutdown().await?;
    Ok(())
}

// 跨租 fail-closed：A 种入并临时锁定 alice，B 仍只观察到 unknown。
#[tokio::test(flavor = "multi_thread")]
async fn credential_repo_cross_tenant_fail_closed() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let repo = PgCredentialRepo::from_unverified_for_test(&store);
    let a = cred_tenant(CRED_TENANT_A)?;
    let b = cred_tenant(CRED_TENANT_B)?;
    repo.insert(
        identity_scope(a),
        make_cred("alice", CRED_USER_ALICE, "correct", 1, a)?,
    )
    .await?;
    let now = cred_epoch(CRED_BASE_SECS);

    // 跨租 find → None（不泄露存在性）。
    assert!(
        repo.find_by_user_id(identity_scope(b), cred_uid(CRED_USER_ALICE)?)
            .await?
            .is_none(),
        "跨租 find → None"
    );
    // 跨租 authenticate → RejectedUnknown（跨租即未知）。
    assert_eq!(
        repo.authenticate(
            identity_scope(b),
            login_id("alice"),
            raw_password("correct"),
            now
        )
        .await?,
        AuthOutcome::RejectedUnknown,
        "跨租 authenticate → RejectedUnknown"
    );
    // 在 A 锁定 alice（5 次错）；A/B 经统一 authenticate 各自 fail-closed。
    for i in 1..=5 {
        repo.authenticate(
            identity_scope(a),
            login_id("alice"),
            raw_password("wrong"),
            cred_epoch(CRED_BASE_SECS + i),
        )
        .await?;
    }
    assert_eq!(
        repo.authenticate(
            identity_scope(a),
            login_id("alice"),
            raw_password("correct"),
            cred_epoch(CRED_BASE_SECS + 5)
        )
        .await?,
        AuthOutcome::RejectedKnown
    );
    assert_eq!(
        repo.authenticate(
            identity_scope(b),
            login_id("alice"),
            raw_password("correct"),
            cred_epoch(CRED_BASE_SECS + 5)
        )
        .await?,
        AuthOutcome::RejectedUnknown
    );

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn credential_repo_tenant_noop_conformance() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let repo = PgCredentialRepo::from_unverified_for_test(&store);
    let a = cred_tenant(CRED_TENANT_A)?;
    let b = cred_tenant(CRED_TENANT_B)?;
    let alice_uid = cred_uid(CRED_USER_ALICE)?;
    let now = cred_epoch(CRED_BASE_SECS);
    let credential = make_cred("alice", CRED_USER_ALICE, "correct", 1, a)?;

    testkit::repo_conformance::assert_cross_tenant_noop(
        || async {
            repo.insert(identity_scope(a), credential).await?;
            Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
        },
        || async {
            Ok::<bool, Box<dyn std::error::Error + Send + Sync>>(
                repo.find_by_user_id(identity_scope(a), alice_uid)
                    .await?
                    .is_some(),
            )
        },
        || async {
            Ok::<bool, Box<dyn std::error::Error + Send + Sync>>(
                repo.find_by_user_id(identity_scope(b), alice_uid)
                    .await?
                    .is_some(),
            )
        },
        || async {
            let outcome = repo
                .authenticate(
                    identity_scope(b),
                    login_id("alice"),
                    raw_password("correct"),
                    now,
                )
                .await?;
            if outcome == AuthOutcome::RejectedUnknown {
                Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
            } else {
                Err(format!("cross-tenant authenticate returned {outcome:?}").into())
            }
        },
        || async {
            Ok::<bool, Box<dyn std::error::Error + Send + Sync>>(
                repo.find_by_user_id(identity_scope(a), alice_uid)
                    .await?
                    .is_some(),
            )
        },
    )
    .await?;

    store.shutdown().await?;
    Ok(())
}

// 原子推进：连续 authenticate(错) 经仓储持久化累计——未达阈值未锁，第 5 次（窗口内）达阈值锁定。
#[tokio::test(flavor = "multi_thread")]
async fn credential_repo_accumulate_failures_then_locks() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let repo = PgCredentialRepo::from_unverified_for_test(&store);
    let a = cred_tenant(CRED_TENANT_A)?;
    repo.insert(
        identity_scope(a),
        make_cred("alice", CRED_USER_ALICE, "correct", 1, a)?,
    )
    .await?;

    for i in 1..5 {
        assert_eq!(
            repo.authenticate(
                identity_scope(a),
                login_id("alice"),
                raw_password("wrong"),
                cred_epoch(CRED_BASE_SECS + i)
            )
            .await?,
            AuthOutcome::RejectedKnown,
            "第 {i} 次失败"
        );
        assert!(
            db_locked_until(&store, CRED_TENANT_A, "alice")
                .await?
                .is_none()
        );
    }
    // 第 5 次（窗口内）→ 达阈值锁定（DB 持久化失败计数 = 5）。
    repo.authenticate(
        identity_scope(a),
        login_id("alice"),
        raw_password("wrong"),
        cred_epoch(CRED_BASE_SECS + 5),
    )
    .await?;
    assert!(
        db_locked_until(&store, CRED_TENANT_A, "alice")
            .await?
            .is_some()
    );
    assert_eq!(
        db_failure_count(&store, CRED_TENANT_A, "alice").await?,
        5,
        "失败计数持久化推进至阈值"
    );

    store.shutdown().await?;
    Ok(())
}

// lazy-unlock：TTL 内统一认证拒绝；TTL 后 authenticate 原子解锁。
#[tokio::test(flavor = "multi_thread")]
async fn credential_repo_lockout_lazy_unlocks_after_ttl() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let repo = PgCredentialRepo::from_unverified_for_test(&store);
    let a = cred_tenant(CRED_TENANT_A)?;
    repo.insert(
        identity_scope(a),
        make_cred("alice", CRED_USER_ALICE, "correct", 1, a)?,
    )
    .await?;
    for i in 1..=5 {
        repo.authenticate(
            identity_scope(a),
            login_id("alice"),
            raw_password("wrong"),
            cred_epoch(CRED_BASE_SECS + i),
        )
        .await?;
    }
    let lock_at = CRED_BASE_SECS + 5;

    // TTL 内仍锁。
    assert_eq!(
        repo.authenticate(
            identity_scope(a),
            login_id("alice"),
            raw_password("correct"),
            cred_epoch(lock_at + LOCK_TTL_SECS - 1)
        )
        .await?,
        AuthOutcome::RejectedKnown
    );
    // TTL 后 lazy-unlock + 正确密码成功并持久化清锁。
    assert_eq!(
        authenticated_user(
            repo.authenticate(
                identity_scope(a),
                login_id("alice"),
                raw_password("correct"),
                cred_epoch(lock_at + LOCK_TTL_SECS + 1)
            )
            .await?
        )?,
        cred_uid(CRED_USER_ALICE)?
    );
    assert!(
        db_locked_until(&store, CRED_TENANT_A, "alice")
            .await?
            .is_none(),
        "lazy-unlock 持久化清 locked_until"
    );
    // 解锁后再失败从 1 重计（不沿用旧计数）→ RejectedKnown、未锁。
    let after = lock_at + LOCK_TTL_SECS + 2;
    assert_eq!(
        repo.authenticate(
            identity_scope(a),
            login_id("alice"),
            raw_password("wrong"),
            cred_epoch(after)
        )
        .await?,
        AuthOutcome::RejectedKnown
    );
    assert!(
        db_locked_until(&store, CRED_TENANT_A, "alice")
            .await?
            .is_none()
    );

    store.shutdown().await?;
    Ok(())
}

// 成功登录原子清零失败计数（authenticate 内折叠 clear——不需独立 clear 端口）。
#[tokio::test(flavor = "multi_thread")]
async fn credential_repo_authenticate_success_clears_lockout() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let repo = PgCredentialRepo::from_unverified_for_test(&store);
    let a = cred_tenant(CRED_TENANT_A)?;
    repo.insert(
        identity_scope(a),
        make_cred("alice", CRED_USER_ALICE, "correct", 1, a)?,
    )
    .await?;

    // 4 次错（未达阈值 5，未锁）→ 失败计数持久化 = 4。
    for i in 1..=4 {
        repo.authenticate(
            identity_scope(a),
            login_id("alice"),
            raw_password("wrong"),
            cred_epoch(CRED_BASE_SECS + i),
        )
        .await?;
    }
    assert_eq!(
        db_failure_count(&store, CRED_TENANT_A, "alice").await?,
        4,
        "失败累积 4"
    );
    // 正确密码 → Authenticated + 原子清零失败计数。
    assert_eq!(
        authenticated_user(
            repo.authenticate(
                identity_scope(a),
                login_id("alice"),
                raw_password("correct"),
                cred_epoch(CRED_BASE_SECS + 5)
            )
            .await?
        )?,
        cred_uid(CRED_USER_ALICE)?
    );
    assert_eq!(
        db_failure_count(&store, CRED_TENANT_A, "alice").await?,
        0,
        "成功登录清零失败计数"
    );

    store.shutdown().await?;
    Ok(())
}

/// material-never-persisted 断言（DoD review-critical）：`information_schema.columns` 校验 credentials 列集
/// 恰为预期（含 `password_hash`，**无明文 `password` 列**）。
#[tokio::test(flavor = "multi_thread")]
async fn ts_credentials_no_plaintext_password_column() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    let rows: Vec<(String,)> = sqlx::query_as(
        "SELECT column_name FROM information_schema.columns \
         WHERE table_name = 'credentials' AND table_schema = 'public' \
         ORDER BY column_name",
    )
    .fetch_all(&store.pool)
    .await?;
    let cols: Vec<&str> = rows.iter().map(|(s,)| s.as_str()).collect();

    let expected = [
        "created_at",
        "failure_count",
        "locked_until",
        "lockout_window_start",
        "login",
        "password_hash",
        "tenant_id",
        "user_id",
        "version",
    ];
    assert_eq!(
        cols, expected,
        "credentials 列集应恰为预期（仅 PHC，无明文密码列），实际：{cols:?}"
    );
    // 显式守 DoD：无明文 password 列，仅 argon2 PHC。
    assert!(
        !cols.contains(&"password"),
        "禁止明文 password 列（明文永不落库）"
    );
    assert!(cols.contains(&"password_hash"), "仅持久化 argon2 PHC 列");

    store.shutdown().await?;
    Ok(())
}

// 已临时锁定时，正确密码也必须经统一 authenticate 拒绝且不得清锁。
#[tokio::test(flavor = "multi_thread")]
async fn credential_repo_authenticate_correct_rejects_active_lock() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let repo = PgCredentialRepo::from_unverified_for_test(&store);
    let a = cred_tenant(CRED_TENANT_A)?;
    repo.insert(
        identity_scope(a),
        make_cred("alice", CRED_USER_ALICE, "correct", 1, a)?,
    )
    .await?;

    // 5 次错 → 达阈值锁定（locked_until 持久化非 NULL）。
    for i in 1..=5 {
        repo.authenticate(
            identity_scope(a),
            login_id("alice"),
            raw_password("wrong"),
            cred_epoch(CRED_BASE_SECS + i),
        )
        .await?;
    }
    assert!(
        db_locked_until(&store, CRED_TENANT_A, "alice")
            .await?
            .is_some(),
        "达阈值后 locked_until 持久化"
    );

    // 正确密码仍拒绝，锁定状态不变。
    assert_eq!(
        repo.authenticate(
            identity_scope(a),
            login_id("alice"),
            raw_password("correct"),
            cred_epoch(CRED_BASE_SECS + 6)
        )
        .await?,
        AuthOutcome::RejectedKnown
    );
    assert!(
        db_locked_until(&store, CRED_TENANT_A, "alice")
            .await?
            .is_some(),
        "temporary lock is not bypassed by a correct password"
    );
    assert_eq!(
        db_failure_count(&store, CRED_TENANT_A, "alice").await?,
        5,
        "temporary lock rejection preserves failure count"
    );

    store.shutdown().await?;
    Ok(())
}

// DB CHECK 约束红用例（#1316 review F2）：0012 的域不变式 CHECK 拒非法行——version/failure_count 越 u32 界、
// 锁定态缺滑窗起点。证 domain `u32` 边界 + 锁定一致性已下沉为 DB 硬约束（坏迁移/外部直写不可绕）。
#[tokio::test(flavor = "multi_thread")]
async fn credential_repo_db_check_constraints_reject_invalid() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let t = CRED_TENANT_A;
    let u = CRED_USER_ALICE;

    // 正例基线（合法行 INSERT 成功 → 证下列拒绝非因其它列约束，anti-vacuity）。
    insert_account_security_pair(&store, t, u, "ok").await?;

    // 非法：version < 0 → credentials_version_u32 拒。
    let mut neg_ver_tx = store.pool.begin().await?;
    let neg_ver = sqlx::query(
        "INSERT INTO credentials (tenant_id, user_id, login, password_hash, version) \
         VALUES ($1::uuid, $2::uuid, 'bad1', 'phc', -1)",
    )
    .bind(t)
    .bind(uuid::Uuid::new_v4().to_string())
    .execute(&mut *neg_ver_tx)
    .await;
    assert_database_constraint(neg_ver, "credentials_version_u32");
    neg_ver_tx.rollback().await?;

    // 非法：version > u32::MAX（4294967296）→ credentials_version_u32 拒。
    let mut over_ver_tx = store.pool.begin().await?;
    let over_ver = sqlx::query(
        "INSERT INTO credentials (tenant_id, user_id, login, password_hash, version) \
         VALUES ($1::uuid, $2::uuid, 'bad2', 'phc', 4294967296)",
    )
    .bind(t)
    .bind(uuid::Uuid::new_v4().to_string())
    .execute(&mut *over_ver_tx)
    .await;
    assert_database_constraint(over_ver, "credentials_version_u32");
    over_ver_tx.rollback().await?;

    // 非法：failure_count < 0 → credentials_failure_count_u32 拒。
    let mut neg_fc_tx = store.pool.begin().await?;
    let neg_fc = sqlx::query(
        "INSERT INTO credentials (tenant_id, user_id, login, password_hash, version, failure_count) \
         VALUES ($1::uuid, $2::uuid, 'bad3', 'phc', 1, -1)",
    )
    .bind(t)
    .bind(uuid::Uuid::new_v4().to_string())
    .execute(&mut *neg_fc_tx)
    .await;
    assert_database_constraint(neg_fc, "credentials_failure_count_u32");
    neg_fc_tx.rollback().await?;

    // 非法：locked_until 非空但 lockout_window_start 为空 → credentials_lock_requires_window 拒。
    let mut lock_tx = store.pool.begin().await?;
    let lock_no_window = sqlx::query(
        "INSERT INTO credentials (tenant_id, user_id, login, password_hash, version, locked_until) \
         VALUES ($1::uuid, $2::uuid, 'bad4', 'phc', 1, now())",
    )
    .bind(t)
    .bind(uuid::Uuid::new_v4().to_string())
    .execute(&mut *lock_tx)
    .await;
    assert_database_constraint(lock_no_window, "credentials_lock_requires_window");
    lock_tx.rollback().await?;

    store.shutdown().await?;
    Ok(())
}

// 并发行锁 RMW 红用例（#1316 review F1）：同 (tenant, login) 5 路并发 wrong-password authenticate——
// SELECT ... FOR UPDATE 串行化各事务 RMW，全部完成后失败计数恰 = 5（无丢更新）且达阈值锁定。
// 对标 role_definition_concurrent_revisions_are_contiguous（Arc<lifecycle> + tokio::spawn 竞争同行）。
#[tokio::test(flavor = "multi_thread")]
async fn credential_repo_concurrent_failures_no_lost_update() -> TestResult {
    use std::sync::Arc;

    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let repo = Arc::new(PgCredentialRepo::from_unverified_for_test(&store));
    let a = cred_tenant(CRED_TENANT_A)?;
    repo.insert(
        identity_scope(a),
        make_cred("alice", CRED_USER_ALICE, "correct", 1, a)?,
    )
    .await?;

    // 5 路并发错密码（同一行）——同一 now，行锁强制串行 RMW（非各自读 stale 副本各 +1 丢更新）。
    let now = cred_epoch(CRED_BASE_SECS);
    let mut handles = Vec::new();
    for _ in 0..5 {
        let repo = Arc::clone(&repo);
        handles.push(tokio::spawn(async move {
            repo.authenticate(
                identity_scope(a),
                login_id("alice"),
                raw_password("wrong"),
                now,
            )
            .await
        }));
    }
    for h in handles {
        // 每路均应返回 RejectedKnown（已知主体 + 错），无 task panic / Storage 错。
        let outcome = h.await.map_err(|e| format!("join failed: {e}"))??;
        assert_eq!(
            outcome,
            AuthOutcome::RejectedKnown,
            "并发错密码各路 RejectedKnown"
        );
    }

    // 行锁串行化 ⇒ 失败计数恰 5（无丢更新）+ 达阈值锁定。
    assert_eq!(
        db_failure_count(&store, CRED_TENANT_A, "alice").await?,
        5,
        "5 路并发错密码 → 失败计数恰 5（FOR UPDATE 无丢更新）"
    );
    assert!(
        db_locked_until(&store, CRED_TENANT_A, "alice")
            .await?
            .is_some()
    );

    store.shutdown().await?;
    Ok(())
}
