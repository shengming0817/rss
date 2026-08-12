//! Postgres integration tests — audit_persistence seam.

use super::support::*;

#[tokio::test(flavor = "multi_thread")]
async fn auth_audit_facade_rejects_embedded_tenant_mismatch_without_writing() -> TestResult {
    let (pg, owner) = connect_pg().await?;
    owner.run_migrations().await?;
    let app = connect_pg_rss_app_role(&pg, &owner).await?;
    let transaction_tenant = vocab::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
    let embedded_tenant = vocab::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
    let (scope, _, _) = audit_list_tenant_command(transaction_tenant).into_parts();
    let principal_id = format!("auth-audit-mismatch-{}", uuid::Uuid::new_v4());
    let event = crate::cotx::settings_audit::EncodedAuditEvent {
        occurred_at_secs: i64::try_from(TEST_OCCURRED_SECS)?,
        occurred_at_nanos: 0,
        principal_id: principal_id.clone(),
        principal_kind: "super_admin",
        tenant_context: Some(embedded_tenant.as_uuid().to_string()),
        resource_kind: "audit_entries",
        resource_id: embedded_tenant.as_uuid().to_string(),
        action: "audit:list-cross-tenant",
        outcome: "success",
        failure_reason: None,
        request_id: None,
        correlation_id: None,
    };
    let scoped =
        crate::cotx::TenantDb::<crate::cotx::ServingWriteLane>::from_unverified_for_test(&app);

    let result: Result<(), sqlx::Error> = scoped
        .retry_auth_audit_write(
            scope,
            crate::tx_retry::localtx_deadline_for_test(),
            move |mut tx| Box::pin(async move { tx.append_event(event).await }),
            |error| error,
        )
        .await
        .into_result();
    let error = result.expect_err("embedded audit tenant mismatch must fail closed");
    assert!(
        error
            .to_string()
            .contains("auth audit event tenant does not match transaction tenant"),
        "unexpected mismatch error: {error}"
    );

    let durable_rows: i64 =
        sqlx::query_scalar("SELECT count(*) FROM auth_audit_events WHERE principal_id = $1")
            .bind(principal_id)
            .fetch_one(&owner.pool)
            .await?;
    assert_eq!(
        durable_rows, 0,
        "an embedded tenant mismatch must not write an auth audit row under either tenant"
    );

    app.shutdown().await?;
    owner.shutdown().await?;
    Ok(())
}

/// Real Postgres enrollment for the audit LocalTx contract. Every backend shard constructs and
/// drives the route-specific `PgAuthAuditSink`, then snapshots its production
/// `auth_audit_events` table. HTTP validation and authorization rejection happen before this
/// provider and are covered only by the route journey.
#[tokio::test(flavor = "multi_thread")]
async fn localtx_audit_backend_profile_commit_and_rollback() -> TestResult {
    use std::sync::atomic::{AtomicUsize, Ordering};

    const LOCALTX_BACKEND_PROFILE_AUDIT_LIST_TENANT_ENTRIES: ::vocab::HttpRouteBinding<
        ::generated::http::audit_v1::list_tenant_entries::RouteMarker,
        ::vocab::http::LocalTx,
    > = ::generated::http::audit_v1::list_tenant_entries::ROUTE;
    const LOCALTX_BACKEND_PROVIDER_AUDIT_LIST_TENANT_ENTRIES: ::std::marker::PhantomData<(
        ::generated::http::audit_v1::list_tenant_entries::RouteMarker,
        crate::PgAuthAuditSink,
    )> = ::std::marker::PhantomData;
    let _typed_enrollment = LOCALTX_BACKEND_PROFILE_AUDIT_LIST_TENANT_ENTRIES;

    let (pg, owner) = connect_pg().await?;
    owner.run_migrations().await?;
    let app = connect_pg_rss_app_role(&pg, &owner).await?;
    let commit_sink = crate::PgAuthAuditSink::from_unverified_for_test(&app);
    let _typed_provider = LOCALTX_BACKEND_PROVIDER_AUDIT_LIST_TENANT_ENTRIES;
    let tenant_a = vocab::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;

    let commit_writes = AtomicUsize::new(0);
    ::rss_conformance::localtx::assert_commit(::rss_conformance::localtx::CommitCase::new(
        || async {
            commit_sink
                .append(audit_list_tenant_command(tenant_a))
                .await
                .map_err(|error| {
                    AuditLocalTxProfileError::provider(
                        rss_conformance::ConformanceErrorCategory::Permanent,
                        error,
                    )
                })
                .map_err(audit_profile_classified)?;
            commit_writes.fetch_add(1, Ordering::Relaxed);
            Ok(())
        },
        || async {
            auth_audit_snapshot(&owner, tenant_a)
                .await
                .map_err(audit_profile_classified)
        },
        1,
        || commit_writes.load(Ordering::Relaxed),
    ))
    .await?;

    let rollback_tenant = vocab::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
    let rollback_sink = crate::PgAuthAuditSink::from_unverified_for_test(&app).with_append_fault(
        rollback_tenant,
        crate::auth_audit_sink::AuthAuditAppendFault::Permanent,
        1,
    );
    ::rss_conformance::localtx::assert_rollback(::rss_conformance::localtx::RollbackCase::new(
        || async {
            rollback_sink
                .append(audit_list_tenant_command(rollback_tenant))
                .await
                .map_err(|error| {
                    AuditLocalTxProfileError::provider(
                        rss_conformance::ConformanceErrorCategory::Permanent,
                        error,
                    )
                })
                .map_err(audit_profile_classified)
        },
        rss_conformance::ConformanceErrorCategory::Permanent,
        || async {
            auth_audit_snapshot(&owner, rollback_tenant)
                .await
                .map_err(audit_profile_classified)
        },
        0,
    ))
    .await?;

    app.shutdown().await?;
    owner.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn localtx_audit_backend_profile_tenant_isolation() -> TestResult {
    const LOCALTX_BACKEND_PROFILE_AUDIT_LIST_TENANT_ENTRIES: ::vocab::HttpRouteBinding<
        ::generated::http::audit_v1::list_tenant_entries::RouteMarker,
        ::vocab::http::LocalTx,
    > = ::generated::http::audit_v1::list_tenant_entries::ROUTE;
    const LOCALTX_BACKEND_PROVIDER_AUDIT_LIST_TENANT_ENTRIES: ::std::marker::PhantomData<(
        ::generated::http::audit_v1::list_tenant_entries::RouteMarker,
        crate::PgAuthAuditSink,
    )> = ::std::marker::PhantomData;
    let _typed_enrollment = LOCALTX_BACKEND_PROFILE_AUDIT_LIST_TENANT_ENTRIES;

    let (pg, owner) = connect_pg().await?;
    owner.run_migrations().await?;
    let app = connect_pg_rss_app_role(&pg, &owner).await?;
    let sink = crate::PgAuthAuditSink::from_unverified_for_test(&app);
    let _typed_provider = LOCALTX_BACKEND_PROVIDER_AUDIT_LIST_TENANT_ENTRIES;
    let tenant_a = vocab::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
    let tenant_b = vocab::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;

    ::testkit::tenant_conformance::assert_tenant_isolation(
        tenant_a,
        tenant_b,
        |tenant| {
            let sink = &sink;
            async move {
                sink.append(audit_list_tenant_command(tenant))
                    .await
                    .map_err(|error| {
                        AuditLocalTxProfileError::provider(
                            rss_conformance::ConformanceErrorCategory::Permanent,
                            error,
                        )
                    })
            }
        },
        |tenant| {
            let owner = &owner;
            async move {
                auth_audit_snapshot(owner, tenant)
                    .await
                    .map(|count| count > 0)
            }
        },
        audit_profile_category,
    )
    .await?;

    app.shutdown().await?;
    owner.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn localtx_audit_backend_profile_retry_policy() -> TestResult {
    const LOCALTX_BACKEND_PROFILE_AUDIT_LIST_TENANT_ENTRIES: ::vocab::HttpRouteBinding<
        ::generated::http::audit_v1::list_tenant_entries::RouteMarker,
        ::vocab::http::LocalTx,
    > = ::generated::http::audit_v1::list_tenant_entries::ROUTE;
    const LOCALTX_BACKEND_PROVIDER_AUDIT_LIST_TENANT_ENTRIES: ::std::marker::PhantomData<(
        ::generated::http::audit_v1::list_tenant_entries::RouteMarker,
        crate::PgAuthAuditSink,
    )> = ::std::marker::PhantomData;
    let _typed_enrollment = LOCALTX_BACKEND_PROFILE_AUDIT_LIST_TENANT_ENTRIES;

    let (pg, owner) = connect_pg().await?;
    owner.run_migrations().await?;
    let app = connect_pg_rss_app_role(&pg, &owner).await?;
    let _typed_provider = LOCALTX_BACKEND_PROVIDER_AUDIT_LIST_TENANT_ENTRIES;

    let success_tenant = vocab::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
    let permanent_tenant = vocab::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
    let exhaustion_tenant = vocab::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
    let success_sink = crate::PgAuthAuditSink::from_unverified_for_test(&app).with_append_fault(
        success_tenant,
        crate::auth_audit_sink::AuthAuditAppendFault::Transient,
        1,
    );
    let permanent_sink = crate::PgAuthAuditSink::from_unverified_for_test(&app).with_append_fault(
        permanent_tenant,
        crate::auth_audit_sink::AuthAuditAppendFault::Permanent,
        1,
    );
    let exhaustion_sink = crate::PgAuthAuditSink::from_unverified_for_test(&app).with_append_fault(
        exhaustion_tenant,
        crate::auth_audit_sink::AuthAuditAppendFault::TransientBeforeWrite,
        3,
    );
    let success_probe = success_sink.append_attempt_probe();
    let permanent_probe = permanent_sink.append_attempt_probe();
    let exhaustion_probe = exhaustion_sink.append_attempt_probe();
    // This append-only command has no business-conflict outcome. Exercise only the retry classes
    // that the production provider can return; a hand-authored conflict would not be evidence.
    success_sink
        .append(audit_list_tenant_command(success_tenant))
        .await
        .map_err(|error| {
            AuditLocalTxProfileError::provider(
                rss_conformance::ConformanceErrorCategory::Transient,
                error,
            )
        })?;
    assert_eq!(success_probe.attempts(success_tenant), 2);
    assert_eq!(auth_audit_snapshot(&owner, success_tenant).await?, 1);

    let permanent = match permanent_sink
        .append(audit_list_tenant_command(permanent_tenant))
        .await
        .map_err(|error| {
            AuditLocalTxProfileError::provider(
                rss_conformance::ConformanceErrorCategory::Permanent,
                error,
            )
        }) {
        Ok(()) => {
            return Err(std::io::Error::other("permanent audit append fault must fail").into());
        }
        Err(error) => error,
    };
    assert_eq!(
        audit_profile_category(&permanent),
        rss_conformance::ConformanceErrorCategory::Permanent
    );
    assert_eq!(permanent_probe.attempts(permanent_tenant), 1);
    assert_eq!(auth_audit_snapshot(&owner, permanent_tenant).await?, 0);

    let exhausted = match exhaustion_sink
        .append(audit_list_tenant_command(exhaustion_tenant))
        .await
        .map_err(|error| {
            AuditLocalTxProfileError::provider(
                rss_conformance::ConformanceErrorCategory::Transient,
                error,
            )
        }) {
        Ok(()) => {
            return Err(
                std::io::Error::other("exhausted transient audit append fault must fail").into(),
            );
        }
        Err(error) => error,
    };
    assert_eq!(
        audit_profile_category(&exhausted),
        rss_conformance::ConformanceErrorCategory::Transient
    );
    assert_eq!(exhaustion_probe.attempts(exhaustion_tenant), 3);
    assert_eq!(auth_audit_snapshot(&owner, exhaustion_tenant).await?, 0);

    app.shutdown().await?;
    owner.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn localtx_audit_backend_profile_unsafe_settlements() -> TestResult {
    const LOCALTX_BACKEND_PROFILE_AUDIT_LIST_TENANT_ENTRIES: ::vocab::HttpRouteBinding<
        ::generated::http::audit_v1::list_tenant_entries::RouteMarker,
        ::vocab::http::LocalTx,
    > = ::generated::http::audit_v1::list_tenant_entries::ROUTE;
    const LOCALTX_BACKEND_PROVIDER_AUDIT_LIST_TENANT_ENTRIES: ::std::marker::PhantomData<(
        ::generated::http::audit_v1::list_tenant_entries::RouteMarker,
        crate::PgAuthAuditSink,
    )> = ::std::marker::PhantomData;
    let _typed_enrollment = LOCALTX_BACKEND_PROFILE_AUDIT_LIST_TENANT_ENTRIES;

    let (pg, owner) = connect_pg().await?;
    owner.run_migrations().await?;
    let app = connect_pg_rss_app_role(&pg, &owner).await?;
    let _typed_provider = LOCALTX_BACKEND_PROVIDER_AUDIT_LIST_TENANT_ENTRIES;

    let unknown_tenant = vocab::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
    let unknown_sink = crate::PgAuthAuditSink::from_unverified_for_test(&app).with_append_fault(
        unknown_tenant,
        crate::auth_audit_sink::AuthAuditAppendFault::CommitUnknown,
        1,
    );
    let unknown_probe = unknown_sink.append_attempt_probe();
    let rollback_failed_tenant = vocab::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
    let rollback_failed_sink = crate::PgAuthAuditSink::from_unverified_for_test(&app)
        .with_append_fault(
            rollback_failed_tenant,
            crate::auth_audit_sink::AuthAuditAppendFault::RollbackFailed,
            1,
        );
    let rollback_failed_probe = rollback_failed_sink.append_attempt_probe();
    let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();
    ::rss_conformance::localtx::assert_commit_unknown_no_replay(
        ::rss_conformance::localtx::CommitUnknownCase::new(
            || async {
                poll_with_local_recorder(
                    &recorder,
                    unknown_sink.append(audit_list_tenant_command(unknown_tenant)),
                )
                .await
                .map_err(|error| {
                    AuditLocalTxProfileError::provider(
                        rss_conformance::ConformanceErrorCategory::CommitUnknown,
                        error,
                    )
                })
                .map_err(audit_profile_classified)
            },
            rss_conformance::ConformanceErrorCategory::CommitUnknown,
            || unknown_probe.attempts(unknown_tenant),
        ),
    )
    .await?;
    ::rss_conformance::localtx::assert_rollback_failed_no_replay(
        ::rss_conformance::localtx::RollbackFailedCase::new(
            || async {
                poll_with_local_recorder(
                    &recorder,
                    rollback_failed_sink.append(audit_list_tenant_command(rollback_failed_tenant)),
                )
                .await
                .map_err(|error| {
                    AuditLocalTxProfileError::provider(
                        rss_conformance::ConformanceErrorCategory::RollbackFailed,
                        error,
                    )
                })
                .map_err(audit_profile_classified)
            },
            rss_conformance::ConformanceErrorCategory::RollbackFailed,
            || rollback_failed_probe.attempts(rollback_failed_tenant),
        ),
    )
    .await?;
    assert_eq!(auth_audit_snapshot(&owner, unknown_tenant).await?, 1);
    assert_eq!(
        auth_audit_snapshot(&owner, rollback_failed_tenant).await?,
        0
    );
    let rendered = handle.render();
    for expected in [
        "localtx_final_total{domain=\"audit\",contract_id=\"audit.list-tenant-entries\",boundary=\"single_domain\",final_status=\"commit_unknown\"} 1",
        "localtx_final_total{domain=\"audit\",contract_id=\"audit.list-tenant-entries\",boundary=\"single_domain\",final_status=\"rollback_failed\"} 1",
    ] {
        assert!(
            rendered.contains(expected),
            "audit route LocalTx metrics omitted {expected}: {rendered}"
        );
    }

    app.shutdown().await?;
    owner.shutdown().await?;
    Ok(())
}

/// TA13: a different 32-byte verification tag under the same typed key generation is rejected.
#[cfg(feature = "integration")]
#[tokio::test(flavor = "multi_thread")]
async fn ta13_audit_chain_key_restart_rejects_wrong_secret() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let k1 = [0x11_u8; 32];
    let k2 = [0x22_u8; 32];
    let first: bool =
        sqlx::query_scalar("SELECT rss_verify_audit_chain_key_v1(1::smallint, $1::bytea)")
            .bind(k1.as_slice())
            .fetch_one(&store.pool)
            .await?;
    let restart_same: bool =
        sqlx::query_scalar("SELECT rss_verify_audit_chain_key_v1(1::smallint, $1::bytea)")
            .bind(k1.as_slice())
            .fetch_one(&store.pool)
            .await?;
    let restart_wrong: bool =
        sqlx::query_scalar("SELECT rss_verify_audit_chain_key_v1(1::smallint, $1::bytea)")
            .bind(k2.as_slice())
            .fetch_one(&store.pool)
            .await?;
    assert!(first && restart_same);
    assert!(!restart_wrong, "K2 must not continue a ledger pinned to K1");
    store.shutdown().await?;
    Ok(())
}

/// 独立 read/write dyn capability 从同一个 provider 派生后必须观察同一 durable 链状态。
#[cfg(feature = "integration")]
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
// reason: integration happy-path uses generated UUIDs and fixed valid test values.
async fn audit_dyn_read_write_wrappers_share_postgres_provider() -> TestResult {
    use std::sync::Arc;

    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let tenant = vocab::TenantId::parse(&uuid::Uuid::new_v4().to_string()).unwrap();
    let provider = Arc::new(make_audit_repo(&store));
    let write: Arc<audit::ports::DynAuditWriteRepo<'static>> = Arc::from(
        audit::ports::DynAuditWriteRepo::new_box(Arc::clone(&provider)),
    );
    let read: Arc<audit::ports::DynAuditReadRepo<'static>> =
        Arc::from(audit::ports::DynAuditReadRepo::new_box(provider));

    let event_resource = "event:33333333-4444-4555-8666-777777777777";
    let mut record = make_audit_record(tenant, 7);
    record.action = vocab::Action::parse("identity:login")?;
    record.resource = audit::ports::ResourceRef::new("session", event_resource);
    write.append(audit_scope(tenant), record).await?;
    let result = read
        .list(audit_scope(tenant), audit_page(500, None))
        .await?;
    assert_eq!(result.entries.len(), 1);
    assert_eq!(result.entries[0].tenant(), tenant);
    assert_eq!(result.entries[0].resource().id(), event_resource);
    read.verify_tail(audit_scope(tenant), 1).await?;

    store.shutdown().await?;
    Ok(())
}

/// TA1: genesis 条目 seq=0，连续 append seq 单调递增。
#[cfg(feature = "integration")]
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
// reason: 集成测试 happy-path——UUID v4 生成不失败；item-level carve-out。
async fn ta1_audit_append_genesis_and_monotonic_seq() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let tenant = vocab::TenantId::parse(&uuid::Uuid::new_v4().to_string()).unwrap();
    let repo = make_audit_repo(&store);

    repo.append(audit_scope(tenant), make_audit_record(tenant, 0))
        .await?;
    repo.append(audit_scope(tenant), make_audit_record(tenant, 0))
        .await?;
    repo.append(audit_scope(tenant), make_audit_record(tenant, 0))
        .await?;

    let result = repo
        .list(audit_scope(tenant), audit_page(500, None))
        .await?;
    assert_eq!(result.entries.len(), 3, "TA1: 应恰有 3 条");
    assert_eq!(result.entries[0].seq(), 0, "TA1: genesis seq=0");
    assert_eq!(result.entries[1].seq(), 1, "TA1: seq 单调+1");
    assert_eq!(result.entries[2].seq(), 2, "TA1: seq 单调+2");
    assert!(!result.has_more);
    assert!(result.next_cursor.is_none());

    store.shutdown().await?;
    Ok(())
}

/// TA2: 每条 prev_hash == 前一条 entry_hash，genesis prev 全零。
#[cfg(feature = "integration")]
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn ta2_audit_prev_links_to_predecessor_entry_hash() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let tenant = vocab::TenantId::parse(&uuid::Uuid::new_v4().to_string()).unwrap();
    let repo = make_audit_repo(&store);

    for _ in 0..3 {
        repo.append(audit_scope(tenant), make_audit_record(tenant, 0))
            .await?;
    }

    let result = repo
        .list(audit_scope(tenant), audit_page(500, None))
        .await?;
    let e = &result.entries;

    assert_eq!(
        e[0].prev_hash().as_bytes(),
        &[0u8; 32],
        "TA2: genesis prev 须全零"
    );
    assert_eq!(
        e[1].prev_hash().as_bytes(),
        e[0].entry_hash().as_bytes(),
        "TA2: e[1].prev_hash 须 == e[0].entry_hash"
    );
    assert_eq!(
        e[2].prev_hash().as_bytes(),
        e[1].entry_hash().as_bytes(),
        "TA2: e[2].prev_hash 须 == e[1].entry_hash"
    );

    store.shutdown().await?;
    Ok(())
}

/// TA3: 同租户并发 append（5 task）——advisory lock 保证 no seq gap / dup。
#[cfg(feature = "integration")]
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn ta3_audit_concurrent_appends_no_seq_gap() -> TestResult {
    use std::sync::Arc;
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let tenant = vocab::TenantId::parse(&uuid::Uuid::new_v4().to_string()).unwrap();
    let repo = Arc::new(make_audit_repo(&store));

    const N: usize = 5;
    let handles: Vec<_> = (0..N)
        .map(|_| {
            let r = Arc::clone(&repo);
            tokio::spawn(async move {
                r.append(audit_scope(tenant), make_audit_record(tenant, 0))
                    .await
            })
        })
        .collect();
    for h in handles {
        h.await.map_err(|e| format!("join error: {e}"))??;
    }

    let result = repo
        .list(audit_scope(tenant), audit_page(500, None))
        .await?;
    assert_eq!(result.entries.len(), N, "TA3: 应恰有 {N} 条");
    let mut seqs: Vec<u64> = result.entries.iter().map(|e| e.seq()).collect();
    seqs.sort_unstable();
    for (i, &s) in seqs.iter().enumerate() {
        assert_eq!(s, i as u64, "TA3: seq 须连续无 gap，i={i} s={s}");
    }

    store.shutdown().await?;
    Ok(())
}
/// TA4 residual: two tenants each get independent genesis seq=0.
/// Visibility / non-interference owned by `ta4b_audit_tenant_conformance`
/// (`assert_tenant_isolation`).
#[cfg(feature = "integration")]
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn ta4_audit_tenants_have_independent_genesis_seq_zero() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let tenant_a = vocab::TenantId::parse(&uuid::Uuid::new_v4().to_string()).unwrap();
    let tenant_b = vocab::TenantId::parse(&uuid::Uuid::new_v4().to_string()).unwrap();
    let repo = make_audit_repo(&store);

    // Minimal seed so each tenant's first append is a real genesis (seq assigned by store).
    repo.append(audit_scope(tenant_a), make_audit_record(tenant_a, 0))
        .await?;
    repo.append(audit_scope(tenant_b), make_audit_record(tenant_b, 0))
        .await?;

    let a = repo
        .list(audit_scope(tenant_a), audit_page(500, None))
        .await?;
    let b = repo
        .list(audit_scope(tenant_b), audit_page(500, None))
        .await?;
    assert_eq!(
        a.entries.len(),
        1,
        "TA4 residual: tenant_a needs one genesis row"
    );
    assert_eq!(
        b.entries.len(),
        1,
        "TA4 residual: tenant_b needs one genesis row"
    );
    assert_eq!(
        a.entries[0].seq(),
        0,
        "TA4 residual: tenant_a genesis seq=0"
    );
    assert_eq!(
        b.entries[0].seq(),
        0,
        "TA4 residual: tenant_b independent genesis seq=0"
    );

    store.shutdown().await?;
    Ok(())
}

/// TA4b：`PgAuditRepo` 接入统一 tenant conformance。
#[cfg(feature = "integration")]
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn ta4b_audit_tenant_conformance() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let tenant_a = vocab::TenantId::parse(&uuid::Uuid::new_v4().to_string()).unwrap();
    let tenant_b = vocab::TenantId::parse(&uuid::Uuid::new_v4().to_string()).unwrap();
    let repo = make_audit_repo(&store);

    testkit::tenant_conformance::assert_tenant_isolation(
        tenant_a,
        tenant_b,
        |tenant| {
            let repo = &repo;
            async move {
                repo.append(audit_scope(tenant), make_audit_record(tenant, 0))
                    .await
            }
        },
        |tenant| {
            let repo = &repo;
            async move {
                repo.list(audit_scope(tenant), audit_page(500, None))
                    .await
                    .map(|page| !page.entries.is_empty())
            }
        },
        |error| match error {
            audit::ports::AuditError::Storage(_) => {
                rss_conformance::ConformanceErrorCategory::Storage
            }
            _ => rss_conformance::ConformanceErrorCategory::Permanent,
        },
    )
    .await?;

    store.shutdown().await?;
    Ok(())
}

/// TA4c：audit record tenant 与 repo scope tenant 不一致 → fail-closed，audit row 不落库。
#[cfg(feature = "integration")]
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn ta4c_audit_rejects_scope_record_tenant_mismatch() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let scope_tenant = vocab::TenantId::parse(&uuid::Uuid::new_v4().to_string()).unwrap();
    let record_tenant = vocab::TenantId::parse(&uuid::Uuid::new_v4().to_string()).unwrap();
    let repo = make_audit_repo(&store);

    let result = repo
        .append(
            audit_scope(scope_tenant),
            make_audit_record(record_tenant, 0),
        )
        .await;
    assert!(
        result.is_err(),
        "audit scope/record mismatch must fail closed"
    );

    let cnt: (i64,) =
        sqlx::query_as("SELECT count(*) FROM audit_entries WHERE tenant_id = $1::uuid")
            .bind(record_tenant.to_string())
            .fetch_one(&store.pool)
            .await?;
    assert_eq!(cnt.0, 0, "scope mismatch 不得写 audit_entries 行");

    store.shutdown().await?;
    Ok(())
}

/// TA6: list 分页游标——5 条, page=2 → 3 页（2+2+1），has_more 正确，cursor 续页完整。
#[cfg(feature = "integration")]
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn ta6_audit_list_pagination_cursor_and_has_more() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let tenant = vocab::TenantId::parse(&uuid::Uuid::new_v4().to_string()).unwrap();
    let repo = make_audit_repo(&store);

    for _ in 0..5 {
        repo.append(audit_scope(tenant), make_audit_record(tenant, 0))
            .await?;
    }

    let p1 = repo.list(audit_scope(tenant), audit_page(2, None)).await?;
    assert_eq!(p1.entries.len(), 2, "TA6: p1 应有 2 条");
    assert!(p1.has_more, "TA6: p1 has_more=true");
    assert!(p1.next_cursor.is_some(), "TA6: p1 应有 next_cursor");
    assert_eq!(p1.entries[0].seq(), 0);
    assert_eq!(p1.entries[1].seq(), 1);

    let p2 = repo
        .list(audit_scope(tenant), audit_page(2, p1.next_cursor))
        .await?;
    assert_eq!(p2.entries.len(), 2, "TA6: p2 应有 2 条");
    assert!(p2.has_more, "TA6: p2 has_more=true");
    assert_eq!(p2.entries[0].seq(), 2);
    assert_eq!(p2.entries[1].seq(), 3);

    let p3 = repo
        .list(audit_scope(tenant), audit_page(2, p2.next_cursor))
        .await?;
    assert_eq!(p3.entries.len(), 1, "TA6: p3 应有 1 条");
    assert!(!p3.has_more, "TA6: p3 has_more=false");
    assert!(p3.next_cursor.is_none(), "TA6: p3 无 next_cursor");
    assert_eq!(p3.entries[0].seq(), 4);

    store.shutdown().await?;
    Ok(())
}

/// TA7: list 语义无效游标（base64url 合法但解码后非数字）→ InvalidCursor（fail-closed）。
#[cfg(feature = "integration")]
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn ta7_audit_list_invalid_cursor_fail_closed() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let tenant = vocab::TenantId::parse(&uuid::Uuid::new_v4().to_string()).unwrap();
    let repo = make_audit_repo(&store);
    repo.append(audit_scope(tenant), make_audit_record(tenant, 0))
        .await?;

    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"not-a-number");
    let cursor = vocab::Cursor::parse(&raw).unwrap();
    let result = repo
        .list(audit_scope(tenant), audit_page(10, Some(cursor)))
        .await;
    assert!(
        matches!(result, Err(audit::ports::AuditError::InvalidCursor)),
        "TA7: 语义无效游标须返回 InvalidCursor"
    );

    store.shutdown().await?;
    Ok(())
}

/// TA8: verify_tail 增量性——篡改 genesis 后，小窗口（不覆盖 seq=0）Ok；大窗口 → HashMismatch。
#[cfg(feature = "integration")]
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn ta8_audit_verify_tail_incremental_and_tamper_detection() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let tenant_str = uuid::Uuid::new_v4().to_string();
    let tenant = vocab::TenantId::parse(&tenant_str).unwrap();
    let repo = make_audit_repo(&store);

    for _ in 0..5 {
        repo.append(audit_scope(tenant), make_audit_record(tenant, 0))
            .await?;
    }

    // 干净链：verify_tail 均通过。
    repo.verify_tail(audit_scope(tenant), 2).await?;
    repo.verify_tail(audit_scope(tenant), 10).await?;

    // 超级用户篡改 seq=0 的 entry_hash（rss_app 无 UPDATE 权）。
    sqlx::query("UPDATE audit_entries SET entry_hash = $1 WHERE tenant_id = $2::uuid AND seq = 0")
        .bind(vec![0xAAu8; 32])
        .bind(&tenant_str)
        .execute(&store.pool)
        .await?;

    // 小窗口（末 2 条 = seq 3,4 + 前驱 seq 2）：不覆盖被篡改 seq 0 → 增量验证仍 Ok。
    let tail2 = repo.verify_tail(audit_scope(tenant), 2).await;
    assert!(
        tail2.is_ok(),
        "TA8: 小窗口不覆盖被篡改 genesis → verify_tail(2) 须 Ok，got: {tail2:?}"
    );

    // 大窗口（全 5 条 seq 0-4）：覆盖被篡改 seq 0 → HashMismatch。
    let tail10 = repo.verify_tail(audit_scope(tenant), 10).await;
    assert!(
        matches!(tail10, Err(audit::ports::AuditError::HashMismatch)),
        "TA8: 大窗口覆盖被篡改 genesis → HashMismatch，got: {tail10:?}"
    );

    store.shutdown().await?;
    Ok(())
}

/// TA9: recorded_at 非零 nanos 往返——存储+读取后 nanos 精确保留，且链哈希仍验证通过。
///
/// Regression: 若用 timestamptz 存储则 nanos 被截断 → 重算 entry_hash 不匹配。
#[cfg(feature = "integration")]
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used, clippy::expect_used)]
// reason: 集成测试——recorded_at 由 UNIX_EPOCH+Duration 构造，duration_since(UNIX_EPOCH) 不失败；item-level carve-out。
async fn ta9_audit_recorded_at_nanos_roundtrip_and_chain_verifies() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let tenant = vocab::TenantId::parse(&uuid::Uuid::new_v4().to_string()).unwrap();
    let repo = make_audit_repo(&store);

    let nanos_input: u32 = 123_456_789;
    repo.append(audit_scope(tenant), make_audit_record(tenant, nanos_input))
        .await?;

    let result = repo.list(audit_scope(tenant), audit_page(10, None)).await?;
    assert_eq!(result.entries.len(), 1, "TA9: 应恰有 1 条");

    let e = &result.entries[0];
    let since_epoch = e
        .recorded_at()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("recorded_at >= UNIX_EPOCH");
    assert_eq!(
        since_epoch.subsec_nanos(),
        nanos_input,
        "TA9: nanos 须精确往返（secs+nanos 两列，非 timestamptz）"
    );

    // list 内置增量验证；额外 verify_tail 确认链完整。
    repo.verify_tail(audit_scope(tenant), 10).await?;

    store.shutdown().await?;
    Ok(())
}

/// TA10: append-only——rss_app 对 audit_entries 的 DELETE / UPDATE 被 DB 权限拒绝。
#[cfg(feature = "integration")]
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn ta10_audit_append_only_delete_update_rejected_for_rss_app() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    sqlx::query("GRANT rss_app TO CURRENT_USER")
        .execute(&store.pool)
        .await?;

    let tenant_str = uuid::Uuid::new_v4().to_string();
    let tenant = vocab::TenantId::parse(&tenant_str).unwrap();
    let repo = make_audit_repo(&store);
    repo.append(audit_scope(tenant), make_audit_record(tenant, 0))
        .await?;

    // rss_app DELETE → permission denied。
    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_str)
            .execute(&mut *tx)
            .await?;
        let del = sqlx::query("DELETE FROM audit_entries WHERE tenant_id = $1::uuid")
            .bind(&tenant_str)
            .execute(&mut *tx)
            .await;
        assert!(
            del.is_err(),
            "TA10: rss_app 应无 DELETE 权限（append-only）"
        );
        tx.rollback().await?;
    }

    // rss_app UPDATE → permission denied。
    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_str)
            .execute(&mut *tx)
            .await?;
        let upd = sqlx::query(
            "UPDATE audit_entries SET action = 'tampered:value' WHERE tenant_id = $1::uuid",
        )
        .bind(&tenant_str)
        .execute(&mut *tx)
        .await;
        assert!(
            upd.is_err(),
            "TA10: rss_app 应无 UPDATE 权限（append-only）"
        );
        tx.rollback().await?;
    }

    store.shutdown().await?;
    Ok(())
}

/// TA12: 空租户链 list → Ok（空结果），verify_tail → Ok（空链无前驱）。
#[cfg(feature = "integration")]
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn ta12_audit_empty_tenant_list_and_verify_tail_ok() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let tenant = vocab::TenantId::parse(&uuid::Uuid::new_v4().to_string()).unwrap();
    let repo = make_audit_repo(&store);

    let result = repo.list(audit_scope(tenant), audit_page(10, None)).await?;
    assert!(result.entries.is_empty(), "TA12: 空租户 list 须空");
    assert!(!result.has_more);

    repo.verify_tail(audit_scope(tenant), 10).await?;

    store.shutdown().await?;
    Ok(())
}

/// TA15: audit admin full-chain verify 从 genesis 扫到尾，返回已验证条目数。
#[cfg(feature = "integration")]
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn ta15_audit_admin_verify_tenant_clean_chain_success() -> TestResult {
    let (pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let tenant = vocab::TenantId::parse(&uuid::Uuid::new_v4().to_string()).unwrap();
    let repo = make_audit_repo(&store);
    for _ in 0..5 {
        repo.append(audit_scope(tenant), make_audit_record(tenant, 0))
            .await?;
    }

    let audit_admin = connect_pg_audit_admin_role(&pg, &store).await?;
    let admin_repo = make_audit_admin_repo(&audit_admin);
    let report = admin_repo
        .verify_tenant(tenant, vocab::Limit::new(2).unwrap())
        .await?;

    assert_eq!(report.tenant, tenant);
    assert_eq!(report.checked_entries, 5);
    audit_admin.shutdown().await?;
    store.shutdown().await?;
    Ok(())
}

/// TA16: audit admin verify 的 tenant scope 精确隔离，A/B 只验证各自链。
#[cfg(feature = "integration")]
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn ta16_audit_admin_verify_tenant_ab_isolation() -> TestResult {
    let (pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let tenant_a = vocab::TenantId::parse(&uuid::Uuid::new_v4().to_string()).unwrap();
    let tenant_b = vocab::TenantId::parse(&uuid::Uuid::new_v4().to_string()).unwrap();
    let repo = make_audit_repo(&store);
    repo.append(audit_scope(tenant_a), make_audit_record(tenant_a, 0))
        .await?;
    repo.append(audit_scope(tenant_a), make_audit_record(tenant_a, 0))
        .await?;
    repo.append(audit_scope(tenant_b), make_audit_record(tenant_b, 0))
        .await?;

    let audit_admin = connect_pg_audit_admin_role(&pg, &store).await?;
    let admin_repo = make_audit_admin_repo(&audit_admin);
    let a = admin_repo
        .verify_tenant(tenant_a, vocab::Limit::new(1).unwrap())
        .await?;
    let b = admin_repo
        .verify_tenant(tenant_b, vocab::Limit::new(1).unwrap())
        .await?;

    assert_eq!(a.checked_entries, 2, "tenant A chain only");
    assert_eq!(b.checked_entries, 1, "tenant B chain only");
    audit_admin.shutdown().await?;
    store.shutdown().await?;
    Ok(())
}

/// TA17: audit admin full-chain verify 覆盖 tail-verify 漏洞：genesis 篡改与 seq gap 都 fail-closed。
#[cfg(feature = "integration")]
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn ta17_audit_admin_verify_tenant_tamper_and_seq_gap_fail() -> TestResult {
    let (pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let tampered_tenant_str = uuid::Uuid::new_v4().to_string();
    let tampered_tenant = vocab::TenantId::parse(&tampered_tenant_str).unwrap();
    let gap_tenant_str = uuid::Uuid::new_v4().to_string();
    let gap_tenant = vocab::TenantId::parse(&gap_tenant_str).unwrap();
    let repo = make_audit_repo(&store);
    for _ in 0..5 {
        repo.append(
            audit_scope(tampered_tenant),
            make_audit_record(tampered_tenant, 0),
        )
        .await?;
        repo.append(audit_scope(gap_tenant), make_audit_record(gap_tenant, 0))
            .await?;
    }
    sqlx::query("UPDATE audit_entries SET entry_hash = $1 WHERE tenant_id = $2::uuid AND seq = 0")
        .bind(vec![0xAAu8; 32])
        .bind(&tampered_tenant_str)
        .execute(&store.pool)
        .await?;
    sqlx::query("DELETE FROM audit_entries WHERE tenant_id = $1::uuid AND seq = 2")
        .bind(&gap_tenant_str)
        .execute(&store.pool)
        .await?;

    let audit_admin = connect_pg_audit_admin_role(&pg, &store).await?;
    let admin_repo = make_audit_admin_repo(&audit_admin);
    let tampered = admin_repo
        .verify_tenant(tampered_tenant, vocab::Limit::new(2).unwrap())
        .await;
    let gap = admin_repo
        .verify_tenant(gap_tenant, vocab::Limit::new(2).unwrap())
        .await;

    assert!(
        matches!(tampered, Err(audit::ports::AuditError::HashMismatch)),
        "tampered genesis must fail full-chain verify, got: {tampered:?}"
    );
    assert!(
        matches!(gap, Err(audit::ports::AuditError::SequenceGap)),
        "deleted seq must fail full-chain verify, got: {gap:?}"
    );
    audit_admin.shutdown().await?;
    store.shutdown().await?;
    Ok(())
}

/// TA18: rss_audit_admin 是 verify/read-only capability，不得拥有 INSERT/UPDATE/DELETE。
#[cfg(feature = "integration")]
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn ta18_audit_admin_role_dml_is_rejected() -> TestResult {
    let (pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let tenant_str = uuid::Uuid::new_v4().to_string();
    let tenant = vocab::TenantId::parse(&tenant_str).unwrap();
    let repo = make_audit_repo(&store);
    repo.append(audit_scope(tenant), make_audit_record(tenant, 0))
        .await?;

    let audit_admin = connect_pg_audit_admin_role(&pg, &store).await?;
    {
        let mut tx = audit_admin.pool.begin().await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_str)
            .execute(&mut *tx)
            .await?;
        let update = sqlx::query(
            "UPDATE audit_entries SET action = 'tampered:value' WHERE tenant_id = $1::uuid",
        )
        .bind(&tenant_str)
        .execute(&mut *tx)
        .await;
        assert!(
            update.is_err(),
            "rss_audit_admin must not UPDATE audit_entries"
        );
        tx.rollback().await.ok();
    }
    {
        let mut tx = audit_admin.pool.begin().await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_str)
            .execute(&mut *tx)
            .await?;
        let delete = sqlx::query("DELETE FROM audit_entries WHERE tenant_id = $1::uuid")
            .bind(&tenant_str)
            .execute(&mut *tx)
            .await;
        assert!(
            delete.is_err(),
            "rss_audit_admin must not DELETE audit_entries"
        );
        tx.rollback().await.ok();
    }
    {
        let mut tx = audit_admin.pool.begin().await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_str)
            .execute(&mut *tx)
            .await?;
        let insert = sqlx::query(
            "INSERT INTO audit_entries \
             (tenant_id, seq, prev_hash, entry_hash, actor, actor_kind, action, resource_kind, resource_id, outcome, recorded_at_secs, recorded_at_nanos) \
             VALUES ($1::uuid, 99, $2, $2, $3::uuid, 'user', 'audit:read', 'session', 'sess-1', 'success', 0, 0)",
        )
        .bind(&tenant_str)
        .bind(vec![0u8; 32])
        .bind("11111111-2222-4333-8444-555555555555")
        .execute(&mut *tx)
        .await;
        assert!(
            insert.is_err(),
            "rss_audit_admin must not INSERT audit_entries"
        );
        tx.rollback().await.ok();
    }

    audit_admin.shutdown().await?;
    store.shutdown().await?;
    Ok(())
}

/// TA13: hydrate_row wrong-length entry_hash — 超级用户临时删 CHECK 约束后注入短 bytea，
/// list 读取时 try_into 失败 → `Err(AuditError::Storage(...))`（bytea-length arm 覆盖）。
#[cfg(feature = "integration")]
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
// reason: 集成测试 happy-path 构造——UUID v4 + audit_page 参数已知合法；item-level carve-out。
async fn ta13_audit_hydrate_row_wrong_length_entry_hash_returns_storage() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let tenant_str = uuid::Uuid::new_v4().to_string();
    let tenant = vocab::TenantId::parse(&tenant_str).unwrap();
    let repo = make_audit_repo(&store);

    repo.append(audit_scope(tenant), make_audit_record(tenant, 0))
        .await?;

    // 超级用户临时删 entry_hash 长度 CHECK 约束（PostgreSQL 自动命名 audit_entries_entry_hash_check），
    // 注入错误长度 bytea（10B ≠ 32B）以覆盖 hydrate_row wrong-length arm。
    sqlx::query(
        "ALTER TABLE audit_entries DROP CONSTRAINT IF EXISTS audit_entries_entry_hash_check",
    )
    .execute(&store.pool)
    .await?;
    sqlx::query("UPDATE audit_entries SET entry_hash = $1 WHERE tenant_id = $2::uuid AND seq = 0")
        .bind(vec![0xBBu8; 10]) // 10B != 32B，触发 hydrate_row try_into 失败臂
        .bind(&tenant_str)
        .execute(&store.pool)
        .await?;

    let result = repo.list(audit_scope(tenant), audit_page(10, None)).await;
    assert!(
        matches!(result, Err(audit::ports::AuditError::Storage(_))),
        "TA13: 错误长度 entry_hash 须返回 AuditError::Storage（实际为 Ok 或其它 Err 变体）"
    );

    store.shutdown().await?;
    Ok(())
}

/// TA14: hydrate_row unknown actor_kind — 超级用户临时删 CHECK 约束后注入闭值集外文本，
/// list 读取时 actor_kind_from_db 返回 None → `Err(AuditError::Storage(...))`（unknown-enum arm 覆盖）。
#[cfg(feature = "integration")]
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
// reason: 集成测试 happy-path 构造——UUID v4 + audit_page 参数已知合法；item-level carve-out。
async fn ta14_audit_hydrate_row_unknown_actor_kind_returns_storage() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let tenant_str = uuid::Uuid::new_v4().to_string();
    let tenant = vocab::TenantId::parse(&tenant_str).unwrap();
    let repo = make_audit_repo(&store);

    repo.append(audit_scope(tenant), make_audit_record(tenant, 0))
        .await?;

    // 超级用户临时删 actor_kind IN 值集 CHECK 约束（PostgreSQL 自动命名 audit_entries_actor_kind_check），
    // 注入闭值集外的 actor_kind 文本以覆盖 hydrate_row actor_kind_from_db → None 的错误臂。
    sqlx::query(
        "ALTER TABLE audit_entries DROP CONSTRAINT IF EXISTS audit_entries_actor_kind_check",
    )
    .execute(&store.pool)
    .await?;
    sqlx::query(
        "UPDATE audit_entries SET actor_kind = 'robot' WHERE tenant_id = $1::uuid AND seq = 0",
    )
    .bind(&tenant_str)
    .execute(&store.pool)
    .await?;

    let result = repo.list(audit_scope(tenant), audit_page(10, None)).await;
    assert!(
        matches!(result, Err(audit::ports::AuditError::Storage(_))),
        "TA14: 未知 actor_kind 须返回 AuditError::Storage（实际为 Ok 或其它 Err 变体）"
    );

    store.shutdown().await?;
    Ok(())
}
