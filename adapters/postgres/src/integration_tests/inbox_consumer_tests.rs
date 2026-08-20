//! Postgres integration tests — inbox_consumer seam.

use super::support::*;
/// inbox_receipts target schema catalog lock (#1626).
///
/// The tenant-scoped mutable receipt table must exist with its target columns,
/// tenant-first primary key, indexes, and DB-level CHECK constraints.
#[tokio::test(flavor = "multi_thread")]
async fn inbox_receipts_schema_catalog_after_migrations() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    let columns: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT column_name, data_type, is_nullable \
         FROM information_schema.columns \
         WHERE table_schema = 'public' AND table_name = 'inbox_receipts' \
         ORDER BY ordinal_position",
    )
    .fetch_all(&store.pool)
    .await?;
    assert_eq!(
        columns,
        vec![
            (
                "tenant_id".to_string(),
                "uuid".to_string(),
                "NO".to_string()
            ),
            ("event_id".to_string(), "text".to_string(), "NO".to_string()),
            (
                "consumer_group".to_string(),
                "text".to_string(),
                "NO".to_string()
            ),
            ("domain".to_string(), "text".to_string(), "NO".to_string()),
            ("topic".to_string(), "text".to_string(), "NO".to_string()),
            (
                "contract_id".to_string(),
                "text".to_string(),
                "NO".to_string()
            ),
            (
                "contract_version".to_string(),
                "text".to_string(),
                "NO".to_string()
            ),
            (
                "schema_hash".to_string(),
                "text".to_string(),
                "NO".to_string()
            ),
            ("trace".to_string(), "text".to_string(), "YES".to_string()),
            (
                "correlation_id".to_string(),
                "text".to_string(),
                "YES".to_string()
            ),
            ("status".to_string(), "text".to_string(), "NO".to_string()),
            (
                "lease_token".to_string(),
                "uuid".to_string(),
                "NO".to_string()
            ),
            (
                "receive_count".to_string(),
                "integer".to_string(),
                "NO".to_string()
            ),
            (
                "claimed_at".to_string(),
                "timestamp with time zone".to_string(),
                "NO".to_string()
            ),
            (
                "committed_at".to_string(),
                "timestamp with time zone".to_string(),
                "YES".to_string()
            ),
            (
                "updated_at".to_string(),
                "timestamp with time zone".to_string(),
                "NO".to_string()
            ),
        ],
        "inbox_receipts columns must match the target runtime replacement shape"
    );

    let pk_columns: (String,) = sqlx::query_as(
        "SELECT string_agg(a.attname, ',' ORDER BY k.ord) \
         FROM pg_constraint c \
         JOIN LATERAL unnest(c.conkey) WITH ORDINALITY AS k(attnum, ord) ON true \
         JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = k.attnum \
         WHERE c.conrelid = 'inbox_receipts'::regclass AND c.contype = 'p'",
    )
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(
        pk_columns.0, "tenant_id,event_id,consumer_group",
        "inbox_receipts primary key must be tenant-first"
    );

    let indexes: Vec<(String, String)> = sqlx::query_as(
        "SELECT indexname, lower(indexdef) \
         FROM pg_indexes \
         WHERE schemaname = 'public' AND tablename = 'inbox_receipts' \
         ORDER BY indexname",
    )
    .fetch_all(&store.pool)
    .await?;
    let index_text = indexes
        .iter()
        .map(|(name, def)| format!("{name}: {def}"))
        .collect::<Vec<_>>()
        .join("\n");
    for needle in [
        "idx_inbox_receipts_stale_claims",
        "tenant_id, consumer_group, claimed_at",
        "where (status = 'claimed'::text)",
        "idx_inbox_receipts_done_retention",
        "status, committed_at",
        "where (status = 'done'::text)",
        "idx_inbox_receipts_contract_schema",
        "tenant_id, domain, contract_id, contract_version, schema_hash",
    ] {
        assert!(
            index_text.contains(needle),
            "missing inbox_receipts index shape `{needle}` in:\n{index_text}"
        );
    }

    let constraints: Vec<(String, String)> = sqlx::query_as(
        "SELECT conname, pg_get_constraintdef(oid) \
         FROM pg_constraint \
         WHERE conrelid = 'inbox_receipts'::regclass \
         ORDER BY conname",
    )
    .fetch_all(&store.pool)
    .await?;
    let constraint_text = constraints
        .iter()
        .map(|(name, def)| format!("{name}: {def}"))
        .collect::<Vec<_>>()
        .join("\n");
    for name in [
        "inbox_receipts_contract_version_valid",
        "inbox_receipts_schema_hash_valid",
        "inbox_receipts_status_valid",
        "inbox_receipts_trace_valid",
        "inbox_receipts_correlation_id_valid",
        "inbox_receipts_receive_count_positive",
        "inbox_receipts_commit_timestamp_matches_status",
    ] {
        assert!(
            constraint_text.contains(name),
            "missing inbox_receipts constraint `{name}` in:\n{constraint_text}"
        );
    }

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn eventing_conformance_inbox_enrolls_postgres() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let event_id = unique_event_id("eventing-conf-inbox");
    let group = unique_domain("eventing-conf-inbox-group");
    let group_b = unique_domain("eventing-conf-inbox-group-b");
    let leases: Arc<Mutex<HashMap<String, LeaseToken>>> = Arc::new(Mutex::new(HashMap::new()));

    let try_leases = Arc::clone(&leases);
    let extend_leases = Arc::clone(&leases);
    let commit_leases = Arc::clone(&leases);
    let release_leases = Arc::clone(&leases);
    eventconf::assert_inbox_conformance(eventconf::InboxConformanceCase {
        ids: eventconf::EventingIds::new(event_id.clone(), event_id.clone(), group, "lease-a"),
        second_group: group_b,
        try_claim: Box::new(|args| {
            Box::pin(conf_try_claim(
                &store,
                &try_leases,
                args.inbox_key,
                args.consumer_group,
                args.lease_alias,
            ))
        }),
        extend: Box::new(|args| {
            Box::pin(conf_extend(
                &store,
                &extend_leases,
                args.inbox_key,
                args.consumer_group,
                args.lease_alias,
            ))
        }),
        commit: Box::new(|args| {
            Box::pin(conf_commit(
                &store,
                &commit_leases,
                args.inbox_key,
                args.consumer_group,
                args.lease_alias,
            ))
        }),
        release: Box::new(|args| {
            Box::pin(conf_release(
                &store,
                &release_leases,
                args.inbox_key,
                args.consumer_group,
                args.lease_alias,
            ))
        }),
        backdate_claim: Box::new(|args| {
            Box::pin(conf_backdate_claim(
                &store,
                args.inbox_key,
                args.consumer_group,
            ))
        }),
    })
    .await?;

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn eventing_conformance_consumer_enrolls_postgres() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let base_id = unique_event_id("eventing-conf-consumer");
    let group = unique_domain("eventing-conf-consumer-group");

    eventconf::assert_consumer_conformance(eventconf::ConsumerConformanceCase {
        ids: eventconf::EventingIds::new(
            base_id.clone(),
            base_id.clone(),
            group.clone(),
            "lease-a",
        ),
        expected_dlx: conf_expected_dlx(),
        duplicate_delivery: Box::new(|| {
            Box::pin(conf_duplicate_delivery(
                &store,
                format!("{base_id}-duplicate"),
                group.clone(),
            ))
        }),
        poison_delivery: Box::new(|| {
            Box::pin(conf_poison_delivery(
                &store,
                format!("{base_id}-poison"),
                group.clone(),
            ))
        }),
        dlx_failure: Box::new(|| {
            Box::pin(conf_dlx_failure(
                &store,
                format!("{base_id}-dlx-failure"),
                group.clone(),
            ))
        }),
        malformed_message_id: Box::new(|| Box::pin(conf_malformed_delivery(&store, group.clone()))),
    })
    .await?;

    store.shutdown().await?;
    Ok(())
}

// ── #1210 inbox_receipts 保留期清理：done 超期被删；claimed + 保留期内 done 存活（anti-vacuity）。──
// sweep 是**全表** DELETE（无 group 过滤），故全局只断言「≥1」+ per-row event_id-scoped 精确断言（跨轮/并发稳健，同 t8）。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
// reason: 集成测试断言 fail-loud（往返结果必 Ok）；item-level carve-out（error-handling.md §Carve-out）。
async fn t_inbox_sweep_removes_old_done_keeps_claimed_and_recent() -> TestResult {
    use consistency::LeaseOutcome;
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let grp = unique_domain("inbox-sweep-grp");
    let inbox = store.inbox();
    let ctx = test_inbox_ctx(&grp);

    // 回拨 receipt 时间锚（2h 前）：done 用 committed_at，claimed 用 claimed_at。
    async fn backdate(store: &PgStore, event_id: &str, grp: &str, age_seconds: i64) -> TestResult {
        let ctx = test_inbox_ctx(grp);
        sqlx::query(
            "UPDATE inbox_receipts \
             SET claimed_at = now() - make_interval(secs => $1), \
                 committed_at = CASE WHEN status = 'done' THEN now() - make_interval(secs => $1) ELSE committed_at END, \
                 updated_at = now() - make_interval(secs => $1) \
             WHERE tenant_id = $2::uuid AND event_id = $3 AND consumer_group = $4",
        )
        .bind(age_seconds)
        .bind(ctx.tenant_id().to_string())
        .bind(event_id)
        .bind(grp)
        .execute(&store.pool)
        .await?;
        Ok(())
    }

    // 1) old done：claim → commit（done）→ 回拨过期。
    let key_old = unique_event_id("inbox-sweep-old");
    let k_old = IdemKey::parse(&key_old).unwrap();
    let lease_old = LeaseToken::mint();
    assert_eq!(
        inbox.try_claim(&ctx, &k_old, &lease_old).await.unwrap(),
        SeenState::Fresh
    );
    assert_eq!(
        inbox.commit(&ctx, &k_old, &lease_old).await.unwrap(),
        LeaseOutcome::Held
    );
    let sweeper = store.inbox_sweeper(crate::delivery_policy::EventDeliveryPolicy::release());
    let retention = sweeper.retention_seconds();
    backdate(&store, &key_old, &grp, i64::try_from(retention + 3600)?).await?;

    // 2) recent done（anti-vacuity）：claim → commit，不回拨。
    let key_recent = unique_event_id("inbox-sweep-recent");
    let k_recent = IdemKey::parse(&key_recent).unwrap();
    let lease_recent = LeaseToken::mint();
    assert_eq!(
        inbox
            .try_claim(&ctx, &k_recent, &lease_recent)
            .await
            .unwrap(),
        SeenState::Fresh
    );
    assert_eq!(
        inbox.commit(&ctx, &k_recent, &lease_recent).await.unwrap(),
        LeaseOutcome::Held
    );

    // 3) claimed（anti-vacuity）：claim 但不 commit，回拨过期——sweep 只删 done，不删 claimed。
    let key_claimed = unique_event_id("inbox-sweep-claimed");
    let k_claimed = IdemKey::parse(&key_claimed).unwrap();
    let lease_claimed = LeaseToken::mint();
    assert_eq!(
        inbox
            .try_claim(&ctx, &k_claimed, &lease_claimed)
            .await
            .unwrap(),
        SeenState::Fresh
    );
    backdate(&store, &key_claimed, &grp, i64::try_from(retention + 3600)?).await?;

    let deleted = sweeper.sweep(retention).await?;
    assert!(deleted >= 1, "至少删除老 done 行: deleted={deleted}");

    let cnt = |event_id: String| {
        let pool = store.pool.clone();
        let grp = grp.clone();
        async move {
            let row: (i64,) = sqlx::query_as(
                "SELECT count(*) FROM inbox_receipts WHERE tenant_id = $1::uuid AND event_id = $2 AND consumer_group = $3",
            )
            .bind(test_tenant().to_string())
            .bind(event_id)
            .bind(grp)
            .fetch_one(&pool)
            .await?;
            Ok::<i64, Box<dyn std::error::Error + Send + Sync>>(row.0)
        }
    };
    assert_eq!(cnt(key_old).await?, 0, "超保留期 done 行必须被 sweep 删");
    assert_eq!(cnt(key_recent).await?, 1, "保留期内 done 行不应被 sweep 删");
    assert_eq!(
        cnt(key_claimed).await?,
        1,
        "claimed 行（非 done）不应被 sweep 删"
    );
    assert_eq!(
        inbox.try_claim(&ctx, &k_old, &LeaseToken::mint()).await?,
        SeenState::Fresh,
        "once the frozen receipt retention window is swept, the same key is Fresh again"
    );

    store.shutdown().await?;
    Ok(())
}

/// 批量 inbox backlog：跨 tenant 聚合，仅返回选中 generated group 的 stale claimed。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
// reason: 集成测试断言 fail-loud（往返结果必 Ok）；item-level carve-out（error-handling.md §Carve-out）。
async fn t_inbox_backlog_counts_only_stale_claimed_for_bound_group() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let specs = generated::event::EVENTS
        .iter()
        .flat_map(|event| event.subscriptions().iter().copied())
        .collect::<Vec<_>>();
    assert!(specs.len() >= 2, "generated topology must be non-vacuous");
    let group_a = specs[0].group();
    let group_b = specs[1].group();
    assert_ne!(
        group_a, group_b,
        "fixture requires two distinct generated groups"
    );
    let selection = InboxBacklogSelection::from_generated(&specs[..1])?;
    let tenant_a = rss_request_context::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
    let tenant_b = rss_request_context::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
    let inbox = store.inbox();
    let backlog = store.inbox_backlog_source();
    let ctx_a = test_inbox_ctx_for(tenant_a, group_a);
    let ctx_b = test_inbox_ctx_for(tenant_b, group_b);

    async fn backdate_claim(
        store: &PgStore,
        event_id: &str,
        group: &str,
        tenant: rss_request_context::TenantId,
        age_seconds: i64,
    ) -> TestResult {
        sqlx::query(
            "UPDATE inbox_receipts SET claimed_at = now() - make_interval(secs => $1), updated_at = now() \
             WHERE tenant_id = $2::uuid AND event_id = $3 AND consumer_group = $4",
        )
        .bind(age_seconds)
        .bind(tenant.to_string())
        .bind(event_id)
        .bind(group)
        .execute(&store.pool)
        .await?;
        Ok(())
    }

    assert_eq!(
        backlog.sample_backlog(&selection).await?,
        InboxBacklogObservation::Active(Vec::new()),
        "无 stale 行时批量函数不伪造 scope"
    );

    let active_key = unique_event_id("inbox-backlog-active");
    let active = IdemKey::parse(&active_key).unwrap();
    let active_lease = LeaseToken::mint();
    assert_eq!(
        inbox
            .try_claim(&ctx_a, &active, &active_lease)
            .await
            .unwrap(),
        SeenState::Fresh
    );

    let done_key = unique_event_id("inbox-backlog-done");
    let done = IdemKey::parse(&done_key).unwrap();
    let done_lease = LeaseToken::mint();
    assert_eq!(
        inbox.try_claim(&ctx_a, &done, &done_lease).await.unwrap(),
        SeenState::Fresh
    );
    assert_eq!(
        inbox.commit(&ctx_a, &done, &done_lease).await.unwrap(),
        consistency::LeaseOutcome::Held
    );
    backdate_claim(&store, &done_key, group_a, tenant_a, 180).await?;

    let other_group_key = unique_event_id("inbox-backlog-other-group");
    let other_group = IdemKey::parse(&other_group_key).unwrap();
    let other_group_lease = LeaseToken::mint();
    assert_eq!(
        inbox
            .try_claim(&ctx_b, &other_group, &other_group_lease)
            .await
            .unwrap(),
        SeenState::Fresh
    );
    backdate_claim(&store, &other_group_key, group_b, tenant_b, 120).await?;

    let InboxBacklogObservation::Active(samples) = backlog.sample_backlog(&selection).await? else {
        panic!("postgres source is always active")
    };
    assert!(
        samples.is_empty(),
        "active、done 与未选 generated group 均排除"
    );

    let stale_key = unique_event_id("inbox-backlog-stale");
    let stale = IdemKey::parse(&stale_key).unwrap();
    let stale_lease = LeaseToken::mint();
    assert_eq!(
        inbox.try_claim(&ctx_a, &stale, &stale_lease).await.unwrap(),
        SeenState::Fresh
    );
    backdate_claim(&store, &stale_key, group_a, tenant_a, 95).await?;

    let older_key = unique_event_id("inbox-backlog-older");
    let older = IdemKey::parse(&older_key).unwrap();
    assert_eq!(
        inbox.try_claim(&ctx_a, &older, &LeaseToken::mint()).await?,
        SeenState::Fresh
    );
    backdate_claim(&store, &older_key, group_a, tenant_a, 150).await?;

    let InboxBacklogObservation::Active(samples) = backlog.sample_backlog(&selection).await? else {
        panic!("postgres source is always active")
    };
    assert_eq!(samples.len(), 1, "selection 只返回一个选中 scope");
    let sample = samples
        .iter()
        .find(|sample| sample.tenant_id() == tenant_a)
        .expect("tenant A scope");
    assert_eq!(
        sample.sample().depth(),
        2,
        "同 scope 的 stale claimed 行聚合计数"
    );
    assert!(
        (145..=165).contains(&sample.sample().oldest_age_seconds()),
        "age 应来自最早 claimed_at 的完整 claim age，而非 updated_at 或逾期时长"
    );

    store.shutdown().await?;
    Ok(())
}

/// Production reader can execute only the narrow aggregate function; raw receipt rows and the
/// writer role cannot bypass that boundary.
#[tokio::test(flavor = "multi_thread")]
async fn t_inbox_backlog_reader_role_is_function_only() -> TestResult {
    let (pg, owner) = connect_pg().await?;
    owner.run_migrations().await?;
    let specs = generated::event::EVENTS
        .iter()
        .flat_map(|event| event.subscriptions().iter().copied())
        .collect::<Vec<_>>();
    assert!(!specs.is_empty(), "generated topology must be non-vacuous");
    let selection = InboxBacklogSelection::from_generated(&specs[..1])?;

    let reader = connect_pg_rss_app_read_role(&pg, &owner).await?;
    assert_eq!(
        reader
            .inbox_backlog_source()
            .sample_backlog(&selection)
            .await?,
        InboxBacklogObservation::Active(Vec::new()),
        "reader executes the fixed aggregate function"
    );
    assert!(
        sqlx::query("SELECT tenant_id FROM public.inbox_receipts LIMIT 1")
            .execute(&reader.pool)
            .await
            .is_err(),
        "reader must not SELECT raw receipt rows"
    );

    let writer = connect_pg_rss_app_role(&pg, &owner).await?;
    let groups = selection
        .groups()
        .iter()
        .map(|group| group.as_str())
        .collect::<Vec<_>>();
    assert!(
        sqlx::query("SELECT * FROM public.rss_inbox_sample_backlog($1::text[])")
            .bind(&groups)
            .execute(&writer.pool)
            .await
            .is_err(),
        "writer must not execute the cross-tenant aggregate function"
    );

    writer.shutdown().await?;
    reader.shutdown().await?;
    owner.shutdown().await?;
    Ok(())
}

/// Inbox sweeper 是全局维护端口：按表清理所有 consumer groups 的超期 done，而不是绑定单个 group。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
// reason: 集成测试断言 fail-loud（往返结果必 Ok）；item-level carve-out（error-handling.md §Carve-out）。
async fn t_inbox_sweeper_removes_old_done_across_consumer_groups() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let groups = [
        unique_domain("inbox-sweep-global-a"),
        unique_domain("inbox-sweep-global-b"),
    ];
    let mut old_done_keys = Vec::new();

    let sweeper = store.inbox_sweeper(crate::delivery_policy::EventDeliveryPolicy::release());
    let retention = sweeper.retention_seconds();
    for group in &groups {
        let inbox = store.inbox();
        let ctx = test_inbox_ctx(group);
        let event_id = unique_event_id("inbox-sweep-global-done");
        let key = IdemKey::parse(&event_id).unwrap();
        let lease = LeaseToken::mint();
        assert_eq!(
            inbox.try_claim(&ctx, &key, &lease).await.unwrap(),
            SeenState::Fresh
        );
        assert_eq!(
            inbox.commit(&ctx, &key, &lease).await.unwrap(),
            consistency::LeaseOutcome::Held
        );
        sqlx::query(
            "UPDATE inbox_receipts SET committed_at = now() - make_interval(secs => $1), updated_at = now() - make_interval(secs => $1) \
             WHERE tenant_id = $2::uuid AND event_id = $3 AND consumer_group = $4",
        )
        .bind(i64::try_from(retention + 3600)?)
        .bind(ctx.tenant_id().to_string())
        .bind(&event_id)
        .bind(group)
        .execute(&store.pool)
        .await?;
        old_done_keys.push((event_id, group.clone()));
    }

    let claimed_event = unique_event_id("inbox-sweep-global-claimed");
    let inbox = store.inbox();
    let claimed_ctx = test_inbox_ctx(&groups[0]);
    let claimed_key = IdemKey::parse(&claimed_event).unwrap();
    assert_eq!(
        inbox
            .try_claim(&claimed_ctx, &claimed_key, &LeaseToken::mint())
            .await
            .unwrap(),
        SeenState::Fresh
    );
    sqlx::query(
        "UPDATE inbox_receipts SET claimed_at = now() - make_interval(secs => $1), updated_at = now() - make_interval(secs => $1) \
         WHERE tenant_id = $2::uuid AND event_id = $3 AND consumer_group = $4",
    )
    .bind(7200i64)
    .bind(claimed_ctx.tenant_id().to_string())
    .bind(&claimed_event)
    .bind(&groups[0])
    .execute(&store.pool)
    .await?;

    let deleted = sweeper.sweep(retention).await?;
    assert!(deleted >= 2, "至少删除两个 group 的 old done 行");

    for (event_id, group) in old_done_keys {
        let ctx = test_inbox_ctx(&group);
        let row: (i64,) = sqlx::query_as(
            "SELECT count(*) FROM inbox_receipts WHERE tenant_id = $1::uuid AND event_id = $2 AND consumer_group = $3",
        )
        .bind(ctx.tenant_id().to_string())
        .bind(event_id)
        .bind(group)
        .fetch_one(&store.pool)
        .await?;
        assert_eq!(row.0, 0, "所有 group 的 old done 都应被全局 sweeper 清理");
    }

    let claimed_row: (i64,) = sqlx::query_as(
        "SELECT count(*) FROM inbox_receipts WHERE tenant_id = $1::uuid AND event_id = $2 AND consumer_group = $3",
    )
    .bind(claimed_ctx.tenant_id().to_string())
    .bind(&claimed_event)
    .bind(&groups[0])
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(
        claimed_row.0, 1,
        "stale claimed 行不应被 retention sweeper 删除"
    );

    store.shutdown().await?;
    Ok(())
}

/// 非法 retain_seconds 必须 fail-closed，且不触发删除。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
// reason: 集成测试断言 fail-loud（往返结果必 Ok）；item-level carve-out（error-handling.md §Carve-out）。
async fn t_inbox_sweeper_invalid_retain_preserves_rows() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let group = unique_domain("inbox-sweep-invalid-retain");
    let inbox = store.inbox();
    let ctx = test_inbox_ctx(&group);
    let event_id = unique_event_id("inbox-sweep-invalid-retain-done");
    let key = IdemKey::parse(&event_id).unwrap();
    let lease = LeaseToken::mint();
    assert_eq!(
        inbox.try_claim(&ctx, &key, &lease).await.unwrap(),
        SeenState::Fresh
    );
    assert_eq!(
        inbox.commit(&ctx, &key, &lease).await.unwrap(),
        consistency::LeaseOutcome::Held
    );
    sqlx::query(
        "UPDATE inbox_receipts SET committed_at = now() - make_interval(secs => $1), updated_at = now() - make_interval(secs => $1) \
         WHERE tenant_id = $2::uuid AND event_id = $3 AND consumer_group = $4",
    )
    .bind(7200i64)
    .bind(ctx.tenant_id().to_string())
    .bind(&event_id)
    .bind(&group)
    .execute(&store.pool)
    .await?;

    let sweeper = store.inbox_sweeper(crate::delivery_policy::EventDeliveryPolicy::release());
    let invalid_retain = sweeper.retention_seconds() - 1;
    let err = match sweeper.sweep(invalid_retain).await {
        Ok(_) => {
            return Err(std::io::Error::other("非冻结策略 retain_seconds 应 fail-closed").into());
        }
        Err(err) => err,
    };
    assert_eq!(err.kind(), consistency::EngineErrorKind::Invariant);

    let row: (i64,) = sqlx::query_as(
        "SELECT count(*) FROM inbox_receipts WHERE tenant_id = $1::uuid AND event_id = $2 AND consumer_group = $3",
    )
    .bind(ctx.tenant_id().to_string())
    .bind(&event_id)
    .bind(&group)
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(row.0, 1, "fail-closed 后 old done 行必须保留");

    store.shutdown().await?;
    Ok(())
}

/// `rss_app` 只能直调读取冻结策略的无参数 SECURITY DEFINER 函数；旧自由 retain 签名不存在。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
// reason: 集成测试断言 fail-loud（往返结果必 Ok）；item-level carve-out（error-handling.md §Carve-out）。
async fn t_inbox_sweeper_rss_app_uses_frozen_policy_without_free_retain_argument() -> TestResult {
    let (pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let app = connect_pg_rss_app_role(&pg, &store).await?;
    let group = unique_domain("inbox-sweep-sql-frozen-policy");
    let inbox = store.inbox();
    let ctx = test_inbox_ctx(&group);
    let event_id = unique_event_id("inbox-sweep-sql-frozen-policy-done");
    let key = IdemKey::parse(&event_id).unwrap();
    let lease = LeaseToken::mint();
    assert_eq!(
        inbox.try_claim(&ctx, &key, &lease).await.unwrap(),
        SeenState::Fresh
    );
    assert_eq!(
        inbox.commit(&ctx, &key, &lease).await.unwrap(),
        consistency::LeaseOutcome::Held
    );
    sqlx::query(
        "UPDATE inbox_receipts SET committed_at = now() - make_interval(secs => $1), updated_at = now() - make_interval(secs => $1) \
         WHERE tenant_id = $2::uuid AND event_id = $3 AND consumer_group = $4",
    )
    .bind(8 * 24 * 3600i64)
    .bind(ctx.tenant_id().to_string())
    .bind(&event_id)
    .bind(&group)
    .execute(&store.pool)
    .await?;

    let old_signature: Option<String> =
        sqlx::query_scalar("SELECT to_regprocedure('rss_sweep_inbox_receipts(bigint)')::text")
            .fetch_one(&store.pool)
            .await?;
    assert_eq!(old_signature, None);
    let deleted: i64 = sqlx::query_scalar("SELECT rss_sweep_inbox_receipts()")
        .fetch_one(&app.pool)
        .await?;
    assert!(deleted >= 1);

    let row: (i64,) = sqlx::query_as(
        "SELECT count(*) FROM inbox_receipts WHERE tenant_id = $1::uuid AND event_id = $2 AND consumer_group = $3",
    )
    .bind(ctx.tenant_id().to_string())
    .bind(&event_id)
    .bind(&group)
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(row.0, 0, "DB 固定策略必须删除超 7 天 old done row");

    app.shutdown().await?;
    store.shutdown().await?;
    Ok(())
}

// ── #1168 DLX archive-before-purge: fixed role/functions and verified receipt gate. ──
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
// reason: integration fixtures use known-valid UUIDs and assert fail-loud.
async fn t_dlx_lifecycle_requires_verified_worm_receipt_before_bounded_purge() -> TestResult {
    use diport::{
        DeadLetterProvenance, DeadLetterRecord, DeadLetterStore, DeadLetterSummary,
        EnvelopeMetadata,
    };

    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    sqlx::query("GRANT rss_dlx_archiver, rss_dlx_verifier, rss_dlx_purger TO CURRENT_USER")
        .execute(&store.pool)
        .await?;

    let catalog: (bool, bool, bool, bool, bool) = sqlx::query_as(
        r#"
        SELECT attribute.attnotnull,
               relation.relrowsecurity,
               relation.relforcerowsecurity,
               has_function_privilege('rss_app', 'rss_dlx_purge_verified()', 'EXECUTE'),
               to_regprocedure('rss_sweep_dead_letter(bigint)') IS NULL
        FROM pg_attribute AS attribute
        JOIN pg_class AS relation ON relation.oid = attribute.attrelid
        WHERE relation.oid = 'dead_letter'::regclass
          AND attribute.attname = 'tenant_id'
        "#,
    )
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(catalog, (true, true, true, false, true));

    let role: (bool, bool, bool) = sqlx::query_as(
        "SELECT rolsuper, rolbypassrls, rolcanlogin FROM pg_roles WHERE rolname = 'rss_dlx_archiver'",
    )
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(role, (false, false, false));

    let hardened_definers: i64 = sqlx::query_scalar(
        r#"
        SELECT count(*)
        FROM pg_catalog.pg_proc AS procedure
        JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = procedure.pronamespace
        WHERE namespace.nspname = 'public'
          AND procedure.proname = ANY(ARRAY[
              'rss_dlx_archive_backlog',
              'rss_dlx_claim_archive_candidates',
              'rss_dlx_settle_archive_retry',
              'rss_dlx_quarantine_archive_candidate',
              'rss_dlx_record_archive_receipt',
              'rss_dlx_purge_verified',
              'rss_dlx_reconcile_expired_receipts',
              'rss_dlx_delete_missing_archive_receipt'
          ])
          AND procedure.prosecdef
          AND 'search_path=pg_catalog, pg_temp' = ANY(procedure.proconfig)
        "#,
    )
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(hardened_definers, 8);

    let tenant = rss_request_context::TenantId::parse(COTX_TENANT_A).unwrap();
    let domain = unique_domain("dlx-lifecycle");
    let writer = store.dead_letter(test_dlx_payload_protector());
    for message in ["verified-old", "unverified-old", "verified-recent"] {
        writer
            .write_dead_letter(DeadLetterRecord::new(
                tenant,
                message,
                DeadLetterProvenance::consumer(domain.as_str(), "dlx-consumer"),
                "contract-x",
                "dlx.topic",
                Some("dlx-consumer".to_string()),
                b"payload".to_vec(),
                DeadLetterSummary::new("safe summary"),
                3,
                EnvelopeMetadata::empty(),
            ))
            .await?;
    }
    sqlx::query(
        "UPDATE dead_letter SET last_attempt_at = now() - interval '31 days' \
         WHERE producer_domain = $1 AND message_id <> 'verified-recent'",
    )
    .bind(&domain)
    .execute(&store.pool)
    .await?;

    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT id::text, message_id FROM dead_letter WHERE producer_domain = $1 ORDER BY message_id",
    )
    .bind(&domain)
    .fetch_all(&store.pool)
    .await?;
    let claims: Vec<(String, String)> = sqlx::query_as(
        "SELECT dead_letter_id::text, archive_claim_token::text FROM rss_dlx_claim_archive_candidates()",
    )
    .fetch_all(&store.pool)
    .await?;
    for (id, _) in rows
        .iter()
        .filter(|(_, message)| message != "unverified-old")
    {
        let claim_token = claims
            .iter()
            .find(|(claimed_id, _)| claimed_id == id)
            .map(|(_, token)| token)
            .ok_or("verified fixture must have a durable archive claim")?;
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_dlx_verifier")
            .execute(&mut *tx)
            .await?;
        let applied: i64 = sqlx::query_scalar(
            r#"
            SELECT rss_dlx_record_archive_receipt(
                $1::uuid, $2::uuid, $3::uuid, 'version-1', decode(repeat('ab', 32), 'hex'),
                'archive-key:1', 'COMPLIANCE', now() + interval '31 days'
            )
            "#,
        )
        .bind(tenant.to_string())
        .bind(id)
        .bind(claim_token)
        .fetch_one(&mut *tx)
        .await?;
        assert_eq!(applied, 1);
        tx.commit().await?;
    }

    let mut tx = store.pool.begin().await?;
    sqlx::query("SET LOCAL ROLE rss_dlx_purger")
        .execute(&mut *tx)
        .await?;
    let deleted: i64 = sqlx::query_scalar("SELECT rss_dlx_purge_verified()")
        .fetch_one(&mut *tx)
        .await?;
    tx.commit().await?;
    assert_eq!(
        deleted, 1,
        "only old + verified + retained HOT row is purgeable"
    );

    let survivors: Vec<String> = sqlx::query_scalar(
        "SELECT message_id FROM dead_letter WHERE producer_domain = $1 ORDER BY message_id",
    )
    .bind(&domain)
    .fetch_all(&store.pool)
    .await?;
    assert_eq!(survivors, vec!["unverified-old", "verified-recent"]);
    let purged_id = rows
        .iter()
        .find(|(_, message)| message == "verified-old")
        .map(|(id, _)| id)
        .ok_or("verified-old fixture must exist")?;
    let retry_after_purge: i64 = sqlx::query_scalar(
        r#"
        SELECT rss_dlx_record_archive_receipt(
            receipt.tenant_id,
            receipt.dead_letter_id,
            'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee'::uuid,
            receipt.object_version_id,
            receipt.checksum_sha256,
            receipt.archive_key_ref,
            receipt.object_lock_mode,
            receipt.object_lock_retain_until
        )
        FROM dead_letter_archive_receipts AS receipt
        WHERE receipt.tenant_id = $1::uuid AND receipt.dead_letter_id = $2::uuid
        "#,
    )
    .bind(tenant.to_string())
    .bind(purged_id)
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(
        retry_after_purge, 0,
        "same receipt retry remains idempotent after another worker purges HOT"
    );
    let receipts: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM dead_letter_archive_receipts WHERE tenant_id = $1::uuid",
    )
    .bind(tenant.to_string())
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(receipts, 2, "purge must retain archive receipt evidence");

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn t_dlx_archiver_pool_gate_requires_exact_role_and_function_only_privileges() -> TestResult {
    let (fixture, store) = connect_pg().await?;
    store.run_migrations().await?;
    sqlx::raw_sql(
        r#"
        ALTER ROLE rss_dlx_archiver LOGIN PASSWORD 'rss_dlx_archiver_test_pw' NOBYPASSRLS NOSUPERUSER;
        ALTER ROLE rss_dlx_verifier LOGIN PASSWORD 'rss_dlx_verifier_test_pw' NOBYPASSRLS NOSUPERUSER;
        ALTER ROLE rss_dlx_purger LOGIN PASSWORD 'rss_dlx_purger_test_pw' NOBYPASSRLS NOSUPERUSER;
        "#,
    )
    .execute(&store.pool)
    .await?;
    let params = fixture.owner_params();
    let config = |username: &str, password: &str| {
        PgConfig::new_for_test_plaintext(
            params.host.clone(),
            params.port,
            params.database.clone(),
            username,
            PgPassword::new(password),
        )
        .with_acquire_timeout(std::time::Duration::from_secs(5))
    };
    let archiver = config("rss_dlx_archiver", "rss_dlx_archiver_test_pw");
    let verifier = config("rss_dlx_verifier", "rss_dlx_verifier_test_pw");
    let purger = config("rss_dlx_purger", "rss_dlx_purger_test_pw");

    crate::PgDlxLifecycleRuntime::preflight_identities(&archiver, &verifier, &purger).await?;
    let runtime = crate::PgDlxLifecycleRuntime::setup(
        &archiver,
        &verifier,
        &purger,
        test_dlx_payload_protector(),
    )
    .await?;
    let _repository = runtime.repository();
    runtime.shutdown().await?;

    sqlx::query("GRANT SELECT ON dead_letter TO rss_dlx_archiver")
        .execute(&store.pool)
        .await?;
    let rejected = crate::PgDlxLifecycleRuntime::setup(
        &archiver,
        &verifier,
        &purger,
        test_dlx_payload_protector(),
    )
    .await;
    assert!(
        matches!(rejected, Err(crate::PgError::DlxLifecyclePrivileges)),
        "table DML must reject archiver pool startup"
    );
    sqlx::query("REVOKE SELECT ON dead_letter FROM rss_dlx_archiver")
        .execute(&store.pool)
        .await?;
    sqlx::query("CREATE ROLE rss_dlx_forbidden_parent NOLOGIN NOSUPERUSER")
        .execute(&store.pool)
        .await?;
    sqlx::query("GRANT rss_dlx_forbidden_parent TO rss_dlx_archiver")
        .execute(&store.pool)
        .await?;
    let rejected =
        crate::PgDlxLifecycleRuntime::preflight_identities(&archiver, &verifier, &purger).await;
    assert!(
        matches!(rejected, Err(crate::PgError::DlxLifecycleBypassRole)),
        "SET ROLE membership must reject pre-migration identity preflight"
    );
    sqlx::raw_sql(
        r#"
        REVOKE rss_dlx_forbidden_parent FROM rss_dlx_archiver;
        DROP ROLE rss_dlx_forbidden_parent;
        CREATE ROLE rss_dlx_forbidden_child NOLOGIN NOSUPERUSER;
        GRANT rss_dlx_archiver TO rss_dlx_forbidden_child;
        "#,
    )
    .execute(&store.pool)
    .await?;
    let rejected =
        crate::PgDlxLifecycleRuntime::preflight_identities(&archiver, &verifier, &purger).await;
    assert!(
        matches!(rejected, Err(crate::PgError::DlxLifecycleBypassRole)),
        "role inheriting archiver must reject identity preflight"
    );
    sqlx::raw_sql(
        r#"
        REVOKE rss_dlx_archiver FROM rss_dlx_forbidden_child;
        DROP ROLE rss_dlx_forbidden_child;
        "#,
    )
    .execute(&store.pool)
    .await?;
    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
// reason: integration fixtures use known-valid UUIDs and exercise opaque durable claims.
async fn t_dlx_poison_candidate_is_quarantined_without_starving_retryable_peer() -> TestResult {
    use diport::{
        DeadLetterProvenance, DeadLetterRecord, DeadLetterStore, DeadLetterSummary,
        DlxLifecycleError, DlxLifecycleOperation, DlxLifecycleReason, DlxLifecycleRepository,
        EnvelopeMetadata,
    };

    let (fixture, store) = connect_pg().await?;
    store.run_migrations().await?;
    sqlx::raw_sql(
        r#"
        ALTER ROLE rss_dlx_archiver LOGIN PASSWORD 'rss_dlx_archiver_test_pw' NOBYPASSRLS NOSUPERUSER;
        ALTER ROLE rss_dlx_verifier LOGIN PASSWORD 'rss_dlx_verifier_test_pw' NOBYPASSRLS NOSUPERUSER;
        ALTER ROLE rss_dlx_purger LOGIN PASSWORD 'rss_dlx_purger_test_pw' NOBYPASSRLS NOSUPERUSER;
        "#,
    )
    .execute(&store.pool)
    .await?;
    let params = fixture.owner_params();
    let config = |username: &str, password: &str| {
        PgConfig::new_for_test_plaintext(
            params.host.clone(),
            params.port,
            params.database.clone(),
            username,
            PgPassword::new(password),
        )
        .with_acquire_timeout(std::time::Duration::from_secs(5))
    };
    let runtime = crate::PgDlxLifecycleRuntime::setup(
        &config("rss_dlx_archiver", "rss_dlx_archiver_test_pw"),
        &config("rss_dlx_verifier", "rss_dlx_verifier_test_pw"),
        &config("rss_dlx_purger", "rss_dlx_purger_test_pw"),
        test_dlx_payload_protector(),
    )
    .await?;
    let repository = runtime.repository();
    let tenant = rss_request_context::TenantId::parse(COTX_TENANT_A).unwrap();
    let domain = unique_domain("dlx-poison-claim");
    let poison_message = unique_event_id("dlx-poison");
    let retryable_message = unique_event_id("dlx-retryable");
    let writer = store.dead_letter(test_dlx_payload_protector());
    for message_id in [&poison_message, &retryable_message] {
        writer
            .write_dead_letter(DeadLetterRecord::new(
                tenant,
                message_id,
                DeadLetterProvenance::consumer(domain.as_str(), "audit"),
                "contract-poison",
                "dlx.poison",
                Some("audit".to_owned()),
                b"payload".to_vec(),
                DeadLetterSummary::new("safe summary"),
                1,
                EnvelopeMetadata::empty(),
            ))
            .await?;
    }
    sqlx::query(
        r#"
        UPDATE dead_letter
        SET replay_capsule = '{"ciphertext":"corrupt"}'::jsonb
        WHERE producer_domain = $1 AND message_id = $2
        "#,
    )
    .bind(&domain)
    .bind(&poison_message)
    .execute(&store.pool)
    .await?;

    let mut claimed = repository.claim_archive_candidates().await?;
    assert_eq!(
        claimed.len(),
        1,
        "poison decode must settle only itself and return the healthy peer"
    );
    assert_eq!(
        claimed[0]
            .candidate()
            .canonical()
            .safe_metadata()
            .message_id(),
        retryable_message
    );
    let poison_state: (bool, bool, i32, Option<String>) = sqlx::query_as(
        r#"
        SELECT archive_quarantined_at IS NOT NULL,
               archive_claim_token IS NULL,
               archive_failure_count,
               archive_last_failure_reason
        FROM dead_letter
        WHERE producer_domain = $1 AND message_id = $2
        "#,
    )
    .bind(&domain)
    .bind(&poison_message)
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(
        poison_state,
        (true, true, 1, Some("key_rejected".to_owned()))
    );

    let first_token: String = sqlx::query_scalar(
        "SELECT archive_claim_token::text FROM dead_letter WHERE producer_domain = $1 AND message_id = $2",
    )
    .bind(&domain)
    .bind(&retryable_message)
    .fetch_one(&store.pool)
    .await?;
    let claimed = claimed.pop().ok_or("healthy claimed candidate missing")?;
    let (claim, _) = claimed.into_parts();
    let settlement = repository
        .settle_archive_failure(
            claim,
            DlxLifecycleError::new(
                DlxLifecycleOperation::PutArchive,
                DlxLifecycleReason::ProviderUnavailable,
            ),
        )
        .await?;
    assert_eq!(settlement, diport::ArchiveClaimSettleOutcome::Applied);
    let retry_state: (bool, bool, i32, Option<String>) = sqlx::query_as(
        r#"
        SELECT archive_claim_token IS NULL,
               archive_next_attempt_at > now(),
               archive_failure_count,
               archive_last_failure_reason
        FROM dead_letter
        WHERE producer_domain = $1 AND message_id = $2
        "#,
    )
    .bind(&domain)
    .bind(&retryable_message)
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(
        retry_state,
        (true, true, 1, Some("provider_unavailable".to_owned()))
    );
    assert!(repository.claim_archive_candidates().await?.is_empty());

    sqlx::query(
        "UPDATE dead_letter SET archive_next_attempt_at = now() - interval '1 second' \
         WHERE producer_domain = $1 AND message_id = $2",
    )
    .bind(&domain)
    .bind(&retryable_message)
    .execute(&store.pool)
    .await?;
    assert_eq!(repository.claim_archive_candidates().await?.len(), 1);
    let second_token: String = sqlx::query_scalar(
        "SELECT archive_claim_token::text FROM dead_letter WHERE producer_domain = $1 AND message_id = $2",
    )
    .bind(&domain)
    .bind(&retryable_message)
    .fetch_one(&store.pool)
    .await?;
    assert_ne!(
        first_token, second_token,
        "reclaim must rotate the opaque CAS token"
    );

    runtime.shutdown().await?;
    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
// reason: integration fixture uses a known-valid tenant UUID.
async fn t_dlx_receipt_retention_boundary_and_hot_row_rearchive_recovery() -> TestResult {
    use diport::{
        DeadLetterProvenance, DeadLetterRecord, DeadLetterStore, DeadLetterSummary,
        EnvelopeMetadata,
    };

    let (_fixture, store) = connect_pg().await?;
    store.run_migrations().await?;
    let tenant = rss_request_context::TenantId::parse(COTX_TENANT_A).unwrap();
    let message_id = unique_event_id("dlx-retention-boundary");
    store
        .dead_letter(test_dlx_payload_protector())
        .write_dead_letter(DeadLetterRecord::new(
            tenant,
            &message_id,
            DeadLetterProvenance::consumer("identity", "audit"),
            "contract-retention-boundary",
            "dlx.retention.boundary",
            Some("audit".to_string()),
            b"payload".to_vec(),
            DeadLetterSummary::new("safe summary"),
            1,
            EnvelopeMetadata::empty(),
        ))
        .await?;
    let id: String = sqlx::query_scalar(
        "SELECT id::text FROM dead_letter WHERE tenant_id = $1::uuid AND message_id = $2",
    )
    .bind(tenant.to_string())
    .bind(&message_id)
    .fetch_one(&store.pool)
    .await?;
    let claim_token: String = sqlx::query_scalar(
        "SELECT archive_claim_token::text FROM rss_dlx_claim_archive_candidates() WHERE dead_letter_id = $1::uuid",
    )
    .bind(&id)
    .fetch_one(&store.pool)
    .await?;

    let exact_boundary: Result<i64, sqlx::Error> = sqlx::query_scalar(
        r#"
        SELECT rss_dlx_record_archive_receipt(
            $1::uuid, $2::uuid, $3::uuid, 'version-1', decode(repeat('ab', 32), 'hex'),
            'archive-key:1', 'COMPLIANCE', now() + interval '30 days'
        )
        "#,
    )
    .bind(tenant.to_string())
    .bind(&id)
    .bind(&claim_token)
    .fetch_one(&store.pool)
    .await;
    assert!(
        exact_boundary.is_err(),
        "exactly 30 days must fail the strict retention boundary"
    );

    let applied: i64 = sqlx::query_scalar(
        r#"
        SELECT rss_dlx_record_archive_receipt(
            $1::uuid, $2::uuid, $3::uuid, 'version-1', decode(repeat('ab', 32), 'hex'),
            'archive-key:1', 'COMPLIANCE',
            now() + interval '30 days 1 second'
        )
        "#,
    )
    .bind(tenant.to_string())
    .bind(&id)
    .bind(&claim_token)
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(applied, 1, "30 days plus epsilon must be accepted");

    sqlx::query(
        r#"
        UPDATE dead_letter_archive_receipts
        SET verified_at = now() - interval '31 days',
            object_lock_retain_until = now() - interval '1 second',
            reconcile_after = now() - interval '1 second'
        WHERE tenant_id = $1::uuid AND dead_letter_id = $2::uuid
        "#,
    )
    .bind(tenant.to_string())
    .bind(&id)
    .execute(&store.pool)
    .await?;
    let expired: (String, String, String, String, Vec<u8>) = sqlx::query_as(
        r#"
        SELECT tenant_id::text, dead_letter_id::text, object_key, object_version_id,
               checksum_sha256
        FROM rss_dlx_reconcile_expired_receipts()
        WHERE tenant_id = $1::uuid AND dead_letter_id = $2::uuid
        "#,
    )
    .bind(tenant.to_string())
    .bind(&id)
    .fetch_one(&store.pool)
    .await?;
    let deleted: i64 = sqlx::query_scalar(
        "SELECT rss_dlx_delete_missing_archive_receipt($1::uuid, $2::uuid, $3, $4, $5)",
    )
    .bind(&expired.0)
    .bind(&expired.1)
    .bind(&expired.2)
    .bind(&expired.3)
    .bind(&expired.4)
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(
        deleted, 1,
        "verified HEAD-missing proof may delete an expired receipt while HOT remains"
    );

    let candidate_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM rss_dlx_claim_archive_candidates() WHERE dead_letter_id = $1::uuid",
    )
    .bind(&id)
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(
        candidate_count, 1,
        "HOT row must become re-archivable after proof CAS"
    );
    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
// reason: integration fixture uses a known-valid tenant UUID.
async fn t_dlx_lifecycle_fixed_batch_boundaries_are_100_1000_100() -> TestResult {
    use diport::{
        DeadLetterProvenance, DeadLetterRecord, DeadLetterStore, DeadLetterSummary,
        EnvelopeMetadata,
    };

    let (_fixture, store) = connect_pg().await?;
    store.run_migrations().await?;
    let tenant = rss_request_context::TenantId::parse(COTX_TENANT_A).unwrap();
    let domain = unique_domain("dlx-fixed-batches");
    let seed_message = unique_event_id("dlx-fixed-seed");
    store
        .dead_letter(test_dlx_payload_protector())
        .write_dead_letter(DeadLetterRecord::new(
            tenant,
            &seed_message,
            DeadLetterProvenance::consumer(domain.as_str(), "audit"),
            "contract-batch",
            "dlx.batch",
            Some("audit".to_string()),
            b"payload".to_vec(),
            DeadLetterSummary::new("safe summary"),
            1,
            EnvelopeMetadata::empty(),
        ))
        .await?;
    sqlx::query(
        r#"
        INSERT INTO dead_letter (
            tenant_id, message_id, producer_domain, consumer_domain, contract_id, topic,
            consumer_group, replay_capsule, replay_capsule_key_ref, payload_len,
            replay_capsule_encoding, metadata_digest, error_summary, num_attempts, source_kind
        )
        SELECT seed.tenant_id,
               seed.message_id,
               seed.producer_domain,
               seed.consumer_domain,
               seed.contract_id,
               seed.topic,
               seed.consumer_group,
               seed.replay_capsule,
               seed.replay_capsule_key_ref,
               seed.payload_len,
               seed.replay_capsule_encoding,
               seed.metadata_digest,
               seed.error_summary,
               seed.num_attempts,
               seed.source_kind
        FROM dead_letter AS seed
        CROSS JOIN generate_series(1, 1000) AS series(value)
        WHERE seed.message_id = $1
        "#,
    )
    .bind(&seed_message)
    .execute(&store.pool)
    .await?;
    sqlx::query(
        "UPDATE dead_letter SET first_attempt_at = now() - interval '31 days', \
         last_attempt_at = now() - interval '31 days' WHERE producer_domain = $1",
    )
    .bind(&domain)
    .execute(&store.pool)
    .await?;

    let candidates: i64 =
        sqlx::query_scalar("SELECT count(*) FROM rss_dlx_claim_archive_candidates()")
            .fetch_one(&store.pool)
            .await?;
    assert_eq!(candidates, 100);
    let backlog: (i64, i64) =
        sqlx::query_as("SELECT pending_depth, oldest_age_seconds FROM rss_dlx_archive_backlog()")
            .fetch_one(&store.pool)
            .await?;
    assert_eq!(backlog.0, 1001);
    assert!(backlog.1 >= 30 * 24 * 3600);

    sqlx::query(
        r#"
        INSERT INTO dead_letter_archive_receipts (
            tenant_id, dead_letter_id, object_key, object_version_id, checksum_sha256,
            archive_key_ref, object_lock_mode, object_lock_retain_until, verified_at,
            reconcile_after
        )
        SELECT tenant_id,
               id,
               'dead-letter/' || id::text || '.v1.enc',
               'version-1',
               decode(repeat('ab', 32), 'hex'),
               'archive-key:1',
               'COMPLIANCE',
               now() + interval '31 days',
               now(),
               now() + interval '31 days'
        FROM dead_letter
        WHERE producer_domain = $1
        "#,
    )
    .bind(&domain)
    .execute(&store.pool)
    .await?;
    let first: i64 = sqlx::query_scalar("SELECT rss_dlx_purge_verified()")
        .fetch_one(&store.pool)
        .await?;
    let second: i64 = sqlx::query_scalar("SELECT rss_dlx_purge_verified()")
        .fetch_one(&store.pool)
        .await?;
    let third: i64 = sqlx::query_scalar("SELECT rss_dlx_purge_verified()")
        .fetch_one(&store.pool)
        .await?;
    assert_eq!((first, second, third), (1000, 1, 0));

    sqlx::query(
        "UPDATE dead_letter_archive_receipts \
         SET verified_at = now() - interval '31 days', \
             object_lock_retain_until = now() - interval '1 second', \
             reconcile_after = now() - interval '1 second' \
         WHERE tenant_id = $1::uuid",
    )
    .bind(tenant.to_string())
    .execute(&store.pool)
    .await?;
    let first_reconcile: Vec<String> =
        sqlx::query_scalar("SELECT dead_letter_id::text FROM rss_dlx_reconcile_expired_receipts()")
            .fetch_all(&store.pool)
            .await?;
    let second_reconcile: Vec<String> =
        sqlx::query_scalar("SELECT dead_letter_id::text FROM rss_dlx_reconcile_expired_receipts()")
            .fetch_all(&store.pool)
            .await?;
    assert_eq!(first_reconcile.len(), 100);
    assert_eq!(second_reconcile.len(), 100);
    assert!(
        first_reconcile
            .iter()
            .all(|id| !second_reconcile.contains(id)),
        "claim-time reconcile_after CAS must advance beyond a permanently Present first page"
    );
    let proof: (String, String, String, String, Vec<u8>) = sqlx::query_as(
        "SELECT tenant_id::text, dead_letter_id::text, object_key, object_version_id, checksum_sha256 \
         FROM rss_dlx_reconcile_expired_receipts() LIMIT 1",
    )
    .fetch_one(&store.pool)
    .await?;
    let stale: i64 = sqlx::query_scalar(
        "SELECT rss_dlx_delete_missing_archive_receipt( \
         $1::uuid, $2::uuid, $3, $4, decode(repeat('cd', 32), 'hex'))",
    )
    .bind(&proof.0)
    .bind(&proof.1)
    .bind(&proof.2)
    .bind(&proof.3)
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(stale, 0, "stale/mismatched proof must not delete receipt");
    let applied: i64 = sqlx::query_scalar(
        "SELECT rss_dlx_delete_missing_archive_receipt($1::uuid, $2::uuid, $3, $4, $5)",
    )
    .bind(&proof.0)
    .bind(&proof.1)
    .bind(&proof.2)
    .bind(&proof.3)
    .bind(&proof.4)
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(applied, 1);
    store.shutdown().await?;
    Ok(())
}

/// T15: 对一个无任何用例写入的专属 domain（`t15-domain`）采样 → 无 scoped sample。
/// domain-scoped 断言：不依赖全表净起点，去掉 `setup_outbox` 全表 DELETE 后仍恒空（#1194）。
#[tokio::test(flavor = "multi_thread")]
async fn t15_sample_backlog_empty_domain_returns_empty() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_outbox(&store).await?;

    let outbox = make_pg_outbox_for_domain(
        &store,
        "t15_domain",
        RecordingPublisher {
            result: || Ok(()),
            calls: Arc::new(Mutex::new(0)),
        },
    );
    // 用 t15 专属 domain（无任何其它用例写入）→ domain-scoped 采样恒空，断言不依赖全表净起点（#1194）。
    let samples = active_backlog(outbox.sample_backlog("t15-domain").await?)?;
    let sample = summarize_backlog(&samples);

    assert!(
        samples.is_empty(),
        "从未观测的专属 domain 不应造假输出 metric scope"
    );
    assert_eq!(
        sample,
        BacklogSample::empty(),
        "无写入的专属 domain 聚合后应为 BacklogSample::empty()"
    );
    assert_eq!(sample.depth(), 0);
    assert_eq!(sample.oldest_age_seconds(), 0);

    store.shutdown().await?;
    Ok(())
}

/// T15b: 已观测 scope 当前无可投递 backlog 时输出 depth=0/age=0；从未出现的 scope 不补 label。
#[tokio::test(flavor = "multi_thread")]
async fn t15b_sample_backlog_observed_scope_without_backlog_returns_zero() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_outbox(&store).await?;

    let domain = unique_domain("t15b-domain");
    let event_id = unique_event_id("t15b-published");
    let event_id_for_write = event_id.clone();
    let domain_for_write = domain.clone();
    store
        .serving_write_fixture::<_, _, sqlx::Error>(test_tenant(), move |cap| {
            let entry = make_entry(&event_id_for_write);
            let env = make_test_env(&domain_for_write, "metrics.zero");
            Box::pin(async move {
                let _outcome = append_outbox(cap, &entry, &env)
                    .await
                    .map_err(test_append_error)?;
                Ok(())
            }) as BoxFuture<'_, Result<(), sqlx::Error>>
        })
        .await?;
    set_outbox_terminal_for_test(&store, &event_id, STATUS_PUBLISHED, 0).await?;

    let outbox = make_pg_outbox_for_domain(
        &store,
        &domain,
        RecordingPublisher {
            result: || Ok(()),
            calls: Arc::new(Mutex::new(0)),
        },
    );
    let samples = active_backlog(outbox.sample_backlog(&domain).await?)?;

    assert_eq!(
        samples.len(),
        1,
        "已观测 scope 当前无 backlog 时仍应输出 zero sample"
    );
    let sample = samples[0].sample();
    assert_eq!(sample.depth(), 0);
    assert_eq!(sample.oldest_age_seconds(), 0);
    assert_eq!(samples[0].subject().tenant_id(), test_tenant());
    assert_eq!(samples[0].subject().contract_id().as_str(), "metrics.zero");

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn t15b_backlog_returns_exact_multi_tenant_contract_map() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_outbox(&store).await?;

    let domain = unique_domain("t15b-scope-map");
    let tenant_a = test_tenant();
    let tenant_b = rss_request_context::TenantId::parse(COTX_TENANT_B)?;
    for (tenant, contract_id, count) in [
        (tenant_a, "metrics.alpha", 2_u8),
        (tenant_a, "metrics.beta", 1_u8),
        (tenant_b, "metrics.alpha", 3_u8),
    ] {
        for index in 0..count {
            let event_id = unique_event_id(&format!("t15b-map-{contract_id}-{index}"));
            let entry = make_entry(&event_id);
            let env = make_test_env_for_tenant(&domain, contract_id, tenant);
            store
                .serving_write_fixture::<_, _, sqlx::Error>(tenant, move |cap| {
                    Box::pin(async move {
                        let _outcome = append_outbox(cap, &entry, &env)
                            .await
                            .map_err(test_append_error)?;
                        Ok(())
                    }) as BoxFuture<'_, Result<(), sqlx::Error>>
                })
                .await?;
        }
    }

    let outbox = make_pg_outbox(&store, || Ok(()));
    let actual: BTreeMap<(String, String), (u64, u64)> =
        active_backlog(outbox.sample_backlog(&domain).await?)?
            .into_iter()
            .map(|sample| {
                (
                    (
                        sample.subject().tenant_id().to_string(),
                        sample.subject().contract_id().as_str().to_string(),
                    ),
                    (sample.sample().depth(), sample.partition_blocked_depth()),
                )
            })
            .collect();
    assert_eq!(
        actual,
        BTreeMap::from([
            ((tenant_a.to_string(), "metrics.alpha".to_string()), (2, 0),),
            ((tenant_a.to_string(), "metrics.beta".to_string()), (1, 0),),
            ((tenant_b.to_string(), "metrics.alpha".to_string()), (3, 0),),
        ]),
        "backlog metrics must preserve the exact tenant/contract partition map"
    );

    store.shutdown().await?;
    Ok(())
}

/// T15c: batch 中任一非法 contract_id 回读到 typed metric subject 时 fail-closed，并回滚整批 claim。
#[tokio::test(flavor = "multi_thread")]
async fn t15c_claim_batch_rolls_back_invalid_persisted_contract_id() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_outbox(&store).await?;

    let domain = unique_domain("t15c-domain");
    let good_event_id = unique_event_id("t15c-good-contract");
    let bad_event_id = unique_event_id("t15c-invalid-contract");
    for event_id in [&good_event_id, &bad_event_id] {
        let entry = make_entry(event_id);
        let env = make_test_env(&domain, "metrics.valid");
        store
            .serving_write_fixture::<_, _, sqlx::Error>(test_tenant(), move |cap| {
                Box::pin(async move {
                    let _outcome = append_outbox(cap, &entry, &env)
                        .await
                        .map_err(test_append_error)?;
                    Ok(())
                }) as BoxFuture<'_, Result<(), sqlx::Error>>
            })
            .await?;
    }
    sqlx::query("UPDATE outbox SET contract_id = 'Metrics.Invalid' WHERE event_id = $1")
        .bind(&bad_event_id)
        .execute(&store.pool)
        .await?;

    let outbox = make_pg_outbox_for_domain(
        &store,
        &domain,
        RecordingPublisher {
            result: || Ok(()),
            calls: Arc::new(Mutex::new(0)),
        },
    );
    let Err(err) = outbox.claim_batch(10).await else {
        return Err("claim_batch must reject invalid persisted contract_id".into());
    };
    assert_eq!(
        err.kind(),
        EngineErrorKind::Invariant,
        "invalid persisted contract_id should be an invariant failure"
    );
    let durable_states: Vec<(String, String, bool, bool)> = sqlx::query_as(
        "SELECT event_id, status, lease_token IS NULL, lease_until IS NULL \
         FROM outbox WHERE event_id = ANY($1) ORDER BY event_id",
    )
    .bind(vec![good_event_id.clone(), bad_event_id.clone()])
    .fetch_all(&store.pool)
    .await?;
    let actual: BTreeMap<_, _> = durable_states
        .into_iter()
        .map(|(event_id, status, token_is_null, deadline_is_null)| {
            (event_id, (status, token_is_null, deadline_is_null))
        })
        .collect();
    let pending = (crate::outbox::STATUS_PENDING.to_string(), true, true);
    assert_eq!(
        actual,
        BTreeMap::from([
            (good_event_id.clone(), pending.clone()),
            (bad_event_id.clone(), pending),
        ]),
        "one bad hydration must roll back both the valid and invalid row claims"
    );

    sqlx::query("UPDATE outbox SET contract_id = 'metrics.valid' WHERE event_id = $1")
        .bind(&bad_event_id)
        .execute(&store.pool)
        .await?;
    let mut reclaimed_ids: Vec<String> = outbox
        .claim_batch(10)
        .await?
        .into_iter()
        .map(|claim| claim.idem_key().as_str().to_string())
        .collect();
    reclaimed_ids.sort();
    let mut expected_ids = vec![good_event_id, bad_event_id];
    expected_ids.sort();
    assert_eq!(
        reclaimed_ids, expected_ids,
        "after repairing the bad row, both rolled-back entries must remain claimable"
    );

    store.shutdown().await?;
    Ok(())
}

/// T16: pending 行计入 depth；published/dlx/**非-stale** publishing 行**不**计
/// （此处 publishing 行 updated_at≈now()、lease 仍有效，属正常 in-flight，正确排除；stale publishing 见 T19）。
#[tokio::test(flavor = "multi_thread")]
async fn t16_sample_backlog_counts_only_pending_rows() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_outbox(&store).await?;

    // per-run 唯一 domain：sample_backlog 按 domain 聚合，跨轮持久库须唯一防旧行计入（#1194 review F1）。
    let domain = unique_domain("t16-domain");

    // seed：1 pending + 1 published + 1 dlx + 1 publishing。
    for (prefix, target_status) in [
        ("t16-pend", "pending"),
        ("t16-pub", "published"),
        ("t16-dlx", "dlx"),
        ("t16-pubing", "publishing"),
    ] {
        let eid = unique_event_id(prefix);
        let entry = make_entry(&eid);
        let domain_for_write = domain.clone();
        store
            .serving_write_fixture::<_, _, sqlx::Error>(test_tenant(), move |cap| {
                let entry = entry.clone();
                let env = make_test_env(&domain_for_write, "c");
                Box::pin(async move {
                    let _outcome = append_outbox(cap, &entry, &env)
                        .await
                        .map_err(test_append_error)?;
                    Ok(())
                }) as BoxFuture<'_, Result<(), sqlx::Error>>
            })
            .await?;
        if target_status != "pending" {
            set_outbox_terminal_for_test(&store, &eid, target_status, 0).await?;
        }
    }

    let outbox = make_pg_outbox(&store, || Ok(()));
    let samples = active_backlog(outbox.sample_backlog(&domain).await?)?;
    let sample = summarize_backlog(&samples);

    assert_eq!(sample.depth(), 1, "仅 pending 行计入 depth，应为 1");

    store.shutdown().await?;
    Ok(())
}

/// T17: oldest_age_seconds 来自最老 pending 行的 created_at（min(created_at)）。
///
/// 插两行，旧行 created_at 人工回拨 10s；断言 oldest_age_seconds >= 10（允许 ±3s 容差）。
#[tokio::test(flavor = "multi_thread")]
async fn t17_sample_backlog_age_tracks_oldest_pending() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_outbox(&store).await?;

    // per-run 唯一 domain：sample_backlog 按 domain 聚合，跨轮持久库须唯一防旧行计入（#1194 review F1）。
    let domain = unique_domain("t17-domain");

    // 先插"新" pending 行（created_at = now()）。
    let new_id = unique_event_id("t17-new");
    let new_domain = domain.clone();
    store
        .serving_write_fixture::<_, _, sqlx::Error>(test_tenant(), move |cap| {
            let entry = make_entry(&new_id);
            let env = make_test_env(&new_domain, "c");
            Box::pin(async move {
                let _outcome = append_outbox(cap, &entry, &env)
                    .await
                    .map_err(test_append_error)?;
                Ok(())
            }) as BoxFuture<'_, Result<(), sqlx::Error>>
        })
        .await?;

    // 插"旧" pending 行，并把 created_at 回拨 10s（模拟 10 秒前写入）。
    let old_id = unique_event_id("t17-old");
    let old_id_for_write = old_id.clone();
    let old_domain = domain.clone();
    store
        .serving_write_fixture::<_, _, sqlx::Error>(test_tenant(), move |cap| {
            let entry = make_entry(&old_id_for_write);
            let env = make_test_env(&old_domain, "c");
            Box::pin(async move {
                let _outcome = append_outbox(cap, &entry, &env)
                    .await
                    .map_err(test_append_error)?;
                Ok(())
            }) as BoxFuture<'_, Result<(), sqlx::Error>>
        })
        .await?;
    sqlx::query(
        "UPDATE outbox SET created_at = now() - make_interval(secs => 10) WHERE event_id = $1",
    )
    .bind(&old_id)
    .execute(&store.pool)
    .await?;

    let outbox = make_pg_outbox(&store, || Ok(()));
    let samples = active_backlog(outbox.sample_backlog(&domain).await?)?;
    let sample = summarize_backlog(&samples);

    assert_eq!(sample.depth(), 2, "两条 pending 行");
    // oldest_age_seconds 须 ≥ 10（旧行回拨 10s）；上限放宽容差至 20s 吸收 testcontainer/CI round-trip
    // 抖动（断言意图是「取最老行龄」而非精确计时，宽上限避免慢 CI 偶发 flaky）。
    assert!(
        sample.oldest_age_seconds() >= 10,
        "oldest_age_seconds 应 ≥ 10，实际={}",
        sample.oldest_age_seconds()
    );
    assert!(
        sample.oldest_age_seconds() < 20,
        "oldest_age_seconds 不应超过 20（宽容差吸收 CI round-trip），实际={}",
        sample.oldest_age_seconds()
    );

    store.shutdown().await?;
    Ok(())
}

/// T18: retry_after > now() 的行**不**计入 depth（与 claim_batch pending 谓词同源）。
#[tokio::test(flavor = "multi_thread")]
async fn t18_sample_backlog_excludes_future_retry_after() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_outbox(&store).await?;

    // per-run 唯一 domain：sample_backlog 按 domain 聚合，跨轮持久库须唯一防旧行计入（#1194 review F1）。
    let domain = unique_domain("t18-domain");

    // seed：1 到期 pending（retry_after IS NULL）+ 1 未到期 pending（retry_after = now()+3600）。
    let due_id = unique_event_id("t18-due");
    let due_domain = domain.clone();
    store
        .serving_write_fixture::<_, _, sqlx::Error>(test_tenant(), move |cap| {
            let entry = make_entry(&due_id);
            let env = make_test_env(&due_domain, "c");
            Box::pin(async move {
                let _outcome = append_outbox(cap, &entry, &env)
                    .await
                    .map_err(test_append_error)?;
                Ok(())
            }) as BoxFuture<'_, Result<(), sqlx::Error>>
        })
        .await?;

    let future_id = unique_event_id("t18-future");
    let future_id_for_write = future_id.clone();
    let future_domain = domain.clone();
    store
        .serving_write_fixture::<_, _, sqlx::Error>(test_tenant(), move |cap| {
            let entry = make_entry(&future_id_for_write);
            let env = make_test_env(&future_domain, "c");
            Box::pin(async move {
                let _outcome = append_outbox(cap, &entry, &env)
                    .await
                    .map_err(test_append_error)?;
                Ok(())
            }) as BoxFuture<'_, Result<(), sqlx::Error>>
        })
        .await?;
    // 把 future 行的 retry_after 置未来（3600s 后），status 保持 pending。
    sqlx::query(
        "UPDATE outbox SET retry_after = now() + make_interval(secs => 3600) WHERE event_id = $1",
    )
    .bind(&future_id)
    .execute(&store.pool)
    .await?;

    let outbox = make_pg_outbox(&store, || Ok(()));
    let samples = active_backlog(outbox.sample_backlog(&domain).await?)?;
    let sample = summarize_backlog(&samples);

    // 仅 due_id（retry_after IS NULL）计入；future_id（retry_after > now()）排除。
    assert_eq!(
        sample.depth(),
        1,
        "retry_after > now() 的行不应计入 depth，应为 1"
    );

    store.shutdown().await?;
    Ok(())
}

/// T19: **stale** publishing（lease 过期、claim_batch 会重捞）计入 depth + oldest-age；**非-stale**
/// publishing（lease 仍有效）排除。锁定 sample_backlog 与 claim_batch 可投递集合同源（#1209 review F1）。
#[tokio::test(flavor = "multi_thread")]
async fn t19_sample_backlog_counts_stale_publishing() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_outbox(&store).await?;

    // per-run 唯一 domain：sample_backlog 按 domain 聚合，跨轮持久库须唯一防旧行计入（#1194 review F1）。
    let domain = unique_domain("t19-domain");
    let lease_ttl = test_relay_lease_ttl_seconds();

    // seed 两行 publishing：stale（lease_until 已过期）+ fresh（lease_until 在将来）。
    for (prefix, stale) in [("t19-stale", true), ("t19-fresh", false)] {
        let eid = unique_event_id(prefix);
        let entry = make_entry(&eid);
        let domain_for_write = domain.clone();
        store
            .serving_write_fixture::<_, _, sqlx::Error>(test_tenant(), move |cap| {
                let entry = entry.clone();
                let env = make_test_env(&domain_for_write, "c");
                Box::pin(async move {
                    let _outcome = append_outbox(cap, &entry, &env)
                        .await
                        .map_err(test_append_error)?;
                    Ok(())
                }) as BoxFuture<'_, Result<(), sqlx::Error>>
            })
            .await?;
        if stale {
            sqlx::query(
                "UPDATE outbox SET status='publishing', lease_token=gen_random_uuid(), \
                 automatic_retry_deadline=COALESCE(automatic_retry_deadline, now()+interval '24 hours'), \
                 created_at=now()-make_interval(secs => $1), updated_at=now()-make_interval(secs => $1), \
                 lease_until=now()-interval '10 seconds' WHERE event_id = $2",
            )
            .bind(lease_ttl + 10)
            .bind(&eid)
            .execute(&store.pool)
            .await?;
        } else {
            sqlx::query(
                "UPDATE outbox SET status='publishing', lease_token=gen_random_uuid(), \
                 automatic_retry_deadline=COALESCE(automatic_retry_deadline, now()+interval '24 hours'), \
                 updated_at=now(), lease_until=now()+interval '60 seconds' WHERE event_id = $1",
            )
            .bind(&eid)
            .execute(&store.pool)
            .await?;
        }
    }

    let outbox = make_pg_outbox(&store, || Ok(()));
    let samples = active_backlog(outbox.sample_backlog(&domain).await?)?;
    let sample = summarize_backlog(&samples);

    // 仅 stale publishing 计入（fresh 行 lease 有效、属正常 in-flight 排除）。
    assert_eq!(
        sample.depth(),
        1,
        "stale publishing 应计入 depth、fresh publishing 排除，应为 1"
    );
    // stale 行存在 ⇒ oldest-age 反映其积压龄（> 0）。
    assert!(
        sample.oldest_age_seconds() > 0,
        "stale publishing 的 oldest_age_seconds 应 > 0，实际={}",
        sample.oldest_age_seconds()
    );

    store.shutdown().await?;
    Ok(())
}
