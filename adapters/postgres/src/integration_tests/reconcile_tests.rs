//! Postgres integration tests — reconcile seam.

use super::support::*;

/// A settings reconcile failure must leave the real postgres receipt claim retryable instead of
/// advancing it to `done`. After the lease becomes stale, the same delivery must be claimable by a
/// new worker token.
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
// reason: fixed integration identifiers are valid and unique_event_id always yields a non-empty key.
async fn settings_consumer_tx_reconcile_failure_keeps_receipt_reclaimable() -> TestResult {
    let (fixture, owner) = connect_pg().await?;
    owner.run_migrations().await?;
    let app = std::sync::Arc::new(connect_pg_rss_app_role(&fixture, &owner).await?);
    let inbox = app.inbox();
    let group = format!("settings-reconcile-failure-{}", uuid::Uuid::new_v4());
    let ctx = InboxReceiptContext::new(
        test_tenant(),
        ConsumerGroup::parse(&group).unwrap(),
        "settings",
        CONFIG_VERSION_CHANGED_TOPIC,
        CONFIG_VERSION_CHANGED_TOPIC,
        "v1",
        TEST_SCHEMA_HASH,
        None,
        None,
    )
    .unwrap();
    let event_id = unique_event_id("settings-reconcile-failure");
    let key = IdemKey::parse(&event_id).unwrap();
    let first_lease = LeaseToken::mint();
    assert_eq!(
        inbox.try_claim(&ctx, &key, &first_lease).await?,
        SeenState::Fresh
    );

    let stores = crate::pool::PgRuntimeStores::from_unverified_for_test(
        std::sync::Arc::clone(&app),
        std::sync::Arc::clone(&app),
    );
    let handler = crate::consumer_tx::PgSettingsConsumerTx::config_version_changed(
        stores.writer_capability(),
        std::sync::Arc::new(settings::ConfigVersionReconciler::test_requeue()),
    );
    let outcome = std::sync::Arc::new(handler)
        .handle(
            diport::Message::new(&event_id, b"{}".to_vec()),
            ctx.clone(),
            key.clone(),
            first_lease,
        )
        .await;
    assert!(
        matches!(
            outcome,
            eventexec::consumer_tx::ConsumerTxOutcome::HandlerTransient
        ),
        "transient reconcile failure must request retry"
    );

    let status: String = sqlx::query_scalar(
        "SELECT status FROM inbox_receipts \
         WHERE tenant_id = $1::uuid AND event_id = $2 AND consumer_group = $3",
    )
    .bind(ctx.tenant_id().to_string())
    .bind(&event_id)
    .bind(&group)
    .fetch_one(&owner.pool)
    .await?;
    assert_eq!(status, "claimed", "failure must not commit Inbox Done");

    sqlx::query(
        "UPDATE inbox_receipts \
         SET claimed_at = now() - make_interval(secs => $1), \
             updated_at = now() - make_interval(secs => $1) \
         WHERE tenant_id = $2::uuid AND event_id = $3 AND consumer_group = $4",
    )
    .bind(crate::inbox::INBOX_LEASE_TTL_SECONDS + 1)
    .bind(ctx.tenant_id().to_string())
    .bind(&event_id)
    .bind(&group)
    .execute(&owner.pool)
    .await?;

    assert_eq!(
        inbox.try_claim(&ctx, &key, &LeaseToken::mint()).await?,
        SeenState::Fresh,
        "stale failed reconcile claim must be reclaimable for redelivery"
    );

    app.shutdown().await?;
    owner.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn reconcile_schema_catalog_after_migrations() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    let tables: Vec<(String,)> = sqlx::query_as(
        "SELECT table_name \
         FROM information_schema.tables \
         WHERE table_schema = 'public' \
           AND table_name IN ( \
             'reconcile_targets', 'reconcile_leases', \
             'reconcile_attempts', 'reconcile_actions', 'reconcile_attempt_results' \
           ) \
         ORDER BY table_name",
    )
    .fetch_all(&store.pool)
    .await?;
    assert_eq!(
        tables,
        vec![
            ("reconcile_actions".to_string(),),
            ("reconcile_attempt_results".to_string(),),
            ("reconcile_attempts".to_string(),),
            ("reconcile_leases".to_string(),),
            ("reconcile_targets".to_string(),),
        ],
        "all reconcile schema tables must exist"
    );

    let target_unique: (String,) = sqlx::query_as(
        "SELECT string_agg(a.attname, ',' ORDER BY k.ord) \
         FROM pg_constraint c \
         JOIN LATERAL unnest(c.conkey) WITH ORDINALITY AS k(attnum, ord) ON true \
         JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = k.attnum \
         WHERE c.conrelid = 'reconcile_targets'::regclass \
           AND c.conname = 'reconcile_targets_tenant_resource_unique'",
    )
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(
        target_unique.0, "tenant_id,reconciler_id,resource_kind,resource_id",
        "target uniqueness must include tenant and full resource identity"
    );
    let disabled_reason: (String, String) = sqlx::query_as(
        "SELECT data_type, is_nullable FROM information_schema.columns \
         WHERE table_schema = 'public' AND table_name = 'reconcile_targets' \
           AND column_name = 'disabled_reason'",
    )
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(disabled_reason, ("text".to_string(), "YES".to_string()));

    let durable_columns: Vec<(String, String, String, Option<String>)> = sqlx::query_as(
        "SELECT table_name, column_name, is_nullable, column_default \
         FROM information_schema.columns \
         WHERE table_schema = 'public' AND ( \
             (table_name = 'reconcile_targets' \
              AND column_name IN ('failure_streak', 'last_result', 'wake_version')) \
             OR (table_name = 'reconcile_attempts' \
                 AND column_name IN ('claimed_failure_streak', 'claimed_wake_version')) \
         ) ORDER BY table_name, column_name",
    )
    .fetch_all(&store.pool)
    .await?;
    assert_eq!(durable_columns.len(), 5);
    for (table, column, nullable, default) in durable_columns {
        match (table.as_str(), column.as_str()) {
            ("reconcile_targets", "failure_streak" | "wake_version") => {
                assert_eq!(nullable, "NO");
                assert_eq!(default.as_deref(), Some("0"));
            }
            ("reconcile_targets", "last_result") => {
                assert_eq!(nullable, "YES");
                assert!(default.is_none());
            }
            ("reconcile_attempts", "claimed_failure_streak" | "claimed_wake_version") => {
                assert_eq!(nullable, "NO");
                assert!(default.is_none(), "future attempts must supply {column}");
            }
            _ => unreachable!("catalog query returned only durable schedule columns"),
        }
    }

    let fk_text: Vec<(String, String)> = sqlx::query_as(
        "SELECT conname, pg_get_constraintdef(oid) \
         FROM pg_constraint \
         WHERE conrelid IN ( \
             'reconcile_leases'::regclass, \
             'reconcile_attempts'::regclass, \
             'reconcile_actions'::regclass, \
             'reconcile_attempt_results'::regclass \
           ) \
           AND contype = 'f' \
         ORDER BY conname",
    )
    .fetch_all(&store.pool)
    .await?;
    let fk_text = fk_text
        .iter()
        .map(|(name, def)| format!("{name}: {def}"))
        .collect::<Vec<_>>()
        .join("\n");
    for needle in [
        "FOREIGN KEY (tenant_id, target_id) REFERENCES reconcile_targets(tenant_id, target_id)",
        "FOREIGN KEY (tenant_id, attempt_id, target_id) REFERENCES reconcile_attempts(tenant_id, attempt_id, target_id)",
    ] {
        assert!(
            fk_text.contains(needle),
            "missing reconcile composite tenant FK `{needle}` in:\n{fk_text}"
        );
    }

    let constraint_text: Vec<(String, String)> = sqlx::query_as(
        "SELECT conname, pg_get_constraintdef(oid) \
         FROM pg_constraint \
         WHERE conrelid IN ( \
             'reconcile_targets'::regclass, \
             'reconcile_leases'::regclass, \
             'reconcile_attempts'::regclass, \
             'reconcile_actions'::regclass, \
             'reconcile_attempt_results'::regclass \
           ) \
         ORDER BY conname",
    )
    .fetch_all(&store.pool)
    .await?;
    let constraint_text = constraint_text
        .iter()
        .map(|(name, def)| format!("{name}: {def}"))
        .collect::<Vec<_>>()
        .join("\n");
    for name in [
        "reconcile_targets_status_valid",
        "reconcile_targets_disabled_reason_valid",
        "reconcile_targets_failure_streak_bounded",
        "reconcile_targets_last_result_closed",
        "reconcile_targets_wake_version_bounded",
        "reconcile_leases_state_valid",
        "reconcile_leases_epoch_non_negative",
        "reconcile_attempts_trigger_kind_valid",
        "reconcile_attempts_claimed_failure_streak_bounded",
        "reconcile_attempts_claimed_wake_version_bounded",
        "reconcile_actions_action_kind_valid",
        "reconcile_actions_result_label_valid",
        "reconcile_attempt_results_result_label_valid",
        "reconcile_attempt_results_error_consistent",
    ] {
        assert!(
            constraint_text.contains(name),
            "missing reconcile CHECK `{name}` in:\n{constraint_text}"
        );
    }

    let index_text: Vec<(String, String)> = sqlx::query_as(
        "SELECT indexname, indexdef \
         FROM pg_indexes \
         WHERE schemaname = 'public' \
           AND tablename = 'reconcile_attempt_results' \
         ORDER BY indexname",
    )
    .fetch_all(&store.pool)
    .await?;
    let index_text = index_text
        .iter()
        .map(|(name, def)| format!("{name}: {def}"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        index_text.contains("idx_reconcile_attempt_results_latest_target")
            && index_text.contains("(tenant_id, target_id, completed_at DESC, attempt_id DESC)"),
        "missing latest-result target covering index:\n{index_text}"
    );

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn reconcile_target_unique_key_includes_tenant_resource() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    let tenant_a = uuid::Uuid::new_v4().to_string();
    let tenant_b = uuid::Uuid::new_v4().to_string();
    let resource = format!("device-{}", uuid::Uuid::new_v4());

    sqlx::query(
        "INSERT INTO reconcile_targets \
         (tenant_id, reconciler_id, resource_kind, resource_id) \
         VALUES ($1::uuid, 'cert-reconciler', 'device-cert', $2)",
    )
    .bind(&tenant_a)
    .bind(&resource)
    .execute(&store.pool)
    .await?;

    let duplicate = sqlx::query(
        "INSERT INTO reconcile_targets \
         (tenant_id, reconciler_id, resource_kind, resource_id) \
         VALUES ($1::uuid, 'cert-reconciler', 'device-cert', $2)",
    )
    .bind(&tenant_a)
    .bind(&resource)
    .execute(&store.pool)
    .await;
    assert!(
        duplicate.is_err(),
        "same tenant/reconciler/resource must be rejected by DB UNIQUE"
    );

    sqlx::query(
        "INSERT INTO reconcile_targets \
         (tenant_id, reconciler_id, resource_kind, resource_id) \
         VALUES ($1::uuid, 'cert-reconciler', 'device-cert', $2)",
    )
    .bind(&tenant_b)
    .bind(&resource)
    .execute(&store.pool)
    .await?;

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn reconcile_lease_cas_rejects_stale_token_and_epoch() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    let tenant = rss_request_context::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
    let resource = format!("lease-device-{}", uuid::Uuid::new_v4());
    let key = ReconcileTargetKey::parse("lease-reconciler", "device", &resource)?;
    let reconcile = store.reconcile();
    let target = reconcile.upsert_target(tenant, &key).await?;

    let first = reconcile
        .acquire_lease(
            tenant,
            target.target_id(),
            "holder-a",
            std::time::Duration::from_secs(60),
        )
        .await?
        .ok_or_else(|| std::io::Error::other("first acquire must win"))?;

    let blocked = reconcile
        .acquire_lease(
            tenant,
            target.target_id(),
            "holder-b",
            std::time::Duration::from_secs(60),
        )
        .await?;
    assert!(blocked.is_none(), "active lease must block another holder");

    sqlx::query(
        "UPDATE reconcile_leases \
         SET acquired_at = now() - make_interval(secs => 120), \
             heartbeat_at = now() - make_interval(secs => 120), \
             expires_at = now() - make_interval(secs => 60) \
         WHERE tenant_id = $1::uuid AND target_id = $2::uuid",
    )
    .bind(tenant.to_string())
    .bind(target.target_id())
    .execute(&store.pool)
    .await?;

    let second = reconcile
        .acquire_lease(
            tenant,
            target.target_id(),
            "holder-b",
            std::time::Duration::from_secs(60),
        )
        .await?
        .ok_or_else(|| std::io::Error::other("expired lease must be reclaimed"))?;
    assert!(
        second.epoch() > first.epoch(),
        "lease reclaim must advance epoch high-water"
    );

    assert_eq!(
        reconcile
            .extend_lease(
                tenant,
                target.target_id(),
                first.lease_token(),
                first.epoch(),
                std::time::Duration::from_secs(60)
            )
            .await?,
        ReconcileLeaseOutcome::Lost,
        "stale token/epoch must not extend a reclaimed lease"
    );
    assert_eq!(
        reconcile
            .release_lease(
                tenant,
                target.target_id(),
                first.lease_token(),
                first.epoch()
            )
            .await?,
        ReconcileLeaseOutcome::Lost,
        "stale token/epoch must not release a reclaimed lease"
    );
    assert_eq!(
        reconcile
            .extend_lease(
                tenant,
                target.target_id(),
                second.lease_token(),
                second.epoch(),
                std::time::Duration::from_secs(60)
            )
            .await?,
        ReconcileLeaseOutcome::Held,
        "current token/epoch must extend"
    );
    assert_eq!(
        reconcile
            .release_lease(
                tenant,
                target.target_id(),
                second.lease_token(),
                second.epoch()
            )
            .await?,
        ReconcileLeaseOutcome::Held,
        "current token/epoch must release"
    );

    let third = reconcile
        .acquire_lease(
            tenant,
            target.target_id(),
            "holder-c",
            std::time::Duration::from_secs(60),
        )
        .await?
        .ok_or_else(|| std::io::Error::other("released lease must be acquirable"))?;
    assert!(
        third.epoch() > second.epoch(),
        "released lease must retain and advance epoch high-water"
    );

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn reconcile_attempts_and_actions_are_append_only_for_rss_app() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    sqlx::query("GRANT rss_app TO CURRENT_USER")
        .execute(&store.pool)
        .await?;

    let tenant = uuid::Uuid::new_v4().to_string();
    let target_id: (String,) = sqlx::query_as(
        "INSERT INTO reconcile_targets \
         (tenant_id, reconciler_id, resource_kind, resource_id) \
         VALUES ($1::uuid, 'append-reconciler', 'device', $2) \
         RETURNING target_id::text",
    )
    .bind(&tenant)
    .bind(format!("append-device-{}", uuid::Uuid::new_v4()))
    .fetch_one(&store.pool)
    .await?;
    let attempt_id: (String,) = sqlx::query_as(
        "INSERT INTO reconcile_attempts \
         (tenant_id, target_id, lease_token, epoch, holder_id, trigger_kind, \
          claimed_failure_streak, claimed_wake_version) \
         VALUES ($1::uuid, $2::uuid, gen_random_uuid(), 1, 'holder-a', 'targeted', 0, 0) \
         RETURNING attempt_id::text",
    )
    .bind(&tenant)
    .bind(&target_id.0)
    .fetch_one(&store.pool)
    .await?;
    let action_id: (String,) = sqlx::query_as(
        "INSERT INTO reconcile_actions \
         (tenant_id, attempt_id, target_id, action_kind, result_label) \
         VALUES ($1::uuid, $2::uuid, $3::uuid, 'noop', 'recorded') \
         RETURNING action_id::text",
    )
    .bind(&tenant)
    .bind(&attempt_id.0)
    .bind(&target_id.0)
    .fetch_one(&store.pool)
    .await?;
    let result_id: (String,) = sqlx::query_as(
        "INSERT INTO reconcile_attempt_results \
         (tenant_id, attempt_id, target_id, result_label, error_kind) \
         VALUES ($1::uuid, $2::uuid, $3::uuid, 'transient', 'transient') \
         RETURNING attempt_id::text",
    )
    .bind(&tenant)
    .bind(&attempt_id.0)
    .bind(&target_id.0)
    .fetch_one(&store.pool)
    .await?;

    for (table, update_sql, delete_sql, id) in [
        (
            "reconcile_attempts",
            "UPDATE reconcile_attempts SET holder_id = 'tampered' \
             WHERE tenant_id = $1::uuid AND attempt_id = $2::uuid",
            "DELETE FROM reconcile_attempts \
             WHERE tenant_id = $1::uuid AND attempt_id = $2::uuid",
            &attempt_id.0,
        ),
        (
            "reconcile_actions",
            "UPDATE reconcile_actions SET result_label = 'transient' \
             WHERE tenant_id = $1::uuid AND action_id = $2::uuid",
            "DELETE FROM reconcile_actions \
             WHERE tenant_id = $1::uuid AND action_id = $2::uuid",
            &action_id.0,
        ),
        (
            "reconcile_attempt_results",
            "UPDATE reconcile_attempt_results SET result_label = 'settled' \
             WHERE tenant_id = $1::uuid AND attempt_id = $2::uuid",
            "DELETE FROM reconcile_attempt_results \
             WHERE tenant_id = $1::uuid AND attempt_id = $2::uuid",
            &result_id.0,
        ),
    ] {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant)
            .execute(&mut *tx)
            .await?;
        let update = sqlx::query(update_sql)
            .bind(&tenant)
            .bind(id)
            .execute(&mut *tx)
            .await;
        assert!(update.is_err(), "rss_app must not UPDATE {table}");
        let delete = sqlx::query(delete_sql)
            .bind(&tenant)
            .bind(id)
            .execute(&mut *tx)
            .await;
        assert!(delete.is_err(), "rss_app must not DELETE {table}");
        tx.rollback().await?;
    }

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn reconcile_scheduler_store_claim_result_action_and_outbox_roundtrip() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    let tenant = rss_request_context::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
    let resource = uuid::Uuid::new_v4().to_string();
    insert_device_desired(&store, tenant, &resource).await?;
    let key = ReconcileTargetKey::parse(
        "identity.device-certificate",
        "device-certificate",
        &resource,
    )?;
    let reconcile = store.reconcile();
    let target = reconcile.upsert_target(tenant, &key).await?;

    ReconcileScheduleStore::pause_target(&reconcile, tenant, target.target_id()).await?;
    let paused = ReconcileScheduleStore::claim_due_targets(
        &reconcile,
        tenant,
        "identity.device-certificate",
        "holder-a",
        reconcile_limit(4),
        std::time::Duration::from_secs(30),
    )
    .await?;
    assert!(paused.is_empty(), "disabled target must not be claimed");

    ReconcileScheduleStore::resume_target(&reconcile, tenant, target.target_id()).await?;
    let claimed = ReconcileScheduleStore::claim_due_targets(
        &reconcile,
        tenant,
        "identity.device-certificate",
        "holder-a",
        reconcile_limit(4),
        std::time::Duration::from_secs(30),
    )
    .await?;
    assert_eq!(claimed.len(), 1, "resumed due target should be claimed");
    let claimed = &claimed[0];
    assert_eq!(claimed.target_id(), target.target_id());
    assert_eq!(claimed.trigger(), AttemptTrigger::Resync);

    let attempt = match ReconcileScheduleStore::append_attempt(&reconcile, claimed, "holder-a")
        .await?
    {
        ScheduleAttemptOutcome::Started(attempt) => attempt,
        ScheduleAttemptOutcome::Lost => {
            return Err(std::io::Error::other("fresh claim should allow append_attempt").into());
        }
    };
    let dispatch_key = format!("reconcile-command-{}", uuid::Uuid::new_v4());
    let command = reviewed_reconcile_command(&store, &attempt, &dispatch_key, 1).await?;
    assert_eq!(
        ReconcileScheduleStore::record_fenced_command(
            &reconcile,
            &attempt,
            ConvergeAction::Create,
            command,
        )
        .await?,
        eventexec::ScheduleActionOutcome::Enqueued,
        "current lease should atomically record action and outbox row"
    );
    let evidence_repo = crate::device_certificate::PgDeviceCertificateRepository::<
        ProductionEligibility,
    >::from_unverified_for_test(&store);
    let evidence_scope = DeviceCertificateScope::for_test(
        tenant,
        ids::DeviceId::parse(attempt.target().resource_id())?,
    );
    assert!(
        evidence_repo
            .load_current_command_evidence_for_test(
                evidence_scope,
                &attempt,
                ExpectedGeneration::try_new(1)?,
            )
            .await?
            .is_none(),
        "queued command is not acknowledged terminal evidence"
    );
    let command_id_for_evidence: String = sqlx::query_scalar(
        "SELECT command_id FROM device_commands \
         WHERE tenant_id=$1::uuid AND device_id=$2::uuid",
    )
    .bind(tenant.to_string())
    .bind(attempt.target().resource_id())
    .fetch_one(&store.pool)
    .await?;
    sqlx::query(
        "UPDATE device_commands SET state='published', version=2, \
         published_at=pg_catalog.transaction_timestamp() \
         WHERE tenant_id=$1::uuid AND command_id=$2",
    )
    .bind(tenant.to_string())
    .bind(&command_id_for_evidence)
    .execute(&store.pool)
    .await?;
    assert!(
        evidence_repo
            .load_current_command_evidence_for_test(
                evidence_scope,
                &attempt,
                ExpectedGeneration::try_new(1)?,
            )
            .await?
            .is_none(),
        "published command is not acknowledged terminal evidence"
    );

    // These structurally valid terminal rows isolate the evidence query from the
    // lifecycle transition matrix. The production trigger is restored before the
    // command is returned to the only accepted `received` state.
    sqlx::query("ALTER TABLE device_commands DISABLE TRIGGER device_command_lifecycle_guard")
        .execute(&store.pool)
        .await?;
    sqlx::query(
        "UPDATE device_commands SET state='rejected', version=3, \
         terminal_at=pg_catalog.transaction_timestamp() \
         WHERE tenant_id=$1::uuid AND command_id=$2",
    )
    .bind(tenant.to_string())
    .bind(&command_id_for_evidence)
    .execute(&store.pool)
    .await?;
    assert!(
        evidence_repo
            .load_current_command_evidence_for_test(
                evidence_scope,
                &attempt,
                ExpectedGeneration::try_new(1)?,
            )
            .await?
            .is_none(),
        "rejected command is not acknowledged terminal evidence"
    );
    sqlx::query(
        "UPDATE device_commands SET state='timed_out', version=3, terminal_at=deadline \
         WHERE tenant_id=$1::uuid AND command_id=$2",
    )
    .bind(tenant.to_string())
    .bind(&command_id_for_evidence)
    .execute(&store.pool)
    .await?;
    assert!(
        evidence_repo
            .load_current_command_evidence_for_test(
                evidence_scope,
                &attempt,
                ExpectedGeneration::try_new(1)?,
            )
            .await?
            .is_none(),
        "timed-out command is not acknowledged terminal evidence"
    );
    sqlx::query(
        "UPDATE device_commands SET state='received', version=3, \
         received_at=pg_catalog.transaction_timestamp(), terminal_at=NULL \
         WHERE tenant_id=$1::uuid AND command_id=$2",
    )
    .bind(tenant.to_string())
    .bind(&command_id_for_evidence)
    .execute(&store.pool)
    .await?;
    sqlx::query("ALTER TABLE device_commands ENABLE TRIGGER device_command_lifecycle_guard")
        .execute(&store.pool)
        .await?;
    assert!(
        evidence_repo
            .load_current_command_evidence_for_test(
                evidence_scope,
                &attempt,
                ExpectedGeneration::try_new(1)?,
            )
            .await?
            .is_some(),
        "received command restores exact audit evidence"
    );
    let original_payload: Vec<u8> =
        sqlx::query_scalar("SELECT payload FROM outbox WHERE event_id=$1")
            .bind(&command_id_for_evidence)
            .fetch_one(&store.pool)
            .await?;
    sqlx::query("UPDATE outbox SET payload='not-json'::bytea WHERE event_id=$1")
        .bind(&command_id_for_evidence)
        .execute(&store.pool)
        .await?;
    assert!(
        evidence_repo
            .load_current_command_evidence_for_test(
                evidence_scope,
                &attempt,
                ExpectedGeneration::try_new(1)?,
            )
            .await
            .is_err(),
        "malformed typed payload cannot restore evidence"
    );
    let mut changed_intent: serde_json::Value = serde_json::from_slice(&original_payload)?;
    changed_intent["intentDigest"] =
        serde_json::Value::String(format!("sha256:{}", "f".repeat(64)));
    sqlx::query("UPDATE outbox SET payload=$2 WHERE event_id=$1")
        .bind(&command_id_for_evidence)
        .bind(serde_json::to_vec(&changed_intent)?)
        .execute(&store.pool)
        .await?;
    assert!(
        evidence_repo
            .load_current_command_evidence_for_test(
                evidence_scope,
                &attempt,
                ExpectedGeneration::try_new(1)?,
            )
            .await
            .is_err(),
        "payload intent drift cannot restore evidence"
    );
    sqlx::query("UPDATE outbox SET payload=$2 WHERE event_id=$1")
        .bind(&command_id_for_evidence)
        .bind(&original_payload)
        .execute(&store.pool)
        .await?;
    sqlx::query(
        "UPDATE reconcile_attempts SET epoch=epoch+1 \
         WHERE tenant_id=$1::uuid AND attempt_id=$2::uuid",
    )
    .bind(tenant.to_string())
    .bind(attempt.attempt_id())
    .execute(&store.pool)
    .await?;
    assert!(
        evidence_repo
            .load_current_command_evidence_for_test(
                evidence_scope,
                &attempt,
                ExpectedGeneration::try_new(1)?,
            )
            .await?
            .is_none(),
        "attempt epoch drift is zero evidence"
    );
    sqlx::query(
        "UPDATE reconcile_attempts SET epoch=epoch-1 \
         WHERE tenant_id=$1::uuid AND attempt_id=$2::uuid",
    )
    .bind(tenant.to_string())
    .bind(attempt.attempt_id())
    .execute(&store.pool)
    .await?;
    assert_eq!(
        ReconcileScheduleStore::record_attempt_result(
            &reconcile,
            &attempt,
            AttemptResult::from_outcome(
                &Outcome::requeue_after(std::time::Duration::from_millis(250)),
                std::time::Duration::from_secs(60),
            ),
        )
        .await?,
        ScheduleResultOutcome::Recorded,
        "current lease should record terminal attempt result"
    );

    let action: (String, String) = sqlx::query_as(
        "SELECT action_kind, result_label \
         FROM reconcile_actions \
         WHERE tenant_id = $1::uuid AND attempt_id = $2::uuid",
    )
    .bind(tenant.to_string())
    .bind(attempt.attempt_id())
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(action, ("create".to_string(), "recorded".to_string()));

    let result: (String, Option<i64>, Option<String>) = sqlx::query_as(
        "SELECT result_label, requeue_after_ms, error_kind \
         FROM reconcile_attempt_results \
         WHERE tenant_id = $1::uuid AND attempt_id = $2::uuid",
    )
    .bind(tenant.to_string())
    .bind(attempt.attempt_id())
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(
        result,
        ("requeue_after".to_string(), Some(250), None),
        "terminal result should live outside reconcile_actions"
    );

    let outbox_count: (i64,) = sqlx::query_as(
        "SELECT count(*) FROM outbox \
         WHERE tenant_id = $1::uuid \
           AND topic = $2 \
           AND metadata->>'subjectId' = $3 \
           AND status = 'pending'",
    )
    .bind(tenant.to_string())
    .bind(generated::command::identity_v1::TOPIC)
    .bind(attempt.target().resource_id())
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(
        outbox_count.0, 1,
        "stable dispatch key must enqueue one outbox row"
    );
    let proof: (bool, bool, i64, i64, String, String, Option<String>) = sqlx::query_as(
        "SELECT command.command_id = outbox.event_id, \
                journal.command_id = command.command_id \
                    AND journal.outbox_event_id = outbox.event_id, \
                command.generation, command.fence_epoch, \
                encode(command.intent_digest, 'hex'), \
                outbox.metadata #>> '{actor,id}', outbox.causation_id \
         FROM device_commands command \
         JOIN outbox ON outbox.tenant_id = command.tenant_id \
                    AND outbox.event_id = command.command_id \
         JOIN command_journal journal ON journal.tenant_id = command.tenant_id \
                                     AND journal.command_id = command.command_id \
         WHERE command.tenant_id = $1::uuid AND command.device_id = $2::uuid",
    )
    .bind(tenant.to_string())
    .bind(attempt.target().resource_id())
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(proof.0, true, "command id must equal outbox event id");
    assert_eq!(
        proof.1, true,
        "journal, command and outbox ids must form one proof"
    );
    assert_eq!(proof.2, 1);
    assert_eq!(proof.3, i64::try_from(attempt.target().epoch())?);
    assert_eq!(proof.4.len(), 64);
    assert_eq!(proof.5, "rss.reconcile.device-certificate.v1");
    assert_eq!(proof.6.as_deref(), Some(attempt.attempt_id()));

    let command_id: String = sqlx::query_scalar(
        "SELECT command_id FROM device_commands \
         WHERE tenant_id = $1::uuid AND device_id = $2::uuid",
    )
    .bind(tenant.to_string())
    .bind(attempt.target().resource_id())
    .fetch_one(&store.pool)
    .await?;
    let maintenance = crate::PgMaintenanceReconcileStore::new(
        &crate::pool::VerifiedPgMaintenanceStore::from_maintenance_store(Arc::new(PgStore {
            pool: store.pool.clone(),
        })),
    );
    let durable = maintenance
        .read_device_command_audit_proof(tenant, &command_id)
        .await?
        .ok_or_else(|| std::io::Error::other("linked audit proof was not restored"))?;
    assert_eq!(durable.tenant(), tenant);
    assert_eq!(durable.device_id().to_string(), resource);
    assert_eq!(durable.desired_generation().get(), 1);
    assert_eq!(
        durable.fence_epoch().get(),
        i64::try_from(attempt.target().epoch())?
    );
    assert_eq!(
        durable.producer_actor_id(),
        "rss.reconcile.device-certificate.v1"
    );
    assert_eq!(durable.attempt_id(), attempt.attempt_id());
    let wrong_tenant = rss_request_context::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
    assert!(
        maintenance
            .read_device_command_audit_proof(wrong_tenant, &command_id)
            .await?
            .is_none(),
        "tenant-scoped audit lookup must not disclose another tenant"
    );

    let original_metadata: serde_json::Value =
        sqlx::query_scalar("SELECT metadata FROM outbox WHERE event_id = $1")
            .bind(&command_id)
            .fetch_one(&store.pool)
            .await?;
    sqlx::query(
        "UPDATE outbox SET metadata = jsonb_set(metadata, '{actor,id}', '\"spoofed\"'::jsonb) \
         WHERE event_id = $1",
    )
    .bind(&command_id)
    .execute(&store.pool)
    .await?;
    assert!(
        maintenance
            .read_device_command_audit_proof(tenant, &command_id)
            .await?
            .is_none(),
        "spoofed actor metadata must break the typed proof"
    );
    sqlx::query("UPDATE outbox SET metadata = $2 WHERE event_id = $1")
        .bind(&command_id)
        .bind(original_metadata)
        .execute(&store.pool)
        .await?;

    let broken_link = format!("command:v2:{}", uuid::Uuid::new_v4());
    let broken = sqlx::query(
        "UPDATE command_journal SET outbox_event_id = $3 \
         WHERE tenant_id = $1::uuid AND command_id = $2",
    )
    .bind(tenant.to_string())
    .bind(&command_id)
    .bind(&broken_link)
    .execute(&store.pool)
    .await
    .expect_err("journal/outbox identity constraint must reject a disconnected audit chain");
    assert_eq!(
        broken
            .as_database_error()
            .and_then(|error| error.code())
            .as_deref(),
        Some("23514")
    );
    assert!(
        maintenance
            .read_device_command_audit_proof(tenant, &command_id)
            .await?
            .is_some(),
        "rejected disconnect must leave the durable proof intact"
    );

    sqlx::query(
        "UPDATE reconcile_targets SET next_run_at=pg_catalog.clock_timestamp() \
         WHERE tenant_id=$1::uuid AND target_id=$2::uuid",
    )
    .bind(tenant.to_string())
    .bind(attempt.target().target_id())
    .execute(&store.pool)
    .await?;
    let restarted_claim = ReconcileScheduleStore::claim_due_targets(
        &reconcile,
        tenant,
        "identity.device-certificate",
        "holder-restarted",
        reconcile_limit(1),
        Duration::from_secs(30),
    )
    .await?
    .pop()
    .ok_or("restarted target was not claimable")?;
    let restarted_attempt = match ReconcileScheduleStore::append_attempt(
        &reconcile,
        &restarted_claim,
        "holder-restarted",
    )
    .await?
    {
        ScheduleAttemptOutcome::Started(attempt) => attempt,
        ScheduleAttemptOutcome::Lost => return Err("restarted attempt lost lease".into()),
    };
    assert!(
        evidence_repo
            .load_current_command_evidence_for_test(
                evidence_scope,
                &restarted_attempt,
                ExpectedGeneration::try_new(1)?,
            )
            .await?
            .is_some(),
        "a new worker attempt can restore the prior current command"
    );
    sqlx::query(
        "UPDATE device_commands SET state='superseded',version=4, \
         terminal_at=pg_catalog.transaction_timestamp() \
         WHERE tenant_id=$1::uuid AND command_id=$2",
    )
    .bind(tenant.to_string())
    .bind(&command_id)
    .execute(&store.pool)
    .await?;
    assert!(
        evidence_repo
            .load_current_command_evidence_for_test(
                evidence_scope,
                &restarted_attempt,
                ExpectedGeneration::try_new(1)?,
            )
            .await?
            .is_none(),
        "superseded commands are never current evidence"
    );
    DevicePolicyLineageFixture::new(
        &store,
        &tenant.to_string(),
        restarted_attempt.target().resource_id(),
    )?
    .advance(2)
    .await?;
    let generation_two = reviewed_reconcile_command_at_generation(
        &store,
        &restarted_attempt,
        "generation-two-evidence",
        2,
        2,
    )
    .await?;
    assert_eq!(
        ReconcileScheduleStore::record_fenced_command(
            &reconcile,
            &restarted_attempt,
            ConvergeAction::Update,
            generation_two,
        )
        .await?,
        ScheduleActionOutcome::Enqueued
    );
    let generation_two_command_id: String = sqlx::query_scalar(
        "SELECT command_id FROM device_commands \
         WHERE tenant_id=$1::uuid AND device_id=$2::uuid AND generation=2",
    )
    .bind(tenant.to_string())
    .bind(restarted_attempt.target().resource_id())
    .fetch_one(&store.pool)
    .await?;
    sqlx::query(
        "UPDATE device_commands SET state='published', version=2, \
         published_at=pg_catalog.transaction_timestamp() \
         WHERE tenant_id=$1::uuid AND command_id=$2",
    )
    .bind(tenant.to_string())
    .bind(&generation_two_command_id)
    .execute(&store.pool)
    .await?;
    sqlx::query(
        "UPDATE device_commands SET state='received', version=3, \
         received_at=pg_catalog.transaction_timestamp() \
         WHERE tenant_id=$1::uuid AND command_id=$2",
    )
    .bind(tenant.to_string())
    .bind(&generation_two_command_id)
    .execute(&store.pool)
    .await?;
    assert!(
        evidence_repo
            .load_current_command_evidence_for_test(
                evidence_scope,
                &restarted_attempt,
                ExpectedGeneration::try_new(2)?,
            )
            .await?
            .is_some(),
        "new desired generation has its own current command evidence"
    );
    DevicePolicyLineageFixture::new(
        &store,
        &tenant.to_string(),
        restarted_attempt.target().resource_id(),
    )?
    .advance(3)
    .await?;
    assert!(
        evidence_repo
            .load_current_command_evidence_for_test(
                evidence_scope,
                &restarted_attempt,
                ExpectedGeneration::try_new(2)?,
            )
            .await?
            .is_none(),
        "desired advance makes the prior generation zero evidence"
    );
    assert_eq!(
        ReconcileScheduleStore::release_lease(&reconcile, restarted_attempt.target()).await?,
        eventexec::reconcile::ScheduleLeaseOutcome::Held
    );

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn reconcile_claim_returns_equal_due_targets_in_target_id_order() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let tenant = rss_request_context::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
    let reconcile = store.reconcile();
    let mut expected = Vec::new();
    for suffix in ["c", "a", "b"] {
        let key = ReconcileTargetKey::parse(
            "ordered-reconciler",
            "device",
            format!("ordered-{suffix}-{}", uuid::Uuid::new_v4()),
        )?;
        expected.push(
            reconcile
                .upsert_target(tenant, &key)
                .await?
                .target_id()
                .to_owned(),
        );
    }
    sqlx::query(
        "UPDATE reconcile_targets SET next_run_at = '2020-01-01 00:00:00+00' \
         WHERE tenant_id = $1::uuid AND reconciler_id = 'ordered-reconciler'",
    )
    .bind(tenant.to_string())
    .execute(&store.pool)
    .await?;
    expected.sort();

    let claimed = ReconcileScheduleStore::claim_due_targets(
        &reconcile,
        tenant,
        "ordered-reconciler",
        "holder-order",
        reconcile_limit(3),
        std::time::Duration::from_secs(30),
    )
    .await?;
    let actual = claimed
        .iter()
        .map(|target| target.target_id().to_owned())
        .collect::<Vec<_>>();
    assert_eq!(actual, expected);

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn reconcile_claim_skips_locked_earliest_target_without_waiting() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let tenant = rss_request_context::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
    let reconcile = store.reconcile();
    let first = reconcile
        .upsert_target(
            tenant,
            &ReconcileTargetKey::parse(
                "skip-locked-reconciler",
                "device",
                &format!("first-{}", uuid::Uuid::new_v4()),
            )?,
        )
        .await?;
    let second = reconcile
        .upsert_target(
            tenant,
            &ReconcileTargetKey::parse(
                "skip-locked-reconciler",
                "device",
                &format!("second-{}", uuid::Uuid::new_v4()),
            )?,
        )
        .await?;
    sqlx::query(
        "UPDATE reconcile_targets SET next_run_at = CASE target_id \
         WHEN $2::uuid THEN '2020-01-01 00:00:00+00'::timestamptz \
         ELSE '2020-01-02 00:00:00+00'::timestamptz END \
         WHERE tenant_id = $1::uuid AND reconciler_id = 'skip-locked-reconciler'",
    )
    .bind(tenant.to_string())
    .bind(first.target_id())
    .execute(&store.pool)
    .await?;
    let mut lock = store.pool.begin().await?;
    sqlx::query(
        "SELECT target_id FROM reconcile_leases \
         WHERE tenant_id = $1::uuid AND target_id = $2::uuid FOR UPDATE",
    )
    .bind(tenant.to_string())
    .bind(first.target_id())
    .fetch_one(&mut *lock)
    .await?;

    let claimed = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        ReconcileScheduleStore::claim_due_targets(
            &reconcile,
            tenant,
            "skip-locked-reconciler",
            "holder-skip",
            reconcile_limit(1),
            std::time::Duration::from_secs(30),
        ),
    )
    .await??;
    assert_eq!(claimed.len(), 1);
    assert_eq!(claimed[0].target_id(), second.target_id());
    lock.rollback().await?;

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn reconcile_two_holders_have_one_claim_winner_for_same_target() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let tenant = rss_request_context::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
    let key = ReconcileTargetKey::parse(
        "single-winner-reconciler",
        "device",
        &format!("winner-{}", uuid::Uuid::new_v4()),
    )?;
    store.reconcile().upsert_target(tenant, &key).await?;
    let holder_a = store.reconcile();
    let holder_b = store.reconcile();
    let (a, b) = tokio::join!(
        ReconcileScheduleStore::claim_due_targets(
            &holder_a,
            tenant,
            "single-winner-reconciler",
            "holder-a",
            reconcile_limit(1),
            std::time::Duration::from_secs(30),
        ),
        ReconcileScheduleStore::claim_due_targets(
            &holder_b,
            tenant,
            "single-winner-reconciler",
            "holder-b",
            reconcile_limit(1),
            std::time::Duration::from_secs(30),
        )
    );
    assert_eq!(a?.len() + b?.len(), 1);

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn reconcile_scheduler_command_dispatch_key_is_tenant_scoped() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    let reconcile = store.reconcile();
    let raw_key = format!("shared-reconcile-command-{}", uuid::Uuid::new_v4());
    let mut dispatched = Vec::new();
    for (tenant, resource) in [
        (
            rss_request_context::TenantId::parse("11111111-1111-1111-1111-111111111111")?,
            uuid::Uuid::new_v4().to_string(),
        ),
        (
            rss_request_context::TenantId::parse("22222222-2222-2222-2222-222222222222")?,
            uuid::Uuid::new_v4().to_string(),
        ),
    ] {
        insert_device_desired(&store, tenant, &resource).await?;
        let key = ReconcileTargetKey::parse(
            "identity.device-certificate",
            "device-certificate",
            &resource,
        )?;
        let _target = reconcile.upsert_target(tenant, &key).await?;
        let claimed = ReconcileScheduleStore::claim_due_targets(
            &reconcile,
            tenant,
            "identity.device-certificate",
            "holder-a",
            reconcile_limit(1),
            std::time::Duration::from_secs(30),
        )
        .await?;
        assert_eq!(claimed.len(), 1);
        let attempt =
            match ReconcileScheduleStore::append_attempt(&reconcile, &claimed[0], "holder-a")
                .await?
            {
                ScheduleAttemptOutcome::Started(attempt) => attempt,
                ScheduleAttemptOutcome::Lost => {
                    return Err(std::io::Error::other("fresh claim should append attempt").into());
                }
            };
        let command = reviewed_reconcile_command(&store, &attempt, &raw_key, 1).await?;
        assert_eq!(
            ReconcileScheduleStore::record_fenced_command(
                &reconcile,
                &attempt,
                ConvergeAction::Create,
                command,
            )
            .await?,
            eventexec::ScheduleActionOutcome::Enqueued
        );
        dispatched.push((tenant, attempt.target().resource_id().to_string()));
    }

    let mut event_ids = Vec::new();
    for (tenant, subject_id) in dispatched {
        let event_id: (String,) = sqlx::query_as(
            "SELECT event_id FROM outbox \
             WHERE tenant_id = $1::uuid AND topic = $2 AND metadata->>'subjectId' = $3",
        )
        .bind(tenant.to_string())
        .bind(generated::command::identity_v1::TOPIC)
        .bind(subject_id)
        .fetch_one(&store.pool)
        .await?;
        assert!(
            !event_id.0.contains(&raw_key),
            "raw idempotency key must not be persisted as the dispatch identity"
        );
        event_ids.push(event_id.0);
    }
    assert_ne!(
        event_ids[0], event_ids[1],
        "same raw key must derive distinct dispatch ids across tenants"
    );

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn reconcile_concurrent_takeover_commits_only_highest_authority_without_residue() -> TestResult
{
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let tenant = rss_request_context::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
    let device = uuid::Uuid::new_v4().to_string();
    insert_device_desired(&store, tenant, &device).await?;
    let reconcile = store.reconcile();
    let target = reconcile
        .upsert_target(
            tenant,
            &ReconcileTargetKey::parse(
                "identity.device-certificate",
                "device-certificate",
                &device,
            )?,
        )
        .await?;
    let first_claim = ReconcileScheduleStore::claim_due_targets(
        &reconcile,
        tenant,
        "identity.device-certificate",
        "holder-old",
        reconcile_limit(1),
        std::time::Duration::from_secs(30),
    )
    .await?
    .pop()
    .ok_or_else(|| std::io::Error::other("old authority was not claimed"))?;
    let old_attempt =
        match ReconcileScheduleStore::append_attempt(&reconcile, &first_claim, "holder-old").await?
        {
            ScheduleAttemptOutcome::Started(attempt) => attempt,
            ScheduleAttemptOutcome::Lost => return Err("old authority lost before setup".into()),
        };
    let old_initial = reviewed_reconcile_command(&store, &old_attempt, "generation-one", 1).await?;
    assert_eq!(
        ReconcileScheduleStore::record_fenced_command(
            &reconcile,
            &old_attempt,
            ConvergeAction::Create,
            old_initial,
        )
        .await?,
        ScheduleActionOutcome::Enqueued
    );
    // Mint while the old authority is still valid; the race exercises durable submission fencing.
    let stale = reviewed_reconcile_command(&store, &old_attempt, "stale-retry", 1).await?;

    DevicePolicyLineageFixture::new(&store, &tenant.to_string(), &device)?
        .advance(2)
        .await?;
    sqlx::query(
        "UPDATE reconcile_leases SET expires_at = acquired_at + interval '1 microsecond' \
         WHERE tenant_id = $1::uuid AND target_id = $2::uuid",
    )
    .bind(tenant.to_string())
    .bind(target.target_id())
    .execute(&store.pool)
    .await?;
    let current_claim = ReconcileScheduleStore::claim_due_targets(
        &reconcile,
        tenant,
        "identity.device-certificate",
        "holder-current",
        reconcile_limit(1),
        std::time::Duration::from_secs(30),
    )
    .await?
    .pop()
    .ok_or_else(|| std::io::Error::other("current authority was not claimed"))?;
    let current_attempt =
        match ReconcileScheduleStore::append_attempt(&reconcile, &current_claim, "holder-current")
            .await?
        {
            ScheduleAttemptOutcome::Started(attempt) => attempt,
            ScheduleAttemptOutcome::Lost => return Err("current authority lost before race".into()),
        };
    let current =
        reviewed_reconcile_command_at_generation(&store, &current_attempt, "generation-two", 2, 2)
            .await?;
    let (stale_result, current_result) =
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            tokio::join!(
                ReconcileScheduleStore::record_fenced_command(
                    &reconcile,
                    &old_attempt,
                    ConvergeAction::Update,
                    stale,
                ),
                ReconcileScheduleStore::record_fenced_command(
                    &reconcile,
                    &current_attempt,
                    ConvergeAction::Update,
                    current,
                )
            )
        })
        .await
        .map_err(|_| std::io::Error::other("scheduler lock order deadlocked during takeover"))?;
    assert_eq!(stale_result?, ScheduleActionOutcome::Lost);
    assert_eq!(current_result?, ScheduleActionOutcome::Enqueued);
    let commands: Vec<(i64, i64, String)> = sqlx::query_as(
        "SELECT generation, fence_epoch, state FROM device_commands \
         WHERE tenant_id = $1::uuid AND device_id = $2::uuid ORDER BY generation, fence_epoch",
    )
    .bind(tenant.to_string())
    .bind(&device)
    .fetch_all(&store.pool)
    .await?;
    assert_eq!(
        commands,
        vec![(1, 1, "superseded".to_owned()), (2, 2, "queued".to_owned())]
    );
    let residue: (i64, i64, i64) = sqlx::query_as(
        "SELECT \
           (SELECT count(*) FROM command_journal WHERE tenant_id = $1::uuid), \
           (SELECT count(*) FROM reconcile_actions WHERE tenant_id = $1::uuid), \
           (SELECT count(*) FROM outbox WHERE tenant_id = $1::uuid)",
    )
    .bind(tenant.to_string())
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(residue, (2, 2, 2));
    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn reconcile_scheduler_faults_roll_back_all_four_command_writes() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    for fault in [
        crate::reconcile::ReconcileCommandWriteFault::Journal,
        crate::reconcile::ReconcileCommandWriteFault::DeviceCommand,
        crate::reconcile::ReconcileCommandWriteFault::Action,
        crate::reconcile::ReconcileCommandWriteFault::Outbox,
    ] {
        let tenant = rss_request_context::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
        let device = uuid::Uuid::new_v4().to_string();
        insert_device_desired(&store, tenant, &device).await?;
        let reconcile = store.reconcile().with_command_write_fault(fault);
        reconcile
            .upsert_target(
                tenant,
                &ReconcileTargetKey::parse(
                    "identity.device-certificate",
                    "device-certificate",
                    &device,
                )?,
            )
            .await?;
        let claim = ReconcileScheduleStore::claim_due_targets(
            &reconcile,
            tenant,
            "identity.device-certificate",
            "fault-holder",
            reconcile_limit(1),
            std::time::Duration::from_secs(30),
        )
        .await?
        .pop()
        .ok_or_else(|| std::io::Error::other("fault target was not claimed"))?;
        let attempt =
            match ReconcileScheduleStore::append_attempt(&reconcile, &claim, "fault-holder").await?
            {
                ScheduleAttemptOutcome::Started(attempt) => attempt,
                ScheduleAttemptOutcome::Lost => return Err("fault attempt lost".into()),
            };
        let command = reviewed_reconcile_command(&store, &attempt, "fault-intent", 1).await?;
        let result = ReconcileScheduleStore::record_fenced_command(
            &reconcile,
            &attempt,
            ConvergeAction::Create,
            command,
        )
        .await;
        assert!(
            matches!(
                result,
                Err(ref error) if error.kind() == ReconcileScheduleErrorKind::Infrastructure
            ),
            "{fault:?} must surface as an infrastructure failure: {result:?}"
        );
        let writes: (i64, i64, i64, i64) = sqlx::query_as(
            "SELECT \
               (SELECT count(*) FROM command_journal WHERE tenant_id = $1::uuid), \
               (SELECT count(*) FROM device_commands WHERE tenant_id = $1::uuid), \
               (SELECT count(*) FROM reconcile_actions WHERE tenant_id = $1::uuid), \
               (SELECT count(*) FROM outbox WHERE tenant_id = $1::uuid)",
        )
        .bind(tenant.to_string())
        .fetch_one(&store.pool)
        .await?;
        assert_eq!(writes, (0, 0, 0, 0), "{fault:?} left a partial write");
    }

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn reconcile_scheduler_supersedes_each_nonterminal_state_and_keeps_terminal_history()
-> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    for old_state in ["queued", "published", "received", "cancelled"] {
        let tenant = rss_request_context::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
        let device = uuid::Uuid::new_v4().to_string();
        insert_device_desired(&store, tenant, &device).await?;
        let reconcile = store.reconcile();
        let target = reconcile
            .upsert_target(
                tenant,
                &ReconcileTargetKey::parse(
                    "identity.device-certificate",
                    "device-certificate",
                    &device,
                )?,
            )
            .await?;
        let first_claim = ReconcileScheduleStore::claim_due_targets(
            &reconcile,
            tenant,
            "identity.device-certificate",
            "holder-a",
            reconcile_limit(1),
            std::time::Duration::from_secs(30),
        )
        .await?
        .pop()
        .ok_or_else(|| std::io::Error::other("first fence was not claimed"))?;
        let first_attempt =
            match ReconcileScheduleStore::append_attempt(&reconcile, &first_claim, "holder-a")
                .await?
            {
                ScheduleAttemptOutcome::Started(attempt) => attempt,
                ScheduleAttemptOutcome::Lost => return Err("first fence lost".into()),
            };
        let first = reviewed_reconcile_command(&store, &first_attempt, "generation-one", 1).await?;
        assert_eq!(
            ReconcileScheduleStore::record_fenced_command(
                &reconcile,
                &first_attempt,
                ConvergeAction::Create,
                first,
            )
            .await?,
            ScheduleActionOutcome::Enqueued
        );

        if matches!(old_state, "published" | "received") {
            sqlx::query(
                "UPDATE device_commands SET state = 'published', version = 2, \
                 published_at = transaction_timestamp() \
                 WHERE tenant_id = $1::uuid AND device_id = $2::uuid",
            )
            .bind(tenant.to_string())
            .bind(&device)
            .execute(&store.pool)
            .await?;
        }
        if old_state == "received" {
            sqlx::query(
                "UPDATE device_commands SET state = 'received', version = 3, \
                 received_at = transaction_timestamp() \
                 WHERE tenant_id = $1::uuid AND device_id = $2::uuid",
            )
            .bind(tenant.to_string())
            .bind(&device)
            .execute(&store.pool)
            .await?;
        }
        if old_state == "cancelled" {
            sqlx::query(
                "UPDATE device_commands SET state = 'cancelled', version = 2, \
                 terminal_at = transaction_timestamp() \
                 WHERE tenant_id = $1::uuid AND device_id = $2::uuid",
            )
            .bind(tenant.to_string())
            .bind(&device)
            .execute(&store.pool)
            .await?;
        }

        DevicePolicyLineageFixture::new(&store, &tenant.to_string(), &device)?
            .advance(2)
            .await?;
        sqlx::query(
            "UPDATE reconcile_leases SET expires_at = acquired_at + interval '1 microsecond' \
             WHERE tenant_id = $1::uuid AND target_id = $2::uuid",
        )
        .bind(tenant.to_string())
        .bind(target.target_id())
        .execute(&store.pool)
        .await?;
        let takeover = ReconcileScheduleStore::claim_due_targets(
            &reconcile,
            tenant,
            "identity.device-certificate",
            "holder-b",
            reconcile_limit(1),
            std::time::Duration::from_secs(30),
        )
        .await?
        .pop()
        .ok_or_else(|| std::io::Error::other("new generation was not claimed"))?;
        let takeover_attempt = match ReconcileScheduleStore::append_attempt(
            &reconcile, &takeover, "holder-b",
        )
        .await?
        {
            ScheduleAttemptOutcome::Started(attempt) => attempt,
            ScheduleAttemptOutcome::Lost => return Err("new generation fence lost".into()),
        };
        let second = reviewed_reconcile_command_at_generation(
            &store,
            &takeover_attempt,
            "generation-two",
            2,
            2,
        )
        .await?;
        assert_eq!(
            ReconcileScheduleStore::record_fenced_command(
                &reconcile,
                &takeover_attempt,
                ConvergeAction::Update,
                second,
            )
            .await?,
            ScheduleActionOutcome::Enqueued
        );

        let rows: Vec<(i64, String)> = sqlx::query_as(
            "SELECT generation, state FROM device_commands \
             WHERE tenant_id = $1::uuid AND device_id = $2::uuid ORDER BY generation",
        )
        .bind(tenant.to_string())
        .bind(&device)
        .fetch_all(&store.pool)
        .await?;
        assert_eq!(rows.len(), 2);
        assert_eq!(
            rows[0],
            (
                1,
                if old_state == "cancelled" {
                    "cancelled"
                } else {
                    "superseded"
                }
                .to_owned()
            )
        );
        assert_eq!(rows[1], (2, "queued".to_owned()));

        let four_writes: (i64, i64, i64, i64) = sqlx::query_as(
            "SELECT \
               (SELECT count(*) FROM command_journal WHERE tenant_id = $1::uuid), \
               (SELECT count(*) FROM device_commands WHERE tenant_id = $1::uuid), \
               (SELECT count(*) FROM reconcile_actions WHERE tenant_id = $1::uuid), \
               (SELECT count(*) FROM outbox WHERE tenant_id = $1::uuid)",
        )
        .bind(tenant.to_string())
        .fetch_one(&store.pool)
        .await?;
        assert_eq!(four_writes, (2, 2, 2, 2));
    }

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn reconcile_scheduler_rejects_same_scoped_key_with_different_payload() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    let tenant = rss_request_context::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
    let resource = uuid::Uuid::new_v4().to_string();
    insert_device_desired(&store, tenant, &resource).await?;
    let key = ReconcileTargetKey::parse(
        "identity.device-certificate",
        "device-certificate",
        &resource,
    )?;
    let reconcile = store.reconcile();
    let _target = reconcile.upsert_target(tenant, &key).await?;
    let claimed = ReconcileScheduleStore::claim_due_targets(
        &reconcile,
        tenant,
        "identity.device-certificate",
        "holder-a",
        reconcile_limit(1),
        std::time::Duration::from_secs(30),
    )
    .await?;
    assert_eq!(claimed.len(), 1);
    let attempt =
        match ReconcileScheduleStore::append_attempt(&reconcile, &claimed[0], "holder-a").await? {
            ScheduleAttemptOutcome::Started(attempt) => attempt,
            ScheduleAttemptOutcome::Lost => {
                return Err(std::io::Error::other("fresh claim should append attempt").into());
            }
        };
    let first = reviewed_reconcile_command(&store, &attempt, "first", 1).await?;
    assert_eq!(
        ReconcileScheduleStore::record_fenced_command(
            &reconcile,
            &attempt,
            ConvergeAction::Create,
            first,
        )
        .await?,
        ScheduleActionOutcome::Enqueued
    );
    let duplicate = reviewed_reconcile_command(&store, &attempt, "first", 1).await?;
    assert_eq!(
        ReconcileScheduleStore::record_fenced_command(
            &reconcile,
            &attempt,
            ConvergeAction::Create,
            duplicate,
        )
        .await?,
        ScheduleActionOutcome::Duplicate,
        "same coordinate and intent must be a write-free duplicate"
    );
    let superseded_conflict =
        reviewed_reconcile_command(&store, &attempt, "superseded-attempt", 1).await?;
    let first_fact: (Vec<u8>, Vec<u8>) = sqlx::query_as(
        "SELECT payload, fact_fingerprint FROM outbox \
         WHERE tenant_id = $1::uuid AND topic = $2 AND metadata->>'subjectId' = $3",
    )
    .bind(tenant.to_string())
    .bind(generated::command::identity_v1::TOPIC)
    .bind(&resource)
    .fetch_one(&store.pool)
    .await?;
    sqlx::query(
        "UPDATE reconcile_leases SET expires_at = acquired_at + interval '1 microsecond' \
         WHERE tenant_id = $1::uuid AND target_id = $2::uuid",
    )
    .bind(tenant.to_string())
    .bind(attempt.target().target_id())
    .execute(&store.pool)
    .await?;
    let takeover_claim = ReconcileScheduleStore::claim_due_targets(
        &reconcile,
        tenant,
        "identity.device-certificate",
        "holder-b",
        reconcile_limit(1),
        std::time::Duration::from_secs(30),
    )
    .await?
    .pop()
    .ok_or_else(|| std::io::Error::other("takeover target was not reclaimed"))?;
    assert!(takeover_claim.epoch() > attempt.target().epoch());
    let takeover_attempt =
        match ReconcileScheduleStore::append_attempt(&reconcile, &takeover_claim, "holder-b")
            .await?
        {
            ScheduleAttemptOutcome::Started(attempt) => attempt,
            ScheduleAttemptOutcome::Lost => return Err("takeover attempt lost fresh lease".into()),
        };
    let second = reviewed_reconcile_command(&store, &takeover_attempt, "second", 1).await?;
    // Emulate a privileged, out-of-band receipt corruption so the command reaches the
    // fact-conflict guard. Normal receipt append is immutable and correctly rejected the
    // changed artifact above; the exact-receipt gate must still preserve quarantine behavior
    // if durable state was tampered with underneath it.
    let second_suffix = format!("{:x}", Sha256::digest(b"second"));
    let second_artifact_id = format!("certificate-artifact-1-{}", &second_suffix[..16]);
    let second_artifact_digest =
        Sha256::digest(format!("certificate-material:{second_artifact_id}").as_bytes());
    sqlx::query(
        "UPDATE device_certificate_authorized_artifacts \
         SET artifact_id = $3, artifact_digest = $4 \
         WHERE tenant_id = $1::uuid AND device_id = $2::uuid AND generation = 1",
    )
    .bind(tenant.to_string())
    .bind(&resource)
    .bind(second_artifact_id)
    .bind(second_artifact_digest.as_slice())
    .execute(&store.pool)
    .await?;
    let conflict = ReconcileScheduleStore::record_fenced_command(
        &reconcile,
        &takeover_attempt,
        ConvergeAction::Create,
        second,
    )
    .await;
    assert!(
        matches!(
            conflict,
            Err(ref error) if error.kind() == ReconcileScheduleErrorKind::FactConflict
        ),
        "same-generation takeover with a changed intent must quarantine: {conflict:?}"
    );

    let action_count: (i64,) = sqlx::query_as(
        "SELECT count(*) FROM reconcile_actions \
         WHERE tenant_id = $1::uuid AND attempt_id = $2::uuid",
    )
    .bind(tenant.to_string())
    .bind(attempt.attempt_id())
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(
        action_count.0, 1,
        "failed command conflict must roll back the action insert"
    );

    let outbox: (Vec<u8>, Vec<u8>) = sqlx::query_as(
        "SELECT payload, fact_fingerprint FROM outbox \
             WHERE tenant_id = $1::uuid AND topic = $2 AND metadata->>'subjectId' = $3",
    )
    .bind(tenant.to_string())
    .bind(generated::command::identity_v1::TOPIC)
    .bind(&resource)
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(
        outbox, first_fact,
        "quarantine must preserve the first fact"
    );

    let target_status: (String,) = sqlx::query_as(
        "SELECT status FROM reconcile_targets WHERE tenant_id = $1::uuid AND target_id = $2::uuid",
    )
    .bind(tenant.to_string())
    .bind(attempt.target().target_id())
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(
        target_status.0, "disabled",
        "fact conflict quarantine must persistently disable automatic reclaim"
    );

    let maintenance = crate::PgMaintenanceReconcileStore::new(
        &crate::pool::VerifiedPgMaintenanceStore::from_maintenance_store(Arc::new(PgStore {
            pool: store.pool.clone(),
        })),
    );
    let capability = OperatorReconcileCapability::issue_for_authorized_operator();
    let inspected = ReconcileOperatorStore::inspect_target(
        &maintenance,
        tenant,
        attempt.target().target_id(),
        capability,
    )
    .await?;
    assert_eq!(inspected.status(), ReconcileTargetStatus::Disabled);
    assert_eq!(
        inspected.disabled_reason(),
        Some(ReconcileQuarantineReason::FactConflict)
    );

    let wrong_tenant = rss_request_context::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
    for result in [
        ReconcileOperatorStore::inspect_target(
            &maintenance,
            wrong_tenant,
            attempt.target().target_id(),
            capability,
        )
        .await,
        ReconcileOperatorStore::resume_target(
            &maintenance,
            wrong_tenant,
            attempt.target().target_id(),
            capability,
        )
        .await,
    ] {
        let Err(error) = result else {
            return Err("cross-tenant reconcile operator access must fail closed".into());
        };
        assert_eq!(error.kind(), ReconcileScheduleErrorKind::Infrastructure);
        assert_eq!(
            error.to_string(),
            "reconcile schedule store operation failed"
        );
    }

    let resumed = ReconcileOperatorStore::resume_target(
        &maintenance,
        tenant,
        attempt.target().target_id(),
        capability,
    )
    .await?;
    assert_eq!(resumed.status(), ReconcileTargetStatus::Active);
    assert_eq!(resumed.disabled_reason(), None);
    let resumed_db: (String, Option<String>, bool) = sqlx::query_as(
        "SELECT status, disabled_reason, next_run_at <= now() \
         FROM reconcile_targets WHERE tenant_id = $1::uuid AND target_id = $2::uuid",
    )
    .bind(tenant.to_string())
    .bind(attempt.target().target_id())
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(resumed_db, ("active".to_string(), None, true));

    sqlx::query(
        "UPDATE reconcile_targets SET wake_version = wake_version + 1, \
         next_run_at = now(), updated_at = now() \
         WHERE tenant_id = $1::uuid AND target_id = $2::uuid",
    )
    .bind(tenant.to_string())
    .bind(attempt.target().target_id())
    .execute(&store.pool)
    .await?;
    assert_eq!(
        ReconcileScheduleStore::record_fenced_command(
            &reconcile,
            &attempt,
            ConvergeAction::Create,
            superseded_conflict,
        )
        .await?,
        ScheduleActionOutcome::Lost,
        "old attempt must not quarantine a target with a newer wake"
    );
    let superseded_status: (String, Option<String>, bool) = sqlx::query_as(
        "SELECT status, disabled_reason, next_run_at <= now() \
         FROM reconcile_targets WHERE tenant_id = $1::uuid AND target_id = $2::uuid",
    )
    .bind(tenant.to_string())
    .bind(attempt.target().target_id())
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(superseded_status, ("active".to_owned(), None, true));

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn reconcile_scheduler_rejects_stale_attempt_writes_after_lease_reclaim() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    let tenant = rss_request_context::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
    let resource = uuid::Uuid::new_v4().to_string();
    insert_device_desired(&store, tenant, &resource).await?;
    let key = ReconcileTargetKey::parse(
        "identity.device-certificate",
        "device-certificate",
        &resource,
    )?;
    let reconcile = store.reconcile();
    let target = reconcile.upsert_target(tenant, &key).await?;

    let first_claim = ReconcileScheduleStore::claim_due_targets(
        &reconcile,
        tenant,
        "identity.device-certificate",
        "holder-a",
        reconcile_limit(1),
        std::time::Duration::from_secs(30),
    )
    .await?;
    assert_eq!(first_claim.len(), 1);
    let stale_claim = &first_claim[0];
    let stale_attempt =
        match ReconcileScheduleStore::append_attempt(&reconcile, stale_claim, "holder-a").await? {
            ScheduleAttemptOutcome::Started(attempt) => attempt,
            ScheduleAttemptOutcome::Lost => {
                return Err(std::io::Error::other("fresh claim should append attempt").into());
            }
        };
    let dispatch_key = format!("stale-reconcile-command-{}", uuid::Uuid::new_v4());
    let stale_command =
        reviewed_reconcile_command(&store, &stale_attempt, &dispatch_key, 1).await?;

    sqlx::query(
        "UPDATE reconcile_leases \
         SET expires_at = acquired_at + interval '1 microsecond' \
         WHERE tenant_id = $1::uuid AND target_id = $2::uuid",
    )
    .bind(tenant.to_string())
    .bind(target.target_id())
    .execute(&store.pool)
    .await?;

    let second_claim = ReconcileScheduleStore::claim_due_targets(
        &reconcile,
        tenant,
        "identity.device-certificate",
        "holder-b",
        reconcile_limit(1),
        std::time::Duration::from_secs(30),
    )
    .await?;
    assert_eq!(second_claim.len(), 1);
    assert_eq!(second_claim[0].trigger(), AttemptTrigger::LeaseReclaim);
    assert!(
        second_claim[0].epoch() > stale_claim.epoch(),
        "lease reclaim must advance target-local epoch"
    );

    assert_eq!(
        ReconcileScheduleStore::record_fenced_command(
            &reconcile,
            &stale_attempt,
            ConvergeAction::Update,
            stale_command,
        )
        .await?,
        eventexec::ScheduleActionOutcome::Lost,
        "stale token+epoch must not record action or outbox"
    );
    assert_eq!(
        ReconcileScheduleStore::record_attempt_result(
            &reconcile,
            &stale_attempt,
            AttemptResult::from_panic(std::time::Duration::from_secs(1)),
        )
        .await?,
        ScheduleResultOutcome::Lost,
        "stale token+epoch must not record terminal result"
    );

    let action_count: (i64,) = sqlx::query_as(
        "SELECT count(*) FROM reconcile_actions \
         WHERE tenant_id = $1::uuid AND attempt_id = $2::uuid",
    )
    .bind(tenant.to_string())
    .bind(stale_attempt.attempt_id())
    .fetch_one(&store.pool)
    .await?;
    let result_count: (i64,) = sqlx::query_as(
        "SELECT count(*) FROM reconcile_attempt_results \
         WHERE tenant_id = $1::uuid AND attempt_id = $2::uuid",
    )
    .bind(tenant.to_string())
    .bind(stale_attempt.attempt_id())
    .fetch_one(&store.pool)
    .await?;
    let outbox_count: (i64,) = sqlx::query_as(
        "SELECT count(*) FROM outbox \
         WHERE tenant_id = $1::uuid AND topic = $2 AND metadata->>'subjectId' = $3",
    )
    .bind(tenant.to_string())
    .bind(generated::command::identity_v1::TOPIC)
    .bind(&dispatch_key)
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(action_count.0, 0);
    assert_eq!(result_count.0, 0);
    assert_eq!(outbox_count.0, 0);

    assert_eq!(
        ReconcileScheduleStore::release_lease(&reconcile, &second_claim[0]).await?,
        eventexec::ScheduleLeaseOutcome::Held
    );

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn reconcile_result_uses_persisted_attempt_evidence_not_forged_claim_snapshot() -> TestResult
{
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let tenant = rss_request_context::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
    let key = ReconcileTargetKey::parse(
        "attempt-evidence-reconciler",
        "device",
        format!("attempt-evidence-{}", uuid::Uuid::new_v4()),
    )?;
    let reconcile = store.reconcile();
    let target = reconcile.upsert_target(tenant, &key).await?;
    let claimed = ReconcileScheduleStore::claim_due_targets(
        &reconcile,
        tenant,
        "attempt-evidence-reconciler",
        "holder-a",
        reconcile_limit(1),
        std::time::Duration::from_secs(30),
    )
    .await?
    .pop()
    .ok_or_else(|| std::io::Error::other("evidence target was not claimed"))?;
    let real =
        match ReconcileScheduleStore::append_attempt(&reconcile, &claimed, "holder-a").await? {
            ScheduleAttemptOutcome::Started(attempt) => attempt,
            ScheduleAttemptOutcome::Lost => return Err("evidence attempt lost lease".into()),
        };
    let forged_target = ClaimedTarget::restore(ClaimedTargetRestore {
        tenant,
        target_id: claimed.target_id().to_owned(),
        reconciler_id: claimed.reconciler_id().to_owned(),
        resource_kind: claimed.resource_kind().to_owned(),
        resource_id: claimed.resource_id().to_owned(),
        lease_token: claimed.lease_token().to_owned(),
        epoch: claimed.epoch(),
        failure_streak: FailureStreak::restore(99),
        wake_version: WakeVersion::try_new(99)?,
        trigger: claimed.trigger(),
    });
    let forged = ReconcileAttempt::new(real.attempt_id(), forged_target);
    assert_eq!(
        ReconcileScheduleStore::record_attempt_result(
            &reconcile,
            &forged,
            AttemptResult::from_panic(std::time::Duration::from_secs(30)),
        )
        .await?,
        ScheduleResultOutcome::Recorded,
        "persisted attempt wake, not the caller snapshot, owns the result fence"
    );
    let schedule: (i64, i64, i64) = sqlx::query_as(
        "SELECT target.failure_streak, attempt.claimed_failure_streak, \
                attempt.claimed_wake_version \
         FROM reconcile_targets target JOIN reconcile_attempts attempt USING (tenant_id, target_id) \
         WHERE target.tenant_id = $1::uuid AND target.target_id = $2::uuid",
    )
    .bind(tenant.to_string())
    .bind(target.target_id())
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(schedule, (1, 0, 0));

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn reconcile_permanent_and_invariant_results_persist_quarantine_without_hot_loop()
-> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let tenant = rss_request_context::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
    let reconcile = store.reconcile();
    for (suffix, label, error_kind, schedule, reason) in [
        (
            "permanent",
            consistency::ReconcileResultLabel::Permanent,
            ReconcileActionErrorKind::Permanent,
            AttemptSchedule::Quarantine(ReconcileQuarantineReason::PermanentFailure),
            "permanent_failure",
        ),
        (
            "invariant",
            consistency::ReconcileResultLabel::Invariant,
            ReconcileActionErrorKind::Invariant,
            AttemptSchedule::Quarantine(ReconcileQuarantineReason::InvariantViolation),
            "invariant_violation",
        ),
    ] {
        let key = ReconcileTargetKey::parse(
            "quarantine-reconciler",
            "device",
            format!("quarantine-{suffix}-{}", uuid::Uuid::new_v4()),
        )?;
        let target = reconcile.upsert_target(tenant, &key).await?;
        let claimed = ReconcileScheduleStore::claim_due_targets(
            &reconcile,
            tenant,
            "quarantine-reconciler",
            &format!("holder-{suffix}"),
            reconcile_limit(1),
            std::time::Duration::from_secs(30),
        )
        .await?
        .pop()
        .ok_or_else(|| std::io::Error::other("quarantine target was not claimed"))?;
        let attempt = match ReconcileScheduleStore::append_attempt(
            &reconcile,
            &claimed,
            &format!("holder-{suffix}"),
        )
        .await?
        {
            ScheduleAttemptOutcome::Started(attempt) => attempt,
            ScheduleAttemptOutcome::Lost => return Err("quarantine attempt lost lease".into()),
        };
        assert_eq!(
            reconcile
                .append_attempt_result(
                    tenant,
                    claimed.lease_token(),
                    claimed.epoch(),
                    ReconcileAttemptResultInsert {
                        attempt_id: attempt.attempt_id(),
                        target_id: target.target_id(),
                        result: label,
                        requeue_after: None,
                        error_kind: Some(error_kind),
                        schedule,
                    },
                )
                .await?,
            ScheduleResultOutcome::Recorded
        );
        let state: (String, Option<String>, String) = sqlx::query_as(
            "SELECT target.status, target.disabled_reason, lease.state \
             FROM reconcile_targets target JOIN reconcile_leases lease USING (tenant_id, target_id) \
             WHERE target.tenant_id = $1::uuid AND target.target_id = $2::uuid",
        )
        .bind(tenant.to_string())
        .bind(target.target_id())
        .fetch_one(&store.pool)
        .await?;
        assert_eq!(
            state,
            (
                "disabled".to_owned(),
                Some(reason.to_owned()),
                "free".to_owned()
            )
        );
        assert!(
            ReconcileScheduleStore::claim_due_targets(
                &reconcile,
                tenant,
                "quarantine-reconciler",
                "holder-no-hotloop",
                reconcile_limit(10),
                std::time::Duration::from_secs(30),
            )
            .await?
            .iter()
            .all(|claim| claim.target_id() != target.target_id())
        );
    }

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn reconcile_scheduler_claims_requeue_after_attempt_as_requeue_trigger() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    let tenant = rss_request_context::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
    let resource = format!("requeue-device-{}", uuid::Uuid::new_v4());
    let key = ReconcileTargetKey::parse("requeue-reconciler", "device", &resource)?;
    let reconcile = store.reconcile();
    let target = reconcile.upsert_target(tenant, &key).await?;

    let first_claim = ReconcileScheduleStore::claim_due_targets(
        &reconcile,
        tenant,
        "requeue-reconciler",
        "holder-a",
        reconcile_limit(1),
        std::time::Duration::from_secs(30),
    )
    .await?;
    assert_eq!(first_claim.len(), 1);
    let attempt =
        match ReconcileScheduleStore::append_attempt(&reconcile, &first_claim[0], "holder-a")
            .await?
        {
            ScheduleAttemptOutcome::Started(attempt) => attempt,
            ScheduleAttemptOutcome::Lost => {
                return Err(std::io::Error::other("fresh claim should append attempt").into());
            }
        };
    assert_eq!(
        ReconcileScheduleStore::record_attempt_result(
            &reconcile,
            &attempt,
            AttemptResult::from_outcome(
                &Outcome::requeue_after(std::time::Duration::ZERO),
                std::time::Duration::from_secs(60),
            ),
        )
        .await?,
        ScheduleResultOutcome::Recorded
    );

    let requeue_claim = ReconcileScheduleStore::claim_due_targets(
        &reconcile,
        tenant,
        "requeue-reconciler",
        "holder-b",
        reconcile_limit(1),
        std::time::Duration::from_secs(30),
    )
    .await?;
    assert_eq!(requeue_claim.len(), 1);
    assert_eq!(requeue_claim[0].target_id(), target.target_id());
    assert_eq!(requeue_claim[0].trigger(), AttemptTrigger::Requeue);

    assert_eq!(
        ReconcileScheduleStore::release_lease(&reconcile, &requeue_claim[0]).await?,
        eventexec::ScheduleLeaseOutcome::Held
    );

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn reconcile_scheduler_persists_retry_streak_across_store_restart_and_resets_on_success()
-> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let tenant = rss_request_context::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
    let resource = format!("retry-device-{}", uuid::Uuid::new_v4());
    let key = ReconcileTargetKey::parse("retry-reconciler", "device", &resource)?;
    let reconcile = store.reconcile();
    let target = reconcile.upsert_target(tenant, &key).await?;
    let first = ReconcileScheduleStore::claim_due_targets(
        &reconcile,
        tenant,
        "retry-reconciler",
        "holder-a",
        reconcile_limit(1),
        std::time::Duration::from_secs(30),
    )
    .await?
    .pop()
    .ok_or_else(|| std::io::Error::other("initial retry target was not claimed"))?;
    assert_eq!(first.failure_streak().get(), 0);
    let first_attempt =
        match ReconcileScheduleStore::append_attempt(&reconcile, &first, "holder-a").await? {
            ScheduleAttemptOutcome::Started(attempt) => attempt,
            ScheduleAttemptOutcome::Lost => return Err("initial retry attempt lost lease".into()),
        };
    assert_eq!(
        ReconcileScheduleStore::record_attempt_result(
            &reconcile,
            &first_attempt,
            AttemptResult::from_panic(std::time::Duration::from_secs(30)),
        )
        .await?,
        ScheduleResultOutcome::Recorded
    );

    drop(reconcile);
    let restarted = store.reconcile();
    assert!(
        ReconcileScheduleStore::claim_due_targets(
            &restarted,
            tenant,
            "retry-reconciler",
            "holder-too-early",
            reconcile_limit(1),
            std::time::Duration::from_secs(30),
        )
        .await?
        .is_empty(),
        "persisted nonzero backoff must survive store reconstruction"
    );
    let next_run_is_future: bool = sqlx::query_scalar(
        "SELECT next_run_at > now() FROM reconcile_targets \
         WHERE tenant_id = $1::uuid AND target_id = $2::uuid",
    )
    .bind(tenant.to_string())
    .bind(target.target_id())
    .fetch_one(&store.pool)
    .await?;
    assert!(next_run_is_future);
    sqlx::query(
        "UPDATE reconcile_targets SET next_run_at = now(), updated_at = now() \
         WHERE tenant_id = $1::uuid AND target_id = $2::uuid",
    )
    .bind(tenant.to_string())
    .bind(target.target_id())
    .execute(&store.pool)
    .await?;
    let second = ReconcileScheduleStore::claim_due_targets(
        &restarted,
        tenant,
        "retry-reconciler",
        "holder-b",
        reconcile_limit(1),
        std::time::Duration::from_secs(30),
    )
    .await?
    .pop()
    .ok_or_else(|| std::io::Error::other("durable retry target was not reclaimed"))?;
    assert_eq!(second.target_id(), target.target_id());
    assert_eq!(second.failure_streak().get(), 1);
    let second_attempt =
        match ReconcileScheduleStore::append_attempt(&restarted, &second, "holder-b").await? {
            ScheduleAttemptOutcome::Started(attempt) => attempt,
            ScheduleAttemptOutcome::Lost => return Err("restarted retry attempt lost lease".into()),
        };
    assert_eq!(
        ReconcileScheduleStore::record_attempt_result(
            &restarted,
            &second_attempt,
            AttemptResult::from_outcome(&Outcome::settled(), std::time::Duration::from_secs(60),),
        )
        .await?,
        ScheduleResultOutcome::Recorded
    );
    let schedule: (i64, Option<String>, String) = sqlx::query_as(
        "SELECT failure_streak, last_result, lease.state \
         FROM reconcile_targets target \
         JOIN reconcile_leases lease USING (tenant_id, target_id) \
         WHERE target.tenant_id = $1::uuid AND target.target_id = $2::uuid",
    )
    .bind(tenant.to_string())
    .bind(target.target_id())
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(schedule, (0, Some("settled".to_owned()), "free".to_owned()));

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn reconcile_wake_supersedes_inflight_result_and_exact_or_periodic_claims_targeted()
-> TestResult {
    let (fixture, store) = connect_pg().await?;
    store.run_migrations().await?;
    let writer = crate::test_pg::connect_pg_rss_app_role(&fixture, &store).await?;
    let reader = crate::test_pg::connect_pg_rss_app_read_role(&fixture, &store).await?;
    let repository = crate::device_certificate::PgDeviceCertificateRepository::<
        ProductionEligibility,
    >::from_unverified_stores_for_test(&reader, &writer);
    let tenant = rss_request_context::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
    let device = ids::DeviceId::new(uuid::Uuid::new_v4());
    let resource = device.as_uuid().to_string();
    let key = ReconcileTargetKey::parse(
        "identity.device-certificate",
        "device-certificate",
        &resource,
    )?;
    let reconcile = store.reconcile();
    let target = reconcile.upsert_target(tenant, &key).await?;
    let original = ReconcileScheduleStore::claim_due_targets(
        &reconcile,
        tenant,
        "identity.device-certificate",
        "holder-a",
        reconcile_limit(1),
        std::time::Duration::from_secs(30),
    )
    .await?
    .pop()
    .ok_or_else(|| std::io::Error::other("initial wake target was not claimed"))?;
    let attempt =
        match ReconcileScheduleStore::append_attempt(&reconcile, &original, "holder-a").await? {
            ScheduleAttemptOutcome::Started(attempt) => attempt,
            ScheduleAttemptOutcome::Lost => return Err("initial wake attempt lost lease".into()),
        };
    let policy = deviceloop::CertificatePolicy::restore(
        3_600,
        600,
        vec!["clientAuth".to_owned()],
        vec!["wake.example".to_owned()],
    )?;
    let accepted = repository
        .accept_desired_policy(AcceptDesiredPolicy::for_test(
            DeviceCertificateScope::for_test(tenant, device),
            ExpectedGeneration::try_new(0)?,
            DevicePolicyIdempotencyKey::new(uuid::Uuid::new_v4()),
            policy,
        )?)
        .await?;
    let wake = match accepted {
        DesiredPolicyAcceptOutcome::Accepted { wake, .. } => wake,
        other => {
            return Err(format!("real desired-policy accept was not accepted: {other:?}").into());
        }
    };
    assert_eq!(wake.target_id(), target.target_id());
    assert_eq!(wake.version().get(), 1);
    assert_eq!(
        ReconcileScheduleStore::record_attempt_result(
            &reconcile,
            &attempt,
            AttemptResult::from_outcome(&Outcome::settled(), std::time::Duration::from_secs(60),),
        )
        .await?,
        ScheduleResultOutcome::WakeSuperseded
    );
    let preserved: (i64, Option<String>, bool, String, i64, i64) = sqlx::query_as(
        "SELECT wake_version, last_result, next_run_at <= now(), lease.state, \
                (SELECT generation FROM device_certificate_desired_states desired \
                 WHERE desired.tenant_id = target.tenant_id \
                   AND desired.device_id::text = target.resource_id), \
                (SELECT count(*) FROM device_certificate_policy_operations operation \
                 WHERE operation.tenant_id = target.tenant_id \
                   AND operation.device_id::text = target.resource_id) \
         FROM reconcile_targets target \
         JOIN reconcile_leases lease USING (tenant_id, target_id) \
         WHERE target.tenant_id = $1::uuid AND target.target_id = $2::uuid",
    )
    .bind(tenant.to_string())
    .bind(target.target_id())
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(preserved, (1, None, true, "free".to_owned(), 1, 1));

    let periodic = ReconcileScheduleStore::claim_due_targets(
        &reconcile,
        tenant,
        "identity.device-certificate",
        "holder-periodic",
        reconcile_limit(1),
        std::time::Duration::from_secs(30),
    )
    .await?
    .pop()
    .ok_or_else(|| std::io::Error::other("periodic scan did not repair lost notification"))?;
    assert_eq!(periodic.trigger(), AttemptTrigger::Targeted);
    assert_eq!(
        ReconcileScheduleStore::release_lease(&reconcile, &periodic).await?,
        eventexec::ScheduleLeaseOutcome::Held
    );

    assert!(
        ReconcileScheduleStore::claim_targeted(
            &reconcile,
            tenant,
            "wrong-reconciler",
            "holder-wrong",
            &wake,
            std::time::Duration::from_secs(30),
        )
        .await?
        .is_none()
    );
    let stale = ReconcileWake::new(target.target_id(), WakeVersion::try_new(0)?);
    assert!(
        ReconcileScheduleStore::claim_targeted(
            &reconcile,
            tenant,
            "identity.device-certificate",
            "holder-stale",
            &stale,
            std::time::Duration::from_secs(30),
        )
        .await?
        .is_none()
    );
    let exact = ReconcileScheduleStore::claim_targeted(
        &reconcile,
        tenant,
        "identity.device-certificate",
        "holder-exact",
        &wake,
        std::time::Duration::from_secs(30),
    )
    .await?
    .ok_or_else(|| std::io::Error::other("exact current wake was not claimed"))?;
    assert_eq!(exact.trigger(), AttemptTrigger::Targeted);
    let exact_attempt =
        match ReconcileScheduleStore::append_attempt(&reconcile, &exact, "holder-exact").await? {
            ScheduleAttemptOutcome::Started(attempt) => attempt,
            ScheduleAttemptOutcome::Lost => return Err("exact wake attempt lost lease".into()),
        };
    let persisted_trigger: String = sqlx::query_scalar(
        "SELECT trigger_kind FROM reconcile_attempts \
         WHERE tenant_id = $1::uuid AND attempt_id = $2::uuid",
    )
    .bind(tenant.to_string())
    .bind(exact_attempt.attempt_id())
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(persisted_trigger, "targeted");
    assert_eq!(
        ReconcileScheduleStore::record_attempt_result(
            &reconcile,
            &exact_attempt,
            AttemptResult::from_outcome(&Outcome::settled(), std::time::Duration::from_secs(60),),
        )
        .await?,
        ScheduleResultOutcome::Recorded
    );
    assert!(
        ReconcileScheduleStore::claim_targeted(
            &reconcile,
            tenant,
            "identity.device-certificate",
            "holder-duplicate",
            &wake,
            std::time::Duration::from_secs(30),
        )
        .await?
        .is_none(),
        "duplicate notification must not hot-loop a completed target"
    );

    drop(repository);
    reader.shutdown().await?;
    writer.shutdown().await?;
    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn reconcile_scheduler_target_pause_resume_missing_target_fails_closed() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    let tenant = rss_request_context::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
    let missing_target = uuid::Uuid::new_v4().to_string();
    let reconcile = store.reconcile();

    let protected_key = ReconcileTargetKey::parse(
        "pause-reconciler",
        "device",
        format!("paused-device-{}", uuid::Uuid::new_v4()),
    )?;
    let protected = reconcile.upsert_target(tenant, &protected_key).await?;
    ReconcileScheduleStore::pause_target(&reconcile, tenant, protected.target_id()).await?;
    let repeated = reconcile.upsert_target(tenant, &protected_key).await?;
    assert_eq!(repeated.target_id(), protected.target_id());
    assert!(
        ReconcileScheduleStore::claim_due_targets(
            &reconcile,
            tenant,
            "pause-reconciler",
            "holder-paused",
            reconcile_limit(1),
            std::time::Duration::from_secs(30),
        )
        .await?
        .is_empty(),
        "generic target upsert must not reactivate a paused row"
    );

    let maintenance = crate::PgMaintenanceReconcileStore::new(
        &crate::pool::VerifiedPgMaintenanceStore::from_maintenance_store(Arc::new(PgStore {
            pool: store.pool.clone(),
        })),
    );
    let capability = OperatorReconcileCapability::issue_for_authorized_operator();
    for reason in ["permanent_failure", "invariant_violation"] {
        sqlx::query(
            "UPDATE reconcile_targets SET status = 'disabled', disabled_reason = $3 \
             WHERE tenant_id = $1::uuid AND target_id = $2::uuid",
        )
        .bind(tenant.to_string())
        .bind(protected.target_id())
        .bind(reason)
        .execute(&store.pool)
        .await?;
        assert!(
            ReconcileScheduleStore::resume_target(&reconcile, tenant, protected.target_id())
                .await
                .is_err(),
            "serving resume must not clear {reason} quarantine"
        );
        assert!(
            ReconcileOperatorStore::resume_target(
                &maintenance,
                tenant,
                protected.target_id(),
                capability,
            )
            .await
            .is_err(),
            "maintenance may clear fact_conflict only, not {reason}"
        );
        let persisted: (String, Option<String>) = sqlx::query_as(
            "SELECT status, disabled_reason FROM reconcile_targets \
             WHERE tenant_id = $1::uuid AND target_id = $2::uuid",
        )
        .bind(tenant.to_string())
        .bind(protected.target_id())
        .fetch_one(&store.pool)
        .await?;
        assert_eq!(persisted, ("disabled".to_owned(), Some(reason.to_owned())));
    }

    assert!(
        ReconcileScheduleStore::pause_target(&reconcile, tenant, &missing_target)
            .await
            .is_err(),
        "pause must fail when the target row is missing"
    );
    assert!(
        ReconcileScheduleStore::resume_target(&reconcile, tenant, &missing_target)
            .await
            .is_err(),
        "resume must fail when the target row is missing"
    );

    store.shutdown().await?;
    Ok(())
}
