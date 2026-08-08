//! Postgres integration tests — command_journal seam.

use super::support::*;

#[tokio::test(flavor = "multi_thread")]
async fn command_outbox_semantic_match_ignores_only_volatile_metadata() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_outbox(&store).await?;
    let tenant = test_tenant();
    let event_id = unique_event_id("direct-command-stable-replay");
    let payload = br#"{"amount":7,"targetId":"target-1"}"#;
    let first = serde_json::json!({
        "tenantId": tenant.to_string(),
        "schemaVersion": generated::command::_seed_v1::CONTRACT.version(),
        "schemaHash": generated::command::_seed_v1::CONTRACT.schema_hash(),
        "subjectId": "command-subject",
        "actor": {
            "kind": "admin",
            "id": "command-actor",
            "tenantId": tenant.to_string(),
            "scope": "tenant"
        },
        "occurredAt": 1,
        "trace": "00-old",
        "correlation": "corr-old"
    });
    let mut retried = first.clone();
    retried["occurredAt"] = serde_json::json!(2);
    retried["trace"] = serde_json::json!("00-new");
    retried["correlation"] = serde_json::json!("corr-new");

    let fingerprint = |metadata: serde_json::Value| {
        let pool = store.pool.clone();
        let event_id = event_id.clone();
        async move {
            sqlx::query_scalar::<_, Vec<u8>>(
                "SELECT rss_outbox_fact_fingerprint($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb)",
            )
            .bind(event_id)
            .bind(tenant.to_string())
            .bind(generated::command::_seed_v1::CONTRACT.domain())
            .bind(generated::command::_seed_v1::TOPIC)
            .bind(generated::command::_seed_v1::CONTRACT_ID)
            .bind(generated::command::_seed_v1::CONTRACT.version())
            .bind(generated::command::_seed_v1::CONTRACT.schema_hash())
            .bind(payload.as_slice())
            .bind("partition-a")
            .bind("cause-a")
            .bind(metadata.to_string())
            .fetch_one(&pool)
            .await
        }
    };

    let first_fingerprint = fingerprint(first).await?;
    assert_eq!(first_fingerprint, fingerprint(retried.clone()).await?);
    retried["actor"]["id"] = serde_json::json!("different-actor");
    assert_ne!(first_fingerprint, fingerprint(retried).await?);

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn command_journal_records_business_marker_and_outbox_atomically() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    prepare_command_journal_markers(&store).await?;

    let tenant = test_tenant();
    let command = command_journal_command(
        tenant,
        &unique_event_id("command-journal-key"),
        br#"{"op":"recorded"}"#,
    )
    .await?;
    let fingerprint = reviewed_command_fingerprint(&command);
    let marker = unique_event_id("command-journal-marker");
    let marker_for_write = marker.clone();

    let outcome = store
        .command_journal(fixed_clock())
        .record_command_with_business_write(command, move |tx| {
            Box::pin(async move {
                tx.command_insert_test_marker(&marker_for_write)
                    .await
                    .map_err(CommandStoreError::internal)?;
                Ok(CommandJournalTerminalSummary::Completed(
                    CommandResultSummary::ENQUEUED,
                ))
            })
                as BoxFuture<'_, Result<CommandJournalTerminalSummary, CommandStoreError>>
        })
        .await?;

    assert_eq!(outcome, CommandJournalOutcome::Recorded);
    let command_id = persisted_command_id(&store.pool, tenant, &fingerprint).await?;
    assert_eq!(command_journal_marker_count(&store, &marker).await?, 1);
    assert_eq!(command_journal_outbox_count(&store, &command_id).await?, 1);
    let row: (String, Option<String>, i32) = sqlx::query_as(
        "SELECT status, result_summary, attempt \
         FROM command_journal WHERE tenant_id = $1::uuid AND command_id = $2",
    )
    .bind(tenant.to_string())
    .bind(&command_id)
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(
        row,
        (
            "completed".to_string(),
            Some("command enqueued".to_string()),
            1
        )
    );
    let outbox_metadata: (serde_json::Value,) =
        sqlx::query_as("SELECT metadata FROM outbox WHERE event_id = $1")
            .bind(&command_id)
            .fetch_one(&store.pool)
            .await?;
    assert_eq!(
        outbox_metadata.0.get("occurredAt").and_then(|v| v.as_i64()),
        Some(expected_occurred_at()),
        "command journal outbox metadata must use the injected producer clock"
    );

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn command_journal_runtime_deps_serving_role_records_and_replays() -> TestResult {
    let (pg, deps) =
        setup_runtime_deps_with_projection_inputs(EMPTY_PROJECTION_INPUT_GENERATION, &[]).await?;
    let owner_pool = runtime_assertion_pool(pg.owner_params()).await?;

    let tenant = test_tenant();
    let idempotency_key = unique_event_id("command-journal-serving-key");
    let first = command_journal_command(tenant, &idempotency_key, br#"{"op":"serving"}"#).await?;
    let fingerprint = reviewed_command_fingerprint(&first);
    let journal = deps.handle().infra().command_journal(fixed_clock());

    assert_eq!(
        CommandJournalStore::record_command(&journal, first, CommandResultSummary::ENQUEUED)
            .await?,
        CommandJournalOutcome::Recorded
    );
    let command_id = persisted_command_id(&owner_pool, tenant, &fingerprint).await?;

    let replay = command_journal_command(tenant, &idempotency_key, br#"{"op":"serving"}"#).await?;
    assert_eq!(
        CommandJournalStore::record_command(&journal, replay, CommandResultSummary::ENQUEUED)
            .await?,
        CommandJournalOutcome::AlreadyCompleted(CommandResultSummary::ENQUEUED)
    );

    let count: (i64,) = sqlx::query_as(
        "SELECT count(*) FROM command_journal WHERE tenant_id = $1::uuid AND command_id = $2",
    )
    .bind(tenant.to_string())
    .bind(&command_id)
    .fetch_one(&owner_pool)
    .await?;
    assert_eq!(count.0, 1, "serving role path must persist one journal row");
    owner_pool.close().await;
    let (resources, _sampler_factory) = deps.into_runtime_parts(std::time::Duration::from_secs(1));
    for resource in resources.into_iter().rev() {
        resource.shutdown().await?;
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn command_journal_business_error_rolls_back_journal_marker_and_outbox() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    prepare_command_journal_markers(&store).await?;

    let tenant = test_tenant();
    let command = command_journal_command(
        tenant,
        &unique_event_id("command-journal-rollback-key"),
        br#"{"op":"rollback"}"#,
    )
    .await?;
    let fingerprint = reviewed_command_fingerprint(&command);
    let marker = unique_event_id("command-journal-rollback-marker");
    let marker_for_write = marker.clone();

    let result = store
        .command_journal(fixed_clock())
        .record_command_with_business_write(command, move |tx| {
            Box::pin(async move {
                tx.command_insert_test_marker(&marker_for_write)
                    .await
                    .map_err(CommandStoreError::internal)?;
                Err(CommandStoreError::internal(std::io::Error::other(
                    "forced command journal rollback",
                )))
            })
                as BoxFuture<'_, Result<CommandJournalTerminalSummary, CommandStoreError>>
        })
        .await;

    assert!(result.is_err(), "business error must surface to caller");
    assert_eq!(command_journal_marker_count(&store, &marker).await?, 0);
    let journal_count: (i64,) = sqlx::query_as(
        "SELECT count(*) FROM command_journal \
         WHERE tenant_id=$1::uuid AND request_fingerprint=$2",
    )
    .bind(tenant.to_string())
    .bind(&fingerprint)
    .fetch_one(&store.pool)
    .await?;
    let alias_count: (i64,) =
        sqlx::query_as("SELECT count(*) FROM command_idempotency_aliases WHERE tenant_id=$1::uuid")
            .bind(tenant.to_string())
            .fetch_one(&store.pool)
            .await?;
    assert_eq!(journal_count.0, 0);
    assert_eq!(
        alias_count.0, 0,
        "alias claim must roll back with business failure"
    );

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn command_journal_outbox_conflict_rolls_back_journal_and_marker() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    prepare_command_journal_markers(&store).await?;

    let tenant = test_tenant();
    let command = command_journal_command(
        tenant,
        &unique_event_id("command-journal-outbox-conflict-key"),
        br#"{"op":"outbox-conflict"}"#,
    )
    .await?;
    let command_id = format!("command:v2:{}", uuid::Uuid::new_v4());
    let current_alias = command
        .intent()
        .aliases()
        .current()
        .ok_or("journal command must carry current alias")?;
    sqlx::query(
        "INSERT INTO command_idempotency_aliases \
         (tenant_id,topic,key_id,alias_digest,command_id) VALUES ($1::uuid,$2,$3,$4,$5)",
    )
    .bind(tenant.to_string())
    .bind(generated::command::_seed_v1::TOPIC)
    .bind(current_alias.key_id())
    .bind(current_alias.digest())
    .bind(&command_id)
    .execute(&store.pool)
    .await?;
    let marker = unique_event_id("command-journal-outbox-conflict-marker");
    let marker_for_write = marker.clone();

    sqlx::query(
        "INSERT INTO outbox (
             event_id, tenant_id, domain, topic, contract_id, contract_version, schema_hash,
             payload, metadata, status
         ) VALUES ($1, $2::uuid, 'test', $3, 'test.contract', 'v1', $4, $5, $6::jsonb, 'pending')",
    )
    .bind(&command_id)
    .bind(tenant.to_string())
    .bind(generated::command::_seed_v1::TOPIC)
    .bind(TEST_SCHEMA_HASH)
    .bind(b"conflicting-payload".as_slice())
    .bind(serde_json::json!({ "tenantId": tenant.to_string() }).to_string())
    .execute(&store.pool)
    .await?;

    let result = store
        .command_journal(fixed_clock())
        .record_command_with_business_write(command, move |tx| {
            Box::pin(async move {
                tx.command_insert_test_marker(&marker_for_write)
                    .await
                    .map_err(CommandStoreError::internal)?;
                Ok(CommandJournalTerminalSummary::Completed(
                    CommandResultSummary::ENQUEUED,
                ))
            })
                as BoxFuture<'_, Result<CommandJournalTerminalSummary, CommandStoreError>>
        })
        .await;

    assert!(
        result.is_err(),
        "outbox event_id conflict with different row must fail the UoW"
    );
    assert_eq!(command_journal_marker_count(&store, &marker).await?, 0);
    assert_eq!(command_journal_row_count(&store, &command_id).await?, 0);
    assert_eq!(
        command_journal_outbox_count(&store, &command_id).await?,
        1,
        "pre-existing conflicting outbox row remains, but journal/marker must roll back"
    );

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn command_journal_duplicate_replays_completed_summary_without_business_write() -> TestResult
{
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    prepare_command_journal_markers(&store).await?;

    let tenant = test_tenant();
    let idempotency_key = unique_event_id("command-journal-replay-key");
    let first = command_journal_command(tenant, &idempotency_key, br#"{"op":"replay"}"#).await?;
    let fingerprint = reviewed_command_fingerprint(&first);
    let first_marker = unique_event_id("command-journal-replay-first");
    let first_marker_for_write = first_marker.clone();
    assert_eq!(
        store
            .command_journal(fixed_clock())
            .record_command_with_business_write(first, move |tx| {
                Box::pin(async move {
                    tx.command_insert_test_marker(&first_marker_for_write)
                        .await
                        .map_err(CommandStoreError::internal)?;
                    Ok(CommandJournalTerminalSummary::Completed(
                        CommandResultSummary::ENQUEUED,
                    ))
                })
                    as BoxFuture<'_, Result<CommandJournalTerminalSummary, CommandStoreError>>
            },)
            .await?,
        CommandJournalOutcome::Recorded
    );
    let command_id = persisted_command_id(&store.pool, tenant, &fingerprint).await?;

    let second = command_journal_command(tenant, &idempotency_key, br#"{"op":"replay"}"#).await?;
    let second_marker = unique_event_id("command-journal-replay-second");
    let second_marker_for_write = second_marker.clone();
    let replay = store
        .command_journal(fixed_clock())
        .record_command_with_business_write(second, move |tx| {
            Box::pin(async move {
                tx.command_insert_test_marker(&second_marker_for_write)
                    .await
                    .map_err(CommandStoreError::internal)?;
                Ok(CommandJournalTerminalSummary::Completed(
                    CommandResultSummary::ENQUEUED,
                ))
            })
                as BoxFuture<'_, Result<CommandJournalTerminalSummary, CommandStoreError>>
        })
        .await?;

    assert_eq!(
        replay,
        CommandJournalOutcome::AlreadyCompleted(CommandResultSummary::ENQUEUED)
    );
    assert_eq!(
        command_journal_marker_count(&store, &first_marker).await?,
        1
    );
    assert_eq!(
        command_journal_marker_count(&store, &second_marker).await?,
        0,
        "duplicate must not re-run business write"
    );
    assert_eq!(command_journal_outbox_count(&store, &command_id).await?, 1);

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn command_journal_key_rotation_backfills_current_alias_without_changing_command_id()
-> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    let tenant = test_tenant();
    let raw_key = unique_event_id("command-journal-rotation-key");
    let payload = br#"{"op":"rotate"}"#;
    let first =
        command_journal_command_with_keyring(tenant, &raw_key, payload, command_keyring_k1_only())
            .await?;
    let fingerprint = reviewed_command_fingerprint(&first);
    let journal = store.command_journal(fixed_clock());
    assert_eq!(
        CommandJournalStore::record_command(&journal, first, CommandResultSummary::ENQUEUED)
            .await?,
        CommandJournalOutcome::Recorded
    );
    let command_id = persisted_command_id(&store.pool, tenant, &fingerprint).await?;

    let rotated =
        command_journal_command_with_keyring(tenant, &raw_key, payload, command_keyring()).await?;
    assert_eq!(
        CommandJournalStore::record_command(&journal, rotated, CommandResultSummary::ENQUEUED)
            .await?,
        CommandJournalOutcome::AlreadyCompleted(CommandResultSummary::ENQUEUED)
    );
    let aliases: Vec<(String, String)> = sqlx::query_as(
        "SELECT key_id, command_id FROM command_idempotency_aliases \
         WHERE tenant_id = $1::uuid ORDER BY key_id",
    )
    .bind(tenant.to_string())
    .fetch_all(&store.pool)
    .await?;
    assert_eq!(
        aliases,
        vec![
            ("k1".to_string(), command_id.clone()),
            ("k2".to_string(), command_id.clone()),
        ],
        "the rotation window must converge both aliases on the original random canonical id"
    );
    assert_eq!(command_journal_outbox_count(&store, &command_id).await?, 1);

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn command_journal_concurrent_same_request_writes_once() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    let tenant = test_tenant();
    let raw_key = unique_event_id("command-journal-concurrent-key");
    let payload = br#"{"op":"concurrent"}"#;
    let first = command_journal_command(tenant, &raw_key, payload).await?;
    let fingerprint = reviewed_command_fingerprint(&first);
    let second = command_journal_command(tenant, &raw_key, payload).await?;
    let journal_a = store.command_journal(fixed_clock());
    let journal_b = store.command_journal(fixed_clock());
    let (outcome_a, outcome_b) = tokio::join!(
        CommandJournalStore::record_command(&journal_a, first, CommandResultSummary::ENQUEUED,),
        CommandJournalStore::record_command(&journal_b, second, CommandResultSummary::ENQUEUED,),
    );
    let outcomes = [outcome_a?, outcome_b?];
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, CommandJournalOutcome::Recorded))
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(
                outcome,
                CommandJournalOutcome::AlreadyCompleted(CommandResultSummary::ENQUEUED)
            ))
            .count(),
        1
    );
    let command_id = persisted_command_id(&store.pool, tenant, &fingerprint).await?;
    assert_eq!(command_journal_row_count(&store, &command_id).await?, 1);
    assert_eq!(command_journal_outbox_count(&store, &command_id).await?, 1);

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn command_journal_duplicate_replays_failed_summary_without_business_write() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    prepare_command_journal_markers(&store).await?;

    let tenant = test_tenant();
    let idempotency_key = unique_event_id("command-journal-failed-replay-key");
    let first =
        command_journal_command(tenant, &idempotency_key, br#"{"op":"failed-replay"}"#).await?;
    let fingerprint = reviewed_command_fingerprint(&first);
    assert_eq!(
        store
            .command_journal(fixed_clock())
            .record_command_with_business_write(first, |_tx| {
                Box::pin(async move {
                    Ok(CommandJournalTerminalSummary::Failed(
                        CommandErrorSummary::FAILED,
                    ))
                })
                    as BoxFuture<'_, Result<CommandJournalTerminalSummary, CommandStoreError>>
            },)
            .await?,
        CommandJournalOutcome::Recorded
    );
    let command_id = persisted_command_id(&store.pool, tenant, &fingerprint).await?;

    let row: (String, Option<String>, Option<String>) = sqlx::query_as(
        "SELECT status, result_summary, error_summary \
         FROM command_journal WHERE tenant_id = $1::uuid AND command_id = $2",
    )
    .bind(tenant.to_string())
    .bind(&command_id)
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(
        row,
        (
            "failed".to_string(),
            None,
            Some("command failed".to_string())
        )
    );
    assert_eq!(
        command_journal_outbox_count(&store, &command_id).await?,
        0,
        "failed terminal command must not enqueue outbox"
    );

    let second =
        command_journal_command(tenant, &idempotency_key, br#"{"op":"failed-replay"}"#).await?;
    let marker = unique_event_id("command-journal-failed-replay-marker");
    let marker_for_write = marker.clone();
    let replay = store
        .command_journal(fixed_clock())
        .record_command_with_business_write(second, move |tx| {
            Box::pin(async move {
                tx.command_insert_test_marker(&marker_for_write)
                    .await
                    .map_err(CommandStoreError::internal)?;
                Ok(CommandJournalTerminalSummary::Completed(
                    CommandResultSummary::ENQUEUED,
                ))
            })
                as BoxFuture<'_, Result<CommandJournalTerminalSummary, CommandStoreError>>
        })
        .await?;

    assert_eq!(
        replay,
        CommandJournalOutcome::AlreadyFailed(CommandErrorSummary::FAILED)
    );
    assert_eq!(
        command_journal_marker_count(&store, &marker).await?,
        0,
        "failed duplicate must not re-run business write"
    );

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn command_journal_same_key_different_fingerprint_conflicts() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    prepare_command_journal_markers(&store).await?;

    let tenant = test_tenant();
    let idempotency_key = unique_event_id("command-journal-conflict-key");
    let first = command_journal_command(tenant, &idempotency_key, br#"{"op":"a"}"#).await?;
    let fingerprint = reviewed_command_fingerprint(&first);
    assert_eq!(
        CommandJournalStore::record_command(
            &store.command_journal(fixed_clock()),
            first,
            CommandResultSummary::ENQUEUED,
        )
        .await?,
        CommandJournalOutcome::Recorded
    );
    let command_id = persisted_command_id(&store.pool, tenant, &fingerprint).await?;

    let conflicting = command_journal_command(tenant, &idempotency_key, br#"{"op":"b"}"#).await?;
    let marker = unique_event_id("command-journal-conflict-marker");
    let marker_for_write = marker.clone();
    let outcome = store
        .command_journal(fixed_clock())
        .record_command_with_business_write(conflicting, move |tx| {
            Box::pin(async move {
                tx.command_insert_test_marker(&marker_for_write)
                    .await
                    .map_err(CommandStoreError::internal)?;
                Ok(CommandJournalTerminalSummary::Completed(
                    CommandResultSummary::ENQUEUED,
                ))
            })
                as BoxFuture<'_, Result<CommandJournalTerminalSummary, CommandStoreError>>
        })
        .await?;

    assert_eq!(outcome, CommandJournalOutcome::Conflict);
    assert_eq!(command_journal_marker_count(&store, &marker).await?, 0);
    assert_eq!(command_journal_outbox_count(&store, &command_id).await?, 1);

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn command_journal_same_key_isolated_by_tenant() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    let tenant_a = vocab::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
    let tenant_b = vocab::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
    let idempotency_key = unique_event_id("command-journal-cross-tenant-key");

    let first =
        command_journal_command(tenant_a, &idempotency_key, br#"{"op":"tenant-a"}"#).await?;
    let first_fingerprint = reviewed_command_fingerprint(&first);
    let second =
        command_journal_command(tenant_b, &idempotency_key, br#"{"op":"tenant-b"}"#).await?;
    let second_fingerprint = reviewed_command_fingerprint(&second);
    assert_eq!(
        CommandJournalStore::record_command(
            &store.command_journal(fixed_clock()),
            first,
            CommandResultSummary::ENQUEUED,
        )
        .await?,
        CommandJournalOutcome::Recorded
    );
    let first_id = persisted_command_id(&store.pool, tenant_a, &first_fingerprint).await?;
    assert_eq!(
        CommandJournalStore::record_command(
            &store.command_journal(fixed_clock()),
            second,
            CommandResultSummary::ENQUEUED,
        )
        .await?,
        CommandJournalOutcome::Recorded
    );
    let second_id = persisted_command_id(&store.pool, tenant_b, &second_fingerprint).await?;
    assert_ne!(
        first_id, second_id,
        "canonical command ids must be random per tenant"
    );
    assert_eq!(command_journal_outbox_count(&store, &first_id).await?, 1);
    assert_eq!(command_journal_outbox_count(&store, &second_id).await?, 1);

    let command_ids = vec![first_id.clone(), second_id.clone()];
    let row_count: (i64,) =
        sqlx::query_as("SELECT count(*) FROM command_journal WHERE command_id = ANY($1::text[])")
            .bind(command_ids.as_slice())
            .fetch_one(&store.pool)
            .await?;
    assert_eq!(row_count.0, 2, "same raw key must be tenant-scoped");

    store.shutdown().await?;
    Ok(())
}

#[derive(Clone, Default)]
struct CaptureReviewedCommand {
    command: std::sync::Arc<std::sync::Mutex<Option<ReviewedCommandJournal>>>,
}

impl CommandJournalStore for CaptureReviewedCommand {
    async fn record_command(
        &self,
        command: ReviewedCommandJournal,
        _result_summary: CommandResultSummary,
    ) -> Result<CommandJournalOutcome, CommandStoreError> {
        *self
            .command
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = Some(command);
        Ok(CommandJournalOutcome::Recorded)
    }
}

async fn command_journal_command(
    tenant: vocab::TenantId,
    key: &str,
    payload: &[u8],
) -> Result<ReviewedCommandJournal, TestError> {
    command_journal_command_with_keyring(tenant, key, payload, command_keyring()).await
}

async fn command_journal_command_with_keyring(
    tenant: vocab::TenantId,
    key: &str,
    payload: &[u8],
    keyring: std::sync::Arc<CommandIdempotencyKeyring>,
) -> Result<ReviewedCommandJournal, TestError> {
    let capture = CaptureReviewedCommand::default();
    let dispatcher = JournaledCommandDispatcher::new(capture.clone(), keyring);
    generated::command::_seed_v1::journal_async(
        &dispatcher,
        generated::command::_seed_v1::SeedDoThingRequest {
            amount: i64::try_from(payload.len()).unwrap_or(i64::MAX),
            target_id: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload),
        },
        tenant,
        subject_id("command-journal-subject"),
        actor_for(tenant),
        key.to_string(),
    )
    .await?;
    capture
        .command
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .take()
        .ok_or_else(|| "generated journal dispatcher did not submit a reviewed command".into())
}

fn reviewed_command_fingerprint(command: &ReviewedCommandJournal) -> String {
    command.intent().request_fingerprint().as_str().to_owned()
}

async fn persisted_command_id(
    pool: &sqlx::PgPool,
    tenant: vocab::TenantId,
    fingerprint: &str,
) -> Result<String, TestError> {
    let (command_id,): (String,) = sqlx::query_as(
        "SELECT command_id FROM command_journal \
         WHERE tenant_id=$1::uuid AND request_fingerprint=$2",
    )
    .bind(tenant.to_string())
    .bind(fingerprint)
    .fetch_one(pool)
    .await?;
    Ok(command_id)
}

async fn prepare_command_journal_markers(store: &PgStore) -> Result<(), sqlx::Error> {
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS command_journal_test_markers \
         (marker text PRIMARY KEY, created_at timestamptz NOT NULL DEFAULT now())",
    )
    .execute(&store.pool)
    .await?;
    Ok(())
}

async fn command_journal_marker_count(store: &PgStore, marker: &str) -> Result<i64, sqlx::Error> {
    let count: (i64,) =
        sqlx::query_as("SELECT count(*) FROM command_journal_test_markers WHERE marker = $1")
            .bind(marker)
            .fetch_one(&store.pool)
            .await?;
    Ok(count.0)
}

async fn command_journal_outbox_count(
    store: &PgStore,
    command_id: &str,
) -> Result<i64, sqlx::Error> {
    let count: (i64,) = sqlx::query_as("SELECT count(*) FROM outbox WHERE event_id = $1")
        .bind(command_id)
        .fetch_one(&store.pool)
        .await?;
    Ok(count.0)
}

async fn command_journal_row_count(store: &PgStore, command_id: &str) -> Result<i64, sqlx::Error> {
    let count: (i64,) =
        sqlx::query_as("SELECT count(*) FROM command_journal WHERE command_id = $1")
            .bind(command_id)
            .fetch_one(&store.pool)
            .await?;
    Ok(count.0)
}
