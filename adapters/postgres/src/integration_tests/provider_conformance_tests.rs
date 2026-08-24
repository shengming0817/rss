//! Provider conformance catalog and enrolled behaviors.

use super::support::*;

testkit::provider_conformance_catalog! {
    provider: postgres,
    error: TestError,
    capabilities: {
        identity => {
            #[tokio::test(flavor = "multi_thread")]
            eventing_conformance_outbox_enrolls_postgres
                => eventing_conformance_outbox_behavior
        },
        conflict => {
            #[tokio::test(flavor = "multi_thread")]
            outbox_append_distinguishes_same_fact_from_conflict
                => outbox_append_distinguishes_same_fact_from_conflict_behavior
        },
        fencing => {
            #[tokio::test(flavor = "multi_thread")]
            t9_settle_rejects_stale_lease_token
                => settle_rejects_stale_lease_token_behavior
        },
        budget => {
            #[tokio::test(flavor = "multi_thread")]
            insufficient_preflight_budget_never_calls_publisher
                => insufficient_preflight_budget_never_calls_publisher_behavior
        },
        commit_ack => {
            #[tokio::test(flavor = "multi_thread")]
            postgres_consumer_commits_before_ack_and_never_acks_uncommitted
                => postgres_consumer_commit_ack_behavior
        },
        ambiguity => {
            #[tokio::test(flavor = "multi_thread")]
            t4b_relay_ambiguous_retries_with_the_original_event_id
                => relay_ambiguous_retries_with_original_event_id_behavior
        },
        archive_receipt => {
            #[tokio::test(flavor = "multi_thread")]
            t_dlx_verified_receipt_concurrent_cas_is_single_winner
                => dlx_verified_receipt_concurrent_cas_behavior
        },
    }
}

async fn outbox_append_distinguishes_same_fact_from_conflict_behavior() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_outbox(&store).await?;
    let event_id = unique_event_id("outbox-fact-conflict");
    let entry = make_entry(&event_id);
    let first_env = OutboxEnvelope::new(
        "identity".to_string(),
        "identity.session-created".to_string(),
        OutboxMetadata::new(1, test_tenant(), test_contract())
            .with_subject_id(subject_id("stable-subject"))
            .with_trace("trace-a")
            .with_correlation("correlation-a"),
    );
    let retried_env = OutboxEnvelope::new(
        "identity".to_string(),
        "identity.session-created".to_string(),
        OutboxMetadata::new(2, test_tenant(), test_contract())
            .with_subject_id(subject_id("stable-subject"))
            .with_trace("trace-b")
            .with_correlation("correlation-b"),
    );

    let first = eventing_test_db(&store)
        .test_write(
            integration_tenant_scope(test_tenant()),
            |cap| Box::pin(async move { append_outbox(cap, &entry, &first_env).await }),
            OutboxAppendError::from,
        )
        .await?;
    assert_eq!(first, OutboxAppendOutcome::Inserted);

    let retry_entry = make_entry(&event_id);
    let retry = eventing_test_db(&store)
        .test_write(
            integration_tenant_scope(test_tenant()),
            |cap| Box::pin(async move { append_outbox(cap, &retry_entry, &retried_env).await }),
            OutboxAppendError::from,
        )
        .await?;
    assert_eq!(retry, OutboxAppendOutcome::SameFact);

    let conflicting_entry = EventEntry::new(
        EventTopic::parse("test.event")?,
        IdemKey::parse(&event_id)?,
        OutboxPayload::from_reviewed_event_bytes(b"SECRET_CONFLICT_PAYLOAD".to_vec()),
    );
    let conflict_env = OutboxEnvelope::new(
        "identity".to_string(),
        "identity.session-created".to_string(),
        OutboxMetadata::new(3, test_tenant(), test_contract())
            .with_subject_id(subject_id("stable-subject")),
    );
    let conflict = eventing_test_db(&store)
        .test_write(
            integration_tenant_scope(test_tenant()),
            move |cap| {
                Box::pin(async move { append_outbox(cap, &conflicting_entry, &conflict_env).await })
            },
            OutboxAppendError::from,
        )
        .await;
    assert!(matches!(conflict, Err(OutboxAppendError::Conflict(_))));
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM outbox WHERE event_id = $1")
            .bind(&event_id)
            .fetch_one(&store.pool)
            .await?,
        1
    );
    let tamper = sqlx::query("UPDATE outbox SET fact_fingerprint = $2 WHERE event_id = $1")
        .bind(&event_id)
        .bind(vec![0_u8; 32])
        .execute(&store.pool)
        .await;
    assert!(
        tamper.is_err(),
        "stored generated fingerprint must reject explicit writes"
    );

    store.shutdown().await?;
    Ok(())
}

async fn eventing_conformance_outbox_behavior() -> TestResult {
    let _sweep_guard = OUTBOX_SWEEP_TEST_LOCK.lock().await;
    let (_pg, store) = connect_pg().await?;
    setup_outbox(&store).await?;
    let domain = unique_domain("eventing-conf-domain");
    let other_domain = unique_domain("eventing-conf-other-domain");
    let event_id = unique_event_id("eventing-conf-outbox");
    let claims: Mutex<HashMap<String, PgClaimedOutboxEntry>> = Mutex::new(HashMap::new());
    let (publisher, publisher_state) = ConformancePublisher::new();
    let relay = make_pg_outbox_for_domain(&store, &domain, publisher);

    eventconf::assert_outbox_relay_conformance(eventconf::OutboxRelayCase {
        ids: eventconf::EventingIds::new(
            event_id.clone(),
            event_id.clone(),
            "eventing-conf-group",
            "lease-a",
        ),
        domain,
        other_domain,
        max_attempts: MAX_PUBLISH_ATTEMPTS as u32,
        seed_pending: Box::new(|args| {
            Box::pin(conf_seed_pending(&store, args.event_id, args.domain))
        }),
        relay: Box::new(|args| {
            Box::pin(conf_relay(
                &store,
                &relay,
                &publisher_state.mode,
                &publisher_state.messages,
                &claims,
                args.event_id,
                args.mode,
            ))
        }),
        claim_batch: Box::new(|args| Box::pin(conf_claim_batch(&relay, &claims, args.domain))),
        state: Box::new(|args| Box::pin(conf_outbox_state(&store, args.event_id))),
        backdate_publishing: Box::new(|args| {
            Box::pin(conf_backdate_publishing(&store, args.event_id))
        }),
        sample_backlog: Box::new(|args| Box::pin(conf_sample_backlog(&store, args.domain))),
        sweep: Box::new(|retain_seconds| Box::pin(conf_sweep_outbox(&store, retain_seconds))),
        seed_terminal: Box::new(|args| {
            Box::pin(conf_seed_terminal(
                &store,
                args.event_id,
                args.domain,
                args.status,
            ))
        }),
    })
    .await?;

    store.shutdown().await?;
    Ok(())
}

async fn postgres_consumer_commit_ack_behavior() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let group = unique_domain("provider-commit-ack-group");

    let committed_event = unique_event_id("provider-commit-before-ack");
    let (committed_observations, committed_acker) =
        CommitObservingAcker::observe(&store, committed_event.clone(), group.clone());
    let committed_message = Message::new_with_metadata(
        &committed_event,
        b"provider-commit-before-ack".to_vec(),
        conf_consumer_metadata(&committed_event),
    );
    run_consumer_ackable(
        Box::pin(futures::stream::iter(vec![Delivery::new(
            committed_message,
            committed_acker,
        )])),
        Arc::new(store.inbox()),
        (DynDeadLetterStore::new_box(store.dead_letter(test_dlx_payload_protector()))).as_ref(),
        &(conf_consumer_meta(&group)),
        &(conf_ack_handler(Arc::new(AtomicU32::new(0)))),
        conf_lease_cfg(),
        eventing::lifecycle::RetryPolicy::STANDARD,
        conf_consumer_admission(),
    )
    .await;

    let uncommitted_event = unique_event_id("provider-uncommitted-non-ack");
    let (uncommitted_observations, uncommitted_acker) =
        CommitObservingAcker::observe(&store, uncommitted_event.clone(), group.clone());
    let uncommitted_message = Message::new_with_metadata(
        &uncommitted_event,
        b"provider-uncommitted-non-ack".to_vec(),
        conf_consumer_metadata(&uncommitted_event),
    );
    run_consumer_ackable(
        Box::pin(futures::stream::iter(vec![Delivery::new(
            uncommitted_message,
            uncommitted_acker,
        )])),
        Arc::new(store.inbox()),
        (DynDeadLetterStore::new_box(FailingDlx::new(Arc::new(Mutex::new(None))))).as_ref(),
        &(conf_consumer_meta(&group)),
        &(conf_requeue_handler(Arc::new(AtomicU32::new(0)))),
        conf_lease_cfg(),
        eventing::lifecycle::RetryPolicy::STANDARD,
        conf_consumer_admission(),
    )
    .await;

    let committed = committed_observations
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .clone();
    let uncommitted = uncommitted_observations
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .clone();
    assert_eq!(
        committed,
        vec![CommitAckAtSettle {
            committed: true,
            action: AckAction::Ack,
        }],
        "broker Ack must observe the durable inbox commit"
    );
    assert!(
        uncommitted
            .iter()
            .any(|observation| !observation.committed && observation.action != AckAction::Ack),
        "an uncommitted delivery must reach a non-Ack settlement"
    );
    assert!(
        uncommitted
            .iter()
            .all(|observation| observation.committed || observation.action != AckAction::Ack),
        "broker Ack was attempted without a durable inbox commit"
    );

    store.shutdown().await?;
    Ok(())
}

// ── T4b: ambiguous relay 保持 event ID 重试 ───────────────────────────────────

#[allow(clippy::cognitive_complexity)]
async fn relay_ambiguous_retries_with_original_event_id_behavior() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_outbox(&store).await?;

    let event_id = unique_event_id("t4b-ambiguous");
    let entry = make_entry(&event_id);
    store
        .serving_write_fixture::<_, _, sqlx::Error>(test_tenant(), move |cap| {
            let entry = entry.clone();
            let env = OutboxEnvelope::new(
                "t4b_ambiguous_domain".to_string(),
                "c".to_string(),
                OutboxMetadata::new(0, test_tenant(), test_contract()),
            );
            Box::pin(async move {
                let _outcome = append_outbox(cap, &entry, &env)
                    .await
                    .map_err(test_append_error)?;
                Ok(())
            }) as BoxFuture<'_, Result<(), sqlx::Error>>
        })
        .await?;

    let (publisher, message_ids) = AmbiguousOncePublisher::new();
    let outbox = make_pg_outbox_for_domain(&store, "t4b_ambiguous_domain", publisher);

    let first_claim = claim_entry_for_relay(&outbox, &event_id).await?;
    assert_eq!(outbox.relay(first_claim).await?, Disposition::Requeue);
    let first_state: (String, i32) =
        sqlx::query_as("SELECT status, retry_count FROM outbox WHERE event_id = $1")
            .bind(&event_id)
            .fetch_one(&store.pool)
            .await?;
    assert_eq!(first_state, ("pending".to_string(), 1));

    sqlx::query(
        "UPDATE outbox SET retry_after = clock_timestamp() - interval '1 microsecond' \
         WHERE event_id = $1",
    )
    .bind(&event_id)
    .execute(&store.pool)
    .await?;
    let retry_claim = claim_entry_for_relay(&outbox, &event_id).await?;
    assert_eq!(outbox.relay(retry_claim).await?, Disposition::Ack);

    let final_state: (String, i32) =
        sqlx::query_as("SELECT status, retry_count FROM outbox WHERE event_id = $1")
            .bind(&event_id)
            .fetch_one(&store.pool)
            .await?;
    assert_eq!(final_state, ("published".to_string(), 1));
    assert_eq!(
        *message_ids
            .lock()
            .unwrap_or_else(|error| error.into_inner()),
        vec![event_id.clone(), event_id],
        "Ambiguous retry must preserve the original broker-visible event ID"
    );

    store.shutdown().await?;
    Ok(())
}

async fn insufficient_preflight_budget_never_calls_publisher_behavior() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_outbox(&store).await?;
    let budget = DeliveryBudget::new(
        Duration::from_secs(2),
        Duration::from_secs(1),
        Duration::from_millis(500),
        Duration::from_millis(499),
    )?;
    set_test_relay_budget_policy(&store, budget).await?;
    let domain = unique_domain("preflight-no-broker");
    let event_id = unique_event_id("preflight-no-broker");
    let entry = make_entry(&event_id);
    let env = make_test_env(&domain, "preflight.no-broker");
    store
        .serving_write_fixture::<_, _, sqlx::Error>(test_tenant(), move |cap| {
            Box::pin(async move {
                let _ = append_outbox(cap, &entry, &env)
                    .await
                    .map_err(test_append_error)?;
                Ok(())
            }) as BoxFuture<'_, Result<(), sqlx::Error>>
        })
        .await?;
    let (publisher, calls) = RecordingPublisher::always_ok();
    let outbox = make_pg_outbox_for_domain_with_budget(&store, &domain, publisher, budget);
    let claim = claim_entry_for_relay(&outbox, &event_id).await?;
    await_delay(Duration::from_millis(5)).await;
    let Err(error) = outbox.relay(claim).await else {
        return Err("insufficient preflight budget must fail before publish".into());
    };
    assert_eq!(error.kind(), EngineErrorKind::Transient);
    #[allow(clippy::unwrap_used)]
    {
        assert_eq!(*calls.lock().unwrap(), 0);
    }

    store.shutdown().await?;
    Ok(())
}

#[allow(clippy::unwrap_used)]
// reason: integration fixture uses a known-valid tenant UUID.
async fn dlx_verified_receipt_concurrent_cas_behavior() -> TestResult {
    use diport::{
        DeadLetterProvenance, DeadLetterRecord, DeadLetterStore, DeadLetterSummary,
        EnvelopeMetadata,
    };

    let (_fixture, store) = connect_pg().await?;
    store.run_migrations().await?;
    let tenant = rss_request_context::TenantId::parse(COTX_TENANT_A).unwrap();
    let message_id = unique_event_id("dlx-receipt-cas");
    store
        .dead_letter(test_dlx_payload_protector())
        .write_dead_letter(DeadLetterRecord::new(
            tenant,
            &message_id,
            DeadLetterProvenance::consumer("identity", "audit"),
            "contract-cas",
            "dlx.cas",
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
    let record = |checksum: &'static str| {
        sqlx::query_scalar::<_, i64>(
            r#"
            SELECT rss_dlx_record_archive_receipt(
                $1::uuid, $2::uuid, $3::uuid, 'version-1', decode(repeat($4, 32), 'hex'),
                'archive-key:1', 'COMPLIANCE',
                to_timestamp(2000000000)
            )
            "#,
        )
        .bind(tenant.to_string())
        .bind(&id)
        .bind(&claim_token)
        .bind(checksum)
        .fetch_one(&store.pool)
    };
    let (left, right) = tokio::join!(record("ab"), record("ab"));
    let mut outcomes = [left?, right?];
    outcomes.sort_unstable();
    assert_eq!(outcomes, [0, 1]);

    let conflict = record("cd").await;
    assert!(
        conflict.is_err(),
        "semantic receipt conflict must fail closed"
    );
    store.shutdown().await?;
    Ok(())
}

#[allow(clippy::cognitive_complexity)]
async fn settle_rejects_stale_lease_token_behavior() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_outbox(&store).await?;

    let event_id = unique_event_id("t9");
    let entry = make_entry(&event_id);

    // seed 1 行 pending。
    store
        .serving_write_fixture::<_, _, sqlx::Error>(test_tenant(), move |cap| {
            let entry = entry.clone();
            Box::pin(async move {
                let _outcome = append_outbox(cap, &entry, &make_test_env("t9_domain", "c"))
                    .await
                    .map_err(test_append_error)?;
                Ok(())
            }) as BoxFuture<'_, Result<(), sqlx::Error>>
        })
        .await?;

    // A 原子 claim；随后令 deadline 过期并由 B 重新 claim。
    let claim_a = claimed_entry_for_event(&store, &event_id).await?;
    let durable_lease: (String, i64, i64) = sqlx::query_as(
        "SELECT lease_token::text, (EXTRACT(EPOCH FROM lease_until) * 1000000)::bigint, \
         EXTRACT(EPOCH FROM updated_at)::bigint FROM outbox WHERE event_id = $1",
    )
    .bind(&event_id)
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(durable_lease.0, claim_a.test_lease_token());
    assert_eq!(
        durable_lease.1,
        claim_a.test_lease_deadline_epoch_micros(),
        "typed claim deadline must be the exact persisted microsecond value"
    );
    assert_eq!(durable_lease.2, claim_a.claim_epoch_seconds());
    sqlx::query(
        "UPDATE outbox SET updated_at=clock_timestamp()-interval '61 seconds', \
         lease_until=clock_timestamp()-interval '1 second' WHERE event_id = $1",
    )
    .bind(&event_id)
    .execute(&store.pool)
    .await?;
    let claim_b = claimed_entry_for_event(&store, &event_id).await?;

    // A 的 token/deadline 组合已 stale，无法结算 B 持有的行。
    let stale_outcome: String =
        sqlx::query_scalar("SELECT rss_outbox_settle_published($1, $2::uuid, $3)::text")
            .bind(&event_id)
            .bind(claim_a.test_lease_token())
            .bind(claim_a.test_lease_deadline_epoch_micros())
            .fetch_one(&store.pool)
            .await?;
    assert_eq!(
        stale_outcome, "lost_lease",
        "stale lease token settle must report LostLease (0-row CAS fencing miss)"
    );
    let status: (String, bool, bool) = sqlx::query_as(
        "SELECT status, published_at IS NULL, dlx_at IS NULL FROM outbox WHERE event_id = $1",
    )
    .bind(&event_id)
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(
        status.0, "publishing",
        "stale lease token must not settle the row (CAS fencing)"
    );
    assert!(
        status.1 && status.2,
        "stale settle must not write terminal timestamps"
    );

    // B 用当前精确 token/deadline 组合结算 → published。
    let settled_outcome: String =
        sqlx::query_scalar("SELECT rss_outbox_settle_published($1, $2::uuid, $3)::text")
            .bind(&event_id)
            .bind(claim_b.test_lease_token())
            .bind(claim_b.test_lease_deadline_epoch_micros())
            .fetch_one(&store.pool)
            .await?;
    assert_eq!(
        settled_outcome, "settled",
        "valid lease token must report Settled"
    );
    let status2: (String, bool, bool, bool) = sqlx::query_as(
        "SELECT status, published_at IS NOT NULL, dlx_at IS NULL, published_at = updated_at \
         FROM outbox WHERE event_id = $1",
    )
    .bind(&event_id)
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(
        status2.0, "published",
        "valid lease token must settle the row"
    );
    assert!(status2.1 && status2.2 && status2.3);

    store.shutdown().await?;
    Ok(())
}
