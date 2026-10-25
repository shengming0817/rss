//! Real batch capacity, partition ordering and partial results on the installed consumer role.
use super::*;
use rss_transactional_messaging::outbox::{OutboxRelayStore, OutboxSettlement};
use tokio::sync::Semaphore;

struct BatchEffect {
    entered: Arc<Semaphore>,
    release: Arc<Semaphore>,
}
impl PgConsumerEffect<Vec<u8>> for BatchEffect {
    async fn apply(
        &self,
        tx: &mut PgTransaction<'_>,
        message: &MessageEnvelope<Vec<u8>>,
        _: OperationDeadline,
    ) -> Result<TerminalDisposition, PgConsumerEffectFailure> {
        self.entered.add_permits(1);
        self.release
            .acquire()
            .await
            .map_err(PgConsumerEffectFailure::handler_transient)?
            .forget();
        if message.id().as_str() == "batch-failure" {
            return Err(PgConsumerEffectFailure::handler_transient(
                std::io::Error::other("fixture failure"),
            ));
        }
        let id = message.id().as_str().to_owned();
        tx.with_connection(move |c| {
            Box::pin(async move {
                sqlx::query("INSERT INTO public.effect_a VALUES($1)")
                    .bind(id)
                    .execute(c)
                    .await?;
                Ok(())
            })
        })
        .await
        .map_err(PgConsumerEffectFailure::infrastructure)?;
        Ok(TerminalDisposition::Succeeded)
    }
}
async fn append(f: &Fixture, entries: Vec<(String, String)>) -> anyhow::Result<()> {
    let writer = PgOutboxWriter::new(f.producer.clone(), domain()?);
    let messages = entries
        .into_iter()
        .map(|(id, partition)| {
            Ok(PendingMessage::new(message_partition(
                &id,
                "orders",
                Some(PartitionKey::parse(&partition)?),
            )?))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    committed(
        f.producer
            .local_tx_with_context(
                tenant(),
                OperationDeadline::from_remaining(Duration::from_secs(30)),
                (writer, messages),
                |(writer, messages), tx| {
                    Box::pin(async move {
                        let partitions = messages
                            .iter()
                            .filter_map(|m| m.partition().cloned())
                            .collect::<Vec<_>>();
                        tx.prepare_outbox_partitions(&partitions).await?;
                        for message in messages.drain(..) {
                            writer.append(tx, message).await?;
                        }
                        Ok(())
                    })
                },
            )
            .await,
    )?;
    Ok(())
}

pub(super) async fn run(f: &Fixture) -> anyhow::Result<()> {
    concurrent_heads(f).await?;
    independent_deadline(f).await?;
    mixed_unknown(f).await?;
    above_old_limit(f).await?;
    history_and_policy(f).await
}
#[allow(
    clippy::cognitive_complexity,
    reason = "Keep the provider scenario and its ordered durable assertions together."
)]
async fn concurrent_heads(f: &Fixture) -> anyhow::Result<()> {
    append(
        f,
        vec![
            ("batch-first".into(), "batch-shared".into()),
            ("batch-next".into(), "batch-shared".into()),
            ("batch-failure".into(), "batch-other".into()),
        ],
    )
    .await?;
    let entered = Arc::new(Semaphore::new(0));
    let release = Arc::new(Semaphore::new(0));
    let capture = PgRecoveryCapture::new(f.worker.clone(), Arc::new(Key(1)), deadline()).await?;
    let projection = Arc::new(
        PgLocalProjection::new(
            capture,
            group()?,
            domain()?,
            BatchEffect {
                entered: entered.clone(),
                release: release.clone(),
            },
            DeliveryBudget::new(
                Duration::from_secs(30),
                Duration::from_secs(5),
                Duration::from_secs(1),
                Duration::from_secs(1),
            )?,
            LeaseRenewalPolicy::from_ttl(Duration::from_secs(30))?,
            deadline(),
        )
        .await?,
    );
    let limit = NonZeroUsize::try_from(70usize)?;
    let task = tokio::spawn({
        let projection = projection.clone();
        async move {
            collect_batch(projection.project_batch(
                &Validator,
                limit,
                deadline(),
                Duration::from_secs(5),
            ))
            .await
        }
    });
    // Both effects must enter before either can complete; sequential execution cannot satisfy this.
    tokio::time::timeout(Duration::from_secs(2), entered.acquire_many(2))
        .await??
        .forget();
    assert_eq!(f.state("batch-next").await?.3, "pending");
    release.add_permits(2);
    let results = task.await??;
    assert_eq!(results.len(), 2);
    for item in results {
        assert_eq!(item.tenant_id(), tenant());
        let id = item.message_id().as_str().to_owned();
        let status = attempt_status(item.into_outcome()?)?;
        assert_eq!(
            status,
            if id == "batch-failure" {
                Status::HandlerTransient
            } else {
                Status::Committed
            }
        );
    }
    assert_eq!(f.state("batch-first").await?.0, 1);
    assert_eq!(f.state("batch-failure").await?.0, 0);
    // Finish the successful partition's successor; a failed sibling cannot roll it back or block it.
    release.add_permits(8);
    let results = collect_batch(projection.project_batch(
        &Validator,
        NonZeroUsize::try_from(8usize)?,
        deadline(),
        Duration::from_secs(5),
    ))
    .await?;
    assert!(
        results
            .iter()
            .any(|item| item.message_id().as_str() == "batch-next")
    );
    for item in results {
        let _ = item.into_outcome()?;
    }
    assert_eq!(f.state("batch-next").await?.0, 1);
    // Resolve the intentional failed fixture without leaving work for unrelated single-event scenarios.
    sqlx::query("UPDATE rss_transactional_messaging.outbox SET status='resolved',lease_token=NULL,lease_until=NULL WHERE message_id='batch-failure'")
        .execute(&f.owner).await?;
    Ok(())
}
async fn above_old_limit(f: &Fixture) -> anyhow::Result<()> {
    append(
        f,
        (0..70)
            .map(|n| (format!("wide-{n}"), format!("wide-{n}")))
            .collect(),
    )
    .await?;
    let outbox = PgOutboxStore::<()>::new(
        f.worker.clone(),
        domain()?,
        DeliveryBudget::new(
            Duration::from_secs(60),
            Duration::from_secs(5),
            Duration::from_secs(1),
            Duration::from_secs(1),
        )?,
    )?;
    let batch = outbox
        .claim_partition_heads(NonZeroUsize::try_from(70usize)?, deadline())
        .await?;
    assert_eq!(
        batch.len(),
        70,
        "one provider call must accept a caller capacity above 64"
    );
    for claim in batch {
        outbox
            .settle(claim, OutboxSettlement::Published(()), deadline())
            .await?;
    }
    Ok(())
}
#[allow(
    clippy::cognitive_complexity,
    reason = "Keep the provider scenario and its ordered durable assertions together."
)]
async fn history_and_policy(f: &Fixture) -> anyhow::Result<()> {
    append(
        f,
        (0..1500)
            .map(|n| (format!("history-{n}"), "history-hot".to_owned()))
            .collect(),
    )
    .await?;
    // These valid producer-authored rows represent a terminal history, then one current head.
    sqlx::query("UPDATE rss_transactional_messaging.outbox SET status='published' WHERE message_id LIKE 'history-%'")
        .execute(&f.owner).await?;
    append(
        f,
        vec![
            ("history-head".into(), "history-hot".into()),
            ("history-tail".into(), "history-hot".into()),
        ],
    )
    .await?;
    // Explain the installed candidate definition as the claim function's effective role. SQL
    // functions with SET search_path otherwise hide their inner plan behind Function Scan.
    let body: String = sqlx::query_scalar("SELECT prosrc FROM pg_proc WHERE oid='rss_transactional_messaging.outbox_candidates(uuid,text)'::regprocedure")
        .fetch_one(&f.owner).await?;
    let explain = format!(
        "EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) {}",
        body.replace("p_tenant", "$1::uuid")
            .replace("p_domain", "$2")
    );
    let mut connection = f.owner.acquire().await?;
    sqlx::query("SET ROLE rss_tmsg_relay")
        .execute(&mut *connection)
        .await?;
    sqlx::query("SET search_path=pg_catalog,rss_transactional_messaging,pg_temp")
        .execute(&mut *connection)
        .await?;
    let plan: serde_json::Value = sqlx::query_scalar(sqlx::AssertSqlSafe(explain))
        .bind(tenant().to_string())
        .bind("orders")
        .fetch_one(&mut *connection)
        .await?;
    fn examined_outbox(plan: &serde_json::Value) -> f64 {
        let own = if plan["Relation Name"] == "outbox" {
            (plan["Actual Rows"].as_f64().unwrap_or(0.0)
                + plan["Rows Removed by Filter"].as_f64().unwrap_or(0.0))
                * plan["Actual Loops"].as_f64().unwrap_or(1.0)
        } else {
            0.0
        };
        own + plan["Plans"]
            .as_array()
            .map(|children| children.iter().map(examined_outbox).sum::<f64>())
            .unwrap_or(0.0)
    }
    assert!(
        examined_outbox(&plan[0]["Plan"]) < 1500.0,
        "candidate query must not traverse the terminal history: {plan}"
    );
    println!("installed candidate plan: {plan}");
    sqlx::query("RESET ROLE").execute(&mut *connection).await?;
    drop(connection);
    let projection = f
        .projection(Effect {
            gate: None,
            reject: false,
            fail: false,
        })
        .await?;
    let items = collect_batch(projection.project_batch(
        &Validator,
        NonZeroUsize::try_from(8usize)?,
        deadline(),
        Duration::from_secs(5),
    ))
    .await?;
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].message_id().as_str(), "history-head");
    assert_eq!(
        committed_projection(only(items)?)?.disposition(),
        TerminalDisposition::Succeeded
    );
    let items = collect_batch(projection.project_batch(
        &Validator,
        NonZeroUsize::MIN,
        deadline(),
        Duration::from_secs(5),
    ))
    .await?;
    assert_eq!(
        committed_projection(only(items)?)?.disposition(),
        TerminalDisposition::Succeeded
    );
    let mut connection = f.raw_worker.acquire().await?;
    let plan:Vec<(String,)> = sqlx::query_as("EXPLAIN (ANALYZE, BUFFERS) SELECT seq FROM rss_transactional_messaging.outbox WHERE domain='orders'")
        .fetch_all(&mut *connection).await?;
    let plan = plan
        .into_iter()
        .map(|(line,)| line)
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        plan.contains("InitPlan"),
        "consumer scope must be evaluated once per statement: {plan}"
    );
    println!("consumer-scope plan: {plan}");
    Ok(())
}

async fn independent_deadline(f: &Fixture) -> anyhow::Result<()> {
    append(f, vec![("batch-budget".into(), "batch-budget".into())]).await?;
    let gate = Gate::default();
    let projection = f
        .projection(Effect {
            gate: Some(gate.clone()),
            reject: false,
            fail: false,
        })
        .await?;
    let task = tokio::spawn(async move {
        collect_batch(projection.project_batch(
            &Validator,
            NonZeroUsize::MIN,
            OperationDeadline::from_remaining(Duration::from_secs(1)),
            Duration::from_secs(5),
        ))
        .await
    });
    tokio::time::timeout(Duration::from_secs(2), gate.entered.notified()).await?;
    // Expire the claim budget while the independent effect is deliberately paused.
    tokio::time::sleep(Duration::from_millis(1100)).await;
    gate.resume.notify_one();
    assert_eq!(
        committed_projection(only(task.await??)?)?.disposition(),
        TerminalDisposition::Succeeded
    );
    Ok(())
}
async fn mixed_unknown(f: &Fixture) -> anyhow::Result<()> {
    append(
        f,
        (0..3)
            .map(|n| (format!("batch-unknown-{n}"), format!("batch-unknown-{n}")))
            .collect(),
    )
    .await?;
    let p = f
        .projection(Effect {
            gate: None,
            reject: false,
            fail: false,
        })
        .await?;
    let entered = Arc::new(Notify::new());
    let resume = Arc::new(Notify::new());
    p.inject_next_projection_fault(PgTransactionFault::CommitUnknownAfterAck, {
        let entered = entered.clone();
        let resume = resume.clone();
        async move {
            entered.notify_one();
            resume.notified().await;
        }
    })?;
    let capacity = NonZeroUsize::try_from(3usize)?;
    let projection = &p;
    let project = async move {
        collect_batch(projection.project_batch(
            &Validator,
            capacity,
            deadline(),
            Duration::from_secs(5),
        ))
        .await
    };
    let siblings = async {
        entered.notified().await;
        // The target has taken its fault but cannot acquire a connection. Other events must
        // finish their source/Inbox/effect transactions without stealing that fault.
        loop {
            let count: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM public.effect_a WHERE id LIKE 'batch-unknown-%'",
            )
            .fetch_one(&f.owner)
            .await?;
            if count == 2 {
                break;
            }
            tokio::task::yield_now().await;
        }
        resume.notify_one();
        Ok::<(), anyhow::Error>(())
    };
    let (batch, siblings) = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(project, siblings)
    })
    .await?;
    siblings?;
    let batch = batch?;
    assert_eq!(batch.len(), 3);
    let mut unknown = 0;
    for item in batch {
        let id = item.message_id().as_str().to_owned();
        let (outcome, recovery) = projection_attempt(item.into_outcome()?)?.into_parts();
        match outcome.status() {
            Status::CommitUnknown => {
                unknown += 1;
                assert!(p.resolve(&recovery, deadline()).await?.is_some());
            }
            status => assert_eq!(status, Status::Committed),
        }
        assert_eq!(f.state(&id).await?.0, 1);
    }
    assert_eq!(
        unknown, 1,
        "one event retains its uncertain acknowledgement independently"
    );
    Ok(())
}
