//! Real maintenance-role checks after generic-plan warmup and increasing historical DR size.
use super::*;
use sqlx::Connection as _;

pub(super) async fn historical_work(owner: &sqlx::PgPool, after: i64) -> anyhow::Result<()> {
    let profile = std::env::var_os("RSS_PG_WORK_PROFILE").is_some();
    if profile {
        let _ = tracing_subscriber::fmt()
            .with_env_filter("sqlx::postgres::notice=info")
            .with_ansi(false)
            .try_init();
    }
    seed_current(owner).await?;
    for (start, end) in [(1_i64, 100_i64), (101, 10_000)] {
        seed_history(owner, after, start, end).await?;
        measure(owner, after, end, "absent", profile).await?;
    }
    sqlx::query("DELETE FROM rss_transactional_messaging.dr_members WHERE operation_id='00000000-0000-0000-0000-000000003284' AND ordinal=1023").execute(owner).await?;
    sqlx::query("INSERT INTO rss_transactional_messaging.dr_members(tenant_id,operation_id,ordinal,message_id,consumer_group,fingerprint,outbox_seq,status,block_reason) SELECT tenant_id,'00000000-0000-0000-0000-000000003284',1023,message_id,'',fingerprint,seq,'blocked','deadline_expired' FROM rss_transactional_messaging.outbox WHERE seq=$1")
        .bind(after+1).execute(owner).await?;
    measure(owner, after, 10_000, "blocked", profile).await?;
    sqlx::query("UPDATE rss_transactional_messaging.dr_members SET status='completed',block_reason=NULL WHERE operation_id='00000000-0000-0000-0000-000000003284' AND ordinal=1023").execute(owner).await?;
    measure(owner, after, 10_000, "completed", profile).await?;
    sqlx::query("DELETE FROM rss_transactional_messaging.dr_members d USING rss_transactional_messaging.dr_plans p WHERE d.tenant_id=p.tenant_id AND d.operation_id=p.operation_id AND p.evidence->>'fixture' IN ('retention-history','retention-current')").execute(owner).await?;
    sqlx::query("DELETE FROM rss_transactional_messaging.dr_plans WHERE evidence->>'fixture' IN ('retention-history','retention-current')").execute(owner).await?;
    sqlx::query(
        "DELETE FROM rss_transactional_messaging.outbox WHERE message_id LIKE 'retention-extra-%'",
    )
    .execute(owner)
    .await?;
    sqlx::query("VACUUM rss_transactional_messaging.outbox")
        .execute(owner)
        .await?;
    Ok(())
}

fn metadata() -> MessageMetadata {
    let template = message("retention-template");
    let m = template.metadata();
    MessageMetadata::new(
        AuthoredMessageMetadata::new(
            m.tenant_id(),
            m.occurred_at(),
            m.domain().clone(),
            m.route().clone(),
            m.contract().clone(),
        ),
        MessageMetadataExtensions::new(None, None, None, Default::default()),
    )
}

async fn seed_current(owner: &sqlx::PgPool) -> anyhow::Result<()> {
    let metadata = metadata();
    let bodies = (0..1024)
        .map(|n| {
            Ok(MessageEnvelope::new(
                MessageId::parse(&format!("retention-extra-{n}"))?,
                metadata.clone(),
                vec![0u8],
            )
            .canonical_bytes())
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    sqlx::query(
        "SELECT rss_transactional_messaging.append_outbox(body,$2) FROM unnest($1::bytea[]) body",
    )
    .bind(bodies)
    .bind(serde_json::json!({"trace":null,"tenant_authority":null}))
    .execute(owner)
    .await?;
    sqlx::query("UPDATE rss_transactional_messaging.outbox SET status='published',automatic_retry_deadline=clock_timestamp()+interval '1 day' WHERE message_id LIKE 'retention-extra-%'").execute(owner).await?;
    sqlx::query("INSERT INTO rss_transactional_messaging.dr_plans(tenant_id,operation_id,request_digest,lineage,epoch,kind,evidence) VALUES($1::uuid,'00000000-0000-0000-0000-000000003284',sha256('current'::bytea),decode(repeat('02',16),'hex'),1,'database','{\"fixture\":\"retention-current\"}')").bind(tenant().to_string()).execute(owner).await?;
    sqlx::query("INSERT INTO rss_transactional_messaging.dr_members(tenant_id,operation_id,ordinal,message_id,consumer_group,fingerprint,outbox_seq,status) SELECT tenant_id,'00000000-0000-0000-0000-000000003284',(row_number() OVER(ORDER BY seq)-1)::integer,message_id,'',fingerprint,seq,'pending' FROM rss_transactional_messaging.outbox WHERE message_id LIKE 'retention-extra-%'").execute(owner).await?;
    Ok(())
}

async fn seed_history(
    owner: &sqlx::PgPool,
    after: i64,
    start: i64,
    end: i64,
) -> anyhow::Result<()> {
    sqlx::query("INSERT INTO rss_transactional_messaging.dr_plans(tenant_id,operation_id,request_digest,lineage,epoch,kind,evidence) SELECT $1::uuid,gen_random_uuid(),sha256('history'::bytea),decode(repeat('03',16),'hex'),100000+n,'database','{\"fixture\":\"retention-history\"}'::jsonb FROM generate_series($2::bigint,$3::bigint) n")
        .bind(tenant().to_string()).bind(start).bind(end).execute(owner).await?;
    sqlx::query("INSERT INTO rss_transactional_messaging.dr_members(tenant_id,operation_id,ordinal,message_id,consumer_group,fingerprint,outbox_seq,status) SELECT p.tenant_id,p.operation_id,0,o.message_id,'',o.fingerprint,o.seq,'pending' FROM rss_transactional_messaging.dr_plans p JOIN rss_transactional_messaging.outbox o ON o.seq=$1 AND o.tenant_id=p.tenant_id WHERE p.evidence->>'fixture'='retention-history' AND p.epoch BETWEEN 100000+$2 AND 100000+$3")
        .bind(after+1).bind(start).bind(end).execute(owner).await?;
    sqlx::query("INSERT INTO rss_transactional_messaging.dr_members(tenant_id,operation_id,ordinal,message_id,consumer_group,fingerprint,outbox_seq,status) SELECT p.tenant_id,p.operation_id,j,o.message_id,'',o.fingerprint,o.seq,'pending' FROM rss_transactional_messaging.dr_plans p CROSS JOIN generate_series(1,8) j JOIN rss_transactional_messaging.outbox o ON o.tenant_id=p.tenant_id AND o.message_id='retention-extra-'||mod((p.epoch-100001)*8+j,1024) WHERE p.evidence->>'fixture'='retention-history' AND p.epoch BETWEEN 100000+$1 AND 100000+$2")
        .bind(start).bind(end).execute(owner).await?;
    sqlx::raw_sql("ANALYZE rss_transactional_messaging.dr_members; ANALYZE rss_transactional_messaging.dr_plans;").execute(owner).await?;
    Ok(())
}

async fn measure(
    owner: &sqlx::PgPool,
    after: i64,
    end: i64,
    state: &str,
    profile: bool,
) -> anyhow::Result<()> {
    let mut c = sqlx::PgConnection::connect_with(owner.connect_options().as_ref()).await?;
    if profile {
        sqlx::raw_sql("LOAD 'auto_explain'; SET auto_explain.log_min_duration=0; SET auto_explain.log_nested_statements=on; SET auto_explain.log_analyze=on; SET auto_explain.log_buffers=on; SET auto_explain.log_timing=off; SET auto_explain.log_format=json; SET auto_explain.log_level=notice;").execute(&mut c).await?;
    }
    sqlx::query("SET SESSION AUTHORIZATION body_operator")
        .execute(&mut c)
        .await?;
    for attempt in 0..7 {
        if profile || attempt == 6 {
            println!("body-history population={end} state={state} attempt={attempt}");
        }
        let mut tx = c.begin().await?;
        let result:(i32,i32)=sqlx::query_as("SELECT scanned,reclaimed FROM rss_transactional_messaging.reclaim_published_bodies($1,$2,1,1048576)")
            .bind(i64::MAX).bind(after).fetch_one(&mut *tx).await?;
        assert_eq!(
            result,
            (1, i32::from(state != "blocked")),
            "only the current blocked member retains the body"
        );
        tx.rollback().await?;
    }
    c.close().await?;
    Ok(())
}

pub(super) async fn byte_budget(
    owner: &sqlx::PgPool,
    maintenance: &PgPublishedBodyMaintenance,
) -> anyhow::Result<()> {
    let after: i64 =
        sqlx::query_scalar("SELECT coalesce(max(seq),0) FROM rss_transactional_messaging.outbox")
            .fetch_one(owner)
            .await?;
    for (n, len) in [8usize, 65536, 32, 16].into_iter().enumerate() {
        let payload: Vec<u8> = (0..len.div_ceil(32))
            .flat_map(|block| {
                ring::digest::digest(&ring::digest::SHA256, &block.to_be_bytes())
                    .as_ref()
                    .to_vec()
            })
            .take(len)
            .collect();
        let body = MessageEnvelope::new(
            MessageId::parse(&format!("byte-page-{n}"))?,
            metadata(),
            payload,
        );
        sqlx::query("SELECT rss_transactional_messaging.append_outbox($1,$2)")
            .bind(body.canonical_bytes())
            .bind(serde_json::json!({"trace":null,"tenant_authority":null}))
            .execute(owner)
            .await?;
    }
    sqlx::query("UPDATE rss_transactional_messaging.outbox SET status='published',automatic_retry_deadline=timestamptz 'epoch' WHERE message_id LIKE 'byte-page-%'").execute(owner).await?;
    let coords:Vec<i64>=sqlx::query_scalar("SELECT seq FROM rss_transactional_messaging.outbox WHERE message_id LIKE 'byte-page-%' ORDER BY seq").fetch_all(owner).await?;
    let stored: i32 = sqlx::query_scalar(
        "SELECT pg_column_size(payload) FROM rss_transactional_messaging.outbox WHERE seq=$1",
    )
    .bind(coords[1])
    .fetch_one(owner)
    .await?;
    assert!(
        stored > 32 * 1024,
        "oversized body requires external TOAST storage"
    );
    let page = async |cursor, limit, budget| -> anyhow::Result<PublishedBodyPage> {
        committed(
            maintenance
                .reclaim(
                    crate::execution(tenant(), 1),
                    PublishedBodyRetention::new(i64::MAX, cursor, limit, budget)?,
                    deadline(),
                )
                .await,
        )
    };
    assert!(PublishedBodyRetention::new(i64::MAX, after, 1, 0).is_err());
    assert!(PublishedBodyRetention::new(i64::MAX, after, 1, u64::MAX).is_err());
    let first = page(after, 4, 8).await?;
    assert_eq!(
        (
            first.scanned,
            first.reclaimed,
            first.verified_bytes,
            first.released_bytes,
            first.next_seq
        ),
        (2, 1, 8, 8, coords[0])
    );
    let oversized = PublishedBodyStop::ByteLimit {
        required_bytes: 65536,
    };
    assert_eq!(first.stop, oversized);
    let again = page(first.next_seq, 4, 64000).await?;
    assert_eq!(
        (
            again.scanned,
            again.reclaimed,
            again.verified_bytes,
            again.next_seq,
            again.stop
        ),
        (1, 0, 0, coords[0], oversized)
    );
    let full = page(again.next_seq, 1, 65536).await?;
    assert_eq!(
        (
            full.stop,
            full.scanned,
            full.verified_bytes,
            full.released_bytes,
            full.next_seq
        ),
        (
            PublishedBodyStop::CandidateLimit,
            1,
            65536,
            65536,
            coords[1]
        )
    );
    sqlx::query("UPDATE rss_transactional_messaging.outbox SET payload=payload||decode('01','hex') WHERE seq=$1").bind(coords[3]).execute(owner).await?;
    assert!(page(full.next_seq, 4, 100).await.is_err());
    let retained:i64=sqlx::query_scalar("SELECT count(*) FROM rss_transactional_messaging.outbox WHERE seq=ANY($1) AND payload IS NOT NULL").bind(&coords[2..]).fetch_one(owner).await?;
    assert_eq!(retained, 2, "corruption rolls back the preceding release");
    sqlx::query("UPDATE rss_transactional_messaging.outbox SET payload=substring(payload FROM 1 FOR 16) WHERE seq=$1").bind(coords[3]).execute(owner).await?;
    maintenance.inject_next_transaction_fault(PgTransactionFault::CommitUnknownAfterAck);
    let unknown = maintenance
        .reclaim(
            crate::execution(tenant(), 1),
            PublishedBodyRetention::new(i64::MAX, full.next_seq, 4, 40)?,
            deadline(),
        )
        .await;
    assert!(unknown.fold(
        |_| false,
        |_| false,
        |_| false,
        |_| false,
        |_| true,
        |_| false
    ));
    let retried = page(full.next_seq, 4, 16).await?;
    assert_eq!(
        (
            retried.stop,
            retried.scanned,
            retried.reclaimed,
            retried.verified_bytes,
            retried.next_seq
        ),
        (PublishedBodyStop::Complete, 1, 1, 16, coords[3])
    );
    assert_eq!(page(after, 4, 1).await?.scanned, 0);
    Ok(())
}
