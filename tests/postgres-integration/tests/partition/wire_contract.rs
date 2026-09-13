//! Independent SQL client rejects malformed canonical input before any durable effect.
use super::*;

async fn append(
    tx: &mut PgConnection,
    bytes: Vec<u8>,
    transport: serde_json::Value,
) -> Result<String, sqlx::Error> {
    sqlx::query_scalar("SELECT rss_transactional_messaging.append_outbox($1,$2)")
        .bind(bytes)
        .bind(transport)
        .fetch_one(tx)
        .await
}

pub(super) async fn run(runtime: Arc<PgRuntime>, raw: &PgPool) -> anyhow::Result<()> {
    rejects(raw).await?;
    complete_message(runtime, raw).await
}

#[allow(clippy::cognitive_complexity)] // reason: one table of malformed SQL inputs keeps every rejection adjacent to its rollback.
async fn rejects(raw: &PgPool) -> anyhow::Result<()> {
    let item = ordered("wire-invalid", "sql-wire", "one");
    let valid = frames(&item);
    let mut malformed = vec![Vec::new(), vec![0; 8]];
    for (tag, replacement) in [
        (0, b"rss-transactional-message-v2".to_vec()),
        (1, b"bad id".to_vec()),
        (1, vec![b'a'; 256]),
        (2, vec![0; 15]),
        (3, vec![255; 8]),
        (4, vec![2]),
        (5, b"bad domain".to_vec()),
        (6, vec![255]),
        (7, b"no-dot".to_vec()),
        (8, vec![0; 4]),
        (9, b"sha256:invalid".to_vec()),
        (10, vec![2]),
        (11, vec![0; 16]),
        (12, b"other-domain".to_vec()),
        (13, b"\n".to_vec()),
        (14, vec![2]),
        (15, vec![255; 8]),
    ] {
        let mut altered = valid.clone();
        altered
            .iter_mut()
            .find(|(t, _)| *t == tag)
            .expect("field")
            .1 = replacement;
        malformed.push(wire(&altered));
    }
    for index in 0..valid.len() {
        let mut altered = valid.clone();
        altered.remove(index);
        malformed.push(wire(&altered));
    }
    let mut trailing = wire(&valid);
    trailing.push(0);
    malformed.push(trailing);
    let mut truncated = wire(&valid);
    truncated.pop();
    malformed.push(truncated);
    let mut length = wire(&valid);
    length[1..9].fill(255);
    malformed.push(length);
    for bytes in malformed {
        let mut tx = sql_tx(raw, item.metadata().tenant_id()).await?;
        sql_prepare(&mut tx, serde_json::json!([["sql-wire", "one"]])).await?;
        let error = append(&mut tx, bytes, transport(&item))
            .await
            .expect_err("malformed canonical input rejected");
        assert_eq!(code(&error).as_deref(), Some("22023"));
        tx.rollback().await?;
    }
    for invalid in [
        serde_json::json!({}),
        serde_json::json!({"trace":4,"tenant_authority":null}),
        serde_json::json!({"trace":null,"tenant_authority":null,"payload":[99]}),
    ] {
        let mut tx = sql_tx(raw, item.metadata().tenant_id()).await?;
        let error = append(&mut tx, wire(&valid), invalid)
            .await
            .expect_err("transport cannot supply authored fields");
        assert_eq!(code(&error).as_deref(), Some("22023"));
        tx.rollback().await?;
    }
    let mut tx = sql_tx(
        raw,
        TenantId::parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")?,
    )
    .await?;
    let error = append(&mut tx, wire(&valid), transport(&item))
        .await
        .expect_err("tenant binding checked");
    assert_eq!(code(&error).as_deref(), Some("22023"));
    tx.rollback().await?;
    Ok(())
}

#[allow(clippy::cognitive_complexity)] // reason: one full-contract vector exercises the independent SQL encoder and all authored fields together.
async fn complete_message(runtime: Arc<PgRuntime>, raw: &PgPool) -> anyhow::Result<()> {
    use rss_contract::{ContractId, ContractVersion, SchemaDigest, Timepoint};
    use rss_diag_context::CorrelationId;
    let template = ordered("wire-complete", "sql-wire", "ключ");
    let item = MessageEnvelope::new(
        template.id().clone(),
        MessageMetadata::new(
            AuthoredMessageMetadata::new(
                template.metadata().tenant_id(),
                Timepoint::try_from(i64::MAX)?,
                template.metadata().domain().clone(),
                template.metadata().route().clone(),
                ContractIdentity::new(
                    ContractId::parse("wire.event-v1")?,
                    ContractVersion::from_major(u32::MAX)?,
                    SchemaDigest::parse(&format!("sha256:{}", "f".repeat(64)))?,
                ),
            ),
            MessageMetadataExtensions::new(
                Some(CorrelationId::parse("trace-1")?),
                Some(PartitionKey::parse("ключ")?),
                Some(MessageId::parse("cause-1")?),
                std::collections::BTreeMap::from([
                    ("a".into(), "".into()),
                    ("é".into(), "世界".into()),
                ]),
            ),
        ),
        vec![0, 127, 128, 255],
    );
    let mut tx = sql_tx(raw, item.metadata().tenant_id()).await?;
    sql_prepare(&mut tx, serde_json::json!([["sql-wire", "ключ"]])).await?;
    assert_eq!(sql_append(&mut tx, &item).await?, "inserted");
    assert_eq!(
        append(
            &mut tx,
            wire(&frames(&item)),
            serde_json::json!({"trace":"different","tenant_authority":"different"})
        )
        .await?,
        "already_present"
    );
    let (digest,envelope):(Vec<u8>,serde_json::Value)=sqlx::query_as("SELECT fingerprint,envelope FROM rss_transactional_messaging.outbox WHERE message_id='wire-complete'").fetch_one(&mut *tx).await?;
    assert_eq!(digest, MessageFingerprint::of(&item).as_bytes());
    let vector: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../crates/transactional-messaging/message-wire-v1-vector.json"
    )))?;
    let hex = |bytes: &[u8]| {
        bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };
    assert_eq!(
        hex(&digest),
        vector["sha256"].as_str().expect("digest vector")
    );
    assert_eq!(
        hex(&item.canonical_bytes()),
        vector["canonical_hex"].as_str().expect("wire vector")
    );
    assert_eq!(
        envelope["attributes"],
        serde_json::json!({"a":"","é":"世界"})
    );
    assert_eq!(envelope["payload"], serde_json::json!([0, 127, 128, 255]));
    assert_eq!(envelope["version"], "v4294967295");
    tx.commit().await?;
    let store = PgOutboxStore::<()>::new(
        runtime,
        MessagingDomain::parse("sql-wire")?,
        outbox_budget(Duration::from_secs(30)),
    )?;
    let claim = store
        .claim_partition_heads(NonZeroUsize::MIN, deadline())
        .await?
        .into_iter()
        .next()
        .expect("SQL message is relay-decodable");
    assert_eq!(
        PgOutboxStore::<()>::message(&claim)
            .envelope()
            .canonical_bytes(),
        item.canonical_bytes()
    );
    store
        .settle(claim, OutboxSettlement::Published(()), deadline())
        .await?;
    // Duplicate and unsorted attributes would give multiple encodings of one authored map.
    for reverse in [false, true] {
        let mut fields = frames(&item);
        let start = fields
            .iter()
            .position(|(tag, _)| *tag == 16)
            .expect("attributes");
        if reverse {
            fields.swap(start, start + 2);
            fields.swap(start + 1, start + 3);
        } else {
            fields[start + 2].1 = fields[start].1.clone();
        }
        let mut tx = sql_tx(raw, item.metadata().tenant_id()).await?;
        let error = append(&mut tx, wire(&fields), transport(&item))
            .await
            .expect_err("noncanonical map rejected");
        assert_eq!(code(&error).as_deref(), Some("22023"));
        tx.rollback().await?;
    }
    Ok(())
}
