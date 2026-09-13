use rss_saga::*;

fn definition() -> Result<Definition, Error> {
    Definition::new(
        "test",
        Identity::new(
            rss_contract::ContractId::from_static("history.test"),
            rss_contract::ContractVersion::from_static_major(1),
            rss_contract::SchemaDigest::from_static(
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
            ActionGeneration::parse(
                "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            )?,
        ),
        vec![StepSpec::new("one", "receipt.v1", "do", "undo", 3)?],
    )
}
fn event(seq: u64, attempt: u32, kind: EventKind) -> Event {
    Event {
        seq,
        step: 0,
        attempt,
        kind,
        receipt: None,
    }
}
#[test]
fn history_capacity_blocks_new_intent_but_preserves_pending_settlement() -> anyhow::Result<()> {
    let capacity = HistoryCapacity::new(5, 32 * 1024 * 1024)?;
    let read = ReadBudget::new(capacity, 1024 * 1024)?;
    let mut snapshot = Snapshot::empty(definition()?, capacity, read)?;
    snapshot.apply(event(0, 1, EventKind::ForwardIntent))?;
    snapshot.apply(event(1, 1, EventKind::ForwardProbeNotApplied))?;
    assert_eq!(
        snapshot
            .apply(event(2, 2, EventKind::ForwardIntent))
            .err()
            .map(|e| e.kind()),
        Some(ErrorKind::HistoryLimited(HistoryLimit::DurableCapacity))
    );
    assert_eq!(snapshot.revision(), 2);
    assert_eq!(snapshot.status(), Status::Ready);
    Ok(())
}
#[test]
fn replay_budget_rejects_history_before_replaying_beyond_the_limit() -> anyhow::Result<()> {
    let capacity = HistoryCapacity::new(100, 64 * 1024 * 1024)?;
    let read = ReadBudget::new(HistoryCapacity::new(1, 32 * 1024 * 1024)?, 1024 * 1024)?;
    let mut snapshot = Snapshot::empty(definition()?, capacity, read)?;
    snapshot.replay(event(0, 1, EventKind::ForwardIntent))?;
    assert_eq!(
        snapshot
            .replay(event(1, 1, EventKind::ForwardProbeNotApplied))
            .err()
            .map(|e| e.kind()),
        Some(ErrorKind::HistoryReadLimit)
    );
    assert_eq!(snapshot.revision(), 1);
    Ok(())
}

#[test]
fn maximum_envelope_fits_the_admitted_settlement_reservation() -> anyhow::Result<()> {
    let bytes = "255,".repeat(2 * 1024 * 1024 - 1) + "255";
    let aad = "255,".repeat(4095) + "255";
    let digest = "255,".repeat(31) + "255";
    let wire = format!(
        "{{\"ciphertext\":{{\"key_ref\":\"{}\",\"bytes\":[{}]}},\"key_id\":\"{}\",\"digest\":[{}],\"aad\":[{}],\"format\":1,\"attempt\":1,\"seq\":1}}",
        "k".repeat(1024),
        bytes,
        "i".repeat(64),
        digest,
        aad
    );
    let receipt: ProtectedReceipt = serde_json::from_str(&wire)?;
    assert_eq!(receipt.encoded_bytes()?, RECEIPT_BYTES);
    let capacity = HistoryCapacity::new(5, 5 * EVENT_BYTES + RECEIPT_BYTES)?;
    let mut snapshot = Snapshot::empty(
        definition()?,
        capacity,
        ReadBudget::new(capacity, PLAINTEXT_BYTES)?,
    )?;
    snapshot.apply(event(0, 1, EventKind::ForwardIntent))?;
    snapshot.apply(Event {
        seq: 1,
        step: 0,
        attempt: 1,
        kind: EventKind::ForwardApplied,
        receipt: Some(receipt),
    })?;
    assert_eq!(snapshot.status(), Status::Succeeded);
    assert_eq!(
        snapshot.head().encoded_bytes(),
        2 * EVENT_BYTES + RECEIPT_BYTES
    );
    Ok(())
}

#[test]
fn authentication_work_is_reserved_before_admitting_an_effect() -> anyhow::Result<()> {
    let capacity = HistoryCapacity::new(100, 64 * 1024 * 1024)?;
    let mut snapshot = Snapshot::empty(
        definition()?,
        capacity,
        ReadBudget::new(capacity, PLAINTEXT_BYTES - 1)?,
    )?;
    assert_eq!(
        snapshot
            .apply(event(0, 1, EventKind::ForwardIntent))
            .err()
            .map(|e| e.kind()),
        Some(ErrorKind::HistoryLimited(HistoryLimit::ReadBudget))
    );
    assert_eq!(snapshot.revision(), 0);
    assert!(HistoryCapacity::new(u64::MAX, 1).is_err());
    assert!(
        serde_json::from_str::<HistoryCapacity>(
            "{\"maxEntries\":18446744073709551615,\"maxEncodedBytes\":1}"
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn a_durable_sequence_gap_is_integrity_failure_and_does_not_advance_replay() -> anyhow::Result<()> {
    let capacity = HistoryCapacity::new(100, 64 * 1024 * 1024)?;
    let mut snapshot = Snapshot::empty(
        definition()?,
        capacity,
        ReadBudget::new(capacity, PLAINTEXT_BYTES)?,
    )?;
    assert_eq!(
        snapshot
            .replay(event(1, 1, EventKind::ForwardIntent))
            .err()
            .map(|e| e.kind()),
        Some(ErrorKind::Integrity)
    );
    assert_eq!(snapshot.revision(), 0);
    Ok(())
}

#[test]
fn encoded_byte_read_limit_rejects_the_first_event_with_entries_available() -> anyhow::Result<()> {
    let capacity = HistoryCapacity::new(100, 64 * 1024 * 1024)?;
    let read = ReadBudget::new(HistoryCapacity::new(100, EVENT_BYTES - 1)?, PLAINTEXT_BYTES)?;
    let mut snapshot = Snapshot::empty(definition()?, capacity, read)?;
    assert_eq!(
        snapshot
            .replay(event(0, 1, EventKind::ForwardIntent))
            .err()
            .map(|e| e.kind()),
        Some(ErrorKind::HistoryReadLimit)
    );
    assert_eq!(snapshot.revision(), 0);
    assert_eq!(snapshot.head().encoded_bytes(), 0);
    assert_eq!(snapshot.status(), Status::Ready);
    Ok(())
}
