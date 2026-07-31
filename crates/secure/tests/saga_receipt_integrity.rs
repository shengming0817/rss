use secure::{
    RedactionHashKey, SagaReceiptFingerprint, SagaReceiptIntegrityKeyId,
    SagaReceiptIntegrityKeyring, VersionedSagaReceiptIntegrityKey,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const CURRENT_KEY_ID: &str = "receipt-v4";
const PREVIOUS_KEY_IDS: [(&str, u8); 3] = [
    ("receipt-v3", 0x33),
    ("receipt-v2", 0x22),
    ("receipt-v1", 0x11),
];
const COMPONENTS: [&[u8]; 3] = [b"tenant-a", b"step-a", b"{\"ok\":true}"];

fn key(id: &str, fill: u8) -> TestResult<VersionedSagaReceiptIntegrityKey> {
    Ok(VersionedSagaReceiptIntegrityKey::new(
        SagaReceiptIntegrityKeyId::parse(id)?,
        RedactionHashKey::from_bytes(vec![fill; 32])?,
    ))
}

fn fingerprint(id: &str, fill: u8) -> TestResult<SagaReceiptFingerprint> {
    Ok(SagaReceiptIntegrityKeyring::new(key(id, fill)?, Vec::new())?.current(&COMPONENTS))
}

#[test]
fn every_rotation_window_position_verifies_an_exact_mac() -> TestResult {
    let previous = PREVIOUS_KEY_IDS
        .into_iter()
        .map(|(id, fill)| key(id, fill))
        .collect::<TestResult<Vec<_>>>()?;
    let ring = SagaReceiptIntegrityKeyring::new(key(CURRENT_KEY_ID, 0x44)?, previous)?;

    let current = fingerprint(CURRENT_KEY_ID, 0x44)?;
    assert_eq!(current.key_id().as_str(), CURRENT_KEY_ID);
    assert!(ring.verify(&COMPONENTS, &current));
    for (id, fill) in PREVIOUS_KEY_IDS {
        assert!(ring.verify(&COMPONENTS, &fingerprint(id, fill)?));
    }

    let changed = [
        b"tenant-a".as_slice(),
        b"step-b".as_slice(),
        b"{\"ok\":true}".as_slice(),
    ];
    assert!(!ring.verify(&changed, &current));
    Ok(())
}

#[test]
fn unknown_and_similar_key_ids_fail_closed() -> TestResult {
    let ring = SagaReceiptIntegrityKeyring::new(key("receipt-prod", 0x42)?, Vec::new())?;
    let valid = ring.current(&COMPONENTS);

    for candidate_id in ["unknown", "receipt-pro", "receipt-prodx", "xreceipt-prod"] {
        let candidate = SagaReceiptFingerprint::from_stored(
            SagaReceiptIntegrityKeyId::parse(candidate_id)?,
            valid.as_bytes().to_vec(),
        )?;
        assert!(!ring.verify(&COMPONENTS, &candidate));
    }
    Ok(())
}

#[test]
fn exact_key_id_rejects_an_invalid_mac() -> TestResult {
    let ring = SagaReceiptIntegrityKeyring::new(key(CURRENT_KEY_ID, 0x44)?, Vec::new())?;
    let valid = ring.current(&COMPONENTS);
    let mut invalid_digest = valid.as_bytes().to_vec();
    invalid_digest[0] ^= 1;
    let invalid = SagaReceiptFingerprint::from_stored(
        SagaReceiptIntegrityKeyId::parse(CURRENT_KEY_ID)?,
        invalid_digest,
    )?;

    assert!(!ring.verify(&COMPONENTS, &invalid));
    Ok(())
}

#[test]
fn stored_fingerprint_is_redacted_and_malformed_values_are_rejected() -> TestResult {
    let id = SagaReceiptIntegrityKeyId::parse(PREVIOUS_KEY_IDS[2].0)?;
    let fingerprint = SagaReceiptFingerprint::from_stored(id, vec![0x55; 32])?;
    assert_eq!(
        format!("{fingerprint:?}"),
        "SagaReceiptFingerprint { key_id: SagaReceiptIntegrityKeyId(\"receipt-v1\"), digest: \"<redacted>\" }"
    );
    assert!(
        SagaReceiptFingerprint::from_stored(
            SagaReceiptIntegrityKeyId::parse(PREVIOUS_KEY_IDS[2].0)?,
            vec![0x55; 31],
        )
        .is_err()
    );
    assert!(SagaReceiptIntegrityKeyId::parse("../unsafe").is_err());
    Ok(())
}

#[test]
fn duplicate_key_ids_are_rejected() -> TestResult {
    assert!(
        SagaReceiptIntegrityKeyring::new(
            key(PREVIOUS_KEY_IDS[2].0, 0x42)?,
            vec![key(PREVIOUS_KEY_IDS[2].0, 0x24)?],
        )
        .is_err()
    );
    Ok(())
}
