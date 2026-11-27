#![allow(missing_docs)]

use rss_audit_core::{
    Action, ActorId, ActorKind, ActorRef, AuditEventV1, AuditPayload, Coordinates, Error,
    EventContext, EventFacts, EventId, Field, MAX_RECORD_BYTES, OperationId, Outcome,
    RecordIdentity, RecordVersion, ResourceId, ResourceKind, ResourceRef, SourceContract, SourceId,
    SourceIdentity, decode_untrusted, prepare,
};
use rss_contract::{ContractId, ContractVersion, SchemaDigest, Timepoint};
use rss_diag_context::CorrelationId;
use rss_request_context::{RequestId, TenantId};

fn event_with(
    action: &str,
    resource_kind: &str,
    payload: Vec<u8>,
) -> Result<AuditEventV1, Box<dyn std::error::Error>> {
    event_with_details(
        action,
        resource_kind,
        payload,
        Outcome::Succeeded,
        Coordinates::new(
            Some(CorrelationId::parse("corr-42")?),
            Some(RequestId::parse("request-42")?),
            Some(OperationId::parse("operation-42")?),
        ),
    )
}

fn event_with_details(
    action: &str,
    resource_kind: &str,
    payload: Vec<u8>,
    outcome: Outcome,
    coordinates: Coordinates,
) -> Result<AuditEventV1, Box<dyn std::error::Error>> {
    let tenant = TenantId::parse("018f47c2-8bd8-7f21-a52b-8d4f6ee2b203")?;
    let source = SourceIdentity::new(
        SourceId::parse("rss-identity")?,
        SourceContract::new(
            ContractId::parse("identity.security-event")?,
            ContractVersion::from_major(3)?,
            SchemaDigest::parse(
                "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            )?,
        ),
    );
    let identity = RecordIdentity::new(tenant, source, EventId::parse("event-42")?);
    let facts = EventFacts::new(
        ActorRef::new(
            ActorKind::parse("user")?,
            ActorId::parse("principal-sensitive")?,
        ),
        Action::parse(action)?,
        ResourceRef::new(
            ResourceKind::parse(resource_kind)?,
            ResourceId::parse("session-sensitive")?,
        ),
        outcome,
        Timepoint::try_from(1_726_000_000_i64)?,
    );
    let context = EventContext::new(coordinates, AuditPayload::new(payload)?);
    Ok(AuditEventV1::new(identity, facts, context))
}

fn event() -> Result<AuditEventV1, Box<dyn std::error::Error>> {
    event_with(
        "session_revoked",
        "session",
        br#"{"reason":"operator"}"#.to_vec(),
    )
}

fn decode_hex(value: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if !value.len().is_multiple_of(2) {
        return Err("hex fixture must have even length".into());
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair)?;
            Ok(u8::from_str_radix(text, 16)?)
        })
        .collect()
}

fn golden_v1() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    decode_hex(concat!(
        "7273732e61756469742e7265636f7264000001018f47c28bd87f21a52b8d4f6ee2b203",
        "0000000c7273732d6964656e74697479000000086576656e742d3432000000176964656e",
        "746974792e73656375726974792d6576656e7400000003000000477368613235363a3031",
        "32333435363738396162636465663031323334353637383961626364656630313233343536",
        "37383961626364656630313233343536373839616263646566000000047573657200000013",
        "7072696e636970616c2d73656e7369746976650000000f73657373696f6e5f7265766f6b",
        "65640000000773657373696f6e0000001173657373696f6e2d73656e7369746976650100",
        "00000066e0ab800000000066e0ab810100000007636f72722d3432010000000a72657175",
        "6573742d3432010000000c6f7065726174696f6e2d3432000000157b22726561736f6e22",
        "3a226f70657261746f72227d"
    ))
}

#[cfg(feature = "ledger")]
#[test]
fn prepares_exact_ledger_identity_and_bytes() -> Result<(), Box<dyn std::error::Error>> {
    let prepared = prepare(event()?, Timepoint::try_from(1_726_000_001_i64)?)?;
    assert_eq!(
        prepared.append_request()?.ledger().chain().as_str(),
        "rss.audit.v1"
    );
    assert_eq!(
        prepared.append_request()?.record_id().as_str(),
        "v1:rss-identity:event-42"
    );
    assert_eq!(
        prepared.append_request()?.payload(),
        prepared.canonical_bytes()
    );
    Ok(())
}

#[test]
fn canonical_v1_matches_independent_golden_bytes() -> Result<(), Box<dyn std::error::Error>> {
    let prepared = prepare(event()?, Timepoint::try_from(1_726_000_001_i64)?)?;
    let golden = golden_v1()?;
    assert_eq!(prepared.canonical_bytes(), golden);
    let decoded = decode_untrusted(&golden)?;
    assert_eq!(decoded.version(), RecordVersion::V1);
    assert_eq!(
        decoded.event().identity().source().source_id().as_str(),
        "rss-identity"
    );
    assert_eq!(decoded.event().facts().action().as_str(), "session_revoked");
    assert_eq!(decoded.recorded_at().unix_seconds(), 1_726_000_001);
    assert_eq!(
        decoded.event().context().payload().as_bytes(),
        br#"{"reason":"operator"}"#
    );
    Ok(())
}

#[test]
fn golden_v1_fixes_every_outcome_tag() -> Result<(), Box<dyn std::error::Error>> {
    const OUTCOME_OFFSET: usize = 251;
    for (outcome, expected_tag) in [
        (Outcome::Denied, 2),
        (Outcome::Failed, 3),
        (Outcome::Unknown, 4),
    ] {
        let mut expected = golden_v1()?;
        expected[OUTCOME_OFFSET] = expected_tag;
        let prepared = prepare(
            event_with_details(
                "session_revoked",
                "session",
                br#"{"reason":"operator"}"#.to_vec(),
                outcome,
                Coordinates::new(
                    Some(CorrelationId::parse("corr-42")?),
                    Some(RequestId::parse("request-42")?),
                    Some(OperationId::parse("operation-42")?),
                ),
            )?,
            Timepoint::try_from(1_726_000_001_i64)?,
        )?;
        assert_eq!(prepared.canonical_bytes(), expected);
        assert_eq!(
            decode_untrusted(&expected)?.event().facts().outcome(),
            outcome
        );
    }
    Ok(())
}

#[test]
fn golden_v1_fixes_absent_and_mixed_optional_tags() -> Result<(), Box<dyn std::error::Error>> {
    const OPTIONALS_OFFSET: usize = 268;
    let payload_suffix = decode_hex("000000157b22726561736f6e223a226f70657261746f72227d")?;

    let mut absent = golden_v1()?[..OPTIONALS_OFFSET].to_vec();
    absent.extend_from_slice(&[0, 0, 0]);
    absent.extend_from_slice(&payload_suffix);
    let absent_record = prepare(
        event_with_details(
            "session_revoked",
            "session",
            br#"{"reason":"operator"}"#.to_vec(),
            Outcome::Succeeded,
            Coordinates::new(None, None, None),
        )?,
        Timepoint::try_from(1_726_000_001_i64)?,
    )?;
    assert_eq!(absent_record.canonical_bytes(), absent);

    let mut mixed = golden_v1()?[..OPTIONALS_OFFSET].to_vec();
    mixed.extend_from_slice(&decode_hex("00010000000a726571756573742d343200")?);
    mixed.extend_from_slice(&payload_suffix);
    let mixed_record = prepare(
        event_with_details(
            "session_revoked",
            "session",
            br#"{"reason":"operator"}"#.to_vec(),
            Outcome::Succeeded,
            Coordinates::new(None, Some(RequestId::parse("request-42")?), None),
        )?,
        Timepoint::try_from(1_726_000_001_i64)?,
    )?;
    assert_eq!(mixed_record.canonical_bytes(), mixed);
    Ok(())
}

#[test]
fn length_prefixes_prevent_adjacent_field_ambiguity() -> Result<(), Box<dyn std::error::Error>> {
    let left = prepare(
        event_with("a", "bc", Vec::new())?,
        Timepoint::try_from(1_726_000_001_i64)?,
    )?;
    let right = prepare(
        event_with("ab", "c", Vec::new())?,
        Timepoint::try_from(1_726_000_001_i64)?,
    )?;
    assert_ne!(left.canonical_bytes(), right.canonical_bytes());
    Ok(())
}

#[test]
fn token_boundaries_are_byte_exact_and_fail_closed() {
    assert_eq!(
        SourceId::parse("").err(),
        Some(Error::Empty(Field::SourceId))
    );
    macro_rules! check_token {
        ($token:ty, $field:expr) => {
            assert_eq!(<$token>::parse(&"a".repeat(255)).err(), None);
            assert_eq!(
                <$token>::parse(&"a".repeat(256)).err(),
                Some(Error::TooLong($field))
            );
        };
    }
    check_token!(SourceId, Field::SourceId);
    check_token!(ActorKind, Field::ActorKind);
    check_token!(ResourceKind, Field::ResourceKind);
    check_token!(EventId, Field::EventId);
    check_token!(Action, Field::Action);
    check_token!(OperationId, Field::OperationId);
    assert_eq!(
        SourceId::parse("RSS").err(),
        Some(Error::InvalidCharacter(Field::SourceId))
    );
}

#[test]
fn reference_boundaries_are_byte_exact_and_fail_closed() {
    assert!(ActorId::parse(&"é".repeat(256)).is_ok());
    assert!(matches!(
        ActorId::parse(&"é".repeat(257)),
        Err(Error::TooLong(Field::ActorId))
    ));
    assert!(matches!(
        ResourceId::parse("line\nbreak"),
        Err(Error::InvalidCharacter(Field::ResourceId))
    ));
}

fn maximal_event(payload: Vec<u8>) -> Result<AuditEventV1, Box<dyn std::error::Error>> {
    let base = event()?;
    let token = "a".repeat(255);
    Ok(AuditEventV1::new(
        RecordIdentity::new(
            base.identity().tenant(),
            SourceIdentity::new(
                SourceId::parse(&token)?,
                base.identity().source().contract().clone(),
            ),
            EventId::parse(&token)?,
        ),
        EventFacts::new(
            ActorRef::new(ActorKind::parse(&token)?, ActorId::parse(&"é".repeat(256))?),
            Action::parse(&token)?,
            ResourceRef::new(
                ResourceKind::parse(&token)?,
                ResourceId::parse(&"é".repeat(256))?,
            ),
            Outcome::Succeeded,
            base.facts().occurred_at(),
        ),
        EventContext::new(
            Coordinates::new(
                Some(CorrelationId::parse(&token)?),
                Some(RequestId::parse(&"r".repeat(128))?),
                Some(OperationId::parse(&token)?),
            ),
            AuditPayload::new(payload)?,
        ),
    ))
}

#[test]
fn complete_record_budget_charges_payload_headers_and_identities()
-> Result<(), Box<dyn std::error::Error>> {
    let recorded = Timepoint::try_from(1_726_000_001_i64)?;
    let overhead = prepare(maximal_event(vec![])?, recorded)?
        .canonical_bytes()
        .len();
    let payload_size = MAX_RECORD_BYTES - overhead;
    assert!(payload_size > 65_536);
    let prepared = prepare(maximal_event(vec![7; payload_size])?, recorded)?;
    assert_eq!(prepared.canonical_bytes().len(), MAX_RECORD_BYTES);
    check_bounded_header(&prepared)?;
    let decoded = decode_untrusted(prepared.canonical_bytes())?;
    assert_eq!(
        decoded.event().context().payload().as_bytes(),
        vec![7; payload_size]
    );
    assert_eq!(
        decoded
            .event()
            .context()
            .coordinates()
            .correlation_id()
            .ok_or("correlation")?
            .as_str()
            .len(),
        255
    );
    assert_eq!(
        rss_audit_core::PreparedAuditV1::from_canonical_bytes(prepared.canonical_bytes())?
            .canonical_bytes(),
        prepared.canonical_bytes()
    );
    assert_eq!(
        prepare(maximal_event(vec![7; payload_size + 1])?, recorded).err(),
        Some(Error::RecordTooLarge)
    );
    assert!(matches!(
        AuditPayload::new(vec![0; MAX_RECORD_BYTES + 1]),
        Err(Error::RecordTooLarge)
    ));
    assert!(CorrelationId::parse(&"a".repeat(256)).is_err());
    assert!(RequestId::parse(&"a".repeat(129)).is_err());
    #[cfg(feature = "ledger")]
    {
        let request = prepared.append_request()?;
        assert_eq!(
            request.record_id().as_str(),
            format!("v1:{}:{}", "a".repeat(255), "a".repeat(255))
        );
        assert_eq!(request.record_id().as_str().len(), 514);
        let auth = rss_ledger::Authenticator::new(rss_ledger::KeyId::parse("key")?, vec![7; 32])?;
        let entry = auth.append(&request, None)?;
        assert!(prepared.matches_entry(&entry));
        assert_eq!(
            rss_audit_core::DecodedAuditWindow::from_ledger(
                prepared.identity().tenant(),
                &auth.verify_window(request.ledger(), None, vec![entry])?
            )?
            .verify_identities()?
            .records()
            .len(),
            1
        );
    }
    Ok(())
}

#[test]
fn decoder_rejects_complete_records_over_the_v1_budget_first() {
    let oversized = vec![0; MAX_RECORD_BYTES + 1];
    assert!(matches!(
        decode_untrusted(&oversized),
        Err(Error::RecordTooLarge)
    ));
}

#[test]
fn decoder_rejects_version_tags_truncation_and_unknown_fields()
-> Result<(), Box<dyn std::error::Error>> {
    let canonical = prepare(event()?, Timepoint::try_from(1_726_000_001_i64)?)?
        .canonical_bytes()
        .to_vec();

    let mut version = canonical.clone();
    version[18] = 2;
    assert!(matches!(
        decode_untrusted(&version),
        Err(Error::UnsupportedVersion)
    ));

    let correlation = b"corr-42";
    let correlation_offset = canonical
        .windows(correlation.len())
        .position(|window| window == correlation)
        .ok_or("correlation fixture missing")?;
    let mut optional_tag = canonical.clone();
    optional_tag[correlation_offset - 5] = 2;
    assert!(matches!(
        decode_untrusted(&optional_tag),
        Err(Error::UnsupportedTag)
    ));

    let resource = b"session-sensitive";
    let resource_offset = canonical
        .windows(resource.len())
        .position(|window| window == resource)
        .ok_or("resource fixture missing")?;
    let mut outcome_tag = canonical.clone();
    outcome_tag[resource_offset + resource.len()] = 9;
    assert!(matches!(
        decode_untrusted(&outcome_tag),
        Err(Error::UnsupportedTag)
    ));

    let payload = br#"{"reason":"operator"}"#;
    let payload_offset = canonical
        .windows(payload.len())
        .position(|window| window == payload)
        .ok_or("payload fixture missing")?;
    let mut oversized_payload = canonical.clone();
    oversized_payload[payload_offset - 4..payload_offset]
        .copy_from_slice(&((MAX_RECORD_BYTES + 1) as u32).to_be_bytes());
    assert!(matches!(
        decode_untrusted(&oversized_payload),
        Err(Error::RecordTooLarge)
    ));

    let mut truncated = canonical.clone();
    let _ = truncated.pop();
    assert!(matches!(
        decode_untrusted(&truncated),
        Err(Error::MalformedEncoding)
    ));

    let mut trailing = canonical;
    trailing.push(0);
    assert!(matches!(
        decode_untrusted(&trailing),
        Err(Error::UnknownField)
    ));
    Ok(())
}

#[test]
fn decoder_preserves_empty_source_contract_diagnostics() -> Result<(), Box<dyn std::error::Error>> {
    const CONTRACT_LENGTH_OFFSET: usize = 63;
    const CONTRACT_BYTES: usize = 23;
    const DIGEST_LENGTH_OFFSET: usize = 94;
    const DIGEST_BYTES: usize = 71;

    let mut empty_contract = golden_v1()?;
    empty_contract[CONTRACT_LENGTH_OFFSET..CONTRACT_LENGTH_OFFSET + 4]
        .copy_from_slice(&0_u32.to_be_bytes());
    empty_contract.drain(CONTRACT_LENGTH_OFFSET + 4..CONTRACT_LENGTH_OFFSET + 4 + CONTRACT_BYTES);
    assert!(matches!(
        decode_untrusted(&empty_contract),
        Err(Error::Empty(Field::SourceContract))
    ));

    let mut empty_digest = golden_v1()?;
    empty_digest[DIGEST_LENGTH_OFFSET..DIGEST_LENGTH_OFFSET + 4]
        .copy_from_slice(&0_u32.to_be_bytes());
    empty_digest.drain(DIGEST_LENGTH_OFFSET + 4..DIGEST_LENGTH_OFFSET + 4 + DIGEST_BYTES);
    assert!(matches!(
        decode_untrusted(&empty_digest),
        Err(Error::Empty(Field::SourceContract))
    ));
    Ok(())
}

#[test]
fn debug_output_redacts_sensitive_values() -> Result<(), Box<dyn std::error::Error>> {
    let bait = "token-secret-line";
    assert!(format!("{bait:?}").contains(bait));
    let actor = ActorId::parse(bait)?;
    let resource = ResourceId::parse(bait)?;
    let payload = AuditPayload::new(bait.as_bytes().to_vec())?;
    for rendered in [
        format!("{actor:?}"),
        format!("{resource:?}"),
        format!("{payload:?}"),
        format!("{:?}", event()?),
        format!(
            "{:?}",
            prepare(event()?, Timepoint::try_from(1_726_000_001_i64)?)?
        ),
    ] {
        assert!(!rendered.contains(bait), "sensitive Debug leak: {rendered}");
    }
    assert_eq!(payload.as_bytes(), bait.as_bytes());
    Ok(())
}

#[test]
fn recovery_adopts_the_validated_allocation_and_shares_summary()
-> Result<(), Box<dyn std::error::Error>> {
    let bytes = golden_v1()?;
    let address = bytes.as_ptr();
    assert_eq!(rss_audit_core::canonical_len(&event()?)?, bytes.len());
    let prepared = rss_audit_core::PreparedAuditV1::from_canonical_bytes(bytes)?;
    assert_eq!(prepared.clone().canonical_bytes().as_ptr(), address);
    assert_eq!(prepared.action().as_str(), "session_revoked");
    assert_eq!(prepared.outcome(), Outcome::Succeeded);
    assert_eq!(prepared.occurred_at().unix_seconds(), 1_726_000_000);
    let mut corrupt = prepared.canonical_bytes().to_vec();
    corrupt.push(0);
    assert_eq!(
        rss_audit_core::PreparedAuditV1::from_canonical_bytes(corrupt).err(),
        Some(Error::UnknownField)
    );
    Ok(())
}

fn check_bounded_header(
    prepared: &rss_audit_core::PreparedAuditV1,
) -> Result<(), Box<dyn std::error::Error>> {
    let bytes = prepared.canonical_bytes();
    let prefix = &bytes[..rss_audit_core::MAX_HEADER_BYTES];
    let (identity, time) = rss_audit_core::inspect_canonical_header(prefix, bytes.len())?;
    assert_eq!(
        identity.event_id().as_str(),
        prepared.identity().event_id().as_str()
    );
    assert_eq!(time, prepared.recorded_at());
    assert!(rss_audit_core::inspect_canonical_header(prefix, bytes.len() - 1).is_err());
    Ok(())
}
