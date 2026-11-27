#![cfg(feature = "ledger")]
#![allow(missing_docs)]

use rss_audit_core::{
    AUDIT_CHAIN_ID, Action, ActorId, ActorKind, ActorRef, AuditEventV1, AuditPayload, Coordinates,
    DecodedAuditWindow, Error, EventContext, EventFacts, EventId, OperationId, Outcome,
    RecordIdentity, ResourceId, ResourceKind, ResourceRef, SourceContract, SourceId,
    SourceIdentity, prepare,
};
use rss_contract::{ContractId, ContractVersion, SchemaDigest, Timepoint};
use rss_ledger::{AppendRequest, Authenticator, ChainId, Entry, KeyId, LedgerId, RecordId};
use rss_request_context::TenantId;

fn tenant(value: &str) -> Result<TenantId, Box<dyn std::error::Error>> {
    Ok(TenantId::parse(value)?)
}

fn event(tenant: TenantId, action: &str) -> Result<AuditEventV1, Box<dyn std::error::Error>> {
    Ok(AuditEventV1::new(
        RecordIdentity::new(
            tenant,
            SourceIdentity::new(
                SourceId::parse("rss-mdm")?,
                SourceContract::new(
                    ContractId::parse("mdm.access-event")?,
                    ContractVersion::from_major(1)?,
                    SchemaDigest::parse(
                        "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
                    )?,
                ),
            ),
            EventId::parse("operation-7")?,
        ),
        EventFacts::new(
            ActorRef::new(ActorKind::parse("device")?, ActorId::parse("device-7")?),
            Action::parse(action)?,
            ResourceRef::new(
                ResourceKind::parse("registration")?,
                ResourceId::parse("registration-7")?,
            ),
            Outcome::Succeeded,
            Timepoint::try_from(1_726_000_000_i64)?,
        ),
        EventContext::new(
            Coordinates::new(None, None, Some(OperationId::parse("operation-7")?)),
            AuditPayload::new(Vec::new())?,
        ),
    ))
}

fn authenticator() -> Result<Authenticator, Box<dyn std::error::Error>> {
    Ok(Authenticator::new(
        KeyId::parse("audit-key-v1")?,
        vec![0x5a; 32],
    )?)
}

#[test]
fn same_identity_and_bytes_replay_but_changed_content_conflicts()
-> Result<(), Box<dyn std::error::Error>> {
    let tenant = tenant("018f47c2-8bd8-7f21-a52b-8d4f6ee2b203")?;
    let recorded = Timepoint::try_from(1_726_000_001_i64)?;
    let first = prepare(event(tenant, "device_enrolled")?, recorded)?;
    let replay = prepare(event(tenant, "device_enrolled")?, recorded)?;
    let changed = prepare(event(tenant, "device_retired")?, recorded)?;
    let entry = authenticator()?.append(&first.append_request()?, None)?;
    assert!(replay.matches_entry(&entry));
    assert!(!changed.matches_entry(&entry));
    assert_eq!(
        first.append_request()?.record_id(),
        changed.append_request()?.record_id()
    );
    Ok(())
}

#[test]
fn verified_window_rechecks_audit_identity() -> Result<(), Box<dyn std::error::Error>> {
    let tenant = tenant("018f47c2-8bd8-7f21-a52b-8d4f6ee2b203")?;
    let prepared = prepare(
        event(tenant, "device_enrolled")?,
        Timepoint::try_from(1_726_000_001_i64)?,
    )?;
    let auth = authenticator()?;
    let entry = auth.append(&prepared.append_request()?, None)?;
    let ledger = entry.ledger();
    let window = auth.verify_window(ledger, None, vec![entry.clone()])?;
    let verified = DecodedAuditWindow::from_ledger(tenant, &window)?.verify_identities()?;
    assert_eq!(verified.ledger_verification().count(), 1);
    assert_eq!(verified.records().len(), 1);
    assert_eq!(verified.records()[0].sequence().get(), 0);

    let mut tampered_payload = entry.payload().to_vec();
    tampered_payload.push(0);
    let tampered_request = AppendRequest::new(
        entry.ledger().clone(),
        entry.record_id().clone(),
        tampered_payload,
    )?;
    let tampered = Entry::from_parts(
        tampered_request,
        entry.sequence(),
        entry.previous_tag(),
        entry.tag(),
        entry.encoding(),
        entry.key_id().clone(),
    );
    assert!(matches!(
        auth.verify_window(ledger, None, vec![tampered]),
        Err(rss_ledger::Error::Authentication)
    ));

    let wrong_id = AppendRequest::new(
        LedgerId::new(tenant, entry.ledger().chain().clone()),
        RecordId::parse("v1:rss-mdm:different-event")?,
        prepared.canonical_bytes().to_vec(),
    )?;
    let wrong_entry = auth.append(&wrong_id, None)?;
    assert!(matches!(
        DecodedAuditWindow::from_ledger(
            tenant,
            &auth.verify_window(ledger, None, vec![wrong_entry])?
        )?
        .verify_identities(),
        Err(Error::IdentityMismatch)
    ));

    let other_tenant = TenantId::parse("018f47c2-8bd8-7f21-a52b-8d4f6ee2b204")?;
    let other_prepared = prepare(
        event(other_tenant, "device_enrolled")?,
        Timepoint::try_from(1_726_000_001_i64)?,
    )?;
    let cross_tenant_request = AppendRequest::new(
        LedgerId::new(tenant, entry.ledger().chain().clone()),
        other_prepared.append_request()?.record_id().clone(),
        other_prepared.canonical_bytes().to_vec(),
    )?;
    let cross_tenant_entry = auth.append(&cross_tenant_request, None)?;
    assert!(matches!(
        DecodedAuditWindow::from_ledger(
            tenant,
            &auth.verify_window(ledger, None, vec![cross_tenant_entry])?
        )?
        .verify_identities(),
        Err(Error::IdentityMismatch)
    ));
    Ok(())
}

#[test]
fn offline_reports_the_first_invalid_record() -> Result<(), Box<dyn std::error::Error>> {
    let tenant = tenant("018f47c2-8bd8-7f21-a52b-8d4f6ee2b203")?;
    let data = prepare(event(tenant, "audit")?, Timepoint::try_from(1_i64)?)?;
    let ledger = data.append_request()?.ledger().clone();
    let auth = authenticator()?;
    let wrong = AppendRequest::new(
        ledger.clone(),
        RecordId::parse("wrong")?,
        data.canonical_bytes().to_vec(),
    )?;
    let first = auth.append(&wrong, None)?;
    let malformed = AppendRequest::new(ledger.clone(), RecordId::parse("malformed")?, vec![])?;
    let second = auth.append(&malformed, Some(&first))?;
    let window = auth.verify_window(&ledger, None, vec![first, second])?;
    let decoded = DecodedAuditWindow::from_ledger(tenant, &window)?;
    assert_eq!(decoded.check_complete(), Err(Error::MalformedEncoding));
    assert!(matches!(
        decoded.verify_identities(),
        Err(Error::IdentityMismatch)
    ));
    Ok(())
}

#[test]
fn empty_window_is_limited_evidence() -> Result<(), Box<dyn std::error::Error>> {
    let tenant = tenant("018f47c2-8bd8-7f21-a52b-8d4f6ee2b203")?;
    let auth = authenticator()?;
    let ledger = LedgerId::new(tenant, ChainId::parse(AUDIT_CHAIN_ID)?);
    let window = auth.verify_window(&ledger, None, vec![])?;
    let other = TenantId::parse("018f47c2-8bd8-7f21-a52b-8d4f6ee2b204")?;
    assert!(matches!(
        DecodedAuditWindow::from_ledger(other, &window),
        Err(Error::IdentityMismatch)
    ));
    let other_chain = LedgerId::new(tenant, ChainId::parse("other")?);
    let wrong = auth.verify_window(&other_chain, None, vec![])?;
    assert!(matches!(
        DecodedAuditWindow::from_ledger(tenant, &wrong),
        Err(Error::IdentityMismatch)
    ));
    let verified = DecodedAuditWindow::from_ledger(tenant, &window)?.verify_identities()?;
    assert_eq!(verified.ledger_verification().count(), 0);
    assert!(verified.records().is_empty());
    Ok(())
}

#[test]
fn recovery_preserves_the_exact_request_and_rejects_unknown_fields()
-> Result<(), Box<dyn std::error::Error>> {
    let prepared = prepare(
        event(
            tenant("018f47c2-8bd8-7f21-a52b-8d4f6ee2b203")?,
            "device_enrolled",
        )?,
        Timepoint::try_from(1_726_000_001_i64)?,
    )?;
    let restored =
        rss_audit_core::PreparedAuditV1::from_canonical_bytes(prepared.canonical_bytes())?;
    assert_eq!(restored.canonical_bytes(), prepared.canonical_bytes());
    assert_eq!(restored.append_request()?, prepared.append_request()?);
    let clone = restored.clone();
    assert_eq!(clone.canonical_bytes(), prepared.canonical_bytes());
    let mut unknown = prepared.canonical_bytes().to_vec();
    unknown.push(0);
    assert!(matches!(
        rss_audit_core::PreparedAuditV1::from_canonical_bytes(&unknown),
        Err(Error::UnknownField)
    ));
    Ok(())
}
