use rss_ledger::*;
use rss_request_context::TenantId;
fn scope() -> anyhow::Result<LedgerId> {
    Ok(LedgerId::new(
        TenantId::parse("10000000-0000-4000-8000-000000000001")?,
        ChainId::parse("chain")?,
    ))
}
fn signer() -> anyhow::Result<Authenticator> {
    Ok(Authenticator::new(KeyId::parse("key")?, vec![0x42; 32])?)
}
#[test]
fn links_and_idempotent_content() -> anyhow::Result<()> {
    let a = signer()?;
    let request = AppendRequest::new(
        scope()?,
        RecordId::parse("record")?,
        b"exact\0bytes".to_vec(),
    )?;
    let first = a.append(&request, None)?;
    assert_eq!(first.sequence().get(), 0);
    assert!(first.matches(&request));
    let second = a.append(
        &AppendRequest::new(scope()?, RecordId::parse("next")?, vec![])?,
        Some(&first),
    )?;
    assert_eq!(second.sequence().get(), 1);
    assert_eq!(
        a.verify_chain(&scope()?, &[first.clone(), second.clone()])?
            .count(),
        2
    );
    assert_eq!(
        a.verify_window(&scope()?, Some(&first), &[second])?.count(),
        1
    );
    assert_eq!(a.verify_chain(&scope()?, &[])?.count(), 0);
    Ok(())
}
#[test]
fn malformed_boundaries_fail() -> anyhow::Result<()> {
    assert!(ChainId::parse("").is_err());
    assert!(RecordId::parse("a\0b").is_err());
    assert!(KeyId::parse(&"x".repeat(256)).is_err());
    assert!(Authenticator::new(KeyId::parse("key")?, vec![1; 31]).is_err());
    assert_eq!(
        Sequence::new(u64::MAX).next(),
        Err(Error::SequenceExhausted)
    );
    assert_eq!(EncodingVersion::parse(2), Err(Error::UnsupportedEncoding));
    let a = signer()?;
    let e = a.append(
        &AppendRequest::new(scope()?, RecordId::parse("r")?, vec![])?,
        None,
    )?;
    let wrong = Authenticator::new(KeyId::parse("key")?, vec![7; 32])?;
    assert_eq!(wrong.verify(&e), Err(Error::Authentication));
    assert!(a.verify_chain(&scope()?, &[e.clone(), e]).is_err());
    Ok(())
}

#[test]
fn independent_canonical_and_hmac_vector() -> anyhow::Result<()> {
    // Independently generated using Python struct + stdlib hmac, not the Rust encoder.
    let a = signer()?;
    let e = a.append(
        &AppendRequest::new(
            scope()?,
            RecordId::parse("record")?,
            b"exact\0bytes".to_vec(),
        )?,
        None,
    )?;
    let hex = |v: &[u8]| v.iter().map(|b| format!("{b:02x}")).collect::<String>();
    assert_eq!(
        hex(&Authenticator::canonical_bytes(&e)?),
        "7273732e6c65646765722e656e7472790000011000000000004000800000000000000100000005636861696e0000000000000000000000067265636f7264000000036b65790000000000000000000000000000000000000000000000000000000000000000000000000000000b6578616374006279746573"
    );
    assert_eq!(
        hex(e.tag().as_bytes()),
        "e5f15e2b30c69251d735289bf54c4421989e59cd2c99c4ed7e792225da6113a5"
    );
    Ok(())
}

#[test]
fn every_authenticated_field_is_bound() -> anyhow::Result<()> {
    let a = signer()?;
    let r = AppendRequest::new(scope()?, RecordId::parse("r")?, b"payload".to_vec())?;
    let e = a.append(&r, None)?;
    let rebuild = |r: AppendRequest, s: Sequence, p: AuthenticationTag, k: KeyId| {
        Entry::from_parts(r, s, p, e.tag(), EncodingVersion::V1, k)
    };
    let other_tenant = LedgerId::new(
        TenantId::parse("10000000-0000-4000-8000-000000000002")?,
        ChainId::parse("chain")?,
    );
    let requests = [
        AppendRequest::new(other_tenant, RecordId::parse("r")?, b"payload".to_vec())?,
        AppendRequest::new(
            LedgerId::new(scope()?.tenant(), ChainId::parse("other")?),
            RecordId::parse("r")?,
            b"payload".to_vec(),
        )?,
        AppendRequest::new(scope()?, RecordId::parse("other")?, b"payload".to_vec())?,
        AppendRequest::new(scope()?, RecordId::parse("r")?, b"payloaD".to_vec())?,
    ];
    for request in requests {
        assert_eq!(
            a.verify(&rebuild(
                request,
                e.sequence(),
                e.previous_tag(),
                e.key_id().clone()
            )),
            Err(Error::Authentication)
        );
    }
    assert_eq!(
        a.verify(&rebuild(
            r.clone(),
            Sequence::new(1),
            e.previous_tag(),
            e.key_id().clone()
        )),
        Err(Error::Authentication)
    );
    assert_eq!(
        a.verify(&rebuild(
            r.clone(),
            e.sequence(),
            AuthenticationTag::from_bytes(&[1; 32])?,
            e.key_id().clone()
        )),
        Err(Error::Authentication)
    );
    assert_eq!(
        a.verify(&rebuild(
            r.clone(),
            e.sequence(),
            e.previous_tag(),
            KeyId::parse("other")?
        )),
        Err(Error::UnsupportedKey)
    );
    let altered_tag = Entry::from_parts(
        r,
        e.sequence(),
        e.previous_tag(),
        AuthenticationTag::from_bytes(&[1; 32])?,
        EncodingVersion::V1,
        e.key_id().clone(),
    );
    assert_eq!(a.verify(&altered_tag), Err(Error::Authentication));
    for size in [0, 1, 31, 33, 64] {
        assert!(AuthenticationTag::from_bytes(&vec![0; size]).is_err());
    }
    assert!(!format!("{a:?} {e:?}").contains("payload"));
    assert!(
        AppendRequest::new(
            scope()?,
            RecordId::parse("r")?,
            vec![0; MAX_PAYLOAD_BYTES + 1]
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn length_prefixes_and_window_anchor_are_unambiguous() -> anyhow::Result<()> {
    let a = signer()?;
    let make = |chain: &str, id: &str| -> anyhow::Result<Entry> {
        Ok(a.append(
            &AppendRequest::new(
                LedgerId::new(scope()?.tenant(), ChainId::parse(chain)?),
                RecordId::parse(id)?,
                vec![],
            )?,
            None,
        )?)
    };
    assert_ne!(
        Authenticator::canonical_bytes(&make("a", "bc")?)?,
        Authenticator::canonical_bytes(&make("ab", "c")?)?
    );
    let first = make("chain", "first")?;
    let second = a.append(
        &AppendRequest::new(scope()?, RecordId::parse("second")?, vec![])?,
        Some(&first),
    )?;
    let third = a.append(
        &AppendRequest::new(scope()?, RecordId::parse("third")?, vec![])?,
        Some(&second),
    )?;
    assert_eq!(
        a.verify_window(&scope()?, Some(&first), &[third]),
        Err(Error::SequenceGap)
    );
    assert!(
        a.verify_window(&scope()?, Some(&make("other", "r")?), &[])
            .is_err()
    );
    assert_eq!(a.verify_window(&scope()?, Some(&second), &[])?.count(), 0);
    let max = Entry::from_parts(
        AppendRequest::new(scope()?, RecordId::parse("max")?, vec![])?,
        Sequence::new(u64::MAX),
        first.previous_tag(),
        first.tag(),
        EncodingVersion::V1,
        KeyId::parse("key")?,
    );
    assert_eq!(
        a.verify_window(&scope()?, Some(&max), &[]),
        Err(Error::Authentication)
    );
    Ok(())
}
