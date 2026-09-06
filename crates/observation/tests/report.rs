use rss_contract::Timepoint;
use rss_observation::*;
use rss_request_context::TenantId;
fn id(s: &str) -> Result<Id, Error> {
    Id::new(s)
}
fn scope() -> anyhow::Result<Scope> {
    Ok(Scope::new(
        TenantId::parse("00000000-0000-0000-0000-000000000001")?,
        id("object")?,
        Registration::new("registration")?,
        id("source")?,
        id("dataset")?,
        Epoch::new("epoch")?,
    ))
}
fn coverage() -> Result<Coverage, Error> {
    Ok(Coverage::new(
        id("all")?,
        id("1")?,
        id("definition")?,
        id("bytes")?,
    ))
}
fn batch(body: Body) -> anyhow::Result<Batch> {
    Ok(Batch::new(
        id("batch")?,
        1,
        Timepoint::try_from(10)?,
        coverage()?,
        body,
    )?)
}
#[test]
fn canonical_bytes_cover_all_inputs() -> anyhow::Result<()> {
    let a = Change::upsert(id("a")?, vec![0, 255]);
    let b = Change::upsert(id("b")?, vec![1]);
    let first = batch(Body::Snapshot(vec![a.clone(), b.clone()]))?;
    let reordered = batch(Body::Snapshot(vec![b, a]))?;
    assert_eq!(first, reordered);
    assert_eq!(
        first.fingerprint(&scope()?)?,
        reordered.fingerprint(&scope()?)?
    );
    assert_eq!(Batch::decode(first.encode())?, first);
    let original: serde_json::Value = serde_json::from_slice(first.encode())?;
    for (pointer, replacement) in [
        ("/id", serde_json::json!("other")),
        ("/sequence", serde_json::json!(2)),
        ("/observedAt", serde_json::json!(9)),
        ("/coverage/id", serde_json::json!("subset")),
        ("/coverage/version", serde_json::json!("2")),
        ("/coverage/definition", serde_json::json!("new-definition")),
        ("/coverage/format", serde_json::json!("new-format")),
        ("/body/data/0/key", serde_json::json!("new-key")),
        ("/body/data/0/value", serde_json::json!([3])),
    ] {
        let mut changed = original.clone();
        *changed
            .pointer_mut(pointer)
            .ok_or_else(|| anyhow::anyhow!("fixture pointer"))? = replacement;
        assert_ne!(
            Batch::decode(&serde_json::to_vec(&changed)?)?.fingerprint(&scope()?)?,
            first.fingerprint(&scope()?)?
        );
    }
    let scope_json = serde_json::to_value(scope()?)?;
    for key in [
        "tenant",
        "object",
        "registration",
        "source",
        "dataset",
        "epoch",
    ] {
        let mut changed = scope_json.clone();
        changed[key] = serde_json::json!(if key == "tenant" {
            "00000000-0000-0000-0000-000000000002"
        } else {
            "other"
        });
        let changed: Scope = serde_json::from_value(changed)?;
        assert_ne!(first.fingerprint(&changed)?, first.fingerprint(&scope()?)?);
    }
    let delta = batch(Body::Delta {
        baseline: id("base")?,
        previous: 0,
        changes: vec![Change::delete(id("key")?)],
    })?;
    let alternate = batch(Body::Delta {
        baseline: id("other")?,
        previous: 0,
        changes: vec![Change::delete(id("key")?)],
    })?;
    assert_ne!(
        delta.fingerprint(&scope()?)?,
        alternate.fingerprint(&scope()?)?
    );
    assert!(!format!("{first:?}").contains("definition"));
    Ok(())
}
#[test]
fn bounds_and_unknown_versions_are_rejected() -> anyhow::Result<()> {
    assert!(id("").is_err());
    assert!(id(&"x".repeat(257)).is_err());
    assert!(id("a\nb").is_err());
    assert!(batch(Body::Snapshot(vec![Change::delete(id("x")?)])).is_err());
    let item = Change::upsert(id("same")?, vec![]);
    assert!(batch(Body::Snapshot(vec![item.clone(), item.clone()])).is_err());
    assert!(batch(Body::Snapshot(vec![item; 1001])).is_err());
    assert!(
        batch(Body::Snapshot(vec![Change::upsert(
            id("large")?,
            vec![0; 65537]
        )]))
        .is_err()
    );
    let large = (0..100)
        .map(|i| Ok(Change::upsert(id(&i.to_string())?, vec![255; 65536])))
        .collect::<Result<Vec<_>, Error>>()?;
    assert!(batch(Body::Snapshot(large)).is_err());
    assert!(Batch::decode(&vec![b' '; 4194305]).is_err());
    let valid = batch(Body::Snapshot(vec![]))?;
    let mut value: serde_json::Value = serde_json::from_slice(valid.encode())?;
    value["version"] = 2.into();
    assert!(Batch::decode(&serde_json::to_vec(&value)?).is_err());
    value["version"] = 1.into();
    value["fragment"] = true.into();
    assert!(Batch::decode(&serde_json::to_vec(&value)?).is_err());
    Ok(())
}
struct Denied;
impl Authority for Denied {
    fn authorize(&self, _: &Scope, _: Option<&Coverage>, _: Access) -> Result<(), Error> {
        Err(ErrorKind::Unauthorized.into())
    }
}
#[test]
fn authority_cannot_come_from_report_fields() -> anyhow::Result<()> {
    assert!(VerifiedBatch::verify(&Denied, scope()?, batch(Body::Snapshot(vec![]))?).is_err());
    assert!(ReadGrant::verify(&Denied, scope()?).is_err());
    assert!(LifecycleGrant::verify(&Denied, scope()?).is_err());
    let err = Error::provider(ErrorKind::Storage, std::io::Error::other("secret-report"));
    assert!(!format!("{err:?} {err}").contains("secret-report"));
    Ok(())
}
