use rss_contract::{
    ContractDescriptor, ContractId, ContractVersion, IdentityError, PageCursor, PageCursorError,
    SchemaDigest, Timepoint, TimepointError,
};
use std::time::{Duration, SystemTime};

#[test]
fn canonical_values_round_trip() -> Result<(), IdentityError> {
    let id = ContractId::parse("runtime.inventory")?;
    let version = ContractVersion::parse("v12")?;
    let digest = SchemaDigest::parse(&format!("sha256:{}", "a".repeat(64)))?;
    assert_eq!(id.as_str(), "runtime.inventory");
    assert_eq!(version.to_string(), "v12");
    assert_eq!(digest.as_str().len(), 71);
    Ok(())
}

#[test]
fn rejects_noncanonical_values() {
    for value in ["", "1", "v0", "v01", "v-1"] {
        assert!(ContractVersion::parse(value).is_err(), "{value}");
    }
    assert!(SchemaDigest::parse(&format!("sha256:{}", "A".repeat(64))).is_err());
}

#[test]
fn identity_error_messages_are_stable_distinct_and_redacted() {
    let messages = [
        IdentityError::Empty,
        IdentityError::TooLong,
        IdentityError::InvalidFormat,
        IdentityError::ZeroVersion,
    ]
    .map(|error| error.to_string());
    assert_eq!(
        messages
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        4
    );
    assert!(messages.iter().all(|message| !message.contains("secret")));
}

#[test]
fn version_digest_and_descriptor_boundaries() -> Result<(), IdentityError> {
    assert_eq!(
        ContractVersion::from_major(0),
        Err(IdentityError::ZeroVersion)
    );
    assert_eq!(ContractVersion::from_major(7)?.major(), 7);
    assert!(ContractVersion::parse("v4294967296").is_err());
    let digest = format!("sha256:{}", "0".repeat(64));
    let parsed = SchemaDigest::parse(&digest)?;
    assert_eq!(parsed.to_string(), digest);
    assert!(SchemaDigest::parse("sha256:00").is_err());
    let descriptor = ContractDescriptor::from_static_version("runtime.inventory", "v12", DIGEST);
    assert_eq!(descriptor.id(), "runtime.inventory");
    assert_eq!(descriptor.version().major(), 12);
    assert_eq!(descriptor.schema_digest().len(), 71);
    assert_eq!(
        descriptor,
        ContractDescriptor::from_static("runtime.inventory", 12, DIGEST,)
    );
    assert_eq!(
        ContractId::from_static("runtime.inventory"),
        ContractId::parse("runtime.inventory")?
    );
    assert_eq!(
        SchemaDigest::from_static(DIGEST),
        SchemaDigest::parse(DIGEST)?
    );
    Ok(())
}

#[test]
#[allow(clippy::expect_used)]
fn timepoint_rejects_out_of_range_values_and_round_trips() {
    assert_eq!(Timepoint::try_from(-1), Err(TimepointError::BeforeEpoch));
    assert_eq!(
        Timepoint::try_from(SystemTime::UNIX_EPOCH - Duration::from_secs(1)),
        Err(TimepointError::BeforeEpoch)
    );
    assert_eq!(
        Timepoint::try_from_duration(Duration::from_secs(i64::MAX as u64 + 1)),
        Err(TimepointError::Overflow)
    );

    let epoch = Timepoint::try_from(0).expect("epoch is representable");
    let later = Timepoint::try_from(42).expect("timestamp is representable");
    assert!(epoch < later);
    assert_eq!(later.unix_seconds(), 42);
    assert_eq!(
        later
            .to_system_time()
            .expect("system time is representable"),
        SystemTime::UNIX_EPOCH + Duration::from_secs(42)
    );
    assert_eq!(
        Timepoint::try_from(i64::MAX)
            .expect("wire maximum is representable")
            .unix_seconds(),
        i64::MAX
    );
}

#[test]
#[allow(clippy::expect_used)]
fn page_cursor_accepts_only_bounded_canonical_base64url() {
    for raw in ["AQ", "AAE", "cGFnZTo0Mg", &"A".repeat(4096)] {
        let cursor = PageCursor::parse(raw).expect("canonical cursor");
        assert_eq!(cursor.as_str(), raw);
    }

    for raw in ["", "A", "AR", "AAF", "abc=", "abc+", "abc/", "not valid"] {
        assert_eq!(PageCursor::parse(raw), Err(PageCursorError::Malformed));
    }
    assert_eq!(
        PageCursor::parse(&"A".repeat(4097)),
        Err(PageCursorError::TooLong)
    );
}

#[test]
#[allow(clippy::expect_used)]
fn page_cursor_diagnostics_are_closed_and_redacted() {
    let raw = "c2VjcmV0LXRva2Vu";
    let cursor = PageCursor::parse(raw).expect("canonical cursor");
    assert!(!format!("{cursor:?}").contains(raw));

    let errors = [
        PageCursorError::Malformed,
        PageCursorError::TooLong,
        PageCursorError::Stale,
    ];
    for error in errors {
        assert!(!error.to_string().contains(raw));
    }
}
const DIGEST: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const SHORTEST: ContractId = ContractId::from_static("a.b");
const DESCRIPTOR: ContractDescriptor = ContractDescriptor::from_static("a.b", 1, DIGEST);
const VERSIONED: ContractDescriptor = ContractDescriptor::from_static_version("a.b", "v1", DIGEST);

#[test]
fn contract_id_constructors_share_canonical_grammar() -> Result<(), IdentityError> {
    assert_eq!(SHORTEST.as_str(), DESCRIPTOR.id());
    assert_eq!(DESCRIPTOR, VERSIONED);
    let max: &'static str = Box::leak(format!("a.{}", "b".repeat(253)).into_boxed_str());
    let overlong: &'static str = Box::leak(format!("a.{}", "b".repeat(254)).into_boxed_str());
    for raw in ["a.b", "runtime.inventory", "a-b.c1.d-2", max] {
        let id = ContractId::parse(raw)?;
        assert_eq!(id, ContractId::from_static(raw));
        assert_eq!(
            id.as_str(),
            ContractDescriptor::from_static(raw, 1, DIGEST).id()
        );
        assert_eq!(
            id.as_str(),
            ContractDescriptor::from_static_version(raw, "v1", DIGEST).id()
        );
    }
    for raw in [
        "",
        "foo",
        "foo-",
        "foo-.bar",
        "foo--bar.baz",
        "foo.bar-",
        ".foo",
        "foo.",
        "foo..bar",
        "foo.-bar",
        "foo.1bar",
        "Foo.bar",
        "foo._bar",
        "foo/bar",
        "foo.bär",
        overlong,
    ] {
        let expected = if raw.is_empty() {
            IdentityError::Empty
        } else if raw.len() > 255 {
            IdentityError::TooLong
        } else {
            IdentityError::InvalidFormat
        };
        assert_eq!(ContractId::parse(raw), Err(expected), "{raw}");
        assert!(
            std::panic::catch_unwind(|| ContractId::from_static(raw)).is_err(),
            "{raw}"
        );
        assert!(
            std::panic::catch_unwind(|| ContractDescriptor::from_static(raw, 1, DIGEST)).is_err(),
            "{raw}"
        );
        assert!(
            std::panic::catch_unwind(|| ContractDescriptor::from_static_version(raw, "v1", DIGEST))
                .is_err(),
            "{raw}"
        );
    }
    Ok(())
}
