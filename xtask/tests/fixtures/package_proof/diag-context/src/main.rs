use release_package::{
    CorrelationId, CorrelationIdError, DiagnosticCtx, correlation, current, scope,
};

fn assert_send_sync<T: Send + Sync>() {}

fn assert_send<T: Send>(_: &T) {}

fn context(raw: &str) -> Result<DiagnosticCtx, CorrelationIdError> {
    Ok(DiagnosticCtx::new(CorrelationId::parse(raw)?))
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    assert_send_sync::<CorrelationId>();
    assert_send_sync::<CorrelationIdError>();
    assert_send_sync::<DiagnosticCtx>();
    assert_eq!(CorrelationId::MAX_LEN, 128);

    let empty_rejected = matches!(CorrelationId::parse(""), Err(CorrelationIdError::Empty));
    let one = CorrelationId::parse("a")?;
    assert_eq!(one.as_str(), "a");
    let at_max = "a".repeat(CorrelationId::MAX_LEN);
    assert_eq!(CorrelationId::parse(&at_max)?.as_str().len(), 128);
    let too_long = "a".repeat(CorrelationId::MAX_LEN + 1);
    let too_long_rejected = matches!(
        CorrelationId::parse(&too_long),
        Err(CorrelationIdError::TooLong)
    );
    let raw_invalid = "private\r\nvalue";
    let invalid = CorrelationId::parse(raw_invalid)
        .err()
        .ok_or_else(|| std::io::Error::other("invalid input was accepted"))?;
    let invalid_char_rejected = matches!(invalid, CorrelationIdError::InvalidChar);
    assert!(!invalid.to_string().contains(raw_invalid));
    assert!(matches!(
        CorrelationId::parse("unicode-雪"),
        Err(CorrelationIdError::InvalidChar)
    ));

    let ambient_missing_fail_open = current().is_none() && correlation().is_none();
    let pending = scope(context("send")?, async { correlation() });
    assert_send(&pending);
    assert_eq!(
        pending.await.map(|id| id.as_str().to_owned()),
        Some("send".to_owned())
    );

    let (scope_roundtrip, nested_restored) = scope(context("outer")?, async {
        let scope_roundtrip = current()
            .map(|ctx| ctx.correlation().as_str().to_owned())
            .as_deref()
            == Some("outer");
        let inner = scope(context("inner").expect("fixed fixture id"), async {
            correlation().map(|id| id.as_str().to_owned())
        })
        .await;
        assert_eq!(inner.as_deref(), Some("inner"));
        let nested_restored = correlation()
            .map(|id| id.as_str().to_owned())
            .as_deref()
            == Some("outer");
        (scope_roundtrip, nested_restored)
    })
    .await;

    println!(
        "{}",
        serde_json::json!({
            "package": "rss-diag-context",
            "maxLen": CorrelationId::MAX_LEN,
            "emptyRejected": empty_rejected,
            "tooLongRejected": too_long_rejected,
            "invalidCharRejected": invalid_char_rejected,
            "ambientMissingFailOpen": ambient_missing_fail_open,
            "scopeRoundtrip": scope_roundtrip,
            "nestedRestored": nested_restored,
            "sendSync": true
        })
    );
    Ok(())
}
