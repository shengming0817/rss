use rss_contract::{DataClass, SafeError, SafeErrorCategory, SafeErrorCode};
use std::error::Error as _;

#[test]
fn data_class_vocabulary_and_labels_are_closed() {
    let cases = [
        (DataClass::Public, "public"),
        (DataClass::Internal, "internal"),
        (DataClass::Pii, "pii"),
        (DataClass::Secret, "secret"),
    ];

    for (class, label) in cases {
        assert_eq!(class.as_str(), label);
        assert_eq!(class.to_string(), label);
    }
}

#[test]
fn safe_error_codes_have_fixed_categories_and_messages() {
    let cases = [
        (
            SafeErrorCode::InvalidInput,
            "invalid-input",
            SafeErrorCategory::InvalidInput,
            "invalid input",
        ),
        (
            SafeErrorCode::Unauthenticated,
            "unauthenticated",
            SafeErrorCategory::Authentication,
            "authentication required",
        ),
        (
            SafeErrorCode::Forbidden,
            "forbidden",
            SafeErrorCategory::Authorization,
            "access denied",
        ),
        (
            SafeErrorCode::NotFound,
            "not-found",
            SafeErrorCategory::NotFound,
            "not found",
        ),
        (
            SafeErrorCode::Conflict,
            "conflict",
            SafeErrorCategory::Conflict,
            "conflict",
        ),
        (
            SafeErrorCode::RateLimited,
            "rate-limited",
            SafeErrorCategory::RateLimited,
            "rate limited",
        ),
        (
            SafeErrorCode::Unavailable,
            "unavailable",
            SafeErrorCategory::Unavailable,
            "service unavailable",
        ),
        (
            SafeErrorCode::Internal,
            "internal",
            SafeErrorCategory::Internal,
            "internal error",
        ),
    ];

    for (code, label, category, message) in cases {
        assert_eq!(code.as_str(), label);
        assert_eq!(code.category(), category);
        assert_eq!(code.message(), message);

        let error = SafeError::new(code);
        assert_eq!(error.code(), code);
        assert_eq!(error.category(), category);
        assert_eq!(error.message(), message);
        assert_eq!(error.to_string(), message);
        assert!(error.source().is_none());
    }
}

#[test]
fn safe_error_category_labels_are_closed() {
    let cases = [
        (SafeErrorCategory::InvalidInput, "invalid-input"),
        (SafeErrorCategory::Authentication, "authentication"),
        (SafeErrorCategory::Authorization, "authorization"),
        (SafeErrorCategory::NotFound, "not-found"),
        (SafeErrorCategory::Conflict, "conflict"),
        (SafeErrorCategory::RateLimited, "rate-limited"),
        (SafeErrorCategory::Unavailable, "unavailable"),
        (SafeErrorCategory::Internal, "internal"),
    ];

    for (category, label) in cases {
        assert_eq!(category.as_str(), label);
        assert_eq!(category.to_string(), label);
    }
}

#[test]
fn safe_error_diagnostics_expose_only_closed_semantics() {
    let error = SafeError::new(SafeErrorCode::Internal);
    let debug = format!("{error:?}");

    assert!(debug.contains("Internal"));
    assert!(debug.contains("category"));
    for forbidden in ["password", "payload", "provider", "source", "postgres://"] {
        assert!(!debug.to_lowercase().contains(forbidden));
        assert!(!error.to_string().to_lowercase().contains(forbidden));
    }
}

#[derive(Debug)]
struct ProviderSource;

impl std::fmt::Display for ProviderSource {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("source=user@example.com")
    }
}

impl std::error::Error for ProviderSource {}

#[derive(Debug)]
struct ProviderFailure {
    source: ProviderSource,
}

impl std::fmt::Display for ProviderFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(
            "password=hunter2 dsn=postgres://admin:secret@db payload={token} type=ProviderFailure",
        )
    }
}

impl std::error::Error for ProviderFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

#[test]
fn synthetic_red_projects_hostile_provider_error_without_leaks() {
    let provider = ProviderFailure {
        source: ProviderSource,
    };
    assert!(provider.source().is_some());
    let raw = format!("{provider:?} {provider} {}", provider.source);
    for marker in [
        "hunter2",
        "postgres://",
        "user@example.com",
        "payload",
        "ProviderFailure",
        "ProviderSource",
    ] {
        assert!(
            raw.contains(marker),
            "synthetic red input lost marker {marker}"
        );
    }

    let projected = SafeError::new(SafeErrorCode::Internal);
    let safe = format!("{projected:?} {projected}");
    for marker in [
        "hunter2",
        "postgres://",
        "user@example.com",
        "payload",
        "ProviderFailure",
        "ProviderSource",
    ] {
        assert!(
            !safe.contains(marker),
            "projected error leaked marker {marker}"
        );
    }
    assert!(projected.source().is_none());
}
