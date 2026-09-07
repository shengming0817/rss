use rss_redact::{ErrorSummary, LastError, Redact, RedactScope};

#[test]
fn summaries_and_last_errors_only_render_closed_labels() {
    for (summary, label) in [
        (ErrorSummary::Io, "io"),
        (ErrorSummary::Protocol, "protocol"),
        (ErrorSummary::State, "state"),
        (ErrorSummary::Runtime, "runtime"),
        (ErrorSummary::Heartbeat, "heartbeat"),
        (ErrorSummary::Client, "client"),
        (ErrorSummary::Unknown, "unknown"),
    ] {
        let last = LastError::from_summary(summary);
        assert_eq!(summary.as_str(), label);
        assert_eq!(summary.to_string(), label);
        assert_eq!(last.as_str(), label);
        assert_eq!(last.to_string(), label);
        assert_eq!(format!("{last:?}"), format!("LastError({label})"));
        assert_eq!(last.clone(), last);
    }
}

struct Untrusted;
impl Redact for Untrusted {
    fn redact_scoped(&self, _: RedactScope) -> String {
        "SENSITIVE_2326".into()
    }
}

#[test]
fn open_rendering_is_caller_policy_not_a_safe_summary() {
    for scope in [RedactScope::Wire, RedactScope::ServerLog] {
        assert_eq!(rss_redact::safe(&Untrusted, scope), "SENSITIVE_2326");
    }
    assert_eq!(
        rss_redact::redact_field("public", "SENSITIVE_2326").as_str(),
        "SENSITIVE_2326"
    );
    assert_eq!(
        rss_redact::redact_url_credentials("https://host/SENSITIVE_2326?token=SENSITIVE_2326")
            .as_str(),
        "https://host/SENSITIVE_2326?token=SENSITIVE_2326"
    );
}
