use privacy::Redact;

#[derive(Redact)]
struct Sensitive {
    #[redact(sensitivity = secret)]
    secret: String,
    #[redact(sensitivity = internal)]
    internal: String,
    #[redact(sensitivity = internal, mode = "fixed")]
    fixed: String,
    #[redact(sensitivity = internal, mode = "drop")]
    dropped: String,
    #[redact(sensitivity = pii, mode = "last4")]
    phone: String,
    #[redact(sensitivity = pii, mode = "email_mask")]
    email: String,
}

fn main() {
    let value = Sensitive {
        secret: "never-output-secret".into(),
        internal: "never-output-internal".into(),
        fixed: "never-output-fixed".into(),
        dropped: "never-output-dropped".into(),
        phone: "12345678".into(),
        email: "alice@example.com".into(),
    };
    let rendered = format!("{value:?}");
    assert!(!rendered.contains("never-output"));
    assert!(!rendered.contains("dropped"));
    assert!(rendered.contains("****5678"));
    assert!(rendered.contains("a***@example.com"));
}
