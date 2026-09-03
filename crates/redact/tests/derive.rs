#[derive(rss_redact::Redact)]
struct Credential {
    #[allow(dead_code)]
    #[redact(sensitivity = secret)]
    value: String,
}

#[test]
fn facade_reexports_a_working_redact_derive() {
    let value = Credential {
        value: "do-not-log".to_owned(),
    };
    assert_eq!(format!("{value:?}"), "Credential { value: <redacted> }");
}
