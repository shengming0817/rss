use privacy::Redact;

#[derive(Redact)]
struct Credential {
    #[redact(sensitivity = secret)]
    value: String,
}

fn main() {
    let value = Credential {
        value: "do-not-log".to_owned(),
    };
    assert_eq!(format!("{value:?}"), "Credential { value: <redacted> }");
}
