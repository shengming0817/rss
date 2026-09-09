use rss_redact_derive::Redact;

#[derive(Redact)]
struct Bad {
    #[redact(sensitivity = secret, mode = "last4")]
    value: String,
}

fn main() {}
