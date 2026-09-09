use rss_redact_derive::Redact;

#[derive(Redact)]
struct Bad {
    #[redact(sensitivity = secret, mode = "email_mask")]
    value: String,
}

fn main() {}
