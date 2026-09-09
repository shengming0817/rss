use rss_redact_derive::Redact;

#[derive(Redact)]
struct Bad {
    #[redact(sensitivity = internal, mode = "email_mask")]
    value: String,
}

fn main() {}
