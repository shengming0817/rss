#![allow(dead_code)]
//! The production grammar is closed over `sensitivity` and `mode`; shorthand keys are rejected.

#[derive(rss_redact_derive::Redact)]
struct PublicShorthand {
    #[redact(public)]
    value: String,
}

#[derive(rss_redact_derive::Redact)]
struct InternalShorthand {
    #[redact(internal)]
    value: String,
}

#[derive(rss_redact_derive::Redact)]
struct SecretShorthand {
    #[redact(secret)]
    value: String,
}

#[derive(rss_redact_derive::Redact)]
struct PiiShorthand {
    #[redact(pii = "generic")]
    value: String,
}

fn main() {}
