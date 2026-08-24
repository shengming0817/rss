#![allow(dead_code)]
//! The production grammar is closed over `sensitivity` and `mode`; shorthand keys are rejected.

#[derive(securederive::Redact)]
struct PublicShorthand {
    #[redact(public)]
    value: String,
}

#[derive(securederive::Redact)]
struct InternalShorthand {
    #[redact(internal)]
    value: String,
}

#[derive(securederive::Redact)]
struct SecretShorthand {
    #[redact(secret)]
    value: String,
}

#[derive(securederive::Redact)]
struct PiiShorthand {
    #[redact(pii = "generic")]
    value: String,
}

fn main() {}
