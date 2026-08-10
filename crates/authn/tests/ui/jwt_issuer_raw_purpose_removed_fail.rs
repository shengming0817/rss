use std::time::Duration;

use authn::{JwtIssuerConfig, SigningKeyRing};
use diport::{KeyId, SigningPurpose};

fn main() {
    let _ = JwtIssuerConfig::rss_access(
        SigningKeyRing::single(KeyId::new("rss-kid")).unwrap(),
        SigningPurpose::new("operator-controlled-purpose"),
        "https://rss.example",
        "rss-api",
        Duration::from_secs(900),
    );
}
