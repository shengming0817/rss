use std::time::Duration;

use authn::JwtIssuerConfig;
use diport::{KeyId, ProjectionOperatorTokenProfile, SigningPurpose};

fn main() {
    let _ = JwtIssuerConfig::<ProjectionOperatorTokenProfile>::service_token(
        KeyId::new("projection-kid"),
        SigningPurpose::new("auth.projection-operator"),
        "https://projection-operator.example",
        "rss-projection-operator",
        Duration::from_secs(300),
    );
}
