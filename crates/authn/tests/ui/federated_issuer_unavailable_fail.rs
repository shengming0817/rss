use std::time::Duration;

use authn::JwtIssuerConfig;
use diport::{FederatedAccessProfile, KeyId, SigningPurpose};

fn main() {
    let _ = JwtIssuerConfig::<FederatedAccessProfile>::federated_access(
        KeyId::new("federated-kid"),
        SigningPurpose::new("auth.federated"),
        "https://federated.example",
        "rss-api",
        Duration::from_secs(900),
    );
}
