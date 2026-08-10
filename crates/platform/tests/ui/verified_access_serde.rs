use rss_platform::VerifiedAccess;

fn require_serialize<T: serde::Serialize>() {}
fn require_deserialize<T: for<'de> serde::Deserialize<'de>>() {}

fn main() {
    require_serialize::<VerifiedAccess>();
    require_deserialize::<VerifiedAccess>();
}
