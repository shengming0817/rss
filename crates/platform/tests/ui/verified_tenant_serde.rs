use rss_platform::VerifiedTenant;

fn require_serialize<T: serde::Serialize>() {}
fn require_deserialize<T: for<'de> serde::Deserialize<'de>>() {}

fn main() {
    require_serialize::<VerifiedTenant<'static>>();
    require_deserialize::<VerifiedTenant<'static>>();
}
