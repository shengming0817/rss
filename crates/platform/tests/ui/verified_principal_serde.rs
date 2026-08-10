use rss_platform::VerifiedPrincipal;

fn require_serialize<T: serde::Serialize>() {}
fn require_deserialize<T: for<'de> serde::Deserialize<'de>>() {}

fn main() {
    require_serialize::<VerifiedPrincipal<'static>>();
    require_deserialize::<VerifiedPrincipal<'static>>();
}
