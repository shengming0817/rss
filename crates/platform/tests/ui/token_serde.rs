use rss_platform::AccessToken;

fn require_serialize<T: serde::Serialize>() {}
fn require_deserialize<T: for<'de> serde::Deserialize<'de>>() {}

fn main() {
    require_serialize::<AccessToken>();
    require_deserialize::<AccessToken>();
}
