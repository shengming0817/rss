//! Private GET cache freshness (RFC 9111 §§4.2.1–4.3.4).
use http::{HeaderMap, HeaderName, header};
use std::time::{Duration, SystemTime};

#[derive(Clone, Copy, Default)]
pub(super) struct Freshness {
    max_age: Option<Duration>,
    expires: Option<SystemTime>,
    no_cache: bool,
    no_store: bool,
}
impl Freshness {
    /// On a 304, absent cache directives continue to describe the stored representation.
    pub fn update(mut self, headers: &HeaderMap) -> Self {
        if headers.contains_key(header::CACHE_CONTROL) {
            self.max_age = None;
            self.no_cache = false;
            self.no_store = false;
            for value in headers.get_all(header::CACHE_CONTROL) {
                let Ok(value) = value.to_str() else {
                    self.no_store = true;
                    continue;
                };
                for token in value.split(',').map(str::trim) {
                    let (name, arg) = token.split_once('=').unwrap_or((token, ""));
                    match name.trim().to_ascii_lowercase().as_str() {
                        "no-store" => self.no_store = true,
                        "no-cache" => self.no_cache = true,
                        "max-age" => {
                            let age = Duration::from_secs(
                                arg.trim().trim_matches('"').parse().unwrap_or(0),
                            );
                            self.max_age = Some(self.max_age.map_or(age, |old| old.min(age)));
                        }
                        _ => {}
                    }
                }
            }
        }
        if headers.contains_key(header::EXPIRES) {
            self.expires = Some(date(headers, header::EXPIRES).unwrap_or(SystemTime::UNIX_EPOCH));
        }
        // The adapter sends one fixed representation. Other variants need a fresh GET.
        if headers.get_all(header::VARY).iter().any(|v| {
            v.to_str().map_or(true, |s| {
                s.split(',')
                    .any(|v| !v.trim().eq_ignore_ascii_case("accept"))
            })
        }) {
            self.no_store = true;
        }
        self
    }
    pub fn storable(self) -> bool {
        !self.no_store
    }
    pub fn remaining(
        self,
        headers: &HeaderMap,
        cap: Duration,
        transfer: Duration,
        now: SystemTime,
    ) -> Duration {
        if self.no_cache {
            return Duration::ZERO;
        }
        let sent = date(headers, header::DATE).unwrap_or(now);
        let apparent = now.duration_since(sent).unwrap_or_default();
        let age = headers.get(header::AGE).map_or(0, |v| {
            v.to_str()
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(u64::MAX)
        });
        let current_age = apparent.max(Duration::from_secs(age).saturating_add(transfer));
        let lifetime = self
            .max_age
            .or_else(|| {
                self.expires
                    .map(|e| e.duration_since(sent).unwrap_or_default())
            })
            .unwrap_or(cap);
        cap.min(lifetime).saturating_sub(current_age)
    }
}
fn date(headers: &HeaderMap, name: HeaderName) -> Option<SystemTime> {
    httpdate::parse_http_date(headers.get(name)?.to_str().ok()?).ok()
}
