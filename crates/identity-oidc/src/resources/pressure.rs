//! Measure the actual entry lock during pool admission. Keep instrumentation outside release builds.
use super::*;
use crate::test_support::reuse_policy;
use rss_identity_core::{InstanceId, federation::*};
use rss_request_context::SharedExecutionTimer;
use std::{cell::Cell, time::SystemTime};
#[path = "../../../../tests/fixtures/pg_clock.rs"]
mod fixture_clock;

thread_local! {
    static VISITED: Cell<usize> = const {Cell::new(0)};
    static HELD: Cell<Duration> = const {Cell::new(Duration::ZERO)};
}
pub(super) fn scan(n: usize) {
    VISITED.set(VISITED.get() + n);
}
pub(super) struct Locked(Instant);
impl Locked {
    #[allow(
        clippy::disallowed_methods,
        reason = "fixture samples actual mutex hold time"
    )]
    pub fn start() -> Self {
        Self(Instant::now())
    }
}
impl Drop for Locked {
    fn drop(&mut self) {
        HELD.set(self.0.elapsed());
    }
}

#[allow(clippy::disallowed_methods, reason = "fixture owns the clock")]
#[test]
fn pool_pressure() -> anyhow::Result<()> {
    const N: usize = 128;
    let policy = ReusePolicy {
        max_providers: N,
        ..reuse_policy()
    };
    let settings: ProviderSettings = ProviderSettingsInput {
        issuer: "https://idp.test".into(),
        client_id: "fixture".into(),
        redirect_uri: "https://rp.test/cb".into(),
        scopes: vec!["openid".into()],
        jit: false,
        claims: ClaimMapping {
            subject: rss_identity_core::entra::SubjectMapping::Oidc,
            profile: Default::default(),
            groups: None,
            department_snapshot: None,
        },
    }
    .try_into()?;
    let base = ProviderRevision {
        tenant: TenantId::parse("11111111-1111-4111-8111-111111111111")?,
        instance: InstanceId::parse("22222222-2222-4222-8222-222222222222")?,
        provider: ProviderId::generate(),
        version: 1,
    };
    let http = reqwest::Client::new();
    for (victims, protected) in [(1, N / 4), (2, N / 4), (16, N / 4), (64, N / 4), (1, N)] {
        let mut samples = Vec::new();
        let mut examined = 0;
        let mut rejected = 0;
        for _ in 0..41 {
            let registry = ProviderRevisions::new(N);
            let resources = Resources::new(
                policy,
                crate::ProviderClock::new(
                    SharedExecutionTimer::new(fixture_clock::TestClock),
                    SystemTime::now,
                ),
            )?;
            let _occupied = resources
                .clients
                .clone()
                .try_acquire_many_owned((N - 1) as u32)?;
            let mut held = Vec::new();
            for i in 0..N {
                let bound = registry.install(
                    ProviderRevision {
                        provider: ProviderId::generate(),
                        ..base
                    },
                    settings.clone(),
                    ProviderCredentials::new("fixture".into(), None)?,
                )?;
                let slot = resources.bind(&bound)?;
                if i + 1 == victims {
                    *slot
                        .client
                        .lock()
                        .map_err(|_| anyhow::anyhow!("client mutex"))? =
                        Some(Arc::new(ClientPool {
                            http: http.clone(),
                            _permit: Some(resources.clients.clone().try_acquire_owned()?),
                        }));
                }
                if i >= N - protected {
                    held.push(slot);
                }
            }
            VISITED.set(0);
            let permit = resources.client_permit();
            rejected += usize::from(permit.is_err());
            examined += VISITED.get();
            samples.push(HELD.get().as_nanos());
            assert_eq!(permit.is_err(), protected == N);
            assert!(held.iter().all(|r| Arc::strong_count(r) > 1));
        }
        if victims >= 16 && protected < N {
            assert!(
                examined <= samples.len() * 3 * N,
                "multi-item admission must bound map scans"
            );
        }
        samples.sort_unstable();
        println!(
            "pool pressure victims={victims} protected={protected} visits={} lock_p50_ns={} lock_p95_ns={} rejected={rejected}/41",
            examined / 41,
            samples[20],
            samples[38]
        );
    }
    Ok(())
}

#[test]
fn active_document_lease_survives_full_budget_replacement() -> anyhow::Result<()> {
    let policy = ReusePolicy {
        max_resident_bytes: 128,
        ..reuse_policy()
    };
    let resources = Resources::new(
        policy,
        crate::ProviderClock::new(SharedExecutionTimer::new(fixture_clock::TestClock), || {
            SystemTime::UNIX_EPOCH
        }),
    )?;
    let mut stored = Arc::new(resources.reserve(128, None)?);
    let reader = Arc::clone(&stored);
    assert!(resources.reserve(128, Arc::get_mut(&mut stored)).is_err());
    assert_eq!(resources.bytes.load(Ordering::Acquire), 128);
    drop(reader);
    let replacement = resources.reserve(128, Arc::get_mut(&mut stored))?;
    drop(stored);
    assert_eq!(resources.bytes.load(Ordering::Acquire), 128);
    drop(replacement);
    assert_eq!(resources.bytes.load(Ordering::Acquire), 0);
    Ok(())
}
