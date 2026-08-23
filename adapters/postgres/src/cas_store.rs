//! PostgreSQL state-CAS provider (`diport::CasStore`).
//!
//! `distributed_cas` stores one opaque byte value plus a monotonically increasing token per key.
//! Each operation takes a per-key transaction advisory lock before reading so create-if-absent has
//! the same single-winner semantics as row-lock updates.

use diport::{CasStore, CasStoreError, CasStoreOutcome, CasStoreRequest};
use sqlx::PgPool;

use crate::PgStore;

/// PostgreSQL state-CAS store.
///
/// Holds a `PgPool` clone from [`PgStore`]. Construction is funneled through
/// [`crate::PgInfraDeps::cas_store`], so callers never receive the raw pool.
pub struct PgCasStore {
    pool: PgPool,
}

impl PgStore {
    /// Construct [`PgCasStore`] from the shared pool.
    pub(crate) fn cas_store(&self) -> PgCasStore {
        PgCasStore {
            pool: self.pool.clone(),
        }
    }
}

fn epoch_from_db(token: i64) -> Result<vocab::Epoch, CasStoreError> {
    Ok(vocab::Epoch::new(
        u64::try_from(token).map_err(CasStoreError::new)?,
    ))
}

fn epoch_to_db(token: vocab::Epoch) -> Result<i64, CasStoreError> {
    i64::try_from(token.get()).map_err(CasStoreError::new)
}

impl CasStore for PgCasStore {
    async fn compare_and_swap(
        &self,
        request: CasStoreRequest,
    ) -> Result<CasStoreOutcome, CasStoreError> {
        let expected_token = request.expected_token.map(epoch_to_db).transpose()?;
        let mut tx = self.pool.begin().await.map_err(CasStoreError::new)?;

        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind(request.key.as_str())
            .execute(&mut *tx)
            .await
            .map_err(CasStoreError::new)?;

        let row: Option<(Vec<u8>, i64)> = sqlx::query_as(
            r#"
            SELECT value, token
            FROM distributed_cas
            WHERE cas_key = $1
            "#,
        )
        .bind(request.key.as_str())
        .fetch_optional(&mut *tx)
        .await
        .map_err(CasStoreError::new)?;

        let outcome = match row {
            None => {
                if request.expected.is_some() {
                    CasStoreOutcome::Conflict { current: None }
                } else {
                    sqlx::query(
                        r#"
                        INSERT INTO distributed_cas (cas_key, value, token)
                        VALUES ($1, $2, 1)
                        "#,
                    )
                    .bind(request.key.as_str())
                    .bind(request.new_value.as_bytes())
                    .execute(&mut *tx)
                    .await
                    .map_err(CasStoreError::new)?;
                    CasStoreOutcome::Applied {
                        token: vocab::Epoch::new(1),
                    }
                }
            }
            Some((current_value, current_token)) => {
                if expected_token.is_some_and(|token| token < current_token) {
                    CasStoreOutcome::Fenced {
                        current_token: epoch_from_db(current_token)?,
                    }
                } else if request
                    .expected
                    .as_ref()
                    .is_none_or(|expected| expected.as_bytes() != current_value.as_slice())
                {
                    CasStoreOutcome::Conflict {
                        current: Some(current_value.into()),
                    }
                } else {
                    let next_token = current_token.checked_add(1).ok_or_else(|| {
                        CasStoreError::new(std::io::Error::other("cas token overflow"))
                    })?;
                    sqlx::query(
                        r#"
                        UPDATE distributed_cas
                        SET value = $2,
                            token = $3,
                            updated_at = now()
                        WHERE cas_key = $1
                        "#,
                    )
                    .bind(request.key.as_str())
                    .bind(request.new_value.as_bytes())
                    .bind(next_token)
                    .execute(&mut *tx)
                    .await
                    .map_err(CasStoreError::new)?;
                    CasStoreOutcome::Applied {
                        token: epoch_from_db(next_token)?,
                    }
                }
            }
        };

        tx.commit().await.map_err(CasStoreError::new)?;
        Ok(outcome)
    }

    async fn shutdown(&self) -> Result<(), CasStoreError> {
        Ok(())
    }
}

#[cfg(test)]
mod smoke {
    use core::marker::PhantomData;

    use diport::CasStore;

    fn assert_cas_store<T: CasStore>(_: PhantomData<T>) {}

    #[test]
    fn pg_cas_store_impl_frozen() {
        assert_cas_store(PhantomData::<super::PgCasStore>);
    }
}

#[cfg(all(test, feature = "integration"))]
mod integration_tests {
    use diport::{CasStore, CasStoreOutcome, CasStoreRequest, GlobalCasStoreKey, ManagedResource};
    use sha2::{Digest, Sha256};

    use crate::{PgConfig, PgPassword, PgStore};

    type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

    fn request(
        key: &str,
        expected: Option<&[u8]>,
        new_value: &[u8],
        expected_token: Option<vocab::Epoch>,
    ) -> CasStoreRequest {
        let topology_scope_sha256: [u8; 32] = Sha256::digest(key.as_bytes()).into();
        CasStoreRequest {
            key: GlobalCasStoreKey::for_resource(
                diport::GlobalCasResource::OutboxBacklog,
                topology_scope_sha256,
            ),
            expected: expected.map(|expected| Vec::from(expected).into()),
            new_value: Vec::from(new_value).into(),
            expected_token,
        }
    }

    async fn connect_rss_app_member(
        fixture: &testkit::OwnedPgFixture,
        owner: &PgStore,
    ) -> Result<PgStore, Box<dyn std::error::Error + Send + Sync>> {
        let role = format!("rss_cas_app_{}", uuid::Uuid::new_v4().simple());
        let password = "cas_test_pw";
        sqlx::query(&format!(
            "CREATE ROLE {role} LOGIN PASSWORD '{password}' NOBYPASSRLS"
        ))
        .execute(&owner.pool)
        .await?;
        sqlx::query(&format!("GRANT rss_app TO {role}"))
            .execute(&owner.pool)
            .await?;

        let p = fixture.owner_params();
        let config = PgConfig::new_for_test_plaintext(
            p.host.clone(),
            p.port,
            p.database.clone(),
            role,
            PgPassword::new(password.to_string()),
        )
        .with_acquire_timeout(std::time::Duration::from_secs(5));
        Ok(PgStore::connect(&config).await?)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn postgres_cas_three_states_and_fencing() -> TestResult {
        let (_pg, store) = crate::test_pg::connect_pg().await?;
        store.run_migrations().await?;

        let cas = store.cas_store();
        let key = format!("cas-{}", uuid::Uuid::new_v4());

        assert_eq!(
            cas.compare_and_swap(request(&key, None, b"v1", None))
                .await?,
            CasStoreOutcome::Applied {
                token: vocab::Epoch::new(1)
            }
        );
        assert_eq!(
            cas.compare_and_swap(request(
                &key,
                Some(b"v1"),
                b"v2",
                Some(vocab::Epoch::new(1))
            ))
            .await?,
            CasStoreOutcome::Applied {
                token: vocab::Epoch::new(2)
            }
        );
        assert_eq!(
            cas.compare_and_swap(request(
                &key,
                Some(b"v1"),
                b"v3",
                Some(vocab::Epoch::new(2))
            ))
            .await?,
            CasStoreOutcome::Conflict {
                current: Some(Vec::from(&b"v2"[..]).into())
            }
        );
        assert_eq!(
            cas.compare_and_swap(request(
                &key,
                Some(b"v2"),
                b"v4",
                Some(vocab::Epoch::new(1))
            ))
            .await?,
            CasStoreOutcome::Fenced {
                current_token: vocab::Epoch::new(2)
            }
        );

        cas.shutdown().await?;
        store.shutdown().await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn postgres_cas_concurrent_create_has_single_winner() -> TestResult {
        let (_pg, store) = crate::test_pg::connect_pg().await?;
        store.run_migrations().await?;

        let key = format!("cas-race-{}", uuid::Uuid::new_v4());
        let cas = std::sync::Arc::new(store.cas_store());
        let mut tasks = Vec::new();
        for idx in 0_u8..8 {
            let cas = std::sync::Arc::clone(&cas);
            let key = key.clone();
            tasks.push(tokio::spawn(async move {
                cas.compare_and_swap(request(&key, None, &[idx], None))
                    .await
            }));
        }

        let mut applied = 0;
        let mut conflicts = 0;
        for task in tasks {
            match task.await?? {
                CasStoreOutcome::Applied { .. } => applied += 1,
                CasStoreOutcome::Conflict { current: Some(_) } => conflicts += 1,
                other => {
                    return Err(
                        std::io::Error::other(format!("unexpected outcome: {other:?}")).into(),
                    );
                }
            }
        }
        assert_eq!(applied, 1, "create-if-absent 应只有一个 winner");
        assert_eq!(conflicts, 7, "其余并发创建应观察到已有值");

        cas.shutdown().await?;
        store.shutdown().await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn rss_app_nobypass_role_can_use_cas_without_delete() -> TestResult {
        let (pg, owner) = crate::test_pg::connect_pg().await?;
        owner.run_migrations().await?;
        let app_store = connect_rss_app_member(&pg, &owner).await?;

        let cas = app_store.cas_store();
        let key = format!("cas-rss-app-{}", uuid::Uuid::new_v4());
        assert_eq!(
            cas.compare_and_swap(request(&key, None, b"v1", None))
                .await?,
            CasStoreOutcome::Applied {
                token: vocab::Epoch::new(1)
            }
        );
        assert_eq!(
            cas.compare_and_swap(request(
                &key,
                Some(b"v1"),
                b"v2",
                Some(vocab::Epoch::new(1))
            ))
            .await?,
            CasStoreOutcome::Applied {
                token: vocab::Epoch::new(2)
            }
        );
        assert_eq!(
            cas.compare_and_swap(request(
                &key,
                Some(b"v1"),
                b"v3",
                Some(vocab::Epoch::new(2))
            ))
            .await?,
            CasStoreOutcome::Conflict {
                current: Some(Vec::from(&b"v2"[..]).into())
            }
        );
        assert_eq!(
            cas.compare_and_swap(request(
                &key,
                Some(b"v2"),
                b"v4",
                Some(vocab::Epoch::new(1))
            ))
            .await?,
            CasStoreOutcome::Fenced {
                current_token: vocab::Epoch::new(2)
            }
        );

        let race_key = format!("cas-rss-app-race-{}", uuid::Uuid::new_v4());
        let cas = std::sync::Arc::new(cas);
        let mut tasks = Vec::new();
        for idx in 0_u8..8 {
            let cas = std::sync::Arc::clone(&cas);
            let race_key = race_key.clone();
            tasks.push(tokio::spawn(async move {
                cas.compare_and_swap(request(&race_key, None, &[idx], None))
                    .await
            }));
        }
        let mut applied = 0;
        let mut conflicts = 0;
        for task in tasks {
            match task.await?? {
                CasStoreOutcome::Applied { .. } => applied += 1,
                CasStoreOutcome::Conflict { current: Some(_) } => conflicts += 1,
                other => {
                    return Err(
                        std::io::Error::other(format!("unexpected outcome: {other:?}")).into(),
                    );
                }
            }
        }
        assert_eq!(applied, 1, "rss_app 并发 create 应只有一个 winner");
        assert_eq!(conflicts, 7, "rss_app 其余并发 create 应 Conflict");

        let delete = sqlx::query("DELETE FROM distributed_cas WHERE cas_key = $1")
            .bind(&key)
            .execute(&app_store.pool)
            .await;
        assert!(
            delete.is_err(),
            "rss_app member must not receive DELETE on distributed_cas"
        );

        cas.shutdown().await?;
        app_store.shutdown().await?;
        owner.shutdown().await?;
        Ok(())
    }
}
