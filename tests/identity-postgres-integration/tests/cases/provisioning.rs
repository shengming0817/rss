//! Actual least-privilege provisioning and host transaction settlement.
use crate::support;
use rss_identity_core::{account::PasswordKdf, session::SessionSecret};
use rss_identity_postgres::*;
use rss_request_context::TenantId;
use rss_transactional_messaging_postgres::PgError;
use std::sync::Arc;
use support::*;

// The host writes this authorization state on the target transaction before Identity
// switches to the source scope. A different connection or transaction cannot consume it.
struct SqlPolicy(Arc<HostPolicy>);
impl ManagementPolicy for SqlPolicy {
    fn authorize<'a>(
        &'a self,
        context: &'a ManagementContext<'a>,
        connection: &'a mut sqlx::PgConnection,
    ) -> futures::future::BoxFuture<'a, Result<ReauthenticationRequirement, ManagementDenied>> {
        Box::pin(async move {
            let (scope, allowed, same_backend, same_transaction): (String, bool, bool, bool) =
                sqlx::query_as("SELECT current_setting('rss.tenant_id'),allowed,backend=pg_backend_pid(),transaction_id=txid_current() FROM pg_temp.provision_authorization")
                    .fetch_one(&mut *connection).await.map_err(|_| ManagementDenied)?;
            if scope != context.actor().tenant.to_string()
                || !allowed
                || !same_backend
                || !same_transaction
            {
                return Err(ManagementDenied);
            }
            self.0.authorize(context, connection).await
        })
    }
}
async fn host_authorization(
    tx: &mut rss_transactional_messaging_postgres::PgTransaction<'_>,
) -> Result<(), PgError> {
    tx.with_connection(|c| Box::pin(async move {
        sqlx::raw_sql("CREATE TEMP TABLE provision_authorization (allowed boolean NOT NULL,backend integer NOT NULL,transaction_id bigint NOT NULL) ON COMMIT DROP; INSERT INTO provision_authorization VALUES(true,pg_backend_pid(),txid_current())")
            .execute(c).await?;
        Ok(())
    })).await
}

#[allow(
    clippy::unwrap_used,
    reason = "Fixed test inputs and immediate fixture assertions"
)]
pub async fn provisioning(f: &Fixture) -> anyhow::Result<()> {
    // Each fixture gets its own role, avoiding shared role mutations across concurrent tests.
    let role = format!("provision_{}", uuid::Uuid::new_v4().simple());
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
        "CREATE ROLE {role} LOGIN PASSWORD 'fixture-only' NOSUPERUSER NOBYPASSRLS"
    )))
    .execute(&f.owner)
    .await?;
    let mut conn = f.owner.acquire().await?;
    grant_profile(&mut conn, &role, AuthorityProfile::Provisioning).await?;
    drop(conn);
    let runtime = f.runtime_as(&role).await?;
    let kdf = Arc::new(
        PasswordKdf::new(
            std::num::NonZeroUsize::new(4).unwrap(),
            std::num::NonZeroU64::new(128 * 1024 * 1024).unwrap(),
        )
        .unwrap(),
    );
    let policy = Arc::new(SqlPolicy(f.policy.clone()));
    let service = Arc::new(
        AccountProvisioner::connect(
            runtime.clone(),
            kdf.clone(),
            f.config(),
            crate::support::binding(
                rss_request_context::TenantId::parse(crate::support::A).unwrap(),
            ),
            f.key.tenant,
            policy.clone(),
            deadline(),
        )
        .await?,
    );
    assert!(
        AccountProvisioner::connect(
            f.runtime.clone(),
            kdf.clone(),
            f.config(),
            crate::support::binding(
                rss_request_context::TenantId::parse(crate::support::A).unwrap()
            ),
            f.key.tenant,
            policy.clone(),
            deadline()
        )
        .await
        .is_err()
    );
    let target = TenantId::parse(B)?;
    let actor = Arc::new(f.actor().await?);
    let prepared = service
        .prepare_local_account(login("new-admin"), password(), deadline())
        .await?;
    let svc = service.clone();
    let who = actor.clone();
    let outcome = runtime
        .local_tx(binding(target), deadline(), move |tx| {
            Box::pin(async move {
                host_authorization(tx).await?;
                let account = svc
                    .create_local_account_in(tx, who, prepared)
                    .await
                    .map_err(|e| PgError::from(sqlx::Error::Protocol(e.to_string())))?;
                let scope: String = tx
                    .with_connection(|c| {
                        Box::pin(async move {
                            sqlx::query_scalar("SELECT current_setting('rss.tenant_id')")
                                .fetch_one(c)
                                .await
                        })
                    })
                    .await?;
                assert_eq!(scope, B);
                Ok(account)
            })
        })
        .await;
    let account = outcome
        .fold(
            Ok,
            |e| Err(e.to_string()),
            |e| Err(e.to_string()),
            |e| Err(e.to_string()),
            |e| Err(e.to_string()),
            |_| Err("fenced".into()),
        )
        .map_err(anyhow::Error::msg)?;
    assert_eq!(account.key().tenant, target);
    let records: Vec<Vec<u8>> =
        sqlx::query_scalar("SELECT canonical FROM rss_audit.records WHERE tenant_id=$1::uuid")
            .bind(B)
            .fetch_all(&f.owner)
            .await?;
    let record = records
        .iter()
        .map(|b| rss_audit_core::decode_untrusted(b))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .find(|r| r.event().facts().action().as_str() == "identity.account.provisioned")
        .ok_or_else(|| anyhow::anyhow!("missing provisioning audit"))?;
    let payload: serde_json::Value =
        serde_json::from_slice(record.event().context().payload().as_bytes())?;
    assert_eq!(payload["actor_tenant"], A);
    assert_eq!(payload["actor_instance"], f.instance.to_string());
    assert_eq!(
        payload["actor_principal"],
        f.key.principal.as_uuid().to_string()
    );
    assert_eq!(record.event().identity().tenant().to_string(), B);
    assert!(payload.get("password").is_none());
    let issued = f
        .store
        .login_local(
            crate::support::binding(target),
            login("new-admin"),
            password(),
            source(),
            None,
            deadline(),
        )
        .await?;
    let proof = f
        .store
        .inspect_session(
            crate::support::binding(target),
            SessionSecret::parse(issued.secret().expose().into())?,
            deadline(),
        )
        .await?;
    assert_eq!(proof.account(), account.key());
    // A host failure rolls back the account and its security event together.
    let events_before_rollback = f.events().await?;
    let prepared = service
        .prepare_local_account(login("rolled-back"), password(), deadline())
        .await?;
    let svc = service.clone();
    let who = actor.clone();
    let outcome = runtime
        .local_tx(binding(target), deadline(), move |tx| {
            Box::pin(async move {
                host_authorization(tx).await?;
                svc.create_local_account_in(tx, who, prepared)
                    .await
                    .map_err(|e| PgError::from(sqlx::Error::Protocol(e.to_string())))?;
                Err::<(), PgError>(sqlx::Error::Protocol("host write failed".into()).into())
            })
        })
        .await;
    assert!(outcome.fold(
        |_| false,
        |_| false,
        |_| true,
        |_| false,
        |_| false,
        |_| false
    ));
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM identity_authority.local_credentials WHERE login_key='rolled-back'",
    )
    .fetch_one(&f.owner)
    .await?;
    assert_eq!(count, 0);
    assert_eq!(f.events().await?, events_before_rollback);
    runtime.close().await;
    Ok(())
}
