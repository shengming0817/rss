//! PostgreSQL request-time fence for verified RSS access-token grant bindings.
//!
//! The validator owns only a serving read lane. One tenant-scoped query observes the grant root
//! and account-security row in the same PostgreSQL snapshot; it cannot mutate either aggregate.

use std::time::SystemTime;

use authn::AccessGrantValidationInput;
use identity::ports::{AuthGrantValidator, IdentityError, TenantRepoScope};

use crate::cotx::PgTenantReadPool;
use crate::outbox::unix_secs;
use crate::pool::VerifiedPgReadStore;

/// Read-only PostgreSQL implementation of the durable RSS access-token fence.
pub struct PgAuthGrantValidator {
    pool: PgTenantReadPool,
}

impl PgAuthGrantValidator {
    pub(crate) fn new(reader: &VerifiedPgReadStore) -> Self {
        Self {
            pool: PgTenantReadPool::new(reader),
        }
    }

    #[cfg(all(test, feature = "integration"))]
    pub(crate) fn from_unverified_for_test(store: &crate::PgStore) -> Self {
        Self {
            pool: PgTenantReadPool::from_unverified_for_test(store),
        }
    }
}

#[derive(sqlx::FromRow)]
struct ValidationRow {
    grant_user_matches: bool,
    grant_auth_time: i64,
    grant_epoch: i64,
    grant_status: String,
    grant_expires_at: i64,
    account_user_matches: Option<bool>,
    account_status: Option<String>,
    account_epoch: Option<i64>,
}

fn storage(error: impl std::error::Error + Send + Sync + 'static) -> IdentityError {
    crate::tx_retry::identity_storage_error(error)
}

fn log_validation_query_failure(error: sqlx::Error) -> IdentityError {
    tracing::error!(
        target: "postgres",
        component = "auth_grant_validator",
        operation = "validate_current",
        error = %secure::redact_error(&error),
        "authentication grant validation query failed"
    );
    storage(error)
}

fn corruption(message: &'static str) -> IdentityError {
    storage(std::io::Error::other(message))
}

fn known_grant_status(status: &str) -> Result<bool, IdentityError> {
    match status {
        "active" => Ok(true),
        "revoked" | "compromised" => Ok(false),
        _ => Err(corruption("invalid persisted authentication grant status")),
    }
}

fn known_account_status(status: &str) -> Result<bool, IdentityError> {
    match status {
        "active" => Ok(true),
        "suspended" | "locked" | "deactivated" => Ok(false),
        _ => Err(corruption("invalid persisted account security status")),
    }
}

impl AuthGrantValidator for PgAuthGrantValidator {
    async fn is_current(
        &self,
        scope: TenantRepoScope,
        input: &AccessGrantValidationInput,
        observed_at: SystemTime,
    ) -> Result<bool, IdentityError> {
        if scope.tenant() != input.tenant() {
            return Ok(false);
        }
        let expected_auth_time = i64::try_from(input.auth_time_unix_secs())
            .map_err(|_| corruption("authentication time exceeds persistence boundary"))?;
        let expected_epoch = i64::try_from(input.authn_epoch().get())
            .map_err(|_| corruption("authentication epoch exceeds persistence boundary"))?;
        let observed_at = unix_secs(observed_at);
        let tenant = scope.tenant();
        let tenant_sql = tenant.as_uuid().to_string();
        let grant_id = input.grant_id().as_str().to_owned();
        let user_id = input.user_id().as_uuid().to_string();

        let row = self
            .pool
            .read(scope, move |conn| {
                Box::pin(async move {
                    sqlx::query_as::<_, ValidationRow>(
                        r#"
                        SELECT g.user_id = $3::uuid AS grant_user_matches,
                               extract(epoch from g.auth_time)::bigint AS grant_auth_time,
                               g.authn_epoch_at_issue AS grant_epoch,
                               g.status AS grant_status,
                               extract(epoch from g.expires_at)::bigint AS grant_expires_at,
                               s.user_id = $3::uuid AS account_user_matches,
                               s.status AS account_status,
                               s.authn_epoch AS account_epoch
                        FROM auth_grants AS g
                        LEFT JOIN account_security_states AS s
                          ON s.tenant_id = g.tenant_id
                         AND s.user_id = g.user_id
                        WHERE g.tenant_id = $1::uuid
                          AND g.grant_id = $2
                        "#,
                    )
                    .bind(tenant_sql)
                    .bind(grant_id)
                    .bind(user_id)
                    .fetch_optional(conn)
                    .await
                })
            })
            .await
            .map_err(log_validation_query_failure)?;

        let Some(row) = row else {
            return Ok(false);
        };
        if row.grant_auth_time < 0 || row.grant_epoch < 0 || row.grant_expires_at < 0 {
            return Err(corruption(
                "invalid persisted authentication grant counters",
            ));
        }
        let Some(account_user_matches) = row.account_user_matches else {
            return Ok(false);
        };
        let Some(account_status) = row.account_status.as_deref() else {
            return Ok(false);
        };
        let Some(account_epoch) = row.account_epoch else {
            return Ok(false);
        };
        if account_epoch < 0 {
            return Err(corruption(
                "negative persisted account authentication epoch",
            ));
        }

        Ok(row.grant_user_matches
            && account_user_matches
            && row.grant_auth_time == expected_auth_time
            && row.grant_epoch == expected_epoch
            && known_grant_status(&row.grant_status)?
            && row.grant_expires_at > observed_at
            && known_account_status(account_status)?
            && account_epoch == row.grant_epoch)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex};

    use tracing::field::Visit;
    use tracing::span::{Attributes, Id, Record};
    use tracing::{Event, Metadata, Subscriber};

    use super::{PgAuthGrantValidator, log_validation_query_failure};

    fn assert_send_sync<T: Send + Sync>() {}

    #[test]
    fn validator_is_send_sync() {
        assert_send_sync::<PgAuthGrantValidator>();
    }

    #[derive(Default)]
    struct CapturedFields(BTreeMap<String, String>);

    impl Visit for CapturedFields {
        fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
            self.0.insert(field.name().to_owned(), value.to_owned());
        }

        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn core::fmt::Debug) {
            self.0.insert(field.name().to_owned(), format!("{value:?}"));
        }
    }

    #[derive(Clone, Default)]
    struct ErrorCapture {
        records: Arc<Mutex<Vec<BTreeMap<String, String>>>>,
    }

    impl Subscriber for ErrorCapture {
        fn enabled(&self, metadata: &Metadata<'_>) -> bool {
            *metadata.level() == tracing::Level::ERROR
        }

        fn new_span(&self, _: &Attributes<'_>) -> Id {
            Id::from_u64(1)
        }

        fn record(&self, _: &Id, _: &Record<'_>) {}

        fn record_follows_from(&self, _: &Id, _: &Id) {}

        fn event(&self, event: &Event<'_>) {
            let mut fields = CapturedFields::default();
            event.record(&mut fields);
            self.records
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(fields.0);
        }

        fn enter(&self, _: &Id) {}

        fn exit(&self, _: &Id) {}
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn query_failure_log_is_actionable_and_contains_no_binding_identifiers() {
        let capture = ErrorCapture::default();
        let records = Arc::clone(&capture.records);
        let dispatch = tracing::Dispatch::new(capture);
        let _guard = tracing::dispatcher::set_default(&dispatch);

        let _ = log_validation_query_failure(sqlx::Error::Protocol(
            "postgres://operator:canary-secret@database/auth".to_owned(),
        ));

        let records = records
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let fields = records.first().expect("validation query failure is logged");
        assert_eq!(
            fields.get("component").map(String::as_str),
            Some("auth_grant_validator")
        );
        assert_eq!(
            fields.get("operation").map(String::as_str),
            Some("validate_current")
        );
        assert!(fields.contains_key("error"));
        assert!(
            fields.keys().all(|key| matches!(
                key.as_str(),
                "message" | "component" | "operation" | "error"
            )),
            "tenant/grant/token identifiers must not be attached: {fields:?}"
        );
        assert!(
            !fields.values().any(|value| value.contains("canary-secret")),
            "database credentials must be redacted: {fields:?}"
        );
    }
}
