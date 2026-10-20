// ref: launchbadge/sqlx sqlx-core/src/transaction.rs@v0.9.0
use crate::ChStore;
use rss_request_context::{Clock, Deadline};
use rss_timeseries::{Error, Outcome, Scope};
use sqlx::{PgConnection, Postgres, Row, pool::PoolConnection};
use std::future::Future;

pub(crate) fn sql_error(e: sqlx::Error) -> Error {
    match e.as_database_error().and_then(|e| e.code()).as_deref() {
        Some("57014" | "55P03") => Error::Deadline,
        Some("42501") => Error::Unauthorized,
        Some("23505") => Error::Conflict,
        Some("23514" | "23503" | "42P01" | "42703") => Error::Invariant,
        _ => Error::Unavailable,
    }
}
pub(crate) fn bytes(v: &impl serde::Serialize) -> Result<Vec<u8>, Error> {
    serde_json::to_vec(v).map_err(|_| Error::Invariant)
}
pub(crate) fn decode<T: serde::de::DeserializeOwned>(v: &[u8]) -> Result<T, Error> {
    serde_json::from_slice(v).map_err(|_| Error::Invariant)
}
pub(crate) async fn now(c: &mut PgConnection) -> Result<i64, Error> {
    sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp())*1000000)::bigint")
        .fetch_one(c)
        .await
        .map_err(sql_error)
}
/// A dropped/unsettled session is never returned to the pool.
pub(crate) struct Session {
    connection: PoolConnection<Postgres>,
    settled: bool,
    pub published: i64,
    pub revision: i64,
}
impl Drop for Session {
    fn drop(&mut self) {
        if !self.settled {
            self.connection.close_on_drop();
        }
    }
}
impl Session {
    pub fn connection(&mut self) -> &mut PgConnection {
        &mut self.connection
    }
    pub async fn finish<T>(
        mut self,
        result: Result<T, Error>,
        write: bool,
    ) -> Result<Outcome<T>, Error> {
        let command = if result.is_ok() && write {
            "COMMIT"
        } else {
            "ROLLBACK"
        };
        if sqlx::query(command)
            .execute(&mut *self.connection)
            .await
            .is_err()
        {
            return Ok(Outcome::Unknown);
        }
        self.settled = true;
        result.map(Outcome::Accepted)
    }
    pub async fn read<T>(self, result: Result<T, Error>) -> Result<T, Error> {
        match self.finish(result, false).await? {
            Outcome::Accepted(value) | Outcome::Replay(value) => Ok(value),
            Outcome::Unknown => Err(Error::Unavailable),
        }
    }
}
impl<C: Clock> ChStore<C> {
    pub(crate) async fn operation(
        &self,
        scope: &Scope,
        deadline: Deadline,
    ) -> Result<tokio::sync::RwLockReadGuard<'_, ()>, Error> {
        self.scope(scope)?;
        self.bounded(deadline, async {
            let guard = self.operations.read().await;
            self.scope(scope)?;
            Ok(guard)
        })
        .await
    }
    pub(crate) fn scope(&self, scope: &Scope) -> Result<(), Error> {
        if scope.tenant() != self.tenant {
            return Err(Error::Unauthorized);
        }
        if self.closed.load(std::sync::atomic::Ordering::Acquire) {
            return Err(Error::Unavailable);
        }
        Ok(())
    }
    pub(crate) async fn bounded<T>(
        &self,
        deadline: Deadline,
        f: impl Future<Output = Result<T, Error>>,
    ) -> Result<T, Error> {
        let remaining = deadline
            .remaining(self.clock.now())
            .ok_or(Error::Deadline)?;
        tokio::time::timeout(remaining, f)
            .await
            .map_err(|_| Error::Deadline)?
    }
    pub(crate) async fn mutation<T>(
        &self,
        deadline: Deadline,
        f: impl Future<Output = Result<Outcome<T>, Error>>,
    ) -> Result<Outcome<T>, Error> {
        match self.bounded(deadline, f).await {
            Err(Error::Deadline) => Ok(Outcome::Unknown),
            result => result,
        }
    }
    pub(crate) async fn begin(
        &self,
        scope: &Scope,
        exclusive: bool,
        deadline: Deadline,
    ) -> Result<Session, Error> {
        self.scope(scope)?;
        let mut s = Session {
            connection: self.pool.acquire().await.map_err(sql_error)?,
            settled: false,
            published: 0,
            revision: 0,
        };
        sqlx::query("BEGIN")
            .execute(s.connection())
            .await
            .map_err(sql_error)?;
        let ms = deadline
            .remaining(self.clock.now())
            .ok_or(Error::Deadline)?
            .as_millis()
            .clamp(1, i32::MAX as u128);
        sqlx::query("SELECT set_config('rss.tenant_id',$1,true),set_config('statement_timeout',$2,true),set_config('lock_timeout',$2,true)")
            .bind(self.tenant.to_string()).bind(format!("{ms}ms")).execute(s.connection()).await.map_err(sql_error)?;
        sqlx::query("INSERT INTO rss_ts_ch.namespaces(tenant_id,namespace) VALUES($1::text::uuid,$2) ON CONFLICT DO NOTHING")
            .bind(self.tenant.to_string()).bind(scope.namespace().as_str()).execute(s.connection()).await.map_err(sql_error)?;
        let sql = if exclusive {
            "SELECT published,revision FROM rss_ts_ch.namespaces WHERE tenant_id=$1::text::uuid AND namespace=$2 FOR UPDATE"
        } else {
            "SELECT published,revision FROM rss_ts_ch.namespaces WHERE tenant_id=$1::text::uuid AND namespace=$2 FOR SHARE"
        };
        let row = sqlx::query(sql)
            .bind(self.tenant.to_string())
            .bind(scope.namespace().as_str())
            .fetch_one(s.connection())
            .await
            .map_err(sql_error)?;
        s.published = row.try_get("published").map_err(sql_error)?;
        s.revision = row.try_get("revision").map_err(sql_error)?;
        Ok(s)
    }
}
pub(crate) fn flatten<T>(v: Outcome<Outcome<T>>) -> Outcome<T> {
    match v {
        Outcome::Accepted(v) | Outcome::Replay(v) => v,
        Outcome::Unknown => Outcome::Unknown,
    }
}
