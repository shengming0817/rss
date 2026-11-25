//! One bounded page driver. PostgreSQL snapshots never cross ClickHouse IO.
// ref: apache/iceberg-rust crates/iceberg/src/scan/mod.rs@b058267a71a067f2782ff710ab03c4c250c51959
use crate::{
    Operation,
    control::Fence,
    transaction::{Session, now, sql_error},
};
use rss_request_context::{Clock, Deadline};
use rss_timeseries::*;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sqlx::PgConnection;

pub(crate) trait Request {
    type Position: Serialize + DeserializeOwned;
    type Metadata;
    type Page;
    const DOMAIN: &'static [u8];
    const INVALIDATED: Error;
    fn query(&self) -> &Query;
    fn binding(&self) -> Result<Digest, Error>;
    async fn dependencies<C: Clock>(
        &self, store: &Operation<'_, C>, connection: &mut PgConnection, fence: i64,
    ) -> Result<Dependencies, Error>;
    async fn metadata<C: Clock>(
        &self, store: &Operation<'_, C>, connection: &mut PgConnection, view: &View<Self::Position>,
    ) -> Result<Self::Metadata, Error>;
    async fn valid<C: Clock>(
        &self, store: &Operation<'_, C>, connection: &mut PgConnection, metadata: &Self::Metadata, ceiling: i64,
    ) -> Result<bool, Error>;
    async fn read<C: Clock>(
        &self, store: &Operation<'_, C>, view: View<Self::Position>, metadata: &mut Self::Metadata, deadline: Deadline,
    ) -> Result<(Self::Page, Option<Self::Position>), Error>;
}
pub(crate) struct Dependencies {
    pub fences: Vec<Fence>,
    pub tag: [u8; 32],
}
#[derive(Clone, Copy, Default)]
struct Version { published: i64, fence: i64 }
impl Version {
    async fn load(tx: &mut Session, scope: &Scope) -> Result<Option<Self>, Error> {
        let row: Option<(i64, i64)> = sqlx::query_as("SELECT published,fence_epoch FROM rss_ts_ch.namespaces WHERE tenant_id=$1::text::uuid AND namespace=$2")
            .bind(scope.tenant().to_string()).bind(scope.namespace().as_str()).fetch_optional(tx.connection()).await.map_err(sql_error)?;
        Ok(row.map(|(published, fence)| Self { published, fence }))
    }
}
#[derive(Serialize, Deserialize)]
struct Cursor<P> {
    ceiling: i64,
    state: [u8; 32],
    position: P,
}
pub(crate) struct View<P> {
    pub published: i64,
    pub fences: Vec<Fence>,
    pub position: Option<P>,
    pub exists: bool,
}
impl<C: Clock> Operation<'_, C> {
    pub(crate) async fn page<R: Request>(
        &self, request: &R, after: Option<&Continuation>, deadline: Deadline,
    ) -> Result<(R::Page, Option<Continuation>), Error> {
        let q = request.query();
        let binding = request.binding()?;
        if q.budget().max_points > self.limits.max_points || q.budget().max_series > self.limits.max_series {
            return Err(Error::BudgetExceeded);
        }
        let scope = q.selection().scope();
        let mut first = None;
        for _ in 0..2 {
            let mut tx = self.session(scope, deadline, "BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY").await?;
            let snapshot = async {
                let current = Version::load(&mut tx, scope).await?;
                let version = current.unwrap_or_default();
                let deps = request.dependencies(self, tx.connection(), version.fence).await?;
                let time = now(tx.connection()).await?;
                let (ceiling, position, expires) = if let Some(token) = after {
                    let (expires, cursor) = self.material.key.open::<Cursor<R::Position>>(
                        R::DOMAIN, token, binding, self.instance, time,
                    )?;
                    if current.is_none() || cursor.ceiling < 0 || cursor.ceiling > version.published || cursor.state != deps.tag {
                        return Err(R::INVALIDATED);
                    }
                    (cursor.ceiling, Some(cursor.position), expires)
                } else {
                    let (ceiling, expires) = *first.get_or_insert((version.published,
                        time.checked_add(self.limits.cursor_micros.get() as i64).ok_or(Error::NumericRange)?));
                    if ceiling > version.published { return Err(R::INVALIDATED); }
                    (ceiling, None, expires)
                };
                let view = View { published: ceiling, fences: deps.fences, position, exists: current.is_some() };
                let metadata = request.metadata(self, tx.connection(), &view).await?;
                Ok((view, metadata, deps.tag, expires))
            }.await;
            let (view, mut metadata, tag, expires) = tx.read(snapshot).await?;
            let ceiling = view.published;
            // Keep attempted-object evidence even when the ClickHouse read fails.
            let result = request.read(self, view, &mut metadata, deadline).await;
            let mut tx = self.session(scope, deadline, "BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY").await?;
            let recheck = async {
                let current = Version::load(&mut tx, scope).await?.unwrap_or_default();
                let deps = request.dependencies(self, tx.connection(), current.fence).await?;
                let same = ceiling <= current.published && tag == deps.tag;
                let valid = same && request.valid(self, tx.connection(), &metadata, ceiling).await?;
                Ok((same, valid))
            }.await;
            let (same, valid) = tx.read(recheck).await?;
            if valid {
                let (page, position) = result?;
                let next = position.map(|position| self.material.key.seal(
                    R::DOMAIN, binding, self.instance, expires, &Cursor { ceiling, state: tag, position },
                )).transpose()?;
                return Ok((page, next));
            }
            if after.is_some() && !same { return Err(R::INVALIDATED); }
        }
        Err(if after.is_some() { R::INVALIDATED } else { Error::Unavailable })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CursorKey;
    #[test]
    fn snapshot_cursor_authenticates_ceiling_scope_dependencies_and_instance() -> Result<(), Error> {
        let key = CursorKey::new([17; 32]);
        let binding = Digest::from_bytes([3; 32]);
        let state = key.page_state(Query::DOMAIN, binding, "instance", &7524i64)?;
        let token = key.seal(Query::DOMAIN, binding, "instance", 100,
            &Cursor { ceiling: 6, position: 12, state })?;
        let (_, cursor) = key.open::<Cursor<i64>>(Query::DOMAIN, &token, binding, "instance", 0)?;
        assert_eq!((cursor.ceiling, cursor.position, cursor.state), (6, 12, state));
        assert_ne!(state, key.page_state(Query::DOMAIN, binding, "instance", &7525i64)?);
        for (scope, instance, now) in [(Digest::from_bytes([4;32]), "instance", 0), (binding, "other", 0), (binding, "instance", 100)] {
            assert!(matches!(key.open::<Cursor<i64>>(Query::DOMAIN, &token, scope, instance, now), Err(Error::InvalidCursor)));
        }
        Ok(())
    }
}
