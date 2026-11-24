//! PG establishes and rechecks each page's view. No PG session crosses ClickHouse IO.
use crate::{
    Operation,
    control::{self, Fence},
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
    const AGGREGATE: bool;
    fn query(&self) -> &Query;
    fn binding(&self) -> Result<Digest, Error>;
    fn fence_start(&self) -> i64;
    async fn metadata<C: Clock>(
        &self,
        store: &Operation<'_, C>,
        connection: &mut PgConnection,
        view: &View<Self::Position>,
    ) -> Result<Self::Metadata, Error>;
    async fn read<C: Clock>(
        &self,
        store: &Operation<'_, C>,
        view: View<Self::Position>,
        metadata: Self::Metadata,
        deadline: Deadline,
    ) -> Result<(Self::Page, Option<Self::Position>), Error>;
}

#[derive(Clone, Copy, Default, PartialEq, Eq)]
struct Version {
    published: i64,
    fence: i64,
    summaries: i64,
}
impl Version {
    fn agrees(self, current: Self, aggregate: bool) -> bool {
        self.fence == current.fence
            && if aggregate {
                self == current
            } else {
                self.published <= current.published
            }
    }
    async fn load(tx: &mut Session, scope: &Scope) -> Result<Option<Self>, Error> {
        let row: Option<(i64,i64,i64)>=sqlx::query_as("SELECT published,fence_epoch,summary_epoch FROM rss_ts_ch.namespaces WHERE tenant_id=$1::text::uuid AND namespace=$2")
            .bind(scope.tenant().to_string()).bind(scope.namespace().as_str()).fetch_optional(tx.connection()).await.map_err(sql_error)?;
        Ok(row.map(|(published, fence, summaries)| Self {
            published,
            fence,
            summaries,
        }))
    }
}
#[derive(Serialize, Deserialize)]
struct Cursor<P> {
    ceiling: Option<i64>,
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
        &self,
        request: &R,
        after: Option<&Continuation>,
        deadline: Deadline,
    ) -> Result<(R::Page, Option<Continuation>), Error> {
        let q = request.query();
        let binding = request.binding()?;
        let domain = R::DOMAIN;
        let aggregate = R::AGGREGATE;
        let state_tag = |v: Version| {
            self.material.key.page_state(
                domain,
                binding,
                self.instance,
                v.fence,
                aggregate.then_some((v.published, v.summaries)),
            )
        };
        if q.budget().max_points > self.limits.max_points
            || q.budget().max_series > self.limits.max_series
        {
            return Err(Error::BudgetExceeded);
        }
        let scope = q.selection().scope();
        for _ in 0..2 {
            let mut tx = self
                .session(
                    scope,
                    deadline,
                    "BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY",
                )
                .await?;
            let snapshot = async {
                let current = Version::load(&mut tx, scope).await?;
                let time = now(tx.connection()).await?;
                let (version, position, expires) = if let Some(token) = after {
                    let (expires, cursor) = self.material.key.open::<Cursor<R::Position>>(
                        domain,
                        token,
                        binding,
                        self.instance,
                        time,
                    )?;
                    let mut version = current.ok_or(Error::HistoryExpired)?;
                    if state_tag(version)? != cursor.state {
                        return Err(Error::HistoryExpired);
                    }
                    if let Some(ceiling) = cursor.ceiling {
                        if ceiling > version.published {
                            return Err(Error::HistoryExpired);
                        }
                        version.published = ceiling;
                    }
                    (version, Some(cursor.position), expires)
                } else {
                    (
                        current.unwrap_or_default(),
                        None,
                        time.checked_add(self.limits.cursor_micros.get() as i64)
                            .ok_or(Error::NumericRange)?,
                    )
                };
                let start = request.fence_start();
                let fences =
                    control::visible_fences(tx.connection(), q, start, self.limits).await?;
                let view = View {
                    published: version.published,
                    fences,
                    position,
                    exists: current.is_some(),
                };
                let meta = request.metadata(self, tx.connection(), &view).await?;
                Ok((view, meta, version, expires))
            }
            .await;
            let (view, meta, version, expires) = tx.read(snapshot).await?;
            let result = request.read(self, view, meta, deadline).await;
            let mut tx = self.session(scope, deadline, "BEGIN READ ONLY").await?;
            let current = Version::load(&mut tx, scope).await;
            let current = tx.read(current).await?.unwrap_or_default();
            if version.agrees(current, aggregate) {
                let (page, position) = result?;
                let next = position
                    .map(|position| {
                        self.material.key.seal(
                            domain,
                            binding,
                            self.instance,
                            expires,
                            &Cursor {
                                ceiling: (!aggregate).then_some(version.published),
                                state: state_tag(version)?,
                                position,
                            },
                        )
                    })
                    .transpose()?;
                return Ok((page, next));
            }
            if after.is_some() {
                return Err(Error::HistoryExpired);
            }
        }
        Err(Error::Unavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CursorKey;
    #[test]
    fn cursor_carries_only_the_ceiling_position_and_bound_state_tag() -> Result<(), Error> {
        let key = CursorKey::new([17; 32]);
        let binding = Digest::from_bytes([3; 32]);
        let state = key.page_state(Query::DOMAIN, binding, "instance", 7524, None)?;
        let token = key.seal(
            Query::DOMAIN,
            binding,
            "instance",
            100,
            &Cursor {
                ceiling: Some(6),
                position: 12,
                state,
            },
        )?;
        let (_, body) =
            key.open::<serde_json::Value>(Query::DOMAIN, &token, binding, "instance", 0)?;
        assert_eq!(
            body,
            serde_json::json!({"ceiling":6,"position":12,"state":state})
        );
        assert_ne!(
            state,
            key.page_state(
                Query::DOMAIN,
                Digest::from_bytes([4; 32]),
                "instance",
                7524,
                None
            )?
        );
        assert_ne!(
            state,
            key.page_state(Query::DOMAIN, binding, "instance", 7525, None)?
        );
        Ok(())
    }
}
