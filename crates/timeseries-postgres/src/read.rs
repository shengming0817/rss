use crate::{
    CursorKey, Limits, PgStore,
    cursor::Position,
    transaction::{certain, check, db_now, sql_error},
};
use futures::TryStreamExt;
use rss_request_context::{Clock, Deadline};
use rss_timeseries::*;
use sqlx::{PgConnection, Row, postgres::PgRow};
fn projected(row: &PgRow) -> Result<Position, Error> {
    let series: Vec<u8> = row.try_get("series_digest").map_err(sql_error)?;
    Ok(Position {
        series: series.try_into().map_err(|_| Error::Invariant)?,
        source: Id::new(row.try_get::<String, _>("source").map_err(sql_error)?)?,
        generation: Id::new(row.try_get::<String, _>("generation").map_err(sql_error)?)?,
        time: row.try_get("observed_at").map_err(sql_error)?,
        sequence: row
            .try_get::<String, _>("sequence_text")
            .map_err(sql_error)?
            .parse()
            .map_err(|_| Error::Invariant)?,
        id: Id::new(row.try_get::<String, _>("sample_id").map_err(sql_error)?)?,
    })
}

struct Read {
    query: Query,
    after: Option<Continuation>,
    limits: Limits,
    key: CursorKey,
    instance: String,
    deadline: Deadline,
}
impl Read {
    async fn run(self, c: &mut PgConnection, clock: &impl Clock) -> Result<Page, Error> {
        let q = &self.query;
        crate::lifecycle::read_lock(c, q.selection().scope()).await?;
        let availability =
            crate::lifecycle::availability(c, q, self.limits.max_points.get()).await?;
        let now = db_now(c).await?;
        let binding = q.binding()?;
        let token = self
            .after
            .as_ref()
            .map(|a| self.key.decode(a, binding, &self.instance, now))
            .transpose()?;
        let expires = match &token {
            Some(t) => t.expires,
            None => now
                .checked_add(self.limits.cursor_micros.get() as i64)
                .ok_or(Error::NumericRange)?,
        };
        let after = token.map(|t| t.last);
        let (series, source, generation, subject, resource, keys) = match q.selection() {
            Selection::Exact { stream, series } => (
                Some(series.digest()?.as_bytes().to_vec()),
                Some(stream.source().as_str()),
                Some(stream.generation().as_str()),
                None,
                None,
                Vec::new(),
            ),
            Selection::Resource {
                subject,
                resource,
                keys,
                ..
            } => (
                None,
                None,
                None,
                Some(subject.as_str()),
                Some(resource.as_str()),
                keys.iter().map(Id::as_str).collect(),
            ),
        };
        let sql = match q.mode() {
            QueryMode::History => include_str!("history.sql"),
            QueryMode::Latest => include_str!("latest.sql"),
        };
        let mut stream = sqlx::query(sql)
            .bind(q.selection().scope().tenant().to_string())
            .bind(q.selection().scope().namespace().as_str())
            .bind(q.window().start().micros())
            .bind(q.window().end().micros())
            .bind(series)
            .bind(source)
            .bind(generation)
            .bind(subject)
            .bind(resource)
            .bind(keys)
            .bind(after.as_ref().map(|p| p.series.to_vec()))
            .bind(after.as_ref().map(|p| p.source.as_str()))
            .bind(after.as_ref().map(|p| p.generation.as_str()))
            .bind(after.as_ref().map(|p| p.time))
            .bind(after.as_ref().map(|p| p.sequence.to_string()))
            .bind(after.as_ref().map(|p| p.id.as_str()))
            .bind(i64::from(q.budget().max_points.get()) + 1)
            .fetch(c);
        let mut rows = Vec::new();
        let mut positions: Vec<Position> = Vec::new();
        let mut groups = 0u32;
        let mut bytes = 0usize;
        let mut more = false;
        while let Some(row) = stream.try_next().await.map_err(sql_error)? {
            check(clock, self.deadline)?;
            if rows.len() == q.budget().max_points.get() as usize {
                more = true;
                break;
            }
            let projected = projected(&row)?;
            let new_group = positions
                .last()
                .is_none_or(|p| p.group() != projected.group());
            if new_group && groups == q.budget().max_series.get() {
                more = true;
                break;
            }
            let raw: Vec<u8> = row.try_get("raw").map_err(sql_error)?;
            bytes = bytes.checked_add(raw.len()).ok_or(Error::BudgetExceeded)?;
            if bytes > self.limits.max_bytes.get() as usize {
                return Err(Error::BudgetExceeded);
            }
            let sample: Sample = serde_json::from_slice(&raw).map_err(|_| Error::Invariant)?;
            let digest: Vec<u8> = row.try_get("digest").map_err(sql_error)?;
            let received: i64 = row.try_get("received_at").map_err(sql_error)?;
            if sample.digest()?.as_bytes().as_slice() != digest
                || received
                    != row
                        .try_get::<i64, _>("original_received")
                        .map_err(sql_error)?
            {
                return Err(Error::Invariant);
            }
            let position = Position::of(&sample)?;
            let series = &sample.input().series;
            if position != projected
                || series.subject().as_str()
                    != row.try_get::<String, _>("subject").map_err(sql_error)?
                || series.resource().as_str()
                    != row.try_get::<String, _>("resource").map_err(sql_error)?
                || series.definition().spec().key.as_str()
                    != row.try_get::<String, _>("key").map_err(sql_error)?
                || series.definition().spec().version.to_string()
                    != row
                        .try_get::<String, _>("version_text")
                        .map_err(sql_error)?
            {
                return Err(Error::Invariant);
            }
            groups += u32::from(new_group);
            positions.push(position);
            rows.push(ObservedSample {
                sample,
                received_at: Timestamp::new(received)?,
            });
        }
        q.validate_page(&rows)?;
        check(clock, self.deadline)?;
        let next = if more {
            Some(self.key.encode(
                binding,
                &self.instance,
                expires,
                positions.pop().ok_or(Error::Invariant)?,
            )?)
        } else {
            None
        };
        Ok(Page {
            rows,
            next,
            availability,
        })
    }
}
impl<C: Clock> Reader for PgStore<C> {
    async fn query(
        &self,
        request: &Authorized<Query>,
        after: Option<&Continuation>,
        deadline: Deadline,
    ) -> Result<Page, Error> {
        let query = request.request().clone();
        if query.budget().max_points > self.limits.max_points
            || query.budget().max_series > self.limits.max_series
        {
            return Err(Error::BudgetExceeded);
        }
        let tenant = query.selection().scope().tenant();
        let read = Read {
            query,
            after: after.cloned(),
            limits: self.limits.clone(),
            key: self.key.clone(),
            instance: self.instance.clone(),
            deadline,
        };
        certain(
            self.transaction(tenant, deadline, false, move |c, clock| {
                Box::pin(read.run(c, clock))
            })
            .await?,
        )
    }
    async fn aggregate(
        &self,
        request: &Authorized<AggregateQuery>,
        after: Option<&Continuation>,
        deadline: Deadline,
    ) -> Result<AggregatePage, Error> {
        crate::aggregate::read(self, request.request(), after, deadline).await
    }
}
