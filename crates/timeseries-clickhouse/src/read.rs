use crate::{
    ChStore, Operation,
    control::{self, Fence},
    cursor::Position,
    page::{Dependencies, ReadBudget, Recheck, Request, View},
    projection::{RAW_FIELDS, Raw, hex, literal},
};
use rss_request_context::{Clock, Deadline};
use rss_timeseries::*;
pub(crate) fn selection(s: &Selection) -> Result<String, Error> {
    let base = format!(
        "tenant={} AND namespace={}",
        literal(&s.scope().tenant().to_string()),
        literal(s.scope().namespace().as_str())
    );
    Ok(match s {
        Selection::Exact { stream, series } => format!(
            "{base} AND source={} AND generation={} AND series={}",
            literal(stream.source().as_str()),
            literal(stream.generation().as_str()),
            literal(&hex(series.digest()?.as_bytes()))
        ),
        Selection::Resource {
            subject,
            resource,
            keys,
            ..
        } => {
            let keys = if keys.is_empty() {
                String::new()
            } else {
                format!(
                    " AND metric_key IN ({})",
                    keys.iter()
                        .map(|k| literal(k.as_str()))
                        .collect::<Vec<_>>()
                        .join(",")
                )
            };
            format!(
                "{base} AND subject={} AND resource={}{}",
                literal(subject.as_str()),
                literal(resource.as_str()),
                keys
            )
        }
    })
}
pub(crate) fn visible(fences: &[Fence]) -> Result<String, Error> {
    let mut condition = String::new();
    for f in fences {
        if f.kind == "cutoff" || (f.kind == "delete" && f.restored) {
            continue;
        }
        condition.push_str(&format!(
            " AND NOT ({} AND observed_at>={} AND observed_at<{})",
            selection(&f.selection)?,
            f.window.start().micros(),
            f.window.end().micros()
        ));
    }
    Ok(condition)
}
const ORDER: &str = "series,source,generation,observed_at,sequence,sample_id";
fn position(p: &Position, latest: bool) -> String {
    let prefix = format!(
        "{},{},{}",
        literal(&hex(&p.series)),
        literal(p.source.as_str()),
        literal(p.generation.as_str())
    );
    if latest {
        format!(" AND (series,source,generation)>({prefix})")
    } else {
        format!(
            " AND ({ORDER})>({prefix},{},{},{})",
            p.time,
            p.sequence,
            literal(p.id.as_str())
        )
    }
}
pub(crate) struct ReadRow {
    pub sample: Sample,
    pub received_at: Timestamp,
    pub revision: i64,
}
impl<C: Clock> Operation<'_, C> {
    pub(crate) async fn raw_rows(
        &self,
        condition: &str,
        order: &str,
        limit: u32,
        deadline: Deadline,
    ) -> Result<Vec<ReadRow>, Error> {
        let sql = format!(
            "SELECT {RAW_FIELDS} FROM rss_ts_ch.raw FINAL WHERE {condition} ORDER BY {order} LIMIT {}",
            u64::from(limit) + 1
        );
        self.fetch_raw(&sql, limit, deadline).await
    }
    async fn fetch_raw(
        &self,
        sql: &str,
        limit: u32,
        deadline: Deadline,
    ) -> Result<Vec<ReadRow>, Error> {
        let mut cursor = self
            .ch_query(self.reader.query_raw(sql), deadline)?
            .fetch::<Raw>()
            .map_err(crate::projection::read_error)?;
        let mut size = 0usize;
        let mut rows = Vec::new();
        while let Some(row) = cursor.next().await.map_err(crate::projection::read_error)? {
            size = size
                .checked_add(row.payload.len())
                .ok_or(Error::BudgetExceeded)?;
            if size > self.limits.max_bytes.get() as usize || rows.len() > limit as usize {
                return Err(Error::BudgetExceeded);
            }
            rows.push(ReadRow {
                revision: row.revision,
                sample: row.sample()?,
                received_at: Timestamp::new(row.received_at)?,
            });
        }
        Ok(rows)
    }
}
impl Request for Query {
    type Position = Position;
    type Metadata = ();
    type Page = Page;
    const DOMAIN: &'static [u8] = b"rss.timeseries.clickhouse.history.v3";
    const INVALIDATED: Error = Error::HistoryExpired;
    fn query(&self) -> &Query {
        self
    }
    fn binding(&self) -> Result<Digest, Error> {
        self.binding()
    }
    async fn dependencies<C: Clock>(
        &self,
        store: &Operation<'_, C>,
        c: &mut sqlx::PgConnection,
        fence: i64,
        _: Option<&Position>,
    ) -> Result<Dependencies, Error> {
        Ok(Dependencies {
            fences: control::visible_fences(
                c,
                self,
                self.window().start().micros(),
                store.limits,
                false,
            )
            .await?,
            tag: store.material.key.page_state(
                Self::DOMAIN,
                self.binding()?,
                store.instance,
                &fence,
            )?,
        })
    }
    fn state<C: Clock>(
        &self,
        _: &Operation<'_, C>,
        _: &(),
        tag: [u8; 32],
    ) -> Result<[u8; 32], Error> {
        Ok(tag)
    }
    async fn recheck<C: Clock>(
        &self,
        store: &Operation<'_, C>,
        _: &mut sqlx::PgConnection,
        _: &(),
        check: Recheck,
    ) -> Result<(bool, bool), Error> {
        let tag = store.material.key.page_state(
            Self::DOMAIN,
            self.binding()?,
            store.instance,
            &check.fence,
        )?;
        let same = tag == check.tag;
        Ok((same, same))
    }
    async fn metadata<C: Clock>(
        &self,
        _: &Operation<'_, C>,
        _: &mut sqlx::PgConnection,
        _: &View<Position>,
    ) -> Result<(), Error> {
        Ok(()) // reason: raw pages only need the shared fence snapshot.
    }
    async fn read<C: Clock>(
        &self,
        store: &Operation<'_, C>,
        view: View<Position>,
        _: &mut (),
        budget: &mut ReadBudget,
    ) -> Result<(Page, Option<Position>), Error> {
        let deadline = budget.deadline;
        let q = self;
        let availability = control::availability(q, &view.fences)?;
        if !view.exists {
            return Ok((
                Page {
                    rows: Vec::new(),
                    availability,
                    next: None,
                },
                None,
            ));
        }
        let latest = q.mode() == QueryMode::Latest;
        let mut condition = format!(
            "{} AND revision<={} AND observed_at>={} AND observed_at<{}{}",
            selection(q.selection())?,
            view.published,
            q.window().start().micros(),
            q.window().end().micros(),
            visible(&view.fences)?
        );
        if let Some(previous) = view.position {
            condition.push_str(&position(&previous, latest));
        }
        let points = q.budget().max_points.get();
        let groups = q.budget().max_series.get();
        let mut more_groups = false;
        if !latest && groups < points && matches!(q.selection(), Selection::Resource { .. }) {
            let sql = format!(
                "SELECT DISTINCT series,source,generation FROM rss_ts_ch.raw FINAL WHERE {condition} ORDER BY series,source,generation LIMIT {}",
                u64::from(groups) + 1
            );
            let keys = store
                .ch_query(store.reader.query_raw(&sql), deadline)?
                .fetch_all::<(String, String, String)>()
                .await
                .map_err(crate::projection::read_error)?;
            if keys.len() > groups as usize {
                let (series, source, generation) = &keys[groups as usize - 1];
                condition.push_str(&format!(
                    " AND (series,source,generation)<=({},{},{})",
                    literal(series),
                    literal(source),
                    literal(generation)
                ));
                more_groups = true;
            }
        }
        let limit = if latest { points.min(groups) } else { points };
        let mut rows = if latest {
            let sql = format!(
                "SELECT {RAW_FIELDS} FROM (SELECT {RAW_FIELDS} FROM rss_ts_ch.raw FINAL WHERE {condition} ORDER BY series,source,generation,observed_at DESC,sequence DESC,sample_id DESC LIMIT 1 BY series,source,generation) ORDER BY {ORDER} LIMIT {}",
                u64::from(limit) + 1
            );
            store.fetch_raw(&sql, limit, deadline).await?
        } else {
            store.raw_rows(&condition, ORDER, limit, deadline).await?
        };
        let more = more_groups || rows.len() > limit as usize;
        rows.truncate(limit as usize);
        let rows: Vec<_> = rows
            .into_iter()
            .map(|row| ObservedSample {
                sample: row.sample,
                received_at: row.received_at,
            })
            .collect();
        q.validate_page(&rows)?;
        let next = if more {
            Some(Position::of(&rows.last().ok_or(Error::Invariant)?.sample)?)
        } else {
            None
        };
        Ok((
            Page {
                rows,
                availability,
                next: None,
            },
            next,
        ))
    }
}
impl<C: Clock> Reader for ChStore<C> {
    async fn query(
        &self,
        q: &Authorized<Query>,
        after: Option<&Continuation>,
        deadline: Deadline,
    ) -> Result<Page, Error> {
        let owner = self.owner.upgrade().ok_or(Error::Unavailable)?;
        let operation = owner
            .read_operation(self, q.request().selection().scope(), deadline)
            .await?;
        let (mut page, next) = operation
            .bounded(deadline, operation.page(q.request(), after, deadline))
            .await?;
        page.next = next;
        Ok(page)
    }
    async fn aggregate(
        &self,
        q: &Authorized<AggregateQuery>,
        after: Option<&Continuation>,
        deadline: Deadline,
    ) -> Result<AggregatePage, Error> {
        let owner = self.owner.upgrade().ok_or(Error::Unavailable)?;
        let operation = owner
            .read_operation(self, q.request().spec().stream().scope(), deadline)
            .await?;
        let (mut page, next) = operation
            .bounded(deadline, operation.page(q.request(), after, deadline))
            .await?;
        page.next = next;
        Ok(page)
    }
}
