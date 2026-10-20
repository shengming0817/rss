use crate::{
    ChStore,
    control::{self, Fence},
    cursor::Position,
    projection::{RAW_FIELDS, Raw, hex, literal},
    transaction::now,
};
use rss_request_context::{Clock, Deadline};
use rss_timeseries::*;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
const DOMAIN: &[u8] = b"rss.timeseries.clickhouse.history.v1";
#[derive(Serialize, Deserialize)]
struct Cursor {
    boundary: i64,
    last: Position,
}
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
impl<C: Clock> ChStore<C> {
    pub(crate) async fn raw_rows(
        &self,
        condition: &str,
        order: &str,
        limit: u32,
        deadline: Deadline,
    ) -> Result<Vec<Raw>, Error> {
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
    ) -> Result<Vec<Raw>, Error> {
        let mut cursor = self
            .ch_query(&self.ch.reader, sql, deadline)?
            .fetch::<Raw>()
            .map_err(|_| Error::Unavailable)?;
        let mut size = 0usize;
        let mut rows = Vec::new();
        while let Some(row) = cursor.next().await.map_err(|_| Error::Unavailable)? {
            size = size
                .checked_add(row.payload.len())
                .ok_or(Error::BudgetExceeded)?;
            if size > self.limits.max_bytes.get() as usize || rows.len() > limit as usize {
                return Err(Error::BudgetExceeded);
            }
            row.sample()?;
            rows.push(row);
        }
        Ok(rows)
    }
    async fn history(
        &self,
        q: &Query,
        after: Option<&Continuation>,
        deadline: Deadline,
    ) -> Result<Page, Error> {
        if q.budget().max_points > self.limits.max_points
            || q.budget().max_series > self.limits.max_series
        {
            return Err(Error::BudgetExceeded);
        }
        let mut tx = self.begin(q.selection().scope(), false, deadline).await?;
        let result=async {
            let time=now(tx.connection()).await?;
            let (expires,previous)=match after {Some(t)=>{let (e,v)=self.key.open::<Cursor>(DOMAIN,t,q.binding()?,&self.instance,time)?;(e,Some(v))},None=>(time.checked_add(self.limits.cursor_micros.get() as i64).ok_or(Error::NumericRange)?,None)};
            let boundary=previous.as_ref().map_or(tx.published,|c|c.boundary);
            if boundary>tx.published || boundary<0 {return Err(Error::InvalidCursor);}
            let fences=control::fences(tx.connection(),q.selection().scope(),self.limits.max_points.get()).await?;
            let mut condition=format!("{} AND revision<={} AND observed_at>={} AND observed_at<{}{}",selection(q.selection())?,boundary,q.window().start().micros(),q.window().end().micros(),visible(&fences)?);
            if let Some(previous)=previous {condition.push_str(&position(&previous.last,q.mode()==QueryMode::Latest));}
            let cap=q.budget().max_points.get();
            let sql=if q.mode()==QueryMode::Latest {
                format!("SELECT {RAW_FIELDS} FROM (SELECT {RAW_FIELDS} FROM rss_ts_ch.raw FINAL WHERE {condition} ORDER BY series,source,generation,observed_at DESC,sequence DESC,sample_id DESC LIMIT 1 BY series,source,generation) ORDER BY {ORDER} LIMIT {}",u64::from(cap)+1)
            } else {format!("SELECT {RAW_FIELDS} FROM rss_ts_ch.raw FINAL WHERE {condition} ORDER BY {ORDER} LIMIT {}",u64::from(cap)+1)};
            let raw=self.fetch_raw(&sql,cap,deadline).await?;
            let mut rows=Vec::new();let mut groups=BTreeSet::new();let mut more=false;let mut last=None;
            for r in raw {
                let s=r.sample()?;let p=Position::of(&s)?;
                let group=(p.series,p.source.clone(),p.generation.clone());
                if rows.len()==cap as usize || (!groups.contains(&group) && groups.len()==q.budget().max_series.get() as usize) {more=true;break;}
                groups.insert(group);last=Some(p);rows.push(ObservedSample {sample:s,received_at:Timestamp::new(r.received_at)?});
            }
            q.validate_page(&rows)?;
            let next=if more {Some(self.key.seal(DOMAIN,q.binding()?,&self.instance,expires,&Cursor {boundary,last:last.ok_or(Error::BudgetExceeded)?})?)} else {None};
            Ok(Page {rows,availability:control::availability(q,&fences)?,next})
        }.await;
        tx.read(result).await
    }
}
impl<C: Clock> Reader for ChStore<C> {
    async fn query(
        &self,
        q: &Authorized<Query>,
        after: Option<&Continuation>,
        deadline: Deadline,
    ) -> Result<Page, Error> {
        let _guard = self
            .operation(q.request().selection().scope(), deadline)
            .await?;
        self.bounded(deadline, self.history(q.request(), after, deadline))
            .await
    }
    async fn aggregate(
        &self,
        q: &Authorized<AggregateQuery>,
        after: Option<&Continuation>,
        deadline: Deadline,
    ) -> Result<AggregatePage, Error> {
        let _guard = self
            .operation(q.request().spec().stream().scope(), deadline)
            .await?;
        self.bounded(
            deadline,
            crate::aggregate::read(self, q.request(), after, deadline),
        )
        .await
    }
}
