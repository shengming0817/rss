use crate::{
    ChStore, Operation,
    control::{self, Fence},
    cursor::Position,
    projection::{RAW_FIELDS, Raw, hex, literal},
    page::{Request,View},
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
impl<C: Clock> Operation<'_, C> {
    pub(crate) async fn raw_rows(
        &self,
        condition: &str,
        order: &str,
        limit: u32,
        deadline: Deadline,
    ) -> Result<Vec<ObservedSample>, Error> {
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
    ) -> Result<Vec<ObservedSample>, Error> {
        let mut cursor = self
            .ch_query(&self.reader, sql, deadline)?
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
            rows.push(ObservedSample {sample:row.sample()?, received_at:Timestamp::new(row.received_at)?});
        }
        Ok(rows)
    }
    async fn history(
        &self,
        q: &Query,
        after: Option<&Continuation>,
        deadline: Deadline,
    ) -> Result<Page, Error> {
        let (mut page,next)=self.page(Request::Raw(q),after,deadline,async |_,_|Ok(()),
            async |view,()|self.history_page(q,view,deadline).await).await?;
        page.next=next;
        Ok(page)
    }
    async fn history_page(&self,q:&Query,view:View<Position>,deadline:Deadline) -> Result<(Page,Option<Position>),Error> {
        let availability=control::availability(q,&view.fences)?;
        if !view.exists {return Ok((Page {rows:Vec::new(),availability,next:None},None));}
        let latest=q.mode()==QueryMode::Latest;
        let mut condition=format!("{} AND revision<={} AND observed_at>={} AND observed_at<{}{}",selection(q.selection())?,view.published,q.window().start().micros(),q.window().end().micros(),visible(&view.fences)?);
        if let Some(previous)=view.position {condition.push_str(&position(&previous,latest));}
        let points=q.budget().max_points.get();
        let groups=q.budget().max_series.get();
        let mut more_groups=false;
        if !latest && groups<points && matches!(q.selection(),Selection::Resource{..}) {
            let sql=format!("SELECT DISTINCT series,source,generation FROM rss_ts_ch.raw FINAL WHERE {condition} ORDER BY series,source,generation LIMIT {}",u64::from(groups)+1);
            let keys=self.ch_query(&self.reader,&sql,deadline)?.fetch_all::<(String,String,String)>().await.map_err(|_|Error::Unavailable)?;
            if keys.len()>groups as usize {
                let (series,source,generation)=&keys[groups as usize-1];
                condition.push_str(&format!(" AND (series,source,generation)<=({},{},{})",literal(series),literal(source),literal(generation)));
                more_groups=true;
            }
        }
        let limit=if latest {points.min(groups)}else{points};
        let mut rows=if latest {
            let sql=format!("SELECT {RAW_FIELDS} FROM (SELECT {RAW_FIELDS} FROM rss_ts_ch.raw FINAL WHERE {condition} ORDER BY series,source,generation,observed_at DESC,sequence DESC,sample_id DESC LIMIT 1 BY series,source,generation) ORDER BY {ORDER} LIMIT {}",u64::from(limit)+1);
            self.fetch_raw(&sql,limit,deadline).await?
        }else{self.raw_rows(&condition,ORDER,limit,deadline).await?};
        let more=more_groups || rows.len()>limit as usize;
        rows.truncate(limit as usize);
        q.validate_page(&rows)?;
        let next=if more {Some(Position::of(&rows.last().ok_or(Error::Invariant)?.sample)?)}else{None};
        Ok((Page{rows,availability,next:None},next))
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
        operation
            .bounded(deadline, operation.history(q.request(), after, deadline))
            .await
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
        operation
            .bounded(
                deadline,
                crate::aggregate::read(&operation, q.request(), after, deadline),
            )
            .await
    }
}
