//! PG establishes and rechecks each page's view. No PG session crosses ClickHouse IO.
use crate::{
    Operation, control::{self, Fence}, transaction::{Session, now, sql_error}
};
use rss_request_context::{Clock,Deadline};
use rss_timeseries::*;
use serde::{Serialize,Deserialize,de::DeserializeOwned};
use sqlx::PgConnection;

pub(crate) enum Request<'a> { Raw(&'a Query), Aggregate(&'a AggregateQuery) }

#[derive(Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
struct Version { published:i64, fence:i64, summaries:i64 }
impl Version {
    fn agrees(self, current:Self, aggregate:bool) -> bool {
        self.fence == current.fence && if aggregate { self == current } else { self.published <= current.published }
    }
    async fn load(tx:&mut Session, scope:&Scope) -> Result<Option<Self>,Error> {
        let row: Option<(i64,i64,i64)>=sqlx::query_as("SELECT published,fence_epoch,summary_epoch FROM rss_ts_ch.namespaces WHERE tenant_id=$1::text::uuid AND namespace=$2")
            .bind(scope.tenant().to_string()).bind(scope.namespace().as_str()).fetch_optional(tx.connection()).await.map_err(sql_error)?;
        Ok(row.map(|(published,fence,summaries)|Self {published,fence,summaries}))
    }
}
#[derive(Serialize,Deserialize)]
struct Cursor<P> { version:Version, position:P }

pub(crate) struct View<P> {
    pub published:i64,
    pub fences:Vec<Fence>,
    pub position:Option<P>,
    pub exists:bool,
}
impl<C: Clock> Operation<'_,C> {
    pub(crate) async fn page<P,M,T>(
        &self, request:Request<'_>, after:Option<&Continuation>, deadline:Deadline,
        metadata: impl AsyncFn(&mut PgConnection, &View<P>)->Result<M,Error>,
        read: impl AsyncFn(View<P>, M)->Result<(T,Option<P>),Error>,
    ) -> Result<(T,Option<Continuation>),Error>
    where P:Serialize+DeserializeOwned {
        let (q,binding,domain,prior,aggregate)=match request {
            Request::Raw(q)=>(q,q.binding()?,b"rss.timeseries.clickhouse.history.v2".as_slice(),false,false),
            Request::Aggregate(a)=>(a.query(),a.binding()?,b"rss.timeseries.clickhouse.aggregate.v2".as_slice(),crate::aggregate::needs_prior(a.spec()),true),
        };
        if q.budget().max_points>self.limits.max_points || q.budget().max_series>self.limits.max_series {return Err(Error::BudgetExceeded);}
        let scope=q.selection().scope();
        for _ in 0..2 {
            let mut tx=self.session(scope,deadline,"BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY").await?;
            let snapshot=async {
                let current=Version::load(&mut tx,scope).await?;
                let time=now(tx.connection()).await?;
                let (version,position,expires)=if let Some(token)=after {
                    let (expires,cursor)=self.material.key.open::<Cursor<P>>(domain,token,binding,self.instance,time)?;
                    if !current.is_some_and(|v|cursor.version.agrees(v,aggregate)) {return Err(Error::HistoryExpired);}
                    (cursor.version,Some(cursor.position),expires)
                } else {
                    (current.unwrap_or_default(),None,time.checked_add(self.limits.cursor_micros.get() as i64).ok_or(Error::NumericRange)?)
                };
                let start=if prior {0} else {q.window().start().micros()};
                let fences=control::visible_fences(tx.connection(),q,start,self.limits).await?;
                let view=View {published:version.published, fences,position,exists:current.is_some()};
                let meta=metadata(tx.connection(),&view).await?;
                Ok((view,meta,version,expires))
            }.await;
            let (view,meta,version,expires)=tx.read(snapshot).await?;
            let result=read(view,meta).await;
            let mut tx=self.session(scope,deadline,"BEGIN READ ONLY").await?;
            let current=Version::load(&mut tx,scope).await;
            let current=tx.read(current).await?.unwrap_or_default();
            if version.agrees(current,aggregate) {
                let (page,position)=result?;
                let next=position.map(|position|self.material.key.seal(domain,binding,self.instance,expires,&Cursor {version,position})).transpose()?;
                return Ok((page,next));
            }
            if after.is_some() {return Err(Error::HistoryExpired);}
        }
        Err(Error::Unavailable)
    }
}
