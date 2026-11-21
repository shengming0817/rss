//! Raw attempts belong to one namespace-unique revision. Commit revocation
//! before observing server termination; compare the pointer again after draining.
use super::Prepared;
use crate::{Operation, projection::{self, Attempt}, transaction::{flatten,sql_error}};
use rss_request_context::{Clock,Deadline};
use rss_timeseries::{Error, Outcome, Receipt, Scope};
use sqlx::PgConnection;

async fn retire(c: &mut PgConnection, scope: &Scope, revision: i64) -> Result<Option<(String,String)>,Error> {
    sqlx::query_as("UPDATE rss_ts_ch.attempts SET allowed=false
        WHERE tenant_id=$1::text::uuid AND namespace=$2 AND target='raw' AND revision=$3
        RETURNING id::text,query_id::text")
        .bind(scope.tenant().to_string()).bind(scope.namespace().as_str()).bind(revision)
        .fetch_optional(c).await.map_err(sql_error)
}

async fn remove(c: &mut PgConnection, id: &str) -> Result<(),Error> {
    let count = sqlx::query("DELETE FROM rss_ts_ch.attempts WHERE id=$1::text::uuid AND NOT allowed")
        .bind(id).execute(c).await.map_err(sql_error)?.rows_affected();
    if count == 1 { Ok(()) } else { Err(Error::Unavailable) }
}

async fn issue(c: &mut PgConnection, scope: &Scope, p: &Prepared, old: Option<&str>) -> Result<Attempt,Error> {
    if let Some(id) = old { remove(c,id).await?; }
    let digest = projection::hex(p.receipt.identity().digest.as_bytes());
    let attempt = projection::permit(c,scope,"raw",&digest,p.revision).await?;
    let count = sqlx::query("UPDATE rss_ts_ch.batches SET attempt=$4::text::uuid
        WHERE tenant_id=$1::text::uuid AND namespace=$2 AND revision=$3 AND phase='prepared'
          AND attempt IS NOT DISTINCT FROM $5::text::uuid")
        .bind(scope.tenant().to_string()).bind(scope.namespace().as_str()).bind(p.revision)
        .bind(&attempt.id).bind(old).execute(c).await.map_err(sql_error)?.rows_affected();
    if count != 1 { return Err(Error::Unavailable); }
    Ok(attempt)
}

impl<C: Clock> Operation<'_,C> {
    pub(super) async fn raw_attempt(&self,scope:&Scope,p:&Prepared,deadline:Deadline) -> Result<Outcome<Attempt>,Error> {
        let mut tx = self.begin(scope,true,deadline).await?;
        let retired = retire(tx.connection(),scope,p.revision).await?;
        let Some((id,query)) = retired else {
            let issued = issue(tx.connection(),scope,p,None).await;
            return tx.finish(issued,true).await;
        };
        if matches!(tx.finish(Ok(()),true).await?, Outcome::Unknown) {return Ok(Outcome::Unknown);}
        self.drain(&[query],deadline).await?;
        let mut tx = self.begin(scope,true,deadline).await?;
        let issued = issue(tx.connection(),scope,p,Some(&id)).await;
        tx.finish(issued,true).await
    }

    pub(super) async fn confirm(&self,scope:&Scope,p:Prepared,attempt:&Attempt,deadline:Deadline) -> Result<Outcome<Receipt>,Error> {
        let mut tx = self.begin(scope,true,deadline).await?;
        // CAS the exact permit: a superseded writer cannot revoke its successor.
        let revoked = sqlx::query("UPDATE rss_ts_ch.attempts SET allowed=false WHERE id=$1::text::uuid AND allowed")
            .bind(&attempt.id).execute(tx.connection()).await.map_err(sql_error)?.rows_affected();
        if revoked != 1 {return tx.finish(Err(Error::Unavailable),false).await;}
        if matches!(tx.finish(Ok(()),true).await?,Outcome::Unknown) {return Ok(Outcome::Unknown);}
        self.drain(std::slice::from_ref(&attempt.query),deadline).await?;
        let mut tx = self.begin(scope,true,deadline).await?;
        let prior = tx.published;
        let result = async {
            remove(tx.connection(), &attempt.id).await?;
            let count = sqlx::query("UPDATE rss_ts_ch.batches SET phase='verified', projection=NULL, attempt=NULL
                WHERE tenant_id=$1::text::uuid AND namespace=$2 AND revision=$3 AND attempt=$4::text::uuid AND phase='prepared'")
                .bind(scope.tenant().to_string()).bind(scope.namespace().as_str()).bind(p.revision)
                .bind(&attempt.id).execute(tx.connection()).await.map_err(sql_error)?.rows_affected();
            if count != 1 { return Err(Error::Unavailable); }
            if p.revision != prior.checked_add(1).ok_or(Error::NumericRange)? {return Ok(Outcome::Unknown);}
            promote(tx.connection(),scope,prior).await?;
            Ok(Outcome::Accepted(p.receipt))
        }.await;
        tx.finish(result,true).await.map(flatten)
    }
}

async fn promote(c: &mut PgConnection, scope: &Scope, prior:i64) -> Result<(),Error> {
    let tenant=scope.tenant().to_string();
    let ns=scope.namespace().as_str();
    let boundary:i64=sqlx::query_scalar("SELECT coalesce(
        (SELECT min(revision)-1 FROM rss_ts_ch.batches WHERE tenant_id=n.tenant_id AND namespace=n.namespace AND phase='prepared'),
        n.allocated) FROM rss_ts_ch.namespaces n WHERE n.tenant_id=$1::text::uuid AND n.namespace=$2")
        .bind(&tenant).bind(ns).fetch_one(&mut *c).await.map_err(sql_error)?;
    let (count,changed):(i64,bool)=sqlx::query_as("WITH published AS (
        UPDATE rss_ts_ch.batches SET phase='published',payload=NULL WHERE tenant_id=$1::text::uuid AND namespace=$2
          AND revision>$3 AND revision<=$4 AND phase='verified' RETURNING new_samples)
        SELECT count(*),coalesce(bool_or(new_samples>0),false) FROM published")
        .bind(&tenant).bind(ns).bind(prior).bind(boundary).fetch_one(&mut *c).await.map_err(sql_error)?;
    if count == 0 || count != boundary - prior {return Err(Error::Invariant);}
    sqlx::query("UPDATE rss_ts_ch.summaries SET dirty=true,invalidate_revision=NULL
        WHERE tenant_id=$1::text::uuid AND namespace=$2 AND invalidate_revision<=$3")
        .bind(&tenant).bind(ns).bind(boundary).execute(&mut *c).await.map_err(sql_error)?;
    sqlx::query("UPDATE rss_ts_ch.namespaces SET published=$3,revision=revision+$4
        WHERE tenant_id=$1::text::uuid AND namespace=$2")
        .bind(tenant).bind(ns).bind(boundary).bind(i64::from(changed)).execute(c).await.map_err(sql_error)?;
    Ok(())
}
