use super::*;
use crate::{
    aggregate,
    projection::{self, SummaryRow},
    read::{selection, visible},
};
#[derive(Serialize, Deserialize)]
pub(super) struct Fold {
    at: Timestamp,
    revision: i64,
    builder: Option<SummaryBuilder>,
    last: Option<(i64, u64, String)>,
}
#[derive(Serialize, Deserialize)]
pub(super) struct Publication {
    attempt: String,
    query: String,
    digest: String,
    row: SummaryRow,
    revision: i64,
}
pub(super) async fn step<C: Clock>(
    store: &ChStore<C>,
    c: &mut PgConnection,
    r: &MaintenanceRequest,
    spec: &SummarySpec,
    window: Interval,
    state: &mut State,
    revision: i64,
    boundary: i64,
    deadline: Deadline,
) -> Result<Step, Error> {
    if spec.bucket(window.start())?.start() != window.start()
        || spec
            .bucket(Timestamp::new(window.end().micros() - 1)?)?
            .end()
            != window.end()
    {
        return Err(Error::InvalidInput);
    }
    if let Some(p) = state.publish.take() {
        if p.revision != revision {
            sqlx::query("UPDATE rss_ts_ch.attempts SET allowed=false WHERE id=$1::text::uuid")
                .bind(&p.attempt)
                .execute(&mut *c)
                .await
                .map_err(sql_error)?;
            state.fold = None;
            return Ok(Step::More(0));
        }
        let a = projection::Attempt {
            id: p.attempt.clone(),
            query: p.query.clone(),
            digest: p.digest.clone(),
            revision: p.row.revision,
            target: "summaries",
        };
        store
            .insert(&a, std::slice::from_ref(&p.row), deadline)
            .await?;
        let summary = store
            .summary_value(&p.row.object_id, r.scope(), deadline)
            .await?;
        if bytes(&summary)? != p.row.payload.as_bytes() {
            return Err(Error::Invariant);
        }
        sqlx::query("INSERT INTO rss_ts_ch.summaries(tenant_id,namespace,spec_digest,semantics,spec,lo,hi,object_id) VALUES($1::text::uuid,$2,$3,$4,$5,$6,$7,$8::text::uuid) ON CONFLICT(tenant_id,namespace,spec_digest,lo) DO UPDATE SET object_id=excluded.object_id,hi=excluded.hi,dirty=false")
            .bind(r.scope().tenant().to_string()).bind(r.scope().namespace().as_str()).bind(spec.binding()?.as_bytes().as_slice()).bind(spec.semantics()?.as_bytes().as_slice()).bind(bytes(spec)?).bind(p.row.lo).bind(p.row.hi).bind(&p.row.object_id).execute(&mut *c).await.map_err(sql_error)?;
        sqlx::query("UPDATE rss_ts_ch.attempts SET allowed=false WHERE id=$1::text::uuid")
            .bind(&p.attempt)
            .execute(&mut *c)
            .await
            .map_err(sql_error)?;
        let fold = state.fold.as_mut().ok_or(Error::Invariant)?;
        fold.at = Timestamp::new(p.row.hi)?;
        fold.last = None;
        fold.builder = None;
        return Ok(if fold.at >= window.end() {
            Step::Done(1)
        } else {
            Step::More(1)
        });
    }
    let fences = control::fences(c, r.scope(), store.limits.max_points.get()).await?;
    if fences.iter().any(|f| {
        f.kind == "pruned"
            && control::overlaps(&f.selection, &spec.selection())
            && f.window.start() < window.end()
            && f.window.end() > window.start()
    }) {
        return Err(Error::HistoryExpired);
    }
    if state.fold.as_ref().is_none_or(|f| f.revision != revision) {
        sqlx::query("INSERT INTO rss_ts_ch.ranges(tenant_id,namespace,spec_digest,spec,lo,hi) VALUES($1::text::uuid,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING")
            .bind(r.scope().tenant().to_string()).bind(r.scope().namespace().as_str()).bind(spec.binding()?.as_bytes().as_slice()).bind(bytes(spec)?).bind(window.start().micros()).bind(window.end().micros()).execute(&mut *c).await.map_err(sql_error)?;
        state.fold = Some(Fold {
            at: window.start(),
            revision,
            builder: None,
            last: None,
        });
    }
    let fold = state.fold.as_mut().ok_or(Error::Invariant)?;
    let bucket = spec.bucket(fold.at)?;
    if fold.builder.is_none() {
        fold.builder = Some(
            store
                .builder(spec, bucket, boundary, &fences, deadline)
                .await?,
        );
    }
    let last = fold.last.as_ref().map_or(String::new(), |(time, seq, id)| {
        format!(
            " AND (observed_at,sequence,sample_id)>({time},{seq},{})",
            projection::literal(id)
        )
    });
    let condition = format!(
        "{} AND revision<={boundary} AND observed_at>={} AND observed_at<{}{}{}",
        selection(&spec.selection())?,
        bucket.start().micros(),
        bucket.end().micros(),
        visible(&fences)?,
        last
    );
    let rows = store
        .raw_rows(
            &condition,
            "observed_at,sequence,sample_id",
            r.budget().rows.get(),
            deadline,
        )
        .await?;
    let more = rows.len() > r.budget().rows.get() as usize;
    let mut processed = 0;
    for row in rows.into_iter().take(r.budget().rows.get() as usize) {
        let sample = row.sample()?;
        fold.last = Some((row.observed_at, row.sequence, row.sample_id));
        let builder = fold.builder.as_mut().ok_or(Error::Invariant)?;
        aggregate::mask(builder, &fences, spec, sample.input().observed_at)?;
        builder.push(sample, store.limits.max_points.get() as usize)?;
        processed += 1;
    }
    if !more {
        let mut builder = fold.builder.take().ok_or(Error::Invariant)?;
        aggregate::mask(&mut builder, &fences, spec, bucket.end())?;
        let summary = builder.finish(store.limits.max_points.get() as usize)?;
        let payload = bytes(&summary)?;
        if payload.len() > store.limits.max_bytes.get() as usize {
            return Err(Error::BudgetExceeded);
        }
        use sha2::{Digest, Sha256};
        let digest = projection::hex(&Sha256::digest(&payload));
        let a = projection::permit(c, r.scope(), "summaries", &digest, revision).await?;
        let row = SummaryRow {
            tenant: r.scope().tenant().to_string(),
            namespace: r.scope().namespace().as_str().to_owned(),
            object_id: a.id.clone(),
            lo: bucket.start().micros(),
            hi: bucket.end().micros(),
            revision,
            digest: digest.clone(),
            payload: String::from_utf8(payload).map_err(|_| Error::Invariant)?,
        };
        state.publish = Some(Publication {
            attempt: a.id,
            query: a.query,
            digest,
            row,
            revision,
        });
    }
    Ok(Step::More(processed))
}
