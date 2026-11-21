//! Set-based admission inside the locked namespace transaction.
//! ref: transact-rs/sqlx FAQ.md@v0.9.0 (PostgreSQL typed UNNEST).
use crate::{control::Fence, definition, projection::Raw, transaction::sql_error};
use rss_timeseries::*;
use serde::Serialize;
use sqlx::PgConnection;
use std::collections::{BTreeMap, BTreeSet, HashMap};

#[derive(Serialize)]
struct Frontier<'a> {
    series: &'a Series,
    at: i64,
}

pub(super) async fn admit(
    c: &mut PgConnection, batch: &Batch, fences: &[Fence], received: i64, revision: i64, max: u32,
) -> Result<Vec<Raw>, Error> {
    let stream = batch.stream();
    let scope = stream.scope();
    let ids: Vec<_> = batch.samples().iter().map(|s| s.input().id.as_str()).collect();
    let existing: HashMap<String, Vec<u8>> = sqlx::query_as(
        "SELECT sample_id,digest FROM rss_ts_ch.identities
         WHERE tenant_id=$1::text::uuid AND namespace=$2 AND source=$3 AND generation=$4 AND sample_id=ANY($5)"
    ).bind(scope.tenant().to_string()).bind(scope.namespace().as_str())
     .bind(stream.source().as_str()).bind(stream.generation().as_str()).bind(&ids)
     .fetch_all(&mut *c).await.map_err(sql_error)?.into_iter().collect();
    let wanted: BTreeSet<_> = batch.samples().iter().filter(|s| !existing.contains_key(s.input().id.as_str()))
        .map(|s| { let d = s.input().series.definition().spec(); (d.key.as_str(), d.version) }).collect();
    let definitions = definitions(c, scope, &wanted).await?;
    let mut rows = Vec::new();
    let mut new_ids = Vec::new();
    let mut digests = Vec::new();
    let mut frontiers = BTreeMap::new();
    for sample in batch.samples() {
        let input = sample.input();
        let digest = sample.digest()?;
        if let Some(old) = existing.get(input.id.as_str()) {
            if old != digest.as_bytes() { return Err(Error::Conflict); }
            continue;
        }
        if fences.iter().any(|f| f.matches(sample)) { return Err(Error::HistoryExpired); }
        let def = input.series.definition();
        let stored = definitions.get(&(def.spec().key.clone(), def.spec().version)).ok_or(Error::InvalidInput)?;
        if &stored.definition != def { return Err(Error::Conflict); }
        if stored.state == DefinitionState::Retired { return Err(Error::Retired); }
        let row = Raw::new(sample, received, revision)?;
        let frontier = frontiers.entry(row.series.clone())
            .or_insert(Frontier { series: &input.series, at: row.observed_at });
        frontier.at = frontier.at.min(row.observed_at);
        new_ids.push(input.id.as_str());
        digests.push(digest.as_bytes().to_vec());
        rows.push(row);
    }
    if rows.is_empty() { return Ok(rows); } // reason: replay owns no new identities or summaries.
    let frontiers: Vec<_> = frontiers.into_values().collect();
    let valid: bool = sqlx::query_scalar(include_str!("reserve_summaries.sql"))
        .bind(scope.tenant().to_string()).bind(scope.namespace().as_str())
        .bind(serde_json::to_string(stream).map_err(|_| Error::Invariant)?)
        .bind(serde_json::to_string(&frontiers).map_err(|_| Error::Invariant)?)
        .bind(i64::from(max)).bind(revision).fetch_one(&mut *c).await.map_err(sql_error)?;
    if !valid { return Err(Error::BudgetExceeded); }
    let inserted = sqlx::query("INSERT INTO rss_ts_ch.identities(tenant_id,namespace,source,generation,sample_id,digest,received_at)
         SELECT $1::text::uuid,$2,$3,$4,u.id,u.digest,$7 FROM unnest($5::text[],$6::bytea[]) u(id,digest)")
        .bind(scope.tenant().to_string()).bind(scope.namespace().as_str()).bind(stream.source().as_str())
        .bind(stream.generation().as_str()).bind(&new_ids).bind(&digests).bind(received)
        .execute(c).await.map_err(sql_error)?.rows_affected();
    if inserted != rows.len() as u64 { return Err(Error::Invariant); }
    Ok(rows)
}

async fn definitions(c: &mut PgConnection, scope: &Scope, wanted: &BTreeSet<(&str,u64)>)
    -> Result<BTreeMap<(Id, u64), DefinitionRecord>, Error> {
    if wanted.is_empty() { return Ok(BTreeMap::new()); } // reason: all samples already own identities.
    let (keys, versions): (Vec<_>, Vec<_>) = wanted.iter().map(|(k,v)| (*k,v.to_string())).unzip();
    let records = sqlx::query("SELECT d.raw,d.digest,d.retired FROM rss_ts_ch.definitions d
         JOIN unnest($3::text[], $4::text[]) u(key,version) ON d.key=u.key AND d.version=u.version::numeric
         WHERE tenant_id=$1::text::uuid AND namespace=$2")
        .bind(scope.tenant().to_string()).bind(scope.namespace().as_str()).bind(keys).bind(versions)
        .fetch_all(c).await.map_err(sql_error)?;
    records.into_iter().map(|row| {
        let record = definition::record(row)?;
        let spec = record.definition.spec();
        Ok(((spec.key.clone(),spec.version),record))
    }).collect()
}
