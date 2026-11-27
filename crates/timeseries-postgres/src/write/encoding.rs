//! Pack typed JSON contiguously and bind binary arrays before checking out a connection.
use super::*;
use hashbrown::{HashMap, hash_map::Entry};
use sqlx::{Arguments, postgres::PgBindIterExt};
use std::hash::RandomState;

struct Payloads {
    raw: Vec<u8>,
    ends: Vec<usize>,
    digests: Vec<[u8; 32]>,
}
impl Payloads {
    fn new(count: usize, bytes: usize) -> Self {
        Self {
            raw: Vec::with_capacity(bytes),
            ends: Vec::with_capacity(count),
            digests: Vec::with_capacity(count),
        }
    }
    fn finish(&mut self, digest: Digest) {
        self.ends.push(self.raw.len());
        self.digests.push(*digest.as_bytes());
    }
    fn slices(&self) -> impl Iterator<Item = &[u8]> {
        self.ends.iter().scan(0, |start, &end| {
            let bytes = &self.raw[*start..end];
            *start = end;
            Some(bytes)
        })
    }
    #[cfg(feature = "integration")]
    fn capacity(&self) -> usize {
        self.raw.capacity()
            + self.ends.capacity() * size_of::<usize>()
            + self.digests.capacity() * 32
    }
}

pub(super) async fn prepare(
    batch: &Batch,
    store: &PgStore<impl Clock>,
    budget: Budget,
    permit: crate::prepare::Permit,
) -> Result<PreparedBatch, Error> {
    #[cfg(feature = "integration")]
    let _encoding = measurement::Encoding::enter();
    let clock = &store.clock;
    let horizon = store.limits.replay_micros.get();
    budget.remaining(clock)?;
    let identity = ReceiptQuery {
        stream: batch.stream().clone(),
        batch_id: batch.id().clone(),
        digest: batch.digest()?,
    };
    let count = batch.samples().len();
    let mut samples = Payloads::new(count, batch.encoded_len());
    let mut series_digests = Vec::with_capacity(count);
    let mut series_index = HashMap::with_hasher(RandomState::new());
    let mut bindings = HashMap::with_hasher(RandomState::new());
    #[cfg(feature = "integration")]
    let buffers = measurement::Buffers::default();
    for (index, sample) in batch.samples().iter().enumerate() {
        checkpoint(index, clock, budget).await?;
        let series = &sample.input().series;
        #[cfg(feature = "integration")]
        let old = (series_index.allocation_size(), bindings.allocation_size());
        let value = match series_index.entry(series) {
            Entry::Occupied(entry) => series_digests[*entry.get()],
            Entry::Vacant(entry) => {
                entry.insert(index);
                *series.digest()?.as_bytes()
            }
        };
        series_digests.push(value);
        let digest = sample.append_canonical(&mut samples.raw)?;
        samples.finish(digest);
        // SQL orders locks and definition errors by key/version. Only the last
        // snapshot per key is bound; sample ordinality remains authoritative.
        let spec = series.definition().spec();
        bindings.insert((&spec.key, spec.version), index);
        #[cfg(feature = "integration")]
        {
            if index == 0 {
                store.phases[0].fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            let new = (series_index.allocation_size(), bindings.allocation_size());
            buffers.index_growth(
                old,
                new,
                samples.capacity() + series_digests.capacity() * 32,
            );
        }
    }
    drop(series_index);
    #[cfg(feature = "integration")]
    rss_timeseries::measurement::Session::detailed()
        .update(|r| r.definition_bindings += bindings.len());
    // Each chosen definition fits in its own canonical sample.
    let max_definition_bytes = bindings
        .values()
        .map(|&i| samples.ends[i] - i.checked_sub(1).map_or(0, |p| samples.ends[p]))
        .sum();
    let mut definitions = Payloads::new(bindings.len(), max_definition_bytes);
    #[cfg(feature = "integration")]
    buffers.set(
        samples.capacity()
            + series_digests.capacity() * 32
            + definitions.capacity()
            + bindings.allocation_size(),
    );
    for (index, sample_index) in bindings.into_values().enumerate() {
        checkpoint(index, clock, budget).await?;
        let definition = batch.samples()[sample_index].input().series.definition();
        let digest = definition.append_canonical(&mut definitions.raw)?;
        definitions.finish(digest);
    }
    budget.remaining(clock)?;
    let stream = &identity.stream;
    let tenant = stream.scope().tenant().to_string();
    let namespace = stream.scope().namespace().as_str();
    let source = stream.source().as_str();
    let generation = stream.generation().as_str();
    let id = identity.batch_id.as_str();
    // 12 argument lengths, five binary array headers, scalar bytes and element lengths.
    let wire = 12 * 4
        + 5 * 20
        + 32
        + 8
        + tenant.len()
        + namespace.len()
        + source.len()
        + generation.len()
        + id.len()
        + 76 * count
        + 40 * definitions.ends.len()
        + samples.raw.len()
        + definitions.raw.len();
    let mut args = PgArguments::default();
    args.reserve(12, wire);
    let horizon = i64::try_from(horizon).map_err(|_| Error::NumericRange)?;
    #[cfg(feature = "integration")]
    let horizon = {
        buffers.set(
            samples.capacity() + definitions.capacity() + series_digests.capacity() * 32 + wire,
        );
        measurement::Observed {
            value: horizon,
            buffers: &buffers,
            scratch: samples.capacity() + definitions.capacity() + series_digests.capacity() * 32,
        }
    };
    // Encode every argument now. A local binding failure must finish before BEGIN.
    (|| -> Result<(), sqlx::error::BoxDynError> {
        args.add(tenant)?;
        args.add(namespace)?;
        args.add(source)?;
        args.add(generation)?;
        args.add(id)?;
        args.add(identity.digest.as_bytes().as_slice())?;
        args.add(samples.slices().bind_iter())?;
        args.add(&samples.digests[..])?;
        args.add(&series_digests[..])?;
        args.add(definitions.slices().bind_iter())?;
        args.add(&definitions.digests[..])?;
        args.add(horizon)
    })()
    .map_err(|_| Error::Invariant)?;
    drop((samples, definitions, series_digests));
    #[cfg(feature = "integration")]
    buffers.keep_arguments();
    const ADMIT: &str = "SELECT * FROM rss_timeseries.admit_batch($1::text::uuid,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)";
    let query = sqlx::query_with(ADMIT, args);
    #[cfg(feature = "integration")]
    store.phases[1].fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    Ok(PreparedBatch {
        identity,
        count,
        query,
        _permit: permit,
        #[cfg(feature = "integration")]
        _buffers: buffers,
    })
}
async fn checkpoint(index: usize, clock: &impl Clock, budget: Budget) -> Result<(), Error> {
    if index > 0 && index.is_multiple_of(32) {
        tokio::task::yield_now().await;
    }
    budget.remaining(clock).map(|_| ())
}

#[cfg(test)]
#[path = "order_measure.rs"]
mod order_measure;
