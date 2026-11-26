//! Pack typed JSON contiguously and bind binary arrays before checking out a connection.
use super::*;
use sqlx::{Arguments, postgres::PgBindIterExt};

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

// Keep the last sample for each key/version, exactly as the SQL admission contract requires.
struct Binding<'a> {
    definition: &'a Definition,
    index: usize,
    sample_bytes: usize,
}
impl Binding<'_> {
    fn key(&self) -> (&Id, u64) {
        let spec = self.definition.spec();
        (&spec.key, spec.version)
    }
}

pub(super) async fn prepare(
    batch: &Batch,
    store: &PgStore<impl Clock>,
    budget: Budget,
    permit: crate::prepare::Permit,
) -> Result<PreparedBatch, Error> {
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
    let mut bindings: Vec<Binding<'_>> = Vec::with_capacity(count);
    let mut previous: Option<(&Series, Digest)> = None;
    #[cfg(feature = "integration")]
    let buffers = measurement::Buffers::default();
    for (index, sample) in batch.samples().iter().enumerate() {
        checkpoint(index, clock, budget).await?;
        let series = &sample.input().series;
        let digest = series_digest(series, &mut previous)?;
        series_digests.push(*digest.as_bytes());
        let offset = samples.raw.len();
        let digest = sample.append_canonical(&mut samples.raw)?;
        samples.finish(digest);
        let binding = Binding {
            definition: series.definition(),
            index,
            sample_bytes: samples.raw.len() - offset,
        };
        if let Some(last) = bindings.last_mut()
            && last.key() == binding.key()
        {
            *last = binding;
        } else {
            bindings.push(binding);
        }
        #[cfg(feature = "integration")]
        if index == 0 {
            store.phases[0].fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            buffers.set(samples.capacity() + series_digests.capacity() * 32);
        }
    }
    bindings.sort_unstable_by(|a, b| a.key().cmp(&b.key()).then_with(|| b.index.cmp(&a.index)));
    bindings.dedup_by(|a, b| a.key() == b.key());
    // Every selected definition occurs inside a different canonical sample. This bound
    // avoids a sizing pass and keeps the definition arena small for a repeated series.
    let max_definition_bytes = bindings.iter().map(|b| b.sample_bytes).sum();
    let mut definitions = Payloads::new(bindings.len(), max_definition_bytes);
    #[cfg(feature = "integration")]
    buffers.set(samples.capacity() + series_digests.capacity() * 32 + definitions.capacity());
    for (index, binding) in bindings.into_iter().enumerate() {
        checkpoint(index, clock, budget).await?;
        let digest = binding.definition.append_canonical(&mut definitions.raw)?;
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
    buffers.set(wire);
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
fn series_digest<'a>(
    series: &'a Series,
    previous: &mut Option<(&'a Series, Digest)>,
) -> Result<Digest, Error> {
    if let Some((last, digest)) = *previous
        && last == series
    {
        return Ok(digest);
    }
    let digest = series.digest()?;
    *previous = Some((series, digest));
    Ok(digest)
}

async fn checkpoint(index: usize, clock: &impl Clock, budget: Budget) -> Result<(), Error> {
    if index > 0 && index.is_multiple_of(32) {
        tokio::task::yield_now().await;
    }
    budget.remaining(clock).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reuse_checks_the_full_definition_snapshot() -> anyhow::Result<()> {
        let spec: DefinitionSpec = serde_json::from_str(
            r#"{"scope":{"tenant":"11111111-1111-4111-8111-111111111111","namespace":"metrics"},"key":"pressure","version":1,"unit":"Pa","metric":{"kind":"gauge","number":"u64"},"dimensions":{"allowed":[],"required":[],"maxCount":0,"maxValueBytes":1,"maxTotalBytes":1}}"#,
        )?;
        let build = |spec| {
            Series::new(
                Definition::new(spec)?,
                Id::new("host")?,
                Id::new("disk")?,
                Default::default(),
            )
        };
        let first = build(spec.clone())?;
        let mut second = spec;
        second.unit = Id::new("kPa")?;
        let second = build(second)?;
        let mut cache = None;
        assert_eq!(series_digest(&first, &mut cache)?, first.digest()?);
        assert_eq!(series_digest(&second, &mut cache)?, second.digest()?);
        assert_ne!(first.digest()?, second.digest()?);
        Ok(())
    }
}
