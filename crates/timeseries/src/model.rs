use crate::{
    Definition, Digest, Error, Id, Interval, Metric, Reading, Scope, Temporality, Timestamp, digest,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// A producer incarnation. Generation is opaque, not a sortable activation revision.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Stream {
    scope: Scope,
    source: Id,
    generation: Id,
}
impl Stream {
    pub const fn new(scope: Scope, source: Id, generation: Id) -> Self {
        Self {
            scope,
            source,
            generation,
        }
    }
    pub const fn scope(&self) -> &Scope {
        &self.scope
    }
    pub const fn source(&self) -> &Id {
        &self.source
    }
    pub const fn generation(&self) -> &Id {
        &self.generation
    }
}

/// A series pins a full immutable definition snapshot. Snapshots are values,
/// not a second registry; adapters may normalize storage using the definition digest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "SeriesDto")]
pub struct Series {
    definition: Definition,
    subject: Id,
    resource: Id,
    dimensions: BTreeMap<Id, Id>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SeriesDto {
    definition: Definition,
    subject: Id,
    resource: Id,
    #[serde(deserialize_with = "unique_dimensions")]
    dimensions: BTreeMap<Id, Id>,
}
fn unique_dimensions<'de, D: serde::Deserializer<'de>>(d: D) -> Result<BTreeMap<Id, Id>, D::Error> {
    struct Visitor;
    impl<'de> serde::de::Visitor<'de> for Visitor {
        type Value = BTreeMap<Id, Id>;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("unique bounded dimensions")
        }
        fn visit_map<A: serde::de::MapAccess<'de>>(
            self,
            mut map: A,
        ) -> Result<Self::Value, A::Error> {
            let mut values = BTreeMap::new();
            while let Some((key, value)) = map.next_entry::<Id, Id>()? {
                if values.len() >= usize::from(crate::definition::MAX_DIMENSIONS)
                    || values.insert(key, value).is_some()
                {
                    return Err(serde::de::Error::custom("invalid dimensions"));
                }
            }
            Ok(values)
        }
    }
    d.deserialize_map(Visitor)
}
impl TryFrom<SeriesDto> for Series {
    type Error = Error;
    fn try_from(v: SeriesDto) -> Result<Self, Error> {
        Self::new(v.definition, v.subject, v.resource, v.dimensions)
    }
}
impl Series {
    pub fn new(
        definition: Definition,
        subject: Id,
        resource: Id,
        dimensions: BTreeMap<Id, Id>,
    ) -> Result<Self, Error> {
        definition.spec().dimensions.validate_values(&dimensions)?;
        Ok(Self {
            definition,
            subject,
            resource,
            dimensions,
        })
    }
    pub const fn definition(&self) -> &Definition {
        &self.definition
    }
    pub const fn subject(&self) -> &Id {
        &self.subject
    }
    pub const fn resource(&self) -> &Id {
        &self.resource
    }
    pub const fn dimensions(&self) -> &BTreeMap<Id, Id> {
        &self.dimensions
    }
    pub fn digest(&self) -> Result<Digest, Error> {
        digest(b"series", self)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "SampleInput")]
pub struct Sample(SampleInput);
/// Untrusted data, validated only by `Sample::new` (including during decode).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SampleInput {
    pub stream: Stream,
    pub series: Series,
    pub id: Id,
    pub sequence: u64,
    pub observed_at: Timestamp,
    pub interval: Option<Interval>,
    pub reading: Reading,
}
impl TryFrom<SampleInput> for Sample {
    type Error = Error;
    fn try_from(v: SampleInput) -> Result<Self, Error> {
        Self::new(v)
    }
}
impl From<Sample> for SampleInput {
    fn from(v: Sample) -> Self {
        v.0
    }
}
impl Sample {
    pub fn new(input: SampleInput) -> Result<Self, Error> {
        // Reserve the largest timestamp as an exclusive query/maintenance bound.
        if input.observed_at.micros() == i64::MAX {
            return Err(Error::NumericRange);
        }
        if input.stream.scope() != &input.series.definition().spec().scope {
            return Err(Error::InvalidInput);
        }
        if let Reading::Valid(value) = &input.reading
            && !input.series.definition().spec().metric.accepts(value)
        {
            return Err(Error::InvalidInput);
        }
        if let Some(i) = input.interval
            && i.end() != input.observed_at
        {
            return Err(Error::InvalidInput);
        }
        if let Metric::Counter { temporality, .. } = input.series.definition().spec().metric {
            let i = input.interval.ok_or(Error::InvalidInput)?;
            if temporality == Temporality::Delta && i.width_micros() == 0 {
                return Err(Error::InvalidInput);
            }
        }
        Ok(Self(input))
    }
    pub const fn input(&self) -> &SampleInput {
        &self.0
    }
    pub fn digest(&self) -> Result<Digest, Error> {
        digest(b"sample", self)
    }
    /// Only samples of the exact same stream/series have a meaningful latest ordering.
    pub fn latest_cmp(&self, other: &Self) -> Result<std::cmp::Ordering, Error> {
        if self.0.stream != other.0.stream || self.0.series != other.0.series {
            return Err(Error::InvalidInput);
        }
        Ok((self.0.observed_at, self.0.sequence, &self.0.id).cmp(&(
            other.0.observed_at,
            other.0.sequence,
            &other.0.id,
        )))
    }
    /// Cross-batch identity comparison. Content includes series, time, sequence and quality.
    pub fn compare(&self, old: &Self) -> Result<IdentityMatch, Error> {
        if self.0.stream != old.0.stream || self.0.id != old.0.id {
            return Ok(IdentityMatch::Distinct);
        }
        if self == old {
            Ok(IdentityMatch::Replay)
        } else {
            Err(Error::Conflict)
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdentityMatch {
    Distinct,
    Replay,
}

/// Fixed ordered batch. Hard protocol ceilings keep serialized input bounded.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "BatchDto")]
pub struct Batch {
    stream: Stream,
    id: Id,
    samples: Vec<Sample>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BatchDto {
    stream: Stream,
    id: Id,
    samples: Vec<Sample>,
}
impl TryFrom<BatchDto> for Batch {
    type Error = Error;
    fn try_from(v: BatchDto) -> Result<Self, Error> {
        Self::new(v.stream, v.id, v.samples)
    }
}
impl Batch {
    pub const MAX_SAMPLES: usize = 4096;
    pub const MAX_BYTES: usize = 4 * 1024 * 1024;
    pub fn new(stream: Stream, id: Id, samples: Vec<Sample>) -> Result<Self, Error> {
        if samples.is_empty() {
            return Err(Error::InvalidInput);
        }
        if samples.len() > Self::MAX_SAMPLES {
            return Err(Error::BudgetExceeded);
        }
        let mut ids = BTreeSet::new();
        for sample in &samples {
            if sample.input().stream != stream {
                return Err(Error::InvalidInput);
            }
            if !ids.insert(&sample.input().id) {
                return Err(Error::Conflict);
            }
        }
        let batch = Self {
            stream,
            id,
            samples,
        };
        #[cfg(feature = "integration")]
        let start = crate::measurement::timer();
        let _bytes = batch.write_to(std::io::sink())?;
        #[cfg(feature = "integration")]
        crate::measurement::record("batch_check", start, _bytes, 0);
        Ok(batch)
    }
    pub const fn stream(&self) -> &Stream {
        &self.stream
    }
    pub const fn id(&self) -> &Id {
        &self.id
    }
    pub fn samples(&self) -> &[Sample] {
        &self.samples
    }
    pub fn digest(&self) -> Result<Digest, Error> {
        digest(b"batch", self)
    }
    pub fn compare(&self, old: &Self) -> Result<IdentityMatch, Error> {
        if self.stream != old.stream || self.id != old.id {
            return Ok(IdentityMatch::Distinct);
        }
        if self == old {
            Ok(IdentityMatch::Replay)
        } else {
            Err(Error::Conflict)
        }
    }
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let mut bytes = Vec::new();
        self.write_to(&mut bytes)?;
        Ok(bytes)
    }
    fn write_to(&self, output: impl std::io::Write) -> Result<usize, Error> {
        let mut writer = BoundedWriter {
            output,
            remaining: Self::MAX_BYTES,
        };
        serde_json::to_writer(&mut writer, self).map_err(|_| Error::BudgetExceeded)?;
        Ok(Self::MAX_BYTES - writer.remaining)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > Self::MAX_BYTES {
            return Err(Error::BudgetExceeded);
        }
        serde_json::from_slice(bytes).map_err(|_| Error::InvalidInput)
    }
}

struct BoundedWriter<W> {
    output: W,
    remaining: usize,
}
impl<W: std::io::Write> std::io::Write for BoundedWriter<W> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > self.remaining {
            return Err(std::io::Error::other("batch budget exceeded"));
        }
        let n = self.output.write(bytes)?;
        self.remaining -= n;
        Ok(n)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.output.flush()
    }
}
