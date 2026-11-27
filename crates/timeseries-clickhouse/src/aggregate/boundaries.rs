//! The control query returns selector-matched fences ordered by (lo,id).
use super::*;

/// Keep original starts even for nested deletes. Prefix ends let an unseeded
/// bucket find the first interval extending past its start.
#[derive(Default)]
struct Ranges(Vec<(Timestamp, Timestamp)>);
impl Ranges {
    fn locate(&self, mut before: impl FnMut(&(Timestamp, Timestamp)) -> bool) -> usize {
        #[cfg(feature = "integration")]
        let start = crate::measurement::cpu_start();
        #[cfg(feature = "integration")]
        let mut checks = 0;
        let n = self.0.partition_point(|entry| {
            #[cfg(feature = "integration")]
            {
                checks += 1;
            }
            before(entry)
        });
        #[cfg(feature = "integration")]
        crate::measurement::record(|m| {
            m.boundary_checks += checks;
            m.match_cpu += crate::measurement::elapsed(start);
        });
        n
    }

    fn push(&mut self, window: Interval) {
        let end = self
            .0
            .last()
            .map_or(window.end(), |&(_, hi)| hi.max(window.end()));
        self.0.push((window.start(), end));
    }
}

#[derive(Default)]
pub(crate) struct Boundaries {
    pub(crate) visible: String,
    deletes: Ranges,
    pruned: Ranges,
}
impl Boundaries {
    pub(crate) fn new(fences: &[Fence]) -> Self {
        #[cfg(feature = "integration")]
        let start = crate::measurement::cpu_start();
        let mut ranges = Self::default();
        for fence in fences {
            match fence.kind.as_str() {
                "delete" if !fence.restored => ranges.deletes.push(fence.window),
                "pruned" => ranges.pruned.push(fence.window),
                _ => continue, // restored deletes remain part of the page snapshot only.
            }
            // The outer raw query pins the exact stream and Series. The control
            // query already matched every interval to this selector.
            ranges.visible.push_str(&format!(
                " AND NOT (observed_at>={} AND observed_at<{})",
                fence.window.start().micros(),
                fence.window.end().micros()
            ));
        }
        #[cfg(feature = "integration")]
        crate::measurement::record(|m| m.build_cpu += crate::measurement::elapsed(start));
        ranges
    }

    pub(crate) fn pruned(&self, lo: i64, hi: i64) -> bool {
        let n = self.pruned.locate(|(start, _)| start.micros() < hi);
        n > 0 && self.pruned.0[n - 1].1.micros() > lo
    }

    pub(crate) fn cuts(&self, builder: &SummaryBuilder, window: Interval) -> Cuts<'_> {
        let ranges = &self.deletes.0;
        let first = match builder.last_observed_at() {
            Some(last) => self.deletes.locate(|(lo, _)| *lo < last),
            None => self.deletes.locate(|(_, end)| *end <= window.start()),
        };
        Cuts {
            pending: &ranges[first..],
        }
    }
}

pub(crate) struct Cuts<'a> {
    pending: &'a [(Timestamp, Timestamp)],
}
impl Cuts<'_> {
    pub(crate) fn apply(
        &mut self,
        builder: &mut SummaryBuilder,
        through: Timestamp,
    ) -> Result<(), Error> {
        #[cfg(feature = "integration")]
        let start = crate::measurement::cpu_start();
        // Only visible samples enter the builder. Once interrupted, another cut
        // before the next observation can only repeat the same Gaps marker.
        let n = self
            .pending
            .iter()
            .take_while(|(lo, _)| *lo <= through)
            .count();
        #[cfg(feature = "integration")]
        let checks = n + usize::from(n < self.pending.len());
        if n > 0 {
            builder.interrupt(self.pending[0].0)?;
            self.pending = &self.pending[n..];
        }
        #[cfg(feature = "integration")]
        crate::measurement::record(|m| {
            m.boundary_checks += checks;
            m.match_cpu += crate::measurement::elapsed(start);
        });
        Ok(())
    }

    pub(crate) fn finish(
        &mut self,
        builder: &mut SummaryBuilder,
        window: Interval,
    ) -> Result<(), Error> {
        self.apply(builder, Timestamp::new(window.end().micros() - 1)?)
    }
}
