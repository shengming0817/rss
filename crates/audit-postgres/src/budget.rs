//! Canonical bytes held by admitted Audit operations within one host-selected domain.
//! ref: tokio-rs/tokio tokio/src/sync/semaphore.rs@tokio-1.53.3
use crate::{Control, Error};
use rss_audit_core::PreparedAuditV1;
use rss_request_context::{ExecutionTimer, TenantId};
use rss_transactional_messaging::transaction::LocalTxDeadlineStage as Stage;
use std::sync::Arc;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Clone to share finite per-batch and aggregate preparation capacity across writers.
#[derive(Clone)]
pub struct WriteBudget {
    rows: usize,
    bytes: u32,
    capacity: Arc<Semaphore>,
    total: usize,
}
impl WriteBudget {
    /// Whether one batch can fit the configured per-batch and aggregate limits.
    /// This does not reserve bytes or observe temporary contention.
    pub fn supports_batch(&self, rows: usize, canonical_bytes: usize) -> bool {
        rows <= self.rows && canonical_bytes <= self.bytes as usize
    }

    /// All limits are positive; a legal batch must fit in the shared capacity.
    pub fn new(rows: usize, bytes: u32, in_flight_bytes: u32) -> Result<Self, Error> {
        if rows == 0
            || bytes == 0
            || bytes > in_flight_bytes
            || in_flight_bytes as usize > Semaphore::MAX_PERMITS
        {
            return Err(Error::WriteLimit);
        }
        check_bind_limit(rows, bytes as usize)?;
        Ok(Self {
            total: in_flight_bytes as usize,
            rows,
            bytes,
            capacity: Arc::new(Semaphore::new(in_flight_bytes as usize)),
        })
    }
    fn charge(&self, rows: usize, bytes: usize) -> Result<u32, Error> {
        if rows > self.rows || bytes > self.bytes as usize || (rows == 0) != (bytes == 0) {
            return Err(Error::WriteLimit);
        }
        Ok(bytes as u32)
    }
    /// Wait before materializing a batch or checking out a connection. The request contains
    /// only dimensions. Cancellation, expiry, and dropping the future relinquish its place.
    pub async fn reserve<T: ExecutionTimer>(
        &self,
        rows: usize,
        bytes: usize,
        control: &Control<'_, T>,
    ) -> Result<WriteReservation, Error> {
        control.check(Stage::Operation)?;
        let charge = self.charge(rows, bytes)?;
        let permit = if charge == 0 {
            None
        } else {
            Some(
                control
                    .run(Stage::Operation, async {
                        self.capacity
                            .clone()
                            .acquire_many_owned(charge)
                            .await
                            .map_err(|_| Error::StorageContract)
                    })
                    .await?,
            )
        };
        control.check(Stage::Operation)?;
        Ok(WriteReservation {
            budget: self.clone(),
            rows,
            bytes,
            permit,
        })
    }
    pub(crate) fn try_reserve(&self, rows: usize, bytes: usize) -> Result<WriteReservation, Error> {
        let charge = self.charge(rows, bytes)?;
        let permit = if charge == 0 {
            None
        } else {
            Some(
                self.capacity
                    .clone()
                    .try_acquire_many_owned(charge)
                    .map_err(|_| Error::WriteBusy)?,
            )
        };
        Ok(WriteReservation {
            budget: self.clone(),
            rows,
            bytes,
            permit,
        })
    }
    /// Admit already prepared input immediately, including inside a borrowed transaction.
    pub fn try_admit<'a>(
        &self,
        records: &'a [PreparedAuditV1],
    ) -> Result<AdmittedBatch<'a>, Error> {
        self.try_with_held(records, 0)
    }

    pub(crate) fn try_with_held<'a>(
        &self,
        records: &'a [PreparedAuditV1],
        held: usize,
    ) -> Result<AdmittedBatch<'a>, Error> {
        let (bytes, tenant) = dimensions(records, self.rows, self.bytes as usize)?;
        add_length(held, bytes, self.total)?;
        let reservation = self.try_reserve(records.len(), bytes)?;
        Ok(AdmittedBatch {
            records,
            tenant,
            reservation,
        })
    }
    pub(crate) fn check_domain(&self, batch: &AdmittedBatch<'_>) -> Result<(), Error> {
        if Arc::ptr_eq(&self.capacity, &batch.reservation.budget.capacity) {
            Ok(())
        } else {
            Err(Error::WriteLimit)
        }
    }
}

/// A single-use reservation for an upper bound. Drop releases its capacity.
pub struct WriteReservation {
    budget: WriteBudget,
    rows: usize,
    bytes: usize,
    permit: Option<OwnedSemaphorePermit>,
}
impl WriteReservation {
    /// Bind to the actual original input, including duplicates; reject an underestimate.
    pub fn bind(mut self, records: &[PreparedAuditV1]) -> Result<AdmittedBatch<'_>, Error> {
        let (actual, tenant) = dimensions(records, self.rows, self.bytes)?;
        if let Some(permit) = &mut self.permit {
            drop(permit.split(self.bytes - actual));
        }
        Ok(AdmittedBatch {
            reservation: self,
            tenant,
            records,
        })
    }
}

/// An exact input slice tied to one live capacity grant. Passed by value to append.
pub struct AdmittedBatch<'a> {
    pub(crate) records: &'a [PreparedAuditV1],
    pub(crate) tenant: Option<TenantId>,
    reservation: WriteReservation,
}
impl AdmittedBatch<'_> {
    pub(crate) fn take_permit(&mut self) -> Option<OwnedSemaphorePermit> {
        self.reservation.permit.take()
    }
}

// Bound the largest Bind we can produce at the configured maxima. The six
// arguments are tenant text and five one-dimensional arrays. 256 covers names,
// formats, length words, the UUID and five 20-byte array headers. Each row adds
// five element lengths, two int8 values and both text IDs outside its canonical.
// ref: postgres src/include/libpq/libpq.h (PQ_LARGE_MESSAGE_LIMIT = MaxAllocSize - 1)
// ref: sqlx-postgres/src/message/bind.rs and types/array.rs@v0.9.0
const MAX_BIND: usize = (1 << 30) - 2;
pub(crate) const FIXED_BIND: usize = 256;
pub(crate) const ROW_FRAMING: usize = 5 * 4 + 2 * 8;
const ROW_BIND: usize =
    ROW_FRAMING + rss_audit_core::SourceId::MAX_BYTES + rss_audit_core::EventId::MAX_BYTES;
fn check_bind_limit(rows: usize, canonical: usize) -> Result<(), Error> {
    let elements = rows.checked_mul(ROW_BIND).ok_or(Error::WriteLimit)?;
    let envelope = add_length(FIXED_BIND, elements, MAX_BIND)?;
    add_length(envelope, canonical, MAX_BIND)?;
    Ok(())
}

fn add_length(total: usize, next: usize, max: usize) -> Result<usize, Error> {
    total
        .checked_add(next)
        .filter(|value| *value <= max)
        .ok_or(Error::WriteLimit)
}
fn dimensions(
    records: &[PreparedAuditV1],
    max_rows: usize,
    max_bytes: usize,
) -> Result<(usize, Option<TenantId>), Error> {
    if records.len() > max_rows {
        return Err(Error::WriteLimit);
    }
    let tenant = records.first().map(|r| r.identity().tenant());
    let mut bytes = 0;
    for record in records {
        if Some(record.identity().tenant()) != tenant {
            return Err(Error::ScopeMismatch);
        }
        bytes = add_length(bytes, record.canonical_bytes().len(), max_bytes)?;
    }
    Ok((bytes, tenant))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bind_framing_limits_a_batch_before_it_can_reserve_capacity() -> anyhow::Result<()> {
        let rows = 1_100_000;
        let bytes = u32::try_from(MAX_BIND - FIXED_BIND - rows * ROW_BIND)?;
        let total = u32::try_from((Semaphore::MAX_PERMITS).min(u32::MAX as usize))?;
        WriteBudget::new(rows, bytes, total)?;
        assert!(matches!(
            WriteBudget::new(rows, bytes + 1, total),
            Err(Error::WriteLimit)
        ));
        assert!(matches!(
            check_bind_limit(usize::MAX, 1),
            Err(Error::WriteLimit)
        ));
        Ok(())
    }
    #[test]
    fn rejects_overflow_and_individually_impossible_requests() -> anyhow::Result<()> {
        let budget = WriteBudget::new(8, 64, 128)?;
        assert!(matches!(
            add_length(usize::MAX, 1, usize::MAX),
            Err(Error::WriteLimit)
        ));
        assert!(matches!(budget.try_reserve(9, 1), Err(Error::WriteLimit)));
        assert!(matches!(budget.try_reserve(8, 65), Err(Error::WriteLimit)));
        let first = budget.try_reserve(8, 64)?;
        let second = budget.clone().try_reserve(8, 64)?;
        assert!(matches!(budget.try_reserve(1, 1), Err(Error::WriteBusy)));
        let _empty = budget.try_admit(&[])?;
        drop((first, second));
        budget.try_reserve(8, 64)?;
        Ok(())
    }
}
