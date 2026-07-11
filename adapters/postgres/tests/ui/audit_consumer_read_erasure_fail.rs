//! INVARIANT: AUDIT-CONSUMER-WRITE-ERASURE-01 { level = "Hard", exec = "verify", source = "trybuild" }

use postgres::AuditConsumerTxEffect;

fn erase_read<T>(handler: T)
where
    T: AuditConsumerTxEffect<Effect = diport::ReadEffect>,
{
    let _ = handler.into_handler();
}

fn main() {}
