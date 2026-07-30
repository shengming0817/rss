use consistency::PartitionKey;
use eventexec::event::ReviewedEvent;

fn reopen_topology(event: ReviewedEvent, partition_key: PartitionKey) -> ReviewedEvent {
    event.with_partition_key(partition_key)
}

fn main() {}
