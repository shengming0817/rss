use eventexec::ConsumerTxHandler;
use eventexec::consumer_tx::policy::TransactionalOnly;

fn cannot_obtain_raw_publisher<H>(handler: H)
where
    H: ConsumerTxHandler<TransactionalOnly>,
{
    let _publisher = handler.publisher();
}

fn main() {}
