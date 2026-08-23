use diport::DeliveryStream;
use eventexec::ManagedDeliveryStream;
use tokio_util::sync::CancellationToken;

fn main() {
    let stream: DeliveryStream = Box::pin(futures::stream::empty());
    let _forged = ManagedDeliveryStream::mint(stream, CancellationToken::new());
}
