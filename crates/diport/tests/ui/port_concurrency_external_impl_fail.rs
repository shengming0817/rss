use diport::{AsyncSend, DiPortConcurrency};

struct ForgedPort;

impl DiPortConcurrency for ForgedPort {
    type Bucket = AsyncSend;
}

fn main() {}
