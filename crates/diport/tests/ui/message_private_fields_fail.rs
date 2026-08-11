use diport::{EnvelopeMetadata, Message};

fn main() {
    let mut message = Message::new("message-1", b"payload".to_vec());

    let _ = &message.id;
    let _ = &message.metadata;
    let _ = &message.payload;
    message.metadata = EnvelopeMetadata::empty();
}
