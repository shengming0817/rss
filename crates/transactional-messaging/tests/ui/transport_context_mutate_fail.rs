use rss_transactional_messaging::message::TransportContext;

fn main() {
    let mut context = TransportContext::default();
    context.trace = Some("forged".to_owned());
}
