use bootstrap::ReconcileSubscriberEffect;

fn main() {
    let _ = ReconcileSubscriberEffect::new(|_message, _tenant| async {
        consistency::HandleResult::ack()
    });
}
