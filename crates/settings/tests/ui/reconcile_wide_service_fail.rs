use bootstrap::ReconcileSubscriberEffect;
use settings::SettingsService;

fn cannot_register_wide_service(service: SettingsService) {
    let _ = ReconcileSubscriberEffect::from_reconciler(service);
}

fn main() {}
