use std::{future::Future, pin::Pin, sync::Arc};

use bootstrap::{ReconcileSubscriber, ReconcileSubscriberEffect};
use settings::SettingsService;

struct WideReconciler {
    service: Arc<SettingsService>,
}

impl ReconcileSubscriber for WideReconciler {
    fn reconcile(
        &self,
        _message: diport::Message,
        _tenant: rss_request_context::TenantId,
    ) -> Pin<Box<dyn Future<Output = consistency::HandleResult> + Send + 'static>> {
        let service = Arc::clone(&self.service);
        Box::pin(async move {
            drop(service);
            consistency::HandleResult::ack()
        })
    }
}

fn bind(service: Arc<SettingsService>) {
    let _ = ReconcileSubscriberEffect::from_reconciler(WideReconciler { service });
}

fn main() {}
