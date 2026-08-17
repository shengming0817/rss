use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use release_package::*;
struct Cancel(AtomicBool);
impl CancellationObserver for Cancel {
    fn is_cancelled(&self) -> bool { self.0.load(Ordering::SeqCst) }
    fn cancelled(&self, _: Deadline) -> CancellationFuture<'_> {
        Box::pin(async move {
            if self.is_cancelled() { CancellationReason::Cancelled } else { std::future::pending().await }
        })
    }
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let tenant = TenantId::parse("8b117a90-752f-4f2a-85f1-00c7c4e1f41c")?;
    let request = RequestId::parse("request.1")?;
    let principal = PrincipalRef::new(PrincipalKind::User, "sensitive-subject")?;
    let now = Instant::now();
    let original_deadline = Deadline::at(now + Duration::from_secs(5));
    let deadline = original_deadline.shortened_to(now + Duration::from_secs(1));
    let cancel = Cancel(AtomicBool::new(true));
    let obligations = ObligationsView::new(Some(RowScope::Tenant), FieldMaskView::new(&["email"]));
    let cancellation = Cancellation::observe(&cancel);
    let view = RequestContextView::new(
        Some(&tenant),
        &request,
        &principal,
        deadline,
        cancellation,
        obligations,
    );
    let deadline_semantics = !deadline.is_expired(now)
        && deadline.is_expired(deadline.instant())
        && deadline.remaining(now) == Some(Duration::from_secs(1))
        && original_deadline.shortened_to(deadline.instant()) == deadline;
    let context_view_read = view.tenant() == Some(&tenant)
        && view.request_id() == &request
        && view.principal() == &principal
        && view.deadline() == deadline
        && view.cancellation().is_cancelled()
        && view.obligations().row_scope() == Some(RowScope::Tenant)
        && view.obligations().field_mask().allows("email");
    println!(r#"{{"package":"rss-request-context","tenantCanonical":{},"requestId":{},"principalRedacted":{},"deadlineShortened":{},"deadlineSemantics":{},"contextViewRead":{},"cancelObserved":{},"obligationsRead":{}}}"#,
        tenant.to_string().starts_with("8b117a90"), request.as_str() == "request.1", !format!("{principal:?}").contains("sensitive-subject"),
        deadline.instant() < original_deadline.instant(), deadline_semantics, context_view_read, cancellation.is_cancelled(),
        obligations.row_scope() == Some(RowScope::Tenant) && obligations.field_mask().allows("email"));
    Ok(())
}
