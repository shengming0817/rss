use postgres::tx_boundary_proof::{IdentityTx, ServingWriteLane, require_identity_operation};

static mut ESCAPED: Option<IdentityTx<'static, 'static, ServingWriteLane>> = None;

fn main() {
    require_identity_operation(|tx| Box::pin(async move {
        unsafe { ESCAPED = Some(tx); }
        Ok(())
    }));
}
