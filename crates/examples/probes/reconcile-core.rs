use rss_reconcile::*;
struct Business;
impl<C: Claim> Reconciler<C> for Business {
    type State = u8;
    async fn observe<T: Timer>(
        &self,
        _: &C,
        _: &Control<'_, T>,
    ) -> Result<ReconcileDiff<u8>, Error> {
        Ok(ReconcileDiff::between(
            DesiredState::present(1),
            ActualState::present(1),
        ))
    }
    async fn apply<T: Timer>(
        &self,
        _: &C,
        _: ReconcileDiff<u8>,
        _: &Control<'_, T>,
    ) -> Result<(), Error> {
        // reason: already-converged core probe has no external effect provider.
        Ok(())
    }
}
fn main() -> anyhow::Result<()> {
    let _implementation = Business;
    let diff = ReconcileDiff::between(DesiredState::present(1), ActualState::present(0));
    anyhow::ensure!(
        diff.drift() == DriftKind::Changed,
        "core drift classification"
    );
    anyhow::ensure!(
        diff.converge_action() == ConvergeAction::Update,
        "core action classification"
    );
    Ok(())
}
