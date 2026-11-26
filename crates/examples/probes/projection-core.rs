use rss_projection::*;
#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let scope = SourceScope::new(
        rss_request_context::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479")?,
        "s".repeat(255),
    )?;
    anyhow::ensure!(BatchLimit::new(1024)?.get() == 1024, "projection capacity");
    let position = Position::new(1)?;
    let event = Event::new(scope.clone(), position, "event", vec![1, 2])?;
    anyhow::ensure!(
        event.position() == position && event.payload() == [1, 2],
        "event identity changed"
    );
    anyhow::ensure!(BatchLimit::new(0).is_err(), "unbounded batch accepted");
    let clock = Clock;
    let cancel = tokio_util::sync::CancellationToken::new();
    let control = Control::new(&clock, std::time::Duration::from_secs(60), &cancel);
    let consumer = Consumer { scope: ProjectionScope::new(scope,"consumer","v1")?, event, position: std::sync::Mutex::new(None) };
    anyhow::ensure!(consumer.high_water(consumer.scope.source(), &control).await? == Some(position));
    let small = RunLimit::new(PageBudget::new(1, 1)?, 2)?;
    let stopped = run(&consumer, &consumer, &control, small).await.into_result()?;
    let Stop::PayloadBudget { position: pending, required_bytes } = stopped.stop else {
        anyhow::bail!("expected a blocked page");
    };
    anyhow::ensure!(pending == position && stopped.position.is_none() && required_bytes == 2);
    let larger = RunLimit::new(PageBudget::new(1, required_bytes)?, 2)?;
    let report = run(&consumer,&consumer,&control,larger).await.into_result()?;
    anyhow::ensure!(report.stop == Stop::CaughtUp && report.applied == 1 && consumer.checkpoint(&control).await?.position == Some(position));
    cancel.cancel();
    anyhow::ensure!(consumer.high_water(consumer.scope.source(), &control).await.err().map(|e|e.kind()) == Some(ErrorKind::Cancelled));
    Ok(())
}

struct Clock;
impl Timer for Clock {
    fn now(&self) -> std::time::Duration { std::time::Duration::ZERO }
    async fn sleep_until(&self, _: std::time::Duration) { std::future::pending().await }
}
struct Consumer { scope: ProjectionScope, event: Event, position: std::sync::Mutex<Option<Position>> }
const DEFINITION: DefinitionIdentity = DefinitionIdentity::new([7;32]);
impl Source for Consumer {
    type Item = rss_projection::Event;
    async fn high_water<T: Timer>(&self, _: &SourceScope, control: &Control<'_,T>) -> Result<Option<Position>,Error> {control.check()?; Ok(Some(self.event.position()))}
    async fn read<T: Timer>(&self, _: &SourceScope, after: Option<Position>, budget: PageBudget, control: &Control<'_,T>) -> Result<ReadPage<Event>,Error> {
        control.check()?;
        let size = self.event.payload().len() as u32;
        if after.is_some_and(|cursor| cursor >= self.event.position()) {
            Ok(ReadPage::Events(vec![]))
        } else if size > budget.payload_bytes() {
            Ok(ReadPage::Blocked {position: self.event.position(), required_bytes: size})
        } else {
            Ok(ReadPage::Events(vec![self.event.clone()]))
        }
    }
}
impl Execution for Consumer {
    type Item = rss_projection::Event;
    fn scope(&self) -> &ProjectionScope { &self.scope }
    fn definition_identity(&self) -> &DefinitionIdentity { &DEFINITION }
    async fn checkpoint<T: Timer>(&self, control: &Control<'_,T>) -> Result<Checkpoint,Error> {
        control.check()?;
        let position = *self.position.lock().map_err(|_|Error::new(ErrorKind::Unavailable))?;
        Ok(Checkpoint {position,bound:ReplayBound::Live})
    }
    async fn execute<T: Timer>(&self, expected: Option<Position>, event: &Event, control: &Control<'_,T>) -> Result<ApplyOutcome,Error> {
        control.check()?;
        let mut position = self.position.lock().map_err(|_|Error::new(ErrorKind::Unavailable))?;
        if *position != expected {return Err(ErrorKind::Fenced.into());}
        *position = Some(event.position());
        Ok(ApplyOutcome::Applied)
    }
}
