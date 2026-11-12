use rss_projection::*;
#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let scope = SourceScope::new(
        rss_request_context::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479")?,
        "s".repeat(255),
    )?;
    anyhow::ensure!(BatchLimit::new(1024)?.get() == 1024, "projection capacity");
    let position = Position::new(1)?;
    let event = Event::new(scope.clone(), position, "event", vec![1])?;
    anyhow::ensure!(
        event.position() == position && event.payload() == [1],
        "event identity changed"
    );
    anyhow::ensure!(BatchLimit::new(0).is_err(), "unbounded batch accepted");
    let clock = Clock;
    let cancel = tokio_util::sync::CancellationToken::new();
    let control = Control::new(&clock, std::time::Duration::from_secs(60), &cancel);
    let consumer = Consumer { scope: ProjectionScope::new(scope,"consumer","v1")?, event, position: std::sync::Mutex::new(None) };
    anyhow::ensure!(consumer.high_water(consumer.scope.source(), &control).await? == Some(position));
    let report = run(&consumer,&consumer,&control,RunLimit::new(BatchLimit::new(1)?,1)?).await.into_result()?;
    anyhow::ensure!(report.applied == 1 && consumer.checkpoint(&control).await?.position == Some(position));
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
    async fn high_water<T: Timer>(&self, _: &SourceScope, control: &Control<'_,T>) -> Result<Option<Position>,Error> {control.check()?; Ok(Some(self.event.position()))}
    async fn read<T: Timer>(&self, _: &SourceScope, after: Option<Position>, _: BatchLimit, control: &Control<'_,T>) -> Result<Vec<Event>,Error> {control.check()?; Ok(if after.is_none() {vec![self.event.clone()]} else {vec![]})}
}
impl Execution for Consumer {
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
