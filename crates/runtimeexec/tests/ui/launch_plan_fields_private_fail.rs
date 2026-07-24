fn ready(_: ()) -> anyhow::Result<()> {
    Ok(())
}

fn main() {
    let _forged: runtimeexec::LaunchPlan<(), (), fn(()) -> anyhow::Result<()>> =
        runtimeexec::LaunchPlan {
            adapter: (),
            probe_receipt: (),
            on_ready: ready,
            trace_exporter: None,
            lifecycle_batches: todo!(),
        };
}
