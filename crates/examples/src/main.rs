//! Minimal public consumers; each selected scenario asserts its observable result.

#[cfg(feature = "diagnostic")]
mod diagnostic;
#[cfg(feature = "memory")]
mod messaging;
#[cfg(feature = "protection")]
mod protection;
#[cfg(feature = "redact")]
mod redact;

fn main() -> anyhow::Result<()> {
    #[cfg(feature = "diagnostic")]
    diagnostic::run()?;
    #[cfg(feature = "trace")]
    trace()?;
    #[cfg(feature = "redact")]
    redact::run()?;
    #[cfg(feature = "derive")]
    derive();
    #[cfg(feature = "protection")]
    protection::run()?;
    #[cfg(feature = "core")]
    assert_eq!(
        rss_transactional_messaging::message::MessageId::parse("message-42")?.as_str(),
        "message-42"
    );
    #[cfg(any(feature = "task-local", feature = "lifecycle", feature = "memory"))]
    tokio::runtime::Runtime::new()?.block_on(asynchronous())?;
    Ok(())
}

#[test]
fn selected_examples_run() -> anyhow::Result<()> {
    main()
}

#[cfg(feature = "trace")]
fn trace() -> anyhow::Result<()> {
    use opentelemetry::trace::TracerProvider as _;
    use rss_trace_context::{RestoreOutcome, TraceParent, capture_current, restore_remote_parent};
    use tracing_subscriber::prelude::*;
    assert!(TraceParent::parse("invalid").is_err());
    let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder().build();
    let layer = tracing_opentelemetry::layer().with_tracer(provider.tracer("rss-example"));
    tracing::subscriber::with_default(tracing_subscriber::registry().with(layer), || {
        let parent = TraceParent::parse("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")?;
        let span = tracing::info_span!(parent: None, "consumer");
        assert_eq!(
            restore_remote_parent(&span, &parent, Some("vendor=value")),
            RestoreOutcome::Restored
        );
        let captured = span
            .in_scope(capture_current)
            .ok_or_else(|| anyhow::anyhow!("trace capture absent"))?;
        assert_eq!(
            &captured.traceparent().as_str()[3..35],
            &parent.as_str()[3..35]
        );
        assert_eq!(captured.tracestate(), Some("vendor=value"));
        Ok::<(), anyhow::Error>(())
    })?;
    provider.shutdown()?;
    Ok(())
}

#[cfg(feature = "derive")]
fn derive() {
    use rss_redact::{Redact, RedactScope};
    #[derive(Redact)]
    struct Login {
        #[redact(sensitivity = secret)]
        token: String,
    }
    let login = Login {
        token: "do-not-log".into(),
    };
    assert!(!login.token.is_empty());
    for scope in [RedactScope::ServerLog, RedactScope::Wire] {
        assert!(!login.redact_scoped(scope).contains("do-not-log"));
    }
    assert!(!format!("{login:?}").contains("do-not-log"));
}

#[cfg(any(feature = "task-local", feature = "lifecycle", feature = "memory"))]
async fn asynchronous() -> anyhow::Result<()> {
    #[cfg(feature = "task-local")]
    task_local().await?;
    #[cfg(feature = "lifecycle")]
    lifecycle().await?;
    #[cfg(feature = "memory")]
    messaging::run().await?;
    Ok(())
}

#[cfg(feature = "task-local")]
async fn task_local() -> anyhow::Result<()> {
    use rss_diag_context::{CorrelationId, DiagnosticCtx, correlation, scope};
    assert!(correlation().is_none());
    let mut tasks = Vec::new();
    for id in ["request-a", "request-b"] {
        let context = DiagnosticCtx::new(CorrelationId::parse(id)?);
        tasks.push(tokio::spawn(scope(context, async move {
            tokio::task::yield_now().await;
            assert_eq!(correlation().as_ref().map(CorrelationId::as_str), Some(id));
            assert!(tokio::spawn(async { correlation() }).await?.is_none());
            Ok::<(), anyhow::Error>(())
        })));
    }
    for task in tasks {
        task.await??;
    }
    assert!(correlation().is_none());
    Ok(())
}

#[cfg(feature = "lifecycle")]
async fn lifecycle() -> anyhow::Result<()> {
    use rss_runtime::{ManagedTask, ShutdownStack, TotalDrainBudget};
    use std::{
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        time::Duration,
    };
    let stopped = Arc::new(AtomicBool::new(false));
    let observed = stopped.clone();
    let mut stack = ShutdownStack::try_new(TotalDrainBudget::new(Duration::from_secs(5))?)?;
    let (start, _) = ManagedTask::prepare("example", Duration::from_secs(2));
    let registration = start.into_registration(|token| async move {
        token.cancelled().await;
        observed.store(true, Ordering::SeqCst);
        Ok(())
    });
    let mut startup = stack.startup()?;
    let _status = startup.stage_task_with_token(registration);
    startup.commit().finish();
    assert!(stack.shutdown().join().await?.is_clean());
    assert!(stopped.load(Ordering::SeqCst));
    Ok(())
}
