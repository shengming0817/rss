use std::cell::Cell;
use std::task::Poll;

use super::{Result, Vhosts};

#[tokio::test]
async fn concurrent_same_vhost_initializes_once() -> Result<()> {
    let vhosts = Vhosts::default();
    let calls = Cell::new(0);
    let create = || async {
        calls.set(calls.get() + 1);
        tokio::task::yield_now().await;
        Ok(())
    };
    let (first, second) = tokio::join!(
        vhosts.ensure_created("shared", create),
        vhosts.ensure_created("shared", create),
    );
    first?;
    second?;
    assert_eq!(
        calls.get(),
        1,
        "same-vhost callers must share initialization"
    );
    assert!(vhosts.is_ready("shared")?);
    Ok(())
}

#[tokio::test]
async fn pending_vhost_is_not_ready_and_does_not_block_other_vhosts() -> Result<()> {
    let vhosts = Vhosts::default();
    let mut pending = Box::pin(vhosts.ensure_created("pending", std::future::pending));
    std::future::poll_fn(|cx| {
        assert!(pending.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    assert!(!vhosts.is_ready("pending")?);
    let mut other = Box::pin(vhosts.ensure_created("other", || async { Ok(()) }));
    std::future::poll_fn(|cx| {
        assert!(
            matches!(other.as_mut().poll(cx), Poll::Ready(Ok(()))),
            "another vhost must initialize while the first is pending"
        );
        Poll::Ready(())
    })
    .await;
    assert!(vhosts.is_ready("other")?);
    drop(pending);
    vhosts
        .ensure_created("pending", || async { Ok(()) })
        .await?;
    assert!(vhosts.is_ready("pending")?);
    Ok(())
}

#[tokio::test]
async fn failed_initialization_can_retry_and_success_is_cached() -> Result<()> {
    let vhosts = Vhosts::default();
    let error = vhosts
        .ensure_created("retry", || async { anyhow::bail!("permissions failed") })
        .await;
    assert!(matches!(error, Err(error) if error.to_string() == "permissions failed"));
    assert!(!vhosts.is_ready("retry")?);
    vhosts.ensure_created("retry", || async { Ok(()) }).await?;
    vhosts
        .ensure_created("retry", || async { anyhow::bail!("must not run twice") })
        .await?;
    assert!(vhosts.is_ready("retry")?);
    Ok(())
}
