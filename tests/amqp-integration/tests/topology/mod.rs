//! Test-owned provisioning. No production adapter API creates queues, bindings or policies.
use super::*;
use lapin::options::{QueueBindOptions, QueueDeclareOptions, QueuePurgeOptions};
use lapin::types::{AMQPValue, FieldTable};

async fn connection(url: &str) -> anyhow::Result<lapin::Connection> {
    // This is an explicitly selected test broker, using the same fixture endpoint constraints.
    AmqpSubscriberEndpoint::for_test(url)?;
    Ok(tokio::time::timeout(
        TIMEOUT,
        lapin::DefaultConnectionBuilder::new()?
            .with_uri_str(url.to_owned())
            .connect(),
    )
    .await??)
}

pub(super) async fn provision(url: &str, route: &MessageRoute, purge: bool) -> anyhow::Result<()> {
    let connection = connection(url).await?;
    let result = tokio::time::timeout(TIMEOUT, async {
        let channel = connection.create_channel().await?;
        let dlq = format!("{}.dlq", route.as_str());
        for (queue, source) in [(dlq.as_str(), false), (route.as_str(), true)] {
            let mut arguments = FieldTable::default();
            arguments.insert(
                "x-queue-type".into(),
                AMQPValue::LongString("quorum".into()),
            );
            if source {
                for (key, value) in [
                    ("x-dead-letter-exchange", "amq.topic"),
                    ("x-dead-letter-routing-key", dlq.as_str()),
                    ("x-dead-letter-strategy", "at-least-once"),
                    ("x-overflow", "reject-publish"),
                ] {
                    arguments.insert(key.into(), AMQPValue::LongString(value.into()));
                }
            }
            channel
                .queue_declare(
                    queue.into(),
                    QueueDeclareOptions {
                        durable: true,
                        ..Default::default()
                    },
                    arguments,
                )
                .await?;
            channel
                .queue_bind(
                    queue.into(),
                    "amq.topic".into(),
                    queue.into(),
                    QueueBindOptions::default(),
                    FieldTable::default(),
                )
                .await?;
            if purge {
                channel
                    .queue_purge(queue.into(), QueuePurgeOptions::default())
                    .await?;
            }
        }
        channel
            .close(200, "fixture channel complete".into())
            .await?;
        Ok::<_, lapin::Error>(())
    })
    .await;
    tokio::time::timeout(
        TIMEOUT,
        connection.close(200, "fixture provisioning complete".into()),
    )
    .await??;
    result??;
    Ok(())
}

pub(super) async fn dead_letter_depth(url: &str, route: &MessageRoute) -> anyhow::Result<u32> {
    let connection = connection(url).await?;
    let result = tokio::time::timeout(TIMEOUT, async {
        let channel = connection.create_channel().await?;
        let queue = channel
            .queue_declare(
                format!("{}.dlq", route.as_str()).into(),
                QueueDeclareOptions {
                    passive: true,
                    ..Default::default()
                },
                FieldTable::default(),
            )
            .await?;
        let depth = queue.message_count();
        channel
            .close(200, "fixture observation complete".into())
            .await?;
        Ok::<_, lapin::Error>(depth)
    })
    .await;
    tokio::time::timeout(
        TIMEOUT,
        connection.close(200, "fixture observation complete".into()),
    )
    .await??;
    Ok(result??)
}
