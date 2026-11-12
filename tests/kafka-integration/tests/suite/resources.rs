use super::support::*;
use rdkafka::{
    ClientConfig,
    admin::{AdminClient, AdminOptions, AlterConfig, ResourceSpecifier},
};
use rss_request_context::Clock;
use rss_transactional_messaging::{message::MessageEnvelope, transport::*};
use rss_transactional_messaging_kafka::*;
use std::{future::Future, sync::Arc, time::Duration};

const PAYLOAD_BYTES: usize = 64 * 1024;
const RECORD_BYTES: usize = 128 * 1024;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shared_kafka_resource_budget_and_broker_rejection() -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(110), async {
        let fixture = testkit::shared_kafka_tls().await?;
        let baseline = resident_bytes()?;
        let peak = measure_peak(async {
            steady_load(&fixture).await?;
            saturated_queue(&fixture).await
        }).await?;
        emit(&format!("memory payload_bytes={PAYLOAD_BYTES} record_bytes={RECORD_BYTES} baseline_rss_bytes={baseline} sampled_peak_rss_bytes={peak} teardown_rss_bytes={} sample_interval_ms=25 scope=client_process_rust_and_native", resident_bytes()?))?;
        broker_rejection(&fixture).await
    }).await??;
    Ok(())
}

async fn steady_load(f: &testkit::KafkaTlsFixture) -> anyhow::Result<()> {
    let timeouts = KafkaTimeouts::new(
        Duration::from_secs(15),
        Duration::from_secs(20),
        Duration::from_micros(1001),
        Duration::from_secs(5),
    )?;
    let limits = KafkaLimits::new(64, 32, RECORD_BYTES, 32_000_000, timeouts)?;
    let (publisher, resource) =
        KafkaPublisher::create(config_with_limits(f, limits)?, Duration::from_secs(5)).await?;
    let template = message("load")?;
    let message = Arc::new(MessageEnvelope::new(
        template.id().clone(),
        template.metadata().clone(),
        vec![42; PAYLOAD_BYTES],
    ));
    let timer = Timer::new();
    let start = timer.now();
    let mut workers = tokio::task::JoinSet::new();
    for _ in 0..32 {
        let publisher = publisher.clone();
        let message = message.clone();
        workers.spawn(async move {
            let timer = Timer::new();
            let mut latencies = Vec::new();
            for _ in 0..32 {
                let start = timer.now();
                let outcome = publisher
                    .publish(&message, deadline(Duration::from_secs(5))?)
                    .await;
                anyhow::ensure!(
                    matches!(outcome, PublishOutcome::Confirmed(_)),
                    "load publication was not confirmed"
                );
                latencies.push(timer.now().duration_since(start).as_micros());
            }
            Ok::<_, anyhow::Error>(latencies)
        });
    }
    let mut latencies = Vec::new();
    while let Some(result) = workers.join_next().await {
        latencies.extend(result??);
    }
    let elapsed = timer.now().duration_since(start).as_secs_f64();
    latencies.sort_unstable();
    assert_eq!(latencies.len(), 1024);
    assert_eq!(publisher.pending_for_test(), 0);
    resource.shutdown(Duration::from_secs(5)).await?;
    assert_eq!(f.topic_end_offset().await?, 1024);
    emit(&format!(
        "steady queued=64 in_flight=32 budget_bytes=32000000 concurrency=32 confirmed=1024 refused=0 ambiguous=0 elapsed_s={elapsed:.6} records_per_s={:.3} p50_us={} p95_us={} p99_us={}",
        1024.0 / elapsed,
        latencies[511],
        latencies[972],
        latencies[1013]
    ))
}

async fn saturated_queue(f: &testkit::KafkaTlsFixture) -> anyhow::Result<()> {
    let limits = KafkaLimits::new(
        64,
        1,
        RECORD_BYTES,
        16_000_000,
        KafkaTimeouts::low_latency(Duration::from_secs(10))?,
    )?;
    let (publisher, resource) =
        KafkaPublisher::create(config_with_limits(f, limits)?, Duration::from_secs(5)).await?;
    let template = message("saturated")?;
    let message = Arc::new(MessageEnvelope::new(
        template.id().clone(),
        template.metadata().clone(),
        vec![42; PAYLOAD_BYTES],
    ));
    let (entered, release) = publisher.pause_next_delivery_for_test();
    let clone = publisher.clone();
    let first = message.clone();
    let task = tokio::spawn(async move {
        clone
            .publish(&first, deadline(Duration::from_secs(5))?)
            .await;
        Ok::<_, anyhow::Error>(())
    });
    entered.await?;
    task.abort();
    assert!(task.await.is_err_and(|error| error.is_cancelled()));
    for _ in 0..64 {
        assert!(
            publisher
                .publish(&message, deadline(Duration::from_millis(20))?)
                .await
                .is_ambiguous()
        );
    }
    assert_eq!(publisher.pending_for_test(), 1);
    let outcome = publisher
        .publish(&message, deadline(Duration::from_secs(1))?)
        .await;
    assert!(matches!(outcome, PublishOutcome::DefinitelyNotPublished(_)));
    let failure = outcome
        .failure()
        .ok_or_else(|| anyhow::anyhow!("missing refusal"))?;
    assert_eq!(failure.kind(), PublishFailureKind::Transient);
    assert_eq!(failure.stage(), PublishFailureStage::Admission);
    emit(&format!(
        "saturated queued=64 in_flight=1 budget_bytes=16000000 queued_ambiguous=64 cancelled_pending=1 refused=1 full_queue_rss_bytes={}",
        resident_bytes()?
    ))?;
    let _ = release.send(());
    resource.shutdown(Duration::from_secs(5)).await?;
    assert_eq!(publisher.pending_for_test(), 0);
    Ok(())
}

async fn broker_rejection(f: &testkit::KafkaTlsFixture) -> anyhow::Result<()> {
    // The fixture topic is process-unique. Change its broker limit, not the adapter's local limit.
    let mut native = ClientConfig::new();
    native
        .set("bootstrap.servers", f.brokers())
        .set("broker.address.family", "v4")
        .set("security.protocol", "ssl")
        .set("ssl.ca.pem", f.ca_pem())
        .set("ssl.certificate.pem", f.client_certificate_pem())
        .set("ssl.key.pem", f.client_key_pem());
    let admin: AdminClient<Quiet> = native.create_with_context(Quiet)?;
    let topic =
        AlterConfig::new(ResourceSpecifier::Topic(f.topic())).set("max.message.bytes", "32768");
    let options = AdminOptions::new().request_timeout(Some(Duration::from_secs(5)));
    for result in admin.alter_configs(&[topic], &options).await? {
        result.map_err(|_| anyhow::anyhow!("fixture topic configuration rejected"))?;
    }
    drop(admin);
    let limits = KafkaLimits::new(
        1,
        1,
        RECORD_BYTES,
        1_048_576,
        KafkaTimeouts::low_latency(Duration::from_secs(5))?,
    )?;
    let (publisher, resource) =
        KafkaPublisher::create(config_with_limits(f, limits)?, Duration::from_secs(5)).await?;
    let template = message("broker-oversize")?;
    let message = MessageEnvelope::new(
        template.id().clone(),
        template.metadata().clone(),
        vec![42; PAYLOAD_BYTES],
    );
    let outcome = publisher
        .publish(&message, deadline(Duration::from_secs(8))?)
        .await;
    assert!(
        outcome.is_ambiguous(),
        "native-accepted broker rejection must remain uncertain"
    );
    let failure = outcome
        .failure()
        .ok_or_else(|| anyhow::anyhow!("missing rejection"))?;
    assert_eq!(failure.kind(), PublishFailureKind::Permanent);
    assert_eq!(failure.stage(), PublishFailureStage::Confirm);
    assert_eq!(failure.reason(), PublishFailureReason::InvalidMessage);
    drained(&publisher).await?;
    resource.shutdown(Duration::from_secs(5)).await?;
    assert!(read_records(f, "broker-oversize", 0).await?.is_empty());
    Ok(())
}

async fn measure_peak(
    operation: impl Future<Output = anyhow::Result<()>>,
) -> anyhow::Result<usize> {
    tokio::pin!(operation);
    let mut interval = tokio::time::interval(Duration::from_millis(25));
    let mut peak = resident_bytes()?;
    loop {
        tokio::select! {
            result = &mut operation => { result?; return Ok(peak.max(resident_bytes()?)); }
            _ = interval.tick() => { peak = peak.max(resident_bytes()?); }
        }
    }
}
fn resident_bytes() -> anyhow::Result<usize> {
    #[cfg(target_os = "linux")]
    {
        let status = std::fs::read_to_string("/proc/self/status")?;
        let rss = status
            .lines()
            .find(|line| line.starts_with("VmRSS:"))
            .and_then(|line| line.split_whitespace().nth(1))
            .ok_or_else(|| anyhow::anyhow!("missing process RSS"))?;
        Ok(rss.parse::<usize>()? * 1024)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let output = std::process::Command::new("/bin/ps")
            .args(["-o", "rss=", "-p", &std::process::id().to_string()])
            .output()?;
        anyhow::ensure!(output.status.success(), "process RSS observation failed");
        Ok(std::str::from_utf8(&output.stdout)?
            .trim()
            .parse::<usize>()?
            * 1024)
    }
}
fn emit(line: &str) -> anyhow::Result<()> {
    use std::io::Write;
    eprintln!("{line}");
    if let Ok(directory) = std::env::var("RSS_TEST_METRICS_DIR") {
        // The fixture-metrics directory accepts JSONL only; keep this readable load report beside it.
        let metrics = std::path::Path::new(&directory);
        let output = metrics
            .parent()
            .ok_or_else(|| anyhow::anyhow!("missing metrics parent"))?;
        std::fs::create_dir_all(output)?;
        writeln!(
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(output.join("kafka-resource-budget.txt"))?,
            "{line}"
        )?;
    }
    Ok(())
}
