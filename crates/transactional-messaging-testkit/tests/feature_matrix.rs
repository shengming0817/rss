use std::collections::BTreeSet;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);
type RegistryPackages = BTreeSet<(String, String, String)>;

const BASE_API: &str = r#"
use rss_transactional_messaging::transaction::{
    FailureClass, LocalTxAttempt, LocalTxDeadlineStage, LocalTxFinalStatus, TxRetryClass,
    TxRetryFinalStatus,
};
use rss_transactional_messaging_testkit::localtx::LocalTxDriver;
use rss_transactional_messaging_testkit::memory::FakeClock;

fn base_api<D: LocalTxDriver>(_: &D, _: FakeClock) {
    let _: LocalTxAttempt<(), FailureClass> = LocalTxAttempt::committed(());
    let _: LocalTxDeadlineStage = LocalTxDeadlineStage::Commit;
    let _: LocalTxFinalStatus = LocalTxFinalStatus::CommitUnknown;
    let _: TxRetryClass = TxRetryClass::Transient;
    let _: TxRetryFinalStatus = TxRetryFinalStatus::NotRetryable(TxRetryClass::Permanent);
}
"#;

const CORE_PRODUCER_API: &str = r#"
fn core_producer_api<S: rss_transactional_messaging::outbox::OutboxStore<Vec<u8>>>(_: &S) {}
"#;

const TESTKIT_PRODUCER_API: &str = r#"
fn testkit_producer_api<D: rss_transactional_messaging_testkit::outbox::OutboxDriver>(_: &D) {}
"#;

const MEMORY_PRODUCER_API: &str = r#"
use rss_transactional_messaging_testkit::memory::{MemoryOutboxStore, MemoryPublisher};

fn memory_producer_api(
    _: Option<MemoryOutboxStore<Vec<u8>>>,
    _: Option<MemoryPublisher<Vec<u8>>>,
) {}
"#;

const CORE_CONSUMER_TRANSACTION_API: &str = r#"
fn core_consumer_transaction_api<T: rss_transactional_messaging::transaction::ConsumerTx<Vec<u8>>>(_: &T) {}
"#;

const CORE_CONSUMER_INBOX_API: &str = r#"
fn core_consumer_inbox_api<I: rss_transactional_messaging::inbox::InboxStore>(_: &I) {}
"#;

const TESTKIT_CONSUMER_API: &str = r#"
fn testkit_consumer_api<C: rss_transactional_messaging_testkit::consumer::ConsumerTxDriver>(_: &C) {}
"#;

const TESTKIT_INBOX_API: &str = r#"
fn testkit_inbox_api<I: rss_transactional_messaging_testkit::inbox::InboxDriver>(_: &I) {}
"#;

const MEMORY_CONSUMER_API: &str = r#"
use rss_transactional_messaging_testkit::memory::{MemoryInboxStore, RecordingSettlement};

fn memory_consumer_api(_: Option<MemoryInboxStore>, _: Option<RecordingSettlement>) {}
"#;

struct TempWorkspace(PathBuf);

impl TempWorkspace {
    fn new() -> Result<Self, Box<dyn Error>> {
        for _ in 0..100 {
            let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "rss-messaging-feature-matrix-{}-{sequence}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error.into()),
            }
        }
        Err("could not allocate a unique feature-matrix workspace".into())
    }
}

impl Drop for TempWorkspace {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct Profile<'a> {
    name: &'a str,
    features: &'a [&'a str],
    core_features: &'a [&'a str],
    positive_api: &'a [&'a str],
    negative_api: &'a [&'a str],
}

#[test]
fn supported_feature_matrix_has_closed_graph_and_api() -> Result<(), Box<dyn Error>> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir
        .parent()
        .and_then(Path::parent)
        .ok_or("testkit must remain under <workspace>/crates")?;
    let core = workspace_root.join("crates/transactional-messaging");
    let testkit = workspace_root.join("crates/transactional-messaging-testkit");
    let workspace_lock = workspace_root.join("Cargo.lock");
    let temp = TempWorkspace::new()?;
    let committed_metadata = cargo(
        workspace_root,
        &temp.0,
        [
            "metadata",
            "--locked",
            "--offline",
            "--all-features",
            "--format-version",
            "1",
        ],
    )?;
    ensure_success("committed workspace", "metadata", &committed_metadata)?;
    let committed_registry = registry_packages(&committed_metadata.stdout)?;

    let profiles = [
        Profile {
            name: "none",
            features: &[],
            core_features: &[],
            positive_api: &[BASE_API],
            negative_api: &[
                CORE_PRODUCER_API,
                TESTKIT_PRODUCER_API,
                MEMORY_PRODUCER_API,
                CORE_CONSUMER_TRANSACTION_API,
                CORE_CONSUMER_INBOX_API,
                TESTKIT_CONSUMER_API,
                TESTKIT_INBOX_API,
                MEMORY_CONSUMER_API,
            ],
        },
        Profile {
            name: "producer",
            features: &["producer"],
            core_features: &["producer"],
            positive_api: &[
                BASE_API,
                CORE_PRODUCER_API,
                TESTKIT_PRODUCER_API,
                MEMORY_PRODUCER_API,
            ],
            negative_api: &[
                CORE_CONSUMER_TRANSACTION_API,
                CORE_CONSUMER_INBOX_API,
                TESTKIT_CONSUMER_API,
                TESTKIT_INBOX_API,
                MEMORY_CONSUMER_API,
            ],
        },
        Profile {
            name: "consumer",
            features: &["consumer"],
            core_features: &["consumer"],
            positive_api: &[
                BASE_API,
                CORE_CONSUMER_TRANSACTION_API,
                CORE_CONSUMER_INBOX_API,
                TESTKIT_CONSUMER_API,
                TESTKIT_INBOX_API,
                MEMORY_CONSUMER_API,
            ],
            negative_api: &[CORE_PRODUCER_API, TESTKIT_PRODUCER_API, MEMORY_PRODUCER_API],
        },
        Profile {
            name: "both",
            features: &["consumer", "producer"],
            core_features: &["consumer", "producer"],
            positive_api: &[
                BASE_API,
                CORE_PRODUCER_API,
                TESTKIT_PRODUCER_API,
                MEMORY_PRODUCER_API,
                CORE_CONSUMER_TRANSACTION_API,
                CORE_CONSUMER_INBOX_API,
                TESTKIT_CONSUMER_API,
                TESTKIT_INBOX_API,
                MEMORY_CONSUMER_API,
            ],
            negative_api: &[],
        },
    ];

    for profile in profiles {
        verify_profile(
            &temp.0,
            &core,
            &testkit,
            &workspace_lock,
            &committed_registry,
            &profile,
        )?;
    }
    Ok(())
}

fn verify_profile(
    temp_root: &Path,
    core: &Path,
    testkit: &Path,
    workspace_lock: &Path,
    committed_registry: &RegistryPackages,
    profile: &Profile<'_>,
) -> Result<(), Box<dyn Error>> {
    let root = temp_root.join(profile.name);
    let source = root.join("src/main.rs");
    fs::create_dir_all(
        source
            .parent()
            .ok_or("generated source must have a parent")?,
    )?;
    fs::write(
        root.join("Cargo.toml"),
        manifest(core, testkit, profile.features),
    )?;
    let generated_lock = root.join("Cargo.lock");
    fs::copy(workspace_lock, &generated_lock)?;
    fs::write(
        &source,
        format!("{}\nfn main() {{}}\n", profile.positive_api.join("\n")),
    )?;

    let metadata = cargo(
        &root,
        temp_root,
        ["metadata", "--offline", "--format-version", "1"],
    )?;
    ensure_success(profile.name, "metadata", &metadata)?;
    assert_committed_dependency_versions(committed_registry, &metadata.stdout)?;
    assert_core_features(profile, &metadata.stdout)?;

    let positive = cargo(&root, temp_root, ["check", "--locked", "--offline"])?;
    ensure_success(profile.name, "positive API check", &positive)?;

    for (index, negative_api) in profile.negative_api.iter().enumerate() {
        fs::write(&source, format!("{negative_api}\nfn main() {{}}\n"))?;
        let negative = cargo(&root, temp_root, ["check", "--locked", "--offline"])?;
        if negative.status.success() {
            return Err(format!(
                "profile {} negative API case {index} unexpectedly compiled",
                profile.name
            )
            .into());
        }
    }
    Ok(())
}

fn assert_committed_dependency_versions(
    committed: &RegistryPackages,
    generated_metadata: &[u8],
) -> Result<(), Box<dyn Error>> {
    let generated = registry_packages(generated_metadata)?;
    let unexpected = generated.difference(committed).collect::<Vec<_>>();
    if unexpected.is_empty() {
        return Ok(());
    }
    Err(format!(
        "independent workspace resolved registry packages outside committed Cargo.lock: {unexpected:?}"
    )
    .into())
}

fn registry_packages(metadata: &[u8]) -> Result<RegistryPackages, Box<dyn Error>> {
    let parsed: serde_json::Value = serde_json::from_slice(metadata)?;
    let packages = parsed["packages"]
        .as_array()
        .ok_or("Cargo metadata omitted packages array")?;
    Ok(packages
        .iter()
        .filter_map(|package| {
            let source = package["source"].as_str()?;
            source.starts_with("registry+").then(|| {
                (
                    package["name"].as_str().unwrap_or_default().to_owned(),
                    package["version"].as_str().unwrap_or_default().to_owned(),
                    source.to_owned(),
                )
            })
        })
        .collect())
}

fn manifest(core: &Path, testkit: &Path, features: &[&str]) -> String {
    let features = features
        .iter()
        .map(|feature| format!("\"{feature}\""))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        r#"[workspace]
resolver = "2"

[package]
name = "feature-matrix-consumer"
version = "0.0.0"
edition = "2024"

[dependencies]
rss-transactional-messaging = {{ path = {core:?}, default-features = false }}
rss-transactional-messaging-testkit = {{ path = {testkit:?}, default-features = false, features = [{features}] }}
"#,
        core = core.as_os_str(),
        testkit = testkit.as_os_str(),
    )
}

fn cargo<const N: usize>(
    root: &Path,
    temp_root: &Path,
    args: [&str; N],
) -> Result<Output, Box<dyn Error>> {
    let cargo = option_env!("CARGO").unwrap_or("cargo");
    Ok(Command::new(cargo)
        .args(args)
        .current_dir(root)
        .env("CARGO_TARGET_DIR", temp_root.join("target"))
        .env_remove("CARGO")
        .env_remove("RUSTC")
        .env_remove("RUSTC_WRAPPER")
        .env_remove("RUSTFLAGS")
        .env_remove("RUSTDOCFLAGS")
        .output()?)
}

fn ensure_success(profile: &str, operation: &str, output: &Output) -> Result<(), Box<dyn Error>> {
    if output.status.success() {
        return Ok(());
    }
    Err(format!(
        "profile {profile} {operation} failed ({}): {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    )
    .into())
}

fn assert_core_features(profile: &Profile<'_>, metadata: &[u8]) -> Result<(), Box<dyn Error>> {
    let metadata: serde_json::Value = serde_json::from_slice(metadata)?;
    let core_id = metadata["packages"]
        .as_array()
        .and_then(|packages| {
            packages.iter().find_map(|package| {
                (package["name"] == "rss-transactional-messaging")
                    .then(|| package["id"].as_str())
                    .flatten()
            })
        })
        .ok_or("metadata omitted rss-transactional-messaging")?;
    let actual = metadata["resolve"]["nodes"]
        .as_array()
        .and_then(|nodes| nodes.iter().find(|node| node["id"] == core_id))
        .and_then(|node| node["features"].as_array())
        .ok_or("metadata omitted resolved core features")?
        .iter()
        .map(|feature| feature.as_str().ok_or("core feature must be a string"))
        .collect::<Result<BTreeSet<_>, _>>()?;
    let expected = profile
        .core_features
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    if actual == expected {
        return Ok(());
    }
    Err(format!(
        "profile {} resolved core features {actual:?}, expected {expected:?}",
        profile.name
    )
    .into())
}
