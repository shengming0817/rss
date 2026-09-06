use ring::{
    aead,
    rand::{SecureRandom as _, SystemRandom},
};
use rss_data_protection::Plaintext;
use rss_saga::*;
use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

pub struct Clock(Instant);
impl Clock {
    #[allow(clippy::disallowed_methods)] // reason: the injected test clock owns its monotonic origin.
    pub fn new() -> Self {
        Self(Instant::now())
    }
}
impl Timer for Clock {
    #[allow(clippy::disallowed_methods)] // reason: elapsed time comes from this injected origin.
    fn now(&self) -> Duration {
        self.0.elapsed()
    }
    async fn sleep_until(&self, deadline: Duration) {
        tokio::time::sleep(deadline.saturating_sub(self.now())).await;
    }
}
pub struct Crypto;
impl SagaReceiptProtector for Crypto {
    async fn seal(&self, plaintext: &[u8], context: &ReceiptContext) -> Result<Ciphertext, Error> {
        let key = aead::LessSafeKey::new(
            aead::UnboundKey::new(&aead::AES_256_GCM, &[42; 32])
                .map_err(|_| Error::new(rss_saga::ErrorKind::Protection))?,
        );
        let mut nonce = [0; 12];
        SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| Error::new(rss_saga::ErrorKind::Protection))?;
        let mut bytes = plaintext.to_vec();
        key.seal_in_place_append_tag(
            aead::Nonce::assume_unique_for_key(nonce),
            aead::Aad::from(context.canonical_aad()),
            &mut bytes,
        )
        .map_err(|_| Error::new(rss_saga::ErrorKind::Protection))?;
        let mut encoded = nonce.to_vec();
        encoded.extend_from_slice(&bytes);
        Ciphertext::new("test-aes-v1".into(), encoded)
    }
    async fn open(
        &self,
        ciphertext: &Ciphertext,
        context: &ReceiptContext,
    ) -> Result<Plaintext, Error> {
        if ciphertext.key_ref() != "test-aes-v1" || ciphertext.bytes().len() < 28 {
            return Err(Error::new(rss_saga::ErrorKind::Protection));
        }
        let nonce: [u8; 12] = ciphertext.bytes()[..12]
            .try_into()
            .map_err(|_| Error::new(rss_saga::ErrorKind::Protection))?;
        let mut bytes = ciphertext.bytes()[12..].to_vec();
        let key = aead::LessSafeKey::new(
            aead::UnboundKey::new(&aead::AES_256_GCM, &[42; 32])
                .map_err(|_| Error::new(rss_saga::ErrorKind::Protection))?,
        );
        let plaintext = key
            .open_in_place(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::from(context.canonical_aad()),
                &mut bytes,
            )
            .map_err(|_| Error::new(rss_saga::ErrorKind::Protection))?;
        Ok(Plaintext::new(plaintext.to_vec()))
    }
}
pub fn protection() -> Result<ReceiptProtection<Crypto>, Error> {
    let id = SagaReceiptIntegrityKeyId::parse("integrity-v1")
        .map_err(|_| Error::new(rss_saga::ErrorKind::Protection))?;
    let key = VersionedSagaReceiptIntegrityKey::from_bytes(id, vec![13; 32])
        .map_err(|_| Error::new(rss_saga::ErrorKind::Protection))?;
    Ok(ReceiptProtection::new(
        Crypto,
        SagaReceiptIntegrityKeyring::new(key, vec![])
            .map_err(|_| Error::new(rss_saga::ErrorKind::Protection))?,
    ))
}
#[derive(Default)]
pub struct Effects {
    pub applied: Mutex<HashMap<String, String>>,
    pub undo: Mutex<Vec<String>>,
    pub fail_undo: AtomicBool,
    pub unknown_once: AtomicBool,
    pub unknown_undo_once: AtomicBool,
    pub calls: Mutex<Vec<String>>,
}
pub struct Action {
    pub name: &'static str,
    pub fail: bool,
    pub effects: Arc<Effects>,
}
impl Step for Action {
    type Receipt = String;
    fn name(&self) -> &str {
        self.name
    }
    fn receipt_schema(&self) -> &str {
        "receipt.v1"
    }
    async fn execute(&self, context: EffectContext) -> EffectOutcome<String> {
        if self.fail {
            return EffectOutcome::NotApplied;
        }
        let key = context.idempotency_key().to_hex();
        match self.effects.applied.lock() {
            Ok(mut map) => {
                map.entry(key).or_insert(self.name.into());
            }
            Err(_) => return EffectOutcome::Unknown,
        }
        if let Ok(mut calls) = self.effects.calls.lock() {
            calls.push(format!("execute:{}", self.name));
        }
        if self.effects.unknown_once.swap(false, Ordering::SeqCst) {
            EffectOutcome::Unknown
        } else {
            EffectOutcome::Applied(self.name.into())
        }
    }
    async fn probe(&self, context: EffectContext) -> ProbeOutcome<String> {
        if let Ok(mut calls) = self.effects.calls.lock() {
            calls.push(format!("probe:{}", self.name));
        }
        match self.effects.applied.lock() {
            Ok(map) => map
                .get(&context.idempotency_key().to_hex())
                .cloned()
                .map_or(ProbeOutcome::NotApplied, ProbeOutcome::Applied),
            Err(_) => ProbeOutcome::Unknown,
        }
    }
    async fn compensate(&self, _: EffectContext, receipt: String) -> EffectOutcome<()> {
        if self.effects.fail_undo.swap(false, Ordering::SeqCst) {
            return EffectOutcome::NotApplied;
        }
        match self.effects.undo.lock() {
            Ok(mut undo) => {
                if !undo.contains(&receipt) {
                    undo.push(receipt);
                }
                if self.effects.unknown_undo_once.swap(false, Ordering::SeqCst) {
                    EffectOutcome::Unknown
                } else {
                    EffectOutcome::Applied(())
                }
            }
            Err(_) => EffectOutcome::Unknown,
        }
    }
    async fn probe_compensation(&self, _: EffectContext, receipt: String) -> ProbeOutcome<()> {
        match self.effects.undo.lock() {
            Ok(undo) => {
                if undo.contains(&receipt) {
                    ProbeOutcome::Applied(())
                } else {
                    ProbeOutcome::NotApplied
                }
            }
            Err(_) => ProbeOutcome::Unknown,
        }
    }
}
pub fn definition(names: &[&str]) -> Result<Definition, Error> {
    let identity = Identity::new(
        rss_contract::ContractId::from_static("orders.checkout"),
        rss_contract::ContractVersion::from_static_major(1),
        rss_contract::SchemaDigest::from_static(
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ),
        rss_saga::ActionGeneration::parse(&format!("sha256:{}", "b".repeat(64)))?,
    );
    Definition::new(
        "orders",
        identity,
        names
            .iter()
            .map(|n| StepSpec::new(n, "receipt.v1", n, &format!("undo.{n}"), 1))
            .collect::<Result<_, _>>()?,
    )
}
pub fn registry(
    definition: Definition,
    effects: Arc<Effects>,
    fail_last: bool,
) -> Result<Registry, Error> {
    let names = definition
        .steps()
        .iter()
        .map(|s| s.name().to_owned())
        .collect::<Vec<_>>();
    let mut builder = DefinitionBuilder::new(definition)?;
    for (i, name) in names.iter().enumerate() {
        let name = match name.as_str() {
            "one" => "one",
            "two" => "two",
            "three" => "three",
            _ => return Err(Error::new(rss_saga::ErrorKind::Definition)),
        };
        builder = builder.step(Action {
            name,
            fail: fail_last && i + 1 == names.len(),
            effects: effects.clone(),
        })?;
    }
    Ok(Registry::builder().register(builder)?.finish())
}
