use crate::{Definition, EffectContext, Error};
use futures::future::BoxFuture;
use rss_data_protection::Plaintext;
use serde::{Serialize, de::DeserializeOwned};
use std::{collections::HashMap, future::Future, sync::Arc};

/// Authoritative outcome of an external call; uncertainty never proves absence.
pub enum EffectOutcome<T> {
    /// The effect is durably applied and its typed receipt is available.
    Applied(T),
    /// The provider proves the effect was not applied; the pinned failure policy may permit retry.
    NotApplied,
    /// The provider cannot prove the outcome; recovery must probe before retrying.
    Unknown,
}
/// Authoritative observation of the effect identified by the unchanged idempotency key.
pub enum ProbeOutcome<T> {
    /// The effect exists durably; reconstruct its exact typed receipt.
    Applied(T),
    /// The provider authoritatively proves absence, authorizing a new intent without charging a proven failure.
    NotApplied,
    /// The observation is still uncertain; preserve the intent and stop this invocation.
    Unknown,
}
/// An action's receipt type stays paired through execution, probing and compensation.
pub trait Step: Send + Sync + 'static {
    /// Typed action receipt. The core owns canonical JSON encoding; schemas must remain stable for pinned definitions.
    type Receipt: Serialize + DeserializeOwned + Send + 'static;
    /// Name of the next registered definition step; not inferred from the Rust type.
    fn name(&self) -> &str;
    /// Exact receipt schema identity declared by this action implementation.
    fn receipt_schema(&self) -> &str;
    /// Invoke the forward effect using the supplied stable key. NotApplied must prove absence; uncertain errors return Unknown.
    fn execute(
        &self,
        context: EffectContext,
    ) -> impl Future<Output = EffectOutcome<Self::Receipt>> + Send;
    /// Query the same key authoritatively after an unfinished intent. Applied must reconstruct the original typed receipt.
    fn probe(
        &self,
        context: EffectContext,
    ) -> impl Future<Output = ProbeOutcome<Self::Receipt>> + Send;
    /// Undo this step using its authenticated forward receipt and the distinct compensation key.
    fn compensate(
        &self,
        context: EffectContext,
        receipt: Self::Receipt,
    ) -> impl Future<Output = EffectOutcome<()>> + Send;
    /// Resolve an unfinished compensation by its stable key before another compensation attempt.
    fn probe_compensation(
        &self,
        context: EffectContext,
        receipt: Self::Receipt,
    ) -> impl Future<Output = ProbeOutcome<()>> + Send;
}
pub(crate) trait Action: Send + Sync {
    fn receipt_type(&self) -> std::any::TypeId;
    /// Invoke the forward effect using the supplied stable key. NotApplied must prove absence; uncertain errors return Unknown.
    fn execute(
        &self,
        context: EffectContext,
        probe: bool,
    ) -> BoxFuture<'_, Result<EffectOutcome<Plaintext>, Error>>;
    /// Undo this step using its authenticated forward receipt and the distinct compensation key.
    fn compensate(
        &self,
        context: EffectContext,
        receipt: Plaintext,
        probe: bool,
    ) -> BoxFuture<'_, Result<EffectOutcome<()>, Error>>;
}
struct Typed<S>(S);
fn encode<R: Serialize>(outcome: EffectOutcome<R>) -> Result<EffectOutcome<Plaintext>, Error> {
    Ok(match outcome {
        EffectOutcome::Applied(receipt) => EffectOutcome::Applied(Plaintext::new(
            serde_json_canonicalizer::to_vec(&receipt)
                .map_err(|_| Error::new(crate::ErrorKind::EffectUnknown))?,
        )),
        EffectOutcome::NotApplied => EffectOutcome::NotApplied,
        EffectOutcome::Unknown => EffectOutcome::Unknown,
    })
}
fn outcome<R>(probe: ProbeOutcome<R>) -> EffectOutcome<R> {
    match probe {
        ProbeOutcome::Applied(r) => EffectOutcome::Applied(r),
        ProbeOutcome::NotApplied => EffectOutcome::NotApplied,
        ProbeOutcome::Unknown => EffectOutcome::Unknown,
    }
}
impl<S: Step> Action for Typed<S> {
    fn receipt_type(&self) -> std::any::TypeId {
        std::any::TypeId::of::<S::Receipt>()
    }
    /// Invoke the forward effect using the supplied stable key. NotApplied must prove absence; uncertain errors return Unknown.
    fn execute(
        &self,
        context: EffectContext,
        probe: bool,
    ) -> BoxFuture<'_, Result<EffectOutcome<Plaintext>, Error>> {
        Box::pin(async move {
            let value = if probe {
                outcome(self.0.probe(context).await)
            } else {
                self.0.execute(context).await
            };
            encode(value)
        })
    }
    /// Undo this step using its authenticated forward receipt and the distinct compensation key.
    fn compensate(
        &self,
        context: EffectContext,
        receipt: Plaintext,
        probe: bool,
    ) -> BoxFuture<'_, Result<EffectOutcome<()>, Error>> {
        Box::pin(async move {
            let receipt = serde_json::from_slice(receipt.expose())
                .map_err(|_| Error::new(crate::ErrorKind::Protection))?;
            Ok(if probe {
                outcome(self.0.probe_compensation(context, receipt).await)
            } else {
                self.0.compensate(context, receipt).await
            })
        })
    }
}
/// Assembly-time typed action registration in the exact definition order.
pub struct DefinitionBuilder {
    definition: Definition,
    actions: Vec<Arc<dyn Action>>,
}
impl DefinitionBuilder {
    /// Start registration from a validated complete definition.
    pub fn new(definition: Definition) -> Result<Self, Error> {
        definition.validate()?;
        Ok(Self {
            definition,
            actions: vec![],
        })
    }
    /// Register the next named Step with its exact receipt schema, rejecting order/schema mismatches.
    pub fn step<S: Step>(mut self, step: S) -> Result<Self, Error> {
        if self
            .definition
            .steps()
            .get(self.actions.len())
            .map(|s| s.receipt_schema())
            != Some(step.receipt_schema())
        {
            return Err(Error::new(crate::ErrorKind::Definition));
        }
        if self.definition.steps()[self.actions.len()].name() != step.name() {
            return Err(Error::new(crate::ErrorKind::Definition));
        }
        self.actions.push(Arc::new(Typed(step)));
        Ok(self)
    }
}
/// Typed witness for the registered final action; callers cannot choose an arbitrary decode type.
pub struct Completion<R> {
    pub(crate) definition: Definition,
    pub(crate) step: usize,
    marker: std::marker::PhantomData<fn() -> R>,
}
impl DefinitionBuilder {
    /// Add the final typed step and return the witness needed to resolve successful receipts.
    pub fn last_step<S: Step>(self, step: S) -> Result<(Self, Completion<S::Receipt>), Error> {
        let index = self.actions.len();
        if index + 1 != self.definition.steps().len() {
            return Err(Error::new(crate::ErrorKind::Definition));
        }
        let completion = Completion {
            definition: self.definition.clone(),
            step: index,
            marker: std::marker::PhantomData,
        };
        Ok((self.step(step)?, completion))
    }
}
#[derive(Clone)]
pub(crate) struct Registered {
    pub definition: Definition,
    pub actions: Vec<Arc<dyn Action>>,
}
#[derive(Default)]
/// Builds an exact immutable registry; a contract/version cannot have competing metadata.
pub struct RegistryBuilder {
    entries: HashMap<crate::Identity, Registered>,
}
impl RegistryBuilder {
    /// Register a complete typed definition, rejecting missing actions or a duplicate contract/version.
    pub fn register(mut self, builder: DefinitionBuilder) -> Result<Self, Error> {
        if builder.actions.len() != builder.definition.steps().len()
            || self.entries.keys().any(|id| {
                id.contract() == builder.definition.identity().contract()
                    && id.version() == builder.definition.identity().version()
            })
        {
            return Err(Error::new(crate::ErrorKind::Definition));
        }
        self.entries.insert(
            builder.definition.identity().clone(),
            Registered {
                definition: builder.definition,
                actions: builder.actions,
            },
        );
        Ok(self)
    }
    /// Seal the registry. No mutation or removal API remains available afterwards.
    pub fn finish(self) -> Registry {
        Registry {
            entries: self.entries,
        }
    }
}
/// Immutable definition-to-action registry, with no latest lookup or retirement operation.
pub struct Registry {
    entries: HashMap<crate::Identity, Registered>,
}
impl Registry {
    /// Begin an immutable registry assembly.
    pub fn builder() -> RegistryBuilder {
        RegistryBuilder::default()
    }
    pub(crate) fn resolve(&self, definition: &Definition) -> Result<Registered, Error> {
        let entry = self
            .entries
            .get(definition.identity())
            .ok_or(Error::new(crate::ErrorKind::UnsupportedDefinition))?;
        if &entry.definition != definition {
            return Err(Error::new(crate::ErrorKind::UnsupportedDefinition));
        }
        Ok(entry.clone())
    }
}
