//! HTTP-specific codecs and exact handler binding, without a registry or application container.
use crate::HttpError;
use axum::{
    Router,
    extract::{Request, State},
    response::{IntoResponse, Response},
    routing::{MethodFilter, MethodRouter},
};
use rss_contract::{Contract, ContractDescriptor, SafeError};
use std::{future::Future, marker::PhantomData};

/// Product-owned HTTP encoding for a protocol-neutral contract.
///
/// Delegate decoding to Axum extractors and encoding to IntoResponse. Neither this trait nor
/// the descriptor proves authentication, authorization or schema/DTO equivalence.
pub trait HttpContract<S>: Contract {
    /// Method selection follows Axum (including its GET/HEAD behavior).
    const METHOD: MethodFilter;
    /// Axum route pattern; invalid patterns and duplicate routes follow Router's own behavior.
    const PATH: &'static str;
    /// Decode with product-supplied state. Classify rejections before exposing them publicly.
    fn decode(
        request: Request,
        state: &S,
    ) -> impl Future<Output = Result<Self::Request, SafeError>> + Send;
    /// Encode a successful result using the product's protocol.
    fn encode(response: Self::Response) -> Response;
}

/// Nominal identity passed only to the handler bound for this contract.
///
/// The private representation prevents callers from manufacturing binding evidence. This is
/// routing evidence, never authentication or proof that an effect happened.
pub struct ContractMarker<C>(PhantomData<fn() -> C>);

/// One inseparable contract, method/path and handler binding.
///
/// INVARIANT: AXUM-CONTRACT-BINDING-01 { level = "Hard", exec = "native-compile", source = "code", native = "Endpoint constructor requires the exact contract marker, input, output and SafeError; private fields prevent replacing route metadata" }.
#[must_use = "mount the endpoint into the product Router"]
pub struct Endpoint<C, S = ()> {
    method_router: MethodRouter<S>,
    contract: PhantomData<fn() -> C>,
}

impl<C, S> Endpoint<C, S>
where
    C: HttpContract<S>,
    S: Clone + Send + Sync + 'static,
{
    /// Bind a function to the exact contract before its output is erased into an HTTP response.
    pub fn new<H, F>(handler: H) -> Self
    where
        H: Fn(ContractMarker<C>, State<S>, C::Request) -> F + Clone + Send + Sync + 'static,
        F: Future<Output = Result<C::Response, SafeError>> + Send + 'static,
    {
        let adapter = move |State(state): State<S>, request: Request| {
            let handler = handler.clone();
            async move {
                let input = match C::decode(request, &state).await {
                    Ok(input) => input,
                    Err(error) => return HttpError::from(error).into_response(),
                };
                match handler(ContractMarker(PhantomData), State(state), input).await {
                    Ok(output) => C::encode(output),
                    Err(error) => HttpError::from(error).into_response(),
                }
            }
        };
        Self {
            method_router: MethodRouter::new().on(C::METHOD, adapter),
            contract: PhantomData,
        }
    }

    /// Authored identity from the same contract used by the handler signature.
    pub fn descriptor(&self) -> ContractDescriptor {
        C::DESCRIPTOR
    }

    /// Mount using the contract's route pattern. Products compose middleware on the Router.
    pub fn mount(self, router: Router<S>) -> Router<S> {
        router.route(C::PATH, self.method_router)
    }
}
