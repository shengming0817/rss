use core::marker::PhantomData;

pub mod http {
    pub struct LocalTx;
}

pub struct HttpRouteBinding<R, C>(PhantomData<fn() -> (R, C)>);

impl<R, C> HttpRouteBinding<R, C> {
    pub const fn new() -> Self {
        Self(PhantomData)
    }
}
