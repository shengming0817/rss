use core::marker::PhantomData;

pub struct HttpRouteBinding<R>(PhantomData<fn() -> R>);

impl<R> HttpRouteBinding<R> {
    pub const fn new() -> Self {
        Self(PhantomData)
    }
}
