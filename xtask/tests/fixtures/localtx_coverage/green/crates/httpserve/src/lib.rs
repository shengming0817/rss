use core::marker::PhantomData;

pub struct ContractMarker<R>(PhantomData<fn() -> R>);

pub struct GeneratedPrimaryEndpoint;

#[derive(Debug)]
pub struct Error;

impl GeneratedPrimaryEndpoint {
    pub fn new<R, C, H>(_: vocab::HttpRouteBinding<R, C>, _: H) -> Result<Self, Error> {
        Ok(Self)
    }
}

pub struct ListenerRouter;

impl ListenerRouter {
    pub fn mount(self, _: GeneratedPrimaryEndpoint) -> Result<Self, Error> {
        Ok(self)
    }
}

pub struct Registry;

impl Registry {
    pub fn route_group<F>(&mut self, register: F) -> Result<(), Error>
    where
        F: FnOnce(ListenerRouter) -> Result<ListenerRouter, Error>,
    {
        let _ = register(ListenerRouter)?;
        Ok(())
    }
}
