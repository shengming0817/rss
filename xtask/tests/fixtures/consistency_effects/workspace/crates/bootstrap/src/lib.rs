pub use httpserve::Registry;
pub trait Domain {
    fn init(&self, registry: &mut Registry) -> Result<(), httpserve::Error>;
}
