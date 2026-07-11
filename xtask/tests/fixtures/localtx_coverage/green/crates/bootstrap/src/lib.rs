pub use httpserve::Registry;

pub trait Domain {
    fn init(&self, reg: &mut Registry) -> Result<(), httpserve::Error>;
}
