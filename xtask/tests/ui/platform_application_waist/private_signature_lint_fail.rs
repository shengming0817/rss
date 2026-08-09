#![deny(private_bounds, private_interfaces)]

mod internal {
    pub(crate) trait SecretBound {}
    pub(crate) struct SecretType;
}

pub fn leak_bound<T: internal::SecretBound>() {}
pub fn leak_type(_: internal::SecretType) {}

fn main() {}
