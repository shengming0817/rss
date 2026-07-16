use std::sync::Arc;

use diport::{DiPortEffect, DynSigner, BusinessWriteEffect};

type HiddenAuthPort = Arc<Box<DynSigner<'static>>>;

fn require_write<T: ?Sized + DiPortEffect<Effect = BusinessWriteEffect>>() {}

fn main() {
    require_write::<HiddenAuthPort>();
}
