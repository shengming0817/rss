use std::sync::Arc;

use diport::{DiPortEffect, DynSigner, WriteEffect};

type HiddenAuthPort = Arc<Box<DynSigner<'static>>>;

fn require_write<T: ?Sized + DiPortEffect<Effect = WriteEffect>>() {}

fn main() {
    require_write::<HiddenAuthPort>();
}
