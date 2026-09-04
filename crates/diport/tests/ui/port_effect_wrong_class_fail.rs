use diport::{DiPortEffect, DynSigner, ReadEffect};

fn require_read<T: ?Sized + DiPortEffect<Effect = ReadEffect>>() {}

fn main() {
    require_read::<DynSigner<'static>>();
}
