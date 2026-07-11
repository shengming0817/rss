use diport::{DiPortEffect, DynAcker, ReadEffect};

fn require_read<T: ?Sized + DiPortEffect<Effect = ReadEffect>>() {}

fn main() {
    require_read::<DynAcker<'static>>();
}
