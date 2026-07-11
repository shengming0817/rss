use diport::{DiPortEffect, LocalPrivilege, ReadEffect};

struct ForgedPort;

impl DiPortEffect for ForgedPort {
    type Effect = ReadEffect;
    type Privilege = LocalPrivilege;
}

fn main() {}
