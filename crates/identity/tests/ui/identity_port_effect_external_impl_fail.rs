use diport::{LocalPrivilege, ReadEffect};
use identity::ports::IdentityPortEffect;

struct ForgedReadPort;

impl IdentityPortEffect for ForgedReadPort {
    type Effect = ReadEffect;
    type Privilege = LocalPrivilege;
}

fn main() {}
