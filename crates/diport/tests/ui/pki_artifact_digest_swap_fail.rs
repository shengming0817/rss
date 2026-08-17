use diport::{PkiPolicyDigest, PkiSpkiDigest};

fn accepts_policy(_: PkiPolicyDigest) {}

fn main() {
    accepts_policy(PkiSpkiDigest::new([0; 32]));
}
