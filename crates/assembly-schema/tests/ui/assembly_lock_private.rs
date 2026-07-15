use assembly_schema::{
    AssemblyDigests, AssemblyFingerprint, AssemblyIdentity, AssemblyLock,
};

fn forge(
    identity: AssemblyIdentity,
    digests: AssemblyDigests,
    fingerprint: AssemblyFingerprint,
) {
    let _ = AssemblyLock {
        schema_version: 1,
        identity,
        digests,
        fingerprint,
    };
}

fn main() {}
