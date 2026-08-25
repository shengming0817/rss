use assembly_schema::{
    AssemblyDigests, AssemblyFingerprint, AssemblyIdentity, CanonicalAssemblyManifestV2,
    ParsedAssemblyLock, RuntimePlan, RuntimePlanV4Input,
};

struct FakeExecutionProof<'a>(&'a ParsedAssemblyLock);

impl FakeExecutionProof<'_> {
    fn identity(&self) -> &AssemblyIdentity {
        self.0.identity()
    }

    fn digests(&self) -> &AssemblyDigests {
        self.0.digests()
    }

    fn fingerprint(&self) -> &AssemblyFingerprint {
        self.0.fingerprint()
    }
}

fn compile(
    manifest: &CanonicalAssemblyManifestV2,
    lock: &ParsedAssemblyLock,
    input: RuntimePlanV4Input,
) {
    let fake = FakeExecutionProof(lock);
    let _ = RuntimePlan::compile_v4(manifest, &fake, input);
}

fn main() {}
