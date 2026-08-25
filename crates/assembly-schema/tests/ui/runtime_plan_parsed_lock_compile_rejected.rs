use assembly_schema::{
    CanonicalAssemblyManifestV2, ParsedAssemblyLock, RuntimePlan, RuntimePlanV4Input,
};

fn compile(
    manifest: &CanonicalAssemblyManifestV2,
    lock: &ParsedAssemblyLock,
    input: RuntimePlanV4Input,
) {
    let _ = RuntimePlan::compile_v4(manifest, lock, input);
}

fn main() {}
