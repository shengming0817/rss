use assembly_schema::{
    CanonicalAssemblyManifestV2, ParsedAssemblyLock, RuntimePlan, RuntimePlanV2Input,
};

fn compile(
    manifest: &CanonicalAssemblyManifestV2,
    lock: &ParsedAssemblyLock,
    input: RuntimePlanV2Input,
) {
    let _ = RuntimePlan::compile_v2(manifest, lock, input);
}

fn main() {}
