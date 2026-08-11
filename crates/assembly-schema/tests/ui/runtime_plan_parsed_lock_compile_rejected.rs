use assembly_schema::{
    CanonicalAssemblyManifestV2, ParsedAssemblyLock, RuntimePlan, RuntimePlanV3Input,
};

fn compile(
    manifest: &CanonicalAssemblyManifestV2,
    lock: &ParsedAssemblyLock,
    input: RuntimePlanV3Input,
) {
    let _ = RuntimePlan::compile_v3(manifest, lock, input);
}

fn main() {}
