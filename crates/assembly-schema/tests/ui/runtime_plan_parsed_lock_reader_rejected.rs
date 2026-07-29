use assembly_schema::{CanonicalAssemblyManifestV2, ParsedAssemblyLock, ParsedRuntimePlan};

fn parse(bytes: &[u8], manifest: &CanonicalAssemblyManifestV2, lock: &ParsedAssemblyLock) {
    let _ = ParsedRuntimePlan::from_json_slice_bound(bytes, manifest, lock);
}

fn main() {}
