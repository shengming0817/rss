use assembly_schema::CanonicalAssemblyManifestV2;

fn forge(base: CanonicalAssemblyManifestV2) -> CanonicalAssemblyManifestV2 {
    CanonicalAssemblyManifestV2 {
        manifest_digest: String::new(),
        ..base
    }
}

fn main() {}
