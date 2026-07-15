use assembly_schema::CanonicalAssemblyManifestV1;

fn forge(base: CanonicalAssemblyManifestV1) -> CanonicalAssemblyManifestV1 {
    CanonicalAssemblyManifestV1 {
        manifest_digest: String::new(),
        ..base
    }
}

fn main() {}
