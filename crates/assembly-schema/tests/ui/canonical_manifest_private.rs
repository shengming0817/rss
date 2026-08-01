use assembly_schema::CanonicalAssemblyManifestV2;

fn forge(base: CanonicalAssemblyManifestV2) -> CanonicalAssemblyManifestV2 {
    CanonicalAssemblyManifestV2 {
        manifest_digest:
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .parse()
                .unwrap(),
        ..base
    }
}

fn main() {}
