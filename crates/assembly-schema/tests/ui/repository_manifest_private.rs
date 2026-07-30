use assembly_schema::RepositoryAssemblyManifestV2;

fn forge(base: RepositoryAssemblyManifestV2) -> RepositoryAssemblyManifestV2 {
    RepositoryAssemblyManifestV2 {
        source_label: "assemblies/forged/assembly.toml".to_owned(),
        ..base
    }
}

fn main() {}
