use assembly_schema::AssemblyDigests;

fn main() {
    let _ = AssemblyDigests {
        manifest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            .parse()
            .unwrap(),
        generated: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            .parse()
            .unwrap(),
        contracts: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
            .parse()
            .unwrap(),
    };
}
