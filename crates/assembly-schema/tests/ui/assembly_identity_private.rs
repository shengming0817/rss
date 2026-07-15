use assembly_schema::{AssemblyIdentity, AssemblyProfile};

fn main() {
    let _ = AssemblyIdentity {
        name: "runtime".to_owned(),
        profile: AssemblyProfile::Production,
    };
}
