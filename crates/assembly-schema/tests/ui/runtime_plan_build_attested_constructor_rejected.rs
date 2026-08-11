use assembly_schema::{ExecutableAssemblyLock, ParsedAssemblyLock};

fn promote(parsed: ParsedAssemblyLock) {
    let _ = ExecutableAssemblyLock::from_build_attested(parsed);
}

fn main() {}
