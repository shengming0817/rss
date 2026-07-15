use assembly_schema::{AssemblyLock, ParsedAssemblyLock};

fn expose(parsed: &ParsedAssemblyLock) -> &AssemblyLock {
    parsed.as_lock()
}

fn main() {}
