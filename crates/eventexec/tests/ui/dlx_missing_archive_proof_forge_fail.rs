use eventexec::MissingArchiveProof;

fn value<T>() -> T {
    panic!("compile-fail fixture")
}

fn main() {
    let _forged = MissingArchiveProof { receipt: value() };
}
