use diport::PkiSan;

fn main() {
    let _forged = PkiSan::Dns("a,b".to_owned());
}
