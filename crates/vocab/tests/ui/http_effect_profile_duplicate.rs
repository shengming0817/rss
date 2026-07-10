use vocab::HttpEffectKind;

const PROFILE: vocab::HttpEffectProfile =
    vocab::HttpEffectProfile::new(&[HttpEffectKind::Read, HttpEffectKind::Read]);

fn main() {
    let _ = PROFILE;
}
