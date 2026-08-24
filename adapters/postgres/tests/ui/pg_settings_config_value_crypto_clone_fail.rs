use postgres::ConfigValueCrypto;

fn crypto_capability_is_move_only(crypto: ConfigValueCrypto) {
    let _ = crypto.clone();
}

fn main() {}
