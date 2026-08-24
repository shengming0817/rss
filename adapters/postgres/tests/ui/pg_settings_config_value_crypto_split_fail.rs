use postgres::ConfigValueCrypto;

fn crypto_cannot_be_split(crypto: ConfigValueCrypto) {
    let _ = crypto.into_handle();
}

fn main() {}
