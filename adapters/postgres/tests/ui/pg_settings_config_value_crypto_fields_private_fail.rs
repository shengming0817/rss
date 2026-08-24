use postgres::ConfigValueCrypto;

fn crypto_fields_are_private(crypto: ConfigValueCrypto) {
    let _ = crypto.handle;
}

fn main() {}
