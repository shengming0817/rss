//! FIELDPROT-NODBG-DECRYPT-01：`Aead::open` 不能返回裸 `Vec<u8>`。
//!
//! 解密结果必须是 `rss_data_protection::Plaintext`，由其手写 `Debug` 和 `secrecy::SecretSlice` 承载
//! no-decrypt-in-debug。若 `open` 回退成裸明文 buffer，本红例会编译通过，从而暴露类型墙退化。

fn misuse<A: rss_data_protection::Aead>(
    aead: &A,
    env: &rss_data_protection::CiphertextEnvelope,
    aad: &rss_data_protection::DerivedAad,
) {
    let _raw: Vec<u8> = aead.open(env, aad).expect("open must not return raw bytes");
}

fn main() {}
