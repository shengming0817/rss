#![allow(dead_code, unknown_lints, unused)]
// compile-flags: --crate-name xtask

mod serde_json {
    pub enum Value {}

    pub mod de {
        pub fn from_slice<T>(_bytes: &[u8]) -> Result<T, ()> {
            Err(())
        }

        pub fn from_str<T>(_text: &str) -> Result<T, ()> {
            Err(())
        }

        pub fn from_reader<R, T>(_reader: R) -> Result<T, ()> {
            Err(())
        }

        pub struct Deserializer;

        impl Deserializer {
            pub fn from_slice(_bytes: &[u8]) -> Self {
                Self
            }
        }
    }

    pub use self::de::{Deserializer, from_reader, from_slice, from_str};
}

mod contract {
    pub mod governance {
        pub struct GovernedContract;
    }

    pub mod breaking {
        pub fn base_contract_side(
            _contract: &super::governance::GovernedContract,
            bytes: &[u8],
        ) {
            let _ = crate::serde_json::from_slice::<crate::serde_json::Value>(bytes);
        }
    }
}

mod codegen {
    pub fn tuple_schema(
        _contract: &crate::contract::governance::GovernedContract,
        bytes: &[u8],
    ) {
        let _ = crate::serde_json::from_reader::<_, crate::serde_json::Value>(bytes);
    }
}

#[path = "auxiliary/parser_helper.rs"]
mod parser_helper;

fn governed_root(_contract: &contract::governance::GovernedContract, bytes: &[u8]) {
    parser_helper::cross_file(bytes);
}

fn allowed_roots(contract: &contract::governance::GovernedContract, bytes: &[u8]) {
    codegen::tuple_schema(contract, bytes);
    contract::breaking::base_contract_side(contract, bytes);
}

fn unrelated(bytes: &[u8]) {
    let _ = crate::serde_json::from_str::<crate::serde_json::Value>(
        std::str::from_utf8(bytes).unwrap(),
    );
}

fn main() {}
