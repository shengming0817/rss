//! support — RSS 跨层通用 helper（http / pg / validation）签名接缝（基础层，仅 std+外部 crate）。

pub mod http;
pub mod pg;
pub mod validation;

pub use http::{BearerParseError, parse_bearer};
pub use validation::ValidationError;
