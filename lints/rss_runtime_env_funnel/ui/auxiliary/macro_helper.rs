#![crate_type = "lib"]

#[macro_export]
macro_rules! invoke_compile_env {
    ($name:ident) => {
        $name!("RSS_CROSS_FILE_COMPILE_ENV")
    };
}

pub use invoke_compile_env as reexported_invoke;
