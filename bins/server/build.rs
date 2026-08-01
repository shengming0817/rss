//! Bake-in compile-time identity for `server version` (#1496).
//!
//! Values come from `GIT_SHA` / `BUILD_DATE` environment variables (Dockerfile ARG → ENV).
//! Defaults are `unknown` so local builds without args still compile; release smoke must pass
//! real values because `.dockerignore` excludes `.git/`.

fn main() {
    emit("GIT_SHA");
    emit("BUILD_DATE");
}

fn emit(name: &str) {
    println!("cargo:rerun-if-env-changed={name}");
    let value = match std::env::var(name) {
        Ok(value) if !value.is_empty() => value,
        _ => "unknown".to_owned(),
    };
    println!("cargo:rustc-env={name}={value}");
}
