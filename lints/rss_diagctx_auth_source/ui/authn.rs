#![allow(dead_code, unused_imports)]

use diagctx::correlation as ambient_correlation;

fn authentication_path() {
    let _ = ambient_correlation();
    let current = diagctx::current;
    let _ = current();
}

fn main() {}
